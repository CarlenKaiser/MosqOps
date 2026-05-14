//! Session tracker fed by `$SYS/broker/log/#`.
//!
//! Why this exists: the Mosquitto plugin event API does not expose a generic
//! "client connected" callback. `MosqEvtBasicAuth` is consumed by whichever
//! plugin owns authentication (in this deployment that's
//! `mosquitto_dynamic_security.so`), so the auth event never reaches mosqops
//! and the in-process connect trampoline records nothing. As a result the
//! SESSIONS map stays empty, even though clients are clearly connecting.
//!
//! The broker also publishes its own log messages to `$SYS/broker/log/<level>`
//! when `log_type` includes the matching level. Those messages are emitted
//! regardless of which plugin authenticates, so we can subscribe with an
//! internal admin MQTT client and rebuild the live session map by parsing
//! the connect / disconnect log lines.
//!
//! This is the authoritative live session source for the `/api/v1/sessions`
//! HTTP endpoint and survives bunkerm (UI) restarts, because the state lives
//! inside the broker process itself.

use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
use std::env;
use std::time::Duration;
use uuid::Uuid;

use crate::{remove_session, upsert_session, SessionInfo};

/// Spawn the background log watcher. Idempotent in practice because we only
/// call it once from `mosquitto_plugin_init`.
pub async fn run() {
    // Use a distinct client_id from the dynsec coordinator so the broker
    // does not treat them as duplicate sessions.
    let client_id = format!("mosqops-logwatch-{}", Uuid::new_v4());
    let mut opts = MqttOptions::new(client_id.clone(), "127.0.0.1", 1883);

    if let (Ok(user), Ok(pass)) = (
        env::var("MOSQUITTO_ADMIN_USERNAME"),
        env::var("MOSQUITTO_ADMIN_PASSWORD"),
    ) {
        opts.set_credentials(user, pass);
    }
    opts.set_keep_alive(Duration::from_secs(15));
    opts.set_clean_session(true);

    let (client, mut eventloop) = AsyncClient::new(opts, 64);

    crate::log_info("mosqops: logwatch connecting to broker...");

    // Subscribe to every log level. Levels are published as single-character
    // topic suffixes (N=notice, I=info, W=warning, E=err, D=debug, M=subscribe).
    // Connects/disconnects show up under N. We subscribe wide so we are robust
    // to broker version differences.
    if let Err(e) = client
        .subscribe("$SYS/broker/log/#", QoS::AtMostOnce)
        .await
    {
        crate::log_error(&format!(
            "mosqops: logwatch failed to subscribe to $SYS/broker/log/#: {:?}",
            e
        ));
        return;
    }

    let connect_re = match regex::Regex::new(
        r"New client connected from (?P<ip>[^\s:]+|\[[^\]]+\]):(?P<port>\d+) as (?P<cid>\S+) \(p(?P<proto>\d+), c(?P<clean>\d+), k(?P<keep>\d+)(?:, u'(?P<user>[^']*)')?\)",
    ) {
        Ok(r) => r,
        Err(e) => {
            crate::log_error(&format!("mosqops: logwatch connect regex error: {:?}", e));
            return;
        }
    };
    // Mosquitto emits several disconnect variants:
    //   "Client <cid> disconnected."
    //   "Client <cid> closed its connection."
    //   "Client <cid> disconnected, no longer authorized."
    //   "Client <cid> already connected, closing old connection." (NOT a real disconnect of cid)
    // We only treat the first three as terminal.
    let disconnect_re = match regex::Regex::new(
        r"Client (?P<cid>\S+) (?:disconnected|closed its connection)",
    ) {
        Ok(r) => r,
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: logwatch disconnect regex error: {:?}",
                e
            ));
            return;
        }
    };

    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Incoming::Publish(p))) => {
                if !p.topic.starts_with("$SYS/broker/log/") {
                    continue;
                }
                let payload = match std::str::from_utf8(&p.payload) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if let Some(caps) = connect_re.captures(payload) {
                    let cid = caps["cid"].to_string();
                    // Suppress our own internal connections so the UI doesn't
                    // report them as live business sessions.
                    if cid.starts_with("mosqops-internal-") || cid.starts_with("mosqops-logwatch-")
                    {
                        continue;
                    }
                    let ip = caps["ip"].trim_matches(|c| c == '[' || c == ']').to_string();
                    let port: u16 = caps["port"].parse().unwrap_or(0);
                    let proto = match &caps["proto"] {
                        "3" => "MQTT v3.1",
                        "4" => "MQTT v3.1.1",
                        "5" => "MQTT v5.0",
                        _ => "unknown",
                    };
                    let clean = &caps["clean"] == "1";
                    let keep: i32 = caps["keep"].parse().unwrap_or(0);
                    let user = caps.name("user").map(|m| m.as_str().to_string());
                    let now = chrono::Utc::now().to_rfc3339();

                    upsert_session(SessionInfo {
                        client_id: cid,
                        username: user,
                        ip_address: Some(ip),
                        port: Some(port),
                        protocol_level: Some(proto.to_string()),
                        clean_session: Some(clean),
                        keep_alive: Some(keep),
                        connected_at: now,
                    });
                    continue;
                }

                if let Some(caps) = disconnect_re.captures(payload) {
                    let cid = caps["cid"].to_string();
                    if cid.starts_with("mosqops-internal-") || cid.starts_with("mosqops-logwatch-")
                    {
                        continue;
                    }
                    remove_session(&cid);
                }
            }
            Ok(_) => {}
            Err(e) => {
                crate::log_error(&format!(
                    "mosqops: logwatch event loop error: {:?} — sleeping 3s",
                    e
                ));
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}
