use axum::extract::Query;
use axum::response::sse::Event;
use axum::response::Sse;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::{BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Serialize, Deserialize)]
pub struct ConfigResponse {
    pub message: String,
    pub status: String,
}

#[derive(Deserialize)]
pub struct ConfigUpdateRequest {
    // Accept either the previous `config_content` (used by API callers)
    // or `mosquitto_conf` which contains the raw mosquitto.conf text from the UI.
    pub config_content: Option<String>,
    pub mosquitto_conf: Option<String>,
}

use crate::dynsec::DynSecCoordinator;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use serde_json::{json, Value};
use sha2::Sha512;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct ApiState {
    pub conf_path: String,
    pub dynsec_path: String,
    pub dynsec: Arc<DynSecCoordinator>,
    pub pending_restart: Arc<AtomicBool>,
    pub dynsec_lock: Arc<tokio::sync::Mutex<()>>,
}

fn get_dynsec_path(conf_path: &str, opt_path: &str) -> String {
    // 1. Environment variable takes highest precedence
    if let Ok(env_path) = std::env::var("DYNSEC_PATH") {
        return env_path;
    }

    // 2. Try to parse the actual mosquitto.conf to see what the dynsec plugin is using
    if let Ok(content) = std::fs::read_to_string(conf_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("plugin_opt_config_file") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let path = parts[1].to_string();
                    crate::log_info(&format!(
                        "mosqops: Sourced dynsec path from {}: {}",
                        conf_path, path
                    ));
                    return path;
                }
            }
        }
    }

    // 3. Fallback to the option passed directly to this plugin
    opt_path.to_string()
}

pub async fn start_api_server(conf_path: String, dynsec_path: String) {
    crate::log_info(&format!(
        "mosqops: Starting Axum server on port 8080, conf_path: {}, dynsec_path: {}",
        conf_path, dynsec_path
    ));

    let dynsec_client = match DynSecCoordinator::new().await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Fatal error initializing DynSecCoordinator: {}",
                e
            ));
            return;
        }
    };

    // Create known-good "working" backups upon successful boot
    if let Err(e) = std::fs::copy(&conf_path, format!("{}.working", conf_path)) {
        crate::log_error(&format!(
            "mosqops: Warning - Could not create safe backup of {}: {}",
            conf_path, e
        ));
    }

    let actual_dynsec_path = get_dynsec_path(&conf_path, &dynsec_path);
    crate::log_info(&format!(
        "mosqops: Initializing with dynsec path: {}",
        actual_dynsec_path
    ));
    if std::path::Path::new(&actual_dynsec_path).exists() {
        if let Err(e) = std::fs::copy(
            &actual_dynsec_path,
            format!("{}.working", actual_dynsec_path),
        ) {
            crate::log_error(&format!(
                "mosqops: Warning - Could not create safe backup of dynsec config: {}",
                e
            ));
        }
    }

    let state = Arc::new(ApiState {
        conf_path,
        dynsec_path: actual_dynsec_path,
        dynsec: dynsec_client,
        pending_restart: Arc::new(AtomicBool::new(false)),
        dynsec_lock: Arc::new(tokio::sync::Mutex::new(())),
    });

    // --- MQTT Events API ---

    let app = Router::new()
        .route("/api/status", get(get_system_status))
        .route("/api/config", get(get_config).post(update_config))
        .route("/api/config/reset", post(reset_config))
        .route("/api/restart", post(trigger_restart))
        .route("/api/v1/clients", post(create_client).get(list_clients))
        .route(
            "/api/v1/clients/{username}",
            get(get_client).delete(remove_client),
        )
        .route(
            "/api/v1/clients/{username}/password",
            axum::routing::put(set_client_password),
        )
        .route(
            "/api/v1/clients/{username}/enable",
            axum::routing::put(enable_client),
        )
        .route(
            "/api/v1/clients/{username}/disable",
            axum::routing::put(disable_client),
        )
        .route("/api/v1/clients/{username}/roles", post(add_client_role))
        .route(
            "/api/v1/clients/{username}/roles/{role_name}",
            axum::routing::delete(remove_client_role),
        )
        .route("/api/v1/roles", post(create_role).get(list_roles))
        .route(
            "/api/v1/roles/{role_name}",
            get(get_role).delete(delete_role),
        )
        .route(
            "/api/v1/roles/{role_name}/acls",
            post(add_role_acl).delete(remove_role_acl),
        )
        .route("/api/v1/groups", post(create_group).get(list_groups))
        .route(
            "/api/v1/groups/{group_name}",
            get(get_group).delete(delete_group),
        )
        .route("/api/v1/groups/{group_name}/roles", post(add_group_role))
        .route(
            "/api/v1/config/dynsec",
            get(get_dynsec_config).put(update_dynsec_config),
        )
        .route("/api/v1/config/dynsec/reset", post(reset_dynsec_config))
        .route(
            "/api/v1/groups/{group_name}/roles/{role_name}",
            axum::routing::delete(remove_group_role),
        )
        .route(
            "/api/v1/groups/{group_name}/clients",
            post(add_client_to_group),
        )
        .route(
            "/api/v1/groups/{group_name}/clients/{username}",
            axum::routing::delete(remove_client_from_group),
        )
        .route("/api/v1/logs/broker", get(get_broker_logs))
        .route("/api/v1/logs/stream", get(stream_logs))
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/health", get(health_check))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub async fn health_check() -> &'static str {
    "OK"
}

/// Returns the live MQTT session table — one row per currently-connected
/// client_id. This is the authoritative source of truth for "who is connected
/// right now" and should be consumed by UIs (BunkerM, etc.) instead of replaying
/// the event log, which loses state across broker restarts.
pub async fn list_sessions() -> Json<Vec<crate::SessionInfo>> {
    Json(crate::list_sessions_snapshot())
}

/// Returns the recent connect/disconnect/auth event log (capped at 1000).
/// Audit trail only; do NOT use to derive current connection state.
pub async fn list_events() -> Json<Vec<crate::MQTTEvent>> {
    let snapshot = match crate::EVENT_LOG.lock() {
        Ok(g) => g.clone(),
        Err(_) => Vec::new(),
    };
    Json(snapshot)
}

#[derive(serde::Serialize)]
pub struct SystemStatus {
    pub pending_restart: bool,
}

async fn get_system_status(State(state): State<Arc<ApiState>>) -> Json<SystemStatus> {
    Json(SystemStatus {
        pending_restart: state.pending_restart.load(Ordering::Relaxed),
    })
}

fn parse_config_value(raw: &str) -> Value {
    let value = raw.trim();
    if value.eq_ignore_ascii_case("true") {
        Value::Bool(true)
    } else if value.eq_ignore_ascii_case("false") {
        Value::Bool(false)
    } else if let Ok(int_value) = value.parse::<i64>() {
        Value::Number(int_value.into())
    } else if let Ok(float_value) = value.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(float_value) {
            Value::Number(number)
        } else {
            Value::String(value.to_string())
        }
    } else {
        Value::String(value.to_string())
    }
}

fn insert_or_append(target: &mut serde_json::Map<String, Value>, key: String, value: Value) {
    match target.get_mut(&key) {
        None => {
            target.insert(key, value);
        }
        Some(existing) => {
            if let Some(array) = existing.as_array_mut() {
                array.push(value);
            } else {
                let previous = existing.take();
                *existing = Value::Array(vec![previous, value]);
            }
        }
    }
}

fn dedup_and_collapse(v: Value) -> Value {
    match v {
        Value::Array(arr) => {
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for item in arr {
                let key = serde_json::to_string(&item).unwrap_or_default();
                if seen.insert(key) {
                    out.push(item);
                }
            }
            if out.len() == 1 {
                out.into_iter().next().unwrap()
            } else {
                Value::Array(out)
            }
        }
        other => other,
    }
}

fn normalize_single_log(v: Value) -> Value {
    if let Value::String(s) = v {
        if s.starts_with("file ") {
            let path = s[5..].to_string();
            let mut m = serde_json::Map::new();
            m.insert("type".to_string(), Value::String("file".to_string()));
            m.insert("path".to_string(), Value::String(path));
            Value::Object(m)
        } else {
            let mut m = serde_json::Map::new();
            m.insert("type".to_string(), Value::String(s));
            Value::Object(m)
        }
    } else {
        v
    }
}

fn normalize_log_dest(v: Value) -> Value {
    match v {
        Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_single_log).collect()),
        other => normalize_single_log(other),
    }
}

async fn get_config(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match std::fs::read_to_string(&state.conf_path) {
        Ok(content) => {
            // Parse config file into config and listeners, matching BunkerM backend
            let mut config = serde_json::Map::new();
            let mut listeners = Vec::new();
            let mut current_listener: Option<serde_json::Map<String, serde_json::Value>> = None;

            for raw_line in content.lines() {
                let line = raw_line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }

                if line.starts_with("listener ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(listener) = current_listener.take() {
                        listeners.push(listener);
                    }
                    let mut listener = serde_json::Map::new();
                    listener.insert(
                        "port".to_string(),
                        parts
                            .get(1)
                            .and_then(|p| p.parse::<i64>().ok())
                            .unwrap_or(0)
                            .into(),
                    );
                    listener.insert(
                        "bind_address".to_string(),
                        if parts.len() > 2 {
                            Value::String(parts[2].to_string())
                        } else {
                            Value::String(String::new())
                        },
                    );
                    listener.insert("per_listener_settings".to_string(), false.into());
                    listener.insert("max_connections".to_string(), (-1).into());
                    current_listener = Some(listener);
                    continue;
                }

                let mut parts = line.split_whitespace();
                let key = match parts.next() {
                    Some(k) => k,
                    None => continue,
                };
                let value_raw = parts.collect::<Vec<&str>>().join(" ");
                let value = parse_config_value(&value_raw);

                if let Some(listener) = current_listener.as_mut() {
                    insert_or_append(listener, key.to_string(), value);
                } else {
                    insert_or_append(&mut config, key.to_string(), value);
                }
            }

            if let Some(listener) = current_listener.take() {
                listeners.push(listener);
            }

            // Post-process: promote known global keys from listeners to top-level config,
            // normalize log destinations, and collapse/dedupe arrays where appropriate.
            let global_keys = vec![
                "plugin",
                "plugin_opt_config_file",
                "plugin_opt_conf_path",
                "persistence",
                "persistence_file",
                "persistence_location",
            ];

            for listener in &mut listeners {
                for g in &global_keys {
                    if let Some(v) = listener.remove(*g) {
                        insert_or_append(&mut config, g.to_string(), v);
                    }
                }
            }

            // Normalize each listener map
            for listener in &mut listeners {
                let orig = std::mem::take(listener);
                let mut new = serde_json::Map::new();
                for (k, v) in orig {
                    let v = if k == "log_dest" {
                        normalize_log_dest(v)
                    } else {
                        dedup_and_collapse(v)
                    };
                    new.insert(k, v);
                }
                *listener = new;
            }

            // Normalize top-level config entries
            let orig_conf = std::mem::take(&mut config);
            let mut new_conf = serde_json::Map::new();
            for (k, v) in orig_conf {
                let v = if k == "log_dest" {
                    normalize_log_dest(v)
                } else {
                    dedup_and_collapse(v)
                };
                new_conf.insert(k, v);
            }
            config = new_conf;

            // Produce output that mirrors mosquitto.conf layout while matching
            // BunkerM backend expectations: return `success`, a `config` object,
            // a `listeners` array, and the raw `mosquitto_conf` string.
            let mut root = serde_json::Map::new();

            // Insert success metadata
            root.insert("success".to_string(), Value::Bool(true));

            // Top-level config object (all non-listener directives)
            root.insert("config".to_string(), Value::Object(config));

            // Insert listeners under the plural `listeners` key (preferred by BunkerM)
            let listener_values: Vec<Value> = listeners.into_iter().map(Value::Object).collect();
            root.insert(
                "listeners".to_string(),
                Value::Array(listener_values.clone()),
            );

            // Also keep the older singular `listener` key for backward compatibility
            root.insert("listener".to_string(), Value::Array(listener_values));

            // Expose the raw mosquitto.conf content so UIs can render the exact file
            root.insert("mosquitto_conf".to_string(), Value::String(content.clone()));

            Ok(Json(Value::Object(root)))
        }
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to read config: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read config file: {}", e),
            ))
        }
    }
}

async fn update_config(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<ConfigUpdateRequest>,
) -> Result<Json<ConfigResponse>, (StatusCode, String)> {
    crate::log_info(&format!("mosqops: Updating config at {}", state.conf_path));

    // Determine the raw configuration text to write. Prefer `mosquitto_conf` (raw)
    // which the UI will send when editing the file directly. Fall back to
    // `config_content` for backwards compatibility.
    let raw_conf = if let Some(m) = payload.mosquitto_conf {
        m
    } else if let Some(c) = payload.config_content {
        c
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "No configuration payload provided".into(),
        ));
    };

    // 1. Write the new configuration to a temporary file
    let tmp_path = format!("{}.test", state.conf_path);
    if let Err(e) = std::fs::write(&tmp_path, &raw_conf) {
        crate::log_error(&format!("mosqops: Failed to write temp config: {}", e));
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to write temporary config file: {}", e),
        ));
    }

    // 2. Validate the syntax of the temporary file using Mosquitto's built-in test flag
    crate::log_info("mosqops: Running pre-flight validation on new mosquitto configuration...");
    let output = std::process::Command::new("mosquitto")
        .arg("-c")
        .arg(&tmp_path)
        .arg("-v")
        .arg("-test")
        .output();

    match output {
        Ok(out) => {
            if !out.status.success() {
                // Formatting the standard error (or stdout) from Mosquitto to return directly to the user
                let err_msg = String::from_utf8_lossy(&out.stderr).to_string();
                let out_msg = String::from_utf8_lossy(&out.stdout).to_string();
                crate::log_error(&format!(
                    "mosqops: Config validation failed. stderr: {}, stdout: {}",
                    err_msg, out_msg
                ));

                let _ = std::fs::remove_file(&tmp_path);
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Invalid configuration syntax:\n{}",
                        if !err_msg.is_empty() {
                            err_msg
                        } else {
                            out_msg
                        }
                    ),
                ));
            }
        }
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Failed to execute mosquitto validation: {}",
                e
            ));
            let _ = std::fs::remove_file(&tmp_path);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to execute mosquitto validation command: {}", e),
            ));
        }
    }

    // 3. Validation passed, move the temporary file over the active configuration
    match std::fs::rename(&tmp_path, &state.conf_path) {
        Ok(_) => {
            state.pending_restart.store(true, Ordering::Relaxed);
            Ok(Json(ConfigResponse {
                message: "Configuration successfully validated and updated.".into(),
                status: "ok".into(),
            }))
        }
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to commit valid config: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to commit config file: {}", e),
            ))
        }
    }
}

async fn reset_config(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ConfigResponse>, (StatusCode, String)> {
    crate::log_info(&format!(
        "mosqops: Resetting config at {} from safe backup",
        state.conf_path
    ));

    let working_path = format!("{}.working", state.conf_path);
    if !std::path::Path::new(&working_path).exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            "No safe working backup found to restore.".into(),
        ));
    }

    match std::fs::copy(&working_path, &state.conf_path) {
        Ok(_) => {
            state.pending_restart.store(false, Ordering::Relaxed);
            Ok(Json(ConfigResponse {
                message: "Configuration successfully restored to the last known working state."
                    .into(),
                status: "ok".into(),
            }))
        }
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to restore config backup: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to restore config file: {}", e),
            ))
        }
    }
}

async fn trigger_restart() -> Json<ConfigResponse> {
    crate::log_info("mosqops: Restart requested via API. Terminating process to allow service manager to restart...");

    // Spawn a delayed exit so we can return the HTTP 200 OK response first
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });

    Json(ConfigResponse {
        message: "Restart triggered. Broker is terminating.".into(),
        status: "ok".into(),
    })
}

// ----------------------------------------------------------------------------
// Log Endpoints
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LogParams {
    pub lines: Option<usize>,
    pub backfill: Option<usize>,
}

pub async fn get_broker_logs(
    Query(params): Query<LogParams>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let lines = params.lines.unwrap_or(100);
    // Path fixed for production deployment
    let log_path = "/var/log/mosquitto/mosquitto.log";

    let output = Command::new("tail")
        .arg("-n")
        .arg(lines.to_string())
        .arg(log_path)
        .output()
        .await;

    match output {
        Ok(out) => {
            let logs: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|s| s.to_string())
                .collect();
            Ok(Json(json!({ "logs": logs })))
        }
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to read logs: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read logs: {}", e),
            ))
        }
    }
}

pub async fn stream_logs(
    Query(params): Query<LogParams>,
) -> Sse<BoxStream<'static, Result<Event, Infallible>>> {
    let backfill = params.backfill.unwrap_or(200);
    let log_path = "/var/log/mosquitto/mosquitto.log";

    crate::log_info(&format!(
        "mosqops: Starting log stream with backfill={}",
        backfill
    ));

    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(format!("tail -n {} -F {}", backfill, log_path))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Failed to spawn tail for streaming: {}",
                e
            ));
            // Return an empty stream if tail fails to start
            return Sse::new(futures_util::stream::empty().boxed());
        }
    };

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    let lines = reader.lines();

    let stream = tokio_stream::wrappers::LinesStream::new(lines)
        .map(|line| {
            let data = line.unwrap_or_else(|e| format!("[Stream Error: {}]", e));
            Ok(Event::default().data(data))
        })
        .boxed();

    Sse::new(stream)
}

// ----------------------------------------------------------------------------
// Dynamic Security JSON Endpoints
// ----------------------------------------------------------------------------

pub async fn get_dynsec_config(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let path = &state.dynsec_path;

    crate::log_info(&format!("mosqops: Reading dynsec config from {}", path));
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(json) => {
                crate::log_info("mosqops: Successfully read and parsed DynSec JSON");
                Ok(Json(json))
            }
            Err(e) => {
                crate::log_error(&format!(
                    "mosqops: Failed to parse JSON from {}: {}",
                    path, e
                ));
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to parse JSON: {}", e),
                ))
            }
        },
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Failed to read dynsec config from {}: {}",
                path, e
            ));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read dynsec config file: {}", e),
            ))
        }
    }
}

fn wildcard_subscriptions_enabled() -> bool {
    match std::env::var("MOSQOPS_ALLOW_WILDCARD_SUBS") {
        Ok(v) => {
            let normalized = v.trim().to_ascii_lowercase();
            !(normalized == "0" || normalized == "false" || normalized == "no")
        }
        Err(_) => true,
    }
}

fn enforce_wildcard_subscription_policy(config: &mut Value) {
    if !wildcard_subscriptions_enabled() {
        return;
    }

    let mut role_updates = 0usize;
    let mut client_updates = 0usize;

    if let Some(roles) = config.get_mut("roles").and_then(Value::as_array_mut) {
        for role in roles {
            if let Some(obj) = role.as_object_mut() {
                let needs_update = !matches!(obj.get("allowwildcardsubs"), Some(Value::Bool(true)));
                if needs_update {
                    obj.insert("allowwildcardsubs".to_string(), Value::Bool(true));
                    role_updates += 1;
                }
            }
        }
    }

    if let Some(clients) = config.get_mut("clients").and_then(Value::as_array_mut) {
        for client in clients {
            if let Some(obj) = client.as_object_mut() {
                let needs_update = !matches!(obj.get("allowwildcardsubs"), Some(Value::Bool(true)));
                if needs_update {
                    obj.insert("allowwildcardsubs".to_string(), Value::Bool(true));
                    client_updates += 1;
                }
            }
        }
    }

    if role_updates > 0 || client_updates > 0 {
        crate::log_info(&format!(
            "mosqops: Enforced wildcard subscription policy (roles updated: {}, clients updated: {})",
            role_updates, client_updates
        ));
    }
}

pub async fn update_dynsec_config(
    State(state): State<Arc<ApiState>>,
    Json(mut payload): Json<serde_json::Value>,
) -> Result<Json<ConfigResponse>, (StatusCode, String)> {
    let path = &state.dynsec_path;
    crate::log_info(&format!("mosqops: Updating dynsec config at {}", path));

    enforce_wildcard_subscription_policy(&mut payload);

    let content = match serde_json::to_string_pretty(&payload) {
        Ok(c) => c,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON payload: {}", e),
            ))
        }
    };

    match std::fs::write(&path, content) {
        Ok(_) => {
            // DynSec needs to be reloaded after file modification
            crate::log_info("mosqops: Reloading Mosquitto config to apply dynsec changes");
            let _ = std::process::Command::new("kill")
                .arg("-HUP")
                .arg("1")
                .status();

            state.pending_restart.store(true, Ordering::Relaxed);

            Ok(Json(ConfigResponse {
                message: "Dynamic security configuration successfully updated and loaded.".into(),
                status: "ok".into(),
            }))
        }
        Err(e) => {
            crate::log_error(&format!("mosqops: Failed to write dynsec config: {}", e));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to write dynsec config file: {}", e),
            ))
        }
    }
}

// ----------------------------------------------------------------------------
// Manual Persistence Layer
// ----------------------------------------------------------------------------

fn generate_password_hash(password: &str) -> String {
    let salt: [u8; 12] = rand::random();

    let mut hash = [0u8; 64];
    let iterations = 101;
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), &salt, iterations, &mut hash)
        .expect("PBKDF2 failed");

    // Format: $7$iterations$salt$hash
    format!(
        "$7${}${}${}",
        iterations,
        BASE64.encode(salt),
        BASE64.encode(hash)
    )
}

async fn sync_dynsec<F>(state: Arc<ApiState>, mutator: F)
where
    F: FnOnce(&mut Value),
{
    let _lock = state.dynsec_lock.lock().await;

    let content = match fs::read_to_string(&state.dynsec_path) {
        Ok(c) => c,
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Manual sync failed to read DynSec JSON: {}",
                e
            ));
            return;
        }
    };

    let mut config: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Manual sync failed to parse DynSec JSON: {}",
                e
            ));
            return;
        }
    };

    mutator(&mut config);
    enforce_wildcard_subscription_policy(&mut config);

    // Pretty print matching Mosquitto's internal format
    let new_content = match serde_json::to_string_pretty(&config) {
        Ok(c) => c,
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Manual sync failed to serialize DynSec JSON: {}",
                e
            ));
            return;
        }
    };

    // Atomic write
    let tmp_path = format!("{}.tmp", state.dynsec_path);
    if let Err(e) = fs::write(&tmp_path, new_content) {
        crate::log_error(&format!(
            "mosqops: Manual sync failed to write temp file: {}",
            e
        ));
        return;
    }

    if let Err(e) = fs::rename(&tmp_path, &state.dynsec_path) {
        crate::log_error(&format!(
            "mosqops: Manual sync failed to rename temp file: {}",
            e
        ));
        let _ = fs::remove_file(&tmp_path);
    } else {
        crate::log_info(&format!(
            "mosqops: Manual sync persisted changes to {}",
            state.dynsec_path
        ));
    }
}

pub async fn reset_dynsec_config(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ConfigResponse>, (StatusCode, String)> {
    let path = &state.dynsec_path;
    crate::log_info(&format!(
        "mosqops: Resetting dynsec config at {} from safe backup",
        path
    ));

    let working_path = format!("{}.working", path);
    if !std::path::Path::new(&working_path).exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            "No safe working backup found to restore.".into(),
        ));
    }

    match std::fs::copy(&working_path, path) {
        Ok(_) => {
            crate::log_info("mosqops: Reloading Mosquitto config to apply restored dynsec changes");
            let _ = std::process::Command::new("kill")
                .arg("-HUP")
                .arg("1")
                .status();

            state.pending_restart.store(false, Ordering::Relaxed);
            Ok(Json(ConfigResponse {
                message: "Dynamic security configuration successfully restored to the last known working state.".into(),
                status: "ok".into(),
            }))
        }
        Err(e) => {
            crate::log_error(&format!(
                "mosqops: Failed to restore dynsec config backup: {}",
                e
            ));
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to restore dynsec config file: {}", e),
            ))
        }
    }
}

// ----------------------------------------------------------------------------
// Dynamic Security API
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ClientCreate {
    pub username: String,
    pub password: String,
}

#[derive(serde::Serialize)]
pub struct ClientResponse {
    pub username: String,
    pub message: String,
    pub success: bool,
}

pub async fn create_client(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<ClientCreate>,
) -> Result<Json<ClientResponse>, (StatusCode, String)> {
    let username = payload.username.clone();
    let password = payload.password.clone();

    // 1. MQTT Command for real-time update
    let create_args = json!({
        "username": username,
        "password": password,
    });

    match state
        .dynsec
        .execute_command("createClient", create_args)
        .await
    {
        Ok(_) => {
            // 2. Manual persistence for pod restart reliability
            let state_clone = state.clone();
            let username_clone = username.clone();
            let password_clone = password.clone();

            tokio::spawn(async move {
                let encoded_password = generate_password_hash(&password_clone);
                sync_dynsec(state_clone, move |cfg| {
                    let clients = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("clients"))
                        .and_then(|c| c.as_array_mut());
                    if let Some(clients) = clients {
                        let entry = json!({
                            "username": username_clone,
                            "roles": [],
                            "groups": [],
                            "encoded_password": encoded_password,
                        });

                        if let Some(pos) = clients.iter().position(|c| {
                            c.get("username").and_then(|u| u.as_str()) == Some(&username_clone)
                        }) {
                            clients[pos] = entry;
                        } else {
                            clients.push(entry);
                        }
                    }
                })
                .await;
            });

            Ok(Json(ClientResponse {
                username: username,
                message: "Client created and password set successfully (manual sync triggered)"
                    .into(),
                success: true,
            }))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("Error creating client: {}", e),
        )),
    }
}

pub async fn set_client_password(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<ClientCreate>,
) -> Result<Json<ClientResponse>, (StatusCode, String)> {
    let password = payload.password.clone();
    let set_args = json!({
        "username": username,
        "password": password.clone(),
    });

    match state
        .dynsec
        .execute_command("setClientPassword", set_args)
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let username_clone = username.clone();
            let password_clone = password.clone();

            tokio::spawn(async move {
                let encoded_password = generate_password_hash(&password_clone);
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(client) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("clients"))
                        .and_then(|c| c.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|c| {
                                c.get("username").and_then(|u| u.as_str()) == Some(&username_clone)
                            })
                        })
                    {
                        if let Some(obj) = client.as_object_mut() {
                            obj.insert("encoded_password".to_string(), json!(encoded_password));
                            // Clean up old fields if they exist from previous manual syncs
                            obj.remove("password");
                            obj.remove("salt");
                            obj.remove("iterations");
                        }
                    }
                })
                .await;
            });

            Ok(Json(ClientResponse {
                username,
                message: "Password set successfully (manual sync triggered)".into(),
                success: true,
            }))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("Error setting password: {}", e),
        )),
    }
}

pub async fn list_clients(
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("listClients", json!({})).await {
        Ok(response) => {
            if let Some(clients) = response.data.get("clients").and_then(|c| c.as_array()) {
                let usernames: Vec<String> = clients
                    .iter()
                    .filter_map(|c| {
                        if let Some(u) = c.as_str() {
                            Some(u.to_string())
                        } else {
                            c.get("username")
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string())
                        }
                    })
                    .collect();
                Ok(format!("Clients:\n{}", usernames.join("\n")))
            } else {
                Ok("Clients:\n".to_string())
            }
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("Failed to list clients: {}", e),
        )),
    }
}

pub async fn get_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("getClient", json!({"username": username}))
        .await
    {
        Ok(response) => {
            // DynSec nests client info under response.data.client
            let client_data = response.data.get("client").unwrap_or(&response.data);
            let mut result = format!("Username: {}\n", username);
            if let Some(client_id) = client_data.get("clientid").and_then(|id| id.as_str()) {
                result.push_str(&format!("Clientid: {}\n", client_id));
            }
            if let Some(roles) = client_data.get("roles").and_then(|r| r.as_array()) {
                for role in roles {
                    let role_name = role.get("rolename").and_then(|n| n.as_str()).unwrap_or("");
                    let priority = role.get("priority").and_then(|p| p.as_i64()).unwrap_or(1);
                    result.push_str(&format!("Roles: {} (priority: {})\n", role_name, priority));
                }
            }
            if let Some(groups) = client_data.get("groups").and_then(|g| g.as_array()) {
                let group_names: Vec<String> = groups
                    .iter()
                    .filter_map(|g| {
                        g.get("groupname")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect();
                if !group_names.is_empty() {
                    result.push_str(&format!("Groups: {}\n", group_names.join(", ")));
                }
            }
            Ok(result)
        }
        Err(e) => Err((StatusCode::NOT_FOUND, format!("Client not found: {}", e))),
    }
}

pub async fn enable_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("enableClient", json!({"username": username}))
        .await
    {
        Ok(_) => Ok(Json(
            json!({"message": format!("Client {} enabled successfully", username)}),
        )),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("Failed to enable client {}: {}", username, e),
        )),
    }
}

pub async fn disable_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("disableClient", json!({"username": username}))
        .await
    {
        Ok(_) => Ok(Json(
            json!({"message": format!("Client {} disabled successfully", username)}),
        )),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("Failed to disable client {}: {}", username, e),
        )),
    }
}

pub async fn remove_client(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("deleteClient", json!({"username": username}))
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let username_clone = username.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(clients) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("clients"))
                        .and_then(|c| c.as_array_mut())
                    {
                        clients.retain(|c| {
                            c.get("username").and_then(|u| u.as_str()) != Some(&username_clone)
                        });
                    }
                    if let Some(groups) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                    {
                        for group in groups {
                            if let Some(members) =
                                group.get_mut("clients").and_then(|c| c.as_array_mut())
                            {
                                members.retain(|m| {
                                    m.get("username").and_then(|u| u.as_str())
                                        != Some(&username_clone)
                                });
                            }
                        }
                    }
                })
                .await;
            });

            Ok(Json(
                json!({"message": format!("Client {} removed successfully (manual sync triggered)", username)}),
            ))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("Failed to remove client: {}", e),
        )),
    }
}

#[derive(serde::Deserialize)]
pub struct RoleAssignment {
    pub role_name: String,
    pub priority: Option<i32>,
}

pub async fn add_client_role(
    axum::extract::Path(username): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RoleAssignment>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let prio = payload.priority.unwrap_or(1);
    let role_name = payload.role_name.clone();

    match state
        .dynsec
        .execute_command(
            "addClientRole",
            json!({
                "username": username,
                "rolename": role_name,
                "priority": prio
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let username_clone = username.clone();
            let role_name_clone = role_name.clone();

            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(client) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("clients"))
                        .and_then(|c| c.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|c| {
                                c.get("username").and_then(|u| u.as_str()) == Some(&username_clone)
                            })
                        })
                    {
                        let roles = client
                            .as_object_mut()
                            .and_then(|o| o.get_mut("roles"))
                            .and_then(|r| r.as_array_mut());
                        if let Some(roles) = roles {
                            if !roles.iter().any(|r| {
                                r.get("rolename").and_then(|n| n.as_str()) == Some(&role_name_clone)
                            }) {
                                roles.push(json!({"rolename": role_name_clone, "priority": prio}));
                            }
                        }
                    }
                })
                .await;
            });

            Ok(Json(
                json!({"message": format!("Role {} assigned to client {} (manual sync triggered)", role_name, username)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn remove_client_role(
    axum::extract::Path((username, role_name)): axum::extract::Path<(String, String)>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command(
            "removeClientRole",
            json!({
                "username": username,
                "rolename": role_name,
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let username_clone = username.clone();
            let role_name_clone = role_name.clone();

            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(client) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("clients"))
                        .and_then(|c| c.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|c| {
                                c.get("username").and_then(|u| u.as_str()) == Some(&username_clone)
                            })
                        })
                    {
                        if let Some(roles) = client
                            .as_object_mut()
                            .and_then(|o| o.get_mut("roles"))
                            .and_then(|r| r.as_array_mut())
                        {
                            roles.retain(|r| {
                                r.get("rolename").and_then(|n| n.as_str()) != Some(&role_name_clone)
                            });
                        }
                    }
                })
                .await;
            });

            Ok(Json(
                json!({"message": format!("Role {} removed from client {} (manual sync triggered)", role_name, username)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

// ----------------------------------------------------------------------------
// ROLE ENDPOINTS
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct RoleCreate {
    pub name: String,
}

pub async fn create_role(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RoleCreate>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let role_name = payload.name.clone();
    match state
        .dynsec
        .execute_command("createRole", json!({"rolename": role_name}))
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let role_name_clone = role_name.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(roles) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("roles"))
                        .and_then(|r| r.as_array_mut())
                    {
                        if !roles.iter().any(|r| {
                            r.get("rolename").and_then(|n| n.as_str()) == Some(&role_name_clone)
                        }) {
                            roles.push(json!({"rolename": role_name_clone, "acls": []}));
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Role {} created successfully (manual sync triggered)", role_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn list_roles(
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("listRoles", json!({})).await {
        Ok(response) => {
            if let Some(roles) = response.data.get("roles").and_then(|r| r.as_array()) {
                let rolenames: Vec<String> = roles
                    .iter()
                    .filter_map(|r| {
                        if let Some(n) = r.as_str() {
                            Some(n.to_string())
                        } else {
                            r.get("rolename")
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string())
                        }
                    })
                    .collect();
                Ok(format!("Roles:\n{}", rolenames.join("\n")))
            } else {
                Ok("Roles:\n".to_string())
            }
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn get_role(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("getRole", json!({"rolename": role_name}))
        .await
    {
        Ok(response) => {
            // DynSec nests role info under response.data.role
            let role_data = response.data.get("role").unwrap_or(&response.data);
            let mut result = format!("Role: {}\n", role_name);
            if let Some(acls) = role_data.get("acls").and_then(|a| a.as_array()) {
                if !acls.is_empty() {
                    result.push_str("ACLs:\n");
                    for acl in acls {
                        let acl_type = acl.get("acltype").and_then(|t| t.as_str()).unwrap_or("");
                        let allow = acl.get("allow").and_then(|a| a.as_bool()).unwrap_or(true);
                        let perm = if allow { "allow" } else { "deny" };
                        let topic = acl.get("topic").and_then(|t| t.as_str()).unwrap_or("");
                        let priority = acl.get("priority").and_then(|p| p.as_i64()).unwrap_or(0);
                        if priority > 0 {
                            result.push_str(&format!(
                                "{}: {}: {} (priority: {})\n",
                                acl_type, perm, topic, priority
                            ));
                        } else {
                            result.push_str(&format!("{}: {}: {}\n", acl_type, perm, topic));
                        }
                    }
                }
            }
            Ok(result)
        }
        Err(e) => Err((StatusCode::NOT_FOUND, format!("Role not found: {}", e))),
    }
}

pub async fn delete_role(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("deleteRole", json!({"rolename": role_name}))
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let role_name_clone = role_name.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(roles) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("roles"))
                        .and_then(|r| r.as_array_mut())
                    {
                        roles.retain(|r| {
                            r.get("rolename").and_then(|n| n.as_str()) != Some(&role_name_clone)
                        });
                    }
                    if let Some(clients) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("clients"))
                        .and_then(|c| c.as_array_mut())
                    {
                        for client in clients {
                            if let Some(roles) =
                                client.get_mut("roles").and_then(|r| r.as_array_mut())
                            {
                                roles.retain(|r| {
                                    r.get("rolename").and_then(|n| n.as_str())
                                        != Some(&role_name_clone)
                                });
                            }
                        }
                    }
                    if let Some(groups) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                    {
                        for group in groups {
                            if let Some(roles) =
                                group.get_mut("roles").and_then(|r| r.as_array_mut())
                            {
                                roles.retain(|r| {
                                    r.get("rolename").and_then(|n| n.as_str())
                                        != Some(&role_name_clone)
                                });
                            }
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Role {} deleted successfully (manual sync triggered)", role_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

#[derive(serde::Deserialize)]
pub struct AclRequest {
    pub topic: String,
    #[serde(rename = "aclType")]
    pub acl_type: String,
    pub permission: String,
}

pub async fn add_role_acl(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<AclRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let allow = payload.permission.to_lowercase() == "allow";
    let acl_type = payload.acl_type.clone();
    let topic = payload.topic.clone();

    match state
        .dynsec
        .execute_command(
            "addRoleACL",
            json!({
                "rolename": role_name,
                "acltype": acl_type,
                "topic": topic,
                "allow": allow
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let role_name_clone = role_name.clone();
            let acl_type_clone = acl_type.clone();
            let topic_clone = topic.clone();

            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(role) = cfg.as_object_mut()
                        .and_then(|o| o.get_mut("roles"))
                        .and_then(|r| r.as_array_mut())
                        .and_then(|a| a.iter_mut().find(|r| r.get("rolename").and_then(|n| n.as_str()) == Some(&role_name_clone))) {

                        let acls = role.as_object_mut().and_then(|o| o.get_mut("acls")).and_then(|a| a.as_array_mut());
                        if let Some(acls) = acls {
                            acls.push(json!({"acltype": acl_type_clone, "topic": topic_clone, "allow": allow}));
                        }
                    }
                }).await;
            });
            Ok(Json(
                json!({"message": format!("ACL added successfully to role {} (manual sync triggered)", role_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

#[derive(serde::Deserialize)]
pub struct RemoveAclQuery {
    pub acl_type: String,
    pub topic: String,
}

pub async fn remove_role_acl(
    axum::extract::Path(role_name): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<RemoveAclQuery>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let acl_type = query.acl_type.clone();
    let topic = query.topic.clone();

    match state
        .dynsec
        .execute_command(
            "removeRoleACL",
            json!({
                "rolename": role_name,
                "acltype": acl_type,
                "topic": topic
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let role_name_clone = role_name.clone();
            let acl_type_clone = acl_type.clone();
            let topic_clone = topic.clone();

            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(role) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("roles"))
                        .and_then(|r| r.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|r| {
                                r.get("rolename").and_then(|n| n.as_str()) == Some(&role_name_clone)
                            })
                        })
                    {
                        if let Some(acls) = role
                            .as_object_mut()
                            .and_then(|o| o.get_mut("acls"))
                            .and_then(|a| a.as_array_mut())
                        {
                            acls.retain(|a| {
                                !(a.get("acltype").and_then(|t| t.as_str())
                                    == Some(&acl_type_clone)
                                    && a.get("topic").and_then(|t| t.as_str())
                                        == Some(&topic_clone))
                            });
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("ACL removed from role {} successfully (manual sync triggered)", role_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

// ----------------------------------------------------------------------------
// GROUP ENDPOINTS
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct GroupCreate {
    pub name: String,
}

pub async fn create_group(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<GroupCreate>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let group_name = payload.name.clone();
    match state
        .dynsec
        .execute_command("createGroup", json!({"groupname": group_name}))
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let group_name_clone = group_name.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(groups) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                    {
                        if !groups.iter().any(|g| {
                            g.get("groupname").and_then(|n| n.as_str()) == Some(&group_name_clone)
                        }) {
                            groups.push(
                                json!({"groupname": group_name_clone, "roles": [], "clients": []}),
                            );
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Group {} created successfully (manual sync triggered)", group_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn list_groups(
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state.dynsec.execute_command("listGroups", json!({})).await {
        Ok(response) => {
            if let Some(groups) = response.data.get("groups").and_then(|g| g.as_array()) {
                let groupnames: Vec<String> = groups
                    .iter()
                    .filter_map(|g| {
                        if let Some(n) = g.as_str() {
                            Some(n.to_string())
                        } else {
                            g.get("groupname")
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string())
                        }
                    })
                    .collect();
                Ok(format!("Groups:\n{}", groupnames.join("\n")))
            } else {
                Ok("Groups:\n".to_string())
            }
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn get_group(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<String, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("getGroup", json!({"groupname": group_name}))
        .await
    {
        Ok(response) => {
            // DynSec nests group info under response.data.group
            let group_data = response.data.get("group").unwrap_or(&response.data);
            let mut result = format!("Group: {}\n", group_name);
            if let Some(roles) = group_data.get("roles").and_then(|r| r.as_array()) {
                for role in roles {
                    let role_name = role.get("rolename").and_then(|n| n.as_str()).unwrap_or("");
                    result.push_str(&format!("Roles: {}\n", role_name));
                }
            }
            if let Some(clients) = group_data.get("clients").and_then(|c| c.as_array()) {
                for client in clients {
                    let client_name = client
                        .get("username")
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    result.push_str(&format!("Clients: {}\n", client_name));
                }
            }
            Ok(result)
        }
        Err(e) => Err((StatusCode::NOT_FOUND, format!("Group not found: {}", e))),
    }
}

pub async fn delete_group(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command("deleteGroup", json!({"groupname": group_name}))
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let group_name_clone = group_name.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(groups) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                    {
                        groups.retain(|g| {
                            g.get("groupname").and_then(|n| n.as_str()) != Some(&group_name_clone)
                        });
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Group {} deleted successfully (manual sync triggered)", group_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn add_group_role(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RoleAssignment>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let role_name = payload.role_name.clone();
    match state
        .dynsec
        .execute_command(
            "addGroupRole",
            json!({
                "groupname": group_name,
                "rolename": role_name
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let group_name_clone = group_name.clone();
            let role_name_clone = role_name.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(group) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|g| {
                                g.get("groupname").and_then(|n| n.as_str())
                                    == Some(&group_name_clone)
                            })
                        })
                    {
                        let roles = group
                            .as_object_mut()
                            .and_then(|o| o.get_mut("roles"))
                            .and_then(|r| r.as_array_mut());
                        if let Some(roles) = roles {
                            if !roles.iter().any(|r| {
                                r.get("rolename").and_then(|n| n.as_str()) == Some(&role_name_clone)
                            }) {
                                roles.push(json!({"rolename": role_name_clone}));
                            }
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Role {} assigned to group {} (manual sync triggered)", role_name, group_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn remove_group_role(
    axum::extract::Path((group_name, role_name)): axum::extract::Path<(String, String)>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command(
            "removeGroupRole",
            json!({
                "groupname": group_name,
                "rolename": role_name
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let group_name_clone = group_name.clone();
            let role_name_clone = role_name.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(group) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|g| {
                                g.get("groupname").and_then(|n| n.as_str())
                                    == Some(&group_name_clone)
                            })
                        })
                    {
                        if let Some(roles) = group
                            .as_object_mut()
                            .and_then(|o| o.get_mut("roles"))
                            .and_then(|r| r.as_array_mut())
                        {
                            roles.retain(|r| {
                                r.get("rolename").and_then(|n| n.as_str()) != Some(&role_name_clone)
                            });
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Role {} removed from group {} (manual sync triggered)", role_name, group_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

#[derive(serde::Deserialize)]
pub struct GroupClientAdd {
    pub username: String,
    pub priority: Option<i32>,
}

pub async fn add_client_to_group(
    axum::extract::Path(group_name): axum::extract::Path<String>,
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<GroupClientAdd>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let prio = payload.priority.unwrap_or(1);
    let username = payload.username.clone();
    match state
        .dynsec
        .execute_command(
            "addGroupClient",
            json!({
                "groupname": group_name,
                "username": username,
                "priority": prio
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let group_name_clone = group_name.clone();
            let username_clone = username.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(group) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|g| {
                                g.get("groupname").and_then(|n| n.as_str())
                                    == Some(&group_name_clone)
                            })
                        })
                    {
                        let clients = group
                            .as_object_mut()
                            .and_then(|o| o.get_mut("clients"))
                            .and_then(|c| c.as_array_mut());
                        if let Some(clients) = clients {
                            if !clients.iter().any(|c| {
                                c.get("username").and_then(|n| n.as_str()) == Some(&username_clone)
                            }) {
                                clients.push(json!({"username": username_clone, "priority": prio}));
                            }
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Client {} added to group {} successfully (manual sync triggered)", username, group_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

pub async fn remove_client_from_group(
    axum::extract::Path((group_name, username)): axum::extract::Path<(String, String)>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state
        .dynsec
        .execute_command(
            "removeGroupClient",
            json!({
                "groupname": group_name,
                "username": username
            }),
        )
        .await
    {
        Ok(_) => {
            let state_clone = state.clone();
            let group_name_clone = group_name.clone();
            let username_clone = username.clone();
            tokio::spawn(async move {
                sync_dynsec(state_clone, move |cfg| {
                    if let Some(group) = cfg
                        .as_object_mut()
                        .and_then(|o| o.get_mut("groups"))
                        .and_then(|g| g.as_array_mut())
                        .and_then(|a| {
                            a.iter_mut().find(|g| {
                                g.get("groupname").and_then(|n| n.as_str())
                                    == Some(&group_name_clone)
                            })
                        })
                    {
                        if let Some(clients) = group
                            .as_object_mut()
                            .and_then(|o| o.get_mut("clients"))
                            .and_then(|c| c.as_array_mut())
                        {
                            clients.retain(|c| {
                                c.get("username").and_then(|u| u.as_str()) != Some(&username_clone)
                            });
                        }
                    }
                })
                .await;
            });
            Ok(Json(
                json!({"message": format!("Client {} removed from group {} successfully (manual sync triggered)", username, group_name)}),
            ))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}
