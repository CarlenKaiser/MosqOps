use rumqttc::{AsyncClient, MqttOptions, QoS, Event, Packet, Incoming};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use std::time::Duration;
use uuid::Uuid;
use std::env;

#[derive(Serialize)]
pub struct DynSecCommand {
    pub command: String,
    #[serde(rename = "correlationData")]
    pub correlation_data: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Serialize)]
pub struct DynSecRequest {
    pub commands: Vec<DynSecCommand>,
}

#[derive(Deserialize, Debug)]
pub struct DynSecResponseItem {
    pub command: String,
    #[serde(rename = "correlationData")]
    pub correlation_data: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

#[derive(Deserialize, Debug)]
pub struct DynSecResponse {
    pub responses: Option<Vec<DynSecResponseItem>>,
}

pub struct DynSecCoordinator {
    client: AsyncClient,
    pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<Result<DynSecResponseItem, String>>>>>,
}

impl DynSecCoordinator {
    pub async fn new() -> Result<Self, String> {
        let mut mqttoptions = MqttOptions::new(
            format!("mosqops-internal-{}", Uuid::new_v4()),
            "127.0.0.1",
            1883,
        );

        if let (Ok(user), Ok(pass)) = (env::var("MOSQUITTO_ADMIN_USERNAME"), env::var("MOSQUITTO_ADMIN_PASSWORD")) {
            mqttoptions.set_credentials(user, pass);
        }

        mqttoptions.set_keep_alive(Duration::from_secs(5));

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
        let pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<Result<DynSecResponseItem, String>>>>> = Arc::new(Mutex::new(HashMap::new()));
        
        let pending_clone = pending_requests.clone();

        crate::log_info("mosqops: Connecting internal DynSec MQTT coordinator...");

        // Subscribe immediately after getting the client handle
        client.subscribe("$CONTROL/dynamic-security/v1/response", QoS::AtLeastOnce).await.map_err(|e| format!("Subscribe error: {:?}", e))?;

        // Background task for the MQTT event loop
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Incoming::Publish(p))) => {
                        if p.topic == "$CONTROL/dynamic-security/v1/response" {
                            if let Ok(response) = serde_json::from_slice::<DynSecResponse>(&p.payload) {
                                if let Some(responses) = response.responses {
                                    for mut item in responses {
                                        if let Some(corr_data) = item.correlation_data.take() {
                                            let mut map = pending_clone.lock().await;
                                            if let Some(sender) = map.remove(&corr_data) {
                                                if let Some(err) = &item.error {
                                                    let _ = sender.send(Err(err.clone()));
                                                } else {
                                                    let _ = sender.send(Ok(item));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        crate::log_error(&format!("mosqops: Internal MQTT event loop error: {:?}", e));
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
            }
        });

        Ok(Self {
            client,
            pending_requests,
        })
    }

    pub async fn execute_command(&self, command_name: &str, mut params: serde_json::Value) -> Result<DynSecResponseItem, String> {
        let corr_id = Uuid::new_v4().to_string();
        
        let cmd = DynSecCommand {
            command: command_name.to_string(),
            correlation_data: corr_id.clone(),
            extra: params,
        };

        let req = DynSecRequest {
            commands: vec![cmd],
        };

        let payload = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        
        let (tx, rx) = oneshot::channel();
        self.pending_requests.lock().await.insert(corr_id.clone(), tx);

        self.client.publish("$CONTROL/dynamic-security/v1", QoS::AtLeastOnce, false, payload).await.map_err(|e| e.to_string())?;

        // Wait with a 5 second timeout
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(e)) => Err(format!("Internal receive error: {:?}", e)),
            Err(_) => {
                self.pending_requests.lock().await.remove(&corr_id);
                Err("DynSec Plugin timed out. Is dynamic-security loaded?".into())
            }
        }
    }
}
