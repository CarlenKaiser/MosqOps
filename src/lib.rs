use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MQTTEvent {
    pub id: Option<String>,
    pub timestamp: String,
    pub event_type: String,
    pub client_id: Option<String>,
    pub details: Option<String>,
    pub status: Option<String>,
    pub protocol_level: Option<String>,
    pub clean_session: Option<bool>,
    pub keep_alive: Option<i32>,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub topic: Option<String>,
    pub payload: Option<String>,
    pub reason: Option<String>,
}

// Thread-safe, in-memory event log (capped at 100 events)
pub static EVENT_LOG: Lazy<Arc<Mutex<Vec<MQTTEvent>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::with_capacity(100))));

// Helper to push event to log (capped)
pub fn push_event(event: MQTTEvent) {
    let mut log = EVENT_LOG.lock().unwrap();
    log.push(event);
    if log.len() > 1000 {
        log.remove(0);
    }
}
use mosquitto_plugin::*;
use std::ffi::{c_int, c_void};
use std::sync::Once;
use tokio::runtime::Runtime;

pub mod api;
pub mod dynsec;

static INIT: Once = Once::new();
static mut RUNTIME: Option<Runtime> = None;

// Mosquitto log level constants (defined as #define macros in mosquitto.h,
// which bindgen doesn't always capture — define them here for portability).
const MOSQ_LOG_INFO: std::os::raw::c_int = 0x04;
const MOSQ_LOG_ERR: std::os::raw::c_int = 0x08;

pub fn log_info(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe {
            mosquitto_dev::mosquitto_log_printf(MOSQ_LOG_INFO, c_msg.as_ptr());
        }
    }
}

pub fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe {
            mosquitto_dev::mosquitto_log_printf(MOSQ_LOG_ERR, c_msg.as_ptr());
        }
    }
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_version(
    _supported_version_count: c_int,
    _supported_versions: *const c_int,
) -> c_int {
    log_info("mosqops: Checking version...");
    5 // Return Mosquitto plugin API version 5
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_init(
    _identifier: *mut mosquitto_plugin_id_t,
    _user_data: *mut *mut c_void,
    opts: *mut mosquitto_opt,
    opt_count: c_int,
) -> c_int {
    log_info("mosqops: Initializing HTTP API plugin...");

    // Install the ring crypto provider for rustls 0.23+
    // Since we've disabled aws-lc-rs to avoid relocation errors on Alpine,
    // we must explicitly provide a crypto provider.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut conf_path = String::from("mosquitto.conf"); // Default
    let mut dynsec_path = String::from("/data/mosquitto/dynamic-security.json"); // Default fallback

    unsafe {
        if !opts.is_null() && opt_count > 0 {
            for i in 0..(opt_count as usize) {
                let opt_ptr = opts as *mut u8;
                let opt_offset =
                    opt_ptr.add(i * std::mem::size_of::<[*mut std::os::raw::c_char; 2]>());
                let opt_array = &*(opt_offset as *mut [*mut std::os::raw::c_char; 2]);

                if !opt_array[0].is_null() && !opt_array[1].is_null() {
                    let key = std::ffi::CStr::from_ptr(opt_array[0]).to_string_lossy();
                    let value = std::ffi::CStr::from_ptr(opt_array[1]).to_string_lossy();
                    if key == "conf_path" {
                        conf_path = value.into_owned();
                    } else if key == "config_file" {
                        dynsec_path = value.into_owned();
                    }
                }
            }
        }
    }

    // Register Mosquitto event callbacks for client connect/disconnect
    unsafe {
        use mosquitto_plugin::*;
        mosquitto_callback_register(
            _identifier as *mut _,
            MosquittoPluginEvent::MosqEvtBasicAuth as i32,
            Some(on_client_connected_trampoline),
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        mosquitto_callback_register(
            _identifier as *mut _,
            MosquittoPluginEvent::MosqEvtDisconnect as i32,
            Some(on_client_disconnected_trampoline),
            std::ptr::null(),
            std::ptr::null_mut(),
        );
    }
    INIT.call_once(|| {
        // Initialize the Tokio runtime for our background HTTP server
        if let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            unsafe {
                RUNTIME = Some(rt);
            }
            log_info("mosqops: Tokio runtime started.");

            unsafe {
                if let Some(ref rt) = RUNTIME {
                    let conf_path_clone = conf_path.clone();
                    let dynsec_path_clone = dynsec_path.clone();
                    rt.spawn(async move {
                        api::start_api_server(conf_path_clone, dynsec_path_clone).await;
                    });
                }
            }
        } else {
            log_error("mosqops: Failed to start Tokio runtime.");
        }
    });

    0 // Success
}

// Trampoline for client connected event (using basic_auth event)
#[no_mangle]
pub extern "C" fn on_client_connected_trampoline(
    _event: c_int,
    event_data: *mut c_void,
    _user_data: *mut c_void,
) -> c_int {
    use mosquitto_plugin::*;
    if event_data.is_null() {
        return 0;
    }
    let evt: &mosquitto_evt_basic_auth =
        unsafe { &*(event_data as *const mosquitto_evt_basic_auth) };
    let now = chrono::Utc::now().to_rfc3339();
    let client = evt.client;
    if client.is_null() {
        return 0;
    }
    unsafe {
        use mosquitto_plugin::*;
        let client_id = {
            let ptr = mosquitto_client_id(client);
            if ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        };
        let username = {
            let ptr = mosquitto_client_username(client);
            if ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        };
        let ip_address = {
            let ptr = mosquitto_client_address(client);
            if ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        };
        let port = mosquitto_client_port(client) as u16;
        let protocol_level = match mosquitto_client_protocol_version(client) as i32 {
            3 => Some("MQTT v3.1".to_string()),
            4 => Some("MQTT v3.1.1".to_string()),
            5 => Some("MQTT v5.0".to_string()),
            _ => Some("unknown".to_string()),
        };
        let clean_session = Some(mosquitto_client_clean_session(client));
        let keep_alive = Some(mosquitto_client_keepalive(client) as i32);
        let details = match (&ip_address, port) {
            (Some(ip), p) => Some(format!("Connected from {}:{}", ip, p)),
            _ => None,
        };
        let id = match (&now, &client_id) {
            (ts, Some(cid)) => Some(format!("{}_{}_connect", ts, cid)),
            _ => None,
        };
        let event = MQTTEvent {
            id,
            timestamp: now,
            event_type: "Client Connection".to_string(),
            client_id: client_id.clone(),
            details,
            status: Some("success".to_string()),
            protocol_level,
            clean_session,
            keep_alive,
            username,
            ip_address,
            port: Some(port),
            topic: None,
            payload: None,
            reason: None,
        };
        push_event(event);
    }
    0
}

// Trampoline for client disconnected event
#[no_mangle]
pub extern "C" fn on_client_disconnected_trampoline(
    _event: c_int,
    event_data: *mut c_void,
    _user_data: *mut c_void,
) -> c_int {
    use mosquitto_plugin::*;
    if event_data.is_null() {
        return 0;
    }
    let evt: &mosquitto_evt_disconnect =
        unsafe { &*(event_data as *const mosquitto_evt_disconnect) };
    let now = chrono::Utc::now().to_rfc3339();
    let client = evt.client;
    if client.is_null() {
        return 0;
    }
    unsafe {
        use mosquitto_plugin::*;
        let client_id = {
            let ptr = mosquitto_client_id(client);
            if ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        };
        let username = {
            let ptr = mosquitto_client_username(client);
            if ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        };
        let ip_address = {
            let ptr = mosquitto_client_address(client);
            if ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        };
        let port = mosquitto_client_port(client) as u16;
        let protocol_level = match mosquitto_client_protocol_version(client) as i32 {
            3 => Some("MQTT v3.1".to_string()),
            4 => Some("MQTT v3.1.1".to_string()),
            5 => Some("MQTT v5.0".to_string()),
            _ => Some("unknown".to_string()),
        };
        let clean_session = Some(mosquitto_client_clean_session(client));
        let keep_alive = Some(mosquitto_client_keepalive(client) as i32);
        let details = match (&ip_address, port) {
            (Some(ip), p) => Some(format!("Disconnected from {}:{}", ip, p)),
            _ => None,
        };
        let id = match (&now, &client_id) {
            (ts, Some(cid)) => Some(format!("{}_{}_disconnect", ts, cid)),
            _ => None,
        };
        let event = MQTTEvent {
            id,
            timestamp: now,
            event_type: "Client Disconnection".to_string(),
            client_id: client_id.clone(),
            details,
            status: Some("warning".to_string()),
            protocol_level,
            clean_session,
            keep_alive,
            username,
            ip_address,
            port: Some(port),
            topic: None,
            payload: None,
            reason: Some(format!("reason: {}", evt.reason)),
        };
        push_event(event);
    }
    0
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_cleanup(
    _user_data: *mut c_void,
    _opts: *mut mosquitto_opt,
    _opt_count: c_int,
) -> c_int {
    log_info("mosqops: Cleaning up plugin...");

    // Shut down the Tokio runtime
    unsafe {
        if let Some(rt) = RUNTIME.take() {
            rt.shutdown_background();
            log_info("mosqops: Tokio runtime shut down.");
        }
    }

    0 // MOSQ_ERR_SUCCESS
}
