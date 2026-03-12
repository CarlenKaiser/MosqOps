use mosquitto_plugin::*;
use std::ffi::{c_int, c_void};
use std::ptr;
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
            mosquitto_dev::mosquitto_log_printf(
                MOSQ_LOG_INFO,
                c_msg.as_ptr(),
            );
        }
    }
}

pub fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe {
            mosquitto_dev::mosquitto_log_printf(
                MOSQ_LOG_ERR,
                c_msg.as_ptr(),
            );
        }
    }
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_version(
    supported_version_count: c_int,
    supported_versions: *const c_int,
) -> c_int {
    log_info("mosqops: Checking version...");
    5 // Return Mosquitto plugin API version 5
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_init(
    identifier: *mut mosquitto_plugin_id_t,
    user_data: *mut *mut c_void,
    opts: *mut mosquitto_opt,
    opt_count: c_int,
) -> c_int {
    log_info("mosqops: Initializing HTTP API plugin...");

    let mut conf_path = String::from("mosquitto.conf"); // Default

    unsafe {
        if !opts.is_null() && opt_count > 0 {
            for i in 0..(opt_count as usize) {
                let opt_ptr = opts as *mut u8;
                let opt_offset = opt_ptr.add(i * std::mem::size_of::<*mut std::ffi::c_char>() * 2);
                let opt_array = &*(opt_offset as *mut [*mut std::os::raw::c_char; 2]);
                
                if !opt_array[0].is_null() && !opt_array[1].is_null() {
                    let key = std::ffi::CStr::from_ptr(opt_array[0]).to_string_lossy();
                    let value = std::ffi::CStr::from_ptr(opt_array[1]).to_string_lossy();
                    if key == "conf_path" {
                        conf_path = value.into_owned();
                        break;
                    }
                }
            }
        }
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
                    rt.spawn(async move {
                        api::start_api_server(conf_path_clone).await;
                    });
                }
            }
        } else {
            log_error("mosqops: Failed to start Tokio runtime.");
        }
    });

    0 // MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_cleanup(
    user_data: *mut c_void,
    opts: *mut mosquitto_opt,
    opt_count: c_int,
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
