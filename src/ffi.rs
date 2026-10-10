use crate::client::{run_client_with_shutdown, ClientConfig};
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::runtime::Runtime;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(err: String) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(err);
    });
}

/// Opaque client instance handle returned to C callers
pub struct NovlClientHandle {
    runtime: Option<Runtime>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    stopped: Arc<AtomicBool>,
}

/// Returns the static NOVL engine version string (e.g. "0.1.0")
#[no_mangle]
pub extern "C" fn novl_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

/// Retrieves the most recent error message on the calling thread.
/// Returns null if no error occurred. The returned string must be freed with `novl_free_string`.
#[no_mangle]
pub extern "C" fn novl_last_error() -> *mut c_char {
    LAST_ERROR.with(|cell| {
        if let Some(err) = cell.borrow_mut().take() {
            if let Ok(c_str) = CString::new(err) {
                return c_str.into_raw();
            }
        }
        std::ptr::null_mut()
    })
}

/// Frees a C string allocated by `novl_*` functions
///
/// # Safety
/// The caller must pass a pointer allocated by NOVL FFI, or NULL.
#[no_mangle]
pub unsafe extern "C" fn novl_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Starts a background NOVL SOCKS5 client instance from a JSON configuration string.
///
/// # Safety
/// `config_json` must be a valid null-terminated C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn novl_start_client(
    config_json: *const c_char,
) -> *mut NovlClientHandle {
    if config_json.is_null() {
        set_last_error("Config JSON pointer is null".to_string());
        return std::ptr::null_mut();
    }

    let c_str = CStr::from_ptr(config_json);
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("Invalid UTF-8 in configuration string: {}", e));
            return std::ptr::null_mut();
        }
    };

    let config: ClientConfig = match serde_json::from_str(json_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_last_error(format!("JSON deserialization error: {}", e));
            return std::ptr::null_mut();
        }
    };

    if config.server_addr.port() == 80 && config.mode == crate::client::TransportMode::TlsChameleon
    {
        set_last_error("TLS mode cannot be used on port 80 (DPI L7 restriction)".to_string());
        return std::ptr::null_mut();
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            set_last_error(format!("Failed to build Tokio runtime: {}", e));
            return std::ptr::null_mut();
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_clone = Arc::clone(&stopped);

    rt.spawn(async move {
        if let Err(e) = run_client_with_shutdown(config, shutdown_rx).await {
            tracing::error!("NOVL FFI client runner error: {}", e);
        }
        stopped_clone.store(true, Ordering::SeqCst);
    });

    let handle = Box::new(NovlClientHandle {
        runtime: Some(rt),
        shutdown_tx,
        stopped,
    });

    Box::into_raw(handle)
}

/// Stops a running NOVL client instance and releases all associated resources.
///
/// # Safety
/// `handle` must be a valid pointer returned by `novl_start_client`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn novl_stop_client(handle: *mut NovlClientHandle) -> c_int {
    if handle.is_null() {
        set_last_error("Handle pointer is null".to_string());
        return -1;
    }

    let mut boxed = Box::from_raw(handle);
    let _ = boxed.shutdown_tx.send(true);

    if let Some(rt) = boxed.runtime.take() {
        rt.shutdown_timeout(std::time::Duration::from_millis(500));
    }

    boxed.stopped.store(true, Ordering::SeqCst);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_version() {
        let v_ptr = novl_version();
        let c_str = unsafe { CStr::from_ptr(v_ptr) };
        assert_eq!(c_str.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_ffi_lifecycle() {
        let json = r#"{
            "socks5_listen": "127.0.0.1:0",
            "server_addr": "127.0.0.1:7443",
            "server_sni": "test.com",
            "secret": "default-novl-secret",
            "mode": "tls",
            "path": "/novl",
            "split_pos": 5,
            "split_delay_ms": 1
        }"#;

        let c_json = CString::new(json).unwrap();
        let handle = unsafe { novl_start_client(c_json.as_ptr()) };
        assert!(!handle.is_null(), "Handle must not be null on valid json");

        let stop_ret = unsafe { novl_stop_client(handle) };
        assert_eq!(stop_ret, 0, "Stop must return 0");
    }

    #[test]
    fn test_ffi_invalid_config() {
        let bad_json = CString::new("{ invalid json ").unwrap();
        let handle = unsafe { novl_start_client(bad_json.as_ptr()) };
        assert!(handle.is_null());

        let err_ptr = novl_last_error();
        assert!(!err_ptr.is_null());
        let err_str = unsafe { CStr::from_ptr(err_ptr) }.to_str().unwrap();
        assert!(err_str.contains("JSON deserialization error"));
        unsafe { novl_free_string(err_ptr) };
    }
}
