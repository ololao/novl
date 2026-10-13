use crate::client::{ClientConfig, TransportMode};
use jni_sys::{jclass, jint, jobject, jstring, JNIEnv, JavaVM, JNI_OK, JNI_VERSION_1_6};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use tun2proxy::{ArgDns, Args, CancellationToken, ProxyParameters};

struct VmWrapper(*mut JavaVM);
unsafe impl Send for VmWrapper {}
unsafe impl Sync for VmWrapper {}

/// A registered `VpnService` and the resolved `protect(I)Z` method. The service
/// reference is a JNI global reference whose lifetime is owned by this struct.
struct VpnServiceState {
    service: jobject,
    protect_method: jni_sys::jmethodID,
}
unsafe impl Send for VpnServiceState {}
unsafe impl Sync for VpnServiceState {}

static JVM: Mutex<Option<VmWrapper>> = Mutex::new(None);
static VPN_STATE: Mutex<Option<VpnServiceState>> = Mutex::new(None);

struct ActiveTunnel {
    handle: i32,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    tun2proxy_token: CancellationToken,
    runtime: tokio::runtime::Runtime,
}

static ACTIVE_TUNNEL: Mutex<Option<ActiveTunnel>> = Mutex::new(None);
static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);

/// Exempts an outbound socket from the Android VPN routing table so its packets
/// reach the physical network (Wi-Fi/Cellular) directly without creating a routing loop.
pub fn protect_socket(fd: std::os::unix::io::RawFd) -> anyhow::Result<()> {
    let vm_ptr = {
        let lock = JVM.lock().unwrap();
        lock.as_ref().map(|w| w.0)
    };
    let vm = match vm_ptr {
        Some(v) => v,
        None => {
            // Not running under the Android JVM (e.g. desktop/test suite).
            return Ok(());
        }
    };

    // Hold the VPN state lock for the entire JNI call so the global reference can
    // never be deleted (by wgRegisterVpnService) while we're using it (N04).
    let state_lock = VPN_STATE.lock().unwrap();
    let state = match state_lock.as_ref() {
        Some(s) => s,
        None => {
            // No VpnService registered (e.g. desktop/test suite).
            return Ok(());
        }
    };

    unsafe {
        let mut env_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let res = ((**vm).v1_2.GetEnv)(vm, &mut env_ptr, JNI_VERSION_1_6);
        let (env, must_detach) = if res == JNI_OK {
            (env_ptr as *mut JNIEnv, false)
        } else {
            let mut attached_env: *mut std::ffi::c_void = std::ptr::null_mut();
            let attach_res = ((**vm).v1_2.AttachCurrentThread)(
                vm,
                &mut attached_env as *mut *mut std::ffi::c_void as _,
                std::ptr::null_mut(),
            );
            if attach_res != JNI_OK {
                anyhow::bail!("Failed to attach thread to JVM: {}", attach_res);
            }
            (attached_env as *mut JNIEnv, true)
        };

        let ok = ((**env).v1_6.CallBooleanMethod)(
            env,
            state.service,
            state.protect_method,
            fd as jint,
        );

        if must_detach {
            let _ = ((**vm).v1_2.DetachCurrentThread)(vm);
        }

        if !ok {
            // A routing loop is possible if the socket is not protected. Treat this as a
            // hard error so the connection is aborted instead of continuing unprotected (N05).
            anyhow::bail!("VpnService.protect(fd={}) returned false", fd);
        }
        log::debug!("VpnService.protect(fd={}) succeeded", fd);
    }
    Ok(())
}

unsafe fn jstring_to_string(env: *mut JNIEnv, js: jstring) -> String {
    if js.is_null() {
        return String::new();
    }
    let chars = ((**env).v1_6.GetStringUTFChars)(env, js, std::ptr::null_mut());
    if chars.is_null() {
        return String::new();
    }
    let cstr = std::ffi::CStr::from_ptr(chars);
    let s = cstr.to_string_lossy().into_owned();
    ((**env).v1_6.ReleaseStringUTFChars)(env, js, chars);
    s
}

unsafe fn string_to_jstring(env: *mut JNIEnv, s: &str) -> jstring {
    let cstr = std::ffi::CString::new(s).unwrap_or_default();
    ((**env).v1_6.NewStringUTF)(env, cstr.as_ptr())
}

fn parse_socket_addr(val: &str) -> Option<SocketAddr> {
    if let Ok(addr) = val.parse::<SocketAddr>() {
        return Some(addr);
    }
    // Domain name resolution fallback.
    val.to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
}

/// Settings as parsed from the `wgTurnOn` settings string. The endpoint and the
/// pre-shared key are always taken from the *same* (first) peer section.
struct ParsedSettings {
    endpoint: Option<SocketAddr>,
    secret: Option<String>,
    sni: String,
    dns: IpAddr,
}

fn parse_settings(settings: &str) -> ParsedSettings {
    let mut sni = "addons.mozilla.org".to_string();
    let mut dns: IpAddr = "1.1.1.1".parse().unwrap();

    // The engine only supports a single remote server, so we use the first peer's
    // endpoint and PSK together (rather than independently scanning for whichever
    // "endpoint=" or "preshared_key=" line happens to appear first, which could
    // mix values from different peers — N08).
    let mut first_peer_endpoint: Option<SocketAddr> = None;
    let mut first_peer_secret: Option<String> = None;
    let mut saw_first_peer = false;

    let mut cur_endpoint: Option<SocketAddr> = None;
    let mut cur_secret: Option<String> = None;
    let mut in_peer = false;

    for line in settings.lines() {
        let line = line.trim();
        if line.starts_with("public_key=") {
            if saw_first_peer {
                // Attributes of the first peer have all been read; stop before
                // a second peer (the engine supports only one remote server).
                break;
            }
            in_peer = true;
            continue;
        }
        if let Some(val) = line.strip_prefix("sni=") {
            let val = val.trim();
            if !val.is_empty() {
                sni = val.to_string();
            }
        } else if let Some(val) = line.strip_prefix("dns=") {
            if let Ok(ip) = val.trim().parse::<IpAddr>() {
                dns = ip;
            }
        } else if in_peer {
            if let Some(val) = line.strip_prefix("endpoint=") {
                if cur_endpoint.is_none() {
                    cur_endpoint = parse_socket_addr(val.trim());
                }
            } else if let Some(val) = line.strip_prefix("preshared_key=") {
                let val = val.trim();
                if cur_secret.is_none() && !val.is_empty() {
                    cur_secret = Some(val.to_string());
                }
            } else if let Some(val) = line.strip_prefix("secret=") {
                let val = val.trim();
                if cur_secret.is_none() && !val.is_empty() {
                    cur_secret = Some(val.to_string());
                }
            }
        }
    }

    // The peer attributes were collected inside the loop; the first peer's
    // values are whatever accumulated before the second "public_key=" line.
    if first_peer_endpoint.is_none() {
        first_peer_endpoint = cur_endpoint;
    }
    if first_peer_secret.is_none() {
        first_peer_secret = cur_secret;
    }

    ParsedSettings {
        endpoint: first_peer_endpoint,
        secret: first_peer_secret,
        sni,
        dns,
    }
}

/// # Safety
///
/// `vm` must be a valid, non-null pointer to a `JavaVM`.
/// `_reserved` must be a null pointer.
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jint {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("NovlNative")
                .with_max_level(log::LevelFilter::Debug),
        );
    }
    let mut lock = JVM.lock().unwrap();
    *lock = Some(VmWrapper(vm));
    log::info!("Novl JNI_OnLoad initialized successfully");
    JNI_VERSION_1_6
}

/// # Safety
///
/// `env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
/// `service` must be a valid `jobject` reference to a `VpnService`.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgRegisterVpnService(
    env: *mut JNIEnv,
    _class: jclass,
    service: jobject,
) {
    let mut state_lock = VPN_STATE.lock().unwrap();

    if let Some(old) = state_lock.take() {
        ((**env).v1_6.DeleteGlobalRef)(env, old.service);
    }

    if service.is_null() {
        log::info!("VpnService unregistered from Novl engine");
        return;
    }

    let global_ref = ((**env).v1_6.NewGlobalRef)(env, service);
    let cls = ((**env).v1_6.GetObjectClass)(env, service);
    let method_name = std::ffi::CString::new("protect").unwrap();
    let method_sig = std::ffi::CString::new("(I)Z").unwrap();
    let mid = ((**env).v1_6.GetMethodID)(env, cls, method_name.as_ptr(), method_sig.as_ptr());
    ((**env).v1_6.DeleteLocalRef)(env, cls);

    *state_lock = Some(VpnServiceState {
        service: global_ref,
        protect_method: mid,
    });
    log::info!("VpnService registered with Novl engine for socket protection");
}

/// # Safety
///
/// `env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
/// `ifname` and `settings` must be valid, non-null `jstring` references.
/// `tun_fd` must refer to a valid file descriptor owned by the caller.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgTurnOn(
    env: *mut JNIEnv,
    _class: jclass,
    ifname: jstring,
    tun_fd: jint,
    settings: jstring,
) -> jint {
    let ifname_str = jstring_to_string(env, ifname);
    let settings_str = jstring_to_string(env, settings);
    log::info!("wgTurnOn invoked: ifname={}, tun_fd={}", ifname_str, tun_fd);

    let parsed = parse_settings(&settings_str);

    // Refuse to start when the endpoint is missing (N09). Never substitute a
    // hard-coded public server address.
    let server_addr = match parsed.endpoint {
        Some(addr) => addr,
        None => {
            log::error!("No endpoint configured for tunnel; refusing to start");
            return -1;
        }
    };

    // Refuse to start without a pre-shared key (N01). Never fall back to a
    // published default secret, which would let anyone derive the transport keys.
    let secret = match parsed.secret {
        Some(secret) => secret,
        None => {
            log::error!("No pre-shared key configured for tunnel; refusing to start");
            return -1;
        }
    };

    let server_sni = parsed.sni;
    let dns_addr = parsed.dns;

    log::info!(
        "Configuring Novl engine: server={}, sni={}, dns={}, secret_len={}",
        server_addr,
        server_sni,
        dns_addr,
        secret.len()
    );

    let client_config = ClientConfig {
        socks5_listen: "127.0.0.1:0".parse().unwrap(),
        server_addr,
        server_sni,
        secret,
        mode: TransportMode::TlsChameleon,
        http_path: "/novl".to_string(),
        split_pos: 2,
        split_delay_ms: 1, // Ultra-fast 1ms Anti-DPI segment jitter
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Failed to create Tokio runtime: {}", e);
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    rt.spawn(async move {
        if let Err(e) = crate::client::run_client_with_shutdown_and_ready(
            client_config,
            shutdown_rx,
            Some(ready_tx),
        )
        .await
        {
            log::error!("Novl client terminated with error: {}", e);
        }
    });

    let bound_addr = match rt.block_on(ready_rx) {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("Failed to bind Novl SOCKS5 listener: {}", e);
            return -1;
        }
    };
    log::info!("Novl SOCKS5 proxy bound and listening on {}", bound_addr);

    let mut tun2proxy_args = Args::default();
    let proxy_url = format!("socks5://{}", bound_addr);
    tun2proxy_args.proxy = match ProxyParameters::try_from(proxy_url.as_str()) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to parse proxy parameters: {:?}", e);
            return -1;
        }
    };
    tun2proxy_args.tun_fd = Some(tun_fd);
    tun2proxy_args.close_fd_on_drop = Some(true);
    tun2proxy_args.dns = ArgDns::OverTcp;
    tun2proxy_args.dns_addr = dns_addr;
    tun2proxy_args.setup = false;
    tun2proxy_args.mtu = 1280;
    tun2proxy_args.tcp_mss = Some(1240);

    let tun2proxy_token = CancellationToken::new();
    let token_clone = tun2proxy_token.clone();

    rt.spawn(async move {
        log::info!(
            "tun2proxy general_run_async started on tun_fd={}, dns={}",
            tun_fd,
            dns_addr
        );
        match tun2proxy::general_run_async(tun2proxy_args, 1280, false, token_clone).await {
            Ok(sessions) => {
                log::info!("tun2proxy exited normally (session count: {})", sessions);
            }
            Err(e) => {
                log::error!("tun2proxy exited with error: {:?}", e);
            }
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    let mut lock = ACTIVE_TUNNEL.lock().unwrap();
    *lock = Some(ActiveTunnel {
        handle,
        shutdown_tx,
        tun2proxy_token,
        runtime: rt,
    });

    log::info!("Novl tunnel online and ready. Handle: {}", handle);
    handle
}

/// # Safety
///
/// `_env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
/// `handle` must refer to a previously returned tunnel handle.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgTurnOff(
    _env: *mut JNIEnv,
    _class: jclass,
    handle: jint,
) {
    log::info!("wgTurnOff requested for handle {}", handle);
    let mut lock = ACTIVE_TUNNEL.lock().unwrap();
    if let Some(tunnel) = lock.as_ref() {
        if tunnel.handle == handle {
            if let Some(t) = lock.take() {
                let _ = t.shutdown_tx.send(true);
                t.tun2proxy_token.cancel();
                std::thread::spawn(move || {
                    t.runtime
                        .shutdown_timeout(std::time::Duration::from_millis(600));
                    log::info!("Novl tunnel handle {} completely stopped", handle);
                });
            }
        }
    }
}

/// # Safety
///
/// `_env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
/// `_handle` must refer to a previously returned tunnel handle.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(
    _env: *mut JNIEnv,
    _class: jclass,
    _handle: jint,
) -> jint {
    -1
}

/// # Safety
///
/// `_env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
/// `_handle` must refer to a previously returned tunnel handle.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(
    _env: *mut JNIEnv,
    _class: jclass,
    _handle: jint,
) -> jint {
    -1
}

/// # Safety
///
/// `_env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
/// `_handle` must refer to a previously returned tunnel handle.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgGetConfig(
    _env: *mut JNIEnv,
    _class: jclass,
    _handle: jint,
) -> jstring {
    std::ptr::null_mut()
}

/// # Safety
///
/// `env` must be a valid, non-null pointer to a `JNIEnv` for the current thread.
#[no_mangle]
pub unsafe extern "system" fn Java_com_wireguard_android_backend_GoBackend_wgVersion(
    env: *mut JNIEnv,
    _class: jclass,
) -> jstring {
    string_to_jstring(env, concat!(env!("CARGO_PKG_VERSION"), "-novl"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_first_peer_endpoint_and_psk() {
        let settings = "private_key=aaa\nreplace_peers=true\n\
            public_key=bbb\nallowed_ip=0.0.0.0/0\n\
            endpoint=89.127.214.155:7443\npreshared_key=deadbeef\n\
            dns=1.1.1.1\ndns=8.8.8.8\n";
        let p = parse_settings(settings);
        assert_eq!(p.endpoint.as_ref().unwrap().to_string(), "89.127.214.155:7443");
        assert_eq!(p.secret.as_deref(), Some("deadbeef"));
        assert_eq!(p.dns.to_string(), "8.8.8.8"); // последний dns= wins, как в wg
    }

    #[test]
    fn stops_at_second_peer() {
        let settings = "public_key=bbb\nendpoint=1.2.3.4:1\npreshared_key=k1\n\
            public_key=ccc\nendpoint=5.6.7.8:2\npreshared_key=k2\n";
        let p = parse_settings(settings);
        assert_eq!(p.endpoint.as_ref().unwrap().to_string(), "1.2.3.4:1");
        assert_eq!(p.secret.as_deref(), Some("k1"));
    }

    #[test]
    fn missing_endpoint_is_none() {
        let p = parse_settings("public_key=bbb\npreshared_key=k\n");
        assert!(p.endpoint.is_none());
        assert_eq!(p.secret.as_deref(), Some("k"));
    }
}
