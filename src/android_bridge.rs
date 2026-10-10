use crate::client::{ClientConfig, TransportMode};
use jni_sys::{jclass, jint, jobject, jstring, JNIEnv, JavaVM, JNI_OK, JNI_VERSION_1_6};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::RwLock;
use tun2proxy::{ArgDns, Args, CancellationToken, ProxyParameters};

struct VmWrapper(*mut JavaVM);
unsafe impl Send for VmWrapper {}
unsafe impl Sync for VmWrapper {}

struct ObjWrapper(jobject);
unsafe impl Send for ObjWrapper {}
unsafe impl Sync for ObjWrapper {}

struct MethodWrapper(jni_sys::jmethodID);
unsafe impl Send for MethodWrapper {}
unsafe impl Sync for MethodWrapper {}

static JVM: RwLock<Option<VmWrapper>> = RwLock::new(None);
static VPN_SERVICE: RwLock<Option<ObjWrapper>> = RwLock::new(None);
static PROTECT_METHOD: RwLock<Option<MethodWrapper>> = RwLock::new(None);

struct ActiveTunnel {
    handle: i32,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    tun2proxy_token: CancellationToken,
    runtime: tokio::runtime::Runtime,
}

static ACTIVE_TUNNEL: RwLock<Option<ActiveTunnel>> = RwLock::new(None);
static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);

/// Exempts an outbound socket from the Android VPN routing table so its packets
/// reach the physical network (Wi-Fi/Cellular) directly without creating a routing loop.
pub fn protect_socket(fd: std::os::unix::io::RawFd) -> anyhow::Result<()> {
    let vm_ptr = {
        let lock = JVM.read().unwrap();
        lock.as_ref().map(|w| w.0)
    };
    let service_ref = {
        let lock = VPN_SERVICE.read().unwrap();
        lock.as_ref().map(|w| w.0)
    };
    let mid = {
        let lock = PROTECT_METHOD.read().unwrap();
        lock.as_ref().map(|w| w.0)
    };

    let (vm, service, mid) = match (vm_ptr, service_ref, mid) {
        (Some(vm), Some(srv), Some(m)) => (vm, srv, m),
        _ => {
            // Not running under Android VpnService (e.g. desktop/test suite)
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

        let ok = ((**env).v1_6.CallBooleanMethod)(env, service, mid, fd as jint);
        if !ok {
            log::warn!("VpnService.protect(fd={}) returned false", fd);
        } else {
            log::debug!("VpnService.protect(fd={}) succeeded", fd);
        }

        if must_detach {
            let _ = ((**vm).v1_2.DetachCurrentThread)(vm);
        }
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

fn parse_endpoint_from_settings(settings: &str) -> Option<SocketAddr> {
    for line in settings.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("endpoint=") {
            let val = val.trim();
            if let Ok(addr) = val.parse::<SocketAddr>() {
                return Some(addr);
            }
            // Domain name resolution fallback
            if let Ok(mut addrs) = val.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    return Some(addr);
                }
            }
        }
    }
    None
}

fn parse_secret_from_settings(settings: &str) -> String {
    for line in settings.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("preshared_key=") {
            let val = val.trim();
            if !val.is_empty() {
                return val.to_string();
            }
        }
        if let Some(val) = line.strip_prefix("secret=") {
            let val = val.trim();
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    "default-novl-secret".to_string()
}

fn parse_sni_from_settings(settings: &str) -> String {
    for line in settings.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("sni=") {
            let val = val.trim();
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    "addons.mozilla.org".to_string()
}

fn parse_dns_from_settings(settings: &str) -> IpAddr {
    for line in settings.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("dns=") {
            let val = val.trim();
            if let Ok(ip) = val.parse::<IpAddr>() {
                return ip;
            }
        }
    }
    "1.1.1.1".parse().unwrap()
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
    let mut lock = JVM.write().unwrap();
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
    let mut srv_lock = VPN_SERVICE.write().unwrap();
    let mut mid_lock = PROTECT_METHOD.write().unwrap();

    if let Some(old) = srv_lock.take() {
        ((**env).v1_6.DeleteGlobalRef)(env, old.0);
    }
    *mid_lock = None;

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

    *srv_lock = Some(ObjWrapper(global_ref));
    *mid_lock = Some(MethodWrapper(mid));
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

    // Terminate any previous tunnel session cleanly
    {
        let mut lock = ACTIVE_TUNNEL.write().unwrap();
        if let Some(existing) = lock.take() {
            log::warn!("Stopping previous tunnel handle {}", existing.handle);
            let _ = existing.shutdown_tx.send(true);
            existing.tun2proxy_token.cancel();
            existing
                .runtime
                .shutdown_timeout(std::time::Duration::from_millis(500));
        }
    }

    let server_addr = parse_endpoint_from_settings(&settings_str)
        .unwrap_or_else(|| "127.0.0.1:7443".parse().unwrap());
    let secret = parse_secret_from_settings(&settings_str);
    let server_sni = parse_sni_from_settings(&settings_str);
    let dns_addr = parse_dns_from_settings(&settings_str);

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
    let mut lock = ACTIVE_TUNNEL.write().unwrap();
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
    let mut lock = ACTIVE_TUNNEL.write().unwrap();
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
