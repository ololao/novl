use anyhow::{bail, Result};
use byteorder::{BigEndian, ByteOrder};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::protocol::{
    build_chameleon_server_hello, build_chameleon_server_hello_v2, derive_master_key,
    derive_session_keys, derive_v2_session_keys, encrypt_tls_frame, extract_client_key_share,
    extract_http_auth, read_decrypted_frame, read_tls_frame,
    verify_auth_session_id_versioned, AuthVersion,
    extract_session_id, verify_auth_session_id, ReplayFilter, StreamCipher,
    CMD_CONNECT, CMD_UDP_ASSOCIATE, HTTP_UPGRADE_RESPONSE,
};
use crate::socks5::{pack_tunnel_udp, unpack_tunnel_udp, TargetAddress};

pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub fallback_addr: SocketAddr,
    pub secret: String,
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    let master_key = Arc::new(derive_master_key(&config.secret));
    let fallback_addr = config.fallback_addr;
    let fail_limiter = Arc::new(FailLimiter::new());
    let replay_filter = Arc::new(ReplayFilter::new(120));

    let listener = TcpListener::bind(config.listen_addr).await?;
    info!("NOVL server listening on {}", config.listen_addr);
    info!(
        "Active probe deflector fallback configured: {}",
        fallback_addr
    );
    info!("Anti-replay sliding window filter initialized");

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let master_key = Arc::clone(&master_key);
                let replay_filter = Arc::clone(&replay_filter);
                let replay_filter = Arc::clone(&replay_filter);
                let fail_limiter = Arc::clone(&fail_limiter);
                tokio::spawn(async move {
                    if let Err(e) = socket.set_nodelay(true) {
                        debug!("Failed to set TCP_NODELAY: {}", e);
                    }
                    crate::protocol::configure_tcp_keepalive(&socket);
                    if let Err(e) = handle_connection(
                        socket,
                        peer_addr,
                        master_key,
                        fallback_addr,
                        replay_filter,
                        fail_limiter,
                    )
                    .await
                    {
                        debug!("Connection from {} closed: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Listener accept error: {}", e);
            }
        }
    }
}

/// Whether an IP address must not be reachable through the tunnel: loopback,
/// link-local, private, multicast, broadcast, or the unspecified address.
fn ip_is_restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ((ip.segments()[0] & 0xfe00) == 0xfc00)
                || ip.is_unspecified()
        }
    }
}

/// Resolves a `TargetAddress` to a list of concrete `SocketAddr`s without ever
/// passing a bracketed IPv6 string to the resolver (N10). Returns an empty list
/// on resolution failure.
async fn resolve_target_addrs(target: &TargetAddress) -> Vec<SocketAddr> {
    match target {
        TargetAddress::IPv4(..) | TargetAddress::IPv6(..) => {
            target.to_socket_addr().into_iter().collect()
        }
        TargetAddress::Domain(domain, port) => {
            match tokio::net::lookup_host((domain.as_str(), *port)).await {
                Ok(addrs) => addrs.collect(),
                Err(_) => Vec::new(),
            }
        }
    }
}

fn target_desc(target: &TargetAddress) -> String {
    let (host, port) = target.to_string_host_port();
    format!("{}:{}", host, port)
}

/// Reads one frame: v2 = TLS-wrapped record, v1 = bare AEAD frame.
async fn read_session_frame<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    decryptor: &mut StreamCipher,
    is_v2: bool,
) -> Result<Vec<u8>> {
    if is_v2 {
        read_tls_frame(reader, decryptor).await
    } else {
        read_decrypted_frame(reader, decryptor).await
    }
}

/// Encrypts one frame: v2 = TLS-wrapped record, v1 = bare AEAD frame.
fn send_frame(encryptor: &mut StreamCipher, payload: &[u8], is_v2: bool) -> Result<Vec<u8>> {
    if is_v2 {
        encrypt_tls_frame(encryptor, payload, None)
    } else {
        encryptor.encrypt_frame(payload, 16)
    }
}

/// Sliding-window per-source limiter for failed MAC verifications: an attacker
/// must not be able to grind MAC candidates (16-byte truncated MAC) for free.
struct FailLimiter {
    map: Mutex<HashMap<std::net::IpAddr, Vec<Instant>>>,
}

impl FailLimiter {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
    /// Returns false when the source exceeded 60 failures in the last 60s.
    fn check(&self, ip: std::net::IpAddr) -> bool {
        let mut m = self.map.lock().unwrap();
        let now = Instant::now();
        let e = m.entry(ip).or_default();
        e.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if e.len() >= 60 {
            return false;
        }
        e.push(now);
        true
    }
}

async fn handle_connection(
    mut client_sock: TcpStream,
    peer_addr: SocketAddr,
    master_key: Arc<[u8; 32]>,
    fallback_addr: SocketAddr,
    replay_filter: Arc<ReplayFilter>,
    fail_limiter: Arc<FailLimiter>,
) -> Result<()> {
    // Robustly read initial handshake with timeout and TCP segmentation assembly
    let initial_buf = match read_handshake_with_timeout(&mut client_sock).await {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };

    // v2 capable handshake? extract both token and ephemeral key share.
    let client_epk: Option<[u8; 32]> = if initial_buf.starts_with(&[0x16]) {
        extract_client_key_share(&initial_buf)
    } else {
        None
    };

    // Check if this is an authentic NOVL handshake (with Anti-Replay verification):
    let (auth, session_id, is_http) = if initial_buf.starts_with(&[0x16]) {
        let sid = extract_session_id(&initial_buf);
        let ver = sid.as_ref().and_then(|s| {
            verify_auth_session_id_versioned(&master_key, s, &replay_filter, client_epk.as_ref())
        });
        (ver, sid, false)
    } else if initial_buf.starts_with(b"GET ") || initial_buf.starts_with(b"POST ") {
        let sid = extract_http_auth(&initial_buf);
        // HTTP mode has no key_share channel for the ECDH binding; accept both
        // protocol versions there (v2 tokens without epk binding).
        let ver =
            sid.as_ref().and_then(|s| verify_auth_session_id_versioned(&master_key, s, &replay_filter, None));
        (ver, sid, true)
    } else {
        (None, None, false)
    };

    if auth.is_none() {
        // Rate-limit MAC grinding per source IP.
        if !fail_limiter.check(peer_addr.ip()) {
            debug!("Dropping unauthenticated flood from {}", peer_addr);
            return Ok(());
        }
        // Unauthenticated traffic, active probe, or replay: forward to fallback server
        warn!(
            "Unauthenticated client or probe from {}; proxying to fallback {}",
            peer_addr, fallback_addr
        );
        match TcpStream::connect(fallback_addr).await {
            Ok(mut fallback_sock) => {
                let _ = fallback_sock.set_nodelay(true);
                fallback_sock.write_all(&initial_buf).await?;
                let _ = crate::splice::zero_copy_splice_bidirectional(
                    &mut client_sock,
                    &mut fallback_sock,
                )
                .await;
            }
            Err(e) => {
                error!(
                    "Failed to connect to fallback server {}: {}",
                    fallback_addr, e
                );
            }
        }
        return Ok(());
    }

    let session_id = session_id.unwrap();
    let auth_version = auth.unwrap();
    info!(
        "Authenticated client {} connected (mode: {}, proto: v{})",
        peer_addr,
        if is_http {
            "HTTP-Upgrade"
        } else {
            "TLS-Chameleon"
        },
        if auth_version == AuthVersion::V2 { 2 } else { 1 }
    );

    let is_v2 = auth_version == AuthVersion::V2 && !is_http;
    let mut server_epk = [0u8; 32];
    let mut v2_hello_bytes: Vec<u8> = Vec::new();

    // Derive session encryption keys
    let keys = if is_v2 {
        let client_epk = client_epk
            .expect("v2 token verified but no key share extracted");
        // One server ephemeral keypair serves both the wire hello and the ECDH,
        // so the client's proof check binds to the exact key used for keys.
        let server_esk_bytes = {
            let mut b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
            b
        };
        let server_esk = x25519_dalek::StaticSecret::from(server_esk_bytes);
        server_epk = x25519_dalek::PublicKey::from(&server_esk).to_bytes();

        let hello = build_chameleon_server_hello_v2(
            Some(&master_key),
            Some(&session_id),
            Some(&client_epk),
            &server_epk,
        );
        v2_hello_bytes = hello;

        let shared = {
            let pk = x25519_dalek::PublicKey::from(client_epk);
            let sh = server_esk.diffie_hellman(&pk);
            if !sh.was_contributory() {
                bail!("client ephemeral key rejected");
            }
            sh.to_bytes()
        };
        derive_v2_session_keys(&master_key, &session_id, &client_epk, &server_epk, &shared)?
    } else {
        derive_session_keys(&master_key, &session_id)
    };
    let mut decryptor = StreamCipher::new(&keys.client_enc_key);
    let mut encryptor = StreamCipher::new(&keys.server_enc_key);

    // Send handshake acknowledgement disguised according to transport mode
    if is_http {
        client_sock.write_all(HTTP_UPGRADE_RESPONSE).await?;
        client_sock.flush().await?;
    } else if is_v2 {
        client_sock.write_all(&v2_hello_bytes).await?;
        client_sock.flush().await?;
    } else {
        let server_hello = build_chameleon_server_hello();
        client_sock.write_all(&server_hello).await?;
        client_sock.flush().await?;
    }

    let (mut client_rx, mut client_tx) = client_sock.into_split();

    // Read initial command frame
    let cmd_frame = read_session_frame(&mut client_rx, &mut decryptor, is_v2).await?;
    if cmd_frame.is_empty() {
        return Ok(());
    }

    if cmd_frame[0] == CMD_UDP_ASSOCIATE {
        // ================= UDP ASSOCIATE (UoT) =================
        info!("UDP-over-TCP session initialized for {}", peer_addr);
        let udp_sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("Failed to bind server UDP socket: {}", e);
                let fail_frame = send_frame(&mut encryptor, &[0x01], is_v2)?;
                let _ = client_tx.write_all(&fail_frame).await;
                return Ok(());
            }
        };

        // Send success frame to client
        let success_frame = send_frame(&mut encryptor, &[0x00], is_v2)?;
        client_tx.write_all(&success_frame).await?;
        client_tx.flush().await?;

        // Channel for thread-safe writes to client_tx
        let (tx_chan, mut rx_chan) = tokio::sync::mpsc::channel::<Vec<u8>>(128);

        // Task 1: Client Frame (TCP) -> Target UDP
        let udp_sock_tx = Arc::clone(&udp_sock);
        let c2u = async move {
            while let Ok(frame) = read_session_frame(&mut client_rx, &mut decryptor, is_v2).await {
                if frame.is_empty() {
                    break;
                }
                match unpack_tunnel_udp(&frame) {
                Ok((target, payload)) => {
                    // Resolve and reject restricted/private targets (N03).
                    let addrs = resolve_target_addrs(&target).await;
                    if addrs.iter().any(|a| ip_is_restricted(a.ip())) {
                        debug!(
                            "Dropping UDP datagram to restricted target {}",
                            target_desc(&target)
                        );
                        continue;
                    }
                    if let Some(addr) = addrs.first() {
                        if let Err(e) = udp_sock_tx.send_to(payload, *addr).await {
                            debug!("UDP send to {} error: {}", addr, e);
                        }
                    } else {
                    }
                }
                Err(e) => {
                }
                }
            }
        };

        // Task 2: Target UDP -> Client Frame (TCP)
        let udp_sock_rx = Arc::clone(&udp_sock);
        let u2c = async move {
            let mut udp_buf = vec![0u8; 65535];
            loop {
                match udp_sock_rx.recv_from(&mut udp_buf).await {
                    Ok((n, src_addr)) => {
                        let target = match src_addr {
                            SocketAddr::V4(v4) => TargetAddress::IPv4(*v4.ip(), v4.port()),
                            SocketAddr::V6(v6) => TargetAddress::IPv6(*v6.ip(), v6.port()),
                        };
                        let tunnel_pkt = pack_tunnel_udp(&target, &udp_buf[..n]);
                        if tx_chan.send(tunnel_pkt).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        };

        // Task 3: Encrypt and send frames to client
        let client_sender = async move {
            let mut packet_count = 0usize;
            while let Some(pkt) = rx_chan.recv().await {
                packet_count += 1;
                // Drop oversized datagrams instead of tearing down the whole
                // association (N11).
                if pkt.len() > crate::protocol::MAX_PAYLOAD_SIZE {
                    debug!("Dropping oversized UDP datagram ({} bytes)", pkt.len());
                    continue;
                }
                let pad = if packet_count < 10 {
                    (rand::random::<u8>() % 32) as u16
                } else {
                    0
                };
                match send_frame(&mut encryptor, &pkt, is_v2) {
                    Ok(frame) => {
                        if let Err(e) = client_tx.write_all(&frame).await {
                            debug!("Write to client UDP stream failed: {}", e);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = client_tx.shutdown().await;
        };

        tokio::select! {
            _ = c2u => {},
            _ = u2c => {},
            _ = client_sender => {},
        }

        return Ok(());
    }

    // ================= TCP CONNECT =================
    let target_bytes = if cmd_frame[0] == CMD_CONNECT {
        &cmd_frame[1..]
    } else {
        &cmd_frame[..]
    };

    let (target, _) = TargetAddress::from_bytes(target_bytes)?;

    // Resolve the target to concrete addresses and reject restricted/private
    // addresses *before* connecting (N03). This also resolves domain names that
    // could point at internal IPs.
    let addrs = resolve_target_addrs(&target).await;
    if addrs.is_empty() {
        warn!(
            "Failed to resolve target {} requested by {}",
            target_desc(&target),
            peer_addr
        );
        let fail_frame = send_frame(&mut encryptor, &[0x01], is_v2)?;
        let _ = client_tx.write_all(&fail_frame).await;
        return Ok(());
    }
    if addrs.iter().any(|a| ip_is_restricted(a.ip())) {
        debug!(
            "Rejecting local/private target {} from {}",
            target_desc(&target),
            peer_addr
        );
        let fail_frame = send_frame(&mut encryptor, &[0x01], is_v2)?;
        let _ = client_tx.write_all(&fail_frame).await;
        return Ok(());
    }

    debug!("Target request from {}: {}", peer_addr, target_desc(&target));

    let connect_fut = TcpStream::connect(&addrs[..]);
    let target_sock = match tokio::time::timeout(Duration::from_secs(6), connect_fut).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            crate::protocol::configure_tcp_keepalive(&s);
            let success_frame = send_frame(&mut encryptor, &[0x00], is_v2)?;
            client_tx.write_all(&success_frame).await?;
            client_tx.flush().await?;
            s
        }
        Ok(Err(e)) => {
            warn!("Failed to connect to {}: {}", target_desc(&target), e);
            let fail_frame = send_frame(&mut encryptor, &[0x01], is_v2)?;
            let _ = client_tx.write_all(&fail_frame).await;
            return Ok(());
        }
        Err(_) => {
            warn!("Connect timeout (6s) to {}", target_desc(&target));
            let fail_frame = send_frame(&mut encryptor, &[0x01], is_v2)?;
            let _ = client_tx.write_all(&fail_frame).await;
            return Ok(());
        }
    };

    let (mut target_rx, mut target_tx) = target_sock.into_split();

    // Pipe 1: Client (Encrypted) -> Target (Plaintext)
    let c2t = async move {
        while let Ok(data) = read_session_frame(&mut client_rx, &mut decryptor, is_v2).await {
            if data.is_empty() {
                break;
            }
            if let Err(e) = target_tx.write_all(&data).await {
                debug!("Write to target failed: {}", e);
                break;
            }
        }
        let _ = target_tx.shutdown().await;
    };

    // Pipe 2: Target (Plaintext) -> Client (Encrypted with anti-DPI jitter padding and MAX_PAYLOAD_SIZE chunking)
    let t2c = async move {
        let mut buf = vec![0u8; 65536];
        let mut packet_count = 0usize;
        loop {
            match target_rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    for chunk in buf[..n].chunks(crate::protocol::MAX_PAYLOAD_SIZE) {
                        packet_count += 1;
                        let pad = if packet_count < 10 {
                            (rand::random::<u8>() % 32) as u16
                        } else {
                            0
                        };
                        match send_frame(&mut encryptor, chunk, is_v2) {
                            Ok(frame) => {
                                if let Err(e) = client_tx.write_all(&frame).await {
                                    debug!("Write to client failed: {}", e);
                                    return;
                                }
                            }
                            Err(e) => {
                                error!("Encryption failed: {}", e);
                                return;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client_tx.shutdown().await;
    };

    // Run both directions to completion so that a half-close (e.g. the client
    // sending a request and shutting down its write side) does not cancel the
    // reverse direction before the response is delivered (N12).
    tokio::join!(c2t, t2c);

    Ok(())
}

async fn read_handshake_with_timeout(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await??;
    if n == 0 {
        bail!("Connection closed before handshake");
    }
    buf.truncate(n);

    // If it is a TLS record, assemble segmented record if needed
    if buf[0] == 0x16 {
        while buf.len() < 5 {
            let mut mini = [0u8; 5];
            let needed = 5 - buf.len();
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(3), sock.read(&mut mini[..needed])).await
            {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&mini[..n]);
            } else {
                break;
            }
        }
        if buf.len() >= 5 {
            let rec_len = BigEndian::read_u16(&buf[3..5]) as usize;
            let expected_total = 5 + rec_len;
            if expected_total > buf.len() && expected_total <= 4096 {
                let remaining = expected_total - buf.len();
                let mut extra = vec![0u8; remaining];
                if let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_secs(3), sock.read_exact(&mut extra)).await
                {
                    buf.extend_from_slice(&extra);
                }
            }
        }
    } else if (buf.starts_with(b"GET ")
        || buf.starts_with(b"POST ")
        || buf.starts_with(b"G")
        || buf.starts_with(b"P"))
        && !buf.windows(4).any(|w| w == b"\r\n\r\n")
    {
        let mut extra = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 4096 {
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(3), sock.read(&mut extra)).await
            {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&extra[..n]);
            } else {
                break;
            }
        }
    }
    Ok(buf)
}
