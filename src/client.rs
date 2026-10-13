use anyhow::{bail, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info};

use crate::protocol::{
    build_chameleon_client_hello_v2, build_http_upgrade_request, chrome_124_profile,
    derive_master_key, derive_v2_session_keys, encrypt_tls_frame, generate_client_ephemeral,
    parse_and_verify_server_hello, read_tls_frame, StreamCipher, CMD_CONNECT,
    CMD_UDP_ASSOCIATE,
};
use crate::socks5::{
    handle_socks5_handshake, pack_socks5_udp, pack_tunnel_udp, send_socks5_success,
    unpack_socks5_udp, unpack_tunnel_udp, SocksCommand,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TransportMode {
    #[serde(rename = "tls")]
    TlsChameleon,
    #[serde(rename = "http")]
    HttpUpgrade,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientConfig {
    pub socks5_listen: SocketAddr,
    pub server_addr: SocketAddr,
    pub server_sni: String,
    pub secret: String,
    pub mode: TransportMode,
    #[serde(default = "default_http_path")]
    pub http_path: String,
    #[serde(default = "default_split_pos")]
    pub split_pos: usize,
    #[serde(default = "default_split_delay")]
    pub split_delay_ms: u64,
}

fn default_http_path() -> String {
    "/novl".to_string()
}
fn default_split_pos() -> usize {
    2
}
fn default_split_delay() -> u64 {
    1
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
    let (_tx, rx) = tokio::sync::watch::channel(false);
    run_client_with_shutdown(config, rx).await
}

pub async fn run_client_with_shutdown(
    config: ClientConfig,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    run_client_with_shutdown_and_ready(config, shutdown_rx, None).await
}

pub async fn run_client_with_shutdown_and_ready(
    config: ClientConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ready_tx: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let master_key = Arc::new(derive_master_key(&config.secret));
    let listener = TcpListener::bind(config.socks5_listen).await?;
    let bound_addr = listener.local_addr()?;
    if let Some(tx) = ready_tx {
        let _ = tx.send(bound_addr);
    }
    info!("NOVL SOCKS5 proxy listening on {}", bound_addr);
    info!(
        "Remote server: {} (mode: {:?}, SNI/Host: {})",
        config.server_addr, config.mode, config.server_sni
    );
    if config.split_pos > 0 {
        info!(
            "Anti-DPI handshake auto-fragmentation active: split at byte {}, delay {}ms",
            config.split_pos, config.split_delay_ms
        );
    }

    let config = Arc::new(config);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Client shutdown signal received, terminating SOCKS5 listener");
                    break;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((client_sock, peer_addr)) => {
                        let master_key = Arc::clone(&master_key);
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            if let Err(e) = client_sock.set_nodelay(true) {
                                debug!("Failed to set TCP_NODELAY: {}", e);
                            }
                            if let Err(e) = handle_client(client_sock, master_key, config).await {
                                debug!("SOCKS connection from {} closed/failed: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("SOCKS listener accept error: {}", e);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Sends data split across multiple TCP segments with inter-segment delay (Anti-DPI / Zapret multisplit)
pub async fn send_desync_handshake(
    sock: &mut TcpStream,
    data: &[u8],
    split_offsets: &[usize],
    delay_ms: u64,
) -> Result<()> {
    if split_offsets.is_empty() || data.is_empty() {
        sock.write_all(data).await?;
        sock.flush().await?;
        return Ok(());
    }

    let mut valid_offsets = split_offsets
        .iter()
        .copied()
        .filter(|&o| o > 0 && o < data.len())
        .collect::<Vec<_>>();
    valid_offsets.sort_unstable();
    valid_offsets.dedup();

    if valid_offsets.is_empty() {
        sock.write_all(data).await?;
        sock.flush().await?;
        return Ok(());
    }

    let mut start = 0;
    for &offset in &valid_offsets {
        if offset > start {
            sock.write_all(&data[start..offset]).await?;
            sock.flush().await?;
            if delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
            start = offset;
        }
    }

    if start < data.len() {
        sock.write_all(&data[start..]).await?;
        sock.flush().await?;
    }

    Ok(())
}

/// Sends data split across two TCP segments with an optional inter-segment delay (Anti-DPI fragmentation)
pub async fn send_fragmented_handshake(
    sock: &mut TcpStream,
    data: &[u8],
    split_pos: usize,
    delay_ms: u64,
) -> Result<()> {
    send_desync_handshake(sock, data, &[split_pos], delay_ms).await
}

/// Reads the complete TLS ServerHello + ChangeCipherSpec response so that no
/// leftover bytes remain in the stream to be misinterpreted as an encrypted
/// frame (N06).
async fn read_tls_server_hello(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut header)).await??;
    if header[0] != 0x16 {
        bail!("Server returned non-TLS response (connection deflected). Verify master secret key!");
    }
    let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if rec_len > crate::protocol::MAX_PAYLOAD_SIZE + 1024 {
        bail!("Server hello record too large ({} bytes)", rec_len);
    }
    let mut body = vec![0u8; rec_len];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut body)).await??;

    // Consume the ChangeCipherSpec record (RFC 8446 middlebox compatibility).
    let mut ccs = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut ccs)).await??;

    let mut hello = Vec::with_capacity(5 + rec_len);
    hello.extend_from_slice(&header);
    hello.extend_from_slice(&body);
    Ok(hello)
}

/// Reads the complete HTTP upgrade response up to the end of the header block,
/// with size and time limits (N06).
async fn read_http_upgrade_response(sock: &mut TcpStream) -> Result<()> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp)).await??;
        if n == 0 {
            bail!("Server closed connection during HTTP handshake");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("HTTP response headers too large");
        }
    }
    let resp_str = String::from_utf8_lossy(&buf);
    if !resp_str.contains("101 Switching Protocols") {
        bail!(
            "Unexpected HTTP response from server (deflected): {}",
            resp_str
        );
    }
    Ok(())
}

async fn handle_client(
    mut client_sock: TcpStream,
    master_key: Arc<[u8; 32]>,
    config: Arc<ClientConfig>,
) -> Result<()> {
    // 1. SOCKS5 handshake with local application
    let cmd = handle_socks5_handshake(&mut client_sock).await?;

    // 2. Connect to remote NOVL server with socket loop protection
    let socket = match config.server_addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    let _ = socket.set_nodelay(true);
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        crate::android_bridge::protect_socket(socket.as_raw_fd())?;
    }
    let mut remote_sock = socket.connect(config.server_addr).await?;
    let _ = remote_sock.set_nodelay(true);
    crate::protocol::configure_tcp_keepalive(&remote_sock);
    let _ = client_sock.set_nodelay(true);
    crate::protocol::configure_tcp_keepalive(&client_sock);

    // 3. Perform handshake based on selected transport mode with Zapret-grade Multi-Segment Desync
    //
    // v2: per-connection randomized desync profile. A fixed split position with
    // a fixed delay across a whole client fleet is itself an active-probing
    // signature, so each connection draws its own (possibly no) split.
    let mut rng = rand::rngs::OsRng;
    let split_mode: u8 = rand::Rng::gen_range(&mut rng, 0..4);
    let split_pos = match split_mode {
        0 => 0usize, // no split at all
        1 => rand::Rng::gen_range(&mut rng, 1..8),
        2 => rand::Rng::gen_range(&mut rng, 8..64),
        _ => rand::Rng::gen_range(&mut rng, 64..256),
    };
    let split_delay = rand::Rng::gen_range(&mut rng, 0..=25u64);
    let use_sni_split = rand::random::<u8>() % 2 == 0;

    match config.mode {
        TransportMode::TlsChameleon => {
            let eph = generate_client_ephemeral();
            let client_hello = build_chameleon_client_hello_v2(
                &chrome_124_profile(),
                &master_key,
                &config.server_sni,
                Some(&eph.epk),
            );
            let session_id = crate::protocol::extract_session_id(&client_hello)
                .ok_or_else(|| anyhow::anyhow!("Failed to extract session id"))?;

            let mut split_points = Vec::new();
            if split_pos > 0 {
                split_points.push(split_pos);
            }
            if use_sni_split {
                if let Some((sni_start, sni_end)) =
                    crate::protocol::locate_sni_offset(&client_hello, &config.server_sni)
                {
                    let sni_mid = sni_start + (sni_end - sni_start) / 2;
                    if sni_mid > split_pos {
                        split_points.push(sni_mid);
                    }
                }
            }

            send_desync_handshake(&mut remote_sock, &client_hello, &split_points, split_delay)
                .await?;

            // v2: verify server proof BEFORE any user data leaves the device.
            let server_hello = read_tls_server_hello(&mut remote_sock).await?;
            let client_epk = eph.epk;
            let server_epk =
                parse_and_verify_server_hello(&server_hello, &master_key, &session_id, &client_epk)
                    .ok_or_else(|| anyhow::anyhow!("Server authentication failed"))?;

            let shared = eph.diffie_hellman(&server_epk)?;
            let keys = derive_v2_session_keys(
                &master_key,
                &session_id,
                &client_epk,
                &server_epk,
                &shared,
            )?;
            let encryptor = StreamCipher::new(&keys.client_enc_key);
            let decryptor = StreamCipher::new(&keys.server_enc_key);
            return run_authenticated_session(
                client_sock,
                remote_sock,
                cmd,
                config,
                encryptor,
                decryptor,
            )
            .await;
        }
        TransportMode::HttpUpgrade => {
            let (req, session_id) =
                build_http_upgrade_request(&config.http_path, &config.server_sni, &master_key);
            let mut split_points = Vec::new();
            if split_pos > 0 {
                split_points.push(split_pos);
            }
            if use_sni_split {
                split_points.push(25);
            }
            send_desync_handshake(&mut remote_sock, &req, &split_points, split_delay).await?;

            read_http_upgrade_response(&mut remote_sock).await?;

            // v1 path for HTTP mode: legacy session (no ECDH yet).
            let keys = crate::protocol::derive_session_keys(&master_key, &session_id);
            let encryptor = StreamCipher::new(&keys.client_enc_key);
            let decryptor = StreamCipher::new(&keys.server_enc_key);
            return run_authenticated_session(
                client_sock,
                remote_sock,
                cmd,
                config,
                encryptor,
                decryptor,
            )
            .await;
        }
    }
}

async fn run_authenticated_session(
    mut client_sock: TcpStream,
    mut remote_sock: TcpStream,
    cmd: SocksCommand,
    _config: Arc<ClientConfig>,
    mut encryptor: StreamCipher,
    mut decryptor: StreamCipher,
) -> Result<()> {

    match cmd {
        SocksCommand::UdpAssociate(_) => {
            // ================= UDP ASSOCIATE (UoT) =================
            let local_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let local_udp_addr = local_udp.local_addr()?;

            // Send UDP Associate command frame to remote server
            let initial_frame = encrypt_tls_frame(&mut encryptor, &[CMD_UDP_ASSOCIATE], Some(16))?;
            remote_sock.write_all(&initial_frame).await?;
            remote_sock.flush().await?;

            // Read confirmation from server
            let status_frame = read_tls_frame(&mut remote_sock, &mut decryptor).await?;
            if status_frame.is_empty() || status_frame[0] != 0x00 {
                bail!("Remote server rejected UDP associate request");
            }

            // Confirm success to local application with local bound UDP address
            send_socks5_success(&mut client_sock, local_udp_addr).await?;

            let (mut remote_rx, mut remote_tx) = remote_sock.into_split();
            let (tx_chan, mut rx_chan) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            let session_map = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<
                crate::socks5::TargetAddress,
                SocketAddr,
            >::new()));
            let last_peer_holder = Arc::new(tokio::sync::Mutex::new(None::<SocketAddr>));

            // Task 1: Local App UDP -> Tunnel Frame (TCP)
            let local_udp_rx = Arc::clone(&local_udp);
            let session_map_tx = Arc::clone(&session_map);
            let last_peer_tx = Arc::clone(&last_peer_holder);
            let u2t = async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match local_udp_rx.recv_from(&mut buf).await {
                        Ok((n, peer_addr)) => {
                            if let Ok((target, payload)) = unpack_socks5_udp(&buf[..n]) {
                                {
                                    let mut map = session_map_tx.lock().await;
                                    if map.len() > 1024 {
                                        map.clear();
                                    }
                                    map.insert(target.clone(), peer_addr);
                                    let mut last = last_peer_tx.lock().await;
                                    *last = Some(peer_addr);
                                }
                                let tunnel_pkt = pack_tunnel_udp(&target, payload);
                                if tx_chan.send(tunnel_pkt).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Local UDP recv error: {}", e);
                            break;
                        }
                    }
                }
            };

            // Task 2: Encrypt and send frames to remote server
            let t_sender = async move {
                let mut packet_count = 0usize;
                while let Some(pkt) = rx_chan.recv().await {
                    packet_count += 1;
                    // Drop oversized datagrams instead of tearing down the whole
                    // UDP association (N11).
                    if pkt.len() > crate::protocol::MAX_PAYLOAD_SIZE {
                        debug!("Dropping oversized UDP datagram ({} bytes)", pkt.len());
                        continue;
                    }
                    let pad = if packet_count < 10 {
                        (rand::random::<u8>() % 32) as u16
                    } else {
                        0
                    };
                    match encrypt_tls_frame(&mut encryptor, &pkt, Some(pad)) {
                        Ok(frame) => {
                            if let Err(e) = remote_tx.write_all(&frame).await {
                                debug!("Write to remote UDP stream failed: {}", e);
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = remote_tx.shutdown().await;
            };

            // Task 3: Remote Server Frame (TCP) -> Local App UDP
            let local_udp_tx = Arc::clone(&local_udp);
            let session_map_rx = Arc::clone(&session_map);
            let last_peer_rx = Arc::clone(&last_peer_holder);
            let t2u = async move {
                while let Ok(frame) = read_tls_frame(&mut remote_rx, &mut decryptor).await {
                    if frame.is_empty() {
                        break;
                    }
                    if let Ok((source, payload)) = unpack_tunnel_udp(&frame) {
                        let socks5_pkt = pack_socks5_udp(&source, payload);
                        let target_peer = {
                            let map = session_map_rx.lock().await;
                            map.get(&source).copied()
                        };
                        let peer_to_send = target_peer.or(*last_peer_rx.lock().await);
                        if let Some(peer) = peer_to_send {
                            if let Err(e) = local_udp_tx.send_to(&socks5_pkt, peer).await {
                                debug!("Send to local app UDP error: {}", e);
                            }
                        }
                    }
                }
            };

            // Task 4: Monitor TCP control connection (RFC 1928)
            let mut check_buf = [0u8; 1];
            tokio::select! {
                _ = u2t => {},
                _ = t_sender => {},
                _ = t2u => {},
                _ = client_sock.read(&mut check_buf) => {},
            }

            Ok(())
        }
        SocksCommand::Connect(target) => {
            // ================= TCP CONNECT =================
            let mut payload = Vec::new();
            payload.push(CMD_CONNECT);
            payload.extend_from_slice(&target.to_bytes());

            let initial_frame = encrypt_tls_frame(&mut encryptor, &payload, Some(16))?;
            remote_sock.write_all(&initial_frame).await?;
            remote_sock.flush().await?;

            // Read confirmation frame from server
            let status_frame = read_tls_frame(&mut remote_sock, &mut decryptor).await?;
            if status_frame.is_empty() || status_frame[0] != 0x00 {
                bail!("Remote server rejected target connection");
            }

            // Confirm success to local application
            send_socks5_success(&mut client_sock, "0.0.0.0:0".parse().unwrap()).await?;

            let (mut client_rx, mut client_tx) = client_sock.into_split();
            let (mut remote_rx, mut remote_tx) = remote_sock.into_split();

            // Pipe 1: Local App (Plaintext) -> Remote Server (Encrypted with MAX_PAYLOAD_SIZE chunking)
            let c2r = async move {
                let mut buf = vec![0u8; 65536];
                let mut packet_count = 0usize;
                loop {
                    match client_rx.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            for chunk in buf[..n].chunks(crate::protocol::MAX_PAYLOAD_SIZE) {
                                packet_count += 1;
                                let pad = if packet_count < 10 {
                                    (rand::random::<u8>() % 32) as u16
                                } else {
                                    0
                                };
                                match encrypt_tls_frame(&mut encryptor, chunk, Some(pad)) {
                                    Ok(frame) => {
                                        if let Err(e) = remote_tx.write_all(&frame).await {
                                            debug!("Write to remote failed: {}", e);
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
                let _ = remote_tx.shutdown().await;
            };

            // Pipe 2: Remote Server (Encrypted) -> Local App (Plaintext)
            let r2c = async move {
                while let Ok(data) = read_tls_frame(&mut remote_rx, &mut decryptor).await {
                    if data.is_empty() {
                        break;
                    }
                    if let Err(e) = client_tx.write_all(&data).await {
                        debug!("Write to client failed: {}", e);
                        break;
                    }
                }
                let _ = client_tx.shutdown().await;
            };

            // Run both directions to completion so that a half-close (the local app
            // sending a request and closing its write side) does not cancel the
            // reverse direction before the response arrives (N12).
            tokio::join!(c2r, r2c);

            Ok(())
        }
    }
}
