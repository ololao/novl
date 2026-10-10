use anyhow::{bail, Result};
use byteorder::{BigEndian, ByteOrder};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::protocol::{
    build_chameleon_server_hello, derive_master_key, derive_session_keys, extract_http_auth,
    extract_session_id, read_decrypted_frame, verify_auth_session_id, ReplayFilter, StreamCipher,
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

async fn handle_connection(
    mut client_sock: TcpStream,
    peer_addr: SocketAddr,
    master_key: Arc<[u8; 32]>,
    fallback_addr: SocketAddr,
    replay_filter: Arc<ReplayFilter>,
) -> Result<()> {
    // Robustly read initial handshake with timeout and TCP segmentation assembly
    let initial_buf = match read_handshake_with_timeout(&mut client_sock).await {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };

    // Check if this is an authentic NOVL handshake (with Anti-Replay verification):
    let (is_authenticated, session_id, is_http) = if initial_buf.starts_with(&[0x16]) {
        let sid = extract_session_id(&initial_buf);
        let ok = sid
            .as_ref()
            .is_some_and(|s| verify_auth_session_id(&master_key, s, &replay_filter));
        (ok, sid, false)
    } else if initial_buf.starts_with(b"GET ") || initial_buf.starts_with(b"POST ") {
        let sid = extract_http_auth(&initial_buf);
        let ok = sid
            .as_ref()
            .is_some_and(|s| verify_auth_session_id(&master_key, s, &replay_filter));
        (ok, sid, true)
    } else {
        (false, None, false)
    };

    if !is_authenticated {
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
    info!(
        "Authenticated client {} connected (mode: {})",
        peer_addr,
        if is_http {
            "HTTP-Upgrade"
        } else {
            "TLS-Chameleon"
        }
    );

    // Derive session encryption keys
    let keys = derive_session_keys(&master_key, &session_id);
    let mut decryptor = StreamCipher::new(&keys.client_enc_key);
    let mut encryptor = StreamCipher::new(&keys.server_enc_key);

    // Send handshake acknowledgement disguised according to transport mode
    if is_http {
        client_sock.write_all(HTTP_UPGRADE_RESPONSE).await?;
        client_sock.flush().await?;
    } else {
        let server_hello = build_chameleon_server_hello();
        client_sock.write_all(&server_hello).await?;
        client_sock.flush().await?;
    }

    let (mut client_rx, mut client_tx) = client_sock.into_split();

    // Read initial command frame
    let cmd_frame = read_decrypted_frame(&mut client_rx, &mut decryptor).await?;
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
                let fail_frame = encryptor.encrypt_frame(&[0x01], 16)?;
                let _ = client_tx.write_all(&fail_frame).await;
                return Ok(());
            }
        };

        // Send success frame to client
        let success_frame = encryptor.encrypt_frame(&[0x00], 16)?;
        client_tx.write_all(&success_frame).await?;
        client_tx.flush().await?;

        // Channel for thread-safe writes to client_tx
        let (tx_chan, mut rx_chan) = tokio::sync::mpsc::channel::<Vec<u8>>(128);

        // Task 1: Client Frame (TCP) -> Target UDP
        let udp_sock_tx = Arc::clone(&udp_sock);
        let c2u = async move {
            while let Ok(frame) = read_decrypted_frame(&mut client_rx, &mut decryptor).await {
                if frame.is_empty() {
                    break;
                }
                if let Ok((target, payload)) = unpack_tunnel_udp(&frame) {
                    let (host, port) = target.to_string_host_port();
                    if let Err(e) = udp_sock_tx.send_to(payload, (host.as_str(), port)).await {
                        debug!("UDP send to {}:{} error: {}", host, port, e);
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
                let pad = if packet_count < 10 {
                    (rand::random::<u8>() % 32) as u16
                } else {
                    0
                };
                match encryptor.encrypt_frame(&pkt, pad) {
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

    fn is_private_or_restricted(target: &TargetAddress) -> bool {
        match target {
            TargetAddress::IPv4(ip, _) => {
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_broadcast()
                    || ip.is_multicast()
                    || ip.octets()[0] == 0
            }
            TargetAddress::IPv6(ip, _) => {
                ip.is_loopback()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
                    || ((ip.segments()[0] & 0xfe00) == 0xfc00)
            }
            TargetAddress::Domain(domain, _) => {
                domain.eq_ignore_ascii_case("localhost") || domain.ends_with(".local")
            }
        }
    }

    let (target, _) = TargetAddress::from_bytes(target_bytes)?;
    let (host, port) = target.to_string_host_port();

    if is_private_or_restricted(&target) {
        debug!(
            "Rejecting local/private target {}:{} from {}",
            host, port, peer_addr
        );
        let fail_frame = encryptor.encrypt_frame(&[0x01], 16)?;
        let _ = client_tx.write_all(&fail_frame).await;
        return Ok(());
    }

    debug!("Target request from {}: {}:{}", peer_addr, host, port);

    let connect_fut = TcpStream::connect((host.as_str(), port));
    let target_sock = match tokio::time::timeout(Duration::from_secs(6), connect_fut).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            crate::protocol::configure_tcp_keepalive(&s);
            let success_frame = encryptor.encrypt_frame(&[0x00], 16)?;
            client_tx.write_all(&success_frame).await?;
            client_tx.flush().await?;
            s
        }
        Ok(Err(e)) => {
            warn!("Failed to connect to {}:{}: {}", host, port, e);
            let fail_frame = encryptor.encrypt_frame(&[0x01], 16)?;
            let _ = client_tx.write_all(&fail_frame).await;
            return Ok(());
        }
        Err(_) => {
            warn!("Connect timeout (6s) to {}:{}", host, port);
            let fail_frame = encryptor.encrypt_frame(&[0x01], 16)?;
            let _ = client_tx.write_all(&fail_frame).await;
            return Ok(());
        }
    };

    let (mut target_rx, mut target_tx) = target_sock.into_split();

    // Pipe 1: Client (Encrypted) -> Target (Plaintext)
    let c2t = async move {
        while let Ok(data) = read_decrypted_frame(&mut client_rx, &mut decryptor).await {
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
                        match encryptor.encrypt_frame(chunk, pad) {
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

    tokio::select! {
        _ = c2t => {},
        _ = t2c => {},
    }

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
