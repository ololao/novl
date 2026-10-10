use anyhow::Result;
use novl::protocol::{
    build_chameleon_client_hello, build_http_upgrade_request, chrome_124_profile,
    derive_master_key, derive_session_keys, extract_session_id, StreamCipher,
};
use novl::server::{run_server, ServerConfig};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper that spawns a mock fallback HTTP server (simulating Nginx)
async fn spawn_mock_fallback_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 13\r\n\r\nFallback Page";
                        let _ = sock.write_all(response).await;
                    }
                }
            });
        }
    });

    (addr, handle)
}

/// Helper that spawns a NOVL server on an ephemeral port
async fn spawn_novl_server(
    secret: &str,
    fallback_addr: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    drop(listener); // Free port for novl server to bind

    let secret = secret.to_string();
    let handle = tokio::spawn(async move {
        let config = ServerConfig {
            listen_addr,
            fallback_addr,
            secret,
        };
        let _ = run_server(config).await;
    });

    // Allow tokio runtime a brief moment to bind
    tokio::time::sleep(Duration::from_millis(50)).await;
    (listen_addr, handle)
}

#[tokio::test]
async fn test_active_probe_deflection_to_fallback() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-1234-probe-deflector";
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    // Simulate an unauthenticated DPI active probe / port scanner sending HTTP GET
    let mut probe_client = TcpStream::connect(server_addr).await?;
    probe_client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: DPI-Active-Probe\r\n\r\n")
        .await?;

    let mut response_buf = vec![0u8; 512];
    let n = probe_client.read(&mut response_buf).await?;
    let response_text = String::from_utf8_lossy(&response_buf[..n]);

    // Verify probe was transparently spliced to mock Nginx fallback
    assert!(
        response_text.contains("HTTP/1.1 200 OK") && response_text.contains("Fallback Page"),
        "Active probe must be forwarded to fallback server, received: {}",
        response_text
    );

    Ok(())
}

#[tokio::test]
async fn test_replay_attack_deflected_to_fallback() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-replay-scenario";
    let master_key = derive_master_key(secret);
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    // 1. Legitimate client creates a Chameleon ClientHello
    let client_hello =
        build_chameleon_client_hello(&chrome_124_profile(), &master_key, "addons.mozilla.org");

    // Connect first time (legitimate)
    let mut sock1 = TcpStream::connect(server_addr).await?;
    sock1.write_all(&client_hello).await?;
    let mut resp1 = [0u8; 512];
    let n1 = sock1.read(&mut resp1).await?;
    assert!(
        n1 > 0 && resp1.starts_with(&[0x16]),
        "Legitimate handshake must receive TLS response"
    );

    // 2. Replay attack: Adversary sends the identical ClientHello
    let mut sock2 = TcpStream::connect(server_addr).await?;
    sock2.write_all(&client_hello).await?;

    let mut resp2 = [0u8; 512];
    let n2 = sock2.read(&mut resp2).await?;
    let resp2_text = String::from_utf8_lossy(&resp2[..n2]);

    // Replay filter must detect duplicate session token and deflect connection to fallback!
    assert!(
        resp2_text.contains("Fallback Page") || resp2_text.contains("HTTP/1.1"),
        "Replayed handshake must be deflected to fallback server, received: {}",
        resp2_text
    );

    Ok(())
}

#[tokio::test]
async fn test_authenticated_http_upgrade_tunnel() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-http-upgrade-flow";
    let master_key = derive_master_key(secret);
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    // Client generates authenticated HTTP Upgrade request
    let (req, session_id) =
        build_http_upgrade_request("/novl-ws", "cdn.cloudflare.com", &master_key);
    let mut sock = TcpStream::connect(server_addr).await?;
    sock.write_all(&req).await?;

    let mut resp = [0u8; 512];
    let n = sock.read(&mut resp).await?;
    let resp_text = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_text.contains("101 Switching Protocols"),
        "Must receive 101 Switching Protocols, got: {}",
        resp_text
    );

    // Initialize session crypto
    let keys = derive_session_keys(&master_key, &session_id);
    let mut enc = StreamCipher::new(&keys.client_enc_key);

    // Send encrypted frame to verify tunnel payload path
    let ping_data = b"ping tunnel payload test";
    let frame = enc.encrypt_frame(ping_data, 16)?;
    sock.write_all(&frame).await?;

    Ok(())
}

#[tokio::test]
async fn test_end_to_end_chameleon_tls_tunnel() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-chameleon-tls-e2e";
    let master_key = derive_master_key(secret);
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    let client_hello =
        build_chameleon_client_hello(&chrome_124_profile(), &master_key, "cloudflare.com");
    let session_id = extract_session_id(&client_hello).expect("Session ID must be extracted");

    let mut sock = TcpStream::connect(server_addr).await?;
    sock.write_all(&client_hello).await?;

    let mut server_hello = [0u8; 512];
    let n = sock.read(&mut server_hello).await?;
    assert!(
        n > 0 && server_hello.starts_with(&[0x16]),
        "Must receive TLS ServerHello"
    );

    let keys = derive_session_keys(&master_key, &session_id);
    let mut enc = StreamCipher::new(&keys.client_enc_key);

    let test_frame = enc.encrypt_frame(b"ping-chameleon", 32)?;
    sock.write_all(&test_frame).await?;

    Ok(())
}

#[tokio::test]
async fn test_fragmented_anti_dpi_tls_handshake() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-split-tls";
    let master_key = derive_master_key(secret);
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    let client_hello =
        build_chameleon_client_hello(&chrome_124_profile(), &master_key, "split-domain.com");

    let mut sock = TcpStream::connect(server_addr).await?;
    // Send split right after 5-byte TLS header with 5ms delay
    novl::client::send_fragmented_handshake(&mut sock, &client_hello, 5, 5).await?;

    let mut server_hello = [0u8; 512];
    let n = sock.read(&mut server_hello).await?;
    assert!(
        n > 0 && server_hello.starts_with(&[0x16]),
        "Server must successfully reassemble fragmented TLS record and reply"
    );

    Ok(())
}

#[tokio::test]
async fn test_fragmented_anti_dpi_http_handshake() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-split-http";
    let master_key = derive_master_key(secret);
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    let (req, _session_id) = build_http_upgrade_request("/ws-split", "split-http.com", &master_key);

    let mut sock = TcpStream::connect(server_addr).await?;
    // Send split right in the middle of headers (byte 20) with 5ms delay
    novl::client::send_fragmented_handshake(&mut sock, &req, 20, 5).await?;

    let mut resp = [0u8; 512];
    let n = sock.read(&mut resp).await?;
    let resp_text = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_text.contains("101 Switching Protocols"),
        "Server must successfully reassemble fragmented HTTP headers"
    );

    Ok(())
}

#[tokio::test]
async fn test_zapret_multisplit_sni_handshake() -> Result<()> {
    let (fallback_addr, _fb_handle) = spawn_mock_fallback_server().await;
    let secret = "test-secret-uuid-zapret-multisplit";
    let master_key = derive_master_key(secret);
    let (server_addr, _srv_handle) = spawn_novl_server(secret, fallback_addr).await;

    let target_sni = "zapret-evasion-test.cloudflare.com";
    let client_hello = build_chameleon_client_hello(&chrome_124_profile(), &master_key, target_sni);

    let (sni_start, sni_end) = novl::protocol::locate_sni_offset(&client_hello, target_sni)
        .expect("SNI offset must be located in ClientHello");
    let sni_mid = sni_start + (sni_end - sni_start) / 2;

    let mut sock = TcpStream::connect(server_addr).await?;
    // Send 3 segments: Record header (byte 2), inside SNI (sni_mid), and remainder
    let split_points = vec![2, sni_mid];
    novl::client::send_desync_handshake(&mut sock, &client_hello, &split_points, 5).await?;

    let mut server_hello = [0u8; 512];
    let n = sock.read(&mut server_hello).await?;
    assert!(
        n > 0 && server_hello.starts_with(&[0x16]),
        "Server must seamlessly reassemble multi-segment desynchronized TLS record and reply"
    );

    Ok(())
}
