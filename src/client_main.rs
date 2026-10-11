use anyhow::Result;
use novl::client::{run_client, ClientConfig, TransportMode};
use std::env;
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut socks5_listen: SocketAddr = "127.0.0.1:10800".parse()?;
    let mut server_addr: SocketAddr = "127.0.0.1:7443".parse()?;
    let mut server_sni = "addons.mozilla.org".to_string();
    let mut secret = String::new();
    let mut mode = TransportMode::TlsChameleon;
    let mut http_path = "/novl".to_string();
    let mut split_pos: usize = 5;
    let mut split_delay_ms: u64 = 5;

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socks5" | "-b" => {
                if i + 1 < args.len() {
                    socks5_listen = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--server" | "-s" => {
                if i + 1 < args.len() {
                    server_addr = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--sni" => {
                if i + 1 < args.len() {
                    server_sni = args[i + 1].clone();
                    i += 1;
                }
            }
            "--mode" | "-m" => {
                if i + 1 < args.len() {
                    if args[i + 1] == "http" || args[i + 1] == "ws" {
                        mode = TransportMode::HttpUpgrade;
                    } else {
                        mode = TransportMode::TlsChameleon;
                    }
                    i += 1;
                }
            }
            "--path" | "-p" => {
                if i + 1 < args.len() {
                    http_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "--secret" => {
                if i + 1 < args.len() {
                    secret = args[i + 1].clone();
                    i += 1;
                }
            }
            "--split-pos" => {
                if i + 1 < args.len() {
                    split_pos = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--split-delay" => {
                if i + 1 < args.len() {
                    split_delay_ms = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("NOVL Client {}", env!("CARGO_PKG_VERSION"));
                println!("Usage: novl-client [OPTIONS]");
                println!("Options:");
                println!("  -b, --socks5 <ADDR>         Local SOCKS5 listen address [default: 127.0.0.1:10800]");
                println!("  -s, --server <ADDR>         Remote NOVL server address [default: 127.0.0.1:7443]");
                println!("      --sni <NAME>            TLS SNI or HTTP Host header [default: addons.mozilla.org]");
                println!("  -m, --mode <tls|http>       Transport camouflage mode [default: tls]");
                println!("  -p, --path <PATH>           HTTP WebSocket path [default: /novl]");
                println!("      --secret <SECRET>       Pre-shared master secret key");
                println!("      --split-pos <N>         Anti-DPI handshake TCP split byte [default: 5, 0 to disable]");
                println!(
                    "      --split-delay <MS>      Delay between split segments in ms [default: 5]"
                );
                println!("  -h, --help                  Print help");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    if server_addr.port() == 80 && mode == TransportMode::TlsChameleon {
        anyhow::bail!(
            "Invalid configuration: TLS mode cannot be used on port 80. \
             DPI L7 inspection strictly validates HTTP on port 80; use '--mode http' for port 80 \
             or connect to a TLS port (e.g. 443)."
        );
    }

    if secret.is_empty() {
        anyhow::bail!(
            "A pre-shared secret is required. Pass it with '--secret <SECRET>'. \
             There is intentionally no default secret: a public default would let anyone \
             derive the transport keys."
        );
    }

    info!("Starting novl-client {}", env!("CARGO_PKG_VERSION"));
    info!("SOCKS5 listen address: {}", socks5_listen);
    info!("Remote server address: {}", server_addr);
    info!("Transport mode:        {:?}", mode);
    info!("Host/SNI header:       {}", server_sni);
    if mode == TransportMode::HttpUpgrade {
        info!("HTTP upgrade path:     {}", http_path);
    }
    if split_pos > 0 {
        info!(
            "Anti-DPI TCP split:    byte {}, delay {}ms",
            split_pos, split_delay_ms
        );
    }

    let config = ClientConfig {
        socks5_listen,
        server_addr,
        server_sni,
        secret,
        mode,
        http_path,
        split_pos,
        split_delay_ms,
    };

    run_client(config).await
}
