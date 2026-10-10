use anyhow::Result;
use novl::server::{run_server, ServerConfig};
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

    let mut listen_addr: SocketAddr = "0.0.0.0:7443".parse()?;
    let mut fallback_addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let mut secret = "default-novl-secret".to_string();

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                if i + 1 < args.len() {
                    listen_addr = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--fallback" | "-f" => {
                if i + 1 < args.len() {
                    fallback_addr = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--secret" | "-s" => {
                if i + 1 < args.len() {
                    secret = args[i + 1].clone();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("NOVL Server {}", env!("CARGO_PKG_VERSION"));
                println!("Usage: novl-server [OPTIONS]");
                println!("Options:");
                println!("  -l, --listen <ADDR>     Listen address [default: 0.0.0.0:7443]");
                println!("  -f, --fallback <ADDR>   Active probe deflector fallback [default: 127.0.0.1:8080]");
                println!("  -s, --secret <SECRET>   Pre-shared master secret key");
                println!("  -h, --help              Print help");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    info!("Starting novl-server {}", env!("CARGO_PKG_VERSION"));
    info!("Listen address:   {}", listen_addr);
    info!("Fallback address: {}", fallback_addr);

    let config = ServerConfig {
        listen_addr,
        fallback_addr,
        secret,
    };

    run_server(config).await
}
