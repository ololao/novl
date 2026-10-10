use anyhow::Result;
use tokio::net::TcpStream;

pub async fn zero_copy_splice_bidirectional(
    client: &mut TcpStream,
    fallback: &mut TcpStream,
) -> Result<()> {
    tokio::io::copy_bidirectional(client, fallback).await?;
    Ok(())
}
