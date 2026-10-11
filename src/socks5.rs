use anyhow::{bail, Result};
use byteorder::{BigEndian, ByteOrder};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddress {
    IPv4(Ipv4Addr, u16),
    Domain(String, u16),
    IPv6(Ipv6Addr, u16),
}

impl TargetAddress {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            TargetAddress::IPv4(ip, port) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddress::Domain(domain, port) => {
                buf.push(0x03);
                let bytes = domain.as_bytes();
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddress::IPv6(ip, port) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }

    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize)> {
        if slice.is_empty() {
            bail!("Empty address buffer");
        }
        match slice[0] {
            0x01 => {
                if slice.len() < 1 + 4 + 2 {
                    bail!("Truncated IPv4 address");
                }
                let ip = Ipv4Addr::new(slice[1], slice[2], slice[3], slice[4]);
                let port = BigEndian::read_u16(&slice[5..7]);
                Ok((TargetAddress::IPv4(ip, port), 7))
            }
            0x03 => {
                if slice.len() < 2 {
                    bail!("Truncated domain length");
                }
                let dlen = slice[1] as usize;
                if slice.len() < 2 + dlen + 2 {
                    bail!("Truncated domain data");
                }
                let domain = String::from_utf8(slice[2..2 + dlen].to_vec())?;
                let port = BigEndian::read_u16(&slice[2 + dlen..4 + dlen]);
                Ok((TargetAddress::Domain(domain, port), 2 + dlen + 2))
            }
            0x04 => {
                if slice.len() < 1 + 16 + 2 {
                    bail!("Truncated IPv6 address");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&slice[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = BigEndian::read_u16(&slice[17..19]);
                Ok((TargetAddress::IPv6(ip, port), 19))
            }
            other => bail!("Unsupported address type: {}", other),
        }
    }

    pub fn to_string_host_port(&self) -> (String, u16) {
        match self {
            TargetAddress::IPv4(ip, port) => (ip.to_string(), *port),
            TargetAddress::Domain(domain, port) => (domain.clone(), *port),
            TargetAddress::IPv6(ip, port) => (format!("[{}]", ip), *port),
        }
    }

    /// Returns a concrete `SocketAddr` for numeric IP targets, or `None` for
    /// domains that must be resolved via DNS. This avoids the lossy `"[addr]"`
    /// bracketed string form when handing addresses to the resolver (N10).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            TargetAddress::IPv4(ip, port) => Some(SocketAddr::from((*ip, *port))),
            TargetAddress::IPv6(ip, port) => Some(SocketAddr::from((*ip, *port))),
            TargetAddress::Domain(..) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksCommand {
    Connect(TargetAddress),
    UdpAssociate(TargetAddress),
}

pub async fn handle_socks5_handshake(stream: &mut TcpStream) -> Result<SocksCommand> {
    // 1. Version & Auth Method negotiation
    let mut ver_methods = [0u8; 2];
    stream.read_exact(&mut ver_methods).await?;
    if ver_methods[0] != 0x05 {
        bail!(
            "Only SOCKS5 protocol is supported (got version {})",
            ver_methods[0]
        );
    }

    let nmethods = ver_methods[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        bail!("No acceptable authentication methods");
    }
    // Reply 0x05, 0x00 (NO AUTH)
    stream.write_all(&[0x05, 0x00]).await?;

    // 2. Request details
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != 0x05 {
        bail!("Invalid SOCKS5 version in request");
    }

    let cmd = req_header[1];
    let atyp = req_header[3];
    let target = match atyp {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            TargetAddress::IPv4(Ipv4Addr::from(ip_bytes), port)
        }
        0x03 => {
            let dlen = stream.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; dlen];
            stream.read_exact(&mut domain_bytes).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8(domain_bytes)?;
            TargetAddress::Domain(domain, port)
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            TargetAddress::IPv6(Ipv6Addr::from(ip_bytes), port)
        }
        _ => {
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("Address type not supported: {}", atyp);
        }
    };

    match cmd {
        0x01 => Ok(SocksCommand::Connect(target)),
        0x03 => Ok(SocksCommand::UdpAssociate(target)),
        _ => {
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("Unsupported SOCKS5 command: {}", cmd);
        }
    }
}

pub async fn send_socks5_success(stream: &mut TcpStream, bind_addr: SocketAddr) -> Result<()> {
    let mut reply = vec![0x05, 0x00, 0x00];
    match bind_addr {
        SocketAddr::V4(v4) => {
            reply.push(0x01);
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            reply.push(0x04);
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

/// Packs UDP payload into SOCKS5 UDP datagram format:
/// [RSV 2B: 0x00, 0x00][FRAG 1B: 0x00][TargetAddress][Payload]
pub fn pack_socks5_udp(target: &TargetAddress, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + 20 + payload.len());
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
    buf.extend_from_slice(&target.to_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Unpacks SOCKS5 UDP datagram format into (TargetAddress, payload)
pub fn unpack_socks5_udp(packet: &[u8]) -> Result<(TargetAddress, &[u8])> {
    if packet.len() < 4 {
        bail!("UDP packet too short for SOCKS5 header");
    }
    let (target, addr_len) = TargetAddress::from_bytes(&packet[3..])?;
    let payload = &packet[3 + addr_len..];
    Ok((target, payload))
}

/// Packs a datagram for NOVL tunnel transmission:
/// [TargetAddress][Payload]
pub fn pack_tunnel_udp(target: &TargetAddress, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + payload.len());
    buf.extend_from_slice(&target.to_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Unpacks a datagram received from NOVL tunnel:
pub fn unpack_tunnel_udp(packet: &[u8]) -> Result<(TargetAddress, &[u8])> {
    let (target, addr_len) = TargetAddress::from_bytes(packet)?;
    let payload = &packet[addr_len..];
    Ok((target, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_address_roundtrip() {
        let addr = TargetAddress::Domain("dns.google".to_string(), 853);
        let bytes = addr.to_bytes();
        let (parsed, len) = TargetAddress::from_bytes(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(bytes.len(), len);
        let (host, port) = addr.to_string_host_port();
        assert_eq!(host, "dns.google");
        assert_eq!(port, 853);
    }

    #[test]
    fn test_ipv4_target_address_roundtrip() {
        let addr = TargetAddress::IPv4(Ipv4Addr::new(192, 168, 1, 100), 8080);
        let bytes = addr.to_bytes();
        let (parsed, len) = TargetAddress::from_bytes(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(bytes.len(), len);
        let (host, port) = addr.to_string_host_port();
        assert_eq!(host, "192.168.1.100");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_ipv6_target_address_roundtrip() {
        let ip: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let addr = TargetAddress::IPv6(ip, 53);
        let bytes = addr.to_bytes();
        let (parsed, len) = TargetAddress::from_bytes(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(bytes.len(), len);
        let (host, port) = addr.to_string_host_port();
        assert_eq!(host, "[2001:4860:4860::8888]");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_domain_target_address_edge_cases() {
        // Max 255-character domain
        let long_domain = "a".repeat(255);
        let addr = TargetAddress::Domain(long_domain.clone(), 443);
        let bytes = addr.to_bytes();
        let (parsed, len) = TargetAddress::from_bytes(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(bytes.len(), len);
    }

    #[test]
    fn test_target_address_malformed_inputs() {
        // 1. Empty buffer
        assert!(TargetAddress::from_bytes(&[]).is_err());

        // 2. Truncated IPv4 (needs 1 + 4 + 2 = 7 bytes)
        assert!(TargetAddress::from_bytes(&[0x01, 127, 0, 0]).is_err());

        // 3. Truncated IPv6 (needs 1 + 16 + 2 = 19 bytes)
        assert!(TargetAddress::from_bytes(&[0x04, 0, 0, 0, 0]).is_err());

        // 4. Truncated domain length byte missing
        assert!(TargetAddress::from_bytes(&[0x03]).is_err());

        // 5. Truncated domain payload
        assert!(TargetAddress::from_bytes(&[0x03, 10, b'a', b'b']).is_err());

        // 6. Unknown address type (0x02, 0xff)
        assert!(TargetAddress::from_bytes(&[0x02, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(TargetAddress::from_bytes(&[0xff, 1, 2, 3, 4, 0, 80]).is_err());
    }

    #[test]
    fn test_socks5_udp_packing() {
        let target = TargetAddress::IPv4(Ipv4Addr::new(1, 1, 1, 1), 53);
        let payload = b"standard-dns-query";
        let packed = pack_socks5_udp(&target, payload);
        let (parsed_target, parsed_payload) = unpack_socks5_udp(&packed).unwrap();
        assert_eq!(target, parsed_target);
        assert_eq!(payload, parsed_payload);

        // Truncated UDP packet (< 4 bytes)
        assert!(unpack_socks5_udp(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_tunnel_udp_packing_all_types() {
        // IPv4
        let t1 = TargetAddress::IPv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let p1 = b"dns-payload-1";
        let pkt1 = pack_tunnel_udp(&t1, p1);
        let (unpacked_t1, unpacked_p1) = unpack_tunnel_udp(&pkt1).unwrap();
        assert_eq!(t1, unpacked_t1);
        assert_eq!(p1.as_slice(), unpacked_p1);

        // IPv6
        let t2 = TargetAddress::IPv6("fe80::1".parse().unwrap(), 1234);
        let p2 = b"ntp-datagram";
        let pkt2 = pack_tunnel_udp(&t2, p2);
        let (unpacked_t2, unpacked_p2) = unpack_tunnel_udp(&pkt2).unwrap();
        assert_eq!(t2, unpacked_t2);
        assert_eq!(p2.as_slice(), unpacked_p2);

        // Domain
        let t3 = TargetAddress::Domain("api.telegram.org".to_string(), 443);
        let p3 = b"quic-initial-datagram";
        let pkt3 = pack_tunnel_udp(&t3, p3);
        let (unpacked_t3, unpacked_p3) = unpack_tunnel_udp(&pkt3).unwrap();
        assert_eq!(t3, unpacked_t3);
        assert_eq!(p3.as_slice(), unpacked_p3);
    }
}
