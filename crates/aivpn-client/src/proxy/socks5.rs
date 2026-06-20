use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS5_VER: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

pub const REP_SUCCESS: u8 = 0;
pub const REP_GENERAL_FAILURE: u8 = 1;
pub const REP_HOST_UNREACHABLE: u8 = 4;
pub const REP_CMD_NOT_SUPPORTED: u8 = 7;
pub const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 8;

#[derive(Clone, Debug)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Clone, Debug)]
pub enum Socks5Command {
    Connect(TargetAddr),          // было Connect(SocketAddr)
    UdpAssociate(SocketAddr),
}

#[derive(Clone, Debug)]
pub enum Socks5UdpTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Clone, Debug)]
pub struct Socks5UdpPacket {
    pub frag: u8,
    pub target: Socks5UdpTarget,
    pub data: Vec<u8>,
}

pub struct Socks5Session {
    pub stream: TcpStream,
}

impl Socks5Session {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Perform SOCKS5 handshake and return the parsed command.
    pub async fn negotiate(&mut self) -> std::io::Result<Socks5Command> {
        // Client greeting: VER NMETHODS METHODS...
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).await?;
        if header[0] != SOCKS5_VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not SOCKS5",
            ));
        }
        let n = header[1] as usize;
        let mut methods = vec![0u8; n];
        self.stream.read_exact(&mut methods).await?;

        if !methods.contains(&METHOD_NO_AUTH) {
            self.stream
                .write_all(&[SOCKS5_VER, METHOD_NO_ACCEPTABLE])
                .await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no acceptable auth method",
            ));
        }
        self.stream.write_all(&[SOCKS5_VER, METHOD_NO_AUTH]).await?;

        // Request: VER CMD RSV ATYP ...
        let mut req = [0u8; 4];
        self.stream.read_exact(&mut req).await?;
        if req[0] != SOCKS5_VER {
            self.send_reply(REP_GENERAL_FAILURE).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS version in request",
            ));
        }

        let cmd = req[1];
        if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
            self.send_reply(REP_CMD_NOT_SUPPORTED).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "only CONNECT and UDP ASSOCIATE are supported",
            ));
        }

        let target = match req[3] {
            ATYP_IPV4 => {
                let mut a = [0u8; 4];
                self.stream.read_exact(&mut a).await?;
                let mut port_buf = [0u8; 2];
                self.stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                TargetAddr::Ip(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(a)),
                    port,
                ))
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                self.stream.read_exact(&mut len_buf).await?;
                let mut name = vec![0u8; len_buf[0] as usize];
                self.stream.read_exact(&mut name).await?;
                let host = String::from_utf8_lossy(&name).into_owned();
                let mut port_buf = [0u8; 2];
                self.stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                TargetAddr::Domain(host, port)          // ← резолв убрали, отдаём домен
            }
            ATYP_IPV6 => {
                let mut a = [0u8; 16];
                self.stream.read_exact(&mut a).await?;
                let mut port_buf = [0u8; 2];
                self.stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                TargetAddr::Ip(SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)),
                    port,
                ))
            }
            _ => {
                self.send_reply(REP_ADDR_TYPE_NOT_SUPPORTED).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown ATYP",
                ));
            }
        };

        Ok(match cmd {
            CMD_CONNECT => Socks5Command::Connect(target),
            CMD_UDP_ASSOCIATE => {
                // Для UDP ASSOCIATE адрес в запросе — клиентский endpoint (обычно 0.0.0.0:0),
                // handle_udp_associate его игнорирует. Домен сюда практически не приходит.
                let sa = match target {
                    TargetAddr::Ip(a) => a,
                    TargetAddr::Domain(_, port) => SocketAddr::from(([0, 0, 0, 0], port)),
                };
                Socks5Command::UdpAssociate(sa)
            }
            _ => unreachable!(),
        })
    }

    /// Send SOCKS5 reply with explicit bind address.
    pub async fn send_reply_with_addr(&mut self, rep: u8, bind: SocketAddr) -> std::io::Result<()> {
        let mut out = Vec::with_capacity(22);
        out.push(SOCKS5_VER);
        out.push(rep);
        out.push(0x00);
        match bind.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&bind.port().to_be_bytes());
        self.stream.write_all(&out).await
    }

    /// Send SOCKS5 reply. Bound address is reported as 0.0.0.0:0.
    pub async fn send_reply(&mut self, rep: u8) -> std::io::Result<()> {
        self.send_reply_with_addr(rep, SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
    }
}

pub fn parse_udp_request(packet: &[u8]) -> std::io::Result<Socks5UdpPacket> {
    if packet.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 UDP packet too short",
        ));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP RSV",
        ));
    }

    let frag = packet[2];
    let atyp = packet[3];
    let mut idx = 4usize;

    let target = match atyp {
        ATYP_IPV4 => {
            if packet.len() < idx + 4 + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP IPv4 header too short",
                ));
            }
            let ip = std::net::Ipv4Addr::new(packet[idx], packet[idx + 1], packet[idx + 2], packet[idx + 3]);
            idx += 4;
            let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
            idx += 2;
            Socks5UdpTarget::Ip(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        ATYP_IPV6 => {
            if packet.len() < idx + 16 + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP IPv6 header too short",
                ));
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&packet[idx..idx + 16]);
            idx += 16;
            let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
            idx += 2;
            Socks5UdpTarget::Ip(SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(oct)), port))
        }
        ATYP_DOMAIN => {
            if packet.len() < idx + 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP domain header too short",
                ));
            }
            let len = packet[idx] as usize;
            idx += 1;
            if packet.len() < idx + len + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP domain header too short",
                ));
            }
            let host = String::from_utf8_lossy(&packet[idx..idx + len]).to_string();
            idx += len;
            let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
            idx += 2;
            Socks5UdpTarget::Domain(host, port)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported SOCKS5 UDP ATYP",
            ));
        }
    };

    Ok(Socks5UdpPacket {
        frag,
        target,
        data: packet[idx..].to_vec(),
    })
}

pub fn build_udp_response(target: &Socks5UdpTarget, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG=0
    match target {
        Socks5UdpTarget::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        },
        Socks5UdpTarget::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "domain name too long for SOCKS5 UDP",
                ));
            }
            out.push(ATYP_DOMAIN);
            out.push(host_bytes.len() as u8);
            out.extend_from_slice(host_bytes);
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(payload);
            return Ok(out);
        }
    }

    let port = match target {
        Socks5UdpTarget::Ip(addr) => addr.port(),
        Socks5UdpTarget::Domain(_, port) => *port,
    };
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub async fn resolve_udp_target(target: &Socks5UdpTarget) -> std::io::Result<SocketAddr> {
    match target {
        Socks5UdpTarget::Ip(addr) => Ok(*addr),
        Socks5UdpTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .find(|a| a.is_ipv4())
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("DNS: no IPv4 result for {host}:{port}"),
            )),
    }
}