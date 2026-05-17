use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AnyTlsError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl SocksAddr {
    pub fn domain(host: impl Into<String>, port: u16) -> Self {
        Self::Domain {
            host: host.into(),
            port,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ip(addr) => addr.ip().to_string(),
            Self::Domain { host, .. } => host.clone(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                out.push(1);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                out.push(4);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Domain { host, port } => {
                let len = u8::try_from(host.len())
                    .map_err(|_| AnyTlsError::protocol("domain name is too long"))?;
                out.push(3);
                out.push(len);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out)
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_all(&self.to_bytes()?).await?;
        Ok(())
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let atyp = reader.read_u8().await?;
        match atyp {
            1 => {
                let mut octets = [0_u8; 4];
                reader.read_exact(&mut octets).await?;
                let port = reader.read_u16().await?;
                Ok(Self::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(octets)),
                    port,
                )))
            }
            3 => {
                let len = reader.read_u8().await? as usize;
                let mut host = vec![0_u8; len];
                reader.read_exact(&mut host).await?;
                let port = reader.read_u16().await?;
                Ok(Self::Domain {
                    host: String::from_utf8(host)
                        .map_err(|_| AnyTlsError::protocol("domain name is not UTF-8"))?,
                    port,
                })
            }
            4 => {
                let mut octets = [0_u8; 16];
                reader.read_exact(&mut octets).await?;
                let port = reader.read_u16().await?;
                Ok(Self::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )))
            }
            _ => Err(AnyTlsError::protocol(format!(
                "unknown SOCKS address type: {atyp}"
            ))),
        }
    }

    pub fn parse_host_port(value: &str) -> Result<Self> {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| AnyTlsError::protocol(format!("missing port in address: {value}")))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| AnyTlsError::protocol(format!("invalid port in address: {value}")))?;
        Ok(Self::domain(host.trim_matches(['[', ']']), port))
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SocksAddr;

    #[test]
    fn domain_socks_addr_uses_rfc1928_encoding() {
        let addr = SocksAddr::domain("example.com", 443);

        assert_eq!(
            addr.to_bytes().unwrap(),
            b"\x03\x0bexample.com\x01\xbb".to_vec()
        );
    }

    #[test]
    fn parses_host_port_as_domain_when_not_socket_addr() {
        let addr = SocksAddr::parse_host_port("example.com:443").unwrap();

        assert_eq!(addr, SocksAddr::domain("example.com", 443));
        assert_eq!(addr.to_string(), "example.com:443");
    }
}
