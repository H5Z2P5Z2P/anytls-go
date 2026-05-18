use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UdpSocket, lookup_host};

use crate::error::{AnyTlsError, Result};
use crate::socks_addr::SocksAddr;

pub const VERSION: u8 = 2;
pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub is_connect: bool,
    pub destination: SocksAddr,
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(u8::from(self.is_connect));
        out.extend_from_slice(&self.destination.to_bytes()?);
        Ok(out)
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let is_connect = reader.read_u8().await? != 0;
        let destination = SocksAddr::read_from(reader).await?;
        Ok(Self {
            is_connect,
            destination,
        })
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_all(&self.encode()?).await?;
        Ok(())
    }
}

pub fn request_destination() -> SocksAddr {
    SocksAddr::domain(MAGIC_ADDRESS, 0)
}

pub fn encode_packet(destination: Option<&SocksAddr>, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(destination) = destination {
        out.extend_from_slice(&encode_uot_addr(destination)?);
    }
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub async fn read_packet<R>(
    reader: &mut R,
    connected_destination: Option<&SocksAddr>,
) -> Result<(Vec<u8>, SocksAddr)>
where
    R: AsyncRead + Unpin,
{
    let destination = if let Some(destination) = connected_destination {
        destination.clone()
    } else {
        read_uot_addr(reader).await?
    };
    let length = reader.read_u16().await? as usize;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok((payload, destination))
}

pub async fn relay_server_stream<S>(stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let request = Request::read_from(&mut reader).await?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let request_destination = request.destination.clone();
    let is_connect = request.is_connect;
    let socket_for_send = socket.clone();
    let uplink = tokio::spawn(async move {
        loop {
            let (payload, destination) = read_packet(
                &mut reader,
                if is_connect {
                    Some(&request_destination)
                } else {
                    None
                },
            )
            .await?;
            let destination = resolve_udp_addr(&destination).await?;
            socket_for_send.send_to(&payload, destination).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), AnyTlsError>(())
    });

    let mut buffer = vec![0_u8; 65_535];
    loop {
        let (n, addr) = socket.recv_from(&mut buffer).await?;
        let source = SocksAddr::Ip(addr);
        let packet = encode_packet(
            if request.is_connect {
                None
            } else {
                Some(&source)
            },
            &buffer[..n],
        )?;
        if let Err(err) = writer.write_all(&packet).await {
            uplink.abort();
            return Err(err.into());
        }
    }
}

async fn resolve_udp_addr(destination: &SocksAddr) -> Result<SocketAddr> {
    match destination {
        SocksAddr::Ip(addr) => Ok(*addr),
        SocksAddr::Domain { host, port } => lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| {
                AnyTlsError::protocol(format!("failed to resolve udp address: {host}:{port}"))
            }),
    }
}

fn encode_uot_addr(destination: &SocksAddr) -> Result<Vec<u8>> {
    match destination {
        SocksAddr::Ip(SocketAddr::V4(addr)) => {
            let mut out = vec![0x00];
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
            Ok(out)
        }
        SocksAddr::Ip(SocketAddr::V6(addr)) => {
            let mut out = vec![0x01];
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
            Ok(out)
        }
        SocksAddr::Domain { host, port } => {
            let len = u8::try_from(host.len())
                .map_err(|_| AnyTlsError::protocol("domain name is too long"))?;
            let mut out = vec![0x02, len];
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            Ok(out)
        }
    }
}

async fn read_uot_addr<R>(reader: &mut R) -> Result<SocksAddr>
where
    R: AsyncRead + Unpin,
{
    let family = reader.read_u8().await?;
    match family {
        0x00 => {
            let mut ip = [0_u8; 4];
            reader.read_exact(&mut ip).await?;
            let port = reader.read_u16().await?;
            Ok(SocksAddr::Ip(SocketAddr::from((ip, port))))
        }
        0x01 => {
            let mut ip = [0_u8; 16];
            reader.read_exact(&mut ip).await?;
            let port = reader.read_u16().await?;
            Ok(SocksAddr::Ip(SocketAddr::from((ip, port))))
        }
        0x02 => {
            let len = reader.read_u8().await? as usize;
            let mut host = vec![0_u8; len];
            reader.read_exact(&mut host).await?;
            let port = reader.read_u16().await?;
            Ok(SocksAddr::domain(
                String::from_utf8(host)
                    .map_err(|_| AnyTlsError::protocol("domain name is not UTF-8"))?,
                port,
            ))
        }
        _ => Err(AnyTlsError::protocol(format!(
            "unknown UoT address family: {family}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, encode_packet, read_packet, request_destination};
    use crate::socks_addr::SocksAddr;

    #[test]
    fn request_encodes_bool_and_socksaddr() {
        let request = Request {
            is_connect: true,
            destination: request_destination(),
        };

        assert_eq!(
            request.encode().unwrap(),
            b"\x01\x03\x17sp.v2.udp-over-tcp.arpa\x00\x00".to_vec()
        );
    }

    #[tokio::test]
    async fn packet_round_trips_connected_mode() {
        let encoded = encode_packet(None, b"hello").unwrap();
        let mut reader = tokio::io::BufReader::new(encoded.as_slice());
        let destination = SocksAddr::domain("example.com", 443);

        let (payload, returned_destination) =
            read_packet(&mut reader, Some(&destination)).await.unwrap();

        assert_eq!(payload, b"hello");
        assert_eq!(returned_destination, destination);
    }

    #[tokio::test]
    async fn packet_round_trips_unconnected_mode() {
        let destination = SocksAddr::domain("example.com", 443);
        let encoded = encode_packet(Some(&destination), b"hello").unwrap();
        let mut reader = tokio::io::BufReader::new(encoded.as_slice());

        let (payload, returned_destination) = read_packet(&mut reader, None).await.unwrap();

        assert_eq!(payload, b"hello");
        assert_eq!(returned_destination, destination);
    }
}
