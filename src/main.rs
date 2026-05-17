use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anytls::auth::password_hash;
use anytls::client::Client;
use anytls::error::{AnyTlsError, Result};
use anytls::logging::init_tracing;
use anytls::padding::PaddingFactory;
use anytls::server::Server;
use anytls::socks_addr::SocksAddr;
use anytls::uot::{Request as UotRequest, request_destination};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::debug;
use url::Url;

#[derive(Parser)]
#[command(name = "anytls")]
#[command(about = "Rust anytls client/server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Client {
        #[arg(short = 'l', default_value = "127.0.0.1:1080")]
        listen: String,
        #[arg(short = 's')]
        server: String,
        #[arg(long, default_value = "")]
        sni: String,
        #[arg(short = 'p', default_value = "")]
        password: String,
        #[arg(short = 'm', default_value_t = 5)]
        min_idle_session: usize,
    },
    Server {
        #[arg(short = 'l', default_value = "0.0.0.0:8443")]
        listen: String,
        #[arg(short = 'p')]
        password: String,
        #[arg(long)]
        padding_scheme: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing("anytls=info,rustls=warn,tokio_rustls=warn");
    let cli = Cli::parse();
    match cli.command {
        Command::Client {
            listen,
            mut server,
            mut sni,
            mut password,
            min_idle_session,
        } => {
            parse_anytls_url(&mut server, &mut sni, &mut password)?;
            if server.is_empty() || password.is_empty() {
                return Err(AnyTlsError::protocol("client requires -s and -p"));
            }
            run_client(&listen, Client::new(server, sni, password_hash(&password), min_idle_session))
                .await
        }
        Command::Server {
            listen,
            password,
            padding_scheme,
        } => {
            let padding = if let Some(path) = padding_scheme {
                let raw = fs::read(&path)?;
                PaddingFactory::new(&raw).ok_or_else(|| {
                    AnyTlsError::protocol(format!("invalid padding scheme file: {path}"))
                })?
            } else {
                PaddingFactory::default_scheme()
            };
            Server::new(password_hash(&password), padding)?.listen(&listen).await
        }
    }
}

fn parse_anytls_url(server: &mut String, sni: &mut String, password: &mut String) -> Result<()> {
    let Ok(url) = Url::parse(server) else {
        return Ok(());
    };
    if url.scheme() != "anytls" {
        return Ok(());
    }
    *server = url
        .host_str()
        .map(|host| match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => format!("{host}:443"),
        })
        .ok_or_else(|| AnyTlsError::protocol("anytls URL is missing host"))?;
    if !url.username().is_empty() {
        *password = url.username().to_owned();
    }
    if let Some(value) = url.query_pairs().find_map(|(key, value)| {
        if key == "sni" {
            Some(value.into_owned())
        } else {
            None
        }
    }) {
        *sni = value;
    }
    Ok(())
}

async fn run_client(listen: &str, client: Client) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    loop {
        let (inbound, _) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_inbound(inbound, client).await {
                eprintln!("inbound connection ended: {err}");
            }
        });
    }
}

async fn handle_inbound(inbound: TcpStream, client: Client) -> Result<()> {
    let mut first = [0_u8; 1];
    inbound.peek(&mut first).await?;
    match first[0] {
        4 => handle_socks4(inbound, client).await,
        5 => handle_socks5(inbound, client).await,
        _ => handle_http(inbound, client).await,
    }
}

async fn handle_socks5(mut inbound: TcpStream, client: Client) -> Result<()> {
    let version = inbound.read_u8().await?;
    if version != 5 {
        return Err(AnyTlsError::protocol("invalid SOCKS5 version"));
    }
    let method_count = inbound.read_u8().await? as usize;
    let mut methods = vec![0_u8; method_count];
    inbound.read_exact(&mut methods).await?;
    inbound.write_all(&[5, 0]).await?;

    let version = inbound.read_u8().await?;
    let command = inbound.read_u8().await?;
    let _reserved = inbound.read_u8().await?;
    if version != 5 {
        return Err(AnyTlsError::protocol("invalid SOCKS5 request version"));
    }
    let destination = read_socks_request_addr(&mut inbound).await?;
    if command == 3 {
        return handle_socks5_udp_associate(inbound, client, destination).await;
    }
    if command != 1 {
        return Err(AnyTlsError::protocol("only SOCKS5 CONNECT and UDP ASSOCIATE are supported"));
    }
    let mut proxy = client.create_proxy_stream(&destination).await?;
    inbound
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    let _ = copy_bidirectional(&mut inbound, proxy.stream_mut()).await?;
    proxy.release().await;
    Ok(())
}

async fn handle_socks5_udp_associate(
    mut inbound: TcpStream,
    client: Client,
    destination: SocksAddr,
) -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bind = match udp_socket.local_addr()? {
        std::net::SocketAddr::V4(addr) => {
            let ip = addr.ip().octets();
            let port = addr.port().to_be_bytes();
            [vec![5, 0, 0, 1], ip.to_vec(), port.to_vec()].concat()
        }
        std::net::SocketAddr::V6(addr) => {
            let ip = addr.ip().octets();
            let port = addr.port().to_be_bytes();
            [vec![5, 0, 0, 4], ip.to_vec(), port.to_vec()].concat()
        }
    };
    inbound.write_all(&bind).await?;

    let mut uot = client.create_proxy_stream(&request_destination()).await?;
    UotRequest {
        is_connect: false,
        destination,
    }
    .write_to(uot.stream_mut())
    .await?;
    let (mut uot_reader, mut uot_writer, lease) = uot.into_split();

    let udp_socket = std::sync::Arc::new(udp_socket);
    let peer_addr = std::sync::Arc::new(tokio::sync::Mutex::new(None::<std::net::SocketAddr>));
    let udp_to_remote = udp_socket.clone();
    let udp_peer_to_remote = peer_addr.clone();
    let udp_task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let (n, client_addr) = udp_to_remote.recv_from(&mut buffer).await?;
            *udp_peer_to_remote.lock().await = Some(client_addr);
            let (payload, destination) = decode_socks5_udp_packet(&buffer[..n])?;
            let packet = anytls::uot::encode_packet(Some(&destination), &payload)?;
            uot_writer.write_all(&packet).await?;
            debug!(%client_addr, destination = %destination, bytes = payload.len(), "forwarded socks5 udp packet to anytls uot");
        }
        #[allow(unreachable_code)]
        Ok::<(), AnyTlsError>(())
    });

    let udp_from_remote = udp_socket.clone();
    let udp_peer_from_remote = peer_addr.clone();
    let recv_task = tokio::spawn(async move {
        loop {
            let (payload, source) = anytls::uot::read_packet(&mut uot_reader, None).await?;
            let packet = encode_socks5_udp_packet(&source, &payload)?;
            let Some(target) = *udp_peer_from_remote.lock().await else {
                continue;
            };
            udp_from_remote.send_to(&packet, target).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), AnyTlsError>(())
    });

    let mut sink = tokio::io::sink();
    let _ = tokio::io::copy(&mut inbound, &mut sink).await;
    udp_task.abort();
    recv_task.abort();
    lease.release().await;
    Ok(())
}

async fn read_socks_request_addr(inbound: &mut TcpStream) -> Result<SocksAddr> {
    let atyp = inbound.read_u8().await?;
    match atyp {
        1 => {
            let mut ip = [0_u8; 4];
            inbound.read_exact(&mut ip).await?;
            let port = inbound.read_u16().await?;
            Ok(SocksAddr::Ip(SocketAddr::new(IpAddr::from(ip), port)))
        }
        3 => {
            let len = inbound.read_u8().await? as usize;
            let mut host = vec![0_u8; len];
            inbound.read_exact(&mut host).await?;
            let port = inbound.read_u16().await?;
            Ok(SocksAddr::domain(
                String::from_utf8(host)
                    .map_err(|_| AnyTlsError::protocol("SOCKS domain is not UTF-8"))?,
                port,
            ))
        }
        4 => {
            let mut ip = [0_u8; 16];
            inbound.read_exact(&mut ip).await?;
            let port = inbound.read_u16().await?;
            Ok(SocksAddr::Ip(SocketAddr::new(IpAddr::from(ip), port)))
        }
        _ => Err(AnyTlsError::protocol("unknown SOCKS address type")),
    }
}

async fn handle_socks4(mut inbound: TcpStream, client: Client) -> Result<()> {
    let version = inbound.read_u8().await?;
    let command = inbound.read_u8().await?;
    if version != 4 || command != 1 {
        return Err(AnyTlsError::protocol("only SOCKS4 CONNECT is supported"));
    }
    let port = inbound.read_u16().await?;
    let mut ip = [0_u8; 4];
    inbound.read_exact(&mut ip).await?;
    read_nul_terminated(&mut inbound).await?;
    let destination = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let host = String::from_utf8(read_nul_terminated(&mut inbound).await?)
            .map_err(|_| AnyTlsError::protocol("SOCKS4a domain is not UTF-8"))?;
        SocksAddr::domain(host, port)
    } else {
        SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
    };

    let mut proxy = client.create_proxy_stream(&destination).await?;
    inbound.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await?;
    let _ = copy_bidirectional(&mut inbound, proxy.stream_mut()).await?;
    proxy.release().await;
    Ok(())
}

async fn read_nul_terminated(inbound: &mut TcpStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let byte = inbound.read_u8().await?;
        if byte == 0 {
            return Ok(out);
        }
        out.push(byte);
        if out.len() > 4096 {
            return Err(AnyTlsError::protocol("NUL-terminated field is too long"));
        }
    }
}

async fn handle_http(mut inbound: TcpStream, client: Client) -> Result<()> {
    let header = read_http_header(&mut inbound).await?;
    let header_text = std::str::from_utf8(&header)
        .map_err(|_| AnyTlsError::protocol("HTTP header is not UTF-8"))?;
    let (request_line, rest) = header_text
        .split_once("\r\n")
        .ok_or_else(|| AnyTlsError::protocol("invalid HTTP request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| AnyTlsError::protocol("missing HTTP method"))?;
    let uri = parts
        .next()
        .ok_or_else(|| AnyTlsError::protocol("missing HTTP URI"))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let destination = SocksAddr::parse_host_port(uri)?;
        let mut proxy = client.create_proxy_stream(&destination).await?;
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let _ = copy_bidirectional(&mut inbound, proxy.stream_mut()).await?;
        proxy.release().await;
        return Ok(());
    }

    let url = Url::parse(uri)?;
    let host = url
        .host_str()
        .ok_or_else(|| AnyTlsError::protocol("HTTP absolute URI is missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| AnyTlsError::protocol("HTTP absolute URI is missing port"))?;
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let destination = SocksAddr::domain(host, port);
    let mut proxy = client.create_proxy_stream(&destination).await?;
    let rewritten = format!("{method} {path} {version}\r\n{rest}");
    proxy.write_all(rewritten.as_bytes()).await?;
    let _ = copy_bidirectional(&mut inbound, proxy.stream_mut()).await?;
    proxy.release().await;
    Ok(())
}

fn decode_socks5_udp_packet(packet: &[u8]) -> Result<(Vec<u8>, SocksAddr)> {
    if packet.len() < 4 {
        return Err(AnyTlsError::protocol("SOCKS5 UDP packet is too short"));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(AnyTlsError::protocol("SOCKS5 UDP packet has invalid RSV"));
    }
    if packet[2] != 0 {
        return Err(AnyTlsError::protocol("SOCKS5 UDP fragmentation is not supported"));
    }

    let mut cursor = std::io::Cursor::new(&packet[3..]);
    let destination = read_socks_request_addr_from_reader(&mut cursor)?;
    let payload_offset = 3 + cursor.position() as usize;
    Ok((packet[payload_offset..].to_vec(), destination))
}

fn encode_socks5_udp_packet(source: &SocksAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    packet.extend_from_slice(&source.to_bytes()?);
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn read_socks_request_addr_from_reader(reader: &mut std::io::Cursor<&[u8]>) -> Result<SocksAddr> {
    let mut atyp = [0_u8; 1];
    std::io::Read::read_exact(reader, &mut atyp)?;
    match atyp[0] {
        1 => {
            let mut ip = [0_u8; 4];
            std::io::Read::read_exact(reader, &mut ip)?;
            let mut port = [0_u8; 2];
            std::io::Read::read_exact(reader, &mut port)?;
            Ok(SocksAddr::Ip(SocketAddr::new(IpAddr::from(ip), u16::from_be_bytes(port))))
        }
        3 => {
            let mut len = [0_u8; 1];
            std::io::Read::read_exact(reader, &mut len)?;
            let mut host = vec![0_u8; len[0] as usize];
            std::io::Read::read_exact(reader, &mut host)?;
            let mut port = [0_u8; 2];
            std::io::Read::read_exact(reader, &mut port)?;
            Ok(SocksAddr::domain(
                String::from_utf8(host)
                    .map_err(|_| AnyTlsError::protocol("SOCKS UDP domain is not UTF-8"))?,
                u16::from_be_bytes(port),
            ))
        }
        4 => {
            let mut ip = [0_u8; 16];
            std::io::Read::read_exact(reader, &mut ip)?;
            let mut port = [0_u8; 2];
            std::io::Read::read_exact(reader, &mut port)?;
            Ok(SocksAddr::Ip(SocketAddr::new(IpAddr::from(ip), u16::from_be_bytes(port))))
        }
        _ => Err(AnyTlsError::protocol("unknown SOCKS UDP address type")),
    }
}

async fn read_http_header(inbound: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while header.len() < 64 * 1024 {
        inbound.read_exact(&mut byte).await?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(AnyTlsError::protocol("HTTP header is too large"))
}
