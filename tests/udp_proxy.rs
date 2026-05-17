use anytls::auth::password_hash;
use anytls::client::Client;
use anytls::logging::init_tracing;
use anytls::padding::PaddingFactory;
use anytls::server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
#[ignore = "udp associate path is under active parity work"]
async fn client_proxies_udp_over_anytls_uot() {
    init_tracing("anytls=debug,rustls=info,tokio_rustls=info");

    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0_u8; 1500];
        let (n, peer) = udp_echo.recv_from(&mut buf).await.unwrap();
        udp_echo.send_to(&buf[..n], peer).await.unwrap();
    });

    let server = Server::new(password_hash("secret"), PaddingFactory::default_scheme()).unwrap();
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    tokio::spawn(async move {
        server.serve(server_listener).await.unwrap();
    });

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let client = Client::new(server_addr.to_string(), "localhost", password_hash("secret"), 0);
    tokio::spawn(async move {
        let (inbound, _) = socks_listener.accept().await.unwrap();
        super_handle_socks5_udp_associate(inbound, client).await.unwrap();
    });

    let mut tcp = TcpStream::connect(socks_addr).await.unwrap();
    tcp.write_all(&[5, 1, 0]).await.unwrap();
    let mut auth = [0_u8; 2];
    tcp.read_exact(&mut auth).await.unwrap();
    assert_eq!(&auth, &[5, 0]);

    let udp_target_hint = [5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
    tcp.write_all(&udp_target_hint).await.unwrap();
    let mut response = [0_u8; 10];
    tcp.read_exact(&mut response).await.unwrap();
    assert_eq!(response[1], 0);
    let udp_bind_addr = std::net::SocketAddr::from(([response[4], response[5], response[6], response[7]], u16::from_be_bytes([response[8], response[9]])));

    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = [
        vec![0, 0, 0, 1],
        udp_echo_addr.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets().to_vec(),
        udp_echo_addr.port().to_be_bytes().to_vec(),
        b"ping".to_vec(),
    ]
    .concat();
    udp_client.send_to(&packet, udp_bind_addr).await.unwrap();

    let mut recv_buf = [0_u8; 1500];
    let (n, _) = udp_client.recv_from(&mut recv_buf).await.unwrap();
    assert!(n >= 10);
    assert_eq!(&recv_buf[n - 4..n], b"ping");
}

async fn super_handle_socks5_udp_associate(inbound: TcpStream, client: Client) -> anytls::Result<()> {
    let mut inbound = inbound;
    let version = inbound.read_u8().await?;
    assert_eq!(version, 5);
    let n_methods = inbound.read_u8().await? as usize;
    let mut methods = vec![0_u8; n_methods];
    inbound.read_exact(&mut methods).await?;
    inbound.write_all(&[5, 0]).await?;

    let version = inbound.read_u8().await?;
    let command = inbound.read_u8().await?;
    let _reserved = inbound.read_u8().await?;
    assert_eq!(version, 5);
    assert_eq!(command, 3);
    let _atyp = inbound.read_u8().await?;
    let mut discard = [0_u8; 6];
    inbound.read_exact(&mut discard).await?;

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let bind = match udp_socket.local_addr()? {
        std::net::SocketAddr::V4(addr) => {
            let ip = addr.ip().octets();
            let port = addr.port().to_be_bytes();
            [vec![5, 0, 0, 1], ip.to_vec(), port.to_vec()].concat()
        }
        std::net::SocketAddr::V6(_) => unreachable!(),
    };
    inbound.write_all(&bind).await?;

    let mut uot = client.create_proxy_stream(&anytls::uot::request_destination()).await?;
    anytls::uot::Request {
        is_connect: false,
        destination: anytls::socks_addr::SocksAddr::Ip(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
    }
    .write_to(uot.stream_mut())
    .await?;

    let (mut reader, mut writer, lease) = uot.into_split();
    let udp_socket = std::sync::Arc::new(udp_socket);
    let peer_addr = std::sync::Arc::new(tokio::sync::Mutex::new(None::<std::net::SocketAddr>));

    let socket_to_remote = udp_socket.clone();
    let peer_to_remote = peer_addr.clone();
    let write_task = tokio::spawn(async move {
        let mut buf = [0_u8; 1500];
        loop {
            let (n, peer) = socket_to_remote.recv_from(&mut buf).await?;
            *peer_to_remote.lock().await = Some(peer);
            let (payload, destination) = decode_test_socks5_udp_packet(&buf[..n])?;
            let packet = anytls::uot::encode_packet(Some(&destination), &payload)?;
            writer.write_all(&packet).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anytls::AnyTlsError>(())
    });

    let socket_from_remote = udp_socket.clone();
    let peer_from_remote = peer_addr.clone();
    let read_task = tokio::spawn(async move {
        loop {
            let (payload, source) = anytls::uot::read_packet(&mut reader, None).await?;
            let packet = encode_test_socks5_udp_packet(&source, &payload)?;
            let Some(peer) = *peer_from_remote.lock().await else {
                continue;
            };
            socket_from_remote.send_to(&packet, peer).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anytls::AnyTlsError>(())
    });

    let _ = tokio::io::copy(&mut inbound, &mut tokio::io::sink()).await;
    write_task.abort();
    read_task.abort();
    lease.release().await;
    Ok(())
}

fn decode_test_socks5_udp_packet(packet: &[u8]) -> anytls::Result<(Vec<u8>, anytls::socks_addr::SocksAddr)> {
    if packet.len() < 10 {
        return Err(anytls::AnyTlsError::protocol("short udp packet"));
    }
    let ip = [packet[4], packet[5], packet[6], packet[7]];
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    Ok((
        packet[10..].to_vec(),
        anytls::socks_addr::SocksAddr::Ip(std::net::SocketAddr::from((ip, port))),
    ))
}

fn encode_test_socks5_udp_packet(source: &anytls::socks_addr::SocksAddr, payload: &[u8]) -> anytls::Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    packet.extend_from_slice(&source.to_bytes()?);
    packet.extend_from_slice(payload);
    Ok(packet)
}
