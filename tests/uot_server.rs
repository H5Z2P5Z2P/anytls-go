use anytls::logging::init_tracing;
use anytls::socks_addr::SocksAddr;
use anytls::uot::{Request, encode_packet, read_packet, relay_server_stream};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

#[tokio::test]
async fn relay_server_stream_proxies_uot_v2_packets() {
    init_tracing("anytls=debug");

    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0_u8; 1500];
        let (n, peer) = udp_echo.recv_from(&mut buf).await.unwrap();
        udp_echo.send_to(&buf[..n], peer).await.unwrap();
    });

    let (mut client_io, server_io) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        relay_server_stream(server_io).await.unwrap();
    });

    Request {
        is_connect: true,
        destination: SocksAddr::Ip(echo_addr),
    }
    .write_to(&mut client_io)
    .await
    .unwrap();
    client_io
        .write_all(&encode_packet(None, b"ping").unwrap())
        .await
        .unwrap();

    let (payload, destination) = read_packet(&mut client_io, Some(&SocksAddr::Ip(echo_addr)))
        .await
        .unwrap();

    assert_eq!(payload, b"ping");
    assert_eq!(destination, SocksAddr::Ip(echo_addr));
}
