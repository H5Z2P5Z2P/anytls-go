use anytls::auth::{password_hash, read_and_verify_auth};
use anytls::client::Client;
use anytls::logging::init_tracing;
use anytls::padding::PaddingFactory;
use anytls::session::{Session, SharedPadding};
use anytls::socks_addr::SocksAddr;
use anytls::tls::self_signed_server_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn client_proxies_tcp_through_anytls_session() {
    init_tracing("anytls=debug,rustls=info,tokio_rustls=info");
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0_u8; 32];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let password = password_hash("secret");
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = server_listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(self_signed_server_config().unwrap())
            .accept(tcp)
            .await
            .unwrap();
        read_and_verify_auth(&mut tls, &password).await.unwrap();
        let session = Session::new_server(
            tls,
            SharedPadding::new(PaddingFactory::default_scheme()),
            |mut stream| async move {
                let destination = SocksAddr::read_from(&mut stream).await.unwrap();
                let mut outbound = TcpStream::connect(destination.to_string()).await.unwrap();
                stream.report_handshake_success().await.unwrap();
                let _ = copy_bidirectional(&mut stream, &mut outbound).await.unwrap();
            },
        )
        .await;
        session.closed().await;
    });

    let client = Client::new(
        server_addr.to_string(),
        "localhost",
        password_hash("secret"),
        0,
    );
    let mut proxy = client
        .create_proxy_stream(&SocksAddr::Ip(echo_addr))
        .await
        .unwrap();

    proxy.write_all(b"hello").await.unwrap();
    let mut echoed = [0_u8; 5];
    proxy.read_exact(&mut echoed).await.unwrap();

    assert_eq!(&echoed, b"hello");

    proxy.release().await;
    client.close().await;
}
