use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anytls::auth::password_hash;
use anytls::logging::init_tracing;
use anytls::padding::PaddingFactory;
use anytls::server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

static BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
#[ignore = "process-based interop test with anytls-go client"]
async fn rust_server_interops_with_anytls_go_client() {
    init_tracing("anytls=debug,rustls=info,tokio_rustls=info");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut conn, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0_u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let server = Server::new(password_hash("secret"), PaddingFactory::default_scheme()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    let socks_addr = reserve_local_addr().await;
    let client_bin = build_anytls_go_client().await;
    let mut child = Command::new(&client_bin)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("-l")
        .arg(socks_addr.to_string())
        .arg("-s")
        .arg(server_addr.to_string())
        .arg("-p")
        .arg("secret")
        .arg("-m")
        .arg("0")
        .env("LOG_LEVEL", "debug")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn anytls-go client");

    wait_for_tcp_listener(socks_addr).await;

    let mut conn = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect_ipv4(&mut conn, echo_addr).await;
    conn.write_all(b"interop").await.unwrap();
    let mut buf = [0_u8; 7];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"interop");

    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    server_task.abort();
    echo_task.abort();
}

async fn reserve_local_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn build_anytls_go_client() -> std::path::PathBuf {
    let build_id = BUILD_COUNTER.fetch_add(1, Ordering::SeqCst);
    let out_dir = std::path::Path::new("/tmp/opencode/anytls-go-test-bin");
    std::fs::create_dir_all(out_dir).unwrap();
    let output = out_dir.join(format!("anytls-go-client-{build_id}"));

    let status = Command::new("go")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg("-o")
        .arg(&output)
        .arg("./cmd/client")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .expect("failed to run go build for anytls-go client");
    assert!(status.success(), "go build for anytls-go client failed");
    output
}

async fn wait_for_tcp_listener(addr: std::net::SocketAddr) {
    timeout(Duration::from_secs(20), async move {
        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    drop(stream);
                    return;
                }
                Err(_) => sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .expect("timed out waiting for local socks listener");
}

async fn socks5_connect_ipv4(conn: &mut TcpStream, target: std::net::SocketAddr) {
    let ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("test helper only supports ipv4 targets"),
    };

    conn.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0_u8; 2];
    conn.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, &[5, 0]);

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&target.port().to_be_bytes());
    conn.write_all(&request).await.unwrap();

    let mut response = [0_u8; 10];
    conn.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], 5);
    assert_eq!(response[1], 0);
}
