use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anytls::auth::password_hash;
use anytls::client::Client;
use anytls::logging::init_tracing;
use anytls::socks_addr::SocksAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;

static BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
#[ignore = "process-based interop test with anytls-go server"]
async fn rust_client_interops_with_anytls_go_server() {
    init_tracing("anytls=debug,rustls=info,tokio_rustls=info");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut conn, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0_u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let server_addr = reserve_local_addr().await;
    let server_bin = build_anytls_go_server().await;
    let mut child = Command::new(&server_bin)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("-l")
        .arg(server_addr.to_string())
        .arg("-p")
        .arg("secret")
        .env("LOG_LEVEL", "debug")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn anytls-go server");

    wait_for_tcp_listener(server_addr).await;

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
    proxy.write_all(b"interop").await.unwrap();
    let mut buf = [0_u8; 7];
    proxy.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"interop");

    proxy.release().await;
    client.close().await;
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    echo_task.abort();
}

async fn reserve_local_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn build_anytls_go_server() -> std::path::PathBuf {
    let build_id = BUILD_COUNTER.fetch_add(1, Ordering::SeqCst);
    let out_dir = std::path::Path::new("/tmp/opencode/anytls-go-test-bin");
    std::fs::create_dir_all(out_dir).unwrap();
    let output = out_dir.join(format!("anytls-go-server-{build_id}"));

    let status = Command::new("go")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg("-o")
        .arg(&output)
        .arg("./cmd/server")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .expect("failed to run go build for anytls-go server");
    assert!(status.success(), "go build for anytls-go server failed");
    output
}

async fn wait_for_tcp_listener(addr: std::net::SocketAddr) {
    timeout(Duration::from_secs(20), async move {
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => {
                    drop(stream);
                    return;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .expect("timed out waiting for go server listener");
}
