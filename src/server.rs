use std::sync::Arc;

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::auth::{PASSWORD_HASH_LEN, read_and_verify_auth};
use crate::error::Result;
use crate::padding::PaddingFactory;
use crate::session::{Session, SharedPadding, Stream};
use crate::socks_addr::SocksAddr;
use crate::tls::self_signed_server_config;
use crate::uot::{MAGIC_ADDRESS, relay_server_stream};

pub struct Server {
    password_hash: [u8; PASSWORD_HASH_LEN],
    padding: SharedPadding,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub fn new(password_hash: [u8; PASSWORD_HASH_LEN], padding: PaddingFactory) -> Result<Self> {
        Ok(Self {
            password_hash,
            padding: SharedPadding::new(padding),
            tls_acceptor: TlsAcceptor::from(self_signed_server_config()?),
        })
    }

    pub async fn listen(self, listen_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!(listen_addr, "rust anytls server listening");
        self.serve(listener).await
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let listen_addr = listener.local_addr()?;
        info!(%listen_addr, "rust anytls server serving listener");
        let server = Arc::new(self);
        loop {
            let (tcp, peer_addr) = listener.accept().await?;
            debug!(%peer_addr, "accepted inbound tcp connection");
            let server = server.clone();
            tokio::spawn(async move {
                if let Err(err) = server.handle_connection(tcp).await {
                    warn!(error = %err, %peer_addr, "server connection ended with error");
                }
            });
        }
    }

    async fn handle_connection(self: Arc<Self>, tcp: TcpStream) -> Result<()> {
        let peer_addr = tcp.peer_addr().ok();
        let mut tls = self.tls_acceptor.accept(tcp).await?;
        read_and_verify_auth(&mut tls, &self.password_hash).await?;
        info!(peer_addr = ?peer_addr, "client authenticated over tls");

        let session = Session::new_server(tls, self.padding.clone(), move |stream| async move {
            if let Err(err) = handle_stream(stream).await {
                warn!(error = %err, "server stream ended with error");
            }
        })
        .await;
        session.closed().await;
        info!(peer_addr = ?peer_addr, "session closed");
        Ok(())
    }
}

async fn handle_stream(mut stream: Stream) -> Result<()> {
    let destination = SocksAddr::read_from(&mut stream).await?;
    info!(stream_id = stream.id(), destination = %destination, "accepted proxy stream");
    if matches!(&destination, SocksAddr::Domain { host, .. } if host == MAGIC_ADDRESS) {
        stream.report_handshake_success().await?;
        relay_server_stream(stream).await?;
        return Ok(());
    }

    let mut outbound = match TcpStream::connect(destination.to_string()).await {
        Ok(outbound) => outbound,
        Err(err) => {
            warn!(stream_id = stream.id(), destination = %destination, error = %err, "outbound tcp connect failed");
            stream.report_handshake_failure(&err).await?;
            return Err(err.into());
        }
    };
    stream.report_handshake_success().await?;
    debug!(stream_id = stream.id(), destination = %destination, "outbound tcp handshake reported to client");
    let _ = copy_bidirectional(&mut stream, &mut outbound).await?;
    let _ = stream.shutdown().await;
    info!(stream_id = stream.id(), destination = %destination, "proxy stream finished");
    Ok(())
}
