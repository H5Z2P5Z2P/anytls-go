use std::sync::Arc;

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::auth::{PASSWORD_HASH_LEN, read_and_verify_auth};
use crate::error::Result;
use crate::padding::PaddingFactory;
use crate::reality::{RealityConfig, RealityServer};
use crate::session::{Session, SharedPadding, Stream};
use crate::socks_addr::SocksAddr;
use crate::tcp_brutal::{TcpBrutalConfig, apply_to_stream};
use crate::tls::{self_signed_server_config, server_config_from_paths};
use crate::uot::{MAGIC_ADDRESS, relay_server_stream};

pub struct Server {
    password_hash: [u8; PASSWORD_HASH_LEN],
    padding: SharedPadding,
    security: ServerSecurity,
    tcp_brutal: Option<TcpBrutalConfig>,
}

enum ServerSecurity {
    Tls(TlsAcceptor),
    Reality(RealityServer),
}

impl Server {
    pub fn new(password_hash: [u8; PASSWORD_HASH_LEN], padding: PaddingFactory) -> Result<Self> {
        Self::new_with_tcp_brutal(password_hash, padding, None)
    }

    pub fn new_with_tcp_brutal(
        password_hash: [u8; PASSWORD_HASH_LEN],
        padding: PaddingFactory,
        tcp_brutal: Option<TcpBrutalConfig>,
    ) -> Result<Self> {
        Ok(Self {
            password_hash,
            padding: SharedPadding::new(padding),
            security: ServerSecurity::Tls(TlsAcceptor::from(self_signed_server_config()?)),
            tcp_brutal,
        })
    }

    pub fn new_tls_with_tcp_brutal(
        password_hash: [u8; PASSWORD_HASH_LEN],
        padding: PaddingFactory,
        certificate_path: &str,
        key_path: &str,
        tcp_brutal: Option<TcpBrutalConfig>,
    ) -> Result<Self> {
        Ok(Self {
            password_hash,
            padding: SharedPadding::new(padding),
            security: ServerSecurity::Tls(TlsAcceptor::from(server_config_from_paths(
                certificate_path,
                key_path,
            )?)),
            tcp_brutal,
        })
    }

    pub fn new_reality(
        password_hash: [u8; PASSWORD_HASH_LEN],
        padding: PaddingFactory,
        reality: RealityConfig,
    ) -> Result<Self> {
        Self::new_reality_with_tcp_brutal(password_hash, padding, reality, None)
    }

    pub fn new_reality_with_tcp_brutal(
        password_hash: [u8; PASSWORD_HASH_LEN],
        padding: PaddingFactory,
        reality: RealityConfig,
        tcp_brutal: Option<TcpBrutalConfig>,
    ) -> Result<Self> {
        Ok(Self {
            password_hash,
            padding: SharedPadding::new(padding),
            security: ServerSecurity::Reality(
                RealityServer::new(reality)
                    .map_err(|err| crate::AnyTlsError::protocol(err.to_string()))?,
            ),
            tcp_brutal,
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
        if let Some(config) = self.tcp_brutal {
            apply_to_stream(&tcp, config)?;
            info!(peer_addr = ?peer_addr, rate = config.rate, cwnd_gain = config.cwnd_gain, "enabled tcp brutal on inbound anytls transport");
        }
        match &self.security {
            ServerSecurity::Tls(acceptor) => {
                let mut tls = acceptor.accept(tcp).await?;
                read_and_verify_auth(&mut tls, &self.password_hash).await?;
                info!(peer_addr = ?peer_addr, "client authenticated over tls");
                let session = Session::new_server(tls, self.padding.clone(), move |stream| async move {
                    if let Err(err) = handle_stream(stream).await {
                        if is_expected_stream_end(&err) {
                            debug!(error = %err, "server stream ended normally");
                        } else {
                            warn!(error = %err, "server stream ended with error");
                        }
                    }
                })
                .await;
                session.closed().await;
                info!(peer_addr = ?peer_addr, "session closed");
                Ok(())
            }
            ServerSecurity::Reality(reality) => {
                let mut tls = reality
                    .accept(tcp)
                    .await
                    .map_err(|err| crate::AnyTlsError::protocol(err.to_string()))?;
                read_and_verify_auth(&mut tls, &self.password_hash).await?;
                info!(peer_addr = ?peer_addr, "client authenticated over reality");
                let session = Session::new_server(tls, self.padding.clone(), move |stream| async move {
                    if let Err(err) = handle_stream(stream).await {
                        if is_expected_stream_end(&err) {
                            debug!(error = %err, "server stream ended normally");
                        } else {
                            warn!(error = %err, "server stream ended with error");
                        }
                    }
                })
                .await;
                session.closed().await;
                info!(peer_addr = ?peer_addr, "session closed");
                Ok(())
            }
        }
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
    match copy_bidirectional(&mut stream, &mut outbound).await {
        Ok(_) => {}
        Err(err) if is_expected_io_end(&err) => {
            debug!(stream_id = stream.id(), destination = %destination, error = %err, "proxy stream closed by peer");
        }
        Err(err) => return Err(err.into()),
    }
    let _ = stream.shutdown().await;
    info!(stream_id = stream.id(), destination = %destination, "proxy stream finished");
    Ok(())
}

fn is_expected_stream_end(err: &crate::AnyTlsError) -> bool {
    match err {
        crate::AnyTlsError::Io(io_err) => is_expected_io_end(io_err),
        crate::AnyTlsError::SessionClosed => true,
        _ => false,
    }
}

fn is_expected_io_end(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    ) || err.to_string() == "stream is closed"
}

#[cfg(test)]
mod tests {
    use super::is_expected_io_end;

    #[test]
    fn stream_closed_io_error_is_expected_shutdown() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "stream is closed");
        assert!(is_expected_io_end(&err));
    }
}
