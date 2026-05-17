use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

use crate::auth::{PASSWORD_HASH_LEN, write_auth_request};
use crate::error::Result;
use crate::padding::PaddingFactory;
use crate::session::{Session, SharedPadding, Stream};
use crate::socks_addr::SocksAddr;
use crate::tcp_brutal::{TcpBrutalConfig, apply_to_stream};
use crate::tls::{client_config_insecure, server_name};

pub trait ClientTransport: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> ClientTransport for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

type BoxedTransport = Box<dyn ClientTransport>;
type DialFuture = Pin<Box<dyn Future<Output = Result<BoxedTransport>> + Send>>;
type Dialer = dyn Fn() -> DialFuture + Send + Sync;

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    password_hash: [u8; PASSWORD_HASH_LEN],
    padding: SharedPadding,
    session_counter: AtomicU64,
    idle_sessions: Mutex<BTreeMap<u64, IdleSession>>,
    sessions: Mutex<HashMap<u64, Session>>,
    idle_session_timeout: Duration,
    min_idle_session: usize,
    closed: AtomicBool,
    dialer: Arc<Dialer>,
}

struct IdleSession {
    session: Session,
    idle_since: Instant,
}

impl Client {
    pub fn new(
        server_addr: impl Into<String>,
        sni: impl Into<String>,
        password_hash: [u8; PASSWORD_HASH_LEN],
        min_idle_session: usize,
    ) -> Self {
        Self::new_with_tcp_brutal(server_addr, sni, password_hash, min_idle_session, None)
    }

    pub fn new_with_tcp_brutal(
        server_addr: impl Into<String>,
        sni: impl Into<String>,
        password_hash: [u8; PASSWORD_HASH_LEN],
        min_idle_session: usize,
        tcp_brutal: Option<TcpBrutalConfig>,
    ) -> Self {
        let server_addr = server_addr.into();
        let sni = sni.into();
        let dial_server_addr = server_addr.clone();
        let dial_sni = sni.clone();
        let dial_tcp_brutal = tcp_brutal;
        let dialer: Arc<Dialer> = Arc::new(move || {
            let server_addr = dial_server_addr.clone();
            let sni = dial_sni.clone();
            let tcp_brutal = dial_tcp_brutal;
            Box::pin(async move {
                let tcp = TcpStream::connect(&server_addr).await?;
                if let Some(config) = tcp_brutal {
                    apply_to_stream(&tcp, config)?;
                    info!(rate = config.rate, cwnd_gain = config.cwnd_gain, "enabled tcp brutal on client anytls transport");
                }
                let connector = TlsConnector::from(client_config_insecure());
                let tls = connector.connect(server_name(&sni)?, tcp).await?;
                Ok(Box::new(tls) as BoxedTransport)
            })
        });

        Self::new_with_dialer(password_hash, min_idle_session, dialer)
    }

    pub fn new_with_dialer(
        password_hash: [u8; PASSWORD_HASH_LEN],
        min_idle_session: usize,
        dialer: Arc<Dialer>,
    ) -> Self {
        let client = Self {
            inner: Arc::new(ClientInner {
                password_hash,
                padding: SharedPadding::new(PaddingFactory::default_scheme()),
                session_counter: AtomicU64::new(0),
                idle_sessions: Mutex::new(BTreeMap::new()),
                sessions: Mutex::new(HashMap::new()),
                idle_session_timeout: Duration::from_secs(30),
                min_idle_session,
                closed: AtomicBool::new(false),
                dialer,
            }),
        };
        client.spawn_idle_cleanup_task();
        client
    }

    fn spawn_idle_cleanup_task(&self) {
        let client = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                if client.inner.closed.load(Ordering::SeqCst) {
                    break;
                }
                client.cleanup_idle_sessions().await;
            }
        });
    }

    pub async fn create_proxy_stream(&self, destination: &SocksAddr) -> Result<ProxyStream> {
        let session = match self.take_idle_session().await {
            Some(session) => session,
            None => self.create_session().await?,
        };

        let mut stream = match session.open_stream().await {
            Ok(stream) => stream,
            Err(err) => {
                session.close().await;
                return Err(err);
            }
        };

        if let Err(err) = destination.write_to(&mut stream).await {
            session.close().await;
            return Err(err);
        }

        info!(
            session_seq = session.seq(),
            stream_id = stream.id(),
            destination = %destination,
            "proxy stream opened"
        );
        Ok(ProxyStream {
            stream,
            session,
            client: self.clone(),
        })
    }

    async fn take_idle_session(&self) -> Option<Session> {
        let mut sessions = self.inner.idle_sessions.lock().await;
        while let Some((_, idle)) = sessions.pop_last() {
            if !idle.session.is_closed() {
                debug!(session_seq = idle.session.seq(), "reusing idle session");
                return Some(idle.session);
            }
        }
        None
    }

    async fn create_session(&self) -> Result<Session> {
        let mut transport = (self.inner.dialer)().await?;
        let padding = self.inner.padding.get().await;
        write_auth_request(&mut transport, &self.inner.password_hash, &padding).await?;

        let session = Session::new_client(transport, self.inner.padding.clone()).await?;
        let seq = self.inner.session_counter.fetch_add(1, Ordering::SeqCst) + 1;
        session.set_seq(seq);
        self.inner.sessions.lock().await.insert(seq, session.clone());

        let client = self.clone();
        let tracked_session = session.clone();
        tokio::spawn(async move {
            tracked_session.closed().await;
            client.inner.sessions.lock().await.remove(&seq);
            client.inner.idle_sessions.lock().await.remove(&seq);
        });

        info!(session_seq = session.seq(), "created new tls session");
        Ok(session)
    }

    async fn release_session(&self, session: Session) {
        if session.is_closed() {
            return;
        }
        self.cleanup_idle_sessions().await;
        debug!(session_seq = session.seq(), "returned session to idle pool");
        self.inner.idle_sessions.lock().await.insert(
            session.seq(),
            IdleSession {
                session,
                idle_since: Instant::now(),
            },
        );
    }

    async fn cleanup_idle_sessions(&self) {
        let expire_before = Instant::now() - self.inner.idle_session_timeout;
        let mut idle_sessions = self.inner.idle_sessions.lock().await;
        let session_ids = idle_sessions.keys().copied().collect::<Vec<_>>();

        let mut retained_count = 0usize;
        let mut to_close = Vec::new();

        for seq in session_ids.into_iter().rev() {
            let Some(idle) = idle_sessions.get_mut(&seq) else {
                continue;
            };

            if idle.session.is_closed() {
                idle_sessions.remove(&seq);
                continue;
            }

            if idle.idle_since >= expire_before {
                retained_count += 1;
                continue;
            }

            if retained_count < self.inner.min_idle_session {
                idle.idle_since = Instant::now();
                retained_count += 1;
                continue;
            }

            if let Some(idle) = idle_sessions.remove(&seq) {
                debug!(session_seq = idle.session.seq(), "closing expired idle session");
                to_close.push(idle.session);
            }
        }

        drop(idle_sessions);

        for session in to_close {
            session.close().await;
        }
    }

    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);

        let idle_sessions = {
            let mut idle = self.inner.idle_sessions.lock().await;
            let sessions = idle.values().map(|entry| entry.session.clone()).collect::<Vec<_>>();
            idle.clear();
            sessions
        };

        let tracked_sessions = self
            .inner
            .sessions
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        self.inner.sessions.lock().await.clear();

        info!(
            idle_session_count = idle_sessions.len(),
            active_session_count = tracked_sessions.len(),
            "closing client sessions"
        );

        let mut seen = std::collections::HashSet::new();
        for session in idle_sessions.into_iter().chain(tracked_sessions.into_iter()) {
            if seen.insert(session.seq()) {
                session.close().await;
            }
        }
    }
}

pub struct ProxyStream {
    stream: Stream,
    session: Session,
    client: Client,
}

pub struct ProxyStreamLease {
    session: Session,
    client: Client,
}

impl ProxyStream {
    pub fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }

    pub fn into_split(
        self,
    ) -> (
        tokio::io::ReadHalf<Stream>,
        tokio::io::WriteHalf<Stream>,
        ProxyStreamLease,
    ) {
        let ProxyStream {
            stream,
            session,
            client,
        } = self;
        let (reader, writer) = tokio::io::split(stream);
        (reader, writer, ProxyStreamLease { session, client })
    }

    pub async fn release(self) {
        let ProxyStream {
            mut stream,
            session,
            client,
        } = self;
        let _ = stream.shutdown().await;
        drop(stream);
        debug!(session_seq = session.seq(), "releasing proxy stream and returning session");
        client.release_session(session).await;
    }
}

impl ProxyStreamLease {
    pub async fn release(self) {
        debug!(session_seq = self.session.seq(), "releasing leased proxy stream session");
        self.client.release_session(self.session).await;
    }
}

impl std::ops::Deref for ProxyStream {
    type Target = Stream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for ProxyStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{BoxedTransport, Client, DialFuture, Dialer};
    use crate::auth::password_hash;
    use crate::session::{Session, SharedPadding};
    use crate::socks_addr::SocksAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn client_reuses_latest_idle_session() {
        crate::logging::init_tracing("anytls=debug");

        let queue = Arc::new(Mutex::new(VecDeque::<tokio::io::DuplexStream>::new()));
        let queue_for_dialer = queue.clone();
        let dialer: Arc<Dialer> = Arc::new(move || {
            let queue = queue_for_dialer.clone();
            Box::pin(async move {
                let stream = queue.lock().await.pop_front().expect("missing test transport");
                Ok(Box::new(stream) as BoxedTransport)
            }) as DialFuture
        });

        let (server_io, client_io) = tokio::io::duplex(4096);
        queue.lock().await.push_back(client_io);
        let server = spawn_mock_anytls_server(server_io);

        let client = Client::new_with_dialer(password_hash("secret"), 0, dialer);

        let mut first = client
            .create_proxy_stream(&SocksAddr::domain("example.com", 443))
            .await
            .unwrap();
        first.write_all(b"x").await.unwrap();
        let mut buf = [0_u8; 2];
        first.read_exact(&mut buf).await.unwrap();
        first.release().await;

        let mut second = client
            .create_proxy_stream(&SocksAddr::domain("example.com", 443))
            .await
            .unwrap();
        second.write_all(b"x").await.unwrap();
        second.read_exact(&mut buf).await.unwrap();
        second.release().await;

        assert_eq!(client.inner.sessions.lock().await.len(), 1);
        assert_eq!(client.inner.idle_sessions.lock().await.len(), 1);

        client.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn client_close_closes_tracked_active_sessions() {
        let queue = Arc::new(Mutex::new(VecDeque::<tokio::io::DuplexStream>::new()));
        let queue_for_dialer = queue.clone();
        let dialer: Arc<Dialer> = Arc::new(move || {
            let queue = queue_for_dialer.clone();
            Box::pin(async move {
                let stream = queue.lock().await.pop_front().expect("missing test transport");
                Ok(Box::new(stream) as BoxedTransport)
            }) as DialFuture
        });

        let (server_io, client_io) = tokio::io::duplex(4096);
        queue.lock().await.push_back(client_io);
        let _server = spawn_mock_anytls_server(server_io);

        let client = Client::new_with_dialer(password_hash("secret"), 0, dialer);
        let _stream = client
            .create_proxy_stream(&SocksAddr::domain("example.com", 443))
            .await
            .unwrap();

        assert_eq!(client.inner.sessions.lock().await.len(), 1);
        client.close().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(client.inner.sessions.lock().await.len(), 0);
    }

    fn spawn_mock_anytls_server(io: tokio::io::DuplexStream) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut io = io;
            let mut auth = [0_u8; 64];
            io.read_exact(&mut auth[..34]).await.unwrap();
            let padding_len = u16::from_be_bytes([auth[32], auth[33]]) as usize;
            if padding_len > 0 {
                let mut padding = vec![0_u8; padding_len];
                io.read_exact(&mut padding).await.unwrap();
            }

            let session = Session::new_server(io, SharedPadding::default(), |mut stream| async move {
                let _ = SocksAddr::read_from(&mut stream).await.unwrap();
                stream.write_all(b"ok").await.unwrap();
            })
            .await;
            session.closed().await;
        })
    }
}
