use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, WriteHalf,
};
use tokio::task::AbortHandle;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::time::{Duration, sleep};
use tracing::{debug, info, trace, warn};

use crate::PROGRAM_VERSION_NAME;
use crate::error::{AnyTlsError, Result};
use crate::frame::{Command, Frame, HEADER_SIZE, MAX_FRAME_DATA_LEN, waste_frame};
use crate::padding::{CHECK_MARK, PaddingFactory};
use crate::settings::StringMap;

const STREAM_BUFFER_SIZE: usize = 256 * 1024;
const STREAM_READ_CHUNK_SIZE: usize = 16 * 1024;

type StreamCallback = Arc<
    dyn Fn(Stream) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + Sync + 'static,
>;

#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

struct SessionInner {
    tx: mpsc::Sender<WriterMessage>,
    streams: Mutex<HashMap<u32, StreamEntry>>,
    next_stream_id: AtomicU32,
    seq: AtomicU64,
    peer_version: AtomicU8,
    pending_syn_ack: Mutex<Option<AbortHandle>>,
    is_client: bool,
    closed: AtomicBool,
    closed_tx: watch::Sender<bool>,
}

struct StreamEntry {
    inbound: Arc<Mutex<WriteHalf<DuplexStream>>>,
    state: Arc<StreamState>,
    reader_abort: AbortHandle,
}

enum WriterMessage {
    Frame(Frame),
    Close,
}

#[derive(Clone)]
pub struct SharedPadding(Arc<RwLock<PaddingFactory>>);

impl SharedPadding {
    pub fn new(factory: PaddingFactory) -> Self {
        Self(Arc::new(RwLock::new(factory)))
    }

    pub async fn get(&self) -> PaddingFactory {
        self.0.read().await.clone()
    }

    pub async fn update(&self, factory: PaddingFactory) {
        *self.0.write().await = factory;
    }
}

impl Default for SharedPadding {
    fn default() -> Self {
        Self::new(PaddingFactory::default_scheme())
    }
}

pub struct Stream {
    id: u32,
    io: DuplexStream,
    session: Arc<SessionInner>,
    state: Arc<StreamState>,
    report_once: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
enum StreamCloseReason {
    Closed,
    RemoteError(String),
}

struct StreamState {
    closed: AtomicBool,
    reason: StdMutex<Option<StreamCloseReason>>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            reason: StdMutex::new(None),
        }
    }

    fn mark_closed(&self, reason: StreamCloseReason) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let mut guard = self.reason.lock().expect("stream reason lock poisoned");
            *guard = Some(reason);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn io_error(&self) -> io::Error {
        match self.reason.lock().expect("stream reason lock poisoned").clone() {
            Some(StreamCloseReason::RemoteError(message)) => io::Error::other(message),
            Some(StreamCloseReason::Closed) | None => {
                io::Error::new(io::ErrorKind::BrokenPipe, "stream is closed")
            }
        }
    }
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub async fn report_handshake_success(&self) -> Result<()> {
        self.report_syn_ack(Vec::new()).await
    }

    pub async fn report_handshake_failure(&self, error: impl ToString) -> Result<()> {
        self.report_syn_ack(error.to_string().into_bytes()).await
    }

    async fn report_syn_ack(&self, data: Vec<u8>) -> Result<()> {
        if self.session.peer_version.load(Ordering::SeqCst) < 2 {
            return Ok(());
        }
        if self.report_once.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.session
            .send_frame(Frame::new(Command::SynAck, self.id, data)?)
            .await
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() == before && self.state.is_closed() {
                    Poll::Ready(Err(self.state.io_error()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.state.is_closed() {
            return Poll::Ready(Err(self.state.io_error()));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Session {
    pub fn seq(&self) -> u64 {
        self.inner.seq.load(Ordering::SeqCst)
    }

    pub fn set_seq(&self, seq: u64) {
        self.inner.seq.store(seq, Ordering::SeqCst);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub async fn close(&self) {
        self.inner.mark_closed().await;
        let _ = self.inner.tx.send(WriterMessage::Close).await;
    }

    pub async fn closed(&self) {
        let mut rx = self.inner.closed_tx.subscribe();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    }

    pub async fn new_client<T>(transport: T, padding: SharedPadding) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let factory = padding.get().await;
        let session = Self::spawn(transport, true, padding, None).await;
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", PROGRAM_VERSION_NAME);
        settings.insert("padding-md5", factory.md5());
        session
            .inner
            .send_frame(Frame::new(Command::Settings, 0, settings.to_bytes())?)
            .await?;
        info!(padding_md5 = factory.md5(), "client session sent settings");
        Ok(session)
    }

    pub async fn new_server<T, F, Fut>(transport: T, padding: SharedPadding, on_new_stream: F) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(Stream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let callback: StreamCallback = Arc::new(move |stream| Box::pin(on_new_stream(stream)));
        Self::spawn(transport, false, padding, Some(callback)).await
    }

    async fn spawn<T>(
        transport: T,
        is_client: bool,
        padding: SharedPadding,
        on_new_stream: Option<StreamCallback>,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, writer) = tokio::io::split(transport);
        let (tx, rx) = mpsc::channel(1024);
        let (closed_tx, _) = watch::channel(false);
        let inner = Arc::new(SessionInner {
            tx,
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(0),
            seq: AtomicU64::new(0),
            peer_version: AtomicU8::new(1),
            pending_syn_ack: Mutex::new(None),
            is_client,
            closed: AtomicBool::new(false),
            closed_tx,
        });
        let session = Self {
            inner: inner.clone(),
        };

        debug!(role = role_name(is_client), "spawned session loops");

        tokio::spawn(write_loop(writer, rx, is_client, padding.clone(), inner.clone()));
        tokio::spawn(async move {
            let result = read_loop(&mut reader, inner.clone(), padding, on_new_stream).await;
            if let Err(err) = result {
                if !matches!(err, AnyTlsError::Io(ref io_err) if io_err.kind() == io::ErrorKind::UnexpectedEof)
                {
                    warn!(role = role_name(inner.is_client), error = %err, "session read loop ended with error");
                }
            }
            inner.mark_closed().await;
        });

        session
    }

    pub async fn open_stream(&self) -> Result<Stream> {
        if self.is_closed() {
            return Err(AnyTlsError::SessionClosed);
        }
        let id = self.inner.next_stream_id.fetch_add(1, Ordering::SeqCst) + 1;
        let stream = self.inner.create_stream(id).await;

        if id >= 2 && self.inner.peer_version.load(Ordering::SeqCst) >= 2 {
            self.inner.arm_syn_ack_timeout(id).await;
        }

        self.inner
            .send_frame(Frame::empty(Command::Syn, id))
            .await
            .inspect_err(|_| {
                self.inner.closed.store(true, Ordering::SeqCst);
            })?;
        debug!(role = role_name(self.inner.is_client), stream_id = id, session_seq = self.seq(), "opened stream");
        Ok(stream)
    }
}

impl SessionInner {
    async fn send_frame(&self, frame: Frame) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(AnyTlsError::SessionClosed);
        }
        self.tx
            .send(WriterMessage::Frame(frame))
            .await
            .map_err(|_| AnyTlsError::SessionClosed)
    }

    async fn create_stream(self: &Arc<Self>, id: u32) -> Stream {
        let (user_io, session_io) = tokio::io::duplex(STREAM_BUFFER_SIZE);
        let (mut local_reader, local_writer) = tokio::io::split(session_io);
        let state = Arc::new(StreamState::new());

        let session = self.clone();
        let reader_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; STREAM_READ_CHUNK_SIZE];
            loop {
                match local_reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        trace!(role = role_name(session.is_client), stream_id = id, bytes = n, "read local stream payload for multiplexing");
                        for chunk in buffer[..n].chunks(MAX_FRAME_DATA_LEN) {
                            let Ok(frame) = Frame::new(Command::Psh, id, chunk.to_vec()) else {
                                break;
                            };
                            if session.send_frame(frame).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            if !session.closed.load(Ordering::SeqCst) {
                debug!(role = role_name(session.is_client), stream_id = id, "local stream reader reached eof, sending fin");
                let _ = session.send_frame(Frame::empty(Command::Fin, id)).await;
            }
            session.streams.lock().await.remove(&id);
        });

        let entry = StreamEntry {
            inbound: Arc::new(Mutex::new(local_writer)),
            state: state.clone(),
            reader_abort: reader_task.abort_handle(),
        };
        self.streams.lock().await.insert(id, entry);

        Stream {
            id,
            io: user_io,
            session: self.clone(),
            state,
            report_once: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn write_to_stream(&self, id: u32, data: &[u8]) -> Result<()> {
        let writer = {
            let streams = self.streams.lock().await;
            streams.get(&id).map(|entry| entry.inbound.clone())
        };
        if let Some(writer) = writer {
            writer.lock().await.write_all(data).await?;
        }
        Ok(())
    }

    async fn close_stream_locally(&self, id: u32, reason: StreamCloseReason) {
        let entry = self.streams.lock().await.remove(&id);
        if let Some(entry) = entry {
            debug!(role = role_name(self.is_client), stream_id = id, "closing local stream state");
            entry.reader_abort.abort();
            entry.state.mark_closed(reason);
            let _ = entry.inbound.lock().await.shutdown().await;
        }
    }

    async fn arm_syn_ack_timeout(self: &Arc<Self>, stream_id: u32) {
        if !self.is_client {
            return;
        }

        let mut pending = self.pending_syn_ack.lock().await;
        if let Some(previous) = pending.take() {
            previous.abort();
        }

        let session = self.clone();
        let handle = tokio::spawn(async move {
            sleep(Duration::from_secs(3)).await;
            warn!(stream_id, "synack timeout expired, closing session");
            session.mark_closed().await;
        });
        *pending = Some(handle.abort_handle());
    }

    async fn clear_syn_ack_timeout(&self) {
        let mut pending = self.pending_syn_ack.lock().await;
        if let Some(handle) = pending.take() {
            handle.abort();
        }
    }

    async fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut streams = self.streams.lock().await;
        let stream_count = streams.len();
        info!(role = role_name(self.is_client), stream_count, "closing session");
        let entries = streams.drain().collect::<Vec<_>>();
        drop(streams);
        self.clear_syn_ack_timeout().await;
        for (_, entry) in entries {
            entry.reader_abort.abort();
            entry.state.mark_closed(StreamCloseReason::Closed);
            let _ = entry.inbound.lock().await.shutdown().await;
        }
        let _ = self.closed_tx.send(true);
        let _ = self.tx.send(WriterMessage::Close).await;
    }
}

async fn read_loop<R>(
    reader: &mut R,
    session: Arc<SessionInner>,
    padding: SharedPadding,
    on_new_stream: Option<StreamCallback>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut received_settings_from_client = false;

    loop {
        let frame = Frame::read_from(reader).await?;
        trace!(role = role_name(session.is_client), command = ?frame.command, stream_id = frame.stream_id, data_len = frame.data.len(), "received frame");
        match frame.command {
            Command::Psh => {
                if !frame.data.is_empty() {
                    session.write_to_stream(frame.stream_id, &frame.data).await?;
                }
            }
            Command::Syn => {
                debug!(role = role_name(session.is_client), stream_id = frame.stream_id, "received syn");
                if !session.is_client && !received_settings_from_client {
                    session
                        .send_frame(Frame::new(
                            Command::Alert,
                            0,
                            b"client did not send its settings".to_vec(),
                        )?)
                        .await?;
                    return Ok(());
                }
                if !session.streams.lock().await.contains_key(&frame.stream_id) {
                    let stream = session.create_stream(frame.stream_id).await;
                    if let Some(callback) = &on_new_stream {
                        let callback = callback.clone();
                        tokio::spawn(async move {
                            callback(stream).await;
                        });
                    }
                }
            }
            Command::SynAck => {
                debug!(role = role_name(session.is_client), stream_id = frame.stream_id, ok = frame.data.is_empty(), "received synack");
                session.clear_syn_ack_timeout().await;
                if !frame.data.is_empty() {
                    session
                        .close_stream_locally(
                            frame.stream_id,
                            StreamCloseReason::RemoteError(format!(
                                "remote: {}",
                                String::from_utf8_lossy(&frame.data)
                            )),
                        )
                        .await;
                }
            }
            Command::Fin => {
                debug!(role = role_name(session.is_client), stream_id = frame.stream_id, "received fin");
                session
                    .close_stream_locally(frame.stream_id, StreamCloseReason::Closed)
                    .await;
            }
            Command::Waste => {}
            Command::Settings => {
                if !session.is_client {
                    received_settings_from_client = true;
                    let settings = StringMap::from_bytes(&frame.data);
                    info!(
                        role = role_name(session.is_client),
                        client_version = settings.get("v").unwrap_or("unknown"),
                        padding_md5 = settings.get("padding-md5").unwrap_or("missing"),
                        "received client settings"
                    );
                    let current_padding = padding.get().await;
                    if settings.get("padding-md5") != Some(current_padding.md5()) {
                        info!(padding_md5 = current_padding.md5(), "sending updated padding scheme to client");
                        session
                            .send_frame(Frame::new(
                                Command::UpdatePaddingScheme,
                                0,
                                current_padding.raw_scheme().to_vec(),
                            )?)
                            .await?;
                    }
                    if settings
                        .get("v")
                        .and_then(|value| value.parse::<u8>().ok())
                        .is_some_and(|version| version >= 2)
                    {
                        session.peer_version.store(2, Ordering::SeqCst);
                        info!(peer_version = 2, "enabling protocol v2 features for peer");
                        let mut server_settings = StringMap::new();
                        server_settings.insert("v", "2");
                        session
                            .send_frame(Frame::new(
                                Command::ServerSettings,
                                0,
                                server_settings.to_bytes(),
                            )?)
                            .await?;
                    }
                }
            }
            Command::Alert => {
                if session.is_client && !frame.data.is_empty() {
                    warn!(message = %String::from_utf8_lossy(&frame.data), "received alert from server");
                }
                return Ok(());
            }
            Command::UpdatePaddingScheme => {
                if session.is_client {
                    if let Some(factory) = PaddingFactory::new(&frame.data) {
                        info!(padding_md5 = factory.md5(), "updated client padding scheme from server");
                        padding.update(factory).await;
                    } else {
                        warn!("ignored invalid padding scheme from server");
                    }
                }
            }
            Command::HeartRequest => {
                debug!(role = role_name(session.is_client), stream_id = frame.stream_id, "received heart request");
                session
                    .send_frame(Frame::empty(Command::HeartResponse, frame.stream_id))
                    .await?;
            }
            Command::HeartResponse => {}
            Command::ServerSettings => {
                if session.is_client {
                    let settings = StringMap::from_bytes(&frame.data);
                    if let Some(version) = settings.get("v").and_then(|value| value.parse::<u8>().ok())
                    {
                        session.peer_version.store(version, Ordering::SeqCst);
                        info!(peer_version = version, "received server settings");
                    }
                }
            }
        }
    }
}

async fn write_loop<W>(
    mut writer: W,
    mut rx: mpsc::Receiver<WriterMessage>,
    send_padding: bool,
    padding: SharedPadding,
    session: Arc<SessionInner>,
) where
    W: AsyncWrite + Unpin,
{
    let mut state = PaddingWriteState {
        enabled: send_padding,
        packet_counter: 0,
        initial_buffering: send_padding,
        initial_buffer: Vec::new(),
    };

    while let Some(message) = rx.recv().await {
        match message {
            WriterMessage::Frame(frame) => {
                trace!(role = role_name(send_padding), command = ?frame.command, stream_id = frame.stream_id, data_len = frame.data.len(), "sending frame");
                let bytes = frame.encode();
                let should_buffer = state.initial_buffering
                    && matches!(frame.command, Command::Settings | Command::Syn);
                if should_buffer {
                    debug!(command = ?frame.command, stream_id = frame.stream_id, data_len = frame.data.len(), "buffering initial control frame for first padded record");
                    state.initial_buffer.extend_from_slice(&bytes);
                    continue;
                }

                let payload = if state.initial_buffer.is_empty() {
                    bytes
                } else {
                    state.initial_buffering = false;
                    let mut payload = std::mem::take(&mut state.initial_buffer);
                    payload.extend_from_slice(&bytes);
                    payload
                };

                let factory = padding.get().await;
                if write_conn(&mut writer, &payload, &mut state, &factory)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            WriterMessage::Close => break,
        }
    }

    let _ = writer.shutdown().await;
    session.mark_closed().await;
}

struct PaddingWriteState {
    enabled: bool,
    packet_counter: u32,
    initial_buffering: bool,
    initial_buffer: Vec<u8>,
}

async fn write_conn<W>(
    writer: &mut W,
    payload: &[u8],
    state: &mut PaddingWriteState,
    padding: &PaddingFactory,
) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if !state.enabled {
        writer.write_all(payload).await?;
        return Ok(payload.len());
    }

    state.packet_counter += 1;
    if state.packet_counter >= padding.stop() {
        state.enabled = false;
        writer.write_all(payload).await?;
        return Ok(payload.len());
    }

    let mut written_payload = 0;
    let mut remaining = payload;
    for size in padding.generate_record_payload_sizes(state.packet_counter) {
        if size == CHECK_MARK {
            if remaining.is_empty() {
                break;
            }
            continue;
        }
        let size = size.max(0) as usize;
        if remaining.len() > size {
            writer.write_all(&remaining[..size]).await?;
            written_payload += size;
            remaining = &remaining[size..];
        } else if !remaining.is_empty() {
            let remaining_len = remaining.len();
            let padding_len = size.saturating_sub(remaining_len + HEADER_SIZE);
            if padding_len > 0 {
                let mut with_padding = Vec::with_capacity(remaining_len + HEADER_SIZE + padding_len);
                with_padding.extend_from_slice(remaining);
                with_padding.extend_from_slice(&waste_frame(padding_len).map_err(io::Error::other)?);
                writer.write_all(&with_padding).await?;
            } else {
                writer.write_all(remaining).await?;
            }
            written_payload += remaining_len;
            remaining = &[];
        } else {
            writer
                .write_all(&waste_frame(size).map_err(io::Error::other)?)
                .await?;
        }
    }

    if !remaining.is_empty() {
        writer.write_all(remaining).await?;
        written_payload += remaining.len();
    }

    Ok(written_payload)
}

fn role_name(is_client: bool) -> &'static str {
    if is_client {
        "client"
    } else {
        "server"
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, sleep};

    use super::{Session, SharedPadding};
    use crate::frame::{Command, Frame};
    use crate::padding::PaddingFactory;
    use crate::settings::StringMap;

    #[tokio::test]
    async fn server_rejects_syn_before_settings() {
        let (mut client_io, server_io) = tokio::io::duplex(1024);
        let _server = Session::new_server(server_io, SharedPadding::default(), |_stream| async {}).await;

        client_io
            .write_all(&Frame::empty(Command::Syn, 1).encode())
            .await
            .unwrap();

        let frame = Frame::read_from(&mut client_io).await.unwrap();
        assert_eq!(frame.command, Command::Alert);
        assert_eq!(frame.data, b"client did not send its settings");
    }

    #[tokio::test]
    async fn server_replies_to_heart_request() {
        let (mut client_io, server_io) = tokio::io::duplex(1024);
        let _server = Session::new_server(server_io, SharedPadding::default(), |_stream| async {}).await;

        client_io
            .write_all(&Frame::empty(Command::HeartRequest, 99).encode())
            .await
            .unwrap();

        let frame = Frame::read_from(&mut client_io).await.unwrap();
        assert_eq!(frame.command, Command::HeartResponse);
        assert_eq!(frame.stream_id, 99);
        assert!(frame.data.is_empty());
    }

    #[tokio::test]
    async fn server_sends_padding_update_when_client_md5_differs() {
        let (mut client_io, server_io) = tokio::io::duplex(2048);
        let server_padding = PaddingFactory::new(b"stop=2\n0=1-1\n1=9-9").unwrap();
        let _server = Session::new_server(
            server_io,
            SharedPadding::new(server_padding.clone()),
            |_stream| async {},
        )
        .await;
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", "test-client");
        settings.insert("padding-md5", "different");

        client_io
            .write_all(
                &Frame::new(Command::Settings, 0, settings.to_bytes())
                    .unwrap()
                    .encode(),
            )
            .await
            .unwrap();

        let update = Frame::read_from(&mut client_io).await.unwrap();
        assert_eq!(update.command, Command::UpdatePaddingScheme);
        assert_eq!(update.data, server_padding.raw_scheme());
        let server_settings = Frame::read_from(&mut client_io).await.unwrap();
        assert_eq!(server_settings.command, Command::ServerSettings);
        assert_eq!(StringMap::from_bytes(&server_settings.data).get("v"), Some("2"));
    }

    #[tokio::test]
    async fn client_updates_shared_padding_from_server_command() {
        let (client_io, mut server_io) = tokio::io::duplex(2048);
        let shared_padding = SharedPadding::new(PaddingFactory::new(b"stop=1\n0=1-1").unwrap());
        let _client = Session::new_client(client_io, shared_padding.clone()).await.unwrap();
        let new_padding = PaddingFactory::new(b"stop=2\n0=3-3\n1=4-4").unwrap();

        server_io
            .write_all(
                &Frame::new(Command::UpdatePaddingScheme, 0, new_padding.raw_scheme().to_vec())
                    .unwrap()
                    .encode(),
            )
            .await
            .unwrap();
        sleep(Duration::from_millis(20)).await;

        assert_eq!(shared_padding.get().await.md5(), new_padding.md5());
    }

    #[tokio::test]
    async fn client_and_server_exchange_stream_data() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let padding = SharedPadding::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap());
        let _server = Session::new_server(server_io, padding.clone(), |mut stream| async move {
            stream.report_handshake_success().await.unwrap();
            let mut input = [0_u8; 4];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await;
        let client = Session::new_client(client_io, padding).await.unwrap();

        let mut stream = client.open_stream().await.unwrap();
        stream.write_all(b"ping").await.unwrap();

        let mut output = [0_u8; 4];
        stream.read_exact(&mut output).await.unwrap();

        assert_eq!(&output, b"pong");
    }

    #[tokio::test]
    async fn synack_error_is_returned_to_client_stream() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let padding = SharedPadding::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap());
        let _server = Session::new_server(server_io, padding.clone(), |stream| async move {
            stream
                .report_handshake_failure("dial tcp 127.0.0.1:1: connect: connection refused")
                .await
                .unwrap();
        })
        .await;
        let client = Session::new_client(client_io, padding).await.unwrap();

        let mut stream = client.open_stream().await.unwrap();
        let mut buf = [0_u8; 1];
        stream.write_all(b"x").await.unwrap();
        let read_err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out waiting for synack error")
            .unwrap_err();
        assert!(
            read_err
                .to_string()
                .contains("remote: dial tcp 127.0.0.1:1: connect: connection refused")
        );

        let err = stream.write_all(b"ping").await.unwrap_err();
        assert!(
            err.to_string().contains("remote: dial tcp 127.0.0.1:1: connect: connection refused")
        );
    }
}
