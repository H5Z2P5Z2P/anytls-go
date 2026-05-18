use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::AbortHandle;
use tokio::time::{Duration, sleep};
use tokio_util::sync::PollSender;
use tracing::{debug, info, trace, warn};

use crate::PROGRAM_VERSION_NAME;
use crate::error::{AnyTlsError, Result};
use crate::frame::{Command, Frame, HEADER_SIZE, MAX_FRAME_DATA_LEN, waste_frame_into};
use crate::padding::{CHECK_MARK, PaddingFactory};
use crate::settings::StringMap;

const STREAM_READ_CHUNK_SIZE: usize = 16 * 1024;
const STREAM_CHANNEL_SIZE: usize = 16;
const WRITER_QUEUE_SIZE: usize = 16;

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
    inbound: mpsc::Sender<Bytes>,
    state: Arc<StreamState>,
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
    inbound: mpsc::Receiver<Bytes>,
    read_buffer: Bytes,
    read_offset: usize,
    tx: PollSender<WriterMessage>,
    session: Arc<SessionInner>,
    state: Arc<StreamState>,
    report_once: Arc<AtomicBool>,
    shutdown_sent: bool,
    shutdown_in_progress: bool,
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
        match self
            .reason
            .lock()
            .expect("stream reason lock poisoned")
            .clone()
        {
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
        if self.read_offset < self.read_buffer.len() {
            let n = (self.read_buffer.len() - self.read_offset).min(buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + n]);
            self.read_offset += n;
            if self.read_offset == self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.inbound).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                if n > 0 {
                    buf.put_slice(&data[..n]);
                }
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_offset = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                if self.state.is_closed() {
                    Poll::Ready(Err(self.state.io_error()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => Poll::Pending,
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
        if self.shutdown_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is shut down",
            )));
        }
        if self.shutdown_in_progress {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is shutting down",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let len = buf.len().min(MAX_FRAME_DATA_LEN);
                let data = Bytes::copy_from_slice(&buf[..len]);
                let frame = Frame::new(Command::Psh, self.id, data).map_err(anytls_to_io_error)?;
                self.tx
                    .send_item(WriterMessage::Frame(frame))
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "session is closed"))?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session is closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_sent || self.session.closed.load(Ordering::SeqCst) {
            self.shutdown_sent = true;
            self.shutdown_in_progress = false;
            return Poll::Ready(Ok(()));
        }
        self.shutdown_in_progress = true;
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let id = self.id;
                self.tx
                    .send_item(WriterMessage::Frame(Frame::empty(Command::Fin, id)))
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "session is closed"))?;
                self.shutdown_sent = true;
                self.shutdown_in_progress = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                self.shutdown_sent = true;
                self.shutdown_in_progress = false;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.shutdown_sent
            || self.state.is_closed()
            || self.session.closed.load(Ordering::SeqCst)
        {
            return;
        }
        let _ = self
            .session
            .tx
            .try_send(WriterMessage::Frame(Frame::empty(Command::Fin, self.id)));
    }
}

fn anytls_to_io_error(err: AnyTlsError) -> io::Error {
    match err {
        AnyTlsError::Io(err) => err,
        other => io::Error::other(other),
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

    pub async fn new_server<T, F, Fut>(
        transport: T,
        padding: SharedPadding,
        on_new_stream: F,
    ) -> Self
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
        let (tx, rx) = mpsc::channel(WRITER_QUEUE_SIZE);
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

        tokio::spawn(write_loop(
            writer,
            rx,
            is_client,
            padding.clone(),
            inner.clone(),
        ));
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
        debug!(
            role = role_name(self.inner.is_client),
            stream_id = id,
            "opened stream"
        );
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
        let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
        let state = Arc::new(StreamState::new());

        let entry = StreamEntry {
            inbound: inbound_tx,
            state: state.clone(),
        };
        self.streams.lock().await.insert(id, entry);

        Stream {
            id,
            inbound: inbound_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            tx: PollSender::new(self.tx.clone()),
            session: self.clone(),
            state,
            report_once: Arc::new(AtomicBool::new(false)),
            shutdown_sent: false,
            shutdown_in_progress: false,
        }
    }

    async fn write_to_stream(&self, id: u32, data: Bytes) -> Result<()> {
        let writer = {
            let streams = self.streams.lock().await;
            streams.get(&id).map(|entry| entry.inbound.clone())
        };
        if let Some(writer) = writer {
            if writer.send(data).await.is_err() {
                self.streams.lock().await.remove(&id);
            }
        }
        Ok(())
    }

    async fn close_stream_locally(&self, id: u32, reason: StreamCloseReason) {
        let entry = self.streams.lock().await.remove(&id);
        if let Some(entry) = entry {
            debug!(
                role = role_name(self.is_client),
                stream_id = id,
                "closing local stream state"
            );
            entry.state.mark_closed(reason);
            drop(entry.inbound);
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
        info!(
            role = role_name(self.is_client),
            stream_count, "closing session"
        );
        let entries = streams.drain().collect::<Vec<_>>();
        drop(streams);
        self.clear_syn_ack_timeout().await;
        for (_, entry) in entries {
            entry.state.mark_closed(StreamCloseReason::Closed);
            drop(entry.inbound);
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
    let mut buffer = BytesMut::with_capacity(STREAM_READ_CHUNK_SIZE);

    loop {
        if buffer.len() < HEADER_SIZE {
            buffer.reserve(STREAM_READ_CHUNK_SIZE);
        }
        let n = reader.read_buf(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }

        while let Some(frame) = Frame::decode(&mut buffer)? {
            trace!(role = role_name(session.is_client), command = ?frame.command, stream_id = frame.stream_id, data_len = frame.data.len(), "received frame");
            let should_continue = handle_frame(
                session.clone(),
                &padding,
                &on_new_stream,
                &mut received_settings_from_client,
                frame,
            )
            .await?;
            if !should_continue {
                return Ok(());
            }
        }
    }
}

async fn handle_frame(
    session: Arc<SessionInner>,
    padding: &SharedPadding,
    on_new_stream: &Option<StreamCallback>,
    received_settings_from_client: &mut bool,
    frame: Frame,
) -> Result<bool> {
    match frame.command {
        Command::Psh => {
            if !frame.data.is_empty() {
                session.write_to_stream(frame.stream_id, frame.data).await?;
            }
        }
        Command::Syn => {
            debug!(
                role = role_name(session.is_client),
                stream_id = frame.stream_id,
                "received syn"
            );
            if !session.is_client && !*received_settings_from_client {
                session
                    .send_frame(Frame::new(
                        Command::Alert,
                        0,
                        Bytes::from_static(b"client did not send its settings"),
                    )?)
                    .await?;
                return Ok(false);
            }
            if !session.streams.lock().await.contains_key(&frame.stream_id) {
                let stream = session.create_stream(frame.stream_id).await;
                if let Some(callback) = on_new_stream {
                    let callback = callback.clone();
                    tokio::spawn(async move {
                        callback(stream).await;
                    });
                }
            }
        }
        Command::SynAck => {
            debug!(
                role = role_name(session.is_client),
                stream_id = frame.stream_id,
                ok = frame.data.is_empty(),
                "received synack"
            );
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
            debug!(
                role = role_name(session.is_client),
                stream_id = frame.stream_id,
                "received fin"
            );
            session
                .close_stream_locally(frame.stream_id, StreamCloseReason::Closed)
                .await;
        }
        Command::Waste => {}
        Command::Settings => {
            if !session.is_client {
                *received_settings_from_client = true;
                let settings = StringMap::from_bytes(&frame.data);
                info!(
                    role = role_name(session.is_client),
                    client_version = settings.get("v").unwrap_or("unknown"),
                    padding_md5 = settings.get("padding-md5").unwrap_or("missing"),
                    "received client settings"
                );
                let current_padding = padding.get().await;
                if settings.get("padding-md5") != Some(current_padding.md5()) {
                    info!(
                        padding_md5 = current_padding.md5(),
                        "sending updated padding scheme to client"
                    );
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
            return Ok(false);
        }
        Command::UpdatePaddingScheme => {
            if session.is_client {
                if let Some(factory) = PaddingFactory::new(&frame.data) {
                    info!(
                        padding_md5 = factory.md5(),
                        "updated client padding scheme from server"
                    );
                    padding.update(factory).await;
                } else {
                    warn!("ignored invalid padding scheme from server");
                }
            }
        }
        Command::HeartRequest => {
            debug!(
                role = role_name(session.is_client),
                stream_id = frame.stream_id,
                "received heart request"
            );
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
    Ok(true)
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
        padding_buffer: Vec::with_capacity(HEADER_SIZE + MAX_FRAME_DATA_LEN),
    };
    let mut write_buffer = Vec::with_capacity(HEADER_SIZE + MAX_FRAME_DATA_LEN);
    let mut header = [0_u8; HEADER_SIZE];

    while let Some(message) = rx.recv().await {
        match message {
            WriterMessage::Frame(frame) => {
                trace!(role = role_name(send_padding), command = ?frame.command, stream_id = frame.stream_id, data_len = frame.data.len(), "sending frame");
                if !state.enabled && state.initial_buffer.is_empty() {
                    if write_frame_unpadded(&mut writer, &frame, &mut header)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }

                write_buffer.clear();
                frame.encode_into(&mut write_buffer);
                let should_buffer = state.initial_buffering
                    && matches!(frame.command, Command::Settings | Command::Syn);
                if should_buffer {
                    debug!(command = ?frame.command, stream_id = frame.stream_id, data_len = frame.data.len(), "buffering initial control frame for first padded record");
                    state.initial_buffer.extend_from_slice(&write_buffer);
                    continue;
                }

                let mut combined_payload;
                let payload = if state.initial_buffer.is_empty() {
                    write_buffer.as_slice()
                } else {
                    state.initial_buffering = false;
                    combined_payload = std::mem::take(&mut state.initial_buffer);
                    combined_payload.extend_from_slice(&write_buffer);
                    combined_payload.as_slice()
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

async fn write_frame_unpadded<W>(
    writer: &mut W,
    frame: &Frame,
    header: &mut [u8; HEADER_SIZE],
) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    *header = frame.encode_header();
    let mut header_pos = 0;
    let mut data_pos = 0;

    while header_pos < HEADER_SIZE || data_pos < frame.data.len() {
        let mut slices = [IoSlice::new(&[]), IoSlice::new(&[])];
        let mut count = 0;
        if header_pos < HEADER_SIZE {
            slices[count] = IoSlice::new(&header[header_pos..]);
            count += 1;
        }
        if data_pos < frame.data.len() {
            slices[count] = IoSlice::new(&frame.data[data_pos..]);
            count += 1;
        }

        let mut written = writer.write_vectored(&slices[..count]).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write frame",
            ));
        }

        if header_pos < HEADER_SIZE {
            let header_written = written.min(HEADER_SIZE - header_pos);
            header_pos += header_written;
            written -= header_written;
        }
        if written > 0 {
            data_pos += written.min(frame.data.len() - data_pos);
        }
    }

    Ok(frame.data.len())
}

struct PaddingWriteState {
    enabled: bool,
    packet_counter: u32,
    initial_buffering: bool,
    initial_buffer: Vec<u8>,
    padding_buffer: Vec<u8>,
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
                state.padding_buffer.clear();
                state
                    .padding_buffer
                    .reserve(remaining_len + HEADER_SIZE + padding_len);
                state.padding_buffer.extend_from_slice(remaining);
                waste_frame_into(&mut state.padding_buffer, padding_len)
                    .map_err(io::Error::other)?;
                writer.write_all(&state.padding_buffer).await?;
            } else {
                writer.write_all(remaining).await?;
            }
            written_payload += remaining_len;
            remaining = &[];
        } else {
            state.padding_buffer.clear();
            waste_frame_into(&mut state.padding_buffer, size).map_err(io::Error::other)?;
            writer.write_all(&state.padding_buffer).await?;
        }
    }

    if !remaining.is_empty() {
        writer.write_all(remaining).await?;
        written_payload += remaining.len();
    }

    Ok(written_payload)
}

fn role_name(is_client: bool) -> &'static str {
    if is_client { "client" } else { "server" }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Mutex, mpsc, watch};
    use tokio::time::{Duration, sleep, timeout};
    use tokio_util::sync::PollSender;

    use super::{Session, SessionInner, SharedPadding, Stream, StreamState, WriterMessage};
    use crate::frame::{Command, Frame, MAX_FRAME_DATA_LEN};
    use crate::padding::PaddingFactory;
    use crate::settings::StringMap;

    fn test_stream_with_writer_capacity(
        capacity: usize,
    ) -> (Stream, mpsc::Receiver<WriterMessage>) {
        let (tx, rx) = mpsc::channel(capacity);
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (closed_tx, _) = watch::channel(false);
        let session = Arc::new(SessionInner {
            tx: tx.clone(),
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(0),
            seq: AtomicU64::new(0),
            peer_version: AtomicU8::new(2),
            pending_syn_ack: Mutex::new(None),
            is_client: true,
            closed: AtomicBool::new(false),
            closed_tx,
        });
        let state = Arc::new(StreamState::new());
        let stream = Stream {
            id: 1,
            inbound: inbound_rx,
            read_buffer: Default::default(),
            read_offset: 0,
            tx: PollSender::new(tx),
            session,
            state,
            report_once: Arc::new(AtomicBool::new(false)),
            shutdown_sent: false,
            shutdown_in_progress: false,
        };

        (stream, rx)
    }

    #[tokio::test]
    async fn stream_write_waits_for_writer_capacity() {
        let (mut stream, mut rx) = test_stream_with_writer_capacity(1);

        stream.write_all(b"one").await.unwrap();

        assert!(
            timeout(Duration::from_millis(50), stream.write_all(b"two"))
                .await
                .is_err()
        );

        let WriterMessage::Frame(frame) = rx.recv().await.unwrap() else {
            panic!("expected frame")
        };
        assert_eq!(frame.command, Command::Psh);
        assert_eq!(&frame.data[..], b"one");

        stream.write_all(b"two").await.unwrap();
        let WriterMessage::Frame(frame) = rx.recv().await.unwrap() else {
            panic!("expected frame")
        };
        assert_eq!(&frame.data[..], b"two");
    }

    #[tokio::test]
    async fn stream_shutdown_blocks_late_writes_until_fin_is_queued() {
        let (mut stream, mut rx) = test_stream_with_writer_capacity(1);

        stream.write_all(b"queued").await.unwrap();

        assert!(
            timeout(Duration::from_millis(50), stream.shutdown())
                .await
                .is_err()
        );

        let err = stream.write_all(b"late").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(err.to_string(), "stream is shutting down");

        let _ = rx.recv().await.unwrap();
        stream.shutdown().await.unwrap();

        let WriterMessage::Frame(frame) = rx.recv().await.unwrap() else {
            panic!("expected frame")
        };
        assert_eq!(frame.command, Command::Fin);
        assert!(frame.data.is_empty());
    }

    #[tokio::test]
    async fn stream_write_caps_payload_at_frame_limit() {
        let (mut stream, mut rx) = test_stream_with_writer_capacity(1);
        let payload = vec![7_u8; MAX_FRAME_DATA_LEN + 9];

        let written = stream.write(&payload).await.unwrap();

        assert_eq!(written, MAX_FRAME_DATA_LEN);
        let WriterMessage::Frame(frame) = rx.recv().await.unwrap() else {
            panic!("expected frame")
        };
        assert_eq!(frame.command, Command::Psh);
        assert_eq!(frame.data.len(), MAX_FRAME_DATA_LEN);
    }

    #[tokio::test]
    async fn empty_stream_write_does_not_queue_frame() {
        let (mut stream, mut rx) = test_stream_with_writer_capacity(1);

        let written = stream.write(&[]).await.unwrap();

        assert_eq!(written, 0);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn server_rejects_syn_before_settings() {
        let (mut client_io, server_io) = tokio::io::duplex(1024);
        let _server =
            Session::new_server(server_io, SharedPadding::default(), |_stream| async {}).await;

        client_io
            .write_all(&Frame::empty(Command::Syn, 1).encode())
            .await
            .unwrap();

        let frame = Frame::read_from(&mut client_io).await.unwrap();
        assert_eq!(frame.command, Command::Alert);
        assert_eq!(&frame.data[..], b"client did not send its settings");
    }

    #[tokio::test]
    async fn server_replies_to_heart_request() {
        let (mut client_io, server_io) = tokio::io::duplex(1024);
        let _server =
            Session::new_server(server_io, SharedPadding::default(), |_stream| async {}).await;

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
        assert_eq!(
            StringMap::from_bytes(&server_settings.data).get("v"),
            Some("2")
        );
    }

    #[tokio::test]
    async fn client_updates_shared_padding_from_server_command() {
        let (client_io, mut server_io) = tokio::io::duplex(2048);
        let shared_padding = SharedPadding::new(PaddingFactory::new(b"stop=1\n0=1-1").unwrap());
        let _client = Session::new_client(client_io, shared_padding.clone())
            .await
            .unwrap();
        let new_padding = PaddingFactory::new(b"stop=2\n0=3-3\n1=4-4").unwrap();

        server_io
            .write_all(
                &Frame::new(
                    Command::UpdatePaddingScheme,
                    0,
                    new_padding.raw_scheme().to_vec(),
                )
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
            err.to_string()
                .contains("remote: dial tcp 127.0.0.1:1: connect: connection refused")
        );
    }
}
