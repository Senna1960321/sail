//! A session: many streams over one authenticated TLS connection, carried
//! by the stream core (`transport::muxcore`) as AnyTLS frames them.
//!
//! AnyTLS has no window. What a stream receives waits in its inbox, and
//! while one inbox holds `mux.stream_buffer` unread the session stops
//! reading the connection, which holds the peer back; a stream nothing
//! reads is reset in `mux.stall_timeout`, alone. The reader never waits for
//! a stream, as the reference implementation's did: one stream's consumer
//! stalled its whole session, and missed a client's reset. Control frames
//! -- `SYNACK`, heartbeats, settings -- go out ahead of stream data. The
//! client pads its first writes as the padding scheme says (`Padder`).
//!
//! A stream closes whole: `FIN` tells the peer to close its end without
//! answering, so a stream that has sent one reads no further either, and
//! one that has received one writes no further.

use portable_atomic::AtomicU64;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::adapter::AnyStream;
use crate::transport::muxcore::{
    self, Closing, Codec, Decoder, Event, Flow, Framing, Shaper, Tuning,
};

use super::frame::{self, *};
use super::padding::{string_map, PaddingScheme, Size};

/// The padding scheme a client uses, which its server may replace. Shared
/// by all of the client's sessions.
pub type PaddingCell = Arc<RwLock<Arc<PaddingScheme>>>;

/// The most a stream writes into one frame. Smaller than a frame could be,
/// so that the write queue stays small.
const MAX_WRITE: usize = 16 * 1024;
/// Streams open at once on one session. A server refuses more.
pub const MAX_STREAMS: usize = muxcore::MAX_STREAMS;
/// How long a client waits for a `SYNACK` on a reused session before it
/// takes the session to be stuck, as the reference client does.
const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Which end a session is, with its padding scheme.
enum Role {
    Client { padding: PaddingCell },
    Server { padding: Arc<PaddingScheme> },
}

/// What the frames, their decoder and the session share.
struct Proto {
    role: Role,
    peer_version: AtomicU8,
    /// Bumped by every `SYNACK`, so that a pending timeout can tell whether
    /// one has come since it was armed.
    synack_generation: AtomicU64,
    /// The stream whose `SYNACK` did not come in time, which closed the
    /// session: 0 for none.
    synack_missed: AtomicU32,
    /// The client's settings, sent with its first stream.
    settings: Mutex<Option<BytesMut>>,
}

/// AnyTLS's frames, for the core.
struct AnyTls(Arc<Proto>);

impl Codec for AnyTls {
    fn name(&self) -> &'static str {
        "anytls"
    }

    fn flow(&self) -> Flow {
        Flow::Pause
    }

    fn closing(&self) -> Closing {
        Closing::Whole
    }

    fn max_data(&self) -> usize {
        MAX_WRITE
    }

    fn first_id(&self, _server: bool) -> u32 {
        1
    }

    fn id_step(&self) -> u32 {
        1
    }

    /// Settings with the first stream, `SYN` and the destination go out
    /// as one write, which is what the padding scheme counts as the first.
    fn open(&self, id: u32, first: &[u8]) -> Bytes {
        let mut unit = self
            .0
            .settings
            .lock()
            .ok()
            .and_then(|mut s| s.take())
            .unwrap_or_default();
        frame::put(&mut unit, CMD_SYN, id, &[]);
        frame::put(&mut unit, CMD_PSH, id, first);
        unit.freeze()
    }

    fn refuse(&self, id: u32) -> Bytes {
        frame::encode(CMD_FIN, id, &[]).freeze()
    }

    fn data(&self, id: u32, data: &[u8]) -> Bytes {
        frame::encode(CMD_PSH, id, data).freeze()
    }

    fn fin(&self, id: u32) -> Bytes {
        frame::encode(CMD_FIN, id, &[]).freeze()
    }

    fn reset(&self, id: u32) -> Bytes {
        frame::encode(CMD_FIN, id, &[]).freeze()
    }

    fn decoder(&self, _server: bool) -> Box<dyn Decoder> {
        Box::new(AnyTlsDecoder {
            proto: self.0.clone(),
            settings_received: false,
            framing: Framing::default(),
            events: VecDeque::new(),
        })
    }

    fn shaper(&self) -> Option<Box<dyn Shaper>> {
        match &self.0.role {
            Role::Client { padding } => Some(Box::new(Padder {
                padding: padding.clone(),
                pkt: 0,
                done: false,
            })),
            Role::Server { .. } => None,
        }
    }
}

struct AnyTlsDecoder {
    proto: Arc<Proto>,
    settings_received: bool,
    framing: Framing,
    /// Events a frame gave beyond the first.
    events: VecDeque<Event>,
}

impl AnyTlsDecoder {
    /// What a control frame with data asks, now that all of it is in.
    fn control(&mut self, cmd: u8, sid: u32, data: &[u8]) -> Option<Event> {
        match (cmd, &self.proto.role) {
            (CMD_SYNACK, Role::Client { .. }) => Some(Event::Refused(
                sid,
                format!("anytls server: {}", String::from_utf8_lossy(data)),
            )),
            // A client sends its settings once, at the start of the
            // session, as the reference client does: later ones are
            // dropped unanswered, so that a peer cannot have the scheme
            // sent over and over.
            (CMD_SETTINGS, Role::Server { .. }) if self.settings_received => None,
            (CMD_SETTINGS, Role::Server { padding }) => {
                self.settings_received = true;
                let settings = string_map(data);
                if settings.get("padding-md5").map(String::as_str) != Some(padding.md5()) {
                    self.events.push_back(Event::Reply(
                        frame::encode(CMD_UPDATE_PADDING_SCHEME, 0, padding.raw()).freeze(),
                    ));
                }
                if let Some(v) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                    if v >= 2 {
                        self.proto.peer_version.store(v, Ordering::Relaxed);
                        let settings = frame::settings(&[("v", &VERSION.to_string())]);
                        self.events.push_back(Event::Reply(
                            frame::encode(CMD_SERVER_SETTINGS, 0, &settings).freeze(),
                        ));
                    }
                }
                None
            }
            (CMD_ALERT, role) => {
                let alert = String::from_utf8_lossy(data).into_owned();
                if let Role::Client { .. } = role {
                    warn!("anytls alert from server: {}", alert);
                }
                Some(Event::Close(format!("alert: {}", alert)))
            }
            (CMD_UPDATE_PADDING_SCHEME, Role::Client { padding }) => {
                match PaddingScheme::parse(data) {
                    Some(scheme) => {
                        debug!("anytls padding scheme updated to {}", scheme.md5());
                        if let Ok(mut current) = padding.write() {
                            *current = Arc::new(scheme);
                        }
                    }
                    None => warn!(
                        "anytls server sent a padding scheme that does not parse or is past the bounds; the current one stays"
                    ),
                }
                None
            }
            (CMD_SERVER_SETTINGS, Role::Client { .. }) => {
                let settings = string_map(data);
                if let Some(v) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                    self.proto.peer_version.store(v, Ordering::Relaxed);
                }
                None
            }
            _ => None,
        }
    }
}

impl Decoder for AnyTlsDecoder {
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if let Some(next) = self.framing.next(buf) {
                return Ok(next);
            }
            if buf.len() < HEADER_LEN {
                return Ok(None);
            }
            let mut raw = [0u8; HEADER_LEN];
            raw.copy_from_slice(&buf[..HEADER_LEN]);
            let header = Header::decode(&raw);
            let (sid, len) = (header.sid, header.len as usize);
            if len > 0 && carries_no_data(header.cmd) {
                // The reference reads such data as frames. What follows
                // could not be told from frames, so the session ends.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "anytls: command {} carries {} bytes of data, and takes none",
                        header.cmd, len
                    ),
                ));
            }
            match header.cmd {
                CMD_PSH => {
                    buf.advance(HEADER_LEN);
                    self.framing.frame(&[], Some((sid, len)), &[]);
                }
                CMD_WASTE => {
                    buf.advance(HEADER_LEN);
                    self.framing.skip(len);
                }
                CMD_SYN => {
                    buf.advance(HEADER_LEN);
                    if let Role::Server { .. } = self.proto.role {
                        if !self.settings_received {
                            let why = "client did not send its settings";
                            self.events.push_back(Event::Reply(
                                frame::encode(CMD_ALERT, 0, why.as_bytes()).freeze(),
                            ));
                            self.events.push_back(Event::Close(why.to_string()));
                        } else {
                            self.events.push_back(Event::Open(sid));
                        }
                    }
                }
                CMD_FIN => {
                    buf.advance(HEADER_LEN);
                    self.events.push_back(Event::Fin(sid));
                }
                CMD_HEART_REQUEST => {
                    buf.advance(HEADER_LEN);
                    self.events.push_back(Event::Reply(
                        frame::encode(CMD_HEART_RESPONSE, sid, &[]).freeze(),
                    ));
                }
                CMD_SYNACK
                | CMD_SETTINGS
                | CMD_ALERT
                | CMD_UPDATE_PADDING_SCHEME
                | CMD_SERVER_SETTINGS => {
                    // A `SYNACK` is the server's to send: a server reads
                    // one and drops it.
                    if header.cmd == CMD_SYNACK && matches!(self.proto.role, Role::Client { .. }) {
                        self.proto.synack_generation.fetch_add(1, Ordering::Relaxed);
                    }
                    if len == 0 {
                        buf.advance(HEADER_LEN);
                        continue;
                    }
                    // Whole, and small: a frame's length is 16 bits.
                    if buf.len() < HEADER_LEN + len {
                        return Ok(None);
                    }
                    buf.advance(HEADER_LEN);
                    let data = buf.split_to(len);
                    if let Some(event) = self.control(header.cmd, sid, &data) {
                        self.events.push_back(event);
                    }
                }
                // Heartbeat answers carry no data (checked above). An
                // unknown command's data, if it has any, is skipped, so
                // that the frames after it are read as frames.
                _ => {
                    buf.advance(HEADER_LEN);
                    self.framing.skip(len);
                }
            }
        }
    }
}

/// Whether `cmd` is one whose frames never carry data: a stream's opening
/// and end, and the heartbeats.
fn carries_no_data(cmd: u8) -> bool {
    matches!(
        cmd,
        CMD_SYN | CMD_FIN | CMD_HEART_REQUEST | CMD_HEART_RESPONSE
    )
}

/// Pads a client's first writes, as the padding scheme says.
struct Padder {
    padding: PaddingCell,
    /// Writes so far; the authentication before the session was the 0th.
    pkt: u32,
    done: bool,
}

impl Shaper for Padder {
    fn active(&mut self) -> bool {
        !self.done
    }

    fn shape(&mut self, write: BytesMut) -> Vec<BytesMut> {
        self.pkt = self.pkt.wrapping_add(1);
        let scheme = match self.padding.read() {
            Ok(scheme) => scheme.clone(),
            Err(_) => {
                self.done = true;
                return vec![write];
            }
        };
        if self.pkt < scheme.stop() {
            return pad(write, &scheme.sizes(self.pkt));
        }
        self.done = true;
        vec![write]
    }
}

/// The records `unit` is written in, as `writeConn` in the reference
/// writes them: payload first, padded out with waste frames where the
/// payload runs short.
fn pad(mut unit: BytesMut, sizes: &[Size]) -> Vec<BytesMut> {
    let mut records = Vec::new();
    for size in sizes {
        let record = match *size {
            Size::Check if unit.is_empty() => break,
            Size::Check => continue,
            Size::Record(n) => n,
        };
        let remaining = unit.len();
        if remaining > record {
            records.push(unit.split_to(record));
        } else if remaining > 0 {
            let padding = record as isize - remaining as isize - HEADER_LEN as isize;
            if padding > 0 {
                unit.extend_from_slice(&frame::waste(padding as usize));
            }
            records.push(unit.split());
        } else {
            records.push(frame::waste(record));
        }
    }
    if !unit.is_empty() {
        records.push(unit);
    }
    records
}

pub struct Session {
    core: muxcore::Session,
    proto: Arc<Proto>,
}

impl Session {
    /// A client session over `conn`, which has been authenticated.
    pub fn client(
        conn: AnyStream,
        padding: PaddingCell,
        tuning: Tuning,
        label: &str,
    ) -> Arc<Session> {
        let md5 = padding
            .read()
            .map(|p| p.md5().to_string())
            .unwrap_or_default();
        let settings = frame::encode(
            CMD_SETTINGS,
            0,
            &frame::settings(&[
                ("v", &VERSION.to_string()),
                ("client", CLIENT_NAME),
                ("padding-md5", &md5),
            ]),
        );
        Self::start(
            conn,
            Role::Client { padding },
            Some(settings),
            tuning,
            label,
        )
        .0
    }

    /// A server session over `conn`, which has been authenticated, and
    /// the streams the client opens on it.
    pub fn server(
        conn: AnyStream,
        padding: Arc<PaddingScheme>,
        tuning: Tuning,
        label: &str,
    ) -> (Arc<Session>, mpsc::UnboundedReceiver<muxcore::Stream>) {
        let (session, accept) = Self::start(conn, Role::Server { padding }, None, tuning, label);
        // A server's session always has somewhere to put streams.
        (
            session,
            accept.unwrap_or_else(|| mpsc::unbounded_channel().1),
        )
    }

    fn start(
        conn: AnyStream,
        role: Role,
        settings: Option<BytesMut>,
        tuning: Tuning,
        label: &str,
    ) -> (
        Arc<Session>,
        Option<mpsc::UnboundedReceiver<muxcore::Stream>>,
    ) {
        let server = matches!(role, Role::Server { .. });
        let proto = Arc::new(Proto {
            role,
            peer_version: AtomicU8::new(0),
            synack_generation: AtomicU64::new(0),
            synack_missed: AtomicU32::new(0),
            settings: Mutex::new(settings),
        });
        let (core, accept) =
            muxcore::Session::new(conn, Arc::new(AnyTls(proto.clone())), server, tuning, label);
        (Arc::new(Session { core, proto }), accept)
    }

    pub fn is_closed(&self) -> bool {
        self.core.is_closed()
    }

    /// Whether a new stream may go on the session: it is not closed, and
    /// no stream on it ended while the server was still sending it.
    pub fn is_reusable(&self) -> bool {
        self.core.is_reusable()
    }

    pub fn close(&self) {
        self.core.close();
    }

    /// A stream the client opened, as the server hands it out.
    pub fn stream(self: &Arc<Self>, inner: muxcore::Stream) -> Stream {
        Stream {
            inner,
            session: self.clone(),
            on_drop: OnDrop(None),
        }
    }

    /// Opens a stream whose first data is `first`: the destination, and
    /// whatever else is known to follow it.
    pub async fn open_stream(self: &Arc<Self>, first: &[u8]) -> io::Result<Stream> {
        let inner = self.core.open_with(first).await?;
        if inner.id() >= 2 && self.proto.peer_version.load(Ordering::Relaxed) >= 2 {
            self.watch_synack(inner.id());
        }
        Ok(self.stream(inner))
    }

    /// Closes the session unless a `SYNACK` arrives in time: a reused
    /// session that has gone quiet is taken to be stuck. Stream `id`, which
    /// waits for it, hears that it was why (`Stream::synack_missed`).
    fn watch_synack(self: &Arc<Self>, id: u32) {
        let generation = self
            .proto
            .synack_generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let session = Arc::downgrade(self);
        crate::runtime::scope::spawn("anytls synack watch", async move {
            tokio::time::sleep(SYNACK_TIMEOUT).await;
            if let Some(session) = session.upgrade() {
                let current = session.proto.synack_generation.load(Ordering::Relaxed);
                if current == generation && !session.is_closed() {
                    debug!("anytls session got no SYNACK in time, closing it");
                    session.proto.synack_missed.store(id, Ordering::Relaxed);
                    session.close();
                }
            }
        });
    }
}

/// Run when a stream is gone: how a client puts its session back.
struct OnDrop(Option<Box<dyn FnOnce() + Send + Sync>>);

impl Drop for OnDrop {
    fn drop(&mut self) {
        if let Some(on_drop) = self.0.take() {
            on_drop();
        }
    }
}

/// One stream of a session.
pub struct Stream {
    // Dropped first: the stream is done before its session is put back.
    inner: muxcore::Stream,
    session: Arc<Session>,
    on_drop: OnDrop,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    pub fn set_on_drop(&mut self, on_drop: Box<dyn FnOnce() + Send + Sync>) {
        self.on_drop = OnDrop(Some(on_drop));
    }

    /// Whether the session was closed because this stream's `SYNACK` did
    /// not come in time.
    pub fn synack_missed(&self) -> bool {
        self.session.proto.synack_missed.load(Ordering::Relaxed) == self.id()
    }

    /// Tells a version 2 client whether the stream opened: `None` for
    /// success, or the error.
    pub async fn report(&self, error: Option<&str>) -> io::Result<()> {
        if self.session.proto.peer_version.load(Ordering::Relaxed) < 2 {
            return Ok(());
        }
        let data = error.map(str::as_bytes).unwrap_or_default();
        let data = &data[..data.len().min(MAX_DATA)];
        self.inner
            .send_control(frame::encode(CMD_SYNACK, self.id(), data).freeze())
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The length of the password's SHA-256 a client starts with.
pub const AUTH_HASH_LEN: usize = 32;

/// Reads the rest of the authentication a client starts with, after the
/// password's SHA-256: the padding's length, and the padding.
pub async fn read_auth_padding<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let len = r.read_u16().await? as u64;
    let skipped = tokio::io::copy(&mut r.take(len), &mut tokio::io::sink()).await?;
    if skipped != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// The authentication a client starts with.
pub fn auth(hash: &[u8; 32], padding: usize) -> Vec<u8> {
    let padding = padding.min(u16::MAX as usize);
    let mut buf = Vec::with_capacity(32 + 2 + padding);
    buf.extend_from_slice(hash);
    buf.extend_from_slice(&(padding as u16).to_be_bytes());
    buf.resize(32 + 2 + padding, 0);
    buf
}

/// Fuzzing (sail::fuzzing): what a peer sends an AnyTLS end. A padding
/// scheme as a server pushes it, read, drawn from and used to pad a write;
/// and the bytes of a session as each end's decoder takes them, in
/// pieces.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    if let Some(scheme) = PaddingScheme::parse(data) {
        let _ = scheme.auth_padding();
        for pkt in 0..scheme.stop().min(16) {
            let unit = BytesMut::from(&data[..data.len().min(300)]);
            let written: usize = pad(unit, &scheme.sizes(pkt))
                .iter()
                .map(BytesMut::len)
                .sum();
            assert!(written >= data.len().min(300), "padding lost payload");
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = PaddingScheme::parse_strict(text);
    }
    let _ = string_map(data);
    let _ = futures::FutureExt::now_or_never(read_auth_padding(&mut &data[..]));
    let step = 1 + usize::from(data.first().copied().unwrap_or(0) % 97);
    for server in [false, true] {
        let role = if server {
            Role::Server {
                padding: Arc::new(PaddingScheme::default_scheme()),
            }
        } else {
            Role::Client {
                padding: Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme()))),
            }
        };
        let proto = Arc::new(Proto {
            role,
            peer_version: AtomicU8::new(0),
            synack_generation: AtomicU64::new(0),
            synack_missed: AtomicU32::new(0),
            settings: Mutex::new(None),
        });
        let mut decoder = AnyTls(proto).decoder(server);
        let mut buf = BytesMut::new();
        'feed: for chunk in data.chunks(step) {
            buf.extend_from_slice(chunk);
            // A frame gives a few events at most: the bound only stops a
            // decoder that would give them for ever.
            for _ in 0..chunk.len() + 64 {
                match decoder.decode(&mut buf) {
                    Ok(Some(_)) => {}
                    Ok(None) => continue 'feed,
                    Err(_) => break 'feed,
                }
            }
            panic!("the decoder gives events without end");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn cell() -> PaddingCell {
        Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme())))
    }

    /// A decoder for a server with the default scheme, or for a client
    /// whose scheme is in `padding`.
    fn decoder(server: bool, padding: &PaddingCell) -> Box<dyn Decoder> {
        let role = if server {
            Role::Server {
                padding: Arc::new(PaddingScheme::default_scheme()),
            }
        } else {
            Role::Client {
                padding: padding.clone(),
            }
        };
        AnyTls(Arc::new(Proto {
            role,
            peer_version: AtomicU8::new(0),
            synack_generation: AtomicU64::new(0),
            synack_missed: AtomicU32::new(0),
            settings: Mutex::new(None),
        }))
        .decoder(server)
    }

    /// What a decoder makes of `wire`, up to its first error.
    fn events(decoder: &mut dyn Decoder, wire: &[u8]) -> io::Result<Vec<Event>> {
        let mut buf = BytesMut::from(wire);
        let mut events = Vec::new();
        while let Some(event) = decoder.decode(&mut buf)? {
            events.push(event);
        }
        Ok(events)
    }

    /// A client's settings, with a padding md5 no scheme has.
    fn client_settings() -> BytesMut {
        frame::encode(
            CMD_SETTINGS,
            0,
            &frame::settings(&[("v", "2"), ("padding-md5", "0")]),
        )
    }

    /// `SYN`, `FIN` and the heartbeats carry no data. One that comes with
    /// some ends the session at either end, rather than have its data read
    /// as frames.
    #[test]
    fn a_frame_that_takes_no_data_and_carries_some_is_refused() {
        for (server, cmd) in [
            (true, CMD_SYN),
            (true, CMD_FIN),
            (true, CMD_HEART_REQUEST),
            (true, CMD_HEART_RESPONSE),
            (false, CMD_FIN),
            (false, CMD_HEART_REQUEST),
            (false, CMD_HEART_RESPONSE),
        ] {
            let mut decoder = decoder(server, &cell());
            let mut wire = client_settings();
            wire.extend_from_slice(&frame::encode(cmd, 1, b"abc"));
            wire.extend_from_slice(&frame::encode(CMD_PSH, 1, b"hi"));
            let result = events(decoder.as_mut(), &wire);
            assert!(result.is_err(), "{} {}: {:?}", server, cmd, result);
        }
    }

    /// An unknown command's data is skipped: the frames after it are still
    /// frames.
    #[test]
    fn an_unknown_commands_data_is_skipped() {
        let mut decoder = decoder(false, &cell());
        let mut wire = frame::encode(42, 0, b"abcdefghij");
        wire.extend_from_slice(&frame::encode(CMD_PSH, 1, b"hi"));
        let events = events(decoder.as_mut(), &wire).unwrap();
        assert_eq!(events, vec![Event::Data(1, Bytes::from_static(b"hi"))]);
    }

    /// A `SYNACK` is the server's: one a client sends, with an error or
    /// without, fails no stream of the server's.
    #[test]
    fn a_server_drops_a_synack() {
        let mut decoder = decoder(true, &cell());
        let mut wire = client_settings();
        wire.extend_from_slice(&frame::encode(CMD_SYN, 1, &[]));
        wire.extend_from_slice(&frame::encode(CMD_SYNACK, 1, b"refused"));
        wire.extend_from_slice(&frame::encode(CMD_SYNACK, 1, &[]));
        let events = events(decoder.as_mut(), &wire).unwrap();
        assert!(events.contains(&Event::Open(1)), "{:?}", events);
        assert!(
            !events.iter().any(|e| matches!(e, Event::Refused(..))),
            "{:?}",
            events
        );
    }

    /// Settings after the first are dropped unanswered: the scheme and the
    /// server's settings go out once a session.
    #[test]
    fn a_server_answers_the_first_settings_only() {
        let mut decoder = decoder(true, &cell());
        let mut wire = BytesMut::new();
        for _ in 0..3 {
            wire.extend_from_slice(&client_settings());
        }
        wire.extend_from_slice(&frame::encode(CMD_SYN, 1, &[]));
        wire.extend_from_slice(&client_settings());
        let events = events(decoder.as_mut(), &wire).unwrap();
        let replies: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                Event::Reply(frame) => Some(frame[0]),
                _ => None,
            })
            .collect();
        assert_eq!(
            replies,
            vec![CMD_UPDATE_PADDING_SCHEME, CMD_SERVER_SETTINGS]
        );
        assert!(events.contains(&Event::Open(1)), "{:?}", events);
    }

    /// A scheme past the bounds leaves a client with the one it has.
    #[test]
    fn a_client_keeps_its_scheme_over_one_past_the_bounds() {
        let padding = cell();
        let mut decoder = decoder(false, &padding);
        let wire = frame::encode(CMD_UPDATE_PADDING_SCHEME, 0, b"stop=100000\n1=100-200");
        events(decoder.as_mut(), &wire).unwrap();
        assert_eq!(padding.read().unwrap().stop(), 8);
        let wire = frame::encode(CMD_UPDATE_PADDING_SCHEME, 0, b"stop=3\n1=100-200");
        events(decoder.as_mut(), &wire).unwrap();
        assert_eq!(padding.read().unwrap().stop(), 3);
    }

    #[test]
    fn auth_round_trips() {
        runtime().block_on(async {
            let hash = [7u8; 32];
            let raw = auth(&hash, 30);
            assert_eq!(raw.len(), 64);
            assert_eq!(raw[..AUTH_HASH_LEN], hash);
            let mut r = &raw[AUTH_HASH_LEN..];
            read_auth_padding(&mut r).await.unwrap();
            assert!(r.is_empty());
        });
    }

    #[test]
    fn padded_writes_follow_the_sizes() {
        let lens = |records: Vec<BytesMut>| records.iter().map(BytesMut::len).collect::<Vec<_>>();
        // Payload longer than the first record, then padded out: 20 bytes,
        // then 10 bytes and a waste frame of 40 - 10 - 7.
        let records = pad(
            BytesMut::from(&[1u8; 30][..]),
            &[Size::Record(20), Size::Record(40)],
        );
        assert_eq!(records[1][10], CMD_WASTE);
        assert_eq!(lens(records), vec![20, 10 + HEADER_LEN + 23]);

        // Nothing left at a check: stop.
        let records = pad(
            BytesMut::from(&[1u8; 5][..]),
            &[Size::Record(100), Size::Check, Size::Record(100)],
        );
        assert_eq!(lens(records), vec![100]);

        // No payload at all before a record: all padding.
        let records = pad(BytesMut::new(), &[Size::Record(9)]);
        assert_eq!(lens(records), vec![HEADER_LEN + 9]);
    }

    /// A client and a server session over a pipe, the server echoing every
    /// stream.
    #[test]
    fn sessions_carry_streams_both_ways() {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let (server, mut accept) = Session::server(
                Box::new(b),
                Arc::new(PaddingScheme::parse(b"stop=1").unwrap()),
                Tuning::default(),
                "test",
            );
            let echo = server.clone();
            tokio::spawn(async move {
                while let Some(stream) = accept.recv().await {
                    let mut stream = echo.stream(stream);
                    tokio::spawn(async move {
                        stream.report(None).await.unwrap();
                        let mut buf = vec![0u8; 4096];
                        loop {
                            let n = stream.read(&mut buf).await.unwrap();
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&buf[..n]).await.unwrap();
                        }
                    });
                }
            });
            let padding = cell();
            let client = Session::client(Box::new(a), padding.clone(), Tuning::default(), "test");
            for i in 0..3u8 {
                let mut stream = client.open_stream(&[i]).await.unwrap();
                let mut echo = [0u8; 1];
                stream.read_exact(&mut echo).await.unwrap();
                assert_eq!(echo[0], i);
                let data = vec![i; 100_000];
                stream.write_all(&data).await.unwrap();
                let mut back = vec![0u8; data.len()];
                stream.read_exact(&mut back).await.unwrap();
                assert_eq!(back, data);
                stream.shutdown().await.unwrap();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
            }
            // The server's scheme differs from the default, so it was sent.
            assert_eq!(padding.read().unwrap().stop(), 1);
            assert!(!client.is_closed());
            drop(server);
        });
    }

    /// A server that fails to open a stream says why, and the client's
    /// stream fails with it.
    #[test]
    fn a_refused_stream_fails_with_the_servers_reason() {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let (server, mut accept) = Session::server(
                Box::new(b),
                Arc::new(PaddingScheme::default_scheme()),
                Tuning::default(),
                "test",
            );
            tokio::spawn(async move {
                while let Some(stream) = accept.recv().await {
                    let stream = server.stream(stream);
                    stream.report(Some("no route")).await.unwrap();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
            let client = Session::client(Box::new(a), cell(), Tuning::default(), "test");
            let mut stream = client.open_stream(b"x").await.unwrap();
            let err = stream.read(&mut [0u8; 8]).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
            assert!(err.to_string().contains("no route"), "{}", err);
        });
    }

    /// What came in as several frames is read in one read, as far as the
    /// buffer holds it: a read a frame made a write a frame downstream.
    #[test]
    fn a_read_takes_every_frame_queued() {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let (server, mut accept) = Session::server(
                Box::new(b),
                Arc::new(PaddingScheme::parse(b"stop=1").unwrap()),
                Tuning::default(),
                "test",
            );
            tokio::spawn(async move {
                while let Some(stream) = accept.recv().await {
                    let mut stream = server.stream(stream);
                    stream.report(None).await.unwrap();
                    for i in 0..3u8 {
                        stream.write_all(&[i; 1000]).await.unwrap();
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
            let client = Session::client(Box::new(a), cell(), Tuning::default(), "test");
            let mut stream = client.open_stream(b"x").await.unwrap();
            while client.core.received() < 3000 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut buf = vec![0u8; 64 * 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, 3000);
            assert!(buf[..1000].iter().all(|b| *b == 0));
            assert!(buf[2000..3000].iter().all(|b| *b == 2));
        });
    }
}
