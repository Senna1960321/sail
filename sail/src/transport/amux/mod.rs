//! amux, sail's own multiplexer: streams over one connection of a
//! transport (TLS, WebSocket, ...), below a proxy protocol, which runs on
//! each stream. Both ends are sail, so the frames are its own, carried by
//! the stream core (`transport::muxcore`), all big-endian:
//!
//! - `0x00 SYN | id u16`: the client opens a stream.
//! - `0x01 DATA | id u16 | len u16 | data`.
//! - `0x02 FIN | id u16`: no more data this way; the other goes on.
//! - `0x03 WINDOW | id u16 | delta u32`: the sender may send `delta` more.
//! - `0x04 RST | id u16`: the stream is abandoned both ways.
//! - `0x05 PING | ack u8 | opaque u32`: answered with `ack` 1 and the
//!   same `opaque`; the round trip is what windows grow with.
//!
//! Every stream starts with a window of `muxcore::INITIAL_WINDOW` each
//! way, which the reader grows as it reads fast (`mux.stream_window_max`).
//! The amux before these frames had neither windows nor resets, and a
//! stream nobody read stalled its whole session; the two do not speak to
//! each other.

use std::io;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::trace;

use crate::transport::muxcore::{self, Closing, Codec, Decoder, Event, Flow, Framing, Tuning};

#[cfg(feature = "inbound-amux")]
pub mod inbound;
#[cfg(feature = "outbound-amux")]
pub mod outbound;
#[cfg(test)]
mod stall_tests;

const FRAME_SYN: u8 = 0x00;
const FRAME_DATA: u8 = 0x01;
const FRAME_FIN: u8 = 0x02;
const FRAME_WINDOW: u8 = 0x03;
const FRAME_RST: u8 = 0x04;
const FRAME_PING: u8 = 0x05;
/// The largest data frame sent.
const MAX_FRAME_DATA: usize = 32 << 10;

pub fn random_u16() -> u16 {
    rand::random()
}

/// A stream of an amux session.
pub type MuxStream = muxcore::Stream;

fn short(kind: u8, id: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(3);
    buf.put_u8(kind);
    buf.put_u16(id as u16);
    buf.freeze()
}

fn data(buf: &mut BytesMut, id: u32, data: &[u8]) {
    for chunk in data.chunks(MAX_FRAME_DATA) {
        buf.put_u8(FRAME_DATA);
        buf.put_u16(id as u16);
        buf.put_u16(chunk.len() as u16);
        buf.put_slice(chunk);
    }
}

/// amux's frames, for the core.
struct Amux;

impl Codec for Amux {
    fn name(&self) -> &'static str {
        "amux"
    }

    fn flow(&self) -> Flow {
        Flow::Window
    }

    fn closing(&self) -> Closing {
        Closing::Half
    }

    fn max_data(&self) -> usize {
        MAX_FRAME_DATA
    }

    fn first_id(&self, _server: bool) -> u32 {
        1
    }

    fn id_step(&self) -> u32 {
        1
    }

    fn max_id(&self) -> u32 {
        u16::MAX.into()
    }

    fn open(&self, id: u32, first: &[u8]) -> Bytes {
        let mut buf = BytesMut::from(&short(FRAME_SYN, id)[..]);
        data(&mut buf, id, first);
        buf.freeze()
    }

    fn refuse(&self, id: u32) -> Bytes {
        short(FRAME_RST, id)
    }

    fn data(&self, id: u32, bytes: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + bytes.len());
        data(&mut buf, id, bytes);
        buf.freeze()
    }

    fn fin(&self, id: u32) -> Bytes {
        short(FRAME_FIN, id)
    }

    fn reset(&self, id: u32) -> Bytes {
        short(FRAME_RST, id)
    }

    fn window_update(&self, id: u32, delta: u32) -> Option<Bytes> {
        let mut buf = BytesMut::with_capacity(7);
        buf.put_u8(FRAME_WINDOW);
        buf.put_u16(id as u16);
        buf.put_u32(delta);
        Some(buf.freeze())
    }

    fn ping(&self, ack: bool, opaque: u32) -> Option<Bytes> {
        let mut buf = BytesMut::with_capacity(6);
        buf.put_u8(FRAME_PING);
        buf.put_u8(ack as u8);
        buf.put_u32(opaque);
        Some(buf.freeze())
    }

    fn decoder(&self, _server: bool) -> Box<dyn Decoder> {
        Box::<AmuxDecoder>::default()
    }
}

/// Fuzzing (sail::fuzzing): amux's frames, as a session reads them.
#[cfg(all(feature = "fuzzing", feature = "mux"))]
pub(crate) fn fuzz_frames(data: &[u8], step: usize) {
    crate::transport::mux::fuzz::decode_all(&mut *Amux.decoder(false), data, step);
}

#[derive(Default)]
struct AmuxDecoder {
    framing: Framing,
}

impl Decoder for AmuxDecoder {
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>> {
        loop {
            if let Some(next) = self.framing.next(buf) {
                return Ok(next);
            }
            let Some(&kind) = buf.first() else {
                return Ok(None);
            };
            let len = match kind {
                FRAME_SYN | FRAME_FIN | FRAME_RST => 3,
                FRAME_DATA => 5,
                FRAME_WINDOW => 7,
                FRAME_PING => 6,
                kind => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("amux: unknown frame type {}", kind),
                    ))
                }
            };
            if buf.len() < len {
                return Ok(None);
            }
            let mut header = buf.split_to(len);
            header.advance(1);
            if kind == FRAME_PING {
                let ack = header.get_u8() != 0;
                let opaque = header.get_u32();
                let event = if ack {
                    Event::Pong(opaque)
                } else {
                    Event::Ping(opaque)
                };
                self.framing.frame(&[event], None, &[]);
                continue;
            }
            let id = u32::from(header.get_u16());
            match kind {
                FRAME_SYN => self.framing.frame(&[Event::Open(id)], None, &[]),
                FRAME_DATA => {
                    let len = usize::from(header.get_u16());
                    self.framing.frame(&[], Some((id, len)), &[]);
                }
                FRAME_FIN => self.framing.frame(&[Event::Fin(id)], None, &[]),
                FRAME_WINDOW => {
                    let delta = header.get_u32();
                    self.framing.frame(&[Event::Window(id, delta)], None, &[]);
                }
                _ => self.framing.frame(&[Event::Reset(id)], None, &[]),
            }
        }
    }
}

pub struct MuxSession;

impl MuxSession {
    /// A client session over `conn`, which opens streams until one of the
    /// limits is reached. `label` says who it serves in logs.
    pub fn connector<S>(
        conn: S,
        max_accepts: usize,
        concurrency: usize,
        max_recv_bytes: usize,
        max_lifetime: u64,
        tuning: Tuning,
        label: &str,
    ) -> MuxConnector
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (session, _) = muxcore::Session::new(conn, Arc::new(Amux), false, tuning, label);
        let session_id = random_u16();
        trace!(
            "new mux connector {} (max_accepts: {}, concurrency: {})",
            session_id,
            max_accepts,
            concurrency
        );
        MuxConnector {
            max_accepts,
            concurrency,
            max_recv_bytes,
            max_lifetime,
            started_at: Instant::now(),
            session_id,
            total_accepted: 0,
            session,
        }
    }

    /// A server session over `conn`: the streams the client opens.
    pub fn acceptor<S>(conn: S, tuning: Tuning, label: &str) -> MuxAcceptor
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (session, accept) = muxcore::Session::new(conn, Arc::new(Amux), true, tuning, label);
        let session_id = random_u16();
        trace!("new mux acceptor {}", session_id);
        MuxAcceptor {
            _session: session,
            // A server's session always has somewhere to put streams.
            accept: accept.unwrap_or_else(|| mpsc::unbounded_channel().1),
        }
    }
}

pub struct MuxConnector {
    /// Streams opened at most.
    max_accepts: usize,
    /// Streams open at once at most.
    concurrency: usize,
    /// No new streams once the session has received this much (0: no
    /// limit).
    max_recv_bytes: usize,
    /// No new streams once the session is this old, in seconds (0: no
    /// limit).
    max_lifetime: u64,
    started_at: Instant,
    /// For logs.
    session_id: u16,
    /// Streams opened so far.
    total_accepted: usize,
    /// Held by its streams too: dropping the connector ends the session
    /// once they are done.
    session: muxcore::Session,
}

impl MuxConnector {
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// Whether the session is spent: closed or retired, its streams going
    /// on without it here, or it takes no more streams and has none left.
    pub fn is_done(&self) -> bool {
        !self.session.is_reusable() || (!self.takes_more() && self.session.num_streams() == 0)
    }

    /// The streams open on the session.
    pub fn num_streams(&self) -> usize {
        self.session.num_streams()
    }

    /// Ends the session, and any stream on it.
    pub fn close(&self) {
        self.session.close();
    }

    /// Whether the limits let the session take another stream, some time.
    fn takes_more(&self) -> bool {
        self.total_accepted < self.max_accepts
            && (self.max_recv_bytes == 0 || self.session.received() < self.max_recv_bytes as u64)
            && (self.max_lifetime == 0 || self.started_at.elapsed().as_secs() < self.max_lifetime)
    }

    pub async fn new_stream(&mut self) -> Option<MuxStream> {
        if !self.session.is_reusable()
            || !self.takes_more()
            || self.session.num_streams() >= self.concurrency
        {
            return None;
        }
        let stream = self.session.open().await.ok()?;
        self.total_accepted += 1;
        Some(stream)
    }
}

/// The streams a client opens on a server's session. Dropping it takes no
/// more; those taken go on.
pub struct MuxAcceptor {
    _session: muxcore::Session,
    accept: mpsc::UnboundedReceiver<MuxStream>,
}

impl Stream for MuxAcceptor {
    type Item = MuxStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.accept.poll_recv(cx)
    }
}
