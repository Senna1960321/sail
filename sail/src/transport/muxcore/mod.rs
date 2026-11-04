//! What every stream multiplexer sail speaks has in common: many streams
//! over one connection, read by one task and written by another, with
//! every buffer bounded (`session`).
//!
//! A protocol is only its frames (`Codec`): how a stream is opened,
//! carries data, is finished or reset, how more window is granted, and
//! what it reads off the connection, decoded into `Event`s. The session
//! does the rest the same way for all of them:
//!
//! - The reader never waits for a stream. What a stream receives waits in
//!   its inbox. With windows (yamux), the peer sends no more than the
//!   window; windows start at `INITIAL_WINDOW` and grow, as quic-go's do,
//!   while a stream is read faster than its window lets data come in one
//!   round trip, up to `Tuning::window_max`; a session's windows together
//!   grow by a bounded budget, and a stream idle for a while gives its
//!   growth back when another needs it. Without windows (smux), the
//!   reader stops reading the connection while a stream holds
//!   `Tuning::inbox` unread, and TCP holds the peer back.
//! - A stream whose inbox holds data that nothing has read for
//!   `Tuning::stall_timeout` is reset, alone: its data dropped, the peer
//!   told as the protocol tells it. A stream that is read, however slowly,
//!   never is.
//! - Without windows, a session whose connection takes nothing written to
//!   it for `Tuning::write_stall`, the reader having stopped for a full
//!   inbox meanwhile, fails: when neither end reads, a TCP connection may
//!   never move again (as on Linux 6.17 to 7.0), and a write to it never
//!   ends of itself.
//! - Control frames -- acknowledgements, window updates, pings -- go out
//!   ahead of data, in a queue of their own the reader never waits on.
//! - Streams the peer opens are never turned away for being many at
//!   once, only past `MAX_STREAMS`.
//! - Where the peer acknowledges the streams this end opens (yamux), no
//!   more than `MAX_UNACKED` wait for it: an open waits for one of them to
//!   be. hashicorp/yamux resets streams past that many it has not
//!   accepted.
//! - A stream holds its session: dropping the session's handle takes no
//!   new streams and closes it once the last stream is done.
//! - Without half-close (smux, AnyTLS), so does a client's session once
//!   one of its streams ended while the peer may still be sending it:
//!   dropped before the peer's FIN, reset for stalling, or with data still
//!   coming after its FIN. What the peer sent is on its way, ahead of
//!   anything a new stream would get, and nothing tells the peer to stop:
//!   on a slow link, long enough for it to fail. With half-close (yamux,
//!   amux), a stream dropped before the peer's FIN is reset, alone, and
//!   what the peer sent it meanwhile, no more than its window, is dropped
//!   as it comes: the session goes on.
//!
//! How many sessions and streams there are, and how many were reset for
//! stalling, is counted per protocol (`stats`).

// Without a protocol on the core, only the stall timer is used (QUIC).
#![cfg_attr(
    not(any(
        feature = "mux",
        feature = "inbound-amux",
        feature = "outbound-amux",
        feature = "inbound-anytls",
        feature = "outbound-anytls",
        feature = "muxcore"
    )),
    allow(dead_code, unused_imports)
)]

use std::io;
use std::time::Duration;

use bytes::{Bytes, BytesMut};

mod session;
pub mod stall;
pub mod stats;
#[cfg(any(feature = "mux", feature = "muxcore"))]
pub mod yamux;

pub use session::{Session, Stream, MAX_STREAMS, MAX_UNACKED};

/// The window every stream starts with, where there are windows.
pub const INITIAL_WINDOW: u32 = 256 << 10;

/// What sessions run with: `runtime::options::Mux`, the relay's write
/// stall timeout, and how long a client keeps one with no streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// The largest a stream's receive window grows to.
    pub window_max: u32,
    /// Without windows: what a stream holds unread before its session
    /// stops reading the connection.
    pub inbox: usize,
    /// A stream whose data nothing has read for this long is reset.
    pub stall_timeout: Duration,
    /// Without windows: a session whose connection has taken nothing
    /// written to it for this long, while its reader stopped for a full
    /// inbox, fails.
    pub write_stall: Duration,
    /// h2mux: every stream's window, which does not grow; the
    /// connection's is eight times as much.
    pub h2_stream_window: u32,
    /// A client's session with no streams for this long is closed (mux,
    /// amux): the profile's carrier idle timeout.
    pub idle_timeout: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning::from(&crate::runtime::options::RuntimeOptions::default())
    }
}

impl From<&crate::runtime::options::RuntimeOptions> for Tuning {
    fn from(options: &crate::runtime::options::RuntimeOptions) -> Self {
        let mux = &options.mux;
        Tuning {
            window_max: u32::try_from(mux.stream_window_max.saturating_mul(1024))
                .unwrap_or(u32::MAX)
                .max(INITIAL_WINDOW),
            inbox: mux.stream_buffer.saturating_mul(1024).max(16 << 10),
            stall_timeout: mux.stall_timeout.max(Duration::from_secs(1)),
            write_stall: options.relay.write_stall_timeout,
            // A quarter of what a window grows to: 4 MiB, 2 on the mobile
            // and router profiles.
            h2_stream_window: u32::try_from(mux.stream_window_max.saturating_mul(1024) / 4)
                .unwrap_or(u32::MAX)
                .max(1 << 20),
            idle_timeout: options.profile.carrier_idle_timeout(),
        }
    }
}

impl Tuning {
    /// How often streams are checked for stalling.
    fn stall_check(&self) -> Duration {
        stall::check_interval(self.stall_timeout)
    }
}

/// How a protocol keeps what a stream has received and not read bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The peer sends a stream no more than its window, which grows as
    /// the stream is read (yamux, amux).
    Window,
    /// No window: the session stops reading its connection while a
    /// stream's inbox is full (smux, AnyTLS).
    Pause,
}

/// What finishing a stream means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closing {
    /// A FIN ends one direction; the other goes on, and a reset ends one
    /// stream alone (yamux, amux).
    Half,
    /// There is no half-close: a FIN ends a stream both ways, sent when it
    /// is shut down: what comes after is dropped, what came before is
    /// still read (smux, AnyTLS). Shutting down ends the stream, as
    /// sing-box closes a connection that cannot half-close once one way is
    /// done: a stream left open would wait on a peer that never hears the
    /// end, and hold its session.
    Whole,
}

/// What a decoder makes of the frames it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The peer opens a stream.
    Open(u32),
    /// The peer acknowledges a stream this end opened.
    Ack(u32),
    /// Data on a stream, all of a frame's or part of it.
    Data(u32, Bytes),
    /// The peer is done sending on a stream.
    Fin(u32),
    /// The peer abandons a stream.
    Reset(u32),
    /// The peer grants a stream more window.
    Window(u32, u32),
    /// The peer asks for its ping to be answered.
    Ping(u32),
    /// The peer answers a ping.
    Pong(u32),
    /// The peer takes no more streams.
    GoAway,
    /// The peer failed to open a stream this end opened, and says why.
    Refused(u32, String),
    /// A frame the protocol answers with, sent ahead of stream data.
    Reply(Bytes),
    /// The session is over, as the protocol says why.
    Close(String),
}

/// A protocol's frames.
pub trait Codec: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn flow(&self) -> Flow;
    fn closing(&self) -> Closing;
    /// The most data one frame carries.
    fn max_data(&self) -> usize;
    /// The id of the first stream this end opens; the next are `id_step`
    /// apart.
    fn first_id(&self, server: bool) -> u32;
    fn id_step(&self) -> u32 {
        2
    }
    /// The largest id a stream may have.
    fn max_id(&self) -> u32 {
        u32::MAX - 2
    }
    /// Whether the peer acknowledges the streams this end opens
    /// (`Event::Ack`), and opening waits while `MAX_UNACKED` are not.
    fn acknowledges(&self) -> bool {
        false
    }

    /// Opens stream `id` with `first` as its first data, which is no more
    /// than the initial window, as one write.
    fn open(&self, id: u32, first: &[u8]) -> Bytes;
    /// Acknowledges a stream the peer opened, if the protocol does.
    fn ack(&self, _id: u32) -> Option<Bytes> {
        None
    }
    /// Turns away a stream the peer opened.
    fn refuse(&self, id: u32) -> Bytes;
    fn data(&self, id: u32, data: &[u8]) -> Bytes;
    fn fin(&self, id: u32) -> Bytes;
    fn reset(&self, id: u32) -> Bytes;
    /// Grants the peer `delta` more window on stream `id`.
    fn window_update(&self, _id: u32, _delta: u32) -> Option<Bytes> {
        None
    }
    /// A ping, or its answer, if the protocol has them.
    fn ping(&self, _ack: bool, _opaque: u32) -> Option<Bytes> {
        None
    }

    /// Reads frames, for a server or a client.
    fn decoder(&self, server: bool) -> Box<dyn Decoder>;
    /// Shapes what the session writes, if the protocol does.
    fn shaper(&self) -> Option<Box<dyn Shaper>> {
        None
    }
}

/// Shapes the writes of a session, as AnyTLS pads the first of them.
pub trait Shaper: Send {
    /// Whether writes are still shaped. While they are, each frame, or run
    /// of frames queued at once, is a write of its own.
    fn active(&mut self) -> bool;
    /// The records one write is made of, each written and flushed on its
    /// own.
    fn shape(&mut self, write: BytesMut) -> Vec<BytesMut>;
}

/// Reads a protocol's frames off what the connection has given so far.
pub trait Decoder: Send {
    /// The next event in `buf`, taking what it read from it; `None` if more
    /// has to be read first. A frame's data comes out whole, or in pieces of
    /// `PIECE` where it is longer (`Framing`).
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>>;
}

/// The most of a frame's data a decoder holds back until the rest has
/// come: a frame comes in as many pieces as it was read in, as TLS records
/// of 16 KiB do, and a stream that was given each piece as it came made a
/// write of each downstream, four to sing-box's one.
pub const PIECE: usize = 64 << 10;

/// Where a decoder is between frames: the events a frame's header gave,
/// the data that follows it, and the events after that data.
#[derive(Default)]
pub struct Framing {
    before: std::collections::VecDeque<Event>,
    /// The stream, and how much of its frame's data is still to come.
    data: Option<(u32, usize)>,
    /// The frame's data read so far and not given out, less than `PIECE`.
    piece: BytesMut,
    /// Data to be skipped, for frames of no use.
    skip: usize,
    after: Vec<Event>,
}

impl Framing {
    /// A frame's header has been read: `before`, then `len` bytes of data
    /// for stream `id`, then `after`.
    pub fn frame(&mut self, before: &[Event], data: Option<(u32, usize)>, after: &[Event]) {
        self.before.extend(before.iter().cloned());
        self.data = data.filter(|(_, len)| *len > 0);
        match self.data {
            Some(_) => self.after.extend(after.iter().cloned()),
            None => self.before.extend(after.iter().cloned()),
        }
    }

    /// Skips the next `len` bytes.
    pub fn skip(&mut self, len: usize) {
        self.skip += len;
    }

    /// Whether a header is to be read next.
    pub fn at_header(&self) -> bool {
        self.before.is_empty() && self.data.is_none() && self.skip == 0
    }

    /// What is left of the frame being read, if it is not done: `Some(None)`
    /// while more has to be read first.
    pub fn next(&mut self, buf: &mut BytesMut) -> Option<Option<Event>> {
        use bytes::Buf;
        if let Some(event) = self.before.pop_front() {
            return Some(Some(event));
        }
        if self.skip > 0 {
            let n = self.skip.min(buf.len());
            buf.advance(n);
            self.skip -= n;
            if self.skip > 0 {
                return Some(None);
            }
        }
        if let Some((id, left)) = self.data {
            if buf.is_empty() {
                return Some(None);
            }
            let n = left.min(buf.len());
            let done = n == left;
            let data = if self.piece.is_empty() && (done || n >= PIECE) {
                Bytes::copy_from_slice(&buf[..n])
            } else {
                self.piece.extend_from_slice(&buf[..n]);
                if !done && self.piece.len() < PIECE {
                    // All of `buf` taken: the rest is still to be read.
                    buf.advance(n);
                    self.data = Some((id, left - n));
                    return Some(None);
                }
                self.piece.split().freeze()
            };
            buf.advance(n);
            if done {
                self.data = None;
                self.before.extend(self.after.drain(..));
            } else {
                self.data = Some((id, left - n));
            }
            return Some(Some(Event::Data(id, data)));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::options::{Profile, RuntimeOptions};

    /// Data with nothing more to come, as `next` gives it out.
    fn drain(framing: &mut Framing, buf: &mut BytesMut) -> Vec<Event> {
        let mut events = Vec::new();
        while let Some(Some(event)) = framing.next(buf) {
            events.push(event);
        }
        events
    }

    #[test]
    fn a_frame_read_in_pieces_comes_out_whole() {
        let mut framing = Framing::default();
        framing.frame(&[], Some((3, 30_000)), &[Event::Fin(3)]);
        let mut events = Vec::new();
        for piece in [16_384, 13_000, 616] {
            let mut buf = BytesMut::from(&vec![7u8; piece][..]);
            events.extend(drain(&mut framing, &mut buf));
            assert!(buf.is_empty());
        }
        assert_eq!(
            events,
            vec![
                Event::Data(3, Bytes::from(vec![7u8; 30_000])),
                Event::Fin(3)
            ]
        );
    }

    #[test]
    fn a_long_frame_comes_out_in_pieces_of_64_kib() {
        let mut framing = Framing::default();
        framing.frame(&[], Some((1, PIECE + 100)), &[]);
        let mut lens = Vec::new();
        for _ in 0..5 {
            let mut buf = BytesMut::from(&vec![0u8; 16_384][..]);
            for event in drain(&mut framing, &mut buf) {
                if let Event::Data(_, data) = event {
                    lens.push(data.len());
                }
            }
        }
        // The fifth read holds the frame's last 100 bytes and what follows.
        assert_eq!(lens, vec![PIECE, 100]);
    }

    #[test]
    fn windows_grow_to_16_mib_or_8_on_small_devices() {
        let tuning = |profile| Tuning::from(&RuntimeOptions::profile(profile));
        for (profile, max, h2) in [
            (Profile::Desktop, 16 << 20, 4 << 20),
            (Profile::Server, 16 << 20, 4 << 20),
            (Profile::Mobile, 8 << 20, 2 << 20),
            (Profile::Router, 8 << 20, 2 << 20),
        ] {
            assert_eq!(tuning(profile).window_max, max, "{:?}", profile);
            assert_eq!(tuning(profile).h2_stream_window, h2, "{:?}", profile);
        }
    }
}
