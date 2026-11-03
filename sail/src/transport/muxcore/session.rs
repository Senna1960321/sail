//! A session: the streams of one connection, and the task that reads and
//! writes it.
//!
//! One task reads the connection, writes it, and looks for stalled streams
//! (`driver`). The reader hands what it reads to the streams' inboxes and
//! never waits for a stream to take it: with windows it has no need to,
//! and without, it stops reading the connection while an inbox is full,
//! which the stall timer ends in `Tuning::stall_timeout` at most; a
//! connection that, meanwhile, takes nothing written to it for
//! `Tuning::write_stall` ends the session, as neither end then reads it
//! and it may never move again. What
//! streams write waits in one queue, and a stream stops being taken writes
//! while that queue holds `OUT_SOFT_LIMIT`; control frames wait in one of
//! their own, written first, and a peer that makes it grow past
//! `CONTROL_LIMIT` with frames it never reads loses the session.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tokio::time::{timeout, Instant};
use tracing::{debug, trace};

use super::stats::{self, Counters};
use super::{Closing, Codec, Event, Flow, Tuning, INITIAL_WINDOW};

/// Stream data queued for the connection: past this, streams wait to
/// write.
const OUT_SOFT_LIMIT: usize = 1 << 20;
/// Control frames queued for the connection: past this, the peer does not
/// read what it asks for, and loses the session.
const CONTROL_LIMIT: usize = 1 << 20;
/// Written to the connection at once, at most. The batch is as large as
/// what is queued, and is given back once nothing is.
const WRITE_BATCH: usize = 64 << 10;
/// Read from the connection at once, at most. A session reads into
/// `READ_SMALL` at first, and twice as much each time a read fills what it
/// had room for, up to this.
const READ_BUFFER: usize = 64 << 10;
/// What a session reads into at first, and once it has had nothing to read
/// for `READ_IDLE_AFTER`: a session that carries little, or is idle, pooled
/// or with streams that send nothing, holds this much of a buffer rather
/// than `READ_BUFFER`.
const READ_SMALL: usize = 4 << 10;
/// How long a session goes without anything to read before its read
/// buffer is small again. A reader that keeps up with its connection waits
/// often and briefly, and would read in small pieces if every wait made it
/// small (a sixth less upload through AnyTLS).
const READ_IDLE_AFTER: Duration = Duration::from_secs(1);
/// Streams one session carries at once.
pub const MAX_STREAMS: usize = 1024;
/// The most a peer may grant a stream, beyond which it is taken to be
/// misbehaving.
const MAX_SEND_WINDOW: u32 = 1 << 30;
/// The windows of a session's streams grow, together, by no more than this
/// many times `Tuning::window_max`.
const SESSION_GROWTH: u64 = 4;
/// A stream that has read nothing for this long, and holds nothing
/// unread, gives what its window grew by back to the session once another
/// stream needs it to grow.
const RECLAIM_IDLE: Duration = Duration::from_secs(1);
/// How long a closed session has to write what it has left.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// One stream's state.
struct Slot {
    /// What the stream received and has not read.
    recv: VecDeque<Bytes>,
    /// Bytes in `recv`.
    inbox: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// The peer is done sending.
    remote_fin: bool,
    /// Sent a FIN.
    local_fin: bool,
    /// The peer reset the stream.
    reset: bool,
    /// Reset by this end, for nothing read what it received.
    stalled: bool,
    /// The peer failed to open the stream, and said why.
    refused: Option<String>,
    /// Without half-close: the peer still sent data after this end's FIN.
    sent_past_fin: bool,
    /// Since when what is in the inbox has waited unread: when data came
    /// into an empty inbox, or when the stream last read.
    progress: Instant,
    /// With windows: what may still be sent.
    send_window: u32,
    /// With windows: what the peer may still send.
    recv_window: u32,
    /// With windows: what `recv_window` is topped up to as the stream is
    /// read, which grows while it is read fast.
    window: u32,
    /// With windows: read since the last window update.
    consumed: u32,
    /// With windows: since when, and how much, the stream has read while
    /// its window stayed the same.
    epoch_start: Instant,
    epoch_read: u64,
}

impl Slot {
    fn new(flow: Flow) -> Self {
        let window = match flow {
            Flow::Window => INITIAL_WINDOW,
            Flow::Pause => 0,
        };
        let now = Instant::now();
        Slot {
            recv: VecDeque::new(),
            inbox: 0,
            read_waker: None,
            write_waker: None,
            remote_fin: false,
            local_fin: false,
            reset: false,
            stalled: false,
            refused: None,
            sent_past_fin: false,
            progress: now,
            send_window: window,
            recv_window: window,
            window,
            consumed: 0,
            epoch_start: now,
            epoch_read: 0,
        }
    }

    /// Whether what the peer sends is no longer taken: the stream is over
    /// both ways, or failed.
    fn deaf(&self, closing: Closing) -> bool {
        self.stalled
            || self.refused.is_some()
            || (closing == Closing::Whole && (self.local_fin || self.remote_fin))
    }

    fn wake(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

/// Frames waiting for the writer.
#[derive(Default)]
struct Out {
    queue: VecDeque<Bytes>,
    bytes: usize,
}

impl Out {
    fn push(&mut self, frame: Bytes) {
        self.bytes += frame.len();
        self.queue.push_back(frame);
    }
}

struct State {
    streams: HashMap<u32, Slot>,
    /// Control frames, written first.
    control: Out,
    /// What the streams send: opening, data, finishing and resetting, in
    /// order.
    data: Out,
    /// Why the session ended, once it has.
    error: Option<String>,
    /// The peer asked for no more streams.
    going_away: bool,
    /// No new streams, and the session ends with its last one: the handle
    /// is gone, or a stream of this end's ended abruptly (`Drop for
    /// Stream`).
    retired: bool,
    /// The id of the next stream this end opens.
    next_id: u32,
    /// Stream data received, all told.
    received: u64,
    /// Without windows: the streams whose inbox is full, which stop the
    /// reader.
    full: usize,
    /// Since when the writer has had frames to write and the connection
    /// has taken none of them: `None` while it has nothing to write.
    write_waiting: Option<Instant>,
    /// Without windows: the reader stopped for a full inbox while the
    /// writer waited, since `write_waiting`.
    paused_while_waiting: bool,
    /// With windows: what the streams' windows have grown by, together.
    grown: u64,
    /// With windows: the shortest round trip measured.
    rtt: Option<Duration>,
    /// With windows: `rtt` is set, not measured (tests).
    rtt_pinned: bool,
    /// With windows: the ping waiting for its answer, and when it went.
    ping: Option<(u32, Instant)>,
    pings: u32,
    /// Where accepted streams go, on a server.
    accept: Option<mpsc::UnboundedSender<Stream>>,
}

struct Shared {
    codec: Arc<dyn Codec>,
    flow: Flow,
    closing: Closing,
    server: bool,
    tuning: Tuning,
    /// Who the session serves, as its logs say it.
    label: Arc<str>,
    counters: Arc<Counters>,
    state: Mutex<State>,
    /// Wakes the writer.
    writer: Notify,
    /// Wakes the reader waiting for a full inbox to be read.
    reader: Notify,
    /// Stops the task that reads and writes the connection.
    task: Mutex<Option<AbortHandle>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock cannot leave the state worse than
        // any other failure would: carry on with it.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake_writer(&self) {
        self.writer.notify_one();
    }

    /// Ends the session: every stream fails, or reads what it has and
    /// then fails. What is queued is still written, for a while.
    fn fail(&self, reason: String) {
        let mut state = self.lock();
        if state.error.is_none() {
            debug!("{} session closed: {}", self.codec.name(), reason);
            state.error = Some(reason);
            self.counters.session_closed();
        }
        let accept = state.accept.take();
        for slot in state.streams.values_mut() {
            slot.wake();
        }
        drop(state);
        drop(accept);
        self.writer.notify_one();
        self.reader.notify_one();
    }

    /// Ends the session at once.
    fn abort(&self, reason: &str) {
        self.fail(reason.to_string());
        let task = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            task.abort();
        }
    }

    /// Queues a control frame. The peer makes this end send them: a peer
    /// that never reads them loses the session.
    fn control(&self, state: &mut State, frame: Bytes) -> io::Result<()> {
        state.control.push(frame);
        if state.control.bytes > CONTROL_LIMIT {
            return Err(io::Error::other("peer does not read what it asks for"));
        }
        self.writer.notify_one();
        Ok(())
    }

    /// Waits until no inbox is full.
    async fn wait_for_room(&self) {
        loop {
            let notified = self.reader.notified();
            {
                let state = self.lock();
                if state.full == 0 || state.error.is_some() {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Does what the peer's frames ask.
    fn apply(self: &Arc<Self>, event: Event) -> io::Result<()> {
        let mut guard = self.lock();
        let state = &mut *guard;
        match event {
            Event::Open(id) => {
                if state.streams.contains_key(&id) {
                    return Ok(());
                }
                if !self.server
                    || state.retired
                    || state.accept.is_none()
                    || state.streams.len() >= MAX_STREAMS
                {
                    self.counters.refused();
                    return self.control(state, self.codec.refuse(id));
                }
                state.streams.insert(id, Slot::new(self.flow));
                self.counters.stream_opened();
                if let Some(frame) = self.codec.ack(id) {
                    self.control(state, frame)?;
                }
                let accept = state.accept.clone();
                drop(guard);
                // Sent without the lock: a stream the server no longer
                // takes comes back and is dropped, which refuses it.
                if let Some(accept) = accept {
                    let _ = accept.send(Stream {
                        id,
                        shared: self.clone(),
                    });
                }
            }
            Event::Data(id, data) => self.deliver(state, id, data)?,
            Event::Window(id, delta) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.send_window = slot
                        .send_window
                        .checked_add(delta)
                        .filter(|w| *w <= MAX_SEND_WINDOW)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("{}: window overflows", self.codec.name()),
                            )
                        })?;
                    slot.wake();
                }
            }
            Event::Fin(id) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.remote_fin = true;
                    slot.wake();
                }
            }
            Event::Reset(id) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.reset = true;
                    slot.wake();
                }
            }
            Event::Ping(opaque) => {
                if let Some(frame) = self.codec.ping(true, opaque) {
                    self.control(state, frame)?;
                }
            }
            Event::Pong(opaque) => {
                if let Some((sent, at)) = state.ping {
                    if sent == opaque {
                        let rtt = at.elapsed();
                        if !state.rtt_pinned {
                            state.rtt = Some(state.rtt.map_or(rtt, |min| min.min(rtt)));
                        }
                        state.ping = None;
                    }
                }
            }
            Event::GoAway => state.going_away = true,
            Event::Refused(id, why) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.refused = Some(why);
                    slot.wake();
                }
            }
            Event::Reply(frame) => self.control(state, frame)?,
            Event::Close(why) => return Err(io::Error::other(why)),
        }
        Ok(())
    }

    /// Puts data received for stream `id` in its inbox; dropped if the
    /// stream is gone.
    fn deliver(&self, state: &mut State, id: u32, data: Bytes) -> io::Result<()> {
        let Some(slot) = state.streams.get_mut(&id) else {
            // For a stream this end dropped: the peer was still sending it.
            // With half-close the stream was reset, alone, and what the
            // peer sent before it heard is dropped here.
            if !self.server && self.closing == Closing::Whole {
                self.retire_abrupt(state, id);
                if state.retired && state.streams.is_empty() && state.error.is_none() {
                    let reason = "retired, and its last stream is done";
                    debug!("{} session closed: {}", self.codec.name(), reason);
                    state.error = Some(reason.to_string());
                    self.counters.session_closed();
                    self.writer.notify_one();
                }
            }
            return Ok(());
        };
        if self.flow == Flow::Window {
            if data.len() as u32 > slot.recv_window {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: stream {} sent past its window", self.codec.name(), id),
                ));
            }
            slot.recv_window -= data.len() as u32;
        }
        state.received += data.len() as u64;
        if slot.deaf(self.closing) {
            slot.sent_past_fin |= slot.local_fin && !slot.remote_fin;
            return Ok(());
        }
        if slot.recv.is_empty() {
            slot.progress = Instant::now();
        }
        let was_full = slot.inbox >= self.tuning.inbox;
        slot.inbox += data.len();
        slot.recv.push_back(data);
        if self.flow == Flow::Pause && !was_full && slot.inbox >= self.tuning.inbox {
            state.full += 1;
            state.paused_while_waiting |= state.write_waiting.is_some();
        }
        if let Some(w) = slot.read_waker.take() {
            w.wake();
        }
        Ok(())
    }

    /// Takes no new streams on a client session without half-close one of
    /// whose streams, `id`, ended while the peer was still sending it: what
    /// the peer sent is on its way, ahead of anything a new stream would
    /// get, and the protocol has no reset that stops it. The session ends
    /// with its last stream.
    fn retire_abrupt(&self, state: &mut State, id: u32) {
        if state.retired || state.error.is_some() {
            return;
        }
        debug!(
            "{} {} session retired: stream {} ended before the peer finished",
            self.codec.name(),
            self.label,
            id
        );
        state.retired = true;
    }

    /// Resets the streams whose data has waited unread for too long.
    fn check_stalls(&self) {
        let now = Instant::now();
        let mut guard = self.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return;
        }
        let mut stalled = Vec::new();
        for (id, slot) in state.streams.iter_mut() {
            if slot.inbox == 0 || slot.stalled {
                continue;
            }
            let idle = now.saturating_duration_since(slot.progress);
            if idle < self.tuning.stall_timeout {
                continue;
            }
            super::stall::log(
                self.codec.name(),
                &self.label,
                u64::from(*id),
                Some(slot.inbox),
                idle,
            );
            if self.flow == Flow::Pause && slot.inbox >= self.tuning.inbox {
                state.full -= 1;
            }
            state.grown -= u64::from(slot.window.saturating_sub(INITIAL_WINDOW));
            slot.window = slot.window.min(INITIAL_WINDOW);
            slot.recv.clear();
            slot.inbox = 0;
            slot.stalled = true;
            slot.wake();
            stalled.push(*id);
        }
        if stalled.is_empty() {
            return;
        }
        for id in stalled {
            self.counters.stalled();
            state.data.push(self.codec.reset(id));
        }
        drop(guard);
        self.reader.notify_one();
        self.writer.notify_one();
    }

    /// The connection took some of what the writer has, or the writer
    /// starts on more: it waits from now.
    fn wrote(&self) {
        let mut state = self.lock();
        state.write_waiting = Some(Instant::now());
        state.paused_while_waiting = state.full > 0;
    }

    /// Says why the session ends if its connection has taken nothing for
    /// `Tuning::write_stall` while the reader stopped for a full inbox:
    /// neither end then reads it, and a TCP connection where neither does
    /// may never move again (Linux 6.17 to 7.0), while a write to it waits
    /// for as long as it does not.
    fn check_write_stall(&self) -> Option<String> {
        let state = self.lock();
        let since = state.write_waiting?;
        if state.error.is_some() || !state.paused_while_waiting {
            return None;
        }
        let idle = Instant::now().saturating_duration_since(since);
        if idle < self.tuning.write_stall {
            return None;
        }
        Some(format!(
            "write timed out: nothing taken for {}s, and not read for a full inbox",
            idle.as_secs()
        ))
    }

    /// Measures the round trip, which windows grow with.
    fn ping(&self) {
        if self.flow != Flow::Window {
            return;
        }
        let mut state = self.lock();
        if state.error.is_some() || state.ping.is_some_and(|(_, at)| at.elapsed() < CLOSE_GRACE) {
            return;
        }
        state.pings = state.pings.wrapping_add(1);
        let opaque = state.pings;
        if let Some(frame) = self.codec.ping(false, opaque) {
            state.ping = Some((opaque, Instant::now()));
            state.control.push(frame);
            drop(state);
            self.writer.notify_one();
        }
    }
}

/// A session over one connection. Its streams hold it: dropping the handle
/// takes no new streams, and ends the session once the last is done.
pub struct Session {
    shared: Arc<Shared>,
}

impl Session {
    /// Starts a session over `conn`; a server also gets the streams the
    /// peer opens. `label` says who the session serves in its logs, as
    /// `inbound=tag user=name` or `outbound=tag`.
    pub fn new<S>(
        conn: S,
        codec: Arc<dyn Codec>,
        server: bool,
        tuning: Tuning,
        label: impl Into<Arc<str>>,
    ) -> (Self, Option<mpsc::UnboundedReceiver<Stream>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (accept_tx, accept_rx) = if server {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let counters = stats::counters(codec.name());
        counters.session_opened();
        let shared = Arc::new(Shared {
            flow: codec.flow(),
            closing: codec.closing(),
            state: Mutex::new(State {
                streams: HashMap::new(),
                control: Out::default(),
                data: Out::default(),
                error: None,
                going_away: false,
                retired: false,
                next_id: codec.first_id(server),
                received: 0,
                full: 0,
                write_waiting: None,
                paused_while_waiting: false,
                grown: 0,
                rtt: None,
                rtt_pinned: false,
                ping: None,
                pings: 0,
                accept: accept_tx,
            }),
            codec,
            server,
            tuning,
            label: label.into(),
            counters,
            writer: Notify::new(),
            reader: Notify::new(),
            task: Mutex::new(None),
        });
        // Read and written by one task: a connection's halves polled from
        // two tasks may each take the other's wakeup, as a TLS stream that
        // writes while it reads does.
        let (r, w) = tokio::io::split(conn);
        let (driver, task) = abortable({
            let shared = shared.clone();
            async move {
                let writer = write_loop(&shared, w);
                tokio::pin!(writer);
                let reason = tokio::select! {
                    result = read_loop(&shared, r) => match result {
                        Ok(()) => "connection closed".to_string(),
                        Err(e) => e.to_string(),
                    },
                    reason = &mut writer => {
                        shared.fail(reason);
                        return;
                    }
                    reason = tick_loop(&shared) => reason,
                };
                shared.fail(reason);
                // What the session had to say before it ended, as a reason
                // the protocol gives the peer, still goes out.
                let _ = tokio::time::timeout(CLOSE_GRACE, writer).await;
            }
        });
        *shared.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        crate::runtime::scope::spawn("mux session", driver);
        shared.ping();
        (Session { shared }, accept_rx)
    }

    /// Opens a stream.
    pub fn open(&self) -> io::Result<Stream> {
        self.open_with(&[])
    }

    /// Opens a stream whose first data, sent with what opens it, is
    /// `first`: no more than `INITIAL_WINDOW`.
    pub fn open_with(&self, first: &[u8]) -> io::Result<Stream> {
        let name = self.shared.codec.name();
        let mut state = self.shared.lock();
        if let Some(e) = &state.error {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, e.clone()));
        }
        if state.going_away || state.retired {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{}: going away", name),
            ));
        }
        if state.streams.len() >= MAX_STREAMS {
            return Err(io::Error::other(format!("{}: too many streams", name)));
        }
        let id = state.next_id;
        state.next_id = id
            .checked_add(self.shared.codec.id_step())
            .filter(|id| *id <= self.shared.codec.max_id())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("{}: stream ids exhausted", name),
                )
            })?;
        let mut slot = Slot::new(self.shared.flow);
        if self.shared.flow == Flow::Window {
            if first.len() > slot.send_window as usize {
                return Err(io::Error::other(format!(
                    "{}: more to open a stream with than its window",
                    name
                )));
            }
            slot.send_window -= first.len() as u32;
        }
        state.streams.insert(id, slot);
        self.shared.counters.stream_opened();
        state.data.push(self.shared.codec.open(id, first));
        drop(state);
        self.shared.wake_writer();
        Ok(Stream {
            id,
            shared: self.shared.clone(),
        })
    }

    pub fn num_streams(&self) -> usize {
        self.shared.lock().streams.len()
    }

    /// Stream data received, all told.
    pub fn received(&self) -> u64 {
        self.shared.lock().received
    }

    /// Whether the session has ended, or the peer takes no new streams.
    pub fn is_closed(&self) -> bool {
        let state = self.shared.lock();
        state.error.is_some() || state.going_away
    }

    /// Whether a new stream may go on the session: it is not closed, and
    /// not retired, as it is once one of its streams ended abruptly. A
    /// retired session's streams go on, and it ends with the last.
    pub fn is_reusable(&self) -> bool {
        let state = self.shared.lock();
        state.error.is_none() && !state.going_away && !state.retired
    }

    /// Ends the session and every stream on it, at once.
    pub fn close(&self) {
        self.shared.abort("closed");
    }

    /// What closes the session, as `close` does, without keeping it.
    pub fn closer(&self) -> impl Fn() + Send + Sync + 'static {
        let shared = Arc::downgrade(&self.shared);
        move || {
            if let Some(shared) = shared.upgrade() {
                shared.abort("closed");
            }
        }
    }

    /// Takes no new streams, and ends the session once the last stream is
    /// done.
    pub fn retire(&self) {
        let mut state = self.shared.lock();
        state.retired = true;
        let accept = state.accept.take();
        let idle = state.streams.is_empty();
        drop(state);
        drop(accept);
        if idle {
            self.shared.fail("retired".to_string());
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Reads the connection until it ends, and does what its frames ask.
async fn read_loop<R: AsyncRead + Unpin>(shared: &Arc<Shared>, mut r: R) -> io::Result<()> {
    let mut decoder = shared.codec.decoder(shared.server);
    let mut buf = BytesMut::new();
    let mut want = READ_SMALL;
    loop {
        while let Some(event) = decoder.decode(&mut buf)? {
            shared.apply(event)?;
        }
        shared.wait_for_room().await;
        buf.reserve(want);
        let room = buf.capacity() - buf.len();
        let read = match buf.is_empty() && want > READ_SMALL {
            // Nothing half read: once nothing has come for a while either,
            // the wait goes on with a small buffer, the large one given
            // back. What is ready is read without a timer.
            true => match r.read_buf(&mut buf).now_or_never() {
                Some(read) => read,
                None => match timeout(READ_IDLE_AFTER, r.read_buf(&mut buf)).await {
                    Ok(read) => read,
                    Err(_) => {
                        buf = BytesMut::with_capacity(READ_SMALL);
                        want = READ_SMALL;
                        r.read_buf(&mut buf).await
                    }
                },
            },
            false => r.read_buf(&mut buf).await,
        };
        match read? {
            0 if buf.is_empty() => return Ok(()),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n if n == room => want = (want * 2).min(READ_BUFFER),
            _ => {}
        }
    }
}

/// Writes what is queued until the session ends and all of it is written,
/// and says why.
async fn write_loop<W: AsyncWrite + Unpin>(shared: &Shared, mut w: W) -> String {
    let mut batch = BytesMut::new();
    let mut shaper = shared.codec.shaper();
    loop {
        let notified = shared.writer.notified();
        let shaped = shaper.as_mut().is_some_and(|s| s.active());
        let (ended, control, data) = {
            let mut guard = shared.lock();
            let state = &mut *guard;
            batch.reserve((state.control.bytes + state.data.bytes).min(WRITE_BATCH));
            let control = take(&mut state.control, &mut batch, shaped);
            let data = match shaped && control > 0 {
                true => 0,
                false => take(&mut state.data, &mut batch, shaped),
            };
            (state.error.is_some(), control, data)
        };
        if batch.is_empty() {
            if ended {
                let _ = w.shutdown().await;
                return "closed".to_string();
            }
            // Nothing to write: the batch's memory goes back until there
            // is.
            batch = BytesMut::new();
            notified.await;
            continue;
        }
        shared.wrote();
        let result = async {
            match shaper.as_mut().filter(|_| shaped) {
                Some(shaper) => {
                    for record in shaper.shape(batch.split()) {
                        write_all(shared, &mut w, &record).await?;
                        w.flush().await?;
                    }
                    Ok(())
                }
                None => {
                    write_all(shared, &mut w, &batch).await?;
                    w.flush().await
                }
            }
        }
        .await;
        batch.clear();
        if let Err(e) = result {
            return format!("write: {}", e);
        }
        trace!("{} wrote {} bytes", shared.codec.name(), control + data);
        let mut state = shared.lock();
        state.write_waiting = None;
        state.control.bytes -= control;
        state.data.bytes -= data;
        if data > 0 && state.data.bytes < OUT_SOFT_LIMIT {
            for slot in state.streams.values_mut() {
                if let Some(w) = slot.write_waker.take() {
                    w.wake();
                }
            }
        }
    }
}

/// Writes all of `buf`, and tells the session each time the connection
/// takes some of it.
async fn write_all<W: AsyncWrite + Unpin>(
    shared: &Shared,
    w: &mut W,
    mut buf: &[u8],
) -> io::Result<()> {
    while !buf.is_empty() {
        let n = w.write(buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        shared.wrote();
    }
    Ok(())
}

/// Moves frames from `out` to `batch` while it has room, or only one,
/// and says how many bytes.
fn take(out: &mut Out, batch: &mut BytesMut, one: bool) -> usize {
    let mut taken = 0;
    while let Some(frame) = out.queue.front() {
        if !batch.is_empty() && (one || batch.len() + frame.len() > WRITE_BATCH) {
            break;
        }
        taken += frame.len();
        batch.extend_from_slice(frame);
        out.queue.pop_front();
    }
    taken
}

/// Looks for stalled streams and a stalled connection, and measures the
/// round trip, until the session has ended and had its while to write
/// what it had left.
async fn tick_loop(shared: &Shared) -> String {
    let every = shared.tuning.stall_check();
    loop {
        tokio::time::sleep(every).await;
        if shared.lock().error.is_some() {
            tokio::time::sleep(CLOSE_GRACE).await;
            return "closed, and could not write what it had left".to_string();
        }
        if let Some(reason) = shared.check_write_stall() {
            return reason;
        }
        shared.check_stalls();
        if !shared.lock().streams.is_empty() {
            shared.ping();
        }
    }
}

/// One stream of a session.
pub struct Stream {
    id: u32,
    shared: Arc<Shared>,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sends a control frame of the protocol's about this stream, ahead of
    /// stream data.
    pub fn send_control(&self, frame: Bytes) -> io::Result<()> {
        let mut state = self.shared.lock();
        if state.error.is_some() {
            return Err(closed(&self.shared, &state));
        }
        state.control.push(frame);
        drop(state);
        self.shared.wake_writer();
        Ok(())
    }

    /// Takes the session's round trip to be `rtt`, whatever it measures.
    #[cfg(test)]
    pub fn pin_rtt(&self, rtt: Duration) {
        let mut state = self.shared.lock();
        state.rtt = Some(rtt);
        state.rtt_pinned = true;
    }

    /// The window this stream grants the peer, as it has grown.
    #[cfg(test)]
    pub fn window(&self) -> u32 {
        self.shared
            .lock()
            .streams
            .get(&self.id)
            .map_or(0, |slot| slot.window)
    }
}

/// Takes `growth` more window for stream `id` out of the session's
/// budget, if there is room, or once the idle streams' grown windows are
/// taken back: back to `INITIAL_WINDOW`, which their peers are held to as
/// they use up what they were granted before.
fn make_room(state: &mut State, id: u32, growth: u32, tuning: &Tuning, now: Instant) -> bool {
    let budget = SESSION_GROWTH * u64::from(tuning.window_max);
    let need = u64::from(growth);
    if state.grown + need > budget {
        for (other, slot) in state.streams.iter_mut() {
            if *other == id
                || slot.window <= INITIAL_WINDOW
                || slot.inbox > 0
                || now.saturating_duration_since(slot.progress) < RECLAIM_IDLE
            {
                continue;
            }
            state.grown -= u64::from(slot.window - INITIAL_WINDOW);
            slot.window = INITIAL_WINDOW;
            slot.epoch_start = now;
            slot.epoch_read = 0;
            if state.grown + need <= budget {
                break;
            }
        }
    }
    if state.grown + need > budget {
        return false;
    }
    state.grown += need;
    true
}

fn closed(shared: &Shared, state: &State) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!(
            "{} session closed: {}",
            shared.codec.name(),
            state.error.as_deref().unwrap_or("unknown")
        ),
    )
}

fn refused(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, why.to_string())
}

fn stalled(shared: &Shared) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "{}: stream reset, nothing read its data for {}s",
            shared.codec.name(),
            shared.tuning.stall_timeout.as_secs()
        ),
    )
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        let Some(slot) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed(shared, state)));
        };
        if slot.stalled {
            return Poll::Ready(Err(stalled(shared)));
        }
        if !slot.recv.is_empty() {
            // All that is queued, as far as `buf` holds it: a read of one
            // frame's data at a time made a write of each downstream.
            let mut n = 0;
            while let Some(front) = slot.recv.front_mut() {
                let take = front.len().min(buf.remaining());
                if take == 0 {
                    break;
                }
                buf.put_slice(&front[..take]);
                front.advance(take);
                n += take;
                if front.is_empty() {
                    slot.recv.pop_front();
                }
            }
            let now = Instant::now();
            let was_full = slot.inbox >= shared.tuning.inbox;
            slot.inbox -= n;
            slot.progress = now;
            if shared.flow == Flow::Pause && was_full && slot.inbox < shared.tuning.inbox {
                state.full -= 1;
                shared.reader.notify_one();
            }
            if shared.flow == Flow::Window && !slot.reset && state.error.is_none() {
                slot.consumed += n as u32;
                slot.epoch_read += n as u64;
                // As quic-go does: more window once a quarter of it is
                // read, and twice the window if half of it was read in
                // less than what it takes to come in two round trips.
                if slot.consumed >= slot.window / 4 {
                    let mut growth = 0;
                    if slot.epoch_read > u64::from(slot.window / 2) {
                        if let Some(rtt) = state.rtt {
                            let fraction = slot.epoch_read as f64 / f64::from(slot.window);
                            let fast = now.saturating_duration_since(slot.epoch_start)
                                < rtt.mul_f64(4.0 * fraction);
                            let grown = slot.window.saturating_mul(2).min(shared.tuning.window_max);
                            if fast {
                                growth = grown.saturating_sub(slot.window);
                            }
                        }
                        slot.epoch_start = now;
                        slot.epoch_read = 0;
                    }
                    let id = self.id;
                    if growth > 0 && !make_room(state, id, growth, &shared.tuning, now) {
                        growth = 0;
                    }
                    let Some(slot) = state.streams.get_mut(&id) else {
                        return Poll::Ready(Ok(()));
                    };
                    slot.window += growth;
                    slot.consumed = 0;
                    // Topped up to the window: all that was read, and what
                    // it grew by; less, or nothing, while the peer still
                    // has more than the window to send, once the stream's
                    // growth was taken back.
                    let delta = slot
                        .window
                        .saturating_sub(slot.recv_window.saturating_add(slot.inbox as u32));
                    if delta > 0 {
                        slot.recv_window += delta;
                        if let Some(frame) = shared.codec.window_update(id, delta) {
                            state.control.push(frame);
                            shared.wake_writer();
                        }
                    }
                }
            }
            return Poll::Ready(Ok(()));
        }
        if let Some(why) = &slot.refused {
            return Poll::Ready(Err(refused(why)));
        }
        if slot.remote_fin || (shared.closing == Closing::Whole && slot.local_fin) {
            return Poll::Ready(Ok(()));
        }
        if slot.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if state.error.is_some() {
            return Poll::Ready(Err(closed(shared, state)));
        }
        slot.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return Poll::Ready(Err(closed(shared, state)));
        }
        let Some(slot) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed(shared, state)));
        };
        if slot.stalled {
            return Poll::Ready(Err(stalled(shared)));
        }
        if let Some(why) = &slot.refused {
            return Poll::Ready(Err(refused(why)));
        }
        if slot.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        // Without half-close, a stream the peer finished is closed.
        if slot.local_fin || (shared.closing != Closing::Half && slot.remote_fin) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let windowed = shared.flow == Flow::Window;
        if state.data.bytes >= OUT_SOFT_LIMIT || (windowed && slot.send_window == 0) {
            slot.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut n = buf.len().min(shared.codec.max_data());
        if windowed {
            n = n.min(slot.send_window as usize);
            slot.send_window -= n as u32;
        }
        state.data.push(shared.codec.data(self.id, &buf[..n]));
        drop(guard);
        shared.wake_writer();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Sends a FIN: with half-close, the stream can still be read; without,
    /// it is over both ways.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.shared.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return Poll::Ready(Ok(()));
        }
        if let Some(slot) = state.streams.get_mut(&self.id) {
            if !slot.local_fin && !slot.reset && !slot.deaf(self.shared.closing) {
                slot.local_fin = true;
                // Over both ways: a read waiting sees the end.
                if self.shared.closing == Closing::Whole {
                    slot.wake();
                }
                state.data.push(self.shared.codec.fin(self.id));
                drop(guard);
                self.shared.wake_writer();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        let Some(slot) = state.streams.remove(&self.id) else {
            return;
        };
        shared.counters.stream_closed();
        if shared.flow == Flow::Pause && slot.inbox >= shared.tuning.inbox {
            state.full -= 1;
            shared.reader.notify_one();
        }
        state.grown -= u64::from(slot.window.saturating_sub(INITIAL_WINDOW));
        // Without half-close, dropped while the peer may still be sending
        // -- before its FIN, unless it reset the stream -- or reset here
        // for stalling: the session takes no new streams (`retire_abrupt`).
        // The peer never answers this end's FIN: a stream shut down here is
        // taken to be finished unless data came after the FIN, or comes
        // once it is gone (`deliver`). With half-close the stream is reset,
        // alone, and the session goes on. A server's peer opens the
        // streams, and decides for itself.
        let finished = slot.remote_fin || slot.reset || (slot.local_fin && !slot.sent_past_fin);
        if !shared.server
            && shared.closing == Closing::Whole
            && slot.refused.is_none()
            && (slot.stalled || !finished)
        {
            shared.retire_abrupt(state, self.id);
        }
        let last = state.retired && state.streams.is_empty();
        if state.error.is_none() && !slot.stalled && slot.refused.is_none() {
            let codec = &shared.codec;
            let frame = match shared.closing {
                Closing::Whole if !slot.local_fin && !slot.remote_fin => Some(codec.fin(self.id)),
                Closing::Whole => None,
                // Abandoned before the peer finished: reset, so that it
                // stops sending, where Go's yamux `Close` sends a FIN and
                // reads on. Otherwise finish, if not done yet.
                Closing::Half if !slot.remote_fin && !slot.reset => Some(codec.reset(self.id)),
                Closing::Half if !slot.local_fin && !slot.reset => Some(codec.fin(self.id)),
                Closing::Half => None,
            };
            if let Some(frame) = frame {
                state.data.push(frame);
                shared.wake_writer();
            }
        }
        drop(guard);
        if last {
            shared.fail("retired, and its last stream is done".to_string());
        }
    }
}
