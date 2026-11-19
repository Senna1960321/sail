use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Upper bound on the bytes of idle buffers cached per thread, unless
/// `set_pool_max` says otherwise: `relay.buffer_pool`.
const BUFFER_POOL_MAX_BYTES: usize = 1024 * 1024;

/// The bytes of idle buffers a thread caches at most: the process's, as
/// the pool is the thread's; the last instance to start sets it.
static POOL_MAX: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(BUFFER_POOL_MAX_BYTES);

/// Caches at most `bytes` of idle buffers a thread, from now on: a pool
/// over it shrinks as its buffers are taken.
pub(crate) fn set_pool_max(bytes: usize) {
    POOL_MAX.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

struct BufferPool {
    bytes: usize,
    buffers: Vec<Box<[u8]>>,
}

thread_local! {
    // Relay buffers released by idle connections, reused by the next reader on
    // this thread instead of going back to the allocator.
    static BUFFER_POOL: RefCell<BufferPool> = const {
        RefCell::new(BufferPool { bytes: 0, buffers: Vec::new() })
    };
}

pub(crate) fn acquire_buffer(size: usize) -> io::Result<Box<[u8]>> {
    let pooled = BUFFER_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let i = pool.buffers.iter().rposition(|b| b.len() == size)?;
        let buf = pool.buffers.swap_remove(i);
        pool.bytes -= buf.len();
        Some(buf)
    });
    if let Some(buf) = pooled {
        return Ok(buf);
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(size)
        .map_err(|e| io::Error::other(format!("new buffer failed: {}", e)))?;
    buf.resize(size, 0);
    Ok(buf.into_boxed_slice())
}

pub(crate) fn release_buffer(buf: Box<[u8]>) {
    let max = POOL_MAX.load(std::sync::atomic::Ordering::Relaxed);
    BUFFER_POOL.with(|pool| pool.borrow_mut().keep(buf, max));
}

impl BufferPool {
    /// Keeps `buf` for reuse if the pool stays within `max` bytes with it;
    /// otherwise it goes back to the allocator.
    fn keep(&mut self, buf: Box<[u8]>, max: usize) {
        if self.bytes + buf.len() <= max {
            self.bytes += buf.len();
            self.buffers.push(buf);
        }
    }
}

/// A copy buffer that only holds memory while it has data in flight: the
/// buffer is taken from a per-thread pool right before reading and given back
/// as soon as the reader has nothing to offer, so idle connections cost no
/// buffer memory.
///
/// The buffer size adapts between `min_size` and `max_size`: a read that fills
/// the whole buffer doubles the next one, cutting syscalls on bulk transfers,
/// and a read using at most a quarter of it halves the next one.
#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    size: usize,
    min_size: usize,
    max_size: usize,
    buf: Option<Box<[u8]>>,
    /// Whether bytes were read or written since the flag was last taken.
    progressed: bool,
    /// Whether the last Pending was the writer's: data waiting to be
    /// written or flushed, rather than nothing to read.
    writer_blocked: bool,
}

impl CopyBuffer {
    pub fn new() -> Self {
        Self::with_sizes(2 * 1024, 2 * 1024)
    }

    pub fn new_with_capacity(size: usize) -> Result<Self, std::io::Error> {
        Self::new_adaptive(size, size)
    }

    pub fn new_adaptive(min_size: usize, max_size: usize) -> Result<Self, std::io::Error> {
        if min_size == 0 || max_size < min_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid buffer sizes: min={} max={}", min_size, max_size),
            ));
        }
        Ok(Self::with_sizes(min_size, max_size))
    }

    fn with_sizes(min_size: usize, max_size: usize) -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            size: min_size,
            min_size,
            max_size,
            buf: None,
            progressed: false,
            writer_blocked: false,
        }
    }

    /// Whether bytes moved since the last call.
    fn take_progress(&mut self) -> bool {
        std::mem::take(&mut self.progressed)
    }

    /// Whether the copy waits on its writer: it has data the writer does
    /// not take, or a flush the writer does not finish.
    fn writer_blocked(&self) -> bool {
        self.writer_blocked
    }

    fn adapt_size(&mut self, n: usize) {
        if n == self.size && self.size < self.max_size {
            self.size = (self.size * 2).min(self.max_size);
        } else if n <= self.size / 4 && self.size > self.min_size {
            self.size = (self.size / 2).max(self.min_size);
        }
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                if self.buf.as_ref().is_some_and(|b| b.len() != self.size) {
                    release_buffer(self.buf.take().expect("checked above"));
                }
                if self.buf.is_none() {
                    self.buf = Some(acquire_buffer(self.size)?);
                }
                let me = &mut *self;
                let mut buf = ReadBuf::new(me.buf.as_deref_mut().expect("buffer acquired above"));

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Nothing buffered and nothing to read: hand the buffer
                        // back while this direction waits. A reader returning
                        // Pending yields no data, so nothing is lost.
                        if let Some(buf) = self.buf.take() {
                            release_buffer(buf);
                        }
                        // Try flushing when the reader has no progress to avoid deadlock
                        // when the reader depends on buffered writer.
                        if self.need_flush {
                            self.writer_blocked = true;
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }
                        self.writer_blocked = false;

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                    self.adapt_size(n);
                    self.progressed = true;
                }
            }

            // If our buffer has some data, let's write it out!
            self.writer_blocked = true;
            while self.pos < self.cap {
                let me = &mut *self;
                let data = me.buf.as_deref().expect("buffer holds unwritten data");
                let i = ready!(writer.as_mut().poll_write(cx, &data[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                    self.progressed = true;
                }
            }

            // If pos larger than cap, this loop will never stop.
            // In particular, user's wrong poll_write implementation returning
            // incorrect written length may lead to thread blocking.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

impl Drop for CopyBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            release_buffer(buf);
        }
    }
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// When a relay gives up on a direction that does not move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTimeouts {
    /// A direction with data its writer does not take (or a flush or a
    /// shutdown it does not finish) for this long aborts the relay, both
    /// sides closed.
    pub write_stall: Duration,
    /// Idle after half-close: once `b` closed its side, `a` to `b` is
    /// closed after this long without a byte moving, counted from the
    /// close or the last byte, whichever is later.
    pub a_to_b_idle: Duration,
    /// Idle after half-close the other way: `b` to `a` once `a` closed
    /// its side.
    pub b_to_a_idle: Duration,
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

/// Why a direction that stood still is given up on.
enum Expired {
    WriteStall,
    Idle,
}

/// One direction of a relay, and when it last moved.
struct Direction {
    state: TransferState,
    count: u64,
    /// When bytes last moved this way, or the other direction closed,
    /// whichever is later.
    last_progress: Instant,
    /// Set once the other direction is done: how long this one may then
    /// stand still.
    idle_timeout: Option<Duration>,
    /// Wakes the relay at the earliest deadline it has, or earlier: it is
    /// reset only when it fires, not on every byte.
    timer: Option<Pin<Box<Sleep>>>,
    /// Since when it waits, and whether on its writer: counted when it is
    /// polled again (sail#69).
    #[cfg(feature = "internal-diagnostics")]
    waiting: Option<(std::time::Instant, bool)>,
    /// From the outbound to the client.
    #[cfg(feature = "internal-diagnostics")]
    downlink: bool,
}

impl Direction {
    fn new(buf: CopyBuffer) -> Self {
        Self {
            state: TransferState::Running(buf),
            count: 0,
            last_progress: Instant::now(),
            idle_timeout: None,
            timer: None,
            #[cfg(feature = "internal-diagnostics")]
            waiting: None,
            #[cfg(feature = "internal-diagnostics")]
            downlink: false,
        }
    }

    /// The direction from the outbound to the client.
    #[cfg(feature = "internal-diagnostics")]
    fn downlink(mut self) -> Self {
        self.downlink = true;
        self
    }

    fn is_done(&self) -> bool {
        matches!(self.state, TransferState::Done)
    }

    /// The other direction is done: from now on, this one ends when it has
    /// stood still for `idle`.
    fn other_done(&mut self, idle: Duration) {
        if let TransferState::Running(_) = self.state {
            self.last_progress = Instant::now();
            self.idle_timeout = Some(idle);
        }
    }

    /// Copies from `reader` to `writer`, then shuts `writer` down: ready
    /// once that is done, or failed.
    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        write_stall: Duration,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            match &mut self.state {
                TransferState::Running(buf) => {
                    #[cfg(feature = "internal-diagnostics")]
                    if let Some((since, writer)) = self.waiting.take() {
                        crate::app::transport_diagnostics::relay_waited(
                            self.downlink,
                            writer,
                            since.elapsed(),
                        );
                    }
                    let res = buf.poll_copy(cx, reader.as_mut(), writer.as_mut());
                    if buf.take_progress() {
                        self.last_progress = Instant::now();
                    }
                    match res {
                        Poll::Ready(Ok(count)) => {
                            self.state = TransferState::ShuttingDown(count);
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            let amount = buf.amount_transferred();
                            let blocked = buf.writer_blocked();
                            #[cfg(feature = "internal-diagnostics")]
                            {
                                self.waiting = Some((std::time::Instant::now(), blocked));
                            }
                            match ready!(self.poll_deadline(cx, blocked, write_stall)) {
                                Expired::WriteStall => return Poll::Ready(Err(write_stalled())),
                                Expired::Idle => {
                                    self.state = TransferState::ShuttingDown(amount);
                                }
                            }
                        }
                    }
                    // Shutting down, only a stalled writer is given up on.
                    self.idle_timeout = None;
                }
                TransferState::ShuttingDown(count) => {
                    let count = *count;
                    match writer.as_mut().poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            self.count = count;
                            self.state = TransferState::Done;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            ready!(self.poll_deadline(cx, true, write_stall));
                            return Poll::Ready(Err(write_stalled()));
                        }
                    }
                }
                TransferState::Done => return Poll::Ready(Ok(())),
            }
        }
    }

    /// Pending until the direction has stood still for longer than it may:
    /// `write_stall` while `writer_blocked`, the idle timeout once the other
    /// direction is done.
    fn poll_deadline(
        &mut self,
        cx: &mut Context<'_>,
        writer_blocked: bool,
        write_stall: Duration,
    ) -> Poll<Expired> {
        let stall = writer_blocked.then(|| (self.last_progress + write_stall, Expired::WriteStall));
        let idle = self
            .idle_timeout
            .map(|idle| (self.last_progress + idle, Expired::Idle));
        let (deadline, expired) = match (stall, idle) {
            (Some(s), Some(i)) => {
                if s.0 <= i.0 {
                    s
                } else {
                    i
                }
            }
            (Some(d), None) | (None, Some(d)) => d,
            (None, None) => return Poll::Pending,
        };
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if timer.deadline() > deadline {
            timer.as_mut().reset(deadline);
        }
        loop {
            ready!(timer.as_mut().poll(cx));
            if Instant::now() >= deadline {
                return Poll::Ready(expired);
            }
            // Bytes moved since the timer was set: wait out the rest.
            timer.as_mut().reset(deadline);
        }
    }
}

/// A side that took nothing it was written for too long.
#[derive(Debug)]
struct WriteStalled;

impl std::fmt::Display for WriteStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay write stalled")
    }
}

impl std::error::Error for WriteStalled {}

fn write_stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, WriteStalled)
}

/// Whether a relay ended with `e` because a side took nothing it was
/// written for longer than its write-stall timeout.
pub fn is_write_stall(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<WriteStalled>())
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: Direction,
    b_to_a: Direction,
    timeouts: RelayTimeouts,
    /// Whether `b` to `a` goes first at the next poll: the directions take
    /// turns. A direction with data and room copies until the task's
    /// budget is spent (tokio's, 128 reads and writes a poll), and what
    /// is polled after it then moves nothing; were one always first, the
    /// other would wait for it to end. Measured over loopback with both
    /// directions offered without limit: the downlink ran at 0.07 of
    /// 31 Gbit/s until the uplink was done.
    b_first: bool,
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            timeouts,
            b_first,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);
        let b_goes_first = std::mem::replace(b_first, !*b_first);

        loop {
            let a_to_b_open = !a_to_b.is_done();
            let b_to_a_open = !b_to_a.is_done();
            for b_to_a_now in [b_goes_first, !b_goes_first] {
                let copied = match b_to_a_now {
                    false if a_to_b_open => {
                        a_to_b.poll_copy(cx, a.as_mut(), b.as_mut(), timeouts.write_stall)
                    }
                    true if b_to_a_open => {
                        b_to_a.poll_copy(cx, b.as_mut(), a.as_mut(), timeouts.write_stall)
                    }
                    _ => continue,
                };
                if let Poll::Ready(Err(err)) = copied {
                    return Poll::Ready(Err(err));
                }
            }
            if a_to_b.is_done() && b_to_a.is_done() {
                return Poll::Ready(Ok((a_to_b.count, b_to_a.count)));
            }
            // A direction just done leaves the other on its idle timeout,
            // which it must be polled again to arm.
            if a_to_b_open && a_to_b.is_done() {
                b_to_a.other_done(timeouts.b_to_a_idle);
            } else if b_to_a_open && b_to_a.is_done() {
                a_to_b.other_done(timeouts.a_to_b_idle);
            } else {
                return Poll::Pending;
            }
        }
    }
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    min_size: usize,
    max_size: usize,
    timeouts: RelayTimeouts,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: Direction::new(CopyBuffer::new_adaptive(min_size, max_size)?),
        #[cfg(not(feature = "internal-diagnostics"))]
        b_to_a: Direction::new(CopyBuffer::new_adaptive(min_size, max_size)?),
        #[cfg(feature = "internal-diagnostics")]
        b_to_a: Direction::new(CopyBuffer::new_adaptive(min_size, max_size)?).downlink(),
        timeouts,
        b_first: false,
    }
    .await
}

/// Relays `a` and `b` both ways with the buffers and timeouts `relay`
/// sets, as a routed connection is: `a` is the client's side.
pub async fn copy_with_options<A, B>(
    a: &mut A,
    b: &mut B,
    relay: &crate::runtime::options::Relay,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_buf_bidirectional_with_timeout(
        a,
        b,
        relay.buffer_size * 1024,
        relay.buffer_max_size.max(relay.buffer_size) * 1024,
        RelayTimeouts {
            write_stall: relay.write_stall_timeout,
            a_to_b_idle: relay.uplink_idle_timeout,
            b_to_a_idle: relay.downlink_idle_timeout,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    /// A thread keeps idle buffers up to the pool's bound, and gives back
    /// the rest: the mobile and router profiles' 256 KiB hold sixteen of
    /// 16 KiB, a desktop's 1 MiB sixty-four.
    #[test]
    fn the_pool_keeps_buffers_up_to_its_bound() {
        use crate::runtime::{Profile, RuntimeOptions};
        let bound = |profile| RuntimeOptions::profile(profile).relay.buffer_pool << 10;
        assert_eq!(bound(Profile::Mobile), 256 << 10);
        assert_eq!(bound(Profile::Router), 256 << 10);
        assert_eq!(bound(Profile::Desktop), 1 << 20);
        for (profile, kept) in [(Profile::Mobile, 16), (Profile::Desktop, 64)] {
            let mut pool = BufferPool {
                bytes: 0,
                buffers: Vec::new(),
            };
            for _ in 0..100 {
                pool.keep(vec![0u8; 16 << 10].into_boxed_slice(), bound(profile));
            }
            assert_eq!(pool.buffers.len(), kept, "{:?}", profile);
            assert_eq!(pool.bytes, kept * (16 << 10));
        }
    }

    use super::*;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::task::JoinHandle;
    use tokio::time::sleep;

    const STALL: Duration = Duration::from_secs(300);

    fn timeouts() -> RelayTimeouts {
        let relay = crate::runtime::options::Relay::default();
        RelayTimeouts {
            write_stall: relay.write_stall_timeout,
            a_to_b_idle: relay.uplink_idle_timeout,
            b_to_a_idle: relay.downlink_idle_timeout,
        }
    }

    /// A relay between a client and a server, each end a pipe of `size`
    /// bytes: the client's end, the relay, and the server's end.
    fn relay(
        size: usize,
    ) -> (
        DuplexStream,
        JoinHandle<io::Result<(u64, u64)>>,
        DuplexStream,
    ) {
        let (client, mut a) = duplex(size);
        let (mut b, server) = duplex(size);
        let relay = tokio::spawn(async move {
            copy_buf_bidirectional_with_timeout(&mut a, &mut b, 1024, 1024, timeouts()).await
        });
        (client, relay, server)
    }

    /// An end that always has bytes to read and always takes what is
    /// written, counting it, and that spends the task's budget as a socket
    /// does.
    struct Endless(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl AsyncRead for Endless {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let budget = ready!(tokio::task::coop::poll_proceed(cx));
            let n = buf.remaining();
            buf.initialize_unfilled_to(n).fill(7);
            buf.advance(n);
            budget.made_progress();
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Endless {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let budget = ready!(tokio::task::coop::poll_proceed(cx));
            self.0
                .fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
            budget.made_progress();
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Both directions with data and room without end: each moves, turn
    /// by turn. With one always polled first the other moved nothing, the
    /// first spending the task's budget at every poll.
    #[tokio::test]
    async fn two_busy_directions_take_turns() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let (to_a, to_b) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (mut a, mut b) = (Endless(to_a.clone()), Endless(to_b.clone()));
        let relay = tokio::spawn(async move {
            copy_buf_bidirectional_with_timeout(&mut a, &mut b, 1024, 1024, timeouts()).await
        });
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        relay.abort();
        let (to_a, to_b) = (to_a.load(Ordering::Relaxed), to_b.load(Ordering::Relaxed));
        assert!(to_a > 0 && to_b > 0, "{} to a, {} to b", to_a, to_b);
        assert!(
            to_a.min(to_b) * 2 >= to_a.max(to_b),
            "{} to a, {} to b",
            to_a,
            to_b
        );
    }

    #[test]
    fn the_defaults_are_the_measured_ones() {
        let t = timeouts();
        assert_eq!(t.write_stall, STALL);
        assert_eq!(t.a_to_b_idle, Duration::from_secs(300));
        assert_eq!(t.b_to_a_idle, Duration::from_secs(300));
    }

    /// A server that takes nothing for the write-stall timeout ends the
    /// relay, both sides closed.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_write_aborts_the_relay() {
        let (mut client, relay, mut server) = relay(64);
        let writer = tokio::spawn(async move {
            let _ = client.write_all(&[7u8; 4096]).await;
            client
        });
        sleep(STALL - Duration::from_secs(1)).await;
        assert!(!relay.is_finished(), "cut before the timeout");
        sleep(Duration::from_secs(2)).await;
        let err = relay.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // Told apart from a side's own timeout, for the connection's record.
        assert!(is_write_stall(&err));
        assert!(!is_write_stall(&io::Error::from(io::ErrorKind::TimedOut)));
        // The relay's ends are gone: both sides see the connection close.
        let mut client = writer.await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        let mut seen = 0;
        loop {
            match server.read(&mut buf).await.unwrap() {
                0 => break,
                n => seen += n,
            }
        }
        assert!(seen < 4096);
    }

    /// A writer that takes a little now and then is slow, not stalled.
    #[tokio::test(start_paused = true)]
    async fn a_slow_writer_is_not_a_stalled_one() {
        let (mut client, relay, mut server) = relay(64);
        tokio::spawn(async move {
            let _ = client.write_all(&[7u8; 4096]).await;
            // Kept open: the relay is to end only by the stall.
            std::future::pending::<()>().await;
            drop(client);
        });
        for _ in 0..10 {
            sleep(STALL * 2 / 3).await;
            let mut buf = [0u8; 16];
            assert!(server.read(&mut buf).await.unwrap() > 0);
            assert!(!relay.is_finished(), "a moving direction cut");
        }
        // Then nothing is taken any more.
        sleep(STALL + Duration::from_secs(1)).await;
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    /// Slow upload: the client sent everything and closed its side, and
    /// the server answers only once what it was sent has made its way to
    /// it, longer after than the old half-close timeout of 10 s. The answer
    /// still arrives.
    #[tokio::test(start_paused = true)]
    async fn a_response_after_a_slow_upload_is_delivered() {
        let (mut client, relay, mut server) = relay(1 << 16);
        client.write_all(b"upload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut upload = Vec::new();
        server.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload, b"upload");
        // What the server does with it takes a minute.
        sleep(Duration::from_secs(60)).await;
        server.write_all(b"OK 6").await.unwrap();
        server.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"OK 6");
        assert_eq!(relay.await.unwrap().unwrap(), (6, 4));
    }

    /// Once the client closed its side, a server that neither answers nor
    /// closes has its connection reclaimed at the idle timeout, counted
    /// from the last byte it sent.
    #[tokio::test(start_paused = true)]
    async fn a_half_closed_idle_connection_is_reclaimed() {
        let idle = timeouts().b_to_a_idle;
        let (mut client, relay, mut server) = relay(1 << 16);
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(server.read(&mut buf).await.unwrap(), 0);
        // A byte now and then keeps it open, however long.
        for _ in 0..5 {
            sleep(idle - Duration::from_secs(1)).await;
            server.write_all(b"x").await.unwrap();
            assert_eq!(client.read(&mut buf).await.unwrap(), 1);
        }
        assert!(!relay.is_finished(), "a moving direction cut");
        sleep(idle - Duration::from_secs(1)).await;
        assert!(!relay.is_finished(), "cut before the timeout");
        sleep(Duration::from_secs(2)).await;
        assert!(relay.is_finished());
        assert_eq!(relay.await.unwrap().unwrap(), (0, 5));
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        drop(server);
    }

    /// A connection nobody half-closed has no idle timeout.
    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_stays() {
        let (_client, relay, _server) = relay(1 << 16);
        sleep(Duration::from_secs(24 * 3600)).await;
        assert!(!relay.is_finished());
    }
}
