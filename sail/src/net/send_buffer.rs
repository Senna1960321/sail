//! The send buffer of a TCP connection an inbound accepted, grown out of
//! the process's transfer budget while it is what holds the client's
//! transfer back (sail#10).
//!
//! A fixed buffer is the window of a download to a LAN client: at 256 KiB
//! (Linux keeps twice what is set) a client 8 ms away takes about 500
//! Mbit/s a connection, whatever the server behind. One large enough for
//! that, kept by every connection, is what twenty clients that stopped
//! reading would hold. So a connection starts at `inbound.tcp_send_buffer`
//! and doubles, up to `inbound.tcp_send_buffer_max`, when a write finds the
//! buffer full with almost all of it sent and not yet acknowledged: the
//! window, not the network or the client, is the limit then. What is
//! queued unsent tells the two apart, as quinn's windows grow only while
//! they are read about as fast as data arrives. The configured buffer
//! returns to its base when the connection goes a second without filling
//! it, or a write stays blocked a second. Queued data survives that change:
//! its allowance is retained until a later write observes it drained, or
//! the connection closes.
//!
//! What the kernel keeps, twice the size set, is what the budget is
//! charged. Only Linux and Android grow it: elsewhere the size stays as
//! set.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// How long a buffer that grew may go without filling, or stay full, before
/// its configured size returns to the base. Allowance for queued excess
/// stays reserved until a later write observes it drained, or close.
#[cfg(any(target_os = "linux", target_os = "android"))]
const GIVE_BACK_AFTER: Duration = Duration::from_secs(1);

/// An accepted connection, its send buffer grown while that is what holds
/// its client back.
pub struct Growing {
    inner: TcpStream,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    growth: Option<Growth>,
}

impl Growing {
    /// `stream`, whose send buffer was set to `base` bytes, growing up to
    /// `max`; no growth if `max` is not more than `base`, `base` is zero
    /// (the system's own tuning), or outside Linux and Android.
    pub fn new(stream: TcpStream, base: usize, max: usize) -> Self {
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = (base, max);
        Self {
            inner: stream,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            growth: (base > 0 && max > base)
                .then(|| Growth::new(base, max, crate::runtime::transfer_budget::global())),
        }
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.inner
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct Growth {
    budget: &'static crate::runtime::transfer_budget::TransferBudget,
    base: usize,
    max: usize,
    /// The size set now, in bytes.
    size: usize,
    /// Reserved kernel bytes above twice the base. Lowering SO_SNDBUF
    /// does not discard queued data, so this may outlive the larger size.
    reserved: u64,
    /// Whether the last write found the buffer full.
    full: bool,
    /// When a write last found it full.
    last_full: tokio::time::Instant,
    /// Armed while a grown buffer is full: when it fires, the growth goes.
    give_back: Option<Pin<Box<tokio::time::Sleep>>>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Growth {
    fn new(
        base: usize,
        max: usize,
        budget: &'static crate::runtime::transfer_budget::TransferBudget,
    ) -> Self {
        Self {
            budget,
            base,
            max,
            size: base,
            reserved: 0,
            full: false,
            last_full: tokio::time::Instant::now(),
            give_back: None,
        }
    }

    /// What the budget holds for this buffer: what the kernel keeps past
    /// twice the base.
    fn charged(&self) -> u64 {
        self.reserved
    }

    /// After a write to `stream`, which found the buffer full if `full`.
    fn wrote(&mut self, stream: &TcpStream, cx: &mut Context<'_>, full: bool) {
        let now = tokio::time::Instant::now();
        if self.size == self.base && self.reserved != 0 {
            self.release_drained(stream);
        }
        if !full {
            if !self.full && self.size > self.base && now - self.last_full >= GIVE_BACK_AFTER {
                self.shrink(stream);
            }
            self.full = false;
            return;
        }
        if !self.full {
            self.full = true;
            self.last_full = now;
            if self.size < self.max && window_limited(stream, self.size) {
                self.grow(stream);
            }
            if self.size > self.base {
                let deadline = now + GIVE_BACK_AFTER;
                match &mut self.give_back {
                    Some(timer) => timer.as_mut().reset(deadline),
                    None => self.give_back = Some(Box::pin(tokio::time::sleep_until(deadline))),
                }
            }
        }
        if self.size > self.base {
            if let Some(timer) = &mut self.give_back {
                if std::future::Future::poll(timer.as_mut(), cx).is_ready() {
                    self.shrink(stream);
                }
            }
        }
    }

    fn grow(&mut self, stream: &TcpStream) {
        let size = (self.size * 2).min(self.max);
        let more = (2 * (size - self.base) as u64).saturating_sub(self.reserved);
        if more > 0 && !self.budget.try_grow(more) {
            return;
        }
        // Setting it wakes the blocked write.
        if let Err(e) = super::dial::sockopt::send_buffer(socket2::SockRef::from(stream), size) {
            // Its readback can fail after setsockopt has already grown it.
            tracing::debug!("send buffer growth could not be confirmed: {}", e);
        }
        let actual = socket2::SockRef::from(stream)
            .send_buffer_size()
            .map_or(size, |bytes| (bytes / 2).max(self.size).min(size));
        // Refund only unused new allowance. A regrowth may still need the
        // old reservation for data queued before shrink. If readback fails,
        // assume the requested size and keep the provisional reservation.
        let reserved = self.reserved.max(2 * (actual - self.base) as u64);
        self.budget.release(self.reserved + more - reserved);
        self.reserved = reserved;
        self.size = actual;
    }

    fn shrink(&mut self, stream: &TcpStream) {
        // What is queued past the new size drains; nothing more is taken
        // until it has.
        if let Err(e) = super::dial::sockopt::send_buffer(socket2::SockRef::from(stream), self.base)
        {
            tracing::debug!("send buffer not given back: {}", e);
            return;
        }
        self.size = self.base;
        self.release_drained(stream);
    }

    fn release_drained(&mut self, stream: &TcpStream) {
        // A stopped reader may never drain what was queued before shrink.
        // Keep its reservation until the kernel actually releases those bytes.
        // Old kernels without SO_MEMINFO conservatively retain it until close.
        if let Some(queued) = queued_memory(stream) {
            let retained = queued
                .saturating_sub(2 * self.base as u64)
                .min(self.reserved);
            self.budget.release(self.reserved - retained);
            self.reserved = retained;
        }
    }
}

/// Linux SO_MEMINFO's SK_MEMINFO_WMEM_QUEUED is the allocation held by the
/// TCP write queue (including sent but unacknowledged data), not SO_SNDBUF's
/// configured limit or SIOCOUTQ's payload byte count.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn queued_memory(stream: &TcpStream) -> Option<u64> {
    use std::os::unix::io::AsRawFd;
    let mut info = [0u32; 9];
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    // Linux UAPI sock_diag.h; Android libc does not expose these names.
    #[cfg(target_os = "linux")]
    let option = libc::SO_MEMINFO;
    #[cfg(target_os = "android")]
    let option = 55;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (ret == 0 && len as usize >= 6 * std::mem::size_of::<u32>()).then_some(info[5] as u64)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for Growth {
    fn drop(&mut self) {
        self.budget.release(self.charged());
    }
}

/// Whether a full send buffer of `size` bytes is what limits `stream`:
/// almost all of what the kernel keeps (twice `size`) is sent and waits to
/// be acknowledged, less than a quarter queued unsent. Otherwise the
/// network, or a client that reads slower, holds the data back, and a
/// larger buffer would only queue more.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn window_limited(stream: &TcpStream, size: usize) -> bool {
    match unsent(stream) {
        Some(unsent) => unsent < size / 2,
        None => false,
    }
}

/// The start of Linux's `struct tcp_info`, to `tcpi_notsent_bytes` (Linux
/// 4.6): libc's Android one ends before it.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[repr(C)]
#[derive(Default)]
struct TcpInfo {
    bytes: [u8; 8],
    words: [u32; 24],
    rates: [u64; 4],
    segs: [u32; 2],
    notsent_bytes: u32,
}

/// The bytes `stream` has queued and not yet sent; none on a kernel too old
/// to say.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unsent(stream: &TcpStream) -> Option<usize> {
    use std::os::unix::io::AsRawFd;
    let mut info = TcpInfo::default();
    let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    let end = std::mem::offset_of!(TcpInfo, notsent_bytes) + std::mem::size_of::<u32>();
    (ret == 0 && len as usize >= end).then_some(info.notsent_bytes as usize)
}

impl AsyncRead for Growing {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Growing {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let written = Pin::new(&mut me.inner).poll_write(cx, buf);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(growth) = &mut me.growth {
            growth.wrote(&me.inner, cx, written.is_pending());
        }
        written
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let written = Pin::new(&mut me.inner).poll_write_vectored(cx, bufs);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(growth) = &mut me.growth {
            growth.wrote(&me.inner, cx, written.is_pending());
        }
        written
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use crate::runtime::transfer_budget::TransferBudget;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const BASE: usize = 64 << 10;

    /// An accepted connection whose buffer grows out of a budget of its
    /// own of `limit` bytes, and its client.
    async fn pair(base: usize, max: usize, limit: u64) -> (Growing, TcpStream) {
        let listener = crate::net::TcpListener::bind_now(&"127.0.0.1:0".parse().unwrap())
            .unwrap()
            .send_buffer(base);
        let addr = listener.io().local_addr().unwrap();
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size((BASE / 2) as u32).unwrap();
        let client = socket.connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let mut accepted = Growing::new(accepted, base, max);
        let budget: &'static TransferBudget = Box::leak(Box::new(TransferBudget::limited(limit)));
        if let Some(growth) = &mut accepted.growth {
            growth.budget = budget;
        }
        (accepted, client)
    }

    fn kernel_size(stream: &Growing) -> usize {
        socket2::SockRef::from(stream.get_ref())
            .send_buffer_size()
            .unwrap()
    }

    /// Observe the real kernel queue independently of the growth bookkeeping.
    fn kernel_queue(stream: &Growing) -> u64 {
        use std::os::fd::AsRawFd;
        let mut info = [0u32; 9];
        let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
        #[cfg(target_os = "linux")]
        let option = libc::SO_MEMINFO;
        #[cfg(target_os = "android")]
        let option = 55;
        let result = unsafe {
            libc::getsockopt(
                stream.inner.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        assert_eq!(result, 0, "SO_MEMINFO: {}", io::Error::last_os_error());
        assert!(len as usize >= 6 * std::mem::size_of::<u32>());
        info[5] as u64
    }

    /// Queue data in an actually grown TCP socket while its peer does not
    /// read. Direct writes keep this setup independent of the shrink timer.
    async fn fill_grown_queue(accepted: &mut Growing) -> usize {
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 3 * BASE);
        let mut sent = 0;
        let chunk = [0x5a; BASE];
        let until = tokio::time::Instant::now() + Duration::from_millis(300);
        while tokio::time::Instant::now() < until {
            match accepted.inner.try_write(&chunk) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(e) => panic!("queue setup: {e}"),
            }
        }
        assert!(kernel_queue(accepted) > 2 * BASE as u64);
        sent
    }

    /// Each growth doubles the buffer up to the most and charges the
    /// budget what the kernel keeps for it; closing gives it all back.
    #[tokio::test]
    async fn growth_doubles_to_the_most_and_is_charged() {
        let (mut accepted, _client) = pair(BASE, 3 * BASE, u64::MAX).await;
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 2 * BASE);
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 3 * BASE);
        let budget = growth.budget;
        assert_eq!(budget.held(), 4 * BASE as u64);
        assert!(kernel_size(&accepted) >= 6 * BASE);
        drop(accepted);
        assert_eq!(budget.held(), 0);
    }

    /// A growth the budget has no room for leaves the buffer as it is.
    #[tokio::test]
    async fn a_growth_the_budget_refuses_keeps_the_size() {
        let (mut accepted, _client) = pair(BASE, 4 * BASE, BASE as u64).await;
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!((growth.size, growth.budget.held()), (BASE, 0));
        assert!(kernel_size(&accepted) < 4 * BASE);
    }

    /// A client that stopped reading: its writes stay blocked, with what
    /// is queued unsent, so the buffer does not grow; and one that grew
    /// goes back to the base a second later, keeping queued excess charged.
    #[tokio::test]
    async fn a_stalled_client_s_growth_goes_back() {
        let (mut accepted, _client) = pair(BASE, 3 * BASE, u64::MAX).await;
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 2 * BASE);
        let budget = growth.budget;
        let chunk = vec![0; BASE];
        let blocked = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                accepted.write_all(&chunk).await.unwrap();
            }
        })
        .await;
        assert!(blocked.is_err());
        assert_eq!(accepted.growth.as_ref().unwrap().size, BASE);
        assert!(kernel_queue(&accepted) > 2 * BASE as u64);
        assert!(
            budget.held() > 0,
            "a stopped reader still holds queued memory"
        );
        assert!(kernel_size(&accepted) < 4 * BASE);
    }

    /// Lowering SO_SNDBUF does not free queued allocations. Another flow
    /// must not be allowed to borrow the same complete allowance again.
    #[tokio::test]
    async fn shrinking_an_unread_queue_retains_its_budget() {
        let limit = 4 * BASE as u64;
        let (mut accepted, _client) = pair(BASE, 3 * BASE, limit).await;
        fill_grown_queue(&mut accepted).await;
        let budget = accepted.growth.as_ref().unwrap().budget;
        assert_eq!(budget.held(), limit);
        accepted.growth.as_mut().unwrap().shrink(&accepted.inner);
        assert_eq!(kernel_size(&accepted), 2 * BASE);
        assert!(kernel_queue(&accepted) > 2 * BASE as u64);
        assert!(
            budget.held() > 0,
            "shrink returned memory still held by TCP"
        );
        let queued_excess = kernel_queue(&accepted).saturating_sub(2 * BASE as u64);
        assert!(
            budget.held() >= queued_excess.min(limit),
            "the retained reservation must cover the still-queued excess"
        );
        assert!(!budget.try_grow(limit), "the same allowance was lent twice");
    }

    /// Once the peer drains the actual queue, the next writer poll gives
    /// the reservation back so a different flow can use it.
    #[tokio::test]
    async fn a_drained_queue_releases_its_budget_on_the_next_write() {
        let limit = 4 * BASE as u64;
        let (mut accepted, mut client) = pair(BASE, 3 * BASE, limit).await;
        let sent = fill_grown_queue(&mut accepted).await;
        let budget = accepted.growth.as_ref().unwrap().budget;
        accepted.growth.as_mut().unwrap().shrink(&accepted.inner);
        assert!(budget.held() > 0);
        let mut received = vec![0; sent];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert!(received.iter().all(|&byte| byte == 0x5a));
        tokio::time::timeout(Duration::from_secs(2), async {
            while kernel_queue(&accepted) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(accepted.write(&[]).await.unwrap(), 0);
        assert_eq!(budget.held(), 0);
        assert!(budget.try_grow(limit), "drained memory should be reusable");
        budget.release(limit);
    }

    /// A socket may fill again before its old queue drains. Reusing the
    /// retained reservation must let it regrow without a second charge.
    #[tokio::test]
    async fn regrowth_reuses_the_still_queued_reservation() {
        let limit = 4 * BASE as u64;
        let (mut accepted, _client) = pair(BASE, 3 * BASE, limit).await;
        fill_grown_queue(&mut accepted).await;
        let budget = accepted.growth.as_ref().unwrap().budget;
        accepted.growth.as_mut().unwrap().shrink(&accepted.inner);
        assert!(budget.held() > 0);
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 2 * BASE);
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 3 * BASE);
        assert_eq!(budget.held(), limit);
        drop(accepted);
        assert_eq!(budget.held(), 0);
    }

    /// Without a larger most, or with the system's tuning, nothing grows.
    #[tokio::test]
    async fn no_growth_without_room_to_grow() {
        assert!(pair(BASE, BASE, u64::MAX).await.0.growth.is_none());
        assert!(pair(0, BASE, u64::MAX).await.0.growth.is_none());
    }

    // These ABIs pass socket-option arguments directly, low word first.
    // Each irreversible seccomp filter stays inside its own child process.
    #[cfg(all(
        target_os = "linux",
        target_endian = "little",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    mod syscall_failures {
        use super::*;

        fn isolated_child(name: &str) -> bool {
            const CHILD: &str = "SAIL_TEST_SEND_BUFFER_SYSCALL_CHILD";
            if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(name)) {
                return true;
            }
            // libtest names omit the crate prefix from module_path!().
            let (_, module) = module_path!().split_once("::").unwrap();
            let name = format!("{module}::{name}");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, name.rsplit("::").next().unwrap())
                .output()
                .expect("start isolated socket-option regression");
            assert!(
                output.status.success(),
                "socket-option child failed: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "the child must execute its one selected test: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            false
        }

        fn deny_option(syscall: libc::c_long, option: libc::c_int) {
            let load = |offset| libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: offset,
            };
            let equal = |value, otherwise| libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: otherwise,
                k: value,
            };
            let result = |value| libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: value,
            };
            let args = std::mem::offset_of!(libc::seccomp_data, args) as u32;
            let mut instructions = [
                load(std::mem::offset_of!(libc::seccomp_data, nr) as u32),
                equal(syscall as u32, 5),
                load(args + 8),
                equal(libc::SOL_SOCKET as u32, 3),
                load(args + 16),
                equal(option as u32, 1),
                result(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
                result(libc::SECCOMP_RET_ALLOW),
            ];
            let program = libc::sock_fprog {
                len: instructions.len() as u16,
                filter: instructions.as_mut_ptr(),
            };
            let no_privileges = unsafe {
                libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            assert_eq!(
                no_privileges,
                0,
                "PR_SET_NO_NEW_PRIVS: {}",
                io::Error::last_os_error()
            );
            let filtered = unsafe {
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &program as *const libc::sock_fprog as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            assert_eq!(
                filtered,
                0,
                "install socket-option seccomp filter: {}",
                io::Error::last_os_error()
            );
        }

        #[test]
        fn failed_readback_retains_real_growth_until_close() {
            if !isolated_child("failed_readback_retains_real_growth_until_close") {
                return;
            }
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (mut accepted, _client) = pair(BASE, 3 * BASE, 4 * BASE as u64).await;
                    let budget = accepted.growth.as_ref().unwrap().budget;
                    assert_eq!(kernel_size(&accepted), 2 * BASE);
                    std::thread::scope(|scope| {
                        let (grown, observe) = std::sync::mpsc::channel();
                        // This thread predates the filter and independently
                        // verifies the actual kernel allocation afterward.
                        let observed = &accepted.inner;
                        let observer = scope.spawn(move || {
                            observe.recv_timeout(Duration::from_secs(5)).unwrap();
                            socket2::SockRef::from(observed).send_buffer_size().unwrap()
                        });
                        deny_option(libc::SYS_getsockopt, libc::SO_SNDBUF);
                        let socket = socket2::SockRef::from(&accepted.inner);
                        assert_eq!(
                            socket.send_buffer_size().unwrap_err().raw_os_error(),
                            Some(libc::EPERM)
                        );
                        assert!(unsent(&accepted.inner).is_some(), "TCP_INFO stays readable");
                        socket
                            .set_send_buffer_size(BASE)
                            .expect("SO_SNDBUF writes must remain allowed");

                        accepted.growth.as_mut().unwrap().grow(&accepted.inner);
                        grown.send(()).unwrap();
                        assert_eq!(observer.join().unwrap(), 4 * BASE, "the kernel really grew");
                        let growth = accepted.growth.as_ref().unwrap();
                        assert_eq!(
                            (growth.size, growth.reserved, budget.held()),
                            (2 * BASE, 2 * BASE as u64, 2 * BASE as u64),
                            "successful growth must stay charged when readback fails"
                        );
                    });
                    drop(accepted);
                    assert_eq!(budget.held(), 0, "closing releases the retained charge");
                });
        }

        #[test]
        fn denied_force_refunds_only_the_unallocated_growth() {
            use std::os::fd::AsRawFd;

            if !isolated_child("denied_force_refunds_only_the_unallocated_growth") {
                return;
            }
            let cap: usize = std::fs::read_to_string("/proc/sys/net/core/wmem_max")
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(cap >= BASE, "fixture needs wmem_max at least {BASE}");
            let requested = libc::c_int::try_from(2 * cap).unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (mut accepted, _client) = pair(cap, 2 * cap, 4 * cap as u64).await;
                    let budget = accepted.growth.as_ref().unwrap().budget;
                    assert_eq!(kernel_size(&accepted), 2 * cap);
                    deny_option(libc::SYS_setsockopt, libc::SO_SNDBUFFORCE);
                    let forced = unsafe {
                        libc::setsockopt(
                            accepted.inner.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUFFORCE,
                            (&requested as *const libc::c_int).cast(),
                            std::mem::size_of_val(&requested) as libc::socklen_t,
                        )
                    };
                    assert_eq!(forced, -1);
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

                    accepted.growth.as_mut().unwrap().grow(&accepted.inner);
                    assert_eq!(kernel_size(&accepted), 2 * cap);
                    let growth = accepted.growth.as_ref().unwrap();
                    assert_eq!(
                        (growth.size, growth.reserved, budget.held()),
                        (cap, 0, 0),
                        "a denied FORCE must not charge unallocated growth"
                    );
                    drop(accepted);
                    assert_eq!(budget.held(), 0);
                });
        }
    }
}
