//! With the diagnostics features off, a UoT write allocates what it did
//! before they existed: 2 allocations and 421 bytes a packet, measured on
//! the source before diagnostics (fb5a1f4) with this driver. Loopback mocks
//! only. CI runs it: `--features alloc-stats --test test_diagnostics_off_alloc`.
#![cfg(all(
    feature = "alloc-stats",
    not(feature = "internal-diagnostics"),
    not(feature = "internal-udp-target-diagnostics")
))]
use sail::adapter::OutboundDatagram;
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[global_allocator]
static COUNTING: sail::alloc_stats::Counting = sail::alloc_stats::Counting;
static WRITES: AtomicUsize = AtomicUsize::new(0);
struct Discard;
impl AsyncRead for Discard {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Discard {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        WRITES.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[test]
fn diagnostics_feature_off_uot_writes_allocate_as_before() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let target = sail::session::SocksAddr::Ip("127.0.0.1:41001".parse().unwrap());
        let datagram = sail::transport::uot::OutboundDatagram::new(Discard, &target);
        let uot_size = std::mem::size_of_val(&datagram);
        let (_, mut sender) = Box::new(datagram).split();
        sender.send_to(&[1; 64], &target).await.unwrap();
        let writes_before = WRITES.load(Ordering::Relaxed);
        let before = sail::alloc_stats::counts();
        for _ in 0..32 { sender.send_to(&[2; 64], &target).await.unwrap(); }
        let after = sail::alloc_stats::counts();
        assert_eq!(WRITES.load(Ordering::Relaxed) - writes_before, 32);
        let (allocations, bytes) = (after.0 - before.0, after.1 - before.1);
        assert_eq!(allocations, 2 * 32, "allocations per UoT write changed");
        assert!(bytes <= 421 * 32, "UoT writes allocate {bytes} bytes for 32 packets");
        eprintln!("DIAG_OFF_ALLOC packets=32 allocations={} bytes={} sessions_size={} dispatcher_size={} kinds_size={} uot_size={}",
            allocations, bytes,
            std::mem::size_of::<sail::app::sessions::Sessions>(),
            std::mem::size_of::<sail::app::dispatcher::Dispatcher>(),
            std::mem::size_of::<sail::embed::HostKinds>(), uot_size);
    });
}
