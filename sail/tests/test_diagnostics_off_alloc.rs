//! Paired baseline/candidate measurement; the driver uses loopback mocks only.
#![cfg(feature = "alloc-stats")]
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
fn diagnostics_feature_off_allocation_and_layout_measurement() {
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
        assert!(after.0 > before.0, "the existing frame/future path must execute");
        eprintln!("DIAG_OFF_ALLOC packets=32 allocations={} bytes={} sessions_size={} dispatcher_size={} kinds_size={} uot_size={}",
            after.0-before.0, after.1-before.1,
            std::mem::size_of::<sail::app::sessions::Sessions>(),
            std::mem::size_of::<sail::app::dispatcher::Dispatcher>(),
            std::mem::size_of::<sail::embed::HostKinds>(), uot_size);
    });
}
