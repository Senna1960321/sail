//! How many proxied sessions live at once: `inbound.max_connections`. Every
//! connection, UDP session and stream of a multiplexed or QUIC inbound
//! holds one place while it lives; one more waits for a place, and is
//! refused when none comes. Memory, which each session takes 24 to 39 KiB
//! of (measured), is what the limit keeps within a small router's budget.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::adapter::{
    AnyOutboundDatagram, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
};
use crate::session::SocksAddr;

/// How long a session over the limit waits for a place (judged: a burst
/// of new connections passes, a sustained excess is refused soon).
pub const MAX_CONNECTIONS_WAIT: Duration = Duration::from_secs(1);

/// The refusals are logged at most this often, with their count since.
const WARN_EVERY: Duration = Duration::from_secs(10);

#[cfg(feature = "internal-diagnostics")]
#[doc(hidden)]
pub mod diagnostics;

/// The places, when there is a limit.
pub struct Sessions {
    #[cfg(feature = "internal-diagnostics")]
    diagnostics: diagnostics::Counters,
    places: Arc<Semaphore>,
    limit: usize,
    /// Those waiting for a place: they hold their inbound side already, so
    /// that more of them than this are refused at once.
    waiting: AtomicUsize,
    max_waiting: usize,
    refused: AtomicUsize,
    warned: Mutex<Option<Instant>>,
}

/// A session's place, given back when it is dropped.
pub struct Place(#[allow(dead_code)] OwnedSemaphorePermit);

/// One queued admission. Cancellation drops this along with the semaphore
/// wait, so it cannot permanently consume the bounded waiting budget.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Sessions {
    /// None for 0, no limit.
    pub fn new(limit: usize) -> Option<Self> {
        (limit > 0).then(|| Self {
            #[cfg(feature = "internal-diagnostics")]
            diagnostics: Default::default(),
            places: Arc::new(Semaphore::new(limit)),
            limit,
            waiting: AtomicUsize::new(0),
            // A quarter of the limit (judged): a burst passes, and those
            // waiting cost a quarter of what the places do at most.
            max_waiting: (limit / 4).max(1),
            refused: AtomicUsize::new(0),
            warned: Mutex::new(None),
        })
    }

    /// A place for one more session, waiting `wait` at most, and only
    /// while fewer than `max_waiting` wait; none, and the session is
    /// refused.
    pub async fn enter(&self, wait: Duration) -> Option<Place> {
        if let Ok(permit) = self.places.clone().try_acquire_owned() {
            #[cfg(feature = "internal-diagnostics")]
            self.diagnostics.admitted();
            return Some(Place(permit));
        }
        #[cfg(feature = "internal-diagnostics")]
        let mut observation = diagnostics::WaitObservation::new(&self.diagnostics);
        let previous = self.waiting.fetch_add(1, Ordering::AcqRel);
        let waiting = Waiting(&self.waiting);
        if previous >= self.max_waiting {
            #[cfg(feature = "internal-diagnostics")]
            observation.finish();
            self.refused();
            return None;
        }
        let waited = tokio::time::timeout(wait, self.places.clone().acquire_owned()).await;
        #[cfg(feature = "internal-diagnostics")]
        {
            observation.finish();
            if waited.is_err() {
                self.diagnostics.timed_out();
            }
        }
        drop(waiting);
        match waited {
            Ok(Ok(permit)) => {
                #[cfg(feature = "internal-diagnostics")]
                self.diagnostics.admitted();
                Some(Place(permit))
            }
            _ => {
                self.refused();
                None
            }
        }
    }

    /// The sessions living now.
    pub fn live(&self) -> usize {
        self.limit - self.places.available_permits()
    }

    #[cfg(feature = "internal-diagnostics")]
    pub(crate) fn diagnostics_snapshot(&self) -> diagnostics::AdmissionDiagnostics {
        self.diagnostics.snapshot(
            self.limit,
            self.live(),
            self.waiting.load(Ordering::Acquire),
            self.max_waiting,
        )
    }

    fn refused(&self) {
        #[cfg(feature = "internal-diagnostics")]
        self.diagnostics.refused();
        let refused = self.refused.fetch_add(1, Ordering::Relaxed) + 1;
        let mut warned = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if warned.is_none_or(|at| now.duration_since(at) >= WARN_EVERY) {
            *warned = Some(now);
            self.refused.store(0, Ordering::Relaxed);
            tracing::warn!(
                "{} session(s) refused: {} live, the limit of inbound.max_connections",
                refused,
                self.limit
            );
        }
    }
}

/// A UDP session's datagram, which holds its place until both its halves
/// are dropped.
pub struct Held {
    inner: AnyOutboundDatagram,
    place: Place,
}

impl Held {
    /// `inner`, holding `place` until both its halves are dropped.
    pub fn wrap(inner: AnyOutboundDatagram, place: Place) -> AnyOutboundDatagram {
        Box::new(Self { inner, place })
    }
}

impl OutboundDatagram for Held {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let place = Arc::new(self.place);
        let (recv, send) = self.inner.split();
        (
            Box::new(RecvHalf(recv, place.clone())),
            Box::new(SendHalf(send, place)),
        )
    }
}

struct RecvHalf(
    Box<dyn OutboundDatagramRecvHalf>,
    #[allow(dead_code)] Arc<Place>,
);

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        self.0.recv_from(buf).await
    }
}

struct SendHalf(
    Box<dyn OutboundDatagramSendHalf>,
    #[allow(dead_code)] Arc<Place>,
);

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        self.0.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_session_over_the_limit_waits_and_is_then_refused() {
        assert!(Sessions::new(0).is_none(), "0 is no limit");
        let sessions = Sessions::new(2).unwrap();
        let a = sessions.enter(Duration::from_millis(50)).await.unwrap();
        let _b = sessions.enter(Duration::from_millis(50)).await.unwrap();
        assert_eq!(sessions.live(), 2);
        // A third is refused once its wait is over.
        let started = Instant::now();
        assert!(sessions.enter(Duration::from_millis(50)).await.is_none());
        assert!(started.elapsed() >= Duration::from_millis(50));
        // One that waits gets the place a session gives back.
        let give_back = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(a);
        };
        let (place, ()) = tokio::join!(sessions.enter(Duration::from_secs(1)), give_back);
        assert!(place.is_some());
        assert_eq!(sessions.live(), 2);
    }

    /// On the mobile profile, as on the router's, the 513th session waits
    /// for a place and is refused when none comes.
    #[tokio::test]
    async fn the_mobile_profile_s_513th_session_waits_and_is_refused() {
        let limit = crate::runtime::RuntimeOptions::profile(crate::runtime::Profile::Mobile)
            .inbound
            .max_connections;
        assert_eq!(limit, 512);
        let sessions = Sessions::new(limit).unwrap();
        let mut held = Vec::new();
        for _ in 0..limit {
            held.push(sessions.enter(Duration::ZERO).await.unwrap());
        }
        let started = Instant::now();
        assert!(sessions.enter(Duration::from_millis(50)).await.is_none());
        assert!(started.elapsed() >= Duration::from_millis(50), "it waited");
        drop(held.pop());
        assert!(sessions.enter(Duration::from_millis(50)).await.is_some());
    }

    /// Beyond a quarter of the limit waiting, one more is refused at once.
    #[tokio::test]
    async fn no_more_than_a_quarter_of_the_limit_waits() {
        let sessions = Arc::new(Sessions::new(4).unwrap());
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(sessions.enter(Duration::ZERO).await.unwrap());
        }
        // One may wait (4 / 4).
        let waiter = {
            let sessions = sessions.clone();
            tokio::spawn(async move { sessions.enter(Duration::from_secs(5)).await.is_some() })
        };
        while sessions.waiting.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        // A second is refused without waiting.
        let started = Instant::now();
        assert!(sessions.enter(Duration::from_secs(5)).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
        // The one waiting gets the next place given back.
        drop(held.pop());
        assert!(waiter.await.unwrap());
        assert_eq!(sessions.waiting.load(Ordering::Acquire), 0);
    }

    // Poll once without yielding: a pending admission has claimed a waiter
    // slot and registered its semaphore wait, so dropping it cancels that wait.
    fn pending_wait(future: std::pin::Pin<&mut impl std::future::Future<Output = Option<Place>>>) {
        use std::task::{Context, Poll, Waker};
        assert!(matches!(
            future.poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }

    #[tokio::test]
    async fn canceling_a_full_wait_queue_allows_another_waiter() {
        let sessions = Sessions::new(4).unwrap();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(sessions.enter(Duration::ZERO).await.unwrap());
        }
        let mut canceled = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(canceled.as_mut());
        assert!(
            sessions.enter(Duration::from_secs(10)).await.is_none(),
            "queue is full"
        );
        drop(canceled);
        let mut replacement = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(replacement.as_mut());
        drop(held.pop());
        let place = replacement
            .await
            .expect("replacement gets the released place");
        assert_eq!(sessions.live(), 4);
        drop(place);
        assert!(sessions.enter(Duration::ZERO).await.is_some());
    }

    #[tokio::test]
    async fn repeated_and_unpolled_cancellation_keeps_other_waiters() {
        let sessions = Sessions::new(8).unwrap();
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(sessions.enter(Duration::ZERO).await.unwrap());
        }
        let mut survivor = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(survivor.as_mut());
        for _ in 0..32 {
            // Dropping a future that never started must return no slot.
            drop(Box::pin(sessions.enter(Duration::from_secs(10))));
            let mut canceled = Box::pin(sessions.enter(Duration::from_secs(10)));
            pending_wait(canceled.as_mut());
            assert!(
                sessions.enter(Duration::from_secs(10)).await.is_none(),
                "survivor still occupies its slot"
            );
            drop(canceled);
        }
        drop(held.pop());
        held.push(survivor.await.expect("original waiter was not displaced"));
        let mut next = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(next.as_mut());
        drop(held.pop());
        assert!(next.await.is_some());
    }

    #[tokio::test]
    async fn cancel_after_a_place_is_released_returns_both_budgets() {
        let sessions = Sessions::new(1).unwrap();
        let held = sessions.enter(Duration::ZERO).await.unwrap();
        let mut canceled = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(canceled.as_mut());
        drop(held); // The semaphore has notified this waiter, not polled yet.
        drop(canceled);
        let held = sessions
            .enter(Duration::ZERO)
            .await
            .expect("place was returned");
        let mut next = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(next.as_mut());
        drop(held);
        assert!(next.await.is_some());
    }

    #[tokio::test]
    async fn timeout_returns_the_wait_slot_for_a_later_admission() {
        let sessions = Sessions::new(1).unwrap();
        let held = sessions.enter(Duration::ZERO).await.unwrap();
        assert!(sessions.enter(Duration::from_millis(1)).await.is_none());
        let mut next = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(next.as_mut());
        drop(held);
        let held = next.await.expect("admitted after timeout");
        let mut after_success = Box::pin(sessions.enter(Duration::from_secs(10)));
        pending_wait(after_success.as_mut());
        drop(held);
        assert!(
            after_success.await.is_some(),
            "success also returned its wait slot"
        );
    }

    struct Quiet;

    #[async_trait]
    impl OutboundDatagramRecvHalf for Quiet {
        async fn recv_from(&mut self, _: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl OutboundDatagramSendHalf for Quiet {
        async fn send_to(&mut self, buf: &[u8], _: &SocksAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl OutboundDatagram for Quiet {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn OutboundDatagramRecvHalf>,
            Box<dyn OutboundDatagramSendHalf>,
        ) {
            (Box::new(Quiet), Box::new(Quiet))
        }
    }

    /// A UDP session holds its place until both its halves are dropped.
    #[tokio::test]
    async fn a_udp_session_holds_its_place_while_either_half_lives() {
        let sessions = Sessions::new(1).unwrap();
        let place = sessions.enter(Duration::from_millis(10)).await.unwrap();
        let (recv, send) = Held::wrap(Box::new(Quiet), place).split();
        assert_eq!(sessions.live(), 1);
        drop(send);
        assert_eq!(sessions.live(), 1, "the receive half still lives");
        drop(recv);
        assert_eq!(sessions.live(), 0);
    }
}

#[cfg(test)]
mod diagnostics_tests;
