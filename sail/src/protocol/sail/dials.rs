//! Sessions being dialled, shared by the streams that wait for them.
//!
//! A stream that finds no kept session with room waits for a dial under
//! way that has room for it, up to `per` streams a dial, or starts one: as
//! many dials run at once as the waiting streams need, so a burst of
//! streams on a cold pool shares them rather than each dialling its own.
//! A dial runs in a task of its own, to its end or its timeout, whether or
//! not the streams that waited for it are still there; one that fails
//! fails every stream that waited for it, and none of them dials again for
//! itself. A stream that stops waiting gives its place back.

use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::watch;

/// What a dial came to, for every stream that waited for it.
type Outcome<T> = Option<Result<T, (io::ErrorKind, String)>>;

/// A dial under way, and the streams waiting for it.
struct Dialing<T> {
    id: u64,
    /// No more than `per`.
    claimed: usize,
    done: watch::Receiver<Outcome<T>>,
}

struct State<T> {
    under_way: Vec<Dialing<T>>,
    next: u64,
}

/// The dials under way of one pool.
pub(crate) struct Dials<T> {
    per: usize,
    timeout: Duration,
    state: Mutex<State<T>>,
}

impl<T: Clone + Send + Sync + 'static> Dials<T> {
    /// Up to `per` streams a dial, each taking no longer than `timeout`.
    pub(crate) fn new(per: usize, timeout: Duration) -> Self {
        Dials {
            per: per.max(1),
            timeout,
            state: Mutex::new(State {
                under_way: Vec::new(),
                next: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What `kept` finds, or the outcome of a dial under way with room, or
    /// of `dial`, started now. `kept` is asked with the dials locked, so
    /// that a dial that ends meanwhile, its session kept, is found there.
    pub(crate) async fn get<K, D, F>(self: &std::sync::Arc<Self>, kept: K, dial: D) -> io::Result<T>
    where
        K: FnOnce() -> Option<T>,
        D: FnOnce() -> F,
        F: Future<Output = io::Result<T>> + Send + 'static,
    {
        let (claim, mut done) = {
            let mut state = self.lock();
            if let Some(found) = kept() {
                return Ok(found);
            }
            let per = self.per;
            let (id, done) = match state.under_way.iter_mut().find(|d| d.claimed < per) {
                Some(dialing) => {
                    dialing.claimed += 1;
                    (dialing.id, dialing.done.clone())
                }
                None => {
                    let id = state.next;
                    state.next += 1;
                    let (tx, rx) = watch::channel(None);
                    state.under_way.push(Dialing {
                        id,
                        claimed: 1,
                        done: rx.clone(),
                    });
                    let dials = self.clone();
                    let dialing = dial();
                    crate::runtime::scope::spawn("sail session dial", async move {
                        let outcome = match tokio::time::timeout(dials.timeout, dialing).await {
                            Ok(Ok(found)) => Ok(found),
                            Ok(Err(e)) => Err((e.kind(), e.to_string())),
                            Err(_) => Err((
                                io::ErrorKind::TimedOut,
                                format!("sail: no session in {}s", dials.timeout.as_secs()),
                            )),
                        };
                        // Gone from those under way before anyone hears:
                        // a stream that comes next finds the session kept,
                        // or dials anew after a failure.
                        dials.lock().under_way.retain(|d| d.id != id);
                        let _ = tx.send(Some(outcome));
                    });
                    (id, rx)
                }
            };
            (
                Claim {
                    dials: self.as_ref(),
                    id,
                },
                done,
            )
        };
        let outcome = done
            .wait_for(Option::is_some)
            .await
            .map_err(|_| io::Error::other("sail: the session's dial ended"))?
            .clone();
        drop(claim);
        match outcome {
            Some(Ok(found)) => Ok(found),
            Some(Err((kind, message))) => Err(io::Error::new(kind, message)),
            None => Err(io::Error::other("sail: the session's dial ended")),
        }
    }

    /// The streams waiting for each dial under way, in the order they began.
    #[cfg(test)]
    fn waiting(&self) -> Vec<usize> {
        self.lock().under_way.iter().map(|d| d.claimed).collect()
    }
}

/// A stream's place on a dial under way: given back once it has the
/// outcome, or once it stops waiting.
struct Claim<'a, T> {
    dials: &'a Dials<T>,
    id: u64,
}

impl<T> Drop for Claim<'_, T> {
    fn drop(&mut self) {
        let mut state = self.dials.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dialing) = state.under_way.iter_mut().find(|d| d.id == self.id) {
            dialing.claimed -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;

    /// Dials that each wait for `go`, and count themselves.
    struct Fake {
        started: Arc<AtomicUsize>,
        go: Arc<Notify>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                started: Arc::new(AtomicUsize::new(0)),
                go: Arc::new(Notify::new()),
            }
        }

        fn dial(&self, fail: bool) -> impl Future<Output = io::Result<usize>> + Send + 'static {
            let n = self.started.fetch_add(1, Ordering::SeqCst);
            let go = self.go.clone();
            async move {
                go.notified().await;
                if fail {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                } else {
                    Ok(n)
                }
            }
        }
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// Forty streams on a cold pool, 32 a session: exactly two dials, the
    /// first 32 on the first, the other eight on the second.
    #[tokio::test]
    async fn forty_streams_share_two_dials() {
        let dials = Arc::new(Dials::<usize>::new(32, Duration::from_secs(5)));
        let fake = Arc::new(Fake::new());
        let waiters: Vec<_> = (0..40)
            .map(|_| {
                let (dials, fake) = (dials.clone(), fake.clone());
                tokio::spawn(async move { dials.get(|| None, || fake.dial(false)).await })
            })
            .collect();
        settle().await;
        assert_eq!(fake.started.load(Ordering::SeqCst), 2);
        assert_eq!(dials.waiting(), [32, 8]);
        fake.go.notify_waiters();
        let mut on = [0usize; 2];
        for waiter in waiters {
            on[waiter.await.unwrap().unwrap()] += 1;
        }
        assert_eq!(on, [32, 8]);
        assert!(dials.waiting().is_empty());
    }

    /// A kept session is taken without a dial.
    #[tokio::test]
    async fn a_kept_one_is_taken() {
        let dials = Arc::new(Dials::<usize>::new(32, Duration::from_secs(5)));
        let fake = Fake::new();
        assert_eq!(dials.get(|| Some(7), || fake.dial(false)).await.unwrap(), 7);
        assert_eq!(fake.started.load(Ordering::SeqCst), 0);
    }

    /// A failed dial fails every stream waiting for it, and none dials
    /// again; the next stream after it dials anew.
    #[tokio::test]
    async fn a_failure_fails_every_waiter_once() {
        let dials = Arc::new(Dials::<usize>::new(32, Duration::from_secs(5)));
        let fake = Arc::new(Fake::new());
        let waiters: Vec<_> = (0..5)
            .map(|_| {
                let (dials, fake) = (dials.clone(), fake.clone());
                tokio::spawn(async move { dials.get(|| None, || fake.dial(true)).await })
            })
            .collect();
        settle().await;
        fake.go.notify_waiters();
        for waiter in waiters {
            let e = waiter.await.unwrap().unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        }
        assert_eq!(fake.started.load(Ordering::SeqCst), 1);
        assert!(dials.waiting().is_empty());
    }

    /// A stream that stops waiting gives its place back, and leaves the
    /// dial to the others: one that comes after joins it, and has its
    /// session.
    #[tokio::test]
    async fn a_waiter_that_goes_leaves_nothing_behind() {
        let dials = Arc::new(Dials::<usize>::new(2, Duration::from_secs(5)));
        let fake = Arc::new(Fake::new());
        let gone = {
            let (dials, fake) = (dials.clone(), fake.clone());
            tokio::spawn(async move { dials.get(|| None, || fake.dial(false)).await })
        };
        settle().await;
        assert_eq!(dials.waiting(), [1]);
        gone.abort();
        let _ = gone.await;
        assert_eq!(dials.waiting(), [0]);
        let later = {
            let (dials, fake) = (dials.clone(), fake.clone());
            tokio::spawn(async move { dials.get(|| None, || fake.dial(false)).await })
        };
        settle().await;
        assert_eq!(dials.waiting(), [1]);
        assert_eq!(fake.started.load(Ordering::SeqCst), 1);
        fake.go.notify_waiters();
        assert_eq!(later.await.unwrap().unwrap(), 0);
        assert!(dials.waiting().is_empty());
    }

    /// A dial past its timeout fails its streams, and is gone.
    #[tokio::test(start_paused = true)]
    async fn a_dial_past_its_timeout_fails() {
        let dials = Arc::new(Dials::<usize>::new(32, Duration::from_secs(15)));
        let fake = Fake::new();
        let e = dials.get(|| None, || fake.dial(false)).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(dials.waiting().is_empty());
    }
}
