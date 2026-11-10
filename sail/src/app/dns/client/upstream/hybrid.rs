//! Mihomo's `prefer-h3`: an `https` server asked over HTTP/3 beside
//! HTTP/2, and kept to HTTP/3 once that answers, as Mihomo's DoH client,
//! after AdGuard's dnsproxy, has it.
//!
//! Which one a query goes over is the choice: unknown at first, and again
//! after a network move; HTTP/3 once an HTTP/3 query was answered;
//! HTTP/2 for a while once one failed. While it is unknown, a query goes
//! over both at once and the first answer is taken, but the choice is
//! the HTTP/3 query's alone, which runs on to its end: a kept HTTP/2
//! connection would answer first every time, and HTTP/3 never be taken
//! up. An answer is a DNS message, whatever its rcode; a failure is a
//! connection that failed or timed out, or an HTTP error.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::time::{timeout, Instant};
use tracing::{debug, info};

use super::{doh, quic, State, Upstream};
use crate::app::dns::DnsClient;

/// How long HTTP/2 is kept to after HTTP/3 failed, before HTTP/3 is
/// tried again. A judgment value: often enough to take HTTP/3 up again
/// soon on a network that lets it through, seldom enough that a network
/// that blocks it costs one failed query in the background every while.
const H2_FOR: Duration = Duration::from_secs(10 * 60);

/// The connections of a `prefer_h3` server, and which one queries take.
pub(super) struct Hybrid {
    pub h2: doh::Pool,
    pub h3: quic::Pool,
    choice: Mutex<Choice>,
    /// Whether an HTTP/3 query that settles the choice is under way: one
    /// at a time, the queries meanwhile over HTTP/2.
    probing: AtomicBool,
    /// Counts the network moves: what an HTTP/3 query begun before one
    /// came to was learned on a network that is gone, and settles nothing.
    generation: AtomicUsize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    /// Both, the first answer taken: at first, after a network move, and
    /// once HTTP/2 has been kept to for `H2_FOR`.
    Unknown,
    H3,
    /// Until then.
    H2(Instant),
}

impl Default for Hybrid {
    fn default() -> Self {
        Self {
            h2: doh::Pool::default(),
            h3: quic::Pool::new(quic::Kind::H3),
            choice: Mutex::new(Choice::Unknown),
            probing: AtomicBool::new(false),
            generation: AtomicUsize::new(0),
        }
    }
}

impl Hybrid {
    fn choice(&self) -> Choice {
        let choice = *self.choice.lock().unwrap_or_else(|e| e.into_inner());
        match choice {
            Choice::H2(until) if Instant::now() >= until => Choice::Unknown,
            choice => choice,
        }
    }

    /// The network the queries begun now go over, as `settle` takes it.
    fn generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }

    /// Takes HTTP/3, or HTTP/2 for `H2_FOR`, after what an HTTP/3 query
    /// begun in `generation` came to, unless the network has moved since;
    /// said once at each change.
    fn settle(&self, upstream: &dyn std::fmt::Display, h3: &Result<Vec<u8>>, generation: usize) {
        let next = match h3 {
            Ok(_) => Choice::H3,
            Err(_) => Choice::H2(Instant::now() + H2_FOR),
        };
        let mut choice = self.choice.lock().unwrap_or_else(|e| e.into_inner());
        if self.generation() != generation {
            return;
        }
        let was = *choice;
        *choice = next;
        drop(choice);
        match (was, h3) {
            (Choice::H3, Ok(_)) | (Choice::H2(_), Err(_)) => {}
            (_, Ok(_)) => info!("{}: answers over HTTP/3", upstream),
            (_, Err(e)) => info!(
                "{}: answers over HTTP/2, HTTP/3 failed: {:#}; tried again in {}s",
                upstream,
                e,
                H2_FOR.as_secs()
            ),
        }
    }

    /// Drops the connections it keeps, and the choice, made on a network
    /// that is gone: one that blocks UDP would cost a query its timeout.
    pub(super) async fn clear(&self) {
        self.h2.clear().await;
        self.h3.clear().await;
        let mut choice = self.choice.lock().unwrap_or_else(|e| e.into_inner());
        self.generation.fetch_add(1, Ordering::AcqRel);
        *choice = Choice::Unknown;
    }
}

impl DnsClient {
    pub(super) async fn exchange_hybrid(
        &self,
        upstream: &Arc<Upstream>,
        hybrid: &Hybrid,
        addr: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        // A sequential retry follows a failed kept-protocol probe. Give
        // HTTP/2 the complete new attempt without probing HTTP/3 again.
        let Some(wait) = super::kept_wait(self.reused_connection_timeout()) else {
            return self.exchange_doh(upstream, &hybrid.h2, addr, request).await;
        };
        match hybrid.choice() {
            Choice::H2(_) => self.exchange_doh(upstream, &hybrid.h2, addr, request).await,
            Choice::H3 => {
                let generation = hybrid.generation();
                // Half this member's attempt, or half the normal query's
                // time outside a sequential server, left for HTTP/2.
                let probed = timeout(
                    wait,
                    self.exchange_quic(upstream, &hybrid.h3, addr, request),
                )
                .await;
                let timed_out = probed.is_err();
                let h3 = probed.unwrap_or_else(|_| Err(anyhow!("timed out")));
                if h3.is_ok() {
                    return h3;
                }
                hybrid.settle(upstream.as_ref(), &h3, generation);
                if timed_out && super::kept_timed_out() {
                    return h3;
                }
                self.exchange_doh(upstream, &hybrid.h2, addr, request).await
            }
            Choice::Unknown => self.exchange_both(upstream, hybrid, addr, request).await,
        }
    }

    /// Over HTTP/3 and HTTP/2 at once: the first answer is taken, and the
    /// HTTP/3 query runs on to its end, which settles the choice.
    async fn exchange_both(
        &self,
        upstream: &Arc<Upstream>,
        hybrid: &Hybrid,
        addr: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        // A client no one holds has no task to settle the choice in.
        let Some(me) = self.me.upgrade() else {
            return self.exchange_doh(upstream, &hybrid.h2, addr, request).await;
        };
        if hybrid.probing.swap(true, Ordering::AcqRel) {
            return self.exchange_doh(upstream, &hybrid.h2, addr, request).await;
        }
        let (tx, h3) = tokio::sync::oneshot::channel();
        let probed = Probing(upstream.clone());
        let probe = request.to_vec();
        let generation = hybrid.generation();
        crate::runtime::scope::spawn("dns http/3 probe", async move {
            let result = me.probe_h3(&probed.0, addr, &probe, generation).await;
            drop(probed);
            let _ = tx.send(result);
        });
        let h2 = self.exchange_doh(upstream, &hybrid.h2, addr, request);
        tokio::pin!(h2, h3);
        let (mut h2_done, mut h3_done) = (None, false);
        loop {
            tokio::select! {
                result = &mut h2, if h2_done.is_none() => match result {
                    Ok(response) => return Ok(response),
                    Err(e) => {
                        debug!("{}: over HTTP/2: {:#}", upstream, e);
                        // DoH can ask for a fresh sequential attempt while
                        // the background H3 probe is still pending.
                        let retry = super::ATTEMPT
                            .try_with(|attempt| attempt.kept_timed_out.load(Ordering::Relaxed))
                            .unwrap_or(false);
                        if h3_done || retry {
                            return Err(e);
                        }
                        h2_done = Some(e);
                    }
                },
                result = &mut h3, if !h3_done => match result {
                    // The HTTP/2 query's stream goes as it is dropped; its
                    // connection is kept.
                    Ok(Ok(response)) => return Ok(response),
                    _ => {
                        h3_done = true;
                        if let Some(e) = h2_done.take() {
                            return Err(e);
                        }
                    }
                },
            }
        }
    }

    /// An HTTP/3 query, within the query's time, which settles the choice.
    async fn probe_h3(
        &self,
        upstream: &Upstream,
        addr: SocketAddr,
        request: &[u8],
        generation: usize,
    ) -> Result<Vec<u8>> {
        let State::Hybrid(hybrid) = &upstream.state else {
            return Err(anyhow!("not a prefer_h3 server"));
        };
        let result = timeout(
            self.timeout,
            self.exchange_quic(upstream, &hybrid.h3, addr, request),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow!("timed out")));
        hybrid.settle(upstream, &result, generation);
        result
    }
}

/// The server an HTTP/3 query that settles the choice is under way for:
/// let go of, however the query ends, aborted or panicked too, so that the
/// next may begin.
struct Probing(Arc<Upstream>);

impl Drop for Probing {
    fn drop(&mut self) {
        if let State::Hybrid(hybrid) = &self.0.state {
            hybrid.probing.store(false, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_choice_is_http3_s_answer_and_a_network_move_forgets_it() {
        let hybrid = Hybrid::default();
        assert_eq!(hybrid.choice(), Choice::Unknown);
        // Any DNS message is an answer: the rcode is in it.
        let first = hybrid.generation();
        hybrid.settle(&"s", &Ok(vec![0; 12]), first);
        assert_eq!(hybrid.choice(), Choice::H3);
        hybrid.clear().await;
        assert_eq!(hybrid.choice(), Choice::Unknown);
        // What a query begun on the network before came to settles
        // nothing.
        hybrid.settle(&"s", &Ok(vec![0; 12]), first);
        assert_eq!(hybrid.choice(), Choice::Unknown);
        // HTTP/3 failed: HTTP/2 for H2_FOR, then both again.
        hybrid.settle(&"s", &Err(anyhow!("timed out")), hybrid.generation());
        assert!(matches!(hybrid.choice(), Choice::H2(_)));
        tokio::time::advance(H2_FOR - Duration::from_secs(1)).await;
        assert!(matches!(hybrid.choice(), Choice::H2(_)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(hybrid.choice(), Choice::Unknown);
    }
}
