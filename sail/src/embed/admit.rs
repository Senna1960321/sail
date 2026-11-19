//! A host's own admission (docs/embed.md, Admission): two synchronous
//! checks registered on [`Options`], one of each connection by its
//! addresses before its handshake, one of each session before it is
//! routed. They run after sail's own admission, so a host sees only what
//! sail would take in.
//!
//! [`Options`]: super::Options

use std::borrow::Cow;
use std::net::SocketAddr;

use super::{Options, SessionInfo};
use crate::app::inbound::admission::HostVerdict;

/// What a host's check says of a connection or session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    /// Refused, why: counted under it in `Instance::admission()`.
    Reject(Cow<'static, str>),
}

impl Verdict {
    pub fn reject(reason: impl Into<Cow<'static, str>>) -> Self {
        Verdict::Reject(reason.into())
    }
}

fn verdict(verdict: Verdict) -> HostVerdict {
    match verdict {
        Verdict::Accept => Ok(()),
        Verdict::Reject(reason) => Err(reason),
    }
}

/// A named built-in authentication row being constructed. The snapshot
/// returned for it is retained by that exact row and the sessions it
/// authenticates, even after a same-name credential replacement.
/// `credential` is sensitive configured material: never log it. It is
/// the configured UUID/password/PSK string, not packet bytes.
#[non_exhaustive]
pub struct CredentialInfo<'a> {
    pub protocol: &'static str,
    pub inbound: &'a str,
    pub name: &'a str,
    pub credential: &'a str,
}

impl Options {
    /// Freezes metadata when a named SS2022, VLESS or AnyTLS authentication
    /// row is built, including reload candidates. `bind` must resolve this
    /// exact credential/version, never current name alone. Candidates can
    /// be discarded: do not perform external side effects in this callback.
    /// Pool exhaustion or panic fails configuration construction; existing
    /// rows stay unchanged. `capacity` bounds retained row snapshots across
    /// old/new configurations, sessions and record payloads, not bytes.
    /// Anonymous credentials and other protocols have no such snapshot.
    /// Read it through SessionInfo::credential_context in record_context.
    pub fn credential_context<T, F>(
        mut self,
        capacity: usize,
        bind: F,
    ) -> Result<Self, super::Error>
    where
        T: Send + Sync + 'static,
        F: Fn(&CredentialInfo<'_>) -> T + Send + Sync + 'static,
    {
        if capacity == 0 {
            return Err(super::Error::new(
                super::ErrorKind::InvalidArgument,
                "credential context capacity must be positive",
            ));
        }
        let pool = crate::control::context::ContextPool::new(capacity);
        self.admission.credential = Some(Box::new(move |info| {
            pool.bind(|| bind(info))
                .ok_or(Cow::Borrowed("credential_context_capacity"))
        }));
        Ok(self)
    }

    /// Freezes a host-private binding once per authenticated session,
    /// before Sail's user check and the host's admission check. Additional
    /// UDP targets inherit it. `capacity` limits distinct live bindings
    /// across runs, including retained views and queued/read envelopes;
    /// it does not bound payload bytes or host-created clones.
    ///
    /// Exhaustion refuses before calling `bind`, with the counted host
    /// reason `record_context_capacity`. A panic is a counted host panic.
    /// These refusals have an unbound zero-byte record when recording;
    /// they must be handled explicitly by the reader. Require a lossless
    /// sink at Instance::new. A source/handshake/backlog refusal precedes
    /// authentication and has no binding. Keep `bind` fast and its result
    /// immutable and free of Instance/Session/record back-references.
    pub fn record_context<T, F>(mut self, capacity: usize, bind: F) -> Result<Self, super::Error>
    where
        T: Send + Sync + 'static,
        F: Fn(&SessionInfo) -> T + Send + Sync + 'static,
    {
        if capacity == 0 {
            return Err(super::Error::new(
                super::ErrorKind::InvalidArgument,
                "record context capacity must be positive",
            ));
        }
        let pool = crate::control::context::ContextPool::new(capacity);
        self.admission.bind = Some(Box::new(move |sess| {
            pool.bind_with_credential(
                sess.user
                    .as_ref()
                    .and_then(|u| u.credential_context())
                    .cloned(),
                || bind(&SessionInfo::untold(sess)),
            )
            .ok_or(Cow::Borrowed("record_context_capacity"))
        }));
        Ok(self)
    }

    /// The host's check of each session, once its inbound authenticated it
    /// and sail's own checks of its user took it, before it is routed: a
    /// stream of a multiplexed connection, a UDP association's first
    /// target and each later uncached target (including its port), and
    /// sessions a host inbound or `Instance::sessions` submits. A UDP
    /// association remembers at most 64 recently accepted targets; an
    /// evicted target is checked again, and rejections are not cached.
    /// Later accepted targets keep the association's original outbound,
    /// connection place and counter; only a rejected target has a separate
    /// zero-byte closed record by its check's attempt id. For a later
    /// target, `SessionInfo::parent_id` and the record's `parent_id`
    /// identify the original association within its run. Record backlog
    /// admission runs before the hook (`RecordStream::refused`). A session
    /// it rejects is closed as one of a user that may not connect is,
    /// never routed; its closed record is `Rejected`, ended
    /// `Closed(ClosedBy::Host)`, with the reason told. It is called in
    /// the session's own task and never awaited: it is to answer in
    /// microseconds, from what the host holds, as one slower holds back
    /// the worker thread it runs on and the connections that thread
    /// serves. A panic in it rejects the
    /// session, and is counted (`AdmissionInfo::host_panics`) where the
    /// host is built to unwind. Kept for every run and reload.
    pub fn admit<F>(mut self, check: F) -> Self
    where
        F: Fn(&SessionInfo) -> Verdict + Send + Sync + 'static,
    {
        self.admission.admit = Some(Box::new(move |sess| {
            verdict(check(&SessionInfo::untold(sess)))
        }));
        self
    }

    /// The host's check of each TCP connection an inbound accepts and each
    /// QUIC handshake, by the client's address and the one it came to,
    /// before its handshake and after sail's own admission took it in. One
    /// it rejects is closed (a QUIC one refused) at once. It runs in the
    /// connection's own task, as `admit` does.
    pub fn admit_source<F>(mut self, check: F) -> Self
    where
        F: Fn(SocketAddr, SocketAddr) -> Verdict + Send + Sync + 'static,
    {
        self.admission.admit_source =
            Some(Box::new(move |source, local| verdict(check(source, local))));
        self
    }
}

#[cfg(all(test, feature = "inbound-socks", feature = "outbound-direct"))]
mod tests {
    use crate::embed::{
        Address, Config, DatagramRecv, DatagramSend, Datagrams, HostStream, Instance, NewSession,
        Options, RecordKind, Threads, Verdict,
    };
    use futures::future::BoxFuture;
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    struct OnePacket(Option<(Vec<u8>, Address)>);

    impl DatagramRecv for OnePacket {
        fn recv_from<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> BoxFuture<'a, io::Result<(usize, Address)>> {
            Box::pin(async move {
                match self.0.take() {
                    Some((pkt, dst)) => {
                        buf[..pkt.len()].copy_from_slice(&pkt);
                        Ok((pkt.len(), dst))
                    }
                    None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "done")),
                }
            })
        }
    }

    struct SinkDatagrams;

    impl DatagramSend for SinkDatagrams {
        fn send_to<'a>(
            &'a mut self,
            _data: &'a [u8],
            _to: &'a Address,
        ) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Default)]
    struct GateState {
        hold_call: Option<usize>,
        entered: usize,
        completed: usize,
        release_all: bool,
    }

    struct HoldGate {
        state: Mutex<GateState>,
        cvar: Condvar,
        changed: Notify,
    }

    impl HoldGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(GateState::default()),
                cvar: Condvar::new(),
                changed: Notify::new(),
            })
        }

        fn hold_call(&self, call: usize) {
            self.state.lock().unwrap().hold_call = Some(call);
        }

        async fn wait_entered(&self, call: usize) {
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.state.lock().unwrap().entered >= call {
                    return;
                }
                notified.await;
            }
        }

        async fn finish_step(&self, expected_completed: usize) {
            {
                let mut st = self.state.lock().unwrap();
                st.hold_call = None;
                self.cvar.notify_all();
            }
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.state.lock().unwrap().completed >= expected_completed {
                    return;
                }
                notified.await;
            }
        }

        fn open_all(&self) {
            let mut st = self.state.lock().unwrap();
            st.hold_call = None;
            st.release_all = true;
            self.cvar.notify_all();
        }

        fn on_closed_enqueue(&self) {
            let (call, should_hold) = {
                let mut st = self.state.lock().unwrap();
                st.entered += 1;
                let call = st.entered;
                self.changed.notify_waiters();
                (call, !st.release_all && st.hold_call == Some(call))
            };
            if should_hold {
                tokio::task::block_in_place(|| {
                    let _g = self
                        .cvar
                        .wait_while(self.state.lock().unwrap(), |st| {
                            !st.release_all && st.hold_call == Some(call)
                        })
                        .unwrap();
                });
            }
            self.state.lock().unwrap().completed += 1;
            self.changed.notify_waiters();
        }
    }

    struct ReleaseOnDrop(Arc<HoldGate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.open_all();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_closed_record_frees_slot_while_session_teardown_is_held() {
        let allow = Arc::new(AtomicBool::new(false));
        let allow_check = allow.clone();
        let next_seq = Arc::new(AtomicUsize::new(1));
        let seq_provider = next_seq.clone();

        let instance = Instance::new(
            Options::new()
                .connection_records_lossless(8)
                .record_context(1, move |_| seq_provider.fetch_add(1, Ordering::SeqCst))
                .unwrap()
                .admit(move |_| {
                    if allow_check.load(Ordering::SeqCst) {
                        Verdict::Accept
                    } else {
                        Verdict::reject("policy")
                    }
                })
                .threads(Threads::Workers(2, 2 << 20)),
        )
        .unwrap();

        let gate = HoldGate::new();
        let _guard = ReleaseOnDrop(gate.clone());
        let hook_gate = gate.clone();
        instance
            .inner()
            .events()
            .lossless_records()
            .unwrap()
            .set_after_closed_enqueue(Some(Arc::new(move || hook_gate.on_closed_enqueue())));

        let mut records = instance.connection_records().unwrap();
        instance
            .start(Config::Json(
                serde_json::json!({
                    "inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}],
                    "outbounds":[{"type":"direct","tag":"direct"}]
                })
                .to_string(),
            ))
            .await
            .unwrap();
        let sessions = instance.sessions("in").unwrap();

        // 1. Refused TCP session: hold worker between closed-record enqueue and session drop.
        let tcp_dst = Address::Ip("127.0.0.1:80".parse().unwrap());
        gate.hold_call(1);
        let (a, _b) = tokio::io::duplex(64);
        sessions
            .tcp(NewSession::new(tcp_dst.clone()), HostStream::new(a))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), gate.wait_entered(1))
            .await
            .unwrap();
        let first = records.try_next_envelope().unwrap();
        assert_eq!(
            first.context.as_ref().and_then(|c| c.get::<usize>()),
            Some(&1)
        );
        assert!(matches!(first.record.kind, RecordKind::Closed(_)));
        drop(first);

        let (c, _d) = tokio::io::duplex(64);
        sessions
            .tcp(NewSession::new(tcp_dst.clone()), HostStream::new(c))
            .await
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
            .await
            .unwrap();
        assert_eq!(
            second.context.as_ref().and_then(|c| c.get::<usize>()),
            Some(&2),
            "TCP session slot must be back in the pool as soon as the reader drops the closed record"
        );
        drop(second);
        tokio::time::timeout(Duration::from_secs(5), gate.finish_step(2))
            .await
            .unwrap();

        // 2. Refused UDP session through NAT: admission_session must not retain a second clone either.
        gate.hold_call(3);
        let udp_dst = Address::Ip("127.0.0.1:5353".parse().unwrap());
        sessions
            .udp(
                NewSession::new(udp_dst.clone()),
                Datagrams {
                    recv: Box::new(OnePacket(Some((b"x".to_vec(), udp_dst.clone())))),
                    send: Box::new(SinkDatagrams),
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), gate.wait_entered(3))
            .await
            .unwrap();
        let udp_first = records.try_next_envelope().unwrap();
        assert_eq!(
            udp_first.context.as_ref().and_then(|c| c.get::<usize>()),
            Some(&3)
        );
        drop(udp_first);

        let (e, _f) = tokio::io::duplex(64);
        sessions
            .tcp(NewSession::new(tcp_dst.clone()), HostStream::new(e))
            .await
            .unwrap();
        let after_udp = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
            .await
            .unwrap();
        assert_eq!(
            after_udp.context.as_ref().and_then(|c| c.get::<usize>()),
            Some(&4),
            "UDP refused dispatch must not hold a second binding reference past its closed record"
        );
        drop(after_udp);
        tokio::time::timeout(Duration::from_secs(5), gate.finish_step(4))
            .await
            .unwrap();

        // 3. Accepted, relayed TCP connection closing through Accounts::drop.
        allow.store(true, Ordering::SeqCst);
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        gate.hold_call(5);
        let (mut client, host_side) = tokio::io::duplex(64);
        sessions
            .tcp(
                NewSession::new(Address::Ip(echo_addr)),
                HostStream::new(host_side),
            )
            .await
            .unwrap();
        let (mut peer, _) = tokio::time::timeout(Duration::from_secs(5), echo.accept())
            .await
            .unwrap()
            .unwrap();
        let _ = client.shutdown().await;
        drop(client);
        let _ = peer.shutdown().await;
        drop(peer);
        tokio::time::timeout(Duration::from_secs(5), gate.wait_entered(5))
            .await
            .unwrap();
        let relayed = records.try_next_envelope().unwrap();
        assert_eq!(
            relayed.context.as_ref().and_then(|c| c.get::<usize>()),
            Some(&5)
        );
        drop(relayed);

        allow.store(false, Ordering::SeqCst);
        let (g, _h) = tokio::io::duplex(64);
        sessions
            .tcp(NewSession::new(tcp_dst.clone()), HostStream::new(g))
            .await
            .unwrap();
        let after_relayed = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
            .await
            .unwrap();
        assert_eq!(
            after_relayed
                .context
                .as_ref()
                .and_then(|c| c.get::<usize>()),
            Some(&6),
            "listed closed record must free its slot before Accounts/Established teardown finishes"
        );
        drop(after_relayed);
        tokio::time::timeout(Duration::from_secs(5), gate.finish_step(6))
            .await
            .unwrap();

        // 4. Accepted unlisted NAT UDP session (healthcheck.sail): Number::drop must run after
        // admission_session drops, freeing the slot as soon as the closed record is dropped.
        allow.store(true, Ordering::SeqCst);
        gate.hold_call(7);
        let hc_dst = Address::Domain("healthcheck.sail".into(), 53);
        sessions
            .udp(
                NewSession::new(hc_dst.clone()),
                Datagrams {
                    recv: Box::new(OnePacket(Some((b"PING".to_vec(), hc_dst)))),
                    send: Box::new(SinkDatagrams),
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), gate.wait_entered(7))
            .await
            .unwrap();
        let unlisted_udp = records.try_next_envelope().unwrap();
        assert_eq!(
            unlisted_udp.context.as_ref().and_then(|c| c.get::<usize>()),
            Some(&7)
        );
        drop(unlisted_udp);

        allow.store(false, Ordering::SeqCst);
        let (i, _j) = tokio::io::duplex(64);
        sessions
            .tcp(NewSession::new(tcp_dst), HostStream::new(i))
            .await
            .unwrap();
        let after_unlisted_udp =
            tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
                .await
                .unwrap();
        assert_eq!(
            after_unlisted_udp
                .context
                .as_ref()
                .and_then(|c| c.get::<usize>()),
            Some(&8),
            "unlisted NAT UDP session must release admission_session before Number::drop enqueues its closed record"
        );
        drop(after_unlisted_udp);
        tokio::time::timeout(Duration::from_secs(5), gate.finish_step(8))
            .await
            .unwrap();

        instance
            .inner()
            .events()
            .lossless_records()
            .unwrap()
            .set_after_closed_enqueue(None);
        instance.stop().await.unwrap();
    }
}
