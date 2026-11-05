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
