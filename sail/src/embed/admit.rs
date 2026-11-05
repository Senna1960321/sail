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

impl Options {
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
