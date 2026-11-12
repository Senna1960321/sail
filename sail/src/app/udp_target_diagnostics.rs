//! Feature-only, observation-only fixed-target UDP breadcrumbs. No raw text.
use crate::session::{Chain, SocksAddr};
use portable_atomic::{AtomicU64, Ordering};
use serde_derive::Serialize;
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};

/// A public protocol identifier, independent of the private endpoint.
pub const FIXTURE: &str = "fixed-ipv4-policy-v1";

/// One immutable, opt-in endpoint chosen by the host before instance creation.
#[derive(Clone)]
pub struct InternalUdpTargetPolicy {
    target: std::net::SocketAddrV4,
}
impl std::fmt::Debug for InternalUdpTargetPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalUdpTargetPolicy")
            .finish_non_exhaustive()
    }
}
impl InternalUdpTargetPolicy {
    pub fn new(target: std::net::SocketAddrV4) -> Result<Self, crate::embed::Error> {
        if target.port() == 0
            || target.ip().is_unspecified()
            || target.ip().is_multicast()
            || target.ip().is_broadcast()
        {
            return Err(crate::embed::Error::new(
                crate::embed::ErrorKind::InvalidArgument,
                "UDP diagnostics require one unicast IPv4 endpoint with a nonzero port",
            ));
        }
        Ok(Self { target })
    }
    fn matches(&self, address: &SocksAddr) -> bool {
        matches!(address, SocksAddr::Ip(std::net::SocketAddr::V4(a)) if *a == self.target)
    }
}
pub const FINAL_RULE: u32 = u32::MAX;
pub const UNKNOWN_RULE: u32 = u32::MAX - 1;
macro_rules! numeric_enum {
    ($name:ident { $($variant:ident = $value:expr),* $(,)? }) => {
        #[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
        #[serde(into = "u8")]
        #[repr(u8)]
        pub enum $name { #[default] None = 0, $($variant = $value),* }
        impl From<$name> for u8 { fn from(value: $name) -> Self { value as u8 } }
    };
}
numeric_enum!(Stage { Native=1, NatEntry=2, NatQueue=3, Dispatch=4, Route=5, Chain=6,
    AnyTls=7, Open=8, Request=9, Write=10, ConnectTransport=11, ConnectLayers=12, Authenticate=13 });
numeric_enum!(Outcome { Accepted=1, Failed=2 });
numeric_enum!(QueueStatus { Accepted=1, Full=2, Closed=3, ReserveRefused=4 });
numeric_enum!(Action { Route=1, Direct=2, Reject=3, Drop=4, HijackDns=5 });
numeric_enum!(ErrorCode { NotFound=1, PermissionDenied=2, ConnectionRefused=3,
    ConnectionReset=4, ConnectionAborted=5, NotConnected=6, AddrInUse=7,
    AddrNotAvailable=8, BrokenPipe=9, WouldBlock=10, InvalidInput=11,
    InvalidData=12, TimedOut=13, WriteZero=14, Interrupted=15,
    UnexpectedEof=16, OutOfMemory=17, Other=18, Unclassified=255 });
pub(crate) const NATIVE: Stage = Stage::Native;
pub(crate) const NAT_ENTRY: Stage = Stage::NatEntry;
pub(crate) const NAT_QUEUE: Stage = Stage::NatQueue;
pub(crate) const DISPATCH: Stage = Stage::Dispatch;
pub(crate) const ROUTE: Stage = Stage::Route;
pub(crate) const CHAIN: Stage = Stage::Chain;
pub(crate) const ANYTLS: Stage = Stage::AnyTls;
pub(crate) const OPEN: Stage = Stage::Open;
pub(crate) const REQUEST: Stage = Stage::Request;
pub(crate) const WRITE: Stage = Stage::Write;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub selected: bool,
    pub opaque: u64,
}
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
pub struct Event {
    pub epoch: u64,
    pub flow_id: u64,
    pub parent_flow_id: u64,
    pub stage: Stage,
    pub result: Outcome,
    pub queue_status: QueueStatus,
    pub error_kind: ErrorCode,
    pub bytes: u32,
    pub router_generation: u64,
    pub source_rule_index: u32,
    pub action: Action,
    pub hops: [Hop; 4],
    pub hop_count: u8,
    pub chain_truncated: bool,
    pub chain_available: bool,
    pub address_kind: u8,
    pub matches_fixture: bool,
    pub entry_hit: bool,
    pub original_is_fixture: bool,
    pub coverage_missing: bool,
    pub carrier_reused: bool,
    pub transport_present: bool,
}
// Fixed 16 x 512-byte storage, with no dynamically sized event fields.
#[derive(Clone, Copy)]
#[repr(C)]
struct Slot {
    event: Option<Event>,
    _padding: [u8; 512 - std::mem::size_of::<Option<Event>>()],
}
impl Slot {
    const EMPTY: Self = Self {
        event: None,
        _padding: [0; 512 - std::mem::size_of::<Option<Event>>()],
    };
}
struct Ring {
    slots: [Slot; 16],
    len: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub fixture: &'static str,
    pub configured: bool,
    pub epoch: u64,
    pub dropped: u64,
    pub snapshot_contended: bool,
    pub events: Vec<Event>,
}
impl Snapshot {
    pub(crate) fn unconfigured(epoch: u64) -> Self {
        Self {
            schema_version: 2,
            fixture: FIXTURE,
            configured: false,
            epoch,
            dropped: 0,
            snapshot_contended: false,
            events: Vec::new(),
        }
    }
}
pub(crate) struct Sink {
    policy: InternalUdpTargetPolicy,
    epoch: u64,
    next: AtomicU64,
    dropped: AtomicU64,
    ring: Mutex<Ring>,
}
#[derive(Clone)]
pub(crate) struct Trace {
    sink: Arc<Sink>,
    pub(crate) flow_id: u64,
}
tokio::task_local! { static CURRENT: Option<Trace>; }

pub(crate) fn address_kind(addr: &SocksAddr) -> u8 {
    match addr {
        SocksAddr::Ip(std::net::SocketAddr::V4(_)) => 1,
        SocksAddr::Ip(std::net::SocketAddr::V6(_)) => 2,
        SocksAddr::Domain(..) => 3,
    }
}
pub(crate) fn error_kind(kind: io::ErrorKind) -> ErrorCode {
    match kind {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::ConnectionRefused => ErrorCode::ConnectionRefused,
        io::ErrorKind::ConnectionReset => ErrorCode::ConnectionReset,
        io::ErrorKind::ConnectionAborted => ErrorCode::ConnectionAborted,
        io::ErrorKind::NotConnected => ErrorCode::NotConnected,
        io::ErrorKind::AddrInUse => ErrorCode::AddrInUse,
        io::ErrorKind::AddrNotAvailable => ErrorCode::AddrNotAvailable,
        io::ErrorKind::BrokenPipe => ErrorCode::BrokenPipe,
        io::ErrorKind::WouldBlock => ErrorCode::WouldBlock,
        io::ErrorKind::InvalidInput => ErrorCode::InvalidInput,
        io::ErrorKind::InvalidData => ErrorCode::InvalidData,
        io::ErrorKind::TimedOut => ErrorCode::TimedOut,
        io::ErrorKind::WriteZero => ErrorCode::WriteZero,
        io::ErrorKind::Interrupted => ErrorCode::Interrupted,
        io::ErrorKind::UnexpectedEof => ErrorCode::UnexpectedEof,
        io::ErrorKind::OutOfMemory => ErrorCode::OutOfMemory,
        io::ErrorKind::Other => ErrorCode::Other,
        _ => ErrorCode::Unclassified,
    }
}
pub(crate) fn current() -> Option<Trace> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}
pub(crate) async fn scope<T>(trace: Option<Trace>, future: impl Future<Output = T>) -> T {
    CURRENT.scope(trace, future).await
}
impl Sink {
    pub(crate) fn new(epoch: u64, policy: InternalUdpTargetPolicy) -> Arc<Self> {
        Arc::new(Self {
            policy,
            epoch,
            next: AtomicU64::new(1),
            dropped: AtomicU64::new(0),
            ring: Mutex::new(Ring {
                slots: [Slot::EMPTY; 16],
                len: 0,
            }),
        })
    }
    pub(crate) fn is_fixture(&self, address: &SocksAddr) -> bool {
        self.policy.matches(address)
    }
    pub(crate) fn begin(self: &Arc<Self>, addr: &SocksAddr) -> Option<Trace> {
        self.policy.matches(addr).then(|| Trace {
            sink: self.clone(),
            flow_id: self.next.fetch_add(1, Ordering::Relaxed),
        })
    }
    pub(crate) fn owns(&self, trace: &Trace) -> bool {
        self.epoch == trace.sink.epoch && std::ptr::eq(self, Arc::as_ptr(&trace.sink))
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        let (events, snapshot_contended) = match self.ring.try_lock() {
            Ok(ring) => (
                ring.slots[..ring.len]
                    .iter()
                    .filter_map(|s| s.event)
                    .collect(),
                false,
            ),
            Err(_) => (Vec::new(), true),
        };
        Snapshot {
            schema_version: 2,
            fixture: FIXTURE,
            configured: true,
            epoch: self.epoch,
            dropped: self.dropped.load(Ordering::Relaxed),
            snapshot_contended,
            events,
        }
    }
}
impl Trace {
    pub(crate) fn is_fixture(&self, address: &SocksAddr) -> bool {
        self.sink.policy.matches(address)
    }
    pub(crate) fn event(&self, stage: Stage) -> Event {
        Event {
            epoch: self.sink.epoch,
            flow_id: self.flow_id,
            stage,
            source_rule_index: UNKNOWN_RULE,
            ..Event::default()
        }
    }
    pub(crate) fn emit(&self, event: Event) {
        if event.epoch != self.sink.epoch || event.flow_id != self.flow_id {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(mut ring) = self.sink.ring.try_lock() else {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let index = ring.len;
        if index == 16 {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        ring.slots[index].event = Some(event);
        ring.len += 1;
    }
    pub(crate) fn result(&self, stage: Stage, result: Result<(), io::ErrorKind>) {
        let mut event = self.event(stage);
        match result {
            Ok(()) => event.result = Outcome::Accepted,
            Err(kind) => {
                event.result = Outcome::Failed;
                event.error_kind = error_kind(kind);
            }
        }
        self.emit(event);
    }
    pub(crate) fn address(&self, stage: Stage, addr: &SocksAddr) {
        let mut event = self.event(stage);
        event.address_kind = address_kind(addr);
        event.matches_fixture = self.is_fixture(addr);
        self.emit(event);
    }
    pub(crate) fn chain(&self, root: &str, chain: &Chain) {
        use sha2::{Digest, Sha256};
        let mut event = self.event(CHAIN);
        let mut add = |tag: &str| {
            if event.hop_count == 4 {
                event.chain_truncated = true;
                return;
            }
            let hop = if tag == "selected" {
                Hop {
                    selected: true,
                    opaque: 0,
                }
            } else {
                let mut hash = Sha256::new();
                hash.update(self.sink.epoch.to_be_bytes());
                hash.update(tag.as_bytes());
                let bytes = hash.finalize();
                Hop {
                    selected: false,
                    opaque: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
                }
            };
            event.hops[event.hop_count as usize] = hop;
            event.hop_count += 1;
        };
        add(root);
        let visited = chain.diagnostic_visit(&mut add);
        event.chain_available = visited.is_some();
        event.chain_truncated |= visited.unwrap_or(false);
        if !event.chain_available {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.emit(event);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) const TEST_ADDR: std::net::SocketAddrV4 =
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 41001);
#[cfg(test)]
pub(crate) fn test_policy() -> InternalUdpTargetPolicy {
    InternalUdpTargetPolicy::new(TEST_ADDR).unwrap()
}
#[cfg(all(test, feature = "outbound-direct"))]
pub(crate) fn test_env() -> crate::runtime::RuntimeEnv {
    let mut env = crate::runtime::RuntimeEnv::default();
    env.host.kinds = env
        .host
        .kinds
        .with_internal_udp_target_policy(test_policy());
    env
}
