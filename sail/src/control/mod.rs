//! What an instance is controlled and watched through: its traffic and
//! connections, its outbounds and groups, delay tests and the mode rules
//! match. The Clash API, the FFI and the command service all go through
//! it, so they tell the same; its types are owned, and outlive the locks
//! they were read under.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::adapter::AnyOutboundHandler;
use crate::app::healthcheck::{HttpProbe, DEFAULT_URL};
use crate::session::{Network, SniffedFrom, SocksAddr};
use crate::RuntimeManager;

pub mod context;
mod dial;
pub mod events;
mod inbounds;
pub mod json;
pub mod listen;
mod providers;
pub mod records;

pub use crate::app::inbound::manager::InboundChange;
pub use dial::{Dialed, Dialer, DIAL_INBOUND};

/// What a reload did: each inbound the configuration has, in its order,
/// then those it no longer has, with what became of it. A host tells by
/// it whose connections were closed: those of the inbounds removed and
/// replaced, and no others.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReloadReport {
    /// How much was built again: a host tells by it why what its
    /// connections went through was kept, or was not.
    pub path: ReloadPath,
    pub inbounds: Vec<(String, InboundChange)>,
    /// What the reload took and did not reach everything with.
    pub notes: Vec<ReloadNote>,
    /// What the recheck of the connections open found, when the reload
    /// was asked for one (`RecheckOpen::CloseRejected`).
    pub recheck: Option<RecheckReport>,
    /// The users whose limits the host set (`set_user_limits`, the
    /// management API) the reload dropped, in order: it changed what the
    /// configuration sets for them, which they are limited by now.
    pub user_limits_dropped: Vec<String>,
}

/// How a reload treats what is not in its configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReloadOptions {
    /// What becomes of the connections open.
    pub recheck_open: RecheckOpen,
}

impl ReloadOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// With the connections open treated as `how` says.
    pub fn recheck_open(mut self, how: RecheckOpen) -> Self {
        self.recheck_open = how;
        self
    }
}

/// What a reload does with the connections open, besides closing those of
/// the inbounds it removes or replaces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecheckOpen {
    /// They go on as they were routed, and are not looked at.
    #[default]
    Keep,
    /// Each is matched again against the routing the reload leaves, as it
    /// was routed and with no side effect: those the rules now reject or
    /// drop are closed, and those they send to another outbound are told
    /// and go on.
    CloseRejected,
}

impl RecheckOpen {
    /// As the API and the C ABI name it.
    pub fn name(self) -> &'static str {
        match self {
            RecheckOpen::Keep => "keep",
            RecheckOpen::CloseRejected => "close_rejected",
        }
    }
}

/// What a reload's recheck of the connections open found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecheckReport {
    /// Those it closed, the rules rejecting or dropping them now.
    pub closed: Vec<RecheckClosed>,
    /// Those the rules now send to another outbound than the one they
    /// went to: told, and not closed.
    pub differ: Vec<RecheckDiffer>,
}

/// A connection a recheck closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecheckClosed {
    /// Its id, as the connections list it.
    pub id: u64,
    /// The index in `route.rules` of the rule that rejects it, as the
    /// routed event names it.
    pub rule: Option<u32>,
}

/// A connection the rules now send elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecheckDiffer {
    /// Its id, as the connections list it.
    pub id: u64,
    /// The outbound it went to, the last of its chain as the connections
    /// list it.
    pub old: String,
    /// The one the rules send it to now; `hijack-dns` when a hijack-dns
    /// rule takes it.
    pub new: String,
}

/// Something a reload took that did not reach all it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReloadNote {
    /// The reload changed defaults every dial goes by, `options` as the
    /// configuration names them, while the endpoint `endpoint` runs: an
    /// endpoint is only set up at a start, so it, and the outbounds it is
    /// built on, go on with the defaults they were built with. The change
    /// applies to them at the next start, and to all else now.
    EndpointKeepsDefaults {
        endpoint: String,
        options: Vec<&'static str>,
    },
}

impl std::fmt::Display for ReloadNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReloadNote::EndpointKeepsDefaults { endpoint, options } => write!(
                f,
                "[{}] endpoint: {} changed; it goes on with what it was built with: applies at the next start",
                endpoint,
                options.join(", ")
            ),
        }
    }
}

/// How much a reload built again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ReloadPath {
    /// Everything the configuration has: the outbounds and groups, the
    /// DNS client, the routing and the rule-sets were built anew, and what
    /// they held of state is as docs/embed.md tells of a reload.
    #[default]
    Full,
    /// The inbounds alone, the configuration being otherwise what ran:
    /// the outbounds and their sessions, the groups and what they know,
    /// the DNS client and its cache, the routing and the rule-sets are
    /// those that ran before, untouched.
    InboundsOnly,
}

impl ReloadPath {
    /// As the API and the log tell it.
    pub fn name(self) -> &'static str {
        match self {
            ReloadPath::Full => "full",
            ReloadPath::InboundsOnly => "inbounds_only",
        }
    }
}
pub use inbounds::{InboundError, InboundInfo};
pub use providers::{Failure, ProviderInfo, RuleSetInfo, SourceKind, SubscriptionInfo};

/// What the instance sent and received since it started, those
/// connections closed included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Traffic {
    pub up_total: u64,
    pub down_total: u64,
    /// The connections open now.
    pub connections: usize,
    /// The panics of tasks the instance went on after, in this run.
    pub faults: u64,
}

/// A connection open now.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionInfo {
    pub id: u64,
    pub network: Network,
    pub inbound_type: String,
    pub inbound_tag: String,
    pub source: SocketAddr,
    pub destination: SocksAddr,
    /// The domain it goes to: the destination's, the name it was dialled
    /// as (`override_destination`), else the one sniffed.
    pub host: Option<String>,
    /// The domain a sniff found, from a TLS server name or an HTTP Host.
    pub sniff_host: Option<String>,
    /// Where the name it was dialled as came from, `sniff` or
    /// `reverse_mapping`; none where it was dialled as asked.
    pub dial_domain_source: Option<&'static str>,
    /// Whether `host` came from the DNS answers sail gave for the
    /// address (`dns.reverse_mapping`), found before routing or dialled:
    /// Mihomo's `mapping` DNS mode.
    pub reverse_mapped: bool,
    pub process: Option<String>,
    pub user: Option<String>,
    /// Who opened it, as the host tells it (Android): the uid, and the
    /// packages that run as it.
    pub uid: Option<u32>,
    pub packages: Vec<String>,
    /// Since the connection started.
    pub upload: u64,
    pub download: u64,
    /// Unix seconds.
    pub start: u32,
    /// The members the groups took to get here, the last first, then the
    /// outbound the rules picked, as Mihomo lists them.
    /// (`["m", "G", "F"]`). The events tell the same outbounds the other
    /// way round, outermost first: `RoutedConnection::chain` is
    /// `["F", "G", "m"]`.
    pub chains: Vec<String>,
    /// The rule that matched; none for `final`.
    pub rule: Option<String>,
}

/// A delay measured of an outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delay {
    pub time: SystemTime,
    /// None for a test that failed.
    pub delay: Option<Duration>,
}

/// An outbound, or a member of an outbound provider.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OutboundInfo {
    pub tag: String,
    /// Its type as Mihomo names it: `Selector`, `Vless`, `Direct`.
    pub kind: &'static str,
    /// The type it was configured with, sing-box's; none for a provider
    /// member.
    pub protocol: Option<String>,
    /// The outbound provider it is a member of.
    pub provider: Option<String>,
    pub udp: bool,
    /// The delays measured, the latest last.
    pub history: Vec<Delay>,
    /// What it selects, for a group.
    pub group: Option<GroupInfo>,
}

/// What a group selects.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupInfo {
    /// The member connections go to now.
    pub selected: String,
    pub members: Vec<String>,
    /// Whether a member is selected by hand; else the group picks itself.
    pub selectable: bool,
    /// For a group that picks itself and can be pinned to a member by hand
    /// (`select`), as a fallback can: the member pinned, `""` for none.
    pub fixed: Option<String>,
    /// For a group that tests its members: what it requests through them,
    /// and the HTTP statuses that pass, as Mihomo shows them (`*`, any).
    pub test_url: Option<String>,
    pub expected_status: Option<String>,
}

/// The mode rules match, and the modes they name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Mode {
    pub current: String,
    pub modes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    #[error("no outbound [{0}]")]
    NotFound(String),
    #[error("[{0}] is not a selector")]
    NotSelector(String),
    /// The selector refused the member.
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    InvalidUrl(String),
    #[error("the delay test failed: {0}")]
    Failed(String),
    #[error("the delay test timed out")]
    Timeout,
    #[error("no mode [{0}]")]
    NoMode(String),
    #[error("the instance has no mode: its configuration has no Clash API")]
    NoModes,
    #[error("no outbound provider [{0}]")]
    NoProvider(String),
    #[error("no rule-set [{0}]")]
    NoRuleSet(String),
    /// The update was made, and failed; what was held before is kept.
    #[error("the update failed: {0}")]
    UpdateFailed(String),
    #[error("the instance is stopping")]
    Stopping,
}

/// The delays kept of an outbound, the latest last; Mihomo's.
const HISTORY: usize = 10;

/// The delays measured of each outbound, the instance's, whoever asked.
#[derive(Default)]
pub(crate) struct Delays(Mutex<HashMap<String, VecDeque<Delay>>>);

impl Delays {
    /// Keeps `delay` as measured now, which it returns.
    fn record(&self, tag: &str, delay: Option<Duration>) -> SystemTime {
        let time = SystemTime::now();
        let mut all = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entries = all.entry(tag.to_string()).or_default();
        entries.push_back(Delay { time, delay });
        while entries.len() > HISTORY {
            entries.pop_front();
        }
        time
    }

    fn of(&self, tag: &str) -> Vec<Delay> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tag)
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// The name Mihomo gives outbounds of `protocol`.
pub(crate) fn mihomo_kind(protocol: &str) -> &'static str {
    match protocol {
        "direct" => "Direct",
        "drop" | "block" | "reject" => "Reject",
        "pass" => "Pass",
        "dns" => "Dns",
        "selector" => "Selector",
        "urltest" => "URLTest",
        "fallback" => "Fallback",
        "load-balance" => "LoadBalance",
        "smart" => "Smart",
        "network" => "Network",
        "chain" => "Relay",
        "shadowsocks" => "Shadowsocks",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "socks" => "Socks5",
        "http" => "Http",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "anytls" => "AnyTLS",
        "shadowtls" => "ShadowTLS",
        "wireguard" => "WireGuard",
        "redirect" => "Redirect",
        _ => "Unknown",
    }
}

/// The modes, as sing-box lists them: those the routing and DNS rules
/// name that are not Clash's own, sorted, then Clash's own they name, in
/// Clash's order; the default mode first if none of them.
pub(crate) fn modes(config: &crate::config::model::Config) -> Vec<String> {
    use crate::config::model::Rule;
    fn collect(rule: &Rule, into: &mut Vec<String>) {
        if let Some(mode) = &rule.clash_mode {
            into.push(mode.clone());
        }
        for rule in &rule.rules {
            collect(rule, into);
        }
    }
    let mut named = Vec::new();
    for rule in &config.route.rules {
        collect(rule, &mut named);
    }
    for rule in &config.dns.rules {
        collect(&rule.conditions(), &mut named);
    }
    const CLASH: [&str; 3] = ["Rule", "Global", "Direct"];
    let is_clash = |m: &str| CLASH.iter().any(|c| c.eq_ignore_ascii_case(m));
    let mut modes: Vec<String> = named.iter().filter(|m| !is_clash(m)).cloned().collect();
    modes.sort();
    modes.dedup();
    for clash in CLASH {
        if named.iter().any(|m| m.eq_ignore_ascii_case(clash)) {
            modes.push(clash.to_string());
        }
    }
    let default = config
        .clash_api
        .as_ref()
        .and_then(|api| api.default_mode.clone())
        .unwrap_or_else(|| "Rule".to_string());
    if !modes.iter().any(|m| m.eq_ignore_ascii_case(&default)) {
        modes.insert(0, default);
    }
    modes
}

/// The process's resident memory, in bytes; 0 where it is not known.
pub fn resident_memory() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let pages = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0);
        // SAFETY: sysconf only reads a constant.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        pages * page.max(0) as u64
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // SAFETY: `info` is as large as the call is told it is.
        let read = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if read == size {
            info.pti_resident_size
        } else {
            0
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        0
    }
}

/// The features this build of sail has: protocols, transports, the
/// configuration formats and what the host can use.
pub fn features() -> Vec<&'static str> {
    vec![
        #[cfg(feature = "config-clash")]
        "config-clash",
        #[cfg(feature = "config-surge")]
        "config-surge",
        #[cfg(feature = "quic")]
        "quic",
        #[cfg(feature = "tls")]
        "tls",
        #[cfg(feature = "dns-doh")]
        "dns-doh",
        #[cfg(feature = "dns-h3")]
        "dns-h3",
        #[cfg(feature = "rule-process-name")]
        "rule-process-name",
        #[cfg(feature = "http-client")]
        "http-client",
        #[cfg(feature = "rule-set")]
        "rule-set",
        #[cfg(feature = "outbound-provider")]
        "outbound-provider",
        #[cfg(feature = "outbound-direct")]
        "outbound-direct",
        #[cfg(feature = "outbound-drop")]
        "outbound-drop",
        #[cfg(feature = "outbound-pass")]
        "outbound-pass",
        #[cfg(feature = "outbound-redirect")]
        "outbound-redirect",
        #[cfg(feature = "outbound-shadowsocks")]
        "outbound-shadowsocks",
        #[cfg(feature = "outbound-obfs")]
        "outbound-obfs",
        #[cfg(feature = "outbound-socks")]
        "outbound-socks",
        #[cfg(feature = "outbound-trojan")]
        "outbound-trojan",
        #[cfg(feature = "outbound-http")]
        "outbound-http",
        #[cfg(feature = "outbound-hysteria2")]
        "outbound-hysteria2",
        #[cfg(feature = "outbound-tuic")]
        "outbound-tuic",
        #[cfg(feature = "outbound-anytls")]
        "outbound-anytls",
        #[cfg(feature = "outbound-shadowtls")]
        "outbound-shadowtls",
        #[cfg(feature = "outbound-tls")]
        "outbound-tls",
        #[cfg(feature = "outbound-ws")]
        "outbound-ws",
        #[cfg(feature = "outbound-httpupgrade")]
        "outbound-httpupgrade",
        #[cfg(feature = "outbound-grpc")]
        "outbound-grpc",
        #[cfg(feature = "outbound-tryall")]
        "outbound-tryall",
        #[cfg(feature = "outbound-vless")]
        "outbound-vless",
        #[cfg(feature = "outbound-reality")]
        "outbound-reality",
        #[cfg(feature = "outbound-amux")]
        "outbound-amux",
        #[cfg(feature = "outbound-quic")]
        "outbound-quic",
        #[cfg(feature = "outbound-mptp")]
        "outbound-mptp",
        #[cfg(feature = "outbound-select")]
        "outbound-select",
        #[cfg(feature = "outbound-urltest")]
        "outbound-urltest",
        #[cfg(feature = "outbound-load-balance")]
        "outbound-load-balance",
        #[cfg(feature = "outbound-smart")]
        "outbound-smart",
        #[cfg(feature = "outbound-fallback")]
        "outbound-fallback",
        #[cfg(feature = "outbound-network-group")]
        "outbound-network-group",
        #[cfg(feature = "outbound-vmess")]
        "outbound-vmess",
        #[cfg(feature = "inbound-trojan")]
        "inbound-trojan",
        #[cfg(feature = "inbound-vless")]
        "inbound-vless",
        #[cfg(feature = "inbound-vmess")]
        "inbound-vmess",
        #[cfg(feature = "inbound-mixed")]
        "inbound-mixed",
        #[cfg(feature = "inbound-hysteria2")]
        "inbound-hysteria2",
        #[cfg(feature = "inbound-tuic")]
        "inbound-tuic",
        #[cfg(feature = "inbound-anytls")]
        "inbound-anytls",
        #[cfg(feature = "inbound-shadowtls")]
        "inbound-shadowtls",
        #[cfg(feature = "inbound-mptp")]
        "inbound-mptp",
        #[cfg(feature = "inbound-shadowsocks")]
        "inbound-shadowsocks",
        #[cfg(feature = "inbound-socks")]
        "inbound-socks",
        #[cfg(feature = "inbound-http")]
        "inbound-http",
        #[cfg(feature = "inbound-tun")]
        "inbound-tun",
        #[cfg(feature = "inbound-ws")]
        "inbound-ws",
        #[cfg(feature = "inbound-httpupgrade")]
        "inbound-httpupgrade",
        #[cfg(feature = "inbound-grpc")]
        "inbound-grpc",
        #[cfg(feature = "inbound-amux")]
        "inbound-amux",
        #[cfg(feature = "inbound-quic")]
        "inbound-quic",
        #[cfg(feature = "inbound-tls")]
        "inbound-tls",
        #[cfg(feature = "inbound-reality")]
        "inbound-reality",
        #[cfg(feature = "inbound-direct")]
        "inbound-direct",
        #[cfg(feature = "inbound-redirect")]
        "inbound-redirect",
        #[cfg(feature = "inbound-tproxy")]
        "inbound-tproxy",
        #[cfg(feature = "wireguard")]
        "wireguard",
        #[cfg(feature = "mux")]
        "mux",
        #[cfg(feature = "clash-api")]
        "clash-api",
        #[cfg(feature = "auto-reload")]
        "auto-reload",
    ]
}

/// How many members of a group are measured at a time: Mihomo's.
const MEMBER_TESTS: usize = 10;

/// A member's last check by a group that checks its members.
#[cfg(feature = "outbound-select")]
type Tested = crate::protocol::group::members::Tested;
#[cfg(not(feature = "outbound-select"))]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Tested {
    latency: Option<Duration>,
    at: SystemTime,
}

/// The groups' changes from when it was made: of a selection, or of a
/// member's checks. See `RuntimeManager::group_changes`.
pub struct GroupChanges(
    #[cfg(feature = "outbound-select")] Vec<crate::app::outbound::selector::GroupChanges>,
);

impl GroupChanges {
    /// Returns at the first change, or once a group is gone, as a reload
    /// replaces them; never when there is no group.
    pub async fn changed(self) {
        #[cfg(feature = "outbound-select")]
        {
            let mut changes = self.0;
            if !changes.is_empty() {
                let changed = changes.iter_mut().map(|c| Box::pin(c.changed()));
                futures::future::select_all(changed).await;
                return;
            }
        }
        std::future::pending::<()>().await
    }
}

/// The names a connection's list entry shows, and where they came from.
struct Names {
    host: Option<String>,
    sniff_host: Option<String>,
    dial_domain_source: Option<&'static str>,
    reverse_mapped: bool,
}

impl Names {
    /// Of `sess`: the destination's domain, else the name it was dialled
    /// as, else the one sniffed or reverse-mapped.
    fn of(sess: &crate::session::Session) -> Self {
        use crate::session::DialDomainSource;
        let dialled = sess.state.get::<crate::session::Dialled>().get();
        let sniff_host = [SniffedFrom::Tls, SniffedFrom::Http]
            .into_iter()
            .find_map(|from| sess.sniffed_domain_from(from))
            .map(str::to_owned);
        let (host, reverse_mapped) = match (sess.destination.domain(), &dialled, &sess.sniffed) {
            (Some(domain), _, _) => (Some(domain.clone()), false),
            (None, Some((domain, source)), _) => (
                Some(domain.clone()),
                *source == DialDomainSource::ReverseMapping,
            ),
            (None, None, Some((from, domain))) => (Some(domain.clone()), *from == SniffedFrom::Dns),
            (None, None, None) => (None, false),
        };
        Names {
            host,
            sniff_host,
            dial_domain_source: dialled.map(|(_, source)| source.name()),
            reverse_mapped,
        }
    }
}

impl RuntimeManager {
    /// What the instance sent and received.
    pub async fn traffic(&self) -> Traffic {
        let (up_total, down_total) = self.stat_manager.totals();
        Traffic {
            up_total,
            down_total,
            connections: self.stat_manager.live(),
            faults: self.env.scope.faults(),
        }
    }

    /// The connections open now, by id.
    pub async fn connections(&self) -> Vec<ConnectionInfo> {
        self.stat_manager
            .connections()
            .iter()
            .map(|counter| {
                let sess = &counter.sess;
                // Mihomo's order: the member last, innermost, first, the
                // outbound routed to last.
                let mut chains = sess.chain.get();
                chains.reverse();
                chains.push(sess.outbound_tag.clone());
                let names = Names::of(sess);
                ConnectionInfo {
                    id: counter.id,
                    network: sess.network,
                    inbound_type: sess.inbound_type.to_string(),
                    inbound_tag: sess.inbound_tag.clone(),
                    source: sess.source,
                    destination: sess.destination.clone(),
                    host: names.host,
                    sniff_host: names.sniff_host,
                    dial_domain_source: names.dial_domain_source,
                    reverse_mapped: names.reverse_mapped,
                    process: sess.process_name.clone(),
                    user: crate::user::name(&sess.user).map(str::to_owned),
                    uid: sess.owner.as_ref().map(|o| o.uid),
                    packages: sess
                        .owner
                        .as_ref()
                        .map(|o| o.packages.clone())
                        .unwrap_or_default(),
                    upload: counter.bytes_sent(),
                    download: counter.bytes_recvd(),
                    start: counter.start_time(),
                    chains,
                    rule: sess.matched_rule.as_deref().map(str::to_owned),
                }
            })
            .collect()
    }

    /// Closes the connection `id`: its reads and writes fail. False when
    /// there is none so numbered.
    pub async fn close_connection(&self, id: u64) -> bool {
        self.stat_manager.close(id)
    }

    /// An interim pass the host asks for: a record of each connection
    /// open, idle ones too, its bytes since it started (control::events'
    /// `ConnectionRecord`), each queued to a lossless sink by the time it
    /// returns; how many were told, none while no one listens.
    pub async fn report_connections(&self) -> usize {
        self.stat_manager.report(true)
    }

    /// Closes every connection open, returning how many.
    pub async fn close_all_connections(&self) -> usize {
        self.stat_manager.close_all()
    }

    /// The outbound `tag`, or else the first outbound provider member so
    /// named.
    pub async fn outbound(&self, tag: &str) -> Option<OutboundInfo> {
        let latencies = self.latencies().await;
        let (handler, kind, protocol, provider) = self.find_outbound(tag)?;
        Some(
            self.describe(tag, &handler, kind, protocol, provider, &latencies)
                .await,
        )
    }

    /// The outbounds, in the order the configuration has them (those added
    /// since after), then the members of outbound providers, in their
    /// providers' order, for the groups that take them; an outbound so
    /// named comes first.
    pub async fn outbounds(&self) -> Vec<OutboundInfo> {
        let latencies = self.latencies().await;
        let om = self.outbound_manager.load_full();
        let mut out = Vec::new();
        // By tag, not by handler: identical outbounds share one, which
        // goes by one of their tags.
        let tags = self.order.load();
        for tag in tags.iter() {
            if let Some(handler) = om.get(tag) {
                let protocol = om.protocol(tag).unwrap_or_default();
                out.push(
                    self.describe(
                        tag,
                        &handler,
                        mihomo_kind(protocol),
                        Some(protocol.to_string()),
                        None,
                        &latencies,
                    )
                    .await,
                );
            }
        }
        #[cfg(feature = "outbound-provider")]
        for provider in om.providers().all() {
            for member in provider.members().load().members.iter() {
                let name = member.key.name.to_string();
                if out.iter().any(|o| o.tag == name) {
                    continue;
                }
                out.push(
                    self.describe(
                        &name,
                        &member.handler,
                        member.kind,
                        None,
                        member.key.source.as_deref().map(str::to_owned),
                        &latencies,
                    )
                    .await,
                );
            }
        }
        out
    }

    /// The groups: the outbounds that select among members.
    pub async fn groups(&self) -> Vec<OutboundInfo> {
        let mut groups = self.outbounds().await;
        groups.retain(|o| o.group.is_some());
        groups
    }

    /// Whether the instance has a TUN inbound.
    pub fn has_tun(&self) -> bool {
        #[cfg(feature = "inbound-tun")]
        return self.tun_control.is_some();
        #[cfg(not(feature = "inbound-tun"))]
        false
    }

    /// The outbound connections take when the rules pick none.
    pub fn default_outbound(&self) -> Option<String> {
        self.outbound_manager.load().default_handler()
    }

    /// Selects `member` of the selector `group` by hand; the choice is kept
    /// in the cache file, as sing-box keeps it. A group that picks itself
    /// and can be pinned, a fallback, is pinned to `member`, as Mihomo
    /// pins it: see `unfix`.
    pub async fn select(&self, group: &str, member: &str) -> Result<(), ControlError> {
        #[cfg(feature = "outbound-select")]
        {
            let om = self.outbound_manager.load_full();
            let Some(selector) = om.get_selector(group) else {
                return Err(match om.get(group) {
                    Some(_) => ControlError::NotSelector(group.to_string()),
                    None => ControlError::NotFound(group.to_string()),
                });
            };
            let mut selector = selector.write().await;
            if !selector.is_selectable() && !selector.is_pinnable() {
                return Err(ControlError::NotSelector(group.to_string()));
            }
            selector
                .set_selected(member)
                .map_err(|e| ControlError::Rejected(e.to_string()))
        }
        #[cfg(not(feature = "outbound-select"))]
        {
            let _ = member;
            Err(match self.outbound_manager.load().get(group) {
                Some(_) => ControlError::NotSelector(group.to_string()),
                None => ControlError::NotFound(group.to_string()),
            })
        }
    }

    /// Unpins the group `group`, which goes back to its own choice, as
    /// Mihomo's `DELETE /proxies/{name}` does; nothing for an outbound that
    /// is not pinned or cannot be. A selector, selected by hand, is not
    /// such an outbound.
    pub async fn unfix(&self, group: &str) -> Result<(), ControlError> {
        let om = self.outbound_manager.load_full();
        if om.get(group).is_none() {
            return Err(ControlError::NotFound(group.to_string()));
        }
        #[cfg(feature = "outbound-select")]
        if let Some(selector) = om.get_selector(group) {
            let selector = selector.read().await;
            if selector.is_selectable() {
                return Err(ControlError::Rejected(format!(
                    "[{}] is a selector, selected by hand: nothing pins it",
                    group
                )));
            }
            selector.unfix();
        }
        Ok(())
    }

    /// Measures the delay of the outbound `tag` with an HTTP request to
    /// `url` (sing-box's default when none), and keeps it, a failure too,
    /// among `tag`'s delays.
    pub async fn url_test(
        &self,
        tag: &str,
        url: Option<&str>,
        timeout: Duration,
    ) -> Result<Duration, ControlError> {
        let (handler, ..) = self
            .find_outbound(tag)
            .ok_or_else(|| ControlError::NotFound(tag.to_string()))?;
        self.probe(tag, &handler, url.unwrap_or(DEFAULT_URL), timeout)
            .await
    }

    /// Measures each member of the group `group`, ten at a time, as
    /// Mihomo does; each kept among its delays. A group that checks its
    /// members runs its own check instead, as sing-box's API has its
    /// urltest do: with its own URL and its own timeout for each, within
    /// `timeout` in all; the group chooses from it as from any other.
    pub async fn url_test_members(
        &self,
        group: &str,
        url: Option<&str>,
        timeout: Duration,
    ) -> Result<Vec<(String, Result<Duration, ControlError>)>, ControlError> {
        use futures::StreamExt;
        #[cfg(feature = "outbound-select")]
        if let Some(checks) = self.group_checks(group).await {
            // In the instance's scope, as `probe` is.
            let checked = tokio::time::timeout(timeout, self.env.scope.enter(checks.check()))
                .await
                .map_err(|_| ControlError::Timeout)?;
            return Ok(checked
                .into_iter()
                .map(|(member, latency)| {
                    let latency = latency
                        .map(|l| l.max(Duration::from_millis(1)))
                        .ok_or_else(|| ControlError::Failed("the group's test failed".into()));
                    (member.name.to_string(), latency)
                })
                .collect());
        }
        let members = self
            .outbound(group)
            .await
            .ok_or_else(|| ControlError::NotFound(group.to_string()))?
            .group
            .ok_or_else(|| ControlError::NotFound(group.to_string()))?
            .members;
        let url = url.unwrap_or(DEFAULT_URL);
        Ok(futures::stream::iter(members)
            .map(|member| async move {
                let delay = self.url_test(&member, Some(url), timeout).await;
                (member, delay)
            })
            .buffer_unordered(MEMBER_TESTS)
            .collect()
            .await)
    }

    /// The members of the outbound provider `provider`, in its order; none
    /// if there is no such provider.
    #[cfg(feature = "outbound-provider")]
    pub async fn provider_members(&self, provider: &str) -> Option<Vec<OutboundInfo>> {
        let provider = self.find_provider(provider)?;
        let latencies = HashMap::new();
        let mut out = Vec::new();
        for member in provider.members().load().members.iter() {
            out.push(
                self.describe(
                    &member.key.name,
                    &member.handler,
                    member.kind,
                    None,
                    Some(provider.tag.to_string()),
                    &latencies,
                )
                .await,
            );
        }
        Some(out)
    }

    /// Measures the member `member` of the outbound provider `provider`,
    /// as `url_test` does an outbound, though an outbound or another
    /// provider's member has the name too.
    #[cfg(feature = "outbound-provider")]
    pub async fn url_test_provider_member(
        &self,
        provider: &str,
        member: &str,
        url: Option<&str>,
        timeout: Duration,
    ) -> Result<Duration, ControlError> {
        let handler = self
            .find_provider(provider)
            .ok_or_else(|| ControlError::NoProvider(provider.to_string()))?
            .members()
            .load()
            .find(member)
            .map(|m| m.handler.clone())
            .ok_or_else(|| ControlError::NotFound(member.to_string()))?;
        self.probe(member, &handler, url.unwrap_or(DEFAULT_URL), timeout)
            .await
    }

    #[cfg(feature = "outbound-provider")]
    fn find_provider(&self, tag: &str) -> Option<std::sync::Arc<crate::app::provider::Provider>> {
        self.outbound_manager
            .load()
            .providers()
            .all()
            .iter()
            .find(|p| &*p.tag == tag)
            .cloned()
    }

    /// What the configuration sets that sail ignores or that is
    /// deprecated, since the last start or reload: told once, as libbox's
    /// deprecated notes are, then gone.
    pub fn take_warnings(&self) -> Vec<String> {
        std::mem::take(&mut *self.warnings.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The mode rules match and the modes they name; none when the
    /// configuration has no Clash API, as in sing-box.
    pub fn mode(&self) -> Option<Mode> {
        let current = self.env.clash_mode.get()?;
        Some(Mode {
            current,
            modes: (**self.modes.load()).clone(),
        })
    }

    /// Switches to `mode`, matched as it is, then in any case, among the
    /// modes.
    pub fn set_mode(&self, mode: &str) -> Result<(), ControlError> {
        let Some(Mode { modes, .. }) = self.mode() else {
            return Err(ControlError::NoModes);
        };
        let found = modes
            .iter()
            .find(|m| *m == mode)
            .or_else(|| modes.iter().find(|m| m.eq_ignore_ascii_case(mode)))
            .ok_or_else(|| ControlError::NoMode(mode.to_string()))?;
        self.switch_clash_mode(found);
        Ok(())
    }

    /// The outbound `tag`, or else the first member of an outbound
    /// provider so named: its handler, Mihomo's type, the configured type,
    /// and the provider.
    fn find_outbound(
        &self,
        tag: &str,
    ) -> Option<(
        AnyOutboundHandler,
        &'static str,
        Option<String>,
        Option<String>,
    )> {
        let om = self.outbound_manager.load_full();
        if let Some(handler) = om.get(tag) {
            let protocol = om.protocol(tag).unwrap_or_default();
            return Some((
                handler,
                mihomo_kind(protocol),
                Some(protocol.to_string()),
                None,
            ));
        }
        #[cfg(feature = "outbound-provider")]
        for provider in om.providers().all() {
            if let Some(member) = provider.members().load().find(tag) {
                return Some((
                    member.handler.clone(),
                    member.kind,
                    None,
                    member.key.source.as_deref().map(str::to_owned),
                ));
            }
        }
        None
    }

    async fn describe(
        &self,
        tag: &str,
        handler: &AnyOutboundHandler,
        kind: &'static str,
        protocol: Option<String>,
        provider: Option<String>,
        latencies: &HashMap<String, Tested>,
    ) -> OutboundInfo {
        let mut history = self.delays.of(tag);
        // A group's own last check, failed or not, at the time it ended,
        // where nothing was measured here since: the state the group
        // goes by. A failed one is kept, delay 0 and not alive, as Mihomo
        // keeps its alive state (adapter/adapter.go), which dashboards
        // read; sing-box deletes a failed member's history instead, and
        // has no alive.
        if let Some(tested) = latencies.get(tag) {
            if history.last().is_none_or(|d| d.time < tested.at) {
                history.push(Delay {
                    time: tested.at,
                    delay: tested.latency,
                });
                if history.len() > HISTORY {
                    history.remove(0);
                }
            }
        }
        #[cfg_attr(not(feature = "outbound-select"), allow(unused_mut))]
        let mut group = None;
        #[cfg(feature = "outbound-select")]
        if let Some(selector) = provider
            .is_none()
            .then(|| self.outbound_manager.load().get_selector(tag))
            .flatten()
        {
            let selector = selector.read().await;
            let checks = selector.checks();
            group = Some(GroupInfo {
                selected: selector.get_selected_tag(),
                members: selector.get_available_tags(),
                selectable: selector.is_selectable(),
                fixed: selector
                    .is_pinnable()
                    .then(|| selector.fixed().unwrap_or_default()),
                test_url: checks.as_ref().map(|c| c.url()),
                expected_status: checks.as_ref().map(|c| c.expected_status()),
            });
        }
        OutboundInfo {
            tag: tag.to_string(),
            kind,
            protocol,
            provider,
            udp: handler.datagram().is_ok(),
            history,
            group,
        }
    }

    /// The last check the groups made of each of their members, failed
    /// or not; the latest, of a member of several.
    async fn latencies(&self) -> HashMap<String, Tested> {
        #[cfg_attr(not(feature = "outbound-select"), allow(unused_mut))]
        let mut out: HashMap<String, Tested> = HashMap::new();
        #[cfg(feature = "outbound-select")]
        {
            let om = self.outbound_manager.load_full();
            for handler in om.handlers() {
                if let Some(selector) = om.get_selector(handler.tag()) {
                    let tested = selector.read().await.get_tested().unwrap_or_default();
                    for (tag, tested) in tested {
                        let Some(tested) = tested else { continue };
                        if out.get(&tag).is_none_or(|t| t.at < tested.at) {
                            out.insert(tag, tested);
                        }
                    }
                }
            }
        }
        out
    }

    /// The changes of the groups from now on: of the member one selects,
    /// or of a member's checks. Made before the groups are read, it
    /// misses none after.
    pub async fn group_changes(&self) -> GroupChanges {
        #[cfg(feature = "outbound-select")]
        {
            let om = self.outbound_manager.load_full();
            let mut changes = Vec::new();
            for handler in om.handlers() {
                if let Some(selector) = om.get_selector(handler.tag()) {
                    changes.push(selector.read().await.changes());
                }
            }
            GroupChanges(changes)
        }
        #[cfg(not(feature = "outbound-select"))]
        GroupChanges()
    }

    /// The checks of the group `group`, if it checks its members.
    #[cfg(feature = "outbound-select")]
    async fn group_checks(
        &self,
        group: &str,
    ) -> Option<std::sync::Arc<dyn crate::app::outbound::selector::GroupChecks>> {
        let selector = self.outbound_manager.load().get_selector(group)?;
        let checks = selector.read().await.checks();
        checks
    }

    /// Gives a delay of `tag` measured here at `at` to the groups that
    /// check it among their members, as sing-box's API has its urltest
    /// groups check again after one.
    #[cfg_attr(not(feature = "outbound-select"), allow(unused_variables))]
    async fn feed_groups(&self, tag: &str, delay: Option<Duration>, at: SystemTime) {
        #[cfg(feature = "outbound-select")]
        {
            let om = self.outbound_manager.load_full();
            for handler in om.handlers() {
                if let Some(selector) = om.get_selector(handler.tag()) {
                    let selector = selector.read().await;
                    if let (Some(checks), Some(member)) = (selector.checks(), selector.member(tag))
                    {
                        checks.record(&member, delay, at);
                    }
                }
            }
        }
    }

    /// Measures the delay of `handler`, keeping it as `tag`'s.
    async fn probe(
        &self,
        tag: &str,
        handler: &AnyOutboundHandler,
        url: &str,
        timeout: Duration,
    ) -> Result<Duration, ControlError> {
        let dns = self.dns_client.clone();
        let probe = HttpProbe::new(url, dns.clone(), &self.env)
            .map_err(|e| ControlError::InvalidUrl(e.to_string()))?;
        // The instance's work, whoever's task awaits it (a host's, the C
        // ABI's): what the probe spawns (a QUIC endpoint's driver) is in
        // its scope, and a stop ends it.
        let measured = match tokio::time::timeout(
            timeout,
            self.env.scope.enter(probe.run(dns, handler, timeout)),
        )
        .await
        {
            Ok(Ok(delay)) => Ok(delay.max(Duration::from_millis(1))),
            Ok(Err(e)) => Err(ControlError::Failed(e.to_string())),
            Err(_) => Err(ControlError::Timeout),
        };
        let delay = measured.as_ref().ok().copied();
        let at = self.delays.record(tag, delay);
        self.feed_groups(tag, delay, at).await;
        measured
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name a connection shows, and whether it came from the DNS
    /// answers sail gave (Mihomo's `mapping` DNS mode): found before
    /// routing, or the one dialled.
    #[test]
    fn a_name_shows_where_it_came_from() {
        use crate::session::{DialDomainSource, Dialled, Session, SocksAddr};
        let to_ip = || Session {
            destination: SocksAddr::from(("192.0.2.1".parse::<std::net::IpAddr>().unwrap(), 443)),
            ..Default::default()
        };
        let names = |sess: &Session| {
            let n = Names::of(sess);
            (n.host, n.sniff_host, n.dial_domain_source, n.reverse_mapped)
        };
        let mut sess = to_ip();
        assert_eq!(names(&sess), (None, None, None, false));
        sess.set_sniffed_domain(SniffedFrom::Dns, "mapped.test".into());
        assert_eq!(names(&sess), (Some("mapped.test".into()), None, None, true));
        sess.set_sniffed_domain(SniffedFrom::Tls, "sni.test".into());
        assert_eq!(
            names(&sess),
            (
                Some("sni.test".into()),
                Some("sni.test".into()),
                None,
                false
            )
        );
        // Dialled by the reverse-mapped name, which goes before the sniff.
        sess.state
            .get::<Dialled>()
            .set("mapped.test", DialDomainSource::ReverseMapping);
        assert_eq!(
            names(&sess),
            (
                Some("mapped.test".into()),
                Some("sni.test".into()),
                Some("reverse_mapping"),
                true
            )
        );
        let named = Session {
            destination: SocksAddr::Domain("a.test".into(), 443),
            ..Default::default()
        };
        assert_eq!(names(&named), (Some("a.test".into()), None, None, false));
    }

    #[test]
    fn delays_keep_the_latest_ten() {
        let delays = Delays::default();
        for ms in 1..=12 {
            delays.record("a", Some(Duration::from_millis(ms)));
        }
        delays.record("a", None);
        let kept = delays.of("a");
        assert_eq!(kept.len(), HISTORY);
        assert_eq!(kept[0].delay, Some(Duration::from_millis(4)));
        assert_eq!(kept.last().unwrap().delay, None);
        assert!(delays.of("b").is_empty());
    }
}
