//! Routing: the rules of `route`, compiled, and matched in order against
//! what is known about a connection. A rule's action either decides where
//! the connection goes (`route`, `reject`) or learns more about it
//! (`sniff`, `resolve`) and lets the next rules decide.

pub(crate) mod describe;
pub(crate) mod matcher;
#[cfg(feature = "rule-set")]
pub(crate) mod rule_set;

/// Without the rule-set feature: no rule-sets, and a configuration that has
/// some is refused.
#[cfg(not(feature = "rule-set"))]
pub(crate) mod rule_set {
    use anyhow::{anyhow, Result};

    #[derive(Default, Clone)]
    pub(crate) struct RuleSets;

    /// A rule-set, by tag: there is none to get.
    pub(crate) type SharedRuleSet = ();

    /// The domain matchers of binary rule-sets, of which there are none.
    pub(crate) enum SuccinctSet {}

    impl SuccinctSet {
        pub(crate) fn matches(&self, _domain: &str) -> bool {
            match *self {}
        }

        pub(crate) fn len(&self) -> usize {
            match *self {}
        }
    }

    impl RuleSets {
        pub(crate) fn load(
            configs: &[crate::config::rule_set::RuleSet],
            _clients: &crate::app::http::HttpClients,
            _env: &crate::runtime::RuntimeEnv,
            _before: Option<&RuleSets>,
        ) -> Result<Self> {
            match configs.first() {
                Some(_) => Err(anyhow!(
                    "route.rule_set: not supported, the rule-set feature is not compiled in"
                )),
                None => Ok(RuleSets),
            }
        }

        #[allow(dead_code)]
        pub(crate) fn ip_ranges(
            &self,
            tag: &str,
        ) -> Result<Vec<(std::net::IpAddr, std::net::IpAddr)>> {
            self.get(tag).map(|()| Vec::new())
        }

        #[allow(dead_code)]
        pub(crate) fn subscribe(&self, tag: &str) -> Result<tokio::sync::watch::Receiver<u64>> {
            self.get(tag).map(|()| tokio::sync::watch::channel(0).1)
        }

        pub(crate) fn get(&self, tag: &str) -> Result<()> {
            Err(anyhow!("rule-set [{}] does not exist", tag))
        }

        pub(crate) async fn fetch_missing(
            &self,
            _dispatcher: &crate::app::dispatcher::Dispatcher,
        ) -> Result<()> {
            Ok(())
        }

        pub(crate) fn spawn_updater(
            &self,
            _dispatcher: std::sync::Weak<crate::app::dispatcher::Dispatcher>,
        ) -> Option<tokio::task::AbortHandle> {
            None
        }
    }
}

pub(crate) mod hijack_dns;

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tracing::debug;

use crate::app::SyncDnsClient;
use crate::config::model::{self, RejectMethod, RuleAction};
use crate::net::DialDefaults;
use crate::runtime::RuntimeEnv;
use crate::session::{Session, SocksAddr, TlsFragment};

use matcher::{Facts, Matcher};

/// What the pre-match of a connection's first packet decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreMatch {
    /// The kernel carries the connection, past sail.
    Bypass,
    /// It is refused before it is set up: reset, or dropped when `drop`.
    Reject { drop: bool },
    /// It goes on to be set up and routed as usual.
    Proceed,
}

/// Where a connection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// To this outbound; to the default one when `None`.
    Route(Option<String>),
    /// Direct, past every outbound configured: each rule that matched, and
    /// `final`, routed to a group that passes, as Mihomo's DIRECT takes
    /// what no rule decides.
    Direct,
    /// Nowhere: it is closed at once, or left unanswered when `drop`.
    Reject { drop: bool },
    /// To sail's DNS client, which answers the queries it carries.
    HijackDns,
}

/// What a `sniff` rule asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffAction {
    /// The protocols to look for.
    pub protocols: crate::sniff::Protocols,
    /// How long to wait for the first bytes.
    pub timeout: Duration,
    /// Which dials go to the name known for the address asked for; or,
    /// `AtSniff`, the sniffed domain becomes the destination here.
    pub override_destination: Option<model::OverrideDestination>,
    /// Domains found that are not taken.
    pub skip: SniffSkip,
}

/// The rule-sets whose domains a `sniff` rule does not take, by tag.
#[derive(Clone, Default)]
pub struct SniffSkip(Vec<(String, rule_set::SharedRuleSet)>);

impl SniffSkip {
    /// The rule-sets, each with its tag.
    pub(crate) fn of(sets: Vec<(String, rule_set::SharedRuleSet)>) -> Self {
        SniffSkip(sets)
    }

    /// Whether one of the rule-sets matches `domain`.
    #[cfg(not(feature = "rule-set"))]
    pub fn matches(&self, _domain: &str) -> bool {
        false
    }

    /// Whether one of the rule-sets matches `domain`.
    #[cfg(feature = "rule-set")]
    pub fn matches(&self, domain: &str) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let sess = Session {
            destination: SocksAddr::Domain(domain.to_string(), 0),
            ..Default::default()
        };
        let facts = Facts::new(&sess, &[]);
        self.0
            .iter()
            .any(|(_, set)| set.load().matches(&facts, false))
    }
}

impl std::fmt::Debug for SniffSkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(tag, _)| tag))
            .finish()
    }
}

impl PartialEq for SniffSkip {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.0.iter().zip(&other.0).all(|(a, b)| a.0 == b.0)
    }
}

impl Eq for SniffSkip {}

/// Reads what a `sniff` rule asks for from a connection, into its session.
/// Only the dispatcher, which holds the connection, can.
#[async_trait]
pub trait Sniffer: Send {
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()>;
}

/// Whether an outbound hands a connection on to the next rule, as
/// Mihomo's PASS does: a `pass` outbound, or a group whose pick at the
/// time is one, followed down through the groups picked. Only the
/// dispatcher, which holds the outbounds, can tell.
pub trait Passes: Sync {
    fn passes(&self, tag: &str) -> impl std::future::Future<Output = bool> + Send;
}

/// For connections nothing can be read from.
pub struct NoSniffer;

#[async_trait]
impl Sniffer for NoSniffer {
    async fn sniff(&mut self, _sess: &mut Session, _action: &SniffAction) -> io::Result<()> {
        Ok(())
    }
}

/// The route options of a `route` or `route-options` rule.
#[derive(Default)]
struct Options(Option<Box<OptionsSet>>);

/// The route options a rule sets, when it sets any.
struct OptionsSet {
    override_address: Option<SocksAddr>,
    override_port: Option<u16>,
    udp_disable_domain_unmapping: bool,
    udp_connect: bool,
    udp_timeout: Option<Duration>,
    tls_fragment: Option<TlsFragment>,
    network_strategy: Option<crate::net::dial::NetworkStrategy>,
    fallback_delay: Option<Duration>,
    override_destination: Option<model::OverrideDestination>,
}

/// How long apart the pieces of a fragmented ClientHello go when the rule
/// does not say, as in sing-box.
const TLS_FRAGMENT_DELAY: Duration = crate::transport::fragment::FALLBACK_DELAY;

impl Options {
    fn new(rule: &model::Rule, path: &str) -> Result<Self> {
        let override_address = match &rule.override_address {
            None => None,
            Some(address) if address.is_empty() || address.contains(char::is_whitespace) => {
                return Err(anyhow!(
                    "{}.override_address: \"{}\" is neither an address nor a domain",
                    path,
                    address
                ))
            }
            Some(address) => Some(SocksAddr::try_from((address.as_str(), 0)).map_err(|e| {
                anyhow!(
                    "{}.override_address: \"{}\" is neither an address nor a domain: {}",
                    path,
                    address,
                    e
                )
            })?),
        };
        let tls_fragment = TlsFragment::of(
            rule.tls_fragment,
            rule.tls_record_fragment,
            rule.tls_fragment_fallback_delay
                .unwrap_or(TLS_FRAGMENT_DELAY),
        );
        let set = OptionsSet {
            override_address,
            override_port: rule.override_port,
            udp_disable_domain_unmapping: rule.udp_disable_domain_unmapping,
            udp_connect: rule.udp_connect,
            udp_timeout: rule.udp_timeout,
            tls_fragment,
            network_strategy: rule.network_strategy,
            // Zero is unset, as in sing-box (route/route.go:646).
            fallback_delay: rule.fallback_delay.filter(|d| !d.is_zero()),
            override_destination: rule.override_destination(),
        };
        // Most rules set none: those keep nothing.
        let none = set.override_address.is_none()
            && set.override_port.is_none()
            && !set.udp_disable_domain_unmapping
            && !set.udp_connect
            && set.udp_timeout.is_none()
            && set.tls_fragment.is_none()
            && set.network_strategy.is_none()
            && set.fallback_delay.is_none()
            && set.override_destination.is_none();
        Ok(Options((!none).then(|| Box::new(set))))
    }

    /// Sets the options in `sess`, as sing-box's `matchRule` does: an
    /// override changes the destination the next rules match, and those
    /// rules can set other options still.
    fn apply(&self, sess: &mut Session) {
        if let Some(set) = &self.0 {
            set.apply(sess);
        }
    }

    /// Whether it sets another address to go to.
    fn overrides_address(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|set| set.override_address.is_some())
    }
}

impl OptionsSet {
    fn apply(&self, sess: &mut Session) {
        if self.override_address.is_some() || self.override_port.is_some() {
            if sess.route.original_destination.is_none() {
                sess.route.original_destination = Some(sess.destination.clone());
            }
            // What was resolved is of the destination before (route/route.go:633-635).
            if self.override_address.is_some() {
                sess.route.resolved.clear();
                sess.route.resolved_for_every_outbound = false;
            }
            let port = self.override_port.unwrap_or(sess.destination.port());
            sess.destination = match self.override_address.as_ref().unwrap_or(&sess.destination) {
                SocksAddr::Ip(addr) => SocksAddr::Ip(std::net::SocketAddr::new(addr.ip(), port)),
                SocksAddr::Domain(domain, _) => SocksAddr::Domain(domain.clone(), port),
            };
        }
        let route = &mut sess.route;
        route.udp_disable_domain_unmapping |= self.udp_disable_domain_unmapping;
        route.udp_connect |= self.udp_connect;
        if self.udp_timeout.is_some() {
            route.udp_timeout = self.udp_timeout;
        }
        if self.tls_fragment.is_some() {
            route.tls_fragment = self.tls_fragment;
        }
        // A later rule's go before, as in sing-box (route/route.go:637-648).
        if self.network_strategy.is_some() {
            route.network_strategy = self.network_strategy;
        }
        if self.fallback_delay.is_some() {
            route.fallback_delay = self.fallback_delay;
        }
        if self.override_destination.is_some() {
            route.override_destination = self.override_destination;
        }
    }
}

/// Takes the dial-time `override_destination` of the sniff rule `action`,
/// taken for `sess`, as a route option; `AtSniff` the sniff itself acts on.
fn sniff_options(action: &SniffAction, sess: &mut Session) {
    match action.override_destination {
        Some(model::OverrideDestination::AtSniff) | None => {}
        how => sess.route.override_destination = how,
    }
}

/// A `reject` rule's way.
struct Reject {
    method: RejectMethod,
    no_drop: bool,
    /// When the rule last rejected, for the last 30 seconds.
    recent: Mutex<VecDeque<Instant>>,
}

impl Reject {
    /// Past this many rejections in 30 seconds, a rule drops those after,
    /// as sing-box's does, unless `no_drop`.
    const FLOOD: usize = 50;
    const WINDOW: Duration = Duration::from_secs(30);

    /// Whether a rejection drops the connection by the rule's method
    /// alone, as a recheck takes it: it counts toward no flood.
    fn drops_by_method(&self) -> bool {
        self.method == RejectMethod::Drop
    }

    /// Whether this rejection drops the connection.
    fn drops(&self) -> bool {
        match self.method {
            RejectMethod::Drop => true,
            _ if self.no_drop => false,
            _ => {
                let now = Instant::now();
                let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
                while recent
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > Self::WINDOW)
                {
                    recent.pop_front();
                }
                recent.push_back(now);
                recent.len() > Self::FLOOD
            }
        }
    }
}

enum Action {
    Route(String, Options),
    /// sing-box's bypass: in auto_redirect's pre-match the kernel carries
    /// the connection past sail; elsewhere it routes to the outbound, when
    /// there is one, and is skipped when there is not.
    Bypass(Option<(String, Options)>),
    RouteOptions(Options),
    // Boxed, the few rules that have them: every rule is as large as the
    // largest action.
    Reject(Box<Reject>),
    HijackDns,
    Sniff(Box<SniffAction>),
    Resolve(Box<Resolve>),
    /// `on_demand` sniff: taken when a later rule needs it.
    ArmSniff(Box<SniffAction>),
    /// `on_demand` resolve, likewise.
    ArmResolve(Box<Resolve>),
    /// sing-box 1.14.1's `direct`, which does nothing.
    Direct,
}

/// How a `resolve` rule resolves.
struct Resolve {
    /// The DNS server to ask, when not the one the DNS rules pick.
    server: Option<String>,
    strategy: Option<model::DnsStrategy>,
    /// How long to wait.
    timeout: Option<Duration>,
    /// Whether a domain that does not resolve goes on without addresses,
    /// rather than failing the connection.
    ignore_failure: bool,
    /// How the queries are sent: the cache, TTLs, client subnet.
    options: crate::app::dns::LookupOptions,
}

struct Rule {
    matcher: Matcher,
    action: Action,
    /// The rule told, for the Clash API.
    about: describe::About,
    /// Its index in `route.rules` as written, before inline lines were
    /// merged: what its matches are reported by.
    index: u32,
    /// The inline lines merged into it, each told and numbered as the rule
    /// it was; empty for any other rule.
    lines: Box<[Told]>,
    /// Turned off through the Clash API (`PATCH /rules/disable`), and how
    /// often and when it last matched: for this router only, so that a
    /// reload starts them anew, as in Mihomo.
    state: RuleState,
}

/// What the Clash API sets and reads of a rule while the router lives.
#[derive(Default)]
#[cfg_attr(not(feature = "clash-api"), allow(dead_code))]
struct RuleState {
    disabled: std::sync::atomic::AtomicBool,
    hits: portable_atomic::AtomicU64,
    /// Milliseconds since the epoch; 0 for never.
    hit_at: portable_atomic::AtomicU64,
}

impl RuleState {
    /// It matched a connection, now.
    fn hit(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.hits.fetch_add(1, Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        self.hit_at.store(now, Relaxed);
    }
}

/// A rule's state as the Clash API lists it.
#[cfg(feature = "clash-api")]
pub(crate) struct RuleStats {
    pub disabled: bool,
    pub hits: u64,
    /// Milliseconds since the epoch; 0 for never.
    pub hit_at: u64,
}

/// An inline line merged into a rule (`config::inline`), as the rule it
/// was: its domain, its index, and its `matched`, as it would have had.
struct Told {
    index: u32,
    kind: model::LineKind,
    value: Box<str>,
    matched: std::sync::Arc<str>,
}

impl Rule {
    /// The rule a match of it reports, its `matched` and index: of a rule
    /// lines were merged into, the first line the domain matches, as the
    /// unmerged rules would have matched it.
    fn reported(&self, facts: &Facts) -> (&std::sync::Arc<str>, u32) {
        let domain = facts.domain().map(str::to_ascii_lowercase);
        let first = domain.as_deref().and_then(|domain| {
            self.lines.iter().find(|line| {
                let value = line.value.as_ref();
                match line.kind {
                    model::LineKind::Domain => domain == value,
                    model::LineKind::Suffix => match value.strip_prefix('.') {
                        Some(parent) => domain
                            .strip_suffix(parent)
                            .is_some_and(|rest| rest.ends_with('.')),
                        None => {
                            domain == value
                                || domain
                                    .strip_suffix(value)
                                    .is_some_and(|rest| rest.ends_with('.'))
                        }
                    },
                    model::LineKind::Keyword => domain.contains(value),
                }
            })
        });
        match first {
            Some(line) => (&line.matched, line.index),
            None => (&self.about.matched, self.index),
        }
    }
}

/// Where a walk over the rules stopped.
enum Stop {
    Route(String),
    Reject {
        drop: bool,
    },
    HijackDns,
    /// A bypass rule, in pre-match.
    Bypass,
    /// A rule that needs the connection's data, in pre-match.
    NeedsData,
    /// No rule decided: `final`.
    Final,
}

/// What a walk over the rules is for.
enum Walk<'a> {
    /// Routing a connection, which the sniffer reads for the sniff rules.
    Route(&'a mut dyn Sniffer),
    /// Pre-match: nothing is read, and an armed sniff is never taken.
    PreMatch,
    /// A recheck of a connection routed before, as its session was when
    /// it was routed: nothing is read, resolved or counted.
    Recheck(&'a Session),
}

impl<'a> Walk<'a> {
    /// The session a recheck's connection was routed with.
    fn routed(&self) -> Option<&'a Session> {
        match self {
            Walk::Recheck(routed) => Some(routed),
            _ => None,
        }
    }

    /// Takes the sniff `action` for `sess`: routing reads the connection,
    /// a recheck gives back what was sniffed when it was routed. False in
    /// pre-match, which reads nothing.
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> Result<bool> {
        match self {
            Walk::Route(sniffer) => sniffer
                .sniff(sess, action)
                .await
                .map_err(|e| anyhow!("sniff: {}", e))?,
            Walk::Recheck(routed) => {
                sess.sniffed = routed.sniffed.clone();
                sess.sniffed_protocol = routed.sniffed_protocol;
                sess.sniffed_http = routed.sniffed_http.clone();
            }
            Walk::PreMatch => return Ok(false),
        }
        sniff_options(action, sess);
        Ok(true)
    }
}

/// Where the rules send a connection routed before, as `Router::recheck`
/// finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recheck {
    /// What they decide: `Reject` when they reject or drop it.
    pub decision: Decision,
    /// The index in `route.rules` of the rule that decided, as the routed
    /// event names it; `None` for `final`.
    pub rule: Option<u32>,
}

impl Rule {
    fn new(
        rule: &model::Rule,
        path: &str,
        env: &RuntimeEnv,
        rule_sets: &rule_set::RuleSets,
        dial: &DialDefaults,
    ) -> Result<Self> {
        let action = match rule.action() {
            RuleAction::Route => Action::Route(
                rule.outbound
                    .clone()
                    .ok_or_else(|| anyhow!("{}: outbound: a route rule needs one", path))?,
                Options::new(rule, path)?,
            ),
            RuleAction::Bypass => Action::Bypass(match &rule.outbound {
                Some(tag) => Some((tag.clone(), Options::new(rule, path)?)),
                None => None,
            }),
            RuleAction::RouteOptions => Action::RouteOptions(Options::new(rule, path)?),
            RuleAction::Reject => {
                let method = rule.method.unwrap_or_default();
                if method == RejectMethod::Reply {
                    return Err(anyhow!(
                        "{}.method: reply answers ICMP, which sail does not route",
                        path
                    ));
                }
                Action::Reject(Box::new(Reject {
                    method,
                    no_drop: rule.no_drop,
                    recent: Default::default(),
                }))
            }
            RuleAction::HijackDns => Action::HijackDns,
            RuleAction::Direct => {
                check_direct(rule, path, dial)?;
                Action::Direct
            }
            RuleAction::Resolve => Action::Resolve(Box::new(Resolve {
                server: rule.server.clone(),
                strategy: rule.strategy,
                timeout: rule.timeout,
                ignore_failure: rule.ignore_failure,
                options: crate::app::dns::LookupOptions {
                    disable_cache: rule.disable_cache,
                    disable_optimistic_cache: rule.disable_optimistic_cache,
                    rewrite_ttl: rule.rewrite_ttl,
                    client_subnet: rule.client_subnet,
                },
            })),
            RuleAction::Sniff => {
                if !cfg!(feature = "btls") && rule.sniffer.contains(&model::Sniffer::Quic) {
                    return Err(anyhow!(
                        "{}.sniffer: quic is never sniffed, sail is built without btls",
                        path
                    ));
                }
                let protocols = crate::sniff::Protocols::of(&rule.sniffer);
                Action::Sniff(Box::new(SniffAction {
                    protocols,
                    timeout: rule.timeout.unwrap_or(Duration::from_millis(300)),
                    override_destination: rule.override_destination(),
                    skip: SniffSkip::of(
                        rule.skip_rule_set
                            .iter()
                            .map(|tag| {
                                rule_sets
                                    .get(tag)
                                    .map(|set| (tag.clone(), set))
                                    .map_err(|e| anyhow!("{}.skip_rule_set: {}", path, e))
                            })
                            .collect::<Result<_>>()?,
                    ),
                }))
            }
        };
        let action = match action {
            Action::Resolve(how) if rule.on_demand => Action::ArmResolve(how),
            Action::Sniff(how) if rule.on_demand => Action::ArmSniff(how),
            action => action,
        };
        // Each merged line, told as the rule of its one domain it was.
        let lines = rule
            .lines
            .iter()
            .map(|line| {
                let mut alone = model::Rule {
                    domain: model::List::new(),
                    domain_suffix: model::List::new(),
                    domain_keyword: model::List::new(),
                    lines: model::List::new(),
                    index: None,
                    ..rule.clone()
                };
                let value = line.value.to_ascii_lowercase();
                match line.kind {
                    model::LineKind::Domain => alone.domain = vec![line.value.clone()].into(),
                    model::LineKind::Suffix => {
                        alone.domain_suffix = vec![line.value.clone()].into()
                    }
                    model::LineKind::Keyword => {
                        alone.domain_keyword = vec![line.value.clone()].into()
                    }
                }
                Told {
                    index: line.index,
                    kind: line.kind,
                    value: value.into(),
                    matched: describe::About::of(&alone).matched,
                }
            })
            .collect();
        Ok(Rule {
            matcher: Matcher::at(rule, path, env, rule_sets)?,
            action,
            about: describe::About::of(rule),
            index: rule.index.unwrap_or(0),
            lines,
            state: RuleState::default(),
        })
    }
}

/// Checks the `direct` rule `rule`, at `path`: builds the dialer of its
/// dial fields over the route's defaults, as an outbound's, as sing-box
/// builds it with the rule (route/rule/rule_action.go:76-98), only for its
/// mistakes, the rule having no effect.
fn check_direct(rule: &model::Rule, path: &str, dial: &DialDefaults) -> Result<()> {
    if !cfg!(feature = "outbound-direct") {
        return Err(anyhow!(
            "{}.action: direct, which sail is built without",
            path
        ));
    }
    let fields = rule.direct_fields();
    fields
        .check(crate::net::dial::fields::IMPLEMENTED)
        .and_then(|()| dial.dialer(&fields, None))
        .map(drop)
        .map_err(|e| anyhow!("{}.{}", path, e))
}

pub struct Router {
    rules: Vec<Rule>,
    /// The rule-sets its rules name, for the Clash API to list.
    #[cfg(feature = "rule-set")]
    rule_sets: rule_set::RuleSets,
    final_outbound: Option<String>,
    /// `route.block_quic`: the outbounds QUIC is refused to.
    block_quic: std::collections::HashSet<String>,
    /// `route.find_process`: who opened every connection is looked up.
    find_process: bool,
    dns_client: SyncDnsClient,
    /// The network the host is on, when a rule may have conditions on
    /// it: its state is taken once for each connection matched.
    network: Option<crate::net::network::Network>,
    /// Its number among the routers an instance stored, in the order it
    /// stored them: 1 for the first, one more at each reload.
    generation: u64,
}

impl Router {
    /// The rules built, from the last: each is dropped once built, and its
    /// list given back as it empties, so that a configuration's rules and
    /// the router's are never both whole. The first in order that fails is
    /// the one said, as when they were built in order.
    fn load_rules(
        mut rules: Vec<model::Rule>,
        env: &RuntimeEnv,
        rule_sets: &rule_set::RuleSets,
        dial: &DialDefaults,
    ) -> Result<Vec<Rule>> {
        let mut built = Vec::with_capacity(rules.len());
        let mut failed = None;
        while let Some(rule) = rules.pop() {
            let i = rules.len();
            let index = rule.index.unwrap_or(u32::try_from(i).unwrap_or(u32::MAX));
            match Rule::new(
                &rule,
                &format!("route.rules[{}]", index),
                env,
                rule_sets,
                dial,
            ) {
                Ok(mut rule) if failed.is_none() => {
                    rule.index = index;
                    built.push(rule);
                }
                Ok(_) => {}
                Err(e) => {
                    failed = Some(e);
                    built = Vec::new();
                }
            }
            drop(rule);
            if rules.len() < rules.capacity() / 2 {
                rules.shrink_to_fit();
            }
        }
        if let Some(e) = failed {
            return Err(e);
        }
        built.reverse();
        Ok(built)
    }

    /// A router whose `direct` rules dial over no defaults: for tests.
    pub fn new(route: &model::Route, dns_client: SyncDnsClient, env: &RuntimeEnv) -> Result<Self> {
        Self::with_rule_sets(
            route,
            route.rules.clone(),
            dns_client,
            env,
            &Default::default(),
            &Default::default(),
        )
    }

    /// A router of `rules`, taken out of `route`, whose rules can name the
    /// rule-sets of `rule_sets`, and whose `direct` rules dial over `dial`.
    pub(crate) fn with_rule_sets(
        route: &model::Route,
        rules: Vec<model::Rule>,
        dns_client: SyncDnsClient,
        env: &RuntimeEnv,
        rule_sets: &rule_set::RuleSets,
        dial: &DialDefaults,
    ) -> Result<Self> {
        let rules = Self::load_rules(rules, env, rule_sets, dial)?;
        let network = rules
            .iter()
            .any(|rule| rule.matcher.may_need_network())
            .then(|| env.network.clone());
        Ok(Router {
            rules,
            #[cfg(feature = "rule-set")]
            rule_sets: rule_sets.clone(),
            final_outbound: route.final_outbound.clone(),
            block_quic: route.block_quic.iter().cloned().collect(),
            find_process: route.find_process,
            dns_client,
            network,
            generation: 1,
        })
    }

    /// This router, numbered as the one after `before`, which it replaces.
    pub(crate) fn after(mut self, before: &Router) -> Self {
        self.generation = before.generation + 1;
        self
    }

    /// Its number among the routers an instance stored: a connection
    /// carries the number of the one that routed it (`Session::routed_by`).
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether QUIC is refused to the outbound `tag` (`route.block_quic`).
    pub fn blocks_quic(&self, tag: &str) -> bool {
        self.block_quic.contains(tag)
    }

    /// Whether a rule has conditions on the network the host is on
    /// (`wifi_ssid`, `network_type`, …), its rule-sets' as they are now.
    pub fn needs_network(&self) -> bool {
        self.rules.iter().any(|rule| rule.matcher.needs().network)
    }

    /// Whether a rule, or a rule-set it names as it is now, has conditions
    /// on who opened a connection.
    pub fn needs_owner(&self) -> bool {
        self.rules.iter().any(|rule| rule.matcher.needs().owner)
    }

    /// Whether who opened a connection is looked up: `find_process`, or a
    /// rule needs it.
    pub fn wants_owner(&self) -> bool {
        self.find_process || self.needs_owner()
    }

    /// Whether the program that opened a connection is wanted too:
    /// `find_process`, or a rule on it.
    pub fn wants_process(&self) -> bool {
        self.find_process || self.rules.iter().any(|rule| rule.matcher.needs().process)
    }

    /// Whether a rule, or `final`, routes to the outbound `tag`.
    pub fn uses(&self, tag: &str) -> bool {
        self.final_outbound.as_deref() == Some(tag)
            || self.rules.iter().any(|rule| match &rule.action {
                Action::Route(t, _) | Action::Bypass(Some((t, _))) => t == tag,
                _ => false,
            })
    }

    /// The rule-sets its rules may name.
    #[cfg(feature = "rule-set")]
    pub(crate) fn rule_sets(&self) -> &rule_set::RuleSets {
        &self.rule_sets
    }

    /// Without the feature there are none.
    #[cfg(not(feature = "rule-set"))]
    pub(crate) fn rule_sets(&self) -> &rule_set::RuleSets {
        &rule_set::RuleSets
    }

    /// The rules, told, in order.
    #[cfg(feature = "clash-api")]
    pub(crate) fn rules(&self) -> impl Iterator<Item = &describe::About> {
        self.rules.iter().map(|rule| &rule.about)
    }

    /// The rules, told, in order, each with its proxy as Mihomo lists it
    /// and what the Clash API sets and reads of it.
    #[cfg(feature = "clash-api")]
    pub(crate) fn rules_with_stats(
        &self,
    ) -> impl Iterator<Item = (&describe::About, &str, RuleStats)> {
        use std::sync::atomic::Ordering::Relaxed;
        self.rules.iter().map(|rule| {
            let stats = RuleStats {
                disabled: rule.state.disabled.load(Relaxed),
                hits: rule.state.hits.load(Relaxed),
                hit_at: rule.state.hit_at.load(Relaxed),
            };
            let outbound = match &rule.action {
                Action::Route(tag, _) | Action::Bypass(Some((tag, _))) => Some(tag.as_str()),
                _ => None,
            };
            (&rule.about, rule.about.clash_proxy.told(outbound), stats)
        })
    }

    /// Turns the rule at `index` (its place among `rules`) off, or on
    /// again: a rule off is passed over as if it matched nothing. False
    /// for no such rule.
    #[cfg(feature = "clash-api")]
    pub(crate) fn set_disabled(&self, index: usize, disabled: bool) -> bool {
        match self.rules.get(index) {
            Some(rule) => {
                rule.state
                    .disabled
                    .store(disabled, std::sync::atomic::Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// The index, in the configuration's `route.rules`, of the rule whose
    /// `matched` this is: this router's own, the one a session it routed
    /// carries. `load_rules` builds one rule a configured rule, in order,
    /// a logical rule and one naming rule-sets one each, so the index is
    /// the one a configuration error's `route.rules[i]` names. Each rule
    /// has a `matched` of its own, so two written alike are told apart.
    pub(crate) fn rule_index(&self, matched: &std::sync::Arc<str>) -> Option<u32> {
        self.rules.iter().find_map(|rule| {
            if std::sync::Arc::ptr_eq(&rule.about.matched, matched) {
                return Some(rule.index);
            }
            rule.lines
                .iter()
                .find(|line| std::sync::Arc::ptr_eq(&line.matched, matched))
                .map(|line| line.index)
        })
    }

    /// Matches `sess` against the rules in order, sniffing through
    /// `sniffer`, resolving and setting route options as they say, until
    /// one decides. A rule whose outbound `passes` does not: see `walk`.
    /// `final` passing sends the connection direct.
    pub async fn pick_route(
        &self,
        sess: &mut Session,
        sniffer: &mut dyn Sniffer,
        passes: &impl Passes,
    ) -> Result<Decision> {
        let stop = self.walk(sess, Walk::Route(sniffer), passes).await?;
        Ok(self.decide(stop, passes).await)
    }

    /// Where a walk that stopped at `stop` sends the connection: `final`
    /// passing sends it direct.
    async fn decide(&self, stop: Stop, passes: &impl Passes) -> Decision {
        match stop {
            Stop::Route(tag) => Decision::Route(Some(tag)),
            Stop::Reject { drop } => Decision::Reject { drop },
            Stop::HijackDns => Decision::HijackDns,
            Stop::Final => match &self.final_outbound {
                Some(tag) if passes.passes(tag).await => {
                    debug!("final [{}] passes: direct", tag);
                    Decision::Direct
                }
                tag => Decision::Route(tag.clone()),
            },
            // With a sniffer the walk never stops at these; a release build
            // that somehow did routes to `final` rather than panicking.
            Stop::Bypass | Stop::NeedsData => {
                debug_assert!(false, "only pre-match stops at a bypass or for the data");
                Decision::Route(self.final_outbound.clone())
            }
        }
    }

    /// Where these rules send the connection `routed` now, whose session
    /// is the one it was routed with, as `pick_route` would decide, with
    /// no side effect. A copy of the session is walked from the
    /// destination asked for, before any override, as routing walked it.
    /// Nothing is read of the connection: from the first sniff rule on,
    /// what was sniffed when it was routed stands. No DNS is asked: a
    /// resolve rule gives the addresses resolved when it was routed, for
    /// the destination it had then, and none for another, as `no_resolve`
    /// has it. A rejection counts toward no flood. The network and the
    /// clash mode are as they are now; the rule-sets as they were loaded.
    pub async fn recheck(&self, routed: &Session, passes: &impl Passes) -> Recheck {
        let mut sess = routed.clone();
        sess.route = Default::default();
        if let Some(asked) = routed.route.original_destination.clone() {
            sess.destination = asked;
        }
        // Sniffed later in the walk; what reverse mapping found, before
        // routing, is known from the start.
        sess.sniffed_protocol = None;
        sess.sniffed_http = None;
        if !matches!(sess.sniffed, Some((crate::session::SniffedFrom::Dns, _))) {
            sess.sniffed = None;
        }
        // A recheck neither reads nor resolves, the only ways a walk fails.
        let stop = self
            .walk(&mut sess, Walk::Recheck(routed), passes)
            .await
            .unwrap_or(Stop::Final);
        let decision = self.decide(stop, passes).await;
        Recheck {
            decision,
            rule: sess
                .matched_rule
                .as_ref()
                .and_then(|rule| self.rule_index(rule)),
        }
    }

    /// What a connection's first packet meets before the connection is
    /// set up, as TUN's auto_redirect asks: sing-box's pre-match with
    /// bypass supported (route/route.go:293-318, 470-590). Rules match on
    /// what the packet tells, so those that need a sniffed domain or a
    /// user do not; route options apply and resolve rules resolve, and the
    /// first rule that routes, hijacks DNS or needs the connection's data
    /// (sniff) leaves it to be set up. Any bypass rule lets the kernel
    /// carry it past sail. A failure, such as a domain that does not
    /// resolve, leaves the connection to be set up too, where it fails, as
    /// sing-box accepts the packet on any other error.
    pub async fn pre_match(&self, sess: &mut Session, passes: &impl Passes) -> PreMatch {
        match self.walk(sess, Walk::PreMatch, passes).await {
            Ok(Stop::Bypass) => PreMatch::Bypass,
            Ok(Stop::Reject { drop }) => PreMatch::Reject { drop },
            Ok(_) | Err(_) => PreMatch::Proceed,
        }
    }

    /// The one walk over the rules, for routing, pre-match or a recheck,
    /// as `walk` says (`Walk`).
    ///
    /// A rule that routes to an outbound that `passes` is skipped, as
    /// Mihomo's tunnel skips a rule whose proxy unwraps to PASS
    /// (tunnel/tunnel.go `match`): its route options are not set, and the
    /// sniff and resolve armed stay armed for the rules after.
    async fn walk(
        &self,
        sess: &mut Session,
        mut walk: Walk<'_>,
        passes: &impl Passes,
    ) -> Result<Stop> {
        let pre_match = matches!(walk, Walk::PreMatch);
        sess.matched_rule = None;
        sess.route.resolved.clear();
        sess.route.resolved_for_every_outbound = false;
        // The network as it is when the connection is matched, for every
        // rule alike.
        let network = self.network.as_ref().map(|n| n.snapshot());
        // The destination's IP version, once, from the address asked for,
        // as sing-box has it (route/route.go:585-589): a sniff that makes
        // the sniffed domain the destination does not change it.
        let ip_version = Facts::ip_version_of(sess);
        let facts_of = |sess: &Session, resolved: &[IpAddr]| {
            let facts = Facts::new(sess, resolved).with_ip_version(ip_version);
            match &network {
                Some(state) => facts.with_network(state.clone()),
                None => facts,
            }
        };
        let mut resolved: Vec<IpAddr> = Vec::new();
        let mut facts = facts_of(sess, &resolved);
        // The on_demand actions armed and not yet taken, and whether an
        // armed resolve was, which it is at most once for a destination.
        let mut armed_sniff: Option<&SniffAction> = None;
        let mut armed_resolve: Option<&Resolve> = None;
        let mut resolve_taken = false;
        for rule in self.rules.iter() {
            // As written, before inline lines were merged.
            let i = rule.index;
            if armed_sniff.is_some() || armed_resolve.is_some() {
                let needs = rule.matcher.needs();
                if let Some(action) = armed_sniff {
                    if needs.sniff || (needs.domain && facts.domain().is_none()) {
                        armed_sniff = None;
                        debug!("rule {} needs the connection sniffed", i);
                        if walk.sniff(sess, action).await? {
                            facts = facts_of(sess, &resolved);
                        }
                    }
                }
                if let Some(how) = armed_resolve {
                    if needs.ip && resolved.is_empty() && !resolve_taken && !sess.skip_resolve {
                        if let Some(domain) = sess.destination.domain().cloned() {
                            debug!("rule {} needs {} resolved", i, domain);
                            armed_resolve = None;
                            resolve_taken = true;
                            resolved = self
                                .resolve_in(walk.routed(), how, &domain, sess, network.as_ref())
                                .await?;
                            sess.route.resolved = resolved.clone();
                            sess.route.resolved_for_every_outbound = false;
                            facts = facts_of(sess, &resolved);
                        }
                    }
                }
            }
            if rule
                .state
                .disabled
                .load(std::sync::atomic::Ordering::Relaxed)
                || !rule.matcher.matches(&facts)
            {
                continue;
            }
            if !pre_match {
                rule.state.hit();
            }
            match &rule.action {
                // Pre-match's bypass leaves the connection to the kernel,
                // and routes to no outbound.
                Action::Route(tag, _) | Action::Bypass(Some((tag, _)))
                    if !(pre_match && matches!(rule.action, Action::Bypass(_)))
                        && passes.passes(tag).await =>
                {
                    debug!("rule {} routes to {}, which passes", i, tag);
                    continue;
                }
                Action::Route(tag, options) => {
                    debug!("rule {} routes to {}", i, tag);
                    options.apply(sess);
                    sess.matched_rule_set = rule.matcher.narrow_rule_set(&facts);
                    sess.matched_rule = Some(rule.reported(&facts).0.clone());
                    return Ok(Stop::Route(tag.clone()));
                }
                // Only pre-match bypasses; elsewhere a bypass with an
                // outbound routes, and one without is skipped.
                Action::Bypass(_) if pre_match => {
                    debug!("rule {} bypasses", i);
                    return Ok(Stop::Bypass);
                }
                Action::Bypass(Some((tag, options))) => {
                    debug!("rule {} routes to {}", i, tag);
                    options.apply(sess);
                    sess.matched_rule_set = rule.matcher.narrow_rule_set(&facts);
                    sess.matched_rule = Some(rule.reported(&facts).0.clone());
                    return Ok(Stop::Route(tag.clone()));
                }
                Action::Bypass(None) => {}
                Action::RouteOptions(options) => {
                    debug!("rule {} sets route options", i);
                    if options.overrides_address() {
                        resolved.clear();
                        resolve_taken = false;
                    }
                    options.apply(sess);
                }
                Action::Reject(reject) => {
                    let drop = match walk {
                        Walk::Recheck(_) => reject.drops_by_method(),
                        _ => reject.drops(),
                    };
                    debug!("rule {} rejects{}", i, if drop { ", dropping" } else { "" });
                    sess.matched_rule = Some(rule.reported(&facts).0.clone());
                    return Ok(Stop::Reject { drop });
                }
                Action::HijackDns => {
                    debug!("rule {} hijacks dns", i);
                    sess.matched_rule = Some(rule.reported(&facts).0.clone());
                    return Ok(Stop::HijackDns);
                }
                // As in sing-box 1.14.1, whose router acts on a direct rule
                // nowhere, nor stops at it (route/route.go:690-697).
                Action::Direct => debug!("rule {} is direct, which does nothing", i),
                Action::Sniff(action) => {
                    if !walk.sniff(sess, action).await? {
                        return Ok(Stop::NeedsData);
                    }
                }
                Action::Resolve(how) => {
                    // As sing-box's, only the domain the connection goes
                    // to, not one sniffed: nothing for an address
                    // (route/route.go:898-921).
                    if resolved.is_empty() && !sess.skip_resolve {
                        if let Some(domain) = sess.destination.domain().cloned() {
                            resolved = self
                                .resolve_in(walk.routed(), how, &domain, sess, network.as_ref())
                                .await?;
                            sess.route.resolved = resolved.clone();
                            sess.route.resolved_for_every_outbound = true;
                        }
                    }
                }
                Action::ArmSniff(action) => {
                    // Pre-match reads nothing: the rules that would need
                    // the sniff match without it.
                    if !pre_match {
                        debug!("rule {} arms a sniff", i);
                        armed_sniff = Some(action);
                    }
                }
                Action::ArmResolve(how) => {
                    debug!("rule {} arms a resolve", i);
                    armed_resolve = Some(how);
                }
            }
            facts = facts_of(sess, &resolved);
        }
        Ok(Stop::Final)
    }

    /// The addresses of `domain` for the resolve rule `how`, as
    /// `resolve_as` finds them; for a recheck of the connection `routed`,
    /// those resolved when it was routed, while its destination is the one
    /// it had then, and none otherwise.
    async fn resolve_in(
        &self,
        routed: Option<&Session>,
        how: &Resolve,
        domain: &str,
        sess: &Session,
        network: Option<&std::sync::Arc<crate::net::network::NetworkState>>,
    ) -> Result<Vec<IpAddr>> {
        match routed {
            Some(routed) => Ok(match sess.destination == routed.destination {
                true => routed.route.resolved.clone(),
                false => Vec::new(),
            }),
            None => self.resolve_as(how, domain, sess, network).await,
        }
    }

    /// The addresses of `domain`, as the resolve rule `how` says: none,
    /// with matching going on, for one that does not resolve when it
    /// ignores the failure.
    async fn resolve_as(
        &self,
        how: &Resolve,
        domain: &str,
        sess: &Session,
        network: Option<&std::sync::Arc<crate::net::network::NetworkState>>,
    ) -> Result<Vec<IpAddr>> {
        match self.resolve(domain, sess, how, network).await {
            Ok(ips) => Ok(ips),
            Err(e) if how.ignore_failure => {
                debug!("resolve {}: {}; matching goes on", domain, e);
                Ok(Vec::new())
            }
            Err(e) => Err(anyhow!("resolve {}: {}", domain, e)),
        }
    }

    /// The addresses of `domain`. As in sing-box, a domain that does not
    /// resolve in time fails the connection rather than going on to rules
    /// that would match it without its addresses. The DNS rules match the
    /// network the routing rules matched, when these took it.
    async fn resolve(
        &self,
        domain: &str,
        sess: &Session,
        how: &Resolve,
        network: Option<&std::sync::Arc<crate::net::network::NetworkState>>,
    ) -> Result<Vec<IpAddr>> {
        let dns = self.dns_client.load_full();
        let lookup = async {
            match &how.server {
                Some(server) => {
                    let resolver = model::DomainResolver {
                        server: server.clone(),
                        strategy: how.strategy,
                        disable_cache: how.options.disable_cache,
                        disable_optimistic_cache: how.options.disable_optimistic_cache,
                        rewrite_ttl: how.options.rewrite_ttl,
                        client_subnet: how.options.client_subnet,
                        ..Default::default()
                    };
                    dns.lookup_resolver(&resolver, domain).await
                }
                None => {
                    let ctx = crate::app::dns::LookupContext {
                        inbound: Some(sess.inbound_tag.clone()),
                        user: sess.user.clone(),
                        neighbor: sess.neighbor.clone(),
                        owner: sess.owner.clone(),
                        outbound: None,
                        strategy: how.strategy,
                        options: how.options.clone(),
                        network: network.cloned(),
                    };
                    dns.lookup_in(domain, &ctx).await
                }
            }
        };
        let result = match how.timeout {
            Some(timeout) => tokio::time::timeout(timeout, lookup)
                .await
                .unwrap_or_else(|_| Err(anyhow!("timed out after {:?}", timeout))),
            None => lookup.await,
        };
        let ips = result?;
        debug!("resolved {} to {:?} for routing", domain, ips);
        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns_client::DnsClient;
    use crate::session::SocksAddr;

    /// Where no outbound passes.
    struct NoPass;

    impl Passes for NoPass {
        async fn passes(&self, _tag: &str) -> bool {
            false
        }
    }

    fn router(rules: serde_json::Value) -> Router {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [
                    { "type": "hosts", "predefined": { "test.sail": "127.0.0.1" } },
                    { "type": "hosts", "tag": "lan", "predefined": { "test.sail": "10.0.0.1" } },
                    // A server that never answers, in the documentation range.
                    { "type": "udp", "tag": "slow", "server": "192.0.2.1" }
                ] },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": rules, "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap()
    }

    /// As in sing-box: no Clash API, no mode, and `clash_mode` never
    /// matches; with one, the mode is its default_mode, and whatever it is
    /// switched to.
    #[tokio::test]
    async fn clash_mode_matches_the_api_s_mode() {
        let rules = serde_json::json!([{ "clash_mode": "direct", "outbound": "a" }]);
        let route = |rules: &serde_json::Value, env: &RuntimeEnv| {
            let config = crate::config::Config::from_json(
                &serde_json::json!({
                    "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                    "route": { "rules": rules, "final": "b" },
                })
                .to_string(),
            )
            .unwrap();
            let dns = DnsClient::new(&config.dns, Default::default(), env)
                .unwrap()
                .into_shared();
            Router::new(&config.route, dns, env).unwrap()
        };
        let pick = |router: Router| async move {
            let mut sess = Session {
                destination: SocksAddr::Domain("x.example".into(), 443),
                ..Default::default()
            };
            router
                .pick_route(&mut sess, &mut NoSniffer, &NoPass)
                .await
                .unwrap()
        };
        let env = RuntimeEnv::default();
        assert_eq!(
            pick(route(&rules, &env)).await,
            Decision::Route(Some("b".into()))
        );

        env.clash_mode.configure(
            Some(&crate::config::model::ClashApi {
                default_mode: Some("Direct".into()),
                ..Default::default()
            }),
            false,
            None,
        );
        assert_eq!(
            pick(route(&rules, &env)).await,
            Decision::Route(Some("a".into()))
        );
        // Switched while running: the rules see it.
        let router = route(&rules, &env);
        env.clash_mode.set(Some("Global".into()));
        assert_eq!(pick(router).await, Decision::Route(Some("b".into())));
    }

    /// Plays a connection whose first bytes carry `domain`.
    struct FakeSniffer {
        domain: &'static str,
        calls: usize,
    }

    #[async_trait]
    impl Sniffer for FakeSniffer {
        async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()> {
            self.calls += 1;
            if action
                .protocols
                .contains(crate::session::SniffedProtocol::Tls)
            {
                sess.set_sniffed_domain(crate::session::SniffedFrom::Tls, self.domain.to_string());
                sess.sniffed_protocol = Some(crate::session::SniffedProtocol::Tls);
                if action.override_destination == Some(model::OverrideDestination::AtSniff) {
                    sess.destination =
                        SocksAddr::Domain(self.domain.into(), sess.destination.port());
                }
            }
            Ok(())
        }
    }

    fn to_ip() -> Session {
        Session {
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_sniffed_domain_is_matched_by_the_rules_after_the_sniff() {
        let router = router(serde_json::json!([
            { "domain_suffix": ["example.com"], "outbound": "a" },
            { "action": "sniff", "port": [443] },
            { "domain_suffix": ["example.com"], "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let mut sess = to_ip();
        let decision = router
            .pick_route(&mut sess, &mut sniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(sniffer.calls, 1);
        assert_eq!(sess.sniffed_domain(), Some("www.example.com"));
    }

    /// As sing-box's, a resolve rule resolves the domain the connection
    /// goes to, never one only sniffed: to an address, it resolves nothing
    /// (route/route.go:898-921). Once the sniffed domain is where it goes,
    /// by `override_destination: at_sniff`, it is resolved; the dial-time
    /// override leaves the destination as it is.
    #[tokio::test]
    async fn a_resolve_rule_resolves_the_destination_not_the_sniffed_domain() {
        let route = |override_destination: serde_json::Value| async move {
            let router = router(serde_json::json!([
                { "action": "sniff", "override_destination": override_destination },
                { "action": "resolve", "server": "lan" },
                { "ip_cidr": "10.0.0.1/32", "outbound": "a" },
            ]));
            let mut sniffer = FakeSniffer {
                domain: "test.sail",
                calls: 0,
            };
            let mut sess = to("127.0.0.2:443");
            let decision = router
                .pick_route(&mut sess, &mut sniffer, &NoPass)
                .await
                .unwrap();
            assert_eq!(sess.sniffed_domain(), Some("test.sail"));
            (decision, sess.route.resolved)
        };
        for dial_time in [false.into(), true.into(), "proxy_and_direct".into()] {
            assert_eq!(
                route(dial_time).await,
                (Decision::Route(Some("b".into())), vec![])
            );
        }
        assert_eq!(
            route("at_sniff".into()).await,
            (
                Decision::Route(Some("a".into())),
                vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
            )
        );
    }

    /// `override_destination` on a sniff rule is a route option for the
    /// dial: the rules after still match the address, so a LAN address
    /// sniffed goes where its rule says (B2).
    #[tokio::test]
    async fn a_dial_time_override_leaves_the_rules_the_address() {
        for how in [
            serde_json::json!(true),
            serde_json::json!("proxy_and_direct"),
        ] {
            let router = router(serde_json::json!([
                { "action": "sniff", "override_destination": how },
                { "ip_cidr": "127.0.0.2/32", "outbound": "a" },
            ]));
            let mut sniffer = FakeSniffer {
                domain: "lan.test",
                calls: 0,
            };
            let mut sess = to("127.0.0.2:443");
            let decision = router
                .pick_route(&mut sess, &mut sniffer, &NoPass)
                .await
                .unwrap();
            assert_eq!(decision, Decision::Route(Some("a".into())), "{}", how);
            assert_eq!(sess.destination, to("127.0.0.2:443").destination);
            assert_eq!(sess.sniffed_domain(), Some("lan.test"));
            let expected = match how.as_bool() {
                Some(true) => model::OverrideDestination::Proxy,
                _ => model::OverrideDestination::ProxyAndDirect,
            };
            assert_eq!(sess.route.override_destination, Some(expected));
        }
    }

    /// A route or route-options rule sets it too, a later rule's value
    /// going before; a rule skipped sets nothing.
    #[tokio::test]
    async fn route_rules_set_the_override_a_later_one_going_before() {
        let router = router(serde_json::json!([
            { "port": [443], "action": "route-options", "override_destination": "proxy" },
            { "port": [80], "action": "route-options", "override_destination": "proxy" },
            { "ip_cidr": "2000::/3", "action": "route-options",
              "override_destination": "proxy_and_direct" },
            { "port": [443], "outbound": "a" },
        ]));
        let mut sess = to("[2001:db8::50]:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(
            sess.route.override_destination,
            Some(model::OverrideDestination::ProxyAndDirect)
        );
        let mut sess = to("192.0.2.1:443");
        pick(&router, &mut sess).await;
        assert_eq!(
            sess.route.override_destination,
            Some(model::OverrideDestination::Proxy)
        );
        let mut sess = to("192.0.2.1:8443");
        pick(&router, &mut sess).await;
        assert_eq!(sess.route.override_destination, None);
    }

    /// `at_sniff` is a sniff rule's only.
    #[test]
    fn at_sniff_is_a_sniff_rule_s_only() {
        let err = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "rules": [
                    { "port": [443], "action": "route-options", "override_destination": "at_sniff" }
                ] },
            })
            .to_string(),
        )
        .err()
        .unwrap();
        assert!(
            format!("{:#}", err).contains("override_destination: at_sniff is a sniff rule's only"),
            "{:#}",
            err
        );
        let err = crate::config::Config::from_json(
            &serde_json::json!({
                "route": { "rules": [
                    { "action": "sniff", "override_destination": "proxy_only" }
                ] },
            })
            .to_string(),
        )
        .err()
        .unwrap();
        assert!(format!("{:#}", err).contains("proxy_only"), "{:#}", err);
    }

    /// The IP version is the destination's when matching began, as in
    /// sing-box: a sniff that makes the sniffed domain the destination
    /// leaves it (route/route.go:585-589).
    #[tokio::test]
    async fn the_ip_version_is_the_address_asked_for_s() {
        let router = router(serde_json::json!([
            { "action": "sniff", "override_destination": "at_sniff" },
            { "ip_version": 4, "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "v4.test",
            calls: 0,
        };
        let mut sess = to("127.0.0.2:443");
        let decision = router
            .pick_route(&mut sess, &mut sniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(sess.destination, to("v4.test:443").destination);
        assert_eq!(decision, Decision::Route(Some("a".into())));
    }

    /// As the Clash front-end lowers Mihomo's sniffer: only a connection to
    /// an address, not to a name, and none from an address skipped.
    #[tokio::test]
    async fn a_sniff_rule_on_any_address_leaves_a_name_alone() {
        let router = router(serde_json::json!([
            {
                "type": "logical", "mode": "and",
                "rules": [
                    { "ip_cidr": ["0.0.0.0/0", "::/0"] },
                    { "source_ip_cidr": ["192.168.0.0/16"], "invert": true },
                    { "network": ["tcp"], "port": [443] }
                ],
                "action": "sniff", "sniffer": ["tls"]
            },
            { "domain_suffix": ["example.com"], "outbound": "a" },
        ]));
        let sniffed = |sess: Session| {
            let router = &router;
            async move {
                let mut sess = sess;
                let mut sniffer = FakeSniffer {
                    domain: "www.example.com",
                    calls: 0,
                };
                router
                    .pick_route(&mut sess, &mut sniffer, &NoPass)
                    .await
                    .unwrap();
                sniffer.calls
            }
        };
        assert_eq!(sniffed(to_ip()).await, 1);
        let to_name = Session {
            destination: SocksAddr::Domain("example.org".into(), 443),
            ..Default::default()
        };
        assert_eq!(sniffed(to_name).await, 0);
        let from_lan = Session {
            source: "192.168.1.2:5000".parse().unwrap(),
            ..to_ip()
        };
        assert_eq!(sniffed(from_lan).await, 0);
    }

    #[tokio::test]
    async fn without_a_sniff_rule_nothing_is_sniffed() {
        let router = router(serde_json::json!([
            { "domain_suffix": ["example.com"], "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let decision = router
            .pick_route(&mut to_ip(), &mut sniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("b".into())));
        assert_eq!(sniffer.calls, 0);
    }

    #[tokio::test]
    async fn reject_ends_the_matching() {
        let router = router(serde_json::json!([
            { "ip_cidr": ["1.2.3.0/24"], "action": "reject" },
            { "ip_cidr": ["1.2.3.0/24"], "outbound": "a" },
        ]));
        let decision = router
            .pick_route(&mut to_ip(), &mut NoSniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Reject { drop: false });
    }

    #[tokio::test]
    async fn a_resolved_domain_is_matched_by_address() {
        let router = router(serde_json::json!([
            { "action": "resolve" },
            { "ip_cidr": ["127.0.0.0/8"], "outbound": "a" },
        ]));
        let mut sess = Session {
            destination: SocksAddr::Domain("test.sail".into(), 80),
            ..Default::default()
        };
        let decision = router
            .pick_route(&mut sess, &mut NoSniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));

        // Not for the lookups the DNS client makes for itself.
        sess.skip_resolve = true;
        let decision = router
            .pick_route(&mut sess, &mut NoSniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("b".into())));
    }

    #[tokio::test]
    async fn a_resolve_rule_asks_the_server_it_names() {
        let router = router(serde_json::json!([
            { "action": "resolve", "server": "lan", "strategy": "ipv4_only" },
            { "ip_cidr": ["10.0.0.0/8"], "outbound": "a" },
        ]));
        let mut sess = Session {
            destination: SocksAddr::Domain("test.sail".into(), 80),
            ..Default::default()
        };
        let decision = router
            .pick_route(&mut sess, &mut NoSniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
    }

    /// A UDP DNS server answering every A query with 10.0.0.1, TTL 300,
    /// that keeps the client subnet each query carried.
    async fn recording_server() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>) {
        use crate::util::DnsMessageExt;
        use hickory_proto::op::{Message, MessageType};
        use hickory_proto::rr::rdata::opt::EdnsOption;
        use hickory_proto::rr::{rdata::A, RData, Record};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let queries = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let q = Message::from_vec(&buf[..n]).unwrap();
                let subnet = q.extensions().as_ref().and_then(|e| {
                    e.options().as_ref().iter().find_map(|(_, o)| match o {
                        EdnsOption::Subnet(s) => Some(format!("{:?}", s)),
                        _ => None,
                    })
                });
                queries.lock().unwrap().push(subnet);
                let mut r = Message::new(q.id(), MessageType::Response, q.op_code());
                for query in q.queries() {
                    r.add_query(query.clone());
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        300,
                        RData::A(A::new(10, 0, 0, 1)),
                    ));
                }
                let _ = socket.send_to(&r.to_vec().unwrap(), peer).await;
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn a_resolve_rule_sends_its_queries_as_it_says() {
        let (port, seen) = recording_server().await;
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [
                    { "type": "udp", "tag": "up", "server": "127.0.0.1", "server_port": port }
                ] },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": [
                    { "domain": "fresh.sail", "action": "resolve", "strategy": "ipv4_only",
                      "disable_cache": true, "client_subnet": "1.2.3.0/24" },
                    { "domain": "named.sail", "action": "resolve", "server": "up",
                      "strategy": "ipv4_only", "disable_cache": true },
                    { "domain": "kept.sail", "action": "resolve", "strategy": "ipv4_only" },
                    { "ip_cidr": ["10.0.0.0/8"], "outbound": "a" },
                ], "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let router = Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap();
        let route = |domain: &str| {
            let mut sess = Session {
                destination: SocksAddr::Domain(domain.into(), 80),
                ..Default::default()
            };
            let router = &router;
            async move {
                router
                    .pick_route(&mut sess, &mut NoSniffer, &NoPass)
                    .await
                    .unwrap()
            }
        };
        for domain in ["fresh.sail", "fresh.sail", "named.sail", "named.sail"] {
            assert_eq!(route(domain).await, Decision::Route(Some("a".into())));
        }
        // The cache kept: asked once.
        for _ in 0..2 {
            assert_eq!(route("kept.sail").await, Decision::Route(Some("a".into())));
        }
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 5, "{:?}", seen);
        // fresh.sail's carried its client subnet; the others none.
        assert!(
            seen[0].as_deref().is_some_and(|s| s.contains("1.2.3.0")),
            "{:?}",
            seen
        );
        assert!(seen[1].is_some());
        assert!(seen[2..].iter().all(Option::is_none), "{:?}", seen);
    }

    /// An armed resolve sends its queries as the rule that armed it says,
    /// and asks once however many rules on addresses follow.
    #[tokio::test]
    async fn an_on_demand_resolve_sends_its_queries_as_it_says() {
        let (port, seen) = recording_server().await;
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [
                    { "type": "udp", "tag": "up", "server": "127.0.0.1", "server_port": port }
                ] },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": [
                    { "action": "resolve", "on_demand": true, "strategy": "ipv4_only",
                      "disable_cache": true, "client_subnet": "1.2.3.0/24" },
                    { "domain": "early.sail", "outbound": "b" },
                    { "ip_cidr": ["192.0.2.0/24"], "outbound": "b" },
                    { "ip_cidr": ["10.0.0.0/8"], "outbound": "a" },
                ], "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let router = Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap();
        assert_eq!(
            pick(&router, &mut to("early.sail:80")).await,
            Decision::Route(Some("b".into()))
        );
        assert!(seen.lock().unwrap().is_empty());
        for _ in 0..2 {
            assert_eq!(
                pick(&router, &mut to("late.sail:80")).await,
                Decision::Route(Some("a".into()))
            );
        }
        // Uncached, asked each time, once, with the client subnet.
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "{:?}", seen);
        assert!(
            seen.iter()
                .all(|s| s.as_deref().is_some_and(|s| s.contains("1.2.3.0"))),
            "{:?}",
            seen
        );
    }

    fn to(destination: &str) -> Session {
        Session {
            destination: match destination.parse::<std::net::SocketAddr>() {
                Ok(addr) => SocksAddr::Ip(addr),
                Err(_) => {
                    let (host, port) = destination.rsplit_once(':').unwrap();
                    SocksAddr::Domain(host.into(), port.parse().unwrap())
                }
            },
            ..Default::default()
        }
    }

    async fn pick(router: &Router, sess: &mut Session) -> Decision {
        router
            .pick_route(sess, &mut NoSniffer, &NoPass)
            .await
            .unwrap()
    }

    /// Who opened a connection is looked up only when a rule needs it, a
    /// rule-set's rule too, or `find_process` asks for it always.
    #[test]
    fn the_owner_is_wanted_only_when_something_needs_it() {
        assert!(!router(serde_json::json!([{ "port": [443], "outbound": "a" }])).wants_owner());
        assert!(router(serde_json::json!([
            { "process_name": ["curl"], "outbound": "a" }
        ]))
        .wants_owner());
        assert!(router(serde_json::json!([
            { "type": "logical", "mode": "or",
              "rules": [{ "port": [1] }, { "process_path": ["/usr/bin/curl"] }], "outbound": "a" }
        ]))
        .needs_owner());
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "find_process": true, "rules": [] },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let router = Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap();
        assert!(!router.needs_owner());
        assert!(router.wants_owner());
    }

    /// A rule turned off is passed over as if it matched nothing, until
    /// it is turned on again; each match is counted, with its time.
    #[cfg(feature = "clash-api")]
    #[tokio::test]
    async fn a_rule_turned_off_is_passed_over() {
        let router = router(serde_json::json!([
            { "port": [443], "outbound": "a" },
            { "port": [443], "outbound": "b" },
        ]));
        let to_443 = || Session {
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        };
        assert!(router.set_disabled(0, true));
        assert!(!router.set_disabled(9, true));
        assert_eq!(
            pick(&router, &mut to_443()).await,
            Decision::Route(Some("b".into()))
        );
        assert!(router.set_disabled(0, false));
        assert_eq!(
            pick(&router, &mut to_443()).await,
            Decision::Route(Some("a".into()))
        );
        let stats: Vec<(bool, u64, bool)> = router
            .rules_with_stats()
            .map(|(_, _, s)| (s.disabled, s.hits, s.hit_at > 0))
            .collect();
        assert_eq!(stats, [(false, 1, true), (false, 1, true)]);
    }

    /// What every rule keeps, whatever it has: a profile of thousands of
    /// one-condition rules keeps this much a rule, before its condition.
    /// It was 344 bytes, with the route options of the few rules that set
    /// any, and the reject, sniff and resolve actions' own, in each.
    #[test]
    fn a_rule_is_no_larger_than_the_common_one_needs() {
        use std::mem::size_of;
        println!(
            "SIZE Rule {} Action {} About {} Matcher {} Options {}",
            size_of::<Rule>(),
            size_of::<Action>(),
            size_of::<describe::About>(),
            size_of::<Matcher>(),
            size_of::<Options>()
        );
        assert!(size_of::<Action>() <= 40, "{}", size_of::<Action>());
        assert!(size_of::<Rule>() <= 200, "{}", size_of::<Rule>());
    }

    /// A rule that sets no route option keeps none, and one that does has
    /// them applied as before.
    #[test]
    fn route_options_are_kept_only_when_set() {
        let rule =
            |json: serde_json::Value| -> model::Rule { serde_json::from_value(json).unwrap() };
        let none = Options::new(&rule(serde_json::json!({ "outbound": "a" })), "r").unwrap();
        assert!(none.0.is_none() && !none.overrides_address());
        let some = Options::new(
            &rule(serde_json::json!({ "outbound": "a", "override_port": 53, "udp_connect": true })),
            "r",
        )
        .unwrap();
        assert!(some.0.is_some() && !some.overrides_address());
        let mut sess = Session {
            destination: SocksAddr::Domain("a.example".into(), 443),
            ..Default::default()
        };
        none.apply(&mut sess);
        assert_eq!(sess.destination.port(), 443);
        some.apply(&mut sess);
        assert_eq!(sess.destination.port(), 53);
        assert!(sess.route.udp_connect);
        let address = Options::new(
            &rule(serde_json::json!({ "outbound": "a", "override_address": "b.example" })),
            "r",
        )
        .unwrap();
        assert!(address.overrides_address());
    }

    /// The Clash API lists a rule's proxy as Mihomo does: the outbound it
    /// routes to, which the rule itself has, or what it does.
    #[cfg(feature = "clash-api")]
    #[tokio::test]
    async fn a_rule_s_proxy_is_listed_from_what_it_does() {
        let router = router(serde_json::json!([
            { "port": [80], "outbound": "a" },
            { "port": [81], "action": "reject" },
            { "port": [82], "action": "reject", "method": "drop" },
            { "action": "sniff" },
        ]));
        let proxies: Vec<&str> = router
            .rules_with_stats()
            .map(|(_, proxy, _)| proxy)
            .collect();
        assert_eq!(proxies, ["a", "REJECT", "REJECT-DROP", "sniff"]);
    }

    /// A rule's index is its place in `route.rules` as written: a logical
    /// rule before it counts once, and of two rules written alike each has
    /// its own.
    #[tokio::test]
    async fn a_rule_is_numbered_as_the_configuration_lists_it() {
        let router = router(serde_json::json!([
            { "port": [80], "outbound": "a" },
            { "type": "logical", "mode": "or",
              "rules": [{ "port": [1] }, { "port": [2] }, { "port": [3] }], "outbound": "a" },
            { "port": [80], "outbound": "a" },
            { "port": [443], "outbound": "a" },
        ]));
        assert_eq!(router.rules.len(), 4);
        assert_eq!(router.rules[0].about.matched, router.rules[2].about.matched);
        for (i, rule) in router.rules.iter().enumerate() {
            assert_eq!(
                router.rule_index(&rule.about.matched),
                u32::try_from(i).ok()
            );
        }
        let mut sess = Session {
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        };
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        let matched = sess.matched_rule.clone().unwrap();
        assert_eq!(router.rule_index(&matched), Some(3));
        // Another router's rule, though written alike, is not this one's.
        let other: std::sync::Arc<str> = matched.to_string().into();
        assert_eq!(router.rule_index(&other), None);
    }

    /// The narrow rule-set a route rule matched by goes with the
    /// connection, for the smart group's sites.
    #[cfg(feature = "rule-set")]
    #[tokio::test]
    async fn a_route_rule_tells_the_narrow_rule_set_it_matched_by() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": {
                    "rule_set": [
                        { "tag": "video", "type": "inline",
                          "rules": [{ "domain_suffix": ["video.test"] }] },
                        { "tag": "nets", "type": "inline",
                          "rules": [{ "ip_cidr": ["10.0.0.0/8"] }] },
                    ],
                    "rules": [
                        { "rule_set": ["nets", "video"], "outbound": "a" },
                        { "domain": ["plain.test"], "outbound": "a" },
                    ],
                    "final": "b",
                },
            })
            .to_string(),
        )
        .unwrap();
        let env = RuntimeEnv::default();
        let sets =
            rule_set::RuleSets::load(&config.route.rule_set, &Default::default(), &env, None)
                .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &env)
            .unwrap()
            .into_shared();
        let router = Router::with_rule_sets(
            &config.route,
            config.route.rules.clone(),
            dns,
            &env,
            &sets,
            &Default::default(),
        )
        .unwrap();
        let mut sess = to("www.video.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.matched_rule_set.as_deref(), Some("video"));
        let mut sess = to("10.1.1.1:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.matched_rule_set, None);
        let mut sess = to("plain.test:443");
        pick(&router, &mut sess).await;
        assert_eq!(sess.matched_rule_set, None);
    }

    #[tokio::test]
    async fn route_options_set_and_the_next_rules_decide() {
        let router = router(serde_json::json!([
            { "domain": "old.test", "action": "route-options",
              "override_address": "10.9.9.9", "override_port": 8443,
              "udp_timeout": "10s", "udp_connect": true },
            // The rules after match the destination put in place.
            { "ip_cidr": "10.9.9.9", "port": 8443, "outbound": "a",
              "tls_record_fragment": true, "udp_disable_domain_unmapping": true },
        ]));
        let mut sess = to("old.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.destination, to("10.9.9.9:8443").destination);
        let route = &sess.route;
        assert_eq!(
            route.original_destination,
            Some(to("old.test:443").destination)
        );
        assert_eq!(route.udp_timeout, Some(Duration::from_secs(10)));
        assert!(route.udp_connect && route.udp_disable_domain_unmapping);
        assert_eq!(
            route.tls_fragment,
            Some(TlsFragment {
                records: true,
                segments: None
            })
        );

        // A port alone keeps the address; the first destination is kept.
        let router = self::router(serde_json::json!([
            { "port": 53, "action": "route-options", "override_port": 5353 },
            { "port": 5353, "action": "route-options", "override_address": "dns.test",
              "tls_fragment": true },
        ]));
        let mut sess = to("1.1.1.1:53");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("b".into()))
        );
        assert_eq!(sess.destination, to("dns.test:5353").destination);
        assert_eq!(
            sess.route.original_destination,
            Some(to("1.1.1.1:53").destination)
        );
        assert_eq!(
            sess.route.tls_fragment,
            Some(TlsFragment {
                records: false,
                segments: Some(TLS_FRAGMENT_DELAY)
            })
        );
    }

    #[tokio::test]
    async fn a_route_rule_sets_its_options_as_it_routes() {
        let router = router(serde_json::json!([
            { "port": 443, "outbound": "a", "override_address": "::1",
              "tls_fragment": true, "tls_fragment_fallback_delay": "10ms" },
        ]));
        let mut sess = to("x.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.destination, to("[::1]:443").destination);
        assert_eq!(
            sess.route.tls_fragment,
            Some(TlsFragment {
                records: false,
                segments: Some(Duration::from_millis(10))
            })
        );
    }

    /// As in sing-box, both cuts combine: each record a segment of its own.
    #[tokio::test]
    async fn tls_fragment_and_tls_record_fragment_combine() {
        let router = router(serde_json::json!([
            { "port": 443, "outbound": "a", "tls_fragment": true,
              "tls_record_fragment": true },
        ]));
        let mut sess = to("x.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(
            sess.route.tls_fragment,
            Some(TlsFragment {
                records: true,
                segments: Some(TLS_FRAGMENT_DELAY)
            })
        );
    }

    /// Without auto_redirect's pre-match, bypass is sing-box's: with an
    /// outbound it routes there, options and all; without one the rule is
    /// skipped.
    #[tokio::test]
    async fn bypass_routes_to_its_outbound_or_is_skipped() {
        let router = router(serde_json::json!([
            { "port": 22, "action": "bypass" },
            { "port": 443, "action": "bypass", "outbound": "a", "override_address": "::1" },
            { "port": 22, "outbound": "a" },
        ]));
        let mut sess = to("x.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.destination, to("[::1]:443").destination);
        assert_eq!(
            pick(&router, &mut to("x.test:22")).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(
            pick(&router, &mut to("x.test:80")).await,
            Decision::Route(Some("b".into()))
        );
    }

    /// sing-box's pre-match with bypass supported: any bypass lets the
    /// kernel carry the connection, reject refuses it, and the first rule
    /// that routes or needs the connection's data leaves it to be set up.
    #[tokio::test]
    async fn pre_match_bypasses_rejects_or_proceeds() {
        let router = router(serde_json::json!([
            { "port": 22, "action": "bypass" },
            { "port": 23, "action": "bypass", "outbound": "a" },
            { "port": 25, "action": "reject" },
            { "port": 26, "action": "reject", "method": "drop" },
            { "port": 443, "action": "sniff" },
            { "port": 443, "action": "bypass" },
            { "port": 80, "outbound": "a" },
            { "port": 80, "action": "bypass" },
        ]));
        for (destination, expected) in [
            ("1.2.3.4:22", PreMatch::Bypass),
            ("1.2.3.4:23", PreMatch::Bypass),
            ("1.2.3.4:25", PreMatch::Reject { drop: false }),
            ("1.2.3.4:26", PreMatch::Reject { drop: true }),
            ("1.2.3.4:443", PreMatch::Proceed),
            ("1.2.3.4:80", PreMatch::Proceed),
            ("1.2.3.4:8080", PreMatch::Proceed),
        ] {
            assert_eq!(
                router.pre_match(&mut to(destination), &NoPass).await,
                expected,
                "{destination}"
            );
        }
    }

    /// The first packet tells no sniffed domain and no user, so rules that
    /// need them do not match in pre-match, as in sing-box: they cannot
    /// bypass what they would not have matched.
    #[tokio::test]
    async fn pre_match_sees_only_what_the_first_packet_tells() {
        let router = router(serde_json::json!([
            { "domain_suffix": ["example.com"], "action": "bypass" },
            { "auth_user": ["alice"], "action": "bypass" },
            { "protocol": ["tls"], "action": "bypass" },
            { "port": 443, "action": "route-options", "override_port": 22 },
            { "port": 22, "action": "bypass" },
        ]));
        assert_eq!(
            router.pre_match(&mut to("1.2.3.4:8443"), &NoPass).await,
            PreMatch::Proceed
        );
        // Route options apply on the way, and the rules after them see it.
        assert_eq!(
            router.pre_match(&mut to("1.2.3.4:443"), &NoPass).await,
            PreMatch::Bypass
        );
    }

    #[tokio::test]
    async fn hijack_dns_ends_the_matching() {
        let router = router(serde_json::json!([
            { "port": 53, "action": "hijack-dns" },
            { "port": 53, "outbound": "a" },
        ]));
        assert_eq!(
            pick(&router, &mut to("8.8.8.8:53")).await,
            Decision::HijackDns
        );
        assert_eq!(
            pick(&router, &mut to("8.8.8.8:853")).await,
            Decision::Route(Some("b".into()))
        );
    }

    #[tokio::test]
    async fn reject_drops_as_its_method_says_and_past_a_flood() {
        let router = router(serde_json::json!([
            { "port": 1, "action": "reject", "method": "drop" },
            { "port": 2, "action": "reject" },
            { "port": 3, "action": "reject", "no_drop": true },
        ]));
        assert_eq!(
            pick(&router, &mut to("1.1.1.1:1")).await,
            Decision::Reject { drop: true }
        );
        for i in 0..60 {
            let expected = Decision::Reject {
                drop: i >= Reject::FLOOD,
            };
            assert_eq!(pick(&router, &mut to("1.1.1.1:2")).await, expected, "{}", i);
            assert_eq!(
                pick(&router, &mut to("1.1.1.1:3")).await,
                Decision::Reject { drop: false }
            );
        }
    }

    /// A recheck decides as routing did, reading nothing of the
    /// connection: a rule before the sniff sees nothing sniffed, those
    /// after it what was sniffed when it was routed; an override walks on
    /// from the destination asked for. The rule is numbered as the routed
    /// event numbers it.
    #[tokio::test]
    async fn a_recheck_decides_as_routing_did_without_reading() {
        let router = router(serde_json::json!([
            { "domain_suffix": ["example.com"], "action": "reject" },
            { "action": "sniff" },
            { "port": [443], "action": "route-options", "override_port": 8443 },
            { "domain_suffix": ["example.com"], "port": [8443], "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let mut routed = to_ip();
        let decision = router
            .pick_route(&mut routed, &mut sniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(routed.destination.port(), 8443);
        assert_eq!(
            router.recheck(&routed, &NoPass).await,
            Recheck {
                decision: Decision::Route(Some("a".into())),
                rule: Some(3),
            }
        );
        assert_eq!(sniffer.calls, 1, "a recheck read the connection");

        // Walked from the port asked for, a rule on it rejects.
        let stricter = self::router(serde_json::json!([
            { "port": [8443], "outbound": "a" },
            { "port": [443], "action": "reject" },
        ]));
        assert_eq!(
            stricter.recheck(&routed, &NoPass).await,
            Recheck {
                decision: Decision::Reject { drop: false },
                rule: Some(1),
            }
        );
    }

    /// A recheck asks no DNS, a resolve rule giving the addresses resolved
    /// when the connection was routed, and its rejections count toward no
    /// rule's flood.
    #[tokio::test]
    async fn a_recheck_asks_no_dns_and_counts_toward_no_flood() {
        let (port, seen) = recording_server().await;
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [
                    { "type": "udp", "tag": "up", "server": "127.0.0.1", "server_port": port }
                ] },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": [
                    { "domain": "named.sail", "action": "resolve", "server": "up",
                      "strategy": "ipv4_only", "disable_cache": true },
                    { "ip_cidr": ["10.0.0.0/8"], "outbound": "a" },
                    { "port": [2], "action": "reject" },
                ], "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let router = Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap();
        let mut routed = to("named.sail:80");
        assert_eq!(
            pick(&router, &mut routed).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        for _ in 0..3 {
            assert_eq!(
                router.recheck(&routed, &NoPass).await.decision,
                Decision::Route(Some("a".into()))
            );
        }
        assert_eq!(seen.lock().unwrap().len(), 1, "a recheck asked the DNS");

        let rejected = to("1.1.1.1:2");
        for i in 0..2 * Reject::FLOOD {
            assert_eq!(
                router.recheck(&rejected, &NoPass).await.decision,
                Decision::Reject { drop: false },
                "{}",
                i
            );
        }
        assert_eq!(
            pick(&router, &mut to("1.1.1.1:2")).await,
            Decision::Reject { drop: false },
            "the rechecks counted toward the flood"
        );
    }

    #[tokio::test]
    async fn logical_and_inverted_rules_route() {
        let router = router(serde_json::json!([
            { "type": "logical", "mode": "and", "outbound": "a", "rules": [
                { "domain_suffix": "example.com" },
                { "port": 80, "invert": true }
            ] },
            { "ip_is_private": true, "invert": true, "action": "reject" },
        ]));
        assert_eq!(
            pick(&router, &mut to("www.example.com:443")).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(
            pick(&router, &mut to("www.example.com:80")).await,
            Decision::Reject { drop: false }
        );
        assert_eq!(
            pick(&router, &mut to("192.168.1.1:80")).await,
            Decision::Route(Some("b".into()))
        );
    }

    #[tokio::test]
    async fn a_resolve_rule_fails_the_connection_at_its_timeout() {
        let router = router(serde_json::json!([
            { "action": "resolve", "timeout": "1ms", "server": "slow" },
            { "ip_cidr": ["192.0.2.0/24"], "outbound": "a" },
        ]));
        let mut sess = to("test.sail:80");
        let start = std::time::Instant::now();
        let err = router
            .pick_route(&mut sess, &mut NoSniffer, &NoPass)
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("resolve test.sail:"), "{}", err);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn with_ignore_failure_matching_goes_on_past_a_timeout() {
        let router = router(serde_json::json!([
            { "action": "resolve", "timeout": "1ms", "server": "slow", "ignore_failure": true },
            { "ip_cidr": ["192.0.2.0/24"], "outbound": "a" },
            { "domain_suffix": "sail", "outbound": "b" },
        ]));
        let start = std::time::Instant::now();
        assert_eq!(
            pick(&router, &mut to("test.sail:80")).await,
            Decision::Route(Some("b".into()))
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn mistakes_name_their_path() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "rules": [
                    { "port": 1, "outbound": "a" },
                    { "type": "logical", "mode": "or", "outbound": "a", "rules": [
                        { "port": 2 }, { "port_range": "9:1" }
                    ] },
                ] },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let err = Router::new(&config.route, dns, &RuntimeEnv::default())
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.starts_with("route.rules[1].rules[1].port_range: invalid port range"),
            "{}",
            err
        );
        for bad in ["", "a b"] {
            let rule: model::Rule = serde_json::from_value(
                serde_json::json!({ "action": "route-options", "override_address": bad }),
            )
            .unwrap();
            assert!(Options::new(&rule, "route.rules[0]").is_err(), "{:?}", bad);
        }
    }

    /// `network_strategy` and `fallback_delay` are set as other route
    /// options are, a later rule's going before (route/route.go:637-648);
    /// `fallback_delay` a duration or, as sing-box reads it, nanoseconds.
    #[tokio::test]
    async fn a_later_rule_s_network_goes_before() {
        use crate::net::dial::NetworkStrategy;
        let router = router(serde_json::json!([
            { "port": 443, "action": "route-options",
              "network_strategy": "hybrid", "fallback_delay": "1s" },
            { "port": 443, "action": "route-options", "network_strategy": "fallback" },
            // Zero is unset.
            { "port": 443, "action": "route-options", "fallback_delay": 0 },
            { "domain": "a.test", "outbound": "a", "fallback_delay": 40000000 },
            { "domain": "b.test", "outbound": "a" },
        ]));
        let mut sess = to("a.test:443");
        pick(&router, &mut sess).await;
        assert_eq!(sess.route.network_strategy, Some(NetworkStrategy::Fallback));
        assert_eq!(sess.route.fallback_delay, Some(Duration::from_millis(40)));
        let mut sess = to("b.test:443");
        pick(&router, &mut sess).await;
        assert_eq!(sess.route.network_strategy, Some(NetworkStrategy::Fallback));
        assert_eq!(sess.route.fallback_delay, Some(Duration::from_secs(1)));
        // Rules that do not match set nothing.
        let mut sess = to("b.test:80");
        pick(&router, &mut sess).await;
        assert_eq!(sess.route.network_strategy, None);
        assert_eq!(sess.route.fallback_delay, None);
    }

    /// A `direct` rule does nothing and matching goes on past it, as in
    /// sing-box 1.14.1, whose router acts on it nowhere
    /// (route/route.go:690-697).
    #[tokio::test]
    async fn a_direct_rule_does_not_stop_the_matching() {
        let router = router(serde_json::json!([
            { "domain": "x.test", "action": "direct", "connect_timeout": "2s" },
            { "domain": "x.test", "outbound": "a" },
        ]));
        let mut sess = to("x.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(&*sess.matched_rule.unwrap(), "domain=x.test => route(a)");
        let mut sess = to("y.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("b".into()))
        );
    }

    /// The rules' `network_strategy` applies to a domain once a `resolve`
    /// rule resolved it, and not to one the direct outbound resolves
    /// itself, as sing-box hands it over only with the addresses known
    /// (route/conn.go:101-105).
    #[tokio::test]
    async fn the_rules_network_waits_for_a_resolved_domain() {
        use crate::adapter::OutboundConnect;
        use crate::net::dial::NetworkStrategy;
        let router = router(serde_json::json!([
            { "action": "route-options", "network_strategy": "hybrid" },
            { "domain": "test.sail", "action": "resolve" },
            { "port": 443, "outbound": "a" },
        ]));
        let direct = crate::adapter::outbound::HandlerBuilder::default()
            .is_direct(true)
            .build();
        let strategy = |sess: &Session| {
            let connect = OutboundConnect::Direct(crate::net::Dialer::system());
            match crate::net::routed(sess, &direct, connect, false) {
                OutboundConnect::Direct(dialer) => {
                    dialer.spec().networks.as_ref().map(|n| n.strategy)
                }
                _ => unreachable!(),
            }
        };
        let mut unresolved = to("other.test:443");
        pick(&router, &mut unresolved).await;
        assert_eq!(
            unresolved.route.network_strategy,
            Some(NetworkStrategy::Hybrid)
        );
        assert!(unresolved.route.resolved.is_empty());
        assert_eq!(strategy(&unresolved), None);
        let mut resolved = to("test.sail:443");
        pick(&router, &mut resolved).await;
        assert!(!resolved.route.resolved.is_empty());
        assert_eq!(strategy(&resolved), Some(NetworkStrategy::Hybrid));

        // An override after puts another destination in place, its
        // addresses unknown.
        let router = self::router(serde_json::json!([
            { "domain": "test.sail", "action": "resolve" },
            { "port": 443, "action": "route-options", "override_address": "other.test" },
            { "port": 443, "outbound": "a" },
        ]));
        let mut sess = to("test.sail:443");
        pick(&router, &mut sess).await;
        assert!(sess.route.resolved.is_empty());
    }

    /// A `direct` rule's dial fields are checked when the router is built,
    /// each mistake named by where it is.
    #[test]
    fn a_direct_rule_s_mistakes_name_their_place() {
        let build = |rule: serde_json::Value| {
            let config = crate::config::Config::from_json(
                &serde_json::json!({
                    "outbounds": [{ "type": "direct", "tag": "a" }],
                    "route": { "rules": [{ "port": 1, "outbound": "a" }, rule] },
                })
                .to_string(),
            )?;
            let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
                .unwrap()
                .into_shared();
            Router::new(&config.route, dns, &RuntimeEnv::default()).map(|_| ())
        };
        let err = |rule| build(rule).unwrap_err().to_string();
        if cfg!(feature = "outbound-direct") {
            assert_eq!(
                err(serde_json::json!({ "port": 2, "action": "direct",
                    "network_strategy": "hybrid", "inet4_bind_address": "127.0.0.1" })),
                "route.rules[1].network_strategy: not with inet4_bind_address, \
                 which binds the socket itself"
            );
            if crate::net::dial::interface_exists("no-such-if0") == Some(false) {
                assert_eq!(
                    err(serde_json::json!({ "port": 2, "action": "direct",
                        "bind_interface": "no-such-if0" })),
                    "route.rules[1].bind_interface: there is no interface \"no-such-if0\""
                );
            }
            let marked = build(serde_json::json!({ "port": 2, "action": "direct",
                "routing_mark": 1 }));
            match marked {
                Ok(()) => assert!(crate::net::dial::supports_routing_mark()),
                Err(e) => assert_eq!(
                    e.to_string(),
                    "route.rules[1].routing_mark: only supported on Linux"
                ),
            }
        }
        // A dial field on another action.
        assert_eq!(
            err(serde_json::json!({ "port": 2, "outbound": "a", "bind_interface": "lo" })),
            "route.rules[1].bind_interface: not for a route rule"
        );
    }

    #[tokio::test]
    async fn the_sniffed_protocol_is_a_condition_of_the_rules_after() {
        let router = router(serde_json::json!([
            { "protocol": "tls", "outbound": "a" },
            { "action": "sniff" },
            // Not quic: builds without btls take quic as a config error.
            { "protocol": ["http", "tls"], "port": 443, "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let mut sess = to_ip();
        let decision = router
            .pick_route(&mut sess, &mut sniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(sniffer.calls, 1);
        // Unsniffed, no protocol matches.
        let router = self::router(serde_json::json!([{ "protocol": "tls", "outbound": "a" }]));
        assert_eq!(
            pick(&router, &mut to_ip()).await,
            Decision::Route(Some("b".into()))
        );
    }

    /// A router of `rules`, with the rule-sets `sets` and the DNS servers
    /// of `router`.
    #[cfg(feature = "rule-set")]
    fn router_with_sets(
        sets: serde_json::Value,
        rules: serde_json::Value,
    ) -> (Router, rule_set::RuleSets) {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [
                    { "type": "hosts", "predefined": { "test.sail": "127.0.0.1" } },
                    { "type": "udp", "tag": "slow", "server": "192.0.2.1" }
                ] },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rule_set": sets, "rules": rules, "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let env = RuntimeEnv::default();
        let sets =
            rule_set::RuleSets::load(&config.route.rule_set, &Default::default(), &env, None)
                .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &env)
            .unwrap()
            .into_shared();
        let router = Router::with_rule_sets(
            &config.route,
            config.route.rules.clone(),
            dns,
            &env,
            &sets,
            &Default::default(),
        )
        .unwrap();
        (router, sets)
    }

    /// An on_demand resolve that would fail the connection were it taken:
    /// its server never answers.
    fn failing_resolve() -> serde_json::Value {
        serde_json::json!({
            "action": "resolve", "on_demand": true, "server": "slow", "timeout": "1ms"
        })
    }

    /// Whether routing `destination` resolved it, by `failing_resolve`
    /// failing it; else where it went.
    async fn resolved(router: &Router, destination: &str) -> std::result::Result<Decision, ()> {
        match router
            .pick_route(&mut to(destination), &mut NoSniffer, &NoPass)
            .await
        {
            Ok(decision) => Ok(decision),
            Err(e) => {
                assert!(e.to_string().starts_with("resolve "), "{}", e);
                Err(())
            }
        }
    }

    #[tokio::test]
    async fn an_on_demand_resolve_waits_for_a_rule_on_addresses() {
        let router = router(serde_json::json!([
            failing_resolve(),
            { "domain_suffix": "early.test", "outbound": "a" },
            { "port": 81, "outbound": "a" },
            { "ip_cidr": "10.0.0.0/8", "outbound": "a" },
        ]));
        // Matched before any rule on addresses: never resolved.
        assert_eq!(
            resolved(&router, "www.early.test:80").await,
            Ok(Decision::Route(Some("a".into())))
        );
        assert_eq!(
            resolved(&router, "x.test:81").await,
            Ok(Decision::Route(Some("a".into())))
        );
        // Resolved right before the rule on addresses.
        assert_eq!(resolved(&router, "x.test:80").await, Err(()));
        // An address is not resolved.
        assert_eq!(
            resolved(&router, "10.1.1.1:80").await,
            Ok(Decision::Route(Some("a".into())))
        );

        // Armed with a server that answers, the rule matches the address.
        let router = self::router(serde_json::json!([
            { "action": "resolve", "on_demand": true },
            { "domain": "other.test", "outbound": "b" },
            { "ip_cidr": "127.0.0.0/8", "outbound": "a" },
        ]));
        assert_eq!(
            pick(&router, &mut to("test.sail:80")).await,
            Decision::Route(Some("a".into()))
        );
    }

    /// The arm takes its own options: `ignore_failure` goes on without
    /// addresses. Taken once, an armed resolve is not again, however
    /// often armed after.
    #[tokio::test]
    async fn an_on_demand_resolve_keeps_its_options_and_is_taken_once() {
        let router = router(serde_json::json!([
            { "action": "resolve", "on_demand": true, "server": "slow", "timeout": "1ms",
              "ignore_failure": true },
            { "ip_cidr": "192.0.2.0/24", "outbound": "a" },
            failing_resolve(),
            { "ip_cidr": "198.51.100.0/24", "outbound": "a" },
            { "domain_suffix": "sail", "outbound": "b" },
        ]));
        assert_eq!(
            resolved(&router, "test.sail:80").await,
            Ok(Decision::Route(Some("b".into())))
        );
        // Without ignore_failure, it fails the connection, as the eager
        // resolve does.
        let router = self::router(serde_json::json!([
            { "action": "resolve", "on_demand": true, "ignore_failure": true },
            failing_resolve(),
            { "ip_cidr": "192.0.2.0/24", "outbound": "a" },
        ]));
        assert_eq!(resolved(&router, "test.sail:80").await, Err(()));
        // Resolved already, it is not taken.
        let router = self::router(serde_json::json!([
            { "action": "resolve" },
            failing_resolve(),
            { "ip_cidr": "127.0.0.0/8", "outbound": "a" },
        ]));
        assert_eq!(
            resolved(&router, "test.sail:80").await,
            Ok(Decision::Route(Some("a".into())))
        );
        // Not for the lookups the DNS client makes for itself.
        let router = self::router(serde_json::json!([
            failing_resolve(),
            { "ip_cidr": "127.0.0.0/8", "outbound": "a" },
        ]));
        let mut sess = to("test.sail:80");
        sess.skip_resolve = true;
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("b".into()))
        );
    }

    /// A rule that is no_resolve, or a logical one within which the rule
    /// on addresses is, matches only the addresses known.
    #[tokio::test]
    async fn a_no_resolve_rule_takes_no_on_demand_resolve() {
        let router = router(serde_json::json!([
            failing_resolve(),
            { "ip_cidr": "127.0.0.0/8", "no_resolve": true, "outbound": "a" },
            { "type": "logical", "mode": "and", "outbound": "a", "rules": [
                { "ip_is_private": true, "no_resolve": true }, { "port": 80 }
            ] },
            { "domain_suffix": "sail", "outbound": "b" },
        ]));
        assert_eq!(
            resolved(&router, "test.sail:80").await,
            Ok(Decision::Route(Some("b".into())))
        );
        assert_eq!(
            resolved(&router, "127.0.0.1:443").await,
            Ok(Decision::Route(Some("a".into())))
        );
        // Resolved by a rule before, the addresses are known.
        let router = self::router(serde_json::json!([
            { "action": "resolve" },
            { "ip_cidr": "127.0.0.0/8", "no_resolve": true, "outbound": "a" },
        ]));
        assert_eq!(
            pick(&router, &mut to("test.sail:80")).await,
            Decision::Route(Some("a".into()))
        );
    }

    #[cfg(feature = "rule-set")]
    #[tokio::test]
    async fn a_rule_set_needs_addresses_only_for_lines_that_resolve() {
        let (router, _) = router_with_sets(
            serde_json::json!([
                { "tag": "names", "type": "inline",
                  "rules": [{ "domain_suffix": "names.test" }, { "port": 81 }] },
                { "tag": "lan", "type": "inline",
                  "rules": [{ "ip_cidr": "127.0.0.0/8", "no_resolve": true }] },
                { "tag": "nets", "type": "inline",
                  "rules": [{ "domain": "x.test" }, { "ip_cidr": "10.0.0.0/8" }] },
            ]),
            serde_json::json!([
                failing_resolve(),
                { "rule_set": "names", "outbound": "a" },
                { "rule_set": "lan", "outbound": "a" },
                { "domain_suffix": "sail", "outbound": "b" },
                { "rule_set": "nets", "outbound": "a" },
            ]),
        );
        assert_eq!(
            resolved(&router, "www.names.test:80").await,
            Ok(Decision::Route(Some("a".into())))
        );
        // Past the set of names alone, and the set whose addresses are
        // no_resolve, no resolve.
        assert_eq!(
            resolved(&router, "test.sail:80").await,
            Ok(Decision::Route(Some("b".into())))
        );
        assert_eq!(
            resolved(&router, "127.0.0.1:80").await,
            Ok(Decision::Route(Some("a".into())))
        );
        // A set with an address rule that resolves.
        assert_eq!(resolved(&router, "y.test:80").await, Err(()));
    }

    /// A downloaded rule-set replaced by one with other lines needs what
    /// the new lines need.
    #[cfg(feature = "rule-set")]
    #[tokio::test]
    async fn a_rule_set_replaced_needs_what_its_new_rules_need() {
        let (router, sets) = router_with_sets(
            serde_json::json!([
                { "tag": "s", "type": "inline", "rules": [{ "domain": "a.test" }] },
            ]),
            serde_json::json!([
                failing_resolve(),
                { "rule_set": "s", "outbound": "a" },
            ]),
        );
        assert_eq!(
            resolved(&router, "test.sail:80").await,
            Ok(Decision::Route(Some("b".into())))
        );
        let rules: Vec<crate::config::rule_set::HeadlessRule> =
            serde_json::from_value(serde_json::json!([{ "ip_cidr": "10.0.0.0/8" }])).unwrap();
        let set = rule_set::RuleSet::from_rules(&rules, &RuntimeEnv::default()).unwrap();
        sets.get("s").unwrap().publish(std::sync::Arc::new(set));
        assert_eq!(resolved(&router, "test.sail:80").await, Err(()));
    }

    #[tokio::test]
    async fn an_on_demand_sniff_waits_for_a_rule_that_needs_it() {
        let router = router(serde_json::json!([
            { "action": "sniff", "on_demand": true },
            { "port": 80, "outbound": "b" },
            { "domain_suffix": "example.com", "outbound": "a" },
        ]));
        let sniffed = |sess: Session| {
            let router = &router;
            async move {
                let mut sess = sess;
                let mut sniffer = FakeSniffer {
                    domain: "www.example.com",
                    calls: 0,
                };
                let decision = router
                    .pick_route(&mut sess, &mut sniffer, &NoPass)
                    .await
                    .unwrap();
                (decision, sniffer.calls)
            }
        };
        // To an address, a domain rule needs the domain sniffed.
        assert_eq!(
            sniffed(to_ip()).await,
            (Decision::Route(Some("a".into())), 1)
        );
        // Decided before it: never sniffed.
        assert_eq!(
            sniffed(to("1.2.3.4:80")).await,
            (Decision::Route(Some("b".into())), 0)
        );
        // To a domain, the domain rule matches the domain asked for.
        assert_eq!(
            sniffed(to("www.example.com:443")).await,
            (Decision::Route(Some("a".into())), 0)
        );
    }

    #[tokio::test]
    async fn protocol_and_http_rules_take_an_on_demand_sniff() {
        let mut rules = vec![serde_json::json!({ "protocol": "tls", "outbound": "a" })];
        if cfg!(feature = "regex") {
            rules.push(serde_json::json!({ "http_user_agent": "curl*", "outbound": "a" }));
            rules.push(serde_json::json!({ "url_regex": "^http://x/", "outbound": "a" }));
        }
        for rule in rules {
            let router = router(serde_json::json!([
                { "action": "sniff", "on_demand": true, "sniffer": "tls" },
                rule,
            ]));
            let mut sniffer = FakeSniffer {
                domain: "www.example.com",
                calls: 0,
            };
            router
                .pick_route(&mut to("www.example.com:443"), &mut sniffer, &NoPass)
                .await
                .unwrap();
            assert_eq!(sniffer.calls, 1, "{}", rule);
        }
    }

    /// Pre-match reads nothing: an armed sniff is never taken there, and
    /// the rules that would need it match without; an armed resolve is.
    #[tokio::test]
    async fn pre_match_takes_an_on_demand_resolve_but_no_sniff() {
        let router = router(serde_json::json!([
            { "action": "sniff", "on_demand": true },
            { "domain_suffix": "example.com", "action": "reject" },
            { "action": "resolve", "on_demand": true },
            { "ip_cidr": "127.0.0.0/8", "action": "bypass" },
            { "port": 443, "action": "bypass" },
        ]));
        assert_eq!(
            router.pre_match(&mut to("1.2.3.4:443"), &NoPass).await,
            PreMatch::Bypass
        );
        assert_eq!(
            router.pre_match(&mut to("test.sail:80"), &NoPass).await,
            PreMatch::Bypass
        );
        assert_eq!(
            router.pre_match(&mut to("1.2.3.4:80"), &NoPass).await,
            PreMatch::Proceed
        );
    }

    #[test]
    fn needs_are_the_conditions_and_those_within() {
        let needs = |rule: serde_json::Value| {
            let rule: model::Rule = serde_json::from_value(rule).unwrap();
            Matcher::new(&rule, &RuntimeEnv::default(), &Default::default())
                .unwrap()
                .needs()
        };
        use matcher::Needs;
        let ip = Needs {
            ip: true,
            ..Default::default()
        };
        let domain = Needs {
            domain: true,
            ..Default::default()
        };
        let sniff = Needs {
            sniff: true,
            ..Default::default()
        };
        assert_eq!(needs(serde_json::json!({ "port": 1 })), Needs::default());
        // An address's family is the destination's, never resolved.
        assert_eq!(
            needs(serde_json::json!({ "ip_version": 4 })),
            Needs::default()
        );
        assert_eq!(needs(serde_json::json!({ "ip_is_private": true })), ip);
        assert_eq!(
            needs(serde_json::json!({ "ip_cidr": "10.0.0.0/8", "no_resolve": true })),
            Needs::default()
        );
        assert_eq!(needs(serde_json::json!({ "domain_regex": "x" })), domain);
        assert_eq!(needs(serde_json::json!({ "protocol": "tls" })), sniff);
        let logical = serde_json::json!({ "type": "logical", "mode": "and", "invert": true,
            "rules": [
                { "domain": "a.test", "invert": true },
                { "type": "logical", "mode": "or", "rules": [
                    { "ip_cidr": "10.0.0.0/8" }, { "protocol": "http" }
                ] }
            ] });
        assert_eq!(needs(logical.clone()), ip.or(domain).or(sniff));
        let mut unresolved = logical;
        unresolved["no_resolve"] = serde_json::json!(true);
        assert_eq!(needs(unresolved), domain.or(sniff));
        let network = Needs {
            network: true,
            ..Default::default()
        };
        assert_eq!(needs(serde_json::json!({ "wifi_ssid": "Home" })), network);
        assert_eq!(
            needs(
                serde_json::json!({ "type": "logical", "mode": "or", "rules": [
                { "port": 1 }, { "network_is_expensive": true }
            ] })
            ),
            network
        );
    }

    /// A router of `rules` whose network is `env`'s.
    fn router_in(rules: serde_json::Value, env: &RuntimeEnv) -> Router {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": rules, "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), env)
            .unwrap()
            .into_shared();
        Router::new(&config.route, dns, env).unwrap()
    }

    /// The rules match the network as it is when a connection is routed:
    /// a router built before a change sees it.
    #[tokio::test]
    async fn rules_match_the_network_the_host_is_on() {
        let env = RuntimeEnv::default();
        let router = router_in(
            serde_json::json!([
                { "wifi_ssid": "Home", "network_type": "wifi", "outbound": "a" }
            ]),
            &env,
        );
        assert!(router.needs_network());
        let pick = || async {
            let mut sess = Session {
                destination: SocksAddr::Domain("x.example".into(), 443),
                ..Default::default()
            };
            router
                .pick_route(&mut sess, &mut NoSniffer, &NoPass)
                .await
                .unwrap()
        };
        // Nothing known: the rule does not match.
        assert_eq!(pick().await, Decision::Route(Some("b".into())));
        let push = |json: serde_json::Value| {
            env.network
                .push(crate::net::network::NetworkState::from_json(&json.to_string()).unwrap())
        };
        push(serde_json::json!({ "type": "wifi", "ssid": "Home" }));
        assert_eq!(pick().await, Decision::Route(Some("a".into())));
        push(serde_json::json!({ "type": "cellular" }));
        assert_eq!(pick().await, Decision::Route(Some("b".into())));
        // Pre-match sees it too.
        push(serde_json::json!({ "type": "wifi", "ssid": "Home" }));
        let bypass = router_in(
            serde_json::json!([{ "wifi_ssid": "Home", "action": "bypass" }]),
            &env,
        );
        let mut sess = Session {
            destination: SocksAddr::from(("10.0.0.1".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        };
        assert_eq!(bypass.pre_match(&mut sess, &NoPass).await, PreMatch::Bypass);
    }

    /// A resolve in routing asks the DNS rules with the network the
    /// routing rules matched.
    #[tokio::test]
    async fn a_resolve_s_dns_rules_match_the_same_network() {
        let env = RuntimeEnv::default();
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": {
                    "servers": [
                        { "type": "hosts", "tag": "home",
                          "predefined": { "nas.home.arpa": "192.168.1.2" } },
                        { "type": "hosts", "tag": "world",
                          "predefined": { "nas.home.arpa": "203.0.113.9" } }
                    ],
                    "rules": [{ "wifi_ssid": "Home", "server": "home" }],
                    "final": "world"
                },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": {
                    "rules": [
                        { "network_type": "wifi", "action": "resolve" },
                        { "ip_cidr": "192.168.1.2/32", "outbound": "a" }
                    ],
                    "final": "b"
                },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &env)
            .unwrap()
            .into_shared();
        let router = Router::new(&config.route, dns, &env).unwrap();
        env.network.push(
            crate::net::network::NetworkState::from_json(r#"{ "type": "wifi", "ssid": "Home" }"#)
                .unwrap(),
        );
        let mut sess = Session {
            destination: SocksAddr::Domain("nas.home.arpa".into(), 443),
            ..Default::default()
        };
        assert_eq!(
            router
                .pick_route(&mut sess, &mut NoSniffer, &NoPass)
                .await
                .unwrap(),
            Decision::Route(Some("a".into()))
        );
    }

    #[test]
    fn a_router_needs_the_network_only_for_rules_on_it() {
        let env = RuntimeEnv::default();
        assert!(
            !router_in(serde_json::json!([{ "port": 1, "outbound": "a" }]), &env).needs_network()
        );
        assert!(router_in(
            serde_json::json!([{ "network_mcc_mnc": "46001", "outbound": "a" }]),
            &env
        )
        .needs_network());
        // Such a rule's mistakes are the configuration's.
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "rules": [{ "network_type": "wimax", "outbound": "a" }] },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &env)
            .unwrap()
            .into_shared();
        let err = Router::new(&config.route, dns, &env).err().unwrap();
        assert!(
            err.to_string()
                .starts_with("route.rules[0].network_type: unknown network type \"wimax\""),
            "{}",
            err
        );
    }

    #[test]
    fn a_protocol_never_sniffed_is_refused() {
        for (name, message) in [
            (
                "ssh",
                "route.rules[0].protocol: sail does not sniff ssh yet",
            ),
            (
                "gopher",
                "route.rules[0].protocol: unknown protocol \"gopher\"",
            ),
        ] {
            let err = matcher::sniffed_protocol("route.rules[0].protocol", name)
                .unwrap_err()
                .to_string();
            assert_eq!(err, message);
        }
        let quic = matcher::sniffed_protocol("protocol", "quic");
        assert_eq!(quic.is_ok(), cfg!(feature = "btls"), "{:?}", quic.err());
        assert_eq!(
            matcher::sniffed_protocol("protocol", "bittorrent").unwrap(),
            crate::session::SniffedProtocol::Bittorrent
        );
    }

    /// The outbounds here pass, as a group picking PASS would.
    struct PassesThese(&'static [&'static str]);

    impl Passes for PassesThese {
        async fn passes(&self, tag: &str) -> bool {
            self.0.contains(&tag)
        }
    }

    /// A router over `a`, `b`, a selector `g` of them and PASS, and a
    /// pass outbound `PASS`, `final` going to `final_outbound`.
    fn router_to(rules: serde_json::Value, final_outbound: &str) -> Result<Router> {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [
                    { "type": "hosts", "predefined": { "test.sail": "127.0.0.1" } },
                ] },
                "outbounds": [
                    { "type": "direct", "tag": "a" },
                    { "type": "direct", "tag": "b" },
                    { "type": "selector", "tag": "g", "outbounds": ["PASS", "a"] },
                    { "type": "pass", "tag": "PASS" },
                ],
                "route": { "rules": rules, "final": final_outbound },
            })
            .to_string(),
        )?;
        let dns =
            DnsClient::new(&config.dns, Default::default(), &Default::default())?.into_shared();
        Router::new(&config.route, dns, &RuntimeEnv::default())
    }

    fn to_domain(domain: &str) -> Session {
        Session {
            destination: SocksAddr::Domain(domain.into(), 443),
            ..Default::default()
        }
    }

    /// Mihomo's tunnel `match`: a rule whose proxy is PASS, or a group
    /// picking it, is skipped, and the next rules decide.
    #[tokio::test]
    async fn a_rule_to_an_outbound_that_passes_is_skipped() {
        let router = router_to(
            serde_json::json!([
                { "domain": ["x.example"], "outbound": "PASS" },
                { "domain": ["y.example"], "outbound": "g" },
                { "port": [443], "outbound": "a" },
            ]),
            "b",
        )
        .unwrap();
        let passes = PassesThese(&["PASS", "g"]);
        for domain in ["x.example", "y.example"] {
            let mut sess = to_domain(domain);
            let decision = router
                .pick_route(&mut sess, &mut NoSniffer, &passes)
                .await
                .unwrap();
            assert_eq!(decision, Decision::Route(Some("a".into())), "{}", domain);
            assert_eq!(
                sess.matched_rule.as_deref(),
                Some("port=443 => route(a)"),
                "{}",
                domain
            );
        }
        // The group picking a member that does not pass: it routes.
        let decision = router
            .pick_route(
                &mut to_domain("y.example"),
                &mut NoSniffer,
                &PassesThese(&["PASS"]),
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("g".into())));
    }

    #[tokio::test]
    async fn a_rule_skipped_sets_none_of_its_route_options() {
        let router = router_to(
            serde_json::json!([
                { "port": [443], "outbound": "g", "override_port": 8443, "udp_timeout": "1m",
                  "tls_record_fragment": true },
                { "port": [443], "outbound": "a" },
            ]),
            "b",
        )
        .unwrap();
        let mut sess = to_domain("x.example");
        let decision = router
            .pick_route(&mut sess, &mut NoSniffer, &PassesThese(&["g"]))
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(sess.destination, SocksAddr::Domain("x.example".into(), 443));
        assert!(sess.route.original_destination.is_none());
        assert_eq!(sess.route.udp_timeout, None);
        assert!(sess.route.tls_fragment.is_none());
    }

    #[tokio::test]
    async fn an_armed_sniff_stays_armed_past_a_rule_skipped() {
        let router = router_to(
            serde_json::json!([
                { "action": "sniff", "on_demand": true },
                { "port": [443], "outbound": "g" },
                { "domain_suffix": ["example.com"], "outbound": "a" },
            ]),
            "b",
        )
        .unwrap();
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let decision = router
            .pick_route(&mut to_ip(), &mut sniffer, &PassesThese(&["g"]))
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(sniffer.calls, 1);
    }

    /// Where every rule passes, Mihomo's DIRECT takes the connection:
    /// `final` through a group that passes goes direct.
    #[tokio::test]
    async fn final_through_a_group_that_passes_goes_direct() {
        let router =
            router_to(serde_json::json!([{ "port": [443], "outbound": "g" }]), "g").unwrap();
        let decision = router
            .pick_route(&mut to_ip(), &mut NoSniffer, &PassesThese(&["g"]))
            .await
            .unwrap();
        assert_eq!(decision, Decision::Direct);
        let decision = router
            .pick_route(&mut to_ip(), &mut NoSniffer, &NoPass)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Route(Some("g".into())));
    }

    #[tokio::test]
    async fn pre_match_skips_a_rule_that_passes_too() {
        let router = router_to(
            serde_json::json!([
                { "port": [443], "outbound": "g" },
                { "port": [443], "action": "bypass" },
            ]),
            "b",
        )
        .unwrap();
        assert_eq!(
            router.pre_match(&mut to_ip(), &PassesThese(&["g"])).await,
            PreMatch::Bypass
        );
        assert_eq!(
            router.pre_match(&mut to_ip(), &NoPass).await,
            PreMatch::Proceed
        );
    }

    #[test]
    fn final_naming_a_pass_outbound_is_refused() {
        let err = router_to(serde_json::json!([]), "PASS")
            .err()
            .unwrap()
            .to_string();
        assert_eq!(
            err,
            "route.final: [PASS] is a pass outbound, and no rule comes after final"
        );
    }

    /// Inline lines merged (`config::inline`, for Clash and Surge) route a
    /// connection as the rules they were, and report it so: the rule and
    /// index of the first line it matches, as unmerged. A rule of another
    /// kind or target between two lines keeps them apart.
    #[cfg(any(feature = "config-clash", feature = "config-surge"))]
    #[tokio::test]
    async fn merged_lines_route_and_report_as_the_rules_they_were() {
        let rules = serde_json::json!([
            { "domain_suffix": ["example.test"], "outbound": "a" },
            { "domain_suffix": ["sub.example.test"], "outbound": "a" },
            { "domain_keyword": ["kw"], "outbound": "a" },
            { "domain": ["x.test"], "outbound": "a" },
            { "domain_suffix": ["y.test"], "outbound": "b" },
            { "domain_suffix": ["z.test"], "outbound": "b" },
            { "port": [8080], "outbound": "a" },
            { "domain_suffix": ["w.test"], "outbound": "b" },
            { "domain_suffix": ["example.test"], "outbound": "b" },
        ]);
        let build = |merged: bool| {
            let mut json = serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": rules.clone(), "final": "b" },
            });
            // As a Clash or Surge lowering merges: in the JSON, before the
            // model is read, which then learns what each rule was.
            let told = merged.then(|| crate::config::inline::merge(&mut json));
            let mut config = crate::config::Config::from_json(&json.to_string()).unwrap();
            if let Some(told) = told {
                crate::config::inline::attach(&mut config.route.rules, told);
            }
            let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
                .unwrap()
                .into_shared();
            Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap()
        };
        let (plain, merged) = (build(false), build(true));
        assert_eq!(plain.rules.len(), 9);
        assert_eq!(merged.rules.len(), 4, "0-3, 4-5, 6, 7-8");
        let told = |router: &Router, sess: &Session| {
            let matched = sess.matched_rule.clone();
            let index = matched.as_ref().and_then(|m| router.rule_index(m));
            (matched.map(|m| m.to_string()), index)
        };
        for (host, port) in [
            ("a.example.test", 443),
            ("sub.example.test", 443),
            ("foo-kw.test", 443),
            ("x.test", 443),
            ("www.x.test", 443),
            ("y.test", 443),
            ("q.z.test", 443),
            ("w.test", 8080),
            ("w.test", 443),
            ("nothing.test", 443),
        ] {
            let at = || Session {
                destination: SocksAddr::Domain(host.into(), port),
                ..Default::default()
            };
            let (mut a, mut b) = (at(), at());
            let decided = (pick(&plain, &mut a).await, pick(&merged, &mut b).await);
            assert_eq!(decided.0, decided.1, "{host}:{port}");
            assert_eq!(told(&plain, &a), told(&merged, &b), "{host}:{port}");
        }
        // The second line of a run reports itself; a line after a merged
        // run keeps its index.
        let mut sess = Session {
            destination: SocksAddr::Domain("www.sub.example.test".into(), 443),
            ..Default::default()
        };
        pick(&merged, &mut sess).await;
        assert_eq!(
            told(&merged, &sess).1,
            Some(0),
            "example.test, written first"
        );
        let mut sess = Session {
            destination: SocksAddr::Domain("q.z.test".into(), 443),
            ..Default::default()
        };
        pick(&merged, &mut sess).await;
        assert_eq!(told(&merged, &sess).1, Some(5));
        assert_eq!(
            told(&merged, &sess).0.as_deref(),
            Some("domain_suffix=z.test => route(b)")
        );
    }
}
