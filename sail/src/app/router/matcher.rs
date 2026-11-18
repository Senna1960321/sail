//! The conditions of a rule, compiled into indexes: a domain is looked up
//! in hash sets, an address is binary-searched in sorted ranges. Routing
//! rules, DNS rules and the rules of rule-sets all compile to the same
//! [`Condition`], and match as sing-box's `DefaultRule` and `LogicalRule`
//! do.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use cidr::IpCidr;
use maxminddb::geoip2::Country;

use super::rule_set::SuccinctSet;
use crate::config::external_rule::{self, DomainKind, External};
use crate::config::model::{self, LogicalMode, RuleType};
use crate::runtime::RuntimeEnv;
use crate::session::{Network, Session, SniffedProtocol};

mod network;
pub(crate) use network::NetworkConditions;

/// What rules are matched against: what is known about a connection at
/// the time.
#[derive(Clone)]
pub(crate) struct Facts {
    /// The domain, sniffed or asked for, in lowercase.
    domain: Option<String>,
    /// The address asked for, and those the domain resolved to.
    ips: Vec<IpAddr>,
    port: u16,
    /// 4 or 6, when the destination is an address.
    ip_version: Option<u8>,
    network: Network,
    inbound: String,
    user: Option<crate::user::UserRef>,
    /// The protocol sniffing found.
    protocol: Option<SniffedProtocol>,
    /// The plain HTTP request sniffing read.
    http: Option<Arc<crate::sniff::http::Request>>,
    /// The path of the program the connection comes from.
    process_path: Option<String>,
    source: std::net::SocketAddr,
    /// The record type, for a DNS query.
    query_type: Option<u16>,
    /// The DNS servers that prefer the name, for a DNS query.
    preferred_by: Option<Arc<Vec<String>>>,
    /// The LAN device the source is, when it was looked up.
    neighbor: Option<Arc<crate::net::neighbor::Neighbor>>,
    /// Who opened the connection, as the host tells it.
    owner: Option<Arc<crate::runtime::platform::ConnectionOwner>>,
    /// The code of the DNS response matched.
    rcode: Option<u16>,
    /// The DNS response matched, whose records `response_answer`,
    /// `response_ns` and `response_extra` match.
    response: Option<Arc<hickory_proto::op::Message>>,
    /// The evaluated DNS responses, by what `match_response` calls them,
    /// for the rules a logical one combines that name their own.
    responses: Option<Arc<Responses>>,
    /// The network the host is on, at the time: taken only for rules
    /// with conditions on it, which do not match without it.
    network_state: Option<Arc<crate::net::network::NetworkState>>,
}

/// The evaluated DNS responses a DNS rule may match, by what
/// `match_response` calls them: none for a server that did not answer.
pub(crate) type Responses = std::collections::HashMap<model::ResponseRef, Option<ResponseFacts>>;

/// What the conditions on a DNS response see of it.
#[derive(Clone)]
pub(crate) struct ResponseFacts {
    /// Its addresses.
    pub ips: Vec<IpAddr>,
    pub rcode: u16,
    pub message: Arc<hickory_proto::op::Message>,
}

impl Facts {
    pub fn new(sess: &Session, resolved: &[IpAddr]) -> Self {
        let domain = sess
            .sniffed_domain()
            .or_else(|| sess.destination.domain().map(String::as_str))
            .map(str::to_ascii_lowercase);
        let destination = sess.destination.ip().map(|ip| ip.to_canonical());
        let mut ips: Vec<IpAddr> = destination.into_iter().collect();
        ips.extend_from_slice(resolved);
        Facts {
            domain,
            ips,
            port: sess.destination.port(),
            ip_version: Self::ip_version_of(sess),
            network: sess.network,
            inbound: sess.inbound_tag.clone(),
            user: sess.user.clone(),
            protocol: sess.sniffed_protocol,
            http: sess.sniffed_http.clone(),
            process_path: sess.process_name.clone(),
            source: sess.source,
            query_type: None,
            preferred_by: None,
            neighbor: sess.neighbor.clone(),
            owner: sess.owner.clone(),
            rcode: None,
            response: None,
            responses: None,
            network_state: None,
        }
    }

    /// The facts a host gives of a session of its own (`embed::RuleSet`):
    /// what headless rules match, and nothing else.
    #[cfg(feature = "rule-set")]
    pub(crate) fn of_host(
        network: Network,
        domain: Option<&str>,
        ips: &[IpAddr],
        port: u16,
        source: std::net::SocketAddr,
    ) -> Self {
        let ips: Vec<IpAddr> = ips.iter().map(IpAddr::to_canonical).collect();
        // As `new` has it of a destination that is an address.
        let ip_version = match (domain, ips.first()) {
            (None, Some(ip)) => Some(if ip.is_ipv4() { 4 } else { 6 }),
            _ => None,
        };
        Facts {
            domain: domain.map(str::to_ascii_lowercase),
            ips,
            port,
            ip_version,
            network,
            inbound: String::new(),
            user: None,
            protocol: None,
            http: None,
            process_path: None,
            source,
            query_type: None,
            preferred_by: None,
            neighbor: None,
            owner: None,
            rcode: None,
            response: None,
            responses: None,
            network_state: None,
        }
    }

    /// 4 or 6, when the destination of `sess` is an address.
    pub fn ip_version_of(sess: &Session) -> Option<u8> {
        sess.destination
            .ip()
            .map(|ip| if ip.to_canonical().is_ipv4() { 4 } else { 6 })
    }

    /// With the IP version `ip_version`, the destination's when the
    /// matching began.
    pub fn with_ip_version(mut self, ip_version: Option<u8>) -> Self {
        self.ip_version = ip_version;
        self
    }

    /// With the network the host is on, which conditions on it
    /// (`wifi_ssid`, `network_type`, …) match.
    pub fn with_network(mut self, state: Arc<crate::net::network::NetworkState>) -> Self {
        self.network_state = Some(state);
        self
    }

    /// The facts of the DNS response `message`, whose records the rules
    /// may match.
    pub fn with_response(mut self, message: Arc<hickory_proto::op::Message>) -> Self {
        self.response = Some(message);
        self
    }

    /// With the evaluated responses the rules a logical one combines may
    /// name.
    pub fn with_responses(mut self, responses: Arc<Responses>) -> Self {
        self.responses = Some(responses);
        self
    }

    /// These facts, of the evaluated response `response` names instead;
    /// none when there is no such response.
    fn of_response(&self, response: &model::ResponseRef) -> Option<Facts> {
        let of = self.responses.as_ref()?.get(response)?.as_ref()?;
        let mut facts = self.clone();
        facts.ips = of.ips.clone();
        facts.rcode = Some(of.rcode);
        facts.response = Some(of.message.clone());
        Some(facts)
    }

    /// The facts of a DNS response with code `rcode`, whose addresses
    /// are those resolved.
    pub fn with_rcode(mut self, rcode: u16) -> Self {
        self.rcode = Some(rcode);
        self
    }

    /// The facts of a DNS query of `query_type`.
    pub fn with_query_type(mut self, query_type: u16) -> Self {
        self.query_type = Some(query_type);
        self
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Where the connection came from; none for the DNS client's own
    /// queries.
    pub fn source(&self) -> Option<std::net::SocketAddr> {
        Some(self.source).filter(|s| !s.ip().is_unspecified() || s.port() != 0)
    }

    pub fn ips(&self) -> &[IpAddr] {
        &self.ips
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The name of the program the connection comes from: its path's last
    /// part.
    pub fn process_name(&self) -> Option<&str> {
        self.process_path
            .as_deref()
            .map(|path| path.rsplit(['/', '\\']).next().unwrap_or(path))
    }

    pub fn query_type(&self) -> Option<u16> {
        self.query_type
    }

    /// The facts of a DNS query for a name the servers `tags` prefer.
    pub fn with_preferred_by(mut self, tags: Arc<Vec<String>>) -> Self {
        self.preferred_by = Some(tags);
        self
    }

    /// The URL of the plain HTTP request sniffed, unless it was too long
    /// to keep.
    fn url(&self) -> Option<&str> {
        self.http.as_ref()?.url.as_ref()?.whole()
    }

    /// Its User-Agent, likewise.
    fn user_agent(&self) -> Option<&str> {
        self.http.as_ref()?.user_agent.as_ref()?.whole()
    }
}

/// The things a rule has conditions on, as sing-box groups them: of the
/// conditions on one thing, any matching will do.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Groups {
    required: u8,
    satisfied: u8,
}

impl Groups {
    pub const SOURCE_ADDRESS: u8 = 1;
    pub const SOURCE_PORT: u8 = 2;
    pub const DESTINATION_ADDRESS: u8 = 4;
    pub const DESTINATION_PORT: u8 = 8;

    /// Conditions on `group`, which match or not.
    pub fn require(&mut self, group: u8, matched: bool) {
        self.required |= group;
        if matched {
            self.satisfied |= group;
        }
    }

    /// Whether every thing with conditions matches.
    pub fn done(self) -> bool {
        self.required & !self.satisfied == 0
    }

    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub fn merge(self, other: Groups) -> Groups {
        Groups {
            required: self.required | other.required,
            satisfied: self.satisfied | other.satisfied,
        }
    }
}

/// Domains by how they are compared: a few as a list gone through, more
/// in sets. A rule of one domain, as a profile of thousands of lines has
/// them, keeps a list of one, not three tables.
pub(crate) struct DomainIndex(Domains);

enum Domains {
    /// At most `DomainIndex::FEW`, none twice, allocated to fit.
    Few(Vec<(Compared, Box<str>)>),
    Many(Box<DomainSets>),
}

/// How a domain is compared with one of a rule's.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Compared {
    /// The same.
    Full,
    /// The same, or a subdomain of it.
    Suffix,
    /// A subdomain of it: a suffix written with a leading dot, as sing-box
    /// reads it.
    Subdomain,
    /// Containing it.
    Keyword,
}

#[derive(Default)]
struct DomainSets {
    full: HashSet<String>,
    /// A domain matches when it is one of these or a subdomain of one.
    suffix: HashSet<String>,
    /// A domain matches when it is a subdomain of one of these.
    subdomain: HashSet<String>,
    keyword: Vec<String>,
}

impl Default for DomainIndex {
    fn default() -> Self {
        DomainIndex(Domains::Few(Vec::new()))
    }
}

impl DomainSets {
    fn insert(&mut self, compared: Compared, value: String) {
        match compared {
            Compared::Full => {
                self.full.insert(value);
            }
            Compared::Suffix => {
                self.suffix.insert(value);
            }
            Compared::Subdomain => {
                self.subdomain.insert(value);
            }
            Compared::Keyword => self.keyword.push(value),
        }
    }

    fn matches(&self, domain: &str) -> bool {
        if self.full.contains(domain) {
            return true;
        }
        if !self.suffix.is_empty() || !self.subdomain.is_empty() {
            let mut rest = domain;
            let mut is_parent = false;
            loop {
                if self.suffix.contains(rest) || (is_parent && self.subdomain.contains(rest)) {
                    return true;
                }
                match rest.find('.') {
                    Some(dot) => rest = &rest[dot + 1..],
                    None => break,
                }
                is_parent = true;
            }
        }
        self.keyword.iter().any(|k| domain.contains(k.as_str()))
    }
}

impl DomainIndex {
    /// Past this many, sets: a list is gone through for every connection.
    const FEW: usize = 8;

    pub(crate) fn insert(&mut self, kind: DomainKind, value: &str) {
        let value = value.to_ascii_lowercase();
        let (compared, value) = match kind {
            DomainKind::Full => (Compared::Full, value),
            DomainKind::Suffix => match value.strip_prefix('.') {
                Some(parent) => (Compared::Subdomain, parent.to_string()),
                None => (Compared::Suffix, value),
            },
            DomainKind::Keyword => (Compared::Keyword, value),
        };
        match &mut self.0 {
            Domains::Few(few) => {
                // A keyword twice is kept twice, as the sets keep it.
                let twice = compared != Compared::Keyword
                    && few.iter().any(|(c, v)| *c == compared && **v == *value);
                if twice {
                    return;
                }
                if few.len() < Self::FEW {
                    few.reserve_exact(1);
                    few.push((compared, value.into()));
                } else {
                    let mut sets = DomainSets::default();
                    for (compared, value) in few.drain(..) {
                        sets.insert(compared, value.into());
                    }
                    sets.insert(compared, value);
                    self.0 = Domains::Many(Box::new(sets));
                }
            }
            Domains::Many(sets) => sets.insert(compared, value),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many domains, suffixes and keywords it has.
    pub(crate) fn len(&self) -> usize {
        match &self.0 {
            Domains::Few(few) => few.len(),
            Domains::Many(sets) => {
                sets.full.len() + sets.suffix.len() + sets.subdomain.len() + sets.keyword.len()
            }
        }
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        // Whether `domain` is a subdomain of `of`.
        let under = |of: &str| {
            domain
                .strip_suffix(of)
                .is_some_and(|rest| rest.ends_with('.'))
        };
        match &self.0 {
            Domains::Few(few) => few.iter().any(|(compared, value)| match compared {
                Compared::Full => domain == &**value,
                Compared::Suffix => domain == &**value || under(value),
                Compared::Subdomain => under(value),
                Compared::Keyword => domain.contains(&**value),
            }),
            Domains::Many(sets) => sets.matches(domain),
        }
    }
}

/// Address ranges, sorted and merged, per family.
#[derive(Default)]
pub(crate) struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    /// CIDRs, or plain addresses, which stand for themselves. A CIDR with
    /// bits set past its prefix stands for its network, as Go's
    /// netip.ParsePrefix reads it in sing-box: "10.1.2.3/8" is 10.0.0.0/8.
    pub(crate) fn new(cidrs: &[String]) -> Result<Self> {
        let mut index = CidrIndex::default();
        for value in cidrs {
            let cidr = value
                .parse::<cidr::IpInet>()
                .map(|inet| inet.network())
                .or_else(|e| value.parse::<IpAddr>().map(IpCidr::new_host).map_err(|_| e))
                .map_err(|e| anyhow!("invalid CIDR \"{}\": {}", value, e))?;
            match (cidr.first_address(), cidr.last_address()) {
                (IpAddr::V4(first), IpAddr::V4(last)) => index.v4.push((first.into(), last.into())),
                (IpAddr::V6(first), IpAddr::V6(last)) => index.v6.push((first.into(), last.into())),
                _ => unreachable!("a CIDR is of one family"),
            }
        }
        merge(&mut index.v4);
        merge(&mut index.v6);
        Ok(index)
    }

    /// Inclusive ranges of addresses, each of one family.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn from_ranges(ranges: &[(IpAddr, IpAddr)]) -> Result<Self> {
        let mut index = CidrIndex::default();
        for &(first, last) in ranges {
            // Each in the family it is written in: an IPv4-mapped range
            // stays IPv6, as in sing-box (MRS maps its own on reading).
            match (first, last) {
                (IpAddr::V4(first), IpAddr::V4(last)) if first <= last => {
                    index.v4.push((first.into(), last.into()))
                }
                (IpAddr::V6(first), IpAddr::V6(last)) if first <= last => {
                    index.v6.push((first.into(), last.into()))
                }
                _ => return Err(anyhow!("invalid address range {} - {}", first, last)),
            }
        }
        merge(&mut index.v4);
        merge(&mut index.v6);
        Ok(index)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Its inclusive ranges, IPv4 first.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn ranges(&self) -> impl Iterator<Item = (IpAddr, IpAddr)> + '_ {
        let v4 = self.v4.iter().map(|&(first, last)| {
            (
                IpAddr::from(std::net::Ipv4Addr::from(first)),
                IpAddr::from(std::net::Ipv4Addr::from(last)),
            )
        });
        let v6 = self.v6.iter().map(|&(first, last)| {
            (
                IpAddr::from(std::net::Ipv6Addr::from(first)),
                IpAddr::from(std::net::Ipv6Addr::from(last)),
            )
        });
        v4.chain(v6)
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => within(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => within(&self.v6, u128::from(ip)),
        }
    }
}

fn merge<T: Ord + Copy>(ranges: &mut Vec<(T, T)>) {
    ranges.sort();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges.iter() {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    *ranges = merged;
}

fn within<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let after = ranges.partition_point(|r| r.0 <= x);
    after > 0 && ranges[after - 1].1 >= x
}

/// Whether `ip` is not a public address, as sing's `IsPublicAddr` says:
/// private, loopback, link-local, multicast or unspecified.
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            (first & 0xfe00) == 0xfc00
                || ip.is_loopback()
                || ip.is_multicast()
                || (first & 0xffc0) == 0xfe80
                || ip.is_unspecified()
        }
    }
}

struct Mmdb {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
    /// Uppercase, as the databases have them.
    country_code: String,
}

impl Mmdb {
    fn contains(&self, ip: IpAddr) -> bool {
        self.reader
            .lookup(ip)
            .and_then(|result| result.decode::<Country>())
            .is_ok_and(|country| {
                country.is_some_and(|country| {
                    country.country.iso_code == Some(self.country_code.as_str())
                })
            })
    }
}

/// The ASN database `ip_asn` looks addresses up in, in the asset directory.
pub(crate) const ASN_FILE: &str = "asn.mmdb";

/// A MaxMind database file as it is now: its path, length and time of
/// change. A file replaced is another.
type MmdbKey = (String, u64, Option<std::time::SystemTime>);

/// The MaxMind database `file`, a data file (`env.data_path`; a path given
/// whole stays as it is), opened once: every rule, rule-set or group that
/// opens the same file while one still holds it shares it. A file replaced
/// since, of another length or time of change, is opened again, so that a
/// reload reads the new one while the old rules keep the old. A file that
/// does not open is an error naming its path.
pub(crate) fn open_mmdb(env: &RuntimeEnv, file: &str) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
    use std::sync::{Mutex, OnceLock, Weak};
    type Open = Mutex<HashMap<MmdbKey, Weak<maxminddb::Reader<Vec<u8>>>>>;
    static OPEN: OnceLock<Open> = OnceLock::new();
    let path = env.data_path(file);
    let meta = std::fs::metadata(&path).map_err(|e| crate::assets::open_error("", &path, e))?;
    let key = (path, meta.len(), meta.modified().ok());
    let mut open = OPEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(reader) = open.get(&key).and_then(Weak::upgrade) {
        return Ok(reader);
    }
    let reader = Arc::new(
        maxminddb::Reader::open_readfile(&key.0)
            .map_err(|e| anyhow!("open {} failed: {}", key.0, e))?,
    );
    open.retain(|_, r| r.strong_count() > 0);
    open.insert(key, Arc::downgrade(&reader));
    Ok(reader)
}

/// `ip_asn`: autonomous systems, of an ASN database.
struct Asns {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
    /// Sorted.
    numbers: Vec<u32>,
}

/// An ASN database's record: GeoLite2-ASN's number, or ipinfo's `AS`
/// string.
#[derive(serde_derive::Deserialize)]
struct AsnRecord<'a> {
    autonomous_system_number: Option<u32>,
    asn: Option<&'a str>,
}

impl Asns {
    fn contains(&self, ip: IpAddr) -> bool {
        let Ok(Some(record)) = self
            .reader
            .lookup(ip)
            .and_then(|result| result.decode::<AsnRecord>())
        else {
            return false;
        };
        let number = record.autonomous_system_number.or_else(|| {
            record
                .asn
                .and_then(|a| a.strip_prefix("AS").unwrap_or(a).parse().ok())
        });
        number.is_some_and(|n| self.numbers.binary_search(&n).is_ok())
    }
}

/// A regular expression, when sail is built with them.
#[cfg(feature = "regex")]
type Pattern = regex::Regex;

/// Without regular expressions, there are none to match.
#[cfg(not(feature = "regex"))]
enum Pattern {}

#[cfg(not(feature = "regex"))]
impl Pattern {
    fn is_match(&self, _: &str) -> bool {
        match *self {}
    }
}

/// A User-Agent pattern, as Surge's `USER-AGENT` has it, as a regular
/// expression: `*` any run of characters, `?` any one, everything else
/// itself.
fn user_agent_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut literal = [0u8; 4];
    for c in pattern.chars() {
        match c {
            '*' => regex.push_str("(?s:.*)"),
            '?' => regex.push_str("(?s:.)"),
            c => regex.push_str(&regex_escape(c.encode_utf8(&mut literal))),
        }
    }
    regex.push('$');
    regex
}

#[cfg(feature = "regex")]
fn regex_escape(s: &str) -> String {
    regex::escape(s)
}

/// Without regular expressions, no pattern is compiled.
#[cfg(not(feature = "regex"))]
fn regex_escape(s: &str) -> String {
    s.to_string()
}

fn patterns(field: &str, values: &[String]) -> Result<Vec<Pattern>> {
    #[cfg(feature = "regex")]
    {
        values
            .iter()
            .map(|v| Pattern::new(v).map_err(|e| anyhow!("{}: \"{}\": {}", field, v, e)))
            .collect()
    }
    #[cfg(not(feature = "regex"))]
    match values.first() {
        Some(_) => Err(anyhow!(
            "{}: not supported, sail is built without regular expressions",
            field
        )),
        None => Ok(Vec::new()),
    }
}

/// Whether sail can tell which program a connection comes from: the
/// NetFilter inbound on Windows says; on Linux and macOS sail finds it
/// itself (app::owner). Tests match as if it could.
const PROCESS_KNOWN: bool = cfg!(any(
    test,
    all(feature = "inbound-nf", windows),
    target_os = "linux",
    target_os = "macos"
));
/// Whether sail finds the user who opened a connection itself.
const USER_KNOWN: bool = cfg!(any(target_os = "linux", target_os = "macos"));
/// Whether process conditions are compiled in.
const PROCESS_COMPILED: bool = cfg!(any(test, feature = "rule-process-name"));

/// Refuses a condition on the program a connection comes from, where it is
/// never known: it would never match.
fn process_known(field: &str, compiled: bool, known: bool) -> Result<()> {
    if !compiled {
        return Err(anyhow!(
            "{}: not supported, rule-process-name is not compiled in",
            field
        ));
    }
    if !known {
        return Err(anyhow!(
            "{}: sail cannot tell which program a connection comes from on this platform",
            field
        ));
    }
    Ok(())
}

/// The protocol sing-box names `name`, as `field` gives it: one sail
/// sniffs, or a condition that could never match is refused.
pub(crate) fn sniffed_protocol(field: &str, name: &str) -> Result<SniffedProtocol> {
    match SniffedProtocol::ALL.into_iter().find(|p| p.name() == name) {
        Some(SniffedProtocol::Quic) if !cfg!(feature = "btls") => Err(anyhow!(
            "{}: quic is never sniffed, sail is built without btls",
            field
        )),
        Some(protocol) => Ok(protocol),
        None if ["ssh", "rdp", "ntp"].contains(&name) => {
            Err(anyhow!("{}: sail does not sniff {} yet", field, name))
        }
        None => Err(anyhow!("{}: unknown protocol \"{}\"", field, name)),
    }
}

/// What building a condition needs from outside it.
pub(crate) struct Context<'a> {
    pub env: &'a RuntimeEnv,
    pub rule_sets: &'a super::rule_set::RuleSets,
}

/// What the rules of a binary rule-set give in forms of their own.
#[derive(Default)]
pub(crate) struct Extras {
    pub succinct: Option<SuccinctSet>,
    pub ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub source_ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub query_types: Vec<u16>,
}

/// `field` of the rule at `path`, as errors name it.
fn at(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{}.{}", path, field)
    }
}

/// Rules nested deeper than this are refused, as sing-box refuses them.
pub(crate) const MAX_DEPTH: usize = 100;

/// What a rule's conditions need learnt of a connection, beyond what it
/// comes with, to match as they would with it: what an `on_demand`
/// resolve or sniff is taken for.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Needs {
    /// The destination's addresses: a domain's, resolved. Conditions
    /// that are `no_resolve` do not need them.
    pub ip: bool,
    /// A domain: sniffed, when the destination is an address.
    pub domain: bool,
    /// What sniffing alone tells: the protocol, the plain HTTP request.
    pub sniff: bool,
    /// The network the host is on: never learnt of a connection, but
    /// taken for it only when a rule needs it.
    pub network: bool,
    /// Who opened the connection: the program, the package, the user;
    /// looked up only when a rule needs it (sing-box's find_process).
    pub owner: bool,
    /// Of the owner, the program: costlier to find than the user (on
    /// Linux a walk of /proc).
    pub process: bool,
}

impl Needs {
    pub(crate) fn or(self, other: Needs) -> Needs {
        Needs {
            ip: self.ip || other.ip,
            domain: self.domain || other.domain,
            sniff: self.sniff || other.sniff,
            network: self.network || other.network,
            owner: self.owner || other.owner,
            process: self.process || other.process,
        }
    }

    /// These needs, of conditions that are `no_resolve` when `no_resolve`.
    fn resolving(self, no_resolve: bool) -> Needs {
        Needs {
            ip: self.ip && !no_resolve,
            ..self
        }
    }
}

/// A logical rule's rules and how they combine.
pub(crate) struct Logical {
    /// `and`; `or` otherwise.
    pub(crate) all: bool,
    pub(crate) rules: Vec<Condition>,
    pub(crate) invert: bool,
    /// Its rules' conditions on addresses never need them resolved.
    pub(crate) no_resolve: bool,
    /// A DNS rule's own `match_response`, within a logical one.
    pub(crate) response: Option<model::ResponseRef>,
}

/// A rule's conditions, compiled.
pub(crate) enum Condition {
    /// A default rule: conditions of its own.
    Default(Box<Conditions>),
    /// A logical rule: others, combined. Boxed, as a default rule's are:
    /// a rule-set of thousands of rules keeps a pointer for each.
    Logical(Box<Logical>),
}

impl Condition {
    /// Compiles the conditions of `rule`, found at `path`, and of the
    /// rules nested in it.
    pub(crate) fn compile(rule: &model::Rule, path: &str, ctx: &mut Context) -> Result<Self> {
        Self::compile_at(rule, path, ctx, 0)
    }

    fn compile_at(rule: &model::Rule, path: &str, ctx: &mut Context, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(anyhow!("{}: logical rules nested too deep", path));
        }
        match rule.kind {
            RuleType::Default => Ok(Condition::Default(Box::new(Conditions::compile(
                rule,
                Extras::default(),
                path,
                ctx,
            )?))),
            RuleType::Logical => {
                let all = match rule.mode {
                    Some(LogicalMode::And) => true,
                    Some(LogicalMode::Or) => false,
                    None => return Err(anyhow!("{}: missing", at(path, "mode"))),
                };
                if rule.rules.is_empty() {
                    return Err(anyhow!("{}: a logical rule needs some", at(path, "rules")));
                }
                let rules = rule
                    .rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        Self::compile_at(r, &at(path, &format!("rules[{}]", i)), ctx, depth + 1)
                    })
                    .collect::<Result<_>>()?;
                Ok(Condition::Logical(Box::new(Logical {
                    all,
                    rules,
                    invert: rule.invert,
                    no_resolve: rule.no_resolve,
                    response: rule.match_response.clone(),
                })))
            }
        }
    }

    /// Whether the connection `facts` tells of matches; a rule-set's
    /// `ip_cidr` matches the source when `ip_match_source`.
    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        match self {
            Condition::Default(conditions) => conditions.matches(facts, ip_match_source),
            Condition::Logical(logical) => {
                let Logical {
                    all,
                    rules,
                    invert,
                    response,
                    ..
                } = &**logical;
                // On a response it names, which it matches only inverted
                // without, as in sing-box.
                let switched;
                let facts = match response {
                    None => facts,
                    Some(r) => match facts.of_response(r) {
                        Some(f) => {
                            switched = f;
                            &switched
                        }
                        None => return *invert,
                    },
                };
                let matched = if *all {
                    rules.iter().all(|r| r.matches(facts, ip_match_source))
                } else {
                    rules.iter().any(|r| r.matches(facts, ip_match_source))
                };
                matched != *invert
            }
        }
    }

    /// What its conditions need learnt of a connection, however deep,
    /// with a rule-set's `ip_cidr` on the source when `ip_match_source`;
    /// an inverted rule needs what it would without.
    pub(crate) fn needs(&self, ip_match_source: bool) -> Needs {
        match self {
            Condition::Default(c) => c.needs(ip_match_source),
            Condition::Logical(l) => l
                .rules
                .iter()
                .fold(Needs::default(), |n, r| n.or(r.needs(ip_match_source)))
                .resolving(l.no_resolve),
        }
    }

    /// Whether it names rule-sets, however deep: rules a download may
    /// replace with others that need more.
    pub(crate) fn names_rule_sets(&self) -> bool {
        match self {
            Condition::Default(c) => c.has_rule_sets(),
            Condition::Logical(l) => l.rules.iter().any(Condition::names_rule_sets),
        }
    }

    /// The destination `ip_cidr` ranges of its default rules, however
    /// deep, as sing-box extracts a rule-set's addresses.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn ip_ranges(&self, out: &mut Vec<(IpAddr, IpAddr)>) {
        match self {
            Condition::Default(c) => out.extend(c.ip_cidr_ranges()),
            Condition::Logical(l) => l.rules.iter().for_each(|r| r.ip_ranges(out)),
        }
    }

    /// How many domains its default rules name, however deep; `None` when
    /// any of them matches addresses, and so more than sites.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn domain_count(&self) -> Option<usize> {
        match self {
            Condition::Default(c) => c.domain_count(),
            Condition::Logical(l) => l
                .rules
                .iter()
                .try_fold(0, |n, r| r.domain_count().map(|m| n + m)),
        }
    }

    /// The tag of a narrow rule-set of this rule's that `facts` matches,
    /// if any: the first such, however deep.
    #[cfg(feature = "rule-set")]
    fn narrow_rule_set(&self, facts: &Facts) -> Option<std::sync::Arc<str>> {
        match self {
            Condition::Default(c) => c.narrow_rule_set(facts),
            Condition::Logical(l) if !l.invert => {
                l.rules.iter().find_map(|r| r.narrow_rule_set(facts))
            }
            Condition::Logical(_) => None,
        }
    }

    /// The conditions a rule-set of this rule alone merges into the rule
    /// that names it: a default rule's, not inverted, naming no rule-set.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn mergeable(&self) -> Option<&Conditions> {
        match self {
            Condition::Default(c) if !c.invert && !c.has_rule_sets() => Some(c),
            _ => None,
        }
    }
}

/// The conditions of a default rule. Those on one thing (the source's
/// address, its port, the destination's address, its port) match when any
/// of them does; the rule when each thing it has conditions on matches,
/// and every other condition does.
/// What `compile` gathers of a default rule, every kind of condition in
/// a field of its own; kept as `Conditions`, which holds only those it has.
#[derive(Default)]
struct Parts {
    /// The mode wanted, and the instance's.
    clash_mode: Option<(String, crate::app::clash_mode::ClashMode)>,
    inbounds: Vec<String>,
    ip_version: Option<u8>,
    networks: Vec<Network>,
    auth_users: Vec<String>,
    protocols: Vec<SniffedProtocol>,
    domains: DomainIndex,
    /// The domains and suffixes of a binary rule-set.
    succinct: Option<SuccinctSet>,
    domain_regex: Vec<Pattern>,
    source_ip_cidr: CidrIndex,
    source_ip_is_private: bool,
    ip_cidr: CidrIndex,
    mmdbs: Vec<Mmdb>,
    asns: Option<Asns>,
    ip_is_private: bool,
    /// Any address matches, of a DNS response.
    ip_accept_any: bool,
    response_rcode: Option<u16>,
    /// Records the DNS response matched has, in each section: any of
    /// them.
    response_answer: Vec<hickory_proto::rr::Record>,
    response_ns: Vec<hickory_proto::rr::Record>,
    response_extra: Vec<hickory_proto::rr::Record>,
    /// A DNS rule's own `match_response`, within a logical one.
    response: Option<model::ResponseRef>,
    source_ports: Vec<(u16, u16)>,
    ports: Vec<(u16, u16)>,
    process_names: Vec<String>,
    process_paths: Vec<String>,
    process_path_regex: Vec<Pattern>,
    process_name_regex: Vec<Pattern>,
    /// Of who opened the connection, as the host tells it.
    package_names: Vec<String>,
    package_name_regex: Vec<Pattern>,
    process_users: Vec<String>,
    process_user_ids: Vec<i32>,
    /// Of the plain HTTP request sniffed.
    http_user_agent: Vec<Pattern>,
    url_regex: Vec<Pattern>,
    query_types: Vec<u16>,
    /// DNS servers, one of which prefers the name.
    preferred_by: Vec<String>,
    /// MAC addresses of the source's LAN device, as sing-box writes them.
    source_macs: Vec<String>,
    /// Host names of the source's LAN device.
    source_hostnames: Vec<String>,
    /// On the network the host is on.
    network: NetworkConditions,
    /// Each by its tag.
    #[cfg(feature = "rule-set")]
    rule_sets: Vec<(std::sync::Arc<str>, super::rule_set::SharedRuleSet)>,
    #[cfg(feature = "rule-set")]
    ip_match_source: bool,
    /// Its conditions on addresses, and its rule-sets', never need them
    /// resolved.
    no_resolve: bool,
    invert: bool,
}

/// The conditions of a default rule: only those it has, each an item, in
/// `Parts`' order. A rule with one condition, as an inline Clash or Surge
/// rule is, keeps that one and not room for every kind.
pub(crate) struct Conditions {
    items: Box<[Item]>,
    /// A DNS rule's own `match_response`, within a logical one.
    response: Option<model::ResponseRef>,
    /// Each by its tag.
    #[cfg(feature = "rule-set")]
    rule_sets: Vec<(std::sync::Arc<str>, super::rule_set::SharedRuleSet)>,
    #[cfg(feature = "rule-set")]
    ip_match_source: bool,
    /// Its conditions on addresses, and its rule-sets', never need them
    /// resolved.
    no_resolve: bool,
    invert: bool,
    /// Whether it has no conditions at all, and so matches everything,
    /// inverted or not, as in sing-box.
    empty: bool,
}

/// A condition a rule has. Those on addresses and ports match as sing-box
/// groups them (any of a group's); the others must each hold.
enum Item {
    ClashMode(String, crate::app::clash_mode::ClashMode),
    Inbounds(Box<[String]>),
    IpVersion(u8),
    Networks(Box<[Network]>),
    AuthUsers(Box<[String]>),
    Protocols(Box<[SniffedProtocol]>),
    Domains(DomainIndex),
    Succinct(Box<SuccinctSet>),
    DomainRegex(Box<[Pattern]>),
    SourceIpCidr(Box<CidrIndex>),
    SourceIpIsPrivate,
    IpCidr(Box<CidrIndex>),
    Mmdbs(Box<[Mmdb]>),
    Asns(Asns),
    IpIsPrivate,
    IpAcceptAny,
    ResponseRcode(u16),
    /// A DNS response's records, in one of its sections (0 answers, 1
    /// authorities, 2 additionals): any of them.
    ResponseRecords(u8, Box<[hickory_proto::rr::Record]>),
    SourcePorts(Box<[(u16, u16)]>),
    Ports(Box<[(u16, u16)]>),
    ProcessNames(Box<[String]>),
    ProcessPaths(Box<[String]>),
    ProcessPathRegex(Box<[Pattern]>),
    ProcessNameRegex(Box<[Pattern]>),
    PackageNames(Box<[String]>),
    PackageNameRegex(Box<[Pattern]>),
    ProcessUsers(Box<[String]>),
    ProcessUserIds(Box<[i32]>),
    HttpUserAgent(Box<[Pattern]>),
    UrlRegex(Box<[Pattern]>),
    QueryTypes(Box<[u16]>),
    PreferredBy(Box<[String]>),
    SourceMacs(Box<[String]>),
    SourceHostnames(Box<[String]>),
    Network(Box<NetworkConditions>),
}

impl Item {
    /// Whether it is on the destination given as IPs.
    fn on_ips(&self) -> bool {
        matches!(
            self,
            Item::IpCidr(_)
                | Item::Mmdbs(_)
                | Item::Asns(_)
                | Item::IpIsPrivate
                | Item::IpAcceptAny
        )
    }

    fn on_domains(&self) -> bool {
        matches!(
            self,
            Item::Domains(_) | Item::Succinct(_) | Item::DomainRegex(_)
        )
    }
}

impl Conditions {
    /// Compiles the conditions of the default rule `rule`, found at
    /// `path`, with what a binary rule-set gives in `extras`.
    pub(crate) fn compile(
        rule: &model::Rule,
        extras: Extras,
        path: &str,
        ctx: &mut Context,
    ) -> Result<Self> {
        let field = |f: &str| at(path, f);
        let mut domains = DomainIndex::default();
        for d in &rule.domain {
            domains.insert(DomainKind::Full, d);
        }
        for d in &rule.domain_suffix {
            domains.insert(DomainKind::Suffix, d);
        }
        for d in &rule.domain_keyword {
            domains.insert(DomainKind::Keyword, d);
        }
        for code in &rule.geosite {
            for (kind, d) in external_rule::geosite(code, ctx.env)
                .map_err(|e| anyhow!("{}: {}", field("geosite"), e))?
            {
                domains.insert(kind, &d);
            }
        }
        let mut mmdbs: Vec<external_rule::Mmdb> =
            rule.geoip.iter().map(|c| external_rule::geoip(c)).collect();
        for filter in &rule.external {
            match external_rule::load(filter, ctx.env)
                .map_err(|e| anyhow!("{}: {}", field("external"), e))?
            {
                External::Mmdb(mmdb) => mmdbs.push(mmdb),
                External::Domains(list) => {
                    for (kind, d) in list {
                        domains.insert(kind, &d);
                    }
                }
            }
        }
        let mmdbs = mmdbs
            .into_iter()
            .map(|mmdb| {
                let reader = open_mmdb(ctx.env, &mmdb.file)
                    .map_err(|e| anyhow!("{}: {}", field("geoip"), e))?;
                Ok(Mmdb {
                    reader,
                    country_code: mmdb.country_code.to_ascii_uppercase(),
                })
            })
            .collect::<Result<_>>()?;

        let asns = match rule.ip_asn.is_empty() {
            true => None,
            false => {
                let mut numbers = rule.ip_asn.to_vec();
                numbers.sort_unstable();
                numbers.dedup();
                Some(Asns {
                    reader: open_mmdb(ctx.env, ASN_FILE)
                        .map_err(|e| anyhow!("{}: {}", field("ip_asn"), e))?,
                    numbers,
                })
            }
        };

        #[cfg(feature = "rule-set")]
        let rule_sets = rule
            .rule_set
            .iter()
            .map(|tag| ctx.rule_sets.get(tag).map(|set| (tag.as_str().into(), set)))
            .collect::<Result<_>>()
            .map_err(|e| anyhow!("{}: {}", field("rule_set"), e))?;
        #[cfg(not(feature = "rule-set"))]
        if let Some(tag) = rule.rule_set.first() {
            ctx.rule_sets
                .get(tag)
                .map_err(|e| anyhow!("{}: {}", field("rule_set"), e))?;
        }

        for (name, set) in [
            ("process_name", !rule.process_name.is_empty()),
            ("process_path", !rule.process_path.is_empty()),
            ("process_path_regex", !rule.process_path_regex.is_empty()),
            ("process_name_regex", !rule.process_name_regex.is_empty()),
        ] {
            if set {
                process_known(&field(name), PROCESS_COMPILED, PROCESS_KNOWN)?;
            }
        }
        // Who opened a connection only the host tells (Android's
        // VpnService); without it, these never match, so they are errors.
        let host_tells = ctx
            .env
            .host
            .platform
            .as_ref()
            .is_some_and(|p| p.finds_connection_owner());
        for (name, set) in [
            ("package_name", !rule.package_name.is_empty()),
            ("package_name_regex", !rule.package_name_regex.is_empty()),
            ("user", !rule.user.is_empty() && !USER_KNOWN),
            ("user_id", !rule.user_id.is_empty() && !USER_KNOWN),
        ] {
            if set && !host_tells {
                return Err(anyhow!(
                    "{}: sail tells who opened a connection only from a host that finds it \
                     (find_connection_owner, on Android)",
                    field(name)
                ));
            }
        }
        let ip_version = match rule.ip_version {
            None => None,
            Some(v @ (4 | 6)) => Some(v),
            Some(v) => return Err(anyhow!("{}: 4 or 6, not {}", field("ip_version"), v)),
        };

        let cidrs = |strings: &[String], ranges: &Option<Vec<(IpAddr, IpAddr)>>, name: &str| {
            match ranges {
                Some(ranges) => CidrIndex::from_ranges(ranges),
                None => CidrIndex::new(strings),
            }
            .map_err(|e| anyhow!("{}: {}", field(name), e))
        };
        let ports = |ports: &[u16], ranges: &[String], name: &str| {
            ports
                .iter()
                .map(|&p| Ok((p, p)))
                .chain(ranges.iter().map(|r| port_range(r)))
                .collect::<Result<Vec<_>>>()
                .map_err(|e| anyhow!("{}: {}", field(name), e))
        };
        let records = |texts: &[String], name: &str| {
            texts
                .iter()
                .enumerate()
                .map(|(i, text)| {
                    crate::app::dns::parse_record(text)
                        .map_err(|e| anyhow!("{}[{}]: {}", field(name), i, e))
                })
                .collect::<Result<Vec<_>>>()
        };
        let parts = Parts {
            inbounds: rule.inbound.to_vec(),
            ip_version,
            networks: rule
                .network
                .iter()
                .map(|net| match net.to_ascii_lowercase().as_str() {
                    "tcp" => Ok(Network::Tcp),
                    "udp" => Ok(Network::Udp),
                    _ => Err(anyhow!("{}: unknown network \"{}\"", field("network"), net)),
                })
                .collect::<Result<_>>()?,
            auth_users: rule.auth_user.to_vec(),
            protocols: rule
                .protocol
                .iter()
                .map(|name| sniffed_protocol(&field("protocol"), name))
                .collect::<Result<_>>()?,
            domains,
            succinct: extras.succinct,
            domain_regex: patterns(&field("domain_regex"), &rule.domain_regex)?,
            source_ip_cidr: cidrs(
                &rule.source_ip_cidr,
                &extras.source_ip_ranges,
                "source_ip_cidr",
            )?,
            source_ip_is_private: rule.source_ip_is_private,
            ip_cidr: cidrs(&rule.ip_cidr, &extras.ip_ranges, "ip_cidr")?,
            mmdbs,
            asns,
            ip_is_private: rule.ip_is_private,
            ip_accept_any: rule.ip_accept_any,
            response_rcode: rule.response_rcode,
            response_answer: records(&rule.response_answer, "response_answer")?,
            response_ns: records(&rule.response_ns, "response_ns")?,
            response_extra: records(&rule.response_extra, "response_extra")?,
            response: rule.match_response.clone(),
            source_ports: ports(
                &rule.source_port,
                &rule.source_port_range,
                "source_port_range",
            )?,
            ports: ports(&rule.port, &rule.port_range, "port_range")?,
            process_names: rule.process_name.to_vec(),
            process_paths: rule.process_path.to_vec(),
            process_path_regex: patterns(&field("process_path_regex"), &rule.process_path_regex)?,
            process_name_regex: patterns(&field("process_name_regex"), &rule.process_name_regex)?,
            package_names: rule.package_name.to_vec(),
            package_name_regex: patterns(&field("package_name_regex"), &rule.package_name_regex)?,
            process_users: rule.user.to_vec(),
            process_user_ids: rule.user_id.to_vec(),
            http_user_agent: patterns(
                &field("http_user_agent"),
                &rule
                    .http_user_agent
                    .iter()
                    .map(|p| user_agent_regex(p))
                    .collect::<Vec<_>>(),
            )?,
            url_regex: patterns(&field("url_regex"), &rule.url_regex)?,
            clash_mode: rule
                .clash_mode
                .clone()
                .map(|mode| (mode, ctx.env.clash_mode.clone())),
            query_types: if extras.query_types.is_empty() {
                rule.query_type
                    .iter()
                    .map(query_type)
                    .collect::<Result<_>>()
                    .map_err(|e| anyhow!("{}: {}", field("query_type"), e))?
            } else {
                extras.query_types
            },
            preferred_by: rule.preferred_by.to_vec(),
            source_macs: rule
                .source_mac_address
                .iter()
                .map(|m| normalized_mac(m))
                .collect(),
            source_hostnames: rule.source_hostname.to_vec(),
            network: NetworkConditions::compile(rule, path)?,
            #[cfg(feature = "rule-set")]
            rule_sets,
            #[cfg(feature = "rule-set")]
            ip_match_source: rule.rule_set_ip_cidr_match_source,
            no_resolve: rule.no_resolve,
            invert: rule.invert,
        };
        Ok(Conditions::keeping(parts))
    }

    /// The conditions `parts` has, each kept as an item in its order.
    fn keeping(parts: Parts) -> Self {
        fn list<T>(v: Vec<T>, item: fn(Box<[T]>) -> Item, items: &mut Vec<Item>) {
            if !v.is_empty() {
                items.push(item(v.into_boxed_slice()));
            }
        }
        let p = parts;
        let mut items = Vec::new();
        if let Some((wanted, mode)) = p.clash_mode {
            items.push(Item::ClashMode(wanted, mode));
        }
        list(p.inbounds, Item::Inbounds, &mut items);
        if let Some(v) = p.ip_version {
            items.push(Item::IpVersion(v));
        }
        list(p.networks, Item::Networks, &mut items);
        list(p.auth_users, Item::AuthUsers, &mut items);
        list(p.protocols, Item::Protocols, &mut items);
        if !p.domains.is_empty() {
            items.push(Item::Domains(p.domains));
        }
        if let Some(set) = p.succinct {
            items.push(Item::Succinct(Box::new(set)));
        }
        list(p.domain_regex, Item::DomainRegex, &mut items);
        if !p.source_ip_cidr.is_empty() {
            items.push(Item::SourceIpCidr(Box::new(p.source_ip_cidr)));
        }
        if p.source_ip_is_private {
            items.push(Item::SourceIpIsPrivate);
        }
        if !p.ip_cidr.is_empty() {
            items.push(Item::IpCidr(Box::new(p.ip_cidr)));
        }
        list(p.mmdbs, Item::Mmdbs, &mut items);
        if let Some(asns) = p.asns {
            items.push(Item::Asns(asns));
        }
        if p.ip_is_private {
            items.push(Item::IpIsPrivate);
        }
        if p.ip_accept_any {
            items.push(Item::IpAcceptAny);
        }
        if let Some(rcode) = p.response_rcode {
            items.push(Item::ResponseRcode(rcode));
        }
        for (section, records) in [p.response_answer, p.response_ns, p.response_extra]
            .into_iter()
            .enumerate()
        {
            if !records.is_empty() {
                items.push(Item::ResponseRecords(
                    section as u8,
                    records.into_boxed_slice(),
                ));
            }
        }
        list(p.source_ports, Item::SourcePorts, &mut items);
        list(p.ports, Item::Ports, &mut items);
        list(p.process_names, Item::ProcessNames, &mut items);
        list(p.process_paths, Item::ProcessPaths, &mut items);
        list(p.process_path_regex, Item::ProcessPathRegex, &mut items);
        list(p.process_name_regex, Item::ProcessNameRegex, &mut items);
        list(p.package_names, Item::PackageNames, &mut items);
        list(p.package_name_regex, Item::PackageNameRegex, &mut items);
        list(p.process_users, Item::ProcessUsers, &mut items);
        list(p.process_user_ids, Item::ProcessUserIds, &mut items);
        list(p.http_user_agent, Item::HttpUserAgent, &mut items);
        list(p.url_regex, Item::UrlRegex, &mut items);
        list(p.query_types, Item::QueryTypes, &mut items);
        list(p.preferred_by, Item::PreferredBy, &mut items);
        list(p.source_macs, Item::SourceMacs, &mut items);
        list(p.source_hostnames, Item::SourceHostnames, &mut items);
        if !p.network.is_empty() {
            items.push(Item::Network(Box::new(p.network)));
        }
        let mut conditions = Conditions {
            items: items.into_boxed_slice(),
            response: p.response,
            #[cfg(feature = "rule-set")]
            rule_sets: p.rule_sets,
            #[cfg(feature = "rule-set")]
            ip_match_source: p.ip_match_source,
            no_resolve: p.no_resolve,
            invert: p.invert,
            empty: false,
        };
        conditions.empty = conditions.items.is_empty() && !conditions.has_rule_sets();
        conditions
    }

    /// Whether it has no conditions, and so matches everything.
    #[cfg(feature = "rule-set")]
    pub(crate) fn is_unconditional(&self) -> bool {
        self.empty
    }

    fn has_rule_sets(&self) -> bool {
        #[cfg(feature = "rule-set")]
        return !self.rule_sets.is_empty();
        #[cfg(not(feature = "rule-set"))]
        false
    }

    /// How many domains it names; `None` when it matches addresses too.
    fn domain_count(&self) -> Option<usize> {
        let mut count = 0;
        for item in self.items.iter() {
            match item {
                Item::Domains(d) => count += d.len(),
                Item::Succinct(s) => count += s.len(),
                Item::DomainRegex(r) => count += r.len(),
                Item::SourceIpCidr(_) | Item::SourceIpIsPrivate => return None,
                item if item.on_ips() => return None,
                _ => {}
            }
        }
        Some(count)
    }

    /// The destination `ip_cidr` ranges it has.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    fn ip_cidr_ranges(&self) -> impl Iterator<Item = (IpAddr, IpAddr)> + '_ {
        self.items
            .iter()
            .filter_map(|item| match item {
                Item::IpCidr(c) => Some(c.ranges()),
                _ => None,
            })
            .flatten()
    }

    /// The tag of the first of its narrow rule-sets that `facts` matches.
    #[cfg(feature = "rule-set")]
    fn narrow_rule_set(&self, facts: &Facts) -> Option<std::sync::Arc<str>> {
        if self.invert {
            return None;
        }
        self.rule_sets.iter().find_map(|(tag, set)| {
            let set = set.load();
            (set.is_narrow() && set.matches(facts, self.ip_match_source)).then(|| tag.clone())
        })
    }

    /// What its conditions, and its rule-sets' as they are now, need
    /// learnt of a connection; its own `ip_cidr` looks at the source when
    /// `ip_match_source`, and needs nothing resolved then.
    fn needs(&self, ip_match_source: bool) -> Needs {
        let has = |f: fn(&Item) -> bool| self.items.iter().any(f);
        let ip = if ip_match_source {
            has(|i| matches!(i, Item::Mmdbs(_) | Item::Asns(_) | Item::IpIsPrivate))
        } else {
            self.has_ip_cidr()
        };
        #[allow(unused_mut)]
        let mut needs = Needs {
            ip,
            domain: self.has_domains(),
            sniff: has(|i| {
                matches!(
                    i,
                    Item::Protocols(_) | Item::HttpUserAgent(_) | Item::UrlRegex(_)
                )
            }),
            network: has(|i| matches!(i, Item::Network(n) if n.needs())),
            owner: has(|i| {
                matches!(
                    i,
                    Item::ProcessNames(_)
                        | Item::ProcessPaths(_)
                        | Item::ProcessPathRegex(_)
                        | Item::ProcessNameRegex(_)
                        | Item::PackageNames(_)
                        | Item::PackageNameRegex(_)
                        | Item::ProcessUsers(_)
                        | Item::ProcessUserIds(_)
                )
            }),
            process: has(|i| {
                matches!(
                    i,
                    Item::ProcessNames(_)
                        | Item::ProcessPaths(_)
                        | Item::ProcessPathRegex(_)
                        | Item::ProcessNameRegex(_)
                )
            }),
        };
        #[cfg(feature = "rule-set")]
        for (_, set) in &self.rule_sets {
            needs = needs.or(set.load().needs(self.ip_match_source));
        }
        needs.resolving(self.no_resolve)
    }

    /// Whether it has conditions on a destination address given as IPs.
    pub(crate) fn has_ip_cidr(&self) -> bool {
        self.items.iter().any(Item::on_ips)
    }

    fn has_domains(&self) -> bool {
        self.items.iter().any(Item::on_domains)
    }

    /// Which things it has conditions on, and which of them match; `None`
    /// when a condition on anything else does not. Its `ip_cidr` matches
    /// the source when `ip_match_source`, the other conditions on IPs the
    /// destination's, counted with the source then.
    pub(crate) fn evaluate(&self, facts: &Facts, ip_match_source: bool) -> Option<Groups> {
        let mut groups = Groups::default();
        let source_ip = facts.source().map(|s| s.ip());
        let ips = facts.ips();
        let ip_group = if ip_match_source {
            Groups::SOURCE_ADDRESS
        } else {
            Groups::DESTINATION_ADDRESS
        };
        let domain = facts.domain();
        for item in self.items.iter() {
            let holds = match item {
                Item::SourceIpCidr(c) => {
                    groups.require(
                        Groups::SOURCE_ADDRESS,
                        source_ip.is_some_and(|ip| c.contains(ip)),
                    );
                    true
                }
                Item::SourceIpIsPrivate => {
                    groups.require(Groups::SOURCE_ADDRESS, source_ip.is_some_and(is_private));
                    true
                }
                Item::IpCidr(c) => {
                    let matched = if ip_match_source {
                        source_ip.is_some_and(|ip| c.contains(ip))
                    } else {
                        ips.iter().any(|&ip| c.contains(ip))
                    };
                    groups.require(ip_group, matched);
                    true
                }
                Item::Mmdbs(m) => {
                    groups.require(
                        ip_group,
                        ips.iter().any(|&ip| m.iter().any(|m| m.contains(ip))),
                    );
                    true
                }
                Item::Asns(a) => {
                    groups.require(ip_group, ips.iter().any(|&ip| a.contains(ip)));
                    true
                }
                Item::IpIsPrivate => {
                    groups.require(ip_group, ips.iter().any(|&ip| is_private(ip)));
                    true
                }
                // Any address of the destination; with the source looked at,
                // it holds the group but matches nothing there.
                Item::IpAcceptAny => {
                    groups.require(ip_group, !ip_match_source && !ips.is_empty());
                    true
                }
                Item::SourcePorts(ranges) => {
                    let port = facts.source().map(|s| s.port());
                    groups.require(
                        Groups::SOURCE_PORT,
                        port.is_some_and(|p| in_ranges(ranges, p)),
                    );
                    true
                }
                Item::Domains(d) => {
                    groups.require(
                        Groups::DESTINATION_ADDRESS,
                        domain.is_some_and(|x| d.matches(x)),
                    );
                    true
                }
                Item::Succinct(set) => {
                    groups.require(
                        Groups::DESTINATION_ADDRESS,
                        domain.is_some_and(|x| set.matches(x)),
                    );
                    true
                }
                Item::DomainRegex(r) => {
                    groups.require(
                        Groups::DESTINATION_ADDRESS,
                        domain.is_some_and(|x| r.iter().any(|r| r.is_match(x))),
                    );
                    true
                }
                Item::Ports(ranges) => {
                    groups.require(Groups::DESTINATION_PORT, in_ranges(ranges, facts.port()));
                    true
                }
                Item::Inbounds(v) => v.contains(&facts.inbound),
                Item::IpVersion(v) => facts.ip_version == Some(*v),
                Item::Networks(v) => v.contains(&facts.network()),
                Item::AuthUsers(v) => facts
                    .user
                    .as_ref()
                    .is_some_and(|user| v.iter().any(|u| **u == **user.name())),
                Item::Protocols(v) => facts.protocol.is_some_and(|p| v.contains(&p)),
                Item::ProcessNames(v) => facts
                    .process_name()
                    .is_some_and(|name| v.iter().any(|p| p == name)),
                Item::ProcessPaths(v) => facts
                    .process_path
                    .as_deref()
                    .is_some_and(|path| v.iter().any(|p| p == path)),
                Item::ProcessPathRegex(v) => facts
                    .process_path
                    .as_deref()
                    .is_some_and(|path| v.iter().any(|r| r.is_match(path))),
                Item::ProcessNameRegex(v) => facts
                    .process_name()
                    .is_some_and(|name| v.iter().any(|r| r.is_match(name))),
                Item::PackageNames(v) => facts
                    .owner
                    .as_ref()
                    .is_some_and(|o| o.packages.iter().any(|p| v.contains(p))),
                Item::PackageNameRegex(v) => facts
                    .owner
                    .as_ref()
                    .is_some_and(|o| o.packages.iter().any(|p| v.iter().any(|r| r.is_match(p)))),
                Item::ProcessUsers(v) => facts
                    .owner
                    .as_ref()
                    .is_some_and(|o| o.user.as_ref().is_some_and(|u| v.contains(u))),
                Item::ProcessUserIds(v) => facts
                    .owner
                    .as_ref()
                    .and_then(|o| i32::try_from(o.uid).ok())
                    .is_some_and(|uid| v.contains(&uid)),
                Item::HttpUserAgent(v) => facts
                    .user_agent()
                    .is_some_and(|ua| v.iter().any(|r| r.is_match(ua))),
                Item::UrlRegex(v) => facts
                    .url()
                    .is_some_and(|url| v.iter().any(|r| r.is_match(url))),
                Item::QueryTypes(v) => facts.query_type().is_some_and(|t| v.contains(&t)),
                Item::PreferredBy(v) => facts
                    .preferred_by
                    .as_ref()
                    .is_some_and(|tags| v.iter().any(|t| tags.contains(t))),
                Item::SourceMacs(v) => facts
                    .neighbor
                    .as_ref()
                    .and_then(|n| n.mac_string())
                    .is_some_and(|mac| v.contains(&mac)),
                Item::SourceHostnames(v) => facts
                    .neighbor
                    .as_ref()
                    .and_then(|n| n.hostname.as_ref())
                    .is_some_and(|name| v.contains(name)),
                Item::ResponseRcode(c) => facts.rcode == Some(*c),
                Item::ResponseRecords(section, wanted) => {
                    facts.response.as_ref().is_some_and(|m| {
                        let records = match section {
                            0 => &m.answers,
                            1 => &m.authorities,
                            _ => &m.additionals,
                        };
                        wanted
                            .iter()
                            .any(|w| records.iter().any(|r| crate::app::dns::same_record(w, r)))
                    })
                }
                Item::ClashMode(wanted, mode) => mode.is(wanted),
                Item::Network(n) => n.matches(facts.network_state.as_deref()),
            };
            if !holds {
                return None;
            }
        }
        Some(groups)
    }

    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        // On a response it names, which it matches only inverted without,
        // as in sing-box.
        let switched;
        let facts = match &self.response {
            None => facts,
            Some(r) => match facts.of_response(r) {
                Some(f) => {
                    switched = f;
                    &switched
                }
                None => return self.invert,
            },
        };
        if self.empty {
            return true;
        }
        let matched = match self.evaluate(facts, ip_match_source) {
            None => false,
            #[cfg(feature = "rule-set")]
            Some(groups) if !self.rule_sets.is_empty() => self
                .rule_sets
                .iter()
                .any(|(_, set)| set.load().matches_with(groups, facts, self.ip_match_source)),
            Some(groups) => groups.done(),
        };
        matched != self.invert
    }
}

fn in_ranges(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| (start..=end).contains(&port))
}

/// The conditions of a routing or DNS rule, as they match.
pub(crate) struct Matcher(Condition);

impl Matcher {
    /// Compiles the conditions of `rule`; errors name the field at fault.
    #[cfg(test)]
    pub fn new(
        rule: &model::Rule,
        env: &RuntimeEnv,
        rule_sets: &super::rule_set::RuleSets,
    ) -> Result<Self> {
        Self::at(rule, "", env, rule_sets)
    }

    /// Compiles the conditions of `rule`, found at `path`, which errors
    /// name.
    pub fn at(
        rule: &model::Rule,
        path: &str,
        env: &RuntimeEnv,
        rule_sets: &super::rule_set::RuleSets,
    ) -> Result<Self> {
        let mut ctx = Context { env, rule_sets };
        Condition::compile(rule, path, &mut ctx).map(Matcher)
    }

    pub fn matches(&self, facts: &Facts) -> bool {
        self.0.matches(facts, false)
    }

    /// What its conditions need learnt of a connection, its rule-sets'
    /// as they are now.
    pub fn needs(&self) -> Needs {
        self.0.needs(false)
    }

    /// Whether it may need the network the host is on: it does now, or it
    /// names rule-sets, whose rules a download may replace with some that
    /// do.
    pub fn may_need_network(&self) -> bool {
        self.needs().network || self.0.names_rule_sets()
    }

    /// The tag of a narrow rule-set (see `RuleSet::is_narrow`) the rule
    /// names that `facts`, which the rule matches, match: the site's
    /// group, for the smart group.
    pub fn narrow_rule_set(&self, facts: &Facts) -> Option<std::sync::Arc<str>> {
        #[cfg(feature = "rule-set")]
        return self.0.narrow_rule_set(facts);
        #[cfg(not(feature = "rule-set"))]
        {
            let _ = facts;
            None
        }
    }
}

/// `mac` as sing-box compares it: Go's net.ParseMAC then String(), lower
/// case and colon-separated, for the forms `01:23:45:67:89:ab`,
/// `01-23-45-67-89-ab` and `0123.4567.89ab`; kept as written otherwise, as
/// sing-box keeps it, matching nothing. Unlike Go, the 8-byte (EUI-64) and
/// 20-byte (IPoIB) forms are kept as written too: a LAN device's MAC here
/// has 6 bytes.
fn normalized_mac(mac: &str) -> String {
    let hex = |s: &str| u8::from_str_radix(s, 16).ok().filter(|_| s.len() == 2);
    let groups: Option<Vec<u8>> = if mac.contains(':') || mac.contains('-') {
        let sep = if mac.contains(':') { ':' } else { '-' };
        mac.split(sep).map(hex).collect()
    } else if mac.contains('.') {
        mac.split('.')
            .filter(|g| g.len() == 4)
            .flat_map(|g| [hex(&g[..2]), hex(&g[2..])])
            .collect::<Option<Vec<u8>>>()
            .filter(|_| mac.split('.').count() == 3 && mac.split('.').all(|g| g.len() == 4))
    } else {
        None
    };
    match groups {
        Some(bytes) if bytes.len() == 6 => bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
        _ => mac.to_string(),
    }
}

/// A record type as sing-box writes one: its name, or its number.
pub(crate) fn query_type(value: &serde_json::Value) -> Result<u16> {
    use std::str::FromStr;
    match value {
        serde_json::Value::String(name) => {
            hickory_proto::rr::RecordType::from_str(&name.to_ascii_uppercase())
                .map(u16::from)
                .map_err(|_| anyhow!("unknown record type \"{}\"", name))
        }
        serde_json::Value::Number(n) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| anyhow!("invalid record type {}", n)),
        other => Err(anyhow!("invalid record type {}", other)),
    }
}

/// An inclusive range as sing-box writes it: `1000:2000`, or open at one
/// end, `:1024`, `8000:`.
pub(crate) fn port_range(value: &str) -> Result<(u16, u16)> {
    let invalid = || anyhow!("invalid port range \"{}\"", value);
    let (start, end) = value.split_once(':').ok_or_else(invalid)?;
    let bound = |s: &str, open: u16| match s.trim() {
        "" => Ok(open),
        s => s.parse::<u16>().map_err(|_| invalid()),
    };
    let (start, end) = (bound(start, 0)?, bound(end, u16::MAX)?);
    if start > end || value.trim() == ":" {
        return Err(invalid());
    }
    Ok((start, end))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn matcher(rule: model::Rule) -> Matcher {
        Matcher::new(&rule, &RuntimeEnv::default(), &Default::default()).unwrap()
    }

    fn to(destination: SocksAddr) -> Facts {
        Facts::new(
            &Session {
                destination,
                ..Default::default()
            },
            &[],
        )
    }

    fn domain(d: &str, port: u16) -> Facts {
        to(SocksAddr::Domain(d.to_string(), port))
    }

    fn ip(ip: &str, port: u16) -> Facts {
        to(SocksAddr::from((ip.parse::<IpAddr>().unwrap(), port)))
    }

    #[test]
    fn domains_match_by_kind() {
        let m = matcher(model::Rule {
            domain: vec!["exact.org".into()].into(),
            domain_suffix: vec!["google.com".into(), ".cn".into()].into(),
            domain_keyword: vec!["tube".into()].into(),
            ..Default::default()
        });
        assert!(m.matches(&domain("exact.org", 80)));
        assert!(!m.matches(&domain("www.exact.org", 80)));
        assert!(m.matches(&domain("google.com", 80)));
        assert!(m.matches(&domain("video.GOOGLE.com", 80)));
        assert!(!m.matches(&domain("gle.com", 80)));
        assert!(!m.matches(&domain("agoogle.com", 80)));
        assert!(m.matches(&domain("baidu.cn", 80)));
        assert!(m.matches(&domain("youtube.com", 80)));
        assert!(!m.matches(&ip("1.1.1.1", 80)));
    }

    #[test]
    fn addresses_match_merged_ranges() {
        let m = matcher(model::Rule {
            ip_cidr: vec![
                "192.168.1.0/24".into(),
                "192.168.0.0/16".into(),
                "10.0.0.1/32".into(),
                "fd00::/8".into(),
            ]
            .into(),
            ..Default::default()
        });
        assert!(m.matches(&ip("192.168.1.100", 80)));
        assert!(m.matches(&ip("192.168.200.1", 80)));
        assert!(!m.matches(&ip("192.169.0.1", 80)));
        assert!(m.matches(&ip("10.0.0.1", 80)));
        assert!(!m.matches(&ip("10.0.0.2", 80)));
        assert!(m.matches(&ip("fd12::1", 80)));
        assert!(m.matches(&ip("::ffff:10.0.0.1", 80)));
        assert!(!m.matches(&domain("example.com", 80)));
    }

    /// As in sing-box: `example.com` matches it and its subdomains,
    /// `.example.com` its subdomains alone.
    #[test]
    fn a_suffix_with_a_leading_dot_matches_subdomains_only() {
        let m = matcher(model::Rule {
            domain_suffix: vec![".dot.example".into(), "plain.example".into()].into(),
            ..Default::default()
        });
        assert!(!m.matches(&domain("dot.example", 80)));
        assert!(m.matches(&domain("a.dot.example", 80)));
        assert!(m.matches(&domain("plain.example", 80)));
        assert!(m.matches(&domain("a.plain.example", 80)));
        assert!(!m.matches(&domain("xplain.example", 80)));
    }

    /// As in sing-box: a domain condition and an address condition are
    /// alternatives, not both required.
    #[test]
    fn destination_conditions_are_alternatives() {
        let m = matcher(model::Rule {
            domain_suffix: vec!["example.com".into()].into(),
            ip_cidr: vec!["10.0.0.0/8".into()].into(),
            port: vec![443].into(),
            ..Default::default()
        });
        assert!(m.matches(&domain("example.com", 443)));
        assert!(m.matches(&ip("10.1.2.3", 443)));
        assert!(!m.matches(&ip("10.1.2.3", 80)));
        let resolved = Facts::new(
            &Session {
                destination: SocksAddr::Domain("other.org".into(), 443),
                ..Default::default()
            },
            &["10.0.0.9".parse().unwrap()],
        );
        assert!(m.matches(&resolved));
    }

    #[test]
    fn ports_networks_and_inbounds() {
        let m = matcher(model::Rule {
            port: vec![22].into(),
            port_range: vec!["1024:5000".into()].into(),
            network: vec!["tcp".into()].into(),
            inbound: vec!["socks".into()].into(),
            ..Default::default()
        });
        let mut sess = Session {
            destination: SocksAddr::Domain("a.com".into(), 2000),
            inbound_tag: "socks".into(),
            ..Default::default()
        };
        assert!(m.matches(&Facts::new(&sess, &[])));
        sess.destination = SocksAddr::Domain("a.com".into(), 22);
        assert!(m.matches(&Facts::new(&sess, &[])));
        sess.destination = SocksAddr::Domain("a.com".into(), 5001);
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.destination = SocksAddr::Domain("a.com".into(), 22);
        sess.network = Network::Udp;
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.network = Network::Tcp;
        sess.inbound_tag = "http".into();
        assert!(!m.matches(&Facts::new(&sess, &[])));
    }

    #[test]
    fn users_match_by_name() {
        let m = matcher(model::Rule {
            auth_user: vec!["alice".into()].into(),
            ..Default::default()
        });
        let mut sess = Session::default();
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.user = Some(crate::user::UserRef::unbound("bob"));
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.user = Some(crate::user::UserRef::unbound("alice"));
        assert!(m.matches(&Facts::new(&sess, &[])));
    }

    #[test]
    fn invalid_values_are_errors() {
        for (rule, message) in [
            (
                model::Rule {
                    ip_cidr: vec!["10.0.0.0/33".into()].into(),
                    ..Default::default()
                },
                "ip_cidr: invalid CIDR",
            ),
            (
                model::Rule {
                    network: vec!["sctp".into()].into(),
                    ..Default::default()
                },
                "network: unknown network",
            ),
        ] {
            let err = Matcher::new(&rule, &RuntimeEnv::default(), &Default::default())
                .err()
                .unwrap();
            assert!(err.to_string().starts_with(message), "{}", err);
        }
        for bad in ["22", "22:21", ":", "22-23", "22:abc", "22:23:24"] {
            assert!(port_range(bad).is_err(), "{}", bad);
        }
        assert_eq!(port_range("22:22").unwrap(), (22, 22));
        assert_eq!(port_range(":1024").unwrap(), (0, 1024));
        assert_eq!(port_range("8000:").unwrap(), (8000, u16::MAX));
    }

    /// `source_mac_address` and `source_hostname` match the LAN device the
    /// session was found to come from, the MAC as Go's net.ParseMAC writes
    /// it, whatever form the rule gives; nothing matches without one.
    #[test]
    fn neighbor_conditions_match_the_source_s_device() {
        let device = |mac: Option<[u8; 6]>, hostname: Option<&str>| Session {
            neighbor: Some(std::sync::Arc::new(crate::net::neighbor::Neighbor {
                mac,
                hostname: hostname.map(str::to_string),
            })),
            ..Default::default()
        };
        let nas = device(Some([0x02, 0xab, 0, 0, 0, 0x0a]), Some("nas"));
        for written in ["02:ab:00:00:00:0a", "02-AB-00-00-00-0A", "02ab.0000.000a"] {
            let m = json(serde_json::json!({ "source_mac_address": written }));
            assert!(m.matches(&Facts::new(&nas, &[])), "{}", written);
        }
        let m = json(serde_json::json!({ "source_mac_address": ["02:ab:00:00:00:0b"] }));
        assert!(!m.matches(&Facts::new(&nas, &[])));
        let m = json(serde_json::json!({ "source_hostname": ["nas", "tv"] }));
        assert!(m.matches(&Facts::new(&nas, &[])));
        // Compared as written, as sing-box compares it.
        let m = json(serde_json::json!({ "source_hostname": "NAS" }));
        assert!(!m.matches(&Facts::new(&nas, &[])));
        // No device known, or no name for it: no match.
        let m = json(serde_json::json!({ "source_hostname": "nas" }));
        assert!(!m.matches(&Facts::new(&Session::default(), &[])));
        assert!(!m.matches(&Facts::new(&device(Some([2, 0, 0, 0, 0, 1]), None), &[])));
        // Both: each must hold.
        let m = json(serde_json::json!({
            "source_mac_address": "02:ab:00:00:00:0a", "source_hostname": "tv" }));
        assert!(!m.matches(&Facts::new(&nas, &[])));
    }

    /// Go's net.ParseMAC and String(), for the 6-byte forms; anything else
    /// as written.
    #[test]
    fn macs_are_written_as_go_writes_them() {
        assert_eq!(normalized_mac("02:AB:00:00:00:0A"), "02:ab:00:00:00:0a");
        assert_eq!(normalized_mac("02-ab-00-00-00-0a"), "02:ab:00:00:00:0a");
        assert_eq!(normalized_mac("02ab.0000.000a"), "02:ab:00:00:00:0a");
        assert_eq!(normalized_mac("2:ab:0:0:0:a"), "2:ab:0:0:0:a");
        assert_eq!(normalized_mac("02:ab:00:00:00"), "02:ab:00:00:00");
        assert_eq!(normalized_mac("02ab.0000.000a.0000"), "02ab.0000.000a.0000");
        assert_eq!(normalized_mac("not a mac"), "not a mac");
    }

    /// A rule written as sing-box's JSON.
    fn json(rule: serde_json::Value) -> Matcher {
        let rule: model::Rule = serde_json::from_value(rule).unwrap();
        matcher(rule)
    }

    fn compile_err(rule: serde_json::Value) -> String {
        let rule: model::Rule = serde_json::from_value(rule).unwrap();
        let err = Matcher::at(
            &rule,
            "route.rules[3]",
            &RuntimeEnv::default(),
            &Default::default(),
        )
        .err()
        .unwrap();
        err.to_string()
    }

    /// A connection from `source` to `destination`.
    fn conn(source: &str, destination: &str) -> Facts {
        let destination = match destination.parse::<std::net::SocketAddr>() {
            Ok(addr) => SocksAddr::Ip(addr),
            Err(_) => {
                let (host, port) = destination.rsplit_once(':').unwrap();
                SocksAddr::Domain(host.into(), port.parse().unwrap())
            }
        };
        Facts::new(
            &Session {
                source: source.parse().unwrap(),
                destination,
                ..Default::default()
            },
            &[],
        )
    }

    #[test]
    fn source_conditions() {
        let m = json(serde_json::json!({
            "source_ip_cidr": "192.168.0.0/16", "source_port_range": "1000:2000"
        }));
        assert!(m.matches(&conn("192.168.1.2:1500", "1.1.1.1:80")));
        assert!(!m.matches(&conn("192.168.1.2:999", "1.1.1.1:80")));
        assert!(!m.matches(&conn("10.0.0.1:1500", "1.1.1.1:80")));
        let m = json(serde_json::json!({ "source_port": [53, 5353] }));
        assert!(m.matches(&conn("10.0.0.1:5353", "1.1.1.1:80")));
        assert!(!m.matches(&conn("10.0.0.1:5354", "1.1.1.1:80")));
        // Without a source, as for the DNS client's own queries, none
        // matches.
        assert!(!m.matches(&domain("a.com", 80)));
    }

    /// As sing's `IsPublicAddr` has it.
    #[test]
    fn private_addresses() {
        for (ip, private) in [
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("192.168.9.9", true),
            ("127.0.0.1", true),
            ("169.254.1.1", true),
            ("224.0.0.1", true),
            ("0.0.0.0", true),
            ("100.64.0.1", false),
            ("8.8.8.8", false),
            ("fd00::1", true),
            ("fe80::1", true),
            ("::1", true),
            ("ff02::1", true),
            ("::ffff:10.0.0.1", true),
            ("2001:4860::8888", false),
        ] {
            assert_eq!(is_private(ip.parse().unwrap()), private, "{}", ip);
        }
        let m = json(serde_json::json!({ "ip_is_private": true }));
        assert!(m.matches(&conn("8.8.8.8:1", "192.168.1.1:80")));
        assert!(!m.matches(&conn("192.168.1.1:1", "8.8.8.8:80")));
        // An address a domain resolved to counts.
        let resolved = Facts::new(
            &Session {
                destination: SocksAddr::Domain("lan.example".into(), 80),
                ..Default::default()
            },
            &["10.0.0.9".parse().unwrap()],
        );
        assert!(m.matches(&resolved));
        let m = json(serde_json::json!({ "source_ip_is_private": true }));
        assert!(m.matches(&conn("192.168.1.1:1", "8.8.8.8:80")));
        assert!(!m.matches(&conn("8.8.8.8:1", "192.168.1.1:80")));
    }

    #[test]
    fn ip_version_is_the_destination_s() {
        let v6 = json(serde_json::json!({ "ip_version": 6 }));
        let v4 = json(serde_json::json!({ "ip_version": 4 }));
        assert!(v6.matches(&conn("1.1.1.1:1", "[2001:db8::1]:80")));
        assert!(!v4.matches(&conn("1.1.1.1:1", "[2001:db8::1]:80")));
        assert!(v4.matches(&conn("1.1.1.1:1", "1.2.3.4:80")));
        assert!(v4.matches(&conn("1.1.1.1:1", "[::ffff:1.2.3.4]:80")));
        // A domain has no version.
        assert!(!v4.matches(&domain("a.com", 80)));
        assert!(!v6.matches(&domain("a.com", 80)));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn domain_regex_is_a_destination_address_condition() {
        let m = json(serde_json::json!({
            "domain_regex": "^ads?\\.", "ip_cidr": "10.0.0.0/8"
        }));
        assert!(m.matches(&domain("ad.example.com", 80)));
        assert!(m.matches(&domain("ADS.example.com", 80)));
        assert!(!m.matches(&domain("bad.example.com", 80)));
        assert!(m.matches(&ip("10.0.0.1", 80)));
        assert!(compile_err(serde_json::json!({ "domain_regex": "(" }))
            .starts_with("route.rules[3].domain_regex: \"(\""));
    }

    #[test]
    fn processes_match_as_sing_box_does() {
        let from = |path: &str| {
            Facts::new(
                &Session {
                    process_name: Some(path.into()),
                    ..Default::default()
                },
                &[],
            )
        };
        let m = json(serde_json::json!({ "process_name": "curl" }));
        assert!(m.matches(&from("/usr/bin/curl")));
        assert!(m.matches(&from("C:\\Tools\\curl")));
        assert!(!m.matches(&from("/usr/bin/curl2")));
        assert!(!m.matches(&Facts::new(&Session::default(), &[])));
        // An exact name, not a pattern.
        assert!(!json(serde_json::json!({ "process_name": "cu.l" })).matches(&from("/bin/curl")));
        let m = json(serde_json::json!({ "process_path": "/usr/bin/curl" }));
        assert!(m.matches(&from("/usr/bin/curl")));
        assert!(!m.matches(&from("/bin/curl")));
        if cfg!(feature = "regex") {
            // The name alone, as Mihomo's PROCESS-NAME-REGEX: not a directory.
            let m = json(serde_json::json!({ "process_name_regex": ".*telegram.*" }));
            assert!(m.matches(&from(
                "/Applications/Telegram.app/Contents/MacOS/telegram-desktop"
            )));
            assert!(m.matches(&from("C:\\Apps\\telegram.exe")));
            assert!(!m.matches(&from("/opt/telegram/bin/curl")));
            let m = json(serde_json::json!({ "process_path_regex": "^/usr/(local/)?bin/" }));
            assert!(m.matches(&from("/usr/local/bin/curl")));
            assert!(!m.matches(&from("/opt/curl")));
        }
    }

    /// A host that tells who opened a connection, as an Android app's does.
    struct Tells;

    impl crate::runtime::platform::Platform for Tells {
        fn log(&self, _: &str) {}

        fn finds_connection_owner(&self) -> bool {
            true
        }
    }

    #[test]
    fn apps_and_users_match_who_the_host_says_opened_it() {
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                platform: Some(crate::runtime::PlatformRef(std::sync::Arc::new(Tells))),
                ..Default::default()
            },
            ..Default::default()
        };
        let compile = |rule: serde_json::Value| {
            let rule: model::Rule = serde_json::from_value(rule).unwrap();
            Matcher::new(&rule, &env, &Default::default()).unwrap()
        };
        let opened_by = |uid: u32, user: Option<&str>, packages: &[&str]| {
            Facts::new(
                &Session {
                    owner: Some(std::sync::Arc::new(
                        crate::runtime::platform::ConnectionOwner {
                            uid,
                            user: user.map(str::to_owned),
                            packages: packages.iter().map(|p| p.to_string()).collect(),
                        },
                    )),
                    ..Default::default()
                },
                &[],
            )
        };
        let unknown = Facts::new(&Session::default(), &[]);
        // Any of the uid's packages, as sing-box's package_name.
        let m = compile(serde_json::json!({ "package_name": "com.example.b" }));
        assert!(m.matches(&opened_by(10123, None, &["com.example.a", "com.example.b"])));
        assert!(!m.matches(&opened_by(10123, None, &["com.example.a"])));
        assert!(!m.matches(&unknown));
        let m = compile(serde_json::json!({ "user_id": [10123, 0] }));
        assert!(m.matches(&opened_by(10123, None, &[])));
        assert!(!m.matches(&opened_by(10124, None, &[])));
        assert!(!m.matches(&unknown));
        let m = compile(serde_json::json!({ "user": "u0_a123" }));
        assert!(m.matches(&opened_by(10123, Some("u0_a123"), &[])));
        assert!(!m.matches(&opened_by(10123, None, &[])));
        if cfg!(feature = "regex") {
            let m = compile(serde_json::json!({ "package_name_regex": "^com\\.google\\." }));
            assert!(m.matches(&opened_by(10010, None, &["com.google.android.gms"])));
            assert!(!m.matches(&opened_by(10011, None, &["org.mozilla.firefox"])));
        }
    }

    #[test]
    fn what_the_platform_cannot_tell_is_refused() {
        assert_eq!(
            process_known("process_name", false, true)
                .unwrap_err()
                .to_string(),
            "process_name: not supported, rule-process-name is not compiled in"
        );
        assert!(process_known("rules[0].process_path", true, false)
            .unwrap_err()
            .to_string()
            .starts_with("rules[0].process_path: sail cannot tell which program"));
        let mut refused = vec![
            (
                serde_json::json!({ "package_name": "com.android.chrome" }),
                "route.rules[3].package_name: sail tells who opened a connection only from a host",
            ),
            (
                serde_json::json!({ "package_name_regex": "^com\\." }),
                "route.rules[3].package_name_regex: sail tells who opened a connection only from a host",
            ),
            (
                serde_json::json!({ "type": "logical", "mode": "or", "rules": [
                    { "port": 1 }, { "type": "logical", "mode": "and", "rules": [
                        { "port": 2 }, { "source_ip_cidr": "10.0.0.0/33" }
                    ] }
                ] }),
                "route.rules[3].rules[1].rules[1].source_ip_cidr: invalid CIDR",
            ),
            (
                serde_json::json!({ "source_port_range": "2:1" }),
                "route.rules[3].source_port_range: invalid port range",
            ),
        ];
        // Where sail finds the user itself, a rule on it needs no host.
        if !USER_KNOWN {
            refused.push((
                serde_json::json!({ "user": "root" }),
                "route.rules[3].user: sail tells who opened a connection only from a host",
            ));
            refused.push((
                serde_json::json!({ "user_id": [0, 1000] }),
                "route.rules[3].user_id: sail tells who opened a connection only from a host",
            ));
        }
        for (rule, message) in refused {
            let err = compile_err(rule.clone());
            assert!(err.starts_with(message), "{}: {}", rule, err);
        }
    }

    #[test]
    fn invert_turns_a_default_rule_around() {
        let m = json(serde_json::json!({ "domain_suffix": "example.com", "invert": true }));
        assert!(!m.matches(&domain("www.example.com", 80)));
        assert!(m.matches(&domain("example.org", 80)));
        // A rule of no conditions matches everything, inverted or not, as
        // in sing-box.
        assert!(json(serde_json::json!({ "invert": true })).matches(&domain("a.com", 80)));
    }

    #[test]
    fn logical_rules_nest() {
        // (port 443 and not (udp or domain a.com)) or source 10.0.0.0/8
        let m = json(
            serde_json::json!({ "type": "logical", "mode": "or", "rules": [
            { "type": "logical", "mode": "and", "rules": [
                { "port": 443 },
                { "type": "logical", "mode": "or", "invert": true, "rules": [
                    { "network": "udp" }, { "domain": "a.com" }
                ] }
            ] },
            { "source_ip_cidr": "10.0.0.0/8" }
        ] }),
        );
        assert!(m.matches(&conn("1.1.1.1:1", "b.com:443")));
        assert!(!m.matches(&conn("1.1.1.1:1", "a.com:443")));
        assert!(!m.matches(&conn("1.1.1.1:1", "b.com:80")));
        assert!(m.matches(&conn("10.1.1.1:1", "a.com:80")));
        let mut udp = conn("1.1.1.1:1", "b.com:443");
        udp.network = Network::Udp;
        assert!(!m.matches(&udp));
        // A logical rule inverted, and a rule inverted inside one.
        let m = json(
            serde_json::json!({ "type": "logical", "mode": "and", "invert": true,
            "rules": [{ "port": 80 }, { "domain": "a.com", "invert": true }] }),
        );
        assert!(!m.matches(&domain("b.com", 80)));
        assert!(m.matches(&domain("a.com", 80)));
        assert!(m.matches(&domain("b.com", 443)));
    }

    /// Rules and connections checked against sing-box 1.14: what its
    /// `DefaultRule` and `LogicalRule` say for each, by reading
    /// rule_abstract.go and the rule items.
    #[test]
    fn a_table_of_rules_as_sing_box_matches_them() {
        /// A source, a destination, and whether the rule matches.
        type Case<'a> = (&'a str, &'a str, bool);
        let table: &[(serde_json::Value, &[Case])] = &[
            // The conditions on one thing are alternatives; the things
            // are all required.
            (
                serde_json::json!({ "domain": "a.com", "ip_cidr": "10.0.0.0/8",
                                    "port": 443, "source_port": 1 }),
                &[
                    ("1.1.1.1:1", "a.com:443", true),
                    ("1.1.1.1:1", "10.0.0.1:443", true),
                    ("1.1.1.1:2", "a.com:443", false),
                    ("1.1.1.1:1", "a.com:80", false),
                    ("1.1.1.1:1", "b.com:443", false),
                ],
            ),
            // source_ip_cidr and source_ip_is_private are one thing.
            (
                serde_json::json!({ "source_ip_cidr": "8.8.8.0/24",
                                    "source_ip_is_private": true }),
                &[
                    ("8.8.8.8:1", "a.com:1", true),
                    ("192.168.0.1:1", "a.com:1", true),
                    ("1.1.1.1:1", "a.com:1", false),
                ],
            ),
            // ip_cidr and ip_is_private are one thing, apart from the
            // domain's only in that either will do.
            (
                serde_json::json!({ "ip_cidr": "8.8.8.0/24", "ip_is_private": true }),
                &[
                    ("1.1.1.1:1", "8.8.8.8:53", true),
                    ("1.1.1.1:1", "192.168.1.1:53", true),
                    ("1.1.1.1:1", "1.1.1.1:53", false),
                    ("1.1.1.1:1", "a.com:53", false),
                ],
            ),
            // port and port_range are one thing, as are the source's.
            (
                serde_json::json!({ "port": 22, "port_range": "8000:", "source_port_range": ":1024",
                                    "source_port": 5000 }),
                &[
                    ("1.1.1.1:5000", "a.com:22", true),
                    ("1.1.1.1:80", "a.com:9000", true),
                    ("1.1.1.1:2000", "a.com:22", false),
                    ("1.1.1.1:80", "a.com:7999", false),
                ],
            ),
            // Other conditions each must hold.
            (
                serde_json::json!({ "domain_keyword": "exa", "network": "tcp", "ip_version": 4 }),
                &[
                    ("1.1.1.1:1", "example.com:1", false),
                    ("1.1.1.1:1", "1.2.3.4:1", false),
                ],
            ),
            // invert of the whole.
            (
                serde_json::json!({ "domain": "a.com", "port": 443, "invert": true }),
                &[
                    ("1.1.1.1:1", "a.com:443", false),
                    ("1.1.1.1:1", "a.com:80", true),
                    ("1.1.1.1:1", "b.com:443", true),
                ],
            ),
            // and / or over nested rules, each grouping on its own.
            (
                serde_json::json!({ "type": "logical", "mode": "and", "rules": [
                    { "domain": "a.com" }, { "ip_cidr": "10.0.0.0/8", "invert": true }
                ] }),
                &[
                    ("1.1.1.1:1", "a.com:1", true),
                    ("1.1.1.1:1", "10.0.0.1:1", false),
                ],
            ),
            (
                serde_json::json!({ "type": "logical", "mode": "or", "invert": true, "rules": [
                    { "domain": "a.com" }, { "port": 22 }
                ] }),
                &[
                    ("1.1.1.1:1", "a.com:1", false),
                    ("1.1.1.1:1", "b.com:22", false),
                    ("1.1.1.1:1", "b.com:23", true),
                ],
            ),
        ];
        for (rule, cases) in table {
            let m = json(rule.clone());
            for &(source, destination, expected) in *cases {
                assert_eq!(
                    m.matches(&conn(source, destination)),
                    expected,
                    "{} from {} to {}",
                    rule,
                    source,
                    destination
                );
            }
        }
    }

    /// A MaxMind database of IPv4 prefixes, each with the record whose
    /// encoding is given, as the format has it: a search tree of 24-bit
    /// records, 16 zero bytes, the records, then the metadata.
    pub(crate) fn mmdb(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        const EMPTY: u64 = u64::MAX;
        // Each node's two records: another node, a record, or none.
        enum To {
            Node(usize),
            Data(usize),
            Empty,
        }
        let mut nodes: Vec<[To; 2]> = vec![[To::Empty, To::Empty]];
        let mut data = Vec::new();
        for (prefix, record) in entries {
            let net: cidr::Ipv4Cidr = prefix.parse().unwrap();
            let bits = u32::from(net.first_address());
            let offset = data.len();
            data.extend_from_slice(record);
            let mut node = 0;
            for i in 0..net.network_length() {
                let bit = ((bits >> (31 - i)) & 1) as usize;
                if i + 1 == net.network_length() {
                    nodes[node][bit] = To::Data(offset);
                    break;
                }
                node = match nodes[node][bit] {
                    To::Node(next) => next,
                    _ => {
                        nodes.push([To::Empty, To::Empty]);
                        let next = nodes.len() - 1;
                        nodes[node][bit] = To::Node(next);
                        next
                    }
                };
            }
        }
        let count = nodes.len() as u64;
        let mut out = Vec::new();
        for node in &nodes {
            for to in node {
                let value = match to {
                    To::Node(n) => *n as u64,
                    To::Data(offset) => count + 16 + *offset as u64,
                    To::Empty => EMPTY,
                };
                let value = if value == EMPTY { count } else { value };
                out.extend_from_slice(&value.to_be_bytes()[5..]);
            }
        }
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        let string = |s: &str| {
            let mut v = vec![0x40 | s.len() as u8];
            v.extend_from_slice(s.as_bytes());
            v
        };
        let mut meta = vec![0xe0 | 9];
        for (key, value) in [
            ("binary_format_major_version", vec![0xa1, 2]),
            ("binary_format_minor_version", vec![0xa0]),
            ("build_epoch", vec![0x00, 0x02]),
            ("database_type", string("Test-ASN")),
            ("description", vec![0xe0]),
            ("ip_version", vec![0xa1, 4]),
            ("languages", vec![0x00, 0x04]),
            ("node_count", vec![0xc1, count as u8]),
            ("record_size", vec![0xa1, 24]),
        ] {
            meta.extend(string(key));
            meta.extend(value);
        }
        out.extend(meta);
        out
    }

    /// A record of GeoLite2-ASN's, and one of ipinfo's.
    pub(crate) fn asn_records(geolite: u16, ipinfo: &str) -> (Vec<u8>, Vec<u8>) {
        let mut a = vec![0xe1, 0x40 | 24];
        a.extend_from_slice(b"autonomous_system_number");
        a.push(0xc2);
        a.extend_from_slice(&geolite.to_be_bytes());
        let mut b = vec![0xe1, 0x43];
        b.extend_from_slice(b"asn");
        b.push(0x40 | ipinfo.len() as u8);
        b.extend_from_slice(ipinfo.as_bytes());
        (a, b)
    }

    #[test]
    fn autonomous_systems_are_looked_up_in_the_asn_database() {
        let dir = std::env::temp_dir().join(format!("sail-asn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (geolite, ipinfo) = asn_records(13335, "AS15169");
        std::fs::write(
            dir.join(ASN_FILE),
            mmdb(&[("1.0.0.0/8", geolite), ("8.8.0.0/16", ipinfo)]),
        )
        .unwrap();
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                data_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let rule: model::Rule =
            serde_json::from_value(serde_json::json!({ "ip_asn": [15169, 13335] })).unwrap();
        let m = Matcher::new(&rule, &env, &Default::default()).unwrap();
        assert!(m.matches(&ip("1.1.1.1", 443)));
        assert!(m.matches(&ip("8.8.8.8", 53)));
        assert!(!m.matches(&ip("8.9.8.8", 53)));
        assert!(!m.matches(&ip("2001:db8::1", 53)));
        // A domain, by the addresses it resolved to.
        let resolved = Facts::new(
            &Session {
                destination: SocksAddr::Domain("one.example".into(), 443),
                ..Default::default()
            },
            &["1.0.0.1".parse().unwrap()],
        );
        assert!(m.matches(&resolved));
        assert!(!m.matches(&domain("one.example", 443)));
        // Opened once.
        let old = open_mmdb(&env, ASN_FILE).unwrap();
        assert!(Arc::ptr_eq(&old, &open_mmdb(&env, ASN_FILE).unwrap()));
        // Replaced, as before a reload, it is opened again; the rules
        // compiled before keep the old one.
        let (geolite, _) = asn_records(64512, "");
        std::fs::write(
            dir.join(ASN_FILE),
            mmdb(&[("1.0.0.0/8", geolite), ("9.0.0.0/8", asn_records(1, "").0)]),
        )
        .unwrap();
        let new = open_mmdb(&env, ASN_FILE).unwrap();
        assert!(!Arc::ptr_eq(&old, &new));
        let reloaded = Matcher::new(&rule, &env, &Default::default()).unwrap();
        assert!(!reloaded.matches(&ip("1.1.1.1", 443)));
        assert!(m.matches(&ip("1.1.1.1", 443)));
        std::fs::remove_dir_all(&dir).unwrap();
        // Without the database, the rule is an error naming it.
        let err = compile_err(serde_json::json!({ "ip_asn": 13335 }));
        assert!(
            err.starts_with("route.rules[3].ip_asn: open ") && err.contains("asn.mmdb"),
            "{}",
            err
        );
    }

    #[cfg(not(feature = "regex"))]
    #[test]
    fn without_regular_expressions_http_patterns_are_errors() {
        for (rule, field) in [
            (
                serde_json::json!({ "http_user_agent": "a*" }),
                "http_user_agent",
            ),
            (serde_json::json!({ "url_regex": "^http://" }), "url_regex"),
        ] {
            let err = compile_err(rule);
            assert!(
                err.starts_with(&format!("route.rules[3].{}: not supported", field)),
                "{}",
                err
            );
        }
    }

    #[cfg(feature = "regex")]
    #[test]
    fn a_plain_http_request_s_user_agent_and_url() {
        let request = |head: &str| {
            let sess = Session {
                destination: SocksAddr::Domain("example.com".into(), 80),
                sniffed_http: Some(Arc::new(crate::sniff::http::request(head.as_bytes()))),
                ..Default::default()
            };
            Facts::new(&sess, &[])
        };
        let ua = json(serde_json::json!({ "http_user_agent": ["Instagram*", "a?c.(x)"] }));
        let get = |ua: &str| request(&format!("GET / HTTP/1.1\r\nUser-Agent: {}\r\n\r\n", ua));
        assert!(ua.matches(&get("Instagram 300.0")));
        assert!(!ua.matches(&get("instagram 300.0")));
        assert!(!ua.matches(&get("My Instagram")));
        assert!(ua.matches(&get("abc.(x)")));
        assert!(!ua.matches(&get("abc.(xx)")));
        assert!(!ua.matches(&get("abcx(x)")));
        // Nothing sniffed, nothing matched; nor one cut short.
        assert!(!ua.matches(&domain("example.com", 80)));
        let long = format!(
            "Instagram{}",
            "x".repeat(crate::sniff::http::MAX_USER_AGENT)
        );
        assert!(!ua.matches(&get(&long)));

        let url = json(serde_json::json!({ "url_regex": "^http://example\\.com/api/" }));
        let at = |path: &str| {
            request(&format!(
                "GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                path
            ))
        };
        assert!(url.matches(&at("/api/v1?x=1")));
        assert!(!url.matches(&at("/web/api/")));
        // Found anywhere, unless anchored.
        let anywhere = json(serde_json::json!({ "url_regex": "token=" }));
        assert!(anywhere.matches(&at("/a?token=1")));
        assert!(compile_err(serde_json::json!({ "url_regex": "(" }))
            .starts_with("route.rules[3].url_regex: \"(\""));
    }

    /// As sing-box reads one (Go's netip.ParsePrefix, then the set masks
    /// it): bits past the prefix are left out, not an error.
    #[test]
    fn a_cidr_with_host_bits_is_its_network() {
        let m = json(serde_json::json!({ "ip_cidr": ["10.1.2.3/8", "2001:db8::1/32"] }));
        assert!(m.matches(&ip("10.200.0.1", 1)));
        assert!(!m.matches(&ip("11.0.0.1", 1)));
        assert!(m.matches(&ip("2001:db8:ffff::1", 1)));
        assert!(!m.matches(&ip("2001:db9::1", 1)));
        assert!(
            compile_err(serde_json::json!({ "ip_cidr": ["10.0.0.0/33"] })).contains("invalid CIDR")
        );
    }

    #[test]
    fn a_plain_address_is_a_cidr_of_itself() {
        let m = json(serde_json::json!({ "ip_cidr": ["1.2.3.4", "2001:db8::1"] }));
        assert!(m.matches(&ip("1.2.3.4", 1)));
        assert!(!m.matches(&ip("1.2.3.5", 1)));
        assert!(m.matches(&ip("2001:db8::1", 1)));
    }

    /// A default rule keeps only the conditions it has: an inline rule of
    /// one condition, as Clash and Surge conversions write thousands of,
    /// keeps at most 112 bytes of them (its Conditions and one item, before
    /// what the item holds), where it kept 240, and 1,288 before that; and
    /// a pointer in the rule that has them.
    #[test]
    fn a_rule_keeps_only_the_conditions_it_has() {
        let one = std::mem::size_of::<Conditions>() + std::mem::size_of::<Item>();
        println!(
            "SIZE Conditions {} Item {} DomainIndex {} CidrIndex {} Condition {}",
            std::mem::size_of::<Conditions>(),
            std::mem::size_of::<Item>(),
            std::mem::size_of::<DomainIndex>(),
            std::mem::size_of::<CidrIndex>(),
            std::mem::size_of::<Condition>()
        );
        assert!(one <= 112, "{} bytes", one);
        assert_eq!(std::mem::size_of::<Condition>(), 16);
    }

    /// A few domains are a list gone through, more are sets: either way
    /// the same domains match, and as many are counted.
    #[test]
    fn a_few_domains_match_as_many_do() {
        let entries = [
            (DomainKind::Full, "full.example"),
            (DomainKind::Suffix, "suffix.example"),
            (DomainKind::Suffix, ".sub.example"),
            (DomainKind::Keyword, "keyw"),
            (DomainKind::Suffix, "Upper.Example"),
            // Twice: counted once.
            (DomainKind::Full, "full.example"),
        ];
        let mut few = DomainIndex::default();
        let mut many = DomainIndex::default();
        for (kind, value) in entries {
            few.insert(kind, value);
            many.insert(kind, value);
        }
        // Past `FEW`, with others that match none of the probes.
        for i in 0..DomainIndex::FEW {
            many.insert(DomainKind::Full, &format!("filler{}.invalid", i));
        }
        assert!(matches!(few.0, Domains::Few(_)) && matches!(many.0, Domains::Many(_)));
        assert_eq!(few.len(), 5);
        assert_eq!(many.len(), 5 + DomainIndex::FEW);
        for probe in [
            "full.example",
            "a.full.example",
            "xfull.example",
            "suffix.example",
            "a.suffix.example",
            "a.b.suffix.example",
            "xsuffix.example",
            "sub.example",
            "a.sub.example",
            "xsub.example",
            "upper.example",
            "a.upper.example",
            "has-keyw-in.it",
            "keyw",
            "example",
            "",
            ".",
            "suffix.example.",
        ] {
            assert_eq!(few.matches(probe), many.matches(probe), "{:?}", probe);
        }
        assert!(few.matches("a.suffix.example") && !few.matches("sub.example"));
        assert!(few.matches("a.sub.example") && few.matches("has-keyw-in.it"));
        assert!(!few.matches("a.full.example") && !few.matches("xsuffix.example"));
        // A list of one is allocated for one.
        let mut one = DomainIndex::default();
        one.insert(DomainKind::Suffix, "a.example");
        assert!(matches!(&one.0, Domains::Few(few) if few.capacity() == 1));
    }
}
