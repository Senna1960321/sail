use std::{
    convert::TryFrom,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::ToString,
};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Network {
    Tcp,
    Udp,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum StreamId {
    U64(u64),
    Uuid(uuid::Uuid),
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::U64(id) => write!(f, "{}", id),
            Self::Uuid(id) => write!(f, "{}", id),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct DatagramSource {
    pub address: SocketAddr,
    pub stream_id: Option<StreamId>,
    pub process_name: Option<String>,
    /// Who sent it, for inbounds that authenticate each datagram. It is
    /// part of the key: datagrams of different users never share a
    /// session.
    pub user: Option<crate::user::UserRef>,
    /// The association it was sent under, for inbounds whose datagrams
    /// belong to one, as SOCKS5's `UDP ASSOCIATE`. Its sessions end with
    /// it, and datagrams of different associations never share a session.
    pub association: Option<UdpAssociation>,
    /// Keeps protocol resources pinned while NAT owns this source. Copies
    /// share an identity, so a later generation cannot reuse its NAT session.
    pub resource_lease: Option<DatagramResourceLease>,
}

impl DatagramSource {
    pub fn new(address: SocketAddr, stream_id: Option<StreamId>) -> Self {
        DatagramSource {
            address,
            stream_id,
            process_name: None,
            user: None,
            association: None,
            resource_lease: None,
        }
    }

    /// The same source, sent by `user`.
    pub fn with_user(mut self, user: Option<crate::user::UserRef>) -> Self {
        self.user = user;
        self
    }

    /// The same source, sent under `association`.
    pub fn with_association(mut self, association: Option<UdpAssociation>) -> Self {
        self.association = association;
        self
    }

    pub fn new_with_process_name(
        address: SocketAddr,
        stream_id: Option<StreamId>,
        process_name: Option<String>,
    ) -> Self {
        DatagramSource {
            address,
            stream_id,
            process_name,
            user: None,
            association: None,
            resource_lease: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DatagramResourceLease(pub(crate) std::sync::Arc<()>);

impl PartialEq for DatagramResourceLease {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for DatagramResourceLease {}

impl std::hash::Hash for DatagramResourceLease {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&std::sync::Arc::as_ptr(&self.0), state);
    }
}

/// A group of datagrams that ends as a whole: SOCKS5's `UDP ASSOCIATE`,
/// which lasts as long as the TCP connection that asked for it.
///
/// Copies compare by identity. The association ends when its
/// [`UdpAssociationOwner`] is dropped.
#[derive(Clone)]
pub struct UdpAssociation {
    id: u64,
    ended: tokio::sync::watch::Receiver<()>,
}

/// Keeps a [`UdpAssociation`] alive; dropping it ends the association.
pub struct UdpAssociationOwner {
    association: UdpAssociation,
    _alive: tokio::sync::watch::Sender<()>,
}

impl UdpAssociation {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Whether the association has ended.
    pub fn has_ended(&self) -> bool {
        self.ended.has_changed().is_err()
    }

    /// Returns once the association has ended.
    pub async fn ended(&self) {
        let mut ended = self.ended.clone();
        while ended.changed().await.is_ok() {}
    }
}

impl UdpAssociationOwner {
    /// A new association, alive until this is dropped.
    pub fn new() -> Self {
        static NEXT_ID: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(1);
        let (alive, ended) = tokio::sync::watch::channel(());
        UdpAssociationOwner {
            association: UdpAssociation {
                id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                ended,
            },
            _alive: alive,
        }
    }

    /// The association this keeps alive.
    pub fn association(&self) -> &UdpAssociation {
        &self.association
    }
}

impl Default for UdpAssociationOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for UdpAssociation {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for UdpAssociation {}

impl std::hash::Hash for UdpAssociation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl fmt::Debug for UdpAssociation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UdpAssociation({})", self.id)
    }
}

impl std::fmt::Display for DatagramSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(id) = self.stream_id.as_ref() {
            write!(f, "{}(stream-{})", self.address, id)?;
        } else {
            write!(f, "{}", self.address)?;
        }
        if let Some(association) = self.association.as_ref() {
            write!(f, "(association-{})", association.id)?;
        }
        Ok(())
    }
}

/// Where a sniffed domain came from, in rising order of precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SniffedFrom {
    /// The DNS answers seen for the destination address.
    Dns,
    /// The HTTP Host header.
    Http,
    /// The TLS server name, over TCP or in QUIC's Initial packets.
    Tls,
}

/// The protocol sniffing recognized a connection by, as sing-box names it
/// for a rule's `protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SniffedProtocol {
    Http,
    Tls,
    Quic,
    Dns,
    Stun,
    Bittorrent,
    Dtls,
}

impl SniffedProtocol {
    /// Every protocol, in the order sniffing tries them.
    pub const ALL: [SniffedProtocol; 7] = [
        SniffedProtocol::Tls,
        SniffedProtocol::Http,
        SniffedProtocol::Quic,
        SniffedProtocol::Dns,
        SniffedProtocol::Stun,
        SniffedProtocol::Bittorrent,
        SniffedProtocol::Dtls,
    ];

    /// The name a rule's `protocol` and `sniffer` give it.
    pub fn name(self) -> &'static str {
        match self {
            SniffedProtocol::Http => "http",
            SniffedProtocol::Tls => "tls",
            SniffedProtocol::Quic => "quic",
            SniffedProtocol::Dns => "dns",
            SniffedProtocol::Stun => "stun",
            SniffedProtocol::Bittorrent => "bittorrent",
            SniffedProtocol::Dtls => "dtls",
        }
    }
}

impl fmt::Display for SniffedProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// State the layers of one connection share, by type: one layer sets it,
/// another reads it, as the VLESS stream and the TLS stream beneath it
/// share XTLS Vision. The clones of a session share it too.
#[derive(Clone, Default)]
pub struct ConnectionState(
    std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                std::any::TypeId,
                std::sync::Arc<dyn std::any::Any + Send + Sync>,
            >,
        >,
    >,
);

impl ConnectionState {
    /// The connection's `T`, made the first time it is asked for.
    pub fn get<T: std::any::Any + Send + Sync + Default>(&self) -> std::sync::Arc<T> {
        // The map is only ever inserted into, so a panic elsewhere while
        // the lock was held cannot leave it inconsistent.
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map
            .entry(std::any::TypeId::of::<T>())
            .or_insert_with(|| std::sync::Arc::new(T::default()));
        entry
            .clone()
            .downcast::<T>()
            .expect("the entry of a type holds that type")
    }
}

/// What a host's own inbound kind tells its own outbound kind of a
/// session, by type (`embed::Extensions`): carried from the inbound to the
/// outbound, through groups and `Via`, and never read by sail. Set once,
/// so a clone of the session shares it; a change makes a copy.
#[derive(Clone, Default)]
pub struct Extensions(
    Option<
        std::sync::Arc<
            std::collections::HashMap<
                std::any::TypeId,
                std::sync::Arc<dyn std::any::Any + Send + Sync>,
            >,
        >,
    >,
);

impl Extensions {
    /// Puts `value` in, in place of one of its type.
    pub fn insert<T: Send + Sync + 'static>(&mut self, value: T) {
        std::sync::Arc::make_mut(self.0.get_or_insert_with(Default::default))
            .insert(std::any::TypeId::of::<T>(), std::sync::Arc::new(value));
    }

    /// The value of type `T`, if one was put in.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.0
            .as_ref()?
            .get(&std::any::TypeId::of::<T>())?
            .downcast_ref::<T>()
    }

    /// Takes the value of type `T` out.
    pub fn remove<T: Send + Sync + 'static>(&mut self) {
        if let Some(map) = &mut self.0 {
            std::sync::Arc::make_mut(map).remove(&std::any::TypeId::of::<T>());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_none_or(|map| map.is_empty())
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Extensions({})",
            self.0.as_ref().map_or(0, |map| map.len())
        )
    }
}

impl fmt::Debug for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionState")
    }
}

#[derive(Debug)]
pub struct Session {
    pub span: tracing::Span,
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The socket address of the local socket of an inbound connection.
    pub local_addr: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The destination was a fake IP, which the dispatcher made the domain
    /// it stands for (TCP; a UDP session's domain is as asked).
    pub fake_ip: bool,
    /// The tag of the inbound handler this session initiated.
    pub inbound_tag: String,
    /// The tag of the first outbound handler this session goes.
    pub outbound_tag: String,
    /// Optional stream ID for multiplexing transports.
    pub stream_id: Option<StreamId>,
    /// Optional source address which is forwarded via HTTP reverse proxy.
    pub forwarded_source: Option<IpAddr>,
    /// Optional process name that initiated this connection.
    pub process_name: Option<String>,
    /// Instructs a multiplexed transport should creates a new underlying
    /// connection for this session, and it will be used only once.
    pub new_conn_once: bool,
    /// The domain sniffing found, and where; only the one from the source
    /// that takes precedence is kept.
    pub sniffed: Option<(SniffedFrom, String)>,
    /// The protocol sniffing recognized, which a rule's `protocol` matches.
    pub sniffed_protocol: Option<SniffedProtocol>,
    /// The URL and User-Agent of the plain HTTP request sniffing read,
    /// which `url_regex` and `http_user_agent` match.
    pub sniffed_http: Option<std::sync::Arc<crate::sniff::http::Request>>,
    /// State the layers of this connection share.
    pub state: ConnectionState,
    /// The protocol of the inbound this session came in through.
    pub inbound_type: &'static str,
    /// The user the inbound authenticated.
    pub user: Option<crate::user::UserRef>,
    /// Skip domain resolution during routing.
    pub skip_resolve: bool,
    /// The application protocol the inbound TLS negotiated with the peer,
    /// if any: an inbound's fallback is chosen by it.
    pub tls_alpn: Option<String>,
    /// How the routing rules said the connection is to be carried.
    pub route: RouteOptions,
    /// The narrow rule-set by which the rule that routed the connection
    /// matched, if any: the site it belongs to, as the smart group keeps
    /// one member per site.
    pub matched_rule_set: Option<std::sync::Arc<str>>,
    /// The routing rule that decided where the connection goes, as it is
    /// written out: `None` for `route.final`.
    pub matched_rule: Option<std::sync::Arc<str>>,
    /// The number of the router that routed it (`Router::generation`):
    /// 0 when no rules did, as for a host's own dial.
    pub routed_by: u64,
    /// The members the groups the connection went through handed it to,
    /// the outermost first: shared by the session's copies, as each group
    /// adds its member before it dials the member.
    pub chain: Chain,
    /// The LAN device the source address is, as the neighbor table and
    /// DHCP leases know it: looked up before routing, when a rule or a DNS
    /// server needs it, as sing-box does.
    pub neighbor: Option<std::sync::Arc<crate::net::neighbor::Neighbor>>,
    /// Who opened the connection, as the host tells it, when it does:
    /// looked up before routing, as sing-box's libbox does on Android.
    pub owner: Option<std::sync::Arc<crate::runtime::platform::ConnectionOwner>>,
    /// The answer the inbound owes its client once the outbound connects,
    /// as a SOCKS inbound gives it: shared by the session's copies.
    pub reply: Option<std::sync::Arc<crate::adapter::reply::Reply>>,
    /// The connection's place among its inbound's handshakes, from the
    /// listener to the dispatcher, which gives it back once the session
    /// has its place among the sessions: held by one or the other from
    /// accept on. No copy of the session carries it. Public only because
    /// a session is made with `..Default::default()` outside the crate;
    /// nothing outside can make a place, so there it is always `None`.
    #[doc(hidden)]
    pub handshake: Option<crate::app::inbound::HandshakePlace>,
    /// What a host's inbound kind put in for its outbound kind: see
    /// `Extensions`. Empty for sail's own inbounds.
    pub extensions: Extensions,
    /// The number it is listed by, from when it is routed or submitted:
    /// shared by its copies. Public only as `handshake` is.
    #[doc(hidden)]
    pub number: Option<std::sync::Arc<crate::app::stat_manager::Number>>,
}

/// The members groups handed a connection to, the outermost first: each
/// group adds the member it tries before it dials it, so that the last is
/// the member being tried, or the one that failed. Mihomo's connections
/// list them the other way round, see `control`.
///
/// It also carries what the groups on the way tell of their members'
/// failures (control::events): whether the connection's failures are
/// told at all, whether a group gave up on it, having told the failure of
/// its last member, and whether a group around the one trying a member
/// has another member to try after it.
#[derive(Debug, Clone, Default)]
pub struct Chain(std::sync::Arc<std::sync::Mutex<Links>>);

#[derive(Debug, Clone, Default)]
struct Links {
    tags: Vec<String>,
    /// The connection's failures are told: the dispatcher tells them.
    telling: bool,
    /// How many groups gave up on the connection, its last member's
    /// failure told.
    ended: usize,
    /// A group around the one trying a member goes on to another member
    /// if this one fails.
    more: bool,
}

impl Chain {
    fn links(&self) -> std::sync::MutexGuard<'_, Links> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A chain for a connection whose failures are told: the groups on
    /// the way tell their members', the dispatcher the rest.
    pub(crate) fn telling() -> Self {
        let chain = Self::default();
        chain.links().telling = true;
        chain
    }

    /// Adds `tag`, the member a group hands the connection to.
    pub fn push(&self, tag: &str) {
        self.links().tags.push(tag.to_string());
    }

    pub fn get(&self) -> Vec<String> {
        self.links().tags.clone()
    }

    /// Puts `to` where `from` was last added: a group went over to another
    /// member.
    pub fn replace(&self, from: &str, to: &str) {
        let mut links = self.links();
        match links.tags.iter().rposition(|t| t == from) {
            Some(i) => links.tags[i] = to.to_string(),
            None => links.tags.push(to.to_string()),
        }
    }

    /// Where the chain is now, to be put back to with `truncate`.
    #[cfg_attr(
        not(any(feature = "outbound-fallback", feature = "outbound-smart")),
        allow(dead_code)
    )]
    pub(crate) fn mark(&self) -> usize {
        self.links().tags.len()
    }

    /// Puts the chain back to `mark`: what was added since goes.
    pub(crate) fn truncate(&self, mark: usize) {
        self.links().tags.truncate(mark);
    }

    #[cfg_attr(
        not(any(
            feature = "outbound-fallback",
            feature = "outbound-smart",
            feature = "outbound-tryall"
        )),
        allow(dead_code)
    )]
    pub(crate) fn tells(&self) -> bool {
        self.links().telling
    }

    /// How many groups gave up on the connection: a group in them, or the
    /// dispatcher, tells nothing more of it.
    pub(crate) fn ended(&self) -> usize {
        self.links().ended
    }

    /// A group gave up on the connection.
    #[cfg_attr(
        not(any(
            feature = "outbound-fallback",
            feature = "outbound-smart",
            feature = "outbound-tryall"
        )),
        allow(dead_code)
    )]
    pub(crate) fn end(&self) {
        self.links().ended += 1;
    }

    /// Whether a group around the one trying a member goes on to another.
    #[cfg_attr(
        not(any(
            feature = "outbound-fallback",
            feature = "outbound-smart",
            feature = "outbound-tryall"
        )),
        allow(dead_code)
    )]
    pub(crate) fn more(&self) -> bool {
        self.links().more
    }

    /// Sets `more`, returning what it was.
    pub(crate) fn set_more(&self, more: bool) -> bool {
        std::mem::replace(&mut self.links().more, more)
    }

    /// A chain of its own, as this one is but with no group given up: for an
    /// attempt run beside others, as a tryall's are.
    #[cfg_attr(not(feature = "outbound-tryall"), allow(dead_code))]
    pub(crate) fn fork(&self) -> Self {
        let links = self.links();
        Self(std::sync::Arc::new(std::sync::Mutex::new(Links {
            tags: links.tags.clone(),
            telling: links.telling,
            ended: 0,
            more: links.more,
        })))
    }

    /// Takes on the members of `fork`, if `members`, and the groups that
    /// gave up in it.
    #[cfg_attr(not(feature = "outbound-tryall"), allow(dead_code))]
    pub(crate) fn join(&self, fork: &Chain, members: bool) {
        let theirs = fork.links().clone();
        let mut links = self.links();
        if members {
            links.tags = theirs.tags;
        }
        links.ended += theirs.ended;
    }
}

/// How the routing rules said a connection is to be carried: their route
/// options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteOptions {
    /// The destination asked for, when a rule overrode it.
    pub original_destination: Option<SocksAddr>,
    /// Answers to UDP sent to a domain come from the address it resolved
    /// to.
    pub udp_disable_domain_unmapping: bool,
    /// A direct outbound sends UDP from a connected socket.
    pub udp_connect: bool,
    /// How long the UDP session lasts idle, instead of its inbound's
    /// `udp_timeout`.
    pub udp_timeout: Option<std::time::Duration>,
    /// Sends the TLS ClientHello in pieces.
    pub tls_fragment: Option<TlsFragment>,
    /// How a direct outbound chooses among the host's interfaces for it,
    /// instead of as its own `network_strategy` says.
    pub network_strategy: Option<crate::net::dial::NetworkStrategy>,
    /// How long a direct outbound tries one family's addresses, and its
    /// first interfaces, before the others race them, instead of its own
    /// `fallback_delay`.
    pub fallback_delay: Option<std::time::Duration>,
    /// The addresses a `resolve` rule resolved the destination's domain
    /// to, in the order its strategy put them, known before it is
    /// dialled: sing-box's `DestinationAddresses`. A direct dial goes to
    /// these, not to what it would resolve itself.
    pub resolved: Vec<std::net::IpAddr>,
    /// Whether every outbound is handed `resolved`, a proxy's server told
    /// an address rather than the domain, as sing-box's `resolve` action
    /// has it; not so for an `on_demand` resolve, whose addresses only a
    /// direct dial takes, as Mihomo's rules on addresses have it.
    pub resolved_for_every_outbound: bool,
    /// Which dials of a connection to an address go to the name known for
    /// it, as a rule's `override_destination` says: a proxy's, or a direct
    /// one's too.
    pub override_destination: Option<crate::config::model::OverrideDestination>,
    /// The name the destination's address is dialled as, where
    /// `override_destination` says: found once the rules decided.
    pub dial_domain: Option<DialDomain>,
}

/// The name a connection to an address is dialled as, and where it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialDomain {
    /// The destination it stands for.
    pub address: SocksAddr,
    pub domain: String,
    pub source: DialDomainSource,
    /// A direct dial takes it too.
    pub direct: bool,
}

/// Where the name a connection is dialled as came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialDomainSource {
    /// A sniffed TLS server name or HTTP Host.
    Sniff,
    /// The DNS answer sail gave for the address (`dns.reverse_mapping`).
    ReverseMapping,
}

impl DialDomainSource {
    /// As the connections list and the logs name it.
    pub fn name(self) -> &'static str {
        match self {
            DialDomainSource::Sniff => "sniff",
            DialDomainSource::ReverseMapping => "reverse_mapping",
        }
    }
}

/// The name a connection was dialled as, once a dial took it: shared by
/// the session's copies, for the connections list.
#[derive(Debug, Default)]
pub struct Dialled(std::sync::Mutex<Option<(String, DialDomainSource)>>);

impl Dialled {
    pub fn set(&self, domain: &str, source: DialDomainSource) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some((domain.to_string(), source));
    }

    pub fn get(&self) -> Option<(String, DialDomainSource)> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// How a TLS ClientHello is cut, in its server name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFragment {
    /// Into TCP segments, this long apart.
    Segments(std::time::Duration),
    /// Into TLS records, sent at once.
    Records,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Session {
            span: self.span.clone(),
            network: self.network,
            source: self.source,
            local_addr: self.local_addr,
            destination: self.destination.clone(),
            fake_ip: self.fake_ip,
            inbound_tag: self.inbound_tag.clone(),
            outbound_tag: self.outbound_tag.clone(),
            stream_id: self.stream_id,
            forwarded_source: self.forwarded_source,
            process_name: self.process_name.clone(),
            new_conn_once: self.new_conn_once,
            sniffed: self.sniffed.clone(),
            sniffed_protocol: self.sniffed_protocol,
            sniffed_http: self.sniffed_http.clone(),
            state: self.state.clone(),
            inbound_type: self.inbound_type,
            user: self.user.clone(),
            skip_resolve: self.skip_resolve,
            tls_alpn: self.tls_alpn.clone(),
            route: self.route.clone(),
            matched_rule_set: self.matched_rule_set.clone(),
            matched_rule: self.matched_rule.clone(),
            routed_by: self.routed_by,
            chain: self.chain.clone(),
            neighbor: self.neighbor.clone(),
            owner: self.owner.clone(),
            reply: self.reply.clone(),
            handshake: None,
            extensions: self.extensions.clone(),
            number: self.number.clone(),
        }
    }
}

/// An address that stands for no address in particular.
const UNSPECIFIED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

impl Default for Session {
    fn default() -> Self {
        Session {
            span: Self::create_span(),
            network: Network::Tcp,
            source: UNSPECIFIED,
            local_addr: UNSPECIFIED,
            destination: SocksAddr::any(),
            fake_ip: false,
            inbound_tag: "".to_string(),
            outbound_tag: "".to_string(),
            stream_id: None,
            forwarded_source: None,
            process_name: None,
            new_conn_once: false,
            sniffed: None,
            sniffed_protocol: None,
            sniffed_http: None,
            state: ConnectionState::default(),
            inbound_type: "",
            user: None,
            skip_resolve: false,
            tls_alpn: None,
            route: RouteOptions::default(),
            matched_rule_set: None,
            matched_rule: None,
            routed_by: 0,
            chain: Chain::default(),
            neighbor: None,
            owner: None,
            reply: None,
            handshake: None,
            extensions: Extensions::default(),
            number: None,
        }
    }
}

impl Session {
    pub fn create_span() -> tracing::Span {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let trace_id: String = (0..8)
            .map(|_| {
                const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                let idx = rng.gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect();
        let span = tracing::debug_span!("sess", tid = trace_id);
        let _g = span.enter();
        tracing::debug!("created span");
        span.clone()
    }

    pub fn new_span(&mut self) {
        self.span = Self::create_span();
    }

    pub fn span(&self) -> tracing::Span {
        self.span.clone()
    }

    /// The domain sniffing found, if any.
    pub fn sniffed_domain(&self) -> Option<&str> {
        self.sniffed.as_ref().map(|(_, domain)| domain.as_str())
    }

    /// The sniffed domain, if it came from `from`.
    pub fn sniffed_domain_from(&self, from: SniffedFrom) -> Option<&str> {
        match &self.sniffed {
            Some((source, domain)) if *source == from => Some(domain),
            _ => None,
        }
    }

    /// Records a sniffed domain, unless one from a source that takes
    /// precedence is known already.
    pub fn set_sniffed_domain(&mut self, from: SniffedFrom, domain: String) {
        if self
            .sniffed
            .as_ref()
            .is_none_or(|(known, _)| *known <= from)
        {
            self.sniffed = Some((from, domain));
        }
    }

    /// Forgets what sniffing found, for a session of a connection of its
    /// own that carries this one.
    pub fn forget_sniffed(&mut self) {
        self.sniffed = None;
        self.sniffed_protocol = None;
        self.sniffed_http = None;
    }
}

struct SocksAddrPortLastType;

impl SocksAddrPortLastType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x4;
    const DOMAIN: u8 = 0x3;
}

struct SocksAddrPortFirstType;

impl SocksAddrPortFirstType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x3;
    const DOMAIN: u8 = 0x2;
}

#[derive(Clone, Copy)]
pub enum SocksAddrWireType {
    PortFirst,
    PortLast,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

fn insuff_bytes() -> io::Error {
    io::Error::other("insufficient bytes")
}

fn invalid_domain() -> io::Error {
    io::Error::other("invalid domain")
}

fn invalid_addr_type() -> io::Error {
    io::Error::other("invalid address type")
}

impl SocksAddr {
    pub fn any() -> Self {
        Self::Ip(UNSPECIFIED)
    }

    pub fn any_ipv4() -> Self {
        Self::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }

    pub fn any_ipv6() -> Self {
        Self::Ip(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    }

    /// The socket address, if `self` is not a domain.
    pub fn as_socket_addr(&self) -> Option<&SocketAddr> {
        match self {
            SocksAddr::Ip(a) => Some(a),
            SocksAddr::Domain(..) => None,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::Domain(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(addr) => addr.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(_, _) => true,
        }
    }

    pub fn domain(&self) -> Option<&String> {
        if let SocksAddr::Domain(ref domain, _) = self {
            Some(domain)
        } else {
            None
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(addr) => {
                let ip = addr.ip();
                ip.to_string()
            }
            SocksAddr::Domain(domain, _) => domain.to_owned(),
        }
    }

    /// Writes `self` into `buf`.
    pub fn write_buf<T: BufMut>(&self, buf: &mut T, addr_type: SocksAddrWireType) {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => match addr_type {
                    SocksAddrWireType::PortLast => {
                        buf.put_u8(SocksAddrPortLastType::V4);
                        buf.put_slice(&addr.ip().octets());
                        buf.put_u16(addr.port());
                    }
                    SocksAddrWireType::PortFirst => {
                        buf.put_u16(addr.port());
                        buf.put_u8(SocksAddrPortFirstType::V4);
                        buf.put_slice(&addr.ip().octets());
                    }
                },
                SocketAddr::V6(addr) => match addr_type {
                    SocksAddrWireType::PortLast => {
                        buf.put_u8(SocksAddrPortLastType::V6);
                        buf.put_slice(&addr.ip().octets());
                        buf.put_u16(addr.port());
                    }
                    SocksAddrWireType::PortFirst => {
                        buf.put_u16(addr.port());
                        buf.put_u8(SocksAddrPortFirstType::V6);
                        buf.put_slice(&addr.ip().octets());
                    }
                },
            },
            Self::Domain(domain, port) => match addr_type {
                SocksAddrWireType::PortLast => {
                    buf.put_u8(SocksAddrPortLastType::DOMAIN);
                    buf.put_u8(domain.len() as u8);
                    buf.put_slice(domain.as_bytes());
                    buf.put_u16(*port);
                }
                SocksAddrWireType::PortFirst => {
                    buf.put_u16(*port);
                    buf.put_u8(SocksAddrPortFirstType::DOMAIN);
                    buf.put_u8(domain.len() as u8);
                    buf.put_slice(domain.as_bytes());
                }
            },
        }
    }

    pub async fn read_from<T: AsyncRead + Unpin>(
        r: &mut T,
        addr_type: SocksAddrWireType,
    ) -> io::Result<Self> {
        match addr_type {
            SocksAddrWireType::PortLast => match r.read_u8().await? {
                SocksAddrPortLastType::V4 => {
                    let ip = Ipv4Addr::from(r.read_u32().await?);
                    let port = r.read_u16().await?;
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::V6 => {
                    let ip = Ipv6Addr::from(r.read_u128().await?);
                    let port = r.read_u16().await?;
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::DOMAIN => {
                    let domain_len = r.read_u8().await? as usize;
                    let mut buf = vec![0u8; domain_len];
                    let n = r.read_exact(&mut buf).await?;
                    debug_assert_eq!(domain_len, n);
                    let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                    let port = r.read_u16().await?;
                    Ok(Self::Domain(domain, port))
                }
                _ => Err(invalid_addr_type()),
            },
            SocksAddrWireType::PortFirst => {
                let port = r.read_u16().await?;
                match r.read_u8().await? {
                    SocksAddrPortFirstType::V4 => {
                        let ip = Ipv4Addr::from(r.read_u32().await?);
                        Ok(Self::Ip((ip, port).into()))
                    }
                    SocksAddrPortFirstType::V6 => {
                        let ip = Ipv6Addr::from(r.read_u128().await?);
                        Ok(Self::Ip((ip, port).into()))
                    }
                    SocksAddrPortFirstType::DOMAIN => {
                        let domain_len = r.read_u8().await? as usize;
                        let mut buf = vec![0u8; domain_len];
                        r.read_exact(&mut buf).await?;
                        let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                        Ok(Self::Domain(domain, port))
                    }
                    _ => Err(invalid_addr_type()),
                }
            }
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => Self::Domain(domain.clone(), *port),
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SocksAddr::Ip(addr) => addr.to_string(),
            SocksAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        };
        write!(f, "{}", s)
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<&SocketAddr> for SocksAddr {
    fn from(addr: &SocketAddr) -> Self {
        Self::Ip(addr.to_owned())
    }
}

impl From<SocketAddrV4> for SocksAddr {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for SocksAddr {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

impl TryFrom<(&str, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from((addr, port): (&str, u16)) -> Result<Self, Self::Error> {
        Self::try_from((addr.to_string(), port))
    }
}

impl TryFrom<(&String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from((addr, port): (&String, u16)) -> Result<Self, Self::Error> {
        Self::try_from((addr.to_owned(), port))
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from((addr, port): (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            return Ok(Self::from((ip, port)));
        }
        if addr.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(addr, port))
    }
}

/// Tries to read `SocksAddr` from `&[u8]`.
impl TryFrom<(&[u8], SocksAddrWireType)> for SocksAddr {
    type Error = io::Error;

    fn try_from((buf, addr_type): (&[u8], SocksAddrWireType)) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(insuff_bytes());
        }

        match addr_type {
            SocksAddrWireType::PortLast => match buf[0] {
                SocksAddrPortLastType::V4 => {
                    if buf.len() < 1 + 4 + 2 {
                        return Err(insuff_bytes());
                    }
                    let mut ip_bytes = [0u8; 4];
                    ip_bytes.copy_from_slice(&buf[1..5]);
                    let ip = Ipv4Addr::from(ip_bytes);
                    let mut port_bytes = [0u8; 2];
                    port_bytes.copy_from_slice(&buf[5..7]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::V6 => {
                    if buf.len() < 1 + 16 + 2 {
                        return Err(insuff_bytes());
                    }
                    let mut ip_bytes = [0u8; 16];
                    ip_bytes.copy_from_slice(&buf[1..17]);
                    let ip = Ipv6Addr::from(ip_bytes);
                    let mut port_bytes = [0u8; 2];
                    port_bytes.copy_from_slice(&buf[17..19]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Ip((ip, port).into()))
                }
                SocksAddrPortLastType::DOMAIN => {
                    if buf.len() < 2 {
                        return Err(insuff_bytes());
                    }
                    let domain_len = buf[1] as usize;
                    if buf.len() < 2 + domain_len + 2 {
                        return Err(insuff_bytes());
                    }
                    let domain = String::from_utf8(buf[2..domain_len + 2].to_vec())
                        .map_err(|e| io::Error::other(format!("invalid domain: {}", e)))?;
                    let mut port_bytes = [0u8; 2];
                    port_bytes.copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                    let port = u16::from_be_bytes(port_bytes);
                    Ok(Self::Domain(domain, port))
                }
                _ => Err(io::Error::other("invalid address type")),
            },
            // Port, type, address: Xray's PortThenAddress, as XUDP uses.
            SocksAddrWireType::PortFirst => {
                if buf.len() < 3 {
                    return Err(insuff_bytes());
                }
                let port = u16::from_be_bytes([buf[0], buf[1]]);
                let addr = &buf[3..];
                match buf[2] {
                    SocksAddrPortFirstType::V4 => {
                        let ip: [u8; 4] = addr
                            .get(..4)
                            .ok_or_else(insuff_bytes)?
                            .try_into()
                            .map_err(|_| insuff_bytes())?;
                        Ok(Self::Ip((Ipv4Addr::from(ip), port).into()))
                    }
                    SocksAddrPortFirstType::V6 => {
                        let ip: [u8; 16] = addr
                            .get(..16)
                            .ok_or_else(insuff_bytes)?
                            .try_into()
                            .map_err(|_| insuff_bytes())?;
                        Ok(Self::Ip((Ipv6Addr::from(ip), port).into()))
                    }
                    SocksAddrPortFirstType::DOMAIN => {
                        let domain_len = *addr.first().ok_or_else(insuff_bytes)? as usize;
                        let domain = addr.get(1..1 + domain_len).ok_or_else(insuff_bytes)?;
                        let domain = String::from_utf8(domain.to_vec())
                            .map_err(|e| io::Error::other(format!("invalid domain: {}", e)))?;
                        Ok(Self::Domain(domain, port))
                    }
                    _ => Err(io::Error::other("invalid address type")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(buf: &[u8], ty: SocksAddrWireType) -> io::Result<SocksAddr> {
        SocksAddr::try_from((buf, ty))
    }

    #[test]
    fn truncated_addresses_are_errors() {
        for ty in [SocksAddrWireType::PortLast, SocksAddrWireType::PortFirst] {
            assert!(parse(&[], ty).is_err());
            for kind in [0x01, 0x03, 0x04] {
                assert!(parse(&[kind], ty).is_err());
                assert!(parse(&[kind, 5], ty).is_err());
            }
        }
        // PortLast domain: type, len, name, port. A length byte that
        // claims more than is there must not read past the end.
        assert!(parse(&[0x03, 3, b'a', b'b', b'c', 0], SocksAddrWireType::PortLast).is_err());
        assert!(parse(&[0x03, 3, b'a', b'b', b'c'], SocksAddrWireType::PortLast).is_err());
        assert!(parse(&[0x03, 200, 1, 2], SocksAddrWireType::PortLast).is_err());
        // PortFirst domain: port, type, len, name.
        assert!(parse(&[0, 80, 0x02, 4, b'a'], SocksAddrWireType::PortFirst).is_err());
        assert!(parse(&[0, 80, 0x01, 1, 2, 3], SocksAddrWireType::PortFirst).is_err());
        assert!(parse(&[0, 80, 0x09, 1, 2, 3, 4], SocksAddrWireType::PortFirst).is_err());
        assert!(parse(&[0xff], SocksAddrWireType::PortLast).is_err());
    }

    #[tokio::test]
    async fn addresses_round_trip() {
        let addrs = [
            SocksAddr::from(SocketAddr::from(([1, 2, 3, 4], 80))),
            SocksAddr::from(SocketAddr::from((Ipv6Addr::LOCALHOST, 443))),
            SocksAddr::try_from(("example.com".to_string(), 8080)).unwrap(),
        ];
        for ty in [SocksAddrWireType::PortLast, SocksAddrWireType::PortFirst] {
            for addr in &addrs {
                let mut buf = Vec::new();
                addr.write_buf(&mut buf, ty);
                assert_eq!(buf.len(), addr.size());
                assert_eq!(&parse(&buf, ty).unwrap(), addr);
                let mut r = &buf[..];
                assert_eq!(&SocksAddr::read_from(&mut r, ty).await.unwrap(), addr);
                assert!(r.is_empty());
                for cut in 0..buf.len() {
                    assert!(parse(&buf[..cut], ty).is_err());
                    let mut r = &buf[..cut];
                    assert!(SocksAddr::read_from(&mut r, ty).await.is_err());
                }
            }
        }
    }

    /// Port first is Xray's PortThenAddress: port, then the type (1 IPv4,
    /// 2 domain, 3 IPv6), then the address, as XUDP and Mux.Cool carry it.
    #[test]
    fn port_first_is_port_then_address() {
        let wire = |addr: SocksAddr| {
            let mut buf = Vec::new();
            addr.write_buf(&mut buf, SocksAddrWireType::PortFirst);
            buf
        };
        let v4 = SocksAddr::from(SocketAddr::from(([1, 2, 3, 4], 80)));
        assert_eq!(wire(v4.clone()), [0, 80, 1, 1, 2, 3, 4]);
        let domain = SocksAddr::try_from(("a.b".to_string(), 443)).unwrap();
        assert_eq!(wire(domain.clone()), [1, 187, 2, 3, b'a', b'.', b'b']);
        let v6 = SocksAddr::from(SocketAddr::from((Ipv6Addr::LOCALHOST, 53)));
        let mut expect = vec![0, 53, 3];
        expect.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert_eq!(wire(v6.clone()), expect);
        #[cfg(any(feature = "inbound-vmess", feature = "outbound-vmess"))]
        for addr in [v4, domain, v6] {
            let buf = wire(addr.clone());
            let parsed = crate::protocol::vmess::xudp::parse_addr_port(&buf).unwrap();
            assert_eq!(parsed, (addr, buf.len()));
        }
    }

    #[test]
    fn domain_has_no_socket_addr() {
        let domain = SocksAddr::try_from(("example.com".to_string(), 53)).unwrap();
        assert!(domain.as_socket_addr().is_none());
        assert_eq!(domain.clone(), domain);
        assert!(SocksAddr::any_ipv6().as_socket_addr().unwrap().is_ipv6());
    }
}
