use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use futures::future::select_ok;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType},
};
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::{debug, Instrument};

use crate::{
    adapter::*, app::dispatcher::Dispatcher, config::model::DnsStrategy, net::*, session::*,
    util::DnsMessageExt,
};
include!("client/types.rs");

mod cache;
mod fakeip;
pub(crate) mod mdns;
mod rules;
mod server;
mod system;
mod upstream;

/// What a hosts file answers.
enum FromHosts {
    Reply(Message),
    /// A name another stands for, which it has no addresses of, to look up
    /// with a strategy of the query's family.
    Alias(String, DnsStrategy),
    Missing,
}

pub use cache::CacheStats;
pub use fakeip::FakeIp;

use server::{Address, Dialer, Kind, Server};

/// Where a lookup's queries go.
#[derive(Clone, Copy)]
enum By<'a> {
    /// Where the rules send them.
    Rules(&'a LookupContext),
    /// To this server, sent so.
    Server(&'a str, &'a QueryOptions),
}

/// How long the system resolver's and a hosts server's answers are kept:
/// they carry no TTL.
const LOCAL_TTL: Duration = Duration::from_secs(60);
/// The TTL of a fake IP's answer: sing-box's.
const FAKE_IP_TTL: u32 = 600;
/// The TTL of a hosts server's answer: sing-box's.
const HOSTS_TTL: u32 = 600;
/// What a LAN device's addresses are given for: sing-box's DefaultDNSTTL,
/// which its local server answers them with.
const NEIGHBOR_TTL: u32 = 600;

impl DnsClient {
    pub fn new(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialDefaults>,
        env: &crate::runtime::RuntimeEnv,
    ) -> Result<Self> {
        Self::with_rule_sets(dns, dial, env, &Default::default())
    }

    /// A client whose rules can name the rule-sets of `rule_sets`.
    pub(crate) fn with_rule_sets(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialDefaults>,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
    ) -> Result<Self> {
        Self::build(dns, dial, env, rule_sets, None)
    }

    fn build(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialDefaults>,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
        fake_ips: Option<&Arc<fakeip::FakeIpStore>>,
    ) -> Result<Self> {
        let tuning = env.options.dns.clone();
        let local = crate::config::model::DnsServer {
            kind: "local".into(),
            tag: "local".into(),
            options: Default::default(),
        };
        let configs = if dns.servers.is_empty() {
            std::slice::from_ref(&local)
        } else {
            &dns.servers[..]
        };
        let mut servers = HashMap::new();
        let mut fake_ip_store = None;
        for config in configs {
            let server = Server::new(config, &dial, env, fake_ips)?;
            if let Kind::FakeIp(store) = &server.kind {
                if fake_ip_store.replace(store.clone()).is_some() {
                    return Err(anyhow!(
                        "dns.servers[{}]: one fakeip server is all there can be",
                        config.tag
                    ));
                }
            }
            debug!("dns server {}", server);
            servers.insert(config.tag.clone(), Arc::new(server));
        }
        server::check(&servers)?;
        // A sequential server fails in its budget, before the query does.
        for server in servers.values() {
            if let Kind::Sequential(s) = &server.kind {
                if s.budget >= dns.timeout() {
                    return Err(anyhow!(
                        "dns.servers[{}].budget: {:?} must be less than dns.timeout, {:?}",
                        server.tag,
                        s.budget,
                        dns.timeout()
                    ));
                }
            }
        }
        let final_server = dns
            .final_server
            .clone()
            .unwrap_or_else(|| configs[0].tag.clone());
        let rules = Self::load_rules(dns, env, rule_sets)?;
        let mut preferring: Vec<String> = dns
            .rules
            .iter()
            .flat_map(|r| r.preferred_by())
            .cloned()
            .collect();
        preferring.sort();
        preferring.dedup();
        let network = rules
            .iter()
            .any(|r| r.matcher.needs().network)
            .then(|| env.network.clone());
        let capacity = NonZeroUsize::new(dns.cache_capacity())
            .ok_or_else(|| anyhow!("dns.cache_capacity: must be at least 1"))?;
        let optimistic = dns.optimistic_timeout();
        if optimistic.is_some() && dns.disable_cache {
            return Err(anyhow!("dns.optimistic: not with dns.disable_cache"));
        }
        if optimistic.is_some() && dns.disable_expire {
            return Err(anyhow!("dns.optimistic: not with dns.disable_expire"));
        }
        Ok(Self {
            dispatcher: Default::default(),
            servers,
            rules,
            final_server,
            ech_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ech_query_locks: Arc::new(TokioMutex::new(HashMap::new())),
            answers: Arc::new(cache::Answers::new(
                capacity,
                dns.disable_expire,
                optimistic,
                env.cache_file.get().filter(|file| file.store_dns),
            )),
            disable_cache: dns.disable_cache,
            me: Weak::new(),
            fake_ips: fake_ip_store,
            tuning,
            strategy: dns.strategy,
            client_strategy: dns.client_strategy,
            timeout: dns.timeout(),
            reverse_map: dns.reverse_mapping.then(|| env.reverse_map.clone()),
            client_subnet: dns.client_subnet,
            rules_set_strategy: dns.rules.iter().any(|r| r.strategy.is_some()),
            network,
            preferring,
            events: env.events.clone(),
        })
    }

    /// Whether a rule has conditions on the network the host is on.
    pub fn needs_network(&self) -> bool {
        self.network.is_some()
    }

    /// Whether a rule, or a rule-set it names as it is now, has conditions
    /// on who opened a connection.
    pub fn needs_owner(&self) -> bool {
        self.rules.iter().any(|r| r.matcher.needs().owner)
    }

    /// Whether a rule has conditions on the program that opened it.
    pub fn needs_process(&self) -> bool {
        self.rules.iter().any(|r| r.matcher.needs().process)
    }

    /// Shares the client between its users, who see it replaced whole on
    /// reload.
    pub fn into_shared(self) -> crate::app::SyncDnsClient {
        Arc::new(arc_swap::ArcSwap::new(self.into_arc()))
    }

    /// The client, shared: what it does in the background, such as asking
    /// again for an answer that expired, it does through it.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new_cyclic(|me| DnsClient {
            me: me.clone(),
            ..self
        })
    }

    /// Forgets every answer kept: after the network changed, when those of
    /// the one before may be wrong, or as the Clash API or a user asks.
    pub fn clear_cache(&self) {
        self.answers.clear();
        debug!("dns cache cleared");
    }

    /// Gives up the connections the servers keep that no query is on now,
    /// as after a long sleep, which may have left them dead: those of TCP
    /// and DoT, and DoH, DoQ and HTTP/3 connections, which go once the
    /// queries on them end. The answers kept stay, as does which protocol
    /// a prefer_h3 server answers over: the network is the same.
    pub async fn close_idle(&self) {
        for server in self.servers.values() {
            match &server.kind {
                server::Kind::Tcp { pool, .. } => pool.clear(),
                server::Kind::Upstream(upstream) => upstream.close_idle().await,
                _ => {}
            }
        }
    }

    /// The network changed: the answers kept, and the connections the
    /// servers keep, were of the one before, and go.
    pub async fn network_changed(&self) {
        self.clear_cache();
        for server in self.servers.values() {
            match &server.kind {
                server::Kind::Tcp { pool, .. } => pool.clear(),
                server::Kind::Upstream(upstream) => upstream.reset().await,
                server::Kind::Local(local) => {
                    if let Some(dialed) = &local.dialed {
                        dialed.servers.forget();
                    }
                }
                _ => {}
            }
        }
    }

    /// Forgets the fake IPs handed out, as the Clash API's flush does;
    /// false without a fakeip server.
    pub fn clear_fake_ips(&self) -> bool {
        match &self.fake_ips {
            Some(store) => {
                store.clear();
                true
            }
            None => false,
        }
    }

    /// A query for `name` of type `ty`, as a client would send one.
    pub fn query_message(name: Name, ty: RecordType) -> Message {
        Self::new_query(name, ty)
    }

    /// What the cache holds and how it served.
    pub fn cache_stats(&self) -> CacheStats {
        self.answers.stats()
    }

    /// Servers with a `detour` reach it through `dispatcher`, once it
    /// exists.
    pub fn set_dispatcher(&self, dispatcher: Weak<Dispatcher>) {
        let _ = self.dispatcher.set(dispatcher);
    }

    /// A client for `dns`, to replace this one: it starts with empty caches,
    /// and reaches detours as this one does.
    pub(crate) fn reloaded(
        &self,
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialDefaults>,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
    ) -> Result<Self> {
        // The fake IPs handed out stay theirs, as long as the ranges do.
        let mut client = Self::build(dns, dial, env, rule_sets, self.fake_ips.as_ref())?;
        client.dispatcher = self.dispatcher.clone();
        Ok(client)
    }

    /// Whether `dns.reverse_mapping` is on.
    pub fn reverse_mapping(&self) -> bool {
        self.reverse_map.is_some()
    }

    /// Fails when resolving a name needs what the resolving itself needs:
    /// a server whose `detour` dials a server name that resolves, through
    /// its `domain_resolver`, `route.default_domain_resolver` or the DNS
    /// rules, back at that server; outbounds' own `detour` and a group's
    /// members are followed too. A server with `respect_rules` may go
    /// through any outbound `route` names. Such a query could only time
    /// out. A server's `detour` names an outbound or endpoint that exists.
    pub fn check_loops(&self, config: &crate::config::Config) -> Result<()> {
        let (outbounds, route) = (&config.outbounds, &config.route);
        let tags: std::collections::HashSet<&str> = outbounds
            .iter()
            .map(|o| o.tag.as_str())
            .chain(config.endpoints.iter().map(|e| e.tag.as_str()))
            .collect();
        let default_resolver = route.default_domain_resolver.as_ref();
        let routed = route.outbounds(outbounds);
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        enum Node {
            Dns(String),
            Outbound(String),
        }
        impl std::fmt::Display for Node {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Node::Dns(tag) => write!(f, "dns server [{}]", tag),
                    Node::Outbound(tag) => write!(f, "outbound [{}]", tag),
                }
            }
        }
        let mut edges: HashMap<Node, Vec<Node>> = HashMap::new();
        for server in self.servers.values() {
            let node = Node::Dns(server.tag.clone());
            let next = edges.entry(node).or_default();
            next.extend(server.needs().into_iter().map(|t| Node::Dns(t.to_string())));
            let dialer = match &server.kind {
                Kind::Udp { dialer, .. } | Kind::Tcp { dialer, .. } => Some(dialer),
                Kind::Upstream(u) => Some(&u.dialer),
                Kind::Local(local) => local.dialed.as_ref().map(|d| &d.dialer),
                _ => None,
            };
            if let Some(detour) = dialer.and_then(|d| d.detour.as_ref()) {
                if !tags.contains(detour.as_str()) {
                    return Err(anyhow!(
                        "dns.servers[{}]: detour: outbound [{}] does not exist",
                        server.tag,
                        detour
                    ));
                }
                next.push(Node::Outbound(detour.clone()));
            }
            if dialer.is_some_and(|d| d.respect_rules) {
                next.extend(routed.iter().map(|o| Node::Outbound(o.to_string())));
            }
        }
        for outbound in outbounds {
            let node = Node::Outbound(outbound.tag.clone());
            let next = edges.entry(node).or_default();
            let options = &outbound.options;
            if let Some(members) = options.get("outbounds").and_then(|v| v.as_array()) {
                next.extend(
                    members
                        .iter()
                        .filter_map(|m| m.as_str())
                        .map(|m| Node::Outbound(m.to_string())),
                );
            }
            if let Some(detour) = options.get("detour").and_then(|v| v.as_str()) {
                // Its server is dialled by the detour, which resolves it.
                next.push(Node::Outbound(detour.to_string()));
                continue;
            }
            let Some(host) = options.get("server").and_then(|v| v.as_str()) else {
                continue;
            };
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            let skip_default = options
                .get("skip_default_domain_resolver")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let resolver = options
                .get("domain_resolver")
                .and_then(|v| {
                    <crate::config::model::DomainResolver as serde::Deserialize>::deserialize(v)
                        .ok()
                })
                .or_else(|| default_resolver.filter(|_| !skip_default).cloned());
            let servers = match resolver {
                Some(resolver) => vec![resolver.server],
                None => {
                    let ctx = LookupContext {
                        outbound: Some(outbound.tag.clone()),
                        ..Default::default()
                    };
                    [RecordType::A, RecordType::AAAA]
                        .into_iter()
                        .flat_map(|ty| self.reach(host, ty, &ctx).servers)
                        .collect()
                }
            };
            next.extend(servers.into_iter().map(Node::Dns));
        }

        fn visit(
            edges: &HashMap<Node, Vec<Node>>,
            node: &Node,
            path: &mut Vec<Node>,
            done: &mut std::collections::HashSet<Node>,
        ) -> Result<()> {
            if done.contains(node) {
                return Ok(());
            }
            if let Some(i) = path.iter().position(|n| n == node) {
                let cycle: Vec<String> = path[i..]
                    .iter()
                    .chain(std::iter::once(node))
                    .map(|n| n.to_string())
                    .collect();
                // A loop among DNS servers alone was reported when they
                // were built; this one goes through an outbound.
                return Err(anyhow!(
                    "resolving needs itself: {}; set a domain_resolver that does not \
                     go through it",
                    cycle.join(" -> ")
                ));
            }
            path.push(node.clone());
            for next in edges.get(node).into_iter().flatten() {
                visit(edges, next, path, done)?;
            }
            path.pop();
            done.insert(node.clone());
            Ok(())
        }
        let mut nodes: Vec<&Node> = edges.keys().collect();
        nodes.sort();
        let mut done = std::collections::HashSet::new();
        for node in nodes {
            visit(&edges, node, &mut Vec::new(), &mut done)?;
        }
        Ok(())
    }

    fn server(&self, tag: &str) -> Result<&Arc<Server>> {
        self.servers
            .get(tag)
            .ok_or_else(|| anyhow!("dns server [{}] does not exist", tag))
    }

    // -- Reaching servers ------------------------------------------------

    /// Where a server is: its address, or what its resolver says its domain
    /// resolves to.
    async fn server_addr(&self, address: &Address) -> Result<SocketAddr> {
        if let Some(addr) = address.socket_addr() {
            return Ok(addr);
        }
        // A domain has a resolver: the servers were checked for that.
        let resolver = address
            .resolver
            .as_ref()
            .ok_or_else(|| anyhow!("no resolver for {}", address.host))?;
        let ips = self
            .lookup_resolver(resolver, &address.host)
            .await
            .map_err(|e| anyhow!("resolving {}: {}", address.host, e))?;
        let ip = ips
            .first()
            .ok_or_else(|| anyhow!("{} resolves to no address", address.host))?;
        Ok(SocketAddr::new(*ip, address.port))
    }

    /// The session a detour carries a server's connection in.
    fn detour_session(network: Network, addr: SocketAddr, detour: &str) -> Session {
        let source = match addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        Session {
            network,
            source,
            destination: SocksAddr::from(addr),
            // Keeps a TLS detour from asking the DNS for ECH configs, which
            // could come back here.
            inbound_tag: "dnsclient".to_string(),
            outbound_tag: detour.to_string(),
            ..Default::default()
        }
    }

    fn dispatcher(&self) -> Result<Arc<Dispatcher>> {
        self.dispatcher
            .get()
            .ok_or_else(|| anyhow!("no dispatcher"))?
            .upgrade()
            .ok_or_else(|| anyhow!("dispatcher is gone"))
    }

    /// The outbound a server's connection goes through, and the session
    /// it carries it in: with `respect_rules`, the one the routing rules
    /// pick for it; `None` for its own dialer, a `detour` included.
    async fn outbound_for(
        &self,
        dialer: &Dialer,
        network: Network,
        addr: SocketAddr,
    ) -> Result<Option<(String, Session)>> {
        if dialer.is_direct() {
            return Ok(None);
        }
        let mut sess = Self::detour_session(network, addr, "");
        // The rules match the server's domain, as Mihomo's do, but its
        // address is known already: resolving it again for an IP rule
        // could come back here.
        if let Some(domain) = &dialer.domain {
            sess.set_sniffed_domain(SniffedFrom::Dns, domain.clone());
        }
        sess.skip_resolve = true;
        let outbound = self
            .dispatcher()?
            .outbound_for(&mut sess)
            .await
            .map_err(|e| anyhow!("routing {}: {}", addr, e))?;
        // Every rule and `final` passed it on: direct, as the server dials.
        let Some(outbound) = outbound else {
            debug!("dns server at {} routed direct", addr);
            return Ok(None);
        };
        debug!("dns server at {} routed to [{}]", addr, outbound);
        Ok(Some((outbound, sess)))
    }

    /// A TCP connection to `addr`, as the server's dialer makes them.
    async fn dial_stream(&self, dialer: &Dialer, addr: SocketAddr) -> Result<AnyStream> {
        let routed = self.outbound_for(dialer, Network::Tcp, addr).await?;
        match (routed, dialer.detour.as_deref()) {
            (None, Some(detour)) => Ok(dialer
                .dial
                .stream(
                    &self.dispatcher()?.dns_client(),
                    Some(&Self::detour_session(Network::Tcp, addr, detour)),
                    &SocksAddr::from(addr),
                )
                .await?),
            (None, None) => Ok(Box::new(dialer.dial.tcp_to(addr).await?)),
            (Some((outbound, sess)), _) => self
                .dispatcher()?
                .stream_via(&outbound, sess)
                .await
                .map_err(|e| anyhow!("through [{}]: {}", outbound, e)),
        }
    }

    /// Datagrams to `addr`, as the server's dialer sends them.
    async fn dial_datagram(
        &self,
        dialer: &Dialer,
        addr: SocketAddr,
    ) -> Result<AnyOutboundDatagram> {
        let routed = self.outbound_for(dialer, Network::Udp, addr).await?;
        match (routed, dialer.detour.as_deref()) {
            (None, Some(detour)) => Ok(dialer
                .dial
                .datagram(
                    &self.dispatcher()?.dns_client(),
                    Some(&Self::detour_session(Network::Udp, addr, detour)),
                    &SocksAddr::from(addr),
                )
                .await?),
            (None, None) => {
                let socket = dialer.dial.udp_socket(&addr).await?;
                Ok(Box::new(StdOutboundDatagram::new(socket)))
            }
            (Some((outbound, sess)), _) => {
                let span = sess.span();
                self.dispatcher()?
                    .datagram_via(&outbound, sess)
                    .instrument(span)
                    .await
                    .map_err(|e| anyhow!("through [{}]: {}", outbound, e))
            }
        }
    }

    // -- Asking servers --------------------------------------------------

    /// Asks `server` `request`, within `time`; a race asks its members.
    /// Asking may resolve the server's own name, which asks again. A
    /// sequential server's members that fail are told as events, for the
    /// instance's own query when `for_instance`.
    #[async_recursion]
    async fn query(
        &self,
        server: &Server,
        request: &Message,
        time: Duration,
        for_instance: bool,
    ) -> Result<Asked> {
        if let Kind::Race { members } = &server.kind {
            return self.race(members, request, time).await;
        }
        if let Kind::Sequential(sequential) = &server.kind {
            return self
                .sequential(&server.tag, sequential, request, for_instance)
                .await;
        }
        match timeout(time, self.ask(server, request, time)).await {
            Ok(res) => res.map(|answer| Asked {
                answer,
                member: None,
                attempt: None,
            }),
            Err(_) => Err(anyhow!("{} {}: timeout", server, Self::question(request))),
        }
    }

    /// The question of a query, as logs name it.
    fn question(request: &Message) -> String {
        request
            .queries()
            .first()
            .map(|q| format!("{} {}", q.name(), q.query_type()))
            .unwrap_or_default()
    }

    /// Asks every member at once, and takes the first answer that is not
    /// a failure, as Mihomo does: an error, a timeout, SERVFAIL or REFUSED
    /// counts as none, and the others are waited for.
    async fn race(&self, members: &[String], request: &Message, time: Duration) -> Result<Asked> {
        let asks = members.iter().map(|tag| {
            Box::pin(async move {
                let server = self.server(tag)?;
                let answered = match timeout(time, self.ask(server, request, time)).await {
                    Ok(answered) => answered,
                    Err(_) => Err(anyhow!("timeout")),
                };
                match answered {
                    Ok(Answer::Message(m))
                        if matches!(
                            m.response_code(),
                            ResponseCode::ServFail | ResponseCode::Refused
                        ) =>
                    {
                        Err(anyhow!("[{}]: {}", tag, m.response_code()))
                    }
                    Ok(answer) => Ok(Asked {
                        answer,
                        member: Some(tag.clone()),
                        attempt: None,
                    }),
                    Err(e) => Err(anyhow!("[{}]: {}", tag, e)),
                }
            })
        });
        match select_ok(asks).await {
            Ok((asked, _)) => Ok(asked),
            Err(e) => Err(anyhow!(
                "{}: every server failed, the last {}",
                Self::question(request),
                e
            )),
        }
    }

    /// Asks a sequential server's members one after another, from the one
    /// it prefers, each for its attempt's time and the last for what the
    /// budget leaves, until one answers: any answer, SERVFAIL and REFUSED
    /// too, is its member's. One that does not answer passes the query on.
    /// A kept connection that times out does not: the member is asked once
    /// more on a new connection, with a whole attempt's time, as a NAT that
    /// forgot the connection leaves it silent rather than closed. When no
    /// member answers within the budget, the query fails, which a client is
    /// answered SERVFAIL for.
    async fn sequential(
        &self,
        tag: &str,
        sequential: &server::Sequential,
        request: &Message,
        for_instance: bool,
    ) -> Result<Asked> {
        let started = tokio::time::Instant::now();
        let deadline = started + sequential.budget;
        let n = sequential.members.len();
        let first = {
            let mut preferred = sequential
                .preferred
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match *preferred {
                Some((i, since)) if since.elapsed() < sequential.prefer_for => i,
                _ => {
                    *preferred = None;
                    0
                }
            }
        };
        let (name, ty) = request
            .queries()
            .first()
            .map(|q| (q.name().to_utf8(), q.query_type().to_string()))
            .unwrap_or_default();
        let mut slot = 0;
        let mut attempt = 0;
        let mut fresh = false;
        let mut retried = false;
        let mut failed = anyhow!("no member was asked");
        while slot < n {
            let now = tokio::time::Instant::now();
            let left = deadline.saturating_duration_since(now);
            if left.is_zero() {
                break;
            }
            let i = (first + slot) % n;
            let member = &sequential.members[i];
            let limit = if slot == n - 1 {
                left
            } else {
                sequential.attempt.min(left)
            };
            let kept_timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let scope = upstream::Attempt {
                reuse: (!fresh).then_some(sequential.attempt / 2),
                kept_timed_out: kept_timed_out.clone(),
            };
            attempt += 1;
            let server = self.server(member)?;
            let answered = upstream::ATTEMPT
                .scope(scope, timeout(limit, self.ask(server, request, limit)))
                .await;
            let ms = now.elapsed().as_millis();
            match answered {
                Ok(Ok(answer)) => {
                    let (rcode, answers) = match &answer {
                        Answer::Message(m) => (m.response_code().to_string(), m.answers().len()),
                        _ => ("NoError".into(), 0),
                    };
                    debug!(
                        name = %name, r#type = %ty, server = %member, attempt, rcode = %rcode,
                        answers, ms, "dns: [{}] answered", tag
                    );
                    if i != first && !sequential.prefer_for.is_zero() {
                        *sequential
                            .preferred
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = Some((i, now));
                    }
                    return Ok(Asked {
                        answer,
                        member: Some(member.clone()),
                        attempt: Some(attempt),
                    });
                }
                Ok(Err(e)) => {
                    debug!(
                        name = %name, r#type = %ty, server = %member, attempt, error = %e,
                        ms, "dns: [{}] member failed", tag
                    );
                    self.member_failed(request, member, &e, now.elapsed(), attempt, for_instance);
                    if kept_timed_out.load(std::sync::atomic::Ordering::Relaxed) && !retried {
                        retried = true;
                        fresh = true;
                        continue;
                    }
                    failed = e;
                }
                Err(_) => {
                    debug!(
                        name = %name, r#type = %ty, server = %member, attempt, error = "timeout",
                        ms, "dns: [{}] member failed", tag
                    );
                    failed = anyhow!("[{}]: timeout", member);
                    let timed_out = anyhow!("timeout");
                    self.member_failed(
                        request,
                        member,
                        &timed_out,
                        now.elapsed(),
                        attempt,
                        for_instance,
                    );
                }
            }
            fresh = false;
            slot += 1;
        }
        Err(anyhow!(
            "{}: [{}] had no answer within {:?}: {}",
            Self::question(request),
            tag,
            sequential.budget,
            failed
        ))
    }

    /// Asks one server that is not a race, within `time`.
    async fn ask(&self, server: &Server, request: &Message, time: Duration) -> Result<Answer> {
        let query = request
            .queries()
            .first()
            .ok_or_else(|| anyhow!("a query without a question"))?;
        let (name, ty) = (query.name(), query.query_type());
        let host = name.to_utf8();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host = host.as_str();
        match &server.kind {
            // As sing-box's local server: the names of the hosts file, those
            // of the LAN devices under `neighbor_domain`, and mDNS for
            // `.local` off Apple's systems.
            Kind::Local(local)
                if local.asks_mdns(host)
                    || (matches!(ty, RecordType::A | RecordType::AAAA)
                        && (local.hosts.get(host).is_some()
                            || local.neighbor_addresses(host).is_some())) =>
            {
                match Self::from_hosts(&local.hosts, request, host, ty) {
                    FromHosts::Reply(reply) => Ok(Answer::Message(reply)),
                    FromHosts::Alias(target, strategy) => {
                        let ips = self
                            .lookup_by(&target, strategy, By::Rules(&LookupContext::default()))
                            .await?;
                        Ok(Answer::Message(Self::alias_reply(
                            request, &target, &ips, HOSTS_TTL,
                        )?))
                    }
                    FromHosts::Missing => match local
                        .neighbor_addresses(host)
                        .filter(|_| matches!(ty, RecordType::A | RecordType::AAAA))
                    {
                        // sing-box's FixedResponse: the addresses of the
                        // query's family, with its default TTL.
                        Some(ips) => {
                            let ips: Vec<IpAddr> = ips
                                .into_iter()
                                .filter(|ip| ip.is_ipv4() == (ty == RecordType::A))
                                .collect();
                            Ok(Answer::Message(Self::reply(request, &ips, NEIGHBOR_TTL)))
                        }
                        None => local
                            .mdns
                            .exchange(request, time.min(mdns::WAIT))
                            .await
                            .map(Answer::Message),
                    },
                }
            }
            Kind::Mdns(mdns) => mdns
                .exchange(request, time.min(mdns::WAIT))
                .await
                .map(Answer::Message),
            // As sing-box's local server off Apple's systems: the system's
            // servers, in turn, through the server's dialer.
            Kind::Local(local) if local.dialed.is_some() => {
                let dialed = local.dialed.as_ref().expect("dialed");
                let wire = Self::wire(server, request)?;
                let mut last_err = None;
                let interface = dialed.interface.now();
                // The dialer sends through an interface and has none now: no
                // server could be reached past the TUN, and the system's
                // other servers are not those of the network it will be on.
                if interface.is_none() && dialed.interface.names_one() {
                    return Err(anyhow!("{}: no interface to send through", server));
                }
                let chosen = dialed.servers.choose(
                    &dialed.own_interfaces,
                    interface.as_deref(),
                    host,
                    dialed.split,
                )?;
                // A split resolver is asked through its own interface,
                // which is seldom the one the dialer follows.
                let bound;
                let dialer = match &chosen.interface {
                    Some(via) => {
                        debug!(
                            "{}: {} is under {}: asking its servers on {}",
                            server,
                            host,
                            chosen.domain.as_deref().unwrap_or_default(),
                            via
                        );
                        bound = Dialer {
                            dial: dialed.dialer.dial.bound_to(via),
                            ..dialed.dialer.clone()
                        };
                        &bound
                    }
                    None => &dialed.dialer,
                };
                let servers = chosen.servers;
                // In order, each with its share of the time left, so that
                // one that does not answer leaves time for the next.
                let asked = system::servers_asked(time, servers.len());
                let deadline = tokio::time::Instant::now() + time;
                for (i, addr) in servers.into_iter().take(asked).enumerate() {
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let share = left / (asked - i) as u32;
                    let asked = self
                        .exchange_plain(dialer, addr, &wire, server, share)
                        .await;
                    match asked {
                        Ok(response) => {
                            debug!("{}: {} answered", server, addr);
                            return Ok(Answer::Message(response));
                        }
                        Err(e) => {
                            debug!("{}: {} failed: {}", server, addr, e);
                            last_err = Some(e);
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| anyhow!("no answer")))
            }
            Kind::Local(_) => {
                let family = match ty {
                    RecordType::A => IpAddr::is_ipv4,
                    RecordType::AAAA => IpAddr::is_ipv6,
                    _ => return Err(anyhow!("the system resolver answers no {} query", ty)),
                };
                let addr = format!("{}:0", host);
                let ips = crate::runtime::scope::spawn_blocking("dns system resolver", move || {
                    use std::net::ToSocketAddrs;
                    addr.to_socket_addrs()
                        .map(|iter| iter.map(|x| x.ip()).collect::<Vec<_>>())
                })
                .await
                .map_err(|e| anyhow!("spawn blocking failed: {}", e))?
                .map_err(|e| anyhow!("system resolver failed: {}", e))?;
                Ok(Answer::Ips(ips.into_iter().filter(family).collect()))
            }
            // As sing-box: the addresses of a name it has, and NXDOMAIN for
            // a name it has not, or any other query. A name another stands
            // for, which it has no addresses of, is looked up, and answered
            // with a CNAME, as Mihomo answers it.
            Kind::Hosts(hosts) => match Self::from_hosts(hosts, request, host, ty) {
                FromHosts::Reply(reply) => Ok(Answer::Message(reply)),
                FromHosts::Alias(target, strategy) => {
                    let ips = self
                        .lookup_by(&target, strategy, By::Rules(&LookupContext::default()))
                        .await?;
                    Ok(Answer::Message(Self::alias_reply(
                        request, &target, &ips, HOSTS_TTL,
                    )?))
                }
                FromHosts::Missing => Ok(Answer::Message(Self::status(
                    request,
                    ResponseCode::NXDomain,
                ))),
            },
            Kind::FakeIp(store) => {
                let v6 = match ty {
                    RecordType::A => false,
                    RecordType::AAAA => true,
                    // No records, as Mihomo answers: those it would have
                    // give the real addresses in their hints.
                    RecordType::HTTPS | RecordType::SVCB => {
                        return Ok(Answer::Message(Self::reply(request, &[], FAKE_IP_TTL)))
                    }
                    _ => return Err(anyhow!("a fakeip server answers no {} query", ty)),
                };
                // A family without a range: no address, and no error.
                let ips = match store.serves(v6) {
                    true => vec![store.create(host, v6)?],
                    false => Vec::new(),
                };
                Ok(Answer::Message(Self::reply(request, &ips, FAKE_IP_TTL)))
            }
            Kind::Udp { address, dialer } => {
                let request = Self::wire(server, request)?;
                let addr = self.server_addr(address).await?;
                self.exchange_plain(dialer, addr, &request, server, time)
                    .await
                    .map(Answer::Message)
            }
            Kind::Tcp {
                address,
                dialer,
                pool,
            } => {
                let request = Self::wire(server, request)?;
                let addr = self.server_addr(address).await?;
                // Outside a sequential attempt, a kept connection has the
                // query's whole time, as before.
                let kept = upstream::kept_wait(time).and_then(|wait| Some((wait, pool.take()?)));
                let response = match kept {
                    Some((wait, mut stream)) => {
                        match timeout(wait, upstream::exchange_framed(&mut stream, &request)).await
                        {
                            Ok(Ok(response)) => {
                                pool.put(stream);
                                response
                            }
                            Ok(Err(e)) => {
                                debug!("{}: kept connection failed: {}", server, e);
                                self.exchange_tcp(dialer, addr, pool, &request).await?
                            }
                            Err(_) => {
                                debug!("{}: kept connection timed out", server);
                                if upstream::kept_timed_out() {
                                    return Err(anyhow!("{}: kept connection timed out", server));
                                }
                                self.exchange_tcp(dialer, addr, pool, &request).await?
                            }
                        }
                    }
                    None => self.exchange_tcp(dialer, addr, pool, &request).await?,
                };
                Self::parse(&response, &request, server).map(Answer::Message)
            }
            Kind::Upstream(upstream) => {
                let request = Self::wire(server, request)?;
                let mut last_err = None;
                for _ in 0..self.tuning.max_retries.max(1) {
                    match self.exchange_upstream(upstream, &request).await {
                        Ok(response) => {
                            return Self::parse(&response, &request, server).map(Answer::Message)
                        }
                        Err(e) => {
                            debug!("{} failed: {}", server, e);
                            // A stale-connection probe ends this sequential
                            // attempt. Let its caller give the replacement a
                            // full budget instead of retrying inside the time
                            // the probe left over.
                            if upstream::ATTEMPT
                                .try_with(|attempt| {
                                    attempt
                                        .kept_timed_out
                                        .load(std::sync::atomic::Ordering::Relaxed)
                                })
                                .unwrap_or(false)
                            {
                                return Err(e);
                            }
                            last_err = Some(e);
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| anyhow!("no answer")))
            }
            Kind::Race { .. } => unreachable!("query() takes a race"),
            Kind::Sequential(_) => unreachable!("query() takes a sequential server"),
        }
    }

    /// What `hosts` answer `request` for `host`, of type `ty`: the
    /// addresses of a name they have, and nothing for another query.
    fn from_hosts(
        hosts: &server::Hosts,
        request: &Message,
        host: &str,
        ty: RecordType,
    ) -> FromHosts {
        let family = match ty {
            RecordType::A => IpAddr::is_ipv4 as fn(&IpAddr) -> bool,
            RecordType::AAAA => IpAddr::is_ipv6 as fn(&IpAddr) -> bool,
            _ => return FromHosts::Missing,
        };
        match hosts.resolve(host) {
            Some(server::Host::Ips(ips)) => {
                let ips: Vec<IpAddr> = ips.into_iter().filter(family).collect();
                FromHosts::Reply(Self::reply(request, &ips, HOSTS_TTL))
            }
            Some(server::Host::Alias(target)) => {
                let strategy = match ty {
                    RecordType::A => DnsStrategy::Ipv4Only,
                    _ => DnsStrategy::Ipv6Only,
                };
                FromHosts::Alias(target, strategy)
            }
            None => FromHosts::Missing,
        }
    }

    /// `request` as it goes to `server`: with the client subnet the server
    /// sets.
    fn wire(server: &Server, request: &Message) -> Result<Vec<u8>> {
        match server.client_subnet {
            Some(prefix) => {
                let mut request = request.clone();
                rules::set_client_subnet(&mut request, prefix);
                Ok(request.to_vec()?)
            }
            None => Ok(request.to_vec()?),
        }
    }

    /// Sends `request` until an answer comes, as many times as
    /// `max_retries` says.
    async fn exchange_udp(
        &self,
        socket: AnyOutboundDatagram,
        request: &[u8],
        addr: SocketAddr,
        server: &Server,
        time: Duration,
    ) -> Result<Message> {
        let to = SocksAddr::from(addr);
        let (mut r, mut s) = socket.split();
        let attempts = self.tuning.max_retries.max(1);
        // The query's time, shared by the attempts: a datagram lost is sent
        // again.
        let wait = time / attempts as u32;
        let mut last_err = anyhow!("no answer");
        for _ in 0..attempts {
            if let Err(e) = s.send_to(request, &to).await {
                last_err = anyhow!("send: {}", e);
                continue;
            }
            let deadline = tokio::time::Instant::now() + wait;
            let mut buf = vec![0u8; 4096];
            loop {
                match tokio::time::timeout_at(deadline, r.recv_from(&mut buf)).await {
                    // A late answer to an earlier attempt, or to nothing.
                    Ok(Ok((n, _))) if buf.get(..2) != request.get(..2) || n < 2 => continue,
                    Ok(Ok((n, _))) => return Self::parse(&buf[..n], request, server),
                    Ok(Err(e)) => last_err = anyhow!("receive: {}", e),
                    Err(_) => last_err = anyhow!("timeout"),
                }
                break;
            }
        }
        Err(last_err)
    }

    /// Asks `addr` over UDP, and again over TCP when the answer is cut
    /// short (TC), within `time`, as sing-box's local and UDP servers do.
    async fn exchange_plain(
        &self,
        dialer: &Dialer,
        addr: SocketAddr,
        request: &[u8],
        server: &Server,
        time: Duration,
    ) -> Result<Message> {
        let deadline = tokio::time::Instant::now() + time;
        let socket = self.dial_datagram(dialer, addr).await?;
        let response = self
            .exchange_udp(socket, request, addr, server, time)
            .await?;
        if !response.metadata.truncation {
            return Ok(response);
        }
        debug!("{}: {} cut its answer short; asking over TCP", server, addr);
        let over_tcp = async {
            let mut stream = self.dial_stream(dialer, addr).await?;
            upstream::exchange_framed(&mut stream, request).await
        };
        let response = tokio::time::timeout_at(deadline, over_tcp)
            .await
            .map_err(|_| anyhow!("{}: timeout over TCP after a truncated answer", server))??;
        Self::parse(&response, request, server)
    }

    async fn exchange_tcp(
        &self,
        dialer: &Dialer,
        addr: SocketAddr,
        pool: &upstream::StreamPool,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let mut stream = self.dial_stream(dialer, addr).await?;
        let response = upstream::exchange_framed(&mut stream, request).await?;
        pool.put(stream);
        Ok(response)
    }

    /// An answer to `request`, whatever its code: that the server failed,
    /// or refuses, is an answer the rules can match, as in sing-box.
    fn parse(response: &[u8], request: &[u8], server: &Server) -> Result<Message> {
        if response.get(..2) != request.get(..2) {
            return Err(anyhow!("{}: an answer to another query", server));
        }
        Message::from_vec(response).map_err(|e| anyhow!("{}: invalid answer: {}", server, e))
    }

    /// An answer to `request` made here: `ips` of the family asked for.
    /// A reply that the name asked for is `target`, with its addresses.
    fn alias_reply(request: &Message, target: &str, ips: &[IpAddr], ttl: u32) -> Result<Message> {
        let mut reply = Self::reply(request, &[], ttl);
        let Some(query) = request.queries().first() else {
            return Ok(reply);
        };
        let target = Name::from_str(&format!("{}.", target))
            .map_err(|e| anyhow!("invalid domain name [{}]: {}", target, e))?;
        reply.add_answer(Record::from_rdata(
            query.name().clone(),
            ttl,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
        ));
        for ip in ips {
            let data = match ip {
                IpAddr::V4(v4) => RData::A((*v4).into()),
                IpAddr::V6(v6) => RData::AAAA((*v6).into()),
            };
            reply.add_answer(Record::from_rdata(target.clone(), ttl, data));
        }
        Ok(reply)
    }

    fn reply(request: &Message, ips: &[IpAddr], ttl: u32) -> Message {
        let mut reply = Message::new(0, MessageType::Query, OpCode::Query);
        reply.set_id(request.id());
        reply.set_message_type(MessageType::Response);
        reply.set_op_code(OpCode::Query);
        reply.set_recursion_desired(request.recursion_desired());
        reply.set_recursion_available(true);
        reply.set_response_code(ResponseCode::NoError);
        if let Some(query) = request.queries().first() {
            reply.add_query(query.clone());
            for ip in ips {
                let data = match ip {
                    IpAddr::V4(v4) => RData::A((*v4).into()),
                    IpAddr::V6(v6) => RData::AAAA((*v6).into()),
                };
                reply.add_answer(Record::from_rdata(query.name().clone(), ttl, data));
            }
        }
        reply
    }

    // -- Reading answers -------------------------------------------------

    /// The addresses a response for `host` carries, kept for its TTL.
    fn answer_ips(response: &Message, host: &str) -> Result<Vec<IpAddr>> {
        match response.response_code() {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Err(anyhow!("{} does not exist", host)),
            code => return Err(anyhow!("{}: {}", host, code)),
        }
        let ips = rules::addresses(response);
        if ips.is_empty() {
            return Err(anyhow!("no address for {}", host));
        }
        debug!("{} is {:?}", host, ips);
        Ok(ips)
    }

    /// The ECH configs an HTTPS or SVCB answer carries.
    fn ech_entry(message: &Message, host: &str, ty: RecordType) -> Result<EchCacheEntry> {
        let mut found = false;
        for ans in message.answers() {
            if ans.record_type() != ty {
                continue;
            }
            let data = &ans.data;
            found = true;
            if let Some(ech_config_list) = Self::extract_ech_config_list(&data.to_string()) {
                let deadline = Instant::now()
                    .checked_add(Duration::from_secs(ans.ttl.into()))
                    .ok_or_else(|| anyhow!("invalid ttl"))?;
                debug!("{} {} has an ech config", host, ty);
                return Ok(EchCacheEntry {
                    ech_config_list,
                    deadline,
                });
            }
        }
        if found {
            return Err(anyhow!(
                "missing ech parameter in {} record for {}",
                ty,
                host
            ));
        }
        Err(anyhow!("no {} records for {}", ty, host))
    }

    fn extract_ech_config_list(rdata: &str) -> Option<String> {
        fn extract_quoted(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let rest = &haystack[start + key.len()..];
            let end = rest.find('"')?;
            let value = rest[..end].trim();
            (!value.is_empty()).then(|| value.to_string())
        }

        fn extract_plain(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let rest = &haystack[start + key.len()..];
            let end = rest
                .find(|c: char| c.is_ascii_whitespace() || c == ',')
                .unwrap_or(rest.len());
            let value = rest[..end].trim();
            (!value.is_empty()).then(|| value.to_string())
        }

        extract_quoted(rdata, "echconfig=\"")
            .or_else(|| extract_quoted(rdata, "ech=\""))
            .or_else(|| extract_plain(rdata, "echconfig="))
            .or_else(|| extract_plain(rdata, "ech="))
    }

    fn new_query(name: Name, ty: RecordType) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(name, ty));
        let mut rng = StdRng::from_entropy();
        let id: u16 = rng.gen();
        msg.set_id(id);
        msg.set_op_code(OpCode::Query);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        msg
    }

    // -- Clients' queries ------------------------------------------------

    /// What `ip` is to the fakeip server: a connection to it goes to the
    /// domain it was handed out for.
    pub fn fake_ip(&self, ip: IpAddr) -> FakeIp {
        self.fake_ips
            .as_ref()
            .map_or(FakeIp::NotFake, |store| store.lookup(ip))
    }

    /// The fake IP handed out for `domain`, of the family asked for.
    pub fn fake_ip_of(&self, domain: &str, ipv6: bool) -> Option<IpAddr> {
        self.fake_ips
            .as_ref()
            .and_then(|store| store.address_of(domain, ipv6))
    }

    /// Answers a client's DNS query from the server the rules pick for it:
    /// what the server answered, with the query's ID, or REFUSED for a
    /// rule that rejects it, or SERVFAIL when the server did not answer.
    /// An error only when `query` is not a DNS message.
    pub async fn exchange(&self, query: &[u8], ctx: &LookupContext) -> Result<Vec<u8>> {
        let request = Message::from_vec(query).map_err(|e| anyhow!("not a dns message: {}", e))?;
        let response = self.answer(&request, ctx).await;
        Ok(response.to_vec()?)
    }

    async fn answer(&self, request: &Message, ctx: &LookupContext) -> Message {
        let ctx = &*self.pinned(ctx);
        let Some(query) = request.queries().first() else {
            return Self::status(request, ResponseCode::FormErr);
        };
        if request.message_type() != MessageType::Query || request.op_code() != OpCode::Query {
            return Self::status(request, ResponseCode::NotImp);
        }
        let ty = query.query_type();
        let host = query.name().to_utf8();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let strategy = self.query_strategy(&host, ty, ctx);
        // A family the strategy, or `client_strategy`, leaves out has no
        // records.
        let leaves_out = |strategy: DnsStrategy| {
            (ty == RecordType::AAAA && strategy == DnsStrategy::Ipv4Only)
                || (ty == RecordType::A && strategy == DnsStrategy::Ipv6Only)
        };
        if leaves_out(strategy) || self.client_strategy.is_some_and(leaves_out) {
            return Self::reply(request, &[], LOCAL_TTL.as_secs() as u32);
        }
        match self.walk(request, ctx, true).await {
            Ok(rules::Walked::Response(mut response)) => {
                response.set_id(request.id());
                self.record_reverse_mapping(&response).await;
                *response
            }
            Ok(rules::Walked::Refused) => Self::status(request, ResponseCode::Refused),
            Err(e) => {
                debug!("{}: {}", Self::question(request), e);
                Self::status(request, ResponseCode::ServFail)
            }
        }
    }

    /// With `dns.reverse_mapping`, keeps the domain each address of
    /// `response` is given for, for its TTL, as sing-box's DNS router does
    /// with the answers it gives (dns/router.go recordReverseMapping): the
    /// record's own name, and no fake IP, which stands for its domain anyway.
    async fn record_reverse_mapping(&self, response: &Message) {
        let Some(map) = &self.reverse_map else {
            return;
        };
        for record in response.answers() {
            let ip = match record.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
                _ => continue,
            };
            if !matches!(self.fake_ip(ip), FakeIp::NotFake) {
                continue;
            }
            let name = record.name.to_utf8();
            let domain = name.trim_end_matches('.').to_string();
            let ttl = Duration::from_secs(u64::from(record.ttl));
            map.add_for(ip, domain, ttl).await;
        }
    }

    /// An answer to `request` with no records, and `code`.
    fn status(request: &Message, code: ResponseCode) -> Message {
        let mut status = Self::reply(request, &[], 0);
        status.set_response_code(code);
        status
    }

    // -- The caches ------------------------------------------------------

    async fn get_cached_ech(&self, host: &str) -> Option<String> {
        let mut cache = self.ech_cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if entry.deadline > Instant::now() {
                return Some(entry.ech_config_list.clone());
            }
        }
        cache.pop(host);
        None
    }

    // -- Lookups ---------------------------------------------------------

    /// The addresses of `host`, from the server the rules pick.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.lookup_in(host, &LookupContext::default()).await
    }

    /// The addresses of `host`, needed for `ctx`, from the servers the
    /// rules pick for each record type.
    pub async fn lookup_in(&self, host: &str, ctx: &LookupContext) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let ctx = &*self.pinned(ctx);
        let strategy = self.lookup_strategy(host, ctx);
        self.lookup_by(host, strategy, By::Rules(ctx)).await
    }

    /// The addresses of `host`, which an outbound dials, its names
    /// resolving as `dial` says: from its `domain_resolver`, or else from
    /// the server the rules pick for that outbound, of the families its
    /// `domain_strategy` says.
    pub async fn lookup_dial(
        &self,
        host: &str,
        dial: &crate::net::dial::ResolveSpec,
    ) -> Result<Vec<IpAddr>> {
        match &dial.domain_resolver {
            Some(resolver) => self.lookup_resolver(resolver, host).await,
            None => {
                let ctx = LookupContext {
                    outbound: dial.outbound.clone(),
                    strategy: dial.strategy,
                    ..Default::default()
                };
                self.lookup_in(host, &ctx).await
            }
        }
    }

    /// The addresses of `host` from the server tagged `server`, of the
    /// families `strategy` says: what the rules have no say in.
    pub async fn lookup_from(
        &self,
        server: &str,
        host: &str,
        strategy: Option<DnsStrategy>,
    ) -> Result<Vec<IpAddr>> {
        let resolver = crate::config::model::DomainResolver {
            server: server.to_string(),
            strategy,
            ..Default::default()
        };
        self.lookup_resolver(&resolver, host).await
    }

    /// The addresses of `host`, from `resolver`'s server, asked as it says:
    /// what the rules have no say in.
    #[async_recursion]
    pub async fn lookup_resolver(
        &self,
        resolver: &crate::config::model::DomainResolver,
        host: &str,
    ) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let options = QueryOptions::of_resolver(resolver);
        let strategy = resolver.strategy.unwrap_or(self.strategy);
        self.lookup_by(host, strategy, By::Server(&resolver.server, &options))
            .await
    }

    /// The addresses of `host`, of the families `strategy` says, from the
    /// servers the rules send each query to, or from one server.
    async fn lookup_by(
        &self,
        host: &str,
        strategy: DnsStrategy,
        by: By<'_>,
    ) -> Result<Vec<IpAddr>> {
        let name = Name::from_str(&format!("{}.", host))
            .map_err(|e| anyhow!("invalid domain name [{}]: {}", host, e))?;
        // Each server's answers are kept, see `resolve`.
        let query = |ty| {
            let request = Self::new_query(name.clone(), ty);
            async move {
                let response = match by {
                    By::Rules(ctx) => match self.walk(&request, ctx, false).await? {
                        rules::Walked::Response(response) => *response,
                        rules::Walked::Refused => {
                            return Err(anyhow!("{} {}: rejected by a dns rule", host, ty))
                        }
                    },
                    By::Server(tag, options) => self.resolve(tag, &request, options).await?,
                };
                Self::answer_ips(&response, host)
            }
        };

        let single = match strategy {
            DnsStrategy::Ipv4Only => Some(RecordType::A),
            DnsStrategy::Ipv6Only => Some(RecordType::AAAA),
            DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => None,
        };
        if let Some(ty) = single {
            return query(ty).await;
        }

        let delay = self.tuning.dualstack_delay;
        let mut a = Box::pin(query(RecordType::A));
        let mut aaaa = Box::pin(query(RecordType::AAAA));
        let (first, second) = if strategy == DnsStrategy::PreferIpv6 {
            Self::dualstack_query(&mut aaaa, &mut a, delay).await?
        } else {
            Self::dualstack_query(&mut a, &mut aaaa, delay).await?
        };
        // Each once: an answer need not be of the type asked, as a
        // predefined one is not.
        let mut ips: Vec<IpAddr> = Vec::new();
        for ip in first.into_iter().chain(second.into_iter().flatten()) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        Ok(ips)
    }

    /// The answer of `preferred`, or of `fallback` when `preferred` has
    /// none within `delay`, and the other one too if it is already there.
    async fn dualstack_query<T, P, F>(
        preferred: &mut P,
        fallback: &mut F,
        delay: Duration,
    ) -> Result<(T, Option<T>)>
    where
        P: std::future::Future<Output = Result<T>> + Unpin,
        F: std::future::Future<Output = Result<T>> + Unpin,
    {
        let delay_fut = tokio::time::sleep(delay);
        tokio::pin!(delay_fut);

        let first = tokio::select! {
            biased;
            r = &mut *preferred => Some((true, r)),
            _ = &mut delay_fut => None,
        };

        let (first_is_preferred, first_res) = match first {
            Some(v) => v,
            None => tokio::select! {
                r = &mut *preferred => (true, r),
                r = &mut *fallback => (false, r),
            },
        };

        match first_res {
            Ok(entry) => {
                let other = if first_is_preferred {
                    match timeout(Duration::from_millis(0), &mut *fallback).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                } else {
                    match timeout(Duration::from_millis(0), &mut *preferred).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                };
                Ok((entry, other))
            }
            Err(err1) => {
                let second_res = if first_is_preferred {
                    (&mut *fallback).await
                } else {
                    (&mut *preferred).await
                };
                match second_res {
                    Ok(entry) => Ok((entry, None)),
                    Err(err2) => Err(anyhow!("all dns queries failed: {}; {}", err1, err2)),
                }
            }
        }
    }

    /// The ECH configs `host` publishes, in an HTTPS record or else an SVCB
    /// one, from the server the rules pick.
    pub async fn lookup_ech_config_list(&self, host: &str) -> Result<String> {
        if let Some(cached) = self.get_cached_ech(host).await {
            return Ok(cached);
        }
        let host_lock = {
            let mut locks = self.ech_query_locks.lock().await;
            locks
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };
        let _query_guard = host_lock.lock().await;
        let result = match self.get_cached_ech(host).await {
            Some(cached) => Ok(cached),
            None => match self.query_ech(host).await {
                Ok(entry) => {
                    let list = entry.ech_config_list.clone();
                    self.ech_cache.lock().await.put(host.to_owned(), entry);
                    Ok(list)
                }
                Err(e) => Err(e),
            },
        };
        {
            let mut locks = self.ech_query_locks.lock().await;
            if let Some(current) = locks.get(host) {
                if Arc::ptr_eq(current, &host_lock) {
                    locks.remove(host);
                }
            }
        }
        result
    }

    async fn query_ech(&self, host: &str) -> Result<EchCacheEntry> {
        let name = Name::from_str(&format!("{}.", host))
            .map_err(|e| anyhow!("invalid domain name [{}]: {}", host, e))?;
        let mut errors = Vec::new();
        for ty in [RecordType::HTTPS, RecordType::SVCB] {
            let request = Self::new_query(name.clone(), ty);
            match self.walk(&request, &LookupContext::default(), false).await {
                Ok(rules::Walked::Response(response)) => {
                    match Self::ech_entry(&response, host, ty) {
                        Ok(entry) => return Ok(entry),
                        Err(e) => errors.push(format!("{}: {}", ty, e)),
                    }
                }
                Ok(rules::Walked::Refused) => {
                    errors.push(format!("{}: rejected by a dns rule", ty))
                }
                Err(e) => errors.push(format!("{}: {}", ty, e)),
            }
        }
        Err(anyhow!(
            "ech query failed for {}: {}",
            host,
            errors.join("; ")
        ))
    }
}

include!("client/tests.rs");
