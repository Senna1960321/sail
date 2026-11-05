use std::future::Future;
use std::io::{self};

use crate::app::dns::FakeIp;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn, Instrument};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    net,
    session::*,
    sniff::{self, dns::SniffingDatagram},
};

use super::nat_manager::UdpPacket;

use tokio::io::AsyncWriteExt;

async fn healthcheck_respond_simple<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    stream.write_all(b"PONG").await?;
    stream.flush().await?;
    Ok(())
}

use crate::app::SyncStatManager;

use super::router::{Decision, NoSniffer, Passes, PreMatch, SniffAction, Sniffer};
use crate::config::model::OverrideDestination;

/// Where routing sends a connection.
enum Routed {
    /// Through this outbound; `None`, through the implicit direct, where
    /// every rule and `final` passed the connection on.
    Outbound(Option<String>),
    /// To the DNS client, which answers the queries it carries.
    HijackDns,
    /// Nowhere, and it is left unanswered.
    Drop,
}

/// How long a dropped connection is held unanswered at most: past it, any
/// client has given up.
const DROP_HOLD: std::time::Duration = std::time::Duration::from_secs(60);
use super::{SyncOutboundManager, SyncRouter};

/// Records on `sess` what a `sniff` rule found: the protocol, and the
/// domain a TLS ClientHello, over TCP or QUIC, or an HTTP request names. A
/// DNS query's domain is not where it goes, and is left out.
fn record_sniffed(
    sess: &mut Session,
    action: &SniffAction,
    protocol: SniffedProtocol,
    domain: Option<String>,
) {
    sess.sniffed_protocol = Some(protocol);
    let from = match protocol {
        SniffedProtocol::Tls | SniffedProtocol::Quic => SniffedFrom::Tls,
        SniffedProtocol::Http => SniffedFrom::Http,
        _ => {
            debug!("sniffed protocol={}", protocol);
            return;
        }
    };
    let Some(domain) = domain else {
        debug!("sniffed protocol={}", protocol);
        return;
    };
    if action.skip.matches(&domain) {
        debug!(
            "sniffed protocol={} domain={}, not taken",
            protocol, &domain
        );
        return;
    }
    debug!("sniffed protocol={} domain={}", protocol, &domain);
    // Only Mihomo's match-time override changes the destination here; the
    // dial-time one leaves the rules the address.
    if action.override_destination == Some(OverrideDestination::AtSniff)
        && net::dial_domain::usable(&domain)
    {
        if let Ok(dest) = SocksAddr::try_from((domain.as_str(), sess.destination.port())) {
            debug!("override destination with sniffed domain={}", dest);
            sess.destination = dest;
        }
    }
    sess.set_sniffed_domain(from, domain);
}

/// Whether a `sniff` rule has nothing to do for `sess`: its protocol is
/// known already, or the server of its port speaks first.
fn sniffed_already(sess: &Session) -> bool {
    sess.sniffed_protocol.is_some() || sniff::skips_port(sess.destination.port())
}

/// Sniffs a TCP connection the first time a rule asks, and keeps what it
/// read for whoever reads the connection next. A connection no rule sniffs
/// is left as it is.
struct StreamSniffer<T> {
    stream: Option<T>,
    sniffing: Option<sniff::SniffingStream<T>>,
}

impl<T> StreamSniffer<T>
where
    T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn new(stream: T) -> Self {
        StreamSniffer {
            stream: Some(stream),
            sniffing: None,
        }
    }

    fn into_stream(self) -> Box<dyn ProxyStream> {
        match (self.sniffing, self.stream) {
            (Some(sniffing), _) => Box::new(sniffing),
            (None, Some(stream)) => Box::new(stream),
            (None, None) => unreachable!("the stream is in one or the other"),
        }
    }
}

#[async_trait::async_trait]
impl<T> Sniffer for StreamSniffer<T>
where
    T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()> {
        let protocols = action.protocols.stream();
        if protocols.is_empty() || sniffed_already(sess) {
            return Ok(());
        }
        let sniffing = match self.sniffing.as_mut() {
            Some(sniffing) => sniffing,
            None => {
                let Some(stream) = self.stream.take() else {
                    return Ok(());
                };
                self.sniffing.insert(sniff::SniffingStream::new(stream))
            }
        };
        if let Some((protocol, domain)) = sniffing.sniff(protocols, action.timeout).await? {
            record_sniffed(sess, action, protocol, domain);
            // What rules match of a plain HTTP request: its URL and
            // User-Agent, never logged.
            if protocol == SniffedProtocol::Http {
                let request = sniff::http::request(sniffing.buffered());
                sess.sniffed_http = Some(std::sync::Arc::new(request));
            }
        }
        Ok(())
    }
}

/// Sniffs a UDP session from the datagrams its client sends first, taken
/// off the session's uplink while it is routed; they are sent on once it
/// is.
pub(crate) struct DatagramSniffer<'a> {
    uplink: &'a mut tokio::sync::mpsc::Receiver<UdpPacket>,
    /// The datagrams taken off the uplink, in order.
    read: Vec<UdpPacket>,
    /// The uplink has closed.
    closed: bool,
}

impl<'a> DatagramSniffer<'a> {
    pub(crate) fn new(uplink: &'a mut tokio::sync::mpsc::Receiver<UdpPacket>) -> Self {
        DatagramSniffer {
            uplink,
            read: Vec::new(),
            closed: false,
        }
    }

    /// The datagrams sniffing took off the uplink, still to be sent.
    pub(crate) fn into_read(self) -> Vec<UdpPacket> {
        self.read
    }
}

#[async_trait::async_trait]
impl Sniffer for DatagramSniffer<'_> {
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()> {
        let protocols = action.protocols.datagram();
        if protocols.is_empty() || sniffed_already(sess) {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + action.timeout;
        let mut sniff = sniff::DatagramSniff::new(protocols);
        // Those read by an earlier sniff first, then more as they come. Only
        // those to the session's destination are the client's first ones.
        for next in 0.. {
            if next == self.read.len() {
                if self.closed || next >= sniff::MAX_SNIFF_DATAGRAMS {
                    break;
                }
                match tokio::time::timeout_at(deadline, self.uplink.recv()).await {
                    Ok(Some(packet)) => self.read.push(packet),
                    Ok(None) => {
                        self.closed = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            let packet = &self.read[next];
            if packet.dst_addr != sess.destination {
                continue;
            }
            match sniff.feed(&packet.data) {
                sniff::Sniffed::Found(protocol, domain) => {
                    record_sniffed(sess, action, protocol, domain);
                    return Ok(());
                }
                sniff::Sniffed::NeedMore => {}
                sniff::Sniffed::NotMatch => break,
            }
        }
        if let Some(protocol) = sniff.settle() {
            record_sniffed(sess, action, protocol, None);
        }
        Ok(())
    }
}

struct HealthcheckUdpRecvHalf {
    responded: bool,
    src_addr: SocksAddr,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for HealthcheckUdpRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        if self.responded {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more data"));
        }
        let pong = b"PONG";
        if buf.len() < pong.len() {
            return Err(io::Error::other("buffer too small"));
        }
        buf[..pong.len()].copy_from_slice(pong);
        self.responded = true;
        Ok((pong.len(), self.src_addr.clone()))
    }
}

struct HealthcheckUdpSendHalf;

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for HealthcheckUdpSendHalf {
    async fn send_to(&mut self, buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HealthcheckUdpDatagram {
    recv: HealthcheckUdpRecvHalf,
    send: HealthcheckUdpSendHalf,
}

impl OutboundDatagram for HealthcheckUdpDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

/// A UDP session dispatched: its datagrams, how long it may stand idle
/// where a rule says, and the session as it is listed, where it is (the
/// datagrams of hijacked DNS and health checks are not).
pub type DispatchedDatagram = (
    Box<dyn OutboundDatagram>,
    Option<std::time::Duration>,
    Option<std::sync::Arc<super::stat_manager::Counter>>,
);

/// A connection handed over to its outbound: what its relay keeps.
struct Established {
    lhs: AnyStream,
    rhs: AnyStream,
    /// Its place among the sessions, held while it is relayed.
    place: Option<super::sessions::Place>,
    /// What its relay's failure is told with.
    destination: SocksAddr,
    path: Box<str>,
    /// As it is listed: told how its relay ended.
    listed: Option<std::sync::Arc<super::stat_manager::Counter>>,
}

#[inline]
/// The outbound `tag` with the members the groups on the way took,
/// outermost first, `group>member`, so that a failure names the member it
/// is in.
fn outbound_path(sess: &Session, tag: &str) -> String {
    std::iter::once(tag.to_string())
        .chain(sess.chain.get())
        .collect::<Vec<_>>()
        .join(">")
}

/// The outbounds a connection went through, outermost first, as
/// `outbound_path` joins them.
pub(crate) fn outbound_chain(sess: &Session, tag: &str) -> Vec<String> {
    std::iter::once(tag.to_string())
        .chain(sess.chain.get())
        .collect()
}

/// What routing found of a connection, kept beside it until it is told
/// (control::events' `RoutedConnection`), not in its session.
#[derive(Debug, Clone, Copy, Default)]
struct Matched {
    /// The index of the rule that decided, looked up only while someone
    /// listens for routed connections.
    rule: Option<u32>,
    /// A rule rejected it.
    rejected: bool,
}

/// What is told of a connection besides its session.
#[derive(Debug, Clone, Copy, Default)]
struct Told<'a> {
    matched: Matched,
    /// As the connections list it, once it is listed.
    id: Option<u64>,
    /// What the outbound was asked to reach.
    asked: Option<&'a SocksAddr>,
}

/// The domain known for `sess`, and where it came from.
pub(crate) fn domain_of(sess: &Session) -> Option<(String, crate::control::events::DomainSource)> {
    use crate::control::events::DomainSource;
    use crate::session::{DialDomainSource, Dialled, SniffedFrom};
    if let Some(domain) = sess.destination.domain() {
        let source = match sess.fake_ip {
            true => DomainSource::FakeIp,
            false => DomainSource::Request,
        };
        return Some((domain.clone(), source));
    }
    if let Some((domain, source)) = sess.state.get::<Dialled>().get() {
        let source = match source {
            DialDomainSource::Sniff => DomainSource::Sniffed,
            DialDomainSource::ReverseMapping => DomainSource::ReverseMapping,
        };
        return Some((domain, source));
    }
    sess.sniffed.as_ref().map(|(from, domain)| {
        let source = match from {
            SniffedFrom::Dns => DomainSource::ReverseMapping,
            SniffedFrom::Http | SniffedFrom::Tls => DomainSource::Sniffed,
        };
        (domain.clone(), source)
    })
}

impl Dispatcher {
    /// A connection whose dial ended, well or not: logged, and told to
    /// those who listen for routed connections. Every place a dial ends
    /// goes through here, so that none is logged and not told.
    fn handled(
        &self,
        sess: &Session,
        outbound_tag: &str,
        told: Told<'_>,
        connect: Result<std::time::Duration, io::ErrorKind>,
    ) {
        if let (Err(kind), Some(number)) = (connect, &sess.number) {
            number.failed(sess, kind);
        }
        log_request(
            sess,
            outbound_tag,
            connect.ok().map(|took| took.as_millis()),
        );
        self.tell_routed(
            sess,
            Some(outbound_tag),
            told,
            crate::control::events::RouteAction::Outbound,
            Some(connect),
        );
    }

    /// `handled`, of a connection that connected and is listed only now:
    /// `list` lists it, and gives the id it is listed by. Its session is
    /// copied only while someone listens for routed connections.
    fn handled_listing<T>(
        &self,
        sess: Session,
        outbound_tag: &str,
        took: std::time::Duration,
        list: impl FnOnce(Session) -> (T, u64),
    ) -> T {
        if !self.env.events.routes_wanted() {
            log_request(&sess, outbound_tag, Some(took.as_millis()));
            return list(sess).0;
        }
        let (listed, id) = list(sess.clone());
        let told = Told {
            id: Some(id),
            asked: Some(&sess.destination),
            ..Default::default()
        };
        self.handled(&sess, outbound_tag, told, Ok(took));
        listed
    }

    /// Tells of a connection the rules sent to no outbound, which its
    /// closed record tells as blocked, or served here.
    fn unrouted(
        &self,
        sess: &Session,
        matched: Matched,
        action: crate::control::events::RouteAction,
    ) {
        use crate::control::events::{ClosedBy, End, Outcome, RouteAction};
        if let Some(number) = &sess.number {
            match action {
                RouteAction::HijackDns => number.closed(sess, Outcome::Ok, End::Finished),
                _ => number.closed(sess, Outcome::Blocked, End::Closed(ClosedBy::Rules)),
            }
        }
        let told = Told {
            matched,
            ..Default::default()
        };
        self.tell_routed(sess, None, told, action, None);
    }

    /// Tells of a routed connection (control::events), built only while
    /// someone listens: otherwise this is one load of a counter.
    fn tell_routed(
        &self,
        sess: &Session,
        outbound_tag: Option<&str>,
        told: Told<'_>,
        action: crate::control::events::RouteAction,
        connect: Option<Result<std::time::Duration, io::ErrorKind>>,
    ) {
        self.env.events.routed(|| {
            let (domain, domain_source) = match domain_of(sess) {
                Some((domain, source)) => (Some(domain), Some(source)),
                None => (None, None),
            };
            crate::control::events::RoutedConnection {
                id: told.id,
                network: sess.network,
                inbound: sess.inbound_tag.clone(),
                user: crate::user::name(&sess.user).map(str::to_owned),
                source: sess.source,
                destination: sess.destination.clone(),
                request_destination: told.asked.cloned(),
                domain,
                domain_source,
                sniffed_protocol: sess.sniffed_protocol.map(|protocol| protocol.name()),
                rule: told.matched.rule,
                rule_text: sess.matched_rule.as_deref().map(str::to_owned),
                action,
                chain: outbound_tag
                    .map(|tag| outbound_chain(sess, tag))
                    .unwrap_or_default(),
                target: outbound_tag
                    .and_then(|_| sess.state.get::<net::dial::BoundInterface>().peer()),
                connect,
            }
        });
    }

    /// Tells of a connection that failed (control::events): connecting, or
    /// the outbound's handshake, as its error says. `Dial` means "connect,
    /// or timed out": a handshake that times out (the outbound's own, a
    /// TLS one) is `TimedOut` too, until the dispatcher sees how far an
    /// attempt got. A relay that fails later is not told: most end so.
    /// Nothing when a group on the way gave up on it, having told its
    /// last member's failure.
    fn tell_failed(&self, sess: &Session, outbound_tag: &str, e: &io::Error) {
        use crate::control::events::{DialFailure, DialStage};
        if sess.chain.ended() > 0 {
            return;
        }
        self.env.events.dial_failed(DialFailure::new(
            outbound_path(sess, outbound_tag),
            crate::app::logger::destination(&sess.destination).to_string(),
            e.kind(),
            DialStage::guessed(e.kind()),
        ));
    }
}

fn log_request(sess: &Session, outbound_tag: &str, handshake_time: Option<u128>) {
    use crate::app::logger;
    use crate::config::model::LogRedact;
    if !tracing::enabled!(tracing::Level::INFO) {
        return;
    }
    let hs = handshake_time.map_or("failed".to_string(), |hs| format!("{}ms", hs));
    let outbound_tag = outbound_path(sess, outbound_tag);
    let network = sess.network.to_string();
    let src = logger::source(sess.forwarded_source.unwrap_or_else(|| sess.source.ip()));
    let dst = logger::destination(&sess.destination);

    #[cfg(feature = "rule-process-name")]
    {
        let process_name = sess
            .process_name
            .as_ref()
            .map(|x| {
                std::path::Path::new(x)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(x)
            })
            .unwrap_or("");
        if !logger::redacts(LogRedact::Process) {
            info!(
                "handled process={} src={} proto={} in={} out={} connect={} dst={}",
                process_name, src, network, &sess.inbound_tag, outbound_tag, hs, dst,
            );
            return;
        }
    }

    #[cfg(not(feature = "rule-process-name"))]
    let _ = LogRedact::Process;
    info!(
        "handled src={} proto={} in={} out={} connect={} dst={}",
        src, network, &sess.inbound_tag, outbound_tag, hs, dst,
    );
}

pub struct Dispatcher {
    pub(crate) outbound_manager: SyncOutboundManager,
    pub(crate) router: SyncRouter,
    dns_client: SyncDnsClient,
    stat_manager: SyncStatManager,
    env: crate::runtime::SyncRuntimeEnv,
    /// The protocol of each inbound, by tag.
    inbound_types: std::sync::RwLock<std::collections::HashMap<String, &'static str>>,
    /// Who opened the connections of the last few seconds, by socket.
    owners: super::owner::Owners,
    /// The places for sessions, under `inbound.max_connections`.
    sessions: Option<super::sessions::Sessions>,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: SyncOutboundManager,
        router: SyncRouter,
        dns_client: SyncDnsClient,
        stat_manager: SyncStatManager,
        env: crate::runtime::SyncRuntimeEnv,
    ) -> Self {
        net::relay::set_pool_max(env.options.relay.buffer_pool << 10);
        crate::runtime::transfer_budget::configure(&env.options.memory);
        #[cfg(feature = "quic")]
        crate::transport::quic::configure_stall_timeout(env.options.mux.stall_timeout);
        Dispatcher {
            outbound_manager,
            router,
            dns_client,
            stat_manager,
            sessions: super::sessions::Sessions::new(env.options.inbound.max_connections),
            env,
            inbound_types: Default::default(),
            owners: Default::default(),
        }
    }

    /// What holds back handshakes under memory pressure, when it is on.
    pub(crate) fn admission(
        &self,
    ) -> Option<&std::sync::Arc<super::inbound::admission::Admission>> {
        self.env.admission.as_ref()
    }

    /// A place for one more session, or none: it is refused.
    async fn enter(&self) -> Result<Option<super::sessions::Place>, ()> {
        match &self.sessions {
            None => Ok(None),
            Some(sessions) => sessions
                .enter(super::sessions::MAX_CONNECTIONS_WAIT)
                .await
                .map(Some)
                .ok_or(()),
        }
    }

    /// Records the protocol of the inbound `tag`, or forgets the inbound.
    pub fn set_inbound_type(&self, tag: &str, protocol: Option<&str>) {
        let mut types = self
            .inbound_types
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let protocol = protocol.and_then(|protocol| {
            crate::include::inbound_protocol(protocol)
                .or_else(|| self.env.host.kinds.inbound_name(protocol))
        });
        match protocol {
            Some(protocol) => types.insert(tag.to_string(), protocol),
            None => types.remove(tag),
        };
    }

    /// The type of the inbound `tag`, as the configuration names it; none
    /// when the instance has no such inbound.
    pub(crate) fn inbound_type_of(&self, tag: &str) -> Option<&'static str> {
        self.inbound_types
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(tag)
            .copied()
    }

    /// Fills in what the session's inbound tells about it.
    fn identify_inbound(&self, sess: &mut Session) {
        if sess.inbound_type.is_empty() {
            if let Some(protocol) = self
                .inbound_types
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sess.inbound_tag)
            {
                sess.inbound_type = protocol;
            }
        }
    }

    /// The tuning and host of the instance this dispatcher belongs to.
    pub fn env(&self) -> &crate::runtime::RuntimeEnv {
        &self.env
    }

    /// Routes the connection `lhs`, of `sess`, and relays it to where the
    /// routing sends it.
    ///
    /// A connection lives in two phases: its routing, dial and handshake,
    /// in a future of their own that is freed once it is relayed, and the
    /// relay, which is all an established connection keeps. Each relayed
    /// connection is a task as large as what it awaits: inline, the first
    /// phase's state (the session several times over, the routing, the
    /// dial) was kept for as long as the connection lived.
    pub fn dispatch_stream<T>(&self, sess: Session, lhs: T) -> impl Future<Output = ()> + Send + '_
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let span = sess.span();
        let connecting = Box::pin(self.connect_stream(sess, lhs));
        async move {
            if let Some(established) = connecting.await {
                self.relay(established).await;
            }
        }
        .instrument(span)
    }

    /// What a connection keeps once it is relayed.
    async fn relay(&self, established: Established) {
        let Established {
            mut lhs,
            mut rhs,
            place: _place,
            destination,
            path,
            listed,
        } = established;
        let relay = &self.env.options.relay;
        match net::relay::copy_buf_bidirectional_with_timeout(
            &mut lhs,
            &mut rhs,
            relay.buffer_size * 1024,
            relay.buffer_max_size.max(relay.buffer_size) * 1024,
            net::relay::RelayTimeouts {
                write_stall: relay.write_stall_timeout,
                a_to_b_idle: relay.uplink_idle_timeout,
                b_to_a_idle: relay.downlink_idle_timeout,
            },
        )
        .await
        {
            Ok(_) => {
                debug!("transfer end");
            }
            Err(e) => {
                debug!("transfer dst={} out={} err={}", destination, path, e);
                if let Some(listed) = &listed {
                    listed.ended(match net::relay::is_write_stall(&e) {
                        true => crate::control::events::End::WriteStall,
                        false => crate::control::events::End::Error(e.kind()),
                    });
                }
            }
        }
    }

    /// Routes, dials and hands the connection `lhs` over to its outbound;
    /// `None` when it goes nowhere, or is refused, or served here.
    async fn connect_stream<T>(&self, mut sess: Session, lhs: T) -> Option<Established>
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        // Its place among its inbound's handshakes, taken before any copy
        // of the session is made, and held until it has one among the
        // sessions, or is refused one.
        let handshake = sess.handshake.take();
        if self.env.events.records_refuse()
            || !self.admitted(&mut sess)
            || !self.host_admits(&mut sess)
        {
            return None;
        }
        // Its place, held as long as it lives; without one, it is refused
        // as a general failure (SOCKS REP 1): the limit is sail's own, not
        // the destination refusing.
        let entered = self.enter().await;
        drop(handshake);
        let Ok(place) = entered else {
            let mut lhs = lhs;
            let e = io::Error::other("connection limit reached");
            refuse(&sess, &mut lhs, &e).await;
            return None;
        };
        // Routing, which may sniff and resolve, runs in a future of its own
        // that is freed once it decides: the one relaying for the life of
        // the connection does not keep room for it.
        let (mut sess, routed, matched, mut lhs) = Box::pin(self.route_stream(sess, lhs)).await?;
        use crate::control::events::RouteAction;
        let outbound = match routed {
            Routed::Outbound(tag) => tag,
            Routed::HijackDns => {
                self.unrouted(&sess, matched, RouteAction::HijackDns);
                if let Err(e) =
                    // Boxed, as the dial: a connection keeps no room for it.
                    Box::pin(super::router::hijack_dns::serve_stream(
                        &self.dns_client,
                        lhs,
                        &sess,
                    ))
                    .await
                {
                    debug!("hijack-dns: {}", e);
                }
                return None;
            }
            Routed::Drop => {
                self.unrouted(&sess, matched, RouteAction::Drop);
                // Read and thrown away, and never answered, until the
                // client gives up.
                if let Some(reply) = &sess.reply {
                    reply.withheld();
                }
                let _ = tokio::time::timeout(
                    DROP_HOLD,
                    tokio::io::copy(&mut lhs, &mut tokio::io::sink()),
                )
                .await;
                return None;
            }
        };

        let Some(h) = self.outbound_manager.load().handler(outbound.as_deref()) else {
            warn!("handler not found");
            let e = io::Error::other("no outbound");
            if let Some(number) = &sess.number {
                number.failed(&sess, e.kind());
            }
            refuse(&sess, &mut lhs, &e).await;
            return None;
        };
        self.find_dial_domain(&mut sess).await;
        sess.outbound_tag = h.tag().clone();
        // The groups on the way record the members they take here, and
        // tell their failures.
        sess.chain = crate::session::Chain::telling();

        let handshake_start = tokio::time::Instant::now();
        let th = match h.stream() {
            Ok(th) => th,
            Err(e) => {
                debug!("get stream handler, err={}", e);
                if let Some(number) = &sess.number {
                    number.failed(&sess, e.kind());
                }
                refuse(&sess, &mut lhs, &e).await;
                return None;
            }
        };
        // Each address a resolve rule handed on, in turn, the first that
        // connects taken; or the destination.
        let mut handshake = Err(io::Error::other("nowhere to connect"));
        let mut lhs_counted = false;
        // What is told of it once the dial ends: the id it is listed by,
        // and what the outbound was asked to reach, kept only while someone
        // listens for routed connections or their records; and the
        // connection as it is listed, told how its relay ends.
        let mut id = None;
        let mut listed = None;
        let mut asked: Option<SocksAddr> = None;
        let connect = th.connect_addr();
        let destinations = net::destinations(&sess, &connect);
        let last = destinations.len().saturating_sub(1);
        for (n, to) in destinations.into_iter().enumerate() {
            // Each address its own attempt, its chain alone; a group's
            // failure in it is not the connection's while one is left.
            sess.chain.truncate(0);
            sess.chain.set_more(n < last);
            let attempt;
            let at = if to == sess.destination {
                &sess
            } else {
                attempt = Session {
                    destination: to,
                    ..sess.clone()
                };
                &attempt
            };
            // Where it is dialled as a name, `override_destination`.
            let at = &*net::dial_domain::session(at, &h, &connect);
            if self.env.events.routes_wanted() || self.env.events.records_wanted() {
                asked = Some(at.destination.clone());
            }
            let stream =
                // Boxed: the dial is the largest thing the session awaits,
                // and unboxed, a relayed connection would keep room for it
                // for as long as it lives.
                match Box::pin(crate::net::connect_stream_routed(
                    at,
                    self.dns_client.clone(),
                    &h,
                ))
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        debug!(
                            "connect outbound src={} dst={} out={} err={}",
                            &at.source,
                            &at.destination,
                            outbound_path(at, h.tag()),
                            e
                        );
                        net::dial_domain::failed(at, &e);
                        handshake = Err(e);
                        continue;
                    }
                };
            let stream = match stream {
                Some(s) => {
                    let (s, counter) = self.stat_manager.stat_stream_id(s, sess.clone());
                    counter.dialing();
                    id = Some(counter.id);
                    if self.stat_manager.recheck_due(sess.routed_by) {
                        self.recheck_late(&sess, counter.id).await;
                    }
                    listed = Some(counter);
                    Some(s)
                }
                None => {
                    if !lhs_counted {
                        let (counted, counter) =
                            self.stat_manager.stat_inbound_stream_id(lhs, sess.clone());
                        lhs = counted;
                        counter.dialing();
                        id = Some(counter.id);
                        lhs_counted = true;
                        if self.stat_manager.recheck_due(sess.routed_by) {
                            self.recheck_late(&sess, counter.id).await;
                        }
                        listed = Some(counter);
                    }
                    None
                }
            };
            handshake = th.handle(at, Some(&mut lhs), stream).await;
            match &handshake {
                Ok(_) => {
                    net::dial_domain::connected(at);
                    break;
                }
                Err(e) => {
                    debug!(
                        "outbound handle dst={} out={} err={}",
                        &at.destination,
                        outbound_path(at, h.tag()),
                        e
                    );
                    net::dial_domain::failed(at, e);
                }
            }
        }
        match handshake {
            Ok(mut rhs) => {
                // Connected: the inbound's client is told so before the
                // first bytes either way.
                if let Some(reply) = &sess.reply {
                    reply.succeeded();
                }
                if let Some(how) = sess.route.tls_fragment {
                    rhs = Box::new(super::router::fragment::FragmentStream::new(rhs, how));
                }
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                if let Some(listed) = &listed {
                    listed.connected();
                    if let (true, Some(asked)) = (self.env.events.records_wanted(), &asked) {
                        listed.dialled(asked);
                    }
                }
                let told = Told {
                    matched,
                    id,
                    asked: asked.as_ref(),
                };
                self.handled(&sess, h.tag(), told, Ok(elapsed));
                Some(Established {
                    lhs,
                    rhs,
                    place,
                    destination: sess.destination.clone(),
                    path: outbound_path(&sess, h.tag()).into(),
                    listed,
                })
            }
            Err(e) => {
                debug!(
                    "outbound handle dst={} out={} err={}",
                    &sess.destination,
                    outbound_path(&sess, h.tag()),
                    e
                );
                self.tell_failed(&sess, h.tag(), &e);
                let told = Told {
                    matched,
                    id,
                    asked: asked.as_ref(),
                };
                self.handled(&sess, h.tag(), told, Err(e.kind()));
                refuse(&sess, &mut lhs, &e).await;
                None
            }
        }
    }

    pub async fn dispatch_stream_outbound(&self, mut sess: Session) -> io::Result<AnyStream> {
        match self.route(&mut sess, &mut NoSniffer).await? {
            Routed::Outbound(outbound) => {
                self.find_dial_domain(&mut sess).await;
                self.stream_through(outbound.as_deref(), sess).await
            }
            Routed::HijackDns | Routed::Drop => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "not routed to an outbound",
            )),
        }
    }

    /// The outbound the rules pick for `sess`, which is not dialled: for
    /// a DNS server that respects the rules; `None` when every rule and
    /// `final` passed it on, and it goes direct. An error when they pick
    /// none.
    pub async fn outbound_for(&self, sess: &mut Session) -> io::Result<Option<String>> {
        match self.route(sess, &mut NoSniffer).await? {
            Routed::Outbound(outbound) => Ok(outbound),
            Routed::HijackDns | Routed::Drop => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "not routed to an outbound",
            )),
        }
    }

    /// The DNS client what dials directly resolves with.
    pub(crate) fn dns_client(&self) -> SyncDnsClient {
        self.dns_client.clone()
    }

    /// The outbound connections go to when nothing says otherwise.
    pub fn default_outbound(&self) -> Option<String> {
        self.outbound_manager.load().default_handler()
    }

    /// A stream to the session's destination through the outbound `tag`,
    /// whatever the rules say: for a DNS server's `detour`.
    pub async fn stream_via(&self, tag: &str, sess: Session) -> io::Result<AnyStream> {
        self.stream_through(Some(tag), sess).await
    }

    /// A stream to the session's destination through the outbound `tag`,
    /// or the implicit direct.
    async fn stream_through(&self, tag: Option<&str>, mut sess: Session) -> io::Result<AnyStream> {
        let h = self.outbound_manager.load().handler(tag).ok_or_else(|| {
            io::Error::other(format!("outbound [{}] not found", tag.unwrap_or_default()))
        })?;
        sess.outbound_tag = h.tag().clone();
        sess.chain = Default::default();
        let th = h.stream()?;
        let mut handshake = Err(io::Error::other("nowhere to connect"));
        let connect = th.connect_addr();
        for to in net::destinations(&sess, &connect) {
            let at = Session {
                destination: to,
                ..sess.clone()
            };
            let at = net::dial_domain::session(&at, &h, &connect);
            handshake = net::dial_domain::stream_done(
                &at,
                async {
                    let stream =
                        crate::net::connect_stream_routed(&at, self.dns_client.clone(), &h).await?;
                    th.handle(&at, None, stream).await
                }
                .await,
            );
            if handshake.is_ok() {
                break;
            }
        }
        handshake
    }

    /// Datagrams to the session's destination through the outbound `tag`,
    /// whatever the rules say: for a DNS server's `detour`.
    pub async fn datagram_via(
        &self,
        tag: &str,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        sess.outbound_tag = tag.to_string();
        sess.chain = Default::default();
        let h = self
            .outbound_manager
            .load()
            .get(tag)
            .ok_or_else(|| io::Error::other(format!("outbound [{}] not found", tag)))?;
        let transport =
            crate::net::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;
        h.datagram()?.handle(&sess, transport).await
    }

    /// A stream to the session's destination through the outbound `tag`
    /// alone, as the rules never see it, counted and listed as a connection
    /// of its own until it is dropped: for the host's `dial`. `NotFound`
    /// when there is no such outbound.
    pub async fn dial_stream(&self, tag: &str, mut sess: Session) -> io::Result<AnyStream> {
        let h = self.outbound_manager.load().get(tag).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("outbound [{}] not found", tag),
            )
        })?;
        sess.outbound_tag = h.tag().clone();
        sess.chain = crate::session::Chain::telling();
        self.stat_manager.numbering().number(&mut sess);
        let handshake_start = tokio::time::Instant::now();
        let connected = async {
            let stream =
                crate::net::connect_stream_routed(&sess, self.dns_client.clone(), &h).await?;
            // Counted from the first byte on the wire, as a routed
            // connection is.
            let (stream, id) = match stream {
                Some(s) => {
                    let (s, counter) = self.stat_manager.stat_stream_id(s, sess.clone());
                    counter.dialing();
                    (Some(s), Some(counter))
                }
                None => (None, None),
            };
            let rhs = h.stream()?.handle(&sess, None, stream).await?;
            let id = id.map(|counter| {
                counter.connected();
                counter.id
            });
            io::Result::Ok((rhs, id))
        };
        // A failed dial is logged, and told, as a routed connection's is.
        let (rhs, id) = match connected.await {
            Ok(connected) => connected,
            Err(e) => {
                self.tell_failed(&sess, h.tag(), &e);
                let told = Told {
                    asked: Some(&sess.destination),
                    ..Default::default()
                };
                self.handled(&sess, h.tag(), told, Err(e.kind()));
                return Err(e);
            }
        };
        let elapsed = handshake_start.elapsed();
        match id {
            Some(_) => {
                let told = Told {
                    id,
                    asked: Some(&sess.destination),
                    ..Default::default()
                };
                self.handled(&sess, h.tag(), told, Ok(elapsed));
                Ok(rhs)
            }
            None => Ok(self.handled_listing(sess, h.tag(), elapsed, |sess| {
                let (s, counter) = self.stat_manager.stat_stream_id(rhs, sess);
                (s, counter.id)
            })),
        }
    }

    /// Datagrams to the session's destination through the outbound `tag`
    /// alone, counted and listed until they are dropped: for the host's
    /// `dial`. `NotFound` when there is no such outbound.
    pub async fn dial_datagram(
        &self,
        tag: &str,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let h = self.outbound_manager.load().get(tag).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("outbound [{}] not found", tag),
            )
        })?;
        sess.outbound_tag = h.tag().clone();
        sess.chain = crate::session::Chain::telling();
        self.stat_manager.numbering().number(&mut sess);
        let handshake_start = tokio::time::Instant::now();
        let connected = async {
            let transport =
                crate::net::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;
            h.datagram()?.handle(&sess, transport).await
        };
        let d = match connected.await {
            Ok(d) => d,
            Err(e) => {
                self.tell_failed(&sess, h.tag(), &e);
                let told = Told {
                    asked: Some(&sess.destination),
                    ..Default::default()
                };
                self.handled(&sess, h.tag(), told, Err(e.kind()));
                return Err(e);
            }
        };
        let elapsed = handshake_start.elapsed();
        Ok(self.handled_listing(sess, h.tag(), elapsed, |sess| {
            let (d, counter) = self.stat_manager.stat_outbound_datagram_id(d, sess);
            (d, counter.id)
        }))
    }

    /// Datagrams to where the rules send the UDP session `sess`, which
    /// `sniffer` reads the first datagrams of for a `sniff` rule, and how
    /// long the session lasts idle when a rule says.
    pub async fn dispatch_datagram(
        &self,
        mut sess: Session,
        sniffer: &mut dyn Sniffer,
    ) -> io::Result<DispatchedDatagram> {
        // As a stream's: held until the session has its place, or none.
        let handshake = sess.handshake.take();
        if self.env.events.records_refuse() {
            return Err(io::Error::other(
                "refused: the host has not taken its connection records",
            ));
        }
        // Its place, held by the datagram as long as the session lives.
        let entered = self.enter().await;
        drop(handshake);
        let place = entered
            .map_err(|()| io::Error::other("refused: inbound.max_connections sessions live"))?;
        let (datagram, idle, listed) = self.dispatch_datagram_inner(sess, sniffer).await?;
        let datagram = match place {
            Some(place) => super::sessions::Held::wrap(datagram, place),
            None => datagram,
        };
        Ok((datagram, idle, listed))
    }

    async fn dispatch_datagram_inner(
        &self,
        mut sess: Session,
        sniffer: &mut dyn Sniffer,
    ) -> io::Result<DispatchedDatagram> {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );
        if !self.admitted(&mut sess) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the user may not connect",
            ));
        }
        if !self.host_admits(&mut sess) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refused by the host",
            ));
        }

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.sail" {
                let recv = HealthcheckUdpRecvHalf {
                    responded: false,
                    src_addr: sess.destination.clone(),
                };
                let d = HealthcheckUdpDatagram {
                    recv,
                    send: HealthcheckUdpSendHalf,
                };
                let d: Box<dyn OutboundDatagram> = Box::new(d);
                return Ok((d, None, None));
            }
        }

        self.identify_inbound(&mut sess);
        let reverse_mapping = self.reverse_map(&mut sess).await;
        let origin = sess.destination.clone();
        use crate::control::events::RouteAction;
        let mut matched = Matched::default();
        let routed = match self.route_told(&mut sess, sniffer, &mut matched).await {
            Ok(routed) => routed,
            Err(e) => {
                if matched.rejected {
                    self.unrouted(&sess, matched, RouteAction::Reject);
                } else if let Some(number) = &sess.number {
                    number.failed(&sess, e.kind());
                }
                return Err(e);
            }
        };
        let outbound = match routed {
            Routed::Outbound(outbound) => outbound,
            Routed::HijackDns => {
                self.unrouted(&sess, matched, RouteAction::HijackDns);
                let udp_timeout = sess.route.udp_timeout;
                let d = super::router::hijack_dns::Datagram::new(self.dns_client.clone(), sess);
                return Ok((Box::new(d), udp_timeout, None));
            }
            Routed::Drop => {
                self.unrouted(&sess, matched, RouteAction::Drop);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "dropped by a rule",
                ));
            }
        };

        let Some(h) = self.outbound_manager.load().handler(outbound.as_deref()) else {
            warn!("handler not found");
            let e = io::Error::other("handler not found");
            if let Some(number) = &sess.number {
                number.failed(&sess, e.kind());
            }
            return Err(e);
        };
        self.find_dial_domain(&mut sess).await;
        sess.outbound_tag = h.tag().clone();
        // The groups on the way record the members they take here, and
        // tell their failures.
        sess.chain = crate::session::Chain::telling();

        let handshake_start = tokio::time::Instant::now();

        debug!("connect datagram outbound={}", h.tag());
        let dh = match h.datagram() {
            Ok(dh) => dh,
            Err(e) => {
                if let Some(number) = &sess.number {
                    number.failed(&sess, e.kind());
                }
                return Err(e);
            }
        };
        // Each address a resolve rule handed on, in turn, the first that
        // opens taken; or the destination.
        let mut handshake = Err(io::Error::other("nowhere to send"));
        let mut dialed = sess.destination.clone();
        let connect = dh.connect_addr();
        let destinations = net::destinations(&sess, &connect);
        let last = destinations.len().saturating_sub(1);
        for (n, to) in destinations.into_iter().enumerate() {
            sess.chain.truncate(0);
            sess.chain.set_more(n < last);
            let at = Session {
                destination: to,
                ..sess.clone()
            };
            // Where it is dialled as a name, `override_destination`.
            let at = net::dial_domain::session(&at, &h, &connect);
            handshake = async {
                let transport =
                    crate::net::connect_datagram_routed(&at, self.dns_client.clone(), &h).await?;
                dh.handle(&at, transport).await
            }
            .await;
            match &handshake {
                Ok(_) => {
                    net::dial_domain::connected(&at);
                    dialed = at.destination.clone();
                    break;
                }
                Err(e) => {
                    debug!(
                        "outbound handle dst={} out={} err={}",
                        &at.destination,
                        outbound_path(&at, h.tag()),
                        e
                    );
                    net::dial_domain::failed(&at, e);
                }
            }
        }

        match handshake {
            Ok(mut d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                let (counted, listed) =
                    self.stat_manager.stat_outbound_datagram_id(d, sess.clone());
                d = counted;
                if self.stat_manager.recheck_due(sess.routed_by) {
                    self.recheck_late(&sess, listed.id).await;
                }
                if self.env.events.records_wanted() {
                    listed.dialled(&dialed);
                }
                let told = Told {
                    matched,
                    id: Some(listed.id),
                    asked: Some(&dialed),
                };
                self.handled(&sess, h.tag(), told, Ok(elapsed));

                if reverse_mapping && sess.destination.port() == 53 {
                    d = Box::new(SniffingDatagram::new(d, self.env.reverse_map.clone()));
                }
                // A destination a sniff or a rule overrode, an address a
                // resolve rule handed on, or the name it is dialled as,
                // answers as the one asked for (route/conn.go:228-244).
                // Answers to an address handed on come back from it, and
                // those to the name dialled from the name, not from the
                // destination asked for, with `udp_disable_domain_unmapping`
                // (route/conn.go:237-241).
                if dialed != origin {
                    let handed_on = dialed != sess.destination;
                    d = Box::new(
                        sniff::OverriddenDatagram::new(d, origin, dialed).without_unmapping(
                            handed_on && sess.route.udp_disable_domain_unmapping,
                        ),
                    );
                }

                Ok((d, sess.route.udp_timeout, Some(listed)))
            }
            Err(e) => {
                debug!(
                    "outbound handle dst={} out={} err={}",
                    &sess.destination,
                    outbound_path(&sess, h.tag()),
                    e
                );
                self.tell_failed(&sess, h.tag(), &e);
                let told = Told {
                    matched,
                    id: None,
                    asked: Some(&dialed),
                };
                self.handled(&sess, h.tag(), told, Err(e.kind()));
                Err(e)
            }
        }
    }

    /// Where the connection `lhs` goes, with the session and the stream as
    /// routing left them; `None` when it goes nowhere.
    async fn route_stream<T>(
        &self,
        mut sess: Session,
        mut lhs: T,
    ) -> Option<(Session, Routed, Matched, Box<dyn ProxyStream>)>
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.sail" {
                if let Err(e) = healthcheck_respond_simple(&mut lhs).await {
                    debug!("healthcheck response failed: {}", e);
                }
                return None;
            }
        }

        self.identify_inbound(&mut sess);
        let was_address = sess.destination.domain().is_none();
        if let Err(e) = self.restore_fake_ip(&mut sess.destination) {
            debug!("src={}: {}", &sess.source, e);
            return None;
        }
        sess.fake_ip = was_address && sess.destination.domain().is_some();
        let mut matched = Matched::default();
        self.reverse_map(&mut sess).await;
        let mut sniffer = StreamSniffer::new(lhs);
        match self.route_told(&mut sess, &mut sniffer, &mut matched).await {
            Ok(tag) => Some((sess, tag, matched, sniffer.into_stream())),
            Err(e) => {
                debug!(
                    "route src={} dst={}: {}",
                    &sess.source, &sess.destination, e
                );
                if matched.rejected {
                    self.unrouted(&sess, matched, crate::control::events::RouteAction::Reject);
                } else if let Some(number) = &sess.number {
                    number.failed(&sess, e.kind());
                }
                refuse(&sess, &mut sniffer.into_stream(), &e).await;
                None
            }
        }
    }

    /// The fake IP handed out for `domain`, of the family asked for: where
    /// a reply from the domain appears to come from.
    pub fn fake_ip_of(&self, domain: &str, ipv6: bool) -> Option<std::net::IpAddr> {
        self.dns_client.load().fake_ip_of(domain, ipv6)
    }

    /// A destination that is a fake IP becomes the domain it was handed out
    /// for, as sing-box's router has it. One the fakeip server does not
    /// know, handed out before a restart say, is an error: it cannot go
    /// where it was meant to.
    pub fn restore_fake_ip(&self, destination: &mut SocksAddr) -> io::Result<()> {
        let Some(ip) = destination.ip() else {
            return Ok(());
        };
        match self.dns_client.load().fake_ip(ip) {
            FakeIp::NotFake => Ok(()),
            FakeIp::Domain(domain) => {
                debug!("fake ip {} is {}", ip, domain);
                *destination = SocksAddr::Domain(domain, destination.port());
                Ok(())
            }
            FakeIp::Unknown => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing fakeip record for {}", ip),
            )),
        }
    }

    /// With `dns.reverse_mapping`, takes the domain of an address from the
    /// DNS answers seen, and says whether it is on.
    async fn reverse_map(&self, sess: &mut Session) -> bool {
        if !self.dns_client.load().reverse_mapping() {
            return false;
        }
        // An IPv4-mapped IPv6 address is the IPv4 address the DNS gave.
        if let Some(ip) = sess.destination.ip().map(|ip| ip.to_canonical()) {
            if let Some(domain) = self.env.reverse_map.get(&ip).await {
                debug!("dns reverse mapped domain={}", &domain);
                sess.set_sniffed_domain(SniffedFrom::Dns, domain);
            }
        }
        true
    }

    /// The name a routed `sess` is dialled as, where its
    /// `override_destination` says: looked up once the rules decided, the
    /// reverse mapping as it is then.
    async fn find_dial_domain(&self, sess: &mut Session) {
        if sess.route.override_destination.is_none() {
            return;
        }
        let reverse_map = self
            .dns_client
            .load()
            .reverse_mapping()
            .then_some(&self.env.reverse_map);
        sess.route.dial_domain = net::dial_domain::find(sess, reverse_map).await;
    }

    /// The pre-match of a connection not yet set up, from its first packet
    /// (TUN's auto_redirect). As sing-box, a fake IP stands for its domain
    /// and reverse mapping applies first; a fake IP nobody knows leaves the
    /// connection to be set up, where it fails.
    pub async fn pre_match(&self, sess: &mut Session) -> PreMatch {
        if self.restore_fake_ip(&mut sess.destination).is_err() {
            return PreMatch::Proceed;
        }
        self.find_neighbor(sess);
        self.find_owner(sess).await;
        self.reverse_map(sess).await;
        let outbounds = self.outbound_manager.load_full();
        self.router.load_full().pre_match(sess, &*outbounds).await
    }

    /// The LAN device the session comes from, when the instance looks
    /// devices up, as sing-box's prepareMatchMetadata finds it.
    fn find_neighbor(&self, sess: &mut Session) {
        if sess.neighbor.is_none() {
            sess.neighbor = self.env.neighbors.lookup(sess.source);
        }
    }

    /// Who opened the connection: the host's answer where it finds it
    /// (Android's VpnService), else what this system tells sail (Linux,
    /// macOS); only when something needs it, a rule's conditions on it or
    /// `route.find_process`, as sing-box's `needFindProcess`. Kept a few
    /// seconds by the client's socket (`app::owner`). The answer may wait on
    /// the system (a binder call on Android, a walk of /proc on Linux), so
    /// it is waited for off the runtime's threads, as sing-box asks on the
    /// connection's own goroutine. Each session gets here once:
    /// `pre_match` only judges a packet, on a session of its own.
    async fn find_owner(&self, sess: &mut Session) {
        if sess.owner.is_some() || sess.process_name.is_some() {
            return;
        }
        let (router, dns) = (self.router.load(), self.dns_client.load());
        if !router.wants_owner() && !dns.needs_owner() {
            return;
        }
        let socket = super::owner::Socket {
            network: sess.network,
            local: sess.source,
            remote: sess.local_addr,
            process: router.wants_process() || dns.needs_process(),
        };
        let found = match self.owners.get(&socket) {
            Some(found) => found,
            None => {
                let found = self.look_up_owner(sess, socket).await;
                self.owners.put(socket, found.clone());
                found
            }
        };
        sess.owner = found.owner;
        sess.process_name = found.process;
    }

    /// Who opened the connection of `socket`, asked of the host where it
    /// finds it, else of this system.
    async fn look_up_owner(
        &self,
        sess: &Session,
        socket: super::owner::Socket,
    ) -> super::owner::Found {
        let started = std::time::Instant::now();
        let host = self
            .env
            .host
            .platform
            .clone()
            .filter(|p| p.finds_connection_owner());
        let found = match host {
            Some(platform) => {
                let query = crate::runtime::platform::ConnectionQuery {
                    network: sess.network.to_string(),
                    source: sess.source,
                    destination: sess.destination.to_string(),
                };
                let answer =
                    crate::runtime::scope::spawn_blocking("connection owner lookup", move || {
                        let answer = platform.find_connection_owner(&query);
                        (query, answer)
                    })
                    .await;
                match answer {
                    Ok((_, Ok(owner))) => super::owner::Found {
                        process: None,
                        owner: owner.map(std::sync::Arc::new),
                    },
                    Ok((query, Err(e))) => {
                        debug!("the host did not find who opened {:?}: {}", query, e);
                        Default::default()
                    }
                    Err(e) => {
                        debug!(
                            "the host's search for who opened a connection failed: {}",
                            e
                        );
                        Default::default()
                    }
                }
            }
            None => crate::runtime::scope::spawn_blocking("connection owner lookup", move || {
                super::owner::find(&socket)
            })
            .await
            .unwrap_or_default(),
        };
        let took = started.elapsed();
        if took > std::time::Duration::from_millis(10) {
            debug!("who opened {:?}: looked up in {:?}", socket, took);
        }
        found
    }

    /// The connection `id`, just listed with `sess`, which a router older
    /// than the one a reload rechecked the connections open against routed
    /// (`StatManager::recheck_due`): rechecked now, as that recheck would
    /// have, and closed if the rules reject or drop it. Boxed: a connection
    /// keeps no room for it.
    fn recheck_late<'a>(
        &'a self,
        sess: &'a Session,
        id: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(super::recheck::late(
            &self.stat_manager,
            self.router.load_full(),
            self.outbound_manager.load_full(),
            sess,
            id,
        ))
    }

    /// Where `sess` goes, as the rules decide; an error when a rule rejects
    /// it.
    async fn route(&self, sess: &mut Session, sniffer: &mut dyn Sniffer) -> io::Result<Routed> {
        self.route_told(sess, sniffer, &mut Matched::default())
            .await
    }

    /// `route`, and what it found that is told of a connection, in
    /// `matched`: the rule's index, and whether a rule rejected it.
    async fn route_told(
        &self,
        sess: &mut Session,
        sniffer: &mut dyn Sniffer,
        matched: &mut Matched,
    ) -> io::Result<Routed> {
        self.stat_manager.numbering().number(sess);
        self.find_neighbor(sess);
        self.find_owner(sess).await;
        let outbounds = self.outbound_manager.load_full();
        let router = self.router.load_full();
        sess.routed_by = router.generation();
        let decision = router
            .pick_route(sess, sniffer, &*outbounds)
            .await
            .map_err(|e| io::Error::other(format!("pick route: {}", e)))?;
        // From the router that decided: a reload after numbers its own.
        if self.env.events.routes_wanted() {
            matched.rule = sess
                .matched_rule
                .as_ref()
                .and_then(|rule| router.rule_index(rule));
        }
        let tag = match decision {
            Decision::Route(Some(tag)) => tag,
            // The default outbound, no `final` naming another, passes as
            // `final` would.
            Decision::Route(None) => {
                let tag = outbounds
                    .default_handler()
                    .ok_or_else(|| io::Error::other("no outbound found"))?;
                if outbounds.passes(&tag).await {
                    debug!("the default outbound [{}] passes: direct", tag);
                    return Ok(Routed::Outbound(None));
                }
                tag
            }
            Decision::Direct => return Ok(Routed::Outbound(None)),
            // A reset, as sing-box's reject is (ErrReset): a SOCKS client
            // is answered a general failure.
            Decision::Reject { drop: false } => {
                matched.rejected = true;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "rejected by a rule",
                ));
            }
            Decision::Reject { drop: true } => return Ok(Routed::Drop),
            Decision::HijackDns => return Ok(Routed::HijackDns),
        };
        // Behind a captive portal, as the host says, every connection goes
        // straight out, whatever the rules say, for the user to log in;
        // DNS the rules hijack is still answered.
        #[cfg(feature = "outbound-direct")]
        if self.env.network.snapshot().captive {
            debug!("behind a captive portal: direct, not [{}]", tag);
            return Ok(Routed::Outbound(None));
        }
        // QUIC refused to it (`route.block_quic`), as Surge's block-quic
        // has it: rejected as a reject rule is, for the app to go on over
        // TCP at once. After the captive portal's: what goes direct is not
        // through it.
        if sess.sniffed_protocol == Some(crate::session::SniffedProtocol::Quic)
            && router.blocks_quic(&tag)
        {
            matched.rejected = true;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("QUIC refused through [{}]: route.block_quic", tag),
            ));
        }
        debug!(
            "picked route out={} src={} dst={}",
            tag, &sess.source, &sess.destination
        );
        Ok(Routed::Outbound(Some(tag)))
    }

    pub async fn is_direct_outbound(&self, tag: &str) -> bool {
        if let Some(h) = self.outbound_manager.load().get(tag) {
            h.is_direct()
        } else {
            false
        }
    }
}

impl Dispatcher {
    /// Whether the user of `sess`, if any, may have another connection:
    /// not shut out by `user_limits`, nor at its most. Checked before
    /// routing and dialing; the statistics decide once the connection is
    /// counted. One refused is numbered for its closed record, while
    /// someone listens for records.
    fn admitted(&self, sess: &mut Session) -> bool {
        use crate::control::events::{ClosedBy, End, Outcome};
        match &sess.user {
            Some(user) if !user.admits_on(&sess.inbound_tag, sess.network == Network::Tcp) => {
                debug!("user [{}]: connection refused: {}", user, user.status());
                if self.env.events.records_wanted() {
                    self.stat_manager.numbering().number(sess);
                    if let Some(number) = &sess.number {
                        number.closed(sess, Outcome::Rejected, End::Closed(ClosedBy::User));
                    }
                }
                false
            }
            _ => true,
        }
    }

    /// A new target on an already admitted UDP association. It has its
    /// connection place already: only user revocation/quota/expiry and
    /// the host policy apply, not another max_connections reservation.
    /// Accepted targets stay accounted to the association; a rejection
    /// has an independent, unlisted number and a zero-byte closed record.
    pub(crate) fn admit_datagram_destination(&self, base: &Session, to: &SocksAddr) -> bool {
        use crate::control::events::{ClosedBy, End, Outcome};
        // Same first gate as a newly dispatched session. There is no
        // host verdict to lose yet: the public RecordStream::refused
        // counter reports these backlog refusals, without queueing yet
        // another closed record behind a reader that is not keeping up.
        if self.env.events.records_refuse() {
            return false;
        }
        let mut probe = Session {
            destination: to.clone(),
            number: None,
            state: Default::default(),
            chain: Default::default(),
            outbound_tag: String::new(),
            fake_ip: false,
            sniffed: None,
            sniffed_protocol: None,
            sniffed_http: None,
            route: Default::default(),
            matched_rule: None,
            matched_rule_set: None,
            routed_by: 0,
            ..base.clone()
        };
        if probe
            .user
            .as_ref()
            .is_some_and(|user| !user.active() || user.removed_from(&probe.inbound_tag))
        {
            if self.env.events.records_wanted() {
                self.stat_manager.numbering().number(&mut probe);
                if let Some(number) = &probe.number {
                    number.closed(&probe, Outcome::Rejected, End::Closed(ClosedBy::User));
                }
            }
            return false;
        }
        self.host_admits(&mut probe)
    }

    /// Prepare a root id before dispatch, also for unlisted DNS/health
    /// associations. Numbering alone neither admits nor records a session.
    pub(crate) fn datagram_admission(&self, sess: &mut Session) -> Option<Session> {
        if !self
            .env
            .admission
            .as_ref()
            .is_some_and(|a| a.checks_sessions())
        {
            return None;
        }
        sess.parent_id = None;
        self.stat_manager.numbering().number(sess);
        Some(Session {
            parent_id: sess.number.as_ref().map(|number| number.id()),
            number: None,
            state: Default::default(),
            ..sess.clone()
        })
    }

    /// Whether the host's own check takes the session in, after sail's.
    /// It is numbered first, while someone listens for records, so that
    /// the check sees the id its record has; one refused has its closed
    /// record, `Rejected` for the reason the check told.
    fn host_admits(&self, sess: &mut Session) -> bool {
        let Some(admission) = self.env.admission.as_ref().filter(|a| a.checks_sessions()) else {
            return true;
        };
        if self.env.events.records_wanted() {
            self.stat_manager.numbering().number(sess);
        }
        let Err(reason) = admission.host_admits(sess) else {
            return true;
        };
        let reason = reason.map(std::borrow::Cow::into_owned);
        debug!(
            "session refused by the host: {}",
            reason.as_deref().unwrap_or("its check panicked")
        );
        if let Some(number) = &sess.number {
            number.refused_by_host(sess, reason);
        }
        false
    }
}

/// Tells the client the outbound failed, where its inbound answers it once
/// connected (a SOCKS inbound), before the connection ends.
async fn refuse<T: AsyncWrite + Unpin>(sess: &Session, lhs: &mut T, e: &io::Error) {
    if let Some(reply) = &sess.reply {
        reply.failed(e);
        let _ = lhs.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "outbound-direct")]
    #[tokio::test]
    async fn a_user_refused_udp_target_keeps_its_parent_before_the_host_check() {
        use crate::control::events::{ClosedBy, End, EventHub, Outcome, RecordKind};
        use crate::session::{Network, Session, SocksAddr};
        let config =
            crate::config::Config::from_json(r#"{"outbounds":[{"type":"direct","tag":"d"}]}"#)
                .unwrap();
        let env = std::sync::Arc::new(crate::runtime::RuntimeEnv {
            events: EventHub::with_records(16, Some(16)),
            ..Default::default()
        });
        let instance = crate::app::instance::Instance::build(
            &config,
            Vec::new(),
            env.clone(),
            std::sync::Arc::default(),
        )
        .unwrap();
        let mut records = env.events.lossless_records().unwrap().reader().unwrap();
        let user = env.users.bind("alice");
        let limits = crate::user::Limits {
            expire_at: Some(std::time::UNIX_EPOCH),
            ..Default::default()
        };
        env.users.set_limit(&user, limits);
        let base = Session {
            network: Network::Udp,
            user: Some(user),
            inbound_tag: "in".into(),
            parent_id: Some(42),
            ..Default::default()
        };
        let target = SocksAddr::Domain("new.example".into(), 5353);
        assert!(!instance
            .dispatcher
            .admit_datagram_destination(&base, &target));
        let rejected = records
            .try_next()
            .expect("the user refusal is recorded without a host call");
        assert_eq!(rejected.parent_id, Some(42));
        assert_ne!(rejected.id, 42);
        assert_eq!(
            rejected.kind,
            RecordKind::Closed(End::Closed(ClosedBy::User))
        );
        assert_eq!(rejected.outcome, Some(Outcome::Rejected));
        assert_eq!(rejected.destination, target);
        assert_eq!((rejected.up_total, rejected.down_total), (0, 0));
        assert!(rejected.chain.is_empty());
        let json =
            serde_json::to_value(crate::control::json::ConnectionRecord::of(&rejected)).unwrap();
        assert_eq!(json["parent_id"], 42);
    }

    /// A relayed connection's task is as large as what it awaits: the
    /// routing, dial and handshake are in a future of their own, freed
    /// once the connection is relayed, so the task keeps room for the
    /// relay and not for them. Inline they made it 5,856 bytes.
    #[tokio::test]
    async fn a_connection_s_task_keeps_room_for_its_relay_alone() {
        use std::mem::size_of_val;
        let config = crate::config::Config::from_json(
            r#"{ "outbounds": [{ "type": "direct", "tag": "d" }] }"#,
        )
        .unwrap();
        let instance = crate::app::instance::Instance::build(
            &config,
            Vec::new(),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        )
        .unwrap();
        let d = instance.dispatcher.clone();
        let (a, _b) = tokio::io::duplex(64);
        let task = d.dispatch_stream(crate::session::Session::default(), a);
        let (a, _b) = tokio::io::duplex(64);
        let connect = d.connect_stream(crate::session::Session::default(), a);
        assert!(size_of_val(&task) <= 1_280, "{} bytes", size_of_val(&task));
        // What the task no longer keeps room for.
        assert!(size_of_val(&connect) > 2 * size_of_val(&task));
    }

    /// `route.block_quic`: a UDP connection sniffed as QUIC that the rules
    /// send to an outbound named there is rejected as a reject rule's is;
    /// other UDP through it passes, and so does QUIC elsewhere, and behind
    /// a captive portal, where it goes direct. A group named there is
    /// refused whatever member it has: the member is chosen at the dial.
    #[cfg(feature = "outbound-select")]
    #[tokio::test]
    async fn quic_is_refused_to_the_outbounds_route_block_quic_names() {
        use crate::session::{Network, Session, SniffedProtocol};
        let config = crate::config::Config::from_json(
            r#"{
              "outbounds": [
                { "type": "direct", "tag": "p" },
                { "type": "direct", "tag": "d" },
                { "type": "selector", "tag": "g", "outbounds": ["p", "d"] }
              ],
              "route": {
                "rules": [
                  { "port": 444, "outbound": "d" },
                  { "port": 445, "outbound": "g" }
                ],
                "final": "p",
                "block_quic": ["p", "g"]
              }
            }"#,
        )
        .unwrap();
        let instance = crate::app::instance::Instance::build(
            &config,
            config.route.rules.clone(),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        )
        .unwrap();
        let d = instance.dispatcher.clone();
        let route = |port: u16, quic: bool| {
            let mut sess = Session {
                network: Network::Udp,
                destination: crate::session::SocksAddr::Domain("a.example".into(), port),
                sniffed_protocol: quic.then_some(SniffedProtocol::Quic),
                ..Default::default()
            };
            let d = d.clone();
            async move { d.outbound_for(&mut sess).await }
        };
        let refused = |r: std::io::Result<Option<String>>| {
            matches!(r, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset
                && e.to_string().contains("route.block_quic"))
        };
        assert!(refused(route(443, true).await));
        assert_eq!(route(443, false).await.unwrap().as_deref(), Some("p"));
        assert_eq!(route(444, true).await.unwrap().as_deref(), Some("d"));
        // Its member switched to an unrefused one: refused all the same.
        d.outbound_manager
            .load()
            .get_selector("g")
            .unwrap()
            .write()
            .await
            .set_selected("d")
            .unwrap();
        assert!(refused(route(445, true).await));
        // Behind a captive portal everything goes direct, QUIC as well.
        d.env().network.push(crate::net::network::NetworkState {
            captive: true,
            ..Default::default()
        });
        assert_eq!(route(443, true).await.unwrap(), None);
    }

    /// A failure names the member a group took, not the group alone: the
    /// outermost first, as each group adds its member before dialling it,
    /// a group in a group after the group.
    #[test]
    fn the_outbound_path_names_the_members_taken() {
        let sess = crate::session::Session::default();
        assert_eq!(super::outbound_path(&sess, "direct"), "direct");
        sess.chain.push("hk");
        sess.chain.push("hk-ss");
        assert_eq!(super::outbound_path(&sess, "selected"), "selected>hk>hk-ss");
    }

    /// The domain told of a connection, and where it came from: the
    /// destination's own first, then the name it was dialled as, then
    /// what was sniffed or reverse-mapped.
    #[test]
    fn the_domain_told_of_a_connection_names_its_source() {
        use crate::control::events::DomainSource;
        use crate::session::{DialDomainSource, Dialled, Session, SniffedFrom, SocksAddr};
        let named = Session {
            destination: SocksAddr::Domain("example.com".into(), 443),
            sniffed: Some((SniffedFrom::Tls, "sni.example".into())),
            ..Default::default()
        };
        assert_eq!(
            super::domain_of(&named),
            Some(("example.com".to_string(), DomainSource::Request))
        );
        let faked = Session {
            fake_ip: true,
            ..named.clone()
        };
        assert_eq!(
            super::domain_of(&faked),
            Some(("example.com".to_string(), DomainSource::FakeIp))
        );
        let address = || SocksAddr::from(("1.2.3.4".parse::<std::net::IpAddr>().unwrap(), 443));
        let sniffed = Session {
            destination: address(),
            sniffed: Some((SniffedFrom::Tls, "sni.example".into())),
            ..Default::default()
        };
        assert_eq!(
            super::domain_of(&sniffed),
            Some(("sni.example".to_string(), DomainSource::Sniffed))
        );
        let mapped = Session {
            destination: address(),
            sniffed: Some((SniffedFrom::Dns, "dns.example".into())),
            ..Default::default()
        };
        assert_eq!(
            super::domain_of(&mapped),
            Some(("dns.example".to_string(), DomainSource::ReverseMapping))
        );
        // The name a dial took comes before what was sniffed.
        mapped
            .state
            .get::<Dialled>()
            .set("dialled.example", DialDomainSource::Sniff);
        assert_eq!(
            super::domain_of(&mapped),
            Some(("dialled.example".to_string(), DomainSource::Sniffed))
        );
        let bare = Session {
            destination: address(),
            ..Default::default()
        };
        assert_eq!(super::domain_of(&bare), None);
    }

    use std::net::IpAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::sniff::Protocols;

    fn to_ip(network: Network) -> Session {
        Session {
            network,
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        }
    }

    fn action(protocols: Protocols) -> SniffAction {
        SniffAction {
            protocols,
            timeout: Duration::from_millis(300),
            override_destination: Some(OverrideDestination::AtSniff),
            skip: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_stream_is_sniffed_once_its_protocol_is_known() {
        let (mut client, server) = tokio::io::duplex(4096);
        let request = b"GET /a HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t/1\r\n\r\n";
        client.write_all(request).await.unwrap();
        let mut sess = to_ip(Network::Tcp);
        let mut sniffer = StreamSniffer::new(server);
        let action = action(Protocols::ALL);
        sniffer.sniff(&mut sess, &action).await.unwrap();
        assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Http));
        assert_eq!(
            sess.sniffed_domain_from(SniffedFrom::Http),
            Some("example.com")
        );
        // Its URL and User-Agent, for the rules.
        let http = sess.sniffed_http.clone().unwrap();
        assert_eq!(
            http.url.as_ref().and_then(|u| u.whole()),
            Some("http://example.com/a")
        );
        assert_eq!(
            http.user_agent.as_ref().and_then(|u| u.whole()),
            Some("t/1")
        );
        assert_eq!(
            sess.destination,
            SocksAddr::Domain("example.com".into(), 443)
        );
        // Nothing more is read for a second rule.
        sniffer.sniff(&mut sess, &action).await.unwrap();
        let mut stream = sniffer.into_stream();
        client.shutdown().await.unwrap();
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        assert_eq!(read, request);
    }

    /// The dial-time override leaves the rules the address asked for: only
    /// `at_sniff`, Mihomo's, makes the sniffed domain the destination, and
    /// never a Host that is an address.
    #[tokio::test]
    async fn only_at_sniff_overrides_the_destination_at_the_sniff() {
        for (how, host, overridden) in [
            (Some(OverrideDestination::Proxy), "example.com", false),
            (
                Some(OverrideDestination::ProxyAndDirect),
                "example.com",
                false,
            ),
            (None, "example.com", false),
            (Some(OverrideDestination::AtSniff), "5.6.7.8", false),
            (Some(OverrideDestination::AtSniff), "example.com", true),
        ] {
            let (mut client, server) = tokio::io::duplex(4096);
            let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
            client.write_all(request.as_bytes()).await.unwrap();
            let mut sess = to_ip(Network::Tcp);
            let action = SniffAction {
                override_destination: how,
                ..action(Protocols::ALL)
            };
            StreamSniffer::new(server)
                .sniff(&mut sess, &action)
                .await
                .unwrap();
            // A Host that is an address is no domain.
            let named = host.parse::<IpAddr>().is_err();
            assert_eq!(
                sess.sniffed_domain_from(SniffedFrom::Http),
                named.then_some(host)
            );
            assert_eq!(
                sess.destination.is_domain(),
                overridden,
                "{:?} {}",
                how,
                host
            );
        }
    }

    #[cfg(feature = "rule-set")]
    #[tokio::test]
    async fn a_domain_a_skip_rule_set_matches_is_not_taken() {
        let skip = crate::app::router::rule_set::RuleSet::from_rules(
            &[
                serde_json::from_value(serde_json::json!({ "domain_suffix": ["push.apple.com"] }))
                    .unwrap(),
            ],
            &Default::default(),
        )
        .unwrap();
        let action = SniffAction {
            skip: super::super::router::SniffSkip::of(vec![(
                "skip".to_string(),
                crate::runtime::resource::HotResource::new(skip),
            )]),
            ..action(Protocols::ALL)
        };
        for (host, taken) in [("a.push.apple.com", false), ("example.com", true)] {
            let (mut client, server) = tokio::io::duplex(4096);
            let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
            client.write_all(request.as_bytes()).await.unwrap();
            let mut sess = to_ip(Network::Tcp);
            StreamSniffer::new(server)
                .sniff(&mut sess, &action)
                .await
                .unwrap();
            assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Http));
            assert_eq!(sess.sniffed_domain_from(SniffedFrom::Http).is_some(), taken);
            assert_eq!(matches!(sess.destination, SocksAddr::Domain(..)), taken);
        }
    }

    #[tokio::test]
    async fn a_server_first_port_is_not_waited_on() {
        let (_client, server) = tokio::io::duplex(4096);
        let mut sess = Session {
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 25)),
            ..Default::default()
        };
        let mut sniffer = StreamSniffer::new(server);
        let action = SniffAction {
            timeout: Duration::from_secs(30),
            ..action(Protocols::ALL)
        };
        tokio::time::timeout(Duration::from_secs(1), sniffer.sniff(&mut sess, &action))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sess.sniffed_protocol, None);
    }

    #[tokio::test]
    async fn a_udp_session_is_sniffed_from_its_first_datagrams() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let source = SocksAddr::from(("10.0.0.1".parse::<IpAddr>().unwrap(), 5353));
        let mut sess = to_ip(Network::Udp);
        let mut query = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        // A datagram to another destination is not the session's.
        let other = SocksAddr::from(("5.6.7.8".parse::<IpAddr>().unwrap(), 443));
        for (data, to) in [(vec![0xff; 40], other), (query, sess.destination.clone())] {
            tx.send(UdpPacket::new(data, source.clone(), to))
                .await
                .unwrap();
        }
        let mut sniffer = DatagramSniffer::new(&mut rx);
        sniffer
            .sniff(&mut sess, &action(Protocols::ALL))
            .await
            .unwrap();
        // DNS names no destination.
        assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Dns));
        assert_eq!(sess.sniffed_domain(), None);
        assert!(!sess.destination.is_domain());
        assert_eq!(sniffer.into_read().len(), 2);
    }

    #[cfg(feature = "btls")]
    #[tokio::test]
    async fn quic_across_datagrams_overrides_the_destination() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let source = SocksAddr::from(("10.0.0.1".parse::<IpAddr>().unwrap(), 5353));
        let mut sess = to_ip(Network::Udp);
        let hello = crate::sniff::tls::tests::hello("example.com");
        let half = hello.len() / 2;
        // The second half first.
        for (i, (offset, data)) in [(half, &hello[half..]), (0, &hello[..half])]
            .into_iter()
            .enumerate()
        {
            let mut frames = vec![0x06, 0x40 | (offset >> 8) as u8, offset as u8];
            frames.extend_from_slice(&[0x40 | (data.len() >> 8) as u8, data.len() as u8]);
            frames.extend_from_slice(data);
            frames.resize(1100, 0);
            let initial = crate::sniff::quic::protect(1, &[3; 8], i as u32, &frames).unwrap();
            let packet = UdpPacket::new(initial, source.clone(), sess.destination.clone());
            tx.send(packet).await.unwrap();
        }
        let mut sniffer = DatagramSniffer::new(&mut rx);
        sniffer
            .sniff(&mut sess, &action(Protocols::ALL))
            .await
            .unwrap();
        assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Quic));
        assert_eq!(
            sess.sniffed_domain_from(SniffedFrom::Tls),
            Some("example.com")
        );
        assert_eq!(
            sess.destination,
            SocksAddr::Domain("example.com".into(), 443)
        );
        assert_eq!(sniffer.into_read().len(), 2);
    }

    #[tokio::test]
    async fn a_udp_sniff_waits_no_longer_than_the_timeout() {
        let (_tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut sess = to_ip(Network::Udp);
        let mut sniffer = DatagramSniffer::new(&mut rx);
        let action = SniffAction {
            timeout: Duration::from_millis(50),
            ..action(Protocols::ALL)
        };
        tokio::time::timeout(Duration::from_secs(1), sniffer.sniff(&mut sess, &action))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sess.sniffed_protocol, None);
    }

    /// A relayed connection's routing runs in a task of its own, which
    /// keeps its state for as long as the connection lives: the dial and
    /// the DNS hijack are boxed, so that what it keeps is what relaying
    /// needs. In a test build, unoptimized, 9,000 bytes unboxed and 6,368
    /// boxed (a release build keeps less: 8,152 unboxed).
    #[test]
    fn a_routed_stream_keeps_little_while_it_lives() {
        fn size<A, B, C, F: std::future::Future>(_: impl FnOnce(A, B, C) -> F) -> usize {
            std::mem::size_of::<F>()
        }
        let routed = size(
            |d: std::sync::Arc<super::Dispatcher>,
             s: crate::session::Session,
             lhs: crate::adapter::AnyStream| async move { d.dispatch_stream(s, lhs).await },
        );
        assert!(routed <= 7 * 1024, "{} bytes", routed);
    }
}
