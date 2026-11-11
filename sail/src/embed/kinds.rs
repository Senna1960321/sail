//! Inbound and outbound kinds of the host's own, registered on [`Options`]
//! by their `type`: the host keeps its wire format and its tables, and sail
//! the listener, the limits, the routing, the counts and the connection
//! table, as for its own kinds (docs/embed.md, Host kinds).
//!
//! A host inbound is handed each connection its listener accepts and
//! submits the sessions it carries, any number, each to be routed as a
//! session of a built-in inbound is. A host outbound is handed each session
//! routed to it and returns a stream or datagrams, made by itself or
//! through any outbound of sail's by tag ([`Via`]).
//!
//! [`Options`]: super::Options

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use anyhow::anyhow;
use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::stream::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch};
use tracing::debug;

use super::{Address, Error, ErrorKind};
use crate::adapter::registry::{
    InboundContext, InboundFactory, InboundRegistry, OutboundContext, OutboundFactory,
    OutboundRegistry,
};
use crate::adapter::{
    AnyBaseInboundTransport, AnyInboundHandler, AnyInboundTransport, AnyOutboundDatagram,
    AnyOutboundHandler, AnyOutboundTransport, AnyStream, BaseInboundTransport,
    DatagramTransportType, InboundDatagram, InboundDatagramRecvHalf, InboundDatagramSendHalf,
    InboundStreamHandler, InboundTransport, OutboundConnect, OutboundDatagram,
    OutboundDatagramHandler, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
    OutboundStreamHandler, ProxyError, ProxyResult,
};
use crate::app::stat_manager::{Number, Numbering};
use crate::app::SyncDnsClient;
use crate::control::events::DomainSource;
pub use crate::session::Extensions;
use crate::session::{DatagramSource, Network, Session, SocksAddr, StreamId};
use crate::user::{UserRef, UserRegistry};

/// Sessions a connection has submitted that the listener has not taken
/// yet, at most: a host submitting faster waits.
const SUBMITTED: usize = 64;

// ---------------------------------------------------------------------------
// Registering
// ---------------------------------------------------------------------------

/// What makes a host inbound of an inbound's object: an error is the
/// start's or the reload's, naming the inbound.
pub type InboundKindFactory =
    Arc<dyn Fn(&KindContext<'_>) -> Result<Arc<dyn HostInbound>, String> + Send + Sync>;

/// What makes a host outbound of an outbound's object.
pub type OutboundKindFactory =
    Arc<dyn Fn(&KindContext<'_>) -> Result<Arc<dyn HostOutbound>, String> + Send + Sync>;

/// What an inbound's or outbound's object of a host kind is built from.
#[non_exhaustive]
pub struct KindContext<'a> {
    /// The inbound's or outbound's tag.
    pub tag: &'a str,
    /// Its object, without what sail takes of it: `type`, `tag`, and an
    /// inbound's listen fields (`listen`, `listen_port` and the socket
    /// options beside them).
    pub options: &'a serde_json::Map<String, serde_json::Value>,
    users: &'a UserRegistry,
}

impl KindContext<'_> {
    /// The user `name`, as [`Instance::user`](super::Instance::user) gives
    /// it.
    pub fn user(&self, name: &str) -> User {
        User::bind(self.users, name)
    }
}

/// The kinds a host registered, by name: an instance's, kept across its
/// reloads and runs.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct HostKinds(Arc<Kinds>);

#[derive(Default)]
struct Kinds {
    inbounds: HashMap<&'static str, InboundKindFactory>,
    outbounds: HashMap<&'static str, OutboundKindFactory>,
}

impl HostKinds {
    /// `kinds` with the inbound kind `name` added.
    pub(super) fn with_inbound(
        &self,
        name: &'static str,
        factory: InboundKindFactory,
    ) -> Result<Self, Error> {
        if crate::include::inbound_protocol(name).is_some() {
            return Err(taken("inbound", name));
        }
        let mut kinds = self.copy();
        if kinds.inbounds.insert(name, factory).is_some() {
            return Err(twice("inbound", name));
        }
        Ok(HostKinds(Arc::new(kinds)))
    }

    /// `kinds` with the outbound kind `name` added.
    pub(super) fn with_outbound(
        &self,
        name: &'static str,
        factory: OutboundKindFactory,
    ) -> Result<Self, Error> {
        if crate::include::OUTBOUNDS.get(name).is_some()
            || crate::include::ENDPOINTS.get(name).is_some()
        {
            return Err(taken("outbound", name));
        }
        let mut kinds = self.copy();
        if kinds.outbounds.insert(name, factory).is_some() {
            return Err(twice("outbound", name));
        }
        Ok(HostKinds(Arc::new(kinds)))
    }

    fn copy(&self) -> Kinds {
        Kinds {
            inbounds: self.0.inbounds.clone(),
            outbounds: self.0.outbounds.clone(),
        }
    }

    /// The inbound kind `name`, as it was registered.
    pub(crate) fn inbound_name(&self, name: &str) -> Option<&'static str> {
        self.0.inbounds.get_key_value(name).map(|(name, _)| *name)
    }
}

fn taken(what: &str, name: &str) -> Error {
    Error::new(
        ErrorKind::InvalidArgument,
        format!("{} kind \"{}\": sail has one of that name", what, name),
    )
}

fn twice(what: &str, name: &str) -> Error {
    Error::new(
        ErrorKind::InvalidArgument,
        format!("{} kind \"{}\": registered twice", what, name),
    )
}

impl fmt::Debug for HostKinds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut inbounds: Vec<_> = self.0.inbounds.keys().collect();
        let mut outbounds: Vec<_> = self.0.outbounds.keys().collect();
        inbounds.sort();
        outbounds.sort();
        f.debug_struct("HostKinds")
            .field("inbounds", &inbounds)
            .field("outbounds", &outbounds)
            .finish()
    }
}

/// The same registrations: the host's settings compare equal when they
/// carry the same kinds.
impl PartialEq for HostKinds {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HostKinds {}

static HOST_INBOUND: LazyLock<InboundFactory> =
    LazyLock::new(|| InboundFactory::standalone(build_inbound));

static HOST_OUTBOUND: LazyLock<OutboundFactory> = LazyLock::new(|| {
    // Each its own: a host's state is not to be shared between tags.
    OutboundFactory::composite(crate::adapter::registry::no_dependencies, build_outbound)
});

/// The factory of the inbound `protocol`: sail's, or the host's kind of
/// that name; neither is the error it always was.
pub(crate) fn inbound_factory<'a>(
    registry: &'a InboundRegistry,
    env: &crate::runtime::RuntimeEnv,
    tag: &str,
    protocol: &str,
) -> anyhow::Result<&'a InboundFactory> {
    match registry.get(protocol) {
        Some(factory) => Ok(factory),
        None if env.host.kinds.0.inbounds.contains_key(protocol) => Ok(&HOST_INBOUND),
        None => registry.require(tag, protocol),
    }
}

/// As `inbound_factory`, of outbounds.
pub(crate) fn outbound_factory<'a>(
    registry: &'a OutboundRegistry,
    env: &crate::runtime::RuntimeEnv,
    tag: &str,
    protocol: &str,
) -> anyhow::Result<&'a OutboundFactory> {
    match registry.get(protocol) {
        Some(factory) => Ok(factory),
        None if env.host.kinds.0.outbounds.contains_key(protocol) => Ok(&HOST_OUTBOUND),
        None => registry.require(tag, protocol),
    }
}

/// Calls a host's factory: its panic is the inbound's or outbound's error,
/// as a configuration's is.
fn call<T>(
    what: &str,
    tag: &str,
    factory: impl FnOnce() -> Result<T, String>,
) -> anyhow::Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(factory)) {
        Ok(Ok(built)) => Ok(built),
        Ok(Err(e)) => Err(anyhow!("[{}] {}: {}", tag, what, e)),
        Err(_) => Err(anyhow!("[{}] {}: the host's factory panicked", tag, what)),
    }
}

fn build_inbound(ctx: &InboundContext<'_>) -> anyhow::Result<AnyInboundHandler> {
    let kinds = &ctx.env.host.kinds.0;
    let (&kind, factory) = kinds
        .inbounds
        .get_key_value(ctx.protocol)
        .ok_or_else(|| anyhow!("[{}] inbound: no host kind {}", ctx.tag, ctx.protocol))?;
    let cx = KindContext {
        tag: ctx.tag,
        options: ctx.options,
        users: &ctx.env.users,
    };
    let host = call("inbound", ctx.tag, || factory(&cx))?;
    let stream = Arc::new(HostStreamHandler {
        kind,
        host,
        users: ctx.env.users.clone(),
        numbering: ctx.env.numbering.clone(),
    });
    Ok(Arc::new(crate::adapter::inbound::Handler::new(
        ctx.tag.to_string(),
        Some(stream),
        None,
    )))
}

fn build_outbound(ctx: &mut OutboundContext<'_>) -> anyhow::Result<AnyOutboundHandler> {
    let kinds = &ctx.env.host.kinds.0;
    let factory = kinds
        .outbounds
        .get(ctx.protocol)
        .ok_or_else(|| anyhow!("[{}] outbound: no host kind {}", ctx.tag, ctx.protocol))?;
    let cx = KindContext {
        tag: ctx.tag,
        options: ctx.options,
        users: &ctx.env.users,
    };
    let host = call("outbound", ctx.tag, || factory(&cx))?;
    let via = Via {
        outbounds: ctx.outbounds.clone(),
        dns: ctx.dns_client.clone(),
    };
    let shared = Arc::new(OutboundShared { host, via });
    Ok(crate::adapter::outbound::HandlerBuilder::default()
        .tag(ctx.tag.to_string())
        .stream_handler(Arc::new(HostOutboundStream(shared.clone())))
        .datagram_handler(Arc::new(HostOutboundDatagrams(shared)))
        .build())
}

// ---------------------------------------------------------------------------
// Streams and datagrams
// ---------------------------------------------------------------------------

/// A stream between sail and a host kind: the connection a host inbound's
/// listener accepted, or one a host outbound or [`Via`] connected.
pub struct HostStream(AnyStream);

impl HostStream {
    /// The host's own stream, for sail to relay. It need not be `Sync`.
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        HostStream(Box::new(Unshared(std::sync::Mutex::new(stream))))
    }
}

impl fmt::Debug for HostStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostStream")
    }
}

impl AsyncRead for HostStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for HostStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

/// What is not `Sync`, made one: used through `&mut` alone, its lock is
/// never taken, and `Sync` holds as `Mutex` has it.
struct Owned<T>(std::sync::Mutex<T>);

impl<T> Owned<T> {
    fn new(value: T) -> Self {
        Owned(std::sync::Mutex::new(value))
    }

    fn get(&mut self) -> &mut T {
        self.0.get_mut().unwrap_or_else(|e| e.into_inner())
    }
}

/// A stream that is not `Sync`, made one: it is only ever used through
/// `&mut`, so the lock is never taken, and `Sync` holds as `Mutex` has it.
struct Unshared<S>(std::sync::Mutex<S>);

impl<S> Unshared<S> {
    fn get(self: Pin<&mut Self>) -> Pin<&mut S>
    where
        S: Unpin,
    {
        Pin::new(
            self.get_mut()
                .0
                .get_mut()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Unshared<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get().poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Unshared<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get().poll_shutdown(cx)
    }
}

/// Datagrams both ways, each with an address: on a host inbound, `recv`
/// gives what the client sends and where to, and `send` takes what comes
/// back and where from; on a host outbound or [`Via`], `send` takes what
/// goes out and where to, and `recv` gives what comes back and where from.
pub struct Datagrams {
    pub recv: Box<dyn DatagramRecv>,
    pub send: Box<dyn DatagramSend>,
}

impl fmt::Debug for Datagrams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Datagrams")
    }
}

/// The receiving half of [`Datagrams`].
pub trait DatagramRecv: Send {
    /// The next datagram, into `buf`: its length and its address. An error
    /// ends the datagrams.
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, Address)>>;
}

/// The sending half of [`Datagrams`].
pub trait DatagramSend: Send {
    fn send_to<'a>(
        &'a mut self,
        data: &'a [u8],
        address: &'a Address,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// No more is sent.
    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// A user of an instance, as sail's inbounds authenticate them: the one
/// namespace `user_limits`, the management API and the traffic counts
/// use. A host keeps it in its own table, which holds the user as a
/// built-in inbound's credentials do: a user nothing holds any more is
/// dropped with its counts. A user taken out of the inbound by a reload
/// (its object's `users`) is refused from then on, as on any inbound.
#[derive(Clone)]
pub struct User {
    user: UserRef,
    users: UserRegistry,
}

impl User {
    fn bind(users: &UserRegistry, name: &str) -> User {
        User {
            user: users.bind(name),
            users: users.clone(),
        }
    }

    pub(super) fn of(users: &UserRegistry, name: &str) -> User {
        Self::bind(users, name)
    }

    pub fn name(&self) -> &str {
        self.user.name()
    }
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User({})", self.user.name())
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.user.same(&other.user)
    }
}

impl Eq for User {}

// ---------------------------------------------------------------------------
// Host inbounds
// ---------------------------------------------------------------------------

/// An inbound kind of the host's own.
pub trait HostInbound: Send + Sync + 'static {
    /// Serves one connection the inbound's listener accepted: its
    /// handshake, then the sessions it carries, each submitted with
    /// [`Sessions::tcp`] or [`Sessions::udp`]. It runs as a task of the
    /// instance's, of the connection: a panic ends it alone. It is
    /// dropped when the connection's handshake runs out of time, the
    /// inbound is removed, or the instance stops.
    fn serve(&self, connection: Accepted) -> BoxFuture<'static, io::Result<()>>;
}

/// A connection a host inbound's listener accepted.
#[non_exhaustive]
pub struct Accepted {
    pub stream: HostStream,
    /// The client.
    pub source: SocketAddr,
    /// The address it connected to.
    pub local: SocketAddr,
    pub sessions: Sessions,
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("source", &self.source)
            .field("local", &self.local)
            .finish()
    }
}

/// A session a host inbound submits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NewSession {
    /// Where it goes, which the rules route.
    pub destination: Address,
    /// Who it is of, when the host authenticated one: its limits and its
    /// counts are the user's.
    pub user: Option<User>,
    /// What the host's outbound is to know of it.
    pub extensions: Extensions,
    /// The client, and the address it connected to, where the host knows
    /// them: a session of a listener's connection has the connection's,
    /// one submitted with no listener the unspecified address and port 0.
    pub source: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
}

impl NewSession {
    pub fn new(destination: Address) -> Self {
        NewSession {
            destination,
            user: None,
            extensions: Extensions::default(),
            source: None,
            local: None,
        }
    }

    pub fn user(mut self, user: User) -> Self {
        self.user = Some(user);
        self
    }

    pub fn source(mut self, source: SocketAddr) -> Self {
        self.source = Some(source);
        self
    }

    pub fn local(mut self, local: SocketAddr) -> Self {
        self.local = Some(local);
        self
    }

    pub fn extension<T: Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }
}

/// Why sail did not take a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// The connection is closed to more: its inbound is gone, or the
    /// instance stopping.
    Closed,
    /// Its user may not connect through this inbound now: shut out
    /// (quota, expiry), taken out of the inbound, at its
    /// `max_connections`, or a user of another instance or run.
    User { name: String, reason: String },
    /// Submitted with no listener under hard memory pressure, as a new
    /// connection to any inbound is refused then (`inbound.memory_reserve`).
    Pressure,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::Closed => f.write_str("the connection takes no more sessions"),
            Refused::Pressure => f.write_str("hard memory pressure"),
            Refused::User { name, reason } => write!(f, "user [{}]: {}", name, reason),
        }
    }
}

impl std::error::Error for Refused {}

/// Where sessions go to be routed, each a session of its own: those of a
/// connection a host inbound's listener accepted, through the listener;
/// those a host takes off a link of its own, with no listener
/// (`Instance::sessions`), straight to the dispatcher, the host's stream
/// relayed to the outbound's with one copy. Cheap to clone.
#[derive(Clone)]
pub struct Sessions(Arc<SessionsInner>);

struct SessionsInner {
    /// The connection's session, which each is made from.
    base: Session,
    kind: &'static str,
    users: UserRegistry,
    numbering: Numbering,
    to: Handoff,
}

/// Where a `Sessions`' sessions are handed on.
enum Handoff {
    /// To the listener of the connection, which feeds the dispatcher.
    Listener {
        to: mpsc::Sender<AnyBaseInboundTransport>,
        established: watch::Sender<bool>,
    },
    /// To the dispatcher of the instance, on its runtime.
    Instance(crate::control::Dialer),
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sessions({})", self.0.base.inbound_tag)
    }
}

impl Sessions {
    /// The connection's handshake is over: it gives its place among the
    /// inbound's handshakes back (`inbound.max_handshakes`), and its
    /// handshake timeout no longer applies. The first session submitted
    /// implies it; a connection that never gets here is closed at the
    /// timeout. Twice is as once.
    pub fn established(&self) {
        if let Handoff::Listener { established, .. } = &self.0.to {
            established.send_replace(true);
        }
    }

    /// `Instance::sessions`: those of the inbound `inbound_tag`, routed
    /// with no listener.
    pub(super) fn of_instance(
        dialer: crate::control::Dialer,
        inbound_tag: &str,
    ) -> Result<Self, Error> {
        let (dispatcher, _) = dialer.routing().ok_or_else(Error::not_running)?;
        let kind = dispatcher.inbound_type_of(inbound_tag).ok_or_else(|| {
            Error::new(ErrorKind::NotFound, format!("no inbound [{}]", inbound_tag))
        })?;
        let env = dialer.env();
        let base = Session {
            inbound_tag: inbound_tag.to_string(),
            inbound_type: kind,
            ..Default::default()
        };
        Ok(Sessions(Arc::new(SessionsInner {
            base,
            kind,
            users: env.users.clone(),
            numbering: env.numbering.clone(),
            to: Handoff::Instance(dialer),
        })))
    }

    /// Submits a TCP session, whose bytes are `stream`'s: sail routes it,
    /// and relays the stream to the outbound. Returned once sail has it,
    /// with the number it is known by: its records' `ConnectionRecord::id`,
    /// and `SessionInfo::id` as an outbound of the host's is asked for it.
    /// It has one closed record, however it ends: refused by the rules or
    /// an outbound, or failing to connect, it is one with nothing sent or
    /// received. Its place among the connections, and its user's, are
    /// decided as a built-in inbound's session's are, and a session
    /// refused there has its stream closed.
    pub async fn tcp<S>(&self, session: NewSession, stream: S) -> Result<u64, Refused>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.established();
        let sess = self.session(session, Network::Tcp)?;
        let number = told(&sess);
        self.submit(
            BaseInboundTransport::Stream(HostStream::new(stream).0, sess),
            number,
        )
        .await
    }

    /// Submits a UDP association: its datagrams are `datagrams`'. Returned,
    /// and recorded, as `tcp`. Its targets share one outbound, connection
    /// place and byte counter. With `Options::admit`, uncached targets are
    /// checked before forwarding; only rejected target attempts have
    /// additional, independent zero-byte closed records.
    pub async fn udp(&self, session: NewSession, datagrams: Datagrams) -> Result<u64, Refused> {
        self.established();
        let mut sess = self.session(session, Network::Udp)?;
        // Its own among the sessions of the connection, which share its
        // source, as a UoT stream's is.
        sess.stream_id = Some(StreamId::Uuid(uuid::Uuid::new_v4()));
        let source = DatagramSource::new(sess.source, sess.stream_id).with_user(sess.user.clone());
        let datagram = HostInboundDatagram {
            datagrams: Owned::new(datagrams),
            source,
        };
        let number = told(&sess);
        self.submit(
            BaseInboundTransport::Datagram(Box::new(datagram), Some(sess)),
            number,
        )
        .await
    }

    /// Hands a session on to the dispatcher, its number told the host.
    async fn submit(
        &self,
        transport: AnyBaseInboundTransport,
        number: Arc<Number>,
    ) -> Result<u64, Refused> {
        let dialer = match &self.0.to {
            Handoff::Listener { to, .. } => match to.send(transport).await {
                Ok(()) => return Ok(number.id()),
                Err(_) => {
                    // Never sail's: its number was not told.
                    number.forget();
                    return Err(Refused::Closed);
                }
            },
            Handoff::Instance(dialer) => dialer,
        };
        let Some((dispatcher, nat_manager)) = dialer.routing() else {
            number.forget();
            return Err(Refused::Closed);
        };
        // The instance's task, whichever executor the host submits from.
        dialer.env().scope.spawn_on(
            dialer.handle(),
            "host session",
            crate::app::inbound::network_listener::serve_submitted(
                transport,
                dispatcher,
                nat_manager,
            ),
        );
        Ok(number.id())
    }

    fn session(&self, new: NewSession, network: Network) -> Result<Session, Refused> {
        let inner = &self.0;
        let tag = &inner.base.inbound_tag;
        if let Handoff::Instance(dialer) = &inner.to {
            let Some((dispatcher, _)) = dialer.routing() else {
                return Err(Refused::Closed);
            };
            if dispatcher.inbound_type_of(tag).is_none() {
                return Err(Refused::Closed);
            }
            // No listener took it in: what admission does at accept is
            // done here, as far as it applies to one that authenticated.
            if let Some(admission) = &dialer.env().admission {
                if admission.refuses_submitted() {
                    return Err(Refused::Pressure);
                }
            }
        }
        if let Some(user) = &new.user {
            let refused = |reason: String| Refused::User {
                name: user.name().to_string(),
                reason,
            };
            if !user.users.same(&inner.users) {
                return Err(refused(
                    "a user of another instance, or of an earlier run".into(),
                ));
            }
            if user.user.removed_from(tag) {
                return Err(refused(format!("taken out of the inbound [{}]", tag)));
            }
            if !user.user.active() {
                return Err(refused(user.user.status().to_string()));
            }
            if !user.user.admits_on(tag, network == Network::Tcp) {
                return Err(refused(
                    "at its max_connections or max_tcp_connections".into(),
                ));
            }
        }
        let mut sess = inner.base.clone();
        sess.new_span();
        sess.network = network;
        sess.destination = new.destination;
        sess.user = new.user.map(|user| user.user);
        sess.extensions = new.extensions;
        if let Some(source) = new.source {
            sess.source = source;
        }
        if let Some(local) = new.local {
            sess.local_addr = local;
        }
        sess.inbound_type = inner.kind;
        sess.number = None;
        sess.parent_id = None;
        inner.numbering.number(&mut sess);
        Ok(sess)
    }
}

/// The number of `sess`, a session of a host's inbound, as the host is
/// told it.
fn told(sess: &Session) -> Arc<Number> {
    let number = sess.number.clone().expect("a host's session is numbered");
    number.told(sess);
    number
}

/// A host inbound kind, as sail's inbounds are handlers: each accepted
/// connection served by the host in a task of its own, its sessions taken
/// as a multiplexed connection's.
struct HostStreamHandler {
    kind: &'static str,
    host: Arc<dyn HostInbound>,
    users: UserRegistry,
    numbering: Numbering,
}

/// Aborts the task of a connection's `serve` when what it feeds is gone.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The sessions of one connection, as the listener takes them: they end
/// when every `Sessions` of it is gone; dropped, they end its `serve`.
struct Submitted {
    sessions: mpsc::Receiver<AnyBaseInboundTransport>,
    _serve: AbortOnDrop,
}

impl Stream for Submitted {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.sessions.poll_recv(cx)
    }
}

#[async_trait]
impl InboundStreamHandler for HostStreamHandler {
    /// Called within the inbound's handshake timeout, holding the
    /// connection's place among its handshakes: returns, and gives the
    /// place back, once the host says the connection is established.
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        sess.inbound_type = self.kind;
        let (to, sessions) = mpsc::channel(SUBMITTED);
        let (established, mut is_established) = watch::channel(false);
        let accepted = Accepted {
            stream: HostStream(stream),
            source: sess.source,
            local: sess.local_addr,
            sessions: Sessions(Arc::new(SessionsInner {
                base: sess,
                kind: self.kind,
                users: self.users.clone(),
                numbering: self.numbering.clone(),
                to: Handoff::Listener { to, established },
            })),
        };
        let serving = self.host.serve(accepted);
        let kind = self.kind;
        let serve = AbortOnDrop(
            crate::runtime::scope::spawn("host inbound", async move {
                if let Err(e) = serving.await {
                    debug!("{} inbound: {}", kind, e);
                }
            })
            .abort_handle(),
        );
        // Every `Sessions` gone, or `serve` ended, before it was
        // established: the connection carried nothing.
        if is_established
            .wait_for(|established| *established)
            .await
            .is_err()
        {
            return Ok(InboundTransport::Empty);
        }
        Ok(InboundTransport::Incoming(Box::new(Submitted {
            sessions,
            _serve: serve,
        })))
    }
}

/// A host's datagrams, as a UDP session of an inbound.
struct HostInboundDatagram {
    datagrams: Owned<Datagrams>,
    source: DatagramSource,
}

impl InboundDatagram for HostInboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let Datagrams { recv, send } = self
            .datagrams
            .0
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        (
            Box::new(InboundRecv {
                recv: Owned::new(recv),
                source: self.source,
            }),
            Box::new(InboundSend(Owned::new(send))),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("a host's datagrams"))
    }
}

struct InboundRecv {
    recv: Owned<Box<dyn DatagramRecv>>,
    source: DatagramSource,
}

struct InboundSend(Owned<Box<dyn DatagramSend>>);

#[async_trait]
impl InboundDatagramRecvHalf for InboundRecv {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        match self.recv.get().recv_from(buf).await {
            Ok((n, to)) => Ok((n, self.source.clone(), to)),
            Err(e) => Err(ProxyError::DatagramFatal(e.into())),
        }
    }
}

#[async_trait]
impl InboundDatagramSendHalf for InboundSend {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.get().send_to(buf, src_addr).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.get().close().await
    }
}

// ---------------------------------------------------------------------------
// Host outbounds
// ---------------------------------------------------------------------------

/// An outbound kind of the host's own: a rule routes to its tag, or a
/// group has it as a member, as any outbound.
pub trait HostOutbound: Send + Sync + 'static {
    /// A stream for `session`, to its destination or wherever the host
    /// takes it: made by the host, or through an outbound of sail's with
    /// `via`. It runs in the task of the session's connection: a panic
    /// ends that connection alone.
    fn stream<'a>(
        &'a self,
        session: &'a SessionInfo,
        via: &'a Via,
    ) -> BoxFuture<'a, io::Result<HostStream>>;

    /// Datagrams for the UDP session `session`; none unless the kind has
    /// them.
    fn datagrams<'a>(
        &'a self,
        session: &'a SessionInfo,
        via: &'a Via,
    ) -> BoxFuture<'a, io::Result<Datagrams>> {
        let _ = (session, via);
        Box::pin(async { Err(io::Error::from(io::ErrorKind::Unsupported)) })
    }

    /// The network changed so that connections made on the one before do
    /// not survive: what the kind pools is to be dropped, as sail's
    /// outbounds drop theirs.
    fn network_changed(&self) {}

    /// Closes the carriers with nothing open, as after a long sleep.
    fn close_idle(&self) {}
}

/// What a host outbound knows of a session routed to it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionInfo {
    /// The number the session is known by, from before it is dialled: its
    /// records' `ConnectionRecord::id`, and what `Sessions::tcp` and `udp`
    /// returned for a session of the host's inbound. A session the
    /// outbound refuses has a closed record still, with nothing sent or
    /// received. In `Options::admit`, an additional UDP target instead
    /// has an attempt id: only rejection records that id; acceptance
    /// keeps accounting to the association's original id.
    pub id: u64,
    /// The run carried by this connection's records, so `(run, id)` names
    /// it across restarts. Independent of `State::Running::since`; none
    /// before a number with recording attached is assigned.
    pub run: Option<std::time::SystemTime>,
    /// Root UDP association for an additional target admission attempt;
    /// none for an ordinary session. Interpreted within the same run.
    pub parent_id: Option<u64>,
    /// Snapshot of the actual named built-in credential row that
    /// authenticated it; not a lookup of the user's current credentials.
    pub credential_context: Option<crate::control::context::RecordContext>,
    /// Frozen host binding; present before user and host session checks.
    pub record_context: Option<crate::control::context::RecordContext>,
    pub network: Network,
    /// The client.
    pub source: SocketAddr,
    /// The address it connected to, as `NewSession::local` is; the
    /// unspecified address and port 0 where none is known.
    pub local: SocketAddr,
    pub destination: Address,
    pub inbound_tag: String,
    /// The type of the inbound it came in through.
    pub inbound_type: &'static str,
    pub user: Option<String>,
    /// The domain known for it, and where from, as its records tell them:
    /// the destination's own, the name it is dialled as, or what a `sniff`
    /// rule read of its first bytes.
    pub domain: Option<String>,
    pub domain_source: Option<DomainSource>,
    pub extensions: Extensions,
    /// The session itself, which `Via` carries on.
    sess: Session,
}

impl SessionInfo {
    fn of(sess: &Session) -> Self {
        if let Some(number) = &sess.number {
            number.told(sess);
        }
        Self::untold(sess)
    }

    /// What a host is told of `sess`, its number not yet told: a session a
    /// host's check refuses has the record of a refused one, not of one
    /// told.
    pub(super) fn untold(sess: &Session) -> Self {
        // Every session sail dispatches is numbered before it is dialled.
        let id = sess.number.as_ref().map_or(0, |number| number.id());
        let (domain, domain_source) = match crate::app::dispatcher::domain_of(sess) {
            Some((domain, source)) => (Some(domain), Some(source)),
            None => (None, None),
        };
        SessionInfo {
            id,
            run: sess.number.as_ref().and_then(|number| number.run()),
            parent_id: sess.parent_id,
            record_context: sess.record_context.clone(),
            credential_context: sess
                .user
                .as_ref()
                .and_then(|u| u.credential_context())
                .cloned(),
            network: sess.network,
            source: sess.source,
            local: sess.local_addr,
            destination: sess.destination.clone(),
            inbound_tag: sess.inbound_tag.clone(),
            inbound_type: sess.inbound_type,
            user: crate::user::name(&sess.user).map(str::to_string),
            domain,
            domain_source,
            extensions: sess.extensions.clone(),
            sess: sess.clone(),
        }
    }

    /// The session as it is to go on to `destination`, for the next hop:
    /// the domain known is of the destination replaced, and is dropped.
    pub fn with_destination(mut self, destination: Address) -> Self {
        if destination != self.destination {
            self.domain = None;
            self.domain_source = None;
        }
        self.destination = destination;
        self
    }

    /// The session as it is to go on with `extensions`, for the next hop.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = extensions;
        self
    }

    /// The session `Via` dials with: this one's, going to `destination`,
    /// carrying `extensions`.
    fn next_hop(&self, network: Network) -> Session {
        let mut sess = self.sess.clone();
        // An admission probe is not an accounting identity for a Via
        // dial. In particular a retained rejected view must not reuse
        // its pending terminal record's number or mutate that verdict.
        if sess.parent_id.is_some() {
            sess.number = None;
        }
        sess.parent_id = None;
        sess.network = network;
        if sess.destination != self.destination {
            sess.destination = self.destination.clone();
            // What was sniffed is of the destination just replaced.
            sess.forget_sniffed();
            sess.route.dial_domain = None;
            sess.fake_ip = false;
        }
        sess.extensions = self.extensions.clone();
        sess
    }
}

/// The outbounds of sail's a host outbound dials through, by tag: looked
/// up when it dials, so that the outbounds a reload builds are the ones
/// used. What goes through them is the session's, counted once, as the
/// session it carries: the tag is added to the session's chain, as a
/// group adds its member.
pub struct Via {
    outbounds: crate::net::dial::Outbounds,
    dns: SyncDnsClient,
}

impl fmt::Debug for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Via")
    }
}

impl Via {
    fn handler(&self, outbound: &str) -> io::Result<AnyOutboundHandler> {
        self.outbounds.find(outbound).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("outbound [{}] not found", outbound),
            )
        })
    }

    /// A stream through the outbound `outbound` (sail's own, a group, or
    /// another of the host's) to `session.destination`.
    pub async fn stream(&self, outbound: &str, session: &SessionInfo) -> io::Result<HostStream> {
        let h = self.handler(outbound)?;
        let sess = session.next_hop(Network::Tcp);
        sess.chain.push(h.tag());
        let th = h.stream()?;
        let connect = th.connect_addr();
        let mut handshake = Err(io::Error::other("nowhere to connect"));
        for to in crate::net::destinations(&sess, &connect) {
            let at = Session {
                destination: to,
                ..sess.clone()
            };
            let at = crate::net::dial_domain::session(&at, &h, &connect);
            handshake = crate::net::dial_domain::stream_done(
                &at,
                async {
                    let stream =
                        crate::net::connect_stream_routed(&at, self.dns.clone(), &h).await?;
                    th.handle(&at, None, stream).await
                }
                .await,
            );
            if handshake.is_ok() {
                break;
            }
        }
        handshake.map(HostStream)
    }

    /// Datagrams through the outbound `outbound` for `session`.
    pub async fn datagrams(&self, outbound: &str, session: &SessionInfo) -> io::Result<Datagrams> {
        let h = self.handler(outbound)?;
        let sess = session.next_hop(Network::Udp);
        sess.chain.push(h.tag());
        let transport = crate::net::connect_datagram_outbound(&sess, self.dns.clone(), &h).await?;
        let (recv, send) = h.datagram()?.handle(&sess, transport).await?.split();
        Ok(Datagrams {
            recv: Box::new(OutboundRecv(recv)),
            send: Box::new(OutboundSend(send)),
        })
    }
}

struct OutboundRecv(Box<dyn OutboundDatagramRecvHalf>);

impl DatagramRecv for OutboundRecv {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, Address)>> {
        self.0.recv_from(buf)
    }
}

struct OutboundSend(Box<dyn OutboundDatagramSendHalf>);

impl DatagramSend for OutboundSend {
    fn send_to<'a>(
        &'a mut self,
        data: &'a [u8],
        address: &'a Address,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.0.send_to(data, address).await.map(|_| ()) })
    }

    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        self.0.close()
    }
}

struct OutboundShared {
    host: Arc<dyn HostOutbound>,
    via: Via,
}

struct HostOutboundStream(Arc<OutboundShared>);

#[async_trait]
impl OutboundStreamHandler for HostOutboundStream {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let info = SessionInfo::of(sess);
        Ok(self.0.host.stream(&info, &self.0.via).await?.0)
    }

    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        self.0.host.network_changed();
    }

    fn close_idle(&self) {
        self.0.host.close_idle();
    }
}

struct HostOutboundDatagrams(Arc<OutboundShared>);

#[async_trait]
impl OutboundDatagramHandler for HostOutboundDatagrams {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let info = SessionInfo::of(sess);
        let datagrams = self.0.host.datagrams(&info, &self.0.via).await?;
        Ok(Box::new(HostOutboundDatagram(datagrams)))
    }

    // Both halves of the outbound hear of a change as one: the host's
    // kind hears of it from the stream handler alone.
}

struct HostOutboundDatagram(Datagrams);

impl OutboundDatagram for HostOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let Datagrams { recv, send } = self.0;
        (
            Box::new(HostRecv(Owned::new(recv))),
            Box::new(HostSend(Owned::new(send))),
        )
    }
}

struct HostRecv(Owned<Box<dyn DatagramRecv>>);
struct HostSend(Owned<Box<dyn DatagramSend>>);

#[async_trait]
impl OutboundDatagramRecvHalf for HostRecv {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        self.0.get().recv_from(buf).await
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for HostSend {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        self.0.get().send_to(buf, dst_addr).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.get().close().await
    }
}

#[cfg(test)]
mod parent_tests {
    use super::*;

    #[test]
    fn parent_metadata_is_optional_and_does_not_follow_a_via_hop() {
        assert_eq!(SessionInfo::untold(&Session::default()).parent_id, None);
        assert_eq!(SessionInfo::untold(&Session::default()).run, None);
        let numbering = crate::app::stat_manager::Numbering::default();
        let mut attempt = Session {
            network: Network::Udp,
            parent_id: Some(41),
            ..Session::default()
        };
        numbering.number(&mut attempt);
        let info = SessionInfo::untold(&attempt);
        assert_eq!(info.parent_id, Some(41));
        assert_eq!(info.run, None, "standalone numbering has no recorder");
        assert_eq!(attempt.clone().parent_id, Some(41));
        for network in [Network::Tcp, Network::Udp] {
            let next = info.next_hop(network);
            assert_eq!(next.parent_id, None);
            assert!(
                next.number.is_none(),
                "a probe cannot reactivate its attempt id"
            );
        }
        assert_eq!(info.parent_id, Some(41), "the original view is unchanged");
    }

    #[test]
    fn run_tokens_match_records_even_when_old_closes_after_reused_ids() {
        use crate::app::stat_manager::StatManager;
        use crate::control::events::{EventHub, Outcome};
        use crate::user::UserRegistry;
        let events = EventHub::default();
        let mut records = events.records();
        let old = StatManager::new(0, UserRegistry::default()).recording(events.clone());
        let make = |sm: &StatManager| {
            let mut root = Session::default();
            sm.numbering().number(&mut root);
            let parent = root.number.as_ref().unwrap().id();
            let mut attempt = Session {
                network: Network::Udp,
                parent_id: Some(parent),
                ..Session::default()
            };
            sm.numbering().number(&mut attempt);
            (root, attempt)
        };
        let (_old_root, old_attempt) = make(&old);
        let old_info = SessionInfo::untold(&old_attempt);
        let old_key = (old_info.run.unwrap(), old_info.id);
        drop(old_info);
        let new = StatManager::new(0, UserRegistry::default()).recording(events);
        let (_new_root, new_attempt) = make(&new);
        let new_info = SessionInfo::untold(&new_attempt);
        let new_key = (new_info.run.unwrap(), new_info.id);
        assert_eq!(old_key.1, new_key.1, "ids restart from the same value");
        assert_ne!(old_key.0, new_key.0);
        assert_eq!(new_info.parent_id, old_attempt.parent_id);
        drop(new_info);
        for (attempt, key) in [(new_attempt, new_key), (old_attempt, old_key)] {
            attempt
                .number
                .as_ref()
                .unwrap()
                .refused_by_host(&attempt, None);
            drop(attempt);
            let record = futures::FutureExt::now_or_never(records.recv())
                .unwrap()
                .unwrap();
            assert_eq!((record.run, record.id), key);
            assert_eq!(record.parent_id, Some(1));
            assert_eq!(record.outcome, Some(Outcome::Rejected));
        }
    }
}
