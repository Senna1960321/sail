use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool as CleanupActive, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use sail_netstack::{
    FlowMap, IpEndpoint, NetworkGeneration, PacketIo, ResourceKind, ResourceLedger, RunnerConfig,
    RunnerError, ShardRouterStats, ShardedPacketIo, ShardedPacketIoControl, SingleShardRunner,
    SlabChain, StackStats, StepOutcome, TcpConnection, TcpError, TcpEvent, TcpFlowToken,
    TcpTableError, TransportProtocol, UdpError, UdpFlowToken,
};
use tokio::sync::{mpsc as tokio_mpsc, watch, Notify};

use super::stream::{command_channel, next_command, NativeTcpStream, ReadReply, TcpCommand};

/// How often the runtime tries again what the stack had no room for, while
/// something waits: a write, read, close, connect or release refused by
/// backpressure, or a connect whose caller may leave.
const RETRY_INTERVAL_MS: u64 = 10;

/// A TCP connection the stack carries, accepted from the network or opened
/// by [`NativeRuntimeControl::connect`].
pub(crate) struct NativeConnection {
    pub connection: TcpConnection,
    pub stream: NativeTcpStream,
}

/// A connect that waits for room in the stack.
struct PendingConnect {
    local: SocketAddr,
    remote: SocketAddr,
    response: oneshot::Sender<io::Result<NativeConnection>>,
}

pub(crate) struct NativeUdpDatagram {
    pub token: UdpFlowToken,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: SlabChain,
}

#[derive(Clone)]
pub(crate) struct NativeUdpReplyHandle {
    commands: Vec<mpsc::Sender<TcpCommand>>,
}

impl NativeUdpReplyHandle {
    pub(crate) async fn send(
        &mut self,
        token: UdpFlowToken,
        source: SocketAddr,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let (response, receiver) = oneshot::channel();
        let commands = self
            .commands
            .get_mut(usize::from(token.shard().get()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP token shard")
            })?;
        commands
            .send(TcpCommand::UdpReply {
                token,
                source,
                payload,
                response,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner stopped"))?;
        receiver
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner dropped reply"))?
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeStatsSnapshot {
    pub stack: StackStats,
    pub router: ShardRouterStats,
    pub shard_count: usize,
}

#[derive(Clone)]
pub(crate) struct NativeRuntimeControl {
    commands: Vec<mpsc::Sender<TcpCommand>>,
    router: ShardedPacketIoControl,
    ledger: Arc<ResourceLedger>,
    completion: watch::Receiver<bool>,
    next_shard: Arc<AtomicUsize>,
}

impl NativeRuntimeControl {
    async fn send_all<T>(
        &mut self,
        mut command: impl FnMut(oneshot::Sender<T>) -> TcpCommand,
    ) -> io::Result<Vec<oneshot::Receiver<T>>> {
        let mut receivers = Vec::with_capacity(self.commands.len());
        for commands in &mut self.commands {
            let (response, receiver) = oneshot::channel();
            commands
                .send(command(response))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner stopped"))?;
            receivers.push(receiver);
        }
        Ok(receivers)
    }

    async fn wait_all<T>(receivers: Vec<oneshot::Receiver<T>>) -> io::Result<Vec<T>> {
        futures::future::try_join_all(receivers)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner dropped reply"))
    }

    pub(crate) async fn shutdown(&mut self, grace_period_ms: u64) -> io::Result<()> {
        let receivers = self
            .send_all(|response| TcpCommand::Shutdown {
                grace_period_ms,
                response,
            })
            .await?;
        Self::wait_all(receivers).await.map(|_| ())
    }

    pub(crate) async fn wait_stopped(&mut self) -> io::Result<()> {
        self.completion
            .wait_for(|stopped| *stopped)
            .await
            .map(|_| ())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "native runtime completion channel closed",
                )
            })
    }

    pub(crate) async fn abort(&mut self) -> io::Result<()> {
        let receivers = self
            .send_all(|response| TcpCommand::ControlAbort { response })
            .await?;
        Self::wait_all(receivers).await.map(|_| ())
    }

    pub(crate) async fn reset_network(&mut self, generation: NetworkGeneration) -> io::Result<()> {
        // Change classification first. Packets racing the transition can be
        // dropped, but cannot create fresh ownership under the old generation.
        self.router.reset_network(generation)?;
        let receivers = self
            .send_all(|response| TcpCommand::ResetNetwork {
                generation,
                response,
            })
            .await?;
        Self::wait_all(receivers).await.map(|_| ())
    }

    pub(crate) async fn update_mtu(&mut self, mtu: usize) -> io::Result<()> {
        let receivers = self
            .send_all(|response| TcpCommand::UpdateMtu { mtu, response })
            .await?;
        for result in Self::wait_all(receivers).await? {
            result.map_err(runner_io_error)?;
        }
        Ok(())
    }

    /// Opens a TCP connection from `local` to `remote` once the handshake
    /// completes. Port 0 in `local` picks an ephemeral port. Dropping the
    /// future abandons the connection.
    #[cfg_attr(
        not(any(test, feature = "wireguard")),
        expect(dead_code, reason = "the WireGuard endpoint is its user")
    )]
    pub(crate) async fn connect(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<NativeConnection> {
        let shard = self.shard_for(local, remote, TransportProtocol::Tcp)?;
        let (response, receiver) = oneshot::channel();
        self.commands[shard]
            .send(TcpCommand::Connect {
                local,
                remote,
                response,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner stopped"))?;
        receiver
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner dropped reply"))?
    }

    /// Sends a datagram from `local` to `remote`, and returns the token of
    /// its flow and the local address it went from. Port 0 in `local` picks
    /// an ephemeral port. The remote end's datagrams to that address arrive
    /// with the other datagrams the runtime delivers, under the same token.
    #[cfg_attr(
        not(any(test, feature = "wireguard")),
        expect(dead_code, reason = "the WireGuard endpoint is its user")
    )]
    pub(crate) async fn send_udp(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        payload: Vec<u8>,
    ) -> io::Result<(UdpFlowToken, SocketAddr)> {
        let shard = self.shard_for(local, remote, TransportProtocol::Udp)?;
        let (response, receiver) = oneshot::channel();
        self.commands[shard]
            .send(TcpCommand::UdpOriginate {
                local,
                remote,
                payload,
                response,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner stopped"))?;
        receiver
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner dropped reply"))?
    }

    /// The shard to open a flow on: the one its replies are routed to, or
    /// for an ephemeral port any, which then picks a port that routes back.
    fn shard_for(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        protocol: TransportProtocol,
    ) -> io::Result<usize> {
        if local.port() == 0 {
            return Ok(self.next_shard.fetch_add(1, AtomicOrdering::Relaxed) % self.commands.len());
        }
        let owner = self.router.owner(IpEndpoint {
            source: remote,
            destination: local,
            protocol,
        })?;
        Ok(usize::from(owner.get()))
    }

    pub(crate) async fn stats_snapshot(&mut self) -> io::Result<NativeStatsSnapshot> {
        let receivers = self
            .send_all(|response| TcpCommand::StatsSnapshot { response })
            .await?;
        let shards = Self::wait_all(receivers).await?;
        let shard_count = shards.len();
        let stack = StackStats::aggregate(shards, self.ledger.snapshot()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native shard generations disagree",
            )
        })?;
        Ok(NativeStatsSnapshot {
            stack,
            router: self.router.stats()?,
            shard_count,
        })
    }

    /// Every live TCP flow of each shard, by shard: a diagnostics read.
    #[cfg(feature = "internal-diagnostics")]
    pub(crate) async fn flow_samples(
        &mut self,
    ) -> io::Result<Vec<Vec<sail_netstack::tcp::TcpFlowSample>>> {
        let receivers = self
            .send_all(|response| TcpCommand::FlowSamples { response })
            .await?;
        Self::wait_all(receivers).await
    }
}

struct FlowBridge {
    cleanup_active: Arc<CleanupActive>,
    readable_bytes: usize,
    peer_eof: bool,
    pending_read: Option<(usize, oneshot::Sender<ReadReply>)>,
    pending_write_reservation: Option<(usize, oneshot::Sender<io::Result<usize>>)>,
    reserved_write_bytes: usize,
    pending_write: Option<(Vec<u8>, oneshot::Sender<io::Result<usize>>)>,
    pending_close: Option<oneshot::Sender<io::Result<()>>>,
    /// The application's close went through: its FIN is queued.
    closed: bool,
}

impl FlowBridge {
    fn new(cleanup_active: Arc<CleanupActive>) -> Self {
        Self {
            cleanup_active,
            readable_bytes: 0,
            peer_eof: false,
            pending_read: None,
            pending_write_reservation: None,
            reserved_write_bytes: 0,
            pending_write: None,
            pending_close: None,
            closed: false,
        }
    }

    /// Whether an operation waits that a retry may finish: backpressure
    /// sends no event when it eases. A reservation waits for the flow's
    /// `Writable` event instead.
    fn waits(&self) -> bool {
        self.pending_write.is_some()
            || self.pending_close.is_some()
            || (self.pending_read.is_some() && (self.readable_bytes > 0 || self.peer_eof))
    }

    fn fail(mut self, message: &'static str) {
        self.cleanup_active.store(false, AtomicOrdering::Release);
        if let Some((_, response)) = self.pending_read.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
        if let Some((_, response)) = self.pending_write_reservation.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
        if let Some((_, response)) = self.pending_write.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
        if let Some(response) = self.pending_close.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
    }
}

pub(crate) struct NativeRuntime<I> {
    runner: SingleShardRunner<I>,
    /// The stack's budget, which bytes read ahead are charged to.
    ledger: Arc<ResourceLedger>,
    /// What a read takes beyond what was asked, in bytes: see
    /// `netstack.read_ahead`.
    read_ahead: usize,
    commands_tx: mpsc::Sender<TcpCommand>,
    commands_rx: mpsc::Receiver<TcpCommand>,
    cleanup_tx: tokio_mpsc::Sender<TcpFlowToken>,
    cleanup_rx: tokio_mpsc::Receiver<TcpFlowToken>,
    cleanup_overflow: Arc<Notify>,
    accepted_tx: tokio_mpsc::Sender<NativeConnection>,
    udp_tx: tokio_mpsc::Sender<NativeUdpDatagram>,
    flows: FlowMap<TcpFlowToken, FlowBridge>,
    connecting: FlowMap<TcpFlowToken, oneshot::Sender<io::Result<NativeConnection>>>,
    pending_connects: Vec<PendingConnect>,
    /// Flows let go of or aborted while the stack had no room for the
    /// packet that goes with it, retried on each tick: given up, they would
    /// stay in the table for good, holding their windows (as hundreds of
    /// connections closing at once did, peakpassvpn/sail#6).
    pending_releases: Vec<(TcpFlowToken, Release)>,
    /// Something was left to retry since the loop last looked.
    retry_wanted: bool,
    /// When the next retry is due, while something waits for one.
    retry_at_ms: Option<u64>,
}

/// How a flow the runtime no longer bridges is let go of.
#[derive(Clone, Copy)]
enum Release {
    /// Closed by the application: it finishes its close alone.
    Closed,
    /// Reset.
    Abort,
}

impl<I: PacketIo> NativeRuntime<I> {
    #[cfg(test)]
    pub(crate) fn new(
        io: I,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
        command_capacity: usize,
        accept_capacity: usize,
        udp_capacity: usize,
    ) -> Result<
        (
            Self,
            tokio_mpsc::Receiver<NativeConnection>,
            tokio_mpsc::Receiver<NativeUdpDatagram>,
            NativeUdpReplyHandle,
        ),
        RunnerError,
    > {
        assert!(
            command_capacity > 0,
            "native command capacity must be non-zero"
        );
        assert!(
            accept_capacity > 0,
            "native accept capacity must be non-zero"
        );
        assert!(udp_capacity > 0, "native UDP capacity must be non-zero");
        let (accepted_tx, accepted_rx) = tokio_mpsc::channel(accept_capacity);
        let (udp_tx, udp_rx) = tokio_mpsc::channel(udp_capacity);
        let (runtime, commands_tx) =
            Self::new_with_sinks(io, ledger, config, command_capacity, accepted_tx, udp_tx)?;
        let udp_reply = NativeUdpReplyHandle {
            commands: vec![commands_tx],
        };
        Ok((runtime, accepted_rx, udp_rx, udp_reply))
    }

    fn new_with_sinks(
        io: I,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
        command_capacity: usize,
        accepted_tx: tokio_mpsc::Sender<NativeConnection>,
        udp_tx: tokio_mpsc::Sender<NativeUdpDatagram>,
    ) -> Result<(Self, mpsc::Sender<TcpCommand>), RunnerError> {
        assert!(
            command_capacity > 0,
            "native command capacity must be non-zero"
        );
        let cleanup_capacity = ledger.budget().max_tcp_flows;
        let runner = SingleShardRunner::new(io, Arc::clone(&ledger), config)?;
        let (commands_tx, commands_rx) = command_channel(command_capacity);
        let (cleanup_tx, cleanup_rx) = tokio_mpsc::channel(cleanup_capacity);
        let cleanup_overflow = Arc::new(Notify::new());
        Ok((
            Self {
                runner,
                ledger,
                read_ahead: 0,
                commands_tx: commands_tx.clone(),
                commands_rx,
                cleanup_tx,
                cleanup_rx,
                cleanup_overflow,
                accepted_tx,
                udp_tx,
                flows: FlowMap::default(),
                connecting: FlowMap::default(),
                pending_connects: Vec::new(),
                pending_releases: Vec::new(),
                retry_wanted: false,
                retry_at_ms: None,
            },
            commands_tx,
        ))
    }

    #[cfg(test)]
    pub(crate) fn set_read_ahead(&mut self, bytes: usize) {
        self.read_ahead = bytes;
    }

    pub(crate) async fn run(mut self) -> Result<(), RunnerError> {
        let started = Instant::now();
        let cleanup_overflow = Arc::clone(&self.cleanup_overflow);
        // One timer, for the stack's next deadline or the next retry, and
        // none while neither waits: an idle stack does not wake.
        let mut timer = std::pin::pin!(tokio::time::sleep(Duration::ZERO));
        let mut armed_ms = None;
        loop {
            let now_ms = elapsed_ms(started);
            if std::mem::take(&mut self.retry_wanted) {
                self.retry_at_ms
                    .get_or_insert(now_ms.saturating_add(RETRY_INTERVAL_MS));
            }
            if self.retry_at_ms.is_some_and(|at_ms| at_ms <= now_ms) {
                self.retry_at_ms = self
                    .retry_pending()
                    .then_some(now_ms.saturating_add(RETRY_INTERVAL_MS));
            }
            // What is due already the step does first thing; the timer is
            // for what comes later.
            let wake_ms = [self.runner.next_deadline_ms(), self.retry_at_ms]
                .into_iter()
                .flatten()
                .min()
                .filter(|wake_ms| *wake_ms > now_ms);
            if wake_ms != armed_ms {
                if let Some(wake_ms) = wake_ms {
                    let at = started + Duration::from_millis(wake_ms);
                    timer.as_mut().reset(at.into());
                }
                armed_ms = wake_ms;
            }
            enum Wake {
                Command(Option<TcpCommand>),
                Cleanup(Option<TcpFlowToken>),
                CleanupOverflow,
                Step(Result<StepOutcome, RunnerError>),
                Timer,
            }
            let wake = tokio::select! {
                command = next_command(&mut self.commands_rx) => Wake::Command(command),
                cleanup = self.cleanup_rx.recv() => Wake::Cleanup(cleanup),
                () = cleanup_overflow.notified() => Wake::CleanupOverflow,
                result = self.runner.step_with_clock(now_ms, || elapsed_ms(started)) => Wake::Step(result),
                () = &mut timer, if armed_ms.is_some() => Wake::Timer,
            };
            match wake {
                Wake::Command(Some(command)) => {
                    if self.handle_command(command, now_ms) {
                        return Ok(());
                    }
                }
                Wake::Command(None) => {
                    self.runner.abort();
                    self.fail_all("native TCP command channel closed");
                    return Ok(());
                }
                Wake::Cleanup(Some(token)) => self.drop_flow(token),
                Wake::Cleanup(None) => {}
                Wake::CleanupOverflow => self.cleanup_dropped_streams(),
                Wake::Step(Ok(outcome)) => self.handle_outcome(outcome),
                Wake::Step(Err(RunnerError::Closed)) => {
                    self.fail_all("native network runner stopped");
                    return Ok(());
                }
                Wake::Step(Err(error)) => {
                    self.fail_all("native network runner failed");
                    return Err(error);
                }
                Wake::Timer => armed_ms = None,
            }
        }
    }

    /// Returns true when the runtime should stop after acknowledging a
    /// terminal control command.
    fn handle_command(&mut self, command: TcpCommand, now_ms: u64) -> bool {
        match command {
            TcpCommand::Read {
                token,
                max_bytes,
                response,
            } => {
                let Some(flow) = self.flows.get_mut(&token) else {
                    let _ = response.send(Ok((Vec::new(), None)));
                    return false;
                };
                if flow.pending_read.is_some() {
                    let _ = response.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "concurrent TCP read",
                    )));
                    return false;
                }
                flow.pending_read = Some((max_bytes, response));
                self.service_read(token);
            }
            TcpCommand::ReserveWrite {
                token,
                max_bytes,
                response,
            } => self.try_reserve_write(token, max_bytes, response),
            TcpCommand::CommitWrite {
                token,
                payload,
                response,
            } => self.try_write(token, payload, response),
            TcpCommand::Close { token, response } => self.try_close(token, response),
            TcpCommand::UdpReply {
                token,
                source,
                payload,
                response,
            } => {
                let result = self
                    .runner
                    .queue_udp_reply(token, source, &payload, now_ms)
                    .map_err(runner_io_error);
                let _ = response.send(result);
            }
            TcpCommand::Shutdown {
                grace_period_ms,
                response,
            } => {
                self.runner.shutdown(now_ms.saturating_add(grace_period_ms));
                let _ = response.send(());
            }
            TcpCommand::ControlAbort { response } => {
                self.runner.abort();
                self.fail_all("native network runner aborted");
                let _ = response.send(());
                return true;
            }
            TcpCommand::ResetNetwork {
                generation,
                response,
            } => {
                self.runner.reset_network(generation);
                self.fail_all("native network generation changed");
                let _ = response.send(());
            }
            TcpCommand::UpdateMtu { mtu, response } => {
                let _ = response.send(self.runner.update_mtu(mtu));
            }
            TcpCommand::StatsSnapshot { response } => {
                let _ = response.send(self.runner.stats_snapshot());
            }
            #[cfg(feature = "internal-diagnostics")]
            TcpCommand::FlowSamples { response } => {
                let _ = response.send(self.runner.tcp_flow_samples());
            }
            TcpCommand::Connect {
                local,
                remote,
                response,
            } => self.connect(local, remote, response),
            TcpCommand::UdpOriginate {
                local,
                remote,
                payload,
                response,
            } => {
                let result = self
                    .runner
                    .originate_udp(local, remote, &payload, now_ms)
                    .map_err(runner_io_error);
                let _ = response.send(result);
            }
        }
        false
    }

    fn handle_outcome(&mut self, outcome: StepOutcome) {
        for datagram in outcome.datagrams {
            let datagram = NativeUdpDatagram {
                token: datagram.token,
                source: datagram.source,
                destination: datagram.destination,
                payload: datagram.payload,
            };
            if self.udp_tx.try_send(datagram).is_err() {
                tracing::warn!("native UDP uplink channel is full; dropping datagram");
            }
        }
        for event in outcome.tcp_events {
            match event {
                TcpEvent::Accepted(connection) => self.accept(connection),
                TcpEvent::Connected(connection) => self.connected(connection),
                TcpEvent::Readable { token, bytes } => {
                    if let Some(flow) = self.flows.get_mut(&token) {
                        flow.readable_bytes = flow.readable_bytes.saturating_add(bytes);
                    }
                    self.service_read(token);
                }
                TcpEvent::Writable(token) => {
                    self.retry_write(token);
                    self.retry_write_reservation(token);
                    self.retry_close(token);
                }
                TcpEvent::PeerHalfClosed(token) => {
                    if let Some(flow) = self.flows.get_mut(&token) {
                        flow.peer_eof = true;
                    }
                    self.service_read(token);
                }
                TcpEvent::Closed(token) => {
                    if let Some(response) = self.connecting.remove(&token) {
                        let _ = response.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "TCP connection was refused or never answered",
                        )));
                    }
                    self.finish_flow(token);
                }
            }
        }
    }

    fn accept(&mut self, connection: TcpConnection) {
        let token = connection.token;
        if self.runner.accept_tcp(token).is_err() {
            return;
        }
        let accepted = self.bridge(connection);
        if self.accepted_tx.try_send(accepted).is_err() {
            self.abort_flow(token);
        }
    }

    fn connect(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        response: oneshot::Sender<io::Result<NativeConnection>>,
    ) {
        match self.runner.connect_tcp(local, remote) {
            Ok(token) => {
                self.connecting.insert(token, response);
                self.retry_wanted = true;
            }
            Err(error) if retryable(&error) => {
                self.pending_connects.push(PendingConnect {
                    local,
                    remote,
                    response,
                });
                self.retry_wanted = true;
            }
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn connected(&mut self, connection: TcpConnection) {
        let token = connection.token;
        let Some(response) = self.connecting.remove(&token) else {
            self.release(token, Release::Abort);
            return;
        };
        let opened = self.bridge(connection);
        if response.send(Ok(opened)).is_err() {
            self.abort_flow(token);
        }
    }

    /// Joins an established flow to a new stream.
    fn bridge(&mut self, connection: TcpConnection) -> NativeConnection {
        let token = connection.token;
        let cleanup_active = Arc::new(CleanupActive::new(true));
        let stream = NativeTcpStream::new(
            token,
            self.commands_tx.clone(),
            self.cleanup_tx.clone(),
            Arc::clone(&self.cleanup_overflow),
            Arc::clone(&cleanup_active),
        );
        self.flows.insert(token, FlowBridge::new(cleanup_active));
        NativeConnection { connection, stream }
    }

    fn service_read(&mut self, token: TcpFlowToken) {
        let Some(flow) = self.flows.get_mut(&token) else {
            return;
        };
        let should_complete =
            flow.pending_read.is_some() && (flow.readable_bytes > 0 || flow.peer_eof);
        if !should_complete {
            return;
        }
        let (max_bytes, response) = flow.pending_read.take().expect("checked above");
        if flow.readable_bytes == 0 {
            let _ = response.send(Ok((Vec::new(), None)));
            return;
        }
        let asked = max_bytes.min(flow.readable_bytes);
        // Bytes beyond what the reader asked for, kept by its stream for its
        // next reads, are charged as the stack's own were: once read they
        // open the window, and would otherwise be memory nothing sees. A
        // stalled reader holds them, so they are granted only within the
        // budget's optional share, never from what sends and new
        // connections need; past it the read takes only what was asked.
        let extra = (flow.readable_bytes - asked).min(self.read_ahead.saturating_sub(asked));
        let mut lease = (extra > 0)
            .then(|| {
                self.ledger
                    .try_acquire_within(
                        ResourceKind::TcpPayloadBytes,
                        extra,
                        self.ledger.budget().tcp_optional_ceiling(),
                    )
                    .ok()
            })
            .flatten();
        let amount = asked + lease.as_ref().map_or(0, |l| l.amount());
        match self.runner.read_tcp(token, amount) {
            Ok(bytes) => {
                flow.readable_bytes = flow.readable_bytes.saturating_sub(bytes.len());
                if let Some(l) = &mut lease {
                    l.shrink_to(l.amount().min(bytes.len().saturating_sub(asked)));
                }
                if response.send(Ok((bytes, lease))).is_err() {
                    self.abort_flow(token);
                }
            }
            // Reading reserves a control packet first (its window update),
            // and a full TX queue or packet budget is backpressure, as for
            // a write: the read waits for room, the stream lives on.
            Err(error) if retryable(&error) => {
                flow.pending_read = Some((max_bytes, response));
                self.retry_wanted = true;
            }
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn try_write(
        &mut self,
        token: TcpFlowToken,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<usize>>,
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow is closed",
            )));
            return;
        };
        if flow.pending_write.is_some() {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concurrent TCP write",
            )));
            return;
        }
        if payload.is_empty() || payload.len() > flow.reserved_write_bytes {
            flow.reserved_write_bytes = 0;
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP write exceeded its reservation",
            )));
            return;
        }
        flow.reserved_write_bytes = 0;
        self.submit_write(token, payload, response);
    }

    fn submit_write(
        &mut self,
        token: TcpFlowToken,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<usize>>,
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow is closed",
            )));
            return;
        };
        if flow.pending_write.is_some() {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concurrent TCP write",
            )));
            return;
        }
        match self.runner.write_tcp_segments(token, &payload) {
            Ok((written, _)) if written == payload.len() => {
                if response.send(Ok(payload.len())).is_err() {
                    self.abort_flow(token);
                }
            }
            // Memory ran out partway: the rest goes once the flow is
            // writable again, and the writer hears when all of it went.
            Ok((written, _)) => {
                flow.pending_write = Some((payload[written..].to_vec(), response));
                self.retry_wanted = true;
            }
            Err(error) if retryable(&error) => {
                flow.pending_write = Some((payload, response));
                self.retry_wanted = true;
            }
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn try_reserve_write(
        &mut self,
        token: TcpFlowToken,
        max_bytes: usize,
        response: oneshot::Sender<io::Result<usize>>,
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow is closed",
            )));
            return;
        };
        if max_bytes == 0
            || flow.pending_write_reservation.is_some()
            || flow.reserved_write_bytes != 0
        {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concurrent or empty TCP write reservation",
            )));
            return;
        }
        // A reservation made while the last commit still waits comes after
        // it: the stream sends the next reservation without waiting.
        let limit = if flow.pending_write.is_some() {
            0
        } else {
            match self.runner.tcp_write_capacity(token) {
                Ok(limit) => limit,
                Err(error) => {
                    let _ = response.send(Err(runner_io_error(error)));
                    return;
                }
            }
        };
        // No room is the flow's own (its window, its flight, its send
        // buffer): the ACK or window update that makes room makes it
        // writable, and that event retries the reservation. A stalled
        // reader's flow then waits without a timer.
        if limit == 0 {
            flow.pending_write_reservation = Some((max_bytes, response));
            return;
        }
        let amount = max_bytes.min(limit);
        flow.reserved_write_bytes = amount;
        if response.send(Ok(amount)).is_err() {
            flow.reserved_write_bytes = 0;
        }
    }

    fn retry_write(&mut self, token: TcpFlowToken) {
        let pending = self
            .flows
            .get_mut(&token)
            .and_then(|flow| flow.pending_write.take());
        if let Some((payload, response)) = pending {
            self.submit_write(token, payload, response);
        }
    }

    fn retry_write_reservation(&mut self, token: TcpFlowToken) {
        let pending = self
            .flows
            .get_mut(&token)
            .and_then(|flow| flow.pending_write_reservation.take());
        if let Some((max_bytes, response)) = pending {
            self.try_reserve_write(token, max_bytes, response);
        }
    }

    fn try_close(&mut self, token: TcpFlowToken, response: oneshot::Sender<io::Result<()>>) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Ok(()));
            return;
        };
        flow.pending_write_reservation = None;
        flow.reserved_write_bytes = 0;
        match self.runner.close_tcp(token) {
            Ok(_) => {
                flow.closed = true;
                let _ = response.send(Ok(()));
            }
            Err(error) if retryable(&error) => {
                flow.pending_close = Some(response);
                self.retry_wanted = true;
            }
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn retry_close(&mut self, token: TcpFlowToken) {
        let pending = self
            .flows
            .get_mut(&token)
            .and_then(|flow| flow.pending_close.take());
        if let Some(response) = pending {
            self.try_close(token, response);
        }
    }

    /// Tries again what waits for room, and returns whether anything still
    /// waits.
    fn retry_pending(&mut self) -> bool {
        for (token, release) in std::mem::take(&mut self.pending_releases) {
            self.release(token, release);
        }
        let tokens: Vec<_> = self.flows.keys().copied().collect();
        for token in tokens {
            self.retry_write(token);
            self.retry_write_reservation(token);
            self.retry_close(token);
            self.service_read(token);
        }
        // A connect whose caller is gone stops, rather than retrying its SYN
        // until the handshake times out.
        let abandoned: Vec<_> = self
            .connecting
            .iter()
            .filter_map(|(token, response)| response.is_canceled().then_some(*token))
            .collect();
        for token in abandoned {
            self.connecting.remove(&token);
            self.abort_flow(token);
        }
        for pending in std::mem::take(&mut self.pending_connects) {
            if !pending.response.is_canceled() {
                self.connect(pending.local, pending.remote, pending.response);
            }
        }
        !self.pending_releases.is_empty()
            || !self.pending_connects.is_empty()
            || !self.connecting.is_empty()
            || self.flows.values().any(FlowBridge::waits)
    }

    fn cleanup_dropped_streams(&mut self) {
        let dropped = self
            .flows
            .iter()
            .filter_map(|(token, flow)| {
                (!flow.cleanup_active.load(AtomicOrdering::Acquire)).then_some(*token)
            })
            .collect::<Vec<_>>();
        for token in dropped {
            self.drop_flow(token);
        }
    }

    /// The application dropped its stream: a flow it closed finishes its
    /// close alone, bounded by the stack's timers; any other is aborted.
    fn drop_flow(&mut self, token: TcpFlowToken) {
        match self.flows.get(&token) {
            Some(flow) if flow.closed => {
                if let Some(flow) = self.flows.remove(&token) {
                    flow.fail("TCP stream released");
                }
                self.release(token, Release::Closed);
            }
            _ => self.abort_flow(token),
        }
    }

    fn abort_flow(&mut self, token: TcpFlowToken) {
        if let Some(flow) = self.flows.remove(&token) {
            flow.fail("TCP stream aborted");
        }
        self.release(token, Release::Abort);
    }

    /// Hands a flow back to the stack, and again on each tick while the
    /// stack has no room for its packet.
    fn release(&mut self, token: TcpFlowToken, release: Release) {
        let result = match release {
            Release::Closed => self.runner.release_tcp(token),
            Release::Abort => self.runner.abort_tcp(token),
        };
        if let Err(error) = result {
            if retryable(&error) {
                self.pending_releases.push((token, release));
                self.retry_wanted = true;
            }
        }
    }

    fn finish_flow(&mut self, token: TcpFlowToken) {
        if let Some(mut flow) = self.flows.remove(&token) {
            if let Some((_, response)) = flow.pending_read.take() {
                let _ = response.send(Ok((Vec::new(), None)));
            }
            flow.fail("TCP flow closed");
        }
    }

    fn fail_all(&mut self, message: &'static str) {
        for (_, flow) in self.flows.drain() {
            flow.fail(message);
        }
        let waiting = self.connecting.drain().map(|(_, response)| response).chain(
            self.pending_connects
                .drain(..)
                .map(|pending| pending.response),
        );
        for response in waiting {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
    }
}

pub(crate) struct NativeRuntimeGroup<I: PacketIo> {
    runtimes: Vec<NativeRuntime<ShardedPacketIo<I>>>,
    completion: watch::Sender<bool>,
}

type NativeRuntimeGroupParts<I> = (
    NativeRuntimeGroup<I>,
    tokio_mpsc::Receiver<NativeConnection>,
    tokio_mpsc::Receiver<NativeUdpDatagram>,
    NativeUdpReplyHandle,
    NativeRuntimeControl,
);

impl<I: PacketIo> NativeRuntimeGroup<I> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        queues: Vec<I>,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
        command_capacity: usize,
        accept_capacity: usize,
        udp_capacity: usize,
    ) -> Result<NativeRuntimeGroupParts<I>, RunnerError> {
        assert!(
            accept_capacity > 0,
            "native accept capacity must be non-zero"
        );
        assert!(udp_capacity > 0, "native UDP capacity must be non-zero");
        let (adapters, router) = ShardedPacketIo::group(
            queues,
            Arc::clone(&ledger),
            config.generation,
            config.scheduler,
        )
        .map_err(|error| RunnerError::Io(io::Error::other(error)))?;
        let (accepted_tx, accepted_rx) = tokio_mpsc::channel(accept_capacity);
        let (udp_tx, udp_rx) = tokio_mpsc::channel(udp_capacity);
        let (completion_tx, completion_rx) = watch::channel(false);
        let mut runtimes = Vec::with_capacity(adapters.len());
        let mut commands = Vec::with_capacity(adapters.len());
        for adapter in adapters {
            let mut shard_config = config;
            shard_config.shard = adapter.shard();
            let (runtime, command) = NativeRuntime::new_with_sinks(
                adapter,
                Arc::clone(&ledger),
                shard_config,
                command_capacity,
                accepted_tx.clone(),
                udp_tx.clone(),
            )?;
            runtimes.push(runtime);
            commands.push(command);
        }
        drop(accepted_tx);
        drop(udp_tx);
        Ok((
            Self {
                runtimes,
                completion: completion_tx,
            },
            accepted_rx,
            udp_rx,
            NativeUdpReplyHandle {
                commands: commands.clone(),
            },
            NativeRuntimeControl {
                commands,
                router,
                ledger,
                completion: completion_rx,
                next_shard: Arc::new(AtomicUsize::new(0)),
            },
        ))
    }

    /// What a read of its connections takes beyond what was asked, in
    /// bytes.
    pub(crate) fn set_read_ahead(&mut self, bytes: usize) {
        for runtime in &mut self.runtimes {
            runtime.read_ahead = bytes;
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn shard_count(&self) -> usize {
        self.runtimes.len()
    }

    pub(crate) async fn run(self) -> Result<(), RunnerError> {
        let Self {
            runtimes,
            completion,
        } = self;
        let futures = runtimes
            .into_iter()
            .map(|runtime| Box::pin(runtime.run()))
            .collect::<Vec<_>>();
        let result = futures::future::try_join_all(futures).await.map(|_| ());
        let _ = completion.send(true);
        result
    }
}

/// Milliseconds since `started`, the stack's clock.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn retryable(error: &RunnerError) -> bool {
    matches!(
        error,
        RunnerError::TxQueueFull
            | RunnerError::Budget(_)
            | RunnerError::Tcp(TcpTableError::Budget(_))
            | RunnerError::Tcp(TcpTableError::State(
                TcpError::SendOutstanding | TcpError::SendWindowExceeded
            ))
    )
}

fn runner_io_error(error: RunnerError) -> io::Error {
    let kind = match error {
        RunnerError::Tcp(TcpTableError::AddressInUse)
        | RunnerError::Udp(UdpError::AddressInUse) => io::ErrorKind::AddrInUse,
        RunnerError::Tcp(TcpTableError::InvalidAddress)
        | RunnerError::Udp(UdpError::InvalidAddress) => io::ErrorKind::InvalidInput,
        RunnerError::Closed | RunnerError::Tcp(TcpTableError::StaleToken) => {
            io::ErrorKind::BrokenPipe
        }
        RunnerError::TxQueueFull
        | RunnerError::Budget(_)
        | RunnerError::Tcp(TcpTableError::Budget(_)) => io::ErrorKind::WouldBlock,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::super::channel::ChannelPacketIo;
    use super::super::testing::{tcp_packet, tcp_packet_with_window};
    use super::*;
    use sail_netstack::{
        emit_udp_packet, parse_ip_packet, parse_tcp_segment, parse_udp_datagram, BudgetProfile,
        ResourceKind, SeqNumber, TcpFlags,
    };
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    #[tokio::test]
    async fn runtime_reports_a_partial_write_for_a_small_peer_window() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, RunnerConfig::default(), 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 0, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 0, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet_with_window(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                3,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(accepted.stream.write(b"abcdef").await.unwrap(), 3);
        let outgoing = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"abc");

        runtime_task.abort();
    }

    #[tokio::test]
    async fn runtime_retries_a_committed_write_after_transient_packet_budget_pressure() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), RunnerConfig::default(), 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();

        let snapshot = ledger.snapshot();
        let packet_credit = ledger
            .try_acquire(
                ResourceKind::PacketBytes,
                ledger
                    .budget()
                    .packet_bytes
                    .saturating_sub(snapshot.used(ResourceKind::PacketBytes)),
            )
            .unwrap();
        let denied_before = ledger.snapshot().denied;

        assert_eq!(accepted.stream.write(b"retry").await.unwrap(), 5);
        timeout(Duration::from_secs(1), async {
            while ledger.snapshot().denied == denied_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("committed write never reached transient packet-budget pressure");

        drop(packet_credit);
        timeout(Duration::from_secs(1), accepted.stream.flush())
            .await
            .expect("write was not retried after packet credit returned")
            .unwrap();
        let outgoing = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"retry");

        runtime_task.abort();
    }

    /// A read while the TX queue is full waits for room rather than failing
    /// the stream (64 parallel WireGuard transfers over a slow device reset).
    #[tokio::test]
    async fn a_read_waits_out_a_full_tx_queue() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        // The device takes one packet; one more fills the TX queue.
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(1);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut config = RunnerConfig::default();
        config.scheduler.max_queued_packets = 1;
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, config, 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 5, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 5, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                b"hello",
            ))
            .await
            .unwrap();
        // Its ACK, if any, goes out; the device is empty again.
        while timeout(Duration::from_millis(300), outbound_rx.recv())
            .await
            .is_ok()
        {}

        // Two more handshakes' SYN-ACKs: one fills the device, the other
        // the TX queue.
        for port in [40_001, 40_002] {
            let other = SocketAddr::from((Ipv4Addr::new(10, 8, 5, 2), port));
            inbound_tx
                .send(tcp_packet(other, destination, 100, 0, TcpFlags::SYN, &[]))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let mut buf = [0u8; 16];
        let n = {
            let read = accepted.stream.read(&mut buf);
            tokio::pin!(read);
            assert!(
                timeout(Duration::from_millis(200), &mut read)
                    .await
                    .is_err(),
                "the read waits while the TX queue is full"
            );
            // Room again.
            while timeout(Duration::from_millis(100), outbound_rx.recv())
                .await
                .is_ok()
            {}
            timeout(Duration::from_secs(1), read)
                .await
                .expect("the read was not retried once the TX queue had room")
                .unwrap()
        };
        assert_eq!(&buf[..n], b"hello");

        runtime_task.abort();
    }

    /// Reads four of ten bytes a client sent, with a read-ahead of 64,
    /// then stops the runtime and reads again: what the stream read ahead
    /// it still has, and nothing else. With `exhausted`, the budget's TCP
    /// bytes have no room for a read-ahead.
    async fn read_then_stop_the_runtime(exhausted: bool) -> (Vec<u8>, io::Result<Vec<u8>>) {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(16);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (mut runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), RunnerConfig::default(), 4, 4, 4).unwrap();
        runtime.set_read_ahead(64);
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 6, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 6, 1), 443));
        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                b"0123456789",
            ))
            .await
            .unwrap();
        // The stack has the bytes once it acknowledges them.
        let _ = timeout(Duration::from_millis(500), outbound_rx.recv()).await;
        let mut held = Vec::new();
        if exhausted {
            let mut chunk = 1 << 24;
            while chunk > 0 {
                match ledger.try_acquire(ResourceKind::TcpPayloadBytes, chunk) {
                    Ok(lease) => held.push(lease),
                    Err(_) => chunk /= 2,
                }
            }
        }
        let mut first = [0_u8; 4];
        let n = timeout(Duration::from_secs(1), accepted.stream.read(&mut first))
            .await
            .unwrap()
            .unwrap();
        runtime_task.abort();
        let _ = runtime_task.await;
        let mut rest = [0_u8; 16];
        let second = timeout(Duration::from_secs(1), accepted.stream.read(&mut rest))
            .await
            .unwrap()
            .map(|m| rest[..m].to_vec());
        (first[..n].to_vec(), second)
    }

    #[tokio::test]
    async fn a_read_takes_what_follows_ahead_when_the_budget_has_room() {
        let (first, second) = read_then_stop_the_runtime(false).await;
        assert_eq!(first, b"0123");
        assert_eq!(second.unwrap(), b"456789");
    }

    #[tokio::test]
    async fn a_read_the_budget_has_no_room_ahead_for_takes_only_what_was_asked() {
        let (first, second) = read_then_stop_the_runtime(true).await;
        assert_eq!(first, b"0123");
        assert!(second.is_err(), "nothing was read ahead: {second:?}");
    }

    /// peakpassvpn/sail#6: on the mobile budget, connections opened until
    /// the stack refuses more, each holding bytes read ahead of its reader,
    /// put the TCP bytes past the pressure that refused every new flow: no
    /// DNS query went through while they lived. A new UDP flow still opens,
    /// those connections still send, and once they close a new one opens.
    #[tokio::test]
    async fn a_stack_full_of_connections_still_sends_and_opens_again_once_they_close() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(16);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (mut runtime, mut accepted, mut datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), RunnerConfig::default(), 4, 4, 4).unwrap();
        runtime.set_read_ahead(64 << 10);
        let runtime_task = tokio::spawn(runtime.run());
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 7, 1), 443));
        let client = |port: u16| SocketAddr::from((Ipv4Addr::new(10, 8, 7, 2), port));

        // Opens the connection from `source`, its client sending a
        // segment that the stream reads a byte of: what follows is read
        // ahead and held, as by a relay whose other side has stalled.
        async fn open(
            source: SocketAddr,
            destination: SocketAddr,
            inbound_tx: &tokio_mpsc::Sender<Vec<u8>>,
            outbound_rx: &mut tokio_mpsc::Receiver<Vec<u8>>,
            accepted: &mut tokio_mpsc::Receiver<NativeConnection>,
        ) -> Option<NativeConnection> {
            inbound_tx
                .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
                .await
                .unwrap();
            // The answer to this SYN, past what the stack sent the others.
            let answer = timeout(Duration::from_secs(1), async {
                loop {
                    let packet = outbound_rx.recv().await?;
                    let segment =
                        parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
                    if segment.destination == source {
                        return Some((segment.meta.flags, segment.meta.sequence));
                    }
                }
            })
            .await
            .ok()??;
            let (flags, sequence) = answer;
            if !flags.contains(TcpFlags::SYN) {
                return None;
            }
            let server_next = sequence.wrapping_add(1).get();
            inbound_tx
                .send(tcp_packet(
                    source,
                    destination,
                    101,
                    server_next,
                    TcpFlags::ACK,
                    &[],
                ))
                .await
                .unwrap();
            let mut connection = timeout(Duration::from_secs(1), accepted.recv())
                .await
                .unwrap()
                .unwrap();
            inbound_tx
                .send(tcp_packet(
                    source,
                    destination,
                    101,
                    server_next,
                    TcpFlags::ACK,
                    &[7; 1_200],
                ))
                .await
                .unwrap();
            // Its client reads what the stack sends meanwhile: one that
            // stopped would hold the stack's next send, and with it what
            // the stack receives after.
            let mut first = [0_u8; 1];
            let mut read = std::pin::pin!(connection.stream.read_exact(&mut first));
            timeout(Duration::from_secs(1), async {
                loop {
                    tokio::select! {
                        result = &mut read => break result,
                        Some(_) = outbound_rx.recv() => {}
                    }
                }
            })
            .await
            .unwrap()
            .unwrap();
            Some(connection)
        }
        let mut connections = Vec::new();
        for port in 10_000..12_000 {
            match open(
                client(port),
                destination,
                &inbound_tx,
                &mut outbound_rx,
                &mut accepted,
            )
            .await
            {
                Some(connection) => connections.push(connection),
                None => break,
            }
        }
        assert!(
            connections.len() < 2_000,
            "the budget refused no connection"
        );
        // The window updates of the reads are not waited on.
        while timeout(Duration::from_millis(50), outbound_rx.recv())
            .await
            .is_ok()
        {}

        let dns_client = SocketAddr::from((Ipv4Addr::new(10, 8, 7, 2), 53_000));
        let dns_server = SocketAddr::from((Ipv4Addr::new(10, 8, 7, 1), 53));
        inbound_tx
            .send(emit_udp_packet(dns_client, dns_server, b"query", 64, 1).unwrap())
            .await
            .unwrap();
        let query = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .expect("a DNS query of a full stack did not get through")
            .unwrap();
        assert_eq!(query.payload.to_vec(), b"query");

        // More than a starting window: what the stack had left when it
        // refused the next connection, it could send before.
        let mut connection = connections.swap_remove(0);
        let writer = tokio::spawn(async move {
            connection.stream.write_all(&[9; 64 << 10]).await.unwrap();
            connection
        });
        let sent = timeout(Duration::from_secs(5), async {
            let mut received = 0;
            while received < 64 << 10 {
                let packet = outbound_rx.recv().await.unwrap();
                let segment =
                    parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
                if segment.destination != client(10_000) || segment.payload.is_empty() {
                    continue;
                }
                received += segment.payload.len();
                let acknowledged = segment.meta.sequence.wrapping_add(segment.payload.len());
                inbound_tx
                    .send(tcp_packet(
                        client(10_000),
                        destination,
                        1_301,
                        acknowledged.get(),
                        TcpFlags::ACK,
                        &[],
                    ))
                    .await
                    .unwrap();
            }
        })
        .await;
        assert!(
            sent.is_ok(),
            "a connection of a full stack did not send 64 KiB"
        );
        connections.push(writer.await.unwrap());

        // Each goes with a reset, all of them taken before the next SYN. A
        // flow whose SYN-ACK came too late for `open` may stay a while.
        let held = connections.len();
        let flows = ledger.snapshot().used(ResourceKind::TcpFlows);
        drop(connections);
        timeout(Duration::from_secs(10), async {
            while ledger.snapshot().used(ResourceKind::TcpFlows) > flows - held {
                while outbound_rx.try_recv().is_ok() {}
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the closed connections kept {} of their {held} flows",
                (ledger.snapshot().used(ResourceKind::TcpFlows) + held).saturating_sub(flows)
            )
        });
        while timeout(Duration::from_millis(100), outbound_rx.recv())
            .await
            .is_ok()
        {}
        assert!(
            open(
                client(20_000),
                destination,
                &inbound_tx,
                &mut outbound_rx,
                &mut accepted,
            )
            .await
            .is_some(),
            "no connection opened once the others closed"
        );

        runtime_task.abort();
    }

    #[tokio::test]
    async fn dropped_stream_reclaims_its_flow_when_the_command_channel_is_full() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), RunnerConfig::default(), 1, 1, 1).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 3, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 3, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ledger.snapshot().used(ResourceKind::TcpFlows), 1);

        // Fill the ordinary command queue and drop without yielding. Cleanup
        // must use its dedicated path rather than disappearing behind
        // backpressure.
        accepted.stream.saturate_command_channel_for_test();
        drop(accepted);

        timeout(Duration::from_secs(1), async {
            while ledger.snapshot().used(ResourceKind::TcpFlows) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped stream did not release its TCP flow");

        runtime_task.abort();
    }

    /// A stream shut down and then dropped is let go of, not reset: its
    /// flow finishes the close alone, and leaves FIN-WAIT-2 after the
    /// timeout when the peer never sends its FIN.
    #[tokio::test]
    async fn a_closed_stream_dropped_leaves_fin_wait2_after_the_timeout() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut config = RunnerConfig::default();
        config.tcp.fin_wait2_timeout_ms = 200;
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), config, 4, 4, 1).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 1), 443));
        let next = |outbound_rx: &mut tokio_mpsc::Receiver<Vec<u8>>| {
            let packet = outbound_rx.try_recv().ok()?;
            Some(
                parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true)
                    .unwrap()
                    .meta,
            )
        };

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        accepted.stream.shutdown().await.unwrap();
        let fin = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let fin = parse_tcp_segment(parse_ip_packet(&fin, true).unwrap(), true).unwrap();
        assert!(fin.meta.flags.contains(TcpFlags::FIN));
        // The peer ACKs the FIN and never sends its own.
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next.wrapping_add(1),
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(accepted);

        timeout(Duration::from_secs(3), async {
            while ledger.snapshot().used(ResourceKind::TcpFlows) != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the released flow stayed in FIN-WAIT-2");
        while let Some(meta) = next(&mut outbound_rx) {
            assert!(!meta.flags.contains(TcpFlags::RST), "reset: {:?}", meta);
        }

        runtime_task.abort();
    }

    #[tokio::test]
    async fn runtime_retransmits_an_application_write_after_wire_loss() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, RunnerConfig::default(), 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 1, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 1, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();

        accepted.stream.write_all(b"lost").await.unwrap();
        let first = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let first = parse_tcp_segment(parse_ip_packet(&first, true).unwrap(), true).unwrap();
        assert_eq!(first.payload, b"lost");

        let retransmit = timeout(Duration::from_secs(3), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let retransmit =
            parse_tcp_segment(parse_ip_packet(&retransmit, true).unwrap(), true).unwrap();
        assert_eq!(retransmit.meta.sequence, first.meta.sequence);
        assert_eq!(retransmit.payload, first.payload);

        runtime_task.abort();
    }

    /// Counts how often the runtime's task is polled: each is a wake.
    struct CountPolls<F> {
        inner: std::pin::Pin<Box<F>>,
        polls: Arc<AtomicUsize>,
    }

    impl<F: std::future::Future> std::future::Future for CountPolls<F> {
        type Output = F::Output;

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<F::Output> {
            self.polls.fetch_add(1, AtomicOrdering::Relaxed);
            std::future::Future::poll(self.inner.as_mut(), context)
        }
    }

    #[tokio::test]
    async fn an_idle_runtime_with_an_open_connection_does_not_wake() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, RunnerConfig::default(), 4, 4, 4).unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let runtime_task = tokio::spawn(CountPolls {
            inner: Box::pin(runtime.run()),
            polls: Arc::clone(&polls),
        });
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 3, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 3, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        // The application waits to read, as an idle connection's does.
        let reader = tokio::spawn(async move {
            let mut buffer = [0_u8; 16];
            let _ = accepted.stream.read(&mut buffer).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = polls.load(AtomicOrdering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let woken = polls.load(AtomicOrdering::Relaxed) - before;
        // A 10 ms tick woke it 50 times here.
        assert!(woken <= 2, "woken {woken} times in 500 ms");

        reader.abort();
        runtime_task.abort();
    }

    #[tokio::test]
    async fn a_write_a_full_window_holds_waits_without_waking_until_it_opens() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, RunnerConfig::default(), 4, 4, 4).unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let runtime_task = tokio::spawn(CountPolls {
            inner: Box::pin(runtime.run()),
            polls: Arc::clone(&polls),
        });
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        // A reader that stopped after three bytes.
        inbound_tx
            .send(tcp_packet_with_window(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                3,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.stream.write(b"abc").await.unwrap(), 3);
        let writer = tokio::spawn(async move {
            let written = accepted.stream.write(b"def").await.unwrap();
            (written, accepted)
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!writer.is_finished(), "a write went past a full window");
        let before = polls.load(AtomicOrdering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let woken = polls.load(AtomicOrdering::Relaxed) - before;
        // A 10 ms retry woke it 50 times here.
        assert!(woken <= 2, "woken {woken} times in 500 ms");

        // The three acknowledged, and room for more.
        inbound_tx
            .send(tcp_packet_with_window(
                source,
                destination,
                101,
                server_next.wrapping_add(3),
                TcpFlags::ACK,
                1_000,
                &[],
            ))
            .await
            .unwrap();
        let (written, _accepted) = timeout(Duration::from_secs(1), writer)
            .await
            .expect("the window update did not wake the write")
            .unwrap();
        assert_eq!(written, 3);

        runtime_task.abort();
    }

    #[tokio::test]
    async fn runtime_group_forwards_a_flow_and_keeps_application_commands_on_its_owner() {
        let (first_inbound_tx, first_inbound_rx) = tokio_mpsc::channel(8);
        let (first_outbound_tx, mut first_outbound_rx) = tokio_mpsc::channel(8);
        let (second_inbound_tx, second_inbound_rx) = tokio_mpsc::channel(8);
        let (second_outbound_tx, mut second_outbound_rx) = tokio_mpsc::channel(8);
        let queues = vec![
            ChannelPacketIo::new(first_inbound_rx, first_outbound_tx, 1),
            ChannelPacketIo::new(second_inbound_rx, second_outbound_tx, 1),
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, ledger, RunnerConfig::default(), 8, 8, 8).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 2, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 2, 1), 443));

        first_inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), async {
            tokio::select! {
                packet = first_outbound_rx.recv() => packet,
                packet = second_outbound_rx.recv() => packet,
            }
        })
        .await
        .unwrap()
        .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        first_inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(usize::from(accepted.connection.token.shard().get()) < 2);

        accepted.stream.write_all(b"grouped").await.unwrap();
        let outgoing = timeout(Duration::from_secs(1), async {
            tokio::select! {
                packet = first_outbound_rx.recv() => packet,
                packet = second_outbound_rx.recv() => packet,
            }
        })
        .await
        .unwrap()
        .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"grouped");

        let before_reset = control.stats_snapshot().await.unwrap();
        assert_eq!(before_reset.shard_count, 2);
        assert_eq!(before_reset.stack.tcp_active_flows, 1);
        assert_eq!(before_reset.router.directory_entries, 1);

        control.update_mtu(1_400).await.unwrap();
        control
            .reset_network(NetworkGeneration::new(7))
            .await
            .unwrap();
        let after_reset = control.stats_snapshot().await.unwrap();
        assert_eq!(after_reset.stack.generation, NetworkGeneration::new(7));
        assert_eq!(after_reset.stack.tcp_active_flows, 0);
        assert_eq!(after_reset.stack.mtu_changes, 2);
        assert_eq!(after_reset.stack.network_resets, 2);
        assert_eq!(after_reset.router.directory_entries, 0);
        assert_eq!(after_reset.router.queued_packets, 0);

        control.shutdown(u64::MAX).await.unwrap();
        let draining = control.stats_snapshot().await.unwrap();
        assert_eq!(draining.stack.shutdowns, 2);

        control.abort().await.unwrap();
        control.wait_stopped().await.unwrap();
        runtime_task.await.unwrap().unwrap();
        drop(second_inbound_tx);
    }

    #[tokio::test]
    async fn runtime_bridges_wire_tcp_and_udp_to_sail_channels() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(8);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(8);
        let io = ChannelPacketIo::new(inbound_rx, outbound_tx, 1);
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let config = RunnerConfig {
            generation: NetworkGeneration::new(7),
            ..RunnerConfig::default()
        };
        let (runtime, mut accepted, mut datagrams, mut udp_reply) =
            NativeRuntime::new(io, ledger, config, 8, 8, 8).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 9, 0, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 9, 0, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.connection.source, source);
        assert_eq!(accepted.connection.destination, destination);

        accepted.stream.write_all(b"ping").await.unwrap();
        let outgoing = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"ping");

        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next.wrapping_add(4),
                TcpFlags::ACK,
                b"pong",
            ))
            .await
            .unwrap();
        let mut read = [0_u8; 4];
        timeout(
            Duration::from_secs(1),
            accepted.stream.read_exact(&mut read),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&read, b"pong");
        let read_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            parse_tcp_segment(parse_ip_packet(&read_ack, true).unwrap(), true)
                .unwrap()
                .payload
                .is_empty()
        );

        let udp_source = SocketAddr::from((Ipv4Addr::new(10, 9, 0, 2), 50_000));
        let udp_destination = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        inbound_tx
            .send(emit_udp_packet(udp_source, udp_destination, b"query", 64, 2).unwrap())
            .await
            .unwrap();
        let datagram = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(datagram.source, udp_source);
        assert_eq!(datagram.destination, udp_destination);
        assert_eq!(datagram.payload.to_vec(), b"query");
        udp_reply
            .send(datagram.token, udp_destination, b"answer".to_vec())
            .await
            .unwrap();
        let reply = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let reply = parse_udp_datagram(parse_ip_packet(&reply, true).unwrap(), true).unwrap();
        assert_eq!(reply.source, udp_destination);
        assert_eq!(reply.destination, udp_source);
        assert_eq!(reply.payload, b"answer");

        let second_destination = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let third_destination = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
        inbound_tx
            .send(emit_udp_packet(udp_source, second_destination, b"second", 64, 3).unwrap())
            .await
            .unwrap();
        inbound_tx
            .send(emit_udp_packet(udp_source, third_destination, b"third", 64, 4).unwrap())
            .await
            .unwrap();
        let second = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        let third = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.destination, second_destination);
        assert_eq!(third.destination, third_destination);
        udp_reply
            .send(third.token, third_destination, b"third-reply".to_vec())
            .await
            .unwrap();
        udp_reply
            .send(second.token, second_destination, b"second-reply".to_vec())
            .await
            .unwrap();
        for (expected_source, expected_payload) in [
            (third_destination, b"third-reply".as_slice()),
            (second_destination, b"second-reply".as_slice()),
        ] {
            let reply = timeout(Duration::from_secs(1), outbound_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let reply = parse_udp_datagram(parse_ip_packet(&reply, true).unwrap(), true).unwrap();
            assert_eq!(reply.source, expected_source);
            assert_eq!(reply.destination, udp_source);
            assert_eq!(reply.payload, expected_payload);
        }

        runtime_task.abort();
    }

    /// A runtime group over channel queues, with the ends a test uses as
    /// the network.
    #[allow(clippy::type_complexity)]
    fn channel_group(
        queues: usize,
    ) -> (
        NativeRuntimeGroup<ChannelPacketIo>,
        tokio_mpsc::Receiver<NativeUdpDatagram>,
        NativeUdpReplyHandle,
        NativeRuntimeControl,
        Vec<tokio_mpsc::Sender<Vec<u8>>>,
        Vec<tokio_mpsc::Receiver<Vec<u8>>>,
    ) {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut io = Vec::new();
        for _ in 0..queues {
            let (inbound_tx, inbound_rx) = tokio_mpsc::channel(8);
            let (outbound_tx, outbound_rx) = tokio_mpsc::channel(8);
            io.push(ChannelPacketIo::new(inbound_rx, outbound_tx, 8));
            inputs.push(inbound_tx);
            outputs.push(outbound_rx);
        }
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (group, _accepted, datagrams, udp_reply, control) =
            NativeRuntimeGroup::new(io, ledger, RunnerConfig::default(), 8, 8, 8).unwrap();
        (group, datagrams, udp_reply, control, inputs, outputs)
    }

    /// The next packet any queue sends.
    async fn next_sent(outputs: &mut [tokio_mpsc::Receiver<Vec<u8>>]) -> Vec<u8> {
        let receiving = outputs.iter_mut().map(|output| Box::pin(output.recv()));
        let (packet, _, _) = timeout(
            Duration::from_secs(1),
            futures::future::select_all(receiving),
        )
        .await
        .expect("the stack sent nothing");
        packet.expect("packet output closed")
    }

    #[tokio::test]
    async fn connect_opens_a_stream_from_an_ephemeral_port_that_routes_back() {
        let (group, _datagrams, _udp_reply, control, inputs, mut outputs) = channel_group(2);
        let runtime_task = tokio::spawn(group.run());
        let local = SocketAddr::from((Ipv4Addr::new(10, 30, 0, 1), 0));
        let remote = SocketAddr::from((Ipv4Addr::new(10, 30, 0, 2), 443));

        let mut connecting_control = control.clone();
        let connecting =
            tokio::spawn(async move { connecting_control.connect(local, remote).await });
        let syn = next_sent(&mut outputs).await;
        let syn = parse_tcp_segment(parse_ip_packet(&syn, true).unwrap(), true).unwrap();
        assert_eq!(syn.meta.flags, TcpFlags::SYN);
        assert_eq!(syn.destination, remote);
        assert_eq!(syn.source.ip(), local.ip());
        assert!(syn.source.port() >= 49_152);
        let bound = syn.source;
        let client_next = syn.meta.sequence.wrapping_add(1).get();

        // The answer enters on a queue that may not own the flow; the router
        // must still bring it to the shard that opened it.
        inputs[0]
            .send(tcp_packet(
                remote,
                bound,
                7_000,
                client_next,
                TcpFlags::SYN.union(TcpFlags::ACK),
                &[],
            ))
            .await
            .unwrap();
        let mut opened = timeout(Duration::from_secs(1), connecting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(opened.connection.source, bound);
        assert_eq!(opened.connection.destination, remote);
        let ack = next_sent(&mut outputs).await;
        let ack = parse_tcp_segment(parse_ip_packet(&ack, true).unwrap(), true).unwrap();
        assert_eq!(ack.meta.flags, TcpFlags::ACK);
        assert_eq!(ack.meta.acknowledgment.map(SeqNumber::get), Some(7_001));

        opened.stream.write_all(b"ping").await.unwrap();
        let data = next_sent(&mut outputs).await;
        let data = parse_tcp_segment(parse_ip_packet(&data, true).unwrap(), true).unwrap();
        assert_eq!(data.payload, b"ping");
        assert_eq!(data.meta.sequence.get(), client_next);
        inputs[1]
            .send(tcp_packet(
                remote,
                bound,
                7_001,
                client_next.wrapping_add(4),
                TcpFlags::ACK,
                b"pong",
            ))
            .await
            .unwrap();
        let mut answer = [0_u8; 4];
        timeout(
            Duration::from_secs(1),
            opened.stream.read_exact(&mut answer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&answer, b"pong");

        runtime_task.abort();
    }

    #[tokio::test]
    async fn a_refused_connect_reports_it_and_releases_the_flow() {
        let (group, _datagrams, _udp_reply, mut control, inputs, mut outputs) = channel_group(1);
        let runtime_task = tokio::spawn(group.run());
        let local = SocketAddr::from((Ipv4Addr::new(10, 31, 0, 1), 0));
        let remote = SocketAddr::from((Ipv4Addr::new(10, 31, 0, 2), 443));

        let mut connecting_control = control.clone();
        let connecting =
            tokio::spawn(async move { connecting_control.connect(local, remote).await });
        let syn = next_sent(&mut outputs).await;
        let syn = parse_tcp_segment(parse_ip_packet(&syn, true).unwrap(), true).unwrap();
        inputs[0]
            .send(tcp_packet(
                remote,
                syn.source,
                0,
                syn.meta.sequence.wrapping_add(1).get(),
                TcpFlags::RST.union(TcpFlags::ACK),
                &[],
            ))
            .await
            .unwrap();
        let refused = timeout(Duration::from_secs(1), connecting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        let stats = control.stats_snapshot().await.unwrap();
        assert_eq!(stats.stack.tcp_active_flows, 0);

        runtime_task.abort();
    }

    #[tokio::test]
    async fn an_abandoned_connect_releases_its_flow() {
        let (group, _datagrams, _udp_reply, mut control, _inputs, mut outputs) = channel_group(1);
        let runtime_task = tokio::spawn(group.run());
        let local = SocketAddr::from((Ipv4Addr::new(10, 32, 0, 1), 0));
        let remote = SocketAddr::from((Ipv4Addr::new(10, 32, 0, 2), 443));

        let mut connecting_control = control.clone();
        let connecting =
            tokio::spawn(async move { connecting_control.connect(local, remote).await });
        next_sent(&mut outputs).await;
        assert_eq!(
            control
                .stats_snapshot()
                .await
                .unwrap()
                .stack
                .tcp_active_flows,
            1
        );
        connecting.abort();
        let _ = connecting.await;

        timeout(Duration::from_secs(1), async {
            while control
                .stats_snapshot()
                .await
                .unwrap()
                .stack
                .tcp_active_flows
                != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the abandoned connection kept its flow");
        // SYN-SENT has nothing to reset: the abort sends no segment.
        assert!(outputs[0].try_recv().is_err());

        runtime_task.abort();
    }

    #[tokio::test]
    async fn send_udp_opens_a_flow_that_replies_arrive_on() {
        let (group, mut datagrams, mut udp_reply, mut control, inputs, mut outputs) =
            channel_group(2);
        let runtime_task = tokio::spawn(group.run());
        let local = SocketAddr::from((Ipv4Addr::new(10, 33, 0, 1), 0));
        let remote = SocketAddr::from((Ipv4Addr::new(10, 33, 0, 2), 53));

        let (token, bound) = control
            .send_udp(local, remote, b"query".to_vec())
            .await
            .unwrap();
        assert_eq!(bound.ip(), local.ip());
        let sent = next_sent(&mut outputs).await;
        let sent = parse_udp_datagram(parse_ip_packet(&sent, true).unwrap(), true).unwrap();
        assert_eq!(sent.source, bound);
        assert_eq!(sent.destination, remote);
        assert_eq!(sent.payload, b"query");

        for input in &inputs {
            input
                .send(emit_udp_packet(remote, bound, b"answer", 64, 1).unwrap())
                .await
                .unwrap();
            let answer = timeout(Duration::from_secs(1), datagrams.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(answer.token, token);
            assert_eq!(answer.source, remote);
            assert_eq!(answer.destination, bound);
            assert_eq!(answer.payload.to_vec(), b"answer");
        }

        // Further datagrams of the flow go out through its token.
        udp_reply
            .send(token, bound, b"more".to_vec())
            .await
            .unwrap();
        let more = next_sent(&mut outputs).await;
        let more = parse_udp_datagram(parse_ip_packet(&more, true).unwrap(), true).unwrap();
        assert_eq!(more.source, bound);
        assert_eq!(more.destination, remote);
        assert_eq!(more.payload, b"more");

        runtime_task.abort();
    }
}
