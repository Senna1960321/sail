use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use cidr::{Inet, IpInet, Ipv4Inet, Ipv6Inet};
use lru::LruCache;
use sail_netstack::{BudgetProfile, ResourceLedger, RunnerConfig, UdpFlowToken};
use serde_derive::Deserialize;
use tokio::sync::mpsc::{
    channel as tokio_channel, Receiver as TokioReceiver, Sender as TokioSender,
};
use tracing::{debug, error, info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    app::nat_manager::{NatManager, UdpPacket},
    config::model::{parse_options, Inbound},
    runtime::options::{Netstack, NetstackBudget},
    runtime::TunRequest,
    session::{DatagramSource, Network, Session, SocksAddr},
    Runner,
};

#[cfg(not(target_os = "windows"))]
use super::packet_io::TunPacketIo;
#[cfg(target_os = "linux")]
use super::packet_io::TunRsPacketIo;
use crate::net::netstack::{
    NativeRuntimeControl, NativeRuntimeGroup, NativeTcpStream, NativeUdpDatagram,
    NativeUdpReplyHandle,
};

/// What runs a TUN inbound, and how the instance controls it.
/// Fails the instance: its TUN no longer carries anything, which a host
/// must see rather than an instance that looks up.
fn fail(why: String) {
    error!("{}", why);
    if let Some(scope) = crate::runtime::scope::here() {
        scope.fail(why);
    }
}

/// The netstack failing, when a test arms `fault::Point::NetstackFails`;
/// never otherwise.
async fn netstack_fault() -> String {
    #[cfg(feature = "fault-injection")]
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if crate::fault::take(|point| matches!(point, crate::fault::Point::NetstackFails)) {
            return "fault injected: the TUN's netstack fails".to_string();
        }
    }
    #[cfg(not(feature = "fault-injection"))]
    std::future::pending().await
}

/// `runner`, which panics when a test arms `fault::Point::TunRunner`,
/// beside an essential task that panics on `fault::Point::EssentialTask`.
#[cfg(feature = "fault-injection")]
async fn with_faults(runner: impl std::future::Future<Output = ()>) {
    // A judgment value: a test waits for the panic, 100 ms is quick enough.
    const POLL: std::time::Duration = std::time::Duration::from_millis(100);
    let essential = crate::runtime::scope::spawn_essential("fault: an essential task", async {
        loop {
            tokio::time::sleep(POLL).await;
            fault_point!(crate::fault::Point::EssentialTask, "an essential task");
        }
    });
    let faults = async {
        loop {
            tokio::time::sleep(POLL).await;
            fault_point!(crate::fault::Point::TunRunner, "the TUN runner");
        }
    };
    tokio::select! {
        () = runner => {}
        _ = faults => {}
    }
    essential.abort();
}

pub(crate) struct TunRunner {
    pub runner: Runner,
    pub control: NativeRuntimeControl,
}

const fn budget_profile(budget: NetstackBudget) -> BudgetProfile {
    match budget {
        NetstackBudget::Mobile => BudgetProfile::Mobile,
        NetstackBudget::Router => BudgetProfile::Router,
        NetstackBudget::Desktop => BudgetProfile::Desktop,
        NetstackBudget::Server => BudgetProfile::Server,
    }
}

async fn handle_stream(
    stream: NativeTcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
) {
    // A fake IP destination becomes its domain in the dispatcher.
    let sess = Session {
        network: Network::Tcp,
        source: local_addr,
        local_addr: remote_addr,
        destination: SocksAddr::Ip(remote_addr),
        inbound_tag,
        ..Default::default()
    };
    // The task itself belongs to the attachment. Outbound code may lazily
    // create a pooled carrier on any read/write; those shared tasks belong
    // to the instance, including when the TUN is their first caller.
    let context = dispatcher.env().scope.clone();
    context
        .enter(dispatcher.dispatch_stream(sess, stream))
        .await;
}

/// The stack's UDP flows a reply goes back on. A reply names the client
/// and where it comes from; the stack wants a flow's token, and gives the
/// datagram whatever source it is told (`UdpTable::emit_reply`).
struct ReplyFlows {
    /// By client and the remote address the client sent to.
    by_remote: LruCache<(SocketAddr, SocketAddr), UdpFlowToken>,
    /// With `endpoint_independent_nat`: by client alone, the flow it sent
    /// on last, for a datagram from an address it never sent to. As many
    /// at most as there are flows.
    by_client: Option<LruCache<SocketAddr, UdpFlowToken>>,
}

impl ReplyFlows {
    fn new(capacity: usize, endpoint_independent: bool) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            by_remote: LruCache::new(capacity),
            by_client: endpoint_independent.then(|| LruCache::new(capacity)),
        }
    }

    /// The client sent a datagram to `remote` on the flow `token`.
    fn sent(&mut self, client: SocketAddr, remote: SocketAddr, token: UdpFlowToken) {
        self.by_remote.put((client, remote), token);
        if let Some(by_client) = &mut self.by_client {
            by_client.put(client, token);
        }
    }

    /// The flow a datagram from `source` reaches `client` on: the one the
    /// client sent to `source` on, or, endpoint-independent, the one it
    /// sent on last; none if the client is not to hear from `source`.
    fn for_reply(&mut self, client: SocketAddr, source: SocketAddr) -> Option<UdpFlowToken> {
        if let Some(token) = self.by_remote.get(&(client, source)) {
            return Some(*token);
        }
        self.by_client.as_mut()?.get(&client).copied()
    }
}

async fn handle_datagrams(
    mut uplink: TokioReceiver<NativeUdpDatagram>,
    mut reply: NativeUdpReplyHandle,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    dispatcher: Arc<Dispatcher>,
    flow_capacity: usize,
    endpoint_independent_nat: bool,
) {
    let (downlink_tx, mut downlink_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(nat_manager.env().options.udp.downlink_channel_size);
    let mut flows = ReplyFlows::new(flow_capacity, endpoint_independent_nat);

    loop {
        tokio::select! {
            datagram = uplink.recv() => {
                let Some(datagram) = datagram else {
                    return;
                };
                flows.sent(datagram.source, datagram.destination, datagram.token);
                let payload = datagram.payload.to_vec();

                // A fake IP destination becomes its domain in the NAT, on
                // each datagram; DNS is hijacked by the routing rules.
                let destination = SocksAddr::Ip(datagram.destination);
                let source = DatagramSource::new(datagram.source, None);
                let packet = UdpPacket::new(payload, SocksAddr::Ip(datagram.source), destination);
                nat_manager
                    .send(None, &source, &inbound_tag, &downlink_tx, packet)
                    .await;
            }
            packet = downlink_rx.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                let client = match packet.dst_addr {
                    SocksAddr::Ip(address) => address,
                    SocksAddr::Domain(domain, port) => {
                        warn!("Received a datagram for client {}:{}, which is not an address.", domain, port);
                        continue;
                    }
                };
                let source = match packet.src_addr {
                    SocksAddr::Ip(address) => address,
                    // A reply from a domain comes from the fake IP the
                    // client sent to.
                    SocksAddr::Domain(domain, port) => {
                        let Some(ip) = dispatcher.fake_ip_of(&domain, client.is_ipv6()) else {
                            debug!(
                                "A datagram from {}:{}, which has no fake IP, is dropped.",
                                domain, port
                            );
                            continue;
                        };
                        SocketAddr::new(ip, port)
                    }
                };
                let Some(token) = flows.for_reply(client, source) else {
                    debug!("No netstack UDP flow for client {} and source {}.", client, source);
                    continue;
                };
                if let Err(e) = reply.send(token, source, packet.data).await {
                    warn!("A packet failed to send to the netstack: {}", e);
                }
            }
        }
    }
}

/// Packets a step of the stack sends, and receives, while the TUN takes or
/// has them at once; see `RunnerConfig::packets_per_step`. Measured on a
/// Linux TUN at MTU 9000 with the mobile profile's one-packet batches: one
/// took 24.9 s of CPU a GiB downloaded (median of 5), 8 to 64 took 9.7 to
/// 11.0 s and could not be told apart; 64 and 256 held uploads lower in a
/// first run. Sixteen sits within that range.
const PACKETS_PER_STEP: usize = 16;

/// A connection's receive window: where it starts, reserved when it opens,
/// and how far it may grow.
fn set_receive_window(tcp: &mut sail_netstack::TcpTableConfig, netstack: &Netstack) {
    tcp.receive_credit_bytes = netstack.receive_window.max(1) << 10;
    tcp.max_receive_credit_bytes = (netstack.receive_window_max > netstack.receive_window)
        .then_some(netstack.receive_window_max << 10);
}

pub(crate) fn run<I: sail_netstack::PacketIo + 'static>(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    queues: Vec<I>,
    mtu: usize,
    netstack: &Netstack,
    endpoint_independent_nat: bool,
) -> Result<TunRunner> {
    let profile = budget_profile(netstack.budget);
    let ledger = ResourceLedger::new(profile.budget())?;
    let udp_flow_capacity = profile.budget().max_udp_flows;
    let mut config = RunnerConfig::default();
    config.mtu = mtu;
    config.max_packet_size = config.max_packet_size.max(mtu);
    // No ceiling of its own: each flow sizes its segments from the MTU for
    // its address family and options.
    config.tcp.max_segment_payload_bytes = mtu;
    // A UDP flow of the stack outlives the NAT session it carries, which
    // ends within one check after `udp_timeout` of silence: a reply until
    // then still needs the flow to reach the client.
    let udp_idle = inbound.udp_timeout() + dispatcher.env().options.udp.session_check_interval;
    config.udp_idle_timeout_ms = u64::try_from(udp_idle.as_millis()).unwrap_or(u64::MAX);
    config.tcp.keepalive_idle_ms = Some(2 * 60 * 60 * 1_000);
    config.packets_per_step = PACKETS_PER_STEP;
    set_receive_window(&mut config.tcp, netstack);
    config.tcp.max_send_buffer_bytes =
        (netstack.send_buffer > 0).then_some(netstack.send_buffer << 10);
    let (mut runtime, mut accepted, datagrams, udp_reply, mut control) = NativeRuntimeGroup::new(
        queues,
        ledger,
        config,
        netstack.command_channel_size,
        netstack.command_channel_size,
        netstack.udp_uplink_channel_size,
    )?;
    runtime.set_read_ahead(netstack.read_ahead << 10);

    let runtime_control = control.clone();
    let runner = Box::pin(async move {
        let inbound_tag = inbound.tag;
        let datagram_tag = inbound_tag.clone();
        let datagram_dispatcher = dispatcher.clone();
        let accept_loop = async move {
            while let Some(accepted) = accepted.recv().await {
                crate::runtime::scope::spawn(
                    "tun stream",
                    handle_stream(
                        accepted.stream,
                        accepted.connection.source,
                        accepted.connection.destination,
                        inbound_tag.clone(),
                        dispatcher.clone(),
                    ),
                );
            }
        };
        let datagram_loop = handle_datagrams(
            datagrams,
            udp_reply,
            datagram_tag,
            nat_manager,
            datagram_dispatcher,
            udp_flow_capacity,
            endpoint_independent_nat,
        );
        let mut runtime = Box::pin(runtime.run());
        info!("start tun inbound");
        let runtime_finished = tokio::select! {
            result = &mut runtime => {
                if let Err(e) = result {
                    fail(format!("the TUN's netstack failed: {}", e));
                }
                true
            }
            why = netstack_fault() => {
                fail(why);
                false
            }
            () = accept_loop => {
                error!("netstack accept loop stopped");
                false
            }
            () = datagram_loop => {
                error!("netstack datagram loop stopped");
                false
            }
        };
        // A bridge ended first: stop every shard and wait for them, rather
        // than dropping live runners.
        if !runtime_finished {
            if let Ok(snapshot) = control.stats_snapshot().await {
                debug!(
                    shards = snapshot.shard_count,
                    tcp_flows = snapshot.stack.tcp_active_flows,
                    udp_flows = snapshot.stack.udp_active_flows,
                    queued_packets = snapshot.router.queued_packets,
                    "netstack final snapshot"
                );
            }
            if let Err(e) = control.shutdown(0).await {
                debug!("netstack shutdown failed: {}", e);
                let _ = control.abort().await;
            }
            if let Err(e) = runtime.await {
                error!("netstack runner failed during shutdown: {}", e);
            }
        }
    });
    // A test's faults (feature fault-injection; nothing otherwise).
    #[cfg(feature = "fault-injection")]
    let runner = Box::pin(with_faults(runner));
    Ok(TunRunner {
        runner,
        control: runtime_control,
    })
}

/// The most queues `multi_queue` opens: the server profile's old default.
#[cfg(target_os = "linux")]
const MAX_QUEUES: usize = 8;

/// The device's queues, a shard each with its own runner: one, or with
/// `multi_queue` one to each CPU, up to [`MAX_QUEUES`].
#[cfg(target_os = "linux")]
fn linux_queues(settings: &TunSettings, netstack: &Netstack) -> Result<Vec<TunRsPacketIo>> {
    let queue_count = if settings.multi_queue {
        std::thread::available_parallelism()
            .map_or(1, NonZeroUsize::get)
            .min(MAX_QUEUES)
    } else {
        1
    };
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(&settings.name)
        .mtu(settings.mtu)
        .enable(true)
        .multi_queue(queue_count > 1)
        .offload(netstack.offload);
    if let Some(ipv4) = settings.ipv4 {
        builder = builder.ipv4(ipv4.address(), ipv4.network_length(), Some(peer(ipv4)));
    }
    if let Some(ipv6) = settings.ipv6 {
        builder = builder.ipv6(ipv6.address(), ipv6.network_length());
    }
    let first = builder
        .build_async()
        .map_err(|e| anyhow!("create tun failed: {}", e))?;
    let mut devices = Vec::with_capacity(queue_count);
    for _ in 1..queue_count {
        devices.push(
            first
                .try_clone()
                .map_err(|e| anyhow!("attach tun queue failed: {}", e))?,
        );
    }
    devices.push(first);
    devices
        .into_iter()
        .map(|device| {
            TunRsPacketIo::new(
                device,
                usize::from(settings.mtu),
                netstack.batch_size,
                queue_count,
                netstack.offload,
            )
        })
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// The options of a TUN inbound, as sing-box's `tun` inbound names them.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct TunInboundOptions {
    /// sing-box 1.14's: which remote addresses reach an app through the
    /// port it sent from. `endpoint_independent`: any (full cone, as P2P and
    /// some games need). `address_and_port_dependent`, the default: only an
    /// address and port the app sent to. `address_dependent` is not
    /// implemented, and is an error. An app's port is one mapping in every
    /// case.
    #[serde(default)]
    udp_filtering: Option<String>,
    /// sing-box's older name for `udp_filtering: endpoint_independent`,
    /// deprecated there; the two may not disagree.
    #[serde(default)]
    endpoint_independent_nat: Option<bool>,
    /// sing-box 1.15's: Linux opens the device with `IFF_MULTI_QUEUE`, a
    /// queue and a netstack shard to each CPU, eight at most. Off, the
    /// default, one queue: measured faster in every case tried (Trojan
    /// over TUN, 2 and 4 cores, 2026-10-15: 2 queues 3-9% slower, 4
    /// queues 4-9%). Elsewhere, and on a device the host opens, ignored
    /// with a warning.
    #[serde(default)]
    multi_queue: bool,
    /// The device's name, used as it is: a start fails if it is taken.
    /// Without it, on macOS one past the highest utunN is chosen at start,
    /// as sing-box chooses, and kept across reloads (a host reads it back);
    /// one another program takes before the device opens is given up for
    /// the next free one, three at most. Elsewhere utun233.
    #[serde(default)]
    interface_name: Option<String>,
    /// The device's addresses with their prefixes: one IPv4, one IPv6, or
    /// one of each.
    #[serde(default, with = "crate::config::model::listable")]
    address: Vec<String>,
    /// 9000 when omitted, as sing-box has it on Android.
    #[serde(default = "default_mtu")]
    mtu: u32,
    /// Routes the system's traffic into the device.
    #[serde(default)]
    auto_route: bool,
    /// Linux: redirects TCP to sail with nftables and marks the rest into
    /// the device, and lets rules bypass sail before a connection is set
    /// up (sing-box 1.13). Without it, the fields of the redirect (its
    /// marks, NFQUEUE and fallback rule, and `exclude_mptcp`) change
    /// nothing, and are ignored with a warning, as in sing-box.
    #[serde(default)]
    auto_redirect: bool,
    /// The mark that routes a packet into the device (0x2023). Marks are
    /// numbers, or strings of hexadecimal ("0x2023"); 0 is the default.
    #[serde(default, with = "fw_mark")]
    auto_redirect_input_mark: Option<u32>,
    /// The mark sail's own sockets carry, and flows that bypass it
    /// (0x2024). `route.default_mark` and `routing_mark` conflict with it.
    #[serde(default, with = "fw_mark")]
    auto_redirect_output_mark: Option<u32>,
    /// The mark of a connection pre-match rejects, which the kernel
    /// resets (0x2025).
    #[serde(default, with = "fw_mark")]
    auto_redirect_reset_mark: Option<u32>,
    /// The NFQUEUE pre-match reads first packets from (100). If it cannot
    /// be bound, sail runs without pre-match: `bypass` rules are skipped.
    #[serde(default)]
    auto_redirect_nfqueue: Option<u16>,
    /// Linux: the routing table of the device's routes (2022). Elsewhere,
    /// or without `auto_route`, it changes nothing, and is ignored with a
    /// warning, as in sing-box; so is `iproute2_rule_index`.
    #[serde(default)]
    iproute2_table_index: Option<u32>,
    /// Linux: the first of auto_route's and auto_redirect's ip rules
    /// (9000); the rules from it to 10 after it are sail's, and removed at
    /// start and stop.
    #[serde(default)]
    iproute2_rule_index: Option<u32>,
    /// The ip rule that sends what the main table has no route for into
    /// the device (32768).
    #[serde(default)]
    auto_redirect_iproute2_fallback_rule_index: Option<u32>,
    /// Lets MPTCP go past sail rather than dropping it, which makes
    /// clients fall back to TCP.
    #[serde(default)]
    exclude_mptcp: bool,
    /// With `auto_route`, keeps traffic from going past sail. Linux: with
    /// one family on the device, the other is unreachable. Windows:
    /// firewall rules, as sing-tun's: DNS leaves only through the device,
    /// but for sail's own, and with no IPv6 on the device, none leaves.
    /// Elsewhere it changes nothing, as in sing-box.
    #[serde(default)]
    strict_route: bool,
    /// sing-box 1.14's: whether the TUN's DNS is the system's, `native`,
    /// and its port 53 taken too, `hijack`, or neither, `disabled`.
    /// `hijack` with `auto_route`, `disabled` without, when unset. Port 53
    /// is taken with auto_redirect on Linux and strict_route on Windows;
    /// on macOS `hijack` is `native`.
    #[serde(default)]
    dns_mode: Option<String>,
    /// Addresses whose TCP goes into the device rather than to the
    /// redirect listener: a destination sail's own listeners use, say.
    #[serde(default, with = "crate::config::model::listable")]
    loopback_address: Vec<IpAddr>,
    /// Only these destinations are taken...
    #[serde(default, with = "crate::config::model::listable")]
    route_address: Vec<String>,
    /// ...and not these.
    #[serde(default, with = "crate::config::model::listable")]
    route_exclude_address: Vec<String>,
    /// Rule-sets whose destination `ip_cidr` alone are taken, kept up to
    /// date as they are downloaded again.
    #[serde(default, with = "crate::config::model::listable")]
    route_address_set: Vec<String>,
    /// Rule-sets whose destination `ip_cidr` are not taken.
    #[serde(default, with = "crate::config::model::listable")]
    route_exclude_address_set: Vec<String>,
    /// Linux, with `auto_route`: forwarded traffic is taken only from these
    /// interfaces...
    #[serde(default, with = "crate::config::model::listable")]
    include_interface: Vec<String>,
    /// ...or not from these. Naming `lo` in either leaves the host's own
    /// traffic out.
    #[serde(default, with = "crate::config::model::listable")]
    exclude_interface: Vec<String>,
    /// Linux, with `auto_route`: the host's traffic is taken only from
    /// these users...
    #[serde(default, with = "crate::config::model::listable")]
    include_uid: Vec<u32>,
    /// ...and from these ranges, as "1000:2000".
    #[serde(default, with = "crate::config::model::listable")]
    include_uid_range: Vec<String>,
    /// The host's traffic of these users is not taken...
    #[serde(default, with = "crate::config::model::listable")]
    exclude_uid: Vec<u32>,
    /// ...nor of these ranges.
    #[serde(default, with = "crate::config::model::listable")]
    exclude_uid_range: Vec<String>,
    /// Android users: not supported, as no VpnService can take them in;
    /// `include_uid_range` takes in a user's apps.
    #[serde(default, with = "crate::config::model::listable")]
    include_android_user: Vec<u32>,
    /// Android: the apps the host's VPN takes in or leaves out, applied by
    /// the host.
    #[serde(default, with = "crate::config::model::listable")]
    include_package: Vec<String>,
    #[serde(default, with = "crate::config::model::listable")]
    exclude_package: Vec<String>,
}

/// A TUN inbound's options, checked.
#[derive(Debug, Clone)]
pub(crate) struct TunSettings {
    pub name: String,
    /// Whether a datagram from an address the app never sent to reaches it.
    pub endpoint_independent_nat: bool,
    /// Linux: a queue and a netstack shard to each CPU, eight at most;
    /// otherwise one. Elsewhere only warned of, when set.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub multi_queue: bool,
    pub ipv4: Option<Ipv4Inet>,
    pub ipv6: Option<Ipv6Inet>,
    pub mtu: u16,
    pub auto_route: bool,
    pub auto_redirect: Option<AutoRedirectSettings>,
    /// What auto_route routes, on the systems it routes on.
    pub route: RouteSelection,
    /// Android: the apps the host's VPN takes in or leaves out.
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    /// Fields set that this system does not act on, as sing-box ignores
    /// them here: warned of when the TUN starts.
    pub ignored: Vec<(&'static str, &'static str)>,
}

impl TunSettings {
    /// What a host that opens the device itself is asked for.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub fn request(&self) -> TunRequest {
        TunRequest {
            name: self.name.clone(),
            mtu: self.mtu,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            auto_route: self.auto_route,
            include_package: self.include_package.clone(),
            exclude_package: self.exclude_package.clone(),
        }
    }
}

/// How a TUN with `auto_redirect` redirects, marks and routes, with
/// sing-box's defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AutoRedirectSettings {
    /// Sends a packet into the device.
    pub input_mark: u32,
    /// Sail's own sockets, and flows that bypass it: never redirected.
    pub output_mark: u32,
    /// A connection pre-match rejects: reset by the kernel.
    pub reset_mark: u32,
    pub nfqueue: u16,
    pub fallback_rule_index: u32,
    pub exclude_mptcp: bool,
    pub loopback_address: Vec<IpAddr>,
}

/// What traffic `auto_route` takes into the device, and the table and
/// rules it does it with (Linux), with sing-box's defaults filled in:
/// auto_redirect's nftables rules enforce it, or the routes and ip rules
/// of auto_route alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteSelection {
    pub table_index: u32,
    pub rule_index: u32,
    pub strict_route: bool,
    pub dns_mode: DnsMode,
    pub route_address: Vec<IpInet>,
    pub route_exclude_address: Vec<IpInet>,
    /// Rule sets whose IP CIDRs are what is taken, or what is not.
    pub route_address_set: Vec<String>,
    pub route_exclude_address_set: Vec<String>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<std::ops::RangeInclusive<u32>>,
    pub exclude_uid: Vec<std::ops::RangeInclusive<u32>>,
}

/// What `auto_route` does with DNS, as sing-box 1.14's `dns_mode` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsMode {
    /// The system's DNS is left as it is, and DNS anywhere goes where it
    /// went.
    Disabled,
    /// The system's DNS is the TUN's: the interface's DNS on Windows, the
    /// system resolver on macOS, systemd-resolved's link DNS on Linux.
    Native,
    /// `Native`, and DNS sent elsewhere is taken too: auto_redirect sends
    /// port 53 to sail (Linux), strict_route blocks port 53 off the TUN
    /// (Windows).
    Hijack,
}

/// sing-tun's defaults (redirect.go, tun.go).
pub(crate) const DEFAULT_INPUT_MARK: u32 = 0x2023;
pub(crate) const DEFAULT_OUTPUT_MARK: u32 = 0x2024;
pub(crate) const DEFAULT_RESET_MARK: u32 = 0x2025;
pub(crate) const DEFAULT_NFQUEUE: u16 = 100;
pub(crate) const DEFAULT_TABLE_INDEX: u32 = 2022;
pub(crate) const DEFAULT_RULE_INDEX: u32 = 9000;
pub(crate) const DEFAULT_FALLBACK_RULE_INDEX: u32 = 32768;

/// A firewall mark as sing-box takes it: a number, or a string such as
/// "0x2023"; 0 is the default.
mod fw_mark {
    use serde::{de, Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<u32>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Mark {
            Number(u32),
            Text(String),
        }
        let mark = match Option::<Mark>::deserialize(de)? {
            None => return Ok(None),
            Some(Mark::Number(number)) => number,
            Some(Mark::Text(text)) => {
                let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => text.parse::<u32>(),
                };
                parsed.map_err(|_| de::Error::custom(format!("invalid mark \"{text}\"")))?
            }
        };
        Ok((mark != 0).then_some(mark))
    }
}

/// uid lists and "from:to" ranges, as sing-box's include_uid(_range).
fn uid_ranges(
    uids: &[u32],
    ranges: &[String],
    field: &str,
) -> std::result::Result<Vec<std::ops::RangeInclusive<u32>>, String> {
    let mut all: Vec<_> = uids.iter().map(|uid| *uid..=*uid).collect();
    for range in ranges {
        let (from, to) = range
            .split_once(':')
            .ok_or_else(|| format!("{field}: missing ':' in range \"{range}\""))?;
        let bound = |value: &str| {
            value
                .parse::<u32>()
                .map_err(|_| format!("{field}: \"{range}\" is not a uid range"))
        };
        let (from, to) = (bound(from)?, bound(to)?);
        if from > to {
            return Err(format!("{field}: \"{range}\" ends before it starts"));
        }
        all.push(from..=to);
    }
    Ok(all)
}

/// The name of a TUN with none configured, where it is not chosen at start
/// (macOS chooses one; see `resolve_names`).
const DEFAULT_NAME: &str = "utun233";

use crate::runtime::TunName;

/// Settles the name of each TUN of `inbounds` before anything uses it, and
/// writes it into the inbound's options, so that everything that reads the
/// name (routing, the dialer's and DNS's own interfaces, the default
/// interface's detection, the sweep's ledger) reads the same one. A TUN with
/// no `interface_name` on macOS gets one past the highest utunN there is, as
/// sing-box chooses (sing-tun's CalculateInterfaceName), or the one it had
/// in `kept`, by tag, so that a reload keeps it; elsewhere the default.
/// Returns the names by tag. A name chosen here can be taken by another
/// program before the device opens: the start then fails, and the next
/// start chooses again.
pub(crate) fn resolve_names(
    inbounds: &mut [crate::config::Inbound],
    kept: &std::collections::BTreeMap<String, TunName>,
    host: &crate::runtime::Host,
) -> std::collections::BTreeMap<String, TunName> {
    resolve_names_among(
        inbounds,
        kept,
        host,
        cfg!(target_os = "macos"),
        &interface_names(),
    )
}

fn resolve_names_among(
    inbounds: &mut [crate::config::Inbound],
    kept: &std::collections::BTreeMap<String, TunName>,
    host: &crate::runtime::Host,
    choose: bool,
    existing: &[String],
) -> std::collections::BTreeMap<String, TunName> {
    let mut names = std::collections::BTreeMap::new();
    let configured = |inbound: &crate::config::Inbound| {
        inbound
            .options
            .get("interface_name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    };
    // Names configured, which a chosen one must not take.
    let mut taken: Vec<String> = existing.to_vec();
    taken.extend(
        inbounds
            .iter()
            .filter(|i| i.protocol == "tun")
            .filter_map(configured),
    );
    for inbound in inbounds.iter_mut().filter(|i| i.protocol == "tun") {
        let name = match configured(inbound) {
            Some(name) => TunName {
                name,
                chosen: false,
            },
            // The host opens the device and names it.
            None if host_opens(host) => continue,
            None => match kept.get(&inbound.tag) {
                Some(kept) => kept.clone(),
                None if choose => {
                    let name = next_utun(&taken);
                    taken.push(name.clone());
                    TunName { name, chosen: true }
                }
                None => TunName {
                    name: DEFAULT_NAME.into(),
                    chosen: false,
                },
            },
        };
        inbound
            .options
            .insert("interface_name".into(), name.name.clone().into());
        names.insert(inbound.tag.clone(), name);
    }
    names
}

/// A TUN's name that could not be had: configured and in use, or chosen
/// at start and taken by another program each of `attempts` times. A host
/// tells it from other start failures by `downcast_ref` on the error's
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunNameTaken {
    pub tag: String,
    /// The last name tried.
    pub name: String,
    /// Chosen by sail, as none was configured.
    pub chosen: bool,
    pub attempts: u32,
}

impl std::fmt::Display for TunNameTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.chosen {
            write!(
                f,
                "[{}] inbound: no free utun after {} attempts, the last {}: each was taken \
                 between choosing and opening it",
                self.tag, self.attempts, self.name
            )
        } else {
            write!(
                f,
                "[{}] inbound: interface_name {} is in use by another program",
                self.tag, self.name
            )
        }
    }
}

impl std::error::Error for TunNameTaken {}

/// How many names a chosen TUN tries before its start fails.
// Windows opens its adapter by name with wintun, never chosen.
#[cfg(any(not(target_os = "windows"), test))]
const CHOOSE_ATTEMPTS: u32 = 3;

/// Opens the TUN named `first`. A name sail chose that another program has
/// taken since (EBUSY) is given up for the next free one, logged, up to
/// CHOOSE_ATTEMPTS names; a configured one fails at once. Returns the
/// device and the name it got.
#[cfg(any(not(target_os = "windows"), test))]
fn open_named<T>(
    tag: &str,
    first: &str,
    chosen: bool,
    existing: impl Fn() -> Vec<String>,
    mut open: impl FnMut(&str) -> std::io::Result<T>,
) -> Result<(T, String)> {
    let mut name = first.to_owned();
    let mut tried: Vec<String> = Vec::new();
    loop {
        match open(&name) {
            Ok(device) => return Ok((device, name)),
            Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy => {
                tried.push(name.clone());
                let attempts = tried.len() as u32;
                if !chosen || attempts >= CHOOSE_ATTEMPTS {
                    return Err(anyhow::Error::new(TunNameTaken {
                        tag: tag.to_owned(),
                        name,
                        chosen,
                        attempts,
                    }));
                }
                let mut taken = existing();
                taken.extend(tried.iter().cloned());
                let next = next_utun(&taken);
                warn!(
                    "[{}] inbound: {} was taken between choosing and opening it; trying {}",
                    tag, name, next
                );
                name = next;
            }
            Err(e) => {
                return Err(anyhow!(
                    "[{}] inbound: create tun {} failed: {}",
                    tag,
                    name,
                    e
                ))
            }
        }
    }
}

/// One past the highest utunN among `taken`.
fn next_utun(taken: &[String]) -> String {
    let next = taken
        .iter()
        .filter_map(|name| name.strip_prefix("utun")?.parse::<u32>().ok())
        .max()
        .map_or(0, |n| n + 1);
    format!("utun{}", next)
}

/// The names of the system's network interfaces.
fn interface_names() -> Vec<String> {
    #[cfg(unix)]
    {
        let mut names = Vec::new();
        // SAFETY: if_nameindex returns an array ending with a zeroed entry,
        // freed below and read only before.
        unsafe {
            let list = libc::if_nameindex();
            if list.is_null() {
                return names;
            }
            let mut entry = list;
            while (*entry).if_index != 0 && !(*entry).if_name.is_null() {
                names.push(
                    std::ffi::CStr::from_ptr((*entry).if_name)
                        .to_string_lossy()
                        .into_owned(),
                );
                entry = entry.add(1);
            }
            libc::if_freenameindex(list);
        }
        names
    }
    #[cfg(not(unix))]
    Vec::new()
}

/// sing-box's default: the device is memory, and larger packets are fewer.
fn default_mtu() -> u32 {
    9000
}

/// The other end of the link an address implies: the next address in its
/// network, the one before when it is the last, or itself when it is alone.
pub(crate) fn peer<I: Inet>(inet: I) -> I::Address {
    inet.next()
        .or_else(|| inet.previous())
        .map_or(inet.address(), |peer| peer.address())
}

/// Whether `host` opens the TUN device (Android, iOS), with its routes.
pub(crate) fn host_opens(host: &crate::runtime::Host) -> bool {
    host.platform
        .as_ref()
        .is_some_and(|platform| platform.opens_tun())
}

/// The options of the TUN inbound `inbound`, checked, for `host`.
pub(crate) fn options(inbound: &Inbound, host: &crate::runtime::Host) -> Result<TunSettings> {
    let options: TunInboundOptions = parse_options("inbound", &inbound.tag, &inbound.options)?;
    let error = |message: String| anyhow!("[{}] inbound: {}", inbound.tag, message);
    // A host's VPN takes in or leaves out apps, as Android's VpnService
    // does, and nothing by user: sing-box's libbox refuses these, with these
    // words (experimental/libbox/service.go), before anything else of them
    // is looked at.
    if host_opens(host) {
        if !options.include_uid.is_empty()
            || !options.include_uid_range.is_empty()
            || !options.exclude_uid.is_empty()
            || !options.exclude_uid_range.is_empty()
        {
            return Err(error("platform: unsupported uid options".into()));
        }
        if !options.include_android_user.is_empty() {
            return Err(error("platform: unsupported android_user option".into()));
        }
    }
    // sing-box takes in Android's users only on a rooted device that opens
    // its own tun, which sail does not run on.
    if !options.include_android_user.is_empty() {
        return Err(error(
            "include_android_user: not supported; include_uid_range takes in an Android user's \
             apps (user N's are uids N*100000 to N*100000+99999)"
                .into(),
        ));
    }
    let (mut ipv4, mut ipv6) = (None, None);
    for address in &options.address {
        // As sing-box, the prefix is required: a bare address is no /32.
        let parsed = address
            .contains('/')
            .then(|| address.parse::<IpInet>().ok())
            .flatten()
            .ok_or(());
        match parsed {
            Ok(IpInet::V4(inet)) if ipv4.is_none() => ipv4 = Some(inet),
            Ok(IpInet::V6(inet)) if ipv6.is_none() => ipv6 = Some(inet),
            Ok(_) => {
                return Err(error(format!(
                    "address: {address}: one address of each family is supported"
                )))
            }
            Err(_) => {
                return Err(error(format!(
                    "address: \"{address}\" is not an address with a prefix, such as 172.19.0.1/30"
                )))
            }
        }
    }
    if ipv4.is_none() && ipv6.is_none() {
        return Err(error("address: the device needs an address".into()));
    }
    // IPv4 hosts must take 576-byte datagrams, IPv6 ones 1280-byte packets;
    // an IP packet is at most 64 KiB.
    let minimum = if ipv6.is_some() { 1280 } else { 576 };
    let mtu = u16::try_from(options.mtu)
        .ok()
        .filter(|mtu| *mtu >= minimum)
        .ok_or_else(|| error(format!("mtu {} is outside {minimum} to 65535", options.mtu)))?;
    let auto_redirect = auto_redirect(&options).map_err(error)?;
    let route = route_selection(&options).map_err(error)?;
    let mut ignored = ignored_here(&options);
    if options.multi_queue && host_opens(host) && cfg!(target_os = "linux") {
        ignored.push(("multi_queue", "the host opens the device"));
    }
    let endpoint_independent_nat = match (
        options.udp_filtering.as_deref(),
        options.endpoint_independent_nat,
    ) {
        (None | Some(""), older) => older.unwrap_or(false),
        (Some("endpoint_independent"), None | Some(true)) => true,
        (Some("address_and_port_dependent"), None | Some(false)) => false,
        (Some("endpoint_independent" | "address_and_port_dependent"), Some(older)) => {
            return Err(error(format!(
                "udp_filtering and endpoint_independent_nat: {older} disagree"
            )));
        }
        (Some("address_dependent"), _) => {
            return Err(error(
                "udp_filtering: address_dependent is not implemented; sail filters by \
                 address and port, or, with endpoint_independent, not at all"
                    .into(),
            ));
        }
        (Some(other), _) => {
            return Err(error(format!(
                "udp_filtering: \"{other}\" is none of endpoint_independent, \
                 address_dependent and address_and_port_dependent"
            )));
        }
    };
    Ok(TunSettings {
        endpoint_independent_nat,
        multi_queue: options.multi_queue,
        name: options
            .interface_name
            .unwrap_or_else(|| DEFAULT_NAME.to_string()),
        ipv4,
        ipv6,
        mtu,
        auto_route: options.auto_route,
        auto_redirect,
        route,
        include_package: options.include_package,
        exclude_package: options.exclude_package,
        ignored,
    })
}

/// Whether `strict_route` does anything here: sing-tun acts on it on Linux
/// (its rules) and Windows (firewall rules against DNS leaks); elsewhere
/// sing-box takes it and it changes nothing, as in sail.
const STRICT_ROUTE_ACTS: bool = cfg!(any(target_os = "linux", target_os = "windows"));

/// Whether the iproute2 table and rule indexes do anything here: they
/// number Linux's ip rules; elsewhere sing-box takes them and they change
/// nothing (sing-tun reads them in tun_linux.go only).
const IPROUTE2_HERE: bool = cfg!(target_os = "linux");

/// The fields of `options` set that change nothing, as set, with why:
/// sing-box takes them and ignores them, and sail warns of them. Fields
/// that choose traffic are never among them.
fn ignored_here(options: &TunInboundOptions) -> Vec<(&'static str, &'static str)> {
    let iproute2 = if !IPROUTE2_HERE {
        Some("Linux only")
    } else if !options.auto_route {
        Some("only used with auto_route")
    } else {
        None
    };
    // sing-tun reads these in its redirect files only (redirect_*.go).
    let redirect = (!options.auto_redirect).then_some("only used with auto_redirect");
    [
        (
            "iproute2_table_index",
            options.iproute2_table_index.is_some(),
            iproute2,
        ),
        (
            "iproute2_rule_index",
            options.iproute2_rule_index.is_some(),
            iproute2,
        ),
        ("exclude_mptcp", options.exclude_mptcp, redirect),
        (
            "multi_queue",
            options.multi_queue,
            (!cfg!(target_os = "linux")).then_some("Linux only"),
        ),
        (
            "auto_redirect_input_mark",
            options.auto_redirect_input_mark.is_some(),
            redirect,
        ),
        (
            "auto_redirect_output_mark",
            options.auto_redirect_output_mark.is_some(),
            redirect,
        ),
        (
            "auto_redirect_reset_mark",
            options.auto_redirect_reset_mark.is_some(),
            redirect,
        ),
        (
            "auto_redirect_nfqueue",
            options.auto_redirect_nfqueue.is_some(),
            redirect,
        ),
        (
            "auto_redirect_iproute2_fallback_rule_index",
            options.auto_redirect_iproute2_fallback_rule_index.is_some(),
            redirect,
        ),
    ]
    .into_iter()
    .filter_map(|(field, set, why)| why.filter(|_| set).map(|why| (field, why)))
    .collect()
}

/// What `auto_route` takes, checked against what this system does: every
/// field that chooses traffic is enforced or refused, never ignored.
fn route_selection(options: &TunInboundOptions) -> std::result::Result<RouteSelection, String> {
    let set =
        |fields: &[(&'static str, bool)]| fields.iter().find(|(_, set)| *set).map(|(f, _)| *f);
    // Choosing what auto_route takes, which needs auto_route.
    let choosing = [
        ("strict_route", options.strict_route && STRICT_ROUTE_ACTS),
        ("route_address", !options.route_address.is_empty()),
        (
            "route_exclude_address",
            !options.route_exclude_address.is_empty(),
        ),
        ("route_address_set", !options.route_address_set.is_empty()),
        (
            "route_exclude_address_set",
            !options.route_exclude_address_set.is_empty(),
        ),
        ("include_interface", !options.include_interface.is_empty()),
        ("exclude_interface", !options.exclude_interface.is_empty()),
        ("include_uid", !options.include_uid.is_empty()),
        ("include_uid_range", !options.include_uid_range.is_empty()),
        ("exclude_uid", !options.exclude_uid.is_empty()),
        ("exclude_uid_range", !options.exclude_uid_range.is_empty()),
    ];
    if let Some(field) = set(&choosing).filter(|_| !options.auto_route) {
        return Err(format!("{field}: needs `auto_route`"));
    }
    if !options.auto_redirect {
        // The ip rules are Linux's. Elsewhere sing-box ignores these, which
        // would take in what they leave out.
        let rules = [
            ("include_interface", !options.include_interface.is_empty()),
            ("exclude_interface", !options.exclude_interface.is_empty()),
            ("include_uid", !options.include_uid.is_empty()),
            ("include_uid_range", !options.include_uid_range.is_empty()),
            ("exclude_uid", !options.exclude_uid.is_empty()),
            ("exclude_uid_range", !options.exclude_uid_range.is_empty()),
        ];
        if let Some(field) = set(&rules).filter(|_| !cfg!(target_os = "linux")) {
            return Err(format!(
                "{field}: only on Linux; ignoring it would send traffic the config excludes"
            ));
        }
        // Route management of this system.
        let routes = [
            ("strict_route", options.strict_route && STRICT_ROUTE_ACTS),
            ("route_address", !options.route_address.is_empty()),
            (
                "route_exclude_address",
                !options.route_exclude_address.is_empty(),
            ),
            ("route_address_set", !options.route_address_set.is_empty()),
            (
                "route_exclude_address_set",
                !options.route_exclude_address_set.is_empty(),
            ),
        ];
        let routed_here = cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        ));
        if let Some(field) = set(&routes).filter(|_| !routed_here) {
            return Err(format!(
                "{field}: sail takes it with auto_route on Linux, macOS and Windows, or \
                 auto_redirect; on this system it is route management, not implemented yet"
            ));
        }
    }
    if !options.include_interface.is_empty() && !options.exclude_interface.is_empty() {
        return Err("include_interface and exclude_interface exclude each other".into());
    }
    let dns_mode = match options.dns_mode.as_deref() {
        None | Some("") if options.auto_route => DnsMode::Hijack,
        None | Some("") | Some("disabled") => DnsMode::Disabled,
        // The TUN's DNS is set with its routes.
        Some("native" | "hijack") if !options.auto_route => {
            return Err("dns_mode: needs `auto_route`, which sets the TUN's DNS".into());
        }
        Some("native") => DnsMode::Native,
        Some("hijack") => DnsMode::Hijack,
        Some(other) => {
            return Err(format!(
                "dns_mode: \"{other}\" is none of disabled, native and hijack"
            ))
        }
    };
    let prefixes = |field: &str, values: &[String]| {
        values
            .iter()
            .map(|value| {
                value
                    .contains('/')
                    .then(|| value.parse::<IpInet>().ok())
                    .flatten()
                    .ok_or_else(|| format!("{field}: \"{value}\" is not a prefix"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()
    };
    Ok(RouteSelection {
        table_index: options
            .iproute2_table_index
            .filter(|index| *index != 0)
            .unwrap_or(DEFAULT_TABLE_INDEX),
        rule_index: options
            .iproute2_rule_index
            .filter(|index| *index != 0)
            .unwrap_or(DEFAULT_RULE_INDEX),
        strict_route: options.strict_route,
        dns_mode,
        route_address: prefixes("route_address", &options.route_address)?,
        route_exclude_address: prefixes("route_exclude_address", &options.route_exclude_address)?,
        route_address_set: options.route_address_set.clone(),
        route_exclude_address_set: options.route_exclude_address_set.clone(),
        include_interface: options.include_interface.clone(),
        exclude_interface: options.exclude_interface.clone(),
        include_uid: uid_ranges(
            &options.include_uid,
            &options.include_uid_range,
            "include_uid",
        )?,
        exclude_uid: uid_ranges(
            &options.exclude_uid,
            &options.exclude_uid_range,
            "exclude_uid",
        )?,
    })
}

/// The auto_redirect settings, with sing-box's defaults; what only
/// auto_redirect does is refused without it.
fn auto_redirect(
    options: &TunInboundOptions,
) -> std::result::Result<Option<AutoRedirectSettings>, String> {
    if !options.auto_redirect {
        // sing-box's stacks act on loopback_address too; sail's only with
        // auto_redirect. The redirect's marks and the like change nothing
        // without it: ignored_here warns of them.
        if !options.loopback_address.is_empty() {
            return Err("loopback_address: sail takes it with auto_redirect only".into());
        }
        return Ok(None);
    }
    if !options.auto_route {
        return Err("`auto_route` is required by `auto_redirect`".into());
    }
    if !cfg!(target_os = "linux") {
        return Err("auto_redirect: Linux only".into());
    }
    Ok(Some(AutoRedirectSettings {
        input_mark: options
            .auto_redirect_input_mark
            .unwrap_or(DEFAULT_INPUT_MARK),
        output_mark: options
            .auto_redirect_output_mark
            .unwrap_or(DEFAULT_OUTPUT_MARK),
        reset_mark: options
            .auto_redirect_reset_mark
            .unwrap_or(DEFAULT_RESET_MARK),
        nfqueue: options
            .auto_redirect_nfqueue
            .filter(|queue| *queue != 0)
            .unwrap_or(DEFAULT_NFQUEUE),
        fallback_rule_index: options
            .auto_redirect_iproute2_fallback_rule_index
            .filter(|index| *index != 0)
            .unwrap_or(DEFAULT_FALLBACK_RULE_INDEX),
        exclude_mptcp: options.exclude_mptcp,
        loopback_address: options.loopback_address.clone(),
    }))
}

pub(crate) fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<TunRunner> {
    tracing::debug!("Create TUN inbound");

    // A host that runs the VPN (Android, iOS) opens the device, with its
    // routes; the instance only reads and writes it.
    let platform = dispatcher
        .env()
        .host
        .platform
        .clone()
        .filter(|platform| platform.opens_tun());
    let settings = options(&inbound, &dispatcher.env().host)?;
    for (field, why) in &settings.ignored {
        tracing::warn!("[{}] inbound: {}: ignored: {}", inbound.tag, field, why);
    }
    if platform.is_none() {
        if let Some(field) = [
            ("include_package", !settings.include_package.is_empty()),
            ("exclude_package", !settings.exclude_package.is_empty()),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
        {
            return Err(anyhow!(
                "[{}] inbound: {}: applied by a host that opens the tun (Android)",
                inbound.tag,
                field
            ));
        }
    }
    #[cfg(target_os = "windows")]
    let opened = open_wintun(
        inbound,
        dispatcher,
        nat_manager,
        settings,
        platform.is_some(),
    );
    #[cfg(not(target_os = "windows"))]
    let opened = {
        let teardown = dispatcher.env().teardown.clone();
        open_device(
            inbound,
            dispatcher,
            nat_manager,
            settings,
            platform,
            DeviceContext {
                teardown: &teardown,
                publish_name: true,
            },
        )
    };
    opened
}

/// Checks the dynamic device boundary without opening a device or asking
/// the host to change its network. OS routes and DNS belong to a separate
/// host transaction; construction must not silently enable auto routing.
#[cfg(unix)]
pub(crate) fn dynamic_options(
    inbound: &Inbound,
    host: &crate::runtime::Host,
) -> Result<TunSettings> {
    if inbound.protocol != "tun" {
        return Err(anyhow!("dynamic TUN: expected a tun inbound"));
    }
    let settings = options(inbound, host)?;
    if settings.auto_route || settings.auto_redirect.is_some() {
        return Err(anyhow!(
            "dynamic TUN: auto_route and auto_redirect require a host network transaction"
        ));
    }
    if !host_opens(host)
        && (!settings.include_package.is_empty() || !settings.exclude_package.is_empty())
    {
        return Err(anyhow!(
            "dynamic TUN: package selection requires a host that opens the device"
        ));
    }
    Ok(settings)
}

/// Opens only one attachment's device. The caller enters its child task
/// scope during construction AND runner polling, and uses an attachment
/// NAT on the same dispatcher. Device checks go only to `teardown`.
///
/// Internal device creation still configures addresses and brings it up;
/// this is a commit operation, not a side-effect-free prepare. A host's
/// open_tun transfers its descriptor as in ordinary startup, and must not
/// install routes or DNS without its own rollback transaction.
#[cfg(unix)]
pub(crate) fn new_dynamic(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    teardown: crate::runtime::teardown::Teardown,
) -> Result<TunRunner> {
    let settings = dynamic_options(&inbound, &dispatcher.env().host)?;
    for (field, why) in &settings.ignored {
        warn!("[{}] inbound: {}: ignored: {}", inbound.tag, field, why);
    }
    let platform = dispatcher
        .env()
        .host
        .platform
        .clone()
        .filter(|platform| platform.opens_tun());
    open_device(
        inbound,
        dispatcher,
        nat_manager,
        settings,
        platform,
        DeviceContext {
            teardown: &teardown,
            publish_name: false,
        },
    )
}

/// The TUN on Windows: a wintun adapter sail sets up itself.
#[cfg(target_os = "windows")]
fn open_wintun(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    settings: TunSettings,
    host_opens: bool,
) -> Result<TunRunner> {
    if host_opens {
        return Err(anyhow!(
            "[{}] inbound: a host that opens the tun is not taken on Windows",
            inbound.tag
        ));
    }
    let netstack = &dispatcher.env().options.netstack;
    let mtu = usize::from(settings.mtu);
    let addresses: Vec<(std::net::IpAddr, u8)> = settings
        .ipv4
        .map(|i| (i.address().into(), i.network_length()))
        .into_iter()
        .chain(
            settings
                .ipv6
                .map(|i| (i.address().into(), i.network_length())),
        )
        .collect();
    let device = crate::platform::windows::wintun::open(
        &settings.name,
        &addresses,
        settings.mtu,
        settings.auto_route,
    )
    .map_err(|e| anyhow!("[{}] inbound: {:#}", inbound.tag, e))?;
    // The adapter closes with the last of its session's handles, which
    // the runner holds; a thread waiting for packets holds one too, until
    // the session is shut down. So the step shuts it down, the newest's
    // steps (firewall rules, DNS, routes) having run before it, and a
    // check, once the runner is dropped, sees the adapter gone.
    let session = std::sync::Arc::downgrade(&device.session);
    let teardown = &dispatcher.env().teardown;
    teardown.push(crate::runtime::teardown::Step::new(
        crate::runtime::teardown::LeftKind::Tun,
        format!("the wintun session of {}", settings.name),
        move || match session.upgrade() {
            Some(session) => session
                .shutdown()
                .map_err(|e| std::io::Error::other(e.to_string())),
            None => Ok(()),
        },
    ));
    teardown.push_check(adapter_gone(&settings.name));
    let io = super::packet_io::WintunPacketIo::new(device.session, netstack.batch_size)?;
    run(
        inbound,
        dispatcher.clone(),
        nat_manager,
        vec![io],
        mtu,
        netstack,
        settings.endpoint_independent_nat,
    )
}

/// The check that the wintun adapter `name` went with its runner: it
/// closes with its session's last handle; 1 s is room for a loaded system
/// (judgment).
#[cfg(target_os = "windows")]
fn adapter_gone(name: &str) -> crate::runtime::teardown::Step {
    use crate::runtime::teardown::{LeftKind, Step};
    let adapter = name.to_owned();
    Step::new(
        LeftKind::Tun,
        format!("the wintun adapter {}", name),
        move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                if crate::platform::windows::ip_helper::Luid::by_alias(&adapter).is_err() {
                    return Ok(());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::other(
                        "still there: something of the instance holds its session",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        },
    )
    .clear(format!(
        "powershell -Command \"Get-NetAdapter -IncludeHidden -Name '{}' | ForEach-Object {{ pnputil /remove-device $_.PnPDeviceID }}\"",
        name
    ))
}

/// Where a device registers cleanup checks, and whether a name chosen at
/// ordinary startup is published to the instance's shared network state.
#[cfg(not(target_os = "windows"))]
struct DeviceContext<'a> {
    teardown: &'a crate::runtime::teardown::Teardown,
    publish_name: bool,
}

/// The TUN elsewhere: opened by the host, or through the tun crates.
#[cfg(not(target_os = "windows"))]
fn open_device(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    settings: TunSettings,
    platform: Option<crate::runtime::PlatformRef>,
    context: DeviceContext<'_>,
) -> Result<TunRunner> {
    let netstack = &dispatcher.env().options.netstack;
    let mtu = usize::from(settings.mtu);
    let mut cfg = tun::Configuration::default();
    if !context.publish_name {
        cfg.mtu(settings.mtu);
        #[cfg(target_os = "macos")]
        cfg.platform_config(|config| {
            // Device addressing may still add connected routes. Do not
            // also run tun's explicit route command in the dynamic path.
            config.enable_routing(false);
        });
    }
    let host_opened = platform.is_some();
    if let Some(platform) = platform {
        let fd = platform
            .open_tun(&settings.request())
            .map_err(|e| anyhow!("the host did not open the tun: {}", e))?;
        cfg.raw_fd(fd);
    } else {
        #[cfg(target_os = "linux")]
        {
            let queues = linux_queues(&settings, netstack)?;
            if !context.publish_name {
                context.teardown.push_check(device_gone(&settings.name));
            }
            return run(
                inbound,
                dispatcher.clone(),
                nat_manager,
                queues,
                mtu,
                netstack,
                settings.endpoint_independent_nat,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let Some(ipv4) = settings.ipv4 else {
                return Err(anyhow!(
                    "[{}] inbound: address: this system needs an IPv4 address on the tun",
                    inbound.tag
                ));
            };
            cfg.address(ipv4.address())
                .destination(peer(ipv4))
                .netmask(ipv4.mask())
                .mtu(settings.mtu)
                .up();
        }
    }

    let chosen = context.publish_name
        && dispatcher
            .env()
            .tun_names
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&inbound.tag)
            .is_some_and(|name| name.chosen);
    let opened_here = !host_opened;
    let (tun, name) = if opened_here {
        open_named(
            &inbound.tag,
            &settings.name,
            chosen,
            interface_names,
            |name| {
                cfg.tun_name(name);
                tun::create_as_async(&cfg).map_err(std::io::Error::from)
            },
        )?
    } else {
        let tun = tun::create_as_async(&cfg)
            .map_err(|e| anyhow!("[{}] inbound: open the host's tun: {}", inbound.tag, e))?;
        (tun, settings.name.clone())
    };
    let mut settings = settings;
    if context.publish_name && name != settings.name {
        // What reads the name from here on reads the one the TUN got.
        let names = {
            let mut names = dispatcher
                .env()
                .tun_names
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = names.get_mut(&inbound.tag) {
                entry.name = name.clone();
            }
            names.values().map(|n| n.name.clone()).collect::<Vec<_>>()
        };
        dispatcher.env().network.set_own_interfaces(names);
        settings.name = name;
    }
    info!("[{}] inbound: tun {} is up", inbound.tag, settings.name);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if opened_here {
        context.teardown.push_check(device_gone(&settings.name));
    }
    #[cfg(target_os = "macos")]
    if let Some(ipv6) = settings.ipv6.filter(|_| cfg_opened_here(&dispatcher)) {
        crate::platform::utun::add_ipv6_address(
            &settings.name,
            ipv6.address(),
            ipv6.network_length(),
        )?;
    }
    let io = TunPacketIo::new(tun, mtu, netstack.batch_size)?;
    run(
        inbound,
        dispatcher.clone(),
        nat_manager,
        vec![io],
        mtu,
        netstack,
        settings.endpoint_independent_nat,
    )
}

/// The check that the TUN `name` went with its runner. The kernel
/// removes it as its descriptor closes; 1 s is room for a loaded system
/// (judgment).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn device_gone(name: &str) -> crate::runtime::teardown::Step {
    use crate::runtime::teardown::{LeftKind, Step};
    let tun = name.to_owned();
    let check = Step::new(LeftKind::Tun, format!("the TUN {}", name), move || {
        let Ok(c_name) = std::ffi::CString::new(tun.as_str()) else {
            return Ok(());
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            // SAFETY: a NUL-terminated name.
            if unsafe { libc::if_nametoindex(c_name.as_ptr()) } == 0 {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "still there: something of the instance holds its descriptor",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    });
    // A utun goes only with its descriptor; a Linux TUN can be deleted.
    if cfg!(target_os = "linux") {
        check.clear(format!("ip link delete {}", name))
    } else {
        check
    }
}

/// Whether this instance, not its host, opened the device.
#[cfg(target_os = "macos")]
fn cfg_opened_here(dispatcher: &Dispatcher) -> bool {
    !dispatcher
        .env()
        .host
        .platform
        .as_ref()
        .is_some_and(|platform| platform.opens_tun())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options, for an instance whose host does not open the device.
    fn options(inbound: &Inbound) -> Result<TunSettings> {
        super::options(inbound, &Default::default())
    }

    /// The mobile profile's stack takes 2000 connections at once. Every
    /// connection reserves its starting receive window from the budget, and
    /// at 16 KiB a window the budget's 12 MiB of TCP bytes held only about
    /// 700 (653 of 2000 over a Linux TUN, measured).
    #[test]
    fn the_mobile_stack_holds_two_thousand_connections() {
        use sail_netstack::{
            emit_tcp_segment, parse_ip_packet, parse_tcp_segment, NetworkGeneration, SendControl,
            SeqNumber, TcpEvent, TcpFlags, TcpTable, TcpTableConfig,
        };
        let netstack =
            crate::runtime::RuntimeOptions::profile(crate::runtime::Profile::Mobile).netstack;
        let ledger = ResourceLedger::new(budget_profile(netstack.budget).budget()).unwrap();
        let mut config = TcpTableConfig::default();
        set_receive_window(&mut config, &netstack);
        let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), config);
        let destination = SocketAddr::from(([10, 96, 0, 1], 443));
        let segment = |source, sequence, acknowledgment, flags| {
            emit_tcp_segment(
                source,
                destination,
                SendControl {
                    sequence: SeqNumber::new(sequence),
                    acknowledgment: SeqNumber::new(acknowledgment),
                    flags,
                    window: 65_535,
                },
                &[],
                64,
                1,
            )
            .unwrap()
        };
        for index in 0..2_000_u16 {
            let source = SocketAddr::from(([172, 19, 0, 1], 10_000 + index));
            let syn_ack = table
                .ingest(&segment(source, 100, 0, TcpFlags::SYN))
                .unwrap()
                .outgoing
                .pop()
                .unwrap_or_else(|| panic!("connection {index}: no SYN-ACK"));
            let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true)
                .unwrap()
                .meta;
            let ack = segment(
                source,
                101,
                syn_ack.sequence.wrapping_add(1).get(),
                TcpFlags::ACK,
            );
            match table.ingest(&ack).unwrap().events.as_slice() {
                [TcpEvent::Accepted(connection)] => {
                    table.accept(connection.token).unwrap();
                }
                events => panic!("connection {index} did not open: {events:?}"),
            }
        }
        assert_eq!(table.stats().active_flows, 2_000);
    }

    /// sing-box 1.14's `dns_mode`: `hijack` with auto_route and
    /// `disabled` without, when unset; `native` and `hijack` need
    /// auto_route, which sets the TUN's DNS.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn dns_mode_is_hijack_with_auto_route_unless_set() {
        let mode = |extra: serde_json::Value| {
            let mut tun_options = serde_json::json!({ "address": "172.19.0.1/30" });
            tun_options
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            options(&tun(tun_options)).map(|s| s.route.dns_mode)
        };
        use serde_json::json;
        assert_eq!(
            mode(json!({ "auto_route": true })).unwrap(),
            DnsMode::Hijack
        );
        assert_eq!(mode(json!({})).unwrap(), DnsMode::Disabled);
        assert_eq!(
            mode(json!({ "auto_route": true, "dns_mode": "native" })).unwrap(),
            DnsMode::Native
        );
        assert_eq!(
            mode(json!({ "auto_route": true, "dns_mode": "disabled" })).unwrap(),
            DnsMode::Disabled
        );
        let err = format!("{:#}", mode(json!({ "dns_mode": "native" })).unwrap_err());
        assert!(err.contains("dns_mode: needs `auto_route`"), "{}", err);
        let err = format!(
            "{:#}",
            mode(json!({ "auto_route": true, "dns_mode": "x" })).unwrap_err()
        );
        assert!(
            err.contains("none of disabled, native and hijack"),
            "{}",
            err
        );
    }

    fn tun(options: serde_json::Value) -> Inbound {
        Inbound {
            protocol: "tun".into(),
            tag: "tun".into(),
            listen: None,
            listen_port: None,
            udp_timeout: None,
            tcp_keep_alive: None,
            tcp_keep_alive_interval: None,
            disable_tcp_keep_alive: false,
            tcp_fast_open: false,
            udp_fragment: None,
            options: options.as_object().unwrap().clone(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn dynamic_device_rejects_routing_before_opening() {
        let host = crate::runtime::Host::default();
        for fields in [
            serde_json::json!({"auto_route": true}),
            serde_json::json!({"auto_route": true, "auto_redirect": true}),
        ] {
            let mut inbound = tun(serde_json::json!({"address": ["172.19.0.1/30"]}));
            inbound.options.extend(fields.as_object().unwrap().clone());
            assert!(super::dynamic_options(&inbound, &host).is_err());
        }
        // The same ordinary configuration is still accepted by startup.
        assert!(super::options(
            &tun(serde_json::json!({
                "address": ["172.19.0.1/30"], "auto_route": true
            })),
            &host,
        )
        .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dynamic_device_checks_source_and_accepts_unrouted_settings() {
        let host = crate::runtime::Host::default();
        let inbound = tun(serde_json::json!({
            "address": ["172.19.0.1/30"], "interface_name": "utun77",
            "mtu": 1500
        }));
        let settings = super::dynamic_options(&inbound, &host).unwrap();
        assert_eq!(settings.name, "utun77");
        assert!(!settings.auto_route);
        let mut other = inbound.clone();
        other.protocol = "socks".into();
        assert!(super::dynamic_options(&other, &host).is_err());
        let mut packages = inbound;
        packages
            .options
            .insert("include_package".into(), serde_json::json!(["app"]));
        assert!(super::dynamic_options(&packages, &host).is_err());
    }

    #[test]
    fn sing_box_fields_are_read() {
        let settings = options(&tun(serde_json::json!({
            "interface_name": "tun7",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1500,
            "auto_route": true
        })))
        .unwrap();
        assert_eq!(settings.name, "tun7");
        assert_eq!(settings.ipv4, Some("172.19.0.1/30".parse().unwrap()));
        assert_eq!(
            settings.ipv6,
            Some("fdfe:dcba:9876::1/126".parse().unwrap())
        );
        assert_eq!(settings.mtu, 1500);
        assert!(settings.auto_route);
    }

    #[test]
    fn unset_fields_take_sing_box_defaults() {
        let settings = options(&tun(serde_json::json!({ "address": "172.19.0.1/30" }))).unwrap();
        assert_eq!(settings.name, DEFAULT_NAME);
        assert_eq!(settings.mtu, 9000);
        assert!(!settings.auto_route);
        assert_eq!(settings.ipv6, None);
    }

    #[test]
    fn the_peer_is_the_next_address_or_the_one_before() {
        let peer_of = |inet: &str| peer(inet.parse::<Ipv4Inet>().unwrap()).to_string();
        assert_eq!(peer_of("172.19.0.1/30"), "172.19.0.2");
        assert_eq!(peer_of("172.19.0.3/30"), "172.19.0.2");
        assert_eq!(peer_of("10.0.0.7/32"), "10.0.0.7");
        let peer6 = peer("fdfe::1/126".parse::<Ipv6Inet>().unwrap());
        assert_eq!(peer6.to_string(), "fdfe::2");
    }

    #[test]
    fn unusable_addresses_and_mtus_are_errors() {
        for (given, mentions) in [
            (serde_json::json!({}), "needs an address"),
            (serde_json::json!({ "address": "172.19.0.1" }), "prefix"),
            (
                serde_json::json!({ "address": ["172.19.0.1/30", "172.20.0.1/30"] }),
                "one address of each family",
            ),
            (
                serde_json::json!({ "address": "fdfe::1/126", "mtu": 1200 }),
                "1280",
            ),
            (
                serde_json::json!({ "address": "172.19.0.1/30", "mtu": 70000 }),
                "65535",
            ),
            // No VpnService can take Android users in, and sail opens no
            // tun on a rooted device's own.
            (
                serde_json::json!({ "address": "172.19.0.1/30", "include_android_user": [10] }),
                "include_android_user: not supported; include_uid_range",
            ),
        ] {
            let err = options(&tun(given)).unwrap_err().to_string();
            assert!(err.contains(mentions), "{err}");
        }
    }

    /// A tun inbound as sing-box's documentation writes it.
    #[test]
    fn a_sing_box_tun_inbound_is_read() {
        let config = crate::config::Config::from_json(
            r#"{
                "inbounds": [{
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "tun0",
                    "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
                    "mtu": 9000,
                    "auto_route": true,
                    "stack": "system",
                    "endpoint_independent_nat": false,
                    "udp_timeout": "5m"
                }],
                "outbounds": [{ "type": "direct" }],
                "route": { "auto_detect_interface": true }
            }"#,
        )
        .unwrap();
        // `endpoint_independent_nat: false` is unset, as in sing-box.
        assert_eq!(
            config.warnings,
            ["inbounds[0].stack: sail does not implement this field; ignored"]
        );
        let settings = options(&config.inbounds[0]).unwrap();
        assert_eq!(settings.name, "tun0");
        assert!(settings.ipv4.is_some() && settings.ipv6.is_some());
        assert_eq!(
            config.inbounds[0].udp_timeout(),
            std::time::Duration::from_secs(300)
        );

        // Fields that choose which traffic enters the TUN are not ignored:
        // without auto_route, which takes it, they are an error.
        let config = crate::config::Config::from_json(
            r#"{ "inbounds": [{ "type": "tun", "address": "172.18.0.1/30", "route_address": "10.0.0.0/8" }] }"#,
        )
        .unwrap();
        let err = options(&config.inbounds[0]).unwrap_err().to_string();
        assert!(
            err.contains("route_address") && err.contains("auto_route"),
            "{err}"
        );
        // strict_route too, where sing-box acts on it; elsewhere it is taken
        // and changes nothing, as in sing-box.
        let config = crate::config::Config::from_json(
            r#"{ "inbounds": [{ "type": "tun", "address": "172.18.0.1/30", "auto_route": true, "strict_route": true }] }"#,
        )
        .unwrap();
        assert!(options(&config.inbounds[0])
            .unwrap()
            .auto_redirect
            .is_none());
    }

    #[test]
    fn uid_ranges_and_marks_read_as_sing_box_writes_them() {
        assert_eq!(
            uid_ranges(&[0, 7], &["1000:1999".into()], "include_uid").unwrap(),
            [0..=0, 7..=7, 1000..=1999]
        );
        for (range, mentions) in [
            ("1000", "missing ':'"),
            ("9:1", "ends before"),
            ("a:b", "not a uid"),
        ] {
            let err = uid_ranges(&[], &[range.into()], "exclude_uid").unwrap_err();
            assert!(err.contains(mentions), "{range}: {err}");
        }
        #[derive(serde_derive::Deserialize)]
        struct Mark {
            #[serde(default, with = "fw_mark")]
            mark: Option<u32>,
        }
        let mark = |json: &str| serde_json::from_str::<Mark>(json).map(|m| m.mark);
        assert_eq!(mark(r#"{ "mark": "0x2023" }"#).unwrap(), Some(0x2023));
        assert_eq!(mark(r#"{ "mark": 8228 }"#).unwrap(), Some(8228));
        assert_eq!(mark(r#"{ "mark": "8228" }"#).unwrap(), Some(8228));
        assert_eq!(mark(r#"{ "mark": 0 }"#).unwrap(), None);
        assert!(mark(r#"{ "mark": "0xzz" }"#).is_err());
    }

    #[test]
    fn auto_redirect_needs_auto_route_and_what_it_enforces_needs_it() {
        let err = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_redirect": true
        })))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("`auto_route` is required by `auto_redirect`"),
            "{err}"
        );
        // With auto_route alone: the routes take route_address on Linux and
        // macOS, Linux's rules the uids; elsewhere they are refused, as
        // ignoring them would take in what they leave out.
        for (field, value, elsewhere, here) in [
            (
                "route_address",
                serde_json::json!("10.0.0.0/8"),
                "route management",
                cfg!(any(
                    target_os = "linux",
                    target_os = "macos",
                    target_os = "windows"
                )),
            ),
            (
                "include_uid",
                serde_json::json!(1000),
                "only on Linux; ignoring it would send traffic the config excludes",
                cfg!(target_os = "linux"),
            ),
        ] {
            let taken = options(&tun(serde_json::json!({
                "address": "172.19.0.1/30", "auto_route": true, field: value
            })));
            if here {
                taken.unwrap();
            } else {
                let err = taken.unwrap_err().to_string();
                assert!(err.contains(field) && err.contains(elsewhere), "{err}");
            }
        }
        // loopback_address sail takes with auto_redirect only, where
        // sing-box's stacks act on it too: not ignored.
        let err = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_route": true,
            "loopback_address": "10.7.0.1"
        })))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("loopback_address") && err.contains("auto_redirect only"),
            "{err}"
        );
    }

    /// What only auto_redirect reads changes nothing without it: sing-box
    /// takes it and ignores it (sing-tun reads it in its redirect files
    /// only), and sail warns of it.
    #[test]
    fn what_auto_redirect_reads_is_ignored_without_it() {
        let settings = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_route": true,
            "auto_redirect_input_mark": "0x100", "auto_redirect_output_mark": "0x101",
            "auto_redirect_reset_mark": "0x102", "auto_redirect_nfqueue": 7,
            "auto_redirect_iproute2_fallback_rule_index": 30000, "exclude_mptcp": true
        })))
        .unwrap();
        assert!(settings.auto_redirect.is_none());
        let why = "only used with auto_redirect";
        assert_eq!(
            settings.ignored,
            [
                ("exclude_mptcp", why),
                ("auto_redirect_input_mark", why),
                ("auto_redirect_output_mark", why),
                ("auto_redirect_reset_mark", why),
                ("auto_redirect_nfqueue", why),
                ("auto_redirect_iproute2_fallback_rule_index", why),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_redirect_takes_sing_box_s_defaults_and_fields() {
        let settings = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_route": true, "auto_redirect": true
        })))
        .unwrap();
        let redirect = settings.auto_redirect.unwrap();
        assert_eq!(
            (
                redirect.input_mark,
                redirect.output_mark,
                redirect.reset_mark
            ),
            (0x2023, 0x2024, 0x2025)
        );
        assert_eq!(redirect.nfqueue, 100);
        assert_eq!(
            (
                settings.route.table_index,
                settings.route.rule_index,
                redirect.fallback_rule_index
            ),
            (2022, 9000, 32768)
        );

        let settings = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_route": true, "auto_redirect": true,
            "auto_redirect_output_mark": "0x99", "auto_redirect_nfqueue": 7,
            "route_address": ["10.0.0.0/8", "fd00::/8"], "exclude_interface": "docker0",
            "exclude_uid": 1000, "exclude_uid_range": ["2000:2999"],
            "loopback_address": "10.7.0.1", "strict_route": true
        })))
        .unwrap();
        let redirect = settings.auto_redirect.unwrap();
        assert_eq!(redirect.output_mark, 0x99);
        assert_eq!(redirect.nfqueue, 7);
        assert_eq!(settings.route.route_address.len(), 2);
        assert_eq!(settings.route.exclude_interface, ["docker0"]);
        assert_eq!(settings.route.exclude_uid, [1000..=1000, 2000..=2999]);
        assert!(settings.route.strict_route);

        let err = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_route": true, "auto_redirect": true,
            "include_interface": "eth0", "exclude_interface": "eth1"
        })))
        .unwrap_err()
        .to_string();
        assert!(err.contains("exclude each other"), "{err}");
    }

    /// The iproute2 indexes number Linux's ip rules, which auto_route
    /// adds. Elsewhere, or without auto_route, sing-box takes them and does
    /// nothing with them: sail warns of them, as a configuration written
    /// for every system sets them.
    #[test]
    fn iproute2_indexes_are_ignored_where_they_change_nothing() {
        for auto_route in [true, false] {
            let settings = options(&tun(serde_json::json!({
                "address": "172.19.0.1/30", "auto_route": auto_route,
                "iproute2_table_index": 2100, "iproute2_rule_index": 9100
            })))
            .unwrap();
            let why = match (cfg!(target_os = "linux"), auto_route) {
                (true, true) => {
                    assert!(settings.ignored.is_empty());
                    assert_eq!(settings.route.table_index, 2100);
                    assert_eq!(settings.route.rule_index, 9100);
                    continue;
                }
                (true, false) => "only used with auto_route",
                (false, _) => "Linux only",
            };
            assert_eq!(
                settings.ignored,
                [("iproute2_table_index", why), ("iproute2_rule_index", why)]
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn auto_redirect_is_linux_only() {
        let err = options(&tun(serde_json::json!({
            "address": "172.19.0.1/30", "auto_route": true, "auto_redirect": true
        })))
        .unwrap_err()
        .to_string();
        assert!(err.contains("Linux only"), "{err}");
    }

    /// A name is settled before anything reads it: on macOS one past the
    /// highest utunN, kept across reloads; a configured one as it is.
    #[test]
    fn a_tun_s_name_is_settled_at_start_and_kept() {
        use std::collections::BTreeMap;
        let host = crate::runtime::Host::default();
        let unnamed = |tag: &str| Inbound {
            tag: tag.into(),
            ..tun(serde_json::json!({ "address": "172.19.0.1/30" }))
        };
        let named = |tag: &str, name: &str| Inbound {
            tag: tag.into(),
            ..tun(serde_json::json!({ "address": "172.19.0.1/30", "interface_name": name }))
        };
        let existing = [
            "lo0".to_string(),
            "utun3".into(),
            "utun7".into(),
            "en0".into(),
        ];
        let name_of = |i: &Inbound| i.options["interface_name"].as_str().unwrap().to_owned();

        // Chosen past the highest, past a configured one too, and written in.
        let mut inbounds = vec![unnamed("a"), named("b", "utun9"), unnamed("c")];
        let names = resolve_names_among(&mut inbounds, &BTreeMap::new(), &host, true, &existing);
        assert_eq!(name_of(&inbounds[0]), "utun10");
        assert_eq!(name_of(&inbounds[1]), "utun9");
        assert_eq!(name_of(&inbounds[2]), "utun11");
        assert!(names["a"].chosen && !names["b"].chosen);

        // A reload keeps a chosen name, though its utun now exists.
        let mut existing = existing.to_vec();
        existing.push("utun10".into());
        let mut reloaded = vec![unnamed("a")];
        let again = resolve_names_among(&mut reloaded, &names, &host, true, &existing);
        assert_eq!(again["a"], names["a"]);

        // Unset to configured: the configured one; and back: kept.
        let mut configured = vec![named("a", "utun20")];
        let names = resolve_names_among(&mut configured, &again, &host, true, &existing);
        assert_eq!(
            names["a"],
            TunName {
                name: "utun20".into(),
                chosen: false
            }
        );
        let mut unset = vec![unnamed("a")];
        let names = resolve_names_among(&mut unset, &names, &host, true, &existing);
        assert_eq!(name_of(&unset[0]), "utun20");
        assert!(!names["a"].chosen);

        // Elsewhere, the default, written in all the same.
        let mut elsewhere = vec![unnamed("a")];
        let names = resolve_names_among(&mut elsewhere, &BTreeMap::new(), &host, false, &existing);
        assert_eq!(names["a"].name, DEFAULT_NAME);
        assert_eq!(name_of(&elsewhere[0]), DEFAULT_NAME);
    }

    /// A name sail chose that another program takes before it opens is
    /// given up for the next free one, three names at most; a configured
    /// one fails at once. Either way the failure is a TunNameTaken.
    #[test]
    fn a_chosen_name_taken_in_between_is_chosen_again() {
        let busy = || std::io::Error::from(std::io::ErrorKind::ResourceBusy);
        let existing = || vec!["utun0".to_string(), "utun3".into()];

        // Taken once: the next one past it.
        let mut tries = Vec::new();
        let (_, name) = open_named("t", "utun4", true, existing, |name| {
            tries.push(name.to_owned());
            if tries.len() == 1 {
                Err(busy())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(tries, ["utun4", "utun5"]);
        assert_eq!(name, "utun5");

        // Taken each time: three names, then a TunNameTaken.
        let mut tries = Vec::new();
        let err = open_named(
            "t",
            "utun4",
            true,
            existing,
            |name| -> std::io::Result<()> {
                tries.push(name.to_owned());
                Err(busy())
            },
        )
        .unwrap_err();
        assert_eq!(tries, ["utun4", "utun5", "utun6"]);
        assert_eq!(
            err.downcast_ref::<TunNameTaken>(),
            Some(&TunNameTaken {
                tag: "t".into(),
                name: "utun6".into(),
                chosen: true,
                attempts: 3
            })
        );

        // Configured: no second name.
        let mut tries = 0;
        let err = open_named("t", "utun9", false, existing, |_| -> std::io::Result<()> {
            tries += 1;
            Err(busy())
        })
        .unwrap_err();
        assert_eq!(tries, 1);
        assert!(!err.downcast_ref::<TunNameTaken>().unwrap().chosen);

        // Another failure is not a name's.
        let err = open_named("t", "utun4", true, existing, |_| -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert!(err.downcast_ref::<TunNameTaken>().is_none());
    }

    #[test]
    fn leaf_s_fields_are_mistakes() {
        for field in [
            "fd",
            "auto",
            "gateway_mode",
            "name",
            "netmask",
            "gateway",
            "wintun",
        ] {
            let err = options(&tun(serde_json::json!({
                "address": "172.19.0.1/30",
                field: serde_json::Value::Null
            })))
            .unwrap_err()
            .to_string();
            assert!(err.contains(field), "{field}: {err}");
        }
    }

    /// A reply goes back on the flow the client sent to its source on;
    /// from any other source, on the client's last flow only when
    /// filtering is endpoint-independent, and never to another client.
    #[test]
    fn a_reply_from_an_address_never_sent_to_needs_endpoint_independence() {
        use sail_netstack::{FlowId, NetworkGeneration};
        let token = |n| UdpFlowToken::new(FlowId::new(n), NetworkGeneration::new(1));
        let app: SocketAddr = "10.213.0.1:5000".parse().unwrap();
        let other_app: SocketAddr = "10.213.0.1:5001".parse().unwrap();
        let first: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let stranger: SocketAddr = "198.51.100.9:9".parse().unwrap();
        for endpoint_independent in [false, true] {
            let mut flows = ReplyFlows::new(8, endpoint_independent);
            flows.sent(app, first, token(1));
            flows.sent(app, second, token(2));
            assert_eq!(flows.for_reply(app, first), Some(token(1)));
            assert_eq!(flows.for_reply(app, second), Some(token(2)));
            assert_eq!(
                flows.for_reply(app, stranger),
                endpoint_independent.then(|| token(2)),
                "the flow sent on last, with endpoint independence"
            );
            assert_eq!(flows.for_reply(other_app, stranger), None);
        }
    }

    /// `udp_filtering` and the older `endpoint_independent_nat` say the
    /// same thing; they may not disagree, and what sail does not filter by
    /// is an error.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn udp_filtering_and_its_older_name_agree() {
        use serde_json::json;
        let read = |extra: serde_json::Value| {
            let mut tun_options = json!({ "address": "172.19.0.1/30" });
            tun_options
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            options(&tun(tun_options))
                .map(|s| s.endpoint_independent_nat)
                .map_err(|e| format!("{e:#}"))
        };
        assert_eq!(read(json!({})), Ok(false));
        assert_eq!(read(json!({ "endpoint_independent_nat": true })), Ok(true));
        assert_eq!(
            read(json!({ "udp_filtering": "endpoint_independent" })),
            Ok(true)
        );
        assert_eq!(
            read(json!({ "udp_filtering": "address_and_port_dependent" })),
            Ok(false)
        );
        assert_eq!(
            read(
                json!({ "udp_filtering": "endpoint_independent", "endpoint_independent_nat": true })
            ),
            Ok(true)
        );
        for (extra, part) in [
            (
                json!({ "udp_filtering": "endpoint_independent", "endpoint_independent_nat": false }),
                "disagree",
            ),
            (
                json!({ "udp_filtering": "address_dependent" }),
                "not implemented",
            ),
            (json!({ "udp_filtering": "x" }), "is none of"),
        ] {
            let err = read(extra).unwrap_err();
            assert!(err.contains(part), "{err}");
        }
    }

    /// `multi_queue` is off by default; on, it is a Linux device's, and
    /// elsewhere warned of and ignored, as sing-box supports it on Linux
    /// alone.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn multi_queue_is_off_by_default_and_linux_only() {
        use serde_json::json;
        let off = options(&tun(json!({ "address": "172.19.0.1/30" }))).unwrap();
        assert!(!off.multi_queue);
        let on = options(&tun(
            json!({ "address": "172.19.0.1/30", "multi_queue": true }),
        ))
        .unwrap();
        assert!(on.multi_queue);
        let warned = on.ignored.iter().any(|(field, _)| *field == "multi_queue");
        assert_eq!(warned, !cfg!(target_os = "linux"));
    }
}
