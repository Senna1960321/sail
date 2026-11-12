//! The network the host is on: its type, Wi-Fi name, gateway and carrier,
//! which rules (`wifi_ssid`, `network_type`, …) and `network` groups
//! match, and on whose change connections are reset. The host pushes it
//! (FFI, the runtime API); without a push, sail detects what the system
//! tells it. One state and one notice of change for all of sail.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

use crate::net::dial::Egress;

/// The kind of network, as sing-box names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// What is known of the network. What is not known is `None`, and a
/// condition on it does not match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkState {
    /// The interface of the default route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Its index and MTU, which sail finds itself: a host does not push
    /// them.
    #[serde(skip)]
    pub index: Option<u32>,
    #[serde(skip)]
    pub mtu: Option<u32>,
    /// Its addresses, with their prefixes (`192.168.1.2/24`): a new lease
    /// or IPv6 prefix on the same interface is a change of network too.
    #[serde(default, with = "inets", skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<cidr::IpInet>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<NetworkType>,
    /// The Wi-Fi network's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// The Wi-Fi access point's address, `aa:bb:cc:dd:ee:ff`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    /// The default gateway (the router).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// The cellular carrier, its MCC and MNC as one string of digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcc_mnc: Option<String>,
    /// Metered, as the system says (a cellular network or a hotspot).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expensive: bool,
    /// In a low data mode, as the system says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub constrained: bool,
    /// Behind a captive portal, as the host says: every connection goes
    /// straight out, whatever the rules say, until it clears, for the user
    /// to log in. sail does not look for one itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub captive: bool,
    /// Every interface sail may dial out of, the default's among them
    /// (named by `interface`), for a connection's choice of network. The
    /// fields above describe the default network and are what rules and a
    /// change of network go by; these are for that choice alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<NetworkInterface>,
}

/// One of the host's interfaces, as sing-box's network manager lists them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    pub name: String,
    /// Its index, which sail finds itself: a host does not push it.
    #[serde(skip)]
    pub index: Option<u32>,
    #[serde(rename = "type")]
    pub kind: NetworkType,
    /// Its addresses, with their prefixes.
    #[serde(default, with = "inets", skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<cidr::IpInet>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expensive: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub constrained: bool,
}

impl NetworkState {
    /// Whether going to `other` is a move, which some connections may not
    /// survive: the default interface, its index, gateway or kind differ,
    /// or one of its addresses' networks (IPv6 by /64, as sing-box
    /// compares them) is gone. An address added (a new /64, SLAAC) is not:
    /// the state rules see changes, and no connection is closed. Nor is a
    /// new SSID or access point on the same interface and addresses (a
    /// roam). Losing the default interface, and getting one back, are.
    /// Which connections a move closes is `NetworkChange::closes`.
    pub fn moved_to(&self, other: &NetworkState) -> bool {
        self.interface != other.interface
            || self.index != other.index
            || self.gateway != other.gateway
            || self.kind != other.kind
            || gone(&self.addresses, &other.addresses)
    }

    /// Whether `ip` is an address of this network: of the default
    /// interface or of one listed.
    fn has_address(&self, ip: IpAddr) -> bool {
        self.addresses
            .iter()
            .chain(self.interfaces.iter().flat_map(|i| &i.addresses))
            .any(|inet| inet.address() == ip)
    }

    /// The index and addresses of the interface named `name`: listed, or
    /// the default one.
    fn interface_named(&self, name: &str) -> Option<(Option<u32>, &[cidr::IpInet])> {
        if let Some(interface) = self.interfaces.iter().find(|i| i.name == name) {
            return Some((interface.index, &interface.addresses));
        }
        (self.interface.as_deref() == Some(name)).then_some((self.index, &self.addresses[..]))
    }

    /// What of `moved_to`'s fields differ going to `other`, each `name
    /// old→new`, for the log: what made a change one the connections do
    /// not survive.
    pub fn differences(&self, other: &NetworkState) -> Vec<String> {
        let mut differ = Vec::new();
        let mut field = |name: &str, old: String, new: String| {
            if old != new {
                differ.push(format!("{}={}→{}", name, old, new));
            }
        };
        let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "none".into());
        field("interface", opt(&self.interface), opt(&other.interface));
        field(
            "index",
            format!("{:?}", self.index),
            format!("{:?}", other.index),
        );
        field(
            "gateway",
            format!("{:?}", self.gateway),
            format!("{:?}", other.gateway),
        );
        field(
            "type",
            format!("{:?}", self.kind),
            format!("{:?}", other.kind),
        );
        let list = |a: &[cidr::IpInet]| {
            let networks: Vec<String> = networks(a).iter().map(IpAddr::to_string).collect();
            format!("[{}]", networks.join(" "))
        };
        field("networks", list(&self.addresses), list(&other.addresses));
        differ
    }

    /// Reads a state as a host writes it (JSON), the BSSID normalized.
    pub fn from_json(json: &str) -> Result<NetworkState> {
        let de = &mut serde_json::Deserializer::from_str(json);
        let state: NetworkState = serde_path_to_error::deserialize(de)
            .map_err(|e| anyhow!("network state: {}: {}", e.path(), e.inner()))?;
        state.normalized()
    }

    /// The same state, its BSSID written `aa:bb:cc:dd:ee:ff`, empty
    /// strings taken as unknown, and a carrier code of digits only; its
    /// interfaces each named once, the default among them.
    pub fn normalized(mut self) -> Result<NetworkState> {
        let empty = |s: &mut Option<String>| {
            if s.as_deref().is_some_and(|s| s.trim().is_empty()) {
                *s = None;
            }
        };
        empty(&mut self.interface);
        empty(&mut self.ssid);
        empty(&mut self.bssid);
        empty(&mut self.mcc_mnc);
        if let Some(bssid) = &self.bssid {
            self.bssid =
                Some(normalize_bssid(bssid).ok_or_else(|| {
                    anyhow!("network state: bssid: {:?} is no MAC address", bssid)
                })?);
        }
        if let Some(code) = &self.mcc_mnc {
            if !(5..=6).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
                return Err(anyhow!(
                    "network state: mcc_mnc: {:?} is not an MCC and MNC, 5 or 6 digits",
                    code
                ));
            }
        }
        let mut names = std::collections::HashSet::new();
        for (i, interface) in self.interfaces.iter().enumerate() {
            if interface.name.trim().is_empty() {
                return Err(anyhow!("network state: interfaces[{}].name: empty", i));
            }
            if !names.insert(interface.name.as_str()) {
                return Err(anyhow!(
                    "network state: interfaces[{}].name: {:?} is listed twice",
                    i,
                    interface.name
                ));
            }
        }
        if let Some(default) = &self.interface {
            if !self.interfaces.is_empty() && !names.contains(default.as_str()) {
                return Err(anyhow!(
                    "network state: interface: {:?} is not in interfaces",
                    default
                ));
            }
        }
        Ok(self)
    }
}

/// Addresses written `address/prefix`, or a bare address as a host one.
mod inets {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(inets: &[cidr::IpInet], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(inets.iter().map(ToString::to_string))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<cidr::IpInet>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| {
                s.parse::<cidr::IpInet>()
                    .or_else(|_| s.parse::<std::net::IpAddr>().map(cidr::IpInet::new_host))
                    .map_err(|_| serde::de::Error::custom(format!("{:?} is no address", s)))
            })
            .collect()
    }
}

/// `bssid` as `aa:bb:cc:dd:ee:ff`: from that form in any case, with `-`
/// between the bytes, or as 12 hex digits, as sing-box takes it; else
/// none.
pub fn normalize_bssid(bssid: &str) -> Option<String> {
    let bssid = bssid.trim();
    let hex: String = match bssid.len() {
        12 => bssid.to_string(),
        17 => {
            let sep = bssid.as_bytes()[2];
            if sep != b':' && sep != b'-' {
                return None;
            }
            let parts: Vec<&str> = bssid.split(sep as char).collect();
            if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
                return None;
            }
            parts.concat()
        }
        _ => return None,
    };
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|b| std::str::from_utf8(b).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The addresses as far as a change of network goes: IPv4 whole, IPv6 by
/// its /64, sorted.
/// Whether a network of `old`'s is not one of `new`'s.
fn gone(old: &[cidr::IpInet], new: &[cidr::IpInet]) -> bool {
    let new = networks(new);
    networks(old).iter().any(|n| !new.contains(n))
}

fn networks(addresses: &[cidr::IpInet]) -> Vec<IpAddr> {
    let mut networks: Vec<IpAddr> = addresses
        .iter()
        .map(|inet| match inet.address() {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
            v4 => v4,
        })
        .collect();
    networks.sort();
    networks.dedup();
    networks
}

/// How long a sleep must last for the carriers it left idle to be closed
/// on waking: sing-box's (21ba30b8c, v1.14.3: on iOS most sleeps, for a
/// push or a background task, last less). A shorter sleep closes nothing.
pub const CLOSE_IDLE_AFTER_SLEEP: std::time::Duration = std::time::Duration::from_secs(120);

/// What made sail look at the network again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeReason {
    /// The interface of the default route changed.
    DefaultInterface,
    /// What sail detects of the network changed.
    State,
    /// The host told it.
    HostPush,
    /// The system woke from sleep: no change of network by itself, which
    /// closes nothing, the time asleep told with it (`Network::last_sleep`).
    Wake,
}

impl std::fmt::Display for ChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChangeReason::DefaultInterface => "default-interface",
            ChangeReason::State => "state",
            ChangeReason::HostPush => "host",
            ChangeReason::Wake => "wake",
        })
    }
}

/// A change of network that the connections made on the one before do not
/// survive: what the instance then drops and makes anew.
#[derive(Clone, Debug)]
pub struct NetworkChange {
    /// Counts the changes since the instance started, from 1.
    pub generation: u64,
    pub reason: ChangeReason,
    pub old: Arc<NetworkState>,
    pub new: Arc<NetworkState>,
}

impl NetworkChange {
    /// Whether a connection that went out `egress` from `local` (each as
    /// its dialer recorded it, if it did) does not survive this change:
    /// - one bound to an interface, when that interface is gone or has
    ///   another index, or no longer has its address;
    /// - one on the default route (or not known to be bound), when the
    ///   default interface, its index, gateway or kind changed, or its
    ///   address is on no interface now;
    /// - one through a tunnel endpoint's stack, never: the endpoint binds
    ///   anew and its peer learns the new address from the next packet,
    ///   as over the kernel's WireGuard.
    ///
    /// Without its address (UDP, a connection not yet made), an address
    /// gone counts as its own. A change with nothing different, a wake or the host's word with
    /// nothing pushed before it, is one sail cannot see into: every
    /// connection goes.
    pub fn closes(&self, egress: Option<&Egress>, local: Option<IpAddr>) -> bool {
        let (old, new) = (&*self.old, &*self.new);
        if old.differences(new).is_empty() {
            return true;
        }
        match egress {
            Some(Egress::Interface { name, index }) => {
                let Some((index_now, addresses)) = new.interface_named(name) else {
                    return true;
                };
                if index.is_some() && index_now.is_some() && index_now != *index {
                    return true;
                }
                match local {
                    Some(ip) => !addresses.iter().any(|inet| inet.address() == ip),
                    None => old
                        .interface_named(name)
                        .is_none_or(|(_, before)| gone(before, addresses)),
                }
            }
            Some(Egress::Tunnel { .. }) => false,
            Some(Egress::DefaultRoute) | None => {
                if old.interface != new.interface
                    || old.index != new.index
                    || old.gateway != new.gateway
                    || old.kind != new.kind
                {
                    return true;
                }
                match local {
                    Some(ip) => !new.has_address(ip),
                    None => gone(&old.addresses, &new.addresses),
                }
            }
        }
    }
}

/// How soon after a pushed state the host's word that the network changed
/// is taken as about it (judgment: hosts say both in one callback, as the
/// emulator's test host does within a millisecond; a word later than this
/// is a change of its own).
const FOLDED_WITHIN: std::time::Duration = std::time::Duration::from_secs(2);

/// The state now, and the generation of the last change it came after, 0
/// before any: taken together, so that one does not run ahead of the other.
#[derive(Clone, Debug, Default)]
pub struct Current {
    pub state: Arc<NetworkState>,
    pub generation: u64,
}

/// How many changes a subscriber of `change_events` may fall behind by
/// before it is told it lagged: changes come seconds apart at most, a
/// burst (down, then up) a handful.
pub(crate) const EVENTS: usize = 64;

/// The instance's network, kept across reloads: its state now, and a
/// notice to whoever subscribed when it changes.
#[derive(Clone)]
pub struct Network {
    state: Arc<watch::Sender<Current>>,
    /// The last change the connections do not survive.
    changes: Arc<watch::Sender<Option<Arc<NetworkChange>>>>,
    /// The generation of the last change `follow_network_changes` has fully
    /// handled: a caller that announced a change waits on it, so the call
    /// returns with the old network torn down, not merely told.
    handled: Arc<watch::Sender<u64>>,
    /// Every such change, in order.
    events: Arc<broadcast::Sender<Arc<NetworkChange>>>,
    /// Held while a change is made and told, and while a subscriber takes
    /// the state and its events together.
    telling: Arc<Mutex<()>>,
    /// Whether a state was ever set: the first is no change of network.
    known: Arc<AtomicBool>,
    /// Whether the host pushes the state, which detection then leaves.
    pushed: Arc<AtomicBool>,
    /// Exact host input for egress. The public/rule snapshot may filter
    /// owned interfaces; that must not permanently erase host declarations.
    host_egress: Arc<arc_swap::ArcSwapOption<NetworkState>>,
    /// When the host last pushed a state, until its word that the network
    /// changed comes: that word is about this state, handled already.
    pushed_at: Arc<Mutex<Option<std::time::Instant>>>,
    /// The interfaces sail makes itself (its TUNs'), never listed as ones
    /// to go out of.
    own: Arc<Mutex<OwnedInterfaces>>,
    /// Static configuration uses the same exact-name leases; replacing it
    /// cannot clear a still-published dynamic device's registration.
    configured_own: Arc<Mutex<Vec<OwnedInterfaceLease>>>,
    /// Since when the host says the system sleeps, while it does.
    asleep_since: Arc<Mutex<Option<std::time::SystemTime>>>,
    /// Whether the host tells sail of sleeps, which detection then leaves.
    host_tells_sleep: Arc<AtomicBool>,
    /// How long the system slept before its last wake.
    last_sleep: Arc<Mutex<Option<std::time::Duration>>>,
}

/// One linearized view for automatic egress; no OS fallback is added to
/// a host-provided state. Owned names are an exact exclusion, not a prefix.
pub(crate) struct EgressView {
    pub host: Option<Arc<NetworkState>>,
    pub own: Vec<String>,
}

#[derive(Default)]
struct OwnedInterfaces {
    next_id: u64,
    epoch: u64,
    names: BTreeMap<u64, String>,
}

impl OwnedInterfaces {
    fn advance(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("owned-interface epoch");
    }

    fn names(&self) -> Vec<String> {
        self.names.values().cloned().collect()
    }
}

/// One exact-name registration in one run's network. Not Clone: its owner
/// keeps it until the published device's resources are really released.
/// It retains only the small registry and fence, not the runtime or SDK.
pub(crate) struct OwnedInterfaceLease {
    own: Arc<Mutex<OwnedInterfaces>>,
    telling: Arc<Mutex<()>>,
    id: u64,
}

impl Drop for OwnedInterfaceLease {
    fn drop(&mut self) {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        let mut own = self.own.lock().unwrap_or_else(|e| e.into_inner());
        if own.names.remove(&self.id).is_some() {
            own.advance();
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Network {
            state: Arc::new(watch::Sender::new(Current::default())),
            changes: Arc::new(watch::Sender::new(None)),
            handled: Arc::new(watch::Sender::new(0)),
            events: Arc::new(broadcast::Sender::new(EVENTS)),
            telling: Arc::default(),
            known: Arc::default(),
            pushed: Arc::default(),
            host_egress: Arc::default(),
            pushed_at: Arc::default(),
            own: Arc::default(),
            configured_own: Arc::default(),
            asleep_since: Arc::default(),
            host_tells_sleep: Arc::default(),
            last_sleep: Arc::default(),
        }
    }
}

impl Network {
    /// A network that tells its changes on `events`, a channel that may
    /// outlive it (an embedding instance's, through its runs).
    pub(crate) fn telling_to(events: broadcast::Sender<Arc<NetworkChange>>) -> Self {
        Network {
            events: Arc::new(events),
            ..Default::default()
        }
    }
}

impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("pushed", &self.pushed.load(Ordering::Relaxed))
            .finish()
    }
}

impl Network {
    /// Whether `other` is this network: a clone of it.
    pub fn is(&self, other: &Network) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// The state now.
    pub fn snapshot(&self) -> Arc<NetworkState> {
        self.state.borrow().state.clone()
    }

    /// The state now with the generation of the last change it came after.
    pub fn snapshot_with_generation(&self) -> Current {
        self.state.borrow().clone()
    }

    /// Tells of each change of state from now on: rules that match the
    /// network take every one.
    pub fn subscribe(&self) -> watch::Receiver<Current> {
        self.state.subscribe()
    }

    /// Tells of each change that connections do not survive, from now on:
    /// the instance drops what was of the network before. The last one
    /// only: a reader that is slow sees the latest.
    pub fn changes(&self) -> watch::Receiver<Option<Arc<NetworkChange>>> {
        self.changes.subscribe()
    }

    /// Every change that connections do not survive, in order, from now
    /// on; a subscriber more than 64 behind is told it lagged.
    pub fn change_events(&self) -> broadcast::Receiver<Arc<NetworkChange>> {
        self.events.subscribe()
    }

    /// The state now, and every change after it, taken together: the
    /// events are those whose generation is past the state's, none
    /// missed and none the state already holds.
    pub fn state_and_events(&self) -> (Current, broadcast::Receiver<Arc<NetworkChange>>) {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        (self.state.borrow().clone(), self.events.subscribe())
    }

    pub(crate) fn egress_view(&self) -> EgressView {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        EgressView {
            host: self.host_egress.load_full(),
            own: self.own.lock().unwrap_or_else(|e| e.into_inner()).names(),
        }
    }

    /// The slow OS lookup has finished; publish only if it still has
    /// authority. Recheck owned names at publication, not at lookup start.
    pub(crate) fn publish_automatic<T>(&self, publish: impl FnOnce(&[String]) -> T) -> Option<T> {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        if self.pushed() {
            return None;
        }
        let own = self.own.lock().unwrap_or_else(|e| e.into_inner()).names();
        Some(publish(&own))
    }

    /// Tells of a change whatever the state says: the host says the network
    /// changed, or the system woke. Returns the generation the change took,
    /// or None when the word folded into a pushed state told already (the
    /// generation to wait on is the state's then, `snapshot_with_generation`).
    pub fn announce(&self, reason: ChangeReason) -> Option<u64> {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        // A delayed OS/capture notice cannot reset a host-owned network,
        // nor consume the folding token for an explicit host notification.
        if self.pushed() && matches!(reason, ChangeReason::DefaultInterface | ChangeReason::State) {
            return None;
        }
        // The host's word right after the state it pushed is about that
        // state, which sail handled as it came: folded into it.
        let pushed_at = self
            .pushed_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if reason == ChangeReason::HostPush
            && pushed_at.is_some_and(|at| at.elapsed() < FOLDED_WITHIN)
        {
            drop(_telling);
            tracing::debug!(
                "network changed: the host's word, after the state it pushed; folded into it"
            );
            return None;
        }
        let mut change = None;
        self.state.send_modify(|current| {
            current.generation += 1;
            change = Some(NetworkChange {
                generation: current.generation,
                reason,
                old: current.state.clone(),
                new: current.state.clone(),
            });
        });
        let change = change.expect("set in send_modify");
        let generation = change.generation;
        self.tell(change);
        Some(generation)
    }

    /// Marks `generation` handled: what the change drops is dropped, and a
    /// caller waiting on `wait_handled` for it or an older one goes on.
    pub(crate) fn mark_handled(&self, generation: u64) {
        self.handled.send_modify(|handled| {
            if generation > *handled {
                *handled = generation;
            }
        });
    }

    /// Waits until the change `generation` has been handled, without a
    /// bound of its own: callers that need one put a timeout around it.
    /// The host's word through the TUN inbound is its only caller.
    #[cfg(feature = "inbound-tun")]
    pub(crate) async fn wait_handled(&self, generation: u64) {
        let mut handled = self.handled.subscribe();
        loop {
            if *handled.borrow() >= generation {
                return;
            }
            // None left to handle any change: never satisfied, stop waiting.
            if handled.changed().await.is_err() {
                return;
            }
        }
    }

    /// Tells the subscribers of `change`, whose state is stored already;
    /// with `telling` held.
    fn tell(&self, change: NetworkChange) {
        let change = Arc::new(change);
        self.changes.send_replace(Some(change.clone()));
        // None subscribed is no error.
        let _ = self.events.send(change);
    }

    /// Whether there is no network: a state was known, and now nothing is,
    /// no default interface, address or type; or the host says the system
    /// sleeps. Checks and updates on a timer wait while it is, rather than
    /// find everything failing; the change that ends it (a wake among
    /// them) tells them to look again.
    pub fn is_down(&self) -> bool {
        self.asleep()
            || self.known.load(Ordering::Relaxed) && *self.snapshot() == NetworkState::default()
    }

    /// Whether the host says the system sleeps now.
    pub fn asleep(&self) -> bool {
        self.asleep_since
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// The host says the system goes to sleep. From then on the host tells
    /// sail of sleeps, and its own detection leaves them.
    pub fn sleep(&self) {
        self.host_tells_sleep.store(true, Ordering::Relaxed);
        let mut since = self.asleep_since.lock().unwrap_or_else(|e| e.into_inner());
        since.get_or_insert_with(std::time::SystemTime::now);
    }

    /// The host says the system woke: the time since its `sleep`, by the
    /// wall clock, as sing-box measures it, is the sleep. Nothing when it
    /// said no sleep.
    pub fn wake(&self) {
        let since = self
            .asleep_since
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(since) = since {
            self.woke(since.elapsed().unwrap_or_default());
        }
    }

    /// A wake sail saw itself after `asleep` (platform::sleep), unless the
    /// host tells of sleeps. Public for tests, which cannot sleep 2 minutes.
    #[doc(hidden)]
    pub fn detected_wake(&self, asleep: std::time::Duration) {
        if !self.host_tells_sleep.load(Ordering::Relaxed) {
            self.woke(asleep);
        }
    }

    fn woke(&self, asleep: std::time::Duration) {
        *self.last_sleep.lock().unwrap_or_else(|e| e.into_inner()) = Some(asleep);
        self.announce(ChangeReason::Wake);
    }

    /// How long the system slept before its last wake.
    pub fn last_sleep(&self) -> Option<std::time::Duration> {
        *self.last_sleep.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the host pushes the state.
    pub fn pushed(&self) -> bool {
        self.pushed.load(Ordering::Relaxed)
    }

    /// The state as the host tells it; what sail detects is left from then
    /// on.
    pub fn push(&self, state: NetworkState) {
        self.set(state, ChangeReason::HostPush);
    }

    /// Settles the state sail starts on, before the instance runs: `state`
    /// as detected, or no network (None, the empty state, offline). It is
    /// known from then, at generation 1, and no change is told: a host
    /// subscribes, then reads it; what detection finds later is told as
    /// any change. Nothing when a state is known already, or the host
    /// pushes the state (it is the host's to tell).
    pub fn settle_first(&self, state: Option<NetworkState>) {
        if self.pushed() {
            return;
        }
        let mut state = state.unwrap_or_default();
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        if self.pushed() || self.known.swap(true, Ordering::Relaxed) {
            return;
        }
        self.leave_own_out(&mut state);
        let state = Arc::new(state);
        self.state.send_modify(|current| {
            current.state = state;
            current.generation = 1;
        });
    }

    /// The state as sail detected it, unless the host pushes it, for
    /// `reason`; whether a change connections do not survive was told.
    pub(crate) fn detected(&self, state: NetworkState, reason: ChangeReason) -> bool {
        !self.pushed() && self.set(state, reason)
    }

    /// Names the interfaces sail makes itself, its TUNs', which a state
    /// set from now on does not list as ones a connection may go out of,
    /// as sing-box leaves its own out of the interfaces it picks from
    /// (MyInterfaces). The default interface stays listed whatever it is.
    pub(crate) fn set_own_interfaces(&self, names: Vec<String>) {
        let mut configured = self
            .configured_own
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Acquire replacements before dropping old leases: overlapping names
        // never briefly become eligible. This lock only serializes static
        // updates; egress selection never takes it.
        let replacement = names
            .iter()
            .filter(|name| !name.is_empty())
            .map(|name| self.own_interface(name))
            .collect();
        let old = std::mem::replace(&mut *configured, replacement);
        drop(configured);
        drop(old);
    }

    /// Excludes an actual, verified device name. The SDK acquires this only
    /// while publishing a successful current run/token, never for an open
    /// attempt or a packet bridge. No reset is announced on acquire/drop.
    pub(crate) fn own_interface(&self, actual_name: &str) -> OwnedInterfaceLease {
        assert!(
            !actual_name.is_empty(),
            "owned interface name must be verified"
        );
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        let mut own = self.own.lock().unwrap_or_else(|e| e.into_inner());
        own.next_id = own
            .next_id
            .checked_add(1)
            .expect("owned-interface identity");
        let id = own.next_id;
        own.names.insert(id, actual_name.to_owned());
        own.advance();
        OwnedInterfaceLease {
            own: self.own.clone(),
            telling: self.telling.clone(),
            id,
        }
    }

    /// Leaves sail's own interfaces out of `state`'s, but the default one.
    fn leave_own_out(&self, state: &mut NetworkState) {
        let own = self.own.lock().unwrap_or_else(|e| e.into_inner());
        let default = state.interface.clone();
        state.interfaces.retain(|i| {
            default.as_ref() == Some(&i.name) || !own.names.values().any(|name| name == &i.name)
        });
    }

    /// Changes the state, telling subscribers only of a change, and of a
    /// move when the connections do not survive it; whether that was told.
    fn set(&self, mut state: NetworkState, reason: ChangeReason) -> bool {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        if reason == ChangeReason::HostPush {
            self.host_egress.store(Some(Arc::new(state.clone())));
            self.pushed.store(true, Ordering::Relaxed);
            *self.pushed_at.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(std::time::Instant::now());
        } else if self.pushed() {
            return false;
        }
        self.leave_own_out(&mut state);
        let old = self.snapshot();
        // The first state known, at the start, moves nothing.
        let known = self.known.swap(true, Ordering::Relaxed);
        let changed = *old != state;
        let moved = changed && known && old.moved_to(&state);
        let mut change = None;
        if changed {
            // The state and the generation of its move, in one send.
            let state = Arc::new(state);
            self.state.send_modify(|current| {
                current.state = state.clone();
                if moved {
                    current.generation += 1;
                    change = Some(NetworkChange {
                        generation: current.generation,
                        reason,
                        old: old.clone(),
                        new: state,
                    });
                }
            });
        }
        let now = self.snapshot();
        if let Some(change) = change {
            self.tell(change);
        }
        // Publication is ordered, but host logging must not run under the
        // authority lock: a log callback may query effective egress.
        drop(_telling);
        let captive = now.captive;
        if changed && captive != old.captive {
            if captive {
                tracing::info!(
                    "network: behind a captive portal; every connection goes direct, whatever \
                     the rules say, until it clears"
                );
            } else {
                tracing::info!("network: the captive portal cleared; the rules apply again");
            }
        }
        if changed {
            tracing::info!(
                "network: {} on {} via {}",
                now.kind
                    .map(|k| format!("{:?}", k).to_ascii_lowercase())
                    .unwrap_or_else(|| "unknown".into()),
                now.interface.as_deref().unwrap_or("?"),
                now.gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "?".into()),
            );
            // A network's name says where the user is: not in the log's
            // default level.
            tracing::debug!("network: ssid {:?}, bssid {:?}", now.ssid, now.bssid);
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_s_state_is_read_and_normalized() {
        let state = NetworkState::from_json(
            r#"{ "interface": "en0", "type": "wifi", "ssid": "Home", "bssid": "AA-BB-CC-DD-EE-0F",
                 "gateway": "192.168.1.1", "addresses": ["192.168.1.2/24", "fd00::2"],
                 "expensive": true }"#,
        )
        .unwrap();
        assert_eq!(state.kind, Some(NetworkType::Wifi));
        assert_eq!(state.bssid.as_deref(), Some("aa:bb:cc:dd:ee:0f"));
        assert_eq!(state.gateway, Some("192.168.1.1".parse().unwrap()));
        assert!(state.expensive && !state.constrained);
        assert_eq!(state.addresses[1].to_string(), "fd00::2");
        let back = serde_json::to_value(&state).unwrap();
        assert_eq!(
            back["addresses"],
            serde_json::json!(["192.168.1.2/24", "fd00::2"])
        );

        let state =
            NetworkState::from_json(r#"{ "type": "cellular", "mcc_mnc": "310260", "ssid": "" }"#)
                .unwrap();
        assert_eq!(state.ssid, None);

        for (json, message) in [
            (r#"{ "type": "wired" }"#, "type"),
            (r#"{ "bssid": "aa:bb" }"#, "bssid"),
            (r#"{ "mcc_mnc": "31026x" }"#, "mcc_mnc"),
            (r#"{ "ssi": "x" }"#, "ssi"),
            (r#"{ "addresses": ["x"] }"#, "addresses"),
            (r#"{ "mtu": 1500 }"#, "mtu"),
        ] {
            let err = NetworkState::from_json(json).unwrap_err().to_string();
            assert!(err.contains(message), "{}", err);
        }
    }

    /// The host lists its interfaces, each named once and the default
    /// among them; a change to them alone is no move.
    #[test]
    fn a_host_lists_its_interfaces() {
        let state = NetworkState::from_json(
            r#"{ "interface": "wlan0", "type": "wifi",
                 "interfaces": [
                   { "name": "wlan0", "type": "wifi", "addresses": ["192.168.1.5/24"] },
                   { "name": "rmnet0", "type": "cellular", "expensive": true,
                     "addresses": ["10.1.2.3"] } ] }"#,
        )
        .unwrap();
        assert_eq!(state.interfaces.len(), 2);
        assert_eq!(state.interfaces[1].kind, NetworkType::Cellular);
        assert!(state.interfaces[1].expensive && !state.interfaces[1].constrained);
        assert_eq!(state.interfaces[1].addresses[0].to_string(), "10.1.2.3");
        let back = serde_json::to_value(&state).unwrap();
        assert_eq!(
            back["interfaces"][0],
            serde_json::json!({ "name": "wlan0", "type": "wifi", "addresses": ["192.168.1.5/24"] })
        );

        let mut fewer = state.clone();
        fewer.interfaces.pop();
        assert_ne!(state, fewer);
        assert!(!state.moved_to(&fewer));

        // Without a default named, any list goes.
        NetworkState::from_json(r#"{ "interfaces": [{ "name": "en0", "type": "ethernet" }] }"#)
            .unwrap();
        for (json, message) in [
            (
                r#"{ "interfaces": [{ "name": "en0" }] }"#,
                "interfaces[0]: missing field `type`",
            ),
            (
                r#"{ "interfaces": [{ "name": " ", "type": "wifi" }] }"#,
                "interfaces[0].name: empty",
            ),
            (
                r#"{ "interfaces": [{ "name": "en0", "type": "wifi" },
                                     { "name": "en0", "type": "ethernet" }] }"#,
                "interfaces[1].name: \"en0\" is listed twice",
            ),
            (
                r#"{ "interface": "en1", "interfaces": [{ "name": "en0", "type": "wifi" }] }"#,
                "interface: \"en1\" is not in interfaces",
            ),
            (
                r#"{ "interfaces": [{ "name": "en0", "type": "wifi", "index": 3 }] }"#,
                "index",
            ),
        ] {
            let err = NetworkState::from_json(json).unwrap_err().to_string();
            assert!(err.contains(message), "{}", err);
        }
    }

    #[test]
    fn bssids_are_one_form() {
        for bssid in [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabbccddeeff",
        ] {
            assert_eq!(normalize_bssid(bssid).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        }
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:gg",
            "aa:bbc:cd:dee:ff:0",
        ] {
            assert_eq!(normalize_bssid(bad), None, "{}", bad);
        }
    }

    #[tokio::test]
    async fn subscribers_hear_of_changes_only() {
        let network = Network::default();
        let mut changes = network.subscribe();
        let wifi = NetworkState {
            kind: Some(NetworkType::Wifi),
            ..Default::default()
        };
        network.detected(wifi.clone(), ChangeReason::State);
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        network.detected(wifi.clone(), ChangeReason::State);
        assert!(!changes.has_changed().unwrap());

        // Once the host pushes, detection is left.
        let cellular = NetworkState {
            kind: Some(NetworkType::Cellular),
            ..Default::default()
        };
        network.push(cellular.clone());
        network.detected(wifi, ChangeReason::State);
        assert_eq!(*network.snapshot(), cellular);
    }

    fn on(interface: &str, addresses: &[&str]) -> NetworkState {
        NetworkState {
            interface: Some(interface.into()),
            kind: Some(NetworkType::Wifi),
            gateway: Some("192.168.1.1".parse().unwrap()),
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            ..Default::default()
        }
    }

    fn interface(name: &str, kind: NetworkType) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            index: None,
            kind,
            addresses: Vec::new(),
            expensive: false,
            constrained: false,
        }
    }

    #[test]
    fn sail_s_own_tun_is_not_listed_to_go_out_of() {
        let network = Network::default();
        network.set_own_interfaces(vec!["utun233".into()]);
        let mut state = on("en0", &["192.168.1.2/24"]);
        state.interfaces = vec![
            interface("en0", NetworkType::Wifi),
            interface("utun233", NetworkType::Other),
            interface("utun4", NetworkType::Other),
        ];
        network.detected(state.clone(), ChangeReason::State);
        let names = |network: &Network| {
            network
                .snapshot()
                .interfaces
                .iter()
                .map(|i| i.name.clone())
                .collect::<Vec<_>>()
        };
        // Another VPN's stays, typed other.
        assert_eq!(names(&network), ["en0", "utun4"]);

        // Should the default be sail's own, it is still the default.
        state.interface = Some("utun233".into());
        network.detected(state, ChangeReason::State);
        assert_eq!(names(&network), ["en0", "utun233", "utun4"]);
    }

    #[test]
    fn what_made_a_move_is_told() {
        let state = |json: &str| NetworkState::from_json(json).unwrap();
        let old = state(r#"{"type": "wifi", "interface": "wlan0", "addresses": ["10.0.2.16/24"]}"#);
        let new = state(
            r#"{"type": "wifi", "interface": "wlan0",
                "addresses": ["10.0.2.16/24", "fec0::5054:ff:fe12:3456/64"]}"#,
        );
        assert_eq!(
            old.differences(&new),
            ["networks=[10.0.2.16]→[10.0.2.16 fec0::]"]
        );
        assert!(old.differences(&old).is_empty());
    }

    #[test]
    fn what_connections_do_not_survive_is_a_move() {
        let home = on("en0", &["192.168.1.2/24", "2001:db8:1:2::5/64"]);
        // Another interface, a new lease, another /64, another router.
        assert!(home.moved_to(&on("en1", &["192.168.1.2/24", "2001:db8:1:2::5/64"])));
        assert!(home.moved_to(&on("en0", &["192.168.1.3/24", "2001:db8:1:2::5/64"])));
        assert!(home.moved_to(&on("en0", &["192.168.1.2/24", "2001:db8:1:3::5/64"])));
        let mut router = home.clone();
        router.gateway = Some("192.168.1.254".parse().unwrap());
        assert!(home.moved_to(&router));
        // A new address in the same /64 (privacy addresses), or a roam to
        // another access point of the same network, is not.
        assert!(!home.moved_to(&on("en0", &["192.168.1.2/24", "2001:db8:1:2::77/64"])));
        let mut roamed = home.clone();
        roamed.ssid = Some("Home".into());
        roamed.bssid = Some("aa:bb:cc:dd:ee:ff".into());
        assert!(!home.moved_to(&roamed));
        // Losing the default interface is, and getting it back.
        assert!(home.moved_to(&NetworkState::default()));
        assert!(NetworkState::default().moved_to(&home));
    }

    #[test]
    fn an_address_added_is_no_move_and_one_gone_is() {
        let home = on("wlan0", &["10.0.2.16/24", "fe80::1/64"]);
        // The emulator's: a /64 comes after the Wi-Fi does.
        let more = on("wlan0", &["10.0.2.16/24", "fe80::1/64", "fec0::5/64"]);
        assert!(!home.moved_to(&more));
        assert!(more.moved_to(&home));
    }

    #[test]
    fn a_move_closes_the_connections_it_takes_the_way_or_address_of() {
        let change = |old: NetworkState, new: NetworkState| NetworkChange {
            generation: 2,
            reason: ChangeReason::HostPush,
            old: Arc::new(old),
            new: Arc::new(new),
        };
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        let wlan0 = Egress::Interface {
            name: "wlan0".into(),
            index: None,
        };
        let mut home = on("wlan0", &["192.168.1.2/24", "2001:db8:1:2::5/64"]);
        home.interfaces = vec![NetworkInterface {
            addresses: home.addresses.clone(),
            ..interface("wlan0", NetworkType::Wifi)
        }];
        // Its IPv6 /64 gone, on the same interface and router: only what
        // was made from it goes.
        let mut v4_only = on("wlan0", &["192.168.1.2/24"]);
        v4_only.interfaces = vec![NetworkInterface {
            addresses: v4_only.addresses.clone(),
            ..interface("wlan0", NetworkType::Wifi)
        }];
        let lost = change(home.clone(), v4_only);
        let default = Some(&Egress::DefaultRoute);
        assert!(!lost.closes(default, ip("192.168.1.2")));
        assert!(lost.closes(default, ip("2001:db8:1:2::5")));
        assert!(!lost.closes(Some(&wlan0), ip("192.168.1.2")));
        assert!(lost.closes(Some(&wlan0), ip("2001:db8:1:2::5")));
        // Without its address, an address gone may be its own.
        assert!(lost.closes(default, None));
        // Another default interface: what took the default route goes;
        // what is bound to wlan0, still there with its address, stays.
        let mut cellular = on("rmnet0", &["10.64.0.9/32"]);
        cellular.interfaces = home.interfaces.clone();
        cellular
            .interfaces
            .push(interface("rmnet0", NetworkType::Cellular));
        let moved = change(home.clone(), cellular);
        assert!(moved.closes(default, ip("192.168.1.2")));
        assert!(moved.closes(None, None));
        assert!(!moved.closes(Some(&wlan0), ip("192.168.1.2")));
        // wlan0 gone: what is bound to it goes too.
        let gone = change(home.clone(), on("rmnet0", &["10.64.0.9/32"]));
        assert!(gone.closes(Some(&wlan0), ip("192.168.1.2")));
        // Another kind of network on no named interface (a host that
        // tells only that): what took the default route goes.
        let wifi = NetworkState {
            kind: Some(NetworkType::Wifi),
            ..Default::default()
        };
        let cell = NetworkState {
            kind: Some(NetworkType::Cellular),
            ..Default::default()
        };
        assert!(change(wifi, cell).closes(default, None));
        // A change with nothing to see into (a wake): everything else goes.
        let wake = change(home.clone(), home);
        assert!(wake.closes(Some(&wlan0), ip("192.168.1.2")));
    }

    #[test]
    fn a_move_closes_no_connection_through_a_tunnel_endpoint_and_a_wake_does() {
        let change = |old: NetworkState, new: NetworkState| NetworkChange {
            generation: 2,
            reason: ChangeReason::HostPush,
            old: Arc::new(old),
            new: Arc::new(new),
        };
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        let tunnel = Egress::Tunnel {
            endpoint: "wg".into(),
        };
        let home = on("wlan0", &["192.168.1.2/24", "2001:db8:1:2::5/64"]);
        // Another default interface, an address gone, the network gone.
        let moves = [
            on("rmnet0", &["10.64.0.9/32"]),
            on("wlan0", &["192.168.1.2/24"]),
            NetworkState::default(),
        ];
        for new in moves {
            let moved = change(home.clone(), new);
            assert!(moved.closes(None, None), "{:?}", moved.new);
            for local in [None, ip("10.77.0.2"), ip("2001:db8:1:2::5")] {
                assert!(!moved.closes(Some(&tunnel), local), "{:?}", moved.new);
            }
        }
        // A change with nothing to see into (a wake): it goes too.
        let wake = change(home.clone(), home);
        assert!(wake.closes(Some(&tunnel), ip("10.77.0.2")));
        assert!(wake.closes(Some(&tunnel), None));
    }

    #[test]
    fn the_hosts_word_after_its_pushed_state_is_folded_into_it() {
        let network = Network::default();
        let mut changes = network.changes();
        network.push(on("wlan0", &["10.0.2.16/24"]));
        network.push(on("eth0", &["10.0.2.15/24"]));
        assert_eq!(changes.borrow_and_update().as_ref().unwrap().generation, 1);
        // The host says both in one callback: one move.
        network.announce(ChangeReason::HostPush);
        assert!(!changes.has_changed().unwrap());
        // Its word again, with nothing pushed before it, is a move of its own.
        network.announce(ChangeReason::HostPush);
        assert_eq!(changes.borrow_and_update().as_ref().unwrap().generation, 2);
        // A wake always is.
        network.push(on("wlan0", &["10.0.2.16/24"]));
        changes.borrow_and_update();
        network.announce(ChangeReason::Wake);
        assert_eq!(
            changes.borrow_and_update().as_ref().unwrap().reason,
            ChangeReason::Wake
        );
    }

    /// `announce` comes back with the generation a caller waits on: its own
    /// when a change was told, or the state's when the word folded into a
    /// pushed one, told already.
    #[test]
    fn the_hosts_word_says_which_generation_to_wait_on() {
        let network = Network::default();
        network.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        // No push before it: a change of its own.
        assert_eq!(network.announce(ChangeReason::HostPush), Some(2));
        // Folded into the pushed state: the state's generation is the one.
        network.push(on("wlan0", &["10.0.2.16/24"]));
        assert_eq!(network.announce(ChangeReason::HostPush), None);
        assert_eq!(network.snapshot_with_generation().generation, 3);
    }

    /// The wait a caller of `announce` puts on handling ends only when the
    /// change (or a newer one) has been handled.
    #[cfg(feature = "inbound-tun")]
    #[test]
    fn the_wait_on_handling_ends_when_the_change_is_marked() {
        let network = Network::default();
        network.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        let generation = network.announce(ChangeReason::HostPush).unwrap();
        assert!(
            futures::FutureExt::now_or_never(network.wait_handled(generation)).is_none(),
            "an unhandled change does not release the wait"
        );
        network.mark_handled(generation);
        futures::executor::block_on(network.wait_handled(generation));
        // A newer handled change releases an older wait.
        let generation = network.announce(ChangeReason::HostPush).unwrap();
        network.mark_handled(generation + 5);
        futures::executor::block_on(network.wait_handled(generation));
    }

    /// The host's sleep: timed work waits while it lasts, its wake is told
    /// with the time asleep, and sail's own detection of sleeps is left
    /// from then on. A wake with no sleep before it is nothing.
    #[test]
    fn the_hosts_sleep_holds_timers_and_its_wake_is_told_with_the_time() {
        let network = Network::default();
        network.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        let mut changes = network.changes();
        changes.borrow_and_update();

        // sail's own detection, before the host says anything.
        network.detected_wake(std::time::Duration::from_secs(300));
        assert_eq!(
            changes.borrow_and_update().as_ref().unwrap().reason,
            ChangeReason::Wake
        );
        assert_eq!(
            network.last_sleep(),
            Some(std::time::Duration::from_secs(300))
        );

        network.wake();
        assert!(
            !changes.has_changed().unwrap(),
            "a wake with no sleep before it"
        );
        network.sleep();
        assert!(network.asleep() && network.is_down());
        network.wake();
        assert!(!network.asleep() && !network.is_down());
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!(change.reason, ChangeReason::Wake);
        assert!(change.old.differences(&change.new).is_empty());
        assert!(network.last_sleep().unwrap() < std::time::Duration::from_secs(5));

        // The host tells of sleeps now: sail's detection is left.
        network.detected_wake(std::time::Duration::from_secs(300));
        assert!(!changes.has_changed().unwrap());
    }

    #[test]
    fn a_move_is_told_with_its_reason_and_generation() {
        let network = Network::default();
        let mut changes = network.changes();
        // The first state known, at the start, is no change.
        assert!(!network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));
        assert!(!changes.has_changed().unwrap());
        // A roam: the state changes, the connections survive.
        let mut roamed = on("en0", &["192.168.1.2/24"]);
        roamed.ssid = Some("Home".into());
        assert!(!network.detected(roamed, ChangeReason::State));
        assert!(!changes.has_changed().unwrap());

        assert!(network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::DefaultInterface));
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!(change.generation, 1);
        assert_eq!(change.reason, ChangeReason::DefaultInterface);
        assert_eq!(change.old.interface.as_deref(), Some("en0"));
        assert_eq!(change.new.interface.as_deref(), Some("en1"));

        // Losing the network, and getting it back.
        assert!(network.detected(NetworkState::default(), ChangeReason::State));
        assert!(network.is_down());
        assert!(network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::State));
        assert!(!network.is_down());
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!(change.generation, 3);
        assert_eq!(change.old.interface, None);

        // The host, or waking, tells one whatever the state.
        network.announce(ChangeReason::Wake);
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!((change.generation, change.reason), (4, ChangeReason::Wake));
        assert_eq!(change.old, change.new);
    }

    /// Two changes in quick succession, the network lost and back: a
    /// subscriber of the events, slow to read, gets both, in order, with
    /// consecutive generations, where the watch keeps only the last.
    #[test]
    fn every_change_is_an_event_in_order() {
        let network = Network::default();
        network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State);
        let mut events = network.change_events();
        let changes = network.changes();
        assert!(network.detected(NetworkState::default(), ChangeReason::State));
        assert!(network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));

        let lost = events.try_recv().unwrap();
        let back = events.try_recv().unwrap();
        assert_eq!((lost.generation, back.generation), (1, 2));
        assert_eq!(lost.new.interface, None);
        assert_eq!(back.new.interface.as_deref(), Some("en0"));
        assert!(events.try_recv().is_err());
        assert_eq!(changes.borrow().as_ref().unwrap().generation, 2);
        // The state carries the generation of the change it came after.
        let current = network.snapshot_with_generation();
        assert_eq!(current.generation, 2);
        assert_eq!(current.state, back.new);
    }

    /// The state and the events after it, taken together: none of the
    /// events is one the state holds, and none after it is missed.
    #[test]
    fn the_state_and_its_events_are_taken_together() {
        let network = Network::default();
        network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State);
        network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::State);
        let (current, mut events) = network.state_and_events();
        assert_eq!(current.generation, 1);
        assert_eq!(current.state.interface.as_deref(), Some("en1"));
        assert!(
            events.try_recv().is_err(),
            "the state's own change is not an event"
        );
        network.announce(ChangeReason::Wake);
        assert_eq!(events.try_recv().unwrap().generation, 2);

        // A subscriber falling more than the bound behind is told so.
        let mut slow = network.change_events();
        for _ in 0..EVENTS + 1 {
            network.announce(ChangeReason::Wake);
        }
        assert!(matches!(
            slow.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(1))
        ));
    }

    /// The state sail starts on is known at once, at generation 1, with no
    /// change told; what detection finds later is told from there.
    #[test]
    fn the_first_state_is_settled_before_the_instance_runs() {
        let network = Network::default();
        let mut events = network.change_events();
        network.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        let current = network.snapshot_with_generation();
        assert_eq!(
            (current.generation, current.state.interface.as_deref()),
            (1, Some("en0"))
        );
        assert!(events.try_recv().is_err(), "settling tells no change");
        // Settled once: a second is nothing, and the same state detected
        // is no change.
        network.settle_first(Some(on("en1", &["10.0.0.2/24"])));
        assert_eq!(network.snapshot().interface.as_deref(), Some("en0"));
        assert!(!network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));
        assert!(network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::DefaultInterface));
        assert_eq!(events.try_recv().unwrap().generation, 2);
    }

    /// Settled with no network, sail starts offline, and the first link
    /// is a change from it.
    #[test]
    fn settled_offline_the_first_link_is_a_change() {
        let network = Network::default();
        network.settle_first(None);
        assert!(network.is_down());
        assert_eq!(network.snapshot_with_generation().generation, 1);
        let mut events = network.change_events();
        assert!(network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));
        let change = events.try_recv().unwrap();
        assert_eq!(
            (change.generation, change.old.interface.as_deref()),
            (2, None)
        );
    }

    /// Once a state is known, or the host pushes, settling is nothing.
    #[test]
    fn settling_leaves_a_known_or_pushed_state() {
        let network = Network::default();
        network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State);
        network.settle_first(None);
        assert_eq!(network.snapshot().interface.as_deref(), Some("en0"));
        assert_eq!(network.snapshot_with_generation().generation, 0);

        let pushed = Network::default();
        pushed.push(on("wlan0", &["10.1.0.2/24"]));
        pushed.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        assert_eq!(pushed.snapshot().interface.as_deref(), Some("wlan0"));
    }
}

#[cfg(test)]
#[path = "network_authority_tests.rs"]
mod authority_tests;
