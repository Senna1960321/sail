//! The JSON hosts are answered with, the C ABI and the management API
//! alike: sail's own shape, the control types serialized in snake_case
//! with typed fields (the Clash API renders Mihomo's from the same types).
//!
//! It carries no version number. It only grows: a field, a type or a
//! string value may be added, and a host ignores what it does not know
//! (the Swift and Kotlin bindings do). Taking a field away, renaming it, or
//! changing its type or meaning breaks hosts: it follows the sail release
//! and goes in the release notes; the management API takes it to a new
//! path (/api/v2). The snapshot test below, which the bindings' tests read
//! too, catches a change made by accident.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

fn millis_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn millis(delay: Duration) -> u64 {
    delay.as_millis().max(1) as u64
}

#[derive(Serialize)]
pub struct Capabilities {
    /// The sail release.
    pub version: &'static str,
    /// The commit it was built from: a short hash, or `unknown`.
    pub commit: &'static str,
    /// The modules compiled in (`inbound-tun`, `outbound-vless`…): what was
    /// built, not which calls or fields there are. A call a sail lacks
    /// answers that it is unsupported; a field it lacks is absent.
    pub features: Vec<&'static str>,
}

/// What an instance can do, as it runs.
#[derive(Serialize)]
pub struct InstanceCapabilities {
    /// The sail release the instance runs: through a command service
    /// client, the tunnel process's, which may differ from the app's after
    /// an update (an old system extension still running).
    pub version: String,
    pub has_tun: bool,
    pub opens_tun: bool,
    pub protects_sockets: bool,
    /// Whether the rules or groups pick by the network the host is on, so
    /// the host should tell it (`sail_set_network_state`).
    pub needs_network: bool,
    /// Whether it has modes to switch among.
    pub has_modes: bool,
}

/// An instance's state.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct State {
    /// `idle`, `starting`, `running`, `stopping`, `stopped` or `failed`.
    pub state: String,
    /// Why it failed, for `failed`.
    pub error: Option<String>,
    /// The kind of the failure, as `embed::ErrorKind::code` names it
    /// (`panicked`, `config`, `tun_name_taken`, ...), for `failed`.
    pub error_kind: Option<String>,
    /// What the failed run's teardown left in the system, for `failed`;
    /// empty when nothing is.
    pub left: Vec<Left>,
    /// When it last started running, in milliseconds since the epoch.
    pub started_at_ms: Option<u64>,
}

/// What a reload did.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ReloadReport {
    /// `full`: everything built again; `inbounds_only`: nothing but the
    /// inbounds differed, and the outbounds, groups, DNS and routing (and
    /// what they held) are those that ran.
    pub path: String,
    /// Each inbound the configuration has, in its order, then those it no
    /// longer has.
    pub inbounds: Vec<ReloadedInbound>,
    /// What the reload took and did not reach everything with.
    pub notes: Vec<ReloadNote>,
    /// What the recheck of the connections open found; only there when
    /// the reload was asked for one (`"recheck_open": "close_rejected"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recheck: Option<Recheck>,
    /// The users whose limits the host set the reload dropped: it changed
    /// what the configuration sets for them.
    pub user_limits_dropped: Vec<String>,
}

/// What a reload's recheck of the connections open found.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Recheck {
    /// Those it closed, the rules rejecting or dropping them now.
    pub closed: Vec<RecheckClosed>,
    /// Those the rules now send to another outbound, which go on.
    pub differ: Vec<RecheckDiffer>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct RecheckClosed {
    /// Its id, as the connections list it.
    pub id: u64,
    /// The index in `route.rules` of the rule that rejects it, as the
    /// routed event's `rule`.
    pub rule: Option<u32>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct RecheckDiffer {
    pub id: u64,
    /// The outbound it went to.
    pub old: String,
    /// The one the rules send it to now; `hijack-dns` for a hijack-dns
    /// rule.
    pub new: String,
}

impl Recheck {
    pub fn of(report: &crate::control::RecheckReport) -> Self {
        Self {
            closed: report
                .closed
                .iter()
                .map(|c| RecheckClosed {
                    id: c.id,
                    rule: c.rule,
                })
                .collect(),
            differ: report
                .differ
                .iter()
                .map(|d| RecheckDiffer {
                    id: d.id,
                    old: d.old.clone(),
                    new: d.new.clone(),
                })
                .collect(),
        }
    }
}

/// How a host asks a reload to treat the connections open:
/// `{"recheck_open": "keep" | "close_rejected"}`, the key left out for
/// `keep`. Any other key is an error.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReloadOptions {
    #[serde(default)]
    recheck_open: RecheckOpen,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum RecheckOpen {
    #[default]
    Keep,
    CloseRejected,
}

impl ReloadOptions {
    /// The options `text` gives, or why it gives none.
    pub fn parse(text: &[u8]) -> Result<crate::control::ReloadOptions, String> {
        let options: Self = serde_json::from_slice(text).map_err(|e| e.to_string())?;
        Ok(
            crate::control::ReloadOptions::new().recheck_open(match options.recheck_open {
                RecheckOpen::Keep => crate::control::RecheckOpen::Keep,
                RecheckOpen::CloseRejected => crate::control::RecheckOpen::CloseRejected,
            }),
        )
    }
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ReloadedInbound {
    pub tag: String,
    /// `untouched`, `reloaded`, `added`, `removed`, `replaced` or `lost`:
    /// only the removed and the replaced had their connections closed.
    pub change: String,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ReloadNote {
    /// `endpoint_keeps_defaults`; more may come.
    pub kind: String,
    /// As a person reads it.
    pub text: String,
    /// The endpoint it concerns, for `endpoint_keeps_defaults`.
    pub endpoint: Option<String>,
    /// The options it concerns, as the configuration names them.
    pub options: Vec<String>,
}

impl ReloadReport {
    pub fn of(report: &crate::control::ReloadReport) -> Self {
        Self {
            path: report.path.name().into(),
            inbounds: report
                .inbounds
                .iter()
                .map(|(tag, change)| ReloadedInbound {
                    tag: tag.clone(),
                    change: change.name().into(),
                })
                .collect(),
            notes: report
                .notes
                .iter()
                .map(|note| match note {
                    crate::control::ReloadNote::EndpointKeepsDefaults { endpoint, options } => {
                        ReloadNote {
                            kind: "endpoint_keeps_defaults".into(),
                            text: note.to_string(),
                            endpoint: Some(endpoint.clone()),
                            options: options.iter().map(|o| o.to_string()).collect(),
                        }
                    }
                })
                .collect(),
            recheck: report.recheck.as_ref().map(Recheck::of),
            user_limits_dropped: report.user_limits_dropped.clone(),
        }
    }
}

/// As the events name where a domain came from.
fn domain_source(s: crate::control::events::DomainSource) -> String {
    use crate::control::events::DomainSource;
    match s {
        DomainSource::Request => "request",
        DomainSource::FakeIp => "fake_ip",
        DomainSource::Sniffed => "sniffed",
        DomainSource::ReverseMapping => "reverse_mapping",
    }
    .to_string()
}

/// Milliseconds since the Unix epoch.
fn unix_ms(at: std::time::SystemTime) -> u64 {
    at.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// What a connection sent and received since it started: the connection
/// record event. Its closed record's totals are what it was counted.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ConnectionRecord {
    pub id: u64,
    /// When the instance's run started, Unix milliseconds: with `id`, it
    /// names the connection across restarts.
    pub run_ms: u64,
    /// Its records in order, from 0.
    pub seq: u32,
    /// `interim`, or `closed`, its last.
    pub kind: String,
    /// How it ended, for a closed record: `finished`, `error`,
    /// `idle_timeout`, `write_stall`, `closed` or `aborted`.
    pub end: Option<String>,
    /// For `error`: what failed, as the dial errors are told.
    pub error: Option<String>,
    /// For `closed`: `api`, `user`, `inbound`, `rules`, `network` or
    /// `stopped`.
    pub closed_by: Option<String>,
    /// How it was used, for a closed record: `ok`, `dial_failed`,
    /// `blocked` or `rejected`.
    pub outcome: Option<String>,
    /// `tcp` or `udp`.
    pub network: String,
    pub user: Option<String>,
    pub inbound: String,
    pub source: String,
    /// The address it connected to; `0.0.0.0:0` where it is not known.
    pub local: String,
    /// Where it went, as the rules saw it.
    pub destination: String,
    /// What the outbound was asked to reach, where it was kept.
    pub request_destination: Option<String>,
    pub domain: Option<String>,
    /// `request`, `fake_ip`, `sniffed` or `reverse_mapping`.
    pub domain_source: Option<String>,
    /// The outbound the rules sent it to.
    pub outbound: Option<String>,
    /// The outbounds it went through, the group first.
    pub chain: Vec<String>,
    /// Bytes since it started: up to where it goes, down from it.
    pub up_total: u64,
    pub down_total: u64,
    /// Unix milliseconds: when it started, and when it was counted (for a
    /// closed record, its end).
    pub start_ms: u64,
    pub at_ms: u64,
}

impl ConnectionRecord {
    pub fn of(r: &crate::control::events::ConnectionRecord) -> Self {
        use crate::control::events::{ClosedBy, End, Outcome, RecordKind};
        let end = match r.kind {
            RecordKind::Closed(end) => Some(end),
            _ => None,
        };
        Self {
            id: r.id,
            run_ms: unix_ms(r.run),
            seq: r.seq,
            kind: match r.kind {
                RecordKind::Closed(_) => "closed",
                _ => "interim",
            }
            .into(),
            end: end.map(|end| {
                match end {
                    End::Finished => "finished",
                    End::Error(_) => "error",
                    End::IdleTimeout => "idle_timeout",
                    End::WriteStall => "write_stall",
                    End::Closed(_) => "closed",
                    _ => "aborted",
                }
                .into()
            }),
            error: match end {
                Some(End::Error(kind)) => Some(kind.to_string()),
                _ => None,
            },
            closed_by: match end {
                Some(End::Closed(by)) => Some(
                    match by {
                        ClosedBy::Api => "api",
                        ClosedBy::User => "user",
                        ClosedBy::Inbound => "inbound",
                        ClosedBy::Rules => "rules",
                        ClosedBy::Network => "network",
                        _ => "stopped",
                    }
                    .into(),
                ),
                _ => None,
            },
            outcome: r.outcome.map(|outcome| {
                match outcome {
                    Outcome::Ok => "ok",
                    Outcome::DialFailed => "dial_failed",
                    Outcome::Blocked => "blocked",
                    _ => "rejected",
                }
                .into()
            }),
            network: r.network.to_string(),
            user: r.user.clone(),
            inbound: r.inbound.clone(),
            source: r.source.to_string(),
            local: r.local.to_string(),
            destination: r.destination.to_string(),
            request_destination: r.request_destination.as_ref().map(|d| d.to_string()),
            domain: r.domain.clone(),
            domain_source: r.domain_source.map(domain_source),
            outbound: r.outbound.clone(),
            chain: r.chain.clone(),
            up_total: r.up_total,
            down_total: r.down_total,
            start_ms: unix_ms(r.start),
            at_ms: unix_ms(r.at),
        }
    }
}

/// A connection routed, and dialled where the rules sent it to an outbound:
/// the routed event.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Routed {
    /// Its id among the connections listed, while it is open; none for
    /// one that never opened (a reject, a failed dial).
    pub id: Option<u64>,
    /// `tcp` or `udp`.
    pub network: String,
    pub inbound: String,
    /// The user the inbound authenticated it as.
    pub user: Option<String>,
    pub source: String,
    /// Where it went, as the rules saw it.
    pub destination: String,
    /// What the client asked for, where that differs (a fake IP mapped
    /// back, a domain sniffed).
    pub request_destination: Option<String>,
    pub domain: Option<String>,
    /// `request`, `fake_ip`, `sniffed` or `reverse_mapping`.
    pub domain_source: Option<String>,
    pub sniffed_protocol: Option<String>,
    /// The index of the rule that matched, none for the final outbound.
    pub rule: Option<u32>,
    pub rule_text: Option<String>,
    /// `outbound`, `reject`, `drop` or `hijack_dns`.
    pub action: String,
    /// The outbounds it went through, the group first.
    pub chain: Vec<String>,
    /// The address it was dialled to.
    pub target: Option<String>,
    /// How long the dial took, when it connected.
    pub connect_ms: Option<u64>,
    /// Why the dial failed, when it did.
    pub connect_error: Option<String>,
}

impl Routed {
    pub fn of(r: &crate::control::events::RoutedConnection) -> Self {
        use crate::control::events::RouteAction;
        Self {
            id: r.id,
            network: r.network.to_string(),
            inbound: r.inbound.clone(),
            user: r.user.clone(),
            source: r.source.to_string(),
            destination: r.destination.to_string(),
            request_destination: r.request_destination.as_ref().map(|d| d.to_string()),
            domain: r.domain.clone(),
            domain_source: r.domain_source.map(domain_source),
            sniffed_protocol: r.sniffed_protocol.map(str::to_string),
            rule: r.rule,
            rule_text: r.rule_text.clone(),
            action: match r.action {
                RouteAction::Outbound => "outbound",
                RouteAction::Reject => "reject",
                RouteAction::Drop => "drop",
                RouteAction::HijackDns => "hijack_dns",
            }
            .into(),
            chain: r.chain.clone(),
            target: r.target.map(|t| t.to_string()),
            connect_ms: match &r.connect {
                Some(Ok(took)) => Some(took.as_millis() as u64),
                _ => None,
            },
            connect_error: match &r.connect {
                Some(Err(kind)) => Some(kind.to_string()),
                _ => None,
            },
        }
    }
}

/// A DNS query answered or failed: the DNS event.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct DnsExchange {
    /// The name asked, without its final dot.
    pub name: String,
    /// The type asked, as DNS names it (`A`, `AAAA`, `HTTPS`, ...), and
    /// its number.
    pub qtype: String,
    pub qtype_code: u16,
    /// The server that answered or failed; none where a rule answered.
    pub server: Option<String>,
    /// `exchanged`, `cached`, `optimistic` or `rule`.
    pub source: String,
    /// The response code (`NOERROR`, `NXDOMAIN`, ...) and its number, when
    /// answered.
    pub rcode: Option<String>,
    pub rcode_code: Option<u16>,
    /// Why it failed, when it did.
    pub error: Option<String>,
    /// The first 16 records of the answer section.
    pub answers: Vec<String>,
    pub answers_total: u32,
    pub ttl: Option<u32>,
    /// How long the server took; none from the cache or a rule.
    pub duration_ms: Option<u64>,
    /// Which attempt of a sequential server, from 1.
    pub attempt: Option<u32>,
    /// Asked by the instance itself, rather than by a client.
    pub for_instance: bool,
}

impl DnsExchange {
    pub fn of(e: &crate::control::events::DnsExchange) -> Self {
        use crate::control::events::{DnsOutcome, DnsSource};
        let (rcode, rcode_code, error) = match &e.outcome {
            DnsOutcome::Answered { rcode, rcode_code } => {
                (Some(rcode.clone()), Some(*rcode_code), None)
            }
            DnsOutcome::Failed { error } => (None, None, Some(error.clone())),
        };
        Self {
            name: e.name.clone(),
            qtype: e.qtype.clone(),
            qtype_code: e.qtype_code,
            server: e.server.clone(),
            source: match e.source {
                DnsSource::Exchanged => "exchanged",
                DnsSource::Cached => "cached",
                DnsSource::Optimistic => "optimistic",
                DnsSource::Rule => "rule",
            }
            .into(),
            rcode,
            rcode_code,
            error,
            answers: e.answers.clone(),
            answers_total: e.answers_total,
            ttl: e.ttl,
            duration_ms: e.duration.map(|d| d.as_millis() as u64),
            attempt: e.attempt,
            for_instance: e.for_instance,
        }
    }
}

/// A group took another member: the group event.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct GroupSwitch {
    pub group: String,
    pub from: Option<String>,
    pub to: String,
    /// `member_down`, `test_failed`, `recovered`, `all_down`, `pinned`,
    /// `unpinned`, `selected`, `faster` or `members_changed`.
    pub reason: String,
}

impl GroupSwitch {
    pub fn of(s: &crate::control::events::GroupSwitch) -> Self {
        use crate::control::events::SwitchReason;
        Self {
            group: s.group.clone(),
            from: s.from.clone(),
            to: s.to.clone(),
            reason: match s.reason {
                SwitchReason::MemberDown => "member_down",
                SwitchReason::TestFailed => "test_failed",
                SwitchReason::Recovered => "recovered",
                SwitchReason::AllDown => "all_down",
                SwitchReason::Pinned => "pinned",
                SwitchReason::Unpinned => "unpinned",
                SwitchReason::Selected => "selected",
                SwitchReason::Faster => "faster",
                SwitchReason::MembersChanged => "members_changed",
            }
            .into(),
        }
    }
}

/// Dials through a chain failed: the dial event, one for each chain a
/// second at most.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct DialFailed {
    /// The outbounds, the group first.
    pub chain: String,
    /// The last failure's destination, as `log.redact` leaves it.
    pub destination: String,
    /// The last failure's error.
    pub error: String,
    /// `dial`, `handshake` or `transfer`.
    pub stage: String,
    /// Whether a group goes on to another member.
    pub more_to_try: bool,
    /// The failures through the chain since its event before.
    pub count: u64,
}

impl DialFailed {
    pub fn of(f: &crate::control::events::DialFailure, count: u64) -> Self {
        use crate::control::events::DialStage;
        Self {
            chain: f.chain.clone(),
            destination: f.destination.clone(),
            error: f.kind.to_string(),
            stage: match f.stage {
                DialStage::Dial => "dial",
                DialStage::Handshake => "handshake",
                DialStage::Transfer => "transfer",
            }
            .into(),
            more_to_try: f.more_to_try,
            count,
        }
    }
}

/// A fault event: a task of the instance panicked.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Fault {
    /// The task's name: `inbound tcp`, `group health check`, ...
    pub task: String,
    /// `contained` (the task alone ended; the instance goes on) or
    /// `essential` (the instance failed).
    pub class: String,
    /// What the panic said.
    pub message: String,
    /// The instance's contained panics so far, in this run.
    pub count: u64,
}

impl Fault {
    pub fn of(fault: &crate::control::events::Fault) -> Self {
        use crate::runtime::scope::TaskClass;
        Self {
            task: fault.task.to_string(),
            class: match fault.class {
                TaskClass::Contained => "contained",
                TaskClass::Essential => "essential",
            }
            .into(),
            message: fault.message.clone(),
            count: fault.count,
        }
    }
}

/// Something an instance's teardown could not undo in the system.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Left {
    /// `tun`, `route`, `rule`, `dns`, `nft`, `wfp`, `file` or `task`; more
    /// may come.
    pub kind: String,
    /// The resource, as a person reads it: `nft table inet sail_tun0`.
    pub resource: String,
    /// Why it is left: the error, a timeout, a panic.
    pub why: String,
    /// The one command that clears it by hand, where there is one.
    pub clear: Option<String>,
}

/// A left resource's kind, as `Left` and `SystemChange` name it.
fn left_kind(kind: crate::runtime::teardown::LeftKind) -> &'static str {
    use crate::runtime::teardown::LeftKind as K;
    match kind {
        K::Tun => "tun",
        K::Route => "route",
        K::Rule => "rule",
        K::Dns => "dns",
        K::Nft => "nft",
        K::Wfp => "wfp",
        K::File => "file",
        K::Task => "task",
    }
}

impl Left {
    pub fn of(left: &crate::runtime::teardown::Left) -> Self {
        Self {
            kind: left_kind(left.kind).into(),
            resource: left.resource.clone(),
            why: left.why.clone(),
            clear: left.clear.clone(),
        }
    }
}

/// Something sail set up on the system for a TUN that someone else
/// changed, and that sail left as it is.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct SystemChange {
    /// `route`, `dns` or `tun`, as `Left`'s; more may come.
    pub kind: String,
    /// What and how, the TUN named first: `route 0.0.0.0/0 into tun0: gone`.
    pub resource: String,
}

impl SystemChange {
    pub fn of(kind: crate::runtime::teardown::LeftKind, resource: &str) -> Self {
        Self {
            kind: left_kind(kind).into(),
            resource: resource.into(),
        }
    }
}

/// What the last stop could not end or undo.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct StopReport {
    /// The instance's tasks still running when the stop gave up on them.
    pub tasks: Vec<StopTask>,
    /// How long the stop waited for them, in milliseconds.
    pub waited_ms: u64,
    /// What the teardown left in the system.
    pub left: Vec<Left>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct StopTask {
    pub name: String,
    pub count: usize,
}

impl StopReport {
    pub fn of(report: &crate::runtime::scope::StopReport) -> Self {
        Self {
            tasks: report
                .tasks
                .iter()
                .map(|(name, count)| StopTask {
                    name: name.to_string(),
                    count: *count,
                })
                .collect(),
            waited_ms: report.waited.as_millis() as u64,
            left: report.left.iter().map(Left::of).collect(),
        }
    }
}

#[derive(Serialize)]
pub struct Traffic {
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    /// The process's resident memory, in bytes; 0 where unknown.
    pub memory: u64,
    /// The panics of tasks the instance went on after, in this run: each
    /// is told as a fault event.
    pub faults: u64,
}

impl Traffic {
    pub fn of(traffic: &crate::control::Traffic) -> Self {
        Self {
            up_total: traffic.up_total,
            down_total: traffic.down_total,
            connections: traffic.connections,
            memory: crate::control::resident_memory(),
            faults: traffic.faults,
        }
    }
}

/// A `status` event: the traffic, and its rate since the last.
#[derive(Serialize)]
pub struct Status {
    /// Bytes a second.
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    pub memory: u64,
    /// As `Traffic::faults`.
    pub faults: u64,
}

#[derive(Serialize, Clone)]
pub struct Connection {
    pub id: u64,
    pub network: String,
    pub inbound_type: String,
    pub inbound_tag: String,
    pub source: String,
    pub destination: String,
    /// The domain it goes to: the destination's, else the name it was
    /// dialled as (`override_destination`), else the one sniffed.
    pub host: Option<String>,
    /// The domain a sniff found, from a TLS server name or an HTTP Host.
    pub sniff_host: Option<String>,
    /// Where the name it was dialled as came from, `sniff` or
    /// `reverse_mapping`; none where it was dialled as asked.
    pub dial_domain_source: Option<String>,
    pub process: Option<String>,
    pub user: Option<String>,
    /// Who opened it, as the host tells it (Android).
    pub uid: Option<u32>,
    pub packages: Vec<String>,
    pub upload: u64,
    pub download: u64,
    /// Unix seconds.
    pub start: u32,
    pub chains: Vec<String>,
    pub rule: Option<String>,
}

impl Connection {
    pub fn of(c: &crate::control::ConnectionInfo) -> Self {
        Self {
            id: c.id,
            network: c.network.to_string(),
            inbound_type: c.inbound_type.clone(),
            inbound_tag: c.inbound_tag.clone(),
            source: c.source.to_string(),
            destination: c.destination.to_string(),
            host: c.host.clone(),
            sniff_host: c.sniff_host.clone(),
            dial_domain_source: c.dial_domain_source.map(str::to_owned),
            process: c.process.clone(),
            user: c.user.clone(),
            uid: c.uid,
            packages: c.packages.clone(),
            upload: c.upload,
            download: c.download,
            start: c.start,
            chains: c.chains.clone(),
            rule: c.rule.clone(),
        }
    }
}

/// A user's limits: what `user_limits` sets, or the management API set
/// since. A field that is `null` limits nothing.
#[derive(Serialize)]
pub struct Limits {
    pub max_connections: Option<u32>,
    /// Of them, TCP ones; its UDP sessions not counted.
    pub max_tcp_connections: Option<u32>,
    pub quota_bytes: Option<u64>,
    /// When it may no longer connect, in milliseconds since the epoch.
    pub expire_at_ms: Option<u64>,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
    /// Up and down together.
    pub total_mbps: Option<u64>,
}

impl Limits {
    pub fn of(l: &crate::user::Limits) -> Self {
        Self {
            max_connections: l.max_connections,
            max_tcp_connections: l.max_tcp_connections,
            quota_bytes: l.quota_bytes,
            expire_at_ms: l.expire_at.map(millis_since_epoch),
            up_mbps: l.up_mbps,
            down_mbps: l.down_mbps,
            total_mbps: l.total_mbps,
        }
    }
}

/// Bytes up and down, and the TCP connections and UDP sessions there were.
#[derive(Serialize)]
pub struct Counts {
    pub up: u64,
    pub down: u64,
    pub tcp: u64,
    pub udp: u64,
}

impl Counts {
    pub fn of(c: &crate::app::stat_manager::Counts) -> Self {
        Self {
            up: c.up,
            down: c.down,
            tcp: c.tcp,
            udp: c.udp,
        }
    }
}

/// A user, by name, across the inbounds it is in.
#[derive(Serialize)]
pub struct User {
    pub name: String,
    /// The inbounds whose configuration has it.
    pub inbounds: Vec<String>,
    /// Neither over its quota nor expired: it may connect.
    pub active: bool,
    pub over_quota: bool,
    pub expired: bool,
    pub limits: Limits,
    /// Since it was first counted, across restarts with the cache file.
    pub traffic: Counts,
    /// Its live connections.
    pub live: u64,
    /// Up and down together since its quota was last reset.
    pub quota_used: u64,
}

impl User {
    pub fn of(u: &crate::user::UserSnapshot) -> Self {
        Self {
            name: u.name.clone(),
            inbounds: u.inbounds.clone(),
            active: u.status.active(),
            over_quota: u.status.exhausted(),
            expired: u.status.expired(),
            limits: Limits::of(&u.limits),
            traffic: Counts::of(&u.traffic),
            live: u.live as u64,
            quota_used: u.quota_used,
        }
    }
}

#[derive(Serialize)]
pub struct Users {
    pub users: Vec<User>,
}

/// The traffic of each user, inbound and outbound, by name or tag.
#[derive(Serialize)]
pub struct Stats {
    pub users: std::collections::BTreeMap<String, Counts>,
    pub inbounds: std::collections::BTreeMap<String, Counts>,
    pub outbounds: std::collections::BTreeMap<String, Counts>,
}

impl Stats {
    pub fn of(r: &crate::app::stat_manager::TrafficReport) -> Self {
        let by = |list: &[(String, crate::app::stat_manager::Counts)]| {
            list.iter()
                .map(|(k, c)| (k.clone(), Counts::of(c)))
                .collect()
        };
        Self {
            users: by(&r.users),
            inbounds: by(&r.inbounds),
            outbounds: by(&r.outbounds),
        }
    }
}

/// An inbound as it runs.
#[derive(Serialize)]
pub struct Inbound {
    pub tag: String,
    /// Its type, as the configuration has it.
    pub protocol: String,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    /// Whether its users and certificate change while it runs.
    pub reloadable: bool,
}

impl Inbound {
    pub fn of(i: &crate::control::InboundInfo) -> Self {
        Self {
            tag: i.tag.clone(),
            protocol: i.protocol.clone(),
            listen: i.listen.clone(),
            listen_port: i.listen_port,
            reloadable: i.reloadable,
        }
    }
}

#[derive(Serialize)]
pub struct Inbounds {
    pub inbounds: Vec<Inbound>,
}

/// The names of an inbound's users; their credentials are not told.
#[derive(Serialize)]
pub struct InboundUsers {
    pub users: Vec<String>,
}

/// As the API names an admission level.
fn admission_level(level: crate::control::events::AdmissionLevel) -> &'static str {
    use crate::control::events::AdmissionLevel;
    match level {
        AdmissionLevel::Normal => "normal",
        AdmissionLevel::Pressure => "pressure",
        _ => "hard",
    }
}

/// What admission under memory pressure did since the instance started:
/// the management API's `GET /admission`.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct Admission {
    /// `off`, `normal`, `pressure` or `hard`.
    pub level: String,
    /// Bytes free as last read, and kept free; none where not read.
    pub free: Option<u64>,
    pub reserve: u64,
    /// Connections in their handshake now.
    pub handshakes: usize,
    /// Refused at accept under hard pressure, and for their source.
    pub refused: u64,
    pub refused_sources: u64,
    /// QUIC connections refused before their handshake.
    pub refused_quic: u64,
    /// Closed in their handshake, stalled under pressure, and stalled
    /// while their inbound's places were all taken.
    pub evicted: u64,
    pub evicted_full: u64,
    /// How long it was under pressure.
    pub pressure_ms: u64,
    /// Refused by the embedding host's checks, by reason, and those of its
    /// checks that panicked.
    pub host_refused: std::collections::BTreeMap<String, u64>,
    pub host_panics: u64,
}

impl Admission {
    pub fn of(info: Option<&crate::app::inbound::AdmissionInfo>) -> Self {
        match info {
            None => Self {
                level: "off".into(),
                free: None,
                reserve: 0,
                handshakes: 0,
                refused: 0,
                refused_sources: 0,
                refused_quic: 0,
                evicted: 0,
                evicted_full: 0,
                pressure_ms: 0,
                host_refused: Default::default(),
                host_panics: 0,
            },
            Some(info) => Self {
                level: admission_level(info.level).into(),
                free: info.free,
                reserve: info.reserve,
                handshakes: info.handshakes,
                refused: info.refused,
                refused_sources: info.refused_sources,
                refused_quic: info.refused_quic,
                evicted: info.evicted,
                evicted_full: info.evicted_full,
                pressure_ms: info.pressure.as_millis() as u64,
                host_refused: info.host_refused.clone(),
                host_panics: info.host_panics,
            },
        }
    }
}

/// Admission changed level: an event of the management API's stream.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct AdmissionChange {
    /// `normal`, `pressure` or `hard`.
    pub level: String,
    pub free: Option<u64>,
    pub reserve: u64,
    pub handshakes: usize,
}

impl AdmissionChange {
    pub fn of(change: &crate::control::events::AdmissionChange) -> Self {
        Self {
            level: admission_level(change.level).into(),
            free: change.free,
            reserve: change.reserve,
            handshakes: change.handshakes,
        }
    }
}

/// What happened to a user: an event of the management API's stream.
#[derive(Serialize)]
pub struct UserEvent {
    /// `shut`: it went over its quota, or past its expiry, and was
    /// disconnected; `removed`: it was taken out of `inbound`, and
    /// disconnected from it.
    pub event: &'static str,
    pub user: String,
    /// For `shut`.
    pub over_quota: bool,
    pub expired: bool,
    /// For `removed`.
    pub inbound: Option<String>,
}

impl UserEvent {
    pub fn of(e: &crate::user::UserEvent) -> Self {
        match e {
            crate::user::UserEvent::Shut { user, status } => Self {
                event: "shut",
                user: user.clone(),
                over_quota: status.exhausted(),
                expired: status.expired(),
                inbound: None,
            },
            crate::user::UserEvent::Removed { user, inbound } => Self {
                event: "removed",
                user: user.clone(),
                over_quota: false,
                expired: false,
                inbound: Some(inbound.clone()),
            },
        }
    }
}

#[derive(Serialize)]
pub struct Connections {
    pub connections: Vec<Connection>,
}

#[derive(Serialize, PartialEq)]
pub struct Delay {
    pub time_ms: u64,
    /// None for a test that failed.
    pub delay_ms: Option<u64>,
}

#[derive(Serialize, PartialEq)]
pub struct Group {
    pub selected: String,
    pub members: Vec<String>,
    pub selectable: bool,
}

#[derive(Serialize, PartialEq)]
pub struct Outbound {
    pub tag: String,
    pub kind: String,
    pub protocol: Option<String>,
    pub provider: Option<String>,
    pub udp: bool,
    pub history: Vec<Delay>,
    pub group: Option<Group>,
}

impl Outbound {
    pub fn of(o: &crate::control::OutboundInfo) -> Self {
        Self {
            tag: o.tag.clone(),
            kind: o.kind.to_string(),
            protocol: o.protocol.clone(),
            provider: o.provider.clone(),
            udp: o.udp,
            history: o
                .history
                .iter()
                .map(|d| Delay {
                    time_ms: millis_since_epoch(d.time),
                    delay_ms: d.delay.map(millis),
                })
                .collect(),
            group: o.group.as_ref().map(|g| Group {
                selected: g.selected.clone(),
                members: g.members.clone(),
                selectable: g.selectable,
            }),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct Outbounds {
    pub outbounds: Vec<Outbound>,
}

#[derive(Serialize, PartialEq)]
pub struct Failure {
    pub at_ms: u64,
    pub error: String,
}

impl Failure {
    fn of(f: &crate::control::Failure) -> Self {
        Self {
            at_ms: millis_since_epoch(f.at),
            error: f.error.clone(),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct Subscription {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire_ms: Option<u64>,
}

fn source(kind: crate::control::SourceKind) -> String {
    use crate::control::SourceKind;
    match kind {
        SourceKind::Remote => "remote",
        SourceKind::Local => "local",
        SourceKind::Inline => "inline",
    }
    .to_string()
}

/// An outbound provider.
#[derive(Serialize, PartialEq)]
pub struct Provider {
    pub tag: String,
    /// `remote`, `local` or `inline`.
    pub source: String,
    pub members: u64,
    pub updated_ms: Option<u64>,
    pub next_update_ms: Option<u64>,
    pub failure: Option<Failure>,
    pub subscription: Option<Subscription>,
}

impl Provider {
    pub fn of(p: &crate::control::ProviderInfo) -> Self {
        Self {
            tag: p.tag.clone(),
            source: source(p.source),
            members: p.members as u64,
            updated_ms: p.updated.map(millis_since_epoch),
            next_update_ms: p.next_update.map(millis_since_epoch),
            failure: p.failure.as_ref().map(Failure::of),
            subscription: p.subscription.map(|s| Subscription {
                upload: s.upload,
                download: s.download,
                total: s.total,
                expire_ms: s.expire.map(millis_since_epoch),
            }),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct Providers {
    pub providers: Vec<Provider>,
}

/// A rule-set.
#[derive(Serialize, PartialEq)]
pub struct RuleSet {
    pub tag: String,
    /// `remote`, `local` or `inline`.
    pub source: String,
    pub format: Option<String>,
    pub behavior: Option<String>,
    pub rules: u64,
    pub updated_ms: Option<u64>,
    pub next_update_ms: Option<u64>,
    pub failure: Option<Failure>,
}

impl RuleSet {
    pub fn of(r: &crate::control::RuleSetInfo) -> Self {
        Self {
            tag: r.tag.clone(),
            source: source(r.source),
            format: r.format.clone(),
            behavior: r.behavior.clone(),
            rules: r.rules as u64,
            updated_ms: r.updated.map(millis_since_epoch),
            next_update_ms: r.next_update.map(millis_since_epoch),
            failure: r.failure.as_ref().map(Failure::of),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct RuleSets {
    pub rule_sets: Vec<RuleSet>,
}

#[derive(Serialize)]
pub struct Mode {
    pub mode: String,
    pub modes: Vec<String>,
}

#[derive(Serialize)]
pub struct LogLine {
    /// `error`, `warn`, `info`, `debug` or `trace`.
    pub level: String,
    pub message: String,
    pub time_ms: u64,
}

impl LogLine {
    pub fn of(line: &crate::app::logger::LogLine) -> Self {
        Self {
            level: match line.level {
                tracing::Level::ERROR => "error",
                tracing::Level::WARN => "warn",
                tracing::Level::INFO => "info",
                tracing::Level::DEBUG => "debug",
                tracing::Level::TRACE => "trace",
            }
            .to_string(),
            message: line.message.clone(),
            time_ms: millis_since_epoch(line.time),
        }
    }
}

/// A `network` event: a change of network the connections made on the one
/// before do not survive.
#[derive(Serialize)]
pub struct NetworkEvent {
    /// Counts the changes since the instance started, from 1.
    pub generation: u64,
    /// `default-interface`, `state`, `host` or `wake`.
    pub reason: String,
    /// The network before and now, as `sail_set_network_state` takes it.
    pub old: crate::net::network::NetworkState,
    pub new: crate::net::network::NetworkState,
}

impl NetworkEvent {
    pub fn of(change: &crate::net::network::NetworkChange) -> Self {
        Self {
            generation: change.generation,
            reason: change.reason.to_string(),
            old: (*change.old).clone(),
            new: (*change.new).clone(),
        }
    }
}

/// A `log` event.
#[derive(Serialize)]
pub struct Log {
    /// The lines before were cleared: the host drops the lines it has.
    pub reset: bool,
    pub lines: Vec<LogLine>,
    /// Lines left out since the last event, as the host was too slow to
    /// take them.
    pub dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A reload's report has `recheck` only when one ran, in the shape
    /// docs/ffi.md gives; the options read as the C ABI and the API take
    /// them, and a key they do not have is an error.
    #[test]
    fn a_recheck_is_told_only_when_one_ran() {
        let mut report = crate::control::ReloadReport::default();
        let json = serde_json::to_value(ReloadReport::of(&report)).unwrap();
        assert!(json.get("recheck").is_none(), "{}", json);
        report.recheck = Some(crate::control::RecheckReport {
            closed: vec![crate::control::RecheckClosed {
                id: 1,
                rule: Some(3),
            }],
            differ: vec![crate::control::RecheckDiffer {
                id: 2,
                old: "a".into(),
                new: "b".into(),
            }],
        });
        let json = serde_json::to_value(ReloadReport::of(&report)).unwrap();
        assert_eq!(
            json["recheck"],
            serde_json::json!({
                "closed": [{ "id": 1, "rule": 3 }],
                "differ": [{ "id": 2, "old": "a", "new": "b" }],
            })
        );

        use crate::control::RecheckOpen;
        let read = |text: &str| ReloadOptions::parse(text.as_bytes()).map(|o| o.recheck_open);
        assert_eq!(read(r#"{}"#), Ok(RecheckOpen::Keep));
        assert_eq!(read(r#"{"recheck_open":"keep"}"#), Ok(RecheckOpen::Keep));
        assert_eq!(
            read(r#"{"recheck_open":"close_rejected"}"#),
            Ok(RecheckOpen::CloseRejected)
        );
        assert!(read(r#"{"recheck_open":"close"}"#).is_err());
        let unknown = read(r#"{"recheck":"close_rejected"}"#).unwrap_err();
        assert!(unknown.contains("unknown field"), "{}", unknown);
    }

    /// The contract, as it is: a change to the control types or to these
    /// that changes the JSON fails here.
    #[test]
    fn the_json_of_the_c_abi_is_as_published() {
        let at = UNIX_EPOCH + Duration::from_millis(1_759_300_000_123);
        let snapshot = serde_json::json!({
            "state": State {
                state: "failed".into(), error: Some("x".into()), error_kind: Some("panicked".into()),
                left: vec![Left { kind: "nft".into(), resource: "nft table inet sail_tun0".into(),
                                  why: "timed out after 5s".into(),
                                  clear: Some("nft delete table inet sail_tun0".into()) }],
                started_at_ms: None,
            },
            "reload_report": ReloadReport {
                path: "inbounds_only".into(),
                inbounds: vec![ReloadedInbound { tag: "in".into(), change: "replaced".into() }],
                notes: vec![ReloadNote {
                    kind: "endpoint_keeps_defaults".into(),
                    text: "[wg] endpoint: route.default_mark changed; it goes on with what it was built with: applies at the next start".into(),
                    endpoint: Some("wg".into()),
                    options: vec!["route.default_mark".into()],
                }],
                recheck: Some(Recheck {
                    closed: vec![RecheckClosed { id: 3, rule: Some(1) }],
                    differ: vec![RecheckDiffer { id: 4, old: "proxy".into(), new: "direct".into() }],
                }),
                user_limits_dropped: vec!["alice".into()],
            },
            "routed": Routed {
                id: Some(7), network: "tcp".into(), inbound: "tun-in".into(),
                user: Some("alice".into()), source: "172.19.0.1:50000".into(), destination: "example.com:443".into(),
                request_destination: Some("198.18.0.3:443".into()), domain: Some("example.com".into()),
                domain_source: Some("fake_ip".into()), sniffed_protocol: Some("tls".into()),
                rule: Some(2), rule_text: Some("domain_suffix=example.com => proxy".into()),
                action: "outbound".into(), chain: vec!["proxy".into(), "a".into()],
                target: Some("203.0.113.5:443".into()), connect_ms: Some(31), connect_error: None,
            },
            "connection_record": ConnectionRecord {
                id: 7, run_ms: 1_759_300_000_000, seq: 2, kind: "closed".into(),
                end: Some("error".into()), error: Some("connection reset".into()), closed_by: None,
                outcome: Some("ok".into()),
                network: "tcp".into(), user: Some("alice".into()), inbound: "in".into(),
                source: "172.19.0.1:50000".into(), local: "203.0.113.1:443".into(),
                destination: "example.com:443".into(),
                request_destination: Some("example.com:443".into()), domain: Some("example.com".into()),
                domain_source: Some("request".into()), outbound: Some("proxy".into()),
                chain: vec!["proxy".into(), "a".into()],
                up_total: 300, down_total: 9000,
                start_ms: 1_759_300_000_123, at_ms: 1_759_300_075_000,
            },
            "dns_exchange": DnsExchange {
                name: "example.com".into(), qtype: "A".into(), qtype_code: 1,
                server: Some("remote".into()), source: "exchanged".into(),
                rcode: Some("NOERROR".into()), rcode_code: Some(0), error: None,
                answers: vec!["203.0.113.5".into()], answers_total: 1, ttl: Some(60),
                duration_ms: Some(12), attempt: None, for_instance: false,
            },
            "group_switch": GroupSwitch {
                group: "auto".into(), from: Some("a".into()), to: "b".into(), reason: "member_down".into(),
            },
            "dial_failed": DialFailed {
                chain: "proxy/a".into(), destination: "example.com:443".into(),
                error: "connection refused".into(), stage: "dial".into(), more_to_try: true, count: 3,
            },
            "fault": Fault {
                task: "inbound tcp".into(), class: "contained".into(),
                message: "index out of bounds".into(), count: 1,
            },
            "stop_report": StopReport {
                tasks: vec![StopTask { name: "inbound tcp".into(), count: 2 }],
                waited_ms: 2000,
                left: vec![],
            },
            "traffic": Traffic { up_total: 1, down_total: 2, connections: 3, memory: 4, faults: 1 },
            "status": Status { up: 1, down: 2, up_total: 3, down_total: 4, connections: 5, memory: 6, faults: 1 },
            "connection": Connection {
                id: 12, network: "tcp".into(), inbound_type: "socks".into(),
                inbound_tag: "in".into(), source: "127.0.0.1:5000".into(),
                destination: "example.com:443".into(), host: Some("example.com".into()),
                sniff_host: Some("sni.example.com".into()), dial_domain_source: Some("sniff".into()),
                process: None, user: Some("alice".into()), uid: Some(10123),
                packages: vec!["com.example".into()], upload: 4, download: 5,
                start: 1_759_300_000, chains: vec!["b".into(), "sel".into()], rule: None,
            },
            "outbound": Outbound {
                tag: "sel".into(), kind: "Selector".into(), protocol: Some("selector".into()),
                provider: None, udp: true,
                history: vec![Delay { time_ms: millis_since_epoch(at), delay_ms: Some(millis(Duration::ZERO)) },
                              Delay { time_ms: 0, delay_ms: None }],
                group: Some(Group { selected: "b".into(), members: vec!["a".into(), "b".into()], selectable: true }),
            },
            "mode": Mode { mode: "Rule".into(), modes: vec!["Rule".into(), "Global".into()] },
            "log": Log { reset: true, lines: vec![LogLine { level: "info".into(), message: "m".into(), time_ms: 1 }], dropped: 2 },
            "network": NetworkEvent {
                generation: 2,
                reason: "host".into(),
                old: crate::net::network::NetworkState::default(),
                new: crate::net::network::NetworkState::from_json(
                    r#"{"type": "wifi", "interface": "wlan0", "ssid": "home"}"#,
                )
                .unwrap(),
            },
            "capabilities": InstanceCapabilities {
                version: "0.15.0".into(), has_tun: true, opens_tun: false, protects_sockets: true,
                needs_network: false, has_modes: true,
            },
            "sail_capabilities": Capabilities {
                version: "0.15.0", commit: "5b1dfad5", features: vec!["inbound-socks"],
            },
            "providers": Providers { providers: vec![Provider {
                tag: "sub".into(), source: "remote".into(), members: 3,
                updated_ms: Some(millis_since_epoch(at)), next_update_ms: None,
                failure: Some(Failure { at_ms: 1, error: "http status 503".into() }),
                subscription: Some(Subscription { upload: 1, download: 2, total: 3, expire_ms: None }),
            }] },
            "users": Users { users: vec![User {
                name: "alice".into(), inbounds: vec!["t".into()], active: false, over_quota: true,
                expired: false,
                limits: Limits { max_connections: Some(2), max_tcp_connections: Some(1), quota_bytes: Some(10), expire_at_ms: Some(millis_since_epoch(at)),
                                 up_mbps: None, down_mbps: Some(5), total_mbps: Some(8) },
                traffic: Counts { up: 1, down: 2, tcp: 3, udp: 4 }, live: 1, quota_used: 12,
            }] },
            "inbounds": Inbounds { inbounds: vec![Inbound {
                tag: "t".into(), protocol: "trojan".into(), listen: Some("::".into()),
                listen_port: Some(443), reloadable: true,
            }] },
            "system_change": SystemChange {
                kind: "route".into(), resource: "route 0.0.0.0/0 into tun0: gone".into(),
            },
            "user_event": UserEvent {
                event: "removed", user: "alice".into(), over_quota: false, expired: false,
                inbound: Some("t".into()),
            },
            "inbound_users": InboundUsers { users: vec!["alice".into()] },
            "stats": Stats {
                users: [("alice".to_string(), Counts { up: 1, down: 2, tcp: 3, udp: 0 })].into(),
                inbounds: Default::default(), outbounds: Default::default(),
            },
            "rule_sets": RuleSets { rule_sets: vec![RuleSet {
                tag: "ads".into(), source: "local".into(), format: Some("clash-yaml".into()),
                behavior: Some("domain".into()), rules: 9, updated_ms: None, next_update_ms: None, failure: None,
            }] },
        });
        // The published shape: the bindings' tests read it too.
        let published = include_str!("json_snapshot.json");
        let published: serde_json::Value = serde_json::from_str(published).unwrap();
        let mut gone = Vec::new();
        missing("", &published, &snapshot, &mut gone);
        assert!(
            snapshot == published,
            "the JSON hosts read changed. {}Now:\n{:#}",
            if gone.is_empty() {
                "Something was added or a value changed: update json_snapshot.json.\n".to_string()
            } else {
                format!(
                    "Gone or renamed: {}. That breaks hosts: it follows the sail \
                     release and needs a release note.\n",
                    gone.join(", ")
                )
            },
            snapshot
        );
    }

    /// The keys of `published`, as paths, that `now` has no more.
    fn missing(
        at: &str,
        published: &serde_json::Value,
        now: &serde_json::Value,
        gone: &mut Vec<String>,
    ) {
        use serde_json::Value;
        match (published, now) {
            (Value::Object(was), Value::Object(is)) => {
                for (key, value) in was {
                    let path = format!("{}/{}", at, key);
                    match is.get(key) {
                        Some(now) => missing(&path, value, now, gone),
                        None => gone.push(path),
                    }
                }
            }
            (Value::Array(was), Value::Array(is)) => {
                for (n, (value, now)) in was.iter().zip(is).enumerate() {
                    missing(&format!("{}/{}", at, n), value, now, gone);
                }
            }
            _ => {}
        }
    }
}
