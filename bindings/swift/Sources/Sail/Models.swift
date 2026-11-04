// What sail answers with: its JSON (sail::control::json), decoded.

import Foundation

/// A call that failed: its `SAIL_ERR_*` code, and what sail said.
public struct SailError: Error, CustomStringConvertible, Equatable {
    public let code: Int32
    public let message: String

    public var description: String { "sail error \(code): \(message)" }

    public static let invalidArgument: Int32 = 1
    public static let noInstance: Int32 = 2
    public static let state: Int32 = 3
    public static let config: Int32 = 4
    public static let io: Int32 = 5
    public static let notFound: Int32 = 6
    public static let unsupported: Int32 = 7
    public static let cancelled: Int32 = 8
    public static let timeout: Int32 = 9
    public static let wrongThread: Int32 = 10
    /// Also any code this binding does not name, from a newer sail.
    public static let `internal`: Int32 = 11
    /// An essential task panicked: the instance failed.
    public static let panicked: Int32 = 12
    /// A reload changes what only a start sets up (a TUN): stop and start.
    public static let needsRestart: Int32 = 13
    /// A TUN's device name is in use.
    public static let tunNameTaken: Int32 = 14
    /// A reload lost an inbound it was to replace on its own address.
    public static let inboundLost: Int32 = 15
}

public struct State: Decodable, Equatable, Sendable {
    /// idle, starting, running, stopping, stopped or failed.
    public let state: String
    public let error: String?
    /// The failure's kind: panicked, config, tun_name_taken, ...
    public let errorKind: String?
    /// What the failed run's teardown left in the system; nil from an older sail.
    public let left: [Left]?
    public let startedAtMs: UInt64?
}

/// What a reload did.
public struct ReloadReport: Decodable, Equatable, Sendable {
    /// full, or inbounds_only: the rest, and what it held, kept as it ran.
    public let path: String
    public let inbounds: [ReloadedInbound]
    public let notes: [ReloadNote]
    /// What a recheck of the connections open did; only when one was asked
    /// for.
    public let recheck: Recheck?
    /// The users whose limits the host set the reload dropped: it changed
    /// what the configuration sets for them.
    public let userLimitsDropped: [String]
}

/// What a reload does with the connections open.
public enum RecheckOpen: String, Sendable {
    /// They go on as they were routed (the default).
    case keep
    /// Each is matched again against the new rules: those they reject or
    /// drop are closed.
    case closeRejected = "close_rejected"
}

/// A reload's recheck of the connections open.
public struct Recheck: Decodable, Equatable, Sendable {
    /// Those closed, the new rules rejecting or dropping them.
    public let closed: [RecheckClosed]
    /// Those the new rules send to another outbound: they go on.
    public let differ: [RecheckDiffer]
}

public struct RecheckClosed: Decodable, Equatable, Sendable {
    /// As `Connection.id`.
    public let id: UInt64
    /// The index in `route.rules` of the rule that rejects it; nil for
    /// `final`.
    public let rule: UInt32?
}

public struct RecheckDiffer: Decodable, Equatable, Sendable {
    public let id: UInt64
    /// The outbound it went to.
    public let old: String
    /// The one the rules send it to now; `hijack-dns` for a hijack-dns rule.
    public let new: String
}

public struct ReloadedInbound: Decodable, Equatable, Sendable {
    public let tag: String
    /// untouched, reloaded, added, removed, replaced, lost; only removed and
    /// replaced closed connections.
    public let change: String
}

public struct ReloadNote: Decodable, Equatable, Sendable {
    /// endpoint_keeps_defaults; more may come.
    public let kind: String
    public let text: String
    public let endpoint: String?
    public let options: [String]
}

/// An event of a kind that can lag: the event, or how many of its kind the
/// host fell behind on and missed.
public enum Told<T: Decodable & Equatable & Sendable>: Decodable, Equatable, Sendable {
    case event(T)
    case lagged(UInt64)

    private enum Keys: String, CodingKey { case lagged }

    public init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: Keys.self)
        if let missed = try keys.decodeIfPresent(UInt64.self, forKey: .lagged) {
            self = .lagged(missed)
        } else {
            self = .event(try T(from: decoder))
        }
    }
}

/// A connection routed, and dialled where the rules sent it.
public struct Routed: Decodable, Equatable, Sendable {
    public let id: UInt64?
    public let network: String
    public let inbound: String
    public let user: String?
    public let source: String
    public let destination: String
    public let requestDestination: String?
    public let domain: String?
    /// request, fake_ip, sniffed or reverse_mapping.
    public let domainSource: String?
    public let sniffedProtocol: String?
    public let rule: UInt32?
    public let ruleText: String?
    /// outbound, reject, drop or hijack_dns.
    public let action: String
    public let chain: [String]
    public let target: String?
    public let connectMs: UInt64?
    public let connectError: String?
}

/// What a connection sent and received since it started, as it closed or
/// at an interim pass: its closed record's totals are what it was counted.
public struct ConnectionRecord: Decodable, Equatable, Sendable {
    public let id: UInt64
    /// When the instance's run started, Unix ms: with `id`, it names the
    /// connection.
    public let runMs: UInt64
    public let seq: UInt32
    /// interim, or closed.
    public let kind: String
    /// finished, error, idle_timeout, write_stall, closed or aborted.
    public let end: String?
    public let error: String?
    /// api, user, inbound, rules, network, stopped or host.
    public let closedBy: String?
    /// For a closed record: ok, dial_failed, blocked or rejected.
    public let outcome: String?
    /// For one the host's check rejected (closed_by host): why, as the
    /// check told it.
    public let reason: String?
    public let network: String
    public let user: String?
    public let inbound: String
    public let source: String
    /// The address it connected to; 0.0.0.0:0 where it is not known.
    public let local: String
    public let destination: String
    public let requestDestination: String?
    public let domain: String?
    public let domainSource: String?
    /// The outbound the rules sent it to.
    public let outbound: String?
    public let chain: [String]
    public let upTotal: UInt64
    public let downTotal: UInt64
    public let startMs: UInt64
    public let atMs: UInt64
}

/// A DNS query answered or failed.
public struct DnsExchange: Decodable, Equatable, Sendable {
    public let name: String
    public let qtype: String
    public let qtypeCode: UInt16
    public let server: String?
    /// exchanged, cached, optimistic or rule.
    public let source: String
    public let rcode: String?
    public let rcodeCode: UInt16?
    public let error: String?
    public let answers: [String]
    public let answersTotal: UInt32
    public let ttl: UInt32?
    public let durationMs: UInt64?
    public let attempt: UInt32?
    public let forInstance: Bool
}

/// A group took another member.
public struct GroupSwitch: Decodable, Equatable, Sendable {
    public let group: String
    public let from: String?
    public let to: String
    /// member_down, test_failed, recovered, all_down, pinned, unpinned,
    /// selected, faster or members_changed.
    public let reason: String
}

/// Dials through a chain failed, since its event before.
public struct DialFailed: Decodable, Equatable, Sendable {
    public let chain: String
    public let destination: String
    public let error: String
    /// dial, handshake or transfer.
    public let stage: String
    public let moreToTry: Bool
    public let count: UInt64
}

/// Something sail set up on the system for a TUN that someone else changed,
/// and that sail left: restoring it or rebuilding the instance is the host's.
public struct SystemChange: Decodable, Equatable, Sendable {
    /// route, dns or tun; more may come.
    public let kind: String
    /// What and how, the TUN named first: "route 0.0.0.0/0 into tun0: gone".
    public let resource: String
}

/// What happened to a user.
public struct UserEvent: Decodable, Equatable, Sendable {
    /// shut (over its quota or past its expiry) or removed (from an inbound).
    public let event: String
    public let user: String
    public let overQuota: Bool
    public let expired: Bool
    public let inbound: String?
}

/// A task of the instance panicked.
public struct Fault: Decodable, Equatable, Sendable {
    /// The task's name: inbound tcp, group health check, ...
    public let task: String
    /// contained (the task alone ended) or essential (the instance failed).
    public let `class`: String
    public let message: String
    /// The instance's contained panics so far, in this run.
    public let count: UInt64
}

/// A fault event: a fault, or how many the host fell behind on.
public enum FaultEvent: Decodable, Equatable, Sendable {
    case panicked(Fault)
    case lagged(UInt64)

    private enum Keys: String, CodingKey { case lagged }

    public init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: Keys.self)
        if let missed = try keys.decodeIfPresent(UInt64.self, forKey: .lagged) {
            self = .lagged(missed)
        } else {
            self = .panicked(try Fault(from: decoder))
        }
    }
}

/// Something an instance's teardown could not undo in the system.
public struct Left: Decodable, Equatable, Sendable {
    /// tun, route, rule, dns, nft, wfp, file or task; more may come.
    public let kind: String
    public let resource: String
    public let why: String
    /// The command that clears it by hand, where there is one.
    public let clear: String?
}

/// What a stop could not end or undo.
public struct StopReport: Decodable, Equatable, Sendable {
    public let tasks: [StopTask]
    public let waitedMs: UInt64
    public let left: [Left]
}

public struct StopTask: Decodable, Equatable, Sendable {
    public let name: String
    public let count: Int
}

public struct Traffic: Decodable, Equatable, Sendable {
    public let upTotal: UInt64
    public let downTotal: UInt64
    public let connections: Int
    public let memory: UInt64
    /// The panics of tasks the instance went on after, in this run; nil
    /// from an older sail.
    public let faults: UInt64?
}

/// A status event: the traffic, and its rate in bytes a second.
public struct Status: Decodable, Equatable, Sendable {
    public let up: UInt64
    public let down: UInt64
    public let upTotal: UInt64
    public let downTotal: UInt64
    public let connections: Int
    public let memory: UInt64
    public let faults: UInt64?
}

public struct Connection: Decodable, Equatable, Sendable {
    public let id: UInt64
    public let network: String
    public let inboundType: String
    public let inboundTag: String
    public let source: String
    public let destination: String
    /// The domain it goes to: the destination's, else the name it was
    /// dialled as, else the one sniffed.
    public let host: String?
    /// The domain a sniff found, from a TLS server name or an HTTP Host.
    public let sniffHost: String?
    /// Where the name it was dialled as came from, `sniff` or
    /// `reverse_mapping`; nil where it was dialled as asked.
    public let dialDomainSource: String?
    public let process: String?
    public let user: String?
    /// Who opened it, as the host told (Android).
    public let uid: UInt32?
    public let packages: [String]
    public let upload: UInt64
    public let download: UInt64
    /// Unix seconds.
    public let start: UInt32
    public let chains: [String]
    public let rule: String?
}

public struct Delay: Decodable, Equatable, Sendable {
    public let timeMs: UInt64
    /// nil for a test that failed.
    public let delayMs: UInt64?
}

public struct Group: Decodable, Equatable, Sendable {
    public let selected: String
    public let members: [String]
    public let selectable: Bool
}

public struct Outbound: Decodable, Equatable, Sendable {
    public let tag: String
    /// Mihomo's type name: Selector, Vless, Direct.
    public let kind: String
    /// sing-box's type; nil for a provider's member.
    public let `protocol`: String?
    public let provider: String?
    public let udp: Bool
    public let history: [Delay]
    public let group: Group?
}

/// A connection whose owner the host is asked for.
public struct ConnectionQuery: Decodable, Equatable, Sendable {
    /// tcp or udp.
    public let network: String
    public let source: String
    public let destination: String
}

/// Who opened a connection, as the host tells sail.
public struct ConnectionOwner: Encodable, Equatable, Sendable {
    public let uid: UInt32
    public let user: String?
    public let packages: [String]

    public init(uid: UInt32, user: String? = nil, packages: [String] = []) {
        self.uid = uid
        self.user = user
        self.packages = packages
    }
}

/// An update's failure: when, and why (with no URL in it).
public struct UpdateFailure: Decodable, Equatable, Sendable {
    public let atMs: UInt64
    public let error: String
}

/// What a subscription's server says of it.
public struct Subscription: Decodable, Equatable, Sendable {
    public let upload: UInt64
    public let download: UInt64
    public let total: UInt64
    public let expireMs: UInt64?
}

/// An outbound provider: its members are among the outbounds.
public struct Provider: Decodable, Equatable, Sendable {
    public let tag: String
    /// remote, local or inline.
    public let source: String
    public let members: UInt64
    public let updatedMs: UInt64?
    /// Nil when it is not updated by itself.
    public let nextUpdateMs: UInt64?
    /// The last update's, nil after a success.
    public let failure: UpdateFailure?
    public let subscription: Subscription?
}

public struct RuleSet: Decodable, Equatable, Sendable {
    public let tag: String
    /// remote, local or inline.
    public let source: String
    public let format: String?
    public let behavior: String?
    public let rules: UInt64
    public let updatedMs: UInt64?
    public let nextUpdateMs: UInt64?
    public let failure: UpdateFailure?
}

/// What `dial` connects.
public enum DialNetwork: String, Sendable {
    case tcp
    case udp
}

public struct Mode: Decodable, Equatable, Sendable {
    public let mode: String
    public let modes: [String]
}

public struct LogLine: Decodable, Equatable, Sendable {
    public let level: String
    public let message: String
    public let timeMs: UInt64
}

/// A log event: `reset` drops the lines had so far.
public struct Log: Decodable, Equatable, Sendable {
    public let reset: Bool
    public let lines: [LogLine]
    public let dropped: UInt64
}

public struct InstanceCapabilities: Decodable, Equatable, Sendable {
    /// The sail release the instance runs: through a client, the tunnel
    /// process's, which may differ from `Sail.capabilities()`' after an
    /// update. Nil from an older sail.
    public let version: String?
    public let hasTun: Bool
    public let opensTun: Bool
    public let protectsSockets: Bool
    public let needsNetwork: Bool
    public let hasModes: Bool
}

/// sail's JSON carries no version: it only grows. Decoding ignores what a
/// newer sail adds, and every field added from now on is optional, so that
/// an older sail's JSON, without it, decodes too.
public struct Capabilities: Decodable, Equatable, Sendable {
    /// The sail release.
    public let version: String
    /// The modules compiled in: what was built, not which calls there are.
    public let features: [String]
    /// The commit it was built from: a short hash, or `unknown`; nil from
    /// a sail before it was told.
    public let commit: String?
}

struct Connections: Decodable { let connections: [Connection] }
struct Outbounds: Decodable { let outbounds: [Outbound] }
struct Providers: Decodable { let providers: [Provider] }
struct RuleSets: Decodable { let ruleSets: [RuleSet] }

let decoder: JSONDecoder = {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return decoder
}()

func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
    try decoder.decode(type, from: Data(json.utf8))
}
