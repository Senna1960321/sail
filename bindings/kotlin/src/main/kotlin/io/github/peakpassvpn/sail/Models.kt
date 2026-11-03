package io.github.peakpassvpn.sail

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A call that failed: its SAIL_ERR_* code, and what sail said. */
class SailException(val code: Int, message: String) : Exception(message) {
    companion object {
        const val INVALID_ARGUMENT = 1
        const val NO_INSTANCE = 2
        const val STATE = 3
        const val CONFIG = 4
        const val IO = 5
        const val NOT_FOUND = 6
        const val UNSUPPORTED = 7
        const val CANCELLED = 8
        const val TIMEOUT = 9
        const val WRONG_THREAD = 10
        /** Also any code this binding does not name, from a newer sail. */
        const val INTERNAL = 11
        /** An essential task panicked: the instance failed. */
        const val PANICKED = 12
        /** A reload changes what only a start sets up (a TUN): stop and start. */
        const val NEEDS_RESTART = 13
        /** A TUN's device name is in use. */
        const val TUN_NAME_TAKEN = 14
        /** A reload lost an inbound it was to replace on its own address. */
        const val INBOUND_LOST = 15
    }
}

/**
 * sail's JSON carries no version: it only grows, and what this binding does
 * not know of a newer sail (a field, a string value) is ignored. Every field
 * added from now on has a default, so that an older sail's JSON, without
 * it, decodes too.
 */
internal val json = Json { ignoreUnknownKeys = true }

@Serializable
data class State(
    /** idle, starting, running, stopping, stopped or failed. */
    val state: String,
    val error: String? = null,
    /** The failure's kind: panicked, config, tun_name_taken, ... */
    @SerialName("error_kind") val errorKind: String? = null,
    /** What the failed run's teardown left in the system. */
    val left: List<Left> = emptyList(),
    @SerialName("started_at_ms") val startedAtMs: Long? = null,
)

/** Something an instance's teardown could not undo in the system. */
@Serializable
data class Left(
    /** tun, route, rule, dns, nft, wfp, file or task; more may come. */
    val kind: String,
    val resource: String,
    val why: String,
    /** The command that clears it by hand, where there is one. */
    val clear: String? = null,
)

/** What a stop could not end or undo. */
@Serializable
data class StopReport(
    val tasks: List<StopTask> = emptyList(),
    @SerialName("waited_ms") val waitedMs: Long = 0,
    val left: List<Left> = emptyList(),
)

@Serializable
data class StopTask(val name: String, val count: Int)

@Serializable
data class Traffic(
    @SerialName("up_total") val upTotal: Long,
    @SerialName("down_total") val downTotal: Long,
    val connections: Int,
    val memory: Long,
    /** The panics of tasks the instance went on after, in this run. */
    val faults: Long = 0,
)

/** A status event: the traffic, and its rate in bytes a second. */
@Serializable
data class Status(
    val up: Long,
    val down: Long,
    @SerialName("up_total") val upTotal: Long,
    @SerialName("down_total") val downTotal: Long,
    val connections: Int,
    val memory: Long,
    val faults: Long = 0,
)

/** What a reload did. */
@Serializable
data class ReloadReport(
    /** full, or inbounds_only: the rest, and what it held, kept as it ran. */
    val path: String,
    val inbounds: List<ReloadedInbound> = emptyList(),
    val notes: List<ReloadNote> = emptyList(),
    /** What a recheck of the connections open did; only when one was asked for. */
    val recheck: Recheck? = null,
    /** The users whose limits the host set the reload dropped: it changed theirs. */
    @SerialName("user_limits_dropped") val userLimitsDropped: List<String> = emptyList(),
)

/** A reload's recheck of the connections open. */
@Serializable
data class Recheck(
    /** Those closed, the new rules rejecting or dropping them. */
    val closed: List<RecheckClosed> = emptyList(),
    /** Those the new rules send to another outbound: they go on. */
    val differ: List<RecheckDiffer> = emptyList(),
)

@Serializable
data class RecheckClosed(
    /** As [Connection.id]. */
    val id: Long,
    /** The index in `route.rules` of the rule that rejects it; null for `final`. */
    val rule: Int? = null,
)

@Serializable
data class RecheckDiffer(
    val id: Long,
    /** The outbound it went to. */
    val old: String,
    /** The one the rules send it to now; `hijack-dns` for a hijack-dns rule. */
    val new: String,
)

@Serializable
data class ReloadedInbound(
    val tag: String,
    /** untouched, reloaded, added, removed, replaced, lost; only removed and replaced closed connections. */
    val change: String,
)

@Serializable
data class ReloadNote(
    /** endpoint_keeps_defaults; more may come. */
    val kind: String,
    val text: String,
    val endpoint: String? = null,
    val options: List<String> = emptyList(),
)

/** An event of a kind that can lag: the event, or how many the host missed. */
sealed class Told<out T> {
    data class Event<T>(val value: T) : Told<T>()
    data class Lagged(val missed: Long) : Told<Nothing>()
}

/** A connection routed, and dialled where the rules sent it. */
@Serializable
data class Routed(
    val id: Long? = null,
    val network: String,
    val inbound: String,
    val user: String? = null,
    val source: String,
    val destination: String,
    @SerialName("request_destination") val requestDestination: String? = null,
    val domain: String? = null,
    /** request, fake_ip, sniffed or reverse_mapping. */
    @SerialName("domain_source") val domainSource: String? = null,
    @SerialName("sniffed_protocol") val sniffedProtocol: String? = null,
    val rule: Int? = null,
    @SerialName("rule_text") val ruleText: String? = null,
    /** outbound, reject, drop or hijack_dns. */
    val action: String,
    val chain: List<String> = emptyList(),
    val target: String? = null,
    @SerialName("connect_ms") val connectMs: Long? = null,
    @SerialName("connect_error") val connectError: String? = null,
)

/**
 * What a connection sent and received since it started, as it closed or
 * at an interim pass: its closed record's totals are what it was counted.
 */
@Serializable
data class ConnectionRecord(
    val id: Long,
    /** When the instance's run started, Unix ms: with [id], it names the connection. */
    @SerialName("run_ms") val runMs: Long,
    val seq: Int,
    /** interim, or closed. */
    val kind: String,
    /** finished, error, idle_timeout, write_stall, closed or aborted. */
    val end: String? = null,
    val error: String? = null,
    /** api, user, inbound, rules, network or stopped. */
    @SerialName("closed_by") val closedBy: String? = null,
    /** For a closed record: ok, dial_failed, blocked or rejected. */
    val outcome: String? = null,
    val network: String,
    val user: String? = null,
    val inbound: String,
    val source: String,
    /** The address it connected to; 0.0.0.0:0 where it is not known. */
    val local: String,
    val destination: String,
    @SerialName("request_destination") val requestDestination: String? = null,
    val domain: String? = null,
    @SerialName("domain_source") val domainSource: String? = null,
    /** The outbound the rules sent it to. */
    val outbound: String? = null,
    val chain: List<String> = emptyList(),
    @SerialName("up_total") val upTotal: Long,
    @SerialName("down_total") val downTotal: Long,
    @SerialName("start_ms") val startMs: Long,
    @SerialName("at_ms") val atMs: Long,
)

/** A DNS query answered or failed. */
@Serializable
data class DnsExchange(
    val name: String,
    val qtype: String,
    @SerialName("qtype_code") val qtypeCode: Int,
    val server: String? = null,
    /** exchanged, cached, optimistic or rule. */
    val source: String,
    val rcode: String? = null,
    @SerialName("rcode_code") val rcodeCode: Int? = null,
    val error: String? = null,
    val answers: List<String> = emptyList(),
    @SerialName("answers_total") val answersTotal: Long,
    val ttl: Long? = null,
    @SerialName("duration_ms") val durationMs: Long? = null,
    val attempt: Int? = null,
    @SerialName("for_instance") val forInstance: Boolean,
)

/** A group took another member. */
@Serializable
data class GroupSwitch(
    val group: String,
    val from: String? = null,
    val to: String,
    /** member_down, test_failed, recovered, all_down, pinned, unpinned, selected, faster or members_changed. */
    val reason: String,
)

/** Dials through a chain failed, since its event before. */
@Serializable
data class DialFailed(
    val chain: String,
    val destination: String,
    val error: String,
    /** dial, handshake or transfer. */
    val stage: String,
    @SerialName("more_to_try") val moreToTry: Boolean,
    val count: Long,
)

/**
 * Something sail set up on the system for a TUN that someone else changed,
 * and that sail left: restoring it or rebuilding the instance is the host's.
 */
@Serializable
data class SystemChange(
    /** route, dns or tun; more may come. */
    val kind: String,
    /** What and how, the TUN named first: "route 0.0.0.0/0 into tun0: gone". */
    val resource: String,
)

/** What happened to a user. */
@Serializable
data class UserEvent(
    /** shut (over its quota or past its expiry) or removed (from an inbound). */
    val event: String,
    val user: String,
    @SerialName("over_quota") val overQuota: Boolean = false,
    val expired: Boolean = false,
    val inbound: String? = null,
)

/** A task of the instance panicked. */
@Serializable
data class Fault(
    /** The task's name: inbound tcp, group health check, ... */
    val task: String,
    /** contained (the task alone ended) or essential (the instance failed). */
    val `class`: String,
    val message: String,
    /** The instance's contained panics so far, in this run. */
    val count: Long,
)

/** A fault event: a fault, or how many the host fell behind on. */
sealed class FaultEvent {
    data class Panicked(val fault: Fault) : FaultEvent()
    data class Lagged(val missed: Long) : FaultEvent()
}

@Serializable
data class Connection(
    val id: Long,
    val network: String,
    @SerialName("inbound_type") val inboundType: String,
    @SerialName("inbound_tag") val inboundTag: String,
    val source: String,
    val destination: String,
    /** The domain it goes to: the destination's, else the name it was dialled as, else the one sniffed. */
    val host: String? = null,
    /** The domain a sniff found, from a TLS server name or an HTTP Host. */
    @SerialName("sniff_host") val sniffHost: String? = null,
    /** Where the name it was dialled as came from, `sniff` or `reverse_mapping`; null where it was dialled as asked. */
    @SerialName("dial_domain_source") val dialDomainSource: String? = null,
    val process: String? = null,
    val user: String? = null,
    /** Who opened it, as the host told (Android). */
    val uid: Long? = null,
    val packages: List<String> = emptyList(),
    val upload: Long,
    val download: Long,
    /** Unix seconds. */
    val start: Long,
    val chains: List<String>,
    val rule: String? = null,
)

@Serializable
data class Delay(
    @SerialName("time_ms") val timeMs: Long,
    /** null for a test that failed. */
    @SerialName("delay_ms") val delayMs: Long? = null,
)

@Serializable
data class Group(val selected: String, val members: List<String>, val selectable: Boolean)

@Serializable
data class Outbound(
    val tag: String,
    /** Mihomo's type name: Selector, Vless, Direct. */
    val kind: String,
    /** sing-box's type; null for a provider's member. */
    val protocol: String? = null,
    val provider: String? = null,
    val udp: Boolean,
    val history: List<Delay>,
    val group: Group? = null,
)

/** A connection whose owner the host is asked for. */
@Serializable
data class ConnectionQuery(val network: String, val source: String, val destination: String)

/** Who opened a connection, as the host tells sail. */
@Serializable
data class ConnectionOwner(val uid: Long, val user: String? = null, val packages: List<String> = emptyList())

@Serializable
data class Mode(val mode: String, val modes: List<String>)

@Serializable
data class LogLine(val level: String, val message: String, @SerialName("time_ms") val timeMs: Long)

/** A log event: `reset` drops the lines had so far. */
@Serializable
data class Log(val reset: Boolean, val lines: List<LogLine>, val dropped: Long)

@Serializable
data class InstanceCapabilities(
    /**
     * The sail release the instance runs: through a client, the tunnel
     * process's, which may differ from [Sail.capabilities]' after an update.
     */
    val version: String? = null,
    @SerialName("has_tun") val hasTun: Boolean,
    @SerialName("opens_tun") val opensTun: Boolean,
    @SerialName("protects_sockets") val protectsSockets: Boolean,
    @SerialName("needs_network") val needsNetwork: Boolean,
    @SerialName("has_modes") val hasModes: Boolean,
)

@Serializable
data class Capabilities(
    /** The sail release. */
    val version: String,
    /** The modules compiled in: what was built, not which calls there are. */
    val features: List<String>,
    /** The commit it was built from: a short hash, or `unknown`; null from a sail before it was told. */
    val commit: String? = null,
)

@Serializable
internal data class Connections(val connections: List<Connection>)

@Serializable
internal data class Outbounds(val outbounds: List<Outbound>)

/** An update's failure: when, and why (with no URL in it). */
@Serializable
data class UpdateFailure(@SerialName("at_ms") val atMs: Long, val error: String)

/** What a subscription's server says of it. */
@Serializable
data class Subscription(
    val upload: Long,
    val download: Long,
    val total: Long,
    @SerialName("expire_ms") val expireMs: Long? = null,
)

/** An outbound provider: its members are among the outbounds. */
@Serializable
data class Provider(
    val tag: String,
    /** remote, local or inline. */
    val source: String,
    val members: Long,
    @SerialName("updated_ms") val updatedMs: Long? = null,
    /** Null when it is not updated by itself. */
    @SerialName("next_update_ms") val nextUpdateMs: Long? = null,
    /** The last update's, null after a success. */
    val failure: UpdateFailure? = null,
    val subscription: Subscription? = null,
)

@Serializable
data class RuleSet(
    val tag: String,
    /** remote, local or inline. */
    val source: String,
    val format: String? = null,
    val behavior: String? = null,
    val rules: Long,
    @SerialName("updated_ms") val updatedMs: Long? = null,
    @SerialName("next_update_ms") val nextUpdateMs: Long? = null,
    val failure: UpdateFailure? = null,
)

@Serializable
internal data class Providers(val providers: List<Provider>)

@Serializable
internal data class RuleSets(@SerialName("rule_sets") val ruleSets: List<RuleSet>)
