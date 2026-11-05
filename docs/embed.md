# sail embedded in a Rust host

`sail::embed` runs sail inside a host's own process, as a library. An
in-process engine, a desktop service or a command-line tool links the
`sail` crate and drives instances through it. It is the only stable part of
the crate, with `sail::muxcore` (A host's own links). The C ABI (`sail-ffi`, docs/ffi.md) is built on it, so the two
behave the same.

```rust
use sail::embed::{Config, Instance, Options};

let instance = Instance::new(Options::new().data_dir(state_dir))?;
let mut states = instance.states();            // subscribe first (see below)
instance.start(Config::Json(sing_box_json)).await?;
let traffic = instance.traffic().await?;
let stream = instance.dial_tcp("node-1", target, timeout).await?;
instance.reload(Some(Config::Json(changed))).await?;
instance.stop().await?;
```

## Compatibility

- **What is stable.** Everything in `sail::embed` only grows. Its structs
  and enums are `non_exhaustive`, and functions and variants are added,
  never changed. `ErrorKind` and its `code()` strings only grow too, so a
  host can map them to its own error codes.
- **Breaking changes.** Before 1.0 a breaking change raises the minor
  version (0.16 → 0.17) and is listed in the release notes, so a host
  should pin the version it builds with.
- **`sail::muxcore`** (feature `muxcore`, A host's own links) follows the
  same rules.
- **Everything else.** Every other module of the crate is public only for
  sail's own crates. It is hidden from the docs and changes without notice.
- **Configuration.** sing-box's JSON is the configuration contract. Clash
  YAML and Surge profiles are read too, as the CLI reads them.

## Building against sail

sail builds with forks of a few crates (BoringSSL bindings, QUIC) through
`[patch.crates-io]`. A `[patch]` section applies only
in the workspace that declares it, so a workspace that depends on sail, even
through another crate, copies sail's section exactly. Its CI checks that the
copy is still exact, after `cargo fetch`:

```sh
python3 path/to/sail/tools/embed-patch-check.py
```

The check finds the sail that the lock file pins, wherever it is in the
dependency graph. It resolves the graph with all the workspace's features,
so it finds sail behind an optional dependency too. Arguments after `--` go
to `cargo metadata` in place of that: `embed-patch-check.py . -- --features
rust-core` checks one feature set. It names each entry that is missing or different, and
passes when every entry matches. Extra entries of the host's own are
allowed.

## Checking a configuration

`sail::embed::check(&config, &options)` reads and builds a configuration
as a start with those options would. It starts nothing: no listener,
no dial, no download. It returns the warnings a start would log (as
`sail -T` prints them), or a `Config` error saying why it does not build.
It blocks while it builds, on a thread of its own, so it may be called
from any thread.

## Which sail

`sail::embed::BUILD` says which sail a host runs, for its diagnostics:
`version` (the release) and `commit` (the short hash it was built from).
The commit is the release build's (`CFG_COMMIT_HASH`, or a `SAIL_COMMIT`
override). Without that, it is git's HEAD when sail is built in a checkout
of its own, which includes the checkout Cargo makes of a git dependency, or
that checkout's revision. It is `unknown` when none of these tells, never
empty. The CLI's `--version` and the C ABI's `sail_capabilities` give the
same.

## Runtime and threads

- **Where it runs.** By default each instance runs on a tokio runtime of
  its own, on threads of its own:
  - two workers with the `mobile` and `desktop` profiles (one on a
    single CPU);
  - a worker per core with the `server` and `router` profiles;
  - or what `Options::threads` says. `sail` the CLI runs each profile the
    same way.
- **On the host's runtime.** `Options::runtime(Runtime::Host(handle))`
  runs the instance's tasks on the host's tokio runtime instead; `threads`
  is then ignored, and two or more instances may share one runtime. For a
  client, a runtime of two workers is recommended, as sail starts for a
  desktop: a connection's tasks wake one another, and with a worker to
  each CPU most of those wakes cross threads (on Windows a Hysteria2
  download cost twice the CPU of two workers, and four times that of
  one). The
  runtime must be:
  - multi-thread, with I/O and timers enabled (`enable_all()`). `start()`
    refuses anything else with `ErrorKind::InvalidArgument`, naming what is
    missing. tokio has no query for I/O or timers, so `start()` tries each
    once; under `panic = "abort"` a runtime without them ends the process
    there instead.
  - built without `unhandled_panic(ShutdownRuntime)` (unstable tokio):
    with it, a connection's contained panic would shut the host's runtime
    down.
  - alive until the instance's `stop()` returns. A runtime dropped under
    a running instance ends its tasks; the instance fails
    (`ErrorKind::Panicked`), and what it changed in the system is still
    undone, on threads of sail's.

  What stays sail's under `Host`: one thread per instance, parked on the
  host's runtime for the instance's life (its start and its stop run
  there); the teardown's steps, each on a thread of its own; the
  `cache_file` writer. The instance's log is its own as on its own
  runtime.

  **The blocking pool** is the host's (tokio's default: at most 512
  threads). sail uses it for: one thread per concurrent lookup on a
  `local` DNS server (the system resolver); one per new connection while
  `Platform::find_connection_owner` answers, or sail looks the owner up
  itself (Linux, macOS), when a rule needs it or `route.find_process` is
  set (packages in the connection list need `route.find_process` on
  Android); one per TUN on Windows while
  it waits for a packet; and short single calls (network detection, the
  default interface, NAT64 discovery, a reload's wait, the stats and
  Clash UI files). A host whose own blocking work is near its pool's limit
  raises `max_blocking_threads`.

  **Stopping** under `Host` ends the instance's tasks as below, then
  shuts nothing down: the runtime is the host's. A task that outlasts
  `stop_within` keeps running on it and is named in `stop()`'s `Timeout`
  and `stop_report()`, as on sail's own runtime.
- **Signals.** An instance takes no signals: Ctrl-C, SIGTERM and SIGHUP
  stay the host's, under either runtime and with sail's `ctrlc` feature
  too (which before made any instance stop on the first two and reload on
  SIGHUP). Only `sail` the CLI's instance takes them.
- **Calling it.** The calls are `async` and runtime-agnostic: the host
  awaits them on its own runtime, or on any executor. The work runs on the
  instance's runtime, and the host's future waits for the answer.
- **Stopping.** `stop().await` returns once the instance's thread has ended
  and, on its own runtime, the runtime is gone. By then its listeners are
  closed and its connections dropped. A stream or datagram socket that was
  dialled through the instance then fails; it does not hang.
- **Dropping.** Dropping the last clone of an `Instance` asks it to stop but
  does not wait: the instance's own thread stops it in the background,
  in the order of a `stop()` (below), within `stop_within` and the
  teardown steps' bounds (5 s each). A host that drops it and exits at
  once can leave routes, rules or a TUN behind. Await `stop()` first.
- **Errors.** `ErrorKind::WrongThread` never comes from these async calls.
  Only the blocking wrappers the C ABI uses give it, when they are called on
  one of the instance's own threads (from a `Platform` callback, for
  example). It means a misuse.

## Memory

sail leaves the allocator to whoever links it, and never calls one. A
start, a reload, and a provider's or rule-set's update parse a document and
drop it; an allocator that gives freed memory back to the system only as
later allocations run keeps that peak while the instance idles.
`sail::runtime::memory::on_memory_freed` registers what gives it back.
sail runs it after a start, after each reload, and after a provider's or a
rule-set's update, whether the document was taken or refused: on the task
that loaded it, never on a connection's path. It is process-wide, and the
first registration stays: two instances run the same one, each after its
own loads. The `sail` command registers mimalloc's collect (its router
build, with musl's allocator, registers nothing). A host
registers what its own allocator needs, or nothing: glibc's malloc keeps
freed memory too, which `malloc_trim(0)` gives back; an allocator that
returns memory by itself needs nothing.

**Several instances on glibc.** glibc's malloc gives the threads that
allocate arenas of their own, up to eight a core, and keeps in each what
was freed there. Instances on runtimes of their own each bring their
workers, and their arenas outlive them. Measured on Linux x86-64, 4
cores, each instance of its own runtime on 4 workers (the desktop
profile's default was a worker per core then; it is two now)
(`sail/tests/test_hundred_instances.rs`: 100 instances one after
another, then ten rounds of ten at once, each relaying a connection):

| | RSS after, from 64 MB |
|---|---|
| runtimes of their own (`Runtime::Own`) | 264 MB |
| the same, `MALLOC_ARENA_MAX=2` | 92 MB |
| the host's runtime (`Runtime::Host`) | 133 MB |
| the same, `MALLOC_ARENA_MAX=2` | 79 MB |

The bytes alive came back within a few KiB each time: this is the
allocator keeping memory, not sail holding it. `malloc_trim(0)` gave back
less than a tenth of it, and `on_memory_freed` runs after loads, not
after stops. A glibc host that runs instances side by side or one after
another sets `MALLOC_ARENA_MAX` (2 here; `mallopt(M_ARENA_MAX, …)` before
its first thread does the same), runs them on its own runtime, or links
an allocator of its own (the `sail` command links mimalloc). Only glibc
was measured.

## Logging

- **Without a subscriber of your own.** sail logs as its configuration's
  `log` says, to standard output, a file or the system log.
- **With your own subscriber.** A host that installs a `tracing` subscriber
  of its own adds `sail::embed::tracing_layer()` to it. Each instance's
  lines then reach its `Instance::logs()`, filtered at that instance's
  `log.level`. The host's own layers see sail's lines (targets `sail::…`)
  as they see any crate's, and a configuration's `log.output` is then the
  host's business.
- **The host's global filters apply first.** Let `sail` targets through at
  the levels the instances log at.
- **Redaction is each instance's.** `log.redact` takes destinations,
  sources or processes out of the INFO, WARN and ERROR lines of the
  instance whose configuration names them, and out of its dial-failure
  events; another instance in the process logs as its own says. The text
  is redacted where it is made, so every layer, the host's included, gets
  it redacted. A reload changes it.

## Certificates

An inbound's certificate and key files, replaced on disk, are served from
the next handshake on, with no reload, whether or not the configuration
file is watched. This needs sail built with its `auto-reload` feature (on
by default in sail-ffi). A Rust host that picks sail's features keeps it.


## Reload

`reload(Some(config))` changes a running instance in place. It builds
everything new before it replaces anything, so a reload that fails changes
nothing.

**What did not change is left alone.** A configuration that differs from
what runs in its `inbounds` (and `user_limits`) alone changes the
inbounds and builds nothing else again: the outbounds are those that
ran, with the multiplexed and QUIC sessions they hold; the groups keep
their member, their checks and what they measured; the DNS client keeps
its cache; the routing and the rule-sets are untouched.
`ReloadReport::path` says which it was: `InboundsOnly`, or `Full`, where
the rest of this section applies.

- "The same" is told of the configuration as it is read, not of its
  text: spacing, the order of keys and defaults written out do not count.
- A file the configuration names is not seen by that comparison. Those
  sail follows itself are taken when they change, with no reload: an
  inbound's certificate and key, a local rule-set. Those it reads once,
  when what names them is built, are looked at by size and time of
  modification at each reload, and one written since makes the reload a
  full one: root certificates (`certificate_path`,
  `certificate_directory_path`), an outbound's certificate and key files,
  a provider's or a rule-set's file other than a followed local one, the
  geo databases. A directory is seen to change when an entry is added or
  removed, not when a file in it is rewritten.
- An outbound added or removed while it ran (`add_outbound`,
  `remove_outbound`) is not in the configuration: the reload after is a
  full one, and goes by the configuration.
- A reload with the very configuration that runs is one of the inbounds
  alone that finds them untouched: it no longer empties the DNS cache or
  starts the groups' checks over. To have everything built again, change
  something else, or stop and start.

`ReloadReport::notes` tells what a reload took and did not reach
everything with. Today there is one: an endpoint (WireGuard) is only set
up at a start, so a reload that changes the defaults every dial goes by
(`route.default_interface`, `auto_detect_interface`, `default_mark`,
`default_domain_resolver`, the `default_network_*` options,
`dns.strategy`) while an endpoint runs is taken, applies to everything
else, and gives `ReloadNote::EndpointKeepsDefaults` for each endpoint
with the options that changed: the endpoint, and the outbounds it is
built on, go on with those they were built with until the next start.
The log has the same as a warning.

A full reload:

| | after a full reload |
|---|---|
| inbounds | those the configuration has are those that run. Compared by tag with those running: one that is the same is not touched; one whose users, certificate or key alone changed gets them, its listener kept; a new one is built and listens; one the configuration no longer has is removed; one changed otherwise (its port, its type, its transport) is replaced. A TUN is set up only at a start: see below |
| connections already open | kept, on the outbound they were routed through, except those of an inbound removed or replaced, which are closed (tested: `sail/tests/it/test_reload_inbounds.rs`, where connections on an untouched inbound carry on through a reload byte for byte). Not matched against the new rules, unless the reload asks for it: see *Rechecking the connections open* |
| outbounds | rebuilt from the new configuration. Endpoints (WireGuard) and the outbounds they are built on are kept. Tasks the replaced outbounds ran (health checks, idle-session cleanup) stop. The replaced outbounds' sessions (AnyTLS, sing-mux) carry the connections they hold, and close when those connections end |
| group selections, pins | kept, for groups of the same tag |
| delays measured | kept |
| DNS client | rebuilt from the new `dns`. **Its cache starts empty** |
| routing, rule-sets | rebuilt; rule-sets the configuration still names, and already downloaded, are not downloaded again |
| traffic counters | kept. Counters of inbounds and outbounds that are gone are dropped once nothing counts to them |

**The inbounds.** `reload` returns a `ReloadReport`: each inbound of the
configuration, in its order, then those it no longer has, with what
became of it.

| `InboundChange` | the inbound | its connections |
|---|---|---|
| `Untouched` | as it was | go on |
| `Reloaded` | new users, certificate or key; the listener kept | go on (a removed user's are closed) |
| `Added` | built, listening | — |
| `Removed` | stopped | closed |
| `Replaced` | the one before stopped, this one in its place | the one before's are closed |

- **The configuration is what runs.** An inbound added with
  `add_inbound` and not in the configuration reloaded is removed by the
  reload. A host that adds one keeps it in the configuration it reloads
  with, and finds it `Untouched`.
- **Nothing is half applied.** What is new is built and bound before
  anything running is touched, and a reload that cannot bind what it adds
  fails with all as it was. An inbound replaced on the address it has
  must stop before the new one binds: if that bind fails, the one before
  listens again, its connections never touched, and the reload fails.
- **Two errors of their own.**
  - `ErrorKind::NeedsRestart`: the configuration adds, removes or changes
    an inbound that only a start sets up, a TUN. Nothing changed; stop
    and start to apply it.
  - `ErrorKind::InboundLost`: an inbound was to be replaced on its
    address, the new one did not bind, and the one before could not
    listen again (another program took the port meanwhile). The reload
    failed, all else is as it was, and that inbound, which the message
    names, listens no more: reload again, or add it.
- New and replaced inbounds accept once the new routing is in place.
- sing-box closes every connection on a reload: it builds the instance
  anew. sail closes those of the inbounds removed or replaced, and no
  others, unless the reload is asked to recheck the rest (below): then
  it closes those the new rules reject too, and only those.

**Rechecking the connections open.** By default a reload leaves the
connections open as they were routed: a rule added to reject a site
holds for the connections made after it. `reload_rechecking(config,
ReloadOptions::new().recheck_open(RecheckOpen::CloseRejected))` matches
each connection the rules routed, once the reload took, against the
routing it leaves, and closes those the rules now reject or drop, as an
inbound's removal closes its connections. A reload of the inbounds alone,
or with the very configuration that runs, rechecks against the routing
that ran. The report waits for the recheck; `ReloadReport::recheck`
tells it, `None` when none was asked for:

- `closed`: each connection closed, by its id in the connections list,
  with the index in `route.rules` of the rule that rejects it, as the
  routed event names rules.
- `differ`: each connection the rules now send to another outbound than
  the one it went to (`old`, `new`). It is told, and goes on where it
  was: an open connection is never moved.

The recheck has no side effect. It walks the session the connection was
routed with, from the destination asked for, before any override. It
reads nothing more of the connection: from the first sniff rule on, what
was sniffed then stands. It asks no DNS: a resolve rule gives the
addresses resolved then, and a rule on addresses sees no others, as with
`no_resolve`. A rejection counts toward no rule's flood. The network and
the clash mode are as they are now, and the rule-sets as they were
loaded; a captive portal, which sends connections direct, is not taken
into account. A UDP session is rechecked by its first destination. A
connection the old routing routed that is listed only after the recheck
went by is rechecked as it is listed, until the next reload: a reload
that keeps the connections open ends that too, so one still in its
handshake then is kept, as the newest reload says. Connections
a host dials itself (`dial`) went by no rule and are not rechecked. Only
the connections open are rechecked: the multiplexed sessions an outbound
holds, and what an inbound's carrier holds, are not connections of their
own. Through the C ABI this is `sail_instance_reload_with`, through the
management API `POST /api/v1/runtime/reload` with `{"recheck_open":
"close_rejected"}`.

So a reload that changes only `dns.servers` swaps the servers and does not
interrupt established connections. New queries go to the new servers, with
an empty cache. That holds for connections carried over multiplexed
sessions too: an AnyTLS outbound's, and a sing-mux (smux) one's, are
tested. The rebuilt outbound opens new sessions for new connections, and
the old sessions carry theirs until they close.

The tests that hold this: `sail/tests/it/test_reload.rs`
(`a_reload_of_the_dns_servers_keeps_connections_and_asks_the_new_ones`):
a connection made before the reload goes on, a name looked up after it is
asked of the new server, and the old server is asked nothing more. Also
`sail/tests/it/test_embed.rs`, through `Instance::reload`, and
`sail/tests/it/test_reload_sessions.rs`, over AnyTLS and sing-mux sessions,
which close once their connections end. A TUN staying
up across such a reload needs root and is not among sail's tests.

## A snapshot, then what follows

To read a state and then follow it without a gap, **subscribe first, then
read**:

```rust
let mut states = instance.states();     // 1. subscribe
let now = instance.state();             // 2. read the snapshot
loop { states.changed().await?; /* 3. each change after it */ }
```

A subscription made before a change sees that change. `states()` and
`logs()` outlive an instance's runs, so a subscription made before
`start()` sees the start. A reload leaves the state `Running`. What a
reload changes (groups, providers, rule-sets) comes as events, with the
same rule: subscribe first, then read `outbounds()` and the rest.

## The network

`instance.network()` is the network now: the default interface (name and
index; none when offline), its kind, gateway and addresses, and whether
it is metered, constrained or behind a captive portal, with a
`generation`. `instance.events(Kinds::NETWORK)` gives each change of it
that some connections may not survive (a move), as `Event::Network`:

| `change` | when |
|---|---|
| `InterfaceChanged` | another default interface: its name or index differs |
| `Moved` | the same interface on another network: its gateway or kind differs, or one of its addresses (IPv6 by /64) is gone; or the host says the network changed; or a wake, with nothing different (reason `Wake`, see below) |
| `Offline` | the default interface is gone |
| `Restored` | a default interface is back after none |

- **Roams.** A roam to another access point with the same addresses is no
  change, and no event.
- **Addresses added.** An address added to the default interface (a new
  IPv6 /64, SLAAC) is no move either: `network()` shows it, the rules
  see it, and no connection is closed.
- **Which connections close.** A move closes only the connections it
  takes the way or the address of, each by where its dialer sent it and
  from which address:
  - one bound to an interface (`network_strategy`, `bind_interface`):
    when that interface is gone, or no longer has the connection's
    address;
  - one on the default route: when the default interface, its index,
    gateway or kind changed, or the connection's address is on no
    interface now;
  - one through a WireGuard endpoint: never. The endpoint binds its
    socket anew and its peer learns the new address from the next packet,
    as over the kernel's WireGuard; the endpoint's stop ends the
    connection. A peer gone quiet, as on a network it cannot be reached
    from (a v6-only peer on a v4-only network), does not, as nothing in
    the tunnel closes it: WireGuard retries the handshake every 5 s
    (`REKEY_TIMEOUT`) for 90 s (`REKEY_ATTEMPT_TIME`), then drops what
    it held, and starts again on the next packet out; the keys stop at
    180 s (`REJECT_AFTER_TIME`) and are wiped 540 s after the last
    handshake. The connection lasts until the endpoint's TCP stack gives
    up on it (12 retransmission timeouts, from 1 s doubling to 60 s,
    about 8 minutes, for one with data unacknowledged; 2 h idle and 9
    keepalive probes 75 s apart for an idle one), or until the app's own
    timeouts end it.
  A connection whose address is not known (UDP, one not yet made) counts
  an address gone as its own. A change
  sail cannot see into (the host's `network_changed` alone)
  closes every connection, and ends every TUN flow. A closed connection's
  TUN flow ends at the app with a reset. The log line `network changed:
  generation N, …, closed=K` counts them, and the next line names what
  differed.
- **DNS over TLS.** A move aborts every DoT connection, including an
  older one still finishing queries. It also cancels waits for a
  connection slot and TLS handshakes, so those waits do not hold the
  network change up. Closing idle DNS connections after a long sleep
  lets active DoT queries finish on their existing connection; new
  queries use a new one. A cancelled query's late reply cannot answer
  another query on the shared connection.
- **Sleep and wake.** A wake is no move: after a sleep shorter than 2
  minutes nothing is closed; after one of 2 minutes or more the carriers
  left idle (pooled connections with nothing open, the DNS servers'
  among them) are closed and the groups test their members again, as
  sing-box does (21ba30b8c). Connections in use stay either way, and a
  network that changed across the sleep is a move as above. The host
  says when the system sleeps and wakes with `Instance::sleep()` and
  `Instance::wake()` (`sail_sleep`, `sail_wake`; on iOS from the
  extension's `sleep(completionHandler:)` and `wake()`), as libbox's
  hosts call `Pause` and `Wake`: the sleep is the wall-clock time between
  the two, timed health checks and provider and rule-set updates wait
  while it lasts, and from the first `sleep()` on sail's own detection
  of sleeps is left. A host that never calls them gets sail's detection
  (a clock that counts sleep against one that does not, every 5 s). The
  2 minutes are sing-box's judgment, not measured here. A short sleep
  can still outlast the NAT mappings of a carrier's UDP (often 30 to 120
  s): its first use after the wake then stalls until its keep-alive or
  idle timeout notices (15 s at most for QUIC carriers).
- **The host's word, folded.** `network_changed` (`sail_network_changed`)
  within 2 s after a `set_network_state` is about that state, which sail
  handled as it came: it is folded into it, no second move. A host that
  never pushes a state still moves with it.
- **Settled.** Every change is settled before it is told: sail's detection
  waits until the system has been quiet for 100 ms (1 s at most) before it
  looks. A state the host pushes (`set_network_state`) is taken as given.
- **Old and new.** Each event carries the old and the new state, the
  `reason` (default interface, detected, host, wake) and the generation.
  Generations count from 1 in each run.
- **Settled at start.** The network is settled first thing in a start,
  before anything of the instance is built, and `network()` answers from
  then, in `Starting`: the default interface, or explicitly offline, at
  generation 1, with no event for it. It is the machine's interface, never
  a TUN of sail's own, which is not opened yet. Detection gets 1 s; past
  that the snapshot says offline and the interface found later comes as
  `Restored`. Before that point, as in any state but `Starting`,
  `Running` and `Stopping`, `network()` is `NotRunning`. On Android and iOS the host pushes the state, and the
  generation is 0 until its first push.
- **Pairing with the snapshot.** Subscribe first, then read `network()`,
  then skip the events whose generation is the snapshot's or lower. None is
  missed, and none is taken twice.
- **Falling behind.** A subscriber that falls more than 64 changes behind
  gets `Event::Lagged { kind: Kinds::NETWORK, missed }`; it should then
  read the snapshot again.
- **Restarts.** The subscription goes on through stops and starts. After a
  start, read the snapshot again.

`events(kinds)` takes several kinds at once: `Kinds::STATE` gives each
change of the instance's state as `Event::State`, `Kinds::NETWORK` the
network's. More kinds come; match with `_ => {}`.

`Kinds::ROUTE` gives every connection once, as `Event::Routed`: a TCP
connection, a UDP session or a stream of a multiplexed connection, when
the rules have decided of it and, where they sent it to an outbound, when
its dial has ended, well or not. It tells what a polled list of the
connections open cannot: a connection shorter than the poll, a dial that
failed, a reject, a drop, a hijacked DNS query. Its fields:

- `id`: as `connections()` lists it; none where it never opened.
- `network`, `inbound` (the tag), `source`, `destination`.
- `user`: the user the inbound authenticated it as; none for an inbound
  without users.
- `request_destination`: what the outbound was asked to reach, after the
  rules' overrides and the name `override_destination` has it dialled as.
- `domain` and `domain_source`: the destination's own name (`Request`),
  the name a fake IP stands for (`FakeIp`, TCP only), a sniffed TLS
  server name or HTTP Host (`Sniffed`), or the DNS answers sail gave for
  the address (`ReverseMapping`).
- `sniffed_protocol`.
- `rule`: the index of the rule that decided in the configuration's
  `route.rules`, from 0, each entry of the list counted once, a logical
  rule and one naming rule-sets too; none for `route.final` and for the
  host's own `dial`. `rule_text` is the rule as the log tells it.
- `action`: `Outbound`, `Reject`, `Drop` or `HijackDns`.
- `chain`: the outbounds it went through, outermost first: the outbound
  the rules named, then the member each group on the way took, down to
  the outbound that carried it, which is the last. For a rule that names
  the group `F`, which took the group `G`, which took the member `m`, it
  is `["F", "G", "m"]`: the order of `DialFailed`'s `chain` (`F>G>m`) and
  of the log's `out=`. For a dial that failed, the last is the member
  tried last. `connections()` and `watch_connections` list the same
  outbounds the other way round, as the Clash API does: their `chains`
  is `["m", "G", "F"]`.
- `target`: the address its TCP connection out was made to, the
  destination's for a direct outbound and the server's for a proxy.
- `connect`: how long the dial and the outbound's handshake took, or the
  kind of error they failed with.

These addresses and the domain are whole: `log.redact` governs sail's
log, not what it tells its host, which redacts what it passes on as it
sees fit. (`DialFailed`'s destination is redacted, as the log's is.)

The events are built only while a subscription to `Kinds::ROUTE` is
held; without one a connection costs one load of a counter. A subscriber
may fall 1024 events behind; further behind it gets
`Event::Lagged { kind: Kinds::ROUTE, missed }` and goes on from the oldest
kept. The struct and its enums are `#[non_exhaustive]`: fields and
variants are added.

`Kinds::DNS` gives every DNS query answered or failed, as
`Event::DnsExchange`: those of the clients of sail's DNS (a TUN's, a DNS
inbound's, a hijacked query) and those the instance makes itself, to
dial a domain or reach a server by name. Its fields:

- `name` (without the final dot), `qtype` (`A`, `AAAA`, ...) and
  `qtype_code`.
- `server`: the tag of the server that answered or failed; for a race or
  a sequential server, the member that answered. None where a rule did.
- `source`: `Exchanged` (a server was asked), `Cached`, `Optimistic` (an
  expired answer given under `dns.optimistic` while the server is asked
  again, which is told too) or `Rule` (a `reject` or `predefined` rule).
- `outcome`: `Answered { rcode, rcode_code }` (`NOERROR`, `NXDOMAIN`,
  `REFUSED`, ..., and the code's number)
  or `Failed { error }`.
- `answers`: the data of the answer's first 16 records (an address, a
  name); `answers_total` counts them all; `ttl` the least of their TTLs.
- `duration`: how long the server took; none from the cache or a rule.
- `attempt`: a sequential server's attempt, from 1. Each member that
  fails is told with its own attempt and time, then the one that
  answered; a race tells only the member that won.
- `for_instance`: the instance asked for itself, not for a client.

The names asked and the records are whole, as the addresses of
`Kinds::ROUTE` are: `log.redact` governs sail's log, not what it tells
its host, which redacts what it passes on itself.
Built only while a subscription to `Kinds::DNS` is held; a subscriber may
fall 1024 events behind, then gets
`Event::Lagged { kind: Kinds::DNS, missed }`.

`Kinds::CONNECTION` gives what each connection sent and received, as
`Event::ConnectionRecord`, for a host that counts traffic by connection
(billing): one record when the connection closes, and, as interim passes
find bytes new since its record before, one while it is open. Each
record carries the bytes since the connection started (`up_total`,
`down_total`), so a later record holds all an earlier one did, and a
missed interim record loses nothing. A connection's closed record has
what its user, inbound and outbound were counted (`/stats`, quotas), the
bytes a side wrote after the last read included. Each connection routed
has exactly one closed record, those that never relayed too: a dial
that failed, one the rules blocked, one its user's limits or the host's
check refused. Its fields:

- `id`, as `Kinds::ROUTE` and `connections()` number it, and `run`, when
  the instance's run started: numbers start again with each run, so
  `(run, id)` names a connection across restarts. `seq` numbers its
  records from 0.
- `kind`: `Interim`, or `Closed(end)`, its last, with how it ended:
  `Finished` (both ways closed; a UDP session its client ended),
  `Error(kind)`, `IdleTimeout` (a UDP session), `WriteStall` (a side took
  nothing for `relay.write_stall_timeout`), `Closed(by)` (sail closed it:
  `Api`, `User` — removed, over quota, shut out, at its most
  connections —, `Inbound` removed, `Rules` that reject or drop it or a
  reload's, `Network` changed, `Stopped` instance, `Host`, its check
  (`Options::admit`)) or `Aborted` (nothing
  told how, a handshake that failed after its first bytes, say).
- `outcome`, for a closed record: how the connection was used. `Ok`
  (relayed through an outbound, or hijacked DNS served), `DialFailed`
  (its outbound's dial or handshake failed, or there was no outbound:
  its end is the error where one was told), `Blocked` (a reject or drop
  rule, `route.block_quic`: `Closed(Rules)`) or `Rejected` (its user may
  not connect: `Closed(User)`; or the host's check refused it:
  `Closed(Host)`, and `reason` tells why). None for an interim record.
- `network`, `user`, `inbound`, `source`, `destination`,
  `request_destination`, `domain`, `domain_source` and `chain`, as
  `Kinds::ROUTE` tells them; `local`, the address the client connected
  to (where the inbound accepted it, a TUN's or redirect's original
  destination, what a host gave for a session it submitted;
  `0.0.0.0:0` where not known); `outbound`, the tag of the outbound the
  rules sent it to, none where they sent it to none.
- `start`, and `at` (when it was counted; a closed record's end).

Interim records come from passes over the connections open: every
`Options::record_interval(every)` (none unless set; 1 s at least;
`instance.set_record_interval(Some(every))` or `None` changes it while
the instance runs), skipping a connection with nothing new since its
record before; and whenever the host asks with
`instance.report_connections()`, which records every connection open,
idle ones too, and returns how many it told: a barrier, every live
connection's bytes up to now. A pass racing a connection's close counts
no byte twice: a connection's records leave in order (`seq`), its closed
record last. For a graceful stop, ask for a pass and then stop: the
connections still open are cut by the stop, and their closed records
(`Closed(Stopped)`) carry their totals, told before the subscription
ends. A crash loses what moved since the last pass.

For billing, a host that must lose no closed record asks for
`Options::connection_records_lossless(cap)` and reads
`instance.connection_records()`, a `RecordStream` of one reader at a
time, instead of subscribing. Records are kept for it from the
instance's first start, whether it reads or not. Every closed record is
kept; what bounds them is admission: while `cap` closed records wait for
the reader, each new connection is refused before it is routed, with no
record, and counted (`RecordStream::refused`), until the reader takes
one. Interim records of a timed pass are dropped while `cap` records
wait, and counted (`RecordStream::dropped`): the connection's next
record holds what they did. Those of a pass the host asked for are
kept, queued by the time `report_connections` returns. No connection
ever waits for the reader. The queue is the instance's, so records of
connections a stop cut wait for the reader across the stop (`try_next`
drains them). A crash loses what was not read, and what moved since the
last interim pass: a billing host reads promptly, and sets
`record_interval` to its billing granularity.

A connection is a TCP connection, a UDP session or a stream of a
multiplexed connection, as for `Kinds::ROUTE`; the sessions a host's own
inbound submits are recorded as sail's own are. Records are built only
while a subscription to `Kinds::CONNECTION` is held; bytes counted before
one was are in the connection's next record. A subscriber may fall
4096 records behind (`Options::connection_records(capacity)` sets
another), then gets `Event::Lagged { kind: Kinds::CONNECTION, missed }`
and goes on from the oldest kept: no connection waits for it. A missed
record's bytes show in that connection's next record, and the user's
counts hold them all; a missed closed record is lost to the subscriber,
as the lossless reader's never is.

`Kinds::ADMISSION` gives `Event::Admission(change)` when admission under
memory pressure (`inbound.memory_reserve`, on the server and router
profiles) changes level: `Normal`, `Pressure` (handshakes stalled past
`inbound.handshake_stall` are closed, and sources whose handshakes
mostly fail are refused) or `Hard` (every new connection is refused at
accept as well), with the memory free, the reserve and the handshakes in
flight. `instance.admission()` gives what it did since the instance
started: its level, how many it refused and closed, and how long it was
under pressure; none when it is off. Sessions that authenticated are
never touched.

**A host's own admission.** Two checks on `Options`, registered before
the start and kept across its runs and reloads, refuse what the host's
own state says to (a credential revoked that no reload has taken out
yet, a source of its own list):

- `admit_source(|source, local| ...)` sees each TCP connection an inbound
  accepts and each QUIC handshake, before its handshake. One it rejects
  is closed at once, a QUIC one refused, and has no connection record:
  it is no session yet, as one `inbound.max_connections` refuses.
- `admit(|session: &SessionInfo| ...)` sees each session once its
  inbound authenticated it, before it is routed: a TCP connection, a
  stream of a multiplexed one, the first target of a UDP association,
  and each uncached later target (domain or IP, including its port),
  including sessions a host submitted. One it rejects is closed as a
  session of a user that may not connect is, never routed. Its one closed record is
  `Rejected`, ended `Closed(Host)`, with no bytes and the check's
  `reason` (none where the check panicked): a host that counts only what
  it took in leaves out those `Closed(Host)`.

UDP keeps one NAT association, outbound, connection place and byte counter
per inbound/source identity, not one per target. The first target selects
the route; later targets use that outbound. The host's target check runs
in the association's uplink task before a new target's bytes reach it,
without holding the global NAT lock. Fake IPs have already become their
domains. The most recent 64 accepted targets are remembered; a remembered
target continues without another check, while an evicted one must be
checked again. Rejections are not cached. Ending the NAT drops this cache.

A later target does not reserve another inbound or user connection place:
its user must still be active and present in the inbound, but an association
already filling `max_connections=1` may send to another accepted target.
Record backlog admission still runs first. When the lossless record sink
is full, a new target is refused before the host hook runs and counted by
`RecordStream::refused()`, as new connections are, without adding another
record to the backlog. Already cached targets may continue.

Each later target check has an independent attempt id and
`SessionInfo::parent_id = Some(root_id)`. `SessionInfo::run` is the exact
run captured by its number, identical to `ConnectionRecord::run`, not an
approximation from instance status or the wall clock; it is optional for
views not numbered yet. Its refusal record carries the same `parent_id`
within that `run`; ordinary association records have
`parent_id = None`. This also identifies a target rejected by the user's
state before the host hook, or by a host hook that panicked. Hosts can
bind the root id to authentication metadata frozen at entry, without
looking up current credentials by username or guessing from addresses.
The metadata itself remains the host's; `Extensions` is still passed
unchanged to the hook, and is not serialized as an identity table.

If the host rejects it, that id has the zero-byte `Closed(Host)`/`Rejected` record described
above, with an empty chain; it cannot close the association's record. If
accepted, it has no separate successful connection record: its bytes belong
to the association's original id. An inbound's and a user's connection cap
can therefore refuse a new association before the host sees it, while a
new target of an existing association can reach the host check at the cap.
These refusal reasons are deliberately not interchangeable.

The optional read-only `parent_id` is an additive public field, not a new
configuration or Cargo feature. It is nullable `parent_id` in record JSON
and optional `parentId` in Swift/Kotlin; the C callback layout is unchanged.
Older JSON readers ignore it. Internal Rust users constructing the public
`control::json::ConnectionRecord` DTO with a complete struct literal must
supply the new field; this is not a claim of universal source compatibility.

Each returns `Verdict::Accept` or `Verdict::reject(reason)`. sail's own
admission and its users' checks run first: the host sees only what sail
would take in. The checks are synchronous and never awaited; each is
called in the task of its own connection. They are to answer in
microseconds from what the host holds: one slower holds back the worker
thread it runs on, and the connections that thread serves (with
`Threads::One`, the instance). That is the host's to keep; sail does not
move a check off its thread, which cost a tenth of the accept rate of
short connections for checks that keep it.
`instance.admission()` counts what they rejected by reason
(`host_refused`, 64 reasons apart and the rest as `other`), with admission
on whenever a check is registered. A check that panics rejects its
connection, and is counted (`host_panics`): the panic goes no further,
where the host is built to unwind.

`Kinds::SYSTEM` gives `Event::SystemChanged { kind, resource }` when
someone else changed what sail set up on the system for a TUN with
auto_route: on macOS, a route into the TUN gone, or another route that
wins over one of those auto_route takes from the default route, and the
TUN's address gone (Windows follows). sail leaves it as it is: the host
restores it or rebuilds the instance. `resource` says what and how, the
TUN's name first: "route 128.0.0.0/1 into utun9: 128.0.0.0/2 on utun4
wins". A break is told once, and again only after sail found it right
in between: a host that repairs it gets no word of it. What sail
changes itself, a rule-set's routes, a start or a stop, is never told.
A subscriber may fall 16 events behind, then gets
`Event::Lagged { kind: Kinds::SYSTEM, missed }`.

A host that shows the instance polls snapshots instead of following
events: `instance.status(every)` (the traffic and its rate),
`instance.watch_connections(every)` and `instance.watch_outbounds(every,
groups_only)`, the last at once on a group's change and else only when
something differs. They are quiet while the instance does not run, and
need a tokio runtime. The C ABI's subscriptions are these.

`instance.tun_names()` gives each TUN inbound's device name, by tag. It
is the name configured, or the one sail chose at start (`chosen`; on
macOS one past the highest `utunN`) when none was. A host that opens the
device itself (Android, iOS) has no entry. A chosen name that another
program takes before the device opens fails the start ("chosen at start
as free, was taken before it opened"); starting again chooses another.

### Frozen context in lossless records

A `Closed` record finishes that connection's accounting; it is not a
parent/child family barrier. A host may keep a cloned admission
`SessionInfo`, which can delay an unlisted child's record until after its
root's `Closed`, even across stop/restart. DNS hijack and health checks
also do not have the ordinary outbound `Accounts` lifetime (a health check
may have no root record). Do not retain a closed-root identity table until
an assumed timeout, or infer family drain from an empty queue.

For Rust hosts that need frozen identity, `Options::record_context(capacity,
bind)` attaches a host-defined, `Send + Sync + 'static` payload to each
session before the dispatcher's user and host session checks. It requires
`connection_records_lossless`; `Instance::new` rejects that combination
without a lossless sink. The same `RecordContext` Arc is readable through
`SessionInfo::record_context`, kept by the session/number/counter, inherited
by later UDP targets, and carried in each `RecordEnvelope`. The callback
runs once per root session, not again for a child. Session extensions
remain available for host-submitted inbounds. Copying a host Arc from an
extension or credential snapshot preserves the same host binding for
routing and recording. Do not copy the root's target or refusal outcome
into that identity: each record freezes its own destination and outcome.

A username is not an authentication version. For **named SS2022, VLESS
and AnyTLS credentials**, `Options::credential_context(capacity, bind)`
provides the missing registration point: the callback runs while the
actual credential table entry is constructed, before it authenticates a
session. `CredentialInfo` borrows the protocol, inbound tag, name and
configured credential; use that exact row/version to select the immutable
host snapshot. Never log the borrowed secret or resolve current identity
by name at session capture. That entry's `UserRef` keeps the snapshot,
independently of the shared name-based quota state. A replacement entry
gets its own snapshot; sessions authenticated by the old entry still
expose the old `SessionInfo::credential_context`, even if the replacement
commits before `record_context` runs. The host can store an `Arc` to its
own immutable business type there and copy it into `record_context`.
Sail does not define that business type or history policy.

Credential callbacks may run for candidates that are never committed;
they must have no external side effects. Exhaustion or a panic fails
configuration construction and leaves the old configuration usable.
Reserve headroom for old and new tables and discarded reload candidates.
Anonymous credentials, legacy SS and other built-in protocols do not have
this registration snapshot; their `credential_context` is `None`. A host
must explicitly handle that state, restrict its supported inbounds, or
supply a binding through its own authenticated inbound extensions.
Changing a named credential snapshot also distinguishes its UDP source
identity: same source/name with a different snapshot creates a different
NAT association. This does not change the rule that multiple targets of
one association share one connection place and counter. Global user quota
identity/equality remains name based.

Use `RecordStream::next_envelope` / `try_next_envelope` to read the record
and its optional context together. A late child owns the frozen binding
it needs; it does not depend on a root lookup. Keep the envelope (or an
owned clone of its context) until the existing Collector/spool has
successfully accepted it; retain/retry it if persistence fails. Then drop
it. Root byte cursors and binding ownership have separate lifetimes.
Legacy `next` / `try_next` return only the unchanged record DTO and release
the envelope's context reference; they are unsuitable for this contract.
The context is never included in JSON, C callbacks, broadcast records or
`Debug` output. The JSON/FFI layout and record equality stay unchanged.

Both capacities count **distinct bindings**, including outstanding
configuration entries, live sessions, retained callback views, pending
records and reader batches, across runs. A slot is reserved atomically
before a provider is called and is returned at the last reference's drop,
including unwind. Session binding exhaustion does not invoke the provider:
it refuses with counted host reason `record_context_capacity` and an
explicit zero-byte, **unbound** Host rejection record. A provider panic
is counted in `host_panics`, with the usual no-reason Host rejection.
Readers must handle these unbound refusals explicitly. The existing record
backlog gate runs earlier and refuses without another record, counted in
`RecordStream::refused`. Source/handshake/authentication failures and the
host-submission checks before dispatch precede this binding point; they
retain their existing no-session-record semantics. The protocol does not
invent an authenticated identity for them.

These capacities are not hard memory limits: the host must bound payload
size, configured credentials, retained views/clones and pending spool
batches, and keep providers fast. A retained view can consume a binding
slot for its entire lifetime; new bindings are then refused rather than
creating a second pool or evicting a live binding. The lossless record cap
is still a soft admission threshold: already active work may close past
it. A binding must not retain an Instance, Session, Number, record or other
back-reference to its owners, nor may its provider form such a cycle.
Use immutable host snapshots; interior mutability is the host's explicit
synchronization and versioning responsibility. No TTL, tombstone or new
per-destination meter is introduced.

## Dialling

`dial_tcp` and `dial_udp` go through the outbound named, whatever the
rules say, with no user, as the control plane's dials. What they return is
the outbound's own stream or datagrams, read and written with no relay or
copy between; each poll is made within the instance's runtime, so any
executor of the host's may drive them. No idle or stall timeout of sail's
applies to them: their timeouts are the host's, which reads them itself
and closes them when it is done waiting. Once the instance stops,
they fail. To send a user's traffic, with the rules, limits and records
that come with one, submit it to `Instance::sessions` instead (Host kinds).

**While the instance starts.** A host whose own service the instance
asks during its start, a DNS server in the host's process that the
configuration names, say, can serve it: the start goes in this order,
and the calls work from the point named.

1. The network is settled: `network()` answers.
2. The outbounds are built: `dial_tcp` and `dial_udp` work, in
   `Starting`, through every outbound and group.
3. The instance asks for the names its start needs: remote rule-sets,
   outbound providers, and the groups' first checks.
4. The TUN is opened and routed, the inbounds listen, and it is `Running`.

- A dial made in `Starting` before step 2 waits for it, within its own
  timeout, and then dials; it is not refused. The groups' first checks
  begin as the outbounds are built, a few milliseconds before step 2 is
  told: a lookup they cause may wait that long. If the start fails or is
  stopped meanwhile, the dial is `NotRunning`. The wait needs no runtime
  of the host's.
- One kind is not served that early: an endpoint (WireGuard), whose
  tunnel is driven only once the instance is `Running`. A dial through
  it made earlier waits for the endpoint, 10 s at most or the dial's own
  timeout if that is shorter, and fails if the instance does not run by
  then.
- A direct dial made before the TUN is up stays out of it afterwards:
  the socket is bound, marked or protected when it is dialled, as the
  configuration says, and that is settled before the outbounds are built.
- In `Idle`, `Stopped` and `Failed`, and once a run has ended, a dial is
  `NotRunning`. The C ABI's `dial` works once the instance is `Running`.

Through the direct outbound, two things hold:

- **The zone reaches the kernel unchanged.** A link-local IPv6 address
  given with its scope (`SocketAddrV6::new(ip, port, 0, ifindex)`, the
  index from `if_nametoindex`) keeps it all the way to the socket.
  `sail/tests/it/test_embed.rs` sends to a link-local address of the
  machine: lo0's on macOS, the Ethernet's on Linux. sail does not parse
  "fe80::1%en0": a host turns the name into its index.
- **The socket is the direct outbound's.** It is bound and marked as that
  outbound's dialer says (`bind_interface`, `auto_detect_interface`'s
  default interface, `routing_mark`, `network_strategy`), as a direct
  connection the rules route is.

So a zone that names an interface other than the one the socket is bound
to fails to send. To reach a link-local server on another interface, dial
through a direct outbound whose `bind_interface` is that interface.

A UDP socket's family is the first destination's. An IPv6 one also sends
to IPv4 addresses, and an IPv4 one cannot reach IPv6. On a network with
NAT64 and no IPv4, IPv4 destinations go through its prefix. The prefix is
the process's, as the network is: found through the system's resolver, or
pushed by the host, the last discovery or push wins for every instance in
the process, and an instance that stops leaves it as it was.

## A host's own links

`sail::muxcore` (feature `muxcore`) is the stream multiplexer sail's
yamux, smux, amux and AnyTLS run on, for a host that links its nodes
itself: many streams over one connection, any `AsyncRead + AsyncWrite`
(TCP, TLS, a pipe). It speaks yamux as hashicorp/yamux does, and CI runs
it against hashicorp/yamux both ways. It needs no instance.

```rust
use sail::muxcore::{Config, Protocol, Session};

// The node that accepts: each stream its peer opens.
let (server, mut incoming) = Session::server(tls, Config::new(Protocol::Yamux));
while let Some(stream) = incoming.accept().await {
    tokio::spawn(serve(stream));
}

// The node that dials: streams on one connection.
let link = Session::client(tls, Config::new(Protocol::Yamux).label("node-2"));
let mut stream = link.open().await?;
stream.write_all(&request).await?;
```

- **Its task is the host's.** A session's task, which reads and writes
  the connection, runs on the tokio runtime it is made in, with I/O and
  timers enabled; no instance's stop ends it. It ends when the connection
  does, on `close()`, or once the `Session` is dropped and its last
  stream is done. Dropping it takes no new streams, on either side;
  `accept` then gives `None`.
- **A stream is one connection's worth.** `Stream` is `AsyncRead +
  AsyncWrite`. `shutdown()` sends a FIN, and the other way goes on until
  the peer's. A stream dropped before the peer's FIN is reset, alone:
  the session and its other streams go on (where Go's yamux `Close`
  sends a FIN).
- **Bounded.** No more than `MAX_UNACKED` (256) streams the peer has not
  accepted wait at once: `open` waits for one of them, as
  hashicorp/yamux's backlog is that many. A session carries
  `MAX_STREAMS` (1024) at once; past that `open` fails. A stream's
  window starts at 256 KiB and grows, as it is read fast, to
  `Config::window_max` (16 MiB by default); a stream whose data nothing
  reads for `Config::stall_timeout` (60 s) is reset.
- **Errors.** `open` fails once the session has ended or the peer takes
  no more streams; a stream's reads and writes fail once it is reset or
  its session ends. Neither retries: the host makes a new session.

## Host kinds

A host registers inbound and outbound kinds of its own on `Options`, each
under a `type` name, and a configuration uses them as it uses sail's:

```rust
let options = Options::new()
    .inbound_kind("link", |cx| Ok(Arc::new(LinkInbound::new(cx.options)?)))?
    .outbound_kind("table", |cx| Ok(Arc::new(TableOutbound::new(cx.options)?)))?;
```

```json
{ "type": "link", "tag": "link-in", "listen": "::", "listen_port": 443, "psks": ["..."] }
```

- **Names.** A name of sail's own, or one registered already, is
  `InvalidArgument`. The kinds are the instance's, for all its runs and
  reloads, and `check()` knows those of the options it is given.
- **Building.** The factory gets the object without `type`, `tag` and the
  listen fields, on start and on every reload that builds that tag again.
  Its error, or its panic, is the start's or reload's `Config` error,
  naming the tag.
- **Host inbounds.** The listener is sail's. `listen`, `listen_port`, the
  socket options, `inbound.max_handshakes`, `max_handshakes_per_source`
  and `handshake_timeout` apply as to sail's inbounds.
  - **Accepting.** `HostInbound::serve` is handed each connection
    accepted. It runs as a task of the instance's, and a panic ends that
    connection alone.
  - **The handshake.** The connection holds its place among the
    handshakes until `Sessions::established()`, or until the first session
    submitted. A connection that never gets there is closed at the
    timeout.
  - **Sessions.** `Sessions::tcp` and `Sessions::udp` submit sessions, any
    number on one connection. Each is routed, takes its place among
    `inbound.max_connections`, is counted and listed, and is told in the
    events as a session of sail's own inbounds is. The connection itself
    is not one, as a multiplexed connection is not.
  - **Numbers.** `tcp` and `udp` return the number the session is known
    by: its connection records' `id`, and the `SessionInfo::id` a host
    outbound gets for it. Each number submitted has one closed record,
    however the session ends: one the rules or an outbound refuse, or
    whose dial fails, has one with nothing sent or received. A UDP
    association may send to more than one destination: it keeps one
    successful record and counter, by the returned number. Later target
    admission refusals have independent zero-byte records, as described
    under admission; accepted targets do not create another connection.
  - **Refusals.** A session whose user may not connect through the inbound
    is `Refused::User`, saying why: shut out, taken out of the inbound, at
    its `max_connections`, or a user of another instance or run.
    `Refused::Closed` means the inbound is gone or the instance is
    stopping.
  - **Addresses.** A session has its connection's source and local
    address, the one the client connected to, unless `NewSession::source`
    and `local` give others: a host that carries many clients' streams on
    one connection gives each its own. `SessionInfo::local` tells it.
- **Sessions with no listener.** A host that takes streams off a link of
  its own, a peer node's, submits them to `Instance::sessions(tag)`, as
  sessions of the inbound `tag`, any of the configuration's
  (`NotFound` for none). They are a host inbound's sessions in every way
  above: routed by the rules for that inbound and their user, held to the
  user's limits and rates, counted, numbered and recorded under the
  inbound, dialled with the outbound's bind address. sail relays the
  host's stream to the outbound's directly, one copy, in a task of the
  instance's, whichever executor submits it. With no listener, admission
  refuses them only under hard memory pressure (`Refused::Pressure`), as
  it refuses every new connection then; a reload that takes the inbound
  out, or the instance stopping, refuses them as `Closed`.
- **Users.** `Instance::user(name)`, or `KindContext::user` while a kind
  builds, gives a user of sail's one namespace, which `user_limits`, the
  management API and the traffic counts use.
  - **Holding.** The host keeps the users in its own table, which holds
    them as an inbound's credentials do.
  - **The inbound's `users`.** A host inbound whose object lists `users`
    (`[{"name": ...}]`) has them taken out and put back by a reload, as
    any inbound's are. A reload that changes nothing else of the object
    builds it again with its listener and connections kept; one that
    takes a user out closes that user's sessions through it and refuses
    its new ones. A `User` survives a reload that keeps it.
- **Extensions.** `NewSession::extension` puts typed values of the host's
  in the session's `Extensions`, which sail carries to the outbound,
  through groups and `Via`, and never reads.
- **Host outbounds.** A rule or a group routes to a host outbound as to
  any outbound. `HostOutbound::stream` and `datagrams` get the session's
  `SessionInfo`: its number, user, destination, inbound and extensions,
  and the domain known for it with its `DomainSource`, as its records tell
  them: the destination's own, the name it is dialled as, or what a
  `sniff` rule read of its first bytes. The number is told before the
  session is counted, so that a session the outbound refuses is known by
  its record too.
  - **Via.** They may dial through any outbound of sail's by tag with
    `Via`, a `direct` bound to a source address among them. The tag is
    looked up when it dials, so the outbounds a reload builds are the ones
    used, and it is added to the session's chain.
  - **Counting.** The session is counted once, by sail's relay of what the
    host outbound returns, and has one connection record
    (`Kinds::CONNECTION`) with its user and bytes, as a session of sail's
    own inbounds has: none for the connection that carries it, and none
    for its `Via` dials. A carrier the host pools and shares between
    sessions is not charged to any user; each session over it is.
  - **Routing on a table** of the host's is a host outbound that looks the
    table up and dials the next hop through `Via`. Swapping the table
    needs no reload.
  - **Rule-sets.** `RuleSet` reads a sing-box headless rule-set, binary
    (`.srs`) or source (`.json`), from bytes (`from_bytes`) or a file
    (`from_path`, the format by its extension, or `from_path_as`), with
    the code sail's router reads and matches them with. `matches` takes a
    `MatchInput`: network, domain, the addresses `ip_cidr` matches (sail
    resolves nothing), port and source, or one made from a `SessionInfo`.
    It matches `network`, the `domain` conditions, `ip_cidr`,
    `source_ip_cidr`, the port conditions, `invert` and logical rules, as
    a routing rule does. A rule with any other condition (`process_*`,
    `package_*`, the network's, `query_type`, `ip_asn`, …) is refused as
    the rule-set is read, naming the rule and the condition, rather than
    never matching.
- **Tasks.** What a host kind spawns goes through `sail::embed::spawn`, so
  a stop ends it with the instance's other tasks and a panic in it is a
  `Fault`. A task spawned with `tokio::spawn` is the host's own and
  outlives the stop.
- **Not yet.** The C ABI has no host kinds. A host inbound listens on TCP
  only and takes none of sail's shared blocks: no `tls`, `transport` or
  `multiplex`. A host that needs TLS wraps it itself, inside `serve`.

## The system's DNS

A TUN with `auto_route` points the system's DNS at the address after the
TUN's, while it runs, the same way on each system:

- **Linux:** systemd-resolved, for the TUN's link, where sail runs in
  resolved's own network namespace.
- **Windows:** the Wintun adapter's DNS.
- **macOS:** a resolver with no domain, which macOS ranks first. It is one
  temporary key in the dynamic store, `State:/Network/Service/<id>/DNS`,
  with an id made from the TUN's name. No real network service's DNS is
  touched. The system removes the key with the process that added it,
  after a kill -9 too. sail adds it again when a network change took it
  (a configd restart).

It is undone with the routes, before the device, on every end, and a DNS
that cannot be undone is in `stop_report().left` with `LeftKind::Dns`.

When the host opens the TUN (`Platform::opens_tun`, as an app's
NetworkExtension or VpnService does), sail neither routes nor sets the
system's DNS: the host does both.

**Routes of others (macOS).** A route auto_route adds where another,
bound to no interface, already goes (another VPN's `128.0.0.0/1`, say)
replaces it, as sing-box does. sail writes the one it replaced down and
puts it back when it stops, where that is still right: only if sail's
own route is still there (one its owner put back over sail's is left as
it is), and only to the same interface, by name and index, still up.
`instance.replaced_routes()` lists what is replaced, a line each ("route
128.0.0.0/1 via 10.8.0.1 on utun4"), after a start or a reload. What
could not be put back is in the stop's `StopReport::left`, with why and
the `route add` that puts it back by hand.

## Leftovers after a kill

An instance that changes the system (a TUN, its routes and rules) writes
down each change under its run directory, and undoes it when it stops.
Every start first sweeps what a killed instance left there.

- **Where.** `Options::run_dir(RunDir)` chooses the directory: `Default`
  (`/run/sail` on Linux; `/var/run/sail` on macOS when sail runs as root;
  none elsewhere), `Dir(path)`, or `Off`. A sandboxed host (a Network
  Extension, an App Store app) gives its own. A directory that cannot be
  written is warned of once, and sail runs on without a ledger.
- **macOS.** A kill takes the utun and its routes with it; what is left is
  a route of someone else's that auto_route replaced (below), which the
  sweep puts back, unless the system booted since, a route to its
  destination is there again, or its interface is not the one it was.
- **Without an instance.** `sail::embed::sweep(&run_dir)` sweeps with no
  instance, as a desktop service does at its start, and returns one line
  per thing undone.
- **What is left alone.** An instance that changes nothing never creates
  the directory. An entry whose TUN is still up in this network namespace
  belongs to a live instance and is left.

## Errors

`Error` has a kind and a message. The kinds are:

| `ErrorKind` | `code()` | when |
|---|---|---|
| `Config` | `config` | the configuration or settings do not read or build |
| `InvalidArgument` | `invalid_argument` | a group that is no selector, a member it refuses, a bad URL |
| `NotRunning` | `not_running` | the instance does not run |
| `State` | `state` | starting or running already, stopping |
| `NotFound` | `not_found` | no outbound, group, member, provider, rule-set, inbound or user so named |
| `Unsupported` | `unsupported` | not in this build or on this platform |
| `Timeout` | `timeout` | the call's time ran out |
| `Cancelled` | `cancelled` | the start was stopped |
| `WrongThread` | `wrong_thread` | blocking wrappers only: a misuse |
| `Failed` | `failed` | a dial, a delay test or an update failed |
| `Io` | `io` | a system call failed |
| `Panicked` | `panicked` | sail panicked. The instance has failed and may be started again |
| `Internal` | `internal` | a bug: the message says what |
| `TunNameTaken` | `tun_name_taken` | a TUN's device name is in use. A configured one: change it. One sail chose: each free name it tried was taken before it opened, and starting again may well succeed |
| `NeedsRestart` | `needs_restart` | a reload whose configuration adds, removes or changes an inbound that only a start sets up (a TUN). Nothing changed: stop and start to apply it |
| `InboundLost` | `inbound_lost` | a reload that was to replace an inbound on the address it had: the new one did not bind, and the one before could not listen again. The reload failed, all else is as it was, and the inbound the message names listens no more: reload again, or `add_inbound` it |

## Panics

Build a host with `panic = "unwind"` (Cargo's default). Under it no panic
in sail takes the host down. Assert it at start:
`assert!(sail::embed::PANICS_ARE_CAUGHT)`. Under `panic = "abort"` any
panic ends the process, as in sail-cli's release build.

**Which released builds unwind.** The mobile libraries, the XCFramework
and the AAR, are built with `panic = "unwind"` (the `dist-mobile` profile):
in them all this section says holds, and the app or the network extension
lives on a panic in sail. sail-cli, the router packages and the other
release builds are built with `panic = "abort"`: there a panic anywhere in
sail, in one connection's task as well, ends the process, and nothing
below holds (the next start's sweep clears what the process left on Linux
and macOS; Windows's filters go with the process). A host that builds sail
itself chooses; `PANICS_ARE_CAUGHT` says which a build has.

Every task sail runs for an instance is in the instance's scope, of one of
two classes:

- **Contained:** work bound to one connection, stream, session, request
  or probe. A panic there ends that task alone. It is logged, counted
  (`faults()`, and `Status::faults`), and told as `Event::Fault` under
  `Kinds::FAULT`, with the task's name, class, message and the running
  count. The instance goes on; a host may rebuild it if they repeat.
- **Essential:** what the instance cannot do its job without (listeners,
  its DNS and outbound state, the TUN and netstack drivers, the network
  monitor, group checks, updaters). A panic there fails the instance:
  `State::Failed` with `ErrorKind::Panicked` and the task's name. A lock an
  earlier panic poisoned fails it the same way, rather than cascading.

The instance's start thread and the BoringSSL callbacks are caught as
before. A failed instance is dropped and a new one made; nothing of it is
left.

## Stopping

`stop()` aborts the instance's tasks and waits for them to end, for 2 s
unless `Options::stop_within` says otherwise.

- **Guaranteed:** async tasks end at their next poll after the abort.
- **Reported only:** a blocking call (a DNS lookup on the blocking pool,
  file I/O) or a host callback cannot be interrupted. One that outlasts
  the bound is named in `stop()`'s `Timeout` error and in `stop_report()`
  (the tasks still running by name and count, and how long the stop
  waited).

**What the instance changed in the system** (a TUN's routes, policy rules,
nftables, DNS, Windows filters) is undone however the run ends: a
`stop()`, a failure (an essential task's panic, a root task's), or a start
that fails after the TUN came up. Every end goes the same way: what it
changed in the system first, then the device, then the instance's tasks
within the bound, then the runtime, shut down within the bound too, so
that a blocking thread stuck past it does not hold the end up. A step that fails, panics or outlasts its bound is
named, and the others still run:

- `stop_report().left`: each `Left { kind, resource, why, clear }`, with
  `clear` the one command that clears it by hand where there is one.
- `stop()`'s error (`ErrorKind::Failed` when only resources are left), the
  `Failed` state's error, and a failed start's error say the same in their
  message, after "left in the system:".

`stop()` on an instance that is not running (failed, stopped, or never
started) is safe to call any number of times and returns at once: it
asks for nothing and undoes nothing a second time, and tells again what
the last run left, if anything.

