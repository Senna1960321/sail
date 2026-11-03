# Testing

sail's tests come in four layers. A test's layer is decided by one
question: **what does it need, outside its own process, to run?** The
answer sets where the test lives, how it is gated, and which CI job runs
it (`.github/workflows/ci.yml`).

| Layer | Name | Needs | Plain `cargo test` runs it | CI on a `ci/*` branch | CI on `master` |
|---|---|---|---|---|---|
| **L1** | unit | nothing: no root, no network, no fixed port | yes | always | unless it passed before |
| **L2** | integration | loopback, real sail instances, a process of its own | yes | always | unless it passed before |
| **L3** | system | root, a kernel feature, network namespaces, a real TUN, a platform's runner | no (ignored) | when the change reaches it | always |
| **L4** | release-level | other targets and architectures, packaging, measurement | no | no | always (some only at release) |

Each layer up needs something the one below does not. A test belongs to
the lowest layer whose resources are enough for it.

## L1: unit

The libraries' own tests (`#[cfg(test)]` modules under `src/`), the doc
tests, and sail-netstack's model tests (under `sail-netstack/tests/`, but
needing nothing). An L1 test may bind a loopback socket on a port the
system chooses (port 0) and may read the host's state (its interfaces,
its neighbour table); it binds no fixed port, starts no sail instance
through the test harness, needs no root and reaches no network.
So do muxcore's yamux tests against hashicorp/yamux (`yamux_interop`),
with its peer built by Go from `scripts/yamux-peer`: ignored in a plain
run, they fail without `YAMUX_PEER`.

```sh
cargo test -p sail -p sail-netstack --features sail/auto-reload --lib
(cd scripts/yamux-peer && go build -o /tmp/yamux-peer .)
YAMUX_PEER=/tmp/yamux-peer cargo test -p sail --lib yamux_interop -- --ignored
cargo test -p sail-netstack --test '*'
cargo test -p sail -p sail-netstack --features sail/auto-reload --doc
```

`auto-reload` is on as sail-ffi builds sail, so that the tests run the
code the mobile and desktop libraries ship.

## L2: integration

Tests that start real instances and talk to them over loopback:

- `sail/tests/it/`, one test binary of many modules, through the shared
  harness (`sail/tests/it/common.rs`: ports from below the system's own
  range, runtime IDs it hands out);
- the other binaries directly under `sail/tests/` that need no root
  (`test_embed_host_subscriber`, `test_log_redact`, `test_tls_split`, …);
- sail-ffi's tests: the C ABI as a host calls it, the command service
  included;
- sail-cli's tests: the CLI as a service manager drives it (signals,
  reload);
- `test_panic_unwind` in the `dist-mobile` profile: a contained panic
  leaves the instance and the host process running.

```sh
python3 tools/ci/l2-shard.py 0 1        # every sail test binary; see Shards
cargo test -p sail-ffi
cargo test -p sail-cli
CARGO_PROFILE_DIST_MOBILE_LTO=false \
  cargo test -p sail --profile dist-mobile --features fault-injection --test test_panic_unwind
```

A new L2 test goes into `sail/tests/it/` as a module. It stays a binary
of its own only when it needs a process to itself (a global it sets, a
panic it provokes, a single test thread).

## L3: system

Tests that need root, a kernel feature, network namespaces, a real TUN,
or a platform that only its own runner has:

- Linux, in network namespaces their scripts build
  (`sail/tests/scripts/*_netns.sh`): `test_auto_route_linux`,
  `test_auto_redirect_linux`, `test_tproxy_linux`,
  `test_network_switch_linux`, `test_teardown`, `test_wireguard_interop`;
- Linux, making their own namespaces: `test_tun_linux`,
  `test_wireguard_kernel`, and the ignored tests under `platform::` in
  sail's library (netlink, nf_tables, nfnetlink_queue);
- macOS, as root on a runner: `sail/tests/scripts/macos_utun*.sh` (the
  utun's names and routes, and real DNS, TCP and UDP traffic through it
  over IPv4 and IPv6), `test_teardown`, `test_tun_integrity_macos`,
  `test_tun_replaced_macos`, `platform::route_socket`;
- Windows, as administrator with wintun.dll: `test_tun_windows` (real
  DNS, TCP and UDP traffic through a Wintun adapter over IPv4 and IPv6,
  a stop and a start, no integrity event, nothing left),
  `test_teardown`, `test_tun_integrity_windows`,
  `test_split_dns_windows`;
- the bindings: the Kotlin binding on a desktop JVM, the Swift binding on
  macOS.

```sh
sudo sail/tests/scripts/auto_route_netns.sh        # and the other *_netns.sh
```

## L4: release-level

What only another target, another architecture or a release build shows:
the cross builds (`scripts/cross.sh`, one per target, each CLI started
once under qemu-user or wine), sail's tests natively on aarch64, the
native Windows MSVC build and test run, the Apple and Android packaging
(`release.yml`), and the performance runs (ci.yml's `perf-*` jobs). A repro of sail
against sing-box on the same configuration, end to end, will be one.

## Which layer

```
What the test checks ...
├── a function, a parser, a state machine, a codec          → L1
├── a type's behaviour over a socket on port 0              → L1
├── a configuration read, built and run by an instance      → L2
├── a protocol against sail's own server, or sing-box's     → L2
├── the C ABI, the CLI, a panic's containment               → L2
├── routes, rules, nftables, a TUN, another namespace       → L3
├── what only macOS, Windows or a binding's runtime does    → L3
├── another target, architecture or a release build         → L4
└── not sure                                                → the lowest that can show it
```

Start low: a check that L1 can make does not wait for L3's runner.

## Gating and naming

- **L1 and L2 run in a plain `cargo test`.** An L1 or L2 test does not
  skip itself for want of root. It may step aside on a host that cannot
  do what it checks (no `ss`, a socket option an emulator does not know),
  saying so on stderr; CI's runners have what it needs.
- **An L3 test is `#[ignore = "<what it needs>"]`**, the reason naming
  its resource (`"requires root and nf_tables"`). A plain `cargo test` lists it as
  ignored and prints nothing else. Its script or CI job asks for it with
  `-- --ignored`.
- **Asked for, an L3 test fails when its resource is missing; it never
  skips.** It checks what its script sets (`SAIL_BIN`,
  `SAIL_SWITCH_NETNS`, the namespace paths of `tproxy_netns.sh`, the keys
  of `wireguard_interop_netns.sh`, `ip netns identify`) and fails without
  it. A CI job that runs a layer is there to run it: a test that passes by
  skipping hides the job's own breakage.
- **A bare `#[ignore]`** is a tool run by hand, not a layer: a
  measurement, a check against real sites or published data
  (`measure_connection_memory`, `fingerprints_against_real_sites`,
  `published_rule_sets_match_as_sing_box_does`). No CI job runs it; its
  doc comment says how to.
- **Linux-only L3 binaries end in `_linux.rs`**, and their scripts in
  `_netns.sh`; the `changes` job of ci.yml runs netns-linux on a branch
  that touches either.
- **Ports**: L2 tests take theirs from the harness (`free_port`), from
  below the range the system gives its own sockets; L1 tests take port 0.

## CI

`ci/<name>` is the merge gate: a branch merges when its run is green.
`master` runs more, after the merge.

| Job | Layer | On a `ci/*` branch | On `master` |
|---|---|---|---|
| `lint`: sensitive check, licences, fmt, clippy `--all-targets`, C header, C ABI growth | — | always | always |
| `features`: clippy per feature set, fault-injection out of shipped builds, configuration reference | — | unless passed before | unless passed before |
| `L1 unit` | L1 | unless passed before | unless passed before |
| `L2 integration (shard 0–2)`, then `L2 integration` | L2 | unless passed before | unless passed before |
| `fuzz`: the fuzz workspaces build | — | when fuzz inputs change | always |
| `check-32bit`: clippy for armv7 musl, BoringSSL from source | — | when dependencies, toolchain or cross scripts change | always |
| `netns-linux` | L3 | when the change reaches it | always |
| `tun-macos` | L3 | when the change reaches it | always |
| `tun-windows` | L3 | when the change reaches it | always |
| `clippy-windows`, `clippy-macos`: clippy for those systems, no tests | — | always | macOS only, to keep its cache |
| `bindings-kotlin`, `bindings-swift` | L3 | when the change reaches them | always |
| `cross (<target>)` | L4 | no | always |
| `test-aarch64` | L4 | no | always |
| `windows-msvc` (its teardown step is L3) | L4 | no | always |
| `dependency-security`: dependency sources, RustSec, licences (`tools/security`) | — | when a manifest, the lock file, `tools/security/` or `tools/licences/` changes | when the push changes them |
| `docs`: the website, built and deployed to GitHub Pages | — | no | when the push changes the website, the crates or the root manifest |
| `perf-measure`, `perf-size`, `perf-report`: tier A of the performance checks | L4 | on `ci/perf-*` only | daily schedule (03:17 UTC) and each `v*` tag, not on a push |
| `perf-macos`: iOS's footprint, on macOS | L4 | no | weekly schedule (Monday 02:23 UTC) |
| `upstream-watch`: each fork against its upstream, into one issue | — | no | weekly schedule (Monday 02:23 UTC) |
| `release.yml` | L4 | — | by hand |

ci.yml and release.yml are the only workflows. A schedule runs only
`upstream-watch` and the perf jobs (the weekly cron `upstream-watch` and
`perf-macos`, the daily one the other three); a `v*` tag runs only the
perf jobs. `perf-report` compares with the newest successful scheduled or
tag run's numbers on another commit, and with the last release's. It does
not block: a metric over its limit is a warning on the run, while a
measurement or comparison that fails turns it red (`perf-macos` alike).

A dispatch (`gh workflow run ci.yml --ref <branch>`) runs every job but
`upstream-watch` (and `docs` off master), and looks up no receipt. `features` runs clippy only: each feature set's
tests compile, and L1 and L2 run the full build's.

`netns-linux` runs `test_tun_linux`, `test_wireguard_kernel` (but its
throughput measurement) and the ignored `platform::` tests, as gating
steps. The `platform::` tests compare nft(8) listings in the older nft's
notation, so a newer nft on the runner lists the same rules.

How long each job takes: to be measured.

### Shards

`tools/ci/l2-shard.py INDEX COUNT` builds sail's test binaries once,
lists each one's tests, and runs those whose `<binary>::<test>` name
hashes (CRC-32) to INDEX modulo COUNT, by exact name. The split depends on
the names alone, so a shard is the same on every run, and a new test moves
no other. Each shard also runs one suite that builds sail on its own:
sail-ffi on shard 0, sail-cli on shard 1, the mobile panic on shard 2.
`L2 integration` passes only when every shard did.

### Receipts

A tree that passed `features`, L1 or L2 before, documentation aside,
does not run it again. `tools/ci/receipt.sh` takes the fingerprint of the
tree: `git ls-tree -r HEAD` without `docs/` (but `docs/compat/`, which
tests compare with the code) and the Markdown files at the root. A job
that passes uploads an artifact `green-<layer>-<fingerprint>`; the
`receipts` job looks each layer's up through the API and trusts one only
from this repository's `master` or a `ci/*` branch. An artifact, not a
cache entry: what a `ci/*` branch caches, `master` cannot read.

So a merge, which fast-forwards `master` to the commit that passed on its
`ci/*` branch, does not run L1 and L2 again, and a change to docs alone
runs no tests on a `ci/*` branch. Any other file counts, ci.yml and
`tools/ci/` included.
