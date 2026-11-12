# Dependency security gate

This gate covers the root Rust workspace and its root `Cargo.lock`. It checks
known RustSec advisories, dependency licenses (including development
dependencies), registry checksums, and exact Git dependency sources. It does
not update dependencies or generate a lockfile.

## Run it

The source check only needs Python 3.11 or newer (for `tomllib`):

```sh
tools/security/check.sh sources
```

The complete check additionally requires exactly `cargo-audit 0.22.2` and
`cargo-deny 0.20.2` on `PATH`:

```sh
tools/security/check.sh all
```

Run `tools/security/test.sh` to exercise the fixed-source positive case, a
floating-revision rejection, and the distinct execution-error, network/tool
unavailable, and policy-finding exit paths. The test uses an isolated temporary
fixture and removes it on exit.

With the pinned scanners installed, `tools/security/capture-baseline.sh
<new-output-directory>` records raw scanner output, versions, lock hashes,
database revision, reverse dependency trees, and exact exit classifications.
It refuses to overwrite an existing evidence directory and retains incomplete
evidence with exit 2 when a scanner fails before policy evaluation.

The individual networked checks are also available as
`tools/security/check.sh audit` and `tools/security/check.sh licenses`. The
audit refreshes the RustSec advisory database, denies unsound advisories,
and requires `cargo-deny` advisories with transitive unsound dependencies,
yanked versions, and the native `index-failure` diagnostic treated as errors.
The deny registry check reads Cargo's local index cache; it does not attest
to a fresh online yank query. A zero `cargo-audit` exit does not establish
online availability: any lookup error remains incomplete verification and
must be reported separately, even when the cached check passes.
`python3 tools/security/test-index-failure.py`, after a successful audit,
checks the native warning-to-error behavior with an isolated, vendored fixture;
it does not modify the shared registry cache. `cargo-deny` runs with
`--locked`, the root workspace manifest, and `tools/security/deny.toml`.
Neither command is allowed to resolve a different dependency graph.

For a read-only diagnostic snapshot, `SECURITY_LOCKFILE` can point the audit at
a byte-identical copy of the repository lockfile (other inputs are refused)
and `CARGO_AUDIT_DB` can place the advisory database outside
the user's Cargo directory:

```sh
SECURITY_LOCKFILE=/path/to/Cargo.lock \
CARGO_AUDIT_DB=/path/to/advisory-db \
tools/security/check.sh audit
```

`CARGO_AUDIT_DB` controls only cargo-audit's database; cargo-deny uses its
own database in the Cargo home. CI leaves both variables unset and audits
the committed root lockfile.

Exit status `0` means the requested checks passed, `1` means policy findings,
`2` means a scanner or configuration error prevented a trustworthy result,
and `3` means a pinned tool or required network service was unavailable. The
`all` mode runs every check and reports each result; it never turns a missing
scanner into success.

The policy file lists all five workspace members plus the root manifest. The
source checker compares that list to `[workspace].members`, so adding a member
without extending the policy fails. Registry packages must come from crates.io
and carry a SHA-256 checksum. Git repositories and their exact commits are
listed in `tools/security/policy.toml`; `cargo-deny` independently rejects
unknown Git sources and anything less specific than `rev`.

CI runs it as the `dependency-security` job of `.github/workflows/ci.yml`,
when a Cargo manifest, the root lock file, `THIRD_PARTY_LICENSES.md`,
`tools/security/` or `tools/licences/` changes, and on a dispatch. The job
uses a read-only `contents` token, a commit-pinned checkout action, Rust
1.98.1, and scanner versions pinned above. Scanners install under the runner's
temporary directory rather than a persistent/global `GOBIN` or Cargo bin
directory. The job does not upload data, write repository contents, or
run on `pull_request_target`.

## Forks

Every Git source is a fork under `peakpassvpn`, pinned by full revision in
`tools/security/policy.toml` and allowed by URL in `tools/security/deny.toml`.
Each fork's `sail` branch carries a `FORK.md` with the same reason and drop
condition. How far each is from its upstream is reported weekly by
`tools/upstream-watch`, from ci.yml's `upstream-watch` job (its fork list is `tools/upstream-watch/forks.json`)
into the [upstream sync report](https://github.com/peakpassvpn/sail/issues/1),
which is where a drop condition is seen to be met.

| Fork | Why | Drop when |
| --- | --- | --- |
| `btls` | BoringSSL hooks REALITY needs (the first ClientHello before it is sent, an extra accepted signature algorithm), a fixed ECH GREASE shape, and the Apple deployment target for BoringSSL's build. | When upstream has equivalents; the REALITY and ECH GREASE hooks are likely to stay Sail's, so not planned. |
| `quinn` (`quinn-proto`) | The client's ClientHello scattered over its first Initial packets, as Chrome and quic-go do, so a middlebox decrypting them does not find the SNI in one piece. Tracks upstream's `0.11.x`. | When upstream quinn scatters the client's first CRYPTO data itself. |
| `quinn-btls` | The `btls` crypto provider for `quinn`, with five fixes upstream lacks: the exporter context (TUIC's token), ECH retry configs read only after a rejection, no IP literal in SNI and no panics on fallible calls, the server's session ticket sent in 1-RTT, and `lru` 0.18 (`RUSTSEC-2026-0253`). | Not planned: upstream is archived. |

`tun-rs`'s netlink crates, `netconfig-rs` 0.1.6 and `route_manager` 0.2.16,
come from crates.io since 2026-10-22 (they were a fork and a pin of upstream's
`main`, on `netlink-packet-core` 0.9); both are on `netlink-sys` 0.8, so the
tree still has one. Through `netlink-packet-core` 0.8 they bring the
unmaintained `paste` (`RUSTSEC-2024-0436`), a proc macro used at compile time
only, allowed with its reason in `tools/security/deny.toml`, whose list
`tools/security/check.sh` also passes to `cargo-audit`. It goes when
`netconfig-rs` releases on `netlink-packet-core` 0.9 and `tun-rs` takes it
(upstream PR `tun-rs/netconfig-rs#4`).

Since 2026-10-02 `cargo-audit` reports no warning but that one: of the
warnings below, `lru` 0.16.4 is closed by `quinn-btls`, and the yanked
`yoke-derive` 0.8.3 by 0.8.4.

## Remediation status (2026-09-29)

The root lockfile is now part of the proposed change instead of being ignored.
It is lock format 4 with 407 packages and SHA-256
`a59082b5c3d1ce17a56cabbd765ee7415ef854725b208c351cccce6e02fdc082`.
`cargo metadata --locked` succeeds against this graph.

The three vulnerability findings in the original baseline have been removed:

- `hickory-proto` resolves to 0.26.3. The 0.26 API migration is covered by the
  DNS unit and integration targets, including explicit replacement of an
  existing EDNS Client Subnet option.
- `maxminddb` resolves to 0.27.3. GeoIP readers now use the safe
  `open_readfile` path rather than the new unsafe mmap API, so a database
  cannot be modified underneath a live memory mapping.
- `protobuf`, `protobuf-codegen`, `protobuf-parse`, and `protobuf-support`
  resolve to 3.7.2. The checked-in generated sources were regenerated with
  that version.
- Sail's direct `lru` dependency resolves to 0.18.5.

`cargo-audit 0.22.2` refreshed the 1,273-advisory RustSec database and passed
this lockfile with no vulnerability findings. It still reports two allowed
informational warnings: unmaintained `paste 1.0.15` through target-specific
TUN dependencies, and unsound `lru 0.16.4` through the pinned `quinn-btls`
fork. The fork's current `main` still declares `lru = "0.16"`, so removing
that warning requires an upstream/fork revision that accepts 0.18.2 or later;
the dependency has not been silently patched or waived here.

Local validation passed:

- security gate failure-mode self-tests;
- `cargo fmt --all -- --check`;
- Sail all-target Clippy with `-D warnings` and `auto-reload`;
- Sail library tests: 615 passed, 3 pre-existing ignored, 0 failed, including
  both macOS watcher regressions.

All five first-party crates now declare `Apache-2.0`, matching the repository
license. `webpki-root-certs 1.0.9` has a package-and-version-specific
`CDLA-Permissive-2.0` exception: it contains Mozilla/CCADB trust-anchor data,
and the required agreement text is retained in `THIRD_PARTY_LICENSES.md` and
uploaded with every GitHub release. The exception does not globally allow
CDLA for another dependency or version. `tun 0.7.22` has likewise been
approved through an exact `WTFPL` exception for Sail's cross-platform TUN
implementation. Its license text is included in the same release notice.
Neither exception permits a different package or version without review.

## Historical local baseline (2026-09-28)

The inspected local `Cargo.lock` is format 4 with 400 packages and SHA-256
`6d712f0a2aa10a5fb072f6571dad6ba8a121b87741a168fbf7de8e257e5ba664`.
Its Git packages are fixed to full commits:

| Packages | Repository | Requested and resolved commit |
| --- | --- | --- |
| `btls 0.5.6`, `btls-sys 0.5.6` | `peakpassvpn/btls` | `4123de36dc5ac86914c8a744f958025e598aa712` |
| `quinn-proto 0.11.18` | `peakpassvpn/quinn` | `6d1e2b9e29895c1707a83167fb482348a70ac65c` |
| `quinn-btls 0.1.0` | `peakpassvpn/quinn-btls` | `3a577da6370dbd1b7035bac55141bb625bb4f68a` |

Manifest and lock revisions agree, and no floating Git dependency was found.
The source gate nevertheless reports a policy violation: root `Cargo.lock` is
ignored by `.gitignore` and is not tracked, so a clean CI checkout has no
locked graph to audit. The gate intentionally does not generate one.

The persisted baseline used `cargo-audit 0.22.2` and `cargo-deny 0.20.2`,
installed in an isolated temporary tool directory. Raw run logs are kept
outside the repository. The audit used an exact copy of the
lockfile above. The RustSec database contained 1,273 advisories at commit
`ef03605143a913024f864d2edf476adad5720c93`, committed
`2026-09-28T11:30:11+02:00`. `cargo-audit` exited 1 with three vulnerabilities:

| Package | Advisory | Fixed version | Local applicability evidence |
| --- | --- | --- | --- |
| `hickory-proto 0.24.4` | `RUSTSEC-2026-0119` | `>=0.26.1` | Direct `sail` dependency. Production DNS paths encode messages with `Message::to_vec`; the advisory concerns quadratic name-compression work during encoding. |
| `maxminddb 0.24.0` | `RUSTSEC-2025-0132` | `>=0.27.0` | Direct `sail` dependency with `mmap`; `sail/src/app/router/matcher.rs` calls the affected `Reader::open_mmap`. Exploitability additionally requires the mapped file to change while mapped. |
| `protobuf 3.6.0` | `RUSTSEC-2024-0437` | `>=3.7.2` | Direct and build dependency. External geosite rules and selector cache files are parsed with protobuf; the advisory concerns uncontrolled recursion while parsing unknown fields. |

The same audit reported informational warnings, which do not account for its
exit status but still require triage:

- `paste 1.0.15`, `RUSTSEC-2024-0436` (unmaintained), reached through the
  target-specific `tun-rs -> netconfig-rs/netlink-packet-core` graph.
- `lru 0.12.5`, `RUSTSEC-2026-0253` and `RUSTSEC-2026-0002` (unsound), a
  direct `sail` dependency.
- `lru 0.16.4`, `RUSTSEC-2026-0253` (unsound), reached through the pinned
  `quinn-btls` fork.

The persisted root-workspace `cargo-deny --locked` run stopped before policy
checks because the current manifests require a lockfile update. An isolated
read-only workspace copy showed the only candidate lock delta: add
`serde_json` to `sail-cli`'s locked dependencies. Running `cargo-deny` against
that offline-resolved copy exited 4; its source check passed and its license
check produced these actual diagnostic findings:

- First-party packages `sail 0.1.2`, `sail-cli 0.14.2`, `sail-ffi 0.1.0`,
  and `shadowsocks 0.1.0` have no license expression and are treated as
  unlicensed. `sail-netstack 0.1.0` declares MIT and passed.
- `tun 0.7.22` declares `WTFPL`, which is not in the approved baseline.
- `webpki-root-certs 1.0.9` declares `CDLA-Permissive-2.0`, which is not in
  the approved baseline.

No exception has been enabled. If either third-party license is accepted, add
a package-and-version-specific exception with rationale; do not add it to the
global allow list merely to make CI green. The project must separately decide
and declare the licenses of its first-party packages.

The root lockfile hash remained unchanged throughout capture. The isolated
candidate lock hash and exact one-line dependency delta are retained with the
raw evidence. These results are a local baseline, not proof that a clean
checkout is reproducible: the inspected root lockfile remains ignored,
untracked, and currently inconsistent with the manifests.

## Historical remediation plan

The dependency portion of this plan was implemented on 2026-09-29 as recorded
above. The remaining transitive warnings and license decisions are still open.

1. Upgrade `hickory-proto` from `0.24.4` to at least `0.26.1`. The dependency
   is declared at `sail/Cargo.toml:194`. Affected encoding calls include
   `sail/src/app/dns/client.rs:544` and `:564`, and
   `sail/src/app/fake_dns.rs:156`. Validate UDP/TCP/DoH/DoQ DNS queries,
   fake-DNS responses, malformed-message handling, and an encoding stress case
   with many record labels. Review the 0.24-to-0.26 API migration before
   changing the constraint.
2. Upgrade `maxminddb` from `0.24.0` to at least `0.27.0`, retaining the mmap
   feature only if the new API is used safely. The declaration is
   `sail/Cargo.toml:204`; the affected call is
   `sail/src/app/router/matcher.rs:609`. Validate MMDB country matching,
   missing/corrupt databases, reload/replacement behavior, and ensure mapped
   files cannot be modified in place while readers remain live.
3. Upgrade both `protobuf` (`sail/Cargo.toml:179`) and the exact
   `protobuf-codegen` build dependency (`sail/Cargo.toml:315`) to at least
   `3.7.2`, then regenerate and review generated sources. Direct parse points
   include external geosite input at `sail/src/config/external_rule.rs:81-84`
   and selector cache input at `sail/src/app/outbound/selector.rs:35-45`.
   Validate normal geosite/cache data, truncated input, deeply nested unknown
   groups, and build-time regeneration consistency.
4. Upgrade the direct `lru 0.12.5` dependency at `sail/Cargo.toml:195` to at
   least `0.18.2` to cover both `RUSTSEC-2026-0002` and
   `RUSTSEC-2026-0253`. The pinned `quinn-btls` fork separately resolves
   `lru 0.16.4` and also needs `>=0.18.2` for `RUSTSEC-2026-0253`; that may
   require updating the fork and its pinned revision. Validate DNS cache
   eviction/iteration, panic behavior, QUIC connection-cache churn, and all
   feature combinations that enable QUIC.
5. `paste 1.0.15` is unmaintained rather than a vulnerability. It is reached
   through target-specific `tun-rs -> netconfig-rs/netlink-packet-core` code.
   Prefer an upstream dependency update that removes/replaces it, then validate
   TUN setup on every supported target.

After any dependency change, regenerate and review the root lockfile, run
`cargo metadata --locked`, the full security gate, targeted subsystem tests,
and the existing workspace CI with Rust build concurrency limited to two.

## Historical integration note

The original baseline required the root lockfile and manifest changes recorded
in the remediation section above. This paragraph is retained to explain why
the historical evidence reports an ignored, inconsistent lockfile.

License exceptions are not self-approved. A proposed exception must identify
the exact package and version, the shipped license text, why it is compatible
with distribution, and an owner/review date. Until approval, a rejection is an
actionable gate failure rather than something to suppress.
