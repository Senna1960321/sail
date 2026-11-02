---
title: CLI reference
description: Run, validate and tune Sail from the command line.
---

The `sail-cli` crate produces the `sail` executable. With no arguments it loads `config.json` from the current directory.

The file extension selects the format: `.json` is sing-box JSON (comments and trailing commas allowed), `.yaml` or `.yml` is Clash/Mihomo YAML, and `.conf` is a Surge profile. Any other extension is an error. All three are read directly by the same loader; there is no conversion step.

## Common commands

```sh
# Start with a JSON configuration
sail -c config.json

# Validate and exit
sail -c config.json -T

# Reload after file changes
sail -c config.json --auto-reload

# Print the build version
sail -V
```

## Connectivity test

Test one outbound by tag without starting the normal listeners:

```sh
sail -c config.json -t edge
```

Sail reports TCP and UDP independently with their elapsed time or error. The default timeout is four seconds; change it with `-d`:

```sh
sail -c config.json -t edge -d 10
```

This test is useful after DNS, credential, certificate or route changes. It tests the named outbound itself, not a complete application-to-inbound path.

## Runtime profiles

Runtime profiles tune memory budgets, queues and concurrency without changing the portable configuration file.

| Profile | Intended host |
| --- | --- |
| `mobile` | Phones and memory-sensitive app processes |
| `desktop` | Default general-purpose profile |
| `server` | High concurrency and throughput |
| `router` | Small devices with the tightest memory budget |

```sh
sail -c config.json --profile server
```

Override one setting with a repeatable `--set key=value` option. The key is a dotted path, and the value is a number, `true` or `false`, or a duration such as `10s`. An unknown key or a value of the wrong type is an error.

```sh
sail -c config.json --profile server \
  --set relay.buffer_size=32 \
  --set dns.max_retries=3
```

These settings describe the host runtime, not proxy behavior. Keep protocol, DNS and routing decisions in the configuration file.

The groups are `relay` (TCP relay buffers and half-close idle timeouts), `udp`, `netstack` (the TUN stack's budget, batches and TCP windows), `inbound` (handshake timeout, multiplex accept concurrency, TCP send buffer), `memory` (the shared growth budget for transfer buffers), `quic`, `ws`, `dns` (`max_retries`, `dualstack_delay`), `stats`, `lifecycle` and `mux`. A few values that differ by profile:

| Setting | `desktop` | `mobile` | `router` | `server` |
| --- | --- | --- | --- | --- |
| `relay.buffer_size` (KiB) | `16` | `8` | `4` | `16` |
| `relay.buffer_max_size` (KiB) | `128` | `64` | `64` | `256` |
| `quic.max_concurrent_streams` | `1024` | `256` | `128` | `4096` |
| `inbound.tcp_send_buffer` (KiB, `0` = system) | `0` | `0` | `256` | `0` |
| `inbound.tcp_send_buffer_max` (KiB, `0` = no growth) | `0` | `0` | `2048` | `0` |
| `inbound.max_connections` (sessions at once, `0` = no limit) | `0` | `512` | `512`; on Linux below 276 MiB of memory, twice the MiB beyond 20, at least 64 | `0` |
| `lifecycle.drain_timeout` | `0` | `0` | `0` | `30s` |

`lifecycle.drain_timeout` is how long open TCP connections may finish after SIGTERM or Ctrl-C once no new ones are accepted; `0` stops at once, and a second signal always stops at once.

On Linux and Android, accepted TCP connections can grow their send buffer from `inbound.tcp_send_buffer` to `inbound.tcp_send_buffer_max` while the buffer limits the transfer. The extra allowance comes from `memory.transfer_budget`, shared with Hysteria2 and TUIC windows. Sail charges twice the requested increase above the starting size to account for kernel bookkeeping. Growth is disabled when the starting size is `0`, the maximum is no larger, or the system is neither Linux nor Android.

After a second without filling the buffer, or with a blocked write, Sail lowers the configured size to its starting value as writes are polled. This does not discard queued data. Allowance for excess queued memory stays reserved until a write observes it draining through `SO_MEMINFO`, or the connection closes. If that query is unavailable, the allowance stays reserved until close. An idle connection, including one whose write was canceled, has no background task to reclaim its drained allowance; it may hold the budget until another write or close.

After growth, Sail reads back the configured size and refunds only unused new allowance, preserving any reservation still needed for an older queue. If readback fails, the requested growth stays charged. Closing the connection returns Sail's reservation, but TCP may retain queued memory after a graceful close; this budget is not a bound on all kernel memory.

The `relay` settings, `relay.write_stall_timeout` among them, apply as well to the connections a fallback (Trojan, VLESS, AnyTLS), ShadowTLS or REALITY relays to the real site.

The streams of multiplexed connections (sing-mux smux and yamux, AnyTLS, amux) take three of them:

| Setting | Default | Meaning |
| --- | --- | --- |
| `mux.stream_window_max` | `16384` (KiB); `8192` on `mobile` and `router` | The largest a stream's receive window grows to (yamux, amux). Windows start at 256 KiB and double while a stream is read faster than its window lets data in. h2mux takes a quarter of it a stream and twice it a connection. |
| `mux.stream_buffer` | `256` (KiB) | What a stream of a protocol without windows (smux, AnyTLS) holds unread before its connection stops being read. |
| `mux.stall_timeout` | `60s` | A stream whose data nothing has read for this long is reset, alone, and logged as `event=stream_stalled`; h2mux streams too. QUIC streams (Hysteria2, TUIC) are reset after 60 s. |

A session of a protocol without windows (smux, AnyTLS) whose connection takes nothing written to it for `relay.write_stall_timeout` (`300s`), once it has stopped reading the connection for a stream holding `mux.stream_buffer` unread, ends with all its streams: when neither end reads, a TCP connection may never move again.

The API's `/api/v1/runtime/stat/mux` counts their sessions, streams and stalled streams per protocol.

The UDP sockets of QUIC (Hysteria2, TUIC, the `quic` transport, DNS over QUIC) take two, the same on every profile:

| Setting | Default | Meaning |
| --- | --- | --- |
| `quic.udp_receive_buffer` | `7168` (KiB); `1024` on the mobile and router profiles | The receive buffer (`SO_RCVBUF`) asked for each socket: the datagrams the system holds while sail is busy, and drops beyond. |
| `quic.udp_send_buffer` | `0` (KiB, the system's) | The send buffer (`SO_SNDBUF`) of the same sockets. |

`0` leaves the system's own size, which is 64 KiB on Windows and about 200 KiB on Linux. For comparison, sing-box's QUIC asks for 7 MiB (`7168`) and Chromium for 1 MiB (`1024`). In the 200 KiB a fast sender overruns sail: on links of 50 and 150 ms without a rate limit, a Hysteria2 transfer between two sail lost a quarter of its datagrams there and ran at a third of what it does with 7 MiB. The system may give less than is asked: Linux keeps twice the number and stops at `net.core.rmem_max` and `net.core.wmem_max`. Past those sail is given what it asks only with `CAP_NET_ADMIN` (as root, or as a service allowed to set up a TUN); without it, in most containers and under the packaged systemd unit, raise the limit to get more: `sysctl -w net.core.rmem_max=7340032` (and in a file under `/etc/sysctl.d` to keep it). Measured, 2 MiB already loses nothing on those links and larger sizes do the same; 7 MiB rather than 2 is a judgment, for margin, and so is the 1 MiB of the mobile and router profiles, which were not measured. What a socket got is logged at `debug`, a size the limit kept short is said once at `info`, and a size the system refuses is a warning, not an error. A QUIC connection that goes through a `detour` has no socket of its own to size.

These are the only socket settings of QUIC. Windows' UDP receive offload (URO, `UDP_RECV_MAX_COALESCED_SIZE`) is deliberately not among them and should not be added as an optimisation: on some Windows 11 systems it silently corrupts datagrams.

## One TCP connection on a router

On a fast, distant link, one download over a TCP-based protocol (Trojan, VLESS, Shadowsocks, VMess and the like) runs at most at its receive buffer divided by the round-trip time. sail adds no limit of its own: it stays within 2% of plain TCP. Linux sizes the buffer from RAM at boot: the largest receive buffer (`net.ipv4.tcp_rmem`, third value) is free RAM / 128, from 128 KiB up to 6 MiB, and the largest send buffer (`net.ipv4.tcp_wmem`) the same from 64 KiB up to 4 MiB. All TCP sockets together are held to `net.ipv4.tcp_mem`, about 6–9% of free RAM, which eight full receive buffers already bring under memory pressure.

| RAM | `tcp_rmem` max | `tcp_mem` limit |
| --- | --- | --- |
| 128 MiB | 598 KiB | 7.0 MiB |
| 256 MiB | 1.56 MiB | 18.7 MiB |
| 512 MiB | 3.51 MiB | 42 MiB |
| 1 GiB | 6 MiB | 84 MiB |

What one connection then reached, by receive buffer and round-trip time, in Mbit/s:

| Receive buffer | 20 ms | 50 ms | 100 ms | 150 ms |
| --- | --- | --- | --- | --- |
| 2 MiB | 479 | 192 | 94 | 62 |
| 4 MiB | 962 | 386 | 187 | 122 |
| 6 MiB | 1305 | 552 | 275 | 176 |
| 6 MiB, server `tcp_wmem` 16 MiB | 1453 | 579 | 283 | 183 |
| 8 MiB, server `tcp_wmem` 16 MiB | 1635 | 650 | 317 | 205 |

These numbers were measured on a test host (a sail client and server over Trojan, network namespaces and netem, downloads, three rounds of 20 s), not on a router; a router's own kernel is smaller and gives somewhat larger values for the same RAM. The server's send buffer is the next limit: at a typical VPS's 4 MiB, raising the router's buffer alone past it gains nothing.

On a router's memory (qemu guests of 128, 256 and 512 MiB running sail's router build, the upstream 100 ms away over Trojan, the server's send buffer at 4 MiB), what downloads reached in Mbit/s, with the kernel's cap and with it raised to 6 MiB:

| RAM | one, kernel's cap | one, 6 MiB | four at once, kernel's cap | four at once, 6 MiB |
| --- | --- | --- | --- | --- |
| 128 MiB | 12–14 | 96–118 | 55–61 | 241–257 |
| 256 MiB | 34–37 | 70–120 | 140–150 | 346–376 |
| 512 MiB | 47–73 | 98–117 | | |

The OpenWrt package raises the cap by default: its `tcp_buffers` option writes `/etc/sysctl.d/90-sail-tcp.conf`, keeps the low and default values, and leaves a cap already above 6 MiB alone (`uci set sail.main.tcp_buffers=0` turns it off). Elsewhere, raise it on the router, and the send buffer on the server, each in a file under `/etc/sysctl.d` to keep it:

```sh
# on the router: the first two values as they are, the cap 6 MiB
sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456"
# on the server
sysctl -w net.ipv4.tcp_wmem="4096 16384 16777216"
```

A larger cap costs no memory by itself. The kernel grows a connection's buffer only while it is read fast, and all TCP buffers together stay within `tcp_mem`. In the same guests, with all sessions but 24 stalled for a minute while the upstream kept sending, the lowest free memory and sail's own were the same with either cap, and no connection was dropped for memory. Under such a load every connection's window shrinks, whatever its cap: all TCP sockets reach `tcp_mem`.

sail does not set a fixed receive buffer on its own connections (`SO_RCVBUF`), which would turn the kernel's tuning off for them. In the same guests, one download then reached 180 Mbit/s, but four at once on 128 MiB pushed all TCP memory into pressure (166–231 Mbit/s together). A multiplexed outbound (h2mux, yamux, smux) carries all its streams in one TCP connection, so that connection's limit is shared by all of them. Hysteria2 and TUIC run QUIC over UDP and are not bound by the TCP buffers; their buffer is `quic.udp_receive_buffer` (1 MiB on the router profile), and they are the other answer to a slow long link.

## Paths and persisted state

```sh
sail -c config.json \
  --data-dir /opt/sail/data \
  --cache-dir /var/lib/sail
```

The data directory contains files such as `geo.mmdb`, `site.dat` and relative certificate paths. It defaults to the executable's directory. The cache directory holds `experimental.cache_file` by default (selector choices, a smart group's sites, the Clash mode and, with `store_fakeip`, fake IPs), downloaded remote rule-sets, and the copies of a Surge profile's remote includes.

## Assets

Some rules read data files from the data directory: `geoip` and `mmdb:` external rules read `geo.mmdb`, `geosite` and `site:` read `site.dat`, `ip_asn` (Surge's `IP-ASN`) and a `smart` group's `prefer_asn` read `asn.mmdb`, and an external rule or `asn_file` may name another file. Sail does not download these when it loads a configuration; a configuration that needs one that is missing fails to load, naming the path.

```sh
# What the configuration reads, where, and whether it is there
sail -D /opt/sail/data assets config.json

# Download the missing ones, or all of them again
sail -D /opt/sail/data assets config.json --fetch
sail -D /opt/sail/data assets config.json --update

# From another URL
sail assets config.json --fetch --source geo.mmdb=https://example.com/Country.mmdb

# Download the missing ones before starting
sail -c config.json --fetch-assets
```

`sail assets` prints one line per file: its name, `present` or `missing`, its path, and the fields that read it (`route.rules[3].ip_asn`). A download replaces a file only once it reads as a MaxMind database or a site list, and never leaves half a file. The defaults:

| Asset | Source |
| --- | --- |
| `asn.mmdb` | GeoLite2-ASN, Mihomo's default: `https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb` |
| `geo.mmdb` | GeoLite2-Country format: `https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb` |
| `site.dat` | V2Ray site lists: `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` |

A file a rule names has no default: give it one with `--source name=url` (or `--asset-source name=url` when starting). A rule-set read from a file or downloaded may need `asn.mmdb` too; that is known only when it loads, and its error names the file.

The sources the CLI starts with become the host's `asset_sources`, which the runtime API updates from while sail runs:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/runtime/assets` | The running configuration's assets, as `sail assets` lists them, in JSON |
| `POST /api/v1/runtime/assets/{name}/update` | Downloads one, from the body's `url` or else the host's source, through the body's `detour` outbound or else the default one; puts it in place if it reads, then reloads so that the rules read it. The reply says whether the reload took. 404 for a name the configuration does not read, 400 without a URL, 502 when the download or the file fails |

## Surge includes, Sub-Store and the dashboard

```sh
# Download the URLs a Surge profile includes before reading it
sail -c profile.conf --cache-dir /var/lib/sail --fetch-includes

# Keep a managed Surge profile (#!MANAGED-CONFIG) up to date
sail -c profile.conf --cache-dir /var/lib/sail --managed-update

# Resolve sub.store URLs to your own Sub-Store backend
sail -c profile.conf --sub-store https://substore.example.com/secret-path
```

`--fetch-includes` downloads every `#!include https://...` of a Surge profile, and what those include, into the cache directory, where the profile reads them. It needs `--cache-dir` and a `.conf` file. A download that fails keeps the copy already there; with no copy, startup fails.

`--managed-update` keeps a managed Surge profile up to date, as its `#!MANAGED-CONFIG https://... interval=86400 strict=true` line says. Once the interval has passed since the last update (at startup too), sail fetches the profile again. It loads the new profile as a start would, puts it in place of the file and reloads. A profile that does not load, or that the running instance refuses, leaves the file as it was. An interval below 60 seconds counts as 60. A failed update is retried after a minute, then twice as late each time, up to an hour or the interval. A new profile without the line is taken once, and updating stops. The time of the last update is kept in the cache directory, so `--cache-dir` is needed. With `--fetch-includes`, the new profile's includes are fetched before it is loaded. Unlike Surge, a strict profile whose update fails past its interval is still served: the failure is logged as an error and the update retried. sail never stops serving for it.

`--sub-store` gives the base URL (secret path included) that `sub.store`, the address Sub-Store uses inside Surge, Loon and Quantumult X, stands for in subscription and rule-set URLs.

`--ui-download-url` is the ZIP the Clash API downloads into an empty `external_ui` directory when the configuration names no URL. It defaults to metacubexd; pass an empty value to download none.

## Generating keys

`sail generate` prints a key or password and exits:

```sh
sail generate uuid                              # a random UUID for VLESS, VMess or TUIC users
sail generate rand 16 --base64                  # random bytes: raw, --base64 or --hex
sail generate reality-keypair                   # PrivateKey (server) and PublicKey (clients)
sail generate wg-keypair                        # a WireGuard key pair
sail generate ss2022 2022-blake3-aes-128-gcm    # a key of the length the method takes
sail generate secret                            # a Clash API secret (clash_api.secret)
```

`ss2022` takes `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` or `2022-blake3-chacha20-poly1305`.

## Importing share links

`sail import` reads share links (`ss://`, `trojan://`, `vless://`, `vmess://`, `hysteria2://` or `hy2://`, `tuic://`, `anytls://`) and prints them as sing-box outbounds in JSON:

```sh
sail import 'vless://...'
sail import subscription.txt
cat subscription.txt | sail import
```

The input is one link, a subscription file (base64, or one link per line), or standard input. Each line that cannot be read is reported on stderr with its line number; the command fails only if no link is read. Tags are made unique. ShadowsocksR, Hysteria v1 and WireGuard links are not imported.

## Threading

The runtime's threads follow the profile: two worker threads for `desktop` (one on a single CPU), one thread for `mobile`, a worker thread to each CPU for `server` and `router`. Two is measured: a connection's tasks wake one another, and with a worker to each CPU those wakes cross threads, which on Windows cost Hysteria2 downloads twice the CPU. `--threads` sets the number of worker threads whatever the profile. `--single-thread` is useful for constrained hosts, deterministic debugging or embeddings that provide their own outer concurrency. `--thread-stack-size` changes the worker stack size in bytes (default 256 KiB in release builds, 2 MiB in debug builds); keep the default unless profiling shows a concrete need.

On Unix, the CLI raises the open-file soft limit to the hard limit at startup (on macOS, no higher than `kern.maxfilesperproc`).

## Option summary

| Option | Purpose |
| --- | --- |
| `-c`, `--config` | Configuration path; default `config.json`. Format by extension: `.json`, `.yaml`/`.yml`, `.conf` |
| `--auto-reload` | Watch the configuration and reload changes |
| `--single-thread` | Use a current-thread runtime |
| `--threads` | Worker threads of the runtime; the profile's unless set |
| `--thread-stack-size` | Worker thread stack size in bytes |
| `-T`, `--test` | Validate configuration and exit |
| `-t`, `--test-outbound` | Test one outbound tag |
| `-d`, `--test-outbound-timeout` | Outbound test timeout in seconds; default `4` |
| `--profile` | `mobile`, `desktop`, `server` or `router` |
| `--set` | Override one runtime tuning value; repeatable |
| `-D`, `--data-dir` | Assets and relative certificate base directory |
| `--cache-dir` | Where `experimental.cache_file` is by default, remote rule-sets are cached and Surge includes are kept |
| `--sub-store` | Base URL of your own Sub-Store backend, which `sub.store` stands for |
| `--ui-download-url` | ZIP the Clash API downloads into an empty `external_ui`; default metacubexd, empty for none |
| `--fetch-includes` | Download a Surge profile's remote includes into the cache directory before starting |
| `--managed-update` | Keep a managed Surge profile up to date: fetched again once its interval has passed, and reloaded |
| `--fetch-assets` | Download the missing assets before starting |
| `--asset-source` | `name=url`: where an asset is downloaded from; repeatable |
| `assets [config]` | List the assets (of `-c` when no config is given); `--fetch`, `--update`, `--source name=url` |
| `generate <kind>` | `rand`, `uuid`, `reality-keypair`, `wg-keypair`, `ss2022`, `secret` |
| `import [input]` | Share links to sing-box outbounds JSON |
| `-V`, `--version` | Print version and exit |
| `--help` | Print usage; also after a subcommand |
