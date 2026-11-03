---
title: Configuration
description: Understand Sail's JSON model, defaults, validation and reusable protocol blocks.
---

Sail's native configuration is sing-box's JSON (sing-box 1.14), with a few Sail extensions. Comments and trailing commas are accepted, as in sing-box. Sail also reads Clash / Mihomo YAML and Surge profiles directly: the file extension (`.json`, `.yaml` or `.yml`, `.conf`) or the text itself picks the format, and all three become the same model. See [Protocols](/sail/protocols/#clash-sing-box-and-surge-ecosystems) for how the format is recognised.

A field Sail does not know is an error. A sing-box field Sail does not implement is dropped with a warning when ignoring it changes no routing or security, and is an error otherwise. Sail logs each warning at start.

## Top-level model

For individual fields, see the generated reference: [top level and common](/sail/reference/common/), [DNS](/sail/reference/dns/), [inbounds](/sail/reference/inbounds/), [outbounds and groups](/sail/reference/outbounds/), [endpoints](/sail/reference/endpoints/), [route](/sail/reference/route/) and [shared objects](/sail/reference/shared/), with each field's status against sing-box; the Clash and Surge support tables are under [compatibility](/sail/reference/compatibility/).

| Field | Purpose | Default |
| --- | --- | --- |
| `log` | Log level, format and optional file output | `info`, full format, console |
| `dns` | DNS servers, DNS rules, strategy and cache | The system resolver, `prefer_ipv4` |
| `inbounds` | Listeners or packet sources that accept traffic | Empty |
| `outbounds` | Direct, proxy and group destinations | Empty |
| `endpoints` | Both an inbound and an outbound under one tag (WireGuard) | Empty |
| `route` | Ordered rules, rule-sets and the final outbound | First outbound |
| `certificate` | Root certificates servers are checked against | The system's |
| `http_clients` | How Sail downloads rule-sets and providers, by tag | Through the default outbound |
| `experimental` | `cache_file` and the Clash API | Disabled |
| `api` | Sail's control API, on a unix socket or loopback (extension) | Disabled |
| `clash_api` | The Clash API, also accepted under `experimental` (extension) | Disabled |
| `outbound_providers` | Outbounds downloaded or given together, for groups (extension) | Empty |
| `user_limits` | Per-user limits across inbounds (extension) | Empty |

sing-box's `ntp` section is read: the time it measures is the one the protocols check and TLS and QUIC verify certificates at, and the system's clock is never set. Give its `server` as an IP address, or let its name resolve over plain DNS: until the first answer the time is still the system's, so a name resolved over DoH, DoT or DoQ has that server's certificate verified at the uncorrected time, which fails on a device whose clock is far off. sing-box's `services`, `certificate_providers` and `network_namespaces` are mostly errors.

Every inbound, outbound and endpoint has a `type` and may have a `tag`. When `tag` is omitted it defaults to the protocol type. Explicit tags are recommended once a configuration has more than one item.

## Inbound fields

These fields are shared by network inbounds:

```json
{
  "type": "socks",
  "tag": "lan-socks",
  "listen": "127.0.0.1",
  "listen_port": 1080,
  "udp_timeout": "30s"
}
```

`listen` defaults to `127.0.0.1`. An inbound without `listen_port` does not open a listener and is only useful when composed by another inbound. `udp_timeout` defaults to 5 minutes. Protocol-specific fields, such as SOCKS users or Shadowsocks credentials, live beside the shared fields.

## Outbound fields and blocks

An outbound starts with a protocol and its connection details:

```json
{
  "type": "trojan",
  "tag": "edge",
  "server": "edge.example.com",
  "server_port": 443,
  "password": "replace-me",
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com"
  }
}
```

Stream proxy protocols can use shared blocks around the protocol itself:

| Block | What it controls |
| --- | --- |
| `tls` | TLS, certificates, ALPN, ECH, REALITY and browser ClientHello |
| `transport` | WebSocket, HTTP Upgrade, gRPC or QUIC |
| `multiplex` | sing-mux (smux, yamux, h2mux) over a shared connection |
| `detour` | Dial this outbound's server through another outbound |
| Dial fields | Interface, local address, Linux mark, timeouts, keepalive and name resolution |

The supported blocks depend on the protocol. QUIC-native protocols such as TUIC and Hysteria2 own their TLS configuration and do not accept every stream transport block. See [Protocols](/sail/protocols/#transports-and-security) for the layers.

### Dial fields

```json
{
  "type": "socks",
  "tag": "upstream",
  "server": "192.0.2.10",
  "server_port": 1080,
  "bind_interface": "en0",
  "connect_timeout": "5s"
}
```

The dial fields are sing-box's: `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `routing_mark` (Linux), `reuse_addr`, `connect_timeout`, `tcp_fast_open`, the TCP keepalive fields, `udp_fragment`, `domain_resolver`, and `network_strategy` with `network_type`, `fallback_network_type` and `fallback_delay`. `route.default_interface`, `route.default_mark`, `route.default_domain_resolver` and `route.default_network_strategy` set them for every outbound that sets none of its own. The [shared objects](/sail/reference/shared/) reference lists which are supported where.

## DNS

```json
{
  "dns": {
    "servers": [
      { "type": "local", "tag": "system" },
      { "type": "https", "tag": "cloudflare", "server": "1.1.1.1" }
    ],
    "rules": [
      { "domain_suffix": ["internal.example"], "server": "system" }
    ],
    "final": "cloudflare",
    "strategy": "prefer_ipv4",
    "cache_capacity": 4096,
    "timeout": "4s",
    "reverse_mapping": true
  }
}
```

Server types are `local`, `hosts`, `udp`, `tcp`, `tls`, `quic`, `https`, `h3`, `fakeip` and `mdns`, plus Sail's `race`, which asks its members at once and takes the first good answer. sing-box's `dhcp`, `resolved`, `tailscale`, `openvpn` and `openconnect` servers are errors. With no servers, the system resolver answers. DNS rules pick a server in order; `final`, or else the first server, takes the rest.

`strategy` is one of `prefer_ipv4` (the default), `prefer_ipv6`, `ipv4_only` or `ipv6_only`. The cache holds 1024 answers unless `cache_capacity` is larger, and one query to one server may take 10 seconds unless `timeout` says otherwise. Reverse mapping remembers the domain associated with DNS answers so later connections to those addresses can still match domain rules. Sail's `client_strategy` limits the address families in answers to clients' queries without changing Sail's own lookups.

### Names on the local link (mDNS)

An `mdns` server (`{ "type": "mdns", "tag": "lan", "interface": ["en0"] }`, every multicast interface when `interface` is empty) resolves `.local` names and the link-local reverse zones by multicast DNS. Off Apple's systems a `local` server does the same for those names on its own; on Apple's the system resolver does. A DNS rule's `preferred_by` names servers and matches the names they answer for themselves: a `hosts` server its entries, `local` its hosts file and the mDNS names, `mdns` the mDNS names.

Unlike sing-box, sail's queries ask for a unicast reply (the QU bit of RFC 6762): Windows answers no other query, so sing-box cannot resolve a Windows machine's `.local` name, and sail can. sail also returns as soon as one interface answers instead of waiting out the whole second.

## Logging and control API

```json
{
  "log": {
    "level": "debug",
    "format": "compact",
    "output": "sail.log"
  },
  "api": {}
}
```

Log levels are `trace`, `debug`, `info`, `warn` (or `warning`) and `error`; `fatal` and `panic` are accepted and act as `error`. Set `disabled` to log nothing and `timestamp` to start each line with the time. `format: compact`, a Sail extension, writes the message alone. Leave `output` unset to log to the console. Console lines carry colours only when the console is a terminal, not a pipe or the systemd journal; set the `NO_COLOR` environment variable to leave them out there too (sing-box's `--disable-color`).

The API is served when `api` is set. By default it is on a unix socket, `api.sock` in the data directory (`path` sets another), which only the user Sail runs as can open. `listen` serves it on a loopback address too, such as `127.0.0.1:9091`, and needs `secret`: one `sail generate secret` makes, which every call sends as `Authorization: Bearer <secret>`; a call without it gets 401. Any process on the host can reach a loopback port, and a secret sent over a network travels in the clear, so `listen` takes loopback addresses only; reach the API from elsewhere through an SSH tunnel or a reverse proxy. A `secret` set for the socket is checked there too. Errors are JSON, `{"error": {"code": "invalid", "message": "..."}}`; a reload that fails answers so, with why, and the configuration that ran runs on.

The management API: `GET /api/v1` gives this build's version and features. Under `/api/v1`, routes and fields are only added, and a client ignores those it does not know; a change that takes one away or changes what it means goes under `/api/v2`. Under `/api/v1/runtime`:

| Route | What it does |
| --- | --- |
| `GET /users`, `GET /users/{name}` | Users by name: the inbounds they are in, whether they may connect (`active`, `over_quota`, `expired`), their limits, traffic, live connections and quota used |
| `PUT /users/{name}/limits` | Limits the user by the body until the next reload: the `limits` a GET gives, so it goes back as it came (times in `expire_at_ms`, milliseconds since the epoch), or one user's in `user_limits` (`expire_at` in RFC 3339); 204 |
| `DELETE /users/{name}/limits` | Back to the limits the configuration sets; 204 |
| `POST /users/{name}/quota/reset` | What the user used no longer counts; 204 |
| `POST /users/{name}/disconnect` | Closes its connections, `{"closed": n}`; it may connect again |
| `GET /stats` | Traffic by user, inbound and outbound; `?clear=true` counts from the last such read, which quotas do not |
| `GET /status` | Traffic in total, connections and memory |
| `GET /events` | Server-Sent Events of what happens to users: `shut` (over its quota or expired, and disconnected) and `removed` (taken out of an inbound), the event's JSON as its data; `lagged`, with the `kind` and how many were `missed`, to one that fell behind. `?kinds=connection` (or `user,connection`; `user` alone when not given) adds `connection` events: each connection's record when it closes, the bytes up and down since it started, its user, inbound, the address it connected to, destination, outbound and chain, times, how it ended and how it was used (`ok`, `dial_failed`, `blocked`, `rejected`) (`docs/embed.md`, `Kinds::CONNECTION`); a connection's closed record has what its user was counted |
| `GET /connections`, `DELETE /connections`, `DELETE /connections/{id}` | The connections open, closing them all, or one |
| `GET /admission` | What admission under memory pressure did since the instance started: `{"level": "off" | "normal" | "pressure" | "hard", "free", "reserve", "handshakes", "refused", "refused_sources", "refused_quic", "evicted", "evicted_full", "pressure_ms"}`. `GET /events?kinds=admission` adds an `admission` event at each change of level (`{"level", "free", "reserve", "handshakes"}`) |
| `POST /connections/report` | An interim pass, now: to the subscribers of `connection` events (`GET /events?kinds=connection`), a record of each connection open, idle ones too; `{"recorded": n}`. A host that bills by traffic calls it on its own schedule, and right before a graceful stop |
| `POST /reload`, `POST /shutdown` | Reloads the configuration file, or stops. A reload answers what became of each inbound: `{"inbounds": [{"tag", "change"}]}`, `change` one of `untouched`, `reloaded` (new users or certificate), `added`, `removed`, `replaced`; the connections of those removed and replaced are closed, and no others. 409 (`needs_restart`) when the file adds, removes or changes a TUN: nothing changed |
| `GET /inbounds` | The inbounds: tag, type, where they listen, and whether their users change while they run (`reloadable`) |
| `POST /inbounds`, `DELETE /inbounds/{tag}`, `POST /outbounds`, `DELETE /outbounds/{tag}` | Adds or removes one, as the configuration has them |
| `PUT /inbounds/{tag}` | Replaces a reloadable inbound's users and certificate by the body, the whole inbound, without rebinding its socket; 204 |
| `GET /inbounds/{tag}/users` | The names of its users; their credentials are never told |
| `POST /inbounds/{tag}/users` | Adds a user, as the inbound's `users` has them, with a name; 201, or 409 when the name is there already |
| `PUT /inbounds/{tag}/users/{name}` | Replaces the user's credentials, as a password is changed; its connections go on, as in sing-box; 204 |
| `DELETE /inbounds/{tag}/users/{name}` | Takes the user out of the inbound and closes its connections through it; 204 |

A change to the users of an inbound that is not reloadable answers 422 (`unsupported`): change it with a reload.

What the API changes is not written to the configuration: a reload or a restart goes by the file. An inbound added through the API and not in the file is removed by the next reload, so write it to the file as well. A user is 404 when no inbound has it.
 The Clash API, which dashboards use, is configured in `clash_api` or in sing-box's `experimental.clash_api`, not both.

## Sail extensions

These fields are Sail's own; sing-box does not accept them. The full list closes the sing-box support table linked from the [compatibility](/sail/reference/compatibility/) page.

- `outbound_providers`: outbounds downloaded (`remote`), read from a file (`local`) or written in place (`inline`), as Mihomo's proxy-providers. A download or file holds Clash YAML with `proxies`, or share links. `selector`, `urltest`, `fallback`, `load-balance` and `smart` groups take them through `providers`. See [Routing](/sail/routing/#groups-and-providers).
- `user_limits`: by user name, across every inbound the user is in: `max_connections`, `max_tcp_connections` (its TCP connections and multiplexed streams alone, UDP sessions not counted; both apply when both are set), `quota_bytes` (up and down together; needs `experimental.cache_file`), `expire_at` (RFC 3339), and `up_mbps`, `down_mbps` and `total_mbps` (up and down together: a byte passes when every rate set allows it). A field left out limits nothing; none may be 0. Limits set through the management API stay over these through a reload, unless it changes the user's: then they are dropped, and the reload's report names the user (`user_limits_dropped`).
- `api`, and `clash_api` at the top level.
- Routing additions such as `geoip`, `geosite`, `external`, `ip_asn` and `no_resolve`, and the `fallback`, `load-balance`, `smart`, `network`, `tryall` and `pass` outbounds. See [Routing](/sail/routing/) and [Protocols](/sail/protocols/).

## Validation rules worth knowing

- Tags referenced by `route.final`, route rules, groups and detours must exist, as must the DNS servers that rules and resolvers name.
- A rule that ends matching for every connection (`route`, `reject`, or `bypass` with an outbound) needs at least one condition; use `route.final` for the catch-all path.
- Action fields belong to their action: `sniffer` and `skip_rule_set` to `sniff`; `server` and `strategy` to `resolve`; `timeout` to either; `method` to `reject`. `override_destination` belongs to `sniff`, `route` and `route-options`, and its `"at_sniff"` value to `sniff` only.
- `route.auto_detect_interface` and `route.default_interface` are mutually exclusive.
- `route.default_network_strategy` needs `route.auto_detect_interface`.
- Durations such as DNS, UDP and sniff timeouts must be greater than zero.

A TUN inbound with `auto_route` turns interface detection on by itself; see [TUN loop prevention](/sail/routing/#tun-loop-prevention).

Run `sail -c config.json -T` after every change. See [CLI reference](/sail/cli/) for connectivity testing and runtime settings.

## Clash and Surge files

`sail -c config.yaml` reads a Clash / Mihomo configuration and `sail -c profile.conf` a Surge profile, each into the model above. A Surge profile's included files are read from beside it, or from the host's cache when they were downloaded. What each format sets that Sail ignores or refuses is listed in the [compatibility](/sail/reference/compatibility/) tables. leaf's old `.conf` format is gone: a `.conf` file is read as a Surge profile.
