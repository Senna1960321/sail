---
title: "出站与策略组"
description: "sail 原生配置格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段参考。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

<a id="outbounds"></a>

## `outbounds[]`

Rust 定义：[`Outbound`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `anytls`, `block`, `bridge`, `direct`, `http`, `hysteria`, `hysteria2`, `naive`, `selector`, `shadowsocks`, `shadowtls`, `snell`, `socks`, `ssh`, `tor`, `trojan`, `tuic`, `urltest`, `vless`, `vmess` | 必填 | 支持 | — |

<a id="outbounds-anytls"></a>

## `outbounds[anytls]`

Rust 定义：[`AnyTlsOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/anytls/outbound/mod.rs) · 构建条件：`feature = "outbound-anytls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-outbounds) | 未设置 | 支持 | — |
| `password` | string | 必填 | 支持 | — |
| `idle_session_check_interval` | duration | 未设置 | 支持 | — |
| `idle_session_timeout` | duration | 未设置 | 支持 | — |
| `min_idle_session` | number | `0` | 支持 | — |
| `client_metadata` | string | — | 警告：Metadata the client tells the server: the connection goes the same way without it | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-block"></a>

## `outbounds[block]`

Rust 定义：[`BlockOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/drop/mod.rs) · 构建条件：`feature = "outbound-drop"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |

<a id="outbounds-direct"></a>

## `outbounds[direct]`

Rust 定义：[`DirectOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/direct/outbound/mod.rs) · 构建条件：`feature = "outbound-direct"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | — | 报错：A detour for a direct outbound, which sing-box refuses too | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-fallback"></a>

## `outbounds[fallback]`

Rust 定义：[`FallbackOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/fallback/mod.rs) · 构建条件：`feature = "outbound-fallback"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `outbounds` | 数组，元素为 string | `[]` | sail 扩展 | Its members, in order; none may be when its providers give others. |
| `providers` | string 或 数组，元素为 string | `[]` | sail 扩展 | The outbound providers, by tag, whose outbounds join the group's own, in this order. |
| `filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions, as Mihomo's `filter`: of the providers' outbounds, only those whose names match one are members, those of the first first. The group's own outbounds are not filtered. |
| `exclude_filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions no member's name may match, the group's own outbounds' too. |
| `exclude_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | The types no member may be of, the group's own outbounds too, in Mihomo's names for them, without case: `Shadowsocks`, `Vmess`, `Socks5`, `Direct`, ... |
| `empty_fallback` | string | 未设置 | sail 扩展 | An outbound, not a group, that is the member while there is none else. Without it such a group has none, and its connections fail. |
| `url` | string 或 数组，元素为 string | `default_url()` | sail 扩展 | What is requested through each member to test it: a URL, or a list of them, a sail extension, all tested at once in each round. The latency shown is the first URL's, and the API shows it as the group's `testUrl`. |
| `url_policy` | string, 取值 `any`, `all` | `any` | sail 扩展 | With several URLs, which a member must answer to pass: `any` of them, which tells a dead member from a URL blocked, or `all`; a sail extension. Under `any`, the latency shown is that of the first URL that answered. |
| `expected_status` | string | 未设置 | sail 扩展 | The HTTP statuses a test must be answered with to pass, as Mihomo's `expected-status`: codes and ranges, `200/204/401-429`; any when unset. Each URL's answer must be one. |
| `unified_delay` | bool | `false` | sail 扩展 | The latency of a second request on the connection the first opened, without the connect and handshakes, as Mihomo's `unified-delay`; a sail extension. |
| `interval` | duration | 未设置 | sail 扩展 | — |
| `timeout` | duration | 未设置 | sail 扩展 | How long a test may take before its member counts as failed; 5s, as Mihomo's `timeout`. Also how close together `max_failed_times` failures must come, and `dial_timeout` when that is unset. |
| `dial_timeout` | duration | 未设置 | sail 扩展 | How long a connection attempt through a member, with a member left to fall back to, may take before the group moves on to the next; a sail extension, 1s at least, `timeout` when unset. One still dialling the member's server then marks it down at once; one in the member's handshake is counted toward `max_failed_times`. |
| `max_failed_times` | number | 未设置 | sail 扩展 | How many failed connections, within `timeout` of the first, have the members tested again; 5, as Mihomo's `max-failed-times`. Only failures that may be the destination's count: one that says the member's server cannot be reached marks the member down at once. |
| `lazy` | bool | `true` | sail 扩展 | Tests only while the group is in use: not when it was not used since the last ones. |
| `interrupt_exist_connections` | bool | `false` | sail 扩展 | Ends the connections through the member left once the group switches. |
| `debounce` | 对象 → [对象](#outbounds-fallback-debounce) | 类型的默认值 | sail 扩展 | How many rounds of tests in a row have the group leave a member, or take an earlier one back, and how long it stays on a member at least; a sail extension. Unset, every round counts at once. |
| `disable_udp` | — | — | sail 扩展 | The group carries TCP alone, whatever member it picks (Mihomo's disable-udp) |

<a id="outbounds-fallback-debounce"></a>

### `outbounds[fallback].debounce`

Rust 定义：[`DebounceOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/fallback/mod.rs) · 构建条件：`feature = "outbound-fallback"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `fail_after` | number | `1` | sail 扩展 | Failed rounds in a row before the member the group is on is left, by default one. A connection that finds its server unreachable leaves it at once all the same. |
| `recover_after` | number | `1` | sail 扩展 | Passed rounds in a row before a member that was down, failed or found unreachable, is up again, and taken back if it comes first, by default one. |
| `min_dwell` | duration | 未设置 | sail 扩展 | The least time on a member before the group leaves it, while it is up, for an earlier member up again; 0s. The first round past it switches. A member down is left at once. |

<a id="outbounds-http"></a>

## `outbounds[http]`

Rust 定义：[`HttpOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/http/outbound/mod.rs) · 构建条件：`feature = "outbound-http"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `username` | string | 未设置 | 支持 | — |
| `password` | string | 未设置 | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-outbounds) | 未设置 | 支持 | — |
| `path` | string | 未设置 | 支持 | The request target instead of the destination, which then goes only in `Host`, as sing-box sends it. |
| `headers` | map | `{}` | 支持 | Sent with every `CONNECT`. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |
| `version` | number | 未设置 | sail 扩展 | The HTTP version, sing-box 1.15's: 1, 2 or 3; unset (or 0), 1, as sing-box 1.14 speaks, until sail follows 1.15 stable. HTTP/2 needs TLS, and not REALITY's: without, HTTP/1.1. 3 is HTTP/2, which sail speaks in its place. |
| `disable_version_fallback` | bool | `false` | sail 扩展 | HTTP/2 alone, never HTTP/1.1 in its place: a server that picks no `h2` is an error. |
| `idle_timeout` | duration | 未设置 | sail 扩展 | HTTP/2's, sing-box 1.15's: how long a ping may go unanswered. |
| `keep_alive_period` | duration | 未设置 | sail 扩展 | HTTP/2's: a ping after this long with nothing received. |
| `stream_receive_window` | number | 未设置 | sail 扩展 | HTTP/2's: a tunnel's receive window. |
| `connection_receive_window` | number | 未设置 | sail 扩展 | HTTP/2's: a connection's receive window. |
| `max_concurrent_streams` | number | 未设置 | sail 扩展 | HTTP/2's: the most tunnels one connection carries. |

<a id="outbounds-hysteria2"></a>

## `outbounds[hysteria2]`

Rust 定义：[`Hysteria2OutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hysteria2/outbound/mod.rs) · 构建条件：`feature = "outbound-hysteria2"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 必填 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | The one port; with `server_ports`, not needed. |
| `server_ports` | listable-string | 未设置 | 支持 | Ports or ranges ("20000:30000") to hop between. |
| `hop_interval` | duration | 未设置 | 支持 | How often to hop, 30s unless set. |
| `hop_interval_max` | duration | — | 警告：Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic | — |
| `up_mbps` | number | 未设置 | 支持 | What we may send at; set, it selects Brutal. |
| `down_mbps` | number | 未设置 | 支持 | What we can receive at, told to the server. |
| `obfs` | object → [对象](/sail/zh/reference/shared/#obfs), [[gecko]](/sail/zh/reference/shared/#obfs-gecko), [[salamander]](/sail/zh/reference/shared/#obfs-salamander) | 未设置 | 支持 | — |
| `password` | string | 必填 | 支持 | — |
| `network` | listable-string, 取值 `tcp`, `udp` | 未设置 | 支持 | "tcp" or "udp", or both, as unset. |
| `tls` | object → [对象](#outbounds-hysteria2-tls) | 必填 | 支持 | — |
| `idle_timeout` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `keep_alive_period` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `stream_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `connection_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `max_concurrent_streams` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `initial_packet_size` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `disable_path_mtu_discovery` | bool | — | 警告：QUIC tuning: the same connection without it | — |
| `bbr_profile` | string, 取值 `standard`, `conservative`, `aggressive` | — | 警告：Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic | — |
| `brutal_debug` | bool | — | 警告：Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic | — |
| `disable_chrome_parrot` | bool | — | 警告：Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic | — |
| `realm` | object → [对象](#outbounds-hysteria2-realm) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |

<a id="outbounds-hysteria2-tls"></a>

### `outbounds[hysteria2].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack: sail has one | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | 未设置 | 支持 | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The lowest TLS version to negotiate, `1.0` to `1.3`; unset, 1.2. |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The highest; unset, 1.3. |
| `cipher_suites` | listable-string | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate to trust. |
| `certificate_path` | string | 未设置 | 支持 | A PEM certificate to trust, by path. |
| `certificate_public_key_sha256` | listable-string\|array | 未设置 | 支持 | The SHA-256 hashes, base64, of the public keys to take a server's certificate by, in place of the certificates trusted, the name and `insecure`. |
| `client_certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate, its chain after it, presented when the server asks for one; with `client_key`. |
| `client_certificate_path` | string | 未设置 | 支持 | `client_certificate`, by path. |
| `client_key` | listable-string | 未设置 | 支持 | The inline PEM key of the client certificate. |
| `client_key_path` | string | 未设置 | 支持 | `client_key`, by path. |
| `fragment` | bool | — | 报错：Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do here | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-outbounds) | 未设置 | 支持 | — |
| `utls` | object → [对象](#outbounds-hysteria2-tls-utls) | — | 报错：Not supported over QUIC | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-outbounds) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="outbounds-hysteria2-tls-utls"></a>

### `outbounds[hysteria2].tls.utls`

Rust 定义：[`OutboundUtls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `true` | 支持 | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | — | 报错：Not supported over QUIC | — |

<a id="outbounds-hysteria2-realm"></a>

### `outbounds[hysteria2].realm`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server_url` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `token` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `realm_id` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `stun_servers` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `ip_version` | number, 取值 `0`, `4`, `6` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `port_mapping` | object → [对象](/sail/zh/reference/shared/#port-mapping) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `http_client` | string\|object → [对象](/sail/zh/reference/shared/#http-client) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="outbounds-load-balance"></a>

## `outbounds[load-balance]`

Rust 定义：[`LoadBalanceOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/load_balance/mod.rs) · 构建条件：`feature = "outbound-load-balance"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `outbounds` | 数组，元素为 string | `[]` | sail 扩展 | Its members; none may be when its providers give others. |
| `providers` | string 或 数组，元素为 string | `[]` | sail 扩展 | The outbound providers, by tag, whose outbounds join the group's own, in this order. |
| `filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions, as Mihomo's `filter`: of the providers' outbounds, only those whose names match one are members, those of the first first. The group's own outbounds are not filtered. |
| `exclude_filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions no member's name may match, the group's own outbounds' too. |
| `exclude_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | The types no member may be of, the group's own outbounds too, in Mihomo's names for them, without case: `Shadowsocks`, `Vmess`, `Socks5`, `Direct`, ... |
| `empty_fallback` | string | 未设置 | sail 扩展 | An outbound, not a group, that is the member while there is none else. Without it such a group has none, and its connections fail. |
| `strategy` | string, 取值 `consistent-hashing`, `round-robin`, `sticky-sessions` | `consistent-hashing` | sail 扩展 | — |
| `hash_key` | string, 取值 `user` | 未设置 | sail 扩展 | `user`: a connection's user is its key, not its destination (and source); a sail extension. Unset, or a connection of no user, as without it. round-robin keys on nothing, and refuses it. |
| `url` | string | `default_url()` | sail 扩展 | What is requested through each member to test it. |
| `interval` | duration | 未设置 | sail 扩展 | — |
| `expected_status` | string | 未设置 | sail 扩展 | The HTTP statuses a test must be answered with to pass, as urltest's; any when unset. |
| `unified_delay` | bool | `false` | sail 扩展 | The latency of a second request on the connection the first opened, without the connect and handshakes, as Mihomo's `unified-delay`; a sail extension. |
| `timeout` | duration | 未设置 | sail 扩展 | How long a test may take before its member counts as failed; 5s. Also how close together `max_failed_times` failures must come, as urltest's. |
| `max_failed_times` | number | 未设置 | sail 扩展 | How many failed connections, within `timeout` of the first, have the members tested again; 5, as urltest's. |
| `lazy` | bool | `true` | sail 扩展 | Tests only while the group is in use: not when it was not used since the last ones. |
| `disable_udp` | — | — | sail 扩展 | The group carries TCP alone, whatever member it picks (Mihomo's disable-udp) |

<a id="outbounds-mptp"></a>

## `outbounds[mptp]`

Rust 定义：[`MptpOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/mptp/outbound/mod.rs) · 构建条件：`feature = "outbound-mptp"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `outbounds` | 数组，元素为 string | 必填 | sail 扩展 | — |
| `server` | string | 必填 | sail 扩展 | — |
| `server_port` | number | 必填 | sail 扩展 | — |

<a id="outbounds-network"></a>

## `outbounds[network]`

Rust 定义：[`NetworkGroupOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/network/mod.rs) · 构建条件：`feature = "outbound-network-group"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `branches` | 数组，元素为 对象 → [[]](#outbounds-network-branches) | 必填 | sail 扩展 | Tried in order: the first whose conditions the network matches takes the connection. |
| `default` | string | 必填 | sail 扩展 | Where connections go when no branch matches. |

<a id="outbounds-network-branches"></a>

### `outbounds[network].branches[]`

Rust 定义：[`Branch`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/network/mod.rs) · 构建条件：`feature = "outbound-network-group"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `outbound` | string | 必填 | sail 扩展 | — |
| `wifi_ssid` | string 或 数组，元素为 string | `[]` | sail 扩展 | — |
| `wifi_bssid` | string 或 数组，元素为 string | `[]` | sail 扩展 | — |
| `network_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | `wifi`, `cellular`, `ethernet`, `other`. |
| `network_is_expensive` | bool | `false` | sail 扩展 | — |
| `network_is_constrained` | bool | `false` | sail 扩展 | — |
| `wifi_ssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | — |
| `wifi_bssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | Matched whatever the case. |
| `network_gateway` | string 或 数组，元素为 string | `[]` | sail 扩展 | — |
| `network_mcc_mnc` | string 或 数组，元素为 string | `[]` | sail 扩展 | Only off Wi-Fi. |

<a id="outbounds-pass"></a>

## `outbounds[pass]`

Rust 定义：[`PassOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/pass/mod.rs) · 构建条件：`feature = "outbound-pass"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |

<a id="outbounds-plugin"></a>

## `outbounds[plugin]`

Rust 定义：[`PluginOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/outbound/plugin.rs) · 构建条件：`feature = "outbound-select"` 且 `feature = "plugin"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `path` | string | 必填 | sail 扩展 | The shared library to load. |
| `args` | string | `""` | sail 扩展 | — |

<a id="outbounds-redirect"></a>

## `outbounds[redirect]`

Rust 定义：[`RedirectOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/redirect/outbound/mod.rs) · 构建条件：`feature = "outbound-redirect"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `detour` | string | 未设置 | sail 扩展 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | sail 扩展 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | sail 扩展 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | sail 扩展 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | sail 扩展 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | sail 扩展 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number | 未设置 | sail 扩展 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | sail 扩展 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | 任意 JSON | 未设置 | sail 扩展 | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | sail 扩展 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | sail 扩展 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | 任意 JSON | 未设置 | sail 扩展 | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | sail 扩展 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | sail 扩展 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | sail 扩展 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | sail 扩展 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | 对象 → [对象](#outbounds-redirect-domain-resolver) | 未设置 | sail 扩展 | The DNS server that resolves the names dialled. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |
| `domain_strategy` | string, 取值 `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | sail 扩展 | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `network_strategy` | string, 取值 `default`, `hybrid`, `fallback` | 未设置 | sail 扩展 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | string, 取值 `wifi`, `cellular`, `ethernet`, `other` 或 数组，元素为 string, 取值 `wifi`, `cellular`, `ethernet`, `other` | `[]` | sail 扩展 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | string, 取值 `wifi`, `cellular`, `ethernet`, `other` 或 数组，元素为 string, 取值 `wifi`, `cellular`, `ethernet`, `other` | `[]` | sail 扩展 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | sail 扩展 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `detour` | string | 未设置 | sail 扩展 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | sail 扩展 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | sail 扩展 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | sail 扩展 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | sail 扩展 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | sail 扩展 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number | 未设置 | sail 扩展 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | sail 扩展 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | 任意 JSON | 未设置 | sail 扩展 | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | sail 扩展 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | sail 扩展 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | 任意 JSON | 未设置 | sail 扩展 | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | sail 扩展 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | sail 扩展 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | sail 扩展 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | sail 扩展 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | 对象 → [对象](#outbounds-redirect-domain-resolver) | 未设置 | sail 扩展 | The DNS server that resolves the names dialled. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |
| `domain_strategy` | string, 取值 `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | sail 扩展 | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `network_strategy` | string, 取值 `default`, `hybrid`, `fallback` | 未设置 | sail 扩展 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | string, 取值 `wifi`, `cellular`, `ethernet`, `other` 或 数组，元素为 string, 取值 `wifi`, `cellular`, `ethernet`, `other` | `[]` | sail 扩展 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | string, 取值 `wifi`, `cellular`, `ethernet`, `other` 或 数组，元素为 string, 取值 `wifi`, `cellular`, `ethernet`, `other` | `[]` | sail 扩展 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | sail 扩展 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 必填 | sail 扩展 | — |
| `server_port` | number | 必填 | sail 扩展 | — |

<a id="outbounds-redirect-domain-resolver"></a>

### `outbounds[redirect].domain_resolver`

Rust 定义：[`DomainResolver`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | sail 扩展 | — |
| `strategy` | string, 取值 `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | sail 扩展 | — |
| `timeout` | duration | 未设置 | sail 扩展 | — |
| `disable_cache` | bool | `false` | sail 扩展 | — |
| `disable_optimistic_cache` | bool | `false` | sail 扩展 | — |
| `rewrite_ttl` | number | 未设置 | sail 扩展 | — |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | — |

<a id="outbounds-selector"></a>

## `outbounds[selector]`

Rust 定义：[`SelectorOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/selector/mod.rs) · 构建条件：`feature = "outbound-select"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `outbounds` | array | `[]` | 支持 | Its members; none may be when its providers give others. |
| `default` | string | 未设置 | 支持 | Selected when nothing was selected before, or what was is no longer a member; defaults to the first. It may be a member a provider gives, the first so named. |
| `interrupt_exist_connections` | bool | `false` | 支持 | Ends the connections through the member selected before once another is selected, rather than leaving them on it. |
| `providers` | string 或 数组，元素为 string | `[]` | sail 扩展 | The outbound providers, by tag, whose outbounds join the group's own, in this order. |
| `filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions, as Mihomo's `filter`: of the providers' outbounds, only those whose names match one are members, those of the first first. The group's own outbounds are not filtered. |
| `exclude_filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions no member's name may match, the group's own outbounds' too. |
| `exclude_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | The types no member may be of, the group's own outbounds too, in Mihomo's names for them, without case: `Shadowsocks`, `Vmess`, `Socks5`, `Direct`, ... |
| `empty_fallback` | string | 未设置 | sail 扩展 | An outbound, not a group, that is the member while there is none else. Without it such a group has none, and its connections fail. |
| `disable_udp` | — | — | sail 扩展 | The group carries TCP alone, whatever member it picks (Mihomo's disable-udp) |

<a id="outbounds-shadowsocks"></a>

## `outbounds[shadowsocks]`

Rust 定义：[`ShadowsocksOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowsocks/outbound/mod.rs) · 构建条件：`feature = "outbound-shadowsocks"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `method` | string, 取值 `none`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20` | 必填 | 支持 | — |
| `password` | string | 必填 | 支持 | With a 2022 method, the base64 PSK, or `iPSK:uPSK` for a server with users. |
| `plugin` | string | 未设置 | 支持 | Only `obfs-local` (simple-obfs) is supported. |
| `plugin_opts` | string | 未设置 | 支持 | `obfs=http\|tls;obfs-host=<host>;obfs-uri=<path>`, as simple-obfs takes them. |
| `network` | listable-string, 取值 `tcp`, `udp` | — | 支持 | — |
| `udp_over_tcp` | bool\|object → [对象](/sail/zh/reference/shared/#udp-over-tcp) | 未设置 | 支持 | UDP over its TCP, to `sp.v2.udp-over-tcp.arpa` (version 2, the default) or `sp.udp-over-tcp.arpa` (version 1), instead of its own UDP. |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-outbounds) | 未设置 | 支持 | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |
| `prefix` | string | 未设置 | sail 扩展 | Bytes sent before the first payload, percent-encoded. |

<a id="outbounds-shadowtls"></a>

## `outbounds[shadowtls]`

Rust 定义：[`ShadowTlsOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowtls/outbound.rs) · 构建条件：`feature = "outbound-shadowtls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 必填 | 支持 | — |
| `server_port` | number | 必填 | 支持 | — |
| `version` | number, 取值 `1`, `2`, `3` | `1` | 支持 | Must be 3: versions 1 and 2 are not supported. sing-box's default is 1. |
| `password` | string | `""` | 支持 | Cannot be empty. |
| `tls` | object → [对象](#outbounds-shadowtls-tls) | 未设置 | 支持 | Must be enabled: the handshake with the site the server imitates, `server_name` being the site's (the server's address when unset). A browser fingerprint, disable_sni and a client certificate apply as for TLS; REALITY and ECH do not. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-shadowtls-tls"></a>

### `outbounds[shadowtls].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack: sail has one | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | 未设置 | 支持 | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The lowest TLS version to negotiate, `1.0` to `1.3`; unset, 1.2. |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The highest; unset, 1.3. |
| `cipher_suites` | listable-string | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate to trust. |
| `certificate_path` | string | 未设置 | 支持 | A PEM certificate to trust, by path. |
| `certificate_public_key_sha256` | listable-string\|array | 未设置 | 支持 | The SHA-256 hashes, base64, of the public keys to take a server's certificate by, in place of the certificates trusted, the name and `insecure`. |
| `client_certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate, its chain after it, presented when the server asks for one; with `client_key`. |
| `client_certificate_path` | string | 未设置 | 支持 | `client_certificate`, by path. |
| `client_key` | listable-string | 未设置 | 支持 | The inline PEM key of the client certificate. |
| `client_key_path` | string | 未设置 | 支持 | `client_key`, by path. |
| `fragment` | bool | — | 报错：Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do here | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-outbounds) | 未设置 | 支持 | — |
| `utls` | object → [对象](/sail/zh/reference/shared/#utls-dns-servers-outbounds) | 未设置 | 支持 | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-outbounds) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="outbounds-smart"></a>

## `outbounds[smart]`

Rust 定义：[`SmartOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/smart/mod.rs) · 构建条件：`feature = "outbound-smart"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `outbounds` | 数组，元素为 string | `[]` | sail 扩展 | Its members; none may be when its providers give others. |
| `providers` | string 或 数组，元素为 string | `[]` | sail 扩展 | The outbound providers, by tag, whose outbounds join the group's own, in this order. |
| `filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions, as Mihomo's `filter`: of the providers' outbounds, only those whose names match one are members, those of the first first. The group's own outbounds are not filtered. |
| `exclude_filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions no member's name may match, the group's own outbounds' too. |
| `exclude_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | The types no member may be of, the group's own outbounds too, in Mihomo's names for them, without case: `Shadowsocks`, `Vmess`, `Socks5`, `Direct`, ... |
| `empty_fallback` | string | 未设置 | sail 扩展 | An outbound, not a group, that is the member while there is none else. Without it such a group has none, and its connections fail. |
| `url` | string | `default_url()` | sail 扩展 | What is requested through each member to probe it. |
| `interval` | duration | 未设置 | sail 扩展 | How often members nothing told of lately are probed; 5 minutes. |
| `timeout` | duration | 未设置 | sail 扩展 | How long a probe, or a connection attempt that has a member left to try, may take before its member counts as failed; 5 seconds. |
| `idle_timeout` | duration | 未设置 | sail 扩展 | Probes pause once the group has not been used for this long; 30 minutes. |
| `unified_delay` | bool | `false` | sail 扩展 | The latency of a second request on the connection the first opened, without the connect and handshakes, as Mihomo's `unified-delay`; a sail extension. |
| `tolerance` | number | `30` | sail 扩展 | Milliseconds: a member whose score is within this of the best may be picked. |
| `tolerance_ratio` | number | `0.2` | sail 扩展 | A member whose score is within this fraction of the best may be picked too, whichever of the two is the wider. |
| `policy_priority` | 数组，元素为 对象 → [[]](#outbounds-smart-policy-priority) | `[]` | sail 扩展 | Factors of the scores of the members whose names match a regular expression, the first that matches: below 1 prefers them, above 1 avoids them. 1 for the others. |
| `site_ttl` | duration | 未设置 | sail 扩展 | How long a site is kept on its member after its last connection; an hour. |
| `site_capacity` | number | `4096` | sail 扩展 | How many sites are kept at most; the least recently used goes first. |
| `prefer_asn` | bool | `false` | sail 扩展 | Destinations known by address alone are sites by their autonomous system, but those of CDNs, rather than by their network. Needs an ASN database: `asn.mmdb` in the asset directory, or `asn_file`. |
| `asn_file` | string | 未设置 | sail 扩展 | The ASN database, for `prefer_asn`; relative to the asset directory. |
| `evaluate_before_use` | bool | `false` | sail 扩展 | The first connection waits for the first probes, `timeout` at most, rather than going through a member not measured yet. |
| `interrupt_exist_connections` | bool | `false` | sail 扩展 | Ends the connections through a member once it leaves the group. |
| `disable_udp` | — | — | sail 扩展 | The group carries TCP alone, whatever member it picks (Mihomo's disable-udp) |

<a id="outbounds-smart-policy-priority"></a>

### `outbounds[smart].policy_priority[]`

Rust 定义：[`PolicyPriority`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/smart/mod.rs) · 构建条件：`feature = "outbound-smart"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `regex` | string | 必填 | sail 扩展 | Matched against the member's name, as Mihomo's filters are: lookarounds included, backtracking bounded. |
| `factor` | number | 必填 | sail 扩展 | Multiplies the member's score: above 0. |

<a id="outbounds-socks"></a>

## `outbounds[socks]`

Rust 定义：[`SocksOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/socks/outbound/mod.rs) · 构建条件：`feature = "outbound-socks"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `version` | string, 取值 `4`, `4a`, `5` | 未设置 | 支持 | `5`, the default, which is all sail speaks. sing-box also takes `4` and `4a` (option/simple.go:25), which are errors here. |
| `username` | string | `""` | 支持 | — |
| `password` | string | `""` | 支持 | — |
| `network` | listable-string, 取值 `tcp`, `udp` | — | 支持 | — |
| `udp_over_tcp` | bool\|object → [对象](/sail/zh/reference/shared/#udp-over-tcp) | 未设置 | 支持 | UDP over its TCP, to `sp.v2.udp-over-tcp.arpa` (version 2, the default) or `sp.udp-over-tcp.arpa` (version 1), instead of UDP ASSOCIATE. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-trojan"></a>

## `outbounds[trojan]`

Rust 定义：[`TrojanOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/trojan/outbound/mod.rs) · 构建条件：`feature = "outbound-trojan"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `password` | string | 必填 | 支持 | — |
| `network` | listable-string, 取值 `tcp`, `udp` | — | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-outbounds) | 未设置 | 支持 | — |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-outbounds) | 未设置 | 支持 | — |
| `transport` | object → [对象](/sail/zh/reference/shared/#transport-outbounds), [[grpc]](/sail/zh/reference/shared/#transport-grpc-outbounds), [[http]](/sail/zh/reference/shared/#transport-http-outbounds), [[httpupgrade]](/sail/zh/reference/shared/#transport-httpupgrade-outbounds), [[ws]](/sail/zh/reference/shared/#transport-ws-outbounds) | 未设置 | 支持 | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-tryall"></a>

## `outbounds[tryall]`

Rust 定义：[`TryAllOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/tryall/mod.rs) · 构建条件：`feature = "outbound-tryall"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `outbounds` | 数组，元素为 string | 必填 | sail 扩展 | A group trying its members at once |
| `delay_base` | number | `0` | sail 扩展 | Milliseconds to wait before trying each next outbound. |

<a id="outbounds-tuic"></a>

## `outbounds[tuic]`

Rust 定义：[`TuicOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/tuic/outbound/mod.rs) · 构建条件：`feature = "outbound-tuic"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 必填 | 支持 | — |
| `server_port` | number | 必填 | 支持 | — |
| `uuid` | string | 必填 | 支持 | — |
| `password` | string | `""` | 支持 | — |
| `congestion_control` | string, 取值 `cubic`, `new_reno`, `bbr` | `cubic` | 支持 | — |
| `udp_relay_mode` | string, 取值 `native`, `quic` | 未设置 | 支持 | — |
| `udp_over_stream` | bool | `false` | 支持 | UDP over TCP (v2), as sing-box has it: each UDP session a `Connect` stream to `sp.v2.udp-over-tcp.arpa`, instead of TUIC's own relay. |
| `zero_rtt_handshake` | bool | `false` | 支持 | — |
| `heartbeat` | duration | 未设置 | 支持 | — |
| `network` | listable-string, 取值 `tcp`, `udp` | 未设置 | 支持 | `tcp` or `udp`; both when not set. |
| `tls` | object → [对象](#outbounds-tuic-tls) | 必填 | 支持 | — |
| `idle_timeout` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `keep_alive_period` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `stream_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `connection_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `max_concurrent_streams` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `initial_packet_size` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `disable_path_mtu_discovery` | bool | — | 警告：QUIC tuning: the same connection without it | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |

<a id="outbounds-tuic-tls"></a>

### `outbounds[tuic].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack: sail has one | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | 未设置 | 支持 | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The lowest TLS version to negotiate, `1.0` to `1.3`; unset, 1.2. |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The highest; unset, 1.3. |
| `cipher_suites` | listable-string | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate to trust. |
| `certificate_path` | string | 未设置 | 支持 | A PEM certificate to trust, by path. |
| `certificate_public_key_sha256` | listable-string\|array | 未设置 | 支持 | The SHA-256 hashes, base64, of the public keys to take a server's certificate by, in place of the certificates trusted, the name and `insecure`. |
| `client_certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate, its chain after it, presented when the server asks for one; with `client_key`. |
| `client_certificate_path` | string | 未设置 | 支持 | `client_certificate`, by path. |
| `client_key` | listable-string | 未设置 | 支持 | The inline PEM key of the client certificate. |
| `client_key_path` | string | 未设置 | 支持 | `client_key`, by path. |
| `fragment` | bool | — | 报错：Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do here | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-outbounds) | 未设置 | 支持 | — |
| `utls` | object → [对象](#outbounds-tuic-tls-utls) | — | 报错：Not supported with TUIC | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-outbounds) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="outbounds-tuic-tls-utls"></a>

### `outbounds[tuic].tls.utls`

Rust 定义：[`OutboundUtls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `true` | 支持 | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | — | 报错：Not supported with TUIC | — |

<a id="outbounds-urltest"></a>

## `outbounds[urltest]`

Rust 定义：[`UrlTestOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/group/urltest/mod.rs) · 构建条件：`feature = "outbound-urltest"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `outbounds` | array | `[]` | 支持 | Its members; none may be when its providers give others. |
| `url` | string | `default_url()` | 支持 | What is requested through each member; sing-box's default. |
| `interval` | duration | 未设置 | 支持 | — |
| `tolerance` | number | `50` | 支持 | Milliseconds. |
| `idle_timeout` | duration | 未设置 | 支持 | Tests pause once the group has not been used for this long; 30m, sing-box's. A Clash `url-test` group, lazy, has it equal to its `interval`, as Mihomo's. |
| `interrupt_exist_connections` | bool | `false` | 支持 | Ends the connections through the member left once the group switches. |
| `providers` | string 或 数组，元素为 string | `[]` | sail 扩展 | The outbound providers, by tag, whose outbounds join the group's own, in this order. |
| `filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions, as Mihomo's `filter`: of the providers' outbounds, only those whose names match one are members, those of the first first. The group's own outbounds are not filtered. |
| `exclude_filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | Regular expressions no member's name may match, the group's own outbounds' too. |
| `exclude_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | The types no member may be of, the group's own outbounds too, in Mihomo's names for them, without case: `Shadowsocks`, `Vmess`, `Socks5`, `Direct`, ... |
| `empty_fallback` | string | 未设置 | sail 扩展 | An outbound, not a group, that is the member while there is none else. Without it such a group has none, and its connections fail. |
| `timeout` | duration | 未设置 | sail 扩展 | How long a test may take before its member counts as failed; 5s. Also how close together `max_failed_times` failures must come; Mihomo's `timeout`. |
| `max_failed_times` | number | 未设置 | sail 扩展 | How many failed connections, within `timeout` of the first, have the members tested again; 5, as Mihomo's `max-failed-times`. One whose member's server cannot be reached has them tested at once. |
| `expected_status` | string | 未设置 | sail 扩展 | The HTTP statuses a test must be answered with to pass, as Mihomo's `expected-status`: codes and ranges, `200/204/401-429`; any when unset. |
| `lazy` | bool | `true` | sail 扩展 | `false`: tests never pause, used or not, as Mihomo's `lazy: false`; `idle_timeout` is then a mistake. |
| `unified_delay` | bool | `false` | sail 扩展 | The latency of a second request on the connection the first opened, without the connect and handshakes, as Mihomo's `unified-delay`; a sail extension. |
| `disable_udp` | — | — | sail 扩展 | The group carries TCP alone, whatever member it picks (Mihomo's disable-udp) |

<a id="outbounds-vless"></a>

## `outbounds[vless]`

Rust 定义：[`VlessOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/vless/outbound/mod.rs) · 构建条件：`feature = "outbound-vless"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `uuid` | string | 必填 | 支持 | — |
| `flow` | string | `""` | 支持 | `""` or `xtls-rprx-vision`. |
| `network` | listable-string, 取值 `tcp`, `udp` | — | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-outbounds) | 未设置 | 支持 | — |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-outbounds) | 未设置 | 支持 | — |
| `transport` | object → [对象](/sail/zh/reference/shared/#transport-outbounds), [[grpc]](/sail/zh/reference/shared/#transport-grpc-outbounds), [[http]](/sail/zh/reference/shared/#transport-http-outbounds), [[httpupgrade]](/sail/zh/reference/shared/#transport-httpupgrade-outbounds), [[ws]](/sail/zh/reference/shared/#transport-ws-outbounds) | 未设置 | 支持 | — |
| `packet_encoding` | string | 未设置 | 支持 | How UDP travels: unset means `xudp`, as in sing-box; `""` is VLESS's own UDP, one destination per connection. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-vmess"></a>

## `outbounds[vmess]`

Rust 定义：[`VMessOutboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/vmess/outbound/mod.rs) · 构建条件：`feature = "outbound-vmess"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | May be left out, with `server_port`, by an outbound with a `detour`: one over ShadowTLS, which dials its own server. |
| `server_port` | number | 未设置 | 支持 | — |
| `uuid` | string | 必填 | 支持 | — |
| `security` | string, 取值 `auto`, `none`, `zero`, `aes-128-cfb`, `aes-128-gcm`, `chacha20-poly1305` | `"auto"` | 支持 | `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` or `zero`. |
| `alter_id` | number | `0` | 支持 | Only 0: legacy VMess is not spoken. |
| `global_padding` | bool | `false` | 支持 | Random padding after each chunk, as v2ray pads. |
| `authenticated_length` | bool | — | 报错：VMess's authenticated length: sail would speak VMess otherwise | — |
| `network` | listable-string, 取值 `tcp`, `udp` | — | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-outbounds) | 未设置 | 支持 | — |
| `packet_encoding` | string, 取值 `packetaddr`, `xudp` | `""` | 支持 | `""` (VMess's own UDP) or `xudp`. |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-outbounds) | 未设置 | 支持 | — |
| `transport` | object → [对象](/sail/zh/reference/shared/#transport-outbounds), [[grpc]](/sail/zh/reference/shared/#transport-grpc-outbounds), [[http]](/sail/zh/reference/shared/#transport-http-outbounds), [[httpupgrade]](/sail/zh/reference/shared/#transport-httpupgrade-outbounds), [[ws]](/sail/zh/reference/shared/#transport-ws-outbounds) | 未设置 | 支持 | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |
| `tcp_concurrent` | bool | `false` | sail 扩展 | A sail extension, Mihomo's `tcp-concurrent`: a name's addresses are all connected to at once and the first to connect is taken, rather than one family's one by one, the other's raced against them after `fallback_delay` (Happy Eyeballs). With `network_strategy`, each address is still raced over the interfaces, so as many sockets open at once as there are addresses times interfaces. |

<a id="outbounds-missing"></a>

## sail 未实现的类型：`outbounds`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `outbounds[bridge]` | 报错：A protocol sail does not implement | 5 |
| `outbounds[hysteria]` | 报错：A protocol sail does not implement | 90 |
| `outbounds[naive]` | 报错：A protocol sail does not implement | 81 |
| `outbounds[snell]` | 报错：A protocol sail does not implement | 40 |
| `outbounds[ssh]` | 报错：A protocol sail does not implement | 43 |
| `outbounds[tor]` | 报错：A protocol sail does not implement | 34 |

