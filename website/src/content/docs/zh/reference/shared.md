---
title: "共用对象"
description: "多处取用的配置对象，统一列出。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

多处字段取用、字段、类型与分级均相同的对象，在此统一列出，并注明所在位置。

<a id="brutal"></a>

## `brutal`

所在位置：`inbounds[shadowsocks, trojan, vless, vmess].multiplex.brutal`, `outbounds[shadowsocks, trojan, vless, vmess].multiplex.brutal`

Rust 定义：[`MultiplexBrutal`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `up_mbps` | number | `0` | 支持 | — |
| `down_mbps` | number | `0` | 支持 | — |

<a id="client-subnet"></a>

## `client_subnet`

所在位置：`dns.servers[h3, https, quic, tcp, tls, udp].client_subnet`, `outbounds[redirect, sail].domain_resolver.client_subnet`

Rust 定义：[`Prefix`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `addr` | string | 必填 | sail 扩展 | — |
| `len` | number | 必填 | sail 扩展 | — |

<a id="domain-resolver-inbounds"></a>

## `domain_resolver` — inbounds

所在位置：`inbounds[http, mixed, socks].domain_resolver`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `timeout` | duration | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `disable_cache` | bool | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `disable_optimistic_cache` | bool | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `rewrite_ttl` | number | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `client_subnet` | string | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |

<a id="domain-resolver-inbounds-route-rule-set"></a>

## `domain_resolver` — inbounds, route.rule_set

所在位置：`inbounds[anytls].tls.reality.handshake.domain_resolver`, `route.rule_set[remote].http_client.domain_resolver`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 支持 | — |
| `timeout` | duration | — | 支持 | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 支持 | — |
| `disable_cache` | bool | — | 支持 | — |
| `disable_optimistic_cache` | bool | — | 支持 | — |
| `rewrite_ttl` | number | — | 支持 | — |
| `client_subnet` | string | — | 支持 | — |

<a id="domain-resolver-outbounds"></a>

## `domain_resolver` — outbounds

所在位置：`outbounds[redirect, sail].domain_resolver`

Rust 定义：[`DomainResolver`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | sail 扩展 | — |
| `strategy` | string, 取值 `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | sail 扩展 | — |
| `timeout` | duration | 未设置 | sail 扩展 | — |
| `disable_cache` | bool | `false` | sail 扩展 | — |
| `disable_optimistic_cache` | bool | `false` | sail 扩展 | — |
| `rewrite_ttl` | number | 未设置 | sail 扩展 | — |
| `client_subnet` | 对象 → [对象](#client-subnet) | 未设置 | sail 扩展 | — |

<a id="domain-resolver-default-domain-resolver"></a>

## `domain_resolver / default_domain_resolver`

所在位置：`http_clients[].domain_resolver`, `ntp.domain_resolver`, `dns.servers[h3, https, quic, tcp, tls, udp].domain_resolver`, `inbounds[http, hysteria2, trojan, tuic, vless, vmess].tls.reality.handshake.domain_resolver`, `inbounds[shadowtls].handshake.domain_resolver`, `outbounds[anytls, direct, http, hysteria2, shadowsocks, shadowtls, socks, trojan, tuic, vless, vmess].domain_resolver`, `endpoints[wireguard].domain_resolver`, `route.default_domain_resolver`

Rust 定义：[`DomainResolver`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 支持 | — |
| `timeout` | duration | 未设置 | 支持 | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | 支持 | — |
| `disable_cache` | bool | `false` | 支持 | — |
| `disable_optimistic_cache` | bool | `false` | 支持 | — |
| `rewrite_ttl` | number | 未设置 | 支持 | — |
| `client_subnet` | string | 未设置 | 支持 | — |

<a id="domain-resolver-stun-domain-resolver"></a>

## `domain_resolver / stun_domain_resolver`

所在位置：`inbounds[hysteria2].realm.http_client.domain_resolver`, `inbounds[hysteria2].realm.stun_domain_resolver`, `outbounds[hysteria2].realm.http_client.domain_resolver`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `timeout` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `disable_cache` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `disable_optimistic_cache` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `rewrite_ttl` | number | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `client_subnet` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="ech-dns-servers"></a>

## `ech` — dns.servers

所在位置：`dns.servers[h3, https, quic, tls].tls.ech`

Rust 定义：[`OutboundEch`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Not for a dns server | — |
| `config` | listable-string | — | 报错：Not for a dns server | An ECHConfigList, base64 or PEM. Looked up in DNS when not set. |
| `config_path` | string | — | 报错：An ECH configuration from a file, or looked up under another name: the server name would go in the clear | — |
| `query_server_name` | string | — | 报错：An ECH configuration from a file, or looked up under another name: the server name would go in the clear | — |

<a id="ech-http-clients-route-rule-set"></a>

## `ech` — http_clients, route.rule_set

所在位置：`http_clients[].tls.ech`, `route.rule_set[remote].http_client.tls.ech`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `config` | listable-string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `config_path` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `query_server_name` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |

<a id="ech-inbounds"></a>

## `ech` — inbounds

所在位置：`inbounds[anytls, http, hysteria2, trojan, tuic, vless, vmess].tls.ech`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Encrypted Client Hello on an inbound | — |
| `key` | listable-string | — | 报错：Encrypted Client Hello on an inbound | — |
| `key_path` | string | — | 报错：Encrypted Client Hello on an inbound | — |

<a id="ech-inbounds-outbounds"></a>

## `ech` — inbounds, outbounds

所在位置：`inbounds[hysteria2].realm.http_client.tls.ech`, `outbounds[hysteria2].realm.http_client.tls.ech`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `config` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `config_path` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `query_server_name` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="ech-outbounds"></a>

## `ech` — outbounds

所在位置：`outbounds[anytls, http, hysteria2, shadowtls, trojan, tuic, vless, vmess].tls.ech`

Rust 定义：[`OutboundEch`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `config` | listable-string | 未设置 | 支持 | An ECHConfigList, base64 or PEM. Looked up in DNS when not set. |
| `config_path` | string | — | 报错：An ECH configuration from a file, or looked up under another name: the server name would go in the clear | — |
| `query_server_name` | string | — | 报错：An ECH configuration from a file, or looked up under another name: the server name would go in the clear | — |
| `disable_dns_lookup` | bool | `false` | sail 扩展 | Never look the ECHConfigList up in DNS: `config` is then required. |

<a id="fallback-fallback-for-alpn"></a>

## `fallback / fallback_for_alpn`

所在位置：`inbounds[anytls, sail, vless].fallback`, `inbounds[anytls, sail, vless].fallback_for_alpn`

Rust 定义：[`FallbackServer`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/fallback.rs) · 构建条件：`any (feature = "inbound-anytls" , feature = "inbound-trojan" , feature = "inbound-vless" , feature = "inbound-shadowtls")` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | sail 扩展 | — |
| `server_port` | number | 必填 | sail 扩展 | — |

<a id="handshake-inbounds"></a>

## `handshake` — inbounds

所在位置：`inbounds[http, trojan, vless, vmess].tls.reality.handshake`

Rust 定义：[`RealityHandshake`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 支持 | — |
| `server_port` | number | 必填 | 支持 | — |
| `detour` | string | — | 报错：A detour to the REALITY handshake server: it would be reached otherwise | The outbound to dial through, in place of a socket of its own. |
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
| `domain_resolver` | string\|object → [对象](#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |

<a id="handshake-inbounds-2"></a>

## `handshake` — inbounds (2)

所在位置：`inbounds[hysteria2, tuic].tls.reality.handshake`

Rust 定义：[`RealityHandshake`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 支持 | — |
| `server_port` | number | 必填 | 支持 | — |
| `detour` | string | — | 报错：A detour to the REALITY handshake server: it would be reached otherwise | The outbound to dial through, in place of a socket of its own. |
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
| `domain_resolver` | string\|object → [对象](#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |

<a id="http-client"></a>

## `http_client`

所在位置：`inbounds[hysteria2].realm.http_client`, `outbounds[hysteria2].realm.http_client`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `engine` | string, 取值 `go`, `apple` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `version` | number, 取值 `0`, `1`, `2`, `3` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `disable_version_fallback` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `headers` | map | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `tls` | object → [对象](#tls-inbounds-outbounds) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `detour` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `bind_interface` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `inet4_bind_address` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `inet6_bind_address` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `bind_address_no_port` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `protect_path` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `routing_mark` | number\|string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `reuse_addr` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `netns` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `connect_timeout` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `tcp_fast_open` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `tcp_multi_path` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `disable_tcp_keep_alive` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `tcp_keep_alive` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `tcp_keep_alive_interval` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `udp_fragment` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `domain_resolver` | string\|object → [对象](#domain-resolver-stun-domain-resolver) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `fallback_delay` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `idle_timeout` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `keep_alive_period` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `stream_receive_window` | number\|string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `connection_receive_window` | number\|string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `max_concurrent_streams` | number | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `initial_packet_size` | number | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `disable_path_mtu_discovery` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `domain_strategy` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise (sing-box 已弃用) | — |

<a id="multiplex-inbounds"></a>

## `multiplex` — inbounds

所在位置：`inbounds[shadowsocks, trojan, vless, vmess].multiplex`

Rust 定义：[`InboundMultiplex`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `padding` | bool | `false` | 支持 | sing-mux: refuse connections that are not padded. |
| `brutal` | object → [对象](#brutal) | 未设置 | 支持 | sing-mux: TCP Brutal for clients that ask for it; Linux only. |
| `protocol` | string | 未设置 | sail 扩展 | `amux`; unset, sing-mux, which sing-box's block has no field for: its server takes smux, yamux and h2mux alike. |

<a id="multiplex-outbounds"></a>

## `multiplex` — outbounds

所在位置：`outbounds[shadowsocks, trojan, vless, vmess].multiplex`

Rust 定义：[`OutboundMultiplex`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `protocol` | string, 取值 `h2mux`, `smux`, `yamux` | 未设置 | 支持 | sing-box's multiplex, above the protocol: `h2mux`, the default as in sing-box, `smux` or `yamux`. Or `amux`, sail's own, below the protocol, which is to be removed. |
| `max_connections` | number | 未设置 | 支持 | — |
| `min_streams` | number | 未设置 | 支持 | — |
| `max_streams` | number | 未设置 | 支持 | — |
| `padding` | bool | `false` | 支持 | — |
| `brutal` | object → [对象](#brutal) | 未设置 | 支持 | sing-mux only: TCP Brutal, negotiated on each new connection. |
| `max_accepts` | number | 未设置 | sail 扩展 | amux only. |
| `concurrency` | number | 未设置 | sail 扩展 | With `protocol: amux`: the streams a session carries at once |
| `max_recv_bytes` | number | 未设置 | sail 扩展 | With `protocol: amux`: the bytes a session receives before it takes no more streams; 0, no limit |
| `max_lifetime` | number | 未设置 | sail 扩展 | With `protocol: amux`: the seconds a session takes new streams for; 0, no limit |

<a id="obfs"></a>

## `obfs`

所在位置：`inbounds[hysteria2].obfs`, `outbounds[hysteria2].obfs`

Rust 定义：[`Obfs`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hysteria2/mod.rs) · 构建条件：`any (feature = "inbound-hysteria2" , feature = "outbound-hysteria2")`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `salamander`, `gecko` | 必填 | 支持 | — |

<a id="obfs-gecko"></a>

## `obfs[gecko]`

所在位置：`inbounds[hysteria2].obfs[gecko]`, `outbounds[hysteria2].obfs[gecko]`

Rust 定义：[`Obfs`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hysteria2/mod.rs) · 构建条件：`any (feature = "inbound-hysteria2" , feature = "outbound-hysteria2")`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `password` | string | `""` | 支持 | — |
| `min_packet_size` | number | — | 报错：The packet sizes of the gecko obfuscation: the packets would look otherwise | — |
| `max_packet_size` | number | — | 报错：The packet sizes of the gecko obfuscation: the packets would look otherwise | — |

<a id="obfs-salamander"></a>

## `obfs[salamander]`

所在位置：`inbounds[hysteria2].obfs[salamander]`, `outbounds[hysteria2].obfs[salamander]`

Rust 定义：[`Obfs`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hysteria2/mod.rs) · 构建条件：`any (feature = "inbound-hysteria2" , feature = "outbound-hysteria2")`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `password` | string | `""` | 支持 | — |

<a id="port-mapping"></a>

## `port_mapping`

所在位置：`inbounds[hysteria2].realm.port_mapping`, `outbounds[hysteria2].realm.port_mapping`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `timeout` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `lifetime` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="reality-dns-servers"></a>

## `reality` — dns.servers

所在位置：`dns.servers[h3, https, quic, tls].tls.reality`

Rust 定义：[`OutboundReality`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `public_key` | string | — | 报错：Not for a dns server | — |
| `short_id` | string | `""` | 支持 | — |

<a id="reality-http-clients-route-rule-set"></a>

## `reality` — http_clients, route.rule_set

所在位置：`http_clients[].tls.reality`, `route.rule_set[remote].http_client.tls.reality`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `public_key` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `short_id` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |

<a id="reality-inbounds"></a>

## `reality` — inbounds

所在位置：`inbounds[http, trojan, vless, vmess].tls.reality`

Rust 定义：[`InboundReality`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `handshake` | object → [对象](#handshake-inbounds) | 必填 | 支持 | — |
| `private_key` | string | 必填 | 支持 | X25519, hex or base64url. |
| `short_id` | listable-string | 必填 | 支持 | — |
| `max_time_difference` | duration | 未设置 | 支持 | How far a client's clock may be from ours, e.g. `1m`. Unset, any time is accepted, as in sing-box. |
| `server_names` | 数组，元素为 string | `[]` | sail 扩展 | A sail extension, Xray's `serverNames` and Mihomo's `server-names`: more names clients may ask for, beside `tls.server_name`. |

<a id="reality-inbounds-2"></a>

## `reality` — inbounds (2)

所在位置：`inbounds[hysteria2, tuic].tls.reality`

Rust 定义：[`InboundReality`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `handshake` | object → [对象](#handshake-inbounds-2) | 必填 | 支持 | — |
| `private_key` | string | 必填 | 支持 | X25519, hex or base64url. |
| `short_id` | listable-string | 必填 | 支持 | — |
| `max_time_difference` | duration | 未设置 | 支持 | How far a client's clock may be from ours, e.g. `1m`. Unset, any time is accepted, as in sing-box. |

<a id="reality-inbounds-outbounds"></a>

## `reality` — inbounds, outbounds

所在位置：`inbounds[hysteria2].realm.http_client.tls.reality`, `outbounds[hysteria2].realm.http_client.tls.reality`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `public_key` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `short_id` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="reality-outbounds"></a>

## `reality` — outbounds

所在位置：`outbounds[anytls, http, hysteria2, shadowtls, trojan, tuic, vless, vmess].tls.reality`

Rust 定义：[`OutboundReality`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `public_key` | string | 必填 | 支持 | — |
| `short_id` | string | `""` | 支持 | — |

<a id="tls-http-clients-route-rule-set"></a>

## `tls` — http_clients, route.rule_set

所在位置：`http_clients[].tls`, `route.rule_set[remote].http_client.tls`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `disable_sni` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `server_name` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `insecure` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `alpn` | listable-string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `cipher_suites` | listable-string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `certificate` | listable-string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `certificate_path` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `certificate_public_key_sha256` | listable-string\|array | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `client_certificate` | listable-string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `client_certificate_path` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `client_key` | listable-string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `client_key_path` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `fragment` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `fragment_fallback_delay` | duration | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `record_fragment` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `spoof` | string | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `kernel_tx` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `kernel_rx` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `handshake_timeout` | duration | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `ech` | object → [对象](#ech-http-clients-route-rule-set) | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `utls` | object → [对象](#utls-http-clients-route-rule-set) | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `reality` | object → [对象](#reality-http-clients-route-rule-set) | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |

<a id="tls-inbounds"></a>

## `tls` — inbounds

所在位置：`inbounds[http, trojan, vless, vmess].tls`

Rust 定义：[`InboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `server_name` | string | 未设置 | 支持 | The name REALITY clients must ask for, or the one a `self_signed` certificate is for; otherwise it is ignored with a warning, as sing-box ignores it. |
| `insecure` | bool | — | 警告：Only relaxes checks a server's TLS does not make | — |
| `alpn` | listable-string | 未设置 | 支持 | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The lowest TLS version to accept, `1.0` to `1.3`; unset, 1.2. |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The highest; unset, 1.3. |
| `cipher_suites` | listable-string | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate. |
| `certificate_path` | string | 未设置 | 支持 | — |
| `client_authentication` | string, 取值 `no`, `request`, `require-any`, `verify-if-given`, `require-and-verify` | 未设置 | 支持 | What is asked of clients' certificates, as sing-box takes it: `no` (none is asked for), `request` or `require-any` (one is taken unchecked; `require-any` refuses a client without), `verify-if-given` or `require-and-verify` (one is checked, by the CAs or the pins; `require-and-verify` refuses a client without). Unset is `no`, or `require-and-verify` with CAs set. Pins without a verifying mode, and CAs or pins with `request` or `require-any`, are errors, where sing-box checks no certificate. |
| `client_certificate` | listable-string | 未设置 | 支持 | The CAs clients' certificates are verified by, inline PEM: chained to one of them, by the intermediates the client sends, valid, and for client authentication. With `client_certificate_path` too, the files are ignored with a warning, as sing-box ignores them. |
| `client_certificate_path` | listable-string | 未设置 | 支持 | The CAs, from PEM (or DER) files, as `client_certificate`. The files are followed as the certificate's are: CAs written to them are taken for the connections that come next. |
| `client_certificate_public_key_sha256` | listable-string\|array | 未设置 | 支持 | Clients' certificates taken by the SHA-256 of their public key (SubjectPublicKeyInfo), standard base64, in place of CAs: the leaf alone, no CA or validity period. With `client_certificate_sha256`, either list passing is enough. Beside CAs, ignored with a warning, as sing-box ignores them. |
| `key` | listable-string | 未设置 | 支持 | An inline PEM key. |
| `key_path` | string | 未设置 | 支持 | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `certificate_provider` | string\|object | — | 报错：A certificate from a provider or ACME: the inbound would have none | — |
| `ech` | object → [对象](#ech-inbounds) | — | 报错：Encrypted Client Hello on an inbound | — |
| `reality` | object → [对象](#reality-inbounds) | 未设置 | 支持 | — |
| `acme` | object | — | 报错：A certificate from a provider or ACME: the inbound would have none (sing-box 已弃用) | — |
| `client_certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, read ahead: clients' certificates taken by the SHA-256 of the whole leaf (its DER), standard base64 or hex, looked at before `client_certificate_public_key_sha256`, as that is. |
| `self_signed` | bool | `false` | sail 扩展 | A sail extension: with no certificate or key set, a self-signed one the instance makes, for `server_name` if set, as Mihomo's Hysteria2 and TUIC listeners serve one without a certificate. It is made once and kept across reloads that rebuild the inbound in place; clients take it as `insecure` or by a pin. With a certificate or key, or REALITY, an error. |

<a id="tls-inbounds-2"></a>

## `tls` — inbounds (2)

所在位置：`inbounds[hysteria2, tuic].tls`

Rust 定义：[`InboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `server_name` | string | 未设置 | 支持 | The name REALITY clients must ask for, or the one a `self_signed` certificate is for; otherwise it is ignored with a warning, as sing-box ignores it. |
| `insecure` | bool | — | 警告：Only relaxes checks a server's TLS does not make | — |
| `alpn` | listable-string | 未设置 | 支持 | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The lowest TLS version to accept, `1.0` to `1.3`; unset, 1.2. |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | 未设置 | 支持 | The highest; unset, 1.3. |
| `cipher_suites` | listable-string | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `certificate` | listable-string | 未设置 | 支持 | An inline PEM certificate. |
| `certificate_path` | string | 未设置 | 支持 | — |
| `client_authentication` | string, 取值 `no`, `request`, `require-any`, `verify-if-given`, `require-and-verify` | 未设置 | 支持 | What is asked of clients' certificates, as sing-box takes it: `no` (none is asked for), `request` or `require-any` (one is taken unchecked; `require-any` refuses a client without), `verify-if-given` or `require-and-verify` (one is checked, by the CAs or the pins; `require-and-verify` refuses a client without). Unset is `no`, or `require-and-verify` with CAs set. Pins without a verifying mode, and CAs or pins with `request` or `require-any`, are errors, where sing-box checks no certificate. |
| `client_certificate` | listable-string | 未设置 | 支持 | The CAs clients' certificates are verified by, inline PEM: chained to one of them, by the intermediates the client sends, valid, and for client authentication. With `client_certificate_path` too, the files are ignored with a warning, as sing-box ignores them. |
| `client_certificate_path` | listable-string | 未设置 | 支持 | The CAs, from PEM (or DER) files, as `client_certificate`. The files are followed as the certificate's are: CAs written to them are taken for the connections that come next. |
| `client_certificate_public_key_sha256` | listable-string\|array | 未设置 | 支持 | Clients' certificates taken by the SHA-256 of their public key (SubjectPublicKeyInfo), standard base64, in place of CAs: the leaf alone, no CA or validity period. With `client_certificate_sha256`, either list passing is enough. Beside CAs, ignored with a warning, as sing-box ignores them. |
| `key` | listable-string | 未设置 | 支持 | An inline PEM key. |
| `key_path` | string | 未设置 | 支持 | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `certificate_provider` | string\|object | — | 报错：A certificate from a provider or ACME: the inbound would have none | — |
| `ech` | object → [对象](#ech-inbounds) | — | 报错：Encrypted Client Hello on an inbound | — |
| `reality` | object → [对象](#reality-inbounds-2) | 未设置 | 支持 | — |
| `acme` | object | — | 报错：A certificate from a provider or ACME: the inbound would have none (sing-box 已弃用) | — |
| `client_certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, read ahead: clients' certificates taken by the SHA-256 of the whole leaf (its DER), standard base64 or hex, looked at before `client_certificate_public_key_sha256`, as that is. |
| `self_signed` | bool | `false` | sail 扩展 | A sail extension: with no certificate or key set, a self-signed one the instance makes, for `server_name` if set, as Mihomo's Hysteria2 and TUIC listeners serve one without a certificate. It is made once and kept across reloads that rebuild the inbound in place; clients take it as `insecure` or by a pin. With a certificate or key, or REALITY, an error. |

<a id="tls-inbounds-outbounds"></a>

## `tls` — inbounds, outbounds

所在位置：`inbounds[hysteria2].realm.http_client.tls`, `outbounds[hysteria2].realm.http_client.tls`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `disable_sni` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `server_name` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `insecure` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `alpn` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `cipher_suites` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `certificate` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `certificate_path` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `certificate_public_key_sha256` | listable-string\|array | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `client_certificate` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `client_certificate_path` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `client_key` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `client_key_path` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `fragment` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `fragment_fallback_delay` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `record_fragment` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `spoof` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `kernel_tx` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `kernel_rx` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `handshake_timeout` | duration | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `ech` | object → [对象](#ech-inbounds-outbounds) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `utls` | object → [对象](#utls-inbounds-outbounds) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `reality` | object → [对象](#reality-inbounds-outbounds) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="tls-outbounds"></a>

## `tls` — outbounds

所在位置：`outbounds[anytls, http, trojan, vless, vmess].tls`

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
| `fragment` | bool | `false` | 支持 | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | 未设置 | 支持 | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | `false` | 支持 | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](#ech-outbounds) | 未设置 | 支持 | — |
| `utls` | object → [对象](#utls-dns-servers-outbounds) | 未设置 | 支持 | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](#reality-outbounds) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="transport-inbounds"></a>

## `transport` — inbounds

所在位置：`inbounds[trojan, vless, vmess].transport`

Rust 定义：[`InboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `http`, `ws`, `quic`, `grpc`, `httpupgrade` | 必填 | 支持 | — |

<a id="transport-outbounds"></a>

## `transport` — outbounds

所在位置：`outbounds[trojan, vless, vmess].transport`

Rust 定义：[`OutboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `http`, `ws`, `quic`, `grpc`, `httpupgrade` | 必填 | 支持 | — |

<a id="transport-grpc-inbounds"></a>

## `transport[grpc]` — inbounds

所在位置：`inbounds[trojan, vless, vmess].transport[grpc]`

Rust 定义：[`InboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `service_name` | string | `"TunService"` | 支持 | — |
| `idle_timeout` | duration | 未设置 | 支持 | Unset, no keepalive pings. A client pings this often; a server after this long with nothing received, so give a server no shorter a time than its clients' interval. |
| `ping_timeout` | duration | 未设置 | 支持 | — |
| `permit_without_stream` | bool | — | 警告：Response headers and keepalive of a WebSocket or gRPC server: the same streams | — |

<a id="transport-grpc-outbounds"></a>

## `transport[grpc]` — outbounds

所在位置：`outbounds[trojan, vless, vmess].transport[grpc]`

Rust 定义：[`OutboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `service_name` | string | `"TunService"` | 支持 | — |
| `idle_timeout` | duration | 未设置 | 支持 | Unset, no keepalive pings. A client pings this often; a server after this long with nothing received, so give a server no shorter a time than its clients' interval. |
| `ping_timeout` | duration | 未设置 | 支持 | — |
| `permit_without_stream` | bool | `false` | 支持 | Whether a connection carrying no calls is pinged too. |

<a id="transport-http-inbounds"></a>

## `transport[http]` — inbounds

所在位置：`inbounds[trojan, vless, vmess].transport[http]`

Rust 定义：[`InboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `host` | listable-string | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `path` | string | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `method` | string | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `headers` | map | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `idle_timeout` | duration | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `ping_timeout` | duration | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |

<a id="transport-http-outbounds"></a>

## `transport[http]` — outbounds

所在位置：`outbounds[trojan, vless, vmess].transport[http]`

Rust 定义：[`OutboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `host` | listable-string | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `path` | string | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `method` | string | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `headers` | map | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `idle_timeout` | duration | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |
| `ping_timeout` | duration | — | 报错：Type http (HTTP/2) is not supported, by design; grpc, ws and httpupgrade are | — |

<a id="transport-httpupgrade-inbounds"></a>

## `transport[httpupgrade]` — inbounds

所在位置：`inbounds[trojan, vless, vmess].transport[httpupgrade]`

Rust 定义：[`InboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `host` | string | 未设置 | 支持 | The `Host` a request must carry; unset, any. |
| `path` | string | `"/"` | 支持 | — |
| `headers` | map | `{}` | 支持 | Added to the response. |

<a id="transport-httpupgrade-outbounds"></a>

## `transport[httpupgrade]` — outbounds

所在位置：`outbounds[trojan, vless, vmess].transport[httpupgrade]`

Rust 定义：[`OutboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `host` | string | 未设置 | 支持 | Unset, the server's address. |
| `path` | string | `"/"` | 支持 | — |
| `headers` | map | `{}` | 支持 | — |

<a id="transport-ws-inbounds"></a>

## `transport[ws]` — inbounds

所在位置：`inbounds[trojan, vless, vmess].transport[ws]`

Rust 定义：[`InboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `path` | string | `"/"` | 支持 | — |
| `headers` | map | — | 警告：Response headers and keepalive of a WebSocket or gRPC server: the same streams | — |
| `max_early_data` | number | `0` | 支持 | The most early data a client may send in its upgrade request. |
| `early_data_header_name` | string | 未设置 | 支持 | The header it comes in; unset, it comes in the path. |
| `forwarded_header` | string | 未设置 | sail 扩展 | The header a trusted reverse proxy in front puts the client's address in, such as `X-Forwarded-For`. Unset, no header is believed: anyone can send one. |

<a id="transport-ws-outbounds"></a>

## `transport[ws]` — outbounds

所在位置：`outbounds[trojan, vless, vmess].transport[ws]`

Rust 定义：[`OutboundTransport`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `path` | string | `"/"` | 支持 | — |
| `headers` | map | `{}` | 支持 | — |
| `max_early_data` | number | `0` | 支持 | How many of the first bytes to carry in the upgrade request. |
| `early_data_header_name` | string | 未设置 | 支持 | The header they go in; unset, they go in the path. |

<a id="udp-over-tcp"></a>

## `udp_over_tcp`

所在位置：`outbounds[shadowsocks, socks].udp_over_tcp`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 支持 | — |
| `version` | number, 取值 `1`, `2` | — | 支持 | — |

<a id="utls-dns-servers-outbounds"></a>

## `utls` — dns.servers, outbounds

所在位置：`dns.servers[https, tls].tls.utls`, `outbounds[anytls, http, shadowtls, trojan, vless, vmess].tls.utls`

Rust 定义：[`OutboundUtls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `true` | 支持 | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | `"chrome"` | 支持 | — |

<a id="utls-http-clients-route-rule-set"></a>

## `utls` — http_clients, route.rule_set

所在位置：`http_clients[].tls.utls`, `route.rule_set[remote].http_client.tls.utls`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |

<a id="utls-inbounds-outbounds"></a>

## `utls` — inbounds, outbounds

所在位置：`inbounds[hysteria2].realm.http_client.tls.utls`, `outbounds[hysteria2].realm.http_client.tls.utls`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

