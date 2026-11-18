---
title: "入站"
description: "sail 原生配置格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段参考。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

<a id="inbounds"></a>

## `inbounds[]`

Rust 定义：[`Inbound`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `anytls`, `cloudflared`, `direct`, `http`, `hysteria`, `hysteria2`, `mixed`, `naive`, `redirect`, `shadowsocks`, `shadowtls`, `snell`, `socks`, `tproxy`, `trojan`, `tuic`, `tun`, `vless`, `vmess` | 必填 | 支持 | — |

<a id="inbounds-anytls"></a>

## `inbounds[anytls]`

Rust 定义：[`AnyTlsInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/anytls/inbound/mod.rs) · 构建条件：`feature = "inbound-anytls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `tls` | object → [对象](#inbounds-anytls-tls) | — | 支持 | — |
| `users` | array → [[]](#inbounds-anytls-users) | 必填 | 支持 | — |
| `padding_scheme` | listable-string | 未设置 | 支持 | The padding scheme, as lines. Unset, the default. A scheme that pads past write 1024, gives a write more than 64 sizes or asks for more than 1 MiB of padding in all is refused. |
| `fallback` | 对象 → [对象](/sail/zh/reference/shared/#fallback-fallback-for-alpn) | 未设置 | sail 扩展 | Where a connection that fails to authenticate is relayed. |
| `fallback_for_alpn` | 对象，值为 对象 → [对象](/sail/zh/reference/shared/#fallback-fallback-for-alpn) | `{}` | sail 扩展 | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`. |

<a id="inbounds-anytls-tls"></a>

### `inbounds[anytls].tls`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 支持 | — |
| `server_name` | string | — | 支持 | — |
| `insecure` | bool | — | 警告：Only relaxes checks a server's TLS does not make | — |
| `alpn` | listable-string | — | 支持 | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 支持 | — |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 支持 | — |
| `cipher_suites` | listable-string | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked | — |
| `certificate` | listable-string | — | 支持 | — |
| `certificate_path` | string | — | 支持 | — |
| `client_authentication` | string, 取值 `no`, `request`, `require-any`, `verify-if-given`, `require-and-verify` | — | 支持 | — |
| `client_certificate` | listable-string | — | 支持 | — |
| `client_certificate_path` | listable-string | — | 支持 | — |
| `client_certificate_public_key_sha256` | listable-string\|array | — | 支持 | — |
| `key` | listable-string | — | 支持 | — |
| `key_path` | string | — | 支持 | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `certificate_provider` | string\|object | — | 报错：A certificate from a provider or ACME: the inbound would have none | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-inbounds) | — | 报错：Encrypted Client Hello on an inbound | — |
| `reality` | object → [对象](#inbounds-anytls-tls-reality) | — | 支持 | — |
| `acme` | object | — | 报错：A certificate from a provider or ACME: the inbound would have none (sing-box 已弃用) | — |
| `client_certificate_sha256` | — | — | sail 扩展 | sing-box 1.15's, read ahead: clients' certificates taken by the SHA-256 of the whole leaf (its DER), standard base64 or hex, with a verifying `client_authentication`; looked at before `client_certificate_public_key_sha256`, either list passing |
| `self_signed` | — | — | sail 扩展 | With no certificate or key, a self-signed one made at start for `tls.server_name` (or `sail.invalid`), kept across reloads that leave the inbound in place, as Mihomo's Hysteria2 and TUIC listeners make one; clients need `insecure` or a pin, which changes with each new certificate; an error with a certificate, a key or REALITY |

<a id="inbounds-anytls-tls-reality"></a>

### `inbounds[anytls].tls.reality`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 支持 | — |
| `handshake` | object → [对象](#inbounds-anytls-tls-reality-handshake) | — | 支持 | — |
| `private_key` | string | — | 支持 | — |
| `short_id` | listable-string | — | 支持 | — |
| `max_time_difference` | duration | — | 支持 | — |

<a id="inbounds-anytls-tls-reality-handshake"></a>

### `inbounds[anytls].tls.reality.handshake`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | — | 支持 | — |
| `server_port` | number | — | 支持 | — |
| `detour` | string | — | 报错：A detour to the REALITY handshake server: it would be reached otherwise | — |
| `bind_interface` | string | — | 支持 | — |
| `inet4_bind_address` | string | — | 支持 | — |
| `inet6_bind_address` | string | — | 支持 | — |
| `bind_address_no_port` | bool | — | 支持 | — |
| `protect_path` | string | — | 支持 | — |
| `routing_mark` | number\|string | — | 支持 | — |
| `reuse_addr` | bool | — | 支持 | — |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | — |
| `connect_timeout` | duration | — | 支持 | — |
| `tcp_fast_open` | bool | — | 支持 | — |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `disable_tcp_keep_alive` | bool | — | 支持 | — |
| `tcp_keep_alive` | duration | — | 支持 | — |
| `tcp_keep_alive_interval` | duration | — | 支持 | — |
| `udp_fragment` | bool | — | 支持 | — |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-inbounds-route-rule-set) | — | 支持 | — |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 支持 | — |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 支持 | — |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 支持 | — |
| `fallback_delay` | duration | — | 支持 | — |
| `domain_strategy` | string | — | 支持 (sing-box 已弃用) | — |

<a id="inbounds-anytls-users"></a>

### `inbounds[anytls].users[]`

Rust 定义：[`AnyTlsUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/anytls/inbound/mod.rs) · 构建条件：`feature = "inbound-anytls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-direct"></a>

## `inbounds[direct]`

Rust 定义：[`DirectInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/direct/inbound.rs) · 构建条件：`feature = "inbound-direct"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `network` | listable-string, 取值 `tcp`, `udp` | 未设置 | 支持 | Only `tcp`, or only `udp`; both when unset. |
| `override_address` | string | 未设置 | 支持 | Where what comes in goes, instead of the listener's address. |
| `override_port` | number | 未设置 | 支持 | The port it goes to, instead of the listener's. |

<a id="inbounds-hc"></a>

## `inbounds[hc]`

Rust 定义：[`HcInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hc/inbound/mod.rs) · 构建条件：`feature = "inbound-hc"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `listen` | string | 未设置 | sail 扩展 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | sail 扩展 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `udp_timeout` | 时长，或秒数 | 未设置 | sail 扩展 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `tcp_keep_alive` | duration | 未设置 | sail 扩展 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | sail 扩展 | Between keepalive probes; 75s when unset. |
| `disable_tcp_keep_alive` | bool | `false` | sail 扩展 | — |
| `tcp_fast_open` | bool | `false` | sail 扩展 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `udp_fragment` | bool | 未设置 | sail 扩展 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `path` | string | 必填 | sail 扩展 | — |
| `request` | string | `""` | sail 扩展 | — |
| `response` | string | 必填 | sail 扩展 | — |

<a id="inbounds-http"></a>

## `inbounds[http]`

Rust 定义：[`HttpInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/http/inbound/mod.rs) · 构建条件：`feature = "inbound-http"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-http-users) | `[]` | 支持 | Clients must authenticate as one of these with `Proxy-Authorization: Basic`; anyone may connect when there are none. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-inbounds) | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `set_system_proxy` | bool | — | 警告：The platform proxy is the host's to set | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-inbounds) | 未设置 | 支持 | — |
| `realm` | string | 未设置 | sail 扩展 | The realm a `407` names, which clients show when asking for credentials: a sail extension; `sail` when unset. |
| `skip_auth_prefixes` | 数组，元素为 string | `[]` | sail 扩展 | The clients that go in without credentials, by the IP prefixes they connect from: Mihomo's `skip-auth-prefixes`, a sail extension. |
| `version` | number 或 数组，元素为 number | 未设置 | sail 扩展 | The HTTP versions served, sing-box 1.15's: 1 and 2 when unset. HTTP/2 is told by its preface, over TLS or not. 3 is warned of and not served: sail speaks no HTTP/3. |
| `idle_timeout` | duration | 未设置 | sail 扩展 | HTTP/2's, sing-box 1.15's: how long a ping may go unanswered, and how long a connection with no tunnel is kept. |
| `keep_alive_period` | duration | 未设置 | sail 扩展 | HTTP/2's: a ping after this long with nothing received. |
| `stream_receive_window` | number | 未设置 | sail 扩展 | HTTP/2's: a tunnel's receive window. |
| `connection_receive_window` | number | 未设置 | sail 扩展 | HTTP/2's: a connection's receive window. |
| `max_concurrent_streams` | number | 未设置 | sail 扩展 | HTTP/2's: the most tunnels a client may have open on one connection. |

<a id="inbounds-http-users"></a>

### `inbounds[http].users[]`

Rust 定义：[`HttpUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/http/inbound/mod.rs) · 构建条件：`feature = "inbound-http"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `username` | string | 必填 | 支持 | — |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-hysteria2"></a>

## `inbounds[hysteria2]`

Rust 定义：[`Hysteria2InboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hysteria2/inbound/mod.rs) · 构建条件：`feature = "inbound-hysteria2"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `up_mbps` | number | 未设置 | 支持 | What the server may send at, at most, to each client. |
| `down_mbps` | number | 未设置 | 支持 | What the server can receive at, told to clients. |
| `obfs` | object → [对象](/sail/zh/reference/shared/#obfs), [[gecko]](/sail/zh/reference/shared/#obfs-gecko), [[salamander]](/sail/zh/reference/shared/#obfs-salamander) | 未设置 | 支持 | — |
| `users` | array → [[]](#inbounds-hysteria2-users) | 必填 | 支持 | — |
| `ignore_client_bandwidth` | bool | `false` | 支持 | Ignores the rate clients say they receive at, and has them find their own: BBR both ways. |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-inbounds-2) | 必填 | 支持 | — |
| `idle_timeout` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `keep_alive_period` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `stream_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `connection_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `max_concurrent_streams` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `initial_packet_size` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `disable_path_mtu_discovery` | bool | — | 警告：QUIC tuning: the same connection without it | — |
| `masquerade` | string\|object | 未设置 | 支持 | What anyone without a password is served: an `http://` or `https://` site behind, or a fixed response; 404 when unset. |
| `bbr_profile` | string, 取值 `standard`, `conservative`, `aggressive` | — | 警告：Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic | — |
| `brutal_debug` | bool | — | 警告：Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic | — |
| `realm` | object → [对象](#inbounds-hysteria2-realm) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="inbounds-hysteria2-users"></a>

### `inbounds[hysteria2].users[]`

Rust 定义：[`User`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/hysteria2/inbound/mod.rs) · 构建条件：`feature = "inbound-hysteria2"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-hysteria2-realm"></a>

### `inbounds[hysteria2].realm`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server_url` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `token` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `realm_id` | string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `stun_servers` | listable-string | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `ip_version` | number, 取值 `0`, `4`, `6` | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `port_mapping` | object → [对象](/sail/zh/reference/shared/#port-mapping) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `http_client` | string\|object → [对象](/sail/zh/reference/shared/#http-client) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |
| `stun_domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-stun-domain-resolver) | — | 报错：Meeting peers through a Hysteria realm: connections would be made otherwise | — |

<a id="inbounds-mixed"></a>

## `inbounds[mixed]`

Rust 定义：[`MixedInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/mixed/inbound/mod.rs) · 构建条件：`feature = "inbound-mixed"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-mixed-users) | `[]` | 支持 | Clients must authenticate as one of these, by SOCKS5 username/password or HTTP Basic; anyone may connect when there are none. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-inbounds) | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `set_system_proxy` | bool | — | 警告：The platform proxy is the host's to set | — |
| `tls` | object → [对象](#inbounds-mixed-tls) | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `realm` | string | 未设置 | sail 扩展 | The realm an HTTP `407` names: a sail extension; `sail` when unset. |
| `skip_auth_prefixes` | 数组，元素为 string | `[]` | sail 扩展 | The clients that go in without credentials, by the IP prefixes they connect from: Mihomo's `skip-auth-prefixes`, a sail extension. |

<a id="inbounds-mixed-users"></a>

### `inbounds[mixed].users[]`

Rust 定义：[`MixedUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/mixed/inbound/mod.rs) · 构建条件：`feature = "inbound-mixed"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `username` | string | 必填 | 支持 | — |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-mixed-tls"></a>

### `inbounds[mixed].tls`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `server_name` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `insecure` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `alpn` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `min_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `max_version` | string, 取值 `1.0`, `1.1`, `1.2`, `1.3` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `cipher_suites` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `curve_preferences` | listable-string, 取值 `P256`, `P384`, `P521`, `X25519`, `X25519MLKEM768` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `certificate` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `certificate_path` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `client_authentication` | string, 取值 `no`, `request`, `require-any`, `verify-if-given`, `require-and-verify` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `client_certificate` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `client_certificate_path` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `client_certificate_public_key_sha256` | listable-string\|array | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `key` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `key_path` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `kernel_tx` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `kernel_rx` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `handshake_timeout` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `certificate_provider` | string\|object | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `ech` | object → [对象](#inbounds-mixed-tls-ech) | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `reality` | object → [对象](#inbounds-mixed-tls-reality) | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `acme` | object | — | 报错：TLS on a mixed inbound: it would take plain connections (sing-box 已弃用) | — |

<a id="inbounds-mixed-tls-ech"></a>

### `inbounds[mixed].tls.ech`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `key` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `key_path` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |

<a id="inbounds-mixed-tls-reality"></a>

### `inbounds[mixed].tls.reality`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `handshake` | object → [对象](#inbounds-mixed-tls-reality-handshake) | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `private_key` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `short_id` | listable-string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `max_time_difference` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |

<a id="inbounds-mixed-tls-reality-handshake"></a>

### `inbounds[mixed].tls.reality.handshake`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `server_port` | number | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `detour` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `bind_interface` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `inet4_bind_address` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `inet6_bind_address` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `bind_address_no_port` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `protect_path` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `routing_mark` | number\|string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `reuse_addr` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `netns` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `connect_timeout` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `tcp_fast_open` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `tcp_multi_path` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `disable_tcp_keep_alive` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `tcp_keep_alive` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `tcp_keep_alive_interval` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `udp_fragment` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `domain_resolver` | string\|object → [对象](#inbounds-mixed-tls-reality-handshake-domain-resolver) | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `fallback_delay` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `domain_strategy` | string | — | 报错：TLS on a mixed inbound: it would take plain connections (sing-box 已弃用) | — |

<a id="inbounds-mixed-tls-reality-handshake-domain-resolver"></a>

### `inbounds[mixed].tls.reality.handshake.domain_resolver`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `timeout` | duration | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `disable_cache` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `disable_optimistic_cache` | bool | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `rewrite_ttl` | number | — | 报错：TLS on a mixed inbound: it would take plain connections | — |
| `client_subnet` | string | — | 报错：TLS on a mixed inbound: it would take plain connections | — |

<a id="inbounds-mptp"></a>

## `inbounds[mptp]`

Rust 定义：[`MptpInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/mptp/inbound/mod.rs) · 构建条件：`feature = "inbound-mptp"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `listen` | string | 未设置 | sail 扩展 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | sail 扩展 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `udp_timeout` | 时长，或秒数 | 未设置 | sail 扩展 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `tcp_keep_alive` | duration | 未设置 | sail 扩展 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | sail 扩展 | Between keepalive probes; 75s when unset. |
| `disable_tcp_keep_alive` | bool | `false` | sail 扩展 | — |
| `tcp_fast_open` | bool | `false` | sail 扩展 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `udp_fragment` | bool | 未设置 | sail 扩展 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |

<a id="inbounds-nf"></a>

## `inbounds[nf]`

Rust 定义：[`NfInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/nf/inbound/mod.rs) · 构建条件：`all (feature = "inbound-nf" , windows)` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `listen` | string | 未设置 | sail 扩展 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | sail 扩展 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `udp_timeout` | 时长，或秒数 | 未设置 | sail 扩展 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `tcp_keep_alive` | duration | 未设置 | sail 扩展 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | sail 扩展 | Between keepalive probes; 75s when unset. |
| `disable_tcp_keep_alive` | bool | `false` | sail 扩展 | — |
| `tcp_fast_open` | bool | `false` | sail 扩展 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `udp_fragment` | bool | 未设置 | sail 扩展 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `driver_name` | string | 必填 | sail 扩展 | — |
| `nfapi` | string | `"nfapi.dll"` | sail 扩展 | — |
| `fake_dns_exclude` | 数组，元素为 string | `[]` | sail 扩展 | — |
| `fake_dns_include` | 数组，元素为 string | `[]` | sail 扩展 | — |

<a id="inbounds-redirect"></a>

## `inbounds[redirect]`

Rust 定义：[`RedirectInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/redirect/inbound/mod.rs) · 构建条件：`feature = "inbound-redirect"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |

<a id="inbounds-sail"></a>

## `inbounds[sail]`

Rust 定义：[`SailInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/sail/inbound.rs) · 构建条件：`feature = "inbound-sail"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `listen` | string | 未设置 | sail 扩展 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | sail 扩展 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `udp_timeout` | 时长，或秒数 | 未设置 | sail 扩展 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `tcp_keep_alive` | duration | 未设置 | sail 扩展 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | sail 扩展 | Between keepalive probes; 75s when unset. |
| `disable_tcp_keep_alive` | bool | `false` | sail 扩展 | — |
| `tcp_fast_open` | bool | `false` | sail 扩展 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `udp_fragment` | bool | 未设置 | sail 扩展 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `users` | 数组，元素为 对象 → [[]](#inbounds-sail-users) | 必填 | sail 扩展 | Who may connect, by token. Sail/1 is experimental (sail#60): its wire format is not yet stable, and it is built only with the `inbound-sail` feature, which no default build turns on. |
| `padding_scheme` | string 或 数组，元素为 string | 未设置 | sail 扩展 | The padding scheme, as lines, AnyTLS's syntax. Unset, the default. |
| `fallback` | 对象 → [对象](/sail/zh/reference/shared/#fallback-fallback-for-alpn) | 未设置 | sail 扩展 | — |
| `fallback_for_alpn` | 对象，值为 对象 → [对象](/sail/zh/reference/shared/#fallback-fallback-for-alpn) | `{}` | sail 扩展 | — |

<a id="inbounds-sail-users"></a>

### `inbounds[sail].users[]`

Rust 定义：[`SailUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/sail/inbound.rs) · 构建条件：`feature = "inbound-sail"` · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | sail 扩展 | Who the user is to routing (`auth_user`), statistics and logs. |
| `token` | string | 必填 | sail 扩展 | 32 random bytes as unpadded base64url (43 characters), each user's own. |

<a id="inbounds-shadowsocks"></a>

## `inbounds[shadowsocks]`

Rust 定义：[`ShadowsocksInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowsocks/inbound/mod.rs) · 构建条件：`feature = "inbound-shadowsocks"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `network` | listable-string, 取值 `tcp`, `udp` | — | 报错：Which networks a Shadowsocks inbound serves: it would serve others | — |
| `method` | string, 取值 `none`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` | 必填 | 支持 | — |
| `password` | string | 必填 | 支持 | The PSK with a 2022 method; with `users`, the server's identity PSK. |
| `users` | array → [[]](#inbounds-shadowsocks-users) | 未设置 | 支持 | Shadowsocks 2022 users, told apart by identity headers. |
| `destinations` | array → [[]](#inbounds-shadowsocks-destinations) | — | 报错：Relaying to other Shadowsocks servers | — |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-inbounds) | 未设置 | 支持 | — |
| `managed` | bool | — | 警告：Users managed through the SSM API, a service sail does not run | — |

<a id="inbounds-shadowsocks-users"></a>

### `inbounds[shadowsocks].users[]`

Rust 定义：[`ShadowsocksUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowsocks/inbound/mod.rs) · 构建条件：`feature = "inbound-shadowsocks"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `password` | string | 必填 | 支持 | The user's base64 PSK. |

<a id="inbounds-shadowsocks-destinations"></a>

### `inbounds[shadowsocks].destinations[]`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | — | 报错：Relaying to other Shadowsocks servers | — |
| `password` | string | — | 报错：Relaying to other Shadowsocks servers | — |
| `server` | string | — | 报错：Relaying to other Shadowsocks servers | — |
| `server_port` | number | — | 报错：Relaying to other Shadowsocks servers | — |

<a id="inbounds-shadowtls"></a>

## `inbounds[shadowtls]`

Rust 定义：[`ShadowTlsInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowtls/inbound.rs) · 构建条件：`feature = "inbound-shadowtls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | 未设置 | 支持 | The inbound connections go to after the handshake, by tag: needed. |
| `version` | number, 取值 `1`, `2`, `3` | `1` | 支持 | Must be 3: versions 1 and 2 are not supported. sing-box's default is 1. |
| `password` | string | 未设置 | 支持 | Version 2's, and an error: version 3 takes `users`. |
| `users` | array → [[]](#inbounds-shadowtls-users) | `[]` | 支持 | At least one. |
| `handshake` | object → [对象](#inbounds-shadowtls-handshake) | 未设置 | 支持 | The site whose handshake is relayed, for everyone the other fields do not send elsewhere. Needed unless `wildcard_sni` is on. |
| `handshake_for_server_name` | map | `{}` | 支持 | Handshake servers by the server name the ClientHello asks for. |
| `strict_mode` | bool | `false` | 支持 | Relays a ServerHello that does not pick TLS 1.3 as it would an unauthenticated client. |
| `wildcard_sni` | string, 取值 `off`, `authed`, `all` | `off` | 支持 | — |

<a id="inbounds-shadowtls-users"></a>

### `inbounds[shadowtls].users[]`

Rust 定义：[`ShadowTlsUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowtls/inbound.rs) · 构建条件：`feature = "inbound-shadowtls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | `""` | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-shadowtls-handshake"></a>

### `inbounds[shadowtls].handshake`

Rust 定义：[`ShadowTlsHandshake`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/shadowtls/inbound.rs) · 构建条件：`feature = "inbound-shadowtls"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | `""` | 支持 | — |
| `server_port` | number | `0` | 支持 | — |
| `detour` | string | — | 报错：The protocol's own check: not implemented yet | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：The protocol's own check: not implemented yet | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 报错：The protocol's own check: not implemented yet | Not implemented yet. |
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

<a id="inbounds-socks"></a>

## `inbounds[socks]`

Rust 定义：[`SocksInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/socks/inbound/mod.rs) · 构建条件：`feature = "inbound-socks"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-socks-users) | `[]` | 支持 | Clients must authenticate as one of these; anyone may connect when there are none. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-inbounds) | — | 报错：Resolving requested names with a resolver of its own: another server would answer | — |
| `skip_auth_prefixes` | 数组，元素为 string | `[]` | sail 扩展 | The clients that go in without credentials, by the IP prefixes they connect from: Mihomo's `skip-auth-prefixes`, a sail extension. |

<a id="inbounds-socks-users"></a>

### `inbounds[socks].users[]`

Rust 定义：[`SocksUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/socks/inbound/mod.rs) · 构建条件：`feature = "inbound-socks"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `username` | string | 必填 | 支持 | — |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-tproxy"></a>

## `inbounds[tproxy]`

Rust 定义：[`TproxyInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/tproxy/mod.rs) · 构建条件：`feature = "inbound-tproxy"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `network` | listable-string, 取值 `tcp`, `udp` | 未设置 | 支持 | Only `tcp`, or only `udp`; both when unset. |
| `udp_mapping` | string, 取值 `endpoint_independent`, `address_dependent`, `address_and_port_dependent` | — | 警告：How UDP mappings are made and how many are kept: the same traffic | — |
| `udp_filtering` | string, 取值 `endpoint_independent`, `address_dependent`, `address_and_port_dependent` | — | 报错：Which remote addresses may answer through a UDP mapping: others would | — |
| `udp_nat_max` | number | — | 警告：How UDP mappings are made and how many are kept: the same traffic | — |

<a id="inbounds-trojan"></a>

## `inbounds[trojan]`

Rust 定义：[`TrojanInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/trojan/inbound/mod.rs) · 构建条件：`feature = "inbound-trojan"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-trojan-users) | 必填 | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-inbounds) | 未设置 | 支持 | — |
| `fallback` | object → [对象](#inbounds-trojan-fallback) | 未设置 | 支持 | Where a connection that fails to authenticate is relayed. |
| `fallback_for_alpn` | map | `{}` | 支持 | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`. |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-inbounds) | 未设置 | 支持 | — |
| `transport` | object → [对象](/sail/zh/reference/shared/#transport-inbounds), [[grpc]](/sail/zh/reference/shared/#transport-grpc-inbounds), [[http]](/sail/zh/reference/shared/#transport-http-inbounds), [[httpupgrade]](/sail/zh/reference/shared/#transport-httpupgrade-inbounds), [[ws]](/sail/zh/reference/shared/#transport-ws-inbounds) | 未设置 | 支持 | — |

<a id="inbounds-trojan-users"></a>

### `inbounds[trojan].users[]`

Rust 定义：[`TrojanUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/trojan/inbound/mod.rs) · 构建条件：`feature = "inbound-trojan"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `password` | string | 必填 | 支持 | — |

<a id="inbounds-trojan-fallback"></a>

### `inbounds[trojan].fallback`

Rust 定义：[`FallbackServer`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/fallback.rs) · 构建条件：`any (feature = "inbound-anytls" , feature = "inbound-trojan" , feature = "inbound-vless" , feature = "inbound-shadowtls")`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 支持 | — |
| `server_port` | number | 必填 | 支持 | — |

<a id="inbounds-tuic"></a>

## `inbounds[tuic]`

Rust 定义：[`TuicInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/tuic/inbound/mod.rs) · 构建条件：`feature = "inbound-tuic"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-tuic-users) | 必填 | 支持 | — |
| `congestion_control` | string, 取值 `cubic`, `new_reno`, `bbr` | `cubic` | 支持 | — |
| `auth_timeout` | duration | 未设置 | 支持 | How long a connection may go without authenticating. 3s, as in sing-box, when not set. |
| `zero_rtt_handshake` | bool | `false` | 支持 | — |
| `heartbeat` | duration | 未设置 | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-inbounds-2) | 必填 | 支持 | — |
| `idle_timeout` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `keep_alive_period` | duration | — | 警告：QUIC tuning: the same connection without it | — |
| `stream_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `connection_receive_window` | number\|string | — | 警告：QUIC tuning: the same connection without it | — |
| `max_concurrent_streams` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `initial_packet_size` | number | — | 警告：QUIC tuning: the same connection without it | — |
| `disable_path_mtu_discovery` | bool | — | 警告：QUIC tuning: the same connection without it | — |

<a id="inbounds-tuic-users"></a>

### `inbounds[tuic].users[]`

Rust 定义：[`TuicUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/tuic/inbound/mod.rs) · 构建条件：`feature = "inbound-tuic"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `uuid` | string | 必填 | 支持 | — |
| `password` | string | `""` | 支持 | — |

<a id="inbounds-tun"></a>

## `inbounds[tun]`

Rust 定义：[`TunInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/tun/inbound.rs) · 构建条件：`feature = "inbound-tun"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `interface_name` | string | 未设置 | 支持 | The device's name, used as it is: a start fails if it is taken. Without it, on macOS one past the highest utunN is chosen at start, as sing-box chooses, and kept across reloads (a host reads it back); one another program takes before the device opens is given up for the next free one, three at most. Elsewhere utun233. |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `mtu` | number | `9000` | 支持 | 9000 when omitted, as sing-box has it on Android. |
| `address` | listable-string | `[]` | 支持 | The device's addresses with their prefixes: one IPv4, one IPv6, or one of each. |
| `dns_mode` | string, 取值 `disabled`, `native`, `hijack` | 未设置 | 支持 | sing-box 1.14's: whether the TUN's DNS is the system's, `native`, and its port 53 taken too, `hijack`, or neither, `disabled`. `hijack` with `auto_route`, `disabled` without, when unset. Port 53 is taken with auto_redirect on Linux and strict_route on Windows; on macOS `hijack` is `native`. |
| `dns_address` | listable-string | — | 报错：The TUN's own DNS handling: queries would be answered otherwise | — |
| `auto_route` | bool | `false` | 支持 | Routes the system's traffic into the device. |
| `iproute2_table_index` | number | 未设置 | 支持 | Linux: the routing table of the device's routes (2022). Elsewhere, or without `auto_route`, it changes nothing, and is ignored with a warning, as in sing-box; so is `iproute2_rule_index`. |
| `iproute2_rule_index` | number | 未设置 | 支持 | Linux: the first of auto_route's and auto_redirect's ip rules (9000); the rules from it to 10 after it are sail's, and removed at start and stop. |
| `auto_redirect` | bool | `false` | 支持 | Linux: redirects TCP to sail with nftables and marks the rest into the device, and lets rules bypass sail before a connection is set up (sing-box 1.13). Without it, the fields of the redirect (its marks, NFQUEUE and fallback rule, and `exclude_mptcp`) change nothing, and are ignored with a warning, as in sing-box. |
| `auto_redirect_input_mark` | number\|string | 未设置 | 支持 | The mark that routes a packet into the device (0x2023). Marks are numbers, or strings of hexadecimal ("0x2023"); 0 is the default. |
| `auto_redirect_output_mark` | number\|string | 未设置 | 支持 | The mark sail's own sockets carry, and flows that bypass it (0x2024). `route.default_mark` and `routing_mark` conflict with it. |
| `auto_redirect_reset_mark` | number\|string | 未设置 | 支持 | The mark of a connection pre-match rejects, which the kernel resets (0x2025). |
| `auto_redirect_nfqueue` | number | 未设置 | 支持 | The NFQUEUE pre-match reads first packets from (100). If it cannot be bound, sail runs without pre-match: `bypass` rules are skipped. |
| `auto_redirect_iproute2_fallback_rule_index` | number | 未设置 | 支持 | The ip rule that sends what the main table has no route for into the device (32768). |
| `exclude_mptcp` | bool | `false` | 支持 | Lets MPTCP go past sail rather than dropping it, which makes clients fall back to TCP. |
| `loopback_address` | listable-string | `[]` | 支持 | Addresses whose TCP goes into the device rather than to the redirect listener: a destination sail's own listeners use, say. |
| `strict_route` | bool | `false` | 支持 | With `auto_route`, keeps traffic from going past sail. Linux: with one family on the device, the other is unreachable. Windows: firewall rules, as sing-tun's: DNS leaves only through the device, but for sail's own, and with no IPv6 on the device, none leaves. Elsewhere it changes nothing, as in sing-box. |
| `route_address` | listable-string | `[]` | 支持 | Only these destinations are taken... |
| `route_address_set` | listable-string | `[]` | 支持 | Rule-sets whose destination `ip_cidr` alone are taken, kept up to date as they are downloaded again. |
| `route_exclude_address` | listable-string | `[]` | 支持 | ...and not these. |
| `route_exclude_address_set` | listable-string | `[]` | 支持 | Rule-sets whose destination `ip_cidr` are not taken. |
| `include_interface` | listable-string | `[]` | 支持 | Linux, with `auto_route`: forwarded traffic is taken only from these interfaces... |
| `exclude_interface` | listable-string | `[]` | 支持 | ...or not from these. Naming `lo` in either leaves the host's own traffic out. |
| `include_uid` | listable-number | `[]` | 支持 | Linux, with `auto_route`: the host's traffic is taken only from these users... |
| `include_uid_range` | listable-string | `[]` | 支持 | ...and from these ranges, as "1000:2000". |
| `exclude_uid` | listable-number | `[]` | 支持 | The host's traffic of these users is not taken... |
| `exclude_uid_range` | listable-string | `[]` | 支持 | ...nor of these ranges. |
| `include_android_user` | listable-number | — | 报错：Not supported; include_uid_range takes in an Android user's apps (user N's are uids N*100000 to N*100000+99999) | Android users: not supported, as no VpnService can take them in; `include_uid_range` takes in a user's apps. |
| `include_package` | listable-string | `[]` | 支持 | Android: the apps the host's VPN takes in or leaves out, applied by the host. |
| `exclude_package` | listable-string | `[]` | 支持 | — |
| `include_mac_address` | listable-string | — | 报错：Filtering LAN clients by MAC address | — |
| `exclude_mac_address` | listable-string | — | 报错：Filtering LAN clients by MAC address | — |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `udp_mapping` | string, 取值 `endpoint_independent`, `address_dependent`, `address_and_port_dependent` | — | 警告：How UDP mappings are made and how many are kept: the same traffic | — |
| `udp_filtering` | string, 取值 `endpoint_independent`, `address_dependent`, `address_and_port_dependent` | 未设置 | 支持 | sing-box 1.14's: which remote addresses reach an app through the port it sent from. `endpoint_independent`: any (full cone, as P2P and some games need). `address_and_port_dependent`, the default: only an address and port the app sent to. `address_dependent` is not implemented, and is an error. An app's port is one mapping in every case. |
| `udp_nat_max` | number | — | 警告：How UDP mappings are made and how many are kept: the same traffic | — |
| `stack` | string, 取值 `system`, `gvisor`, `mixed` | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |
| `platform` | object → [对象](#inbounds-tun-platform) | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |
| `endpoint_independent_nat` | bool | 未设置 | 支持 (sing-box 已弃用) | sing-box's older name for `udp_filtering: endpoint_independent`, deprecated there; the two may not disagree. |
| `multi_queue` | bool | `false` | sail 扩展 | sing-box 1.15's: Linux opens the device with `IFF_MULTI_QUEUE`, a queue and a netstack shard to each CPU, eight at most. Off, the default, one queue: measured faster in every case tried (Trojan over TUN, 2 and 4 cores, 2026-10-15: 2 queues 3-9% slower, 4 queues 4-9%). Elsewhere, and on a device the host opens, ignored with a warning. |

<a id="inbounds-tun-platform"></a>

### `inbounds[tun].platform`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `http_proxy` | object → [对象](#inbounds-tun-platform-http-proxy) | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |

<a id="inbounds-tun-platform-http-proxy"></a>

### `inbounds[tun].platform.http_proxy`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |
| `server` | string | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |
| `server_port` | number | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |
| `bypass_domain` | listable-string | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |
| `match_domain` | listable-string | — | 警告：One stack serves every `stack`; the platform proxy is the host's to set | — |

<a id="inbounds-vless"></a>

## `inbounds[vless]`

Rust 定义：[`VlessInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/vless/inbound/mod.rs) · 构建条件：`feature = "inbound-vless"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-vless-users) | 必填 | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-inbounds) | 未设置 | 支持 | — |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-inbounds) | 未设置 | 支持 | — |
| `transport` | object → [对象](/sail/zh/reference/shared/#transport-inbounds), [[grpc]](/sail/zh/reference/shared/#transport-grpc-inbounds), [[http]](/sail/zh/reference/shared/#transport-http-inbounds), [[httpupgrade]](/sail/zh/reference/shared/#transport-httpupgrade-inbounds), [[ws]](/sail/zh/reference/shared/#transport-ws-inbounds) | 未设置 | 支持 | — |
| `fallback` | 对象 → [对象](/sail/zh/reference/shared/#fallback-fallback-for-alpn) | 未设置 | sail 扩展 | Where a connection that fails to authenticate is relayed. |
| `fallback_for_alpn` | 对象，值为 对象 → [对象](/sail/zh/reference/shared/#fallback-fallback-for-alpn) | `{}` | sail 扩展 | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`. |

<a id="inbounds-vless-users"></a>

### `inbounds[vless].users[]`

Rust 定义：[`VlessUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/vless/inbound/mod.rs) · 构建条件：`feature = "inbound-vless"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `uuid` | string | 必填 | 支持 | — |
| `flow` | string | `""` | 支持 | `""` or `xtls-rprx-vision`. |

<a id="inbounds-vmess"></a>

## `inbounds[vmess]`

Rust 定义：[`VMessInboundOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/vmess/inbound/mod.rs) · 构建条件：`feature = "inbound-vmess"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `listen` | string | 未设置 | 支持 | The address to listen on; defaults to `127.0.0.1`. |
| `listen_port` | number | 未设置 | 支持 | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound. |
| `bind_interface` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `routing_mark` | number\|string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `reuse_addr` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `netns` | string | — | 报错：Where and how an inbound listens: it would take connections otherwise | — |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | — |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open on the TCP port it listens on: what a client that has the server's cookie sends with its SYN is taken at once. On Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for client and server), which the default (1) leaves off. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `udp_fragment` | bool | 未设置 | 支持 | Whether the datagrams it sends from its UDP sockets may be fragmented on the way: where not, they carry don't-fragment, and one larger than the path takes is refused rather than sent in pieces. Unset, as sing-box: they may for direct and hysteria2, and may not for the others. |
| `udp_timeout` | number\|duration | 未设置 | 支持 | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box. A number is of seconds. |
| `detour` | string | — | 报错：Handing an inbound's connections to another inbound | — |
| `users` | array → [[]](#inbounds-vmess-users) | 必填 | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-inbounds) | 未设置 | 支持 | — |
| `multiplex` | object → [对象](/sail/zh/reference/shared/#multiplex-inbounds) | 未设置 | 支持 | — |
| `transport` | object → [对象](/sail/zh/reference/shared/#transport-inbounds), [[grpc]](/sail/zh/reference/shared/#transport-grpc-inbounds), [[http]](/sail/zh/reference/shared/#transport-http-inbounds), [[httpupgrade]](/sail/zh/reference/shared/#transport-httpupgrade-inbounds), [[ws]](/sail/zh/reference/shared/#transport-ws-inbounds) | 未设置 | 支持 | — |

<a id="inbounds-vmess-users"></a>

### `inbounds[vmess].users[]`

Rust 定义：[`VMessUser`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/vmess/inbound/mod.rs) · 构建条件：`feature = "inbound-vmess"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 未设置 | 支持 | Who the user is to routing (`auth_user`), statistics and logs. |
| `uuid` | string | 必填 | 支持 | — |
| `alterId` | number | `0` | 支持 | Only 0: AEAD headers. Legacy VMess is not served. |

<a id="inbounds-missing"></a>

## sail 未实现的类型：`inbounds`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `inbounds[cloudflared]` | 报错：A protocol sail does not implement | 69 |
| `inbounds[hysteria]` | 报错：A protocol sail does not implement | 98 |
| `inbounds[naive]` | 报错：A protocol sail does not implement | 83 |
| `inbounds[snell]` | 报错：A protocol sail does not implement | 22 |

