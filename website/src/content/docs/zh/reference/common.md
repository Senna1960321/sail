---
title: "顶层与通用"
description: "sail 原生配置格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段参考。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

<a id="top"></a>

## 顶层

Rust 定义：[`Config`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `$schema` | string | — | 支持 | — |
| `log` | object → [对象](#log) | 各字段取默认值 | 支持 | — |
| `dns` | object → [对象](/sail/zh/reference/dns/#dns) | 各字段取默认值 | 支持 | — |
| `ntp` | object → [对象](#ntp) | 未设置 | 支持 | The time the protocols that check it go by, and certificates are verified at, measured against an NTP server; the system's clock is never set. |
| `certificate` | object → [对象](#certificate) | 未设置 | 支持 | The root certificates servers are checked against; the system's when unset. |
| `certificate_providers` | array → [[]](#certificate-providers), [[acme]](#certificate-providers-missing), [[cloudflare-origin-ca]](#certificate-providers-missing), [[tailscale]](#certificate-providers-missing) | — | 报错：Certificates from ACME and other providers: the inbounds would serve none | — |
| `http_clients` | array → [[]](#http-clients) | `[]` | 支持 | How sail fetches over HTTP, rule-sets for one, by tag. |
| `network_namespaces` | array → [[]](#network-namespaces), [[unshare]](#network-namespaces-missing) | — | 报错：Linux network namespaces to listen and dial in | — |
| `endpoints` | array → [[]](/sail/zh/reference/endpoints/#endpoints), [[openconnect]](/sail/zh/reference/endpoints/#endpoints-missing), [[openvpn-client]](/sail/zh/reference/endpoints/#endpoints-missing), [[openvpn-server]](/sail/zh/reference/endpoints/#endpoints-missing), [[tailscale]](/sail/zh/reference/endpoints/#endpoints-missing), [[wireguard]](/sail/zh/reference/endpoints/#endpoints-wireguard) | `[]` | 支持 | Both an inbound and an outbound under one tag, as sing-box's endpoints: connections routed to the tag go out through it, and what comes in through it is routed with the tag as its inbound. |
| `inbounds` | array → [[]](/sail/zh/reference/inbounds/#inbounds), [[anytls]](/sail/zh/reference/inbounds/#inbounds-anytls), [[cloudflared]](/sail/zh/reference/inbounds/#inbounds-missing), [[direct]](/sail/zh/reference/inbounds/#inbounds-direct), [[hc]](/sail/zh/reference/inbounds/#inbounds-hc), [[http]](/sail/zh/reference/inbounds/#inbounds-http), [[hysteria]](/sail/zh/reference/inbounds/#inbounds-missing), [[hysteria2]](/sail/zh/reference/inbounds/#inbounds-hysteria2), [[mixed]](/sail/zh/reference/inbounds/#inbounds-mixed), [[mptp]](/sail/zh/reference/inbounds/#inbounds-mptp), [[naive]](/sail/zh/reference/inbounds/#inbounds-missing), [[nf]](/sail/zh/reference/inbounds/#inbounds-nf), [[redirect]](/sail/zh/reference/inbounds/#inbounds-redirect), [[shadowsocks]](/sail/zh/reference/inbounds/#inbounds-shadowsocks), [[shadowtls]](/sail/zh/reference/inbounds/#inbounds-shadowtls), [[snell]](/sail/zh/reference/inbounds/#inbounds-missing), [[socks]](/sail/zh/reference/inbounds/#inbounds-socks), [[tproxy]](/sail/zh/reference/inbounds/#inbounds-tproxy), [[trojan]](/sail/zh/reference/inbounds/#inbounds-trojan), [[tuic]](/sail/zh/reference/inbounds/#inbounds-tuic), [[tun]](/sail/zh/reference/inbounds/#inbounds-tun), [[vless]](/sail/zh/reference/inbounds/#inbounds-vless), [[vmess]](/sail/zh/reference/inbounds/#inbounds-vmess) | `[]` | 支持 | — |
| `outbounds` | array → [[]](/sail/zh/reference/outbounds/#outbounds), [[anytls]](/sail/zh/reference/outbounds/#outbounds-anytls), [[block]](/sail/zh/reference/outbounds/#outbounds-block), [[bridge]](/sail/zh/reference/outbounds/#outbounds-missing), [[direct]](/sail/zh/reference/outbounds/#outbounds-direct), [[fallback]](/sail/zh/reference/outbounds/#outbounds-fallback), [[http]](/sail/zh/reference/outbounds/#outbounds-http), [[hysteria]](/sail/zh/reference/outbounds/#outbounds-missing), [[hysteria2]](/sail/zh/reference/outbounds/#outbounds-hysteria2), [[load-balance]](/sail/zh/reference/outbounds/#outbounds-load-balance), [[mptp]](/sail/zh/reference/outbounds/#outbounds-mptp), [[naive]](/sail/zh/reference/outbounds/#outbounds-missing), [[network]](/sail/zh/reference/outbounds/#outbounds-network), [[pass]](/sail/zh/reference/outbounds/#outbounds-pass), [[plugin]](/sail/zh/reference/outbounds/#outbounds-plugin), [[redirect]](/sail/zh/reference/outbounds/#outbounds-redirect), [[selector]](/sail/zh/reference/outbounds/#outbounds-selector), [[shadowsocks]](/sail/zh/reference/outbounds/#outbounds-shadowsocks), [[shadowtls]](/sail/zh/reference/outbounds/#outbounds-shadowtls), [[smart]](/sail/zh/reference/outbounds/#outbounds-smart), [[snell]](/sail/zh/reference/outbounds/#outbounds-missing), [[socks]](/sail/zh/reference/outbounds/#outbounds-socks), [[ssh]](/sail/zh/reference/outbounds/#outbounds-missing), [[tor]](/sail/zh/reference/outbounds/#outbounds-missing), [[trojan]](/sail/zh/reference/outbounds/#outbounds-trojan), [[tryall]](/sail/zh/reference/outbounds/#outbounds-tryall), [[tuic]](/sail/zh/reference/outbounds/#outbounds-tuic), [[urltest]](/sail/zh/reference/outbounds/#outbounds-urltest), [[vless]](/sail/zh/reference/outbounds/#outbounds-vless), [[vmess]](/sail/zh/reference/outbounds/#outbounds-vmess) | `[]` | 支持 | — |
| `route` | object → [对象](/sail/zh/reference/route/#route) | 各字段取默认值 | 支持 | — |
| `services` | array → [[]](#services), [[api]](#services-missing), [[ccm]](#services-missing), [[derp]](#services-missing), [[hysteria-realm]](#services-missing), [[ocm]](#services-missing), [[oom-killer]](#services-missing), [[resolved]](#services-missing), [[ssm-api]](#services-missing), [[usbip-client]](#services-missing), [[usbip-server]](#services-missing) | — | 支持 | — |
| `experimental` | object → [对象](#experimental) | 各字段取默认值 | 支持 | — |
| `api` | 对象 → [对象](#api) | 未设置 | sail 扩展 | The control API |
| `clash_api` | 对象 → [对象](#clash-api) | 未设置 | sail 扩展 | The Clash API, which dashboards (yacd, metacubexd) and clients control the instance through. sing-box has it under `experimental`, which is read too, as the same. |
| `outbound_providers` | 数组，元素为 对象 → [[]](#outbound-providers) | `[]` | sail 扩展 | A sail extension: outbounds given together, downloaded, read from a file or written in place, that groups take as members, as Mihomo's proxy groups take a proxy-provider's proxies. |
| `user_limits` | 对象，值为 对象 → [对象](#user-limits) | `{}` | sail 扩展 | A sail extension: what each user, by name, may do across every inbound it is in. |

<a id="user-limits"></a>

### `user_limits`

Rust 定义：[`UserLimits`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `max_connections` | number | 未设置 | sail 扩展 | How many connections it may have live at once. |
| `max_tcp_connections` | number | 未设置 | sail 扩展 | How many of them may be TCP at once, its UDP sessions not counted; with `max_connections` too, both apply. |
| `quota_bytes` | number | 未设置 | sail 扩展 | How many bytes, up and down together, it may send and receive; kept across restarts in the cache file, which it needs. |
| `expire_at` | string | 未设置 | sail 扩展 | When it may no longer connect, in RFC 3339. |
| `up_mbps` | number | 未设置 | sail 扩展 | Its rate up, what its clients send, in Mbps: the unit of sing-box's Hysteria2 `up_mbps`, not its direction. |
| `down_mbps` | number | 未设置 | sail 扩展 | Its rate down, what its clients receive, in Mbps. |
| `total_mbps` | number | 未设置 | sail 扩展 | Its rate up and down together, in Mbps: both directions draw from it, and from `up_mbps` and `down_mbps` too where they are set. |

<a id="log"></a>

## `log`

Rust 定义：[`Log`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `disabled` | bool | `false` | 支持 | Logs nothing. |
| `level` | string, 取值 `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal`, `panic` | `info` | 支持 | — |
| `output` | string | 未设置 | 支持 | A file to append to. Logs go to the console when it is not set. |
| `timestamp` | bool | `false` | 支持 | Starts each line with the time. |
| `format` | string, 取值 `full`, `compact` | `full` | sail 扩展 | A sail extension: `compact` writes the message alone. |
| `redact` | 数组，元素为 string, 取值 `destination`, `source`, `process` | `[]` | sail 扩展 | A sail extension: what lines at INFO, WARN and ERROR leave out. DEBUG and TRACE lines are not redacted. |

<a id="certificate"></a>

## `certificate`

Rust 定义：[`CertificateOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `store` | string, 取值 `system`, `mozilla`, `chrome`, `none` | `system` | 支持 | — |
| `certificate` | listable-string | `[]` | 支持 | Inline PEM, its lines one to an entry or all in one. |
| `certificate_path` | listable-string | `[]` | 支持 | — |
| `certificate_directory_path` | listable-string | `[]` | 支持 | Directories, every file of which holds certificates. |

<a id="http-clients"></a>

## `http_clients[]`

Rust 定义：[`HttpClient`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Of one in `http_clients`; none inline. |
| `engine` | string, 取值 `go`, `apple` | 未设置 | 支持 | Whose client sing-box downloads with: `go`, its own, when unset, or `apple`, NSURLSession. sail downloads with its own either way, and warns of `apple`. |
| `version` | number, 取值 `0`, `1`, `2`, `3` | 未设置 | 支持 | The HTTP version sing-box asks for, 1, 2 or 3; 2 when unset (or 0). sail downloads over HTTP/1.1 whichever, as sing-box does from a server that speaks no other: a download is the same download. |
| `disable_version_fallback` | bool | `false` | 支持 | `version` alone, never HTTP/1.1 in its place: warned of with 2 or 3, as sail downloads over HTTP/1.1. |
| `headers` | map | `{}` | 支持 | Sent with each request, over sail's own of the same name. |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-http-clients-route-rule-set) | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
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
| `idle_timeout` | duration | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `keep_alive_period` | duration | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `stream_receive_window` | number\|string | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `connection_receive_window` | number\|string | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `max_concurrent_streams` | number | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `initial_packet_size` | number | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `disable_path_mtu_discovery` | bool | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |

<a id="ntp"></a>

## `ntp`

Rust 定义：[`Ntp`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `interval` | duration | 未设置 | 支持 | How often the offset is measured again; 30m when unset. |
| `write_to_system` | bool | `false` | 支持 | Setting the system's clock, which sail never does: an error. |
| `server` | string | 未设置 | 支持 | The server's name or address. |
| `server_port` | number | 未设置 | 支持 | 123 when unset. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | 未设置 | 支持 | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | 未设置 | 支持 | Not implemented yet. |
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

<a id="experimental"></a>

## `experimental`

Rust 定义：[`Experimental`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `cache_file` | object → [对象](#experimental-cache-file) | 未设置 | 支持 | — |
| `clash_api` | object → [对象](#experimental-clash-api) | 未设置 | 支持 | sing-box's place for the Clash API: taken to `clash_api` when the configuration is validated. |
| `v2ray_api` | object → [对象](#experimental-v2ray-api) | — | 警告：V2Ray's statistics API, for watching the instance | — |
| `debug` | object → [对象](#experimental-debug) | — | 警告：Go runtime tuning and debugging: sail is not Go | — |

<a id="experimental-cache-file"></a>

### `experimental.cache_file`

Rust 定义：[`CacheFileOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `path` | string | 未设置 | 支持 | `cache.db` when unset. A relative path is in the host's cache directory, or the data directory. |
| `cache_id` | string | 未设置 | 支持 | What this configuration keeps is kept apart, under this name, from what others sharing the file keep. |
| `store_fakeip` | bool | `false` | 支持 | — |
| `rdrc_timeout` | duration | — | 警告：The cache of the legacy address filter's rejected responses, which sail does not have; deprecated in sing-box 1.14 | — |
| `store_dns` | bool | `false` | 支持 | The DNS answers kept are kept in the file too, and outlive a restart. |
| `store_rdrc` | bool | — | 警告：The cache of the legacy address filter's rejected responses, which sail does not have; deprecated in sing-box 1.14 (sing-box 已弃用) | — |

<a id="experimental-clash-api"></a>

### `experimental.clash_api`

Rust 定义：[`ClashApi`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `external_controller` | string | 未设置 | 支持 | Where it listens, `host:port`; an empty host is every address, as in Mihomo. Unset, it is not served, though `default_mode` still sets the mode rules match. |
| `external_ui` | string | 未设置 | 支持 | A directory of a dashboard's files, served at `/ui/`; relative to the data directory. |
| `external_ui_download_url` | string | 未设置 | 支持 | Where the dashboard is downloaded from, a ZIP, when `external_ui` is empty. The core has none of its own: unset, nothing is downloaded, and a warning says so; a host, such as sail-cli, may give one. |
| `external_ui_download_detour` | string | 未设置 | 支持 | The outbound the download goes through; the default one when unset. |
| `secret` | string | 未设置 | 支持 | What callers authenticate with, `Authorization: Bearer`, or a WebSocket's `?token=`. The API is served only with a strong one (at least 32 characters, 10 distinct): `sail generate secret` makes one. |
| `default_mode` | string | 未设置 | 支持 | The mode rules match at the start, `Rule` when unset. |
| `access_control_allow_origin` | listable-string | `[]` | 支持 | The origins browsers may call it from (CORS); any when empty. |
| `access_control_allow_private_network` | bool | `false` | 支持 | Pages on public addresses may call it on a private one (Private Network Access). |

<a id="experimental-v2ray-api"></a>

### `experimental.v2ray_api`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `listen` | string | — | 警告：V2Ray's statistics API, for watching the instance | — |
| `stats` | object → [对象](#experimental-v2ray-api-stats) | — | 警告：V2Ray's statistics API, for watching the instance | — |

<a id="experimental-v2ray-api-stats"></a>

### `experimental.v2ray_api.stats`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 警告：V2Ray's statistics API, for watching the instance | — |
| `inbounds` | array | — | 警告：V2Ray's statistics API, for watching the instance | — |
| `outbounds` | array | — | 警告：V2Ray's statistics API, for watching the instance | — |
| `users` | array | — | 警告：V2Ray's statistics API, for watching the instance | — |

<a id="experimental-debug"></a>

### `experimental.debug`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `listen` | string | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `gc_percent` | number | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `max_stack` | number | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `max_threads` | number | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `panic_on_fault` | bool | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `trace_back` | string | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `memory_limit` | number\|string | — | 警告：Go runtime tuning and debugging: sail is not Go | — |
| `oom_killer` | bool | — | 报错：Removed in sing-box 1.13, which refuses it: the oom-killer service took its place | — |

<a id="api"></a>

## `api`

Rust 定义：[`Api`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `path` | string | 未设置 | sail 扩展 | The unix socket the API is served on, in the data directory unless absolute; `api.sock` there when neither it nor `listen` is set. |
| `listen` | string | 未设置 | sail 扩展 | A loopback address the API is served on too, as `127.0.0.1:9091`; it takes `secret`. |
| `secret` | string | 未设置 | sail 扩展 | What every call carries, as `Authorization: Bearer <secret>`: one `sail generate secret` makes. Needed with `listen`; on the unix socket, checked when set. |

<a id="clash-api"></a>

## `clash_api`

Rust 定义：[`ClashApi`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `external_controller` | string | 未设置 | sail 扩展 | Where it listens, `host:port`; an empty host is every address, as in Mihomo. Unset, it is not served, though `default_mode` still sets the mode rules match. |
| `secret` | string | 未设置 | sail 扩展 | What callers authenticate with, `Authorization: Bearer`, or a WebSocket's `?token=`. The API is served only with a strong one (at least 32 characters, 10 distinct): `sail generate secret` makes one. |
| `external_ui` | string | 未设置 | sail 扩展 | A directory of a dashboard's files, served at `/ui/`; relative to the data directory. |
| `external_ui_download_url` | string | 未设置 | sail 扩展 | Where the dashboard is downloaded from, a ZIP, when `external_ui` is empty. The core has none of its own: unset, nothing is downloaded, and a warning says so; a host, such as sail-cli, may give one. |
| `external_ui_download_detour` | string | 未设置 | sail 扩展 | The outbound the download goes through; the default one when unset. |
| `access_control_allow_origin` | string 或 数组，元素为 string | `[]` | sail 扩展 | The origins browsers may call it from (CORS); any when empty. |
| `access_control_allow_private_network` | bool | `false` | sail 扩展 | Pages on public addresses may call it on a private one (Private Network Access). |
| `default_mode` | string | 未设置 | sail 扩展 | The mode rules match at the start, `Rule` when unset. |

<a id="outbound-providers"></a>

## `outbound_providers[]`

Rust 定义：[`OutboundProvider`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `remote`, `local`, `inline` | 必填 | sail 扩展 | — |
| `tag` | string | 必填 | sail 扩展 | Its members' keys name it, and groups' `providers`. |
| `url` | string | 未设置 | sail 扩展 | `remote`: where it is downloaded from. |
| `path` | string | 未设置 | sail 扩展 | `local`: the file, in the data directory unless absolute. |
| `update_interval` | duration | 未设置 | sail 扩展 | `remote`: how often it is downloaded again, 1d when unset. `local`: how often the file is read again, never when unset. |
| `download_detour` | string | 未设置 | sail 扩展 | `remote`: the outbound it is downloaded through, as a remote rule-set's. |
| `http_client` | string 或 对象 | 未设置 | sail 扩展 | `remote`: the HTTP client it is downloaded with, as a remote rule-set's. |
| `size_limit` | number | 未设置 | sail 扩展 | `remote`, a sail extension (Mihomo's `size-limit`): the most a download of it may be, in bytes; past it the download fails and the outbounds in use are kept. Unset, the download client's own cap. |
| `filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | `remote`, `local`: regular expressions, as Mihomo's `filter`; only the outbounds whose names match one are taken, those of the first first. |
| `exclude_filter` | string 或 数组，元素为 string | `[]` | sail 扩展 | `remote`, `local`: regular expressions no name taken may match. |
| `exclude_type` | string 或 数组，元素为 string | `[]` | sail 扩展 | `remote`, `local`: the Clash types (`ss`, `vmess`, ...) not taken, without case. |
| `override` | 对象，值为 任意 JSON | 未设置 | sail 扩展 | `remote`, `local`: what is changed in every outbound taken, in the keys of Mihomo's `override` (`skip-cert-verify`, `additional-prefix`, `proxy-name`, ...). |
| `detour` | string | 未设置 | sail 扩展 | `remote`, `local`: the outbound every outbound taken dials through, as Mihomo's `dialer-proxy`. |
| `outbounds` | 数组，元素为 对象 → [[]](#outbound-providers-outbounds) | `[]` | sail 扩展 | `inline`: the outbounds, their tags their names as members. |

<a id="outbound-providers-outbounds"></a>

### `outbound_providers[].outbounds[]`

Rust 定义：[`Outbound`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string | 必填 | sail 扩展 | — |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |

<a id="certificate-providers"></a>

## `certificate_providers[]`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `acme`, `cloudflare-origin-ca`, `tailscale` | — | 报错：Certificates from ACME and other providers: the inbounds would serve none | — |

<a id="network-namespaces"></a>

## `network_namespaces[]`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `default`, `unshare` | — | 报错：Linux network namespaces to listen and dial in | — |
| `tag` | string | 必填 | 报错：Linux network namespaces to listen and dial in | — |
| `path` | string | — | 报错：Linux network namespaces to listen and dial in | — |

<a id="services"></a>

## `services[]`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `api`, `ccm`, `derp`, `hysteria-realm`, `ocm`, `oom-killer`, `resolved`, `ssm-api`, `usbip-client`, `usbip-server` | — | 警告：A service: sail runs none besides its inbounds | — |

<a id="certificate-providers-missing"></a>

## sail 未实现的类型：`certificate_providers`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `certificate_providers[acme]` | 报错：Certificates from ACME and other providers: the inbounds would serve none | 122 |
| `certificate_providers[cloudflare-origin-ca]` | 报错：Certificates from ACME and other providers: the inbounds would serve none | 86 |
| `certificate_providers[tailscale]` | 报错：Certificates from ACME and other providers: the inbounds would serve none | 2 |

<a id="network-namespaces-missing"></a>

## sail 未实现的类型：`network_namespaces`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `network_namespaces[unshare]` | 报错：Linux network namespaces to listen and dial in | 2 |

<a id="services-missing"></a>

## sail 未实现的类型：`services`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `services[api]` | 警告：sing-box's gRPC API, for its clients and dashboard to watch and control the instance | 165 |
| `services[ccm]` | 报错：A service: sail runs none besides its inbounds | 84 |
| `services[derp]` | 报错：A service: sail runs none besides its inbounds | 171 |
| `services[hysteria-realm]` | 报错：A service: sail runs none besides its inbounds | 87 |
| `services[ocm]` | 报错：A service: sail runs none besides its inbounds | 84 |
| `services[oom-killer]` | 报错：A service: sail runs none besides its inbounds | 5 |
| `services[resolved]` | 报错：A service: sail runs none besides its inbounds | 15 |
| `services[ssm-api]` | 报错：A service: sail runs none besides its inbounds | 80 |
| `services[usbip-client]` | 报错：A service: sail runs none besides its inbounds | 37 |
| `services[usbip-server]` | 报错：A service: sail runs none besides its inbounds | 21 |

