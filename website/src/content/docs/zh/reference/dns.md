---
title: "DNS"
description: "sail 原生配置格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段参考。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

<a id="dns"></a>

## `dns`

Rust 定义：[`Dns`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `servers` | array → [[]](#dns-servers), [[dhcp]](#dns-servers-missing), [[fakeip]](#dns-servers-fakeip), [[h3]](#dns-servers-h3), [[hosts]](#dns-servers-hosts), [[https]](#dns-servers-https), [[local]](#dns-servers-local), [[mdns]](#dns-servers-mdns), [[openconnect]](#dns-servers-missing), [[openvpn]](#dns-servers-missing), [[quic]](#dns-servers-quic), [[race]](#dns-servers-race), [[resolved]](#dns-servers-missing), [[sequential]](#dns-servers-sequential), [[tailscale]](#dns-servers-missing), [[tcp]](#dns-servers-tcp), [[tls]](#dns-servers-tls), [[udp]](#dns-servers-udp) | `[]` | 支持 | The servers, each by its tag. None is the system's resolver alone. |
| `rules` | array → [[]](#dns-rules), [[action=evaluate]](#dns-rules-action-evaluate), [[action=predefined]](#dns-rules-action-predefined), [[action=reject]](#dns-rules-action-reject), [[action=respond]](#dns-rules-action-respond), [[action=route]](#dns-rules-action-route), [[action=route-options]](#dns-rules-action-route-options), [[logical]](#dns-rules-logical) | `[]` | 支持 | Which server a query goes to, matched in order. |
| `final` | string | 未设置 | 支持 | The server of the queries no rule matches; the first one when unset. |
| `reverse_mapping` | bool | `false` | 支持 | Remembers the domain of each address the DNS answers that pass through carry, so that connections to the address are routed by the domain. |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | `prefer_ipv4` | 支持 | Which address families names resolve to, and in what order. |
| `timeout` | duration | 未设置 | 支持 | How long one query to one server may take; 10s when unset, as in sing-box. |
| `disable_cache` | bool | `false` | 支持 | No answer is kept: each query goes to its server. |
| `disable_expire` | bool | `false` | 支持 | Answers kept are used however old they are, until the cache is full or cleared. |
| `cache_capacity` | number | 未设置 | 支持 | How many answers are kept; 1024 when unset, and at least that, as in sing-box. |
| `optimistic` | bool\|object → [对象](#dns-optimistic) | 未设置 | 支持 | An answer that has expired is still given, for up to its timeout, while the server is asked again in the background. |
| `client_subnet` | string | 未设置 | 支持 | The EDNS Client Subnet each query carries, unless a rule says otherwise. |
| `independent_cache` | bool | — | 警告：Each server's answers are kept apart, always: what this asks for (sing-box 已弃用) | — |
| `client_strategy` | string, 取值 `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | sail 扩展 | A sail extension: the address families the answers to clients' queries (hijack-dns, a DNS listener) carry, besides what `strategy` and the rules leave out: a family either leaves out is answered with no records. The instance's own lookups keep `strategy`. As Mihomo's `dns.ipv6: false` answers clients, while its connections still resolve IPv6. |

<a id="dns-optimistic"></a>

### `dns.optimistic`

Rust 定义：[`Optimistic`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | 必填 | 支持 | — |
| `timeout` | duration | 未设置 | 支持 | How long after it expired an answer may still be given; 3d when unset, as in sing-box. |

<a id="dns-servers"></a>

## `dns.servers[]`

Rust 定义：[`DnsServer`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `dhcp`, `fakeip`, `h3`, `hosts`, `https`, `local`, `mdns`, `openconnect`, `openvpn`, `quic`, `resolved`, `tailscale`, `tcp`, `tls`, `udp` | 必填 | 支持 | `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, or sail's `race` and `sequential`. |

<a id="dns-servers-fakeip"></a>

## `dns.servers[fakeip]`

Rust 定义：[`FakeIpOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `inet4_range` | string | 未设置 | 支持 | — |
| `inet6_range` | string | 未设置 | 支持 | — |

<a id="dns-servers-h3"></a>

## `dns.servers[h3]`

Rust 定义：[`RemoteOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | — |
| `tls` | object → [对象](#dns-servers-h3-tls) | 未设置 | 支持 | `tls`, `https`, `quic` and `h3`. |
| `path` | string | 未设置 | 支持 | `https` and `h3`. |
| `method` | string | 未设置 | 支持 | `https` and `h3`: `POST`, the default, or `GET` (RFC 8484 §4.1). |
| `headers` | map | `{}` | 支持 | `https` and `h3`: sent with each request; a `Host` one is the host the requests name. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `respect_rules` | bool | `false` | sail 扩展 | A sail extension, as Mihomo's `respect-rules`: the connections go through the outbound the routing rules pick for them, as for a connection from the inbound `dnsclient` to the server, its domain known. |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | A sail extension: the EDNS Client Subnet its queries carry, over any they have, as Mihomo's `ecs` with `ecs-override`. |

<a id="dns-servers-h3-tls"></a>

### `dns.servers[h3].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | — | 报错：A h3 server offers its own | — |
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
| `fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-dns-servers) | — | 报错：Not for a dns server | — |
| `utls` | object → [对象](#dns-servers-h3-tls-utls) | — | 报错：Not for a h3 server | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-dns-servers) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="dns-servers-h3-tls-utls"></a>

### `dns.servers[h3].tls.utls`

Rust 定义：[`OutboundUtls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Not for a h3 server | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | — | 报错：Not for a h3 server | — |

<a id="dns-servers-hosts"></a>

## `dns.servers[hosts]`

Rust 定义：[`HostsOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `path` | listable-string | `[]` | 支持 | Files in the hosts format; the system's own when neither these nor `predefined` are given. |
| `predefined` | map | `{}` | 支持 | Names, and their addresses. A sail extension, as Mihomo's `hosts` has it: a name may be a pattern, `+.a` for a and the names under it, `.a` for those under it alone, a `*` label for any one label; and it may be given another name, whose addresses it takes. |

<a id="dns-servers-https"></a>

## `dns.servers[https]`

Rust 定义：[`RemoteOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | — |
| `tls` | object → [对象](#dns-servers-https-tls) | 未设置 | 支持 | `tls`, `https`, `quic` and `h3`. |
| `path` | string | 未设置 | 支持 | `https` and `h3`. |
| `method` | string | 未设置 | 支持 | `https` and `h3`: `POST`, the default, or `GET` (RFC 8484 §4.1). |
| `headers` | map | `{}` | 支持 | `https` and `h3`: sent with each request; a `Host` one is the host the requests name. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `respect_rules` | bool | `false` | sail 扩展 | A sail extension, as Mihomo's `respect-rules`: the connections go through the outbound the routing rules pick for them, as for a connection from the inbound `dnsclient` to the server, its domain known. |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | A sail extension: the EDNS Client Subnet its queries carry, over any they have, as Mihomo's `ecs` with `ecs-override`. |
| `prefer_h3` | bool | `false` | sail 扩展 | `https`: a sail extension, as Mihomo's `prefer-h3`: queries go over HTTP/3 beside HTTP/2, and over HTTP/3 alone once it answers; over HTTP/2 for a while once it fails. |

<a id="dns-servers-https-tls"></a>

### `dns.servers[https].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | — | 报错：A https server offers its own | — |
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
| `fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-dns-servers) | — | 报错：Not for a dns server | — |
| `utls` | object → [对象](/sail/zh/reference/shared/#utls-dns-servers-outbounds) | 未设置 | 支持 | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-dns-servers) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="dns-servers-local"></a>

## `dns.servers[local]`

Rust 定义：[`LocalOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `domain_resolver` | string\|object → [对象](#dns-servers-local-domain-resolver) | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `prefer_go` | bool | — | 警告：Go's own resolver rather than the system's: sail is not Go | — |
| `neighbor_domain` | listable-string | `[]` | 支持 | Suffixes, each starting with `.`, of the single-label names the LAN devices' addresses answer for, as sing-box's local server has them; `.` for bare single-label names. |
| `domain_strategy` | string | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |

<a id="dns-servers-local-domain-resolver"></a>

### `dns.servers[local].domain_resolver`

Rust 定义：[`DomainResolver`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |
| `timeout` | duration | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |
| `disable_cache` | bool | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |
| `disable_optimistic_cache` | bool | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |
| `rewrite_ttl` | number | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |
| `client_subnet` | string | — | 警告：A local server's servers are the system's, addresses: it has no name to resolve | — |

<a id="dns-servers-mdns"></a>

## `dns.servers[mdns]`

Rust 定义：[`MdnsOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `detour` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `bind_interface` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `inet4_bind_address` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `inet6_bind_address` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `bind_address_no_port` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `protect_path` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `routing_mark` | number\|string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `reuse_addr` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | — |
| `connect_timeout` | duration | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `tcp_fast_open` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `disable_tcp_keep_alive` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `tcp_keep_alive` | duration | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `tcp_keep_alive_interval` | duration | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `udp_fragment` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `domain_resolver` | string\|object → [对象](#dns-servers-mdns-domain-resolver) | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | — |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | — |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | — |
| `fallback_delay` | duration | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `prefer_go` | bool | — | 警告：Go's own resolver rather than the system's: sail is not Go | — |
| `neighbor_domain` | listable-string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `interface` | listable-string | `[]` | 支持 | The interfaces to ask on; all that are up and take multicast when none are named. |
| `domain_strategy` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing (sing-box 已弃用) | — |

<a id="dns-servers-mdns-domain-resolver"></a>

### `dns.servers[mdns].domain_resolver`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `timeout` | duration | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `disable_cache` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `disable_optimistic_cache` | bool | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `rewrite_ttl` | number | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |
| `client_subnet` | string | — | 警告：An mDNS server asks on each interface itself, as sing-box's, which dials nothing | — |

<a id="dns-servers-quic"></a>

## `dns.servers[quic]`

Rust 定义：[`RemoteOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | — |
| `tls` | object → [对象](#dns-servers-quic-tls) | 未设置 | 支持 | `tls`, `https`, `quic` and `h3`. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `respect_rules` | bool | `false` | sail 扩展 | A sail extension, as Mihomo's `respect-rules`: the connections go through the outbound the routing rules pick for them, as for a connection from the inbound `dnsclient` to the server, its domain known. |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | A sail extension: the EDNS Client Subnet its queries carry, over any they have, as Mihomo's `ecs` with `ecs-override`. |

<a id="dns-servers-quic-tls"></a>

### `dns.servers[quic].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | — | 报错：A quic server offers its own | — |
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
| `fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-dns-servers) | — | 报错：Not for a dns server | — |
| `utls` | object → [对象](#dns-servers-quic-tls-utls) | — | 报错：Not for a quic server | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-dns-servers) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="dns-servers-quic-tls-utls"></a>

### `dns.servers[quic].tls.utls`

Rust 定义：[`OutboundUtls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | — | 报错：Not for a quic server | — |
| `fingerprint` | string, 取值 `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized` | — | 报错：Not for a quic server | — |

<a id="dns-servers-race"></a>

## `dns.servers[race]`

Rust 定义：[`RaceOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `servers` | string 或 数组，元素为 string | 必填 | sail 扩展 | A server that asks its members at once and takes the first good answer |

<a id="dns-servers-sequential"></a>

## `dns.servers[sequential]`

Rust 定义：[`SequentialOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs) · **sail 扩展**

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | sail 扩展 | Defaults to the type. |
| `servers` | string 或 数组，元素为 string | 必填 | sail 扩展 | The servers, by tag, in the order they are asked; two or more, none a `race` or `sequential` server. The next is asked only when one gives no answer at all (a timeout, a connection that fails); any answer, SERVFAIL and REFUSED too, ends the query, unlike `race`, which takes those for failures: asked in order, a server's plain answer is not to be passed on to the next. Each goes out as its own `detour` says. |
| `attempt_timeout` | duration | 未设置 | sail 扩展 | How long each server has to answer; the last has what the budget leaves. A kept connection that does not answer in half of it is left for a new one to the same server, with the whole time again, once a query. 3s when unset. |
| `budget` | duration | 未设置 | sail 扩展 | How long a whole query may take, under `dns.timeout`; once it is spent the query fails, and a client is answered SERVFAIL. 8s when unset. |
| `prefer_for` | duration | 未设置 | sail 扩展 | How long a server that answered, not being the first, is asked first (the next ones after it in turn); `0s` keeps the order. 10m when unset. |

<a id="dns-servers-tcp"></a>

## `dns.servers[tcp]`

Rust 定义：[`RemoteOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `respect_rules` | bool | `false` | sail 扩展 | A sail extension, as Mihomo's `respect-rules`: the connections go through the outbound the routing rules pick for them, as for a connection from the inbound `dnsclient` to the server, its domain known. |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | A sail extension: the EDNS Client Subnet its queries carry, over any they have, as Mihomo's `ecs` with `ecs-override`. |

<a id="dns-servers-tls"></a>

## `dns.servers[tls]`

Rust 定义：[`RemoteOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | — |
| `tls` | object → [对象](#dns-servers-tls-tls) | 未设置 | 支持 | `tls`, `https`, `quic` and `h3`. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `respect_rules` | bool | `false` | sail 扩展 | A sail extension, as Mihomo's `respect-rules`: the connections go through the outbound the routing rules pick for them, as for a connection from the inbound `dnsclient` to the server, its domain known. |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | A sail extension: the EDNS Client Subnet its queries carry, over any they have, as Mihomo's `ecs` with `ecs-override`. |

<a id="dns-servers-tls-tls"></a>

### `dns.servers[tls].tls`

Rust 定义：[`OutboundTls`](https://github.com/peakpassvpn/sail/blob/master/sail/src/transport/layers.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `enabled` | bool | `false` | 支持 | — |
| `engine` | string, 取值 `go`, `apple`, `windows` | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `disable_sni` | bool | `false` | 支持 | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`. |
| `server_name` | string | 未设置 | 支持 | Defaults to the server's address. |
| `insecure` | bool | `false` | 支持 | — |
| `alpn` | listable-string | — | 报错：A tls server offers its own | — |
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
| `fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out in TCP segments, cut in its server name, `fragment_fallback_delay` apart. |
| `fragment_fallback_delay` | duration | — | 警告：Only for fragmenting the TLS handshake, which sail does not do | The wait between those segments; unset (or zero), 500ms. sing-box waits for the segment's ACK where it can tell, which sail does not yet. |
| `record_fragment` | bool | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | sing-box 1.12's: the ClientHello goes out as TLS records, cut in its server name, in one write; with `fragment`, each record a segment of its own. |
| `spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `kernel_tx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `kernel_rx` | bool | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `handshake_timeout` | duration | — | 警告：The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them | — |
| `ech` | object → [对象](/sail/zh/reference/shared/#ech-dns-servers) | — | 报错：Not for a dns server | — |
| `utls` | object → [对象](/sail/zh/reference/shared/#utls-dns-servers-outbounds) | 未设置 | 支持 | The browser the ClientHello imitates. Unset, it is Chrome's. |
| `reality` | object → [对象](/sail/zh/reference/shared/#reality-dns-servers) | 未设置 | 支持 | — |
| `certificate_sha256` | string 或 数组，元素为 string | 未设置 | sail 扩展 | sing-box 1.15's, with Mihomo's `fingerprint` semantics beyond it: the SHA-256 hashes, hex or base64, of whole certificates (DER) to take a server by, in place of the certificates trusted and `insecure`. A hash of the server's own certificate takes it outright: no CA and no name are checked, so that exact certificate is trusted for any server name. A hash of a certificate sent after it, an intermediate or a root, is the only CA the server's certificate is verified by, with the server name. With `certificate_public_key_sha256`, either passing is enough. |

<a id="dns-servers-udp"></a>

## `dns.servers[udp]`

Rust 定义：[`RemoteOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/app/dns/client/server.rs)

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
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `server` | string | 未设置 | 支持 | — |
| `server_port` | number | 未设置 | 支持 | — |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `respect_rules` | bool | `false` | sail 扩展 | A sail extension, as Mihomo's `respect-rules`: the connections go through the outbound the routing rules pick for them, as for a connection from the inbound `dnsclient` to the server, its domain known. |
| `client_subnet` | 对象 → [对象](/sail/zh/reference/shared/#client-subnet) | 未设置 | sail 扩展 | A sail extension: the EDNS Client Subnet its queries carry, over any they have, as Mihomo's `ecs` with `ecs-override`. |

<a id="dns-rules"></a>

## `dns.rules[]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `default`, `logical` | `default` | 支持 | `default`, or `logical`. |
| `inbound` | listable-string | `[]` | 支持 | Tags of the inbounds the connection that needs the name came in through. |
| `ip_version` | number, 取值 `4`, `6` | 未设置 | 支持 | — |
| `query_type` | listable-number\|string | `[]` | 支持 | Record types, by name (`A`, `AAAA`, `HTTPS`) or number. |
| `query_client_subnet` | listable-string | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `query_dnssec` | bool | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `network` | listable-string, 取值 `tcp`, `udp` | `[]` | 支持 | — |
| `auth_user` | listable-string | `[]` | 支持 | Names of the users an inbound authenticated. |
| `protocol` | listable-string, 取值 `tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`, `ssh`, `rdp`, `ntp` | `[]` | 支持 | — |
| `domain` | listable-string | `[]` | 支持 | — |
| `domain_suffix` | listable-string | `[]` | 支持 | — |
| `domain_keyword` | listable-string | `[]` | 支持 | — |
| `domain_regex` | listable-string | `[]` | 支持 | — |
| `source_ip_cidr` | listable-string | `[]` | 支持 | — |
| `source_ip_is_private` | bool | `false` | 支持 | — |
| `source_port` | listable-number | `[]` | 支持 | — |
| `source_port_range` | listable-string | `[]` | 支持 | — |
| `port` | listable-number | `[]` | 支持 | — |
| `port_range` | listable-string | `[]` | 支持 | — |
| `process_name` | listable-string | `[]` | 支持 | — |
| `process_path` | listable-string | `[]` | 支持 | — |
| `process_path_regex` | listable-string | `[]` | 支持 | — |
| `package_name` | listable-string | `[]` | 支持 | — |
| `package_name_regex` | listable-string | `[]` | 支持 | — |
| `user` | listable-string | `[]` | 支持 | — |
| `user_id` | listable-number | `[]` | 支持 | — |
| `clash_mode` | string | 未设置 | 支持 | The mode of Clash's API, as in a routing rule. |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The kind of network: `wifi`, `cellular`, `ethernet`, `other`. |
| `network_is_expensive` | bool | `false` | 支持 | The network is metered, as the system says. |
| `network_is_constrained` | bool | `false` | 支持 | The network is in a low data mode, as the system says. |
| `wifi_ssid` | listable-string | `[]` | 支持 | The network the host is on, as the routing rules match it. |
| `wifi_bssid` | listable-string | `[]` | 支持 | The address of the Wi-Fi access point, `aa:bb:cc:dd:ee:ff`, in any case, with `:` or `-`, or as 12 hex digits. |
| `interface_address` | map | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `network_interface_address` | map | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `default_interface_address` | listable-string | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `source_mac_address` | listable-string | `[]` | 支持 | MAC addresses of the LAN device the query comes from, as the neighbor table and DHCP leases know it. |
| `source_hostname` | listable-string | `[]` | 支持 | Host names of the LAN device the query comes from, as its DHCP lease has it. |
| `preferred_by` | listable-string | `[]` | 支持 | Tags of DNS servers: matches a name one of them prefers, one it answers for itself, as sing-box's `preferred_by`. |
| `rule_set` | listable-string | `[]` | 支持 | Tags of rule-sets, any of whose rules matching matches. Their `ip_cidr` rules match no query, which has no address yet. |
| `rule_set_ip_cidr_match_source` | bool | `false` | 支持 | The rule-sets' `ip_cidr` match the source address. |
| `match_response` | bool\|string | 未设置 | 支持 | The response of an `evaluate` rule before it, which the rule then matches: its addresses are what `ip_cidr`, `ip_is_private`, `ip_accept_any` and the rule-sets' `ip_cidr` match. With none, the rule matches only inverted. |
| `ip_cidr` | listable-string | `[]` | 支持 | — |
| `ip_is_private` | bool | `false` | 支持 | — |
| `ip_accept_any` | bool | `false` | 支持 | The response has an address. |
| `response_rcode` | number\|string | 未设置 | 支持 | — |
| `response_answer` | listable-string | `[]` | 支持 | Records the response has among its answers, as `answer` writes them: any of them. |
| `response_ns` | listable-string | `[]` | 支持 | Records the response has among its name servers. |
| `response_extra` | listable-string | `[]` | 支持 | Records the response has among its additional records. |
| `invert` | bool | `false` | 支持 | — |
| `outbound` | listable-string | `[]` | 支持 (sing-box 已弃用) | Tags of the outbounds that dial the name; of the rule itself, not of a rule a logical one combines. |
| `rule_set_ip_cidr_accept_empty` | bool | — | 报错：A condition sail does not match: the rule would match otherwise (sing-box 已弃用) | — |
| `action` | string, 取值 `route`, `evaluate`, `respond`, `route-options`, `reject`, `predefined` | 未设置 | 支持 | `route` when unset. |
| `geosite` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, as in a routing rule. |
| `external` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, as in a routing rule: `site:<file>:<code>`. |
| `process_name_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular expressions the program's name, its path's last part, matches. |
| `wifi_ssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `SSID:`: regular expressions found in the Wi-Fi network's name, with case. |
| `wifi_bssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `BSSID:`: regular expressions found in the access point's address as `aa:bb:cc:dd:ee:ff`, whatever the case. |
| `network_gateway` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `ROUTER:`: the address of the default gateway. |
| `network_mcc_mnc` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `MCCMNC:` and `CELLULAR-CARRIER`: the cellular carrier, its MCC and MNC as 5 or 6 digits; only off Wi-Fi. |
| `ip_match_all` | bool | `false` | sail 扩展 | A sail extension: the rule's conditions on the response's addresses hold for every one of them, rather than for any; a response without one they hold for none. Mihomo's fallback filter keeps an answer so. |

<a id="dns-rules-action-evaluate"></a>

## `dns.rules[action=evaluate]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `race` | bool | `false` | 支持 | `route`, `respond`, `reject` and `predefined`, on a response: the rules after it are matched while its responses are still coming, and the first race rule to match, once they have, decides; the others' actions wait until none of the race rules before them matched. As sing-box 1.14's. |
| `server` | string | 未设置 | 支持 | `route`: the server a matching query goes to. |
| `tag` | string | 未设置 | 支持 | `evaluate`: the name of its response, which `match_response` gives. |
| `speculative` | bool | `false` | 支持 | `route` and `evaluate`: the query is sent as soon as the rule matches, while race rules before it are still pending, rather than once none of them matched; its response is used only then. |
| `timeout` | duration | 未设置 | 支持 | How long the query may take, instead of `dns.timeout`. |
| `disable_cache` | bool | `false` | 支持 | `route`, `evaluate` and `route-options`: the query neither comes from the cache nor goes into it. |
| `disable_optimistic_cache` | bool | `false` | 支持 | An expired answer is not given while it is asked for again, though `dns.optimistic` is enabled. |
| `rewrite_ttl` | number | 未设置 | 支持 | The TTL the answer's records carry, in seconds. |
| `client_subnet` | string | 未设置 | 支持 | The EDNS Client Subnet the query carries, instead of `dns.client_subnet`. |
| `remove_client_subnet` | bool | `false` | 支持 | The query carries no EDNS Client Subnet, whatever it or `dns.client_subnet` has. |
| `strategy` | string | 未设置 | 支持 (sing-box 已弃用) | `route`: the address families, instead of `dns.strategy`. |

<a id="dns-rules-action-predefined"></a>

## `dns.rules[action=predefined]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `race` | bool | `false` | 支持 | `route`, `respond`, `reject` and `predefined`, on a response: the rules after it are matched while its responses are still coming, and the first race rule to match, once they have, decides; the others' actions wait until none of the race rules before them matched. As sing-box 1.14's. |
| `rcode` | number\|string | 未设置 | 支持 | `predefined`: the code of the answer, NOERROR when unset. |
| `answer` | listable-string | `[]` | 支持 | `predefined`: the answer's records, as a zone file writes them (`localhost. IN A 127.0.0.1`, TTL 3600 unless given), or the base64 of their wire form; one named `*.suffix.` takes the name asked for when it ends so. |
| `ns` | listable-string | `[]` | 支持 | `predefined`: its name server records. |
| `extra` | listable-string | `[]` | 支持 | `predefined`: its additional records. |

<a id="dns-rules-action-reject"></a>

## `dns.rules[action=reject]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `race` | bool | `false` | 支持 | `route`, `respond`, `reject` and `predefined`, on a response: the rules after it are matched while its responses are still coming, and the first race rule to match, once they have, decides; the others' actions wait until none of the race rules before them matched. As sing-box 1.14's. |
| `method` | string, 取值 `default`, `drop`, `reply` | — | 警告：How a rejected query is answered: it is rejected all the same | — |
| `no_drop` | bool | — | 警告：How a rejected query is answered: it is rejected all the same | — |

<a id="dns-rules-action-respond"></a>

## `dns.rules[action=respond]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `race` | bool | `false` | 支持 | `route`, `respond`, `reject` and `predefined`, on a response: the rules after it are matched while its responses are still coming, and the first race rule to match, once they have, decides; the others' actions wait until none of the race rules before them matched. As sing-box 1.14's. |

<a id="dns-rules-action-route"></a>

## `dns.rules[action=route]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `race` | bool | `false` | 支持 | `route`, `respond`, `reject` and `predefined`, on a response: the rules after it are matched while its responses are still coming, and the first race rule to match, once they have, decides; the others' actions wait until none of the race rules before them matched. As sing-box 1.14's. |
| `server` | string | 未设置 | 支持 | `route`: the server a matching query goes to. |
| `speculative` | bool | `false` | 支持 | `route` and `evaluate`: the query is sent as soon as the rule matches, while race rules before it are still pending, rather than once none of them matched; its response is used only then. |
| `timeout` | duration | 未设置 | 支持 | How long the query may take, instead of `dns.timeout`. |
| `disable_cache` | bool | `false` | 支持 | `route`, `evaluate` and `route-options`: the query neither comes from the cache nor goes into it. |
| `disable_optimistic_cache` | bool | `false` | 支持 | An expired answer is not given while it is asked for again, though `dns.optimistic` is enabled. |
| `rewrite_ttl` | number | 未设置 | 支持 | The TTL the answer's records carry, in seconds. |
| `client_subnet` | string | 未设置 | 支持 | The EDNS Client Subnet the query carries, instead of `dns.client_subnet`. |
| `remove_client_subnet` | bool | `false` | 支持 | The query carries no EDNS Client Subnet, whatever it or `dns.client_subnet` has. |
| `strategy` | string | 未设置 | 支持 (sing-box 已弃用) | `route`: the address families, instead of `dns.strategy`. |

<a id="dns-rules-action-route-options"></a>

## `dns.rules[action=route-options]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `race` | bool | `false` | 支持 | `route`, `respond`, `reject` and `predefined`, on a response: the rules after it are matched while its responses are still coming, and the first race rule to match, once they have, decides; the others' actions wait until none of the race rules before them matched. As sing-box 1.14's. |
| `timeout` | duration | 未设置 | 支持 | How long the query may take, instead of `dns.timeout`. |
| `disable_cache` | bool | `false` | 支持 | `route`, `evaluate` and `route-options`: the query neither comes from the cache nor goes into it. |
| `disable_optimistic_cache` | bool | `false` | 支持 | An expired answer is not given while it is asked for again, though `dns.optimistic` is enabled. |
| `rewrite_ttl` | number | 未设置 | 支持 | The TTL the answer's records carry, in seconds. |
| `client_subnet` | string | 未设置 | 支持 | The EDNS Client Subnet the query carries, instead of `dns.client_subnet`. |
| `remove_client_subnet` | bool | `false` | 支持 | The query carries no EDNS Client Subnet, whatever it or `dns.client_subnet` has. |
| `strategy` | string | 未设置 | 支持 (sing-box 已弃用) | `route`: the address families, instead of `dns.strategy`. |

<a id="dns-rules-logical"></a>

## `dns.rules[logical]`

Rust 定义：[`DnsRule`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `mode` | string, 取值 `and`, `or` | 未设置 | 支持 | `logical`: `and` or `or`. |
| `rules` | array | `[]` | 支持 | `logical`: the rules combined. |
| `invert` | bool | `false` | 支持 | — |

<a id="dns-servers-missing"></a>

## sail 未实现的类型：`dns.servers`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `dns.servers[dhcp]` | 报错：A type or value sail does not implement: it would route otherwise | 33 |
| `dns.servers[openconnect]` | 报错：A type or value sail does not implement: it would route otherwise | 4 |
| `dns.servers[openvpn]` | 报错：A type or value sail does not implement: it would route otherwise | 4 |
| `dns.servers[resolved]` | 报错：A type or value sail does not implement: it would route otherwise | 3 |
| `dns.servers[tailscale]` | 报错：A type or value sail does not implement: it would route otherwise | 4 |

