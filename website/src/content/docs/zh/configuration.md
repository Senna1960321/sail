---
title: 配置模型
description: 了解 Sail 的 JSON 模型、默认值、验证规则，以及对 Clash 与 Surge 配置的直接读取。
---

Sail 的原生配置就是 sing-box 的 JSON（sing-box 1.14），外加少量 Sail 扩展。与 sing-box 一样，允许注释和尾随逗号。Sail 也能直接读取 Clash / Mihomo 的 YAML 和 Surge 配置：由文件扩展名（`.json`、`.yaml` 或 `.yml`、`.conf`）或文本内容决定格式，三者都会转换为同一个配置模型。格式如何识别见[协议与兼容性](/sail/zh/protocols/#clashsing-box-与-surge-配置生态)。

Sail 不认识的字段会报错。Sail 尚未实现的 sing-box 字段，如果忽略它不影响路由和安全，就丢弃并给出警告，否则报错。启动时会逐条记录这些警告。

## 顶层结构

逐字段查阅请使用自动生成的参考：[顶层与通用](/sail/zh/reference/common/)、[DNS](/sail/zh/reference/dns/)、[入站](/sail/zh/reference/inbounds/)、[出站与策略组](/sail/zh/reference/outbounds/)、[端点](/sail/zh/reference/endpoints/)、[路由](/sail/zh/reference/route/)及[共用对象](/sail/zh/reference/shared/)，并标明每个字段相对 sing-box 的状态；Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

| 字段 | 用途 | 默认值 |
| --- | --- | --- |
| `log` | 日志级别、格式和文件输出 | `info`、完整格式、控制台 |
| `dns` | DNS 服务器、DNS 规则、策略与缓存 | 系统解析器，`prefer_ipv4` |
| `inbounds` | 接收流量的监听器或数据源 | 空 |
| `outbounds` | 直连、代理与策略组 | 空 |
| `endpoints` | 同一标签下既是入站也是出站（WireGuard） | 空 |
| `route` | 有序规则、规则集与最终出站 | 第一个出站 |
| `certificate` | 校验服务器所用的根证书 | 系统证书库 |
| `http_clients` | 按标签定义 Sail 下载规则集和提供者的方式 | 经默认出站 |
| `experimental` | `cache_file` 与 Clash API | 关闭 |
| `api` | Sail 的控制 API，在 Unix socket 或回环地址上（扩展） | 关闭 |
| `clash_api` | Clash API，也可写在 `experimental` 下（扩展） | 关闭 |
| `outbound_providers` | 下载或集中给出、供策略组使用的出站（扩展） | 空 |
| `user_limits` | 跨入站的按用户限制（扩展） | 空 |

sing-box 的 `ntp` 段会被读取：测得的时间用于各协议的时间校验以及 TLS 与 QUIC 的证书有效期校验，系统时钟不会被修改。`server` 请填 IP 地址，或让它的域名经明文 DNS 解析：第一次测得时间之前用的仍是系统时间，若域名经 DoH、DoT 或 DoQ 解析，该 DNS 服务器的证书会按未校正的时间校验，在时钟偏差很大的设备上会失败。sing-box 的 `services`、`certificate_providers` 和 `network_namespaces` 大多会报错。

每个入站、出站和端点都有 `type`，并可设置 `tag`。省略标签时默认使用协议类型；配置中有多个条目后，建议显式命名。

## 入站字段

网络类入站共用以下字段：

```json
{
  "type": "socks",
  "tag": "lan-socks",
  "listen": "127.0.0.1",
  "listen_port": 1080,
  "udp_timeout": "30s"
}
```

`listen` 默认为 `127.0.0.1`。没有 `listen_port` 的入站不会打开监听，只在被其他入站组合使用时有意义。`udp_timeout` 默认 5 分钟。协议专属字段（如 SOCKS 用户、Shadowsocks 凭据）与这些通用字段并列。

## 出站字段与模块

出站从协议及其连接信息开始：

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

流式代理协议可以在协议外层组合通用模块：

| 模块 | 控制内容 |
| --- | --- |
| `tls` | TLS、证书、ALPN、ECH、REALITY 与浏览器 ClientHello |
| `transport` | WebSocket、HTTP Upgrade、gRPC 或 QUIC |
| `multiplex` | 在共享连接上运行 sing-mux（smux、yamux、h2mux） |
| `detour` | 经另一个出站连接本出站的服务器 |
| 拨号字段 | 网卡、本地地址、Linux 标记、超时、keepalive 与域名解析 |

支持哪些模块取决于协议。TUIC、Hysteria2 等原生 QUIC 协议自行管理 TLS 配置，并不接受所有流式传输模块。各层说明见[协议与兼容性](/sail/zh/protocols/#传输层与安全)。

### 拨号字段

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

拨号字段与 sing-box 相同：`bind_interface`、`inet4_bind_address`、`inet6_bind_address`、`routing_mark`（Linux）、`reuse_addr`、`connect_timeout`、`tcp_fast_open`、TCP keepalive 相关字段、`udp_fragment`、`domain_resolver`，以及 `network_strategy` 及其 `network_type`、`fallback_network_type`、`fallback_delay`。`route.default_interface`、`route.default_mark`、`route.default_domain_resolver` 和 `route.default_network_strategy` 为没有自行设置的出站提供默认值。哪些字段在哪里受支持，见[共用对象](/sail/zh/reference/shared/)参考。

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

服务器类型有 `local`、`hosts`、`udp`、`tcp`、`tls`、`quic`、`https`、`h3`、`fakeip` 和 `mdns`，另有 Sail 的 `race`：同时询问所有成员，采用第一个有效应答。sing-box 的 `dhcp`、`resolved`、`tailscale`、`openvpn` 和 `openconnect` 服务器会报错。没有配置服务器时由系统解析器应答。DNS 规则按顺序选择服务器，其余查询交给 `final`，未设置时交给第一个服务器。

`strategy` 可取 `prefer_ipv4`（默认）、`prefer_ipv6`、`ipv4_only` 或 `ipv6_only`。缓存容量为 1024 条，`cache_capacity` 更大时以其为准；对单个服务器的一次查询最长 10 秒，可用 `timeout` 修改。反向映射记住 DNS 应答对应的域名，让后续仅携带 IP 的连接仍能命中域名规则。Sail 的 `client_strategy` 限制返回给客户端查询的地址族，不影响 Sail 自身的解析。

### 本地链路上的名字（mDNS）

`mdns` 服务器（`{ "type": "mdns", "tag": "lan", "interface": ["en0"] }`，`interface` 为空时用所有支持组播的网卡）以组播 DNS 解析 `.local` 名字和链路本地的反向区。非 Apple 系统上，`local` 服务器遇到这些名字也会自己走 mDNS；Apple 系统上交给系统解析器。DNS 规则的 `preferred_by` 列出服务器，匹配它们自己能回答的名字：`hosts` 服务器的条目，`local` 的 hosts 文件与 mDNS 名字，`mdns` 的 mDNS 名字。

与 sing-box 不同，sail 的查询要求单播回复（RFC 6762 的 QU 位）：Windows 只回答这种查询，所以 sing-box 解析不到 Windows 机器的 `.local` 名字，sail 可以。另外，任一网卡答到就立即返回，不必等满一秒。

## 日志与控制 API

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

日志级别有 `trace`、`debug`、`info`、`warn`（或 `warning`）和 `error`；`fatal` 与 `panic` 也接受，效果同 `error`。`disabled` 关闭全部日志，`timestamp` 在每行开头加时间。`format: compact` 是 Sail 扩展，只输出消息本身。不设置 `output` 时输出到控制台。控制台是终端时才带颜色，管道或 systemd journal 不带；设置环境变量 `NO_COLOR` 后终端也不带颜色（对应 sing-box 的 `--disable-color`）。

设置了 `api` 才会提供 API。默认在 Unix socket 上，即数据目录下的 `api.sock`（用 `path` 指定别处），只有运行 Sail 的用户能打开。`listen` 让它同时在回环地址上提供，例如 `127.0.0.1:9091`，此时必须设置 `secret`：用 `sail generate secret` 生成，每次调用以 `Authorization: Bearer <secret>` 携带，缺少或错误时返回 401。本机任何进程都能连上回环端口，而经网络发送的密钥是明文，所以 `listen` 只接受回环地址；要从别处访问，请用 SSH 隧道或反向代理。Unix socket 上设置了 `secret` 时也会校验。错误以 JSON 返回，形如 `{"error": {"code": "invalid", "message": "..."}}`；重载失败时也这样返回原因，原来的配置继续运行。

管理 API：`GET /api/v1` 返回本构建的版本和特性。`/api/v1` 之内只增不减，客户端应忽略不认识的路由和字段；去掉或改动它们的改动放到 `/api/v2` 下。以下路由都在 `/api/v1/runtime` 之下：

| 路由 | 作用 |
| --- | --- |
| `GET /users`、`GET /users/{name}` | 按名字列出用户：所在入站、能否连接（`active`、`over_quota`、`expired`）、限制、流量、活动连接数和已用配额 |
| `PUT /users/{name}/limits` | 按请求体限制该用户，到下次重载为止。请求体可以是 GET 返回的 `limits`，原样 PUT 回去即可（时间为 `expire_at_ms`，Unix 毫秒）；也可以按 `user_limits` 中一个用户的写法（`expire_at` 为 RFC 3339）。返回 204 |
| `DELETE /users/{name}/limits` | 恢复为配置文件中的限制；返回 204 |
| `POST /users/{name}/quota/reset` | 已用流量不再计入配额；返回 204 |
| `POST /users/{name}/disconnect` | 断开该用户的连接，返回 `{"closed": n}`；之后它仍可重新连接 |
| `GET /stats` | 按用户、入站、出站给出流量；`?clear=true` 表示自上次这样读取以来的增量，不影响配额 |
| `GET /status` | 总流量、连接数和内存 |
| `GET /events` | 以 Server-Sent Events 推送用户的变化：`shut`（超额或到期，已断开）与 `removed`（被移出入站），数据为该事件的 JSON；订阅方落后太多时收到 `lagged`，带事件类别 `kind` 和漏掉的条数 `missed`。`?kinds=connection`（或 `user,connection`；不给时只有 `user`）另推送 `connection` 事件：每个连接关闭时的记录，含自连接开始起的上下行字节、用户、入站、客户端连接的本端地址、目的地、出站和出站链、时间、结束方式和使用结果（`ok`、`dial_failed`、`blocked`、`rejected`）（见 `docs/embed.md` 的 `Kinds::CONNECTION`）；连接的关闭记录等于其用户被计的流量 |
| `GET /connections`、`DELETE /connections`、`DELETE /connections/{id}` | 列出进行中的连接，关闭全部或其中一条 |
| `GET /admission` | 内存紧张时的准入自实例启动以来做了什么：`{"level": "off" | "normal" | "pressure" | "hard", "free", "reserve", "handshakes", "refused", "refused_sources", "refused_quic", "evicted", "evicted_full", "pressure_ms", "host_refused", "host_panics"}`，最后两项是嵌入方自己的检查按原因拒绝的数量，以及其中 panic 的次数。`GET /events?kinds=admission` 在级别每次变化时另推送 `admission` 事件（`{"level", "free", "reserve", "handshakes"}`） |
| `POST /connections/report` | 立即做一轮中间记录：向 `connection` 事件的订阅方（`GET /events?kinds=connection`）推送每个进行中连接的记录，空闲的也算；返回 `{"recorded": n}`。按流量计费的主机可按自己的周期调用，也可在正常停止前调用 |
| `POST /reload`、`POST /shutdown` | 重载配置文件，或停止。重载的响应给出每个入站的结果：`{"inbounds": [{"tag", "change"}]}`，`change` 为 `untouched`、`reloaded`（换了用户或证书）、`added`、`removed`、`replaced` 之一；只有被移除和被替换的入站的连接会断开。配置文件增加、移除或修改了 TUN 时返回 409（`needs_restart`），此时什么都没有变 |
| `GET /inbounds` | 列出入站：tag、类型、监听地址，以及运行中能否修改用户（`reloadable`） |
| `POST /inbounds`、`DELETE /inbounds/{tag}`、`POST /outbounds`、`DELETE /outbounds/{tag}` | 增删一个入站或出站，格式同配置文件 |
| `PUT /inbounds/{tag}` | 用请求体（完整的入站配置）替换一个可热更新入站的用户和证书，不重新绑定端口；返回 204 |
| `GET /inbounds/{tag}/users` | 该入站的用户名列表，从不返回凭据 |
| `POST /inbounds/{tag}/users` | 增加一个用户，格式同该入站的 `users`，必须有名字；返回 201，同名已存在时返回 409 |
| `PUT /inbounds/{tag}/users/{name}` | 替换该用户的凭据，例如改密码；已有连接不断开，与 sing-box 一致；返回 204 |
| `DELETE /inbounds/{tag}/users/{name}` | 把该用户移出入站，并断开它经这个入站的连接；返回 204 |

对不可热更新的入站修改用户，返回 422（`unsupported`）：请改配置文件后重载。

经 API 做的修改不写回配置文件：重载或重启以文件为准。经 API 增加、而配置文件里没有的入站，会在下一次重载时被移除，所以要同时写进配置文件。没有入站包含的用户返回 404。
供面板使用的 Clash API 写在 `clash_api` 或 sing-box 的 `experimental.clash_api` 中，二者只能选一。

## Sail 扩展

以下字段是 Sail 自有的，sing-box 不接受。完整列表在[兼容性](/sail/zh/reference/compatibility/)页面所链接的 sing-box 支持表末尾。

- `outbound_providers`：下载（`remote`）、从文件读取（`local`）或直接写在配置中（`inline`）的一组出站，对应 Mihomo 的 proxy-providers。下载内容或文件可以是带 `proxies` 的 Clash YAML，也可以是分享链接。`selector`、`urltest`、`fallback`、`load-balance` 和 `smart` 组通过 `providers` 使用它们，详见[路由规则](/sail/zh/routing/#策略组与提供者)。
- `user_limits`：按用户名设置，作用于该用户所在的所有入站：`max_connections`、`max_tcp_connections`（只计 TCP 连接和多路复用的流，不计 UDP 会话；两者都设时都生效）、`quota_bytes`（上下行合计；需要 `experimental.cache_file`）、`expire_at`（RFC 3339），以及 `up_mbps`、`down_mbps` 和 `total_mbps`（上下行合计：每个已设的速率都允许时字节才通过）。未写的字段不限制；任何字段都不能为 0。通过管理 API 设置的限额在重载后仍覆盖这里的配置，除非重载改了该用户的配置限额：这时覆盖被丢弃，重载报告的 `user_limits_dropped` 列出该用户。
- `api`，以及顶层的 `clash_api`。
- 路由方面的扩展，如 `geoip`、`geosite`、`external`、`ip_asn` 和 `no_resolve`，以及 `fallback`、`load-balance`、`smart`、`network`、`tryall` 和 `pass` 出站。详见[路由规则](/sail/zh/routing/)与[协议与兼容性](/sail/zh/protocols/)。

## 重要验证规则

- `route.final`、路由规则、策略组和 detour 引用的标签必须存在；规则和解析器引用的 DNS 服务器也必须存在。
- 对所有连接都会结束匹配的规则（`route`、`reject`，或带出站的 `bypass`）至少需要一个条件；全量兜底应使用 `route.final`。
- 动作字段只属于对应动作：`sniffer`、`skip_rule_set` 属于 `sniff`；`server`、`strategy` 属于 `resolve`；`timeout` 属于两者之一；`method` 属于 `reject`。`override_destination` 属于 `sniff`、`route` 和 `route-options`，其中 `"at_sniff"` 只能用于 `sniff`。
- `route.auto_detect_interface` 与 `route.default_interface` 不能同时设置。
- `route.default_network_strategy` 需要开启 `route.auto_detect_interface`。
- DNS、UDP、嗅探等超时必须大于零。

开了 `auto_route` 的 TUN 入站会自动开启网卡检测，详见[防止 TUN 回环](/sail/zh/routing/#防止-tun-回环)。

每次修改后运行 `sail -c config.json -T`。连通性测试与运行时设置见 [CLI 参考](/sail/zh/cli/)。

## Clash 与 Surge 文件

`sail -c config.yaml` 读取 Clash / Mihomo 配置，`sail -c profile.conf` 读取 Surge 配置，都转换为上面的模型。Surge 配置引用的文件从其所在目录读取，若由宿主下载，则从宿主的缓存中读取。各格式中 Sail 忽略或拒绝的设置列在[兼容性](/sail/zh/reference/compatibility/)表中。leaf 旧的 `.conf` 格式已不再支持：`.conf` 文件一律按 Surge 配置读取。
