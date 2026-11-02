---
title: CLI 参考
description: 使用命令行运行、验证、测试与调优 Sail。
---

`sail-cli` crate 生成 `sail` 可执行文件。未传参数时，程序默认读取当前目录的 `config.json`。

配置格式由扩展名决定：`.json` 为 sing-box JSON（允许注释和末尾逗号），`.yaml` 或 `.yml` 为 Clash/Mihomo YAML，`.conf` 为 Surge 配置。其他扩展名直接报错。三种格式由同一个加载器直接读取，无需先转换。

## 常用命令

```sh
sail -c config.json                 # 启动
sail -c config.json -T              # 验证后退出
sail -c config.json --auto-reload   # 文件变化后重载
sail -V                             # 显示版本
```

## 出站连通性测试

按标签单独测试一个出站，不启动常规监听：

```sh
sail -c config.json -t edge
sail -c config.json -t edge -d 10
```

Sail 会分别报告 TCP、UDP 的耗时或错误。默认超时为 4 秒，`-d` 可调整。该命令只测试指定出站，不代表完整的“应用—入站—路由—出站”链路。

## 运行时配置档

运行时配置档调整内存预算、队列和并发度，不改动可移植的配置文件。

| 配置档 | 适用宿主 |
| --- | --- |
| `mobile` | 手机与内存敏感进程 |
| `desktop` | 默认通用配置 |
| `server` | 高并发与吞吐优先 |
| `router` | 资源紧张的小型设备 |

```sh
sail -c config.json --profile server
```

用可重复的 `--set key=value` 覆盖单个参数。键是以点分隔的路径，值可以是数字、`true`/`false`，或 `10s` 这样的时长。键不存在或值类型不对都会报错。

```sh
sail -c config.json --profile server \
  --set relay.buffer_size=32 \
  --set dns.max_retries=3
```

这些参数描述宿主资源预算，不改变代理行为。协议、DNS 和路由仍应写入配置文件。

参数分组为 `relay`（TCP 转发缓冲区与半关闭后的空闲超时）、`udp`、`netstack`（TUN 协议栈的预算、批量与 TCP 窗口）、`inbound`（握手超时、多路复用接受并发、TCP 发送缓冲区）、`memory`（传输缓冲区共享的增长预算）、`quic`、`ws`、`dns`（`max_retries`、`dualstack_delay`）、`stats`、`lifecycle` 和 `mux`。几个随配置档变化的值：

| 参数 | `desktop` | `mobile` | `router` | `server` |
| --- | --- | --- | --- | --- |
| `relay.buffer_size`（KiB） | `16` | `8` | `4` | `16` |
| `relay.buffer_max_size`（KiB） | `128` | `64` | `64` | `256` |
| `quic.max_concurrent_streams` | `1024` | `256` | `128` | `4096` |
| `inbound.tcp_send_buffer`（KiB，`0` 表示交给系统） | `0` | `0` | `256` | `0` |
| `inbound.tcp_send_buffer_max`（KiB，`0` 表示不增长） | `0` | `0` | `2048` | `0` |
| `inbound.max_connections`（同时存在的会话数，`0` 表示不限） | `0` | `512` | `512`；Linux 上内存不足 276 MiB 时为（MiB − 20）× 2，至少 64 | `0` |
| `lifecycle.drain_timeout` | `0` | `0` | `0` | `30s` |

`lifecycle.drain_timeout` 指收到 SIGTERM 或 Ctrl-C、停止接受新连接后，已有 TCP 连接最多还能继续多久；`0` 表示立即停止，第二次信号总是立即停止。

在 Linux 和 Android 上，接受的 TCP 连接在发送缓冲区限制传输时，可从 `inbound.tcp_send_buffer` 增长到 `inbound.tcp_send_buffer_max`。额外额度取自 `memory.transfer_budget`，与 Hysteria2、TUIC 的窗口共享；Sail 按超过起始大小的申请增量的两倍计入预算，包含内核记账开销。起始大小为 `0`、上限不大于起始大小，或系统不是 Linux、Android 时，不启用增长。

缓冲区持续一秒未满，或写入阻塞一秒后，Sail 在轮询写入时将设置的大小降回起始值。这不会丢弃队列中的数据。超出起始额度的排队内存仍占用预算，按写入时通过 `SO_MEMINFO` 观察到的排空量退回，连接关闭时退回其余额度；若无法查询，则保留额度至连接关闭。空闲连接（包括写入已取消的连接）没有后台任务回收已排空的额度，可能一直占用预算，直到再次写入或关闭。

增长后，Sail 读回实际设置的大小，只退回本次新申请但未用到的额度，保留旧队列仍需的额度。读回失败时，申请的增长额度继续计入预算。关闭连接会退回 Sail 的预留额度，但正常关闭后 TCP 仍可能保留排队内存，因此该预算不保证限制全部内核内存。

`relay` 的各项（包括 `relay.write_stall_timeout`）同样适用于回落（Trojan、VLESS、AnyTLS）、ShadowTLS 与 REALITY 转发到真实站点的连接。

多路复用连接（sing-mux 的 smux 与 yamux、AnyTLS、amux）上的流使用其中三项：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `mux.stream_window_max` | `16384`（KiB）；`mobile` 与 `router` 为 `8192` | 单条流接收窗口的上限（yamux、amux）。窗口从 256 KiB 起步，流读得比窗口放进来的快时翻倍。h2mux 单流取其四分之一，整条连接取其两倍。 |
| `mux.stream_buffer` | `256`（KiB） | 无窗口协议（smux、AnyTLS）的单条流最多积压的未读数据，超过后暂停读取整条连接。 |
| `mux.stall_timeout` | `60s` | 数据积压且这么久没人读的流被单独重置，并记录 `event=stream_stalled`；h2mux 的流同样适用。QUIC 流（Hysteria2、TUIC）固定 60 秒。 |

无窗口协议（smux、AnyTLS）的会话因某条流积压满 `mux.stream_buffer` 而暂停读取连接后，若连接在 `relay.write_stall_timeout`（`300s`）内一个字节也没写出去，会话连同其所有流一起结束：两端都不读时，TCP 连接可能再也不动。

API 的 `/api/v1/runtime/stat/mux` 按协议给出会话数、流数和被重置的停滞流数。

QUIC（Hysteria2、TUIC、`quic` 传输、DNS over QUIC）的 UDP 套接字使用其中两项，各配置档相同：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `quic.udp_receive_buffer` | `7168`（KiB）；移动档与路由器档为 `1024` | 为每个套接字申请的接收缓冲区（`SO_RCVBUF`）：sail 来不及读时系统替它保留的数据报，超出即丢弃。 |
| `quic.udp_send_buffer` | `0`（KiB，交给系统） | 同一批套接字的发送缓冲区（`SO_SNDBUF`）。 |

`0` 表示沿用系统自己的大小：Windows 为 64 KiB，Linux 约 200 KiB。作为对照，sing-box 的 QUIC 申请 7 MiB（`7168`），Chromium 申请 1 MiB（`1024`）。200 KiB 装不下高速发送方的数据：在 50 ms 与 150 ms、不限速的链路上，两个 sail 之间的 Hysteria2 传输有四分之一的数据报丢在这里，速率只有 7 MiB 时的三分之一。系统给的可能比申请的少：Linux 实际保留申请值的两倍，且不超过 `net.core.rmem_max` 与 `net.core.wmem_max`。超过这两项时，只有具备 `CAP_NET_ADMIN`（以 root 运行，或作为可以配置 TUN 的服务运行）sail 才能拿到申请的大小；没有这项权限时（多数容器如此，打包的 systemd 服务也如此），需先调高上限：`sysctl -w net.core.rmem_max=7340032`（写入 `/etc/sysctl.d` 下的文件以长期生效）。实测 2 MiB 在上述链路上已不再丢包，更大的值效果相同；取 7 MiB 而不是 2 MiB 是留余量的判断值，移动档与路由器档的 1 MiB 同样是判断值，未经实测。套接字实际拿到的大小记录在 `debug` 日志里；因上限而没有拿足时，在 `info` 日志里说明一次；系统拒绝时只给出警告，不算错误。经 `detour` 走的 QUIC 连接没有自己的套接字，不受这两项影响。

QUIC 的套接字参数只有这两项。Windows 的 UDP 接收合并（URO，`UDP_RECV_MAX_COALESCED_SIZE`）是有意不提供的，也不应作为优化加进来：在部分 Windows 11 系统上它会悄悄损坏数据报。

## 路由器上的单条 TCP 连接

在带宽高、距离远的链路上，基于 TCP 的协议（Trojan、VLESS、Shadowsocks、VMess 等）跑一个下载，速度最多是接收缓冲区除以往返时延。sail 本身不额外设限，与裸 TCP 相差不到 2%。Linux 在启动时按内存决定缓冲区大小：最大接收缓冲区（`net.ipv4.tcp_rmem` 的第三个值）为空闲内存的 1/128，最小 128 KiB，最大 6 MiB；最大发送缓冲区（`net.ipv4.tcp_wmem`）同理，最小 64 KiB，最大 4 MiB。所有 TCP 套接字合计受 `net.ipv4.tcp_mem` 约束，约为空闲内存的 6–9%，八个占满的接收缓冲区就会让内核进入内存压力状态。

| 内存 | `tcp_rmem` 最大值 | `tcp_mem` 上限 |
| --- | --- | --- |
| 128 MiB | 598 KiB | 7.0 MiB |
| 256 MiB | 1.56 MiB | 18.7 MiB |
| 512 MiB | 3.51 MiB | 42 MiB |
| 1 GiB | 6 MiB | 84 MiB |

单条连接实测速率（Mbit/s），按接收缓冲区和往返时延：

| 接收缓冲区 | 20 ms | 50 ms | 100 ms | 150 ms |
| --- | --- | --- | --- | --- |
| 2 MiB | 479 | 192 | 94 | 62 |
| 4 MiB | 962 | 386 | 187 | 122 |
| 6 MiB | 1305 | 552 | 275 | 176 |
| 6 MiB，服务器 `tcp_wmem` 16 MiB | 1453 | 579 | 283 | 183 |
| 8 MiB，服务器 `tcp_wmem` 16 MiB | 1635 | 650 | 317 | 205 |

以上数据是在测试主机上测得的（两个 sail 之间走 Trojan，网络命名空间加 netem，下载，每组 20 s、共三轮），并非在真实路由器上；路由器的内核更精简，同样内存下的数值会略高一些。再往上的瓶颈是服务器的发送缓冲区：常见 VPS 默认 4 MiB，只调大路由器一侧、超过这个值也不会更快。

在路由器的内存下（运行 sail 路由器构建的 qemu 客户机，内存 128、256、512 MiB，上游经 Trojan、往返 100 ms，服务器发送缓冲区 4 MiB），内核默认上限与上限调到 6 MiB 时的下载速率（Mbit/s）：

| 内存 | 单个，内核上限 | 单个，6 MiB | 同时四个，内核上限 | 同时四个，6 MiB |
| --- | --- | --- | --- | --- |
| 128 MiB | 12–14 | 96–118 | 55–61 | 241–257 |
| 256 MiB | 34–37 | 70–120 | 140–150 | 346–376 |
| 512 MiB | 47–73 | 98–117 | | |

OpenWrt 软件包默认调大这个上限：它的 `tcp_buffers` 选项写入 `/etc/sysctl.d/90-sail-tcp.conf`，保留最小值与默认值，已高于 6 MiB 的上限不动（`uci set sail.main.tcp_buffers=0` 关闭）。其他系统可在路由器上调大接收上限、在服务器上调大发送缓冲区，并分别写入 `/etc/sysctl.d` 下的文件以长期生效：

```sh
# 路由器上：前两个值保持原样，上限 6 MiB
sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456"
# 服务器上
sysctl -w net.ipv4.tcp_wmem="4096 16384 16777216"
```

上限调大本身不占内存：内核只在连接被快速读取时才增大它的缓冲区，所有 TCP 缓冲区合计仍受 `tcp_mem` 约束。在同样的客户机上，让会话数减 24 条的连接停读一分钟而上游持续发送，两种上限下最低可用内存与 sail 自身内存相同，也没有连接因内存被断开。这样的负载下，不论上限多大，每条连接的窗口都会缩小：所有 TCP 套接字都顶到了 `tcp_mem`。

sail 不在自己的连接上设固定的接收缓冲区（`SO_RCVBUF`），那会关掉内核对这些连接的自动调整。在同样的客户机上，这样做单个下载可达 180 Mbit/s，但 128 MiB 下同时四个下载会让全部 TCP 内存进入压力状态（合计 166–231 Mbit/s）。多路复用出站（h2mux、yamux、smux）的所有流共用一条 TCP 连接，这条连接的上限由所有流分摊。Hysteria2 和 TUIC 基于 UDP 上的 QUIC，不受 TCP 缓冲区限制，它们用的是 `quic.udp_receive_buffer`（路由器档为 1 MiB），也是解决长距离链路慢的另一种办法。

## 数据与状态目录

```sh
sail -c config.json \
  --data-dir /opt/sail/data \
  --cache-dir /var/lib/sail
```

数据目录存放 `geo.mmdb`、`site.dat` 和相对路径证书，默认是可执行文件所在目录。缓存目录默认存放 `experimental.cache_file`（选择器的选择、smart 组的站点记忆、Clash 模式，以及开启 `store_fakeip` 时的 fake IP），还缓存下载的远程规则集和 Surge 配置远程 include 的副本。

## 资源文件

部分规则读取数据目录中的数据文件：`geoip` 与 `mmdb:` 外部规则读 `geo.mmdb`，`geosite` 与 `site:` 读 `site.dat`，`ip_asn`（Surge 的 `IP-ASN`）和 `smart` 组的 `prefer_asn` 读 `asn.mmdb`；外部规则或 `asn_file` 也可以指定别的文件。Sail 加载配置时不会下载这些文件；配置需要的文件不存在时加载失败，并给出路径。

```sh
# 配置读取哪些文件、在哪里、是否存在
sail -D /opt/sail/data assets config.json

# 下载缺少的，或全部重新下载
sail -D /opt/sail/data assets config.json --fetch
sail -D /opt/sail/data assets config.json --update

# 换一个地址
sail assets config.json --fetch --source geo.mmdb=https://example.com/Country.mmdb

# 启动前先下载缺少的
sail -c config.json --fetch-assets
```

`sail assets` 每个文件一行：名称、`present` 或 `missing`、路径，以及读取它的字段（如 `route.rules[3].ip_asn`）。下载的文件只有能按 MaxMind 数据库或站点列表读出时才会替换原文件，且不会留下半个文件。默认来源：

| 文件 | 来源 |
| --- | --- |
| `asn.mmdb` | GeoLite2-ASN，与 Mihomo 默认相同：`https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb` |
| `geo.mmdb` | GeoLite2-Country 格式：`https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb` |
| `site.dat` | V2Ray 站点列表：`https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` |

规则自行指定的文件没有默认来源，用 `--source name=url`（启动时用 `--asset-source name=url`）给出。从文件读取或下载的规则集也可能需要 `asn.mmdb`，这只有在加载时才知道，其错误会给出文件路径。

CLI 启动时使用的来源成为宿主的 `asset_sources`，运行中的更新接口从这里取地址：

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/runtime/assets` | 运行中配置读取的资源文件，内容同 `sail assets`，JSON 格式 |
| `POST /api/v1/runtime/assets/{name}/update` | 下载一个文件：地址取请求体的 `url`，否则取宿主的来源；经请求体的 `detour` 出站，否则经默认出站；能读出才替换，随后重载使规则读到新文件。响应说明重载是否成功。配置不读取该名称时 404，没有地址时 400，下载或文件无效时 502 |

## Surge include、Sub-Store 与面板

```sh
# 读取前先下载 Surge 配置 include 的 URL
sail -c profile.conf --cache-dir /var/lib/sail --fetch-includes

# 保持托管的 Surge 配置（#!MANAGED-CONFIG）为最新
sail -c profile.conf --cache-dir /var/lib/sail --managed-update

# 把 sub.store 地址解析到你自己的 Sub-Store 后端
sail -c profile.conf --sub-store https://substore.example.com/secret-path
```

`--fetch-includes` 把 Surge 配置中每个 `#!include https://...`，以及它们再 include 的内容，下载到缓存目录，配置从那里读取。它需要 `--cache-dir`，且配置必须是 `.conf` 文件。某个下载失败时保留已有副本；没有副本则启动失败。

`--managed-update` 按 `#!MANAGED-CONFIG https://... interval=86400 strict=true` 行保持托管的 Surge 配置为最新：距上次更新超过 interval 时（启动时也检查）重新下载配置，像启动时一样加载验证，替换原文件并重载。下载的配置加载不了，或运行中的实例不接受时，原文件保持不变。interval 小于 60 秒按 60 秒算。更新失败后 1 分钟重试，之后间隔逐次翻倍，最长 1 小时且不超过 interval。新配置没有该行时只采用这一次，此后不再更新。上次更新时间保存在缓存目录中，因此需要 `--cache-dir`。同时给了 `--fetch-includes` 时，先下载新配置的 include 再加载。与 Surge 不同：strict 配置过了 interval 而更新失败时，sail 继续使用现有配置，记录错误并重试，不会停止服务。

`--sub-store` 指定基础 URL（含密钥路径），用来替换订阅和规则集 URL 中的 `sub.store`——这是 Sub-Store 在 Surge、Loon 和 Quantumult X 中使用的地址。

`--ui-download-url` 是配置未指定地址时，Clash API 下载到空 `external_ui` 目录的 ZIP。默认是 metacubexd；传空值则不下载。

## 生成密钥

`sail generate` 输出一个密钥或密码后退出：

```sh
sail generate uuid                              # 随机 UUID，供 VLESS、VMess、TUIC 用户使用
sail generate rand 16 --base64                  # 随机字节：原始、--base64 或 --hex
sail generate reality-keypair                   # PrivateKey（服务端）与 PublicKey（客户端）
sail generate wg-keypair                        # WireGuard 密钥对
sail generate ss2022 2022-blake3-aes-128-gcm    # 长度符合该加密方式的密钥
sail generate secret                            # Clash API 密钥（clash_api.secret）
```

`ss2022` 接受 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 或 `2022-blake3-chacha20-poly1305`。

## 导入分享链接

`sail import` 读取分享链接（`ss://`、`trojan://`、`vless://`、`vmess://`、`hysteria2://` 或 `hy2://`、`tuic://`、`anytls://`），以 JSON 输出为 sing-box 出站：

```sh
sail import 'vless://...'
sail import subscription.txt
cat subscription.txt | sail import
```

输入可以是一条链接、一个订阅文件（base64 或每行一条链接），或标准输入。无法读取的行会连同行号输出到 stderr；只有一条链接都没读出时命令才失败。标签会自动去重。ShadowsocksR、Hysteria v1 和 WireGuard 链接不导入。

## 线程

运行时的线程数随档位而定：`desktop` 两个工作线程（单 CPU 时一个），`mobile` 单线程，`server` 与 `router` 每个 CPU 一个工作线程。两个是实测值：同一连接的任务互相唤醒，每个 CPU 一个工作线程时这些唤醒会跨线程，在 Windows 上使 Hysteria2 下行的 CPU 开销翻倍。`--threads` 指定工作线程数，优先于档位。`--single-thread` 适合资源受限的宿主、可复现的调试，或自带外层并发的嵌入场景。`--thread-stack-size` 以字节为单位设置工作线程栈大小（release 构建默认 256 KiB，debug 构建 2 MiB）；除非性能分析表明确有需要，否则保持默认。

在 Unix 上，CLI 启动时会把打开文件数的软限制提高到硬限制（macOS 上不超过 `kern.maxfilesperproc`）。

## 参数速查

| 参数 | 用途 |
| --- | --- |
| `-c`, `--config` | 配置文件，默认 `config.json`；按扩展名区分格式：`.json`、`.yaml`/`.yml`、`.conf` |
| `--auto-reload` | 监听文件变化并重载 |
| `--single-thread` | 使用单线程运行时 |
| `--threads` | 运行时的工作线程数；未指定时取档位的值 |
| `--thread-stack-size` | 工作线程栈大小（字节） |
| `-T`, `--test` | 验证配置后退出 |
| `-t`, `--test-outbound` | 测试指定出站标签 |
| `-d`, `--test-outbound-timeout` | 出站测试超时秒数，默认 `4` |
| `--profile` | `mobile`、`desktop`、`server` 或 `router` |
| `--set` | 覆盖一个运行时参数，可重复 |
| `-D`, `--data-dir` | 资源与相对证书目录 |
| `--cache-dir` | `experimental.cache_file` 的默认位置，也缓存远程规则集和 Surge include |
| `--sub-store` | 自有 Sub-Store 后端的基础 URL，替换 `sub.store` |
| `--ui-download-url` | Clash API 下载到空 `external_ui` 的 ZIP；默认 metacubexd，空值表示不下载 |
| `--fetch-includes` | 启动前把 Surge 配置的远程 include 下载到缓存目录 |
| `--managed-update` | 保持托管的 Surge 配置为最新：超过 interval 后重新下载并重载 |
| `--fetch-assets` | 启动前下载缺少的资源文件 |
| `--asset-source` | `name=url`：资源文件的下载地址，可重复 |
| `assets [config]` | 列出资源文件（未给出时用 `-c` 的配置）；`--fetch`、`--update`、`--source name=url` |
| `generate <kind>` | `rand`、`uuid`、`reality-keypair`、`wg-keypair`、`ss2022`、`secret` |
| `import [input]` | 把分享链接转为 sing-box 出站 JSON |
| `-V`, `--version` | 显示版本 |
| `--help` | 显示用法；也可放在子命令之后 |
