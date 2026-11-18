---
title: "兼容性"
description: "sail 对 sing-box、Clash / Mihomo 与 Surge 配置的支持表，以及与 sing-box、Mihomo 的互通结果。"
---

sail 直接读取 sing-box、Clash / Mihomo 与 Surge 的配置。每种格式都有一张由注册表测试生成的支持表（`docs/compat/`），逐字段列出 sail 实测的处理方式。原生格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段说明见本节其他页面，从[顶层与通用](/sail/zh/reference/common/)开始。

## sing-box

完整表格：[docs/compat/sing-box.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/sing-box.md) · 中文版：[docs/compat/zh/sing-box.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/zh/sing-box.md)

### 汇总

| 部分 | 字段数 | 支持 | 警告 | 报错 |
|---|--:|--:|--:|--:|
| `$schema` | 1 | 1 | 0 | 0 |
| `log` | 5 | 5 | 0 | 0 |
| `dns` | 578 | 367 | 67 | 144 |
| `ntp` | 35 | 35 | 0 | 0 |
| `certificate` | 5 | 5 | 0 | 0 |
| `certificate_providers` | 212 | 0 | 0 | 212 |
| `http_clients` | 80 | 33 | 8 | 39 |
| `network_namespaces` | 6 | 0 | 0 | 6 |
| `endpoints` | 433 | 48 | 13 | 372 |
| `inbounds` | 1367 | 651 | 116 | 600 |
| `outbounds` | 1228 | 700 | 78 | 450 |
| `route` | 268 | 177 | 38 | 53 |
| `services` | 751 | 1 | 166 | 584 |
| `experimental` | 34 | 16 | 17 | 1 |
| **全部** | **5003** | **2039** | **503** | **2461** |

## Clash / Mihomo

完整表格：[docs/compat/clash.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/clash.md) · 中文版：[docs/compat/zh/clash.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/zh/clash.md)

### 汇总

| 部分 | 字段 | 支持 | 警告 | 报错 |
|---|--:|--:|--:|--:|
| `clash-for-android` | 3 | 0 | 3 | 0 |
| `dns` | 33 | 29 | 4 | 0 |
| `experimental` | 5 | 0 | 5 | 0 |
| `external-controller-cors` | 3 | 3 | 0 | 0 |
| `general` | 48 | 35 | 11 | 2 |
| `geox-url` | 5 | 0 | 5 | 0 |
| `iptables` | 5 | 0 | 0 | 5 |
| `listeners[anytls]` | 45 | 11 | 1 | 33 |
| `listeners[http]` | 29 | 19 | 7 | 3 |
| `listeners[hysteria2]` | 49 | 32 | 14 | 3 |
| `listeners[mieru]` | 10 | 0 | 0 | 10 |
| `listeners[mixed]` | 30 | 8 | 1 | 21 |
| `listeners[redir]` | 6 | 4 | 1 | 1 |
| `listeners[shadowquic]` | 34 | 0 | 0 | 34 |
| `listeners[shadowsocks]` | 76 | 7 | 1 | 68 |
| `listeners[snell]` | 41 | 0 | 0 | 41 |
| `listeners[socks]` | 30 | 8 | 1 | 21 |
| `listeners[sudoku]` | 29 | 0 | 0 | 29 |
| `listeners[tproxy]` | 7 | 5 | 1 | 1 |
| `listeners[trojan]` | 73 | 28 | 7 | 38 |
| `listeners[trusttunnel]` | 18 | 0 | 0 | 18 |
| `listeners[tuic]` | 26 | 12 | 11 | 3 |
| `listeners[tun]` | 56 | 37 | 11 | 8 |
| `listeners[tunnel]` | 8 | 6 | 1 | 1 |
| `listeners[vless]` | 93 | 29 | 7 | 57 |
| `listeners[vmess]` | 116 | 28 | 7 | 81 |
| `ntp` | 7 | 7 | 0 | 0 |
| `profile` | 3 | 3 | 0 | 0 |
| `proxies[anytls]` | 38 | 23 | 3 | 12 |
| `proxies[direct]` | 7 | 6 | 1 | 0 |
| `proxies[dns]` | 7 | 1 | 6 | 0 |
| `proxies[easytier]` | 37 | 0 | 0 | 37 |
| `proxies[gost-relay]` | 22 | 0 | 0 | 22 |
| `proxies[http]` | 19 | 17 | 1 | 1 |
| `proxies[hysteria2]` | 50 | 25 | 9 | 16 |
| `proxies[hysteria]` | 35 | 0 | 0 | 35 |
| `proxies[masque]` | 29 | 0 | 0 | 29 |
| `proxies[mieru]` | 17 | 0 | 0 | 17 |
| `proxies[openvpn]` | 37 | 0 | 0 | 37 |
| `proxies[reject]` | 7 | 1 | 6 | 0 |
| `proxies[rematch]` | 9 | 0 | 0 | 9 |
| `proxies[shadowquic]` | 27 | 0 | 0 | 27 |
| `proxies[snell]` | 17 | 0 | 0 | 17 |
| `proxies[socks5]` | 18 | 15 | 1 | 2 |
| `proxies[ss]` | 93 | 25 | 2 | 66 |
| `proxies[ssh]` | 15 | 0 | 0 | 15 |
| `proxies[ssr]` | 16 | 0 | 0 | 16 |
| `proxies[sudoku]` | 31 | 0 | 0 | 31 |
| `proxies[tailscale]` | 16 | 0 | 0 | 16 |
| `proxies[trojan]` | 56 | 39 | 1 | 16 |
| `proxies[trusttunnel]` | 32 | 0 | 0 | 32 |
| `proxies[tuic]` | 41 | 27 | 11 | 3 |
| `proxies[vless]` | 137 | 46 | 1 | 90 |
| `proxies[vmess]` | 128 | 47 | 1 | 80 |
| `proxies[wireguard]` | 64 | 28 | 5 | 31 |
| `proxies[zerotier]` | 30 | 0 | 0 | 30 |
| `proxy-groups` | 24 | 20 | 4 | 0 |
| `proxy-providers` | 39 | 28 | 8 | 3 |
| `rule-providers` | 11 | 9 | 2 | 0 |
| `sniffer` | 12 | 12 | 0 | 0 |
| `tls` | 7 | 0 | 7 | 0 |
| `tuic-server` | 13 | 0 | 0 | 13 |
| `tun` | 51 | 34 | 10 | 7 |
| **All** | **2080** | **714** | **178** | **1188** |

## Surge

完整表格：[docs/compat/surge.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/surge.md) · 中文版：[docs/compat/zh/surge.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/zh/surge.md)

### 汇总

| 部分 | 字段 | 支持 | 静默忽略 | 警告 | 报错 |
|---|--:|--:|--:|--:|--:|
| `General` | 58 | 24 | 29 | 5 | 0 |
| `Keystore` | 3 | 3 | 0 | 0 | 0 |
| `Proxy Group[fallback]` | 16 | 11 | 4 | 1 | 0 |
| `Proxy Group[load-balance]` | 14 | 10 | 4 | 0 | 0 |
| `Proxy Group[select]` | 13 | 9 | 4 | 0 | 0 |
| `Proxy Group[smart]` | 14 | 10 | 4 | 0 | 0 |
| `Proxy Group[ssid]` | 6 | 3 | 3 | 0 | 0 |
| `Proxy Group[subnet]` | 6 | 3 | 3 | 0 | 0 |
| `Proxy Group[url-test]` | 17 | 11 | 4 | 2 | 0 |
| `Proxy[anytls]` | 28 | 18 | 3 | 6 | 1 |
| `Proxy[direct]` | 12 | 5 | 1 | 6 | 0 |
| `Proxy[external]` | 20 | 0 | 0 | 0 | 20 |
| `Proxy[h2-connect]` | 32 | 0 | 0 | 0 | 32 |
| `Proxy[http]` | 24 | 15 | 3 | 6 | 0 |
| `Proxy[https]` | 30 | 20 | 3 | 6 | 1 |
| `Proxy[hysteria2]` | 29 | 18 | 3 | 6 | 2 |
| `Proxy[masque]` | 27 | 0 | 0 | 0 | 27 |
| `Proxy[reject-drop]` | 12 | 2 | 4 | 6 | 0 |
| `Proxy[reject-no-drop]` | 12 | 2 | 4 | 6 | 0 |
| `Proxy[reject-tinygif]` | 12 | 2 | 4 | 6 | 0 |
| `Proxy[reject]` | 12 | 2 | 4 | 6 | 0 |
| `Proxy[snell]` | 28 | 0 | 0 | 0 | 28 |
| `Proxy[socks5-tls]` | 29 | 0 | 0 | 0 | 29 |
| `Proxy[socks5]` | 23 | 14 | 3 | 6 | 0 |
| `Proxy[ss]` | 27 | 17 | 3 | 6 | 1 |
| `Proxy[ssh]` | 25 | 0 | 0 | 0 | 25 |
| `Proxy[tailscale]` | 5 | 0 | 0 | 0 | 5 |
| `Proxy[trojan]` | 30 | 20 | 3 | 6 | 1 |
| `Proxy[trust-tunnel]` | 31 | 0 | 0 | 0 | 31 |
| `Proxy[tuic-v5]` | 27 | 15 | 4 | 6 | 2 |
| `Proxy[tuic]` | 26 | 0 | 0 | 0 | 26 |
| `Proxy[vmess]` | 33 | 23 | 3 | 6 | 1 |
| `Proxy[wireguard]` | 5 | 3 | 0 | 2 | 0 |
| `Rule` | 152 | 59 | 75 | 0 | 18 |
| `SSID Setting` | 6 | 0 | 0 | 6 | 0 |
| `Sections` | 17 | 3 | 3 | 11 | 0 |
| `WireGuard` | 13 | 11 | 0 | 2 | 0 |
| **All** | **874** | **333** | **178** | **113** | **250** |

## Interop with sing-box and Mihomo

完整表格：[docs/compat/interop.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/interop.md) · 中文版：[docs/compat/zh/interop.md](https://github.com/peakpassvpn/sail/blob/master/docs/compat/zh/interop.md)

### 汇总

| 协议族 | 行 |
|---|---|
| Shadowsocks | aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、2022-blake3-aes-128-gcm、2022-blake3-chacha20-poly1305、2022 加 UDP over TCP；aes-256-gcm 与 2022-blake3-aes-128-gcm 上的 smux、yamux、h2mux |
| VMess | tcp、ws、ws 早期数据、grpc、httpupgrade，各自明文与 TLS，各带 smux、yamux、h2mux；加密方式 chacha20-poly1305、none、zero；下表所列行除外 |
| VLESS | 同样的传输层、TLS 与多路复用；TLS 与 REALITY 上的 Vision；tcp（各种多路复用）与 grpc 上的 REALITY；下表所列行除外 |
| Trojan | TLS 上的 tcp、ws、grpc、httpupgrade，各带 smux、yamux、h2mux；REALITY |
| QUIC | Hysteria2（普通与 salamander）；TUIC（UDP native、UDP over QUIC、cubic） |
| 其他 | AnyTLS；ShadowTLS v3（配 Shadowsocks 2022 与 aes-256-gcm）；SOCKS；HTTP（明文与 TLS） |

