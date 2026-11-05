<h1 align="center">Sail</h1>

<p align="center">
<img src="https://github.com/peakpassvpn/sail/actions/workflows/ci.yml/badge.svg">
</p>

<p align="center">
A proxy platform in Rust: one core for clients, servers and relays.
</p>

<p align="center">
English · <a href="README.zh.md">简体中文</a> · <a href="https://peakpassvpn.github.io/sail/">Documentation</a>
</p>

Sail runs as a command-line client or server, inside an app through its C ABI, or on a router. It reads sing-box JSON as its native format, and it also reads Clash/Mihomo YAML and Surge profiles as they are. Behaviour follows sing-box 1.14 and Mihomo; where Sail differs on purpose, the documentation says so.

Sail started as a fork of [leaf](https://github.com/eycorsican/leaf) by eycorsican and is now developed on its own. It no longer tracks upstream: the configuration, the FFI, the TCP/IP stack and the TLS stack have all been replaced.

> **Status:** under active development. There is no stable release yet; build from source.

## Features

- **Protocols**: SOCKS, HTTP, Mixed (inbound), Shadowsocks (AEAD and 2022), Trojan, VMess, VLESS (Vision, XUDP), Hysteria2, TUIC, AnyTLS, ShadowTLS v3, MPTP (redundant multi-path), and WireGuard as an endpoint. Most are both inbound and outbound; the [protocols page](https://peakpassvpn.github.io/sail/protocols/) has the details.
- **Transports**: TLS, REALITY, WebSocket, HTTPUpgrade, gRPC, QUIC, multiplexing (smux, yamux, h2mux) and UDP over TCP.
- **TLS**: BoringSSL only. Outbounds send a real browser's ClientHello (Chrome by default; Firefox, Safari, iOS and Android profiles), with ECH and certificate pinning.
- **Routing**: sing-box rules and rule actions, logical rules, source and binary rule-sets, sniffing, a structured DNS with its own rules, and fake IP.
- **Groups**: selector, URL test, fallback, load balance, smart and network groups, plus subscriptions (providers) with filters.
- **Transparent proxying**: TUN on Linux, macOS, Windows, iOS and Android, on Sail's own user-space TCP/IP stack, with automatic routes; redirect and TPROXY on Linux.
- **Networks**: follows interface and network changes, closing only the connections they break; picks or races interfaces per outbound (`network_strategy`).
- **Servers**: many users per inbound, per-user traffic statistics, connection limits, quotas, expiry and rate limits; systemd packaging.
- **Control**: the Clash API (dashboards work as they are) and a C ABI with Swift and Kotlin bindings for apps.

The complete, measured list of what Sail takes from each format is in the [compatibility tables](https://peakpassvpn.github.io/sail/reference/compatibility/).

## Quick start

Building needs Rust, CMake and a C/C++ compiler: BoringSSL is compiled from source. On Windows (MSVC), BoringSSL's assembly also needs [NASM](https://www.nasm.us/) on `PATH`; without it the build stops.

```sh
cargo build -p sail-cli --release
```

Save a configuration as `config.json`:

```json
{
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
```

Check it, then run it:

```sh
./target/release/sail -c config.json -T
./target/release/sail -c config.json
```

A Clash/Mihomo or Surge configuration is passed the same way with `-c`; the extension says which format it is: `.json` for sing-box, `.yaml` or `.yml` for Clash, `.conf` for Surge. See [Getting started](https://peakpassvpn.github.io/sail/getting-started/) for the next steps.

## Documentation

- [Local commit checks](docs/contributing.md)

- [Documentation site](https://peakpassvpn.github.io/sail/): getting started, configuration, protocols, routing, the CLI, platform integration and a field-by-field reference.
- [Compatibility with sing-box, Clash and Surge](docs/compat/)
- [FFI contract](docs/ffi.md) for apps
- [Roadmap](docs/roadmap.md)

## License

Licensed under the [Apache License 2.0](LICENSE). Code from leaf keeps its original copyright. Third-party licenses are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
