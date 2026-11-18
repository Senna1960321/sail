//! What sing-box 1.14 accepts and sail does not implement, and how each is
//! treated. A field sing-box does not know either is left to the schema,
//! which rejects it as a mistake.

/// How a field sail does not implement is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Ignoring it would route or secure traffic otherwise than the
    /// configuration says: an error.
    Unsupported,
    /// Ignoring it changes no routing or security: a warning, and the field
    /// is dropped.
    Ignored,
}

use Tier::*;

/// Fields sail does not implement, treated alike for one reason.
pub struct Group {
    /// Why, in a line: the support tables show it.
    pub why: &'static str,
    pub tier: Tier,
    /// The types of the entries (the inbounds, outbounds, DNS servers) the
    /// fields are in that sail lacks them in; in every type when empty.
    pub types: &'static [&'static str],
    /// The fields by path, `*` standing for any list index or object key,
    /// and `key[type]` for the object at `key` when of that type. A rule's
    /// field, `….rules.*.field`, is the field of the rules a logical one
    /// combines too, however deep.
    pub paths: &'static [&'static str],
}

const fn g(why: &'static str, tier: Tier, paths: &'static [&'static str]) -> Group {
    Group {
        why,
        tier,
        types: &[],
        paths,
    }
}

/// `g`, for entries of `types` only.
const fn t(
    why: &'static str,
    tier: Tier,
    types: &'static [&'static str],
    paths: &'static [&'static str],
) -> Group {
    Group {
        why,
        tier,
        types,
        paths,
    }
}

/// Removed without a word: `$schema` only points editors at a schema.
pub const SILENT: &[&str] = &["$schema"];

/// The services, by type, whose absence changes nothing about the traffic,
/// with what each is: sail does not run them, and drops them with a
/// warning. It runs no other service either, and any other is an error.
pub const IGNORED_SERVICES: &[(&str, &str)] = &[(
    "api",
    "sing-box's gRPC API, for its clients and dashboard to watch and control the instance",
)];

/// Why a service other than those is an error.
pub const OTHER_SERVICES: &str = "A service: sail runs none besides its inbounds";

/// An inbound's fields sing-box 1.11 moved to rule actions and 1.13
/// removed: refused as sing-box refuses them, but at their zero value,
/// which it takes as unset.
pub const LEGACY_INBOUND: &[&str] = &[
    "sniff",
    "sniff_override_destination",
    "sniff_timeout",
    "domain_strategy",
    "udp_disable_domain_unmapping",
];

/// Why, in sing-box's words.
pub const LEGACY_INBOUND_WHY: &str = "legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0; use rule actions: https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions";

/// Objects sail has no counterpart for, dropped once the fields they held
/// are.
pub const EMPTIED: &[&str] = &["experimental"];

// Reasons several groups share.
const NETWORKS: &str =
    "Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say";
const NETNS: &str = "Linux network namespaces: sockets would leave another way";
const SOCKET: &str = "Socket tuning: connections go the same way without it";
const TLS_CIPHERS: &str =
    "TLS cipher suites and key exchanges: sail's TLS would negotiate others than asked";
const TLS_TUNING: &str =
    "The TLS stack, kernel TLS and the handshake's timeout: the same TLS without them";
const TLS_FRAGMENT: &str = "Fragmenting or spoofing the TLS handshake against censorship";
const HTTP_TUNING: &str = "HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download";
const QUIC_TUNING: &str = "QUIC tuning: the same connection without it";
const CONDITIONS: &str = "A condition sail does not match: the rule would match otherwise";
const LISTEN: &str = "Where and how an inbound listens: it would take connections otherwise";

pub const GROUPS: &[Group] = &[
    // Top level.
    g(
        "Certificates from ACME and other providers: the inbounds would serve none",
        Unsupported,
        &["certificate_providers"],
    ),
    g(
        "Linux network namespaces to listen and dial in",
        Unsupported,
        &["network_namespaces"],
    ),
    g(
        "The cache of the legacy address filter's rejected responses, which sail does not have; deprecated in sing-box 1.14",
        Ignored,
        &[
            "experimental.cache_file.store_rdrc",
            "experimental.cache_file.rdrc_timeout",
        ],
    ),
    g(
        "V2Ray's statistics API, for watching the instance",
        Ignored,
        &["experimental.v2ray_api"],
    ),
    // Before the object it is in, which is dropped.
    g(
        "Removed in sing-box 1.13, which refuses it: the oom-killer service took its place",
        Unsupported,
        &["experimental.debug.oom_killer"],
    ),
    g(
        "Go runtime tuning and debugging: sail is not Go",
        Ignored,
        &["experimental.debug"],
    ),
    g(
        "sing-box removed it in 1.12, and ignores it",
        Ignored,
        &["route.geoip", "route.geosite"],
    ),
    // DNS.
    g(
        "Each server's answers are kept apart, always: what this asks for",
        Ignored,
        &["dns.independent_cache"],
    ),
    g(
        CONDITIONS,
        Unsupported,
        &[
            "dns.rules.*.query_client_subnet",
            "dns.rules.*.query_dnssec",
            "dns.rules.*.source_geoip",
            "dns.rules.*.geoip",
            "dns.rules.*.interface_address",
            "dns.rules.*.network_interface_address",
            "dns.rules.*.default_interface_address",
            "dns.rules.*.rule_set_ip_cidr_accept_empty",
        ],
    ),
    g(
        "How a rejected query is answered: it is rejected all the same",
        Ignored,
        &["dns.rules.*.method", "dns.rules.*.no_drop"],
    ),
    // HTTP clients.
    g(
        "TLS options of an HTTP client's own: its downloads would be checked otherwise",
        Unsupported,
        &["http_clients.*.tls", "route.rule_set.*.http_client.tls"],
    ),
    g(
        NETNS,
        Unsupported,
        &["http_clients.*.netns", "route.rule_set.*.http_client.netns"],
    ),
    g(
        HTTP_TUNING,
        Ignored,
        &[
            "http_clients.*.idle_timeout",
            "http_clients.*.keep_alive_period",
            "http_clients.*.stream_receive_window",
            "http_clients.*.connection_receive_window",
            "http_clients.*.max_concurrent_streams",
            "http_clients.*.initial_packet_size",
            "http_clients.*.disable_path_mtu_discovery",
            "route.rule_set.*.http_client.idle_timeout",
            "route.rule_set.*.http_client.keep_alive_period",
            "route.rule_set.*.http_client.stream_receive_window",
            "route.rule_set.*.http_client.connection_receive_window",
            "route.rule_set.*.http_client.max_concurrent_streams",
            "route.rule_set.*.http_client.initial_packet_size",
            "route.rule_set.*.http_client.disable_path_mtu_discovery",
        ],
    ),
    g(
        SOCKET,
        Ignored,
        &[
            "http_clients.*.tcp_multi_path",
            "route.rule_set.*.http_client.tcp_multi_path",
        ],
    ),
    // DNS servers.
    g(
        "Go's own resolver rather than the system's: sail is not Go",
        Ignored,
        &["dns.servers.*.prefer_go"],
    ),
    g(NETNS, Unsupported, &["dns.servers.*.netns"]),
    g(
        NETWORKS,
        Unsupported,
        &[
            "dns.servers.*.network_strategy",
            "dns.servers.*.network_type",
            "dns.servers.*.fallback_network_type",
        ],
    ),
    g(
        SOCKET,
        Ignored,
        &[
            "dns.servers.*.tcp_multi_path",
        ],
    ),
    t(
        "An mDNS server asks on each interface itself, as sing-box's, which dials nothing",
        Ignored,
        &["mdns"],
        &[
            "dns.servers.*.detour",
            "dns.servers.*.bind_interface",
            "dns.servers.*.inet4_bind_address",
            "dns.servers.*.inet6_bind_address",
            "dns.servers.*.routing_mark",
            "dns.servers.*.connect_timeout",
            "dns.servers.*.disable_tcp_keep_alive",
            "dns.servers.*.tcp_keep_alive",
            "dns.servers.*.tcp_keep_alive_interval",
            "dns.servers.*.domain_resolver",
            "dns.servers.*.domain_strategy",
            // In the local options sing-box's mdns server takes, and
            // unused by it.
            "dns.servers.*.neighbor_domain",
            "dns.servers.*.bind_address_no_port",
            "dns.servers.*.reuse_addr",
            "dns.servers.*.tcp_fast_open",
            "dns.servers.*.udp_fragment",
            "dns.servers.*.fallback_delay",
            "dns.servers.*.protect_path",
        ],
    ),
    t(
        "A local server's servers are the system's, addresses: it has no name to resolve",
        Ignored,
        &["local"],
        &["dns.servers.*.domain_resolver", "dns.servers.*.domain_strategy"],
    ),
    g(
        TLS_CIPHERS,
        Unsupported,
        &[
            "dns.servers.*.tls.cipher_suites",
            "dns.servers.*.tls.curve_preferences",
        ],
    ),
    g(
        TLS_FRAGMENT,
        Unsupported,
        &[
            "dns.servers.*.tls.fragment",
            "dns.servers.*.tls.record_fragment",
            "dns.servers.*.tls.spoof",
            "dns.servers.*.tls.spoof_method",
        ],
    ),
    g(
        "Only for fragmenting the TLS handshake, which sail does not do",
        Ignored,
        &["dns.servers.*.tls.fragment_fallback_delay"],
    ),
    g(
        TLS_TUNING,
        Ignored,
        &[
            "dns.servers.*.tls.engine",
            "dns.servers.*.tls.kernel_tx",
            "dns.servers.*.tls.kernel_rx",
            "dns.servers.*.tls.handshake_timeout",
        ],
    ),
    // Routing.
    g(
        "Android's VPN is the host's to handle",
        Ignored,
        &["route.override_android_vpn"],
    ),
    g(
        CONDITIONS,
        Unsupported,
        &[
            "route.rules.*.client",
            "route.rules.*.source_geoip",
            "route.rules.*.interface_address",
            "route.rules.*.network_interface_address",
            "route.rules.*.default_interface_address",
            "route.rules.*.preferred_by",
        ],
    ),
    g(
        TLS_FRAGMENT,
        Unsupported,
        &["route.rules.*.tls_spoof", "route.rules.*.tls_spoof_method"],
    ),
    // Listen fields.
    g(
        LISTEN,
        Unsupported,
        &[
            "inbounds.*.bind_interface",
            "inbounds.*.routing_mark",
            "inbounds.*.netns",
            "inbounds.*.proxy_protocol",
            "inbounds.*.proxy_protocol_accept_no_header",
        ],
    ),
    g(
        "Handing an inbound's connections to another inbound",
        Unsupported,
        &["inbounds.*.detour"],
    ),
    g(
        SOCKET,
        Ignored,
        &[
            "inbounds.*.reuse_addr",
            "inbounds.*.tcp_multi_path",
        ],
    ),
    // Dial fields.
    g(
        NETNS,
        Unsupported,
        &["outbounds.*.netns", "route.rules.*.netns"],
    ),
    g(
        SOCKET,
        Ignored,
        &[
            "outbounds.*.tcp_multi_path",
            "route.rules.*.tcp_multi_path",
        ],
    ),
    t(
        "A detour for a direct outbound, which sing-box refuses too",
        Unsupported,
        &["direct"],
        &["outbounds.*.detour"],
    ),
    // TLS, both ways.
    g(
        TLS_CIPHERS,
        Unsupported,
        &["*.*.tls.cipher_suites", "*.*.tls.curve_preferences"],
    ),
    g(
        TLS_TUNING,
        Ignored,
        &[
            "*.*.tls.kernel_tx",
            "*.*.tls.kernel_rx",
            "*.*.tls.handshake_timeout",
        ],
    ),
    g(
        "An ECH configuration from a file, or looked up under another name: the server name would go in the clear",
        Unsupported,
        &[
            "*.*.tls.ech.config_path",
            "*.*.tls.ech.query_server_name",
            "dns.servers.*.tls.ech.config_path",
            "dns.servers.*.tls.ech.query_server_name",
        ],
    ),
    // Inbound TLS.
    g(
        "A certificate from a provider or ACME: the inbound would have none",
        Unsupported,
        &["inbounds.*.tls.certificate_provider", "inbounds.*.tls.acme"],
    ),
    g(
        "Encrypted Client Hello on an inbound",
        Unsupported,
        &["inbounds.*.tls.ech"],
    ),
    g(
        "Only relaxes checks a server's TLS does not make",
        Ignored,
        &["inbounds.*.tls.insecure"],
    ),
    // REALITY's handshake server, dialed as an outbound is.
    g(
        "A detour to the REALITY handshake server: it would be reached otherwise",
        Unsupported,
        &["inbounds.*.tls.reality.handshake.detour"],
    ),
    g(
        NETNS,
        Unsupported,
        &["inbounds.*.tls.reality.handshake.netns"],
    ),
    g(
        SOCKET,
        Ignored,
        &[
            "inbounds.*.tls.reality.handshake.tcp_multi_path",
        ],
    ),
    // Outbound TLS.
    g(
        "The TLS stack: sail has one",
        Ignored,
        &["outbounds.*.tls.engine"],
    ),
    g(
        TLS_FRAGMENT,
        Unsupported,
        &["outbounds.*.tls.spoof", "outbounds.*.tls.spoof_method"],
    ),
    t(
        "Fragmenting the TLS handshake: over QUIC, or under ShadowTLS, whose server reads the ClientHello",
        Unsupported,
        &["hysteria2", "tuic", "shadowtls"],
        &["outbounds.*.tls.fragment", "outbounds.*.tls.record_fragment"],
    ),
    t(
        "Only for fragmenting the TLS handshake, which sail does not do here",
        Ignored,
        &["hysteria2", "tuic", "shadowtls"],
        &["outbounds.*.tls.fragment_fallback_delay"],
    ),
    // TUN.
    g(
        "One stack serves every `stack`; the platform proxy is the host's to set",
        Ignored,
        &[
            "inbounds.*.stack",
            "inbounds.*.platform",
        ],
    ),
    t(
        "The TUN's own DNS handling: queries would be answered otherwise",
        Unsupported,
        &["tun"],
        &["inbounds.*.dns_address"],
    ),
    g(
        "Filtering LAN clients by MAC address",
        Unsupported,
        &[
            "inbounds.*.include_mac_address",
            "inbounds.*.exclude_mac_address",
        ],
    ),
    // UDP NAT, of the TUN, tproxy and WireGuard.
    // The TUN's is its own to read (protocol/tun/inbound.rs).
    g(
        "Which remote addresses may answer through a UDP mapping: others would",
        Unsupported,
        &["endpoints.*.udp_filtering"],
    ),
    t(
        "Which remote addresses may answer through a UDP mapping: others would",
        Unsupported,
        &["tproxy"],
        &["inbounds.*.udp_filtering"],
    ),
    g(
        "How UDP mappings are made and how many are kept: the same traffic",
        Ignored,
        &[
            "inbounds.*.udp_mapping",
            "inbounds.*.udp_nat_max",
            "endpoints.*.udp_mapping",
            "endpoints.*.udp_nat_max",
        ],
    ),
    // Inbounds by type.
    t(
        "The platform proxy is the host's to set",
        Ignored,
        &["http", "mixed"],
        &["inbounds.*.set_system_proxy"],
    ),
    t(
        "Resolving requested names with a resolver of its own: another server would answer",
        Unsupported,
        &["http", "mixed", "socks"],
        &["inbounds.*.domain_resolver"],
    ),
    t(
        "TLS on a mixed inbound: it would take plain connections",
        Unsupported,
        &["mixed"],
        &["inbounds.*.tls"],
    ),
    t(
        "Which networks a Shadowsocks inbound serves: it would serve others",
        Unsupported,
        &["shadowsocks"],
        &["inbounds.*.network"],
    ),
    t(
        "Relaying to other Shadowsocks servers",
        Unsupported,
        &["shadowsocks"],
        &["inbounds.*.destinations"],
    ),
    t(
        "Users managed through the SSM API, a service sail does not run",
        Ignored,
        &["shadowsocks"],
        &["inbounds.*.managed"],
    ),
    t(
        "Response headers and keepalive of a WebSocket or gRPC server: the same streams",
        Ignored,
        &["trojan", "vless", "vmess"],
        &[
            "inbounds.*.transport[ws].headers",
            "inbounds.*.transport[grpc].permit_without_stream",
        ],
    ),
    // Outbounds, and inbounds, by type.
    t(
        "VMess's authenticated length: sail would speak VMess otherwise",
        Unsupported,
        &["vmess"],
        &["outbounds.*.authenticated_length"],
    ),
    t(
        "Metadata the client tells the server: the connection goes the same way without it",
        Ignored,
        &["anytls"],
        &["outbounds.*.client_metadata"],
    ),
    t(
        QUIC_TUNING,
        Ignored,
        &["hysteria2", "tuic"],
        &[
            "inbounds.*.idle_timeout",
            "inbounds.*.keep_alive_period",
            "inbounds.*.stream_receive_window",
            "inbounds.*.connection_receive_window",
            "inbounds.*.max_concurrent_streams",
            "inbounds.*.initial_packet_size",
            "inbounds.*.disable_path_mtu_discovery",
            "outbounds.*.idle_timeout",
            "outbounds.*.keep_alive_period",
            "outbounds.*.stream_receive_window",
            "outbounds.*.connection_receive_window",
            "outbounds.*.max_concurrent_streams",
            "outbounds.*.initial_packet_size",
            "outbounds.*.disable_path_mtu_discovery",
        ],
    ),
    t(
        "Hysteria's congestion tuning and debugging, the longest hop interval, and its QUIC fingerprint: the same traffic",
        Ignored,
        &["hysteria2"],
        &[
            "inbounds.*.bbr_profile",
            "inbounds.*.brutal_debug",
            "outbounds.*.bbr_profile",
            "outbounds.*.brutal_debug",
            "outbounds.*.hop_interval_max",
            "outbounds.*.disable_chrome_parrot",
        ],
    ),
    t(
        "Meeting peers through a Hysteria realm: connections would be made otherwise",
        Unsupported,
        &["hysteria2"],
        &["inbounds.*.realm", "outbounds.*.realm"],
    ),
    t(
        "The packet sizes of the gecko obfuscation: the packets would look otherwise",
        Unsupported,
        &["hysteria2"],
        &[
            "inbounds.*.obfs[gecko].min_packet_size",
            "inbounds.*.obfs[gecko].max_packet_size",
            "outbounds.*.obfs[gecko].min_packet_size",
            "outbounds.*.obfs[gecko].max_packet_size",
        ],
    ),
    // Endpoints: WireGuard's dial fields, as an outbound's.
    g(NETNS, Unsupported, &["endpoints.*.netns"]),
    g(
        NETWORKS,
        Unsupported,
        &[
            "endpoints.*.network_strategy",
            "endpoints.*.network_type",
            "endpoints.*.fallback_network_type",
        ],
    ),
    g(
        SOCKET,
        Ignored,
        &[
            "endpoints.*.tcp_multi_path",
        ],
    ),
    // sing-box 1.15's, read ahead of its stable release.
    g(
        "Connects at start and stays up; on_demand waits for sing-box 1.15 stable",
        Ignored,
        &["endpoints.*.on_demand"],
    ),
];

/// Fields of `GROUPS` that sail implements for some types of entry, by
/// path: left to the schema in an entry of one of those types.
pub const IMPLEMENTED_FOR: &[(&str, &[&str])] = &[
    // Handing connections to another inbound: ShadowTLS's, whose inbound
    // is of no use without it.
    ("inbounds.*.detour", &["shadowtls"]),
];

/// Values sing-box accepts and acts on nowhere, which sail reads as it does,
/// warning of each: where, the value, and the warning. sing-box 1.14.1
/// builds a `direct` rule's dialer, so that its fields are checked, but its
/// router never acts on the rule, nor stops at it (route/route.go:690-697).
pub const NO_EFFECT: &[(&str, &str, &str)] = &[(
    "route.rules.*.action",
    "direct",
    "the direct action has no effect, as in sing-box 1.14.1",
)];

/// Why values of `NO_EFFECT` are warned of, as the support tables say.
pub const NO_EFFECT_WHY: &str = "Accepted, no effect (as sing-box)";

/// Why values of `VALUES` are errors.
pub const VALUES_WHY: &str = "A type or value sail does not implement: it would route otherwise";

/// Values sing-box accepts that sail does not implement: all of them change
/// routing.
pub const VALUES: &[(&str, &[&str])] = &[
    (
        "dns.servers.*.type",
        &["dhcp", "tailscale", "openconnect", "openvpn", "resolved"],
    ),
    (
        "route.rules.*.action",
        &["evaluate", "respond", "predefined"],
    ),
    ("route.rules.*.sniffer", &["ssh", "rdp", "ntp"]),
];
