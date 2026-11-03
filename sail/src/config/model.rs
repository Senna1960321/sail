//! The configuration the runtime is built from, in sing-box's shape: its
//! JSON is read into it directly, other formats are translated into it.
//! Field names follow sing-box wherever the meaning is the same; what sail
//! adds sits in place, and is marked as an extension where it is declared.
//!
//! What an inbound or outbound takes beyond its type and tag belongs to its
//! protocol: the model keeps it as an untyped map, and the protocol's factory
//! reads it into its own options type when the handler is built. That keeps
//! the whole of a protocol, options included, in the protocol's directory.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};

/// The options of one inbound or outbound, read by its protocol.
pub type Options = serde_json::Map<String, serde_json::Value>;

// What a configuration holds of passwords, keys, UUIDs and tokens is not
// printed: the options of inbounds, outbounds, endpoints and DNS servers
// print as their names, a header's values, the Clash API's secret and a
// provider's URL (but its host) not at all.

/// Options, printed as their names only.
struct Names<'a>(&'a Options);

impl std::fmt::Debug for Names<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

/// `value` as JSON, with `hide` done to it: for what prints much of itself.
fn redacted_json<T: serde::Serialize>(
    f: &mut std::fmt::Formatter<'_>,
    name: &str,
    value: &T,
    hide: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> std::fmt::Result {
    let mut json = match serde_json::to_value(value) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => return write!(f, "{}(..)", name),
    };
    hide(&mut json);
    write!(f, "{}({})", name, serde_json::Value::Object(json))
}

/// The host of `url`, and no more of it.
fn url_host(url: &str) -> String {
    crate::common::redact::host(url).to_string()
}

impl std::fmt::Debug for HeaderValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} redacted>", self.0.len())
    }
}

impl std::fmt::Debug for ClashApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        redacted_json(f, "ClashApi", self, |json| {
            if let Some(secret) = json.get_mut("secret") {
                *secret = "<redacted>".into();
            }
        })
    }
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        redacted_json(f, "Api", self, |json| {
            if let Some(secret) = json.get_mut("secret") {
                *secret = "<redacted>".into();
            }
        })
    }
}

impl std::fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsServer")
            .field("kind", &self.kind)
            .field("tag", &self.tag)
            .field("options", &Names(&self.options))
            .finish()
    }
}

impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbound")
            .field("protocol", &self.protocol)
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("listen_port", &self.listen_port)
            .field("options", &Names(&self.options))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("protocol", &self.protocol)
            .field("tag", &self.tag)
            .field("options", &Names(&self.options))
            .finish()
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("protocol", &self.protocol)
            .field("tag", &self.tag)
            .field("options", &Names(&self.options))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OutboundProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        redacted_json(f, "OutboundProvider", self, |json| {
            if let Some(serde_json::Value::String(url)) = json.get_mut("url") {
                *url = format!("{}/<redacted>", url_host(url));
            }
            if let Some(serde_json::Value::Object(client)) = json.get_mut("http_client") {
                if let Some(serde_json::Value::Object(headers)) = client.get_mut("headers") {
                    for value in headers.values_mut() {
                        *value = "<redacted>".into();
                    }
                }
            }
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
    /// Both an inbound and an outbound under one tag, as sing-box's
    /// endpoints: connections routed to the tag go out through it, and
    /// what comes in through it is routed with the tag as its inbound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub route: Route,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<Api>,
    /// The Clash API, which dashboards (yacd, metacubexd) and clients
    /// control the instance through. sing-box has it under `experimental`,
    /// which is read too, as the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApi>,
    #[serde(default, skip_serializing_if = "Experimental::is_default")]
    pub experimental: Experimental,
    /// The time the protocols that check it go by, and certificates are
    /// verified at, measured against an NTP server; the system's clock is
    /// never set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<Ntp>,
    /// The root certificates servers are checked against; the system's
    /// when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateOptions>,
    /// How sail fetches over HTTP, rule-sets for one, by tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_clients: Vec<HttpClient>,
    /// A sail extension: outbounds given together, downloaded, read from
    /// a file or written in place, that groups take as members, as
    /// Mihomo's proxy groups take a proxy-provider's proxies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_providers: Vec<OutboundProvider>,
    /// A sail extension: what each user, by name, may do across every
    /// inbound it is in.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_limits: BTreeMap<String, UserLimits>,
    /// What the configuration sets that sail ignores, one line each; the
    /// start logs them.
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// The dial fields an HTTP client implements: all that sail does but
/// `skip_default_domain_resolver`.
const HTTP_CLIENT_DIAL: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "domain_resolver",
    "domain_strategy",
    "bind_address_no_port",
    "protect_path",
    "reuse_addr",
    "tcp_fast_open",
    "udp_fragment",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
];

/// sing-box's `ntp`: the offset of the system's clock from an NTP
/// server's, measured every `interval`, which the instance's protocols
/// correct the time they check by: vmess, Shadowsocks 2022, REALITY, and
/// the validity of the certificates TLS and QUIC verify. Not WireGuard's
/// handshakes, which want a time that only goes on, not an exact one. Read
/// as the instance starts: a reload keeps the service it started with.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ntp {
    #[serde(default)]
    pub enabled: bool,
    /// The server's name or address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// 123 when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    /// How often the offset is measured again; 30m when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub interval: Option<std::time::Duration>,
    /// Setting the system's clock, which sail never does: an error.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write_to_system: bool,
    /// How it connects, `detour` among them.
    #[serde(flatten)]
    pub dial: crate::net::dial::DialFields,
}

/// An HTTP client: the outbound it fetches through, or, with none, the
/// dial fields it connects with itself.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpClient {
    /// Of one in `http_clients`; none inline.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    /// How it connects, `detour` among them.
    #[serde(flatten)]
    pub dial: crate::net::dial::DialFields,
    /// Sent with each request, over sail's own of the same name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, HeaderValues>,
    /// The HTTP version sing-box asks for, 1, 2 or 3; 2 when unset (or 0).
    /// sail downloads over HTTP/1.1 whichever, as sing-box does from a
    /// server that speaks no other: a download is the same download.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    /// `version` alone, never HTTP/1.1 in its place: warned of with 2 or
    /// 3, as sail downloads over HTTP/1.1.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_version_fallback: bool,
    /// Whose client sing-box downloads with: `go`, its own, when unset, or
    /// `apple`, NSURLSession. sail downloads with its own either way, and
    /// warns of `apple`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
}

/// Its headers, a line each.
pub fn header_lines(headers: &BTreeMap<String, HeaderValues>) -> Vec<(String, String)> {
    headers
        .iter()
        .flat_map(|(name, values)| values.0.iter().map(|v| (name.clone(), v.clone())))
        .collect()
}

/// Checks that each header is one a request can carry: a name, and values
/// that do not break its line. `Connection` is sail's to set.
pub fn check_headers(headers: &BTreeMap<String, HeaderValues>) -> Result<()> {
    for (name, values) in headers {
        let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
        if name.is_empty() || !name.chars().all(token) {
            return Err(anyhow!("headers: {:?} is no header name", name));
        }
        if name.eq_ignore_ascii_case("connection") {
            return Err(anyhow!("headers: Connection is sail's to set"));
        }
        if let Some(v) = values.0.iter().find(|v| v.contains(['\r', '\n', '\0'])) {
            return Err(anyhow!("headers: {}: {:?} breaks the line", name, v));
        }
    }
    Ok(())
}

/// Checks an HTTP `version` as sing-box does: 1, 2 or 3, or 0 for unset.
pub fn check_http_version(version: Option<u8>) -> Result<()> {
    match version.filter(|v| *v > 3) {
        Some(version) => Err(anyhow!("version: {} is none of 1, 2 and 3", version)),
        None => Ok(()),
    }
}

/// The HTTP version an HTTP outbound's options ask for.
pub struct HttpVersion {
    /// `version` as set, 0 being unset.
    pub asked: Option<u8>,
    /// `version` if set, else 1: sing-box 1.14's, whose HTTP proxy speaks
    /// HTTP/1.1 alone, until the registry follows sing-box 1.15 stable,
    /// which takes 2 (1 with a path or a Host header).
    pub resolved: u8,
    pub disable_fallback: bool,
}

impl HttpVersion {
    /// What `options` ask for; values of the wrong type are taken as unset,
    /// for the outbound to refuse.
    pub fn of(options: &Options) -> Self {
        let asked = options
            .get("version")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .filter(|v| *v != 0);
        let resolved = asked.unwrap_or(1);
        let disable_fallback = options
            .get("disable_version_fallback")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        HttpVersion {
            asked,
            resolved,
            disable_fallback,
        }
    }
}

/// The warning for a `disable_version_fallback` that asks for HTTP/2 or 3
/// alone, of which sail speaks neither: what it does, `what`, goes over
/// HTTP/1.1 all the same. `version` is what the configuration says,
/// `default` what sing-box takes when it says nothing (or 0); the client
/// or outbound is at `at`.
pub fn http_fallback_warning(
    at: &str,
    version: Option<u8>,
    default: u8,
    disable_version_fallback: bool,
    what: &str,
) -> Option<String> {
    let version = version.filter(|v| *v != 0).unwrap_or(default);
    (disable_version_fallback && version != 1).then(|| {
        format!(
            "{}.disable_version_fallback: sail {} over HTTP/1.1, not HTTP/{}; ignored",
            at, what, version
        )
    })
}

/// The values of a header: one, or a list.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(transparent)]
pub struct HeaderValues(#[serde(with = "listable")] pub Vec<String>);

impl HttpClient {
    /// Its headers, a line each.
    pub fn header_lines(&self) -> Vec<(String, String)> {
        header_lines(&self.headers)
    }

    /// The dialer it connects with: its dial fields over `defaults`, or
    /// its detour. An error names the field.
    pub fn dialer(&self, defaults: &crate::net::DialDefaults) -> Result<crate::net::Dialer> {
        defaults.dialer(&self.dial, None)
    }

    /// What it asks for that sail's downloads do otherwise, a warning
    /// each, the client being at `at`.
    pub fn warnings(&self, at: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.engine.as_deref() == Some("apple") {
            warnings.push(format!(
                "{}.engine: sail downloads with its own client, not Apple's; ignored",
                at
            ));
        }
        warnings.extend(http_fallback_warning(
            at,
            self.version,
            2,
            self.disable_version_fallback,
            "downloads",
        ));
        warnings
    }

    fn check(&self, outbounds: &HashSet<&str>, dns_servers: &HashSet<String>) -> Result<()> {
        if let Some(detour) = &self.dial.detour {
            if !outbounds.contains(detour.as_str()) {
                return Err(anyhow!("detour: outbound [{}] does not exist", detour));
            }
            // Through an outbound, the names are that outbound's to
            // resolve, unless a domain_resolver resolves them here first.
            if self.dial.domain_strategy.is_some() && self.dial.domain_resolver.is_none() {
                return Err(anyhow!(
                    "domain_strategy: has no effect with a detour and no domain_resolver; \
                     set it on [{}]",
                    detour
                ));
            }
        }
        self.dial.check(HTTP_CLIENT_DIAL)?;
        // What this platform cannot apply, as an outbound's: the defaults
        // take nothing away from it.
        crate::net::dial::DialSpec::resolve(&self.dial, &Default::default())?;
        check_headers(&self.headers)?;
        check_http_version(self.version)?;
        if let Some(engine) = self
            .engine
            .as_deref()
            .filter(|e| !matches!(*e, "" | "go" | "apple"))
        {
            return Err(anyhow!("engine: {:?} is neither go nor apple", engine));
        }
        if let Some(resolver) = &self.dial.domain_resolver {
            if !dns_servers.contains(&resolver.server) {
                return Err(anyhow!(
                    "domain_resolver: dns server [{}] does not exist",
                    resolver.server
                ));
            }
        }
        Ok(())
    }
}

/// An HTTP client named by tag, or given in place; in place, its tag is
/// no name, as in sing-box.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum HttpClientRef {
    Tag(String),
    Inline(Box<HttpClient>),
}

/// sing-box's top-level `certificate`: a store of root certificates, and
/// certificates of one's own besides.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateOptions {
    #[serde(default)]
    pub store: CertificateStore,
    /// Inline PEM, its lines one to an entry or all in one.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub certificate: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub certificate_path: Vec<String>,
    /// Directories, every file of which holds certificates.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub certificate_directory_path: Vec<String>,
}

/// Which roots: the system's, or Mozilla's or Chrome's included lists
/// (without the certificate authorities of China, as sing-box's), or none.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStore {
    #[default]
    System,
    Mozilla,
    Chrome,
    None,
}

/// sing-box's `experimental`: what sail takes of it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Experimental {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<CacheFileOptions>,
    /// sing-box's place for the Clash API: taken to `clash_api` when the
    /// configuration is validated.
    #[serde(default, skip_serializing)]
    pub clash_api: Option<ClashApi>,
}

/// A user's limits in `user_limits`. A field left out limits nothing; none
/// may be 0.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UserLimits {
    /// How many connections it may have live at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// How many of them may be TCP at once, its UDP sessions not counted;
    /// with `max_connections` too, both apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tcp_connections: Option<u32>,
    /// How many bytes, up and down together, it may send and receive; kept
    /// across restarts in the cache file, which it needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    /// When it may no longer connect, in RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_at: Option<String>,
    /// Its rate up, what its clients send, in Mbps: the unit of
    /// sing-box's Hysteria2 `up_mbps`, not its direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u64>,
    /// Its rate down, what its clients receive, in Mbps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u64>,
    /// Its rate up and down together, in Mbps: both directions draw from
    /// it, and from `up_mbps` and `down_mbps` too where they are set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_mbps: Option<u64>,
}

impl UserLimits {
    /// `expire_at`, once `Config::validate` checked it.
    pub fn expire_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.expire_at
            .as_deref()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.with_timezone(&chrono::Utc))
    }

    pub(crate) fn check(&self, name: &str) -> Result<()> {
        let field = |f: &str| format!("user_limits.{}.{}", name, f);
        for (name, max) in [
            ("max_connections", self.max_connections),
            ("max_tcp_connections", self.max_tcp_connections),
        ] {
            if max == Some(0) {
                return Err(anyhow!(
                    "{}: must be more than 0; leave it out for no limit",
                    field(name)
                ));
            }
        }
        for (name, mbps) in [
            ("up_mbps", self.up_mbps),
            ("down_mbps", self.down_mbps),
            ("total_mbps", self.total_mbps),
        ] {
            if mbps == Some(0) {
                return Err(anyhow!(
                    "{}: must be more than 0; leave it out for no limit",
                    field(name)
                ));
            }
        }
        if self.quota_bytes == Some(0) {
            return Err(anyhow!(
                "{}: must be more than 0; leave it out for no limit",
                field("quota_bytes")
            ));
        }
        if let Some(at) = &self.expire_at {
            chrono::DateTime::parse_from_rfc3339(at).map_err(|e| {
                anyhow!(
                    "{}: {:?} is not an RFC 3339 time: {}",
                    field("expire_at"),
                    at,
                    e
                )
            })?;
        }
        Ok(())
    }
}

/// The strings `fields` of the entries of the list `list`.
fn named<'a>(
    list: Option<&'a serde_json::Value>,
    fields: &'a [&'a str],
) -> impl Iterator<Item = &'a str> + 'a {
    list.and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .flat_map(move |user| fields.iter().filter_map(move |f| user.get(*f)?.as_str()))
        .filter(|name| !name.is_empty())
}

impl Inbound {
    /// The names of the users it authenticates: `users[].name`, or
    /// `users[].username` for HTTP, SOCKS and mixed.
    pub fn user_names(&self) -> HashSet<&str> {
        named(self.options.get("users"), &["name", "username"]).collect()
    }
}

/// The names of the users `inbounds` and `endpoints` authenticate: the
/// inbounds' and a WireGuard peer's `public_key`, which names what comes
/// in from it.
fn user_names<'a>(inbounds: &'a [Inbound], endpoints: &'a [Endpoint]) -> HashSet<&'a str> {
    inbounds
        .iter()
        .flat_map(|i| i.user_names())
        .chain(
            endpoints
                .iter()
                .filter(|e| e.protocol == "wireguard")
                .flat_map(|e| named(e.options.get("peers"), &["public_key"])),
        )
        .collect()
}

/// sing-box's `cache_file`: what is kept across restarts. The selections
/// of selector groups and the Clash API's mode, and the fake IPs handed
/// out with `store_fakeip`; nothing without it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CacheFileOptions {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,
    /// `cache.db` when unset. A relative path is in the host's cache
    /// directory, or the data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// What this configuration keeps is kept apart, under this name, from
    /// what others sharing the file keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store_fakeip: bool,
    /// The DNS answers kept are kept in the file too, and outlive a
    /// restart.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store_dns: bool,
}

impl Experimental {
    fn is_default(&self) -> bool {
        *self == Experimental::default()
    }
}

/// The Clash API, as sing-box's `clash_api` has it, and Mihomo's
/// `external-controller` and the fields about it.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClashApi {
    /// Where it listens, `host:port`; an empty host is every address, as
    /// in Mihomo. Unset, it is not served, though `default_mode` still
    /// sets the mode rules match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_controller: Option<String>,
    /// What callers authenticate with, `Authorization: Bearer`, or a
    /// WebSocket's `?token=`. The API is served only with a strong one (at
    /// least 32 characters, 10 distinct): `sail generate secret` makes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// A directory of a dashboard's files, served at `/ui/`; relative to
    /// the data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ui: Option<String>,
    /// Where the dashboard is downloaded from, a ZIP, when `external_ui`
    /// is empty. The core has none of its own: unset, nothing is
    /// downloaded, and a warning says so; a host, such as sail-cli, may
    /// give one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ui_download_url: Option<String>,
    /// The outbound the download goes through; the default one when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ui_download_detour: Option<String>,
    /// The origins browsers may call it from (CORS); any when empty.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub access_control_allow_origin: Vec<String>,
    /// Pages on public addresses may call it on a private one (Private
    /// Network Access).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub access_control_allow_private_network: bool,
    /// The mode rules match at the start, `Rule` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<String>,
}

/// The control API; a sail extension. Served on a unix socket, made the
/// user's only, and on loopback TCP when `listen` is set; not served when
/// `api` is left out.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Api {
    /// The unix socket the API is served on, in the data directory unless
    /// absolute; `api.sock` there when neither it nor `listen` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<std::path::PathBuf>,
    /// A loopback address the API is served on too, as `127.0.0.1:9091`;
    /// it takes `secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<std::net::SocketAddr>,
    /// What every call carries, as `Authorization: Bearer <secret>`: one
    /// `sail generate secret` makes. Needed with `listen`; on the unix
    /// socket, checked when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl Api {
    /// The socket is the default: any process on the host reaches a
    /// loopback port, so the port is only served behind a strong secret,
    /// and on no other address, which would carry the secret in the clear.
    fn check(&self) -> Result<()> {
        if let Some(listen) = self.listen {
            if !listen.ip().is_loopback() {
                return Err(anyhow!(
                    "api.listen: {} is not a loopback address; the API is served on loopback \
                     only (reach it from elsewhere through an SSH tunnel or a reverse proxy)",
                    listen
                ));
            }
            if self.secret.is_none() {
                return Err(anyhow!(
                    "api.secret: missing; api.listen needs one (`sail generate secret`)"
                ));
            }
        }
        if let Some(secret) = &self.secret {
            if let Some(why) = crate::generate::weak_secret(secret) {
                return Err(anyhow!(
                    "api.secret: too weak ({}); use what `sail generate secret` makes",
                    why
                ));
            }
        }
        Ok(())
    }

    /// The unix socket, when one is served: `path`, or the default when
    /// `listen` is not set either.
    pub fn socket(&self) -> Option<std::path::PathBuf> {
        match (&self.path, self.listen) {
            (Some(path), _) => Some(path.clone()),
            (None, None) => Some("api.sock".into()),
            (None, Some(_)) => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    /// Also `warning`, as sing-box takes it.
    #[serde(alias = "warning")]
    Warn,
    Error,
    /// As `error`: sail logs nothing more severe.
    Fatal,
    /// As `error`.
    Panic,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Full,
    Compact,
}

/// What a log line at INFO or above leaves out, a sail extension.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRedact {
    /// Where a connection goes: its host or address, the port kept.
    Destination,
    /// Where it comes from: the client's address, and the LAN devices
    /// sail learns of.
    Source,
    /// The process that opened it.
    Process,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Log {
    /// Logs nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default)]
    pub level: LogLevel,
    /// A file to append to. Logs go to the console when it is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Starts each line with the time.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timestamp: bool,
    /// A sail extension: `compact` writes the message alone.
    #[serde(default)]
    pub format: LogFormat,
    /// A sail extension: what lines at INFO, WARN and ERROR leave out.
    /// DEBUG and TRACE lines are not redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<LogRedact>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// The servers, each by its tag. None is the system's resolver alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,
    /// Which server a query goes to, matched in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,
    /// The server of the queries no rule matches; the first one when unset.
    #[serde(rename = "final", default, skip_serializing_if = "Option::is_none")]
    pub final_server: Option<String>,
    /// Which address families names resolve to, and in what order.
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// A sail extension: the address families the answers to clients'
    /// queries (hijack-dns, a DNS listener) carry, besides what `strategy`
    /// and the rules leave out: a family either leaves out is answered
    /// with no records. The instance's own lookups keep `strategy`. As
    /// Mihomo's `dns.ipv6: false` answers clients, while its connections
    /// still resolve IPv6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_strategy: Option<DnsStrategy>,
    /// No answer is kept: each query goes to its server.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    /// Answers kept are used however old they are, until the cache is full
    /// or cleared.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_expire: bool,
    /// How many answers are kept; 1024 when unset, and at least that, as
    /// in sing-box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_capacity: Option<usize>,
    /// An answer that has expired is still given, for up to its timeout,
    /// while the server is asked again in the background.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimistic: Option<Optimistic>,
    /// How long one query to one server may take; 10s when unset, as in
    /// sing-box.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// Remembers the domain of each address the DNS answers that pass
    /// through carry, so that connections to the address are routed by the
    /// domain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse_mapping: bool,
    /// The EDNS Client Subnet each query carries, unless a rule says
    /// otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
}

/// sing-box's `optimistic`: `true`, or `{ "enabled": true, "timeout": "3d" }`.
#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct Optimistic {
    pub enabled: bool,
    /// How long after it expired an answer may still be given; 3d when
    /// unset, as in sing-box.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
}

impl<'de> serde::Deserialize<'de> for Optimistic {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            #[serde(default)]
            enabled: bool,
            #[serde(default, with = "duration")]
            timeout: Option<std::time::Duration>,
        }
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::Bool(enabled) => Ok(Optimistic {
                enabled,
                timeout: None,
            }),
            value => {
                let full = Full::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(Optimistic {
                    enabled: full.enabled,
                    timeout: full.timeout,
                })
            }
        }
    }
}

/// A DNS server. What it takes beyond its type and tag belongs to its type,
/// and is read when the DNS client is built, as an outbound's options are.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct DnsServer {
    /// `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, or
    /// sail's `race` and `sequential`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub options: Options,
}

/// A DNS rule, matched in order against each query. Its conditions are a
/// routing rule's, matched as they are there, and `query_type` and
/// `outbound` besides; a logical one (`type: logical`) combines others,
/// which take no action of their own.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DnsRule {
    /// `default`, or `logical`.
    #[serde(rename = "type", default, skip_serializing_if = "RuleType::is_default")]
    pub kind: RuleType,
    /// Record types, by name (`A`, `AAAA`, `HTTPS`) or number.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,
    /// Tags of DNS servers: matches a name one of them prefers, one it
    /// answers for itself, as sing-box's `preferred_by`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub preferred_by: Vec<String>,
    /// Tags of the inbounds the connection that needs the name came in
    /// through.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    /// The mode of Clash's API, as in a routing rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Names of the users an inbound authenticated.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    /// A sail extension, as in a routing rule.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// A sail extension, as in a routing rule: `site:<file>:<code>`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_ip_is_private: bool,
    /// MAC addresses of the LAN device the query comes from, as the
    /// neighbor table and DHCP leases know it.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_mac_address: Vec<String>,
    /// Host names of the LAN device the query comes from, as its DHCP
    /// lease has it.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_hostname: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_path_regex: Vec<String>,
    /// A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular
    /// expressions the program's name, its path's last part, matches.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name_regex: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name_regex: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub user_id: Vec<i32>,
    /// The network the host is on, as the routing rules match it.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub wifi_ssid: Vec<String>,
    /// The address of the Wi-Fi access point, `aa:bb:cc:dd:ee:ff`, in any
    /// case, with `:` or `-`, or as 12 hex digits.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub wifi_bssid: Vec<String>,
    /// The kind of network: `wifi`, `cellular`, `ethernet`, `other`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<String>,
    /// The network is metered, as the system says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_is_expensive: bool,
    /// The network is in a low data mode, as the system says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_is_constrained: bool,
    /// A sail extension, for Surge's `SSID:`: regular expressions found in
    /// the Wi-Fi network's name, with case.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub wifi_ssid_regex: Vec<String>,
    /// A sail extension, for Surge's `BSSID:`: regular expressions found in
    /// the access point's address as `aa:bb:cc:dd:ee:ff`, whatever the case.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub wifi_bssid_regex: Vec<String>,
    /// A sail extension, for Surge's `ROUTER:`: the address of the default
    /// gateway.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network_gateway: Vec<String>,
    /// A sail extension, for Surge's `MCCMNC:` and `CELLULAR-CARRIER`: the
    /// cellular carrier, its MCC and MNC as 5 or 6 digits; only off Wi-Fi.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network_mcc_mnc: Vec<String>,
    /// Tags of the outbounds that dial the name; of the rule itself, not
    /// of a rule a logical one combines.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub outbound: Vec<String>,
    /// Tags of rule-sets, any of whose rules matching matches. Their
    /// `ip_cidr` rules match no query, which has no address yet.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    /// The rule-sets' `ip_cidr` match the source address.
    #[serde(
        default,
        alias = "rule_set_ipcidr_match_source",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub rule_set_ip_cidr_match_source: bool,
    /// The response of an `evaluate` rule before it, which the rule then
    /// matches: its addresses are what `ip_cidr`, `ip_is_private`,
    /// `ip_accept_any` and the rule-sets' `ip_cidr` match. With none, the
    /// rule matches only inverted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_response: Option<ResponseRef>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
    /// The response has an address.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_accept_any: bool,
    /// A sail extension: the rule's conditions on the response's addresses
    /// hold for every one of them, rather than for any; a response without
    /// one they hold for none. Mihomo's fallback filter keeps an answer so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_match_all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_rcode: Option<Rcode>,
    /// Records the response has among its answers, as `answer` writes
    /// them: any of them.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub response_answer: Vec<String>,
    /// Records the response has among its name servers.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub response_ns: Vec<String>,
    /// Records the response has among its additional records.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub response_extra: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// `logical`: `and` or `or`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogicalMode>,
    /// `logical`: the rules combined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,

    /// `route` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<DnsRuleAction>,
    /// `route`: the server a matching query goes to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// `route`: the address families, instead of `dns.strategy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
    /// `predefined`: the code of the answer, NOERROR when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<Rcode>,
    /// `predefined`: the answer's records, as a zone file writes them
    /// (`localhost. IN A 127.0.0.1`, TTL 3600 unless given), or the base64
    /// of their wire form; one named `*.suffix.` takes the name asked for
    /// when it ends so.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<String>,
    /// `predefined`: its name server records.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ns: Vec<String>,
    /// `predefined`: its additional records.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
    /// `evaluate`: the name of its response, which `match_response` gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// `route`, `respond`, `reject` and `predefined`, on a response: the
    /// rules after it are matched while its responses are still coming,
    /// and the first race rule to match, once they have, decides; the
    /// others' actions wait until none of the race rules before them
    /// matched. As sing-box 1.14's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub race: bool,
    /// `route` and `evaluate`: the query is sent as soon as the rule
    /// matches, while race rules before it are still pending, rather than
    /// once none of them matched; its response is used only then.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub speculative: bool,
    /// `route`, `evaluate` and `route-options`: the query neither comes
    /// from the cache nor goes into it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    /// An expired answer is not given while it is asked for again, though
    /// `dns.optimistic` is enabled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_optimistic_cache: bool,
    /// The TTL the answer's records carry, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    /// How long the query may take, instead of `dns.timeout`.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// The EDNS Client Subnet the query carries, instead of
    /// `dns.client_subnet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
    /// The query carries no EDNS Client Subnet, whatever it or
    /// `dns.client_subnet` has.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove_client_subnet: bool,
}

/// What a matching DNS rule does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsRuleAction {
    /// Sends the query to `server`.
    #[default]
    Route,
    /// Sends the query to `server` and keeps the response for the rules
    /// after it to match, which goes on with the next rule.
    Evaluate,
    /// Answers with the response kept.
    Respond,
    /// Sets how the query is sent, for the rule that sends it; matching
    /// goes on with the next rule.
    RouteOptions,
    /// Answers that the name does not resolve.
    Reject,
    /// Answers with `rcode` and no records, as sing-box's `predefined`
    /// without its records, which sail does not implement.
    Predefined,
}

impl DnsRuleAction {
    /// As a configuration writes it.
    pub fn name(self) -> &'static str {
        match self {
            DnsRuleAction::Route => "route",
            DnsRuleAction::Evaluate => "evaluate",
            DnsRuleAction::Respond => "respond",
            DnsRuleAction::RouteOptions => "route-options",
            DnsRuleAction::Reject => "reject",
            DnsRuleAction::Predefined => "predefined",
        }
    }
}

/// Which evaluated response a rule matches: `true` for the last one without
/// a tag, or a tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResponseRef {
    Latest,
    Tag(String),
}

impl<'de> serde::Deserialize<'de> for ResponseRef {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::Bool(true) => Ok(ResponseRef::Latest),
            serde_json::Value::String(tag) if !tag.is_empty() => Ok(ResponseRef::Tag(tag)),
            other => Err(serde::de::Error::custom(format!(
                "true, or the tag of an evaluate rule, not {}",
                other
            ))),
        }
    }
}

impl serde::Serialize for ResponseRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            ResponseRef::Latest => s.serialize_bool(true),
            ResponseRef::Tag(tag) => s.serialize_str(tag),
        }
    }
}

/// A DNS response code: its number, or its name (`NOERROR`, `NXDOMAIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rcode(pub u16);

const RCODES: &[(&str, u16)] = &[
    ("NOERROR", 0),
    ("FORMERR", 1),
    ("SERVFAIL", 2),
    ("NXDOMAIN", 3),
    ("NOTIMP", 4),
    ("REFUSED", 5),
    ("YXDOMAIN", 6),
    ("YXRRSET", 7),
    ("NXRRSET", 8),
    ("NOTAUTH", 9),
    ("NOTZONE", 10),
    ("BADSIG", 16),
    ("BADKEY", 17),
    ("BADTIME", 18),
    ("BADMODE", 19),
    ("BADNAME", 20),
    ("BADALG", 21),
    ("BADTRUNC", 22),
    ("BADCOOKIE", 23),
];

impl<'de> serde::Deserialize<'de> for Rcode {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .map(Rcode)
                .ok_or_else(|| serde::de::Error::custom(format!("rcode {} is out of range", n))),
            serde_json::Value::String(name) => RCODES
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, code)| Rcode(*code))
                .ok_or_else(|| serde::de::Error::custom(format!("unknown rcode: {}", name))),
            other => Err(serde::de::Error::custom(format!(
                "an rcode, by name or number, not {}",
                other
            ))),
        }
    }
}

impl serde::Serialize for Rcode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match RCODES.iter().find(|(_, code)| *code == self.0) {
            Some((name, _)) => s.serialize_str(name),
            None => s.serialize_u16(self.0),
        }
    }
}

/// An IP prefix, or an address, which is a prefix of its whole length.
/// The bits past the prefix are kept, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: std::net::IpAddr,
    pub len: u8,
}

impl std::str::FromStr for Prefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (addr, len) = match s.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (s, None),
        };
        let addr: std::net::IpAddr = addr
            .parse()
            .map_err(|_| anyhow!("{:?} is not an address or prefix", s))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            Some(len) => len
                .parse::<u8>()
                .ok()
                .filter(|len| *len <= max)
                .ok_or_else(|| anyhow!("{:?}: the prefix length is 0 to {}", s, max))?,
            None => max,
        };
        Ok(Prefix { addr, len })
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl<'de> serde::Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(de)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl DnsRule {
    /// Its conditions, and those of the rules it combines, as a routing
    /// rule's: they match as those do. Its own `match_response` is for the
    /// DNS client, which matches it against that response; those of the
    /// rules it combines are theirs.
    pub fn conditions(&self) -> Rule {
        Rule {
            match_response: None,
            ..self.combined_conditions()
        }
    }

    fn combined_conditions(&self) -> Rule {
        Rule {
            kind: self.kind,
            query_type: self.query_type.clone().into(),
            preferred_by: self.preferred_by.clone().into(),
            clash_mode: self.clash_mode.clone(),
            inbound: self.inbound.clone().into(),
            ip_version: self.ip_version,
            network: self.network.clone().into(),
            auth_user: self.auth_user.clone().into(),
            protocol: self.protocol.clone().into(),
            domain: self.domain.clone().into(),
            domain_suffix: self.domain_suffix.clone().into(),
            domain_keyword: self.domain_keyword.clone().into(),
            domain_regex: self.domain_regex.clone().into(),
            geosite: self.geosite.clone().into(),
            external: self.external.clone().into(),
            source_ip_cidr: self.source_ip_cidr.clone().into(),
            source_ip_is_private: self.source_ip_is_private,
            source_mac_address: self.source_mac_address.clone().into(),
            source_hostname: self.source_hostname.clone().into(),
            source_port: self.source_port.clone().into(),
            source_port_range: self.source_port_range.clone().into(),
            port: self.port.clone().into(),
            port_range: self.port_range.clone().into(),
            process_name: self.process_name.clone().into(),
            process_path: self.process_path.clone().into(),
            process_path_regex: self.process_path_regex.clone().into(),
            process_name_regex: self.process_name_regex.clone().into(),
            package_name: self.package_name.clone().into(),
            package_name_regex: self.package_name_regex.clone().into(),
            user: self.user.clone().into(),
            user_id: self.user_id.clone().into(),
            wifi_ssid: self.wifi_ssid.clone().into(),
            wifi_bssid: self.wifi_bssid.clone().into(),
            network_type: self.network_type.clone().into(),
            network_is_expensive: self.network_is_expensive,
            network_is_constrained: self.network_is_constrained,
            wifi_ssid_regex: self.wifi_ssid_regex.clone().into(),
            wifi_bssid_regex: self.wifi_bssid_regex.clone().into(),
            network_gateway: self.network_gateway.clone().into(),
            network_mcc_mnc: self.network_mcc_mnc.clone().into(),
            rule_set: self.rule_set.clone().into(),
            rule_set_ip_cidr_match_source: self.rule_set_ip_cidr_match_source,
            ip_cidr: self.ip_cidr.clone().into(),
            ip_is_private: self.ip_is_private,
            ip_accept_any: self.ip_accept_any,
            response_rcode: self.response_rcode.map(|r| r.0),
            response_answer: self.response_answer.clone().into(),
            response_ns: self.response_ns.clone().into(),
            response_extra: self.response_extra.clone().into(),
            match_response: self.match_response.clone(),
            invert: self.invert,
            mode: self.mode,
            rules: self
                .rules
                .iter()
                .map(DnsRule::combined_conditions)
                .collect(),
            ..Default::default()
        }
    }

    /// Whether the rule sets any condition: that there is a response to
    /// match is one.
    pub fn has_conditions(&self) -> bool {
        self.conditions().has_conditions()
            || !self.outbound.is_empty()
            || self.match_response.is_some()
    }

    /// The response the rule matches, or answers with: `respond` without
    /// `match_response` answers with the last one without a tag.
    pub fn response(&self) -> Option<ResponseRef> {
        match (&self.match_response, self.action.unwrap_or_default()) {
            (Some(response), _) => Some(response.clone()),
            (None, DnsRuleAction::Respond) => Some(ResponseRef::Latest),
            (None, _) => None,
        }
    }

    /// Whether it sets how its query is sent.
    fn has_query_options(&self) -> bool {
        self.disable_cache
            || self.disable_optimistic_cache
            || self.rewrite_ttl.is_some()
            || self.timeout.is_some()
            || self.client_subnet.is_some()
            || self.remove_client_subnet
    }

    /// The servers its `preferred_by` names, and those of the rules it
    /// combines.
    pub fn preferred_by(&self) -> Vec<&String> {
        self.preferred_by
            .iter()
            .chain(self.rules.iter().flat_map(|r| r.preferred_by()))
            .collect()
    }

    fn check(&self, servers: &HashSet<String>, fake_ip: Option<&str>) -> Result<()> {
        use DnsRuleAction::*;
        if let Some(tag) = self
            .preferred_by()
            .into_iter()
            .find(|t| !servers.contains(*t))
        {
            return Err(anyhow!("preferred_by: server [{}] does not exist", tag));
        }
        let action = self.action.unwrap_or_default();
        let fields = [
            (
                "server",
                self.server.is_some(),
                &[Route, Evaluate] as &[DnsRuleAction],
            ),
            ("strategy", self.strategy.is_some(), &[Route]),
            ("tag", self.tag.is_some(), &[Evaluate]),
            ("rcode", self.rcode.is_some(), &[Predefined]),
            ("race", self.race, &[Route, Respond, Reject, Predefined]),
            ("speculative", self.speculative, &[Route, Evaluate]),
            ("answer", !self.answer.is_empty(), &[Predefined]),
            ("ns", !self.ns.is_empty(), &[Predefined]),
            ("extra", !self.extra.is_empty(), &[Predefined]),
            (
                "disable_cache",
                self.disable_cache,
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "disable_optimistic_cache",
                self.disable_optimistic_cache,
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "rewrite_ttl",
                self.rewrite_ttl.is_some(),
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "timeout",
                self.timeout.is_some(),
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "client_subnet",
                self.client_subnet.is_some(),
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "remove_client_subnet",
                self.remove_client_subnet,
                &[Route, Evaluate, RouteOptions],
            ),
        ];
        if let Some((field, _, _)) = fields
            .iter()
            .find(|(_, set, actions)| *set && !actions.contains(&action))
        {
            return Err(anyhow!("{}: not with action {}", field, action.name()));
        }
        if matches!(action, Route | Evaluate) {
            let tag = self
                .server
                .as_ref()
                .ok_or_else(|| anyhow!("server: a {} rule needs one", action.name()))?;
            if !servers.contains(tag) {
                return Err(anyhow!("server [{}] does not exist", tag));
            }
            if action == Evaluate && fake_ip == Some(tag.as_str()) {
                return Err(anyhow!(
                    "server: [{}] is the fakeip server, whose answers are not the name's",
                    tag
                ));
            }
        }
        if action == RouteOptions && !self.has_query_options() {
            return Err(anyhow!("a route-options rule sets some option"));
        }
        if self.client_subnet.is_some() && self.remove_client_subnet {
            return Err(anyhow!("client_subnet: not with remove_client_subnet"));
        }
        if self.tag.as_deref() == Some("") {
            return Err(anyhow!("tag: empty"));
        }
        if self.ip_match_all && self.invert {
            return Err(anyhow!("ip_match_all: not with invert"));
        }
        if self.race && self.speculative {
            return Err(anyhow!("race: not with speculative"));
        }
        if self.race && self.responses().is_empty() {
            return Err(anyhow!(
                "race: a race rule matches an evaluated response, and needs match_response \
                 (in the rules a logical one combines, for a logical rule)"
            ));
        }
        let response_fields = [
            ("ip_cidr", !self.ip_cidr.is_empty()),
            ("ip_is_private", self.ip_is_private),
            ("ip_accept_any", self.ip_accept_any),
            ("ip_match_all", self.ip_match_all),
            ("response_rcode", self.response_rcode.is_some()),
            ("response_answer", !self.response_answer.is_empty()),
            ("response_ns", !self.response_ns.is_empty()),
            ("response_extra", !self.response_extra.is_empty()),
        ];
        // sing-box's legacy address filter: a route rule's conditions on the
        // answer's addresses, without match_response (see `legacy_split`).
        let legacy = self.is_legacy_address_filter();
        if self.match_response.is_none() && !legacy {
            if let Some((field, _)) = response_fields.iter().find(|(_, set)| *set) {
                return Err(anyhow!(
                    "{}: matches an evaluated response, and needs match_response{}",
                    field,
                    if self.has_legacy_address_fields() {
                        " (sing-box's legacy form, without it, is a route rule's, not inverted)"
                    } else {
                        ""
                    }
                ));
            }
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check_combined(self.match_response.is_some())
                .map_err(|e| anyhow!("rules[{}]: {}", i, e))?;
        }
        // One with no conditions matches every query, as in sing-box.
        Ok(())
    }

    /// Whether it sets conditions on an answer's addresses, which sing-box
    /// took before 1.14 without match_response.
    fn has_legacy_address_fields(&self) -> bool {
        !self.ip_cidr.is_empty() || self.ip_is_private || self.ip_accept_any
    }

    /// sing-box's legacy address filter, which 1.14 still takes: a route
    /// rule with conditions on the answer's addresses and no match_response
    /// (dns/router.go, `addressLimitResponseCheck`). Only its conditions on
    /// the answer, none that 1.14 added, nor inverted.
    fn is_legacy_address_filter(&self) -> bool {
        self.match_response.is_none()
            && self.has_legacy_address_fields()
            && self.action.unwrap_or_default() == DnsRuleAction::Route
            && !self.invert
            && !self.ip_match_all
            && self.response_rcode.is_none()
            && self.response_answer.is_empty()
            && self.response_ns.is_empty()
            && self.response_extra.is_empty()
    }

    /// The legacy address filter as sail's rules have it, the `index`th of
    /// `dns.rules`: an evaluate rule, with its conditions but those on the
    /// answer, for address queries alone (A, AAAA, HTTPS); then a respond
    /// rule matching what it evaluated by those. An answer they do not hold
    /// for goes on to the rules after, as in sing-box. None for another
    /// rule.
    pub fn legacy_split(&self, index: usize) -> Option<(DnsRule, DnsRule)> {
        if !self.is_legacy_address_filter() {
            return None;
        }
        // A tag no configuration can name.
        let tag = format!("\0legacy dns.rules[{}]", index);
        let mut evaluate = DnsRule {
            action: Some(DnsRuleAction::Evaluate),
            tag: Some(tag.clone()),
            ip_cidr: Vec::new(),
            ip_is_private: false,
            ip_accept_any: false,
            ..self.clone()
        };
        if evaluate.query_type.is_empty() {
            evaluate.query_type = ["A", "AAAA", "HTTPS"]
                .into_iter()
                .map(serde_json::Value::from)
                .collect();
        }
        let respond = DnsRule {
            action: Some(DnsRuleAction::Respond),
            match_response: Some(ResponseRef::Tag(tag)),
            ip_cidr: self.ip_cidr.clone(),
            ip_is_private: self.ip_is_private,
            ip_accept_any: self.ip_accept_any,
            ..DnsRule::default()
        };
        Some((evaluate, respond))
    }

    /// A rule a logical one combines: conditions, and nothing else; those
    /// on a response need a `match_response` of its own, or of a rule it is
    /// within.
    fn check_combined(&self, within_response: bool) -> Result<()> {
        let set = [
            ("action", self.action.is_some()),
            ("server", self.server.is_some()),
            ("strategy", self.strategy.is_some()),
            ("outbound", !self.outbound.is_empty()),
            ("tag", self.tag.is_some()),
            ("rcode", self.rcode.is_some()),
            ("race", self.race),
            ("speculative", self.speculative),
            ("disable_cache", self.disable_cache),
            ("rewrite_ttl", self.rewrite_ttl.is_some()),
            ("timeout", self.timeout.is_some()),
            ("client_subnet", self.client_subnet.is_some()),
            ("remove_client_subnet", self.remove_client_subnet),
        ];
        if self.ip_match_all {
            return Err(anyhow!(
                "ip_match_all: sail takes it on a rule, not on the rules a logical one combines"
            ));
        }
        let response_fields = [
            ("ip_cidr", !self.ip_cidr.is_empty()),
            ("ip_is_private", self.ip_is_private),
            ("ip_accept_any", self.ip_accept_any),
            ("response_rcode", self.response_rcode.is_some()),
            ("response_answer", !self.response_answer.is_empty()),
            ("response_ns", !self.response_ns.is_empty()),
            ("response_extra", !self.response_extra.is_empty()),
        ];
        if !within_response && self.match_response.is_none() {
            if let Some((field, _)) = response_fields.iter().find(|(_, set)| *set) {
                return Err(anyhow!(
                    "{}: matches an evaluated response, and needs match_response",
                    field
                ));
            }
        }
        if let Some((field, _)) = set.iter().find(|(_, set)| *set) {
            return Err(anyhow!("{}: a rule a logical one combines has none", field));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check_combined(within_response || self.match_response.is_some())
                .map_err(|e| anyhow!("rules[{}]: {}", i, e))?;
        }
        Ok(())
    }

    /// The `match_response` of the rule and of those it combines.
    pub fn responses(&self) -> Vec<&ResponseRef> {
        let mut out: Vec<&ResponseRef> = self.match_response.iter().collect();
        for rule in &self.rules {
            out.extend(rule.responses());
        }
        out
    }
}

/// Which address families names resolve to, as sing-box names them.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    /// Both, IPv4 first: sing-box's default.
    #[default]
    PreferIpv4,
    /// Both, IPv6 first.
    PreferIpv6,
    /// IPv4 addresses only.
    Ipv4Only,
    /// IPv6 addresses only.
    Ipv6Only,
}

impl DnsStrategy {
    /// Whether IPv6 destinations are used at all.
    pub fn ipv6(self) -> bool {
        self != DnsStrategy::Ipv4Only
    }
}

impl Dns {
    /// sing-box's: 1024, and a smaller one taken as that.
    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity.unwrap_or(1024).max(1024)
    }

    /// How long after it expired an answer may still be given, when
    /// `optimistic` is enabled.
    pub fn optimistic_timeout(&self) -> Option<std::time::Duration> {
        self.optimistic.filter(|o| o.enabled).map(|o| {
            o.timeout
                .unwrap_or(std::time::Duration::from_secs(3 * 24 * 3600))
        })
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout.unwrap_or(std::time::Duration::from_secs(10))
    }

    /// The tags of the servers: `local` alone when none are given, for the
    /// system's resolver then stands in.
    pub fn server_tags(&self) -> HashSet<String> {
        if self.servers.is_empty() {
            return HashSet::from(["local".to_string()]);
        }
        self.servers.iter().map(|s| s.tag.clone()).collect()
    }

    /// Fills in the tags left to defaults, and checks that tags are unique
    /// and `final` names a server.
    fn validate(&mut self) -> Result<()> {
        let mut tags = HashSet::new();
        for (i, server) in self.servers.iter_mut().enumerate() {
            if server.tag.is_empty() {
                server.tag = server.kind.clone();
            }
            if !tags.insert(server.tag.clone()) {
                return Err(anyhow!(
                    "dns.servers[{}]: another server is tagged [{}]",
                    i,
                    server.tag
                ));
            }
        }
        let tags = self.server_tags();
        if let Some(tag) = &self.final_server {
            if !tags.contains(tag) {
                return Err(anyhow!("dns.final: server [{}] does not exist", tag));
            }
        }
        let fake_ip = self
            .servers
            .iter()
            .find(|s| s.kind == "fakeip")
            .map(|s| s.tag.as_str());
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check(&tags, fake_ip)
                .map_err(|e| anyhow!("dns.rules[{}]: {}", i, e))?;
        }
        self.check_responses()
    }

    /// Checks that each rule matching a response, or answering with one,
    /// has an `evaluate` rule before it that gives it; and that a rule's
    /// own `strategy`, which sing-box keeps for its legacy rules, is not
    /// set alongside them.
    fn check_responses(&self) -> Result<()> {
        let mut latest = false;
        let mut tags = HashSet::new();
        let mut uses_responses = None;
        for (i, rule) in self.rules.iter().enumerate() {
            let at = |e: String| anyhow!("dns.rules[{}]: {}", i, e);
            // Its own, and those of the rules it combines.
            let nested = rule.rules.iter().flat_map(DnsRule::responses).cloned();
            for response in rule.response().into_iter().chain(nested) {
                match response {
                    ResponseRef::Latest if !latest => {
                        return Err(at(if tags.is_empty() {
                            "the response it matches comes from an evaluate rule before it, \
                             and there is none"
                                .to_string()
                        } else {
                            "the response it matches comes from an evaluate rule without a \
                             tag before it; match_response names a tagged one"
                                .to_string()
                        }));
                    }
                    ResponseRef::Tag(tag) if !tags.contains(&tag) => {
                        return Err(at(format!(
                            "match_response: no evaluate rule before it is tagged [{}]",
                            tag
                        )));
                    }
                    _ => {}
                }
            }
            let action = rule.action.unwrap_or_default();
            if action == DnsRuleAction::Evaluate {
                match &rule.tag {
                    None => latest = true,
                    Some(tag) => {
                        if !tags.insert(tag.clone()) {
                            return Err(at(format!(
                                "tag: another evaluate rule is tagged [{}]",
                                tag
                            )));
                        }
                    }
                }
            }
            if uses_responses.is_none()
                && (rule.response().is_some()
                    || !rule.rules.iter().all(|r| r.responses().is_empty())
                    || action == DnsRuleAction::Evaluate)
            {
                uses_responses = Some(i);
            }
        }
        if let Some(i) = uses_responses {
            if let Some(j) = self.rules.iter().position(|r| r.strategy.is_some()) {
                return Err(anyhow!(
                    "dns.rules[{}].strategy: not with evaluated responses (dns.rules[{}]), as in \
                     sing-box; set dns.strategy, or an outbound's domain_resolver",
                    j,
                    i
                ));
            }
        }
        Ok(())
    }
}

/// How long a UDP session lives without traffic when its inbound does not
/// say: sing-box's default.
pub const DEFAULT_UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Inbound {
    #[serde(rename = "type")]
    pub protocol: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    /// The address to listen on; defaults to `127.0.0.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// The port to listen on. An inbound without one does not listen, and is
    /// only useful as a part of another inbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// How long a UDP session through this inbound lives without traffic;
    /// 5m when unset, as in sing-box. A number is of seconds.
    #[serde(
        default,
        with = "duration_or_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub udp_timeout: Option<std::time::Duration>,
    /// How long an accepted TCP connection is idle before keepalive probes
    /// it; 5m when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<std::time::Duration>,
    /// Between keepalive probes; 75s when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<std::time::Duration>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_tcp_keep_alive: bool,
    /// TCP Fast Open on the TCP port it listens on: what a client that
    /// has the server's cookie sends with its SYN is taken at once. On
    /// Linux, only with the server bit of `net.ipv4.tcp_fastopen` (2; 3 for
    /// client and server), which the default (1) leaves off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tcp_fast_open: bool,
    /// Whether the datagrams it sends from its UDP sockets may be
    /// fragmented on the way: where not, they carry don't-fragment, and
    /// one larger than the path takes is refused rather than sent in
    /// pieces. Unset, as sing-box: they may for direct and hysteria2, and
    /// may not for the others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_fragment: Option<bool>,
    #[serde(flatten)]
    pub options: Options,
}

impl Inbound {
    /// Whether its UDP sockets' datagrams may be fragmented:
    /// `udp_fragment`, or sing-box's default for its protocol.
    pub fn udp_fragment(&self) -> bool {
        self.udp_fragment
            .unwrap_or(matches!(self.protocol.as_str(), "direct" | "hysteria2"))
    }

    pub fn udp_timeout(&self) -> std::time::Duration {
        self.udp_timeout.unwrap_or(DEFAULT_UDP_TIMEOUT)
    }

    /// The keepalive of the TCP connections it accepts.
    pub fn tcp_keep_alive(&self) -> Option<crate::net::dial::TcpKeepAlive> {
        crate::net::dial::tcp_keep_alive(
            self.disable_tcp_keep_alive,
            self.tcp_keep_alive,
            self.tcp_keep_alive_interval,
        )
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub protocol: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub options: Options,
}

/// An endpoint: an outbound, and an inbound, under one tag. Like an
/// outbound's, its options belong to its protocol.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Endpoint {
    #[serde(rename = "type")]
    pub protocol: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    /// How long a UDP session coming in through this endpoint lives
    /// without traffic; 5m when unset, as for an inbound.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<std::time::Duration>,
    #[serde(flatten)]
    pub options: Options,
}

impl Endpoint {
    /// The endpoint as the inbound it also is, for what serves inbounds.
    pub fn as_inbound(&self) -> Inbound {
        Inbound {
            protocol: self.protocol.clone(),
            tag: self.tag.clone(),
            listen: None,
            listen_port: None,
            udp_timeout: self.udp_timeout,
            tcp_keep_alive: None,
            tcp_keep_alive_interval: None,
            disable_tcp_keep_alive: false,
            tcp_fast_open: false,
            udp_fragment: None,
            options: Options::new(),
        }
    }
}

/// Outbounds given together, for groups to take as members (their
/// `providers`): a sail extension, with the semantics of Mihomo's
/// proxy-providers. A subscription or a file holds what Mihomo reads from
/// one: Clash's YAML with its `proxies`, or share links, a line each and
/// maybe in base64. It needs the outbound-provider feature.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutboundProvider {
    #[serde(rename = "type")]
    pub kind: OutboundProviderKind,
    /// Its members' keys name it, and groups' `providers`.
    pub tag: String,
    /// `remote`: where it is downloaded from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `local`: the file, in the data directory unless absolute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `remote`: how often it is downloaded again, 1d when unset. `local`:
    /// how often the file is read again, never when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<std::time::Duration>,
    /// `remote`: the outbound it is downloaded through, as a remote
    /// rule-set's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,
    /// `remote`: the HTTP client it is downloaded with, as a remote
    /// rule-set's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_client: Option<HttpClientRef>,
    /// `remote`, a sail extension (Mihomo's `size-limit`): the most a
    /// download of it may be, in bytes; past it the download fails and the
    /// outbounds in use are kept. Unset, the download client's own cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u64>,
    /// `remote`, `local`: regular expressions, as Mihomo's `filter`; only
    /// the outbounds whose names match one are taken, those of the first
    /// first.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub filter: Vec<String>,
    /// `remote`, `local`: regular expressions no name taken may match.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_filter: Vec<String>,
    /// `remote`, `local`: the Clash types (`ss`, `vmess`, ...) not taken,
    /// without case.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_type: Vec<String>,
    /// `remote`, `local`: what is changed in every outbound taken, in the
    /// keys of Mihomo's `override` (`skip-cert-verify`,
    /// `additional-prefix`, `proxy-name`, ...).
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<serde_json::Map<String, serde_json::Value>>,
    /// `remote`, `local`: the outbound every outbound taken dials through,
    /// as Mihomo's `dialer-proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// `inline`: the outbounds, their tags their names as members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundProviderKind {
    Remote,
    Local,
    Inline,
}

/// The protocols of groups, which take other outbounds as members.
pub const GROUP_PROTOCOLS: &[&str] = &[
    "selector",
    "urltest",
    "fallback",
    "load-balance",
    "smart",
    "tryall",
    "network",
];

/// The groups that take members from outbound providers too.
pub const PROVIDER_GROUPS: &[&str] = &["selector", "urltest", "fallback", "load-balance", "smart"];

impl OutboundProvider {
    /// The mistakes one provider can make on its own, and those naming what
    /// is not there: `outbounds` and `http_clients` are the tags there are.
    fn check(
        &self,
        outbounds: &HashSet<&str>,
        http_clients: &HashSet<&str>,
        dns_servers: &HashSet<String>,
    ) -> Result<()> {
        use OutboundProviderKind::*;
        if self.tag.is_empty() {
            return Err(anyhow!("tag: missing"));
        }
        let only = |set: bool, field: &str, kinds: &str| {
            if set {
                Err(anyhow!("{}: only a {} provider takes one", field, kinds))
            } else {
                Ok(())
            }
        };
        match self.kind {
            Remote => {
                let url = self.url.as_deref().ok_or_else(|| anyhow!("url: missing"))?;
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err(anyhow!(
                        "url: {} is not an http(s) URL",
                        crate::common::redact::url(url)
                    ));
                }
                if self.http_client.is_some() && self.download_detour.is_some() {
                    return Err(anyhow!(
                        "http_client: not with download_detour, which it replaces"
                    ));
                }
                if self.size_limit == Some(0) {
                    return Err(anyhow!("size_limit: must be more than 0"));
                }
            }
            Local => {
                if self.path.is_none() {
                    return Err(anyhow!("path: missing"));
                }
            }
            Inline => {
                if self.outbounds.is_empty() {
                    return Err(anyhow!("outbounds: missing"));
                }
                let mut names = HashSet::new();
                for (i, outbound) in self.outbounds.iter().enumerate() {
                    if outbound.tag.is_empty() {
                        return Err(anyhow!("outbounds[{}].tag: missing", i));
                    }
                    if !names.insert(outbound.tag.as_str()) {
                        return Err(anyhow!(
                            "outbounds[{}]: another outbound is tagged [{}]",
                            i,
                            outbound.tag
                        ));
                    }
                    if GROUP_PROTOCOLS.contains(&outbound.protocol.as_str())
                        || outbound.protocol == "plugin"
                        || outbound.protocol == "pass"
                    {
                        return Err(anyhow!(
                            "outbounds[{}]: a group, a plugin or a pass outbound is not a \
                             provider's outbound",
                            i
                        ));
                    }
                }
                only(
                    self.update_interval.is_some(),
                    "update_interval",
                    "remote or local",
                )?;
                let selection = [
                    ("filter", !self.filter.is_empty()),
                    ("exclude_filter", !self.exclude_filter.is_empty()),
                    ("exclude_type", !self.exclude_type.is_empty()),
                    ("override", self.overrides.is_some()),
                    ("detour", self.detour.is_some()),
                ];
                for (field, set) in selection {
                    only(set, field, "remote or local")?;
                }
            }
        }
        if self.kind != Remote {
            only(self.url.is_some(), "url", "remote")?;
            only(self.download_detour.is_some(), "download_detour", "remote")?;
            only(self.http_client.is_some(), "http_client", "remote")?;
            only(self.size_limit.is_some(), "size_limit", "remote")?;
        }
        if self.kind != Local {
            only(self.path.is_some(), "path", "local")?;
        }
        if self.kind != Inline {
            only(!self.outbounds.is_empty(), "outbounds", "inline")?;
        }
        if self.update_interval == Some(std::time::Duration::ZERO) {
            return Err(anyhow!("update_interval: must be more than 0"));
        }
        for (field, tag) in [
            ("detour", &self.detour),
            ("download_detour", &self.download_detour),
        ] {
            if let Some(tag) = tag {
                if !outbounds.contains(tag.as_str()) {
                    return Err(anyhow!("{}: outbound [{}] does not exist", field, tag));
                }
            }
        }
        match &self.http_client {
            Some(HttpClientRef::Tag(tag)) if !http_clients.contains(tag.as_str()) => {
                Err(anyhow!("http_client: http client [{}] does not exist", tag))
            }
            Some(HttpClientRef::Inline(client)) => client
                .check(outbounds, dns_servers)
                .map_err(|e| anyhow!("http_client: {}", e)),
            _ => Ok(()),
        }
    }
}

/// The members a group takes from outbound providers, after its own
/// `outbounds`, and those it leaves out: a sail extension, as Mihomo's
/// proxy groups take them (`use`, `filter`, `exclude-filter`,
/// `exclude-type`, `empty-fallback`). Of `selector`, `urltest`, `fallback`,
/// `load-balance` and `smart`; it needs the outbound-provider feature.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct GroupProviders {
    /// The outbound providers, by tag, whose outbounds join the group's
    /// own, in this order.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    /// Regular expressions, as Mihomo's `filter`: of the providers'
    /// outbounds, only those whose names match one are members, those of
    /// the first first. The group's own outbounds are not filtered.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub filter: Vec<String>,
    /// Regular expressions no member's name may match, the group's own
    /// outbounds' too.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_filter: Vec<String>,
    /// The types no member may be of, the group's own outbounds too, in
    /// Mihomo's names for them, without case: `Shadowsocks`, `Vmess`,
    /// `Socks5`, `Direct`, ...
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_type: Vec<String>,
    /// An outbound, not a group, that is the member while there is none
    /// else. Without it such a group has none, and its connections fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_fallback: Option<String>,
}

impl GroupProviders {
    /// What the group's options set of it.
    pub fn of(options: &Options) -> Result<Self> {
        serde_path_to_error::deserialize(serde_json::Value::Object(options.clone()))
            .map_err(|e| anyhow!("{}: {}", path(&e), e.inner()))
    }

    /// The first of its fields that is set, if any is.
    pub fn first_set(&self) -> Option<&'static str> {
        [
            ("providers", !self.providers.is_empty()),
            ("filter", !self.filter.is_empty()),
            ("exclude_filter", !self.exclude_filter.is_empty()),
            ("exclude_type", !self.exclude_type.is_empty()),
            ("empty_fallback", self.empty_fallback.is_some()),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    /// The outbounds a group with `outbounds` of its own is built on: the
    /// empty fallback too.
    pub fn dependencies(&self, mut outbounds: Vec<String>) -> Vec<String> {
        outbounds.extend(self.empty_fallback.clone());
        outbounds
    }

    fn check(&self, providers: &HashSet<&str>, protocols: &HashMap<&str, &str>) -> Result<()> {
        if !cfg!(feature = "outbound-provider") {
            if let Some(field) = self.first_set() {
                return Err(anyhow!(
                    "{}: needs the outbound-provider feature, which is not compiled in",
                    field
                ));
            }
        }
        if let Some(tag) = self
            .providers
            .iter()
            .find(|p| !providers.contains(p.as_str()))
        {
            return Err(anyhow!("providers: provider [{}] does not exist", tag));
        }
        if !self.filter.is_empty() && self.providers.is_empty() {
            return Err(anyhow!(
                "filter: only with providers, as the group's own outbounds are not filtered"
            ));
        }
        if let Some(tag) = &self.empty_fallback {
            match protocols.get(tag.as_str()) {
                None => {
                    return Err(anyhow!("empty_fallback: outbound [{}] does not exist", tag));
                }
                Some(protocol) if GROUP_PROTOCOLS.contains(protocol) => {
                    return Err(anyhow!("empty_fallback: [{}] is a group", tag));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(
        default,
        deserialize_with = "exactly::deserialize",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub rules: Vec<Rule>,
    /// The rule-sets rules name, by tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<super::rule_set::RuleSet>,
    /// The outbound for connections no rule matches; defaults to the first
    /// outbound.
    #[serde(rename = "final", default, skip_serializing_if = "Option::is_none")]
    pub final_outbound: Option<String>,
    /// The interface outbounds that name none of their own send through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interface: Option<String>,
    /// The routing mark (`SO_MARK`, Linux) of outbounds that set none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mark: Option<u32>,
    /// Sends outbounds that name no interface of their own through the
    /// system's default interface, found at start. Needed when a TUN inbound
    /// routes everything, or outbound traffic would loop back into it.
    #[serde(default)]
    pub auto_detect_interface: bool,
    /// Looks up who opened every connection (the program, the package,
    /// the user), for the connections list, though no rule asks; without
    /// it, only when a rule has conditions on it, as in sing-box.
    #[serde(default)]
    pub find_process: bool,
    /// The DNS server that resolves the names outbounds dial, for those
    /// that name no `domain_resolver` of their own. Unset, the DNS rules
    /// decide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<DomainResolver>,
    /// The `network_strategy`, `network_type`, `fallback_network_type`
    /// and `fallback_delay` of what sets none of the first three, or no
    /// delay; the strategy needs `auto_detect_interface`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network_strategy: Option<crate::net::dial::NetworkStrategy>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub default_network_type: Vec<crate::net::network::NetworkType>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub default_fallback_network_type: Vec<crate::net::network::NetworkType>,
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub default_fallback_delay: Option<std::time::Duration>,
    /// Looks up the LAN device of each connection's source even without a
    /// rule on it, for the logs (sing-box's, since 1.14).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub find_neighbor: bool,
    /// The DHCP lease files the LAN devices' names are read from; the
    /// usual ones of dnsmasq, odhcpd, ISC dhcpd and Kea when none.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub dhcp_lease_files: Vec<String>,
    /// The HTTP client of what names none, by tag; the first of
    /// `http_clients` when unset, or with none, the default outbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_http_client: Option<String>,
    /// A sail extension, Surge's `block-quic`: the outbounds QUIC is
    /// refused to, by tag. A UDP connection sniffing recognized as QUIC
    /// that the rules send to one is rejected as a reject rule would, so
    /// that the app goes on over TCP. Sniffing is the rules' to ask for.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub block_quic: Vec<String>,
}

impl Route {
    /// The outbounds its rules may send a connection to, and `final`, or
    /// else the first of `outbounds`, which takes what no rule matches.
    pub fn outbounds<'a>(&'a self, outbounds: &'a [Outbound]) -> Vec<&'a str> {
        let mut tags: Vec<&str> = self
            .rules
            .iter()
            .filter_map(|r| r.outbound.as_deref())
            .collect();
        match &self.final_outbound {
            Some(tag) => tags.push(tag),
            None => tags.extend(outbounds.first().map(|o| o.tag.as_str())),
        }
        tags.sort();
        tags.dedup();
        tags
    }
}

/// A DNS server that resolves the names something dials: its tag, or
/// `{ "server": tag, "strategy": ... }` with how the queries are sent, as a
/// DNS rule's route options say it.
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainResolver {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_optimistic_cache: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
}

impl<'de> serde::Deserialize<'de> for DomainResolver {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            server: String,
            #[serde(default)]
            strategy: Option<DnsStrategy>,
            #[serde(default, with = "duration")]
            timeout: Option<std::time::Duration>,
            #[serde(default)]
            disable_cache: bool,
            #[serde(default)]
            disable_optimistic_cache: bool,
            #[serde(default)]
            rewrite_ttl: Option<u32>,
            #[serde(default)]
            client_subnet: Option<Prefix>,
        }
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::String(server) => Ok(DomainResolver {
                server,
                ..Default::default()
            }),
            value => {
                let full = Full::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(DomainResolver {
                    server: full.server,
                    strategy: full.strategy,
                    timeout: full.timeout,
                    disable_cache: full.disable_cache,
                    disable_optimistic_cache: full.disable_optimistic_cache,
                    rewrite_ttl: full.rewrite_ttl,
                    client_subnet: full.client_subnet,
                })
            }
        }
    }
}

/// A routing rule, matched in order, as sing-box has it. A default rule
/// sets conditions on the things a connection is known by: of the
/// conditions on one thing (the source's address, its port, the
/// destination's address, its port) any matching will do, and the rule
/// matches when each thing it has conditions on matches and every other
/// condition does. A condition listing several values matches when any of
/// them does. A logical rule (`type: logical`) combines the rules in
/// `rules`, all of them (`mode: and`) or any (`mode: or`); `invert` turns
/// either kind's result around.
///
/// `route`, `reject` and `hijack-dns` end the matching. `route-options`,
/// `sniff` and `resolve` learn more about the connection or say how it is
/// to be carried, and matching goes on with the next rule.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `default`, or `logical`.
    #[serde(rename = "type", default, skip_serializing_if = "RuleType::is_default")]
    pub kind: RuleType,

    /// Record types, by name (`A`, `AAAA`, `HTTPS`) or number: of a DNS
    /// query, and so never of a connection.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub query_type: List<serde_json::Value>,
    /// Tags of DNS servers, one of which prefers the name: of a DNS query,
    /// and so never of a connection.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub preferred_by: List<String>,
    /// The mode of Clash's API: matches while it is that, whatever the
    /// case; never without an API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,
    /// Tags of the inbounds a connection came in through.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub inbound: List<String>,
    /// 4 or 6: the family of the destination address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,
    /// `tcp`, `udp`.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub network: List<String>,
    /// Names of the users an inbound authenticated.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub auth_user: List<String>,
    /// The protocols a `sniff` rule found, by sing-box's names: `tls`,
    /// `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub protocol: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub domain: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub domain_suffix: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub domain_keyword: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub domain_regex: List<String>,
    /// Site groups, looked up in `site.dat` in the asset directory. A sail
    /// extension: sing-box has dropped its GeoIP and GeoSite databases.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub geosite: List<String>,
    /// Country codes, looked up in `geo.mmdb` in the asset directory; a
    /// sail extension, as `geosite` is.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub geoip: List<String>,
    /// A sail extension: `mmdb:<file>:<code>` or `site:<file>:<code>`, for
    /// data files other than the default ones.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub external: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub source_ip_cidr: List<String>,
    /// The source address is not a public one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_ip_is_private: bool,
    /// MAC addresses of the LAN device the connection comes from, as the
    /// neighbor table and DHCP leases know it (sing-box's, since 1.14).
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub source_mac_address: List<String>,
    /// Host names of the LAN device the connection comes from, as its DHCP
    /// lease has it.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub source_hostname: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub ip_cidr: List<String>,
    /// The destination address, or one the domain resolved to, is not a
    /// public one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
    /// A sail extension, for Surge's `USER-AGENT`: patterns the User-Agent
    /// of a plain HTTP request a `sniff` rule read matches, whole and with
    /// case, `*` any run of characters and `?` any one.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub http_user_agent: List<String>,
    /// A sail extension, for Surge's `URL-REGEX`: regular expressions found
    /// in the URL of a plain HTTP request a `sniff` rule read,
    /// `http://host/path?query`.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub url_regex: List<String>,
    /// A sail extension, for Surge's `IP-ASN`: the autonomous systems the
    /// destination address, or one the domain resolved to, belongs to, as
    /// `asn.mmdb` in the asset directory (GeoLite2-ASN's format, or
    /// ipinfo's) has them.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub ip_asn: List<u32>,
    /// A DNS rule's: the response it matches has an address.
    #[serde(skip)]
    pub ip_accept_any: bool,
    /// A DNS rule's: the response it matches has this code.
    #[serde(skip)]
    pub response_rcode: Option<u16>,
    /// A DNS rule's: the response it matches has one of these records
    /// among its answers, as the configuration writes them; parsed when
    /// the rule is compiled.
    #[serde(skip)]
    pub response_answer: List<String>,
    /// A DNS rule's: among its name servers.
    #[serde(skip)]
    pub response_ns: List<String>,
    /// A DNS rule's: among its additional records.
    #[serde(skip)]
    pub response_extra: List<String>,
    /// A DNS rule's, combined by a logical one: the evaluated response it
    /// matches, rather than the one of the rule it is within.
    #[serde(skip)]
    pub match_response: Option<ResponseRef>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub source_port: List<u16>,
    /// Inclusive port ranges, as `port_range` writes them.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub source_port_range: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub port: List<u16>,
    /// Inclusive port ranges, as sing-box writes them: `1000:2000`, `:1024`,
    /// `8000:`.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub port_range: List<String>,
    /// The name of the program a connection comes from, its path's last
    /// part.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub process_name: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub process_path: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub process_path_regex: List<String>,
    /// A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular
    /// expressions the program's name, its path's last part, matches.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub process_name_regex: List<String>,
    /// Android packages: the app the host says opened the connection
    /// (`find_connection_owner`); an error without a host that tells.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub package_name: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub package_name_regex: List<String>,
    /// The user a connection's app runs as, by name and by id, as the host
    /// tells it; an error without a host that tells.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub user: List<String>,
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub user_id: List<i32>,
    /// The name of the Wi-Fi network the host is on, whole and with case.
    /// This and the other conditions on the network match the network as
    /// the host tells it or sail detects it at the time; one on something
    /// not known of it does not match.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub wifi_ssid: List<String>,
    /// The address of the Wi-Fi access point, `aa:bb:cc:dd:ee:ff`, in any
    /// case, with `:` or `-`, or as 12 hex digits.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub wifi_bssid: List<String>,
    /// The kind of network: `wifi`, `cellular`, `ethernet`, `other`.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub network_type: List<String>,
    /// The network is metered, as the system says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_is_expensive: bool,
    /// The network is in a low data mode, as the system says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_is_constrained: bool,
    /// A sail extension, for Surge's `SSID:`: regular expressions found in
    /// the Wi-Fi network's name, with case.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub wifi_ssid_regex: List<String>,
    /// A sail extension, for Surge's `BSSID:`: regular expressions found in
    /// the access point's address as `aa:bb:cc:dd:ee:ff`, whatever the case.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub wifi_bssid_regex: List<String>,
    /// A sail extension, for Surge's `ROUTER:`: the address of the default
    /// gateway.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub network_gateway: List<String>,
    /// A sail extension, for Surge's `MCCMNC:` and `CELLULAR-CARRIER`: the
    /// cellular carrier, its MCC and MNC as 5 or 6 digits; only off Wi-Fi.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub network_mcc_mnc: List<String>,
    /// Tags of rule-sets, any of whose rules matching matches.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub rule_set: List<String>,
    /// The rule-sets' `ip_cidr` match the source address, not the
    /// destination.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rule_set_ip_cidr_match_source: bool,
    /// A sail extension, Surge's and Clash's `no-resolve`: the rule's
    /// conditions on the destination's addresses (`ip_cidr`,
    /// `ip_is_private`, `ip_asn`, `geoip`, those of its rule-sets and of
    /// the rules within) match only addresses already known, and never
    /// have an `on_demand` resolve resolve the domain for them. Only for a
    /// rule with such conditions.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_resolve: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// `logical`: `and` or `or`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogicalMode>,
    /// `logical`: the rules combined. They take no action of their own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,

    /// `route` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RuleAction>,
    /// `route`: where a matching connection goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// `route`, `route-options`: connects to this address, an IP or a
    /// domain, instead of the one asked for, on the same port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,
    /// `route`, `route-options`: connects to this port instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_port: Option<u16>,
    /// `route`, `route-options`: answers to UDP sent to a domain come back
    /// from the address it resolved to, not from the domain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp_disable_domain_unmapping: bool,
    /// `route`, `route-options`: a direct outbound sends UDP from a
    /// connected socket.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp_connect: bool,
    /// `route`, `route-options`: how long a UDP session lasts idle,
    /// instead of its inbound's `udp_timeout`.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<std::time::Duration>,
    /// `route`, `route-options`: sends the TLS ClientHello in pieces, cut
    /// in the server name, each in a TCP segment of its own.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_fragment: bool,
    /// `route`, `route-options`: how long to wait between the pieces;
    /// 500ms when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tls_fragment_fallback_delay: Option<std::time::Duration>,
    /// `route`, `route-options`: sends the TLS ClientHello as several TLS
    /// records, cut in the server name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_record_fragment: bool,
    /// `route`, `route-options`: how a direct outbound the connection goes
    /// out of chooses among the host's interfaces, instead of as its own
    /// says; not where it binds its sockets itself. A later rule's goes
    /// before. As in sing-box, only where the destination is an address
    /// (for UDP, a connected one) or a `resolve` rule resolved it; other
    /// outbounds, a group whose pick is a direct one among them, take no
    /// notice of it. `direct`: checked only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<crate::net::dial::NetworkStrategy>,
    /// `route`, `route-options`: how long a direct outbound the connection
    /// goes out of tries one family's addresses, and its first interfaces,
    /// before the others race them, instead of its own `fallback_delay`,
    /// where `network_strategy` would apply. A later rule's goes before. A
    /// duration string, as sing-box's documentation writes it, or a number
    /// of nanoseconds, as sing-box 1.14.1 reads it here. `direct`: checked
    /// only.
    #[serde(
        default,
        with = "duration_or_nanos",
        skip_serializing_if = "Option::is_none"
    )]
    pub fallback_delay: Option<std::time::Duration>,
    /// `direct`: the interface to send through, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// `direct`: the local address for IPv4 destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_bind_address: Option<std::net::Ipv4Addr>,
    /// `direct`: the local address for IPv6 destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_bind_address: Option<std::net::Ipv6Addr>,
    /// `direct`: `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an
    /// address: Linux only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bind_address_no_port: bool,
    /// `direct`: the Unix socket each socket's descriptor is handed to, to
    /// be protected: Unix only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protect_path: Option<String>,
    /// `direct`: `SO_MARK`, Linux only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<u32>,
    /// `direct`: `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP
    /// sockets.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reuse_addr: bool,
    /// `direct`: how long a TCP connect to one address may take; 5s when
    /// unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<std::time::Duration>,
    /// `direct`: TCP Fast Open.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tcp_fast_open: bool,
    /// `direct`: no TCP keepalive at all.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_tcp_keep_alive: bool,
    /// `direct`: how long a TCP connection is idle before keepalive probes
    /// it; 5m when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<std::time::Duration>,
    /// `direct`: between keepalive probes; 75s when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<std::time::Duration>,
    /// `direct`: whether UDP datagrams may be fragmented on the way; not
    /// when unset, as sing-box's direct action has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_fragment: Option<bool>,
    /// `direct`: the DNS server that resolves the names it dials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<DomainResolver>,
    /// `direct`, a sail extension: without a `domain_resolver` of its own,
    /// the names it dials resolve as the DNS rules say, not as
    /// `route.default_domain_resolver` does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_default_domain_resolver: bool,
    /// `direct`: sing-box's deprecated field for the families names
    /// resolve to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<DnsStrategy>,
    /// `direct`: the types of interface its `fallback` strategy falls back
    /// to. Its `network_type` is not one: a rule's `network_type` is its
    /// condition, as in sing-box.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub fallback_network_type: List<crate::net::network::NetworkType>,
    /// `reject`: how.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<RejectMethod>,
    /// `reject`: never drops, however many connections the rule rejects.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_drop: bool,
    /// `resolve`: the DNS server to ask, rather than the one the DNS rules
    /// pick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// `resolve`: the address families, instead of `dns.strategy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
    /// `resolve`: the answers neither come from the DNS cache nor go into
    /// it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    /// `resolve`: an expired answer is not given while it is asked for
    /// again, though `dns.optimistic` is enabled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_optimistic_cache: bool,
    /// `resolve`: the TTL the answers' records carry, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    /// `resolve`: the EDNS Client Subnet the queries carry, instead of
    /// `dns.client_subnet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
    /// `sniff`: the protocols to look for; all of them when empty.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub sniffer: List<Sniffer>,
    /// `sniff`: how long to wait for the first bytes; 300ms when unset.
    /// `resolve`: how long to wait for the answer; `dns.timeout` when
    /// unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// `route`, `route-options`, `sniff`, a sail extension: a connection to
    /// an address is dialled by the name known for it, the sniffed domain
    /// or else the one `dns.reverse_mapping` keeps, where its last hop
    /// dials a proxy's server (`true` or `"proxy"`), or a direct dial too
    /// (`"proxy_and_direct"`). The rules still match the address. On a
    /// sniff rule, `"at_sniff"` instead makes the sniffed domain the
    /// destination there, for the rules after, as Mihomo's sniffer does.
    #[serde(
        default,
        deserialize_with = "override_destination::deserialize",
        skip_serializing_if = "Option::is_none"
    )]
    pub override_destination: Option<OverrideDestinationField>,
    /// `sniff`, a sail extension: a domain found that one of these
    /// rule-sets matches is not taken, neither matched nor connected to, as
    /// Mihomo's sniffer `skip-domain` has it.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub skip_rule_set: List<String>,
    /// `resolve`, a sail extension: a domain that does not resolve, or not in
    /// time, has no addresses, and matching goes on, as Mihomo's IP rules
    /// have it; rather than the connection failing, as in sing-box.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_failure: bool,
    /// `resolve`, `sniff`, a sail extension: the rule does not act where
    /// it stands but arms its action, with its options, and matching goes
    /// on. The action is taken the first time a later rule needs what it
    /// learns, just before that rule is matched: a resolve for a rule
    /// with conditions on the destination's addresses, while the
    /// destination is a domain; a sniff for one on the protocol, the plain
    /// HTTP request, or a domain while the destination is an address. A
    /// connection no later rule needs it for is never resolved or sniffed,
    /// as Surge and Mihomo have it. A later rule arming the same action
    /// replaces its options.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub on_demand: bool,

    /// The inline Clash or Surge lines merged into this rule, each told and
    /// numbered as the rule it was (`config::inline`); empty for any other
    /// rule. Not configuration: never read from or written to one.
    #[serde(skip)]
    pub lines: List<Line>,
    /// The index the rule had in `route.rules` before lines were merged,
    /// which its matches are reported by; none when nothing was merged,
    /// and its place is that index.
    #[serde(skip)]
    pub index: Option<u32>,
}

/// An inline line merged into a rule: its one domain, and its index in
/// `route.rules` before the merge.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub index: u32,
    pub kind: LineKind,
    pub value: String,
}

/// Which of a rule's domain fields a merged line's domain was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Domain,
    Suffix,
    Keyword,
}

/// Which dials of a connection to an address go to the name known for
/// it: a rule's `override_destination`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverrideDestination {
    /// `true` or `"proxy"`: a proxy's server is asked for the name, and a
    /// direct dial keeps the address.
    Proxy,
    /// `"proxy_and_direct"`: a direct dial too goes to the name, which it
    /// resolves as its own `domain_resolver` says.
    ProxyAndDirect,
    /// `"at_sniff"`, a sniff rule's only: the sniffed domain becomes the
    /// destination where the rule stands, so that the rules after match it
    /// and resolve it, as Mihomo's sniffer `override-destination` does.
    AtSniff,
}

/// `override_destination` as it is written: `true` (`"proxy"`), `false`
/// (none), or a name.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(untagged)]
pub enum OverrideDestinationField {
    Bool(bool),
    Name(OverrideDestination),
}

impl OverrideDestinationField {
    /// What it asks for.
    pub fn get(self) -> Option<OverrideDestination> {
        match self {
            OverrideDestinationField::Bool(on) => on.then_some(OverrideDestination::Proxy),
            OverrideDestinationField::Name(how) => Some(how),
        }
    }
}

/// `override_destination`: `true`, `false` or a name, refused with the
/// values it takes.
mod override_destination {
    use super::{OverrideDestination, OverrideDestinationField};
    use serde::{de, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OverrideDestinationField>, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = Option<OverrideDestinationField>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("true, false, \"proxy\", \"proxy_and_direct\" or \"at_sniff\"")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Some(OverrideDestinationField::Bool(v)))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let how = match v {
                    "proxy" => OverrideDestination::Proxy,
                    "proxy_and_direct" => OverrideDestination::ProxyAndDirect,
                    "at_sniff" => OverrideDestination::AtSniff,
                    _ => return Err(E::invalid_value(de::Unexpected::Str(v), &self)),
                };
                Ok(Some(OverrideDestinationField::Name(how)))
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// A rule's kind.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    /// Conditions of its own.
    #[default]
    Default,
    /// Other rules, combined.
    Logical,
}

impl RuleType {
    fn is_default(&self) -> bool {
        *self == RuleType::Default
    }
}

/// How a logical rule combines its rules.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogicalMode {
    /// All of them match.
    And,
    /// Any of them does.
    Or,
}

/// What a matching rule does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Sends the connection to `outbound`.
    #[default]
    Route,
    /// Sets how the connection is carried, and lets the next rules decide
    /// where it goes.
    RouteOptions,
    /// Closes the connection.
    Reject,
    /// Answers the DNS queries the connection carries.
    HijackDns,
    /// Reads the domain from the first bytes of a TCP connection (TLS SNI,
    /// HTTP Host), so that later rules match it.
    Sniff,
    /// Resolves the domain, so that later rules match its addresses; a
    /// domain that does not resolve fails the connection.
    Resolve,
    /// As sing-box 1.13: lets the kernel carry the connection past the
    /// proxy where TUN's auto_redirect matches it before it is set up.
    /// Elsewhere it routes to `outbound` like `route`, and without one the
    /// rule is skipped.
    Bypass,
    /// As in sing-box 1.14.1, nothing: its dial fields are checked as an
    /// outbound's are, and matching goes on past it, with a warning.
    Direct,
}

/// How a `reject` rule closes a connection.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectMethod {
    /// At once; dropped instead when the rule rejects more than 50
    /// connections in 30 seconds, unless `no_drop`.
    #[default]
    Default,
    /// Left unanswered.
    Drop,
    /// With an ICMP message, for ICMP; sail routes none.
    Reply,
}

/// A protocol a `sniff` rule looks for, by sing-box's name. TLS, HTTP and
/// QUIC name the domain too (QUIC's needs the `btls` crypto compiled in);
/// DNS, STUN, BitTorrent and DTLS are only recognized.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sniffer {
    Tls,
    Http,
    Quic,
    Dns,
    Stun,
    Bittorrent,
    Dtls,
}

impl Rule {
    /// What the rule does.
    pub fn action(&self) -> RuleAction {
        self.action.unwrap_or_default()
    }

    /// Which dials go to the name known for the address, as
    /// `override_destination` says.
    pub fn override_destination(&self) -> Option<OverrideDestination> {
        self.override_destination
            .and_then(OverrideDestinationField::get)
    }

    /// The first condition of a default rule the rule sets, by name.
    pub fn first_condition(&self) -> Option<&'static str> {
        [
            ("query_type", !self.query_type.is_empty()),
            ("preferred_by", !self.preferred_by.is_empty()),
            ("clash_mode", self.clash_mode.is_some()),
            ("inbound", !self.inbound.is_empty()),
            ("ip_version", self.ip_version.is_some()),
            ("network", !self.network.is_empty()),
            ("auth_user", !self.auth_user.is_empty()),
            ("protocol", !self.protocol.is_empty()),
            ("domain", !self.domain.is_empty()),
            ("domain_suffix", !self.domain_suffix.is_empty()),
            ("domain_keyword", !self.domain_keyword.is_empty()),
            ("domain_regex", !self.domain_regex.is_empty()),
            ("geosite", !self.geosite.is_empty()),
            ("geoip", !self.geoip.is_empty()),
            ("external", !self.external.is_empty()),
            ("source_ip_cidr", !self.source_ip_cidr.is_empty()),
            ("source_ip_is_private", self.source_ip_is_private),
            ("source_mac_address", !self.source_mac_address.is_empty()),
            ("source_hostname", !self.source_hostname.is_empty()),
            ("ip_cidr", !self.ip_cidr.is_empty()),
            ("ip_is_private", self.ip_is_private),
            ("ip_asn", !self.ip_asn.is_empty()),
            ("http_user_agent", !self.http_user_agent.is_empty()),
            ("url_regex", !self.url_regex.is_empty()),
            ("ip_accept_any", self.ip_accept_any),
            ("response_rcode", self.response_rcode.is_some()),
            ("response_answer", !self.response_answer.is_empty()),
            ("response_ns", !self.response_ns.is_empty()),
            ("response_extra", !self.response_extra.is_empty()),
            ("match_response", self.match_response.is_some()),
            ("source_port", !self.source_port.is_empty()),
            ("source_port_range", !self.source_port_range.is_empty()),
            ("port", !self.port.is_empty()),
            ("port_range", !self.port_range.is_empty()),
            ("process_name", !self.process_name.is_empty()),
            ("process_path", !self.process_path.is_empty()),
            ("process_path_regex", !self.process_path_regex.is_empty()),
            ("process_name_regex", !self.process_name_regex.is_empty()),
            ("package_name", !self.package_name.is_empty()),
            ("package_name_regex", !self.package_name_regex.is_empty()),
            ("user", !self.user.is_empty()),
            ("user_id", !self.user_id.is_empty()),
            ("wifi_ssid", !self.wifi_ssid.is_empty()),
            ("wifi_bssid", !self.wifi_bssid.is_empty()),
            ("network_type", !self.network_type.is_empty()),
            ("network_is_expensive", self.network_is_expensive),
            ("network_is_constrained", self.network_is_constrained),
            ("wifi_ssid_regex", !self.wifi_ssid_regex.is_empty()),
            ("wifi_bssid_regex", !self.wifi_bssid_regex.is_empty()),
            ("network_gateway", !self.network_gateway.is_empty()),
            ("network_mcc_mnc", !self.network_mcc_mnc.is_empty()),
            ("rule_set", !self.rule_set.is_empty()),
            (
                "rule_set_ip_cidr_match_source",
                self.rule_set_ip_cidr_match_source,
            ),
        ]
        .into_iter()
        .find(|(_, set)| *set)
        .map(|(field, _)| field)
    }

    /// Whether the rule sets any condition; one that sets none matches
    /// every connection.
    pub fn has_conditions(&self) -> bool {
        match self.kind {
            RuleType::Default => self.first_condition().is_some(),
            RuleType::Logical => !self.rules.is_empty(),
        }
    }

    /// The action fields the rule sets, by name, with the actions each
    /// belongs to.
    fn action_fields(&self) -> Vec<(&'static str, &'static [RuleAction])> {
        use RuleAction::*;
        const ROUTE: &[RuleAction] = &[Route, RouteOptions, Bypass];
        [
            ("action", self.action.is_some(), &[] as &[RuleAction]),
            ("outbound", self.outbound.is_some(), &[Route, Bypass]),
            ("override_address", self.override_address.is_some(), ROUTE),
            ("override_port", self.override_port.is_some(), ROUTE),
            (
                "udp_disable_domain_unmapping",
                self.udp_disable_domain_unmapping,
                ROUTE,
            ),
            ("udp_connect", self.udp_connect, ROUTE),
            ("udp_timeout", self.udp_timeout.is_some(), ROUTE),
            ("tls_fragment", self.tls_fragment, ROUTE),
            (
                "tls_fragment_fallback_delay",
                self.tls_fragment_fallback_delay.is_some(),
                ROUTE,
            ),
            ("tls_record_fragment", self.tls_record_fragment, ROUTE),
            (
                "network_strategy",
                self.network_strategy.is_some(),
                &[Route, RouteOptions, Bypass, Direct],
            ),
            (
                "fallback_delay",
                self.fallback_delay.is_some(),
                &[Route, RouteOptions, Bypass, Direct],
            ),
            ("bind_interface", self.bind_interface.is_some(), &[Direct]),
            (
                "inet4_bind_address",
                self.inet4_bind_address.is_some(),
                &[Direct],
            ),
            (
                "inet6_bind_address",
                self.inet6_bind_address.is_some(),
                &[Direct],
            ),
            ("bind_address_no_port", self.bind_address_no_port, &[Direct]),
            ("protect_path", self.protect_path.is_some(), &[Direct]),
            ("routing_mark", self.routing_mark.is_some(), &[Direct]),
            ("reuse_addr", self.reuse_addr, &[Direct]),
            ("connect_timeout", self.connect_timeout.is_some(), &[Direct]),
            ("tcp_fast_open", self.tcp_fast_open, &[Direct]),
            (
                "disable_tcp_keep_alive",
                self.disable_tcp_keep_alive,
                &[Direct],
            ),
            ("tcp_keep_alive", self.tcp_keep_alive.is_some(), &[Direct]),
            (
                "tcp_keep_alive_interval",
                self.tcp_keep_alive_interval.is_some(),
                &[Direct],
            ),
            ("udp_fragment", self.udp_fragment.is_some(), &[Direct]),
            ("domain_resolver", self.domain_resolver.is_some(), &[Direct]),
            (
                "skip_default_domain_resolver",
                self.skip_default_domain_resolver,
                &[Direct],
            ),
            ("domain_strategy", self.domain_strategy.is_some(), &[Direct]),
            (
                "fallback_network_type",
                !self.fallback_network_type.is_empty(),
                &[Direct],
            ),
            ("method", self.method.is_some(), &[Reject]),
            ("no_drop", self.no_drop, &[Reject]),
            ("server", self.server.is_some(), &[Resolve]),
            ("strategy", self.strategy.is_some(), &[Resolve]),
            ("disable_cache", self.disable_cache, &[Resolve]),
            (
                "disable_optimistic_cache",
                self.disable_optimistic_cache,
                &[Resolve],
            ),
            ("rewrite_ttl", self.rewrite_ttl.is_some(), &[Resolve]),
            ("client_subnet", self.client_subnet.is_some(), &[Resolve]),
            ("sniffer", !self.sniffer.is_empty(), &[Sniff]),
            ("timeout", self.timeout.is_some(), &[Sniff, Resolve]),
            ("ignore_failure", self.ignore_failure, &[Resolve]),
            (
                "override_destination",
                self.override_destination().is_some(),
                &[Route, RouteOptions, Bypass, Sniff],
            ),
            ("skip_rule_set", !self.skip_rule_set.is_empty(), &[Sniff]),
            ("on_demand", self.on_demand, &[Resolve, Sniff]),
        ]
        .into_iter()
        .filter(|(_, set, _)| *set)
        .map(|(field, _, actions)| (field, actions))
        .collect()
    }

    /// The configuration mistakes one rule, at `path`, can make on its
    /// own.
    fn check(&self, path: &str, outbounds: &HashSet<&str>) -> Result<()> {
        self.check_conditions(path, 0)?;
        let action = self.action();
        for (field, actions) in self.action_fields() {
            if !actions.is_empty() && !actions.contains(&action) {
                return Err(anyhow!(
                    "{}.{}: not for a {} rule",
                    path,
                    field,
                    action.name()
                ));
            }
        }
        match action {
            RuleAction::Route => {
                let tag = self
                    .outbound
                    .as_ref()
                    .ok_or_else(|| anyhow!("{}: outbound: a route rule needs one", path))?;
                if !outbounds.contains(tag.as_str()) {
                    return Err(anyhow!("{}: outbound [{}] does not exist", path, tag));
                }
            }
            RuleAction::RouteOptions => {
                if self.action_fields().len() == 1 {
                    return Err(anyhow!(
                        "{}: a route-options rule needs an option to set",
                        path
                    ));
                }
            }
            RuleAction::Reject => match self.method.unwrap_or_default() {
                RejectMethod::Reply => {
                    return Err(anyhow!(
                        "{}.method: reply answers ICMP, which sail does not route",
                        path
                    ))
                }
                RejectMethod::Drop if self.no_drop => {
                    return Err(anyhow!("{}.no_drop: not with method drop", path))
                }
                _ => {}
            },
            RuleAction::Bypass => {
                if let Some(tag) = &self.outbound {
                    if !outbounds.contains(tag.as_str()) {
                        return Err(anyhow!("{}: outbound [{}] does not exist", path, tag));
                    }
                }
            }
            RuleAction::HijackDns
            | RuleAction::Sniff
            | RuleAction::Resolve
            | RuleAction::Direct => {}
        }
        if self.override_destination() == Some(OverrideDestination::AtSniff)
            && action != RuleAction::Sniff
        {
            return Err(anyhow!(
                "{}.override_destination: at_sniff is a sniff rule's only",
                path
            ));
        }
        if self.tls_fragment && self.tls_record_fragment {
            return Err(anyhow!(
                "{}: tls_fragment and tls_record_fragment are exclusive",
                path
            ));
        }
        if self.tls_fragment_fallback_delay.is_some() && !self.tls_fragment {
            return Err(anyhow!(
                "{}.tls_fragment_fallback_delay: only with tls_fragment",
                path
            ));
        }
        for (field, value) in [
            ("timeout", self.timeout),
            ("udp_timeout", self.udp_timeout),
            (
                "tls_fragment_fallback_delay",
                self.tls_fragment_fallback_delay,
            ),
        ] {
            if value == Some(std::time::Duration::ZERO) {
                return Err(anyhow!("{}.{}: must be more than 0", path, field));
            }
        }
        if matches!(self.override_address.as_deref(), Some("")) {
            return Err(anyhow!("{}.override_address: empty", path));
        }
        if self.override_port == Some(0) {
            return Err(anyhow!("{}.override_port: must be more than 0", path));
        }
        // A rule with an action and no conditions matches everything, as
        // in sing-box, whose IsValid counts the action as content
        // (option/rule.go:206-210); only a nested rule, which takes no
        // action, must have conditions.
        Ok(())
    }

    /// The dial fields of a `direct` rule: sing-box's
    /// `DirectActionOptions`, all its `AbstractDialerOptions`
    /// (option/rule_action.go:248-250), so no `detour`; nor a
    /// `network_type`, which is the rule's condition
    /// (option/rule.go:198-203 reads the conditions first).
    pub fn direct_fields(&self) -> crate::net::dial::DialFields {
        crate::net::dial::DialFields {
            bind_interface: self.bind_interface.clone(),
            inet4_bind_address: self.inet4_bind_address,
            inet6_bind_address: self.inet6_bind_address,
            bind_address_no_port: self.bind_address_no_port,
            protect_path: self.protect_path.clone(),
            routing_mark: self.routing_mark,
            reuse_addr: self.reuse_addr,
            connect_timeout: self.connect_timeout,
            tcp_fast_open: self.tcp_fast_open,
            disable_tcp_keep_alive: self.disable_tcp_keep_alive,
            tcp_keep_alive: self.tcp_keep_alive,
            tcp_keep_alive_interval: self.tcp_keep_alive_interval,
            udp_fragment: self.udp_fragment,
            domain_resolver: self.domain_resolver.clone(),
            skip_default_domain_resolver: self.skip_default_domain_resolver,
            domain_strategy: self.domain_strategy,
            network_strategy: self.network_strategy,
            fallback_network_type: self.fallback_network_type.to_vec(),
            fallback_delay: self.fallback_delay,
            ..Default::default()
        }
    }

    /// The mistakes of a rule's conditions, and of the rules nested in it,
    /// which take no action.
    fn check_conditions(&self, path: &str, depth: usize) -> Result<()> {
        /// Rules nested deeper than this are refused.
        const MAX_DEPTH: usize = 100;
        if depth > MAX_DEPTH {
            return Err(anyhow!("{}: logical rules nested too deep", path));
        }
        if depth > 0 {
            if let Some((field, _)) = self.action_fields().first() {
                return Err(anyhow!(
                    "{}.{}: a nested rule takes no action; the rule it is in acts",
                    path,
                    field
                ));
            }
        }
        match self.kind {
            RuleType::Default => {
                if self.mode.is_some() {
                    return Err(anyhow!("{}.mode: only a logical rule has one", path));
                }
                if !self.rules.is_empty() {
                    return Err(anyhow!("{}.rules: only a logical rule has them", path));
                }
                if depth > 0 && !self.has_conditions() {
                    return Err(anyhow!("{}: the rule has no conditions", path));
                }
                if self.rule_set_ip_cidr_match_source && self.rule_set.is_empty() {
                    return Err(anyhow!(
                        "{}.rule_set_ip_cidr_match_source: only with rule_set",
                        path
                    ));
                }
                if let Some(version) = self.ip_version {
                    if version != 4 && version != 6 {
                        return Err(anyhow!("{}.ip_version: 4 or 6, not {}", path, version));
                    }
                }
                if self.no_resolve && !self.on_addresses() {
                    return Err(anyhow!(
                        "{}.no_resolve: the rule has no condition on the destination's addresses",
                        path
                    ));
                }
            }
            RuleType::Logical => {
                if self.no_resolve && !self.on_addresses() {
                    return Err(anyhow!(
                        "{}.no_resolve: none of its rules has a condition on the destination's \
                         addresses",
                        path
                    ));
                }
                if let Some(field) = self.first_condition() {
                    return Err(anyhow!(
                        "{}.{}: a logical rule's conditions are its rules",
                        path,
                        field
                    ));
                }
                if self.mode.is_none() {
                    return Err(anyhow!("{}.mode: a logical rule needs and or or", path));
                }
                if self.rules.is_empty() {
                    return Err(anyhow!("{}.rules: a logical rule needs some", path));
                }
                for (i, rule) in self.rules.iter().enumerate() {
                    rule.check_conditions(&format!("{}.rules[{}]", path, i), depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// Whether the rule, or a rule within, has conditions that may be on
    /// the destination's addresses: those of a rule-set are not known
    /// before it is read.
    fn on_addresses(&self) -> bool {
        match self.kind {
            RuleType::Default => {
                !self.ip_cidr.is_empty()
                    || self.ip_is_private
                    || !self.ip_asn.is_empty()
                    || !self.geoip.is_empty()
                    || !self.external.is_empty()
                    || !self.rule_set.is_empty()
            }
            RuleType::Logical => self.rules.iter().any(Rule::on_addresses),
        }
    }

    /// The rule-sets the rule and the rules nested in it name, each with
    /// where.
    fn rule_sets<'a>(&'a self, path: &str, found: &mut Vec<(String, &'a String)>) {
        for tag in &self.rule_set {
            found.push((path.to_string(), tag));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.rule_sets(&format!("{}.rules[{}]", path, i), found);
        }
    }
}

impl RuleAction {
    /// As the configuration writes it.
    pub fn name(self) -> &'static str {
        match self {
            RuleAction::Route => "route",
            RuleAction::RouteOptions => "route-options",
            RuleAction::Reject => "reject",
            RuleAction::HijackDns => "hijack-dns",
            RuleAction::Sniff => "sniff",
            RuleAction::Resolve => "resolve",
            RuleAction::Bypass => "bypass",
            RuleAction::Direct => "direct",
        }
    }
}

impl Config {
    /// Whether a TUN inbound with `auto_route`, which sail routes itself,
    /// would take sail's own traffic too: nothing but binding to the
    /// physical interface keeps it out, unless a host that opens the TUN
    /// routes it, or `auto_redirect` marks sail's sockets.
    pub fn tun_takes_own_traffic(&self, host_routes: bool) -> bool {
        !host_routes
            && self.inbounds.iter().any(|i| {
                i.protocol == "tun"
                    && i.options.get("auto_route") == Some(&serde_json::Value::Bool(true))
                    && i.options.get("auto_redirect") != Some(&serde_json::Value::Bool(true))
            })
    }

    /// REALITY's keys and short IDs, which sing-box checks with the rest
    /// rather than when building.
    #[cfg(any(feature = "inbound-reality", feature = "outbound-reality"))]
    fn check_reality(&self) -> Result<()> {
        use crate::transport::reality::{parse_key, parse_short_id};
        use serde_json::Value;

        fn reality(options: &Options) -> Option<&Value> {
            let enabled = |v: &Value| v.get("enabled").and_then(Value::as_bool) == Some(true);
            let tls = options.get("tls").filter(|t| enabled(t))?;
            tls.get("reality").filter(|r| enabled(r))
        }
        let check = |kind: &str, tag: &str, reality: &Value, key: &str| -> Result<()> {
            let at = |e: anyhow::Error| anyhow!("[{}] {}: tls.reality.{}", tag, kind, e);
            match reality.get(key) {
                None => parse_key(key, "").map_err(at)?,
                Some(Value::String(k)) => parse_key(key, k).map_err(at)?,
                // Of the wrong type: the schema says so when building.
                Some(_) => return Ok(()),
            };
            let ids = match reality.get("short_id") {
                Some(Value::String(id)) => vec![id.as_str()],
                Some(Value::Array(ids)) => ids.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            for id in ids {
                parse_short_id(id).map_err(at)?;
            }
            Ok(())
        };
        for outbound in &self.outbounds {
            if let Some(r) = reality(&outbound.options) {
                check("outbound", &outbound.tag, r, "public_key")?;
            }
        }
        for inbound in &self.inbounds {
            if let Some(r) = reality(&inbound.options) {
                check("inbound", &inbound.tag, r, "private_key")?;
            }
        }
        Ok(())
    }

    /// Each user `user_limits` names is one an inbound has, and its limits
    /// are sound. A quota needs the cache file: a restart would otherwise
    /// forget what was used, and give the quota again.
    fn check_user_limits(&self) -> Result<()> {
        if self.user_limits.is_empty() {
            return Ok(());
        }
        let names = user_names(&self.inbounds, &self.endpoints);
        let cache_file = self
            .experimental
            .cache_file
            .as_ref()
            .is_some_and(|c| c.enabled);
        for (name, limits) in &self.user_limits {
            if !names.contains(name.as_str()) {
                return Err(anyhow!(
                    "user_limits.{}: no inbound has a user of that name",
                    name
                ));
            }
            limits.check(name)?;
            if limits.quota_bytes.is_some() && !cache_file {
                return Err(anyhow!(
                    "user_limits.{}.quota_bytes: needs experimental.cache_file enabled, or a restart forgets what was used",
                    name
                ));
            }
        }
        Ok(())
    }

    /// What its HTTP clients, in `http_clients` or inline, ask for that
    /// sail's downloads do otherwise: a warning each.
    pub fn http_client_warnings(&self) -> Vec<String> {
        fn inline(client: &Option<HttpClientRef>) -> Option<&HttpClient> {
            match client {
                Some(HttpClientRef::Inline(client)) => Some(client),
                _ => None,
            }
        }
        let mut warnings = Vec::new();
        for (i, client) in self.http_clients.iter().enumerate() {
            warnings.extend(client.warnings(&format!("http_clients[{}]", i)));
        }
        for (i, rule_set) in self.route.rule_set.iter().enumerate() {
            if let Some(client) = inline(&rule_set.http_client) {
                warnings.extend(client.warnings(&format!("route.rule_set[{}].http_client", i)));
            }
        }
        for (i, provider) in self.outbound_providers.iter().enumerate() {
            if let Some(client) = inline(&provider.http_client) {
                warnings.extend(client.warnings(&format!("outbound_providers[{}].http_client", i)));
            }
        }
        warnings
    }

    /// HTTP/3 among the versions an HTTP inbound serves, which sail does
    /// not speak, a warning each; HTTP/3 alone is the inbound's to refuse.
    pub fn http_inbound_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for (i, inbound) in self.inbounds.iter().enumerate() {
            if inbound.protocol != "http" {
                continue;
            }
            let versions: Vec<u64> = match inbound.options.get("version") {
                Some(serde_json::Value::Number(n)) => n.as_u64().into_iter().collect(),
                Some(serde_json::Value::Array(list)) => {
                    list.iter().filter_map(|v| v.as_u64()).collect()
                }
                _ => Vec::new(),
            };
            if versions.contains(&3) && versions.iter().any(|v| *v == 1 || *v == 2) {
                warnings.push(format!(
                    "inbounds[{}].version: sail speaks no HTTP/3; 3 is not served",
                    i
                ));
            }
        }
        warnings
    }

    /// What its HTTP outbounds ask for that sail's do otherwise: HTTP/3,
    /// for which sail speaks HTTP/2; HTTP/2 without TLS, which sing-box
    /// and sail speak as HTTP/1.1; HTTP/2 over REALITY, HTTP/1.1 as no
    /// ALPN is told; a warning each. An unset `version`, HTTP/1.1, is
    /// never warned of. A value of the wrong type, and what sing-box refuses,
    /// are the outbound's to refuse.
    pub fn http_outbound_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for (i, outbound) in self.outbounds.iter().enumerate() {
            if outbound.protocol != "http" {
                continue;
            }
            let options = &outbound.options;
            let at = format!("outbounds[{}]", i);
            let version = HttpVersion::of(options);
            let tls = options
                .get("tls")
                .and_then(|t| t.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let reality = tls
                && options
                    .get("tls")
                    .and_then(|t| t.get("reality"))
                    .and_then(|r| r.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            if reality && version.resolved >= 2 {
                warnings.push(format!(
                    "{}.tls.reality: HTTP/2 needs the server's ALPN, which REALITY does not \
                     tell; HTTP/1.1",
                    at
                ));
                continue;
            }
            match (version.resolved, tls) {
                (3, true) => {
                    warnings.push(format!(
                        "{}.version: sail speaks HTTP/2 and HTTP/1.1, not HTTP/3; HTTP/2 used",
                        at
                    ));
                    if version.disable_fallback {
                        warnings.push(format!(
                            "{}.disable_version_fallback: HTTP/2 alone, as sail speaks no \
                             HTTP/3",
                            at
                        ));
                    }
                }
                (2, false) if !version.disable_fallback => warnings.push(format!(
                    "{}.version: HTTP/2 needs TLS; HTTP/1.1, as sing-box",
                    at
                )),
                _ => {}
            }
        }
        warnings
    }

    /// Fills in what the configuration leaves to defaults, and checks what
    /// can be checked without building anything.
    pub fn validate(&mut self) -> Result<()> {
        if let Some(api) = self.experimental.clash_api.take() {
            if self.clash_api.is_some() {
                return Err(anyhow!(
                    "experimental.clash_api: the Clash API is set in clash_api too; keep one"
                ));
            }
            self.clash_api = Some(api);
        }
        for inbound in &mut self.inbounds {
            if inbound.tag.is_empty() {
                inbound.tag = inbound.protocol.clone();
            }
            if inbound.udp_timeout == Some(std::time::Duration::ZERO) {
                return Err(anyhow!(
                    "[{}] inbound: udp_timeout: must be more than 0",
                    inbound.tag
                ));
            }
        }
        self.check_user_limits()?;
        if let Some(api) = &self.api {
            api.check()?;
        }
        self.dns.validate()?;
        if self.dns.timeout == Some(std::time::Duration::ZERO) {
            return Err(anyhow!("dns.timeout: must be more than 0"));
        }
        if self.dns.cache_capacity == Some(0) {
            return Err(anyhow!("dns.cache_capacity: must be at least 1"));
        }
        for outbound in &mut self.outbounds {
            if outbound.tag.is_empty() {
                outbound.tag = outbound.protocol.clone();
            }
        }
        for endpoint in &mut self.endpoints {
            if endpoint.tag.is_empty() {
                endpoint.tag = endpoint.protocol.clone();
            }
            if endpoint.udp_timeout == Some(std::time::Duration::ZERO) {
                return Err(anyhow!(
                    "[{}] endpoint: udp_timeout: must be more than 0",
                    endpoint.tag
                ));
            }
        }
        #[cfg(any(feature = "inbound-reality", feature = "outbound-reality"))]
        self.check_reality()?;
        // The DNS servers named elsewhere.
        let dns_servers = self.dns.server_tags();
        let dns_server = |field: &str, tag: &str| -> Result<()> {
            if dns_servers.contains(tag) {
                Ok(())
            } else {
                Err(anyhow!("{}: dns server [{}] does not exist", field, tag))
            }
        };
        if let Some(resolver) = &self.route.default_domain_resolver {
            dns_server("route.default_domain_resolver", &resolver.server)?;
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            if let Some(server) = &rule.server {
                dns_server(&format!("route.rules[{}].server", i), server)?;
            }
        }
        for (kind, tag, options) in self
            .outbounds
            .iter()
            .map(|o| ("outbound", &o.tag, &o.options))
            .chain(
                self.endpoints
                    .iter()
                    .map(|e| ("endpoint", &e.tag, &e.options)),
            )
        {
            if let Some(value) = options.get("domain_resolver") {
                let resolver = <DomainResolver as serde::Deserialize>::deserialize(value)
                    .map_err(|e| anyhow!("[{}] {}: domain_resolver: {}", tag, kind, e))?;
                dns_server(
                    &format!("[{}] {}: domain_resolver", tag, kind),
                    &resolver.server,
                )?;
            }
        }
        // The handshake servers REALITY and ShadowTLS dial resolve with
        // servers that must exist too.
        for inbound in self.inbounds.iter() {
            // A type sail does not build is refused as such when built.
            if crate::include::INBOUNDS.get(&inbound.protocol).is_none() {
                continue;
            }
            let get = |value: &serde_json::Value, key: &str| value.get(key).cloned();
            let options = serde_json::Value::Object(inbound.options.clone());
            let mut handshakes = Vec::new();
            if let Some(h) = options
                .get("tls")
                .and_then(|t| t.get("reality"))
                .and_then(|r| r.get("handshake"))
            {
                handshakes.push(("tls.reality.handshake".to_string(), h.clone()));
            }
            if inbound.protocol == "shadowtls" {
                if let Some(h) = get(&options, "handshake") {
                    handshakes.push(("handshake".to_string(), h));
                }
                if let Some(serde_json::Value::Object(by_name)) =
                    get(&options, "handshake_for_server_name")
                {
                    for (name, h) in by_name {
                        handshakes.push((format!("handshake_for_server_name.{}", name), h));
                    }
                }
            }
            for (field, handshake) in handshakes {
                let Some(value) = handshake.get("domain_resolver") else {
                    continue;
                };
                let at = format!("[{}] inbound: {}.domain_resolver", inbound.tag, field);
                let resolver = <DomainResolver as serde::Deserialize>::deserialize(value)
                    .map_err(|e| anyhow!("{}: {}", at, e))?;
                dns_server(&at, &resolver.server)?;
            }
        }

        // An endpoint is an inbound and an outbound: its tag is taken in
        // both.
        {
            let mut tags: HashMap<&str, &str> = HashMap::new();
            for (kind, tag) in self
                .inbounds
                .iter()
                .map(|i| ("inbound", i.tag.as_str()))
                .chain(self.endpoints.iter().map(|e| ("endpoint", e.tag.as_str())))
            {
                if let Some(other) = tags.insert(tag, kind) {
                    if kind == "endpoint" {
                        return Err(anyhow!(
                            "[{}] endpoint: the tag is taken by an {}",
                            tag,
                            other
                        ));
                    }
                }
            }
            for outbound in &self.outbounds {
                if tags.get(outbound.tag.as_str()) == Some(&"endpoint") {
                    return Err(anyhow!(
                        "[{}] endpoint: the tag is taken by an outbound",
                        outbound.tag
                    ));
                }
            }
        }

        if self.route.auto_detect_interface && self.route.default_interface.is_some() {
            return Err(anyhow!(
                "route: set default_interface or auto_detect_interface, not both"
            ));
        }

        let outbounds: HashSet<&str> = self
            .outbounds
            .iter()
            .map(|o| o.tag.as_str())
            .chain(self.endpoints.iter().map(|e| e.tag.as_str()))
            .collect();
        for (i, tag) in self.route.block_quic.iter().enumerate() {
            if !outbounds.contains(tag.as_str()) {
                return Err(anyhow!(
                    "route.block_quic[{}]: outbound [{}] does not exist",
                    i,
                    tag
                ));
            }
        }
        if let Some(tag) = &self.route.final_outbound {
            if !outbounds.contains(tag.as_str()) {
                return Err(anyhow!("route.final: outbound [{}] does not exist", tag));
            }
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            rule.check(&format!("route.rules[{}]", i), &outbounds)?;
        }

        let mut http_clients = HashSet::new();
        for (i, client) in self.http_clients.iter().enumerate() {
            if client.tag.is_empty() {
                return Err(anyhow!("http_clients[{}].tag: missing", i));
            }
            if !http_clients.insert(client.tag.as_str()) {
                return Err(anyhow!(
                    "http_clients[{}]: another http client is tagged [{}]",
                    i,
                    client.tag
                ));
            }
            client
                .check(&outbounds, &dns_servers)
                .map_err(|e| anyhow!("http_clients[{}]: {}", i, e))?;
        }
        self.check_detours()?;
        if let Some(tag) = &self.route.default_http_client {
            if !http_clients.contains(tag.as_str()) {
                return Err(anyhow!(
                    "route.default_http_client: http client [{}] does not exist",
                    tag
                ));
            }
        }

        let mut rule_sets = HashSet::new();
        for (i, rule_set) in self.route.rule_set.iter().enumerate() {
            rule_set
                .check()
                .map_err(|e| anyhow!("route.rule_set[{}]: {}", i, e))?;
            for tag in &rule_set.tag {
                if !rule_sets.insert(tag.as_str()) {
                    return Err(anyhow!(
                        "route.rule_set[{}]: another rule-set is tagged [{}]",
                        i,
                        tag
                    ));
                }
            }
            if let Some(detour) = &rule_set.download_detour {
                if !outbounds.contains(detour.as_str()) {
                    return Err(anyhow!(
                        "route.rule_set[{}].download_detour: outbound [{}] does not exist",
                        i,
                        detour
                    ));
                }
            }
            match &rule_set.http_client {
                Some(HttpClientRef::Tag(tag)) if !http_clients.contains(tag.as_str()) => {
                    return Err(anyhow!(
                        "route.rule_set[{}].http_client: http client [{}] does not exist",
                        i,
                        tag
                    ));
                }
                Some(HttpClientRef::Inline(client)) => client
                    .check(&outbounds, &dns_servers)
                    .map_err(|e| anyhow!("route.rule_set[{}].http_client: {}", i, e))?,
                _ => {}
            }
        }
        let mut providers = HashSet::new();
        for (i, provider) in self.outbound_providers.iter().enumerate() {
            if !cfg!(feature = "outbound-provider") {
                return Err(anyhow!(
                    "outbound_providers: need the outbound-provider feature, which is not \
                     compiled in"
                ));
            }
            provider
                .check(&outbounds, &http_clients, &dns_servers)
                .map_err(|e| anyhow!("outbound_providers[{}]: {}", i, e))?;
            if !providers.insert(provider.tag.as_str()) {
                return Err(anyhow!(
                    "outbound_providers[{}]: another provider is tagged [{}]",
                    i,
                    provider.tag
                ));
            }
        }
        let protocols: HashMap<&str, &str> = self
            .outbounds
            .iter()
            .map(|o| (o.tag.as_str(), o.protocol.as_str()))
            .chain(
                self.endpoints
                    .iter()
                    .map(|e| (e.tag.as_str(), e.protocol.as_str())),
            )
            .collect();
        self.check_pass(&protocols)?;
        let mut users: HashMap<&str, Vec<String>> = HashMap::new();
        for group in self
            .outbounds
            .iter()
            .filter(|o| PROVIDER_GROUPS.contains(&o.protocol.as_str()))
        {
            let members = GroupProviders::of(&group.options)
                .and_then(|m| m.check(&providers, &protocols).map(|()| m))
                .map_err(|e| anyhow!("[{}] outbound: {}", group.tag, e))?;
            users.insert(group.tag.as_str(), members.providers);
        }
        // A provider's outbounds dialling through a group of them would go
        // round in a loop.
        for provider in &self.outbound_providers {
            if let Some(detour) = &provider.detour {
                if users
                    .get(detour.as_str())
                    .is_some_and(|p| p.contains(&provider.tag))
                {
                    return Err(anyhow!(
                        "outbound_providers: [{}]: detour: [{}] takes its members from it",
                        provider.tag,
                        detour
                    ));
                }
            }
        }
        let mut in_route = Vec::new();
        for (i, rule) in self.route.rules.iter().enumerate() {
            rule.rule_sets(&format!("route.rules[{}]", i), &mut in_route);
        }
        let named = in_route
            .into_iter()
            .chain(self.dns.rules.iter().enumerate().flat_map(|(i, r)| {
                r.rule_set
                    .iter()
                    .map(move |t| (format!("dns.rules[{}]", i), t))
            }));
        for (at, tag) in named {
            if !rule_sets.contains(tag.as_str()) {
                return Err(anyhow!(
                    "{}.rule_set: rule-set [{}] does not exist",
                    at,
                    tag
                ));
            }
        }
        Ok(())
    }
}

impl Config {
    /// Where a `pass` outbound may be: a rule's outbound, or a member of
    /// a group that picks one member at a time, which the rules follow to
    /// it. `final` has no rule after it to pass to, nor the default
    /// outbound, which is `final` when there is none; and `load-balance`
    /// and `smart` pick a member for each connection as it is dialled,
    /// after the rules, so they cannot pass it on.
    /// The `detour` of no outbound, endpoint, DNS server or HTTP client
    /// names a `direct` outbound of no fields of its own: that dials as no
    /// detour does, which sing-box refuses as making no sense.
    /// `download_detour` is let be, as in sing-box.
    fn check_detours(&self) -> Result<()> {
        let empty_direct = |tag: &str| {
            self.outbounds
                .iter()
                .any(|o| o.tag == tag && o.protocol == "direct" && o.options.is_empty())
        };
        fn detour(options: &Options) -> Option<&str> {
            options.get("detour").and_then(|v| v.as_str())
        }
        let places = self
            .outbounds
            .iter()
            .map(|o| (format!("[{}] outbound", o.tag), detour(&o.options)))
            .chain(
                self.endpoints
                    .iter()
                    .map(|e| (format!("[{}] endpoint", e.tag), detour(&e.options))),
            )
            .chain(
                self.dns
                    .servers
                    .iter()
                    .map(|s| (format!("dns.servers[{}]", s.tag), detour(&s.options))),
            )
            .chain(
                self.http_clients
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (format!("http_clients[{}]", i), c.dial.detour.as_deref())),
            );
        for (place, detour) in places {
            let Some(detour) = detour else {
                continue;
            };
            if empty_direct(detour) {
                return Err(anyhow!(
                    "{}: detour: [{}] is a direct outbound of no fields of its own, \
                     through which it would dial as it does without a detour",
                    place,
                    detour
                ));
            }
        }
        Ok(())
    }

    fn check_pass(&self, protocols: &HashMap<&str, &str>) -> Result<()> {
        let is_pass = |tag: &str| protocols.get(tag) == Some(&"pass");
        match &self.route.final_outbound {
            Some(tag) if is_pass(tag) => {
                return Err(anyhow!(
                    "route.final: [{}] is a pass outbound, and no rule comes after final",
                    tag
                ));
            }
            None if self.outbounds.first().is_some_and(|o| o.protocol == "pass") => {
                return Err(anyhow!(
                    "outbounds[0]: [{}] is a pass outbound, and the first outbound is final \
                     when route.final is not set",
                    self.outbounds[0].tag
                ));
            }
            _ => {}
        }
        let groups: HashMap<&str, &Outbound> = self
            .outbounds
            .iter()
            .filter(|o| GROUP_PROTOCOLS.contains(&o.protocol.as_str()))
            .map(|o| (o.tag.as_str(), o))
            .collect();
        // Whether `tag` is a pass outbound, or a group that picks one
        // member at a time and can pick one, followed down.
        fn can_pass<'a>(
            tag: &'a str,
            protocols: &HashMap<&str, &str>,
            groups: &HashMap<&str, &'a Outbound>,
            seen: &mut Vec<&'a str>,
        ) -> bool {
            match protocols.get(tag) {
                Some(&"pass") => true,
                Some(&("selector" | "urltest" | "fallback" | "network"))
                    if !seen.contains(&tag) =>
                {
                    seen.push(tag);
                    group_members(groups[tag])
                        .into_iter()
                        .any(|(_, member)| can_pass(member, protocols, groups, seen))
                }
                _ => false,
            }
        }
        for group in self
            .outbounds
            .iter()
            .filter(|o| matches!(o.protocol.as_str(), "load-balance" | "smart"))
        {
            for (field, member) in group_members(group) {
                if can_pass(member, protocols, &groups, &mut Vec::new()) {
                    return Err(anyhow!(
                        "[{}] outbound: {}: [{}] {}; PASS is not supported in load-balance/smart",
                        group.tag,
                        field,
                        member,
                        if is_pass(member) {
                            "is a pass outbound"
                        } else {
                            "can pick a pass outbound"
                        }
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The members of the group `group`, by tag, each with the field that
/// names it: `outbounds[i]` and `empty_fallback`, or a network group's
/// `branches[i].outbound` and `default`.
fn group_members(group: &Outbound) -> Vec<(String, &str)> {
    let options = &group.options;
    let mut members: Vec<(String, Option<&serde_json::Value>)> = Vec::new();
    if group.protocol == "network" {
        let branches = options.get("branches").and_then(|b| b.as_array());
        for (i, branch) in branches.into_iter().flatten().enumerate() {
            members.push((format!("branches[{}].outbound", i), branch.get("outbound")));
        }
        members.push(("default".to_string(), options.get("default")));
    } else {
        let outbounds = options.get("outbounds").and_then(|o| o.as_array());
        for (i, member) in outbounds.into_iter().flatten().enumerate() {
            members.push((format!("outbounds[{}]", i), Some(member)));
        }
        members.push(("empty_fallback".to_string(), options.get("empty_fallback")));
    }
    members
        .into_iter()
        .filter_map(|(field, v)| Some((field, v?.as_str()?)))
        .collect()
}

/// Parses a duration as sing-box writes them: a sequence of numbers with
/// units, `500ms`, `5s`, `1m30s`, `2h`, `7d`; or `0`.
pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    let invalid = || anyhow!("invalid duration \"{}\", expected e.g. 500ms, 5s, 1m30s", s);
    let mut total = std::time::Duration::ZERO;
    let mut rest = s.trim();
    if rest.is_empty() {
        return Err(invalid());
    }
    if rest == "0" {
        return Ok(total);
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .ok_or_else(invalid)?;
        let value: f64 = rest[..digits].parse().map_err(|_| invalid())?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let seconds = match &rest[..unit_len] {
            "ns" => 1e-9,
            // The micro sign, and the Greek mu.
            "us" | "\u{b5}s" | "\u{3bc}s" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            _ => return Err(invalid()),
        };
        let part =
            std::time::Duration::try_from_secs_f64(value * seconds).map_err(|_| invalid())?;
        total = total.checked_add(part).ok_or_else(invalid)?;
        rest = &rest[unit_len..];
    }
    Ok(total)
}

/// Serde support for optional durations in the sing-box notation.
pub mod duration {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        d: &Option<std::time::Duration>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_str(&format!("{}ms", d.as_millis())),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<std::time::Duration>, D::Error> {
        let s = String::deserialize(de)?;
        super::parse_duration(&s)
            .map(Some)
            .map_err(serde::de::Error::custom)
    }
}

/// A size in memory as sing-box writes one (sing's `byteformats.MemoryBytes`):
/// a number of bytes, or a string of digits and a unit, `b`, `k`/`kb`,
/// `m`/`mb`, `g`/`gb` (in any case), each 1024 times the one before.
pub mod memory_bytes {
    use serde::de::{self, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<u64>, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Option<u64>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a number of bytes, or one with a unit, e.g. 4MB")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Some(v))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                super::parse_memory_bytes(v).map(Some).map_err(E::custom)
            }
        }

        de.deserialize_any(Visitor)
    }
}

/// `memory_bytes`' string form.
pub fn parse_memory_bytes(s: &str) -> Result<u64> {
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digits == 0 || digits == s.len() {
        return Err(anyhow!("{:?}: a number and a unit, e.g. 4MB", s));
    }
    let value: u64 = s[..digits].parse().map_err(|e| anyhow!("{:?}: {}", s, e))?;
    let shift = match s[digits..].trim().to_ascii_lowercase().as_str() {
        "b" => 0,
        "k" | "kb" => 10,
        "m" | "mb" => 20,
        "g" | "gb" => 30,
        "t" | "tb" => 40,
        unit => return Err(anyhow!("{:?}: unknown unit {:?}", s, unit)),
    };
    value
        .checked_mul(1 << shift)
        .ok_or_else(|| anyhow!("{:?}: too large", s))
}

/// `duration`, or a number of nanoseconds up to `u32::MAX`: a route
/// rule's `fallback_delay`, which sing-box reads as a `uint32` of
/// nanoseconds (option/rule_action.go:182) though its documentation writes
/// it a duration.
pub mod duration_or_nanos {
    use serde::de::{self, Deserializer};

    pub use super::duration::serialize;

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<std::time::Duration>, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Option<std::time::Duration>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a duration, e.g. 300ms, or a number of nanoseconds")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                u32::try_from(v)
                    .map(|v| Some(std::time::Duration::from_nanos(v.into())))
                    .map_err(|_| E::custom("a number of nanoseconds is at most 4294967295"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                super::parse_duration(v).map(Some).map_err(E::custom)
            }
        }

        de.deserialize_any(Visitor)
    }
}

/// `duration`, or a number of seconds: an inbound's `udp_timeout`, as
/// sing-box takes it (its WireGuard endpoint's takes a duration only).
pub mod duration_or_seconds {
    use serde::de::{self, Deserializer};

    pub use super::duration::serialize;

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<std::time::Duration>, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = Option<std::time::Duration>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a duration, e.g. 5m, or a number of seconds")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Some(std::time::Duration::from_secs(v)))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                super::parse_duration(v).map(Some).map_err(E::custom)
            }
        }

        de.deserialize_any(Visitor)
    }
}

/// Serde support for lists that sing-box also takes as a single value.
pub mod listable {
    use serde::de::{self, IntoDeserializer};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Vec<T>, D::Error> {
        // A visitor rather than an untagged enum, which would hide why the
        // value is wrong behind "did not match any variant".
        struct Visitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = Vec<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a value or a list of values")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, seq: A) -> Result<Vec<T>, A::Error> {
                Vec::deserialize(de::value::SeqAccessDeserializer::new(seq))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<T>, E> {
                T::deserialize(v.into_deserializer()).map(|v| vec![v])
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Vec<T>, E> {
                T::deserialize(v.into_deserializer()).map(|v| vec![v])
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Vec<T>, E> {
                T::deserialize(v.into_deserializer()).map(|v| vec![v])
            }
        }

        de.deserialize_any(Visitor(std::marker::PhantomData))
    }
}

/// Reads an array into a `Vec` of the length its input says, rather than
/// of serde's cautious guess, grown by doubling: `route.rules` is read from
/// a JSON value already in memory, whose length is exact, and a guess for
/// thousands of rules would reserve up to twice what they take.
mod exactly {
    use serde::de::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Vec<T>, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = Vec<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a sequence")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
                let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(item) = seq.next_element()? {
                    v.push(item);
                }
                Ok(v)
            }
        }

        de.deserialize_seq(Visitor(std::marker::PhantomData))
    }
}

/// A list a [`Rule`] holds, read and written as [`listable`] reads and
/// writes a `Vec`: one value, or an array of them. 8 bytes rather than a
/// `Vec`'s 24, and nothing allocated while empty, as almost all of a rule's
/// are: a profile of thousands of rules is read into as many `Rule`s at
/// once, and each has some fifty lists.
#[derive(Clone, PartialEq, Eq, Hash)]
// The box is the point: an empty list is a null pointer, not three words.
#[allow(clippy::box_collection)]
pub struct List<T>(Option<Box<Vec<T>>>);

impl<T> List<T> {
    pub const fn new() -> Self {
        Self(None)
    }

    // Never `Some` of an empty `Vec`: every way in keeps it so.
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_deref().map_or(&[], Vec::as_slice)
    }

    pub fn push(&mut self, value: T) {
        self.0.get_or_insert_with(Default::default).push(value);
    }

    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        if let Some(v) = &mut self.0 {
            v.retain(keep);
            if v.is_empty() {
                self.0 = None;
            }
        }
    }

    pub fn clear(&mut self) {
        self.0 = None;
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0.map_or_else(Vec::new, |v| *v)
    }
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for List<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<T> std::ops::Deref for List<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> std::ops::DerefMut for List<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.0.as_deref_mut().map_or(&mut [], Vec::as_mut_slice)
    }
}

impl<T> From<Vec<T>> for List<T> {
    fn from(v: Vec<T>) -> Self {
        Self((!v.is_empty()).then(|| Box::new(v)))
    }
}

impl<T, const N: usize> From<[T; N]> for List<T> {
    fn from(v: [T; N]) -> Self {
        Vec::from(v).into()
    }
}

impl<T> From<List<T>> for Vec<T> {
    fn from(v: List<T>) -> Self {
        v.into_vec()
    }
}

impl<T> FromIterator<T> for List<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        iter.into_iter().collect::<Vec<T>>().into()
    }
}

impl<T> Extend<T> for List<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let mut v = std::mem::take(self).into_vec();
        v.extend(iter);
        *self = v.into();
    }
}

impl<T> IntoIterator for List<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

impl<'a, T> IntoIterator for &'a List<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: PartialEq<U>, U> PartialEq<Vec<U>> for List<T> {
    fn eq(&self, other: &Vec<U>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: PartialEq<U>, U, const N: usize> PartialEq<[U; N]> for List<T> {
    fn eq(&self, other: &[U; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: PartialEq<U>, U> PartialEq<[U]> for List<T> {
    fn eq(&self, other: &[U]) -> bool {
        self.as_slice() == other
    }
}

impl<T: serde::Serialize> serde::Serialize for List<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(s)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for List<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        listable::deserialize(de).map(Self::from)
    }
}

/// Reads the options of the inbound or outbound `tag` into its protocol's
/// options type, naming the field at fault on failure.
pub fn parse_options<T: serde::de::DeserializeOwned>(
    kind: &str,
    tag: &str,
    options: &Options,
) -> Result<T> {
    serde_path_to_error::deserialize(serde_json::Value::Object(options.clone())).map_err(|e| {
        // An error of the options as a whole, or of a field they flatten
        // in, which names the field itself.
        match e.path().to_string().as_str() {
            "." => anyhow!("[{}] {}: {}", tag, kind, e.inner()),
            path => anyhow!("[{}] {}: {}: {}", tag, kind, path, e.inner()),
        }
    })
}

pub(super) fn path<E>(e: &serde_path_to_error::Error<E>) -> String {
    let path = e.path().to_string();
    if path == "." {
        "options".to_string()
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An inbound's UDP is not fragmented unless it says, or is one of
    /// those sing-box lets fragment by default: direct and hysteria2, not
    /// tuic.
    #[test]
    fn an_inbound_s_udp_fragments_as_it_says_or_as_sing_box_does() {
        let inbound = |json| {
            serde_json::from_value::<Inbound>(json)
                .unwrap()
                .udp_fragment()
        };
        assert!(!inbound(serde_json::json!({ "type": "socks" })));
        assert!(!inbound(serde_json::json!({ "type": "shadowsocks" })));
        assert!(!inbound(serde_json::json!({ "type": "tuic" })));
        for protocol in ["direct", "hysteria2"] {
            assert!(
                inbound(serde_json::json!({ "type": protocol })),
                "{}",
                protocol
            );
        }
        assert!(inbound(
            serde_json::json!({ "type": "socks", "udp_fragment": true })
        ));
        assert!(!inbound(
            serde_json::json!({ "type": "hysteria2", "udp_fragment": false })
        ));
    }

    /// A rule's lists take 8 bytes each, empty or not, rather than a
    /// `Vec`'s 24: a rule is 864 bytes, where it was 1,616, and a profile
    /// of thousands of rules is read into as many at once.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_rule_holds_its_lists_in_8_bytes() {
        assert_eq!(std::mem::size_of::<List<String>>(), 8);
        assert!(
            std::mem::size_of::<Rule>() <= 864,
            "{}",
            std::mem::size_of::<Rule>()
        );
    }

    /// A list reads one value or an array of them, and writes an array, as
    /// a `Vec` read through `listable` did; empty, it holds nothing.
    #[test]
    fn a_list_reads_and_writes_as_a_vec_did() {
        let one: List<String> = serde_json::from_value(serde_json::json!("a")).unwrap();
        let two: List<u16> = serde_json::from_value(serde_json::json!([1, 2])).unwrap();
        let none: List<u16> = serde_json::from_value(serde_json::json!([])).unwrap();
        assert_eq!(one, ["a"]);
        assert_eq!(two, [1, 2]);
        assert!(none.is_empty() && none == List::new());
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::json!(["a"])
        );
        let mut l = List::new();
        l.push(3);
        l.retain(|n| *n != 3);
        assert_eq!(l, List::<i32>::new());
        let rule: Rule =
            serde_json::from_value(serde_json::json!({ "domain": "a.test", "port": [443] }))
                .unwrap();
        assert_eq!(
            serde_json::to_value(&rule).unwrap(),
            serde_json::json!({ "domain": ["a.test"], "port": [443] })
        );
    }

    /// `route.rules` is read into a `Vec` of exactly as many rules, not of
    /// serde's guess grown by doubling, which at 3,000 rules reserves 4,852.
    #[test]
    fn route_rules_reserve_what_they_take() {
        let rules: Vec<serde_json::Value> = (0..3000)
            .map(|i| serde_json::json!({ "domain": format!("d{}.test", i), "outbound": "a" }))
            .collect();
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "rules": rules },
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(config.route.rules.capacity(), 3000);
    }

    /// Printed, a configuration shows none of its secrets.
    #[test]
    fn a_configuration_prints_no_secret() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "inbounds": [{ "type": "socks", "tag": "in", "listen_port": 1080,
                               "users": [{ "username": "u", "password": "pw-in-secret" }] }],
                "outbounds": [
                    { "type": "shadowsocks", "tag": "ss", "server": "a", "server_port": 1,
                      "method": "aes-128-gcm", "password": "pw-out-secret" },
                    { "type": "vless", "tag": "v", "server": "a", "server_port": 1,
                      "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b" }
                ],
                "outbound_providers": [{ "type": "remote", "tag": "p",
                    "url": "https://sub.example.com/token-secret?t=q-secret",
                    "http_client": { "headers": { "Authorization": "Bearer h-secret" } } }],
                "clash_api": { "external_controller": "127.0.0.1:9090", "secret": "api-secret" },
            })
            .to_string(),
        )
        .unwrap();
        let printed = format!("{:?}", config);
        for secret in [
            "pw-in-secret",
            "pw-out-secret",
            "1b0e0a3e",
            "token-secret",
            "q-secret",
            "h-secret",
            "api-secret",
        ] {
            assert!(!printed.contains(secret), "{} in {}", secret, printed);
        }
        assert!(
            printed.contains("sub.example.com") && printed.contains("password"),
            "{}",
            printed
        );
    }

    #[test]
    fn protocol_options_stay_with_the_entry() {
        let config = Config::from_json(
            r#"{
                "inbounds": [{ "type": "socks", "listen_port": 1080, "users": [] }],
                "outbounds": [{ "type": "shadowsocks", "tag": "ss", "server": "a", "server_port": 1 }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.inbounds[0].tag, "socks");
        assert_eq!(config.inbounds[0].listen_port, Some(1080));
        assert!(config.inbounds[0].options.contains_key("users"));
        assert_eq!(config.outbounds[0].options["server"], "a");
        assert!(config.dns.servers.is_empty());
    }

    #[test]
    fn an_unknown_top_level_field_is_an_error_that_names_it() {
        let err = Config::from_json(r#"{ "router": {} }"#).unwrap_err();
        assert!(err.to_string().contains("router"), "{}", err);
    }

    #[test]
    fn a_misspelt_rule_field_names_its_path() {
        let err = Config::from_json(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "domian": ["a"], "outbound": "direct" }] }
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("route.rules[0]"), "{}", err);
    }

    #[test]
    fn a_rule_to_a_missing_outbound_is_an_error() {
        let err = Config::from_json(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "domain": ["a"], "outbound": "proxy" }] }
            }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0]: outbound [proxy] does not exist"
        );
    }

    #[test]
    fn rule_actions_and_their_mistakes() {
        let config = |rules: &str| {
            Config::from_json(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": {} }} }}"#,
                rules
            ))
        };
        let ok = config(
            r#"[{ "action": "sniff", "sniffer": ["tls"], "timeout": "1s" },
                { "action": "resolve" },
                { "domain": ["a"], "action": "reject" },
                { "ip_cidr": ["10.0.0.0/8"], "outbound": "direct" }]"#,
        )
        .unwrap();
        assert_eq!(ok.route.rules[0].action(), RuleAction::Sniff);
        assert_eq!(ok.route.rules[0].sniffer, [Sniffer::Tls]);
        assert_eq!(ok.route.rules[3].action(), RuleAction::Route);

        for (rules, message) in [
            (r#"[{ "domain": ["a"] }]"#, "a route rule needs one"),
            (
                r#"[{ "action": "sniff", "outbound": "direct" }]"#,
                "route.rules[0].outbound: not for a sniff rule",
            ),
            (
                r#"[{ "domain": ["a"], "action": "reject", "sniffer": ["tls"] }]"#,
                "route.rules[0].sniffer: not for a reject rule",
            ),
            (r#"[{ "action": "sniff", "sniffer": ["ssh"] }]"#, "ssh"),
            (
                r#"[{ "action": "route-options" }]"#,
                "route.rules[0]: a route-options rule needs an option",
            ),
            (
                r#"[{ "action": "hijack-dns", "port": 53, "sniffer": "tls" }]"#,
                "route.rules[0].sniffer: not for a hijack-dns rule",
            ),
            (
                r#"[{ "action": "reject", "port": 1, "method": "reply" }]"#,
                "route.rules[0].method: reply",
            ),
            (
                r#"[{ "action": "reject", "port": 1, "method": "drop", "no_drop": true }]"#,
                "route.rules[0].no_drop",
            ),
            (
                r#"[{ "action": "reject", "port": 1, "method": "other" }]"#,
                "route.rules[0].method",
            ),
            (
                r#"[{ "action": "route-options", "tls_fragment": true, "tls_record_fragment": true }]"#,
                "exclusive",
            ),
            (
                r#"[{ "action": "route-options", "tls_fragment_fallback_delay": "1s" }]"#,
                "route.rules[0].tls_fragment_fallback_delay: only with tls_fragment",
            ),
            (
                r#"[{ "action": "route-options", "udp_timeout": "0s" }]"#,
                "route.rules[0].udp_timeout: must be more than 0",
            ),
            (
                r#"[{ "action": "resolve", "override_port": 53 }]"#,
                "route.rules[0].override_port: not for a resolve rule",
            ),
            (
                r#"[{ "port": 1, "ip_version": 5, "outbound": "direct" }]"#,
                "route.rules[0].ip_version: 4 or 6",
            ),
            (
                r#"[{ "port": 1, "action": "bypass", "outbound": "proxy" }]"#,
                "route.rules[0]: outbound [proxy] does not exist",
            ),
            (
                r#"[{ "port": 1, "action": "bypass", "method": "drop" }]"#,
                "route.rules[0].method: not for a bypass rule",
            ),
            (
                r#"[{ "port": 1, "outbound": "direct", "ignore_failure": true }]"#,
                "route.rules[0].ignore_failure: not for a route rule",
            ),
            (
                r#"[{ "port": 1, "outbound": "direct", "on_demand": true }]"#,
                "route.rules[0].on_demand: not for a route rule",
            ),
            (
                r#"[{ "port": 1, "action": "route-options", "udp_connect": true,
                      "on_demand": true }]"#,
                "route.rules[0].on_demand: not for a route-options rule",
            ),
            (
                r#"[{ "domain": "a.test", "outbound": "direct", "no_resolve": true }]"#,
                "route.rules[0].no_resolve: the rule has no condition on the destination's \
                 addresses",
            ),
            (
                r#"[{ "type": "logical", "mode": "or", "outbound": "direct", "rules": [
                      { "port": 1 }, { "domain": "a.test", "no_resolve": true }] }]"#,
                "route.rules[0].rules[1].no_resolve: the rule has no condition",
            ),
            (
                r#"[{ "type": "logical", "mode": "or", "outbound": "direct",
                      "no_resolve": true, "rules": [{ "port": 1 }] }]"#,
                "route.rules[0].no_resolve: none of its rules has a condition",
            ),
        ] {
            let err = config(rules).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    /// A rule with an action and no conditions is taken and matches
    /// everything, as sing-box takes it: `{"action": "reject"}` is how a
    /// generated configuration ends with a rejection.
    #[test]
    fn a_rule_with_only_an_action_is_taken() {
        for rules in [
            r#"[{ "outbound": "direct" }]"#,
            r#"[{ "action": "reject" }]"#,
            r#"[{ "action": "bypass", "outbound": "direct" }]"#,
        ] {
            let config = Config::from_json(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": {} }} }}"#,
                rules
            ))
            .unwrap_or_else(|e| panic!("{}: {}", rules, e));
            assert!(!config.route.rules[0].has_conditions(), "{}", rules);
        }
    }

    /// As sing-box has it: a logical rule's conditions are its rules, and
    /// the rules nested in it take no action; a mistake names its full
    /// path.
    #[test]
    fn logical_rules_and_their_mistakes() {
        let config = |rules: &str| {
            Config::from_json(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": {} }} }}"#,
                rules
            ))
        };
        let ok = config(
            r#"[{ "type": "logical", "mode": "and", "outbound": "direct", "rules": [
                    { "port": 443 },
                    { "type": "logical", "mode": "or", "invert": true, "rules": [
                        { "domain": "a" }, { "network": "udp", "invert": true }
                    ] }
                ] }]"#,
        )
        .unwrap();
        assert_eq!(ok.route.rules[0].kind, RuleType::Logical);
        assert_eq!(ok.route.rules[0].rules[1].mode, Some(LogicalMode::Or));

        for (rules, message) in [
            (
                r#"[{ "port": 1, "outbound": "direct" }, { "type": "logical", "mode": "and", "outbound": "direct",
                     "rules": [{ "port": 1 }, { "port": 2, "outbound": "direct" }] }]"#,
                "route.rules[1].rules[1].outbound: a nested rule takes no action",
            ),
            (
                r#"[{ "type": "logical", "mode": "and", "outbound": "direct",
                     "rules": [{ "port": 1, "action": "route" }] }]"#,
                "route.rules[0].rules[0].action: a nested rule takes no action",
            ),
            (
                r#"[{ "type": "logical", "mode": "and", "outbound": "direct",
                     "rules": [{ "type": "logical", "mode": "or", "rules": [{ "invert": true }] }] }]"#,
                "route.rules[0].rules[0].rules[0]: the rule has no conditions",
            ),
            (
                r#"[{ "type": "logical", "mode": "and", "port": 1, "outbound": "direct",
                     "rules": [{ "port": 1 }] }]"#,
                "route.rules[0].port: a logical rule's conditions are its rules",
            ),
            (
                r#"[{ "type": "logical", "outbound": "direct", "rules": [{ "port": 1 }] }]"#,
                "route.rules[0].mode",
            ),
            (
                r#"[{ "type": "logical", "mode": "xor", "outbound": "direct", "rules": [{ "port": 1 }] }]"#,
                "mode",
            ),
            (
                r#"[{ "type": "logical", "mode": "or", "outbound": "direct", "rules": [] }]"#,
                "route.rules[0].rules: a logical rule needs some",
            ),
            (
                r#"[{ "mode": "or", "port": 1, "outbound": "direct" }]"#,
                "route.rules[0].mode: only a logical rule has one",
            ),
            (
                r#"[{ "type": "logical", "mode": "or", "outbound": "direct",
                     "rules": [{ "rule_set": "missing" }] }]"#,
                "route.rules[0].rules[0].rule_set: rule-set [missing] does not exist",
            ),
            (
                r#"[{ "type": "nested", "port": 1, "outbound": "direct" }]"#,
                "route.rules[0]",
            ),
        ] {
            let err = config(rules).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    #[test]
    fn a_tun_taking_the_default_route_takes_sail_s_own_traffic() {
        let tun = |extra: &str| {
            Config::from_json(&format!(
                r#"{{ "inbounds": [{{ "type": "tun", "address": "172.19.0.1/30", "auto_route": true{} }}], "outbounds": [{{ "type": "direct" }}] }}"#,
                extra
            ))
            .unwrap()
        };
        assert!(tun("").tun_takes_own_traffic(false));
        // A host that opens the TUN routes it.
        assert!(!tun("").tun_takes_own_traffic(true));
        // auto_redirect keeps sail's own sockets out by their mark.
        assert!(!tun(r#", "auto_redirect": true"#).tun_takes_own_traffic(false));
    }

    #[test]
    fn a_default_interface_and_auto_detection_exclude_each_other() {
        let err = Config::from_json(
            r#"{ "route": { "default_interface": "en0", "auto_detect_interface": true } }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route: set default_interface or auto_detect_interface, not both"
        );
    }

    #[test]
    fn durations_are_read_as_sing_box_writes_them() {
        use std::time::Duration;
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        // Days, as sing-box's options take them.
        assert_eq!(
            parse_duration("7d").unwrap(),
            Duration::from_secs(7 * 86400)
        );
        assert_eq!(
            parse_duration("1d2h").unwrap(),
            Duration::from_secs(86400 + 7200)
        );
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(
            parse_duration("3\u{3bc}s").unwrap(),
            Duration::from_micros(3)
        );
        for bad in ["", "5", "s", "5 s", "5x", "-1s"] {
            assert!(parse_duration(bad).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn duration_overflow_is_an_error() {
        // One component can overflow Duration during the float conversion.
        assert!(parse_duration("222222222222222222222s").is_err());
        assert!(parse_duration(&format!("{}s", "9".repeat(400))).is_err());

        // Individually representable components can overflow when combined.
        assert!(parse_duration("10000000000000000000s10000000000000000000s").is_err());
    }

    #[test]
    fn protocol_options_errors_name_the_entry_and_field() {
        #[derive(serde_derive::Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct PortOnly {
            server_port: u16,
        }
        let mut options = Options::new();
        options.insert("server_port".into(), serde_json::json!("x"));
        let err = parse_options::<PortOnly>("outbound", "proxy", &options).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("[proxy] outbound: server_port: "),
            "{}",
            err
        );
    }

    #[test]
    fn dns_api_and_udp_timeout_fields() {
        let config = Config::from_json(
            r#"{
                "dns": { "strategy": "prefer_ipv6", "cache_capacity": 8, "timeout": "2s" },
                "api": { "listen": "127.0.0.1:9090", "secret": "Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja" },
                "inbounds": [{ "type": "socks", "listen_port": 1080, "udp_timeout": "1m" }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.dns.strategy, DnsStrategy::PreferIpv6);
        assert!(config.dns.strategy.ipv6());
        // Less than sing-box's least, 1024, is taken as that.
        assert_eq!(config.dns.cache_capacity(), 1024);
        assert_eq!(config.dns.timeout(), std::time::Duration::from_secs(2));
        let api = config.api.as_ref().unwrap();
        assert_eq!(api.listen, Some("127.0.0.1:9090".parse().unwrap()));
        assert_eq!(api.socket(), None);
        assert_eq!(
            config.inbounds[0].udp_timeout(),
            std::time::Duration::from_secs(60)
        );

        let socks = Config::from_json(r#"{ "inbounds": [{ "type": "socks" }] }"#).unwrap();
        assert_eq!(
            socks.inbounds[0].udp_timeout(),
            std::time::Duration::from_secs(300)
        );
        // A number of seconds, as sing-box takes it; not for WireGuard's.
        let seconds = Config::from_json(
            r#"{ "inbounds": [{ "type": "socks", "listen_port": 1080, "udp_timeout": 90 }] }"#,
        )
        .unwrap();
        assert_eq!(
            seconds.inbounds[0].udp_timeout(),
            std::time::Duration::from_secs(90)
        );
        let err =
            Config::from_json(r#"{ "endpoints": [{ "type": "wireguard", "udp_timeout": 90 }] }"#)
                .unwrap_err();
        assert!(
            err.to_string().starts_with("endpoints[0].udp_timeout"),
            "{}",
            err
        );

        let defaults = Config::from_json("{}").unwrap();
        assert_eq!(defaults.dns.strategy, DnsStrategy::PreferIpv4);
        assert_eq!(defaults.dns.timeout(), std::time::Duration::from_secs(10));
        assert_eq!(defaults.api, None);
    }

    #[test]
    fn the_api_is_on_a_socket_or_loopback_with_a_strong_secret() {
        let api = |json: &str| Config::from_json(&format!(r#"{{ "api": {} }}"#, json));
        // Present, it is served on the socket by default.
        let config = api("{}").unwrap();
        assert_eq!(config.api.unwrap().socket(), Some("api.sock".into()));
        let config = api(r#"{ "path": "/run/sail/api.sock" }"#).unwrap();
        assert_eq!(
            config.api.unwrap().socket(),
            Some("/run/sail/api.sock".into())
        );
        let strong = "Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja";
        for (json, error) in [
            (
                r#"{ "listen": "127.0.0.1:9091" }"#.to_string(),
                "api.secret: missing; api.listen needs one",
            ),
            (
                format!(r#"{{ "listen": "0.0.0.0:9091", "secret": "{}" }}"#, strong),
                "api.listen: 0.0.0.0:9091 is not a loopback address",
            ),
            (
                format!(
                    r#"{{ "listen": "192.168.1.2:9091", "secret": "{}" }}"#,
                    strong
                ),
                "api.listen: 192.168.1.2:9091 is not a loopback address",
            ),
            (
                r#"{ "listen": "127.0.0.1:9091", "secret": "s3cret" }"#.to_string(),
                "api.secret: too weak (6 characters, fewer than 32)",
            ),
            // A secret set for the socket is checked as well.
            (
                r#"{ "secret": "s3cret" }"#.to_string(),
                "api.secret: too weak",
            ),
        ] {
            let err = api(&json).unwrap_err().to_string();
            assert!(err.starts_with(error), "{}: {}", json, err);
        }
        let json = format!(r#"{{ "listen": "[::1]:9091", "secret": "{}" }}"#, strong);
        let config = api(&json).unwrap();
        assert_eq!(config.api.as_ref().unwrap().socket(), None);
        // What prints of a configuration does not give the secret away.
        let printed = format!("{:?}", config);
        assert!(
            printed.contains("<redacted>") && !printed.contains(strong),
            "{}",
            printed
        );
    }

    #[cfg(all(feature = "inbound-reality", feature = "outbound-reality"))]
    #[test]
    fn reality_keys_are_checked_when_read() {
        let outbound = |reality: &str| {
            Config::from_json(&format!(
                r#"{{ "outbounds": [{{ "type": "vless", "tag": "r", "server": "a",
                     "server_port": 443, "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
                     "tls": {{ "enabled": true, "server_name": "a",
                       "reality": {{ {} }} }} }}] }}"#,
                reality
            ))
            .map(|_| ())
            .map_err(|e| e.to_string())
        };
        let key = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
        assert_eq!(
            outbound(&format!(
                r#""enabled": true, "public_key": "{}", "short_id": "0123""#,
                key
            )),
            Ok(())
        );
        for (reality, message) in [
            (
                r#""enabled": true, "public_key": "wywOQgzCr2vr85JpoMxzCakHIIvgUtsG""#.to_string(),
                "[r] outbound: tls.reality.public_key: must be 32 bytes",
            ),
            (
                r#""enabled": true, "public_key": "not a key""#.to_string(),
                "[r] outbound: tls.reality.public_key: neither hex nor base64url",
            ),
            (
                format!(
                    r#""enabled": true, "public_key": "{}", "short_id": "str1""#,
                    key
                ),
                "[r] outbound: tls.reality.short_id: not hex",
            ),
        ] {
            assert_eq!(outbound(&reality), Err(message.to_string()), "{}", reality);
        }
        // Not enabled, not checked.
        assert_eq!(outbound(r#""public_key": "x""#), Ok(()));
        let err = Config::from_json(
            r#"{ "inbounds": [{ "type": "vless", "tag": "in", "listen_port": 443,
                 "users": [], "tls": { "enabled": true, "server_name": "a",
                 "reality": { "enabled": true, "private_key": "password1",
                   "short_id": ["00"],
                   "handshake": { "server": "a", "server_port": 443 } } } }] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "[in] inbound: tls.reality.private_key: neither hex nor base64url"
        );
    }

    #[test]
    fn endpoints_take_their_tags_as_inbounds_and_outbounds() {
        let config = Config::from_json(
            r#"{
                "endpoints": [{ "type": "wireguard", "udp_timeout": "2m", "mtu": 1400 }],
                "route": { "final": "wireguard", "rules": [
                    { "inbound": ["wireguard"], "outbound": "wireguard" }
                ] }
            }"#,
        )
        .unwrap();
        let endpoint = &config.endpoints[0];
        assert_eq!(endpoint.tag, "wireguard");
        assert_eq!(endpoint.options["mtu"], 1400);
        assert!(!endpoint.options.contains_key("udp_timeout"));
        let inbound = endpoint.as_inbound();
        assert_eq!(inbound.udp_timeout(), std::time::Duration::from_secs(120));
        assert_eq!(inbound.protocol, "wireguard");

        for (json, message) in [
            (
                r#"{ "inbounds": [{ "type": "socks", "tag": "wg" }],
                     "endpoints": [{ "type": "wireguard", "tag": "wg" }] }"#,
                "[wg] endpoint: the tag is taken by an inbound",
            ),
            (
                r#"{ "outbounds": [{ "type": "direct", "tag": "wg" }],
                     "endpoints": [{ "type": "wireguard", "tag": "wg" }] }"#,
                "[wg] endpoint: the tag is taken by an outbound",
            ),
            (
                r#"{ "endpoints": [{ "type": "wireguard" }, { "type": "wireguard" }] }"#,
                "[wireguard] endpoint: the tag is taken by an endpoint",
            ),
            (
                r#"{ "endpoints": [{ "type": "wireguard", "udp_timeout": "0s" }] }"#,
                "[wireguard] endpoint: udp_timeout: must be more than 0",
            ),
            (
                r#"{ "endpoints": [{ "type": "wireguard" }], "route": { "final": "wg" } }"#,
                "route.final: outbound [wg] does not exist",
            ),
        ] {
            let err = Config::from_json(json).unwrap_err();
            assert_eq!(err.to_string(), message, "{}", json);
        }
    }

    /// PASS has no rule after `final` to pass to, and load-balance and
    /// smart pick after the rules, where nothing can pass.
    #[test]
    fn a_pass_outbound_where_nothing_can_pass_is_an_error() {
        let pass = r#"{ "type": "pass", "tag": "PASS" }"#;
        let with = |outbounds: &str, route: &str| {
            format!(
                r#"{{ "outbounds": [{{ "type": "direct", "tag": "d" }}, {}, {}],
                      "route": {{ {} }} }}"#,
                pass, outbounds, route
            )
        };
        for (json, message) in [
            (
                with(r#"{ "type": "direct", "tag": "x" }"#, r#""final": "PASS""#),
                "route.final: [PASS] is a pass outbound, and no rule comes after final",
            ),
            (
                format!(r#"{{ "outbounds": [{}, {{ "type": "direct" }}] }}"#, pass),
                "outbounds[0]: [PASS] is a pass outbound, and the first outbound is final when \
                 route.final is not set",
            ),
            (
                with(
                    r#"{ "type": "load-balance", "tag": "lb", "outbounds": ["d", "PASS"] }"#,
                    "",
                ),
                "[lb] outbound: outbounds[1]: [PASS] is a pass outbound; PASS is not supported \
                 in load-balance/smart",
            ),
            (
                with(
                    r#"{ "type": "selector", "tag": "s", "outbounds": ["d", "u"] },
                       { "type": "urltest", "tag": "u", "outbounds": ["PASS"] },
                       { "type": "smart", "tag": "sm", "outbounds": ["d", "s"] }"#,
                    "",
                ),
                "[sm] outbound: outbounds[1]: [s] can pick a pass outbound; PASS is not \
                 supported in load-balance/smart",
            ),
            (
                format!(
                    r#"{{ "outbounds": [{{ "type": "direct", "tag": "d" }}],
                          "outbound_providers": [{{ "type": "inline", "tag": "p",
                              "outbounds": [{}] }}] }}"#,
                    pass
                ),
                "outbound_providers[0]: outbounds[0]: a group, a plugin or a pass outbound is \
                 not a provider's outbound",
            ),
        ]
        .into_iter()
        .filter(|(json, _)| cfg!(feature = "outbound-provider") || !json.contains("providers"))
        {
            let err = Config::from_json(&json).unwrap_err();
            assert_eq!(err.to_string(), message, "{}", json);
        }
        // A rule's outbound, final through a group, a group's member.
        Config::from_json(&with(
            r#"{ "type": "selector", "tag": "s", "outbounds": ["PASS", "d"] },
               { "type": "load-balance", "tag": "lb", "outbounds": ["d"] }"#,
            r#""rules": [{ "port": 1, "outbound": "PASS" }], "final": "s""#,
        ))
        .unwrap();
    }

    #[test]
    fn zero_timeouts_and_capacity_and_env_are_errors() {
        for (json, field) in [
            (r#"{ "dns": { "timeout": "0s" } }"#, "dns.timeout"),
            (
                r#"{ "dns": { "cache_capacity": 0 } }"#,
                "dns.cache_capacity",
            ),
            (
                r#"{ "inbounds": [{ "type": "socks", "udp_timeout": "0s" }] }"#,
                "udp_timeout",
            ),
            (r#"{ "env": { "A": "1" } }"#, "env"),
        ] {
            let err = Config::from_json(json).unwrap_err();
            assert!(err.to_string().contains(field), "{}: {}", json, err);
        }
    }

    /// A configuration of a direct outbound `d` and the group `group`, with
    /// the outbound providers `providers`.
    fn with_providers(providers: &str, group: &str) -> Result<Config> {
        Config::from_json(&format!(
            r#"{{ "outbounds": [{{ "type": "direct", "tag": "d" }}, {}],
                  "outbound_providers": [{}] }}"#,
            group, providers
        ))
    }

    const REMOTE: &str = r#"{ "type": "remote", "tag": "p", "url": "https://example.com/s",
        "filter": ["HK", "JP"], "exclude_type": "vmess", "detour": "d",
        "override": { "skip-cert-verify": true, "additional-prefix": "A|" } }"#;

    #[cfg(feature = "outbound-provider")]
    #[test]
    fn outbound_providers_and_the_groups_that_take_them() {
        let group = r#"{ "type": "selector", "tag": "g", "providers": ["p"], "filter": "HK",
            "exclude_type": ["Direct"], "empty_fallback": "d" }"#;
        let config = with_providers(REMOTE, group).unwrap();
        assert_eq!(config.outbound_providers[0].filter, ["HK", "JP"]);
        let members = GroupProviders::of(&config.outbounds[1].options).unwrap();
        assert_eq!(members.providers, ["p"]);
        assert_eq!(members.dependencies(Vec::new()), ["d"]);

        let local = r#"{ "type": "local", "tag": "p", "path": "p.yaml", "update_interval": "1m" }"#;
        let inline =
            r#"{ "type": "inline", "tag": "p", "outbounds": [{ "type": "direct", "tag": "a" }] }"#;
        let taking = r#"{ "type": "urltest", "tag": "g", "providers": "p" }"#;
        with_providers(local, taking).unwrap();
        with_providers(inline, taking).unwrap();

        for (providers, group, error) in [
            (
                REMOTE,
                r#"{ "type": "selector", "tag": "g", "providers": ["q"] }"#,
                "[g] outbound: providers: provider [q] does not exist",
            ),
            (
                REMOTE,
                r#"{ "type": "selector", "tag": "g", "outbounds": ["d"], "filter": "HK" }"#,
                "[g] outbound: filter: only with providers",
            ),
            (
                REMOTE,
                r#"{ "type": "fallback", "tag": "g", "providers": "p", "empty_fallback": "x" }"#,
                "[g] outbound: empty_fallback: outbound [x] does not exist",
            ),
            (
                REMOTE,
                r#"{ "type": "fallback", "tag": "g", "providers": "p", "empty_fallback": "g" }"#,
                "[g] outbound: empty_fallback: [g] is a group",
            ),
            (
                &REMOTE.replace(r#""detour": "d""#, r#""detour": "g""#),
                r#"{ "type": "load-balance", "tag": "g", "providers": "p" }"#,
                "[p]: detour: [g] takes its members from it",
            ),
            (
                &format!("{}, {}", REMOTE, REMOTE),
                r#"{ "type": "direct", "tag": "g" }"#,
                "outbound_providers[1]: another provider is tagged [p]",
            ),
            (
                r#"{ "type": "remote", "tag": "p" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "outbound_providers[0]: url: missing",
            ),
            (
                r#"{ "type": "local", "tag": "p", "path": "a", "url": "https://a" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "url: only a remote provider takes one",
            ),
            (
                r#"{ "type": "inline", "tag": "p", "filter": "HK",
                  "outbounds": [{ "type": "direct", "tag": "a" }] }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "filter: only a remote or local provider takes one",
            ),
            (
                r#"{ "type": "inline", "tag": "p",
                  "outbounds": [{ "type": "selector", "tag": "a", "outbounds": ["d"] }] }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "outbounds[0]: a group, a plugin or a pass outbound is not a provider's outbound",
            ),
            (
                r#"{ "type": "remote", "tag": "p", "url": "https://a", "detour": "x" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "detour: outbound [x] does not exist",
            ),
            (
                r#"{ "type": "remote", "tag": "p", "url": "https://a", "size_limit": 0 }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "size_limit: must be more than 0",
            ),
            (
                r#"{ "type": "local", "tag": "p", "path": "a", "size_limit": 10 }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "size_limit: only a remote provider takes one",
            ),
            // A URL in an error keeps its host alone: its path and query
            // carry a subscription's token.
            (
                r#"{ "type": "remote", "tag": "p", "url": "ftp://h.example/sub/s3cret?token=t0ken" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "url: ftp://h.example/… is not an http(s) URL",
            ),
        ] {
            let err = with_providers(providers, group).unwrap_err();
            assert!(err.to_string().contains(error), "{}: {}", error, err);
            assert!(!err.to_string().contains("s3cret"), "{}", err);
        }
    }

    #[cfg(not(feature = "outbound-provider"))]
    #[test]
    fn outbound_providers_need_their_feature() {
        let err = with_providers(REMOTE, r#"{ "type": "direct", "tag": "g" }"#).unwrap_err();
        assert!(
            err.to_string().contains("outbound-provider feature"),
            "{}",
            err
        );
        let err = with_providers(
            "",
            r#"{ "type": "selector", "tag": "g", "outbounds": ["d"],
            "exclude_filter": "x" }"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("[g] outbound: exclude_filter: needs the outbound-provider feature"),
            "{}",
            err
        );
    }

    /// An HTTP client's TCP connections take sing-box's keepalive fields.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn http_client_connections_get_the_keepalive_it_sets() {
        use crate::net::dial::fields::keepalive_dialled;
        use crate::net::TcpKeepAlive;
        use std::time::Duration;

        let dial = |client: serde_json::Value| {
            serde_json::from_value::<HttpClient>(client)
                .unwrap()
                .dialer(&crate::net::DialDefaults::default())
                .unwrap()
        };
        let set = dial(serde_json::json!({
            "tag": "h", "tcp_keep_alive": "40s", "tcp_keep_alive_interval": "7s",
        }));
        assert_eq!(
            keepalive_dialled(&set).await,
            Some(TcpKeepAlive {
                idle: Duration::from_secs(40),
                interval: Duration::from_secs(7),
            })
        );
        let off = dial(serde_json::json!({ "tag": "h", "disable_tcp_keep_alive": true }));
        assert_eq!(keepalive_dialled(&off).await, None);
        let unset = dial(serde_json::json!({ "tag": "h" }));
        assert_eq!(keepalive_dialled(&unset).await, Some(TcpKeepAlive::DEFAULT));
    }

    /// A field an HTTP client cannot apply here fails the configuration,
    /// with its path, as an outbound's does, rather than its downloads.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_http_client_is_checked_against_the_platform() {
        let err = |json: serde_json::Value| {
            Config::from_json(&json.to_string())
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            err(serde_json::json!({
                "http_clients": [{ "tag": "h", "bind_interface": "no-such-if0" }],
            })),
            "http_clients[0]: bind_interface: there is no interface \"no-such-if0\""
        );
        assert_eq!(
            err(serde_json::json!({
                "route": { "rule_set": [{
                    "type": "remote", "tag": "r", "url": "https://example.com/r.srs",
                    "http_client": { "bind_interface": "no-such-if0" },
                }] },
            })),
            "route.rule_set[0].http_client: bind_interface: there is no interface \"no-such-if0\""
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            err(serde_json::json!({
                "http_clients": [{ "tag": "h", "routing_mark": 1 }],
            })),
            "http_clients[0]: routing_mark: only supported on Linux"
        );
    }

    /// An HTTP client dials with its dial fields over the instance's
    /// defaults, whose host protects its sockets.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_http_client_dials_over_the_defaults() {
        let (mut defaults, protected) = crate::net::dial::recording::defaults();
        defaults.route.routing_mark = Some(7);
        let dialer = serde_json::from_value::<HttpClient>(serde_json::json!({
            "tag": "h", "connect_timeout": "3s",
        }))
        .unwrap()
        .dialer(&defaults)
        .unwrap();
        assert_eq!(dialer.spec().routing_mark, Some(7));
        assert_eq!(dialer.connect_timeout(), std::time::Duration::from_secs(3));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialled, accepted) = tokio::join!(dialer.tcp_to(addr), listener.accept());
        dialled.unwrap();
        accepted.unwrap();
        assert_eq!(protected.count(), 1);
    }
}
