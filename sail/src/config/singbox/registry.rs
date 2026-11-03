//! The registry of sing-box's fields: every field sing-box accepts, as
//! `fields.json` lists it (tools/singbox-fields extracts it from sing-box's
//! source), and how sail treats each, measured by reading a configuration
//! that sets it and building what it configures, short of listening or
//! connecting.
//!
//! What it measures is kept in `fields.tiers.json`, and written out as the
//! support tables in docs/compat; the test fails where either differs from
//! the measurement. `SAIL_REGISTRY_UPDATE=1 cargo test -p sail registry`
//! rewrites them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::upstream;

const FIELDS: &str = include_str!("fields.json");

/// A field of `fields.json`.
#[derive(Deserialize)]
struct Field {
    path: String,
    json: String,
    #[serde(default)]
    r#enum: Vec<Value>,
    #[serde(default)]
    deprecated: bool,
}

#[derive(Deserialize)]
struct Inventory {
    sing_box: String,
    fields: Vec<Field>,
}

/// How sail treats a field, as measured.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
enum Measured {
    /// Read, and acted on.
    Supported,
    /// Dropped with a warning.
    Ignored,
    /// An error saying sail does not implement it.
    Unsupported,
    /// An error for a field sail does not know: neither implemented nor
    /// sorted out in `upstream`.
    Unknown,
}

/// A step of a registry path.
#[derive(Debug, Clone, PartialEq)]
enum Step {
    Key(String),
    /// Into a list's entries, or those of one type: `[]`, `[vless]`,
    /// `[action=route]`.
    Entry(Option<(String, String)>),
}

fn steps(path: &str) -> Vec<Step> {
    let mut out = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        if let Some(inner) = rest.strip_prefix('[') {
            let end = inner.find(']').expect("a closed selector");
            let sel = &inner[..end];
            out.push(Step::Entry(match sel.split_once('=') {
                _ if sel.is_empty() => None,
                Some((k, v)) => Some((k.to_string(), v.to_string())),
                None => Some(("type".to_string(), sel.to_string())),
            }));
            rest = &inner[end + 1..];
        } else {
            let rest_ = rest.strip_prefix('.').unwrap_or(rest);
            let end = rest_.find(['.', '[']).unwrap_or(rest_.len());
            out.push(Step::Key(rest_[..end].to_string()));
            rest = &rest_[end..];
        }
    }
    out
}

/// Values of a field's JSON type to set it to: each of its values when
/// sing-box lists them, the first sail takes deciding.
fn samples(field: &Field) -> Vec<Value> {
    if !field.r#enum.is_empty() {
        return field.r#enum.clone();
    }
    // A value of the field's own kind, where any string would not do.
    let key = field.path.rsplit('.').next().unwrap_or_default();
    let own = match key {
        "inet6_bind_address" => vec![json!("2001:db8::1")],
        k if k.ends_with("_address") => vec![json!("192.0.2.1")],
        "client_subnet" => vec![json!("192.0.2.0/24")],
        "domain_strategy" | "strategy" => vec![json!("prefer_ipv4")],
        _ => vec![],
    };
    own.into_iter()
        .chain(field.json.split('|').flat_map(samples_of))
        .collect()
}

fn samples_of(kind: &str) -> Vec<Value> {
    match kind {
        "string" => vec![json!("x")],
        // Turns nothing on that would reach out of the test.
        "bool" => vec![json!(false)],
        "number" => vec![json!(1), json!(2), json!(3), json!(0)],
        "duration" => vec![json!("1s")],
        "array" => vec![json!([])],
        "object" | "map" | "any" => vec![json!({})],
        _ => match kind.strip_prefix("listable-") {
            Some(item) => samples_of(item),
            None => panic!("fields.json: unknown JSON type {}", kind),
        },
    }
}

/// The configuration every probe starts from: what rules and servers
/// name.
fn base() -> Value {
    json!({
        "inbounds": [{ "type": "shadowsocks", "tag": "ss", "listen_port": 10801,
            "method": "aes-128-gcm", "password": "p" }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "dns": { "servers": [{ "type": "local", "tag": "local" }] },
    })
}

/// A list's entry that is valid on its own, of the type `sel` names; `at`
/// is where the list is, without selectors (`inbounds`, `route.rules`,
/// `inbounds.users`).
fn entry(at: &str, sel: Option<(&str, &str)>, local_rule_set: &Path, pki: &Pki) -> Value {
    let label = sel.map(|(_, v)| v);
    let last = at.rsplit('.').next().unwrap_or(at);
    match (at, sel) {
        ("inbounds", _) => inbound(label.unwrap_or("mixed"), pki),
        ("outbounds", _) => outbound(label.unwrap_or("direct")),
        ("endpoints", _) => endpoint(label.unwrap_or("wireguard")),
        ("dns.servers", _) => dns_server(label.unwrap_or("udp")),
        ("services", _) => json!({ "type": label.unwrap_or("api"), "tag": "probe" }),
        ("route.rules", Some(("action", action))) => route_action(action),
        ("route.rules", Some((_, "logical"))) => json!({ "type": "logical", "mode": "and",
            "rules": [{ "domain": "a" }], "outbound": "direct" }),
        ("route.rules", _) => json!({ "domain": "a", "outbound": "direct" }),
        ("dns.rules", Some(("action", action))) => dns_action(action),
        ("dns.rules", Some((_, "logical"))) => json!({ "type": "logical", "mode": "and",
            "rules": [{ "domain": "a" }], "server": "local" }),
        ("dns.rules", _) => json!({ "domain": "a", "server": "local" }),
        ("route.rule_set", _) => match label.unwrap_or("inline") {
            "local" => json!({ "type": "local", "tag": "probe", "format": "source",
                "path": local_rule_set }),
            "remote" => json!({ "type": "remote", "tag": "probe", "format": "source",
                "url": "https://example.com/probe.json" }),
            kind => json!({ "type": kind, "tag": "probe", "rules": [{ "domain": "a" }] }),
        },
        ("http_clients", _) => json!({ "tag": "probe" }),
        (_, Some((_, "logical"))) if last == "rules" => {
            json!({ "type": "logical", "mode": "and", "rules": [{ "domain": "a" }] })
        }
        (_, Some((key, value))) => json!({ key: value }),
        (_, None) => json!({}),
    }
}

fn inbound(kind: &str, pki: &Pki) -> Value {
    let mut v = json!({ "type": kind, "tag": "probe", "listen_port": 10800 });
    let tls = json!({ "tls": { "enabled": true, "certificate": pki.cert, "key": pki.key } });
    let extra = match kind {
        "shadowsocks" => json!({ "method": "aes-128-gcm", "password": "p" }),
        "trojan" | "naive" | "hysteria" | "vless" | "vmess" => json!({ "users": [] }),
        "anytls" | "hysteria2" | "tuic" => {
            let mut v = json!({ "users": [] });
            merge(&mut v, tls);
            v
        }
        // Handing its connections to the Shadowsocks inbound `base` has.
        "shadowtls" => json!({ "version": 3, "users": [{ "password": "p" }],
            "handshake": { "server": "example.com", "server_port": 443 }, "detour": "ss" }),
        "tun" => {
            v.as_object_mut().map(|v| v.remove("listen_port"));
            json!({ "address": ["172.19.0.1/30"] })
        }
        _ => json!({}),
    };
    merge(&mut v, extra);
    v
}

fn outbound(kind: &str) -> Value {
    let mut v = json!({ "type": kind, "tag": "probe" });
    let server = json!({ "server": "example.com", "server_port": 443 });
    let extra = match kind {
        "direct" | "block" | "bridge" => json!({}),
        "selector" | "urltest" | "fallback" | "load-balance" | "smart" => {
            json!({ "outbounds": ["direct"] })
        }
        "shadowsocks" => json!({ "method": "aes-128-gcm", "password": "p" }),
        "trojan" | "naive" => json!({ "password": "p" }),
        "anytls" | "hysteria2" => json!({ "password": "p",
            "tls": { "enabled": true, "server_name": "example.com" } }),
        "vless" | "vmess" => json!({ "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b" }),
        "tuic" => json!({ "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "password": "p",
            "tls": { "enabled": true, "server_name": "example.com" } }),
        "shadowtls" => json!({ "version": 3, "password": "p",
            "tls": { "enabled": true, "server_name": "example.com" } }),
        _ => json!({}),
    };
    let groups = [
        "selector",
        "urltest",
        "fallback",
        "load-balance",
        "smart",
        "network",
        "tryall",
    ];
    if !matches!(kind, "direct" | "block" | "bridge") && !groups.contains(&kind) {
        merge(&mut v, server);
    }
    merge(&mut v, extra);
    v
}

fn endpoint(kind: &str) -> Value {
    match kind {
        "wireguard" => json!({ "type": kind, "tag": "probe", "address": ["10.0.0.2/32"],
            "private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "peers": [{ "address": "example.com", "port": 51820,
                "public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                "allowed_ips": ["0.0.0.0/0"] }] }),
        _ => json!({ "type": kind, "tag": "probe" }),
    }
}

fn dns_server(kind: &str) -> Value {
    let mut v = json!({ "type": kind, "tag": "probe" });
    let extra = match kind {
        "udp" | "tcp" | "tls" | "https" | "quic" | "h3" => json!({ "server": "1.1.1.1" }),
        "fakeip" => json!({ "inet4_range": "198.18.0.0/15" }),
        _ => json!({}),
    };
    merge(&mut v, extra);
    v
}

fn route_action(action: &str) -> Value {
    let mut v = json!({ "domain": "a", "action": action });
    if matches!(action, "route" | "bypass") {
        merge(&mut v, json!({ "outbound": "direct" }));
    }
    v
}

fn dns_action(action: &str) -> Value {
    let mut v = json!({ "domain": "a", "action": action });
    if matches!(action, "route" | "evaluate") {
        merge(&mut v, json!({ "server": "local" }));
    }
    v
}

/// `from`'s fields into `into`'s, an object in both merged in turn.
fn merge(into: &mut Value, from: Value) {
    if let (Value::Object(into), Value::Object(from)) = (into, from) {
        for (key, value) in from {
            match into.get_mut(&key) {
                Some(at) if at.is_object() && value.is_object() => merge(at, value),
                _ => {
                    into.insert(key, value);
                }
            }
        }
    }
}

/// The value an object on the way to a field starts as.
fn object(key: &str) -> Value {
    match key {
        "domain_resolver" => json!({ "server": "local" }),
        // REALITY's and ShadowTLS's handshake server.
        "handshake" => json!({ "server": "example.com", "server_port": 443 }),
        _ => json!({}),
    }
}

/// What an extension needs to be taken: fields next to it, merged into
/// the entry probed, and entries before that one in its list. A path may
/// name several types, as `inbounds[trojan|vless]`.
const CONTEXT: &[(&str, &str, &str)] = &[
    (
        "inbounds[anytls|http|hysteria2|trojan|tuic|vless|vmess].tls.client_certificate_sha256",
        r#"{ "tls": { "client_authentication": "require-and-verify" } }"#,
        "[]",
    ),
    (
        "inbounds[http|trojan|vless|vmess].tls.reality.server_names",
        r#"{ "tls": { "reality": { "handshake": { "server": "example.com", "server_port": 443 } } } }"#,
        "[]",
    ),
    (
        "dns.servers[race].servers",
        "{}",
        r#"[{ "type": "local", "tag": "other" }]"#,
    ),
    (
        "dns.servers[sequential].servers",
        "{}",
        r#"[{ "type": "local", "tag": "other" }]"#,
    ),
    (
        "dns.servers[sequential].attempt_timeout",
        r#"{ "servers": ["local", "other"] }"#,
        r#"[{ "type": "local", "tag": "other" }]"#,
    ),
    (
        "dns.servers[sequential].budget",
        r#"{ "servers": ["local", "other"] }"#,
        r#"[{ "type": "local", "tag": "other" }]"#,
    ),
    (
        "dns.servers[sequential].prefer_for",
        r#"{ "servers": ["local", "other"] }"#,
        r#"[{ "type": "local", "tag": "other" }]"#,
    ),
    (
        "dns.rules[].ip_match_all",
        r#"{ "match_response": true, "ip_cidr": ["10.0.0.0/8"] }"#,
        r#"[{ "domain": "a", "action": "evaluate", "server": "local" }]"#,
    ),
    (
        "outbounds[network].default",
        r#"{ "branches": [{ "network_type": ["wifi"], "outbound": "direct" }] }"#,
        "[]",
    ),
    (
        "route.rules[].no_resolve",
        r#"{ "ip_cidr": ["10.0.0.0/8"] }"#,
        "[]",
    ),
    (
        "route.rule_set[inline].rules[].no_resolve",
        r#"{ "ip_cidr": ["10.0.0.0/8"] }"#,
        "[]",
    ),
    (
        "route.rule_set[remote].behavior",
        r#"{ "format": "clash-yaml" }"#,
        "[]",
    ),
    (
        "outbounds[selector].providers",
        "{}",
        r#"{ "outbound_providers": [{ "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "a" }] }] }"#,
    ),
    (
        "outbounds[selector].filter",
        r#"{ "providers": "p" }"#,
        r#"{ "outbound_providers": [{ "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "a" }] }] }"#,
    ),
    (
        "outbounds[urltest].providers",
        "{}",
        r#"{ "outbound_providers": [{ "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "a" }] }] }"#,
    ),
    (
        "outbounds[urltest].filter",
        r#"{ "providers": "p" }"#,
        r#"{ "outbound_providers": [{ "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "a" }] }] }"#,
    ),
];

/// `config` with what `path` needs (`CONTEXT`).
fn with_context(config: &mut Value, path: &str) {
    let Some((_, with, before)) = CONTEXT
        .iter()
        .find(|(p, _, _)| expand(p).iter().any(|p| p == path))
    else {
        return;
    };
    let with: Value = serde_json::from_str(with).expect("a context");
    let before: Value = serde_json::from_str(before).expect("a context");
    merge(probed(config, path).expect("the entry probed"), with);
    let before = match before {
        Value::Array(entries) => entries,
        top => {
            merge(config, top);
            return;
        }
    };
    let list = path.split('[').next().expect("a list");
    let pointer = format!("/{}", list.replace('.', "/"));
    if let Some(Value::Array(entries)) = config.pointer_mut(&pointer) {
        let at = entries.len() - 1;
        for (i, entry) in before.into_iter().enumerate() {
            entries.insert(at + i, entry);
        }
    }
}

/// The entry of the list `path` begins in that the probe set it on.
fn probed<'a>(config: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let list = path.split('[').next()?;
    let pointer = format!("/{}", list.replace('.', "/"));
    let entries = config.pointer_mut(&pointer)?.as_array_mut()?;
    let entry = entries.last_mut()?;
    // A rule-set's rules: its first rule is the one set.
    if path.contains("].rules[]") {
        return entry.get_mut("rules")?.as_array_mut()?.first_mut();
    }
    Some(entry)
}

/// The paths `pattern` names: `outbounds[vless|vmess].tls` is
/// `outbounds[vless].tls` and `outbounds[vmess].tls`.
fn expand(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('[') else {
        return vec![pattern.to_string()];
    };
    let close = open + pattern[open..].find(']').expect("a closing bracket");
    let (head, choices, tail) = (
        &pattern[..open],
        &pattern[open + 1..close],
        &pattern[close + 1..],
    );
    choices
        .split('|')
        .flat_map(|choice| {
            expand(tail)
                .into_iter()
                .map(move |rest| format!("{}[{}]{}", head, choice, rest))
        })
        .collect()
}

/// `config` with the entry probed (tagged `probe`) on TLS, if it has a
/// `tls` the probe made: an extension of TLS is read only then. An
/// inbound's takes the certificate, or with REALITY its key; one that
/// makes its own (`self_signed`) is left with none.
fn prepared(mut config: Value, pki: &Pki) -> Value {
    for (list, inbound) in [("inbounds", true), ("outbounds", false), ("dns", false)] {
        let entries = match list {
            "dns" => config.pointer_mut("/dns/servers"),
            _ => config.get_mut(list),
        };
        let Some(Value::Array(entries)) = entries else {
            continue;
        };
        for entry in entries {
            if entry.get("tag").and_then(Value::as_str) != Some("probe") {
                continue;
            }
            let Some(Value::Object(tls)) = entry.get_mut("tls") else {
                continue;
            };
            tls.insert("enabled".into(), json!(true));
            if !inbound {
                tls.entry("server_name").or_insert(json!("example.com"));
            } else if let Some(Value::Object(reality)) = tls.get_mut("reality") {
                reality.insert("enabled".into(), json!(true));
                reality.insert("private_key".into(), json!("11".repeat(32)));
                reality.insert("short_id".into(), json!("0123"));
                tls.insert("server_name".into(), json!("example.com"));
            } else if tls.get("self_signed") != Some(&json!(true)) {
                tls.insert("certificate".into(), json!(pki.cert));
                tls.insert("key".into(), json!(pki.key));
            } else {
                // Entries valid on their own (anytls, hysteria2, tuic) carry one.
                for field in ["certificate", "certificate_path", "key", "key_path"] {
                    tls.remove(field);
                }
            }
        }
    }
    config
}

/// A certificate and its key, for the inbounds that need TLS.
struct Pki {
    cert: String,
    key: String,
}

struct Registry {
    /// The sing-box release `fields.json` is of.
    version: String,
    fields: Vec<Field>,
    kinds: HashMap<String, String>,
    local_rule_set: PathBuf,
    pki: Pki,
}

impl Registry {
    fn new() -> Self {
        let inventory: Inventory = serde_json::from_str(FIELDS).expect("fields.json reads");
        let kinds = inventory
            .fields
            .iter()
            .map(|f| (f.path.clone(), f.json.clone()))
            .collect();
        let local_rule_set =
            std::env::temp_dir().join(format!("sail-registry-{}.json", std::process::id()));
        std::fs::write(
            &local_rule_set,
            r#"{ "version": 3, "rules": [{ "domain": "a" }] }"#,
        )
        .expect("a rule-set written");
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("a certificate");
        Self {
            version: inventory.sing_box,
            fields: inventory.fields,
            kinds,
            local_rule_set,
            pki: Pki {
                cert: cert.pem(),
                key: key_pair.serialize_pem(),
            },
        }
    }

    /// A configuration that sets `path` to `value`, and is otherwise valid.
    fn probe(&self, path: &str, value: Value) -> Value {
        let mut config = base();
        let steps = steps(path);
        let mut cur = &mut config;
        let mut prefix = String::new();
        let mut at = String::new();
        for (i, step) in steps.iter().enumerate() {
            match step {
                Step::Key(key) => {
                    if !prefix.is_empty() {
                        prefix.push('.');
                        at.push('.');
                    }
                    prefix.push_str(key);
                    at.push_str(key);
                    let map = cur.as_object_mut().expect("an object on the way");
                    if i + 1 == steps.len() {
                        // A union's own tag keeps the entry's.
                        if !(matches!(key.as_str(), "type" | "action") && map.contains_key(key)) {
                            map.insert(key.clone(), value);
                        }
                        break;
                    }
                    let list = matches!(steps[i + 1], Step::Entry(_))
                        && self
                            .kinds
                            .get(&prefix)
                            .is_some_and(|k| k.contains("array") || k.starts_with("listable"));
                    let child = map.entry(key.clone()).or_insert(Value::Null);
                    match list {
                        true if !child.is_array() => *child = json!([]),
                        false if !child.is_object() => *child = object(key),
                        _ => {}
                    }
                    cur = child;
                }
                Step::Entry(sel) => {
                    let label = sel.as_ref().map(|(k, v)| (k.as_str(), v.as_str()));
                    prefix.push_str(&match &sel {
                        None => "[]".to_string(),
                        Some((k, v)) if k == "type" => format!("[{}]", v),
                        Some((k, v)) => format!("[{}={}]", k, v),
                    });
                    let top = !at.contains('.')
                        || matches!(
                            at.as_str(),
                            "dns.servers" | "dns.rules" | "route.rules" | "route.rule_set"
                        );
                    let fresh = entry(&at, label, &self.local_rule_set, &self.pki);
                    match cur {
                        Value::Array(list) => {
                            // A nested list's first entry is the one to set, if
                            // it is of the type.
                            let reuse = !top
                                && list.first().is_some_and(|e| match &label {
                                    None => e.is_object(),
                                    Some((k, v)) => e.get(*k).and_then(Value::as_str) == Some(v),
                                });
                            if !reuse {
                                list.insert(if top { list.len() } else { 0 }, fresh);
                            }
                            let index = if top { list.len() - 1 } else { 0 };
                            cur = &mut list[index];
                        }
                        Value::Object(map) => {
                            if let Some((k, v)) = label {
                                if map.get(k).and_then(Value::as_str) != Some(v) {
                                    *cur = fresh;
                                }
                            }
                        }
                        _ => *cur = fresh,
                    }
                }
            }
        }
        config
    }
}

/// Errors that say sail does not implement what the configuration sets,
/// whatever its value: sail's own (`upstream`), a protocol it lacks, and
/// the refusals of the protocols', the transports' and the router's own.
/// A refusal of a value is taken for one of the field when every sample
/// is refused.
const UNSUPPORTED: &[&str] = &[
    "does not implement",
    "unknown protocol",
    "not supported",
    "not for a",
    "cannot tell",
    "does not match it",
    "does not create",
    "offers its own",
];

/// Conditions supported only with a cargo feature, which the tests have
/// on: the tables name it.
const FEATURES: &[(&str, &str)] = &[
    ("process_name", "rule-process-name"),
    ("process_path", "rule-process-name"),
    ("process_path_regex", "rule-process-name"),
];

/// Where a field is measured: an HTTP client in place is one of
/// `http_clients`, whose errors it gets, while in place an unknown field
/// only fails it as neither a tag nor a client.
fn measured_at(path: &str) -> String {
    match path.strip_prefix("route.rule_set[remote].http_client") {
        Some(rest) => format!("http_clients[]{}", rest),
        None => path.to_string(),
    }
}

/// Reads and builds `config`: how sail treats the field at `path` in it,
/// and what it said.
fn measure(config: &Value, path: &str) -> (Measured, String) {
    let text = config.to_string();
    // A sample that is a zero value is set all the same: sail takes it as
    // unset, so it would measure nothing.
    let message = match super::read(&text, false) {
        Err(e) => format!("{:#}", e),
        Ok(config) if !config.warnings.is_empty() => {
            return (Measured::Ignored, config.warnings.join("; "));
        }
        Ok(config) => match crate::check_config(&config, &Default::default()) {
            Ok(()) => return (Measured::Supported, String::new()),
            Err(e) => format!("{:#}", e),
        },
    };
    // The field, or an object it is in.
    let unknown = steps(path).iter().any(|step| match step {
        Step::Key(key) => message.contains(&format!("unknown field `{}`", key)),
        Step::Entry(_) => false,
    });
    let tier = if unknown {
        Measured::Unknown
    } else if UNSUPPORTED.iter().any(|m| message.contains(m)) {
        Measured::Unsupported
    } else {
        // Refused for the value alone.
        Measured::Supported
    };
    (tier, message)
}

/// A field no other field would do for: sail takes an unknown field next
/// to it as a mistake, so what it says of this one is to be believed.
const PROBE: &str = "sail_registry_probe";

/// The object a field is in, and the field; the list or union entry for a
/// union's own tag.
fn parent(path: &str) -> (&str, &str) {
    match path.rsplit_once('.') {
        Some((parent, name)) => (parent, name),
        None => ("", path),
    }
}

/// The entries of these, by type, are what sail implements or not as a
/// whole.
const TYPED: &[&str] = &[
    "inbounds",
    "outbounds",
    "endpoints",
    "services",
    "certificate_providers",
    "network_namespaces",
    "dns.servers",
    "dns.rules",
    "route.rules",
    "route.rule_set",
];

/// The entry of a type `path` is in, as `inbounds[vless]`.
fn entry_of(path: &str) -> Option<&str> {
    TYPED.iter().find_map(|list| {
        let rest = path.strip_prefix(list)?.strip_prefix('[')?;
        let end = rest.find(']')?;
        (end > 0).then(|| &path[..list.len() + end + 2])
    })
}

impl Registry {
    /// How sail treats `field`: supported if it takes one of the samples.
    /// With the configuration that decided it. A sample refused for its
    /// value says nothing of the field while another sample may: one that
    /// sail takes, or warns of, goes before it.
    fn measure(&self, field: &Field) -> (Measured, String, Value) {
        let at = measured_at(&field.path);
        let mut first = None;
        let mut refused = None;
        for value in samples(field) {
            let probe = self.probe(&at, value);
            let (tier, message) = measure(&probe, &at);
            let measured = (tier, message, probe);
            // Only a protocol's refusal, or of a value `upstream::VALUES`
            // lists, may be of the value.
            let whatever = match measured.0 {
                Measured::Supported if !measured.1.is_empty() => {
                    refused.get_or_insert(measured);
                    continue;
                }
                Measured::Supported | Measured::Ignored | Measured::Unknown => true,
                Measured::Unsupported => {
                    measured.1.contains("does not implement this field")
                        || measured.1.contains("unknown protocol")
                }
            };
            if whatever {
                return measured;
            }
            first.get_or_insert(measured);
        }
        refused.or(first).expect("a sample")
    }

    /// How sail treats an unknown field in the object at `path`.
    fn control(&self, path: &str) -> Measured {
        let at = format!("{}.{}", measured_at(path), PROBE);
        measure(&self.probe(&at, json!("x")), &at).0
    }

    /// Measures every field, on as many threads as there are cores.
    fn measure_all(&self) -> Vec<Measurement> {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let chunk = self.fields.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .fields
                .chunks(chunk)
                .map(|fields| {
                    scope.spawn(move || {
                        let mut controls: HashMap<&str, Measured> = HashMap::new();
                        fields
                            .iter()
                            .map(|field| {
                                let (tier, message, probe) = self.measure(field);
                                let (parent, name) = parent(&field.path);
                                // A union's own tag has no object to be
                                // known in.
                                let tag =
                                    matches!(name, "type" | "action") && !field.r#enum.is_empty();
                                // Needed only to believe an error.
                                let control = match tag || message.is_empty() {
                                    true => Measured::Unknown,
                                    false => *controls
                                        .entry(parent)
                                        .or_insert_with(|| self.control(parent)),
                                };
                                let entry = entry_of(&field.path).map(|entry| {
                                    *controls.entry(entry).or_insert_with(|| self.control(entry))
                                });
                                Measurement {
                                    tier,
                                    message,
                                    control,
                                    entry,
                                    probe,
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("a probe thread"))
                .collect()
        })
    }
}

/// A field, as measured.
struct Measurement {
    tier: Measured,
    message: String,
    /// How an unknown field next to it fared: unless as unknown, what
    /// sail said of the field is not to be believed.
    control: Measured,
    /// How an unknown field in the entry of a type it is in fared:
    /// `Unsupported` or `Ignored` for a type sail does not implement.
    entry: Option<Measured>,
    /// The configuration measured.
    probe: Value,
}

impl Measurement {
    /// Whether sail said something of the field it may have said of any
    /// field there, and took none: an object it reads loosely.
    fn unverified(&self) -> bool {
        self.control == Measured::Supported && !self.message.is_empty()
    }
}

/// A step of a registry path as a pattern of `upstream` matches it: a
/// field, maybe of an object of a type, or a list's entry.
struct Token {
    key: String,
    label: Option<String>,
}

impl Registry {
    fn tokens(&self, path: &str) -> Vec<Token> {
        let mut out: Vec<Token> = Vec::new();
        let mut prefix = String::new();
        for step in steps(path) {
            match step {
                Step::Key(key) => {
                    if !prefix.is_empty() {
                        prefix.push('.');
                    }
                    prefix.push_str(&key);
                    out.push(Token { key, label: None });
                }
                Step::Entry(sel) => {
                    let list = self
                        .kinds
                        .get(&prefix)
                        .is_some_and(|k| k.contains("array") || k.starts_with("listable"));
                    prefix.push_str(&match &sel {
                        None => "[]".to_string(),
                        Some((k, v)) if k == "type" => format!("[{}]", v),
                        Some((k, v)) => format!("[{}={}]", k, v),
                    });
                    let label = sel.map(|(_, v)| v);
                    match (list, out.last_mut()) {
                        (false, Some(last)) => last.label = label,
                        _ => out.push(Token {
                            key: "*".to_string(),
                            label,
                        }),
                    }
                }
            }
        }
        out
    }
}

/// Whether `pattern` names the field `path` or an object it is in, for
/// the types `types` (any, if none).
fn names(pattern: &str, types: &[&str], path: &[Token]) -> bool {
    let segments: Vec<&str> = pattern.split('.').collect();
    if segments.len() > path.len() {
        return false;
    }
    let mut first = true;
    for (segment, token) in segments.iter().zip(path) {
        let label = token.label.as_deref();
        if *segment == "*" {
            if first {
                if !types.is_empty() && !label.is_some_and(|l| types.contains(&l)) {
                    return false;
                }
                let implemented = upstream::IMPLEMENTED_FOR
                    .iter()
                    .any(|(p, types)| *p == pattern && label.is_some_and(|l| types.contains(&l)));
                if implemented {
                    return false;
                }
            }
            first = false;
            continue;
        }
        let (key, kind) = match segment.strip_suffix(']').and_then(|s| s.split_once('[')) {
            Some((key, kind)) => (key, Some(kind)),
            None => (*segment, None),
        };
        if key != token.key || kind.is_some_and(|k| Some(k) != label) {
            return false;
        }
    }
    true
}

/// Why sail does not implement the field at `path`, as `upstream` says,
/// or else as its error does.
fn why(registry: &Registry, path: &str, measurement: &Measurement) -> String {
    let path = registry.tokens(path);
    // Of the tier measured: a field an object of the other tier holds has
    // a group of its own.
    let tier = match measurement.tier {
        Measured::Ignored => upstream::Tier::Ignored,
        _ => upstream::Tier::Unsupported,
    };
    let found = upstream::GROUPS
        .iter()
        .flat_map(|g| g.paths.iter().map(move |p| (g, *p)))
        .filter(|(g, p)| g.tier == tier && names(p, g.types, &path))
        .min_by_key(|(_, p)| p.split('.').count());
    if let Some((group, _)) = found {
        return group.why.to_string();
    }
    if path.first().is_some_and(|t| t.key == "services") {
        let kind = path.get(1).and_then(|t| t.label.as_deref());
        return upstream::IGNORED_SERVICES
            .iter()
            .find(|(k, _)| Some(*k) == kind)
            .map_or(upstream::OTHER_SERVICES, |(_, why)| why)
            .to_string();
    }
    for (pattern, values) in upstream::VALUES {
        let (list, _) = pattern.rsplit_once(".*.").expect("a list's field");
        let at: Vec<&str> = list.split('.').collect();
        let label = path.get(at.len()).and_then(|t| t.label.as_deref());
        if path.iter().zip(&at).all(|(t, a)| t.key == *a)
            && label.is_some_and(|l| values.contains(&l))
        {
            return upstream::VALUES_WHY.to_string();
        }
    }
    let message = &measurement.message;
    if upstream::NO_EFFECT
        .iter()
        .any(|(_, _, says)| message.contains(says))
    {
        return upstream::NO_EFFECT_WHY.to_string();
    }
    if message.contains("unknown protocol") {
        return "A protocol sail does not implement".to_string();
    }
    // The protocol's own words, without the entry and field they are of.
    let mut message = message.as_str();
    while let Some((head, rest)) = message.split_once(": ") {
        if head.contains(' ') && !head.starts_with('[') {
            break;
        }
        message = rest;
    }
    if message.starts_with("sail does not implement this field") {
        return "The protocol's own check: not implemented yet".to_string();
    }
    match message.strip_prefix("sail ") {
        Some(_) => message.to_string(),
        None => {
            let mut chars = message.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        }
    }
}

/// What the registry writes.
struct Output {
    tiers: String,
    tables: [(PathBuf, String); 2],
}

/// Where the files the test writes are, from the crate.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

#[test]
fn registry() {
    let start = std::time::Instant::now();
    let registry = Registry::new();
    let measured = registry.measure_all();
    // The configurations of the fields sail warns on, for sing-box to
    // check: `SAIL_REGISTRY_DUMP=<dir>` writes each, and `index.tsv`.
    if let Some(dir) = std::env::var_os("SAIL_REGISTRY_DUMP") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        let mut index = String::new();
        for (i, (field, m)) in registry.fields.iter().zip(&measured).enumerate() {
            if m.tier == Measured::Ignored {
                let name = format!("{}.json", i);
                std::fs::write(dir.join(&name), m.probe.to_string()).expect("written");
                index.push_str(&format!("{}\t{}\n", name, field.path));
            }
        }
        std::fs::write(dir.join("index.tsv"), index).expect("written");
    }
    let _ = std::fs::remove_file(&registry.local_rule_set);
    // What sail said of each field, for a look at why it is measured so.
    if std::env::var_os("SAIL_REGISTRY_DEBUG").is_some() {
        for (field, m) in registry.fields.iter().zip(&measured) {
            println!(
                "{:?}\t{}\t{}",
                m.tier,
                field.path,
                m.message.replace('\n', " ")
            );
        }
    }
    let mut problems = Vec::new();
    for (field, m) in registry.fields.iter().zip(&measured) {
        if m.tier == Measured::Unknown {
            problems.push(format!(
                "{}: unknown to sail, and not in upstream.rs: {}",
                field.path, m.message
            ));
        } else if m.unverified() {
            problems.push(format!(
                "{}: an unknown field there is no error, and this one is: {}",
                field.path, m.message
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    let notes: Vec<String> = registry
        .fields
        .iter()
        .zip(&measured)
        .map(|(field, m)| match m.tier {
            Measured::Supported => String::new(),
            _ => why(&registry, &field.path, m),
        })
        .collect();
    let extensions = registry.extensions();
    let output = render(&registry, &measured, &notes, &extensions);
    let update = std::env::var_os("SAIL_REGISTRY_UPDATE").is_some_and(|v| v == "1");
    let tiers = root().join("src/config/singbox/fields.tiers.json");
    let mut stale = Vec::new();
    for (path, content) in std::iter::once((tiers, output.tiers)).chain(output.tables) {
        if update {
            std::fs::create_dir_all(path.parent().expect("a directory")).expect("a directory");
            std::fs::write(&path, content).expect("written");
        } else if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
            stale.push(path.display().to_string());
        }
    }
    assert!(
        stale.is_empty(),
        "not what sail does now: {}; SAIL_REGISTRY_UPDATE=1 cargo test -p sail registry rewrites them",
        stale.join(", ")
    );
    println!(
        "{} fields measured in {:?}",
        measured.len(),
        start.elapsed()
    );
}

/// What sail accepts that sing-box does not, as the path of a field (or of
/// an entry of a type) in the registry's form, a value it takes, and what
/// it is. The test checks sail takes each, and that sing-box has none.
const EXTENSIONS: &[(&str, &str, &str)] = &[
    ("api", "{}", "The control API"),
    (
        "route.block_quic",
        r#"["direct"]"#,
        "The outbounds QUIC is refused to: a UDP connection sniffed as QUIC that the rules send to one is rejected, for the app to go on over TCP (Surge's block-quic)",
    ),
    (
        "clash_api",
        "{}",
        "The Clash API at the top level, as well as under `experimental`",
    ),
    (
        "outbound_providers",
        "[]",
        "Outbounds given together, downloaded or in place, for groups to take (Mihomo's proxy-providers)",
    ),
    (
        "user_limits",
        "{}",
        "What each user, by name, may do across its inbounds: `max_connections`, `max_tcp_connections` (TCP alone; both apply when both are set), `quota_bytes` (up and down together; needs `cache_file`), `expire_at`, and `up_mbps`, `down_mbps` and `total_mbps` (up and down together)",
    ),
    ("log.format", r#""compact""#, "`compact` writes the message alone"),
    (
        "log.redact",
        r#"["destination", "source", "process"]"#,
        "What lines at INFO, WARN and ERROR leave out: `destination` (the host or address a connection goes to; the port is kept), `source` (the client's address, and the LAN devices learned of) and `process`; DEBUG and TRACE lines are not redacted",
    ),
    (
        "dns.client_strategy",
        r#""ipv4_only""#,
        "The address families of the answers to clients' queries",
    ),
    (
        "dns.servers[race].servers",
        r#"["local", "other"]"#,
        "A server that asks its members at once and takes the first good answer",
    ),
    (
        "dns.servers[sequential].servers",
        r#"["local", "other"]"#,
        "A server that asks its members one after another, the next only when one does not answer, within a budget",
    ),
    (
        "dns.servers[sequential].attempt_timeout",
        r#""3s""#,
        "How long each member of a sequential server has to answer",
    ),
    (
        "dns.servers[sequential].budget",
        r#""8s""#,
        "How long a whole query to a sequential server may take, under dns.timeout",
    ),
    (
        "dns.servers[sequential].prefer_for",
        r#""10m""#,
        "How long a member that answered in place of the first is asked first",
    ),
    (
        "dns.servers[udp|tcp|tls|quic|https|h3].respect_rules",
        "true",
        "Queries go through the outbound the routing rules pick (Mihomo's respect-rules)",
    ),
    (
        "dns.servers[udp|tcp|tls|quic|https|h3].client_subnet",
        r#""1.2.3.0/24""#,
        "The EDNS Client Subnet its queries carry (Mihomo's ecs)",
    ),
    (
        "dns.servers[https].prefer_h3",
        "true",
        "Queries go over HTTP/3 beside HTTP/2, and over HTTP/3 alone once it answers (Mihomo's prefer-h3)",
    ),
    (
        "dns.servers[tls|quic|https|h3].tls.certificate_sha256",
        r#"["abababababababababababababababababababababababababababababababab"]"#,
        "As an outbound's `tls.certificate_sha256`",
    ),
    ("dns.rules[].geosite", r#"["cn"]"#, "Domains of a geosite category"),
    (
        "dns.rules[].external",
        r#"["site:geosite.dat:cn"]"#,
        "Domains or addresses from a geosite or mmdb file",
    ),
    (
        "dns.rules[].process_name_regex",
        r#"["^a"]"#,
        "Process names by regular expression (Mihomo's PROCESS-NAME-REGEX)",
    ),
    (
        "dns.rules[].wifi_ssid_regex",
        r#"["^a"]"#,
        "Wi-Fi names by regular expression (Surge's SSID)",
    ),
    (
        "dns.rules[].wifi_bssid_regex",
        r#"["^a"]"#,
        "Wi-Fi access points by regular expression (Surge's BSSID)",
    ),
    (
        "dns.rules[].network_gateway",
        r#"["192.168.1.1"]"#,
        "The default route's gateway (Surge's ROUTER)",
    ),
    (
        "dns.rules[].network_mcc_mnc",
        r#"["46000"]"#,
        "The cellular carrier (Surge's MCCMNC)",
    ),
    (
        "dns.rules[].ip_match_all",
        "true",
        "The response's address conditions hold for every address, not any",
    ),
    ("route.rules[].geoip", r#"["cn"]"#, "Addresses of a GeoIP country"),
    ("route.rules[].geosite", r#"["cn"]"#, "Domains of a geosite category"),
    (
        "route.rules[].external",
        r#"["site:geosite.dat:cn"]"#,
        "Domains or addresses from a geosite or mmdb file",
    ),
    (
        "route.rules[].http_user_agent",
        r#"["curl*"]"#,
        "A plain HTTP request's User-Agent (Surge's USER-AGENT)",
    ),
    (
        "route.rules[].url_regex",
        r#"["^http://a/"]"#,
        "A plain HTTP request's URL by regular expression (Surge's URL-REGEX)",
    ),
    (
        "route.rules[].ip_asn",
        "[13335]",
        "The destination's autonomous system (Surge's IP-ASN)",
    ),
    (
        "route.rules[].process_name_regex",
        r#"["^a"]"#,
        "Process names by regular expression (Mihomo's PROCESS-NAME-REGEX)",
    ),
    (
        "route.rules[].wifi_ssid_regex",
        r#"["^a"]"#,
        "Wi-Fi names by regular expression (Surge's SSID)",
    ),
    (
        "route.rules[].wifi_bssid_regex",
        r#"["^a"]"#,
        "Wi-Fi access points by regular expression (Surge's BSSID)",
    ),
    (
        "route.rules[].network_gateway",
        r#"["192.168.1.1"]"#,
        "The default route's gateway (Surge's ROUTER)",
    ),
    (
        "route.rules[].network_mcc_mnc",
        r#"["46000"]"#,
        "The cellular carrier (Surge's MCCMNC)",
    ),
    (
        "route.rules[].no_resolve",
        "true",
        "Address conditions do not resolve a domain (Surge's and Clash's no-resolve)",
    ),
    (
        "route.rules[action=route].override_destination",
        r#""proxy""#,
        "Dials a proxy by the domain known for the address (sniffed, else reverse-mapped); `\"proxy_and_direct\"` a direct dial too. The rules still match the address",
    ),
    (
        "route.rules[action=route-options].override_destination",
        r#""proxy_and_direct""#,
        "As a route rule's",
    ),
    (
        "route.rules[action=sniff].override_destination",
        "true",
        "As a route rule's (sing-box's own is deprecated, refused); `\"at_sniff\"` makes the sniffed domain the destination for the rules after, as Mihomo's sniffer does (the Clash front-end's)",
    ),
    (
        "route.rules[action=sniff].skip_rule_set",
        r#"[]"#,
        "Sniffed domains a rule-set matches are not taken (Mihomo's skip-domain)",
    ),
    (
        "route.rules[action=resolve].ignore_failure",
        "true",
        "A domain that does not resolve has no addresses, and matching goes on",
    ),
    (
        "route.rules[action=resolve].on_demand",
        "true",
        "Resolves, or sniffs, only when a later rule needs it (Surge and Mihomo)",
    ),
    (
        "route.rule_set[remote].behavior",
        r#""domain""#,
        "What each line of a Clash rule-provider is",
    ),
    (
        "route.rule_set[remote].size_limit",
        "1048576",
        "The most a download of it may be, in bytes (Mihomo's size-limit); past it the download fails and the rules in use are kept",
    ),
    (
        "route.rule_set[inline].rules[].ip_asn",
        "[13335]",
        "As a routing rule's",
    ),
    (
        "route.rule_set[inline].rules[].http_user_agent",
        r#"["curl*"]"#,
        "As a routing rule's",
    ),
    (
        "route.rule_set[inline].rules[].process_name_regex",
        r#"["^a"]"#,
        "As a routing rule's",
    ),
    (
        "route.rule_set[inline].rules[].wifi_ssid_regex",
        r#"["^a"]"#,
        "As a routing rule's",
    ),
    (
        "route.rule_set[inline].rules[].no_resolve",
        "true",
        "As a routing rule's",
    ),
    (
        "outbounds[anytls|http|hysteria2|shadowtls|trojan|tuic|vless|vmess].tls.certificate_sha256",
        r#"["abababababababababababababababababababababababababababababababab"]"#,
        "In any outbound's `tls`: whole certificates pinned by SHA-256, hex (Mihomo's fingerprint) or base64 (sing-box 1.15's field, read as it is); the server's own is trusted for any name, and, beyond sing-box, a CA's in its chain is the only CA it is verified by; with `certificate_public_key_sha256` either list passing is enough, as in sing-box 1.15",
    ),
    (
        "outbounds[direct|anytls|http|hysteria2|shadowsocks|shadowtls|socks|trojan|tuic|vless|vmess].skip_default_domain_resolver",
        "true",
        "Names resolve as the DNS rules say, not by `route.default_domain_resolver`",
    ),
    (
        "outbounds[direct|anytls|http|shadowsocks|shadowtls|socks|trojan|vless|vmess].tcp_concurrent",
        "true",
        "A name's addresses are all connected to at once and the first to connect taken, rather than Happy Eyeballs (Mihomo's tcp-concurrent)",
    ),
    (
        "endpoints[wireguard].skip_default_domain_resolver",
        "true",
        "As an outbound's, for the peers' names",
    ),
    (
        "inbounds[anytls|http|hysteria2|trojan|tuic|vless|vmess].tls.client_certificate_sha256",
        r#"["q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="]"#,
        "sing-box 1.15's, read ahead: clients' certificates taken by the SHA-256 of the whole leaf (its DER), standard base64 or hex, with a verifying `client_authentication`; looked at before `client_certificate_public_key_sha256`, either list passing",
    ),
    (
        "inbounds[http|mixed].realm",
        r#""Office""#,
        "The realm a 407 names, which clients show when asking for credentials; `sail` when unset (sing-box sends `sing-box`)",
    ),
    (
        "inbounds[http|socks|mixed].skip_auth_prefixes",
        r#"["127.0.0.0/8", "::1/128"]"#,
        "The clients that go in without credentials, by the IP prefixes they connect from (Mihomo's skip-auth-prefixes)",
    ),
    (
        "inbounds[tun].multi_queue",
        "true",
        "sing-box 1.15's, read ahead: Linux opens the device with `IFF_MULTI_QUEUE`, a queue and a netstack shard to each CPU, eight at most; one queue, the default, measured faster in every case tried; elsewhere, and on a device the host opens, ignored with a warning",
    ),
    (
        "inbounds[shadowtls].handshake.skip_default_domain_resolver",
        "true",
        "As an outbound's, for the handshake server's name",
    ),
    (
        "inbounds[http|trojan|vless|vmess].tls.reality.handshake.skip_default_domain_resolver",
        "true",
        "As an outbound's, for the REALITY handshake server's name",
    ),
    (
        "inbounds[http|trojan|vless|vmess].tls.reality.server_names",
        r#"["www.example.org"]"#,
        "More names REALITY clients may ask for, beside `tls.server_name`, which may then be left out; none may be empty (Xray's serverNames, Mihomo's server-names)",
    ),
    (
        "inbounds[anytls|http|hysteria2|trojan|tuic|vless|vmess].tls.self_signed",
        "true",
        "With no certificate or key, a self-signed one made at start for `tls.server_name` (or `sail.invalid`), kept across reloads that leave the inbound in place, as Mihomo's Hysteria2 and TUIC listeners make one; clients need `insecure` or a pin, which changes with each new certificate; an error with a certificate, a key or REALITY",
    ),
    (
        "outbounds[anytls|http|hysteria2|shadowtls|trojan|tuic|vless|vmess].tls.ech.disable_dns_lookup",
        "true",
        "The ECHConfigList is never looked up in DNS",
    ),
    (
        "outbounds[http].version",
        "1",
        "sing-box 1.15's, read ahead: the HTTP version, 1, 2 or 3; unset, 1, as sing-box 1.14 speaks, until sail follows 1.15 stable. 2 is HTTP/2 over TLS, its tunnels CONNECTs on pooled connections, falling back to HTTP/1.1 where the server picks no `h2`; without TLS or over REALITY HTTP/1.1, warned of. 3 is HTTP/2, warned of",
    ),
    (
        "outbounds[http].disable_version_fallback",
        "false",
        "sing-box 1.15's, read ahead: HTTP/2 alone, never HTTP/1.1 in its place: a server that picks no `h2` is an error, as is HTTP/2 without TLS",
    ),
    (
        "outbounds[http].idle_timeout",
        r#""30s""#,
        "sing-box 1.15's, read ahead, with HTTP/2: how long a ping may go unanswered (15s when unset)",
    ),
    (
        "outbounds[http].keep_alive_period",
        r#""20s""#,
        "sing-box 1.15's, read ahead, with HTTP/2: a ping after this long with nothing received (none when unset)",
    ),
    (
        "outbounds[http].stream_receive_window",
        r#""8MB""#,
        "sing-box 1.15's, read ahead, with HTTP/2: a tunnel's receive window (unset, 16 MiB on desktops and servers, 4 MiB on phones, 2 MiB on routers)",
    ),
    (
        "outbounds[http].connection_receive_window",
        r#""32MB""#,
        "sing-box 1.15's, read ahead, with HTTP/2: a connection's receive window (unset, four tunnels' windows)",
    ),
    (
        "outbounds[http].max_concurrent_streams",
        "64",
        "sing-box 1.15's, read ahead, with HTTP/2: the most tunnels one connection carries (128 when unset)",
    ),
    (
        "inbounds[http].version",
        "[1, 2]",
        "sing-box 1.15's, read ahead: the HTTP versions served, 1 and 2 when unset; HTTP/2 by its preface, over TLS or not. 3 is not served, warned of",
    ),
    (
        "inbounds[http].idle_timeout",
        r#""30s""#,
        "sing-box 1.15's, read ahead, with HTTP/2: how long a ping may go unanswered, and a connection with no tunnel is kept",
    ),
    (
        "inbounds[http].keep_alive_period",
        r#""20s""#,
        "sing-box 1.15's, read ahead, with HTTP/2: a ping after this long with nothing received",
    ),
    (
        "inbounds[http].stream_receive_window",
        r#""8MB""#,
        "sing-box 1.15's, read ahead, with HTTP/2: a tunnel's receive window (unset, 16 MiB on desktops and servers, 4 MiB on phones, 2 MiB on routers)",
    ),
    (
        "inbounds[http].connection_receive_window",
        r#""32MB""#,
        "sing-box 1.15's, read ahead, with HTTP/2: a connection's receive window (unset, four tunnels' windows)",
    ),
    (
        "inbounds[http].max_concurrent_streams",
        "64",
        "sing-box 1.15's, read ahead, with HTTP/2: the most tunnels a client may have open on one connection (128 when unset)",
    ),
    (
        "outbounds[shadowsocks].prefix",
        r#""%16%03%01""#,
        "Bytes sent before the first payload, percent-encoded (Outline's prefix); not with the 2022 methods",
    ),
    (
        "outbounds[shadowsocks|trojan|vless|vmess].multiplex.max_accepts",
        "8",
        "With `protocol: amux` (sail's own, to be removed): the streams a session carries in all",
    ),
    (
        "outbounds[shadowsocks|trojan|vless|vmess].multiplex.concurrency",
        "2",
        "With `protocol: amux`: the streams a session carries at once",
    ),
    (
        "outbounds[shadowsocks|trojan|vless|vmess].multiplex.max_recv_bytes",
        "1048576",
        "With `protocol: amux`: the bytes a session receives before it takes no more streams; 0, no limit",
    ),
    (
        "outbounds[shadowsocks|trojan|vless|vmess].multiplex.max_lifetime",
        "600",
        "With `protocol: amux`: the seconds a session takes new streams for; 0, no limit",
    ),
    (
        "inbounds[shadowsocks|trojan|vless|vmess].multiplex.protocol",
        r#""amux""#,
        "`amux`, sail's own multiplex (to be removed); unset, sing-mux",
    ),
    (
        "inbounds[anytls|vless].fallback",
        r#"{ "server": "127.0.0.1", "server_port": 8080 }"#,
        "As the trojan inbound's: where a connection that fails to authenticate is relayed",
    ),
    (
        "inbounds[anytls|vless].fallback_for_alpn",
        r#"{ "h2": { "server": "127.0.0.1", "server_port": 8080 } }"#,
        "As the trojan inbound's: the fallback by the ALPN the client asked for",
    ),
    (
        "inbounds[trojan|vless|vmess].transport[ws].forwarded_header",
        r#""X-Forwarded-For""#,
        "The header a trusted reverse proxy in front puts the client's address in; unset, none is believed",
    ),
    (
        "outbounds[selector|urltest].providers",
        r#""p""#,
        "The outbound providers whose outbounds join the group's own (Mihomo's use)",
    ),
    (
        "outbounds[selector|urltest].filter",
        r#""^a""#,
        "Of the providers' outbounds, only those whose names match a regular expression (Mihomo's filter)",
    ),
    (
        "outbounds[selector|urltest].exclude_filter",
        r#""^b""#,
        "Regular expressions no member's name may match, the group's own outbounds' too (Mihomo's exclude-filter)",
    ),
    (
        "outbounds[selector|urltest].exclude_type",
        r#""Shadowsocks""#,
        "Types no member may be of, in Mihomo's names (Mihomo's exclude-type)",
    ),
    (
        "outbounds[selector|urltest].empty_fallback",
        r#""direct""#,
        "The outbound, not a group, that is the member while there is none else",
    ),
    (
        "outbounds[urltest].timeout",
        r#""3s""#,
        "How long a test may take before its member counts as failed (Mihomo's timeout)",
    ),
    (
        "outbounds[urltest].max_failed_times",
        "3",
        "How many failed connections within the timeout have the members tested again (Mihomo's max-failed-times)",
    ),
    (
        "outbounds[urltest].expected_status",
        r#""200/204""#,
        "The HTTP statuses a test must get to pass (Mihomo's expected-status)",
    ),
    (
        "outbounds[urltest].lazy",
        "false",
        "`false`: the members are tested whether the group is used or not (Mihomo's lazy)",
    ),
    (
        "outbounds[fallback].outbounds",
        r#"["direct"]"#,
        "A group: the first member that works",
    ),
    (
        "outbounds[fallback].debounce",
        r#"{ "fail_after": 2, "recover_after": 3, "min_dwell": "30s" }"#,
        "Failed rounds in a row before a member is left, passed ones before an earlier member is taken back, and the least time on a member before going back",
    ),
    (
        "outbounds[fallback].dial_timeout",
        r#""2s""#,
        "How long a connection attempt through a member may take before the group moves on, apart from the tests' `timeout`; 1s at least",
    ),
    (
        "outbounds[fallback].url",
        r#"["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"]"#,
        "Several URLs to test the members at, at once, as well as one",
    ),
    (
        "outbounds[fallback].url_policy",
        r#""all""#,
        "With several URLs, whether a member passes when `any` of them answers or only when `all` do",
    ),
    (
        "outbounds[load-balance].outbounds",
        r#"["direct"]"#,
        "A group spreading connections over its members",
    ),
    (
        "outbounds[load-balance].hash_key",
        r#""user""#,
        "`user`: consistent-hashing and sticky-sessions key on the user the inbound authenticated, not the destination (and source), so a user's connections go to one member wherever they go; a connection of no user is keyed as without it; not with round-robin (Mihomo's hash-key: in-user)",
    ),
    (
        "outbounds[load-balance].timeout",
        r#""3s""#,
        "How long a test may take before its member counts as failed (Mihomo's timeout)",
    ),
    (
        "outbounds[load-balance].max_failed_times",
        "3",
        "How many failed connections within the timeout have the members tested again (Mihomo's max-failed-times)",
    ),
    (
        "outbounds[load-balance].expected_status",
        r#""200/204""#,
        "The HTTP statuses a test must get to pass (Mihomo's expected-status)",
    ),
    (
        "outbounds[urltest|fallback|load-balance|smart].unified_delay",
        "true",
        "A member's latency is that of a second request on the connection the first opened, without the connect and handshakes (Mihomo's unified-delay)",
    ),
    (
        "outbounds[selector|urltest|fallback|load-balance|smart].disable_udp",
        "true",
        "The group carries TCP alone, whatever member it picks (Mihomo's disable-udp)",
    ),
    (
        "outbounds[smart].outbounds",
        r#"["direct"]"#,
        "A group scoring its members by the connections through them",
    ),
    (
        "outbounds[network].default",
        r#""direct""#,
        "A group picking its member by the network the host is on",
    ),
    (
        "outbounds[tryall].outbounds",
        r#"["direct"]"#,
        "A group trying its members at once",
    ),
];

impl Registry {
    /// The sail extensions, each checked for every type it names: not
    /// sing-box's, and taken as it is, its sample no error.
    fn extensions(&self) -> Vec<(&'static str, &'static str)> {
        let mut problems = Vec::new();
        for (pattern, value, _) in EXTENSIONS {
            let value: Value = serde_json::from_str(value).expect("a sample");
            for path in expand(pattern) {
                if self.kinds.contains_key(&path) {
                    problems.push(format!("{}: sing-box has it; not an extension", path));
                    continue;
                }
                let mut config = prepared(self.probe(&path, value.clone()), &self.pki);
                with_context(&mut config, &path);
                let (tier, message) = measure(&config, &path);
                // A rule on a database sail reads at start: no database here.
                let read = message.is_empty() || message.contains("sail assets --fetch");
                if tier != Measured::Supported || !read {
                    problems.push(format!("{}: {:?}: {}", path, tier, message));
                }
                let (parent, _) = parent(&path);
                if self.control(parent) != Measured::Unknown {
                    problems.push(format!("{}: an unknown field there is no error", path));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        EXTENSIONS.iter().map(|(p, _, what)| (*p, *what)).collect()
    }
}

/// The words of a support table.
struct Words {
    file: &'static str,
    title: &'static str,
    intro: &'static str,
    summary: &'static str,
    area: &'static str,
    total: &'static str,
    all: &'static str,
    tiers: [&'static str; 3],
    types: &'static str,
    kind: &'static str,
    field: &'static str,
    fields: &'static str,
    tier: &'static str,
    note: &'static str,
    inside: &'static str,
    feature: &'static str,
    deprecated: &'static str,
    extensions: &'static str,
    extensions_intro: &'static str,
    what: &'static str,
}

const EN: Words = Words {
    file: "../docs/compat/sing-box.md",
    title: "# sing-box compatibility",
    intro: "sail reads sing-box configurations as they are. Below is every field sing-box {v} accepts \
(`sail/src/config/singbox/fields.json`, extracted from its source by `tools/singbox-fields`), \
with how sail treats it, measured by reading and building a configuration that sets it:

- **Supported**: read and acted on; a value sail cannot take is still an error.
- **Warned**: dropped with a warning: ignoring it changes no routing or security.
- **Error**: the configuration is refused: ignoring it would.

Notes are from `sail/src/config/singbox/upstream.rs`, or else the error sail gives.

A deliberate difference: a remote rule-set's or outbound provider's download is not redirected \
from https to http, nor to another scheme, which sing-box's client follows: what the request \
carries, a subscription's token, would go in the clear.

An HTTP client downloads over HTTP/1.1 whatever its `version`, as sing-box's does from a server \
that speaks no other; `version` and `engine` are checked as sing-box checks them, and \
`disable_version_fallback` with HTTP/2 or 3, and the `apple` engine, are warned of. A download \
is the same download over either.

An HTTP proxy speaks HTTP/2 over TLS as sing-box 1.15 does with `version` 2 (unset, it speaks \
HTTP/1.1, as sing-box 1.14, until sail follows 1.15 stable): its tunnels are CONNECTs on the connections an outbound keeps, \
falling back to HTTP/1.1 where the server picks no `h2` in ALPN until the network changes, and \
an inbound tells HTTP/2 by its preface, over TLS or not. sail speaks no HTTP/3: an outbound's \
`version` 3 is HTTP/2, and an inbound serves its other versions, each warned of. An inbound \
proxies only CONNECT over HTTP/2.

A REALITY outbound offers its fingerprint's ALPN whatever `tls.alpn` says, so an HTTP outbound \
over REALITY offers `h2` while it speaks HTTP/1.1. Harmless with sail and sing-box servers: \
sail's REALITY server negotiates no ALPN, and sing-box's HTTP inbound reads the request it gets.

As in sing-box, the addresses a `resolve` route action resolves the destination's domain to go \
to whatever outbound the connection takes: a proxy's server is sent the address, which the \
local DNS chose, not the domain, and so does not resolve it itself.

A `local` server that asks the system's servers itself (where the default dialer binds its \
sockets, as a TUN taking the default route has it) asks them in order, each with an even share \
of the query's time left, at most three and a second each at least; sing-box gives each server \
resolv.conf's timeout (5 s), so that with a 10 s query its third server is never asked. With no \
interface to send through, it fails at once rather than asking the system's servers of no \
network in particular, where sing-box falls back to 127.0.0.1 and ::1. On macOS, where sing-box \
leaves names to the system's resolver, sail asks the servers of the interface its dialer sends \
through, set by hand or else told by the network. The system's split DNS is followed, which \
neither sing-box's local server asking servers itself nor Mihomo's `system` does: a name under \
the domain of a resolver for some domains only (on macOS one with `SupplementalMatchDomains`, or \
a file of /etc/resolver; on Linux a systemd-resolved link's routing or search domain; on \
Windows an NRPT rule with DNS servers) is asked of that resolver's servers, through the interface the system \
asks it on (for NRPT, which names none, the one the system routes \
its server through), the longest domain first. A resolver on sail's own TUN, or whose servers are all on \
its network, is passed over; a server with a `detour` or a `bind_interface` of its own follows \
none.

The dial fields Windows cannot take are refused there. A known gap is `tcp_fast_open`: Windows \
sends Fast Open data only with the connect itself (`ConnectEx`), and sail connects before the \
first write, where Linux and macOS hold the SYN for it; sing-box's tfo-go returns a connection \
of its own that connects at the first write. `routing_mark` and `route.default_mark` are \
Linux's only (Windows has no socket mark; `bind_interface` chooses the way out), \
`protect_path` Unix's only, and `bind_address_no_port` Linux's only: Windows' \
`SO_REUSE_UNICASTPORT` is taken, but a socket bound with it still gets its port at the bind, \
and the option reads back unset, so that what it does could not be shown.

An outbound closes the carriers it keeps -- a Hysteria2 connection, a pooled connection of the \
quic or grpc transport, an HTTP proxy's HTTP/2 connection, \
a mux or amux session -- once nothing has been open on one for 60 s; the \
next connection dials anew. So does the member a group selects, which sing-box 1.14.3 and later \
keep: they close only the outbounds no rule or group selection references.",
    summary: "## Summary",
    area: "Section",
    total: "Fields",
    all: "All",
    tiers: ["Supported", "Warned", "Error"],
    types: "Types sail does not implement",
    kind: "Type",
    field: "Field",
    fields: "Fields",
    tier: "Tier",
    note: "Note",
    inside: "and the {n} fields in it",
    feature: "Where sail finds the program: itself on Linux and macOS, through the NetFilter inbound on Windows (the `{f}` feature, on by default)",
    deprecated: "deprecated",
    extensions: "## sail extensions",
    extensions_intro: "Fields and types sail accepts that sing-box does not.",
    what: "What",
};

const ZH: Words = Words {
    file: "../docs/compat/zh/sing-box.md",
    title: "# sing-box 兼容性",
    intro: "sail 原样读取 sing-box 配置。下表列出 sing-box {v} 接受的全部字段\
（`sail/src/config/singbox/fields.json`，由 `tools/singbox-fields` 从其源码提取），\
以及 sail 对每个字段的处理方式——逐一构造设置该字段的配置、读取并构建后测得：

- **支持**：读取并生效；sail 不接受的取值仍会报错。
- **警告**：忽略并给出警告：忽略它不改变路由或安全。
- **报错**：拒绝该配置：忽略它会改变路由或安全。

说明列取自 `sail/src/config/singbox/upstream.rs`，否则为 sail 给出的错误，均保留英文原文。

有意的差异：远程规则集与出站订阅的下载不跟随从 https 到 http 或到其他协议的重定向（sing-box 的客户端会跟随），否则请求携带的内容（如订阅令牌）会以明文传出。

HTTP 客户端无论 `version` 为何都通过 HTTP/1.1 下载，与 sing-box 遇到只支持 HTTP/1.1 的服务器时相同；`version` 与 `engine` 按 sing-box 的规则校验，`disable_version_fallback` 配合 HTTP/2 或 3、以及 `apple` 引擎会给出警告。两种方式下载的内容相同。

HTTP 代理在 `version` 为 2 时与 sing-box 1.15 一样在 TLS 之上使用 HTTP/2（未设置时与 sing-box 1.14 一样使用 HTTP/1.1，直到 sail 对照 1.15 正式版）：出站的每条隧道是其保持的连接上的一个 CONNECT 请求，服务器在 ALPN 中未选择 `h2` 时回退到 HTTP/1.1，直到网络变化；入站通过连接前言识别 HTTP/2，无论是否有 TLS。sail 不支持 HTTP/3：出站的 `version` 3 使用 HTTP/2，入站只服务其余版本，均给出警告。入站在 HTTP/2 上只代理 CONNECT。

REALITY 出站无论 `tls.alpn` 如何都提供其指纹的 ALPN，因此经 REALITY 的 HTTP 出站虽然使用 HTTP/1.1，仍会在 ALPN 中提供 `h2`。对 sail 与 sing-box 的服务端无害：sail 的 REALITY 服务端不协商 ALPN，sing-box 的 HTTP 入站按收到的请求本身判断。

与 sing-box 一致，`resolve` 路由动作把目标域名解析出的地址交给连接所走的任一出站：代理服务器收到的是由本地 DNS 决定的地址，而不是域名，它不会自己再解析。

在默认拨号器绑定套接字时（占用默认路由的 TUN 即如此），`local` 服务器自己询问系统的 DNS 服务器：按顺序询问，每个服务器平分查询剩余的时间，最多三个，每个至少一秒；sing-box 给每个服务器 resolv.conf 的超时（5 秒），因此在 10 秒的查询里它的第三个服务器永远不会被询问。没有可发送的接口时立即失败，而不去询问不属于任何网络的系统服务器（sing-box 此时回退到 127.0.0.1 和 ::1）。在 macOS 上 sing-box 把名字交给系统解析器，sail 则询问其拨号器所走接口的服务器：手动设置的优先，否则用网络告知的。sail 会遵循系统的分离 DNS，sing-box 自己询问服务器的 local 服务器和 Mihomo 的 `system` 都不会：名字落在只负责部分域名的解析器的域名下（macOS 上带 `SupplementalMatchDomains` 的解析器，或 /etc/resolver 下的文件；Linux 上 systemd-resolved 某条链路的路由域名或搜索域名；Windows 上带 DNS 服务器的 NRPT 规则）时，询问该解析器的服务器，并从系统询问它所用的接口发出（NRPT 不指定接口，则从系统路由到该服务器的接口发出），最长的域名优先。位于 sail 自己 TUN 上、或服务器全在其网络内的解析器会被跳过；带 `detour` 或自己设了 `bind_interface` 的服务器不遵循分离 DNS。

Windows 无法实现的拨号字段在 Windows 上报错。已知缺口是 `tcp_fast_open`：Windows 只在连接调用本身（`ConnectEx`）里随 SYN 发送 Fast Open 数据，而 sail 在首次写入之前就已连接；Linux 和 macOS 则由内核把 SYN 留到首次写入。sing-box 的 tfo-go 返回自己的连接类型，在首次写入时才连接。`routing_mark` 与 `route.default_mark` 只在 Linux 上支持（Windows 没有 socket 标记，出口由 `bind_interface` 选择），`protect_path` 只在 Unix 上支持，`bind_address_no_port` 只在 Linux 上支持：Windows 接受 `SO_REUSE_UNICASTPORT`，但设了它的 socket 仍在 bind 时分到端口，读回该选项也是未设置，无法证明它起作用。

出站保留的承载连接（Hysteria2 连接、quic 与 grpc 传输层池中的连接、HTTP 代理的 HTTP/2 连接、mux 与 amux 会话）在 60 秒内没有任何打开的流或 UDP 会话时关闭，下一个连接重新拨号。分组当前选中的成员也是如此；sing-box 1.14.3 起保留它，只关闭没有任何规则或分组选择引用的出站。",
    summary: "## 汇总",
    area: "部分",
    total: "字段数",
    all: "全部",
    tiers: ["支持", "警告", "报错"],
    types: "sail 未实现的类型",
    kind: "类型",
    field: "字段",
    fields: "字段数",
    tier: "处理",
    note: "说明",
    inside: "含其下 {n} 个字段",
    feature:
        "仅在 sail 能识别程序时：Linux 与 macOS 上自行查找，Windows 上经 NetFilter 入站（`{f}` feature，默认开启）",
    deprecated: "已弃用",
    extensions: "## sail 扩展",
    extensions_intro: "sail 接受而 sing-box 没有的字段和类型。",
    what: "用途",
};

const GENERATED: &str =
    "<!-- Generated by `SAIL_REGISTRY_UPDATE=1 cargo test -p sail registry`; do not edit. -->";

fn tier_index(tier: Measured) -> usize {
    match tier {
        Measured::Supported => 0,
        Measured::Ignored => 1,
        _ => 2,
    }
}

/// The section a field is listed under: the entry of a type it is in, or
/// the list of rules, or the top-level field.
fn section(path: &str) -> &str {
    if let Some(entry) = entry_of(path) {
        return entry;
    }
    for list in ["dns.servers", "dns.rules", "route.rules", "route.rule_set"] {
        if path.starts_with(list) {
            return list;
        }
    }
    let end = path.find(['.', '[']).unwrap_or(path.len());
    &path[..end]
}

/// The top-level field a field is in.
fn area(path: &str) -> &str {
    let end = path.find(['.', '[']).unwrap_or(path.len());
    &path[..end]
}

/// The objects and entries a field is in, nearest last.
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.char_indices()
        .filter(|(i, c)| *i > 0 && matches!(c, '.' | '['))
        .map(move |(i, _)| &path[..i])
}

fn escape(text: &str) -> String {
    text.replace('|', "\\|")
}

fn render(
    registry: &Registry,
    measured: &[Measurement],
    notes: &[String],
    extensions: &[(&str, &str)],
) -> Output {
    let fields = &registry.fields;
    let version = &registry.version;
    let index: HashMap<&str, usize> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| (f.path.as_str(), i))
        .collect();
    // A field sail does not implement stands for the fields in it, but
    // for an error in one it drops.
    let covered: Vec<Option<usize>> = fields
        .iter()
        .zip(measured)
        .map(|(f, m)| {
            ancestors(&f.path)
                .filter_map(|a| index.get(a).copied())
                .find(|&a| match measured[a].tier {
                    Measured::Supported => false,
                    Measured::Ignored => m.tier != Measured::Unsupported,
                    _ => true,
                })
        })
        .collect();
    let mut inside: HashMap<usize, usize> = HashMap::new();
    for owner in covered.iter().flatten() {
        *inside.entry(*owner).or_default() += 1;
    }
    // By tier, and those sail does not implement by why, in the order of
    // fields.json: a field that changes tier moves from one list to another.
    let mut supported = Vec::new();
    let mut others: [Vec<(&str, Vec<&str>)>; 2] = [Vec::new(), Vec::new()];
    for ((f, m), note) in fields.iter().zip(measured).zip(notes) {
        match tier_index(m.tier) {
            0 => supported.push(f.path.as_str()),
            i => {
                let list = &mut others[i - 1];
                match list.iter_mut().find(|(why, _)| why == note) {
                    Some((_, paths)) => paths.push(&f.path),
                    None => list.push((note, vec![&f.path])),
                }
            }
        }
    }
    let lines = |paths: &[&str], indent: &str| -> String {
        paths
            .iter()
            .map(|p| format!("{}{}", indent, json!(p)))
            .collect::<Vec<_>>()
            .join(",\n")
    };
    let mut tiers = format!(
        "{{\n \"sing_box\": {},\n \"supported\": [\n{}\n ]",
        json!(version),
        lines(&supported, "  ")
    );
    for (name, list) in ["ignored", "unsupported"].iter().zip(&others) {
        let groups: Vec<String> = list
            .iter()
            .map(|(why, paths)| format!("  {}: [\n{}\n  ]", json!(why), lines(paths, "   ")))
            .collect();
        tiers.push_str(&format!(
            ",\n \"{}\": {{\n{}\n }}",
            name,
            groups.join(",\n")
        ));
    }
    tiers.push_str("\n}\n");

    let table = |words: &Words| -> String {
        let mut out = format!(
            "{}\n\n{}\n\n{}\n\n{}\n\n",
            GENERATED,
            words.title,
            words.intro.replace("{v}", version),
            words.summary
        );
        // Counts by area, in the order sing-box has them.
        let mut areas: Vec<&str> = Vec::new();
        let mut counts: HashMap<&str, [usize; 3]> = HashMap::new();
        for (f, m) in fields.iter().zip(measured) {
            let a = area(&f.path);
            if !areas.contains(&a) {
                areas.push(a);
            }
            counts.entry(a).or_default()[tier_index(m.tier)] += 1;
        }
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n|---|--:|--:|--:|--:|\n",
            words.area, words.total, words.tiers[0], words.tiers[1], words.tiers[2]
        ));
        let mut all = [0; 3];
        for a in &areas {
            let c = counts[a];
            for i in 0..3 {
                all[i] += c[i];
            }
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                a,
                c.iter().sum::<usize>(),
                c[0],
                c[1],
                c[2]
            ));
        }
        out.push_str(&format!(
            "| **{}** | **{}** | **{}** | **{}** | **{}** |\n",
            words.all,
            all.iter().sum::<usize>(),
            all[0],
            all[1],
            all[2]
        ));
        for a in &areas {
            out.push_str(&format!("\n## `{}`\n", a));
            // The types sail lacks, a line each.
            let mut lacking: Vec<(&str, Measured, &str, usize)> = Vec::new();
            let mut sections: Vec<&str> = Vec::new();
            for (i, f) in fields.iter().enumerate() {
                if area(&f.path) != *a {
                    continue;
                }
                let m = &measured[i];
                match (entry_of(&f.path), m.entry) {
                    (Some(entry), Some(tier)) if tier != Measured::Unknown => {
                        match lacking.iter_mut().find(|l| l.0 == entry) {
                            Some(l) => l.3 += 1,
                            None => lacking.push((entry, tier, &notes[i], 1)),
                        }
                    }
                    _ => {
                        let s = section(&f.path);
                        if !sections.contains(&s) {
                            sections.push(s);
                        }
                    }
                }
            }
            if !lacking.is_empty() {
                out.push_str(&format!(
                    "\n### {}\n\n| {} | {} | {} | {} |\n|---|---|---|--:|\n",
                    words.types, words.kind, words.tier, words.note, words.fields
                ));
                for (entry, tier, note, n) in &lacking {
                    out.push_str(&format!(
                        "| `{}` | {} | {} | {} |\n",
                        entry,
                        words.tiers[tier_index(*tier)],
                        escape(note),
                        n
                    ));
                }
            }
            for s in sections {
                out.push_str(&format!(
                    "\n### `{}`\n\n| {} | {} | {} |\n|---|---|---|\n",
                    s, words.field, words.tier, words.note
                ));
                for (i, f) in fields.iter().enumerate() {
                    let m = &measured[i];
                    let lacking = m.entry.is_some_and(|t| t != Measured::Unknown);
                    if section(&f.path) != s || lacking || covered[i].is_some() {
                        continue;
                    }
                    let name = f.path[s.len()..].trim_start_matches('.');
                    let name = if name.is_empty() { s } else { name };
                    let mut note = escape(&notes[i]);
                    let (_, name_) = parent(&f.path);
                    if let Some((_, feature)) = FEATURES
                        .iter()
                        .find(|(n, _)| *n == name_ && f.path.contains("rules["))
                    {
                        note = words.feature.replace("{f}", feature);
                    }
                    if let Some(n) = inside.get(&i) {
                        let n = words.inside.replace("{n}", &n.to_string());
                        note = if note.is_empty() {
                            n
                        } else {
                            format!("{} ({})", note, n)
                        };
                    }
                    let deprecated = if f.deprecated {
                        format!(" ({})", words.deprecated)
                    } else {
                        String::new()
                    };
                    out.push_str(&format!(
                        "| `{}`{} | {} | {} |\n",
                        name,
                        deprecated,
                        words.tiers[tier_index(m.tier)],
                        note
                    ));
                }
            }
        }
        out.push_str(&format!(
            "\n{}\n\n{}\n\n| {} | {} |\n|---|---|\n",
            words.extensions, words.extensions_intro, words.field, words.what
        ));
        for (path, what) in extensions {
            out.push_str(&format!("| `{}` | {} |\n", path, escape(what)));
        }
        out
    };
    Output {
        tiers,
        tables: [
            (root().join(EN.file), table(&EN)),
            (root().join(ZH.file), table(&ZH)),
        ],
    }
}
