//! The rules of a rule-set, compiled to the conditions routing rules
//! compile to: sing-box matches a headless rule as it matches the
//! conditions of a routing rule.

use std::net::IpAddr;

use anyhow::{anyhow, Result};

use super::SuccinctSet;
use crate::app::router::matcher::{
    query_type, Condition, Conditions, Context, Extras, Logical, MAX_DEPTH,
};
use crate::config::model;
use crate::config::rule_set::HeadlessRule;
use crate::runtime::RuntimeEnv;

/// What a default rule is made of, before it is compiled: the conditions
/// of a source rule, and those a binary one gives in forms of its own.
#[derive(Default)]
pub(crate) struct Parts {
    pub rule: HeadlessRule,
    pub succinct: Option<SuccinctSet>,
    pub ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub source_ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub query_types: Vec<u16>,
}

/// Compiles a rule of the source format, found at `path`; the data files
/// its conditions name (`ip_asn`'s) are `env`'s.
pub(crate) fn from_source(rule: &HeadlessRule, path: &str, env: &RuntimeEnv) -> Result<Condition> {
    compile(rule, path, 0, env)
}

fn compile(rule: &HeadlessRule, path: &str, depth: usize, env: &RuntimeEnv) -> Result<Condition> {
    if depth > MAX_DEPTH {
        return Err(anyhow!("{}: logical rules nested too deep", path));
    }
    if rule.no_resolve && !rule.on_addresses() {
        return Err(anyhow!(
            "{}.no_resolve: the rule has no condition on the destination's addresses",
            path
        ));
    }
    match rule.kind.as_deref() {
        None | Some("default") => {
            if rule.mode.is_some() || !rule.rules.is_empty() {
                return Err(anyhow!("{}: mode and rules are for a logical rule", path));
            }
            let query_types = rule
                .query_type
                .iter()
                .map(query_type)
                .collect::<Result<_>>()
                .map_err(|e| anyhow!("{}.query_type: {}", path, e))?;
            default(
                Parts {
                    rule: rule.clone(),
                    query_types,
                    ..Default::default()
                },
                path,
                env,
            )
        }
        Some("logical") => {
            let all = match rule.mode.as_deref() {
                Some("and") => true,
                Some("or") => false,
                Some(other) => return Err(anyhow!("{}.mode: unknown mode \"{}\"", path, other)),
                None => return Err(anyhow!("{}.mode: missing", path)),
            };
            if rule.rules.is_empty() {
                return Err(anyhow!("{}.rules: a logical rule needs some", path));
            }
            let rules = rule
                .rules
                .iter()
                .enumerate()
                .map(|(i, r)| compile(r, &format!("{}.rules[{}]", path, i), depth + 1, env))
                .collect::<Result<_>>()?;
            Ok(Condition::Logical(Box::new(Logical {
                all,
                rules,
                invert: rule.invert,
                no_resolve: rule.no_resolve,
                response: None,
            })))
        }
        Some(other) => Err(anyhow!("{}.type: unknown rule type \"{}\"", path, other)),
    }
}

impl Parts {
    /// Whether it names no condition at all, inverted or not.
    fn has_none(&self) -> bool {
        let meta = HeadlessRule {
            kind: self.rule.kind.clone(),
            invert: self.rule.invert,
            no_resolve: self.rule.no_resolve,
            ..Default::default()
        };
        self.rule == meta
            && self.succinct.is_none()
            && self.ip_ranges.is_none()
            && self.source_ip_ranges.is_none()
            && self.query_types.is_empty()
    }
}

/// Compiles a default rule of a sing-box rule-set, found at `path`, of
/// `env`'s data files. One with no conditions is refused, as sing-box
/// refuses it: it would match everything.
pub(crate) fn default(parts: Parts, path: &str, env: &RuntimeEnv) -> Result<Condition> {
    if parts.has_none() {
        return Err(anyhow!("{}: missing conditions", path));
    }
    Ok(Condition::Default(Box::new(conditions(parts, path, env)?)))
}

/// The rule of a list (Clash's, Surge's, an MRS), found at `path`: none
/// when the list has no entry taken, so that it matches nothing, as
/// Mihomo's empty set matches nothing.
pub(crate) fn listed(parts: Parts, path: &str, env: &RuntimeEnv) -> Result<Option<Condition>> {
    let compiled = conditions(parts, path, env)?;
    Ok((!compiled.is_unconditional()).then(|| Condition::Default(Box::new(compiled))))
}

/// `listed`, of the conditions of `rule`.
pub(crate) fn from_list(
    rule: HeadlessRule,
    path: &str,
    env: &RuntimeEnv,
) -> Result<Option<Condition>> {
    listed(
        Parts {
            rule,
            ..Default::default()
        },
        path,
        env,
    )
}

fn conditions(parts: Parts, path: &str, env: &RuntimeEnv) -> Result<Conditions> {
    let rule = &parts.rule;
    if let Some(field) = rule.unsupported() {
        return Err(anyhow!("{}.{}: sail does not match it yet", path, field));
    }
    // The conditions a headless rule shares with a routing rule.
    let conditions = model::Rule {
        network: rule.network.clone().into(),
        domain: rule.domain.clone().into(),
        domain_suffix: rule.domain_suffix.clone().into(),
        domain_keyword: rule.domain_keyword.clone().into(),
        domain_regex: rule.domain_regex.clone().into(),
        source_ip_cidr: rule.source_ip_cidr.clone().into(),
        ip_cidr: rule.ip_cidr.clone().into(),
        ip_asn: rule.ip_asn.clone().into(),
        http_user_agent: rule.http_user_agent.clone().into(),
        url_regex: rule.url_regex.clone().into(),
        source_port: rule.source_port.clone().into(),
        source_port_range: rule.source_port_range.clone().into(),
        port: rule.port.clone().into(),
        port_range: rule.port_range.clone().into(),
        process_name: rule.process_name.clone().into(),
        process_path: rule.process_path.clone().into(),
        process_path_regex: rule.process_path_regex.clone().into(),
        process_name_regex: rule.process_name_regex.clone().into(),
        package_name: rule.package_name.clone().into(),
        package_name_regex: rule.package_name_regex.clone().into(),
        wifi_ssid: rule.wifi_ssid.clone().into(),
        wifi_bssid: rule.wifi_bssid.clone().into(),
        network_type: rule.network_type.clone().into(),
        network_is_expensive: rule.network_is_expensive,
        network_is_constrained: rule.network_is_constrained,
        wifi_ssid_regex: rule.wifi_ssid_regex.clone().into(),
        wifi_bssid_regex: rule.wifi_bssid_regex.clone().into(),
        network_gateway: rule.network_gateway.clone().into(),
        network_mcc_mnc: rule.network_mcc_mnc.clone().into(),
        no_resolve: rule.no_resolve,
        invert: rule.invert,
        ..Default::default()
    };
    let extras = Extras {
        succinct: parts.succinct,
        ip_ranges: parts.ip_ranges,
        source_ip_ranges: parts.source_ip_ranges,
        query_types: parts.query_types,
    };
    let mut ctx = Context {
        env,
        rule_sets: &Default::default(),
    };
    Conditions::compile(&conditions, extras, path, &mut ctx)
}
