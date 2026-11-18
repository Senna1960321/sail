//! Clash's rule-providers, as Mihomo reads them: a line a domain, an IP
//! prefix or a rule without its target (`behavior`), in text, in YAML's
//! `payload` or `rules`, or in Mihomo's binary MRS. A line Mihomo would not
//! take is passed over, as Mihomo passes over it.

use anyhow::{anyhow, Result};
use tracing::debug;

use super::rule::{self, Parts};
use super::{mrs, SuccinctSet};
use crate::app::router::matcher::Condition;
use crate::config::rule_set::{ClashBehavior, HeadlessRule, RuleSetFormat};
use crate::runtime::RuntimeEnv;

/// Reads a rule-set of one of Clash's formats.
pub(crate) fn read(
    data: &[u8],
    format: RuleSetFormat,
    behavior: ClashBehavior,
    env: &RuntimeEnv,
) -> Result<Vec<Condition>> {
    let lines = match format {
        RuleSetFormat::Mrs => {
            return match mrs::read(data, behavior)? {
                mrs::Set::Domains(set) => rule::listed(
                    Parts {
                        succinct: Some(SuccinctSet::Mihomo(set)),
                        ..Default::default()
                    },
                    "rules[0]",
                    env,
                )
                .map(Vec::from_iter),
                mrs::Set::Ranges(ranges) => rule::listed(
                    Parts {
                        ip_ranges: Some(ranges),
                        ..Default::default()
                    },
                    "rules[0]",
                    env,
                )
                .map(Vec::from_iter),
            }
        }
        RuleSetFormat::ClashText => text(data)?,
        RuleSetFormat::ClashYaml => yaml(data)?,
        RuleSetFormat::Source | RuleSetFormat::Binary | RuleSetFormat::SurgeText => {
            unreachable!("sing-box's and Surge's formats are read apart")
        }
    };
    from_lines(&lines, behavior, env)
}

/// The rules of `lines`, each what `behavior` says, of `env`'s data files.
pub(crate) fn from_lines(
    lines: &[String],
    behavior: ClashBehavior,
    env: &RuntimeEnv,
) -> Result<Vec<Condition>> {
    match behavior {
        ClashBehavior::Domain => domain_set(lines.iter(), env).map(Vec::from_iter),
        ClashBehavior::Ipcidr => {
            let prefixes: Vec<String> = lines
                .iter()
                .filter(|l| {
                    let valid =
                        l.parse::<cidr::IpInet>().is_ok() || l.parse::<std::net::IpAddr>().is_ok();
                    if !valid {
                        debug!("rule-set: {:?} is no IP prefix; passed over", l);
                    }
                    valid
                })
                .cloned()
                .collect();
            let rule = HeadlessRule {
                ip_cidr: prefixes,
                ..Default::default()
            };
            rule::from_list(rule, "rules[0]", env).map(Vec::from_iter)
        }
        ClashBehavior::Classical => classical(lines, env),
    }
}

#[cfg(feature = "config-clash")]
fn classical(lines: &[String], env: &RuntimeEnv) -> Result<Vec<Condition>> {
    let mut rules = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let compiled = crate::config::clash::headless(line)
            .and_then(|rule| rule::from_source(&rule, &format!("rules[{}]", i), env));
        match compiled {
            Ok(rule) => rules.push(rule),
            Err(e) => debug!("rule-set: {:?}: {}; passed over", line, e),
        }
    }
    Ok(rules)
}

#[cfg(not(feature = "config-clash"))]
fn classical(_: &[String], _: &RuntimeEnv) -> Result<Vec<Condition>> {
    Err(anyhow!(
        "a classical Clash rule-set needs the config-clash feature, which is not compiled in"
    ))
}

/// The lines of a text rule-set: each trimmed, but the empty ones and the
/// comments (`#`, `//`).
fn text(data: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow!("not UTF-8 text"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(str::to_string)
        .collect())
}

/// The `payload`, or `rules`, of a YAML rule-set.
#[cfg(feature = "config-clash")]
fn yaml(data: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow!("not UTF-8 text"))?;
    crate::config::clash::payload(text)
}

#[cfg(not(feature = "config-clash"))]
fn yaml(_: &[u8]) -> Result<Vec<String>> {
    Err(anyhow!(
        "a YAML Clash rule-set needs the config-clash feature, which is not compiled in"
    ))
}

/// The domains of a domain rule-set, as Mihomo writes them: `+.x` is `x`
/// and every name under it, `.x` every name under it, a label `*` any one
/// label, and a plain name itself alone. None when it has no domain.
fn domain_set<'a>(
    entries: impl Iterator<Item = &'a String>,
    env: &RuntimeEnv,
) -> Result<Option<Condition>> {
    let mut rule = HeadlessRule::default();
    for entry in entries {
        let entry = entry.trim().to_ascii_lowercase();
        if entry.is_empty() || entry.ends_with('.') || entry.contains(char::is_whitespace) {
            debug!("rule-set: {:?} is no domain; passed over", entry);
            continue;
        }
        if let Some(base) = entry.strip_prefix("+.") {
            rule.domain_suffix.push(base.to_string());
        } else if entry.starts_with('.') {
            rule.domain_suffix.push(entry);
        } else if entry.split('.').any(|label| label == "*") {
            rule.domain_regex.push(wildcard(&entry));
        } else {
            rule.domain.push(entry);
        }
    }
    rule::from_list(rule, "rules[0]", env)
}

/// A domain with `*` labels as a regular expression, each `*` one label.
fn wildcard(domain: &str) -> String {
    let labels: Vec<String> = domain
        .split('.')
        .map(|label| match label {
            "*" => "[^.]+".to_string(),
            label => regex::escape(label),
        })
        .collect();
    format!("^{}$", labels.join("\\."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::router::matcher::Facts;
    use crate::session::{Session, SocksAddr};

    fn matches(rules: &[Condition], host: &str) -> bool {
        let facts = Facts::new(
            &Session {
                destination: SocksAddr::Domain(host.into(), 443),
                ..Default::default()
            },
            &[],
        );
        rules.iter().any(|r| r.matches(&facts, false))
    }

    #[test]
    fn domains_match_as_mihomo_s() {
        let lines: Vec<String> = ["+.google.com", ".apple.com", "*.tw.example", "exact.org"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rules = from_lines(&lines, ClashBehavior::Domain, &RuntimeEnv::default()).unwrap();
        for (host, want) in [
            ("google.com", true),
            ("www.google.com", true),
            ("apple.com", false),
            ("www.apple.com", true),
            ("a.tw.example", true),
            ("a.b.tw.example", false),
            ("tw.example", false),
            ("exact.org", true),
            ("www.exact.org", false),
        ] {
            assert_eq!(matches(&rules, host), want, "{}", host);
        }
    }

    /// A line's no-resolve on an address is the rule's: its addresses
    /// need no resolve.
    #[cfg(feature = "config-clash")]
    #[test]
    fn no_resolve_lines_need_no_addresses() {
        let needs = |lines: &[&str]| {
            let lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
            from_lines(&lines, ClashBehavior::Classical, &RuntimeEnv::default())
                .unwrap()
                .iter()
                .any(|r| r.needs(false).ip)
        };
        assert!(!needs(&[
            "IP-CIDR,10.0.0.0/8,no-resolve",
            "DOMAIN,a.test",
            "IP-CIDR,11.0.0.0/8,src"
        ]));
        assert!(needs(&["IP-CIDR,10.0.0.0/8"]));
    }

    #[test]
    fn text_passes_over_comments() {
        assert_eq!(
            text(b"# head\n\n+.a.example\n  // note\n b.example \n").unwrap(),
            ["+.a.example", "b.example"]
        );
    }
}
