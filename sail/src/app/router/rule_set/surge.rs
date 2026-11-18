//! Surge's rule-sets, as Surge reads them: a `RULE-SET` file holds a rule
//! without its policy a line (`classical`), a `DOMAIN-SET` file a domain a
//! line, `.x` for `x` and every name under it (`domain`). Comments start
//! with `#`, `//` or `;`. A line Surge would not take, or sail cannot,
//! is passed over, as Surge passes over a line it does not take.
//!
//! The plain lines of a set, of domains, keywords and IP prefixes, are
//! matched as one rule, and the IP prefixes with `no-resolve` as another;
//! each of the others as a rule of its own.

use anyhow::{anyhow, Result};
use tracing::debug;

use super::rule;
use crate::app::router::matcher::Condition;
use crate::config::rule_set::{ClashBehavior, HeadlessRule};
use crate::runtime::RuntimeEnv;

/// Reads a rule-set of Surge's text, of `behavior`; `env`'s data files are
/// those its rules name.
pub(crate) fn read(
    data: &[u8],
    behavior: ClashBehavior,
    env: &RuntimeEnv,
) -> Result<Vec<Condition>> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow!("not UTF-8 text"))?;
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(['#', ';']) && !l.starts_with("//"));
    match behavior {
        ClashBehavior::Domain => {
            let mut rule = HeadlessRule::default();
            for line in lines {
                // A comment after it, with a space before.
                let mut words = line.split_whitespace();
                let name = words.next().unwrap_or_default().to_ascii_lowercase();
                let comment = words
                    .next()
                    .is_none_or(|w| w.starts_with(['#', ';']) || w.starts_with("//"));
                if !comment || name.ends_with('.') {
                    debug!("rule-set: {:?} is no domain; passed over", line);
                    continue;
                }
                match name.strip_prefix('.') {
                    Some(base) if !base.is_empty() => rule.domain_suffix.push(base.to_string()),
                    Some(_) => debug!("rule-set: {:?} is no domain; passed over", line),
                    None => rule.domain.push(name),
                }
            }
            rule::from_list(rule, "rules[0]", env).map(Vec::from_iter)
        }
        ClashBehavior::Classical => classical(lines, env),
        ClashBehavior::Ipcidr => Err(anyhow!(
            "behavior: a Surge rule-set is of domains or of rules"
        )),
    }
}

/// The rules of `lines`; a line that does not read, or whose rule sail
/// cannot compile (a regular expression over the regex crate's size
/// limit, say: a downloaded set is not trusted), is passed over, and
/// those passed over are warned of once, the first named.
#[cfg(feature = "config-surge")]
fn classical<'a>(lines: impl Iterator<Item = &'a str>, env: &RuntimeEnv) -> Result<Vec<Condition>> {
    let (rules, passed) = classical_lines(lines, env)?;
    if let Some((line, e)) = passed.first() {
        tracing::warn!(
            "rule-set: {} line(s) passed over, as Surge passes over them; the first, {:?}: {}",
            passed.len(),
            line,
            e
        );
    }
    Ok(rules)
}

/// Lines passed over, each with why.
#[cfg(feature = "config-surge")]
type Passed = Vec<(String, String)>;

/// The rules of `lines`, and each line passed over with why.
#[cfg(feature = "config-surge")]
fn classical_lines<'a>(
    lines: impl Iterator<Item = &'a str>,
    env: &RuntimeEnv,
) -> Result<(Vec<Condition>, Passed)> {
    let mut plain = HeadlessRule::default();
    // The plain IP prefixes with `no-resolve`.
    let mut unresolved = HeadlessRule {
        no_resolve: true,
        ..Default::default()
    };
    let mut rules = Vec::new();
    let mut passed = Vec::new();
    for (i, line) in lines.enumerate() {
        let rule = match crate::config::surge::headless(line) {
            Ok(rule) => rule,
            Err(e) => {
                debug!("rule-set: {:?}: {}; passed over", line, e);
                passed.push((line.to_string(), e.to_string()));
                continue;
            }
        };
        let into = if rule.no_resolve {
            &mut unresolved
        } else {
            &mut plain
        };
        if merge(into, &rule) {
            continue;
        }
        match rule::from_source(&rule, &format!("rules[{}]", i), env) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                debug!("rule-set: {:?}: {}; passed over", line, e);
                passed.push((line.to_string(), e.to_string()));
            }
        }
    }
    if !unresolved.ip_cidr.is_empty() {
        rules.insert(0, rule::from_source(&unresolved, "rules[0]", env)?);
    }
    if plain != HeadlessRule::default() {
        rules.insert(0, rule::from_source(&plain, "rules[0]", env)?);
    }
    Ok((rules, passed))
}

#[cfg(not(feature = "config-surge"))]
fn classical<'a>(_: impl Iterator<Item = &'a str>, _: &RuntimeEnv) -> Result<Vec<Condition>> {
    Err(anyhow!(
        "a Surge rule-set of rules needs the config-surge feature, which is not compiled in"
    ))
}

/// Adds `rule` to `plain` when it is a plain one: of one domain, suffix,
/// keyword or IP prefix alone, which match as any of them in one rule;
/// `plain` is of the rules as `no_resolve` as it is.
#[cfg(feature = "config-surge")]
fn merge(plain: &mut HeadlessRule, rule: &HeadlessRule) -> bool {
    type Field = fn(&mut HeadlessRule) -> &mut Vec<String>;
    let fields: [(&Vec<String>, Field); 4] = [
        (&rule.domain, |r| &mut r.domain),
        (&rule.domain_suffix, |r| &mut r.domain_suffix),
        (&rule.domain_keyword, |r| &mut r.domain_keyword),
        (&rule.ip_cidr, |r| &mut r.ip_cidr),
    ];
    for (values, field) in fields {
        if values.is_empty() {
            continue;
        }
        let mut only = HeadlessRule {
            no_resolve: plain.no_resolve,
            ..Default::default()
        };
        field(&mut only).clone_from(values);
        if *rule != only {
            return false;
        }
        field(plain).extend(values.iter().cloned());
        return true;
    }
    false
}

#[cfg(all(test, feature = "config-surge"))]
mod tests {
    use super::*;
    use crate::app::router::matcher::Facts;
    use crate::session::{Session, SocksAddr};

    fn matches(rules: &[Condition], destination: SocksAddr) -> bool {
        let facts = Facts::new(
            &Session {
                destination,
                ..Default::default()
            },
            &[],
        );
        rules.iter().any(|r| r.matches(&facts, false))
    }

    fn domain(name: &str) -> SocksAddr {
        SocksAddr::Domain(name.into(), 443)
    }

    #[test]
    fn a_domain_set_s_dot_is_the_name_and_those_under_it() {
        let rules = read(
            b"# comment\n.apple.com // note\nexact.org\n// note\n; note\nbad name\n.\n",
            ClashBehavior::Domain,
            &RuntimeEnv::default(),
        )
        .unwrap();
        for (host, want) in [
            ("apple.com", true),
            ("www.apple.com", true),
            ("pineapple.com", false),
            ("exact.org", true),
            ("www.exact.org", false),
        ] {
            assert_eq!(matches(&rules, domain(host)), want, "{}", host);
        }
    }

    #[cfg(feature = "regex")]
    #[test]
    fn a_pattern_too_large_or_wrong_is_its_line_alone() {
        let data = "URL-REGEX,(?:\\w{1000}){1000}\nUSER-AGENT,ok*\nURL-REGEX,(\nDOMAIN,a.example\n";
        let (rules, passed) = classical_lines(data.lines(), &RuntimeEnv::default()).unwrap();
        // The name, and the User-Agent.
        assert_eq!(rules.len(), 2);
        assert_eq!(passed.len(), 2, "{:?}", passed);
        assert!(passed[0].1.contains("size limit"), "{:?}", passed);
        assert!(matches(&rules, domain("a.example")));
        assert!(read(
            data.as_bytes(),
            ClashBehavior::Classical,
            &RuntimeEnv::default()
        )
        .is_ok());
    }

    /// A line's no-resolve on an address is the rule's: its addresses
    /// need no resolve.
    #[test]
    fn no_resolve_lines_need_no_addresses() {
        let needs = |data: &[u8]| {
            let rules = read(data, ClashBehavior::Classical, &RuntimeEnv::default()).unwrap();
            rules.iter().any(|r| r.needs(false).ip)
        };
        assert!(!needs(
            b"IP-CIDR,10.0.0.0/8,no-resolve\nIP-CIDR,11.0.0.0/8,no-resolve\nDOMAIN,a.test\n\
              DOMAIN,b.test,no-resolve\n"
        ));
        assert!(needs(
            b"IP-CIDR,10.0.0.0/8,no-resolve\nIP-CIDR,11.0.0.0/8\n"
        ));
    }

    #[test]
    fn a_rule_set_s_lines_are_surge_rules() {
        let rules = read(
            b"DOMAIN-SUFFIX,example.com // note\nDOMAIN,exact.org,extended-matching\n\
              IP-CIDR,10.0.0.0/8,no-resolve\nIP-CIDR6,2001:db8::/32\n\
              DOMAIN-WILDCARD,cdn?.example.net\nAND,((DOMAIN-KEYWORD,video),(DEST-PORT,8443))\n\
              SUBNET,TYPE:WIFI\nNOT A RULE\nGEOIP,CN\n",
            ClashBehavior::Classical,
            &RuntimeEnv::default(),
        )
        .unwrap();
        // The plain ones as one, those with no-resolve as another, the
        // wildcard, the logical one and the one on the network.
        assert_eq!(rules.len(), 5);
        for (to, want) in [
            (domain("a.example.com"), true),
            (domain("exact.org"), true),
            (
                SocksAddr::from((std::net::IpAddr::from([10, 1, 2, 3]), 1)),
                true,
            ),
            (domain("cdn1.example.net"), true),
            (domain("cdn12.example.net"), false),
            (SocksAddr::Domain("video.example".into(), 8443), true),
            (SocksAddr::Domain("video.example".into(), 443), false),
            (domain("other.org"), false),
        ] {
            assert_eq!(matches(&rules, to.clone()), want, "{}", to);
        }
    }
}
