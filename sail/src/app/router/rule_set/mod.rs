//! Rule-sets: rules kept apart from the routing and DNS rules that name
//! them, inline, in a local file or downloaded, in sing-box's source
//! (JSON) or binary (`.srs`) format.

use std::collections::HashMap;
use std::sync::Arc;

use crate::runtime::resource::HotResource;
use anyhow::{anyhow, Context, Result};

use crate::app::dispatcher::Dispatcher;
use crate::app::http::HttpClients;
use crate::app::router::matcher::{Condition, Facts, Groups, Needs};
use crate::config::rule_set::{
    self as config, ClashBehavior, RuleSetFormat, RuleSetKind, MAX_VERSION,
};
use crate::net::network::{Network, NetworkChange};
use crate::runtime::RuntimeEnv;

mod clash;
pub(crate) mod domain_set;
mod mrs;
mod reader;
pub(crate) mod remote;
pub(crate) mod rule;
pub(crate) mod srs;
pub(crate) mod succinct;
mod surge;

/// The domains of a binary rule-set, matched in their compact form:
/// sing-box's (`.srs`) or Mihomo's (`.mrs`).
pub(crate) enum SuccinctSet {
    Sing(succinct::Succinct),
    Mihomo(domain_set::DomainSet),
}

impl SuccinctSet {
    pub(crate) fn matches(&self, domain: &str) -> bool {
        match self {
            SuccinctSet::Sing(set) => set.matches(domain),
            SuccinctSet::Mihomo(set) => set.matches(domain),
        }
    }

    /// How many domains and suffixes it holds.
    pub(crate) fn len(&self) -> usize {
        match self {
            SuccinctSet::Sing(set) => set.len(),
            SuccinctSet::Mihomo(set) => set.len(),
        }
    }
}

/// A rule-set of at most this many domains, and no addresses, is narrow.
pub(crate) const NARROW_DOMAINS: usize = 2000;

/// The rules of one rule-set.
pub(crate) struct RuleSet {
    rules: Vec<Condition>,
    /// Whether it names a few sites rather than a region or a category:
    /// some domains, at most `NARROW_DOMAINS`, and no addresses. The smart
    /// group keeps the sites of a narrow rule-set on one member.
    narrow: bool,
    /// What its rules need learnt of a connection, as the rule naming it
    /// matches them: with their `ip_cidr` on the destination, and on the
    /// source.
    needs: [Needs; 2],
    /// Of the file's bytes a local one was read from: a reload that finds
    /// the file the same keeps it.
    source: Option<(u64, u64)>,
}

/// Two hashes of `data`, the second begun with a byte the first is not:
/// 128 bits together, so that a file changed is not taken for the same.
fn digest(data: &[u8]) -> (u64, u64) {
    use std::hash::Hasher;
    let mut first = std::collections::hash_map::DefaultHasher::new();
    let mut second = std::collections::hash_map::DefaultHasher::new();
    second.write_u8(0x5a);
    first.write(data);
    second.write(data);
    (first.finish(), second.finish())
}

impl RuleSet {
    pub(crate) fn new(rules: Vec<Condition>) -> Self {
        let mut domains = 0usize;
        let mut addresses = false;
        for rule in &rules {
            match rule.domain_count() {
                Some(n) => domains += n,
                None => addresses = true,
            }
        }
        let narrow = !addresses && (1..=NARROW_DOMAINS).contains(&domains);
        let needs = [false, true].map(|source| {
            rules
                .iter()
                .fold(Needs::default(), |n, r| n.or(r.needs(source)))
        });
        Self {
            rules,
            narrow,
            needs,
            source: None,
        }
    }

    /// The rules of the source format, of `env`'s data files.
    pub(crate) fn from_rules(rules: &[config::HeadlessRule], env: &RuntimeEnv) -> Result<Self> {
        let rules = rules
            .iter()
            .enumerate()
            .map(|(i, r)| rule::from_source(r, &format!("rules[{}]", i), env))
            .collect::<Result<_>>()?;
        Ok(Self::new(rules))
    }

    /// How many entries it has, as Mihomo counts a rule-set's: its
    /// domains and address ranges, or else its rules.
    pub(crate) fn size(&self) -> usize {
        let domains: usize = self.rules.iter().filter_map(|r| r.domain_count()).sum();
        match domains + self.ip_ranges().len() {
            0 => self.rules.len(),
            n => n,
        }
    }

    /// Whether it is narrow: see `narrow`.
    pub(crate) fn is_narrow(&self) -> bool {
        self.narrow
    }

    /// What its rules need learnt of a connection, their `ip_cidr` on the
    /// source when `ip_match_source`.
    pub(crate) fn needs(&self, ip_match_source: bool) -> Needs {
        self.needs[usize::from(ip_match_source)]
    }

    /// Reads a rule-set of `format` from `data`; one of Clash's formats is
    /// of `behavior`. The data files its rules name are `env`'s.
    pub(crate) fn read(
        data: &[u8],
        format: RuleSetFormat,
        behavior: Option<ClashBehavior>,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        match format {
            RuleSetFormat::Mrs | RuleSetFormat::ClashYaml | RuleSetFormat::ClashText => {
                let behavior = behavior.ok_or_else(|| anyhow!("behavior: missing"))?;
                Ok(Self::new(clash::read(data, format, behavior, env)?))
            }
            RuleSetFormat::SurgeText => {
                let behavior = behavior.ok_or_else(|| anyhow!("behavior: missing"))?;
                Ok(Self::new(surge::read(data, behavior, env)?))
            }
            RuleSetFormat::Binary => Ok(Self::new(srs::read(data, env)?)),
            RuleSetFormat::Source => {
                let source: config::SourceRuleSet = serde_json::from_slice(data)
                    .map_err(|e| anyhow!("invalid source rule-set: {}", e))?;
                if source.version == 0 || source.version > MAX_VERSION {
                    return Err(anyhow!(
                        "version {}: sail reads 1 to {}",
                        source.version,
                        MAX_VERSION
                    ));
                }
                Self::from_rules(&source.rules, env)
            }
        }
    }

    /// The destination `ip_cidr` ranges of its rules, for sets kept
    /// outside sail (auto_redirect's `route_address_set`).
    #[allow(dead_code)]
    pub(crate) fn ip_ranges(&self) -> Vec<(std::net::IpAddr, std::net::IpAddr)> {
        let mut ranges = Vec::new();
        self.rules.iter().for_each(|r| r.ip_ranges(&mut ranges));
        ranges
    }

    /// Whether any of its rules matches.
    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        self.rules.iter().any(|r| r.matches(facts, ip_match_source))
    }

    /// Whether the rule naming it matches, with its own conditions in
    /// `outer`, as sing-box has it: a rule-set of one plain rule merges its
    /// conditions with the outer ones, so that a domain of either matches;
    /// any other must match itself, and the outer conditions too.
    pub(crate) fn matches_with(&self, outer: Groups, facts: &Facts, ip_match_source: bool) -> bool {
        if let [rule] = &self.rules[..] {
            if let Some(conditions) = rule.mergeable() {
                return conditions
                    .evaluate(facts, ip_match_source)
                    .is_some_and(|groups| outer.merge(groups).done());
            }
        }
        outer.done() && self.matches(facts, ip_match_source)
    }
}

/// A rule-set, as the Clash API lists it.
pub(crate) struct Listed {
    pub tag: String,
    pub kind: RuleSetKind,
    pub format: Option<RuleSetFormat>,
    pub behavior: Option<ClashBehavior>,
    /// Its entries, see `RuleSet::size`.
    pub size: usize,
    /// When a remote one was downloaded, or last found unchanged.
    pub updated: Option<std::time::SystemTime>,
    /// When a remote one is next downloaded.
    pub next_update: Option<std::time::SystemTime>,
    /// A remote one's last failure, until a download succeeds.
    pub failure: Option<crate::control::Failure>,
}

/// A rule-set by tag, replaced whole when a download brings a new one.
pub(crate) type SharedRuleSet = HotResource<RuleSet>;

/// The rule-sets of `route.rule_set`, by tag.
#[derive(Default, Clone)]
pub(crate) struct RuleSets {
    sets: HashMap<String, SharedRuleSet>,
    remotes: Vec<Arc<remote::Remote>>,
    /// Updates wait while it is down.
    network: Network,
    /// Each rule-set's tag and configuration, in order, for the Clash API.
    configs: Vec<(String, Arc<config::RuleSet>)>,
    /// The local rule-sets, which follow their files as sing-box's do.
    #[cfg(feature = "auto-reload")]
    locals: Vec<Arc<Local>>,
}

/// A local rule-set, read again when its file changes.
#[cfg(feature = "auto-reload")]
struct Local {
    tag: String,
    config: Arc<config::RuleSet>,
    path: std::path::PathBuf,
    set: SharedRuleSet,
    env: RuntimeEnv,
    /// The file as it was just before it was read: what tells, once its
    /// watch is set up, whether it was written in between.
    read: Option<crate::runtime::watch::Stamp>,
}

#[cfg(feature = "auto-reload")]
impl Local {
    /// Whether the file may have been written since it was read.
    fn written_since_read(&self) -> bool {
        crate::runtime::watch::written_since(self.read, &self.path)
    }

    /// Puts the file's rules in place; ones that do not read leave the
    /// rules in use, as sing-box does.
    fn reload(&self) {
        let path = self.path.to_string_lossy();
        match read_file(&path, &self.config, &self.env) {
            Ok(set) => {
                self.set.publish(Arc::new(set));
                tracing::info!("rule-set [{}]: reloaded from its file", self.tag);
            }
            Err(e) => tracing::error!(
                "rule-set [{}]: reload failed, keeping the rules in use: {:#}",
                self.tag,
                e
            ),
        }
    }
}

impl RuleSets {
    /// Reads the inline and local rule-sets. A remote one starts from its
    /// cached copy, or its `initial_path`, or else empty until downloaded.
    ///
    /// At a reload, `before` has those that run. One configured as it was
    /// there is kept as it runs, not read again, when its source is the
    /// same: an inline one always, a local one when its file's bytes hash
    /// as those it was read from, a remote one with the copy it has (its
    /// ETag and update time go on). Any other is read as at a start.
    pub(crate) fn load(
        configs: &[config::RuleSet],
        clients: &HttpClients,
        env: &RuntimeEnv,
        before: Option<&RuleSets>,
    ) -> Result<Self> {
        let mut sets = HashMap::new();
        let mut remotes = Vec::new();
        #[cfg(feature = "auto-reload")]
        let mut locals = Vec::new();
        let mut listed = Vec::new();
        for (i, config) in configs.iter().enumerate() {
            let shared = Arc::new(config.clone());
            for tag in &config.tag {
                listed.push((tag.clone(), shared.clone()));
                let context = || format!("route.rule_set[{}]: [{}]", i, tag);
                // The one that runs under this tag, configured the same.
                let before = before.filter(|before| {
                    before
                        .configs
                        .iter()
                        .any(|(t, c)| t == tag && **c == *config)
                });
                let set = if config.kind == RuleSetKind::Remote {
                    let client = clients
                        .client(
                            config.http_client.as_ref(),
                            config.download_detour.as_deref(),
                        )
                        .with_context(context)?;
                    let ran = before.and_then(|b| b.remotes.iter().find(|r| r.tag == *tag));
                    let remote = Arc::new(
                        remote::Remote::load(config, tag, client, env, ran.map(|r| &**r))
                            .with_context(context)?,
                    );
                    let set = remote.set.clone();
                    remotes.push(remote);
                    set
                } else {
                    // The file as it is before it is read: a write while
                    // it is read, or after, shows against this.
                    #[cfg(feature = "auto-reload")]
                    let local = (config.kind == RuleSetKind::Local).then(|| {
                        let path =
                            std::path::PathBuf::from(env.data_path(&config::RuleSet::for_tag(
                                config.path.as_deref().unwrap_or_default(),
                                tag,
                            )));
                        let read = crate::runtime::watch::Stamp::of(&path);
                        (path, read)
                    });
                    let ran = before.and_then(|b| b.sets.get(tag));
                    let set = Self::load_one(config, tag, env, ran).with_context(context)?;
                    #[cfg(feature = "auto-reload")]
                    if let Some((path, read)) = local {
                        locals.push(Arc::new(Local {
                            tag: tag.clone(),
                            config: shared.clone(),
                            path,
                            set: set.clone(),
                            env: env.clone(),
                            read,
                        }));
                    }
                    set
                };
                sets.insert(tag.clone(), set);
            }
        }
        Ok(Self {
            sets,
            remotes,
            network: env.network.clone(),
            configs: listed,
            #[cfg(feature = "auto-reload")]
            locals,
        })
    }

    /// Downloads the remote rule-sets that have no copy yet: the rules
    /// that name them cannot match until they do.
    pub(crate) async fn fetch_missing(&self, dispatcher: &Dispatcher) -> Result<()> {
        let missing = self.remotes.iter().filter(|r| !r.is_loaded());
        let downloads = missing.map(|remote| async move {
            remote
                .update(dispatcher)
                .await
                .map_err(|e| anyhow!("rule-set [{}]: download: {:#}", remote.tag, e))
        });
        futures::future::try_join_all(downloads).await?;
        Ok(())
    }

    /// Downloads the remote rule-sets again as each falls due; stopped by
    /// aborting the task.
    pub(crate) fn spawn_updater(
        &self,
        dispatcher: std::sync::Weak<Dispatcher>,
    ) -> Option<tokio::task::AbortHandle> {
        #[cfg(feature = "auto-reload")]
        let locals = self.locals.clone();
        #[cfg(not(feature = "auto-reload"))]
        let locals: Vec<()> = Vec::new();
        if self.remotes.is_empty() && locals.is_empty() {
            return None;
        }
        let remotes = self.remotes.clone();
        let network = self.network.clone();
        let downloads = async move {
            if remotes.is_empty() {
                return;
            }
            let mut changes = network.changes();
            loop {
                until_due(&remotes, &network, &mut changes).await;
                let Some(dispatcher) = dispatcher.upgrade() else {
                    return;
                };
                let now = std::time::SystemTime::now();
                for remote in remotes.iter().filter(|r| r.due_in(now).is_zero()) {
                    // A panic reading what was downloaded is that update's
                    // failure, not the updater's: the rules in use stay.
                    let updated = crate::runtime::scope::contain(
                        "rule-set update",
                        remote.update(&dispatcher),
                    )
                    .await;
                    match updated {
                        Some(Ok(_)) => {}
                        Some(Err(e)) => tracing::warn!(
                            "rule-set [{}]: download failed, keeping the rules in use: {:#}",
                            remote.tag,
                            e
                        ),
                        None => tracing::warn!(
                            "rule-set [{}]: its update panicked, keeping the rules in use",
                            remote.tag
                        ),
                    }
                }
            }
        };
        let task = crate::runtime::scope::spawn_essential("rule-set updater", async move {
            #[cfg(feature = "auto-reload")]
            tokio::join!(downloads, follow_files(locals));
            #[cfg(not(feature = "auto-reload"))]
            {
                let _ = locals;
                downloads.await;
            }
        });
        Some(task.abort_handle())
    }

    /// An inline or local rule-set; `ran` is the one that runs, configured
    /// the same, kept when its source is the same.
    fn load_one(
        config: &config::RuleSet,
        tag: &str,
        env: &RuntimeEnv,
        ran: Option<&SharedRuleSet>,
    ) -> Result<SharedRuleSet> {
        match config.kind {
            RuleSetKind::Inline => match ran {
                Some(ran) => Ok(ran.clone()),
                None => RuleSet::from_rules(&config.rules, env).map(HotResource::new),
            },
            RuleSetKind::Local => {
                let path = env.data_path(&config::RuleSet::for_tag(
                    config.path.as_deref().unwrap_or_default(),
                    tag,
                ));
                let data = std::fs::read(&path).map_err(|e| anyhow!("{}: {}", path, e))?;
                let source = digest(&data);
                match ran.filter(|ran| ran.load().source == Some(source)) {
                    Some(ran) => {
                        tracing::debug!("rule-set [{}]: its file is unchanged, kept", tag);
                        Ok(ran.clone())
                    }
                    None => read_data(&data, source, &path, config, env).map(HotResource::new),
                }
            }
            RuleSetKind::Remote => unreachable!("remote rule-sets are loaded apart"),
        }
    }

    /// The destination address ranges of the rule-set `tag` as it is now.
    #[allow(dead_code)]
    pub(crate) fn ip_ranges(&self, tag: &str) -> Result<Vec<(std::net::IpAddr, std::net::IpAddr)>> {
        Ok(self.get(tag)?.load().ip_ranges())
    }

    /// Changes whenever the rule-set `tag` is replaced, by a download.
    #[allow(dead_code)]
    pub(crate) fn subscribe(&self, tag: &str) -> Result<tokio::sync::watch::Receiver<u64>> {
        Ok(self.get(tag)?.subscribe())
    }

    /// Each rule-set, in order, as the Clash API lists it.
    pub(crate) fn list(&self) -> Vec<Listed> {
        let now = std::time::SystemTime::now();
        self.configs
            .iter()
            .map(|(tag, config)| {
                let remote = self.remotes.iter().find(|r| r.tag == *tag);
                Listed {
                    tag: tag.clone(),
                    kind: config.kind,
                    format: config.format(),
                    behavior: config.behavior,
                    size: self.sets.get(tag).map_or(0, |set| set.load().size()),
                    updated: remote.and_then(|r| r.updated()),
                    next_update: remote.map(|r| now + r.due_in(now)),
                    failure: remote.and_then(|r| r.failure()),
                }
            })
            .collect()
    }

    /// Downloads the remote rule-set `tag` again; one of another kind is
    /// as it is. False when there is none so tagged.
    pub(crate) async fn update(&self, tag: &str, dispatcher: &Dispatcher) -> Result<bool> {
        if let Some(remote) = self.remotes.iter().find(|r| r.tag == tag) {
            remote.update(dispatcher).await?;
        }
        Ok(self.sets.contains_key(tag))
    }

    pub(crate) fn get(&self, tag: &str) -> Result<SharedRuleSet> {
        self.sets
            .get(tag)
            .cloned()
            .ok_or_else(|| anyhow!("rule-set [{}] does not exist", tag))
    }
}

/// Waits until one of `remotes` falls due while the network is up. While
/// it is down, updates wait rather than fail; the change that ends that
/// sends those due by then at once.
async fn until_due(
    remotes: &[Arc<remote::Remote>],
    network: &Network,
    changes: &mut tokio::sync::watch::Receiver<Option<Arc<NetworkChange>>>,
) {
    loop {
        changes.borrow_and_update();
        if network.is_down() {
            tracing::debug!("rule-set: the network is down, updates wait for it");
            // The instance's network outlives the task: this never fails.
            let _ = changes.changed().await;
            continue;
        }
        let now = std::time::SystemTime::now();
        let next = remotes
            .iter()
            .map(|r| r.due_in(now))
            .min()
            .unwrap_or_default();
        // At least a second apart, whatever the clock does.
        tokio::time::sleep(next.max(std::time::Duration::from_secs(1))).await;
        if !network.is_down() {
            return;
        }
    }
}

/// Reads each local rule-set again when its file changes, a quarter of a
/// second after the last change, so that one write is one read.
///
/// The files were read when the rule-sets were built, at the start or at
/// a reload, and are watched only from here, which may be seconds later
/// at a start: a file written in between is read again now, once its
/// watch is set up, or the edit would never apply.
#[cfg(feature = "auto-reload")]
async fn follow_files(locals: Vec<Arc<Local>>) {
    use std::collections::BTreeSet;
    use std::time::Duration;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<usize>(locals.len().max(1) * 4);
    let mut watchers = Vec::new();
    for (i, local) in locals.iter().enumerate() {
        let tx = tx.clone();
        match crate::runtime::watch::FileWatcher::on_change(vec![local.path.clone()], move || {
            let _ = tx.try_send(i);
        }) {
            Ok(watcher) => watchers.push(watcher),
            Err(e) => tracing::error!("rule-set [{}]: cannot watch its file: {}", local.tag, e),
        }
    }
    drop(tx);
    for local in &locals {
        if local.written_since_read() {
            tracing::debug!(
                "rule-set [{}]: its file was written since it was read",
                local.tag
            );
            local.reload();
        }
    }
    while let Some(first) = rx.recv().await {
        let mut changed = BTreeSet::from([first]);
        loop {
            match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
                Ok(Some(i)) => {
                    changed.insert(i);
                }
                Ok(None) => return,
                Err(_) => break,
            }
        }
        for i in changed {
            // As a download's: a panic reading the file keeps the rules.
            let local = &locals[i];
            if crate::runtime::scope::contain("rule-set reload", async { local.reload() })
                .await
                .is_none()
            {
                tracing::warn!(
                    "rule-set [{}]: its reload panicked, keeping the rules in use",
                    local.tag
                );
            }
        }
    }
    drop(watchers);
}

#[cfg(feature = "auto-reload")]
fn read_file(path: &str, config: &config::RuleSet, env: &RuntimeEnv) -> Result<RuleSet> {
    let data = std::fs::read(path).map_err(|e| anyhow!("{}: {}", path, e))?;
    read_data(&data, digest(&data), path, config, env)
}

/// The rule-set of a local file's bytes, which hash as `source`.
fn read_data(
    data: &[u8],
    source: (u64, u64),
    path: &str,
    config: &config::RuleSet,
    env: &RuntimeEnv,
) -> Result<RuleSet> {
    // Checked with the configuration.
    let format = config.format().unwrap_or(RuleSetFormat::Source);
    let mut set = RuleSet::read(data, format, config.behavior, env)
        .map_err(|e| anyhow!("{}: {}", path, e))?;
    set.source = Some(source);
    Ok(set)
}

#[cfg(test)]
mod tests {
    /// How long a rule-set takes to load into matchers: `SAIL_RS_FILE`, of
    /// `SAIL_RS_FORMAT` (`binary`, `mrs`) and `SAIL_RS_BEHAVIOR`. For
    /// measuring, not run by default; its peak memory is the process's.
    #[test]
    #[ignore]
    fn load_a_rule_set_for_measuring() {
        let file = std::env::var("SAIL_RS_FILE").unwrap();
        let format: RuleSetFormat =
            serde_json::from_value(serde_json::json!(std::env::var("SAIL_RS_FORMAT").unwrap()))
                .unwrap();
        let behavior = std::env::var("SAIL_RS_BEHAVIOR")
            .ok()
            .map(|b| serde_json::from_value(serde_json::json!(b)).unwrap());
        let data = std::fs::read(&file).unwrap();
        let start = std::time::Instant::now();
        let set = RuleSet::read(&data, format, behavior, &RuntimeEnv::default()).unwrap();
        println!("{}: loaded in {:?}", file, start.elapsed());
        std::hint::black_box(set);
    }

    use super::*;
    use crate::session::{Session, SocksAddr};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_set");

    fn facts(probe: &str) -> Facts {
        let destination = match probe.parse::<std::net::IpAddr>() {
            Ok(ip) => SocksAddr::Ip((ip, 443).into()),
            Err(_) => SocksAddr::Domain(probe.to_string(), 443),
        };
        Facts::new(
            &Session {
                destination,
                ..Default::default()
            },
            &[],
        )
    }

    /// sing-box compiled the `.srs` files from the `.json` ones, and
    /// `sing-box rule-set match` gave `expected.json`, for both forms.
    #[test]
    fn source_and_binary_match_as_sing_box_does() {
        let expected: HashMap<String, HashMap<String, bool>> =
            serde_json::from_slice(&std::fs::read(format!("{}/expected.json", FIXTURES)).unwrap())
                .unwrap();
        for (name, probes) in &expected {
            for (file, format) in [
                (format!("{}/{}.json", FIXTURES, name), RuleSetFormat::Source),
                (format!("{}/{}.srs", FIXTURES, name), RuleSetFormat::Binary),
            ] {
                let set = RuleSet::read(
                    &std::fs::read(&file).unwrap(),
                    format,
                    None,
                    &RuntimeEnv::default(),
                )
                .unwrap_or_else(|e| panic!("{}: {}", file, e));
                let wrong: Vec<&String> = probes
                    .iter()
                    .filter(|(probe, matched)| set.matches(&facts(probe), false) != **matched)
                    .map(|(probe, _)| probe)
                    .collect();
                assert!(
                    wrong.is_empty(),
                    "{}: {} wrong: {:?}",
                    file,
                    wrong.len(),
                    wrong
                );
            }
        }
    }

    /// The published rule-sets, against what sing-box said of them: a
    /// directory with `<name>.srs` and `real-expected.json`, in
    /// `SAIL_REAL_RULE_SETS`.
    #[test]
    #[ignore]
    fn published_rule_sets_match_as_sing_box_does() {
        let dir = std::env::var("SAIL_REAL_RULE_SETS").expect("SAIL_REAL_RULE_SETS");
        let expected: HashMap<String, HashMap<String, bool>> =
            serde_json::from_slice(&std::fs::read(format!("{}/real-expected.json", dir)).unwrap())
                .unwrap();
        for (name, probes) in &expected {
            let file = format!("{}/{}.srs", dir, name);
            let set = RuleSet::read(
                &std::fs::read(&file).unwrap(),
                RuleSetFormat::Binary,
                None,
                &RuntimeEnv::default(),
            )
            .unwrap_or_else(|e| panic!("{}: {}", file, e));
            let wrong: Vec<&String> = probes
                .iter()
                .filter(|(probe, matched)| set.matches(&facts(probe), false) != **matched)
                .map(|(probe, _)| probe)
                .collect();
            assert!(
                wrong.is_empty(),
                "{}: {} wrong: {:?}",
                file,
                wrong.len(),
                wrong
            );
        }
    }

    /// A rule of `route` naming the inline rule-sets `sets`, by tag.
    fn rule(route_rule: serde_json::Value, sets: serde_json::Value) -> Matcher {
        let rule: crate::config::model::Rule = serde_json::from_value(route_rule).unwrap();
        let configs: Vec<config::RuleSet> = serde_json::from_value(sets).unwrap();
        let env = RuntimeEnv::default();
        let sets = RuleSets::load(&configs, &HttpClients::default(), &env, None).unwrap();
        Matcher::new(&rule, &env, &sets).unwrap()
    }

    fn at(domain: &str, port: u16, network: crate::session::Network) -> Facts {
        Facts::new(
            &Session {
                destination: SocksAddr::Domain(domain.into(), port),
                network,
                ..Default::default()
            },
            &[],
        )
    }

    use crate::app::router::matcher::Matcher;
    use crate::session::Network::{Tcp, Udp};

    /// A reload keeps a rule-set that is configured as it was and whose
    /// source is the same, the very rules that run, and reads any other
    /// again: one whose file's bytes changed, were they as many and
    /// written in the same instant, or whose configuration did.
    #[test]
    fn a_reload_keeps_the_rule_sets_whose_source_is_the_same() {
        let dir = std::env::temp_dir().join(format!("sail-rs-keep-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("rs.json");
        let write = |domain: &str| {
            let rules = serde_json::json!({ "version": 3, "rules": [{ "domain": [domain] }] });
            std::fs::write(&path, rules.to_string()).unwrap();
        };
        write("a.example");
        let configs = |inline: &str| -> Vec<config::RuleSet> {
            serde_json::from_value(serde_json::json!([
                { "type": "local", "tag": "file", "format": "source", "path": path },
                { "type": "inline", "tag": "in", "rules": [{ "domain": [inline] }] }
            ]))
            .unwrap()
        };
        let env = RuntimeEnv::default();
        let load = |configs: &[config::RuleSet], before: Option<&RuleSets>| {
            RuleSets::load(configs, &HttpClients::default(), &env, before).unwrap()
        };
        let rules = |sets: &RuleSets, tag: &str| sets.get(tag).unwrap().load();
        let kept =
            |a: &RuleSets, b: &RuleSets, tag: &str| Arc::ptr_eq(&rules(a, tag), &rules(b, tag));
        let started = load(&configs("x.example"), None);

        // Nothing changed: both are the rules that ran.
        let same = load(&configs("x.example"), Some(&started));
        assert!(kept(&started, &same, "file") && kept(&started, &same, "in"));

        // The inline one's rules changed: it alone is built again.
        let inline = load(&configs("y.example"), Some(&same));
        assert!(kept(&same, &inline, "file") && !kept(&same, &inline, "in"));
        assert!(rules(&inline, "in").matches(&at("y.example", 443, Tcp), false));

        // The file changed, to as many bytes: it alone is read again.
        write("b.example");
        let file = load(&configs("y.example"), Some(&inline));
        assert!(!kept(&inline, &file, "file") && kept(&inline, &file, "in"));
        assert!(rules(&file, "file").matches(&at("b.example", 443, Tcp), false));

        // A start keeps nothing.
        let again = load(&configs("y.example"), None);
        assert!(!kept(&file, &again, "file") && !kept(&file, &again, "in"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A local rule-set follows its file, as sing-box's does: replaced, its
    /// rules are those of the new file; one that does not read leaves the
    /// rules in use.
    #[cfg(feature = "auto-reload")]
    #[tokio::test]
    async fn a_local_rule_set_follows_its_file() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("sail-rs-follow-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("rs.json");
        let replace = |domain: &str| {
            let staged = dir.join("staged");
            let rules = serde_json::json!({ "version": 3, "rules": [{ "domain": [domain] }] });
            std::fs::write(&staged, rules.to_string()).unwrap();
            std::fs::rename(&staged, &path).unwrap();
        };
        replace("a.example");
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "type": "local", "tag": "rs", "format": "source", "path": path }
        ]))
        .unwrap();
        let sets = RuleSets::load(
            &configs,
            &HttpClients::default(),
            &RuntimeEnv::default(),
            None,
        )
        .unwrap();
        let matches = |domain: &str| {
            sets.get("rs")
                .unwrap()
                .load()
                .matches(&at(domain, 443, Tcp), false)
        };
        assert!(matches("a.example") && !matches("b.example"));
        let updater = sets.spawn_updater(std::sync::Weak::new()).unwrap();
        // The watch is set up on the updater's first run.
        tokio::time::sleep(Duration::from_millis(300)).await;
        replace("b.example");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !(matches("b.example") && !matches("a.example")) {
            assert!(tokio::time::Instant::now() < deadline, "not reloaded");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        std::fs::write(&path, "{ cut sho").unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(matches("b.example") && !matches("a.example"));
        updater.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A local rule-set's file written after it was read and before its
    /// watch is set up, the gap a start or a reload leaves, is read again
    /// when the watch is: no event tells of that write.
    #[cfg(feature = "auto-reload")]
    #[tokio::test]
    async fn a_file_written_before_its_watch_is_set_up_is_read_again() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("sail-rs-gap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("rs.json");
        let write = |domains: &[&str]| {
            let rules = serde_json::json!({ "version": 3, "rules": [{ "domain": domains }] });
            std::fs::write(&path, rules.to_string()).unwrap();
        };
        write(&["a.example"]);
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "type": "local", "tag": "rs", "format": "source", "path": path }
        ]))
        .unwrap();
        let sets = RuleSets::load(
            &configs,
            &HttpClients::default(),
            &RuntimeEnv::default(),
            None,
        )
        .unwrap();
        let matches = |domain: &str| {
            sets.get("rs")
                .unwrap()
                .load()
                .matches(&at(domain, 443, Tcp), false)
        };
        assert!(matches("a.example") && !matches("b.example"));
        // Read, not watched yet: the write no watcher sees.
        write(&["b.example"]);
        let updater = sets.spawn_updater(std::sync::Weak::new()).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !(matches("b.example") && !matches("a.example")) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the write before the watch never applied"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        updater.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Destination CIDRs of every default rule, nested in logical ones
    /// too, merged; source CIDRs and domains are not addresses to route.
    #[test]
    fn ip_ranges_are_the_destination_cidrs() {
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "tag": "s", "rules": [
                { "ip_cidr": ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"] },
                { "source_ip_cidr": ["192.168.0.0/16"], "domain": ["example.com"] },
                { "type": "logical", "mode": "or", "rules": [
                    { "ip_cidr": ["1.1.1.1"] },
                    { "domain_suffix": ["example.org"] }
                ] }
            ] }
        ]))
        .unwrap();
        let sets = RuleSets::load(
            &configs,
            &HttpClients::default(),
            &RuntimeEnv::default(),
            None,
        )
        .unwrap();
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(
            sets.ip_ranges("s").unwrap(),
            vec![
                (ip("10.0.0.0"), ip("10.255.255.255")),
                (
                    ip("2001:db8::"),
                    ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
                ),
                (ip("1.1.1.1"), ip("1.1.1.1")),
            ]
        );
        assert!(sets.ip_ranges("t").is_err());

        let version = sets.subscribe("s").unwrap();
        sets.get("s")
            .unwrap()
            .publish(Arc::new(RuleSet::new(Vec::new())));
        assert!(version.has_changed().unwrap());
        assert!(sets.ip_ranges("s").unwrap().is_empty());
        assert!(sets.subscribe("t").is_err());
    }

    /// A rule-set of a few domains and no addresses names sites; one of
    /// many domains, or with addresses, a region or a category. A rule
    /// that matched by a narrow one says which.
    #[test]
    fn narrow_rule_sets_name_the_sites_a_rule_matched() {
        let many: Vec<String> = (0..=NARROW_DOMAINS)
            .map(|i| format!("d{}.test", i))
            .collect();
        let m = rule(
            serde_json::json!({ "rule_set": ["broad", "addresses", "netflix", "logical"],
                                "outbound": "o" }),
            serde_json::json!([
                { "tag": "broad", "rules": [{ "domain_suffix": many }] },
                { "tag": "addresses", "rules": [
                    { "domain_suffix": ["example.com"], "ip_cidr": ["10.0.0.0/8"] }
                ] },
                { "tag": "netflix", "rules": [
                    { "domain_suffix": ["netflix.com", "nflxvideo.net", "example.com"] }
                ] },
                { "tag": "logical", "rules": [{ "type": "logical", "mode": "or", "rules": [
                    { "domain": ["a.example.org"] }, { "domain_keyword": ["example"] }
                ] }] }
            ]),
        );
        let site = |domain: &str| m.narrow_rule_set(&at(domain, 443, Tcp));
        assert_eq!(site("www.netflix.com").as_deref(), Some("netflix"));
        // Matched by the broad sets first, but they name no site.
        assert_eq!(site("example.com").as_deref(), Some("netflix"));
        assert_eq!(site("d7.test"), None);
        assert_eq!(site("a.example.org").as_deref(), Some("logical"));
        assert_eq!(site("nothing.test"), None);

        let narrow = |rules: serde_json::Value| {
            let rules: Vec<config::HeadlessRule> = serde_json::from_value(rules).unwrap();
            RuleSet::from_rules(&rules, &RuntimeEnv::default())
                .unwrap()
                .is_narrow()
        };
        assert!(narrow(serde_json::json!([{ "domain": ["a.test"] }])));
        assert!(!narrow(serde_json::json!([])));
        assert!(!narrow(serde_json::json!([{ "port": [443] }])));
        assert!(!narrow(
            serde_json::json!([{ "source_ip_cidr": ["10.0.0.0/8"] }])
        ));
        assert!(!narrow(serde_json::json!([{ "domain_suffix": many }])));
    }

    /// A download that brings a set of another size makes it narrow, or
    /// not, from then on.
    #[test]
    fn a_rule_set_replaced_is_measured_again() {
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "tag": "s", "rules": [{ "domain_suffix": ["example.com"] }] }
        ]))
        .unwrap();
        let sets = RuleSets::load(
            &configs,
            &HttpClients::default(),
            &RuntimeEnv::default(),
            None,
        )
        .unwrap();
        let set = sets.get("s").unwrap();
        assert!(set.load().is_narrow());
        let many: Vec<String> = (0..=NARROW_DOMAINS)
            .map(|i| format!("d{}.test", i))
            .collect();
        let rules: Vec<config::HeadlessRule> =
            serde_json::from_value(serde_json::json!([{ "domain": many }])).unwrap();
        set.publish(Arc::new(
            RuleSet::from_rules(&rules, &RuntimeEnv::default()).unwrap(),
        ));
        assert!(!set.load().is_narrow());
    }

    /// The domains of binary sets are counted in their compact form.
    #[test]
    fn binary_sets_are_measured_too() {
        let read = |file: &str, format, behavior| {
            let data = std::fs::read(format!("{}/{}", FIXTURES, file)).unwrap();
            RuleSet::read(&data, format, behavior, &RuntimeEnv::default()).unwrap()
        };
        let count =
            |set: &RuleSet| -> usize { set.rules.iter().filter_map(|r| r.domain_count()).sum() };
        // Its source has 2073 domains, suffixes, keywords and regexes.
        let srs = read("domains.srs", RuleSetFormat::Binary, None);
        let source = read("domains.json", RuleSetFormat::Source, None);
        // The trie keeps a domain that is also a suffix once: about as many.
        let (binary, source) = (count(&srs) as f64, count(&source) as f64);
        assert!(
            (binary - source).abs() / source < 0.05,
            "{} {}",
            binary,
            source
        );
        assert!(!srs.is_narrow());
        let mrs = read(
            "geosite-telegram.mrs",
            RuleSetFormat::Mrs,
            Some(ClashBehavior::Domain),
        );
        let lines = std::fs::read_to_string(format!("{}/geosite-telegram.list", FIXTURES)).unwrap();
        let listed = lines.lines().filter(|l| !l.trim().is_empty()).count();
        // A suffix (`+.telegram.org`) is two keys there: the domain and
        // its subdomains.
        assert!(
            (listed..=2 * listed).contains(&count(&mrs)),
            "{}",
            count(&mrs)
        );
        assert!(mrs.is_narrow());
        assert!(!read("ips.srs", RuleSetFormat::Binary, None).is_narrow());
    }

    /// sing-box's TestRuleSetShapeBoundary: one plain rule merges with the
    /// outer conditions, two do not.
    #[test]
    fn a_set_of_one_rule_merges_with_the_outer_conditions() {
        let outer = serde_json::json!({
            "domain": "extra.example.org", "port": 443, "rule_set": "s", "outbound": "x"
        });
        let single = rule(
            outer.clone(),
            serde_json::json!([{ "tag": "s", "rules": [
                { "domain_suffix": ["a.example.com", "b.example.com"] }
            ] }]),
        );
        let multi = rule(
            outer,
            serde_json::json!([{ "tag": "s", "rules": [
                { "domain_suffix": "a.example.com" }, { "domain_suffix": "b.example.com" }
            ] }]),
        );
        for (domain, port, single_result, multi_result) in [
            ("www.b.example.com", 443, true, false),
            ("extra.example.org", 443, true, false),
            ("other.example.net", 443, false, false),
            ("www.b.example.com", 80, false, false),
        ] {
            let facts = at(domain, port, Tcp);
            assert_eq!(single.matches(&facts), single_result, "single {}", domain);
            assert_eq!(multi.matches(&facts), multi_result, "multi {}", domain);
        }
    }

    #[test]
    fn rule_sets_are_alternatives_and_other_conditions_still_hold() {
        // A later set can satisfy what an earlier one did not.
        let m = rule(
            serde_json::json!({ "ip_cidr": "203.0.113.0/24", "rule_set": ["net", "dom"],
                                "outbound": "x" }),
            serde_json::json!([
                { "tag": "net", "rules": [{ "network": "tcp" }] },
                { "tag": "dom", "rules": [{ "domain_suffix": "example.com" }] }
            ]),
        );
        assert!(m.matches(&at("www.example.com", 443, Tcp)));
        // The outer rule's network stays a condition of its own.
        let m = rule(
            serde_json::json!({ "network": "udp", "rule_set": "dom", "outbound": "x" }),
            serde_json::json!([{ "tag": "dom", "rules": [{ "domain_suffix": "example.com" }] }]),
        );
        assert!(!m.matches(&at("www.example.com", 443, Tcp)));
        assert!(m.matches(&at("www.example.com", 443, Udp)));
        // And the set's, however the outer conditions match.
        let m = rule(
            serde_json::json!({ "domain_suffix": "example.com", "rule_set": "net",
                                "outbound": "x" }),
            serde_json::json!([{ "tag": "net", "rules": [{ "network": "udp" }] }]),
        );
        assert!(!m.matches(&at("www.example.com", 443, Tcp)));
    }

    #[test]
    fn an_empty_set_never_matches_and_an_inverted_one_is_its_own() {
        let m = rule(
            serde_json::json!({ "domain_suffix": "example.com", "rule_set": "empty",
                                "outbound": "x" }),
            serde_json::json!([{ "tag": "empty", "rules": [] }]),
        );
        assert!(!m.matches(&at("www.example.com", 443, Tcp)));
        let m = rule(
            serde_json::json!({ "rule_set": "not", "outbound": "x" }),
            serde_json::json!([{ "tag": "not", "rules": [
                { "domain_suffix": "blocked.example", "invert": true }
            ] }]),
        );
        assert!(m.matches(&at("good.example.org", 443, Tcp)));
        assert!(!m.matches(&at("www.blocked.example", 443, Tcp)));
    }

    #[test]
    fn a_rule_set_s_autonomous_systems_are_its_data_directory_s() {
        use crate::app::router::matcher::tests::{asn_records, mmdb};
        let dir = std::env::temp_dir().join(format!("sail-rs-asn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (geolite, _) = asn_records(13335, "");
        std::fs::write(dir.join("asn.mmdb"), mmdb(&[("1.0.0.0/8", geolite)])).unwrap();
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                data_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let rules = [serde_json::from_value(serde_json::json!({ "ip_asn": 13335 })).unwrap()];
        let set = RuleSet::from_rules(&rules, &env).unwrap();
        let at = |ip: &str| {
            let sess = crate::session::Session {
                destination: crate::session::SocksAddr::from((
                    ip.parse::<std::net::IpAddr>().unwrap(),
                    443,
                )),
                ..Default::default()
            };
            set.matches(&Facts::new(&sess, &[]), false)
        };
        assert!(at("1.1.1.1"));
        assert!(!at("9.9.9.9"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(RuleSet::from_rules(&rules, &RuntimeEnv::default()).is_err());
    }

    #[test]
    fn logical_rules_combine() {
        let m = rule(
            serde_json::json!({ "rule_set": "l", "outbound": "x" }),
            serde_json::json!([{ "tag": "l", "rules": [{
                "type": "logical", "mode": "and", "rules": [
                    { "domain_suffix": "example.com" },
                    { "type": "logical", "mode": "or", "invert": true, "rules": [
                        { "port": 80 }, { "network": "udp" }
                    ] }
                ]
            }] }]),
        );
        assert!(m.matches(&at("a.example.com", 443, Tcp)));
        assert!(!m.matches(&at("a.example.com", 80, Tcp)));
        assert!(!m.matches(&at("a.example.com", 443, Udp)));
        assert!(!m.matches(&at("a.example.org", 443, Tcp)));
    }

    #[test]
    fn a_rule_set_s_ip_cidr_can_match_the_source() {
        let sets =
            serde_json::json!([{ "tag": "lan", "rules": [{ "ip_cidr": "192.168.0.0/16" }] }]);
        let by_source = rule(
            serde_json::json!({ "rule_set": "lan", "rule_set_ip_cidr_match_source": true,
                                "outbound": "x" }),
            sets.clone(),
        );
        let by_destination = rule(
            serde_json::json!({ "rule_set": "lan", "outbound": "x" }),
            sets,
        );
        let facts = Facts::new(
            &Session {
                source: "192.168.1.5:5000".parse().unwrap(),
                destination: SocksAddr::Ip("8.8.8.8:53".parse().unwrap()),
                ..Default::default()
            },
            &[],
        );
        assert!(by_source.matches(&facts));
        assert!(!by_destination.matches(&facts));
    }

    #[test]
    fn unsupported_conditions_are_refused_with_their_name() {
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "tag": "w", "rules": [{ "default_interface_address": "10.0.0.0/8" }] }
        ]))
        .unwrap();
        let err = RuleSets::load(
            &configs,
            &HttpClients::default(),
            &RuntimeEnv::default(),
            None,
        )
        .err()
        .unwrap();
        assert!(
            format!("{:#}", err).contains("default_interface_address: sail does not match it yet"),
            "{:#}",
            err
        );
    }

    fn on_network(state: serde_json::Value) -> Facts {
        at("a.example", 443, Tcp).with_network(std::sync::Arc::new(
            crate::net::network::NetworkState::from_json(&state.to_string()).unwrap(),
        ))
    }

    /// A rule-set's rules match the network the host is on, as a routing
    /// rule's do, and the rule naming it needs the network then.
    #[test]
    fn a_rule_set_matches_the_network() {
        let m = rule(
            serde_json::json!({ "rule_set": "home", "outbound": "x" }),
            serde_json::json!([{ "tag": "home", "rules": [
                { "wifi_ssid": "Home", "network_type": "wifi" }
            ] }]),
        );
        assert!(m.needs().network);
        assert!(m.matches(&on_network(
            serde_json::json!({ "type": "wifi", "ssid": "Home" })
        )));
        assert!(!m.matches(&on_network(
            serde_json::json!({ "type": "wifi", "ssid": "Cafe" })
        )));
        assert!(!m.matches(&at("a.example", 443, Tcp)));
    }

    /// A binary rule of sing-box's: `wifi_ssid` Home, `network_type`
    /// wifi (0), `network_is_expensive`.
    #[test]
    fn a_binary_rule_set_matches_the_network() {
        let mut rules = vec![1u8, 0];
        rules.extend([14, 1, 4]);
        rules.extend(b"Home");
        rules.extend([18, 1, 0]);
        rules.extend([19]);
        rules.extend([0xff, 0]);
        let mut data = b"SRS\x03".to_vec();
        data.extend(miniz_oxide::deflate::compress_to_vec_zlib(&rules, 6));
        let set =
            RuleSet::read(&data, RuleSetFormat::Binary, None, &RuntimeEnv::default()).unwrap();
        assert!(set.needs(false).network);
        let home = |expensive: bool| {
            on_network(serde_json::json!({
                "type": "wifi", "ssid": "Home", "expensive": expensive
            }))
        };
        assert!(set.matches(&home(true), false));
        assert!(!set.matches(&home(false), false));
        assert!(!set.matches(&at("a.example", 443, Tcp), false));

        // A kind of network sing-box does not number is an error.
        let mut data = b"SRS\x03".to_vec();
        data.extend(miniz_oxide::deflate::compress_to_vec_zlib(
            &[1, 0, 18, 1, 9, 0xff, 0],
            6,
        ));
        assert!(RuleSet::read(&data, RuleSetFormat::Binary, None, &RuntimeEnv::default()).is_err());
    }

    fn to_ip(ip: &str) -> Facts {
        Facts::new(
            &Session {
                destination: SocksAddr::Ip(std::net::SocketAddr::new(ip.parse().unwrap(), 443)),
                ..Default::default()
            },
            &[],
        )
    }

    /// A binary rule-set of one default rule of `items`, not inverted.
    fn binary(items: &[u8]) -> Vec<u8> {
        let mut rules = vec![1u8, 0];
        rules.extend(items);
        rules.extend([0xff, 0]);
        let mut data = b"SRS\x03".to_vec();
        data.extend(miniz_oxide::deflate::compress_to_vec_zlib(&rules, 6));
        data
    }

    /// An address of 16 bytes in a binary rule-set is IPv6, a mapped one
    /// too, as sing-box reads it: `::ffff:0:0/96` matches no IPv4 address.
    #[test]
    fn a_mapped_range_of_a_binary_rule_set_stays_ipv6() {
        let v6 = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap().octets();
        let mut items = vec![6u8, 1];
        items.extend(2u64.to_be_bytes());
        for (from, to) in [
            ("::ffff:0:0", "::ffff:ffff:ffff"),
            ("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        ] {
            for addr in [from, to] {
                items.push(16);
                items.extend(v6(addr));
            }
        }
        let set = RuleSet::read(
            &binary(&items),
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default(),
        )
        .unwrap();
        assert!(!set.matches(&to_ip("1.2.3.4"), false));
        assert!(!set.matches(&to_ip("::ffff:1.2.3.4"), false));
        assert!(set.matches(&to_ip("2001:db8::1"), false));
    }

    /// A rule-set rule with no conditions, inverted or not, at any depth,
    /// is refused, as sing-box refuses it: it would match everything.
    #[test]
    fn a_rule_set_rule_with_no_conditions_is_refused() {
        for (rules, path) in [
            (serde_json::json!([{}]), "rules[0]"),
            (serde_json::json!([{ "invert": true }]), "rules[0]"),
            (
                serde_json::json!([{ "domain": "a.example" }, { "type": "default" }]),
                "rules[1]",
            ),
            (
                serde_json::json!([{ "type": "logical", "mode": "or", "rules": [
                    { "domain": "a.example" }, { "invert": true }
                ] }]),
                "rules[0].rules[1]",
            ),
        ] {
            let data = serde_json::json!({ "version": 3, "rules": rules }).to_string();
            let err = RuleSet::read(
                data.as_bytes(),
                RuleSetFormat::Source,
                None,
                &RuntimeEnv::default(),
            )
            .err()
            .unwrap_or_else(|| panic!("{} was taken", rules));
            assert_eq!(err.to_string(), format!("{}: missing conditions", path));
        }
        let err = RuleSet::read(
            &binary(&[]),
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default(),
        )
        .err()
        .expect("an empty binary rule was taken");
        assert_eq!(err.to_string(), "rules[0]: missing conditions");
    }

    /// A list with no entry taken matches nothing, as Mihomo's empty set.
    #[test]
    fn an_empty_list_matches_nothing() {
        let comments = b"# nothing here\n\n// nor here\n";
        for (format, behavior) in [
            (RuleSetFormat::ClashText, ClashBehavior::Domain),
            (RuleSetFormat::ClashText, ClashBehavior::Ipcidr),
            (RuleSetFormat::SurgeText, ClashBehavior::Domain),
        ] {
            let set =
                RuleSet::read(comments, format, Some(behavior), &RuntimeEnv::default()).unwrap();
            assert!(
                !set.matches(&at("a.example", 443, Tcp), false),
                "{:?} {:?}",
                format,
                behavior
            );
            assert!(!set.matches(&to_ip("1.2.3.4"), false));
        }
        // Entries all passed over leave it empty too.
        let set = RuleSet::read(
            b"not-an-ip\n",
            RuleSetFormat::ClashText,
            Some(ClashBehavior::Ipcidr),
            &RuntimeEnv::default(),
        )
        .unwrap();
        assert!(!set.matches(&to_ip("1.2.3.4"), false));
    }

    #[test]
    fn a_damaged_binary_is_an_error_not_a_panic() {
        let data = std::fs::read(format!("{}/domains.srs", FIXTURES)).unwrap();
        assert!(RuleSet::read(
            &data[..data.len() / 2],
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default()
        )
        .is_err());
        assert!(RuleSet::read(
            b"SRS\x09",
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default()
        )
        .is_err());
        assert!(RuleSet::read(
            b"XYZ\x01",
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default()
        )
        .is_err());
        // Each byte flipped in turn: never a panic.
        for i in 4..data.len().min(600) {
            let mut bad = data.clone();
            bad[i] ^= 0x5a;
            let _ = RuleSet::read(&bad, RuleSetFormat::Binary, None, &RuntimeEnv::default());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn updates_wait_while_the_network_is_down() {
        use crate::net::network::{ChangeReason, NetworkState};
        use std::time::Duration;
        let network = Network::default();
        let up = NetworkState {
            interface: Some("en0".into()),
            ..Default::default()
        };
        network.detected(up.clone(), ChangeReason::State);
        network.detected(NetworkState::default(), ChangeReason::State);
        assert!(network.is_down());
        let env = RuntimeEnv {
            network: network.clone(),
            ..Default::default()
        };
        let config: config::RuleSet = serde_json::from_value(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://example.com/s.json"
        }))
        .unwrap();
        // Never downloaded: due now.
        let remote =
            Arc::new(remote::Remote::load(&config, "s", Default::default(), &env, None).unwrap());
        let remotes = [remote];
        let mut changes = network.changes();
        let wait = until_due(&remotes, &network, &mut changes);
        tokio::pin!(wait);
        assert!(tokio::time::timeout(Duration::from_secs(3600), &mut wait)
            .await
            .is_err());
        // Back: what fell due goes at once.
        network.detected(up, ChangeReason::State);
        tokio::time::timeout(Duration::from_secs(2), &mut wait)
            .await
            .unwrap();
    }
}
