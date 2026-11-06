//! Rule-sets downloaded, kept in the cache directory, and downloaded again
//! as `update_interval` says. A download that fails, or that holds no valid
//! rule-set, leaves the one in use as it is.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::runtime::resource::HotResource;
use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use super::{RuleSet, SharedRuleSet};
use crate::app::dispatcher::Dispatcher;
use crate::app::http::{self, write_atomically};
use crate::config::rule_set::{self as config, RuleSetFormat};
use crate::runtime::RuntimeEnv;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after a failed download the next one is tried.
const RETRY: Duration = Duration::from_secs(5 * 60);

pub(crate) struct Remote {
    pub tag: String,
    url: String,
    format: RuleSetFormat,
    behavior: Option<crate::config::rule_set::ClashBehavior>,
    /// The most a download of it may be, its `size_limit`.
    size_limit: Option<u64>,
    interval: Duration,
    client: http::Client,
    /// Where the downloaded copy is kept; none when there is nowhere to.
    cache: Option<PathBuf>,
    /// Whose data files its rules name.
    env: RuntimeEnv,
    pub set: SharedRuleSet,
    state: Mutex<State>,
}

/// What is known of the copy in use.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Whether there is one at all.
    #[serde(skip)]
    loaded: bool,
    etag: Option<String>,
    /// When it was downloaded, or last found unchanged.
    #[serde(default)]
    updated: Option<SystemTime>,
    /// The last download's failure, until one succeeds.
    #[serde(skip)]
    failed: Option<crate::control::Failure>,
}

impl Remote {
    /// The rule-set `tag` of `config`, from its cached copy or its
    /// `initial_path`, or empty until the first download. At a reload,
    /// `before` is the one that ran, configured the same: its copy goes on
    /// as it is, with its ETag and the time it was updated, and nothing is
    /// read again; it is downloaded when it was due before.
    pub(crate) fn load(
        config: &config::RuleSet,
        tag: &str,
        client: http::Client,
        env: &RuntimeEnv,
        before: Option<&Remote>,
    ) -> Result<Self> {
        let format = config.format().unwrap_or(RuleSetFormat::Binary);
        let extension = match format {
            RuleSetFormat::Binary => "srs",
            RuleSetFormat::Source => "json",
            RuleSetFormat::Mrs => "mrs",
            RuleSetFormat::ClashYaml => "yaml",
            RuleSetFormat::ClashText => "txt",
            RuleSetFormat::SurgeText => "list",
        };
        let url = env
            .host
            .download_url(&config::RuleSet::for_tag(
                config.url.as_deref().unwrap_or_default(),
                tag,
            ))
            .map_err(|e| anyhow!("url: {}", e))?;
        // Keep each source apart, including a previous source whose
        // download finishes after a reload. Hash the format, full tag and
        // effective URL: filenames stay bounded, with no subscription token.
        // Delimit the format and length-prefix the tag for unambiguous inputs.
        // The format is hashed too so atomic writes' .partial paths differ.
        // The old tag-only cache cannot be attributed to a source: fetch again.
        let cache = env.host.cache_dir.as_ref().map(|dir| {
            let mut source = Sha256::new();
            source.update(extension.as_bytes());
            source.update([0]);
            source.update((tag.len() as u64).to_be_bytes());
            source.update(tag.as_bytes());
            source.update(url.as_bytes());
            dir.join("rule-set")
                .join(format!("{:x}.{}", source.finalize(), extension))
        });
        let mut remote = Remote {
            tag: tag.to_string(),
            url,
            format,
            behavior: config.behavior,
            size_limit: config.size_limit,
            interval: config.update_interval.unwrap_or(DEFAULT_INTERVAL),
            client,
            cache: cache.clone(),
            env: env.clone(),
            set: HotResource::new(RuleSet::new(Vec::new())),
            state: Mutex::new(State::default()),
        };
        if let Some(before) = before {
            let state = before.state();
            if state.loaded && before.url == remote.url {
                remote.set = before.set.clone();
                *remote.state.get_mut().unwrap_or_else(|e| e.into_inner()) = State {
                    loaded: true,
                    etag: state.etag.clone(),
                    updated: state.updated,
                    failed: state.failed.clone(),
                };
                debug!("rule-set [{}]: unchanged, kept as it runs", tag);
                return Ok(remote);
            }
        }
        // A cached copy that does not read is as good as none.
        if let Some(Ok(data)) = cache.as_ref().map(std::fs::read) {
            let cache = cache.as_ref().expect("read from it");
            match RuleSet::read(&data, format, config.behavior, env) {
                Ok(set) => {
                    let mut state: State = std::fs::read(meta_path(cache))
                        .ok()
                        .and_then(|m| serde_json::from_slice(&m).ok())
                        .unwrap_or_default();
                    state.loaded = true;
                    remote.set.publish(Arc::new(set));
                    *remote.state.get_mut().unwrap_or_else(|e| e.into_inner()) = state;
                    debug!("rule-set [{}]: from {}", tag, cache.display());
                    return Ok(remote);
                }
                Err(e) => warn!("rule-set [{}]: cached {}: {}", tag, cache.display(), e),
            }
        }
        if let Some(initial) = &config.initial_path {
            let path = env.data_path(&config::RuleSet::for_tag(initial, tag));
            let data =
                std::fs::read(&path).map_err(|e| anyhow!("initial_path: {}: {}", path, e))?;
            let set = RuleSet::read(&data, format, config.behavior, env)
                .map_err(|e| anyhow!("initial_path: {}: {}", path, e))?;
            remote.set.publish(Arc::new(set));
            remote
                .state
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .loaded = true;
        }
        Ok(remote)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// When it was downloaded, or last found unchanged.
    pub(crate) fn updated(&self) -> Option<SystemTime> {
        self.state().updated
    }

    /// The last download's failure, until one succeeds.
    pub(crate) fn failure(&self) -> Option<crate::control::Failure> {
        self.state().failed.clone()
    }

    pub(crate) fn is_loaded(&self) -> bool {
        self.state().loaded
    }

    /// How long until it is due for a download; zero when due now.
    pub(crate) fn due_in(&self, now: SystemTime) -> Duration {
        let state = self.state();
        if let Some(failed) = &state.failed {
            return RETRY.saturating_sub(now.duration_since(failed.at).unwrap_or_default());
        }
        match state.updated {
            None => Duration::ZERO,
            Some(updated) => self
                .interval
                .saturating_sub(now.duration_since(updated).unwrap_or_default()),
        }
    }

    /// Downloads it, and puts the new rules in place when they read.
    pub(crate) async fn update(&self, dispatcher: &Dispatcher) -> Result<()> {
        let result = self.download(dispatcher).await;
        let mut state = self.state();
        state.failed = result.as_ref().err().map(crate::control::Failure::now);
        result
    }

    async fn download(&self, dispatcher: &Dispatcher) -> Result<()> {
        let via = match &self.client.via {
            Some(via) => via.clone(),
            None => http::Via::Outbound(
                dispatcher
                    .default_outbound()
                    .ok_or_else(|| anyhow!("no outbound to download through"))?,
            ),
        };
        let etag = {
            let state = self.state();
            state.loaded.then(|| state.etag.clone()).flatten()
        };
        let parsed = match http::get(
            dispatcher,
            &via,
            &self.client.headers,
            &self.url,
            etag.as_deref(),
            self.size_limit,
        )
        .await?
        {
            http::Response::NotModified => {
                debug!("rule-set [{}]: unchanged", self.tag);
                self.state().updated = Some(SystemTime::now());
                false
            }
            http::Response::Body { data, etag, .. } => {
                let set = match RuleSet::read(&data, self.format, self.behavior, &self.env) {
                    Ok(set) => set,
                    Err(e) => {
                        // Refused, it was read and dropped all the same.
                        drop(data);
                        crate::runtime::memory::freed();
                        return Err(e);
                    }
                };
                self.set.publish(Arc::new(set));
                {
                    let mut state = self.state();
                    state.loaded = true;
                    state.etag = etag;
                    state.updated = Some(SystemTime::now());
                }
                info!("rule-set [{}]: downloaded, {} bytes", self.tag, data.len());
                if let Err(e) = self.save(&data) {
                    warn!("rule-set [{}]: not cached: {}", self.tag, e);
                }
                true
            }
        };
        // The document read and dropped: what it took may go back.
        if parsed {
            crate::runtime::memory::freed();
        }
        if let Err(e) = self.save_meta() {
            warn!("rule-set [{}]: not cached: {}", self.tag, e);
        }
        Ok(())
    }

    /// Writes the copy whole or not at all: to a file beside it, then in
    /// its place.
    fn save(&self, data: &[u8]) -> Result<()> {
        let Some(path) = &self.cache else {
            return Ok(());
        };
        write_atomically(path, data)
    }

    fn save_meta(&self) -> Result<()> {
        let Some(path) = &self.cache else {
            return Ok(());
        };
        let meta = serde_json::to_vec(&*self.state())?;
        write_atomically(&meta_path(path), &meta)
    }
}

fn meta_path(cache: &std::path::Path) -> PathBuf {
    // Retain the format too: two formats of a source have separate
    // bodies, and must not share their ETags or update timestamps.
    let mut path = cache.as_os_str().to_os_string();
    path.push(".meta.json");
    path.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::http::file_name;

    #[test]
    fn a_cached_copy_is_used_until_due() {
        let dir = std::env::temp_dir().join(format!(
            "sail-rule-set-cache-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config: config::RuleSet = serde_json::from_value(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://example.com/s.json",
            "update_interval": "1h"
        }))
        .unwrap();
        let remote = Remote::load(&config, "s", Default::default(), &env, None).unwrap();
        assert!(!remote.is_loaded());
        assert!(remote.due_in(SystemTime::now()).is_zero());

        remote
            .save(br#"{ "version": 3, "rules": [{ "domain": "a.example" }] }"#)
            .unwrap();
        remote.state().updated = Some(SystemTime::now());
        remote.save_meta().unwrap();
        let again = Remote::load(&config, "s", Default::default(), &env, None).unwrap();
        assert!(again.is_loaded());
        let due = again.due_in(SystemTime::now());
        assert!(
            due > Duration::from_secs(3500) && due <= Duration::from_secs(3600),
            "{:?}",
            due
        );
        let facts = crate::app::router::matcher::Facts::new(
            &crate::session::Session {
                destination: crate::session::SocksAddr::Domain("a.example".into(), 443),
                ..Default::default()
            },
            &[],
        );
        assert!(again.set.load().matches(&facts, false));

        // A reload's, after the one that ran: its copy and what is known
        // of it, with nothing read: the cached file is gone.
        again.state().etag = Some("\"v1\"".into());
        std::fs::remove_dir_all(&dir).unwrap();
        let kept = Remote::load(&config, "s", Default::default(), &env, Some(&again)).unwrap();
        assert!(Arc::ptr_eq(&kept.set.load(), &again.set.load()));
        assert_eq!(kept.state().etag.as_deref(), Some("\"v1\""));
        assert_eq!(kept.updated(), again.updated());
        // One that has no copy yet is loaded as at a start.
        let unloaded = Remote::load(&config, "s", Default::default(), &env, Some(&remote)).unwrap();
        assert!(!unloaded.is_loaded());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_tag_cannot_leave_the_cache_directory() {
        assert_eq!(file_name("geosite-cn"), "geosite-cn");
        assert_eq!(file_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(file_name(".."), "_");
        assert_eq!(file_name("a/b\\c:d"), "a_b_c_d");
    }

    #[test]
    fn changed_sources_do_not_load_or_overwrite_each_others_cache() {
        let dir = std::env::temp_dir().join(format!(
            "sail-rule-set-source-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = |url: &str| {
            serde_json::from_value(serde_json::json!({
                "type": "remote", "tag": "s", "format": "source", "url": url
            }))
            .unwrap()
        };
        let old_config = config("https://example.com/old.json?token=old-secret");
        let new_config = config("https://example.com/new.json?token=new-secret");
        let old = Remote::load(&old_config, "s", Default::default(), &env, None).unwrap();
        let data = br#"{ "version": 3, "rules": [{ "domain": "old.example" }] }"#;
        old.save(data).unwrap();
        old.state().updated = Some(SystemTime::now());
        old.state().etag = Some("\"old\"".into());
        old.save_meta().unwrap();
        let old = Remote::load(&old_config, "s", Default::default(), &env, None).unwrap();
        assert!(old.is_loaded());

        for before in [None, Some(&old)] {
            let new = Remote::load(&new_config, "s", Default::default(), &env, before).unwrap();
            assert!(!new.is_loaded(), "rules from the previous URL were reused");
            assert!(new.state().etag.is_none());
            assert!(new.updated().is_none());
            assert!(new.due_in(SystemTime::now()).is_zero());
            assert_ne!(new.cache, old.cache);
            assert!(!new
                .cache
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .contains("secret"));

            // An old download may finish after a reload. Its writes must
            // not replace the new source's body or metadata.
            let new_data = br#"{ "version": 3, "rules": [{ "domain": "new.example" }] }"#;
            new.save(new_data).unwrap();
            new.state().etag = Some("\"new\"".into());
            new.save_meta().unwrap();
            old.save(data).unwrap();
            old.save_meta().unwrap();
            assert_eq!(
                std::fs::read(new.cache.as_ref().unwrap()).unwrap(),
                new_data
            );
            let cached = Remote::load(&new_config, "s", Default::default(), &env, None).unwrap();
            assert!(cached.is_loaded());
            assert_eq!(cached.state().etag.as_deref(), Some("\"new\""));
            std::fs::remove_file(new.cache.as_ref().unwrap()).unwrap();
            std::fs::remove_file(meta_path(new.cache.as_ref().unwrap())).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_legacy_cache_without_a_source_is_not_trusted() {
        let dir = std::env::temp_dir().join(format!(
            "sail-rule-set-legacy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(dir.join("rule-set")).unwrap();
        std::fs::write(
            dir.join("rule-set/s.json"),
            br#"{ "version": 3, "rules": [{ "domain": "old.example" }] }"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("rule-set/s.meta.json"),
            serde_json::to_vec(&State {
                etag: Some("\"old\"".into()),
                updated: Some(SystemTime::now()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = serde_json::from_value(serde_json::json!({
            "type": "remote", "tag": "s", "format": "source",
            "url": "https://example.com/new.json"
        }))
        .unwrap();
        let remote = Remote::load(&config, "s", Default::default(), &env, None).unwrap();
        assert!(!remote.is_loaded());
        assert!(remote.state().etag.is_none());
        assert!(remote.due_in(SystemTime::now()).is_zero());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cache_identity_uses_the_effective_url_and_keeps_formats_apart() {
        let mut env = RuntimeEnv::default();
        env.host.cache_dir = Some(PathBuf::from("cache"));
        env.host.sub_store = Some(crate::runtime::SubStore("https://old.example".into()));
        let config: config::RuleSet = serde_json::from_value(serde_json::json!({
            "type": "remote", "tag": "s", "format": "source",
            "url": "https://sub.store/s"
        }))
        .unwrap();
        let old = Remote::load(&config, "s", Default::default(), &env, None).unwrap();
        old.state().loaded = true;
        env.host.sub_store = Some(crate::runtime::SubStore("https://new.example".into()));
        let new = Remote::load(&config, "s", Default::default(), &env, Some(&old)).unwrap();
        assert!(!new.is_loaded());
        assert_ne!(old.cache, new.cache);

        let mut binary_config = config.clone();
        binary_config.format = Some(RuleSetFormat::Binary);
        let binary = Remote::load(&binary_config, "s", Default::default(), &env, None).unwrap();
        assert_ne!(new.cache, binary.cache);
        assert_ne!(
            new.cache.as_ref().unwrap().with_extension("partial"),
            binary.cache.as_ref().unwrap().with_extension("partial")
        );
        assert_ne!(
            meta_path(new.cache.as_ref().unwrap()),
            meta_path(binary.cache.as_ref().unwrap())
        );
    }

    #[test]
    fn long_and_sanitized_alike_tags_have_separate_writable_caches() {
        let dir = std::env::temp_dir().join(format!(
            "sail-rule-set-tags-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = serde_json::from_value(serde_json::json!({
            "type": "remote", "tag": "unused", "format": "source",
            "url": "https://example.com/rules.json"
        }))
        .unwrap();
        let mut paths = Vec::new();
        for tag in ["a".repeat(200), "界".repeat(70), "a/b".into(), "a_b".into()] {
            let remote = Remote::load(&config, &tag, Default::default(), &env, None).unwrap();
            let path = remote.cache.as_ref().unwrap();
            assert_eq!(path.file_name().unwrap().len(), 69);
            assert!(!paths.contains(path), "distinct tags shared a cache");
            paths.push(path.clone());
            remote
                .save(br#"{ "version": 3, "rules": [{ "domain": "a.example" }] }"#)
                .unwrap();
            remote.state().etag = Some("\"v1\"".into());
            remote.save_meta().unwrap();
            let cached = Remote::load(&config, &tag, Default::default(), &env, None).unwrap();
            assert!(cached.is_loaded());
            assert_eq!(cached.state().etag.as_deref(), Some("\"v1\""));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
