//! What an instance runs with besides its configuration: tuning, and what
//! the host provides.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod cache_file;
pub mod memory;
pub mod options;
pub mod platform;
pub(crate) mod resource;
pub(crate) mod running;
pub mod scope;
pub(crate) mod stamp;
pub mod system_memory;
pub mod teardown;
pub mod transfer_budget;
#[cfg(feature = "auto-reload")]
pub(crate) mod watch;

pub use options::{Profile, ProfileThreads, RuntimeOptions};
pub use platform::{Platform, PlatformRef, TunRequest};

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

/// Where the host keeps things, and what it does for the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    /// Data files (`geo.mmdb`, `site.dat`), certificates given by relative
    /// path, and the cache live here. Defaults to the executable's directory.
    pub data_dir: Option<PathBuf>,
    /// Where the cache file is when the configuration gives it no absolute
    /// path, and remote rule-sets are kept; the data directory's when
    /// unset.
    pub cache_dir: Option<PathBuf>,
    /// Sends logs to the platform's system log rather than to standard
    /// output; needs a platform.
    pub log_to_system: bool,
    /// How outbound sockets are kept out of the VPN (Android), when the
    /// platform does not do it.
    pub socket_protect: Option<crate::net::dial::SocketProtect>,
    /// What the embedding host does for the instance.
    pub platform: Option<PlatformRef>,
    /// The base URL of the operator's own Sub-Store backend (its secret
    /// path, if any, included), which downloads from `sub.store` go to:
    /// see [`Host::download_url`].
    pub sub_store: Option<SubStore>,
    /// Where the Clash API's dashboard is downloaded from, a ZIP, when
    /// `external_ui` is empty and the configuration names no URL: the
    /// core has none of its own.
    pub ui_download_url: Option<String>,
    /// Where each asset (`sail::assets`) is downloaded from, by its name
    /// (`asn.mmdb`), for an update the runtime API is asked for without a
    /// URL. The operations plane's: the core has none.
    pub asset_sources: BTreeMap<String, String>,
    /// Where the instance's log lines go, the host's to read; one keeping
    /// none when unset.
    pub log: Option<crate::app::logger::InstanceLogRef>,
    /// Where an instance writes down the changes to the system that a kill
    /// would leave, for the sweep before the next start
    /// (docs/tun-leftover-sweep.md).
    pub run_dir: crate::platform::sweep::RunDir,
    /// Gives the instance Clash modes (`Rule`, `Global`, `Direct` and those
    /// its rules name) though its configuration has no Clash API, as
    /// sing-box's libbox does for its apps: its daemon always has a
    /// PlatformLogWriter (daemon/instance.go:124-128), and box.New makes
    /// the clash-mode manager whenever there is one (box.go:247-259, both
    /// sing-box v1.14.2). The FFI sets it; sail-cli does not, so a
    /// configuration it runs has modes only with a Clash API, as in
    /// sing-box.
    pub clash_modes: bool,
    /// How long a stop waits for the instance's tasks to end before it
    /// reports what is left; `scope::STOP_WITHIN` when unset.
    pub stop_within: Option<std::time::Duration>,
    /// Where the instance tells its events: the embedding instance's,
    /// which outlive its runs; one of the run's own when unset.
    pub events: Option<crate::control::events::EventHub>,
    /// The inbound and outbound kinds the embedding host registered.
    pub kinds: crate::embed::kinds::HostKinds,
    /// The embedding host's own admission checks, run after sail's.
    pub admission_hooks: Option<crate::app::inbound::admission::HostHooksRef>,
}

/// The base URL of a Sub-Store backend. It may carry a secret path, so it
/// prints as its host alone.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SubStore(pub String);

impl std::fmt::Debug for SubStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rest = self.0.split_once("://").map_or("", |(_, rest)| rest);
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        write!(f, "SubStore({:?}, path hidden)", host)
    }
}

/// Sub-Store's address inside Surge, Loon and Quantumult X, which only
/// those apps answer.
const SUB_STORE: &str = "sub.store";

impl Host {
    /// The directory data files are looked up in: `data_dir`, or the
    /// executable's.
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf))
                .unwrap_or_default()
        })
    }

    /// `url` as it is downloaded (outbound providers, remote rule-sets): one
    /// whose host is `sub.store` from `sub_store`, its path and query
    /// kept; any other as it is. Without `sub_store`, one of `sub.store`
    /// is an error that says what to do. Errors name the host alone, as
    /// `sub_store` may hold a secret.
    pub fn download_url(&self, url: &str) -> Result<String> {
        let Some((scheme, rest)) = url.split_once("://") else {
            return Ok(url.to_string());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let host = authority.rsplit('@').next().unwrap_or_default();
        // An IPv6 address is not it; else up to the port.
        let host = match host.starts_with('[') {
            true => host,
            false => host.split(':').next().unwrap_or_default(),
        };
        if !host.trim_end_matches('.').eq_ignore_ascii_case(SUB_STORE)
            || !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
        {
            return Ok(url.to_string());
        }
        let base = self
            .sub_store
            .as_ref()
            .map(|s| s.0.as_str())
            .ok_or_else(|| {
                anyhow!(
                    "{}: sub.store is Sub-Store's address inside Surge, Loon and Quantumult X, \
                 which only they answer; set sub_store (sail --sub-store, or the host's start \
                 settings) to the address of a Sub-Store backend of your own, or use the \
                 subscription's own URL",
                    SUB_STORE
                )
            })?;
        let base_host = base
            .split_once("://")
            .filter(|(scheme, rest)| {
                matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
                    && !rest.is_empty()
                    && !rest.starts_with('/')
            })
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
            .ok_or_else(|| anyhow!("sub_store: not an http(s) URL"))?;
        if base.contains(['?', '#']) {
            return Err(anyhow!(
                "sub_store: {}: a base URL has no query or fragment",
                base_host
            ));
        }
        Ok(format!("{}{}", base.trim_end_matches('/'), tail))
    }
}

/// A TUN's name as a start settled it (protocol::tun::inbound::resolve_names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunName {
    pub name: String,
    /// Chosen at start, as none was configured; else configured, or the
    /// default.
    pub chosen: bool,
}

/// Everything an instance runs with that is not its configuration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeEnv {
    pub options: RuntimeOptions,
    pub host: Host,
    /// The Clash API's mode, which rules can match: what the instance
    /// runs in, not what it is configured with.
    pub clash_mode: crate::app::clash_mode::ClashMode,
    /// The network the host is on, which rules and groups match; kept
    /// across reloads.
    pub network: crate::net::network::Network,
    /// `experimental.cache_file`: what is kept across restarts, when
    /// enabled.
    pub cache_file: cache_file::CacheFileSlot,
    /// The root certificates servers are checked against, as the
    /// configuration's `certificate` chose them.
    #[cfg(feature = "tls")]
    pub tls_roots: crate::transport::tls::roots::TrustRoots,
    /// The mark on the sockets sail listens with (Linux): the TUN's
    /// auto_redirect output mark, which keeps replies to clients out of
    /// its redirection, as it keeps the outbounds' connections out.
    pub listen_mark: Option<u32>,
    /// The users inbounds authenticate, by name; kept across reloads.
    pub users: crate::user::UserRegistry,
    /// The numbers the run's connections are listed by, which a host's
    /// kinds are told before sail counts them; kept across reloads.
    pub numbering: crate::app::stat_manager::Numbering,
    /// The LAN devices, by address, when a rule or DNS server needs them;
    /// kept across reloads.
    pub neighbors: crate::net::neighbor::Neighbors,
    /// `dns.reverse_mapping`'s domains by address, which the DNS client
    /// writes as it answers and routing reads; kept across reloads.
    pub reverse_map: crate::sniff::dns::DnsSniffer,
    /// What finds the interface the instance sends through, where it is
    /// detected (`auto_detect_interface`): the instance's one, made the
    /// first time it is asked for and kept across reloads. What a reload
    /// keeps running, an endpoint and the outbounds under it, holds the
    /// one it was built with: were each reload to make another, theirs
    /// would never be looked at again when the network changes.
    pub auto_interface:
        std::sync::Arc<std::sync::OnceLock<std::sync::Arc<crate::net::interface::AutoInterface>>>,
    /// What this instance has changed in the system and not yet undone,
    /// for a sweep should it be killed.
    pub ledger: crate::platform::sweep::Ledger,
    /// What the instance tells as it happens: groups switching, connections
    /// failing (control::events).
    pub events: crate::control::events::EventHub,
    /// The instance's tasks (scope.rs): a stop ends them, a panic in one
    /// is dealt with by its class.
    pub scope: scope::TaskScope,
    /// How to undo what the instance changed in the system, run however
    /// it ends (teardown.rs).
    pub teardown: teardown::Teardown,
    /// The TUNs' names by inbound tag, as the start settled them; a reload
    /// keeps a chosen one.
    pub tun_names: Arc<std::sync::Mutex<std::collections::BTreeMap<String, TunName>>>,
    /// The routes of others auto_route replaced with its own and puts back
    /// when it stops, in words (macOS).
    pub replaced_routes: Arc<std::sync::Mutex<Vec<String>>>,
    /// What holds back connections that have not authenticated under
    /// memory pressure (`inbound.memory_reserve`), when it is on: the
    /// run's, across its reloads.
    pub admission: Option<Arc<crate::app::inbound::admission::Admission>>,
}

pub type SyncRuntimeEnv = Arc<RuntimeEnv>;

impl RuntimeEnv {
    /// The directory data files are looked up in.
    pub fn data_dir(&self) -> PathBuf {
        self.host.data_dir()
    }

    /// `path` in the data directory, unless it is absolute.
    pub fn data_path(&self, path: &str) -> String {
        let p = Path::new(path);
        if p.is_absolute() {
            return path.to_string();
        }
        self.data_dir().join(p).to_string_lossy().to_string()
    }

    /// A certificate or key given inline or as a path; a relative path is
    /// looked up in the data directory.
    ///
    /// The two halves of a keypair are configured the same way and have to
    /// be read the same way. They were not: a certificate was recognised
    /// inline and a key never was, so an inline key became a path under the
    /// data directory made of PEM, and what the operator saw was "no private
    /// keys found" about a key that was right there in the configuration.
    pub fn certificate(&self, value: &str) -> String {
        if value.contains("-----BEGIN") {
            return value.to_string();
        }
        self.data_path(value)
    }
}

/// How a host describes the tuning and host options of an instance in one
/// piece, for hosts that pass them as text (FFI):
///
/// ```json
/// { "profile": "mobile", "set": ["relay.buffer_size=32"],
///   "data_dir": "/var/lib/sail", "cache_dir": "/var/cache/sail",
///   "log_to_system": true, "socket_protect": "/data/protect.sock",
///   "sub_store": "https://sub.example.com/secret",
///   "asset_sources": { "asn.mmdb": "https://example.com/asn.mmdb" },
///   "run_dir": "/run/sail" }
/// ```
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct StartSettings {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub set: Vec<String>,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    /// Whether to log to the platform's system log; the host decides when
    /// unset.
    #[serde(default)]
    pub log_to_system: Option<bool>,
    /// The path of a Unix socket each outbound socket's descriptor is
    /// handed to, with `SCM_RIGHTS`, to be protected from the host's VPN
    /// before it binds or connects; it answers one byte. sing-box's
    /// `protect_path`, for every outbound. Unix only.
    #[serde(default)]
    pub socket_protect: Option<String>,
    /// The base URL of a Sub-Store backend, which `sub.store` stands for.
    #[serde(default)]
    pub sub_store: Option<SubStore>,
    /// Where the Clash API's dashboard is downloaded from by default.
    #[serde(default)]
    pub ui_download_url: Option<String>,
    /// Where each asset is downloaded from, by its name.
    #[serde(default)]
    pub asset_sources: BTreeMap<String, String>,
    /// Where the ledgers of the leftover sweep are kept: a directory, or
    /// `false` for none; the system's when unset.
    #[serde(default)]
    pub run_dir: Option<RunDirSetting>,
}

/// `run_dir` as start settings give it: a directory, or `false` for none.
#[derive(Debug, Clone)]
pub enum RunDirSetting {
    Dir(PathBuf),
    Off,
}

impl<'de> serde::Deserialize<'de> for RunDirSetting {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = RunDirSetting;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a directory, or false for none")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(RunDirSetting::Dir(v.into()))
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                if v {
                    Err(E::invalid_value(serde::de::Unexpected::Bool(true), &self))
                } else {
                    Ok(RunDirSetting::Off)
                }
            }
        }
        d.deserialize_any(Visitor)
    }
}

impl StartSettings {
    pub fn from_json(json: &str) -> Result<Self> {
        let de = &mut serde_json::Deserializer::from_str(json);
        serde_path_to_error::deserialize(de)
            .map_err(|e| anyhow!("start settings: {}: {}", e.path(), e.inner()))
    }

    /// The tuning and host these settings describe.
    pub fn resolve(self) -> Result<(RuntimeOptions, Host)> {
        let profile = match &self.profile {
            Some(p) => p.parse()?,
            None => Profile::default(),
        };
        let mut options = RuntimeOptions::profile(profile);
        // Before the settings, which win.
        options.fit_to_memory(system_memory::total());
        options.set_all(self.set.iter().map(String::as_str))?;
        let socket_protect = self.socket_protect.map(socket_protect).transpose()?;
        Ok((
            options,
            Host {
                data_dir: self.data_dir,
                cache_dir: self.cache_dir,
                log_to_system: self.log_to_system.unwrap_or(false),
                socket_protect,
                platform: None,
                sub_store: self.sub_store,
                ui_download_url: self.ui_download_url,
                asset_sources: self.asset_sources,
                log: None,
                clash_modes: false,
                stop_within: None,
                events: None,
                kinds: Default::default(),
                admission_hooks: None,
                run_dir: match self.run_dir {
                    None => crate::platform::sweep::RunDir::Default,
                    Some(RunDirSetting::Dir(dir)) => crate::platform::sweep::RunDir::Dir(dir),
                    Some(RunDirSetting::Off) => crate::platform::sweep::RunDir::Off,
                },
            },
        ))
    }
}

/// `socket_protect` as start settings give it: a Unix socket's path. An
/// address is a mistake, of a host that still speaks the protocol sail had
/// before sing-box's (the descriptor's number over TCP).
fn socket_protect(path: String) -> Result<crate::net::dial::SocketProtect> {
    if path.parse::<std::net::SocketAddr>().is_ok() {
        return Err(anyhow!(
            "start settings: socket_protect: {:?} is an address; give the path of a Unix socket, \
             which takes each socket's descriptor by SCM_RIGHTS",
            path
        ));
    }
    if path.is_empty() {
        return Err(anyhow!(
            "start settings: socket_protect: empty; give the path of a Unix socket, or leave it out"
        ));
    }
    if !cfg!(unix) {
        return Err(anyhow!(
            "start settings: socket_protect: only supported on Unix"
        ));
    }
    Ok(crate::net::dial::SocketProtect::Unix(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_dir_is_a_directory_or_false() {
        let dir = |json: &str| {
            StartSettings::from_json(json).map(|s| s.resolve().map(|(_, h)| h.run_dir))
        };
        use crate::platform::sweep::RunDir;
        assert_eq!(dir("{}").unwrap().unwrap(), RunDir::Default);
        assert_eq!(
            dir(r#"{"run_dir": "/srv/run"}"#).unwrap().unwrap(),
            RunDir::Dir("/srv/run".into())
        );
        assert_eq!(dir(r#"{"run_dir": false}"#).unwrap().unwrap(), RunDir::Off);
        for wrong in [r#"{"run_dir": true}"#, r#"{"run_dir": 3}"#] {
            let err = dir(wrong).unwrap_err().to_string();
            assert!(
                err.contains("run_dir") && err.contains("a directory, or false for none"),
                "{err}"
            );
        }
    }

    const INLINE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";

    fn env() -> RuntimeEnv {
        RuntimeEnv {
            host: Host {
                data_dir: Some(PathBuf::from("/data")),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn an_inline_key_is_not_mistaken_for_a_path() {
        assert_eq!(env().certificate(INLINE_KEY), INLINE_KEY);
    }

    /// What counts as absolute is the platform's business, and the test has
    /// to ask the same question the code does.
    #[test]
    fn an_absolute_path_is_left_alone() {
        let absolute = if cfg!(windows) {
            r"C:\sail\cert.pem"
        } else {
            "/etc/sail/cert.pem"
        };
        assert_eq!(env().certificate(absolute), absolute);
    }

    #[test]
    fn a_relative_path_is_in_the_data_directory() {
        let resolved = env().certificate("cert.pem");
        assert_eq!(
            PathBuf::from(resolved),
            PathBuf::from("/data").join("cert.pem")
        );
    }

    #[test]
    fn start_settings_resolve_to_tuning_and_host() {
        let (options, host) = StartSettings::from_json(
            r#"{ "profile": "router", "set": ["relay.buffer_size=2"],
                 "data_dir": "/d",
                 "asset_sources": { "asn.mmdb": "https://example.com/asn.mmdb" } }"#,
        )
        .unwrap()
        .resolve()
        .unwrap();
        assert_eq!(options.relay.buffer_size, 2);
        assert_eq!(
            options.relay.buffer_max_size,
            RuntimeOptions::profile(Profile::Router)
                .relay
                .buffer_max_size
        );
        assert_eq!(host.data_dir, Some(PathBuf::from("/d")));
        assert_eq!(
            host.asset_sources["asn.mmdb"],
            "https://example.com/asn.mmdb"
        );
        // socket_protect, Unix-only: socket_protect_is_a_unix_socket_s_path_only.
        let err = StartSettings::from_json(r#"{ "profile": "mobile", "sett": [] }"#).unwrap_err();
        assert!(err.to_string().contains("sett"), "{}", err);
    }

    #[test]
    fn socket_protect_is_a_unix_socket_s_path_only() {
        let resolve = |json: &str| {
            StartSettings::from_json(json)
                .unwrap()
                .resolve()
                .map(|(_, host)| host.socket_protect)
                .map_err(|e| e.to_string())
        };
        // The protocol over TCP is gone, and an address is a mistake.
        for address in ["127.0.0.1:9000", "[::1]:9000"] {
            let err = resolve(&format!(r#"{{ "socket_protect": "{}" }}"#, address)).unwrap_err();
            assert_eq!(
                err,
                format!(
                    "start settings: socket_protect: \"{}\" is an address; give the path of a \
                     Unix socket, which takes each socket's descriptor by SCM_RIGHTS",
                    address
                )
            );
        }
        assert!(resolve(r#"{ "socket_protect": "" }"#)
            .unwrap_err()
            .contains("empty"));
        let path = resolve(r#"{ "socket_protect": "protect.sock" }"#);
        if cfg!(unix) {
            assert_eq!(
                path,
                Ok(Some(crate::net::dial::SocketProtect::Unix(
                    "protect.sock".into()
                )))
            );
        } else {
            assert_eq!(
                path,
                Err("start settings: socket_protect: only supported on Unix".into())
            );
        }
        assert_eq!(resolve("{}"), Ok(None));
    }

    #[test]
    fn sub_store_is_the_operator_s_backend() {
        let host = |base: Option<&str>| Host {
            sub_store: base.map(|b| SubStore(b.to_string())),
            ..Default::default()
        };
        let url = "https://sub.store/download/collection/all?target=Surge";
        let secret = host(Some("https://sub.example.com:8443/s3cret/"));
        assert_eq!(
            secret.download_url(url).unwrap(),
            "https://sub.example.com:8443/s3cret/download/collection/all?target=Surge"
        );
        assert_eq!(
            secret.download_url("http://SUB.STORE:80").unwrap(),
            "https://sub.example.com:8443/s3cret"
        );
        // Others as they are.
        for other in [
            "https://sub.store.example.com/a",
            "https://a.example/sub.store",
        ] {
            assert_eq!(secret.download_url(other).unwrap(), other);
        }
        let err = host(None).download_url(url).unwrap_err().to_string();
        assert!(err.contains("set sub_store"), "{}", err);
        let err = host(Some("sub.example.com/s3cret"))
            .download_url(url)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("s3cret"), "{}", err);
        let debug = format!("{:?}", secret);
        assert!(
            debug.contains("sub.example.com") && !debug.contains("s3cret"),
            "{}",
            debug
        );
    }
}
