//! Instances by handle: made with their settings and the host's callbacks,
//! started from a configuration, reloaded, stopped and freed, any number
//! at once, any number of times. Each is a `sail::embed::Instance`; this
//! is its C face.

use std::ffi::c_char;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use sail::embed;

use crate::events::Events;
use crate::handles::Table;
use crate::platform::{Callbacks, FfiPlatform, SailPlatform};
use crate::{call, json, opt_str_arg, out_json, out_value, str_arg, Failure};

/// An instance, as the host holds it; 0 is none.
pub type SailInstance = u64;

static INSTANCES: Mutex<Table<Instance>> = Mutex::new(Table::new());

/// The lines an instance keeps of its log, unless the settings say: what
/// both sing-box apps keep (their `LogMaxLines`).
const LOG_LINES: usize = 3000;

/// The stack of each worker thread, unless the settings say: tokio's.
const STACK_SIZE: usize = 2 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn instance(handle: SailInstance) -> Result<Arc<Instance>, Failure> {
    lock(&INSTANCES)
        .get(handle)
        .ok_or_else(Failure::no_instance)
}

/// What a handle names: an instance here, or one a command service client
/// reaches in another process.
pub(crate) enum Target {
    Local(Arc<Instance>),
    #[cfg(feature = "command-server")]
    Remote(Arc<crate::command::client::Client>),
}

pub(crate) fn target(handle: SailInstance) -> Result<Target, Failure> {
    #[cfg(feature = "command-server")]
    if handle & crate::handles::CLIENT_TAG != 0 {
        return crate::command::client::client(handle)
            .map(Target::Remote)
            .ok_or_else(Failure::no_instance);
    }
    instance(handle).map(Target::Local)
}

/// The instance here `handle` names: a client's runs in another process,
/// where what only it does is done.
pub(crate) fn local(handle: SailInstance) -> Result<Arc<Instance>, Failure> {
    match target(handle)? {
        Target::Local(instance) => Ok(instance),
        #[cfg(feature = "command-server")]
        Target::Remote(_) => Err(Failure::new(
            crate::SAIL_ERR_UNSUPPORTED,
            "the instance runs in another process: this is its host's to call there",
        )),
    }
}

/// What an instance is started from.
enum Source {
    Text(String),
    File(String),
}

pub(crate) struct Instance {
    pub id: sail::RuntimeId,
    core: embed::Instance,
    pub log: Arc<sail::app::logger::InstanceLog>,
    callbacks: Arc<Callbacks>,
    pub events: Events,
    /// The command service it serves, if it does.
    #[cfg(feature = "command-server")]
    server: Mutex<Option<crate::command::server::Server>>,
    #[allow(dead_code)]
    me: Weak<Instance>,
}

/// The settings the FFI reads before the core's.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct FfiSettings {
    log_lines: Option<usize>,
    worker_threads: Option<usize>,
    stack_size: Option<usize>,
    stop_within_ms: Option<u64>,
}

/// The state, as the host is told it.
pub(crate) fn state_json(state: &embed::State) -> json::State {
    let failure = match state {
        embed::State::Failed(e) => Some(e),
        _ => None,
    };
    json::State {
        state: state.name().to_string(),
        error: failure.map(|e| e.message().to_string()),
        error_kind: failure.map(|e| e.code().to_string()),
        left: failure
            .map(|e| e.left().iter().map(json::Left::of).collect())
            .unwrap_or_default(),
        started_at_ms: match state {
            embed::State::Running { since } => Some(
                since
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64),
            ),
            _ => None,
        },
    }
}

impl Instance {
    fn new(settings: Option<&str>, platform: SailPlatform) -> Result<Arc<Self>, Failure> {
        let (ffi, core) = split_settings(settings)?;
        let settings = crate::tools::parse_settings(core.as_deref())?;
        let mut options = embed::Options::new();
        // A host that says nothing gets the profile's threads, as the CLI
        // and the embedding do.
        if let Some(n) = ffi.worker_threads.filter(|&n| n > 0) {
            options = options.threads(embed::Threads::Workers(
                n,
                ffi.stack_size.unwrap_or(STACK_SIZE),
            ));
        }
        if let Some(ms) = ffi.stop_within_ms {
            options = options.stop_within(std::time::Duration::from_millis(ms));
        }
        let callbacks = Callbacks::new(platform);
        let log = sail::app::logger::InstanceLog::new(ffi.log_lines.unwrap_or(LOG_LINES));
        let core = embed::Instance::new(
            options
                .settings(settings)
                .platform(Arc::new(FfiPlatform {
                    callbacks: callbacks.clone(),
                }))
                // As libbox's apps have them, a Clash API or not.
                .clash_modes(true)
                .log(log.clone()),
        )?;
        let id = core.id();
        let events = Events::new(id)?;
        Ok(Arc::new_cyclic(|me| Instance {
            id,
            core,
            log,
            callbacks,
            events,
            #[cfg(feature = "command-server")]
            server: Mutex::new(None),
            me: me.clone(),
        }))
    }

    /// The state now, as the host is told it.
    pub fn state(&self) -> json::State {
        state_json(&self.core.state())
    }

    /// The state, as each change is followed.
    pub fn states(&self) -> tokio::sync::watch::Receiver<embed::State> {
        self.core.states()
    }

    /// Whether this thread is one of the instance's own: the one starting
    /// it, or its runtime's. Waiting on the instance there would wait on
    /// itself.
    pub fn on_own_thread(&self) -> bool {
        self.core.on_own_thread()
    }

    /// Whether the host opens the TUN device, and protects sockets.
    pub fn host_callbacks(&self) -> (bool, bool) {
        self.callbacks.given()
    }

    /// The instance, as Rust hosts hold it.
    pub fn core(&self) -> &embed::Instance {
        &self.core
    }

    /// What controls the instance, while it runs.
    pub fn manager(&self) -> Result<Arc<sail::RuntimeManager>, Failure> {
        Ok(self.core.manager()?)
    }

    /// Runs `task` on the instance's runtime, and waits for it.
    pub fn run<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<sail::RuntimeManager>) -> futures::future::BoxFuture<'static, T>,
    ) -> Result<T, Failure> {
        Ok(self.core.blocking_with_manager(task)?)
    }

    fn start(&self, source: Source) -> Result<(), Failure> {
        Ok(self.core.blocking_start(match source {
            Source::Text(text) => embed::Config::Json(text),
            Source::File(path) => embed::Config::File(path.into()),
        })?)
    }

    /// Asks the instance to stop, then waits up to `wait` for it to have
    /// stopped; on a thread of its own, it does not wait.
    pub fn stop(&self, wait: Duration) -> Result<(), Failure> {
        Ok(self.core.blocking_stop(wait)?)
    }

    /// Stops it as the host does, for a command service client.
    #[cfg(feature = "command-server")]
    pub fn service_stop(&self) -> Result<(), Failure> {
        match self.callbacks.service_stop() {
            Some(crate::SAIL_OK) => Ok(()),
            Some(code) => Err(Failure::new(code, "the host did not stop the instance")),
            None => self.stop(Duration::ZERO),
        }
    }

    /// Reloads it as the host does, for a command service client.
    #[cfg(feature = "command-server")]
    pub fn service_reload(&self) -> Result<(), Failure> {
        match self.callbacks.service_reload() {
            Some(crate::SAIL_OK) => Ok(()),
            Some(code) => Err(Failure::new(code, "the host did not reload the instance")),
            None => self.reload(None),
        }
    }

    pub(crate) fn reload(&self, config: Option<String>) -> Result<(), Failure> {
        self.reload_report(config).map(|_| ())
    }

    /// Adds the inbound `inbound`, sing-box's JSON of one, to the running
    /// instance.
    pub(crate) fn add_inbound(&self, inbound: &str) -> Result<(), Failure> {
        let inbound: serde_json::Value = serde_json::from_str(inbound)
            .map_err(|e| Failure::invalid(format!("inbound: {}", e)))?;
        self.wait_on(self.core.add_inbound(inbound))
    }

    /// Removes the inbound `tag`; how many connections it closed.
    pub(crate) fn remove_inbound(&self, tag: &str) -> Result<usize, Failure> {
        self.wait_on(self.core.remove_inbound(tag))
    }

    /// Waits on `call` on this thread, unless it is one of the instance's
    /// own, where it would wait on itself.
    pub(crate) fn wait_on<T>(
        &self,
        call: impl std::future::Future<Output = Result<T, embed::Error>>,
    ) -> Result<T, Failure> {
        if self.on_own_thread() {
            return Err(Failure::new(
                crate::SAIL_ERR_WRONG_THREAD,
                "called on a thread of the instance's own, where it would wait on itself",
            ));
        }
        Ok(futures::executor::block_on(call)?)
    }

    /// Reloads it, and tells what the reload did.
    pub(crate) fn reload_report(
        &self,
        config: Option<String>,
    ) -> Result<json::ReloadReport, Failure> {
        self.reload_rechecking(config, Default::default())
    }

    /// `reload_report`, the connections open treated as `options` says.
    pub(crate) fn reload_rechecking(
        &self,
        config: Option<String>,
        options: embed::ReloadOptions,
    ) -> Result<json::ReloadReport, Failure> {
        if self.on_own_thread() {
            return Err(Failure::new(
                crate::SAIL_ERR_WRONG_THREAD,
                "called on a thread of the instance's own, where it would wait on itself",
            ));
        }
        let report = futures::executor::block_on(
            self.core
                .reload_rechecking(config.map(embed::Config::Json), options),
        )?;
        Ok(json::ReloadReport::of(&report))
    }
}

/// The FFI's own settings, and the rest, the core's, as JSON.
fn split_settings(settings: Option<&str>) -> Result<(FfiSettings, Option<String>), Failure> {
    let Some(settings) = settings else {
        return Ok((FfiSettings::default(), None));
    };
    let mut all: serde_json::Map<String, serde_json::Value> = serde_json::from_str(settings)
        .map_err(|e| Failure::new(crate::SAIL_ERR_CONFIG, format!("settings: {}", e)))?;
    let mut ffi = serde_json::Map::new();
    for key in [
        "log_lines",
        "worker_threads",
        "stack_size",
        "stop_within_ms",
    ] {
        if let Some(value) = all.remove(key) {
            ffi.insert(key.into(), value);
        }
    }
    let ffi: FfiSettings = serde_json::from_value(serde_json::Value::Object(ffi))
        .map_err(|e| Failure::new(crate::SAIL_ERR_CONFIG, format!("settings: {}", e)))?;
    Ok((ffi, Some(serde_json::Value::Object(all).to_string())))
}

/// Makes an instance, idle until started.
///
/// @param settings JSON, or null for the defaults: the core's
///     (`{"profile": "mobile", "set": ["relay.buffer_size=32"], "data_dir",
///     "cache_dir", "log_to_system", "socket_protect", "sub_store"}`; on
///     iOS and Android the "mobile" profile and the system log unless
///     said), and the FFI's: `log_lines`, the lines of its log kept
///     (3000), `worker_threads`, 0 or unset for the profile's,
///     `stack_size` of each worker, in bytes, and `stop_within_ms`, how
///     long a stop waits for the instance's tasks to end (2000).
///     `socket_protect` is the path of a Unix socket each outbound
///     socket's descriptor is handed to by `SCM_RIGHTS`, before it binds
///     or connects, and which answers one byte once it is protected
///     (sing-box's `protect_path`); an address is an error.
/// @param platform What the host does for it, or null for nothing; read
///     during the call, its callbacks kept until `release`.
/// @param out Takes the instance's handle.
/// @param err Takes the message of a failure, or null.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_new(
    settings: *const c_char,
    platform: *const SailPlatform,
    out: *mut SailInstance,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        if out.is_null() {
            return Err(Failure::invalid("the out pointer is null"));
        }
        let settings = unsafe { opt_str_arg(settings, "settings") }?;
        let platform = unsafe { SailPlatform::read(platform) }?;
        let instance = Instance::new(settings, platform)?;
        out_value(out, lock(&INSTANCES).insert(instance))
    })
}

/// Starts the instance with the configuration `config`, in any format sail
/// reads (sing-box's JSON, Clash's YAML, a Surge profile). Returns once it
/// runs, or failed; it runs on a thread of its own until stopped.
///
/// @param err Takes why it did not start, or null.
/// @return SAIL_ERR_STATE when it is starting or running already;
///     SAIL_ERR_CANCELLED when stopped while it started.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_start(
    instance: SailInstance,
    config: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let config = unsafe { str_arg(config, "config") }?.to_string();
        local(instance)?.start(Source::Text(config))
    })
}

/// Starts the instance as `sail_instance_start` does, from the file at
/// `path`, in the format its extension names; a reload without a
/// configuration reads it again.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_start_file(
    instance: SailInstance,
    path: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let path = unsafe { str_arg(path, "path") }?.to_string();
        local(instance)?.start(Source::File(path))
    })
}

/// Reloads the running instance with `config`, or, when null, from the
/// file it was started from. What did not change goes on: connections,
/// selections, the delays measured. A reload that fails leaves the
/// instance as it was.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_reload(
    instance: SailInstance,
    config: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let config = unsafe { opt_str_arg(config, "config") }?.map(str::to_owned);
        match target(instance)? {
            Target::Local(instance) => instance.reload(config),
            #[cfg(feature = "command-server")]
            Target::Remote(client) => match config {
                None => client.managed(|mut m| async move {
                    m.reload_service(crate::command::proto::Empty {}).await
                }),
                Some(_) => Err(Failure::new(
                    crate::SAIL_ERR_UNSUPPORTED,
                    "a client reloads its instance from its file only",
                )),
            },
        }
    })
}

/// `sail_instance_reload`, telling what it did, as JSON: `{"path": "full" |
/// "inbounds_only", "inbounds": [{"tag", "change": "untouched" |
/// "reloaded" | "added" | "removed" | "replaced" | "lost"}], "notes":
/// [{"kind": "endpoint_keeps_defaults", "text", "endpoint", "options"}],
/// "recheck": {"closed": [{"id", "rule"}], "differ": [{"id", "old",
/// "new"}]}, "user_limits_dropped": [user]}`, `recheck` only where
/// `sail_instance_reload_with` asked for one; `user_limits_dropped`, the
/// users whose limits the host set the reload dropped, changing what the
/// configuration sets for them. Only the inbounds removed and replaced had
/// their connections closed; with `inbounds_only`, the outbounds, groups,
/// DNS and routing, and what they held, are those that ran. A reload that
/// fails tells nothing and leaves the instance as it was.
///
/// @return SAIL_ERR_NEEDS_RESTART when it adds, removes or changes what
///     only a start sets up (a TUN); SAIL_ERR_INBOUND_LOST when an inbound
///     it was to replace on its own address listens no more;
///     SAIL_ERR_UNSUPPORTED through a command service client.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_reload_report(
    instance: SailInstance,
    config: *const c_char,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let config = unsafe { opt_str_arg(config, "config") }?.map(str::to_owned);
        let report = match target(instance)? {
            Target::Local(instance) => instance.reload_report(config)?,
            #[cfg(feature = "command-server")]
            Target::Remote(_) => {
                return Err(Failure::new(
                    crate::SAIL_ERR_UNSUPPORTED,
                    "a reload's report is not told through a command service client",
                ))
            }
        };
        out_json(out, &report)
    })
}

/// `sail_instance_reload_report`, the connections open treated as
/// `options` says, JSON, or as when null: `{"recheck_open": "keep" |
/// "close_rejected"}`. With `close_rejected` each connection the rules
/// routed is matched again, once the reload took, against the routing it
/// leaves, with no side effect: those the rules now reject or drop are
/// closed and listed in the report's `recheck.closed`, with the index of
/// the rule in `route.rules`; those they send to another outbound go on,
/// and are listed in `recheck.differ`. `keep`, the default, leaves them.
///
/// @return SAIL_ERR_INVALID_ARGUMENT when `options` is not such JSON, a key
///     unknown; as `sail_instance_reload_report` otherwise.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_reload_with(
    instance: SailInstance,
    config: *const c_char,
    options: *const c_char,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let config = unsafe { opt_str_arg(config, "config") }?.map(str::to_owned);
        let options = match unsafe { opt_str_arg(options, "options") }? {
            None => Default::default(),
            Some(text) => json::ReloadOptions::parse(text.as_bytes())
                .map_err(|e| Failure::invalid(format!("options: {}", e)))?,
        };
        let report = match target(instance)? {
            Target::Local(instance) => instance.reload_rechecking(config, options)?,
            #[cfg(feature = "command-server")]
            Target::Remote(_) => {
                return Err(Failure::new(
                    crate::SAIL_ERR_UNSUPPORTED,
                    "a reload's report is not told through a command service client",
                ))
            }
        };
        out_json(out, &report)
    })
}

/// Stops the instance, and waits up to `timeout_ms` for it to have
/// stopped; 0 asks without waiting. A stop while it starts ends the
/// start. Stopping one not running does nothing. Called on a thread of
/// the instance's own (in `protect_socket` or `open_tun`), it asks
/// without waiting.
///
/// @return SAIL_OK once stopped, or asked; SAIL_ERR_TIMEOUT if it is still
///     stopping.
#[no_mangle]
pub extern "C" fn sail_instance_stop(
    instance: SailInstance,
    timeout_ms: u32,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || match target(instance)? {
        Target::Local(instance) => instance.stop(Duration::from_millis(u64::from(timeout_ms))),
        // The host stops it there, as libbox's ServiceStop asks.
        #[cfg(feature = "command-server")]
        Target::Remote(client) => client
            .managed(|mut m| async move { m.stop_service(crate::command::proto::Empty {}).await }),
    })
}

/// Frees the instance: the handle names nothing from now on. It is asked
/// to stop, without waiting, and its subscriptions end, each context
/// released. The platform's `release` is called once it has stopped and
/// sail calls none of its callbacks any more. Freeing a handle freed, or
/// 0, does nothing.
#[no_mangle]
pub extern "C" fn sail_instance_free(instance: SailInstance) {
    call(std::ptr::null_mut(), || {
        #[cfg(feature = "command-server")]
        if let Some(client) = crate::command::client::remove(instance) {
            client.events.close();
            return Ok(());
        }
        let Some(instance) = lock(&INSTANCES).remove(instance) else {
            return Ok(());
        };
        let _ = instance.stop(Duration::ZERO);
        #[cfg(feature = "command-server")]
        drop(lock(&instance.server).take());
        instance.events.close();
        Ok(())
    });
}

/// Serves the instance to the app's other processes, as libbox's command
/// server does: a client (`sail_client_connect`) there then answers the
/// same calls as the instance. It serves while the instance is idle or
/// failed too, until freed, or this is called again; null `options`
/// stops serving.
///
/// @param options JSON: `{"path"}`, a unix socket (an iOS app's group
///     container's, an Android app's files directory's), made readable
///     and writable by the app's user only, a stale file there replaced,
///     the path at most 103 bytes on Darwin and 107 on Linux, on Unix
///     only; or `{"port", "secret"}`, loopback TCP, every call carrying
///     the secret (32 characters at least, as `sail generate secret`
///     makes), the only one on Windows.
/// @return SAIL_ERR_STATE when a service answers at the path already;
///     SAIL_ERR_CONFIG for options that do not read; SAIL_ERR_UNSUPPORTED
///     in a build without the command service, or for a path on
///     Windows.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_serve(
    instance: SailInstance,
    options: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let options = unsafe { opt_str_arg(options, "options") }?;
        let instance = local(instance)?;
        #[cfg(feature = "command-server")]
        {
            // The one served before goes first: a path is freed for its
            // successor.
            drop(lock(&instance.server).take());
            if let Some(options) = options {
                let address = crate::command::Address::read(options, false)
                    .map_err(crate::command::listen_failure)?;
                #[cfg(not(unix))]
                if !matches!(address, crate::command::Address::Tcp(..)) {
                    return Err(crate::command::off_unix());
                }
                let server = crate::command::server::serve(&instance, address)?;
                *lock(&instance.server) = Some(server);
            }
            Ok(())
        }
        #[cfg(not(feature = "command-server"))]
        {
            let _ = (options, instance);
            Err(Failure::new(
                crate::SAIL_ERR_UNSUPPORTED,
                "this build has no command service",
            ))
        }
    })
}

/// Connects to the command service an instance serves in another process
/// (`sail_instance_serve`), as libbox's command client does: the handle
/// answers the same calls an instance's does, and is freed with
/// `sail_instance_free`. A client does not reconnect: when the connection
/// is lost, its calls fail, and each subscription gets one
/// SAIL_EVENT_DISCONNECTED; the host connects again.
///
/// @param options JSON: `{"path"}`, `{"port", "secret"}`, or `{"fd"}`, a
///     connected socket the host has (a macOS system extension's, passed
///     over XPC), which the client owns from then on. `{"path"}` and
///     `{"fd"}` are Unix only: on Windows only `{"port", "secret"}`.
/// @param out Takes the client's handle.
/// @return SAIL_ERR_IO when no service answers; SAIL_ERR_UNSUPPORTED in a
///     build without the command service, or for a path or descriptor on
///     Windows.
#[no_mangle]
pub unsafe extern "C" fn sail_client_connect(
    options: *const c_char,
    out: *mut SailInstance,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        if out.is_null() {
            return Err(Failure::invalid("the out pointer is null"));
        }
        let options = unsafe { str_arg(options, "options") }?;
        #[cfg(feature = "command-server")]
        {
            out_value(out, crate::command::client::connect(options)?)
        }
        #[cfg(not(feature = "command-server"))]
        {
            let _ = options;
            Err(Failure::new(
                crate::SAIL_ERR_UNSUPPORTED,
                "this build has no command service",
            ))
        }
    })
}

/// The instance's state, as JSON: `{"state": "idle" | "starting" |
/// "running" | "stopping" | "stopped" | "failed", "error": why it failed,
/// or null, "error_kind": the failure's kind (`panicked`, `config`,
/// `tun_name_taken`, ...), or null, "left": what the failed run's teardown
/// left in the system, as `sail_instance_stop_report` gives it (empty when
/// nothing is), "started_at_ms": when it last started running, or null}`.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_state(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let state = match target(instance)? {
            Target::Local(instance) => instance.state(),
            #[cfg(feature = "command-server")]
            Target::Remote(client) => json::State::from(client.unary(|mut s| async move {
                s.get_service_status(crate::command::proto::Empty {}).await
            })?),
        };
        out_json(out, &state)
    })
}

/// What the instance's last stop, or the end of its last run, could not
/// end or undo, as JSON: `{"tasks": [{"name", "count"}], "waited_ms",
/// "left": [{"kind": "tun" | "route" | "rule" | "dns" | "nft" | "wfp" |
/// "file" | "task", "resource", "why", "clear": the command that clears
/// it by hand, or null}]}`; `null` before any stop. A failed or stopped
/// instance's is kept until it starts again.
///
/// @return SAIL_ERR_UNSUPPORTED through a command service client.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_stop_report(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let report = match target(instance)? {
            Target::Local(instance) => instance
                .core
                .stop_report()
                .map(|r| json::StopReport::of(&r)),
            #[cfg(feature = "command-server")]
            Target::Remote(_) => {
                return Err(Failure::new(
                    crate::SAIL_ERR_UNSUPPORTED,
                    "a stop report is not told through a command service client",
                ))
            }
        };
        out_json(out, &report)
    })
}

#[cfg(test)]
pub(crate) fn live_instances() -> usize {
    lock(&INSTANCES).values().count()
}

#[cfg(test)]
pub(crate) fn ids_held() -> usize {
    embed::ids_held()
}
