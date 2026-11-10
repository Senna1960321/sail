//! sing-box's `experimental.cache_file`: what an instance keeps across
//! restarts, in one embedded database. The selections of selector groups,
//! the Clash API's mode, and with `store_fakeip`, the fake IPs handed out.
//! Without it, nothing is kept, as in sing-box.
//!
//! One file per instance: redb locks it, so a second instance, or process,
//! given the same file fails to start rather than share it, once it has
//! waited as long as sing-box does for the lock. A reload with the same
//! file goes on with the database already open; the file is closed as soon
//! as the instance stops, or a reload moves to another, not when the last
//! of what used it goes, so that a restart finds it free. A file that
//! cannot be read is set aside and started afresh, as sing-box resets one.
//!
//! Fake IPs are written by a thread of the file's own, as they are handed
//! out: what has queued up is committed in one transaction, the addresses
//! with the cursor, so that the file always holds a state the store was in.
//! With `store_dns`, the DNS answers kept are written by it too, and those
//! long expired are pruned as sing-box prunes them.
//!
//! The traffic of each user, inbound and outbound is written every minute
//! and as the instance stops, as sing-box's ssm-api keeps its users'.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwapOption;
use redb::{
    Database, DatabaseError, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use tracing::{debug, warn};

use super::RuntimeEnv;
use crate::config::model::CacheFileOptions;

/// The file's name when `path` is not set, in the host's cache directory
/// or the data directory; sing-box's.
const DEFAULT_NAME: &str = "cache.db";

/// Group tag to the name of the outbound selected.
const SELECTED: &str = "selected";
/// `clash_mode`, and `fakeip_ranges`: the ranges the fake IPs are of.
const META: &str = "meta";
/// A fake IP's address (4 or 16 bytes) to its domain, and the order it
/// was handed out in.
const FAKEIP: &str = "fakeip";
/// 4 or 6 to the last address of that family handed out.
const FAKEIP_CURSOR: &str = "fakeip_cursor";
/// A DNS answer's key (server, name, type, client subnet) to the message
/// and when it expires, in milliseconds since the Unix epoch.
const DNS: &str = "dns";
/// `user:`, `inbound:` or `outbound:` and a name or tag, to the bytes up
/// and down and the TCP and UDP sessions counted.
const TRAFFIC: &str = "traffic";
/// A smart group's tag to what it remembers of its sites (JSON), and
/// `SMART_SALT` to the salt their keys are hashed with.
const SMART: &str = "smart";
const SMART_SALT: &str = "\0salt";

/// How often what the instance keeps (`Keep`) is written, when it changed:
/// a judgment, not measured. Up to a megabyte a group rewritten every
/// minute is too much flash and battery on a phone.
pub const KEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// What keeps a state of its own in the cache file, written every
/// `KEEP_INTERVAL` when it changed, as the instance stops, at the host's
/// sleep, and before a reload rebuilds it.
pub trait Keep: Send + Sync {
    /// Writes the state to `cache`, if it changed since the last write.
    fn keep(&self, cache: &CacheFile);
}

/// The instance's cache file, as its configuration has it; none without
/// one. Shared by what the instance builds, and replaced by a reload.
#[derive(Clone, Default)]
pub struct CacheFileSlot(
    Arc<ArcSwapOption<CacheFile>>,
    Arc<Mutex<Vec<std::sync::Weak<dyn Keep>>>>,
);

impl std::fmt::Debug for CacheFileSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.load().as_deref() {
            Some(cache) => write!(f, "CacheFileSlot({})", cache.path().display()),
            None => write!(f, "CacheFileSlot(None)"),
        }
    }
}

impl CacheFileSlot {
    pub fn get(&self) -> Option<Arc<CacheFile>> {
        self.0.load_full()
    }

    /// The cache file `options` describe, in place until the guard is
    /// dropped unless it is kept: a reload that fails leaves the file it
    /// found. The same file is not opened again.
    pub fn replace(
        &self,
        options: Option<&CacheFileOptions>,
        env: &RuntimeEnv,
    ) -> Result<CacheFileGuard> {
        let next = match options.filter(|o| o.enabled) {
            None => None,
            Some(options) => {
                let path = path(options, env);
                let current = self.get();
                let shared = match current.as_ref().filter(|c| c.shared.path == path) {
                    Some(current) => current.shared.clone(),
                    None => Shared::open(path)?,
                };
                Some(Arc::new(CacheFile {
                    shared,
                    id: options.cache_id.clone().unwrap_or_default(),
                    store_fakeip: options.store_fakeip,
                    store_dns: options.store_dns,
                }))
            }
        };
        let previous = self.0.swap(next);
        Ok(CacheFileGuard {
            slot: self.clone(),
            previous: Some(previous),
        })
    }
}

/// The cache file a [`CacheFileSlot::replace`] replaced, put back on drop.
pub struct CacheFileGuard {
    slot: CacheFileSlot,
    previous: Option<Option<Arc<CacheFile>>>,
}

impl CacheFileGuard {
    /// Keeps the new file; the old one is closed, if it is another.
    pub fn keep(mut self) {
        if let Some(previous) = self.previous.take() {
            close_unless_same(previous.as_deref(), self.slot.get().as_deref());
        }
    }
}

impl Drop for CacheFileGuard {
    /// Puts the old file back; the new one is closed, if it is another.
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            let new = self.slot.0.swap(previous.clone());
            close_unless_same(new.as_deref(), previous.as_deref());
        }
    }
}

/// Closes `file` unless it is the database `other` is of.
fn close_unless_same(file: Option<&CacheFile>, other: Option<&CacheFile>) {
    if let Some(file) = file {
        if !other.is_some_and(|other| Arc::ptr_eq(&file.shared, &other.shared)) {
            file.shared.close();
        }
    }
}

impl CacheFileSlot {
    /// `keeper` writes its state from now on, until it is dropped.
    pub fn register(&self, keeper: std::sync::Weak<dyn Keep>) {
        let mut keepers = self.1.lock().unwrap_or_else(|e| e.into_inner());
        keepers.retain(|k| k.strong_count() > 0);
        keepers.push(keeper);
    }

    /// Has every keeper write what changed, now; nothing without a file.
    pub fn store_kept(&self) {
        let Some(cache) = self.get() else {
            return;
        };
        let keepers: Vec<_> = {
            let mut keepers = self.1.lock().unwrap_or_else(|e| e.into_inner());
            keepers.retain(|k| k.strong_count() > 0);
            keepers.iter().filter_map(|k| k.upgrade()).collect()
        };
        for keeper in keepers {
            keeper.keep(&cache);
        }
    }

    /// Writes what the keepers changed every `KEEP_INTERVAL`, on a
    /// blocking thread, as the traffic's writes run.
    pub fn kept_task(&self) -> crate::Runner {
        let slot = self.clone();
        Box::pin(async move {
            let mut interval = tokio::time::interval(KEEP_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                let slot = slot.clone();
                let _ = crate::runtime::scope::spawn_blocking("cache_file: kept", move || {
                    slot.store_kept()
                })
                .await;
            }
        })
    }

    /// Closes the file, as the instance stops: what still holds it finds
    /// it closed.
    pub fn close(&self) {
        if let Some(file) = self.0.swap(None) {
            file.shared.close();
        }
    }
}

/// `path`, in the host's cache directory, or the data directory, unless
/// it is absolute.
fn path(options: &CacheFileOptions, env: &RuntimeEnv) -> PathBuf {
    let name = options.path.as_deref().unwrap_or(DEFAULT_NAME);
    let dir = env.host.cache_dir.clone().unwrap_or_else(|| env.data_dir());
    dir.join(name)
}

pub struct CacheFile {
    shared: Arc<Shared>,
    /// `cache_id`: what the configuration keeps is apart from what others
    /// sharing the file keep under theirs.
    id: String,
    /// Whether fake IPs are kept.
    pub store_fakeip: bool,
    /// Whether DNS answers are kept.
    pub store_dns: bool,
}

/// The open database, which reloads with the same file go on with.
struct Shared {
    /// Tells this opening apart from any other, for what writes to it.
    serial: u64,
    path: PathBuf,
    /// None once closed.
    db: Arc<RwLock<Option<Database>>>,
    /// Feeds the thread that writes fake IPs and DNS answers; taken on
    /// close, which ends it.
    writes: Mutex<Option<mpsc::Sender<Write>>>,
    /// The DNS tables pruned, with how long after expiring an answer is
    /// still of use: the optimistic timeout.
    pruned: Arc<Mutex<std::collections::HashMap<String, Duration>>>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

/// How long a file another instance or process holds is waited for, as
/// sing-box waits (ten tries of a second each).
#[cfg(not(test))]
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

impl Shared {
    fn open(path: PathBuf) -> Result<Arc<Self>> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cache_file: create {}", dir.display()))?;
        }
        let waited = std::time::Instant::now();
        let db = loop {
            match Database::create(&path) {
                Ok(db) => break db,
                Err(DatabaseError::DatabaseAlreadyOpen) if waited.elapsed() < LOCK_WAIT => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(DatabaseError::DatabaseAlreadyOpen) => {
                    return Err(anyhow!(
                        "cache_file: {} is in use by another instance",
                        path.display()
                    ))
                }
                Err(e) => {
                    // Broken, or of a format this redb does not read: set
                    // aside, as sing-box resets a file it cannot open.
                    let aside = path.with_extension("db.broken");
                    warn!(
                        "cache_file: {} cannot be read ({}); moved to {} and started afresh",
                        path.display(),
                        e,
                        aside.display()
                    );
                    std::fs::rename(&path, &aside)
                        .with_context(|| format!("cache_file: move {} aside", path.display()))?;
                    break Database::create(&path)
                        .with_context(|| format!("cache_file: create {}", path.display()))?;
                }
            }
        };
        debug!("cache_file: {}", path.display());
        let db = Arc::new(RwLock::new(Some(db)));
        let (writes, queue) = mpsc::channel();
        let pruned = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let writer = std::thread::Builder::new()
            .name("sail-cache-file".into())
            .spawn({
                let (db, pruned) = (db.clone(), pruned.clone());
                let log = crate::app::logger::current();
                move || {
                    let _log = crate::app::logger::enter(log);
                    write(&db, queue, &pruned)
                }
            })
            .context("cache_file: start its writer")?;
        static SERIAL: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);
        Ok(Arc::new(Shared {
            serial: SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            path,
            db,
            writes: Mutex::new(Some(writes)),
            pruned,
            writer: Mutex::new(Some(writer)),
        }))
    }
}

impl Shared {
    /// Writes what is queued, and closes the file, which frees it.
    fn close(&self) {
        drop(self.writes.lock().unwrap_or_else(|e| e.into_inner()).take());
        if let Some(writer) = self.writer.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = writer.join();
        }
        if self
            .db
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .is_some()
        {
            debug!("cache_file: {} closed", self.path.display());
        }
    }

    /// Runs `f` on the database, unless it is closed.
    fn with<T>(&self, f: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
        with(&self.db, f)
    }
}

fn with<T>(db: &RwLock<Option<Database>>, f: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
    match db.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(db) => f(db),
        None => Err(anyhow!("cache_file: closed")),
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close();
    }
}

impl CacheFile {
    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    /// The name of table `name` for this configuration's `cache_id`.
    fn table(&self, name: &str) -> String {
        table(name, &self.id)
    }

    fn get_str(&self, name: &str, key: &str) -> Result<Option<String>> {
        let table = self.table(name);
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            let table = match tx.open_table(TableDefinition::<&str, &str>::new(&table)) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            Ok(table.get(key)?.map(|v| v.value().to_owned()))
        })
    }

    fn put_str(&self, name: &str, key: &str, value: &str) -> Result<()> {
        let table = self.table(name);
        self.shared.with(|db| {
            let tx = db.begin_write()?;
            tx.open_table(TableDefinition::<&str, &str>::new(&table))?
                .insert(key, value)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// The outbound `group` had selected.
    pub fn load_selected(&self, group: &str) -> Result<Option<String>> {
        self.get_str(SELECTED, group)
    }

    pub fn store_selected(&self, group: &str, selected: &str) -> Result<()> {
        self.put_str(SELECTED, group, selected)
    }

    /// The traffic counted when the instance last wrote it.
    pub fn load_traffic(&self) -> Result<crate::app::stat_manager::TrafficReport> {
        use crate::app::stat_manager::Counts;
        let table = self.table(TRAFFIC);
        self.shared.with(|db| {
            let mut report = crate::app::stat_manager::TrafficReport::default();
            let tx = db.begin_read()?;
            let table =
                match tx.open_table(TableDefinition::<&str, (u64, u64, u64, u64)>::new(&table)) {
                    Ok(table) => table,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(report),
                    Err(e) => return Err(e.into()),
                };
            for entry in table.iter()? {
                let (key, value) = entry?;
                let (up, down, tcp, udp) = value.value();
                let counts = Counts { up, down, tcp, udp };
                let into = match key.value().split_once(':') {
                    Some(("user", name)) => (&mut report.users, name),
                    Some(("inbound", tag)) => (&mut report.inbounds, tag),
                    Some(("outbound", tag)) => (&mut report.outbounds, tag),
                    _ => continue,
                };
                into.0.push((into.1.to_owned(), counts));
            }
            Ok(report)
        })
    }

    /// Replaces the traffic kept with `report`.
    pub fn store_traffic(&self, report: &crate::app::stat_manager::TrafficReport) -> Result<()> {
        let table = self.table(TRAFFIC);
        self.shared.with(|db| {
            let tx = db.begin_write()?;
            let definition = TableDefinition::<&str, (u64, u64, u64, u64)>::new(&table);
            tx.delete_table(definition)?;
            {
                let mut table = tx.open_table(definition)?;
                for (kind, counts) in [
                    ("user", &report.users),
                    ("inbound", &report.inbounds),
                    ("outbound", &report.outbounds),
                ] {
                    for (name, c) in counts {
                        table.insert(
                            format!("{}:{}", kind, name).as_str(),
                            (c.up, c.down, c.tcp, c.udp),
                        )?;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// What the smart group `group` remembered of its sites (JSON).
    pub fn load_smart(&self, group: &str) -> Result<Option<Vec<u8>>> {
        let table = self.table(SMART);
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            let table = match tx.open_table(TableDefinition::<&str, &[u8]>::new(&table)) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            Ok(table.get(group)?.map(|v| v.value().to_vec()))
        })
    }

    pub fn store_smart(&self, group: &str, sites: &[u8]) -> Result<()> {
        let table = self.table(SMART);
        self.shared.with(|db| {
            let tx = db.begin_write()?;
            tx.open_table(TableDefinition::<&str, &[u8]>::new(&table))?
                .insert(group, sites)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// The salt the smart groups' site keys are hashed with: 16 random
    /// bytes, made the first time it is asked for.
    pub fn smart_salt(&self) -> Result<[u8; 16]> {
        if let Some(salt) = self.load_smart(SMART_SALT)? {
            if let Ok(salt) = <[u8; 16]>::try_from(salt.as_slice()) {
                return Ok(salt);
            }
        }
        let salt: [u8; 16] = rand::random();
        self.store_smart(SMART_SALT, &salt)?;
        Ok(salt)
    }

    /// The Clash API's mode when the instance last ran.
    pub fn load_mode(&self) -> Result<Option<String>> {
        self.get_str(META, "clash_mode")
    }

    pub fn store_mode(&self, mode: &str) -> Result<()> {
        self.put_str(META, "clash_mode", mode)
    }

    /// The fake IPs kept for `ranges`, oldest first, and the last address
    /// of each family handed out; none, and the file's cleared of them,
    /// when they were kept for other ranges.
    pub(crate) fn load_fake_ips(&self, ranges: &str) -> Result<Option<FakeIps>> {
        let kept = self.get_str(META, "fakeip_ranges")?;
        if kept.as_deref() != Some(ranges) {
            self.shared.with(|db| {
                let tx = db.begin_write()?;
                clear_fake_ips(&tx, &self.id, ranges)?;
                tx.commit()?;
                Ok(())
            })?;
            return Ok(None);
        }
        let (fakeip, cursor) = (self.table(FAKEIP), self.table(FAKEIP_CURSOR));
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            let mut fake_ips = FakeIps::default();
            if let Ok(table) = tx.open_table(TableDefinition::<&[u8], (&str, u64)>::new(&fakeip)) {
                for entry in table.iter()? {
                    let (address, value) = entry?;
                    let (domain, order) = value.value();
                    let Some(address) = address_of(address.value()) else {
                        continue;
                    };
                    fake_ips.entries.push((order, address, domain.to_owned()));
                }
            }
            fake_ips.entries.sort_unstable_by_key(|(order, ..)| *order);
            if let Ok(table) = tx.open_table(TableDefinition::<u8, u128>::new(&cursor)) {
                fake_ips.cursor4 = table.get(4)?.map(|v| v.value());
                fake_ips.cursor6 = table.get(6)?.map(|v| v.value());
            }
            Ok(Some(fake_ips))
        })
    }

    /// What fake IPs are written to: this file, under this `cache_id`.
    pub(crate) fn fake_ip_binding(&self) -> (u64, String) {
        (self.shared.serial, self.id.clone())
    }

    /// Queues what a fake IP store did, to be written in turn.
    pub(crate) fn write_fake_ips(&self, ops: Vec<FakeIpOp>) {
        self.queue(Write::FakeIps {
            id: self.id.clone(),
            ops,
        });
    }

    fn queue(&self, write: Write) {
        if let Some(writes) = self
            .shared
            .writes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let _ = writes.send(write);
        }
    }

    /// Prunes the DNS answers kept that expired more than `window` ago,
    /// now and from time to time, as sing-box does.
    pub(crate) fn prune_dns(&self, window: Duration) {
        let table = self.table(DNS);
        self.shared
            .pruned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(table.clone(), window);
        self.queue(Write::DnsPrune { table, window });
    }

    /// The DNS answer kept under `key`, and when it expires.
    pub(crate) fn load_dns(&self, key: &str) -> Result<Option<(Vec<u8>, SystemTime)>> {
        let table = self.table(DNS);
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            let table = match tx.open_table(TableDefinition::<&str, (&[u8], u64)>::new(&table)) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            Ok(table.get(key)?.map(|v| {
                let (message, expires) = v.value();
                (
                    message.to_vec(),
                    UNIX_EPOCH + Duration::from_millis(expires),
                )
            }))
        })
    }

    /// Keeps `message` under `key` until `expires`, written in turn.
    pub(crate) fn store_dns(&self, key: String, message: Vec<u8>, expires: SystemTime) {
        self.queue(Write::DnsPut {
            table: self.table(DNS),
            key,
            message,
            expires: millis(expires),
        });
    }

    /// Forgets every DNS answer kept. Readers must ignore the old disk
    /// contents until the returned flag says this clear committed.
    pub(crate) fn clear_dns(&self) -> Arc<AtomicBool> {
        let done = Arc::new(AtomicBool::new(false));
        self.queue(Write::DnsClear {
            table: self.table(DNS),
            done: done.clone(),
        });
        done
    }

    /// How many DNS answers are kept.
    pub(crate) fn dns_entries(&self) -> Result<u64> {
        let table = self.table(DNS);
        self.shared.with(|db| {
            let tx = db.begin_read()?;
            match tx.open_table(TableDefinition::<&str, (&[u8], u64)>::new(&table)) {
                Ok(table) => Ok(table.len()?),
                Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
                Err(e) => Err(e.into()),
            }
        })
    }
}

fn millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn table(name: &str, id: &str) -> String {
    if id.is_empty() {
        name.to_owned()
    } else {
        format!("{}@{}", name, id)
    }
}

fn address_of(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

fn bytes_of(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// The fake IPs a file kept.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct FakeIps {
    /// The order each was handed out in, its address and its domain,
    /// oldest first.
    pub entries: Vec<(u64, IpAddr, String)>,
    pub cursor4: Option<u128>,
    pub cursor6: Option<u128>,
}

/// What a fake IP store did.
#[derive(Debug)]
pub(crate) enum FakeIpOp {
    /// Handed out `address` for `domain`, the `order`th.
    Put {
        address: IpAddr,
        domain: String,
        order: u64,
    },
    /// Forgot `address`.
    Remove(IpAddr),
    /// The last address of the family handed out.
    Cursor { v6: bool, current: u128 },
    /// Forgot every one: what follows is all there is, of `ranges`.
    Clear { ranges: String },
}

enum Write {
    FakeIps {
        /// The `cache_id` the tables are of.
        id: String,
        ops: Vec<FakeIpOp>,
    },
    DnsPut {
        table: String,
        key: String,
        message: Vec<u8>,
        expires: u64,
    },
    DnsClear {
        table: String,
        done: Arc<AtomicBool>,
    },
    DnsPrune {
        table: String,
        window: Duration,
    },
}

/// Empties the fake IP tables of `id`, now kept for `ranges`.
fn clear_fake_ips(tx: &redb::WriteTransaction, id: &str, ranges: &str) -> Result<()> {
    tx.delete_table(TableDefinition::<&[u8], (&str, u64)>::new(&table(
        FAKEIP, id,
    )))?;
    tx.delete_table(TableDefinition::<u8, u128>::new(&table(FAKEIP_CURSOR, id)))?;
    tx.open_table(TableDefinition::<&str, &str>::new(&table(META, id)))?
        .insert("fakeip_ranges", ranges)?;
    Ok(())
}

/// How often the DNS answers kept are pruned: half the optimistic timeout,
/// or hourly without one, as sing-box prunes them.
fn prune_interval(pruned: &Mutex<std::collections::HashMap<String, Duration>>) -> Duration {
    pruned
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|w| !w.is_zero())
        .map(|w| *w / 2)
        .min()
        .unwrap_or(Duration::from_secs(3600))
}

/// Writes what is queued, in one transaction for as much as has queued up
/// while the last committed, until the file closes; and prunes the DNS
/// answers kept when nothing was queued for a while.
fn write(
    db: &RwLock<Option<Database>>,
    queue: mpsc::Receiver<Write>,
    pruned: &Mutex<std::collections::HashMap<String, Duration>>,
) {
    let mut last_pruned = std::time::Instant::now();
    loop {
        let interval = prune_interval(pruned);
        let wait = interval.saturating_sub(last_pruned.elapsed());
        let mut writes = match queue.recv_timeout(wait) {
            Ok(first) => vec![first],
            Err(mpsc::RecvTimeoutError::Timeout) => Vec::new(),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        writes.extend(queue.try_iter());
        if last_pruned.elapsed() >= interval {
            last_pruned = std::time::Instant::now();
            let tables = pruned.lock().unwrap_or_else(|e| e.into_inner()).clone();
            writes.extend(
                tables
                    .into_iter()
                    .map(|(table, window)| Write::DnsPrune { table, window }),
            );
        }
        if writes.is_empty() {
            continue;
        }
        if let Err(e) = with(db, |db| commit(db, &writes)) {
            warn!("cache_file: not written: {}", e);
        } else {
            for write in &writes {
                if let Write::DnsClear { done, .. } = write {
                    done.store(true, Ordering::Release);
                }
            }
        }
    }
}

fn commit(db: &Database, writes: &[Write]) -> Result<()> {
    let tx = db.begin_write()?;
    for write in writes {
        match write {
            Write::FakeIps { id, ops } => commit_fake_ips(&tx, id, ops)?,
            Write::DnsPut {
                table,
                key,
                message,
                expires,
            } => {
                tx.open_table(TableDefinition::<&str, (&[u8], u64)>::new(table))?
                    .insert(key.as_str(), (message.as_slice(), *expires))?;
            }
            Write::DnsClear { table, .. } => {
                tx.delete_table(TableDefinition::<&str, (&[u8], u64)>::new(table))?;
            }
            Write::DnsPrune { table, window } => {
                let before = millis(SystemTime::now()).saturating_sub(window.as_millis() as u64);
                tx.open_table(TableDefinition::<&str, (&[u8], u64)>::new(table))?
                    .retain(|_, (_, expires)| expires >= before)?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

fn commit_fake_ips(tx: &redb::WriteTransaction, id: &str, ops: &[FakeIpOp]) -> Result<()> {
    let (fakeip, cursor) = (table(FAKEIP, id), table(FAKEIP_CURSOR, id));
    let (fakeip, cursor) = (
        TableDefinition::<&[u8], (&str, u64)>::new(&fakeip),
        TableDefinition::<u8, u128>::new(&cursor),
    );
    for op in ops {
        match op {
            FakeIpOp::Put {
                address,
                domain,
                order,
            } => {
                tx.open_table(fakeip)?
                    .insert(bytes_of(*address).as_slice(), (domain.as_str(), *order))?;
            }
            FakeIpOp::Remove(address) => {
                tx.open_table(fakeip)?
                    .remove(bytes_of(*address).as_slice())?;
            }
            FakeIpOp::Cursor { v6, current } => {
                tx.open_table(cursor)?
                    .insert(if *v6 { 6 } else { 4 }, *current)?;
            }
            FakeIpOp::Clear { ranges } => clear_fake_ips(tx, id, ranges)?,
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::runtime::Host;

    pub(crate) fn env(dir: &Path) -> RuntimeEnv {
        RuntimeEnv {
            host: Host {
                cache_dir: Some(dir.to_path_buf()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub(crate) fn with_writes_paused(cache: &CacheFile, f: impl FnOnce()) {
        cache
            .shared
            .with(|db| {
                let _transaction = db.begin_write()?;
                f();
                Ok(())
            })
            .unwrap();
    }

    pub(crate) fn enabled() -> CacheFileOptions {
        CacheFileOptions {
            enabled: true,
            ..Default::default()
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sail-cache-file-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn nothing_is_kept_unless_it_is_enabled() {
        let dir = temp_dir("disabled");
        let slot = CacheFileSlot::default();
        slot.replace(Some(&CacheFileOptions::default()), &env(&dir))
            .unwrap()
            .keep();
        assert!(slot.get().is_none());
        assert!(!dir.exists());
    }

    #[test]
    fn selections_and_the_mode_are_kept_apart_by_cache_id() {
        let dir = temp_dir("ids");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.path(), dir.join("cache.db"));
        assert_eq!(cache.load_selected("g").unwrap(), None);
        cache.store_selected("g", "b").unwrap();
        cache.store_mode("Global").unwrap();

        let other = CacheFileOptions {
            cache_id: Some("other".into()),
            ..enabled()
        };
        slot.replace(Some(&other), &env).unwrap().keep();
        let by_id = slot.get().unwrap();
        // The same database, not opened again, which its lock would refuse.
        assert!(Arc::ptr_eq(&cache.shared, &by_id.shared));
        assert_eq!(by_id.load_selected("g").unwrap(), None);
        assert_eq!(by_id.load_mode().unwrap(), None);
        drop((cache, by_id));

        // Closed, and opened again: as a restart finds it.
        slot.replace(None, &env).unwrap().keep();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.load_selected("g").unwrap().as_deref(), Some("b"));
        assert_eq!(cache.load_mode().unwrap().as_deref(), Some("Global"));
        drop(cache);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What was counted is kept across a restart, and replaced whole: a
    /// user no longer counted is gone from the file.
    #[test]
    fn traffic_is_kept_and_replaced_whole() {
        use crate::app::stat_manager::{Counts, TrafficReport};
        let dir = temp_dir("traffic");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.load_traffic().unwrap(), TrafficReport::default());
        let c = |n| Counts {
            up: n,
            down: n + 1,
            tcp: n + 2,
            udp: n + 3,
        };
        let first = TrafficReport {
            users: vec![("alice".into(), c(1)), ("bob".into(), c(2))],
            inbounds: vec![("in:with:colons".into(), c(10))],
            outbounds: vec![("out".into(), c(20))],
        };
        cache.store_traffic(&first).unwrap();
        let second = TrafficReport {
            users: vec![("alice".into(), c(5))],
            ..first.clone()
        };
        cache.store_traffic(&second).unwrap();
        drop(cache);

        slot.replace(None, &env).unwrap().keep();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let mut kept = slot.get().unwrap().load_traffic().unwrap();
        kept.users.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(kept, second);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reload_that_fails_puts_the_old_file_back() {
        let dir = temp_dir("guard");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let before = slot.get().unwrap().path().to_path_buf();
        {
            let _guard = slot.replace(None, &env).unwrap();
            assert!(slot.get().is_none());
        }
        assert_eq!(slot.get().unwrap().path(), before);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_in_use_is_an_error_and_a_broken_one_is_started_afresh() {
        let dir = temp_dir("lock");
        let env = env(&dir);
        let first = CacheFileSlot::default();
        first.replace(Some(&enabled()), &env).unwrap().keep();
        let err = CacheFileSlot::default()
            .replace(Some(&enabled()), &env)
            .err()
            .unwrap();
        assert!(err.to_string().contains("in use"), "{}", err);
        first.replace(None, &env).unwrap().keep();

        std::fs::write(dir.join("cache.db"), b"not a database").unwrap();
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        slot.get().unwrap().store_selected("g", "a").unwrap();
        assert!(dir.join("cache.db.broken").exists());
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fake_ips_are_kept_for_their_ranges() {
        let dir = temp_dir("fakeip");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(cache.load_fake_ips("a").unwrap(), None);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        cache.write_fake_ips(vec![
            FakeIpOp::Put {
                address: ip("198.18.0.5"),
                domain: "b.example".into(),
                order: 2,
            },
            FakeIpOp::Put {
                address: ip("198.18.0.4"),
                domain: "a.example".into(),
                order: 1,
            },
            FakeIpOp::Put {
                address: ip("fc00::4"),
                domain: "c.example".into(),
                order: 3,
            },
            FakeIpOp::Cursor {
                v6: false,
                current: 5,
            },
        ]);
        cache.write_fake_ips(vec![FakeIpOp::Remove(ip("fc00::4"))]);
        drop(cache);
        // Closing writes what is queued.
        slot.replace(None, &env).unwrap().keep();

        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(
            cache.load_fake_ips("a").unwrap(),
            Some(FakeIps {
                entries: vec![
                    (1, ip("198.18.0.4"), "a.example".into()),
                    (2, ip("198.18.0.5"), "b.example".into()),
                ],
                cursor4: Some(5),
                cursor6: None,
            })
        );
        // Other ranges: what was kept goes.
        assert_eq!(cache.load_fake_ips("b").unwrap(), None);
        assert_eq!(cache.load_fake_ips("b").unwrap(), Some(FakeIps::default()));
        drop(cache);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dns_answers_are_kept_cleared_and_pruned() {
        let dir = temp_dir("dns");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        let options = CacheFileOptions {
            store_dns: true,
            ..enabled()
        };
        slot.replace(Some(&options), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        let now = SystemTime::now();
        let expires = UNIX_EPOCH + Duration::from_millis(millis(now + Duration::from_secs(60)));
        cache.store_dns("fresh".into(), vec![1, 2], expires);
        cache.store_dns("old".into(), vec![3], now - Duration::from_secs(600));
        cache.store_dns("recent".into(), vec![4], now - Duration::from_secs(5));
        // Pruned: what expired over a minute ago.
        cache.prune_dns(Duration::from_secs(60));
        drop(cache);
        slot.replace(None, &env).unwrap().keep();

        slot.replace(Some(&options), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        assert_eq!(
            cache.load_dns("fresh").unwrap(),
            Some((vec![1, 2], expires))
        );
        assert_eq!(cache.load_dns("old").unwrap(), None);
        assert!(cache.load_dns("recent").unwrap().is_some());
        assert_eq!(cache.dns_entries().unwrap(), 2);
        cache.clear_dns();
        drop(cache);
        slot.replace(None, &env).unwrap().keep();
        slot.replace(Some(&options), &env).unwrap().keep();
        assert_eq!(slot.get().unwrap().dns_entries().unwrap(), 0);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dns_clear_reports_only_a_committed_clear_and_stays_pending_when_closed() {
        let dir = temp_dir("dns-clear-completion");
        let env = env(&dir);
        let slot = CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        let cache = slot.get().unwrap();
        let done = with(&cache.shared.db, |db| {
            let _transaction = db.begin_write()?;
            cache.store_dns(
                "old".into(),
                vec![1],
                SystemTime::now() + Duration::from_secs(60),
            );
            let done = cache.clear_dns();
            assert!(!done.load(Ordering::Acquire));
            Ok(done)
        })
        .unwrap();
        // close drains the writer; a queued put before clear must be gone.
        slot.replace(None, &env).unwrap().keep();
        assert!(done.load(Ordering::Acquire));
        assert!(!cache.clear_dns().load(Ordering::Acquire));
        drop(cache);
        slot.replace(Some(&enabled()), &env).unwrap().keep();
        assert_eq!(slot.get().unwrap().dns_entries().unwrap(), 0);
        slot.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
