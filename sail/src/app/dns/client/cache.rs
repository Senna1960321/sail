//! The answers each server gave, kept as sing-box keeps them: for the
//! shortest TTL of their records, or a negative answer for its SOA's
//! (RFC 2308), and not at all without one; every record then carries that
//! TTL, less what has passed. With `disable_expire`, they are kept until
//! the cache is full or cleared. With `optimistic`, an answer that has
//! expired is still given, with a TTL of 1, for up to its timeout, while
//! the server is asked again in the background. With the cache file's
//! `store_dns`, every answer kept is written there as well, and one not in
//! memory is looked for there, so that answers outlive a restart.
//!
//! An answer is kept as the bytes it is sent as, and read again at each
//! hit: two to four times smaller than the parsed message (about 300 bytes
//! an entry against 700, 375 against 1,500 for a CNAME chain), for a
//! parse of under a microsecond.

use portable_atomic::AtomicU64;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use lru::LruCache;

use crate::runtime::cache_file::CacheFile;
use crate::util::DnsMessageExt;
use serde_derive::Serialize;

/// A server's answers, by the server, the question (name, record type)
/// and the client subnet asked for.
pub(super) type AnswerKey = (String, String, u16, Option<crate::config::model::Prefix>);

/// An answer as it was sent, and when it expires.
type Kept = (Arc<[u8]>, Instant);

/// What the cache has for a question.
pub(super) enum Cached {
    Fresh(Message),
    /// Expired, but within the optimistic timeout.
    Stale(Message),
    Missing,
}

pub(super) struct Answers {
    state: Mutex<State>,
    disable_expire: bool,
    optimistic: Option<Duration>,
    /// The cache file, when it keeps DNS answers.
    file: Option<Arc<CacheFile>>,
    hits: AtomicU64,
    stale_hits: AtomicU64,
    misses: AtomicU64,
}

/// The generation, writes and refresh ownership change together on a flush.
struct State {
    entries: LruCache<AnswerKey, Kept>,
    generation: u64,
    refreshing: HashSet<AnswerKey>,
    /// A queued disk clear must commit before old disk answers can be read.
    file_cleared: Option<Arc<AtomicBool>>,
}

/// What the cache holds and how it served, since the DNS client was built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    /// Expired answers given while asked for again.
    pub stale_hits: u64,
    pub misses: u64,
    /// Kept in the cache file, with `store_dns`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored: Option<u64>,
}

impl Answers {
    pub(super) fn new(
        capacity: NonZeroUsize,
        disable_expire: bool,
        optimistic: Option<Duration>,
        file: Option<Arc<CacheFile>>,
    ) -> Self {
        if let Some(file) = &file {
            file.prune_dns(optimistic.unwrap_or_default());
        }
        Answers {
            state: Mutex::new(State {
                entries: LruCache::new(capacity),
                generation: 0,
                refreshing: HashSet::new(),
                file_cleared: None,
            }),
            disable_expire,
            optimistic,
            file,
            hits: Default::default(),
            stale_hits: Default::default(),
            misses: Default::default(),
        }
    }

    /// The answer kept for `key`, with `id`: in memory, or else in the
    /// cache file.
    pub(super) fn get(&self, key: &AnswerKey, id: u16) -> Cached {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.entries.contains(key)
            && state
                .file_cleared
                .as_ref()
                .is_none_or(|done| done.load(Ordering::Acquire))
        {
            if let Some(kept) = self.load(key) {
                state.entries.put(key.clone(), kept);
            }
        }
        let generation = state.generation;
        let Some((bytes, expires)) = state.entries.get(key) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Cached::Missing;
        };
        let now = Instant::now();
        let (ttl, stale) = if self.disable_expire {
            (None, false)
        } else if now < *expires {
            (Some((*expires - now).as_secs().max(1) as u32), false)
        } else if self
            .optimistic
            .is_some_and(|window| now < *expires + window)
        {
            (Some(1), true)
        } else {
            state.entries.pop(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Cached::Missing;
        };
        let bytes = bytes.clone();
        drop(state);
        // Kept only once it was written: one that does not read again is
        // forgotten, and missed.
        let Ok(mut message) = Message::from_vec(&bytes) else {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.generation == generation
                && state
                    .entries
                    .peek(key)
                    .is_some_and(|(kept, _)| Arc::ptr_eq(kept, &bytes))
            {
                state.entries.pop(key);
            }
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Cached::Missing;
        };
        message.set_id(id);
        if let Some(ttl) = ttl {
            set_ttl(&mut message, ttl);
        }
        if stale {
            self.stale_hits.fetch_add(1, Ordering::Relaxed);
            Cached::Stale(message)
        } else {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Cached::Fresh(message)
        }
    }

    /// The answer the cache file keeps for `key`, with when it expires.
    fn load(&self, key: &AnswerKey) -> Option<Kept> {
        let file = self.file.as_ref()?;
        let (bytes, expires) = file
            .load_dns(&file_key(key))
            .inspect_err(|e| tracing::debug!("{}", e))
            .ok()??;
        let now = (Instant::now(), SystemTime::now());
        let expires = match expires.duration_since(now.1) {
            Ok(left) => now.0 + left,
            Err(past) => now.0.checked_sub(past.duration())?,
        };
        Some((bytes.into(), expires))
    }

    /// Captured before looking up or asking for an answer. A flush revokes it.
    pub(super) fn generation(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .generation
    }

    /// Keeps `message` for `ttl` seconds, only if no flush followed its lookup.
    pub(super) fn put(&self, key: AnswerKey, message: &Message, ttl: u32, generation: u64) {
        if ttl == 0 {
            return;
        }
        let Ok(bytes) = message.to_vec() else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.generation != generation {
            return;
        }
        let life = Duration::from_secs(ttl.into());
        // The queue order and in-memory write are serialized with clear().
        if let Some(file) = &self.file {
            file.store_dns(file_key(&key), bytes.clone(), SystemTime::now() + life);
        }
        let expires = Instant::now() + life;
        state.entries.put(key, (bytes.into(), expires));
    }

    /// Whether `key` may be asked again in the background now: not while
    /// it already is. [`Answers::refreshed`] ends it.
    pub(super) fn start_refresh(&self, key: &AnswerKey, generation: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.generation == generation && state.refreshing.insert(key.clone())
    }

    /// How many questions are being asked again in the background now.
    #[cfg(test)]
    pub(super) fn refreshing(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .refreshing
            .len()
    }

    pub(super) fn refreshed(&self, key: &AnswerKey, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.generation == generation {
            state.refreshing.remove(key);
        }
    }

    /// Forgets every answer, in the cache file too.
    pub(super) fn clear(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.entries.clear();
        state.refreshing.clear();
        state.file_cleared = self.file.as_ref().map(|file| file.clear_dns());
    }

    pub(super) fn stats(&self) -> CacheStats {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        CacheStats {
            entries: state.entries.len(),
            capacity: state.entries.cap().get(),
            hits: self.hits.load(Ordering::Relaxed),
            stale_hits: self.stale_hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stored: self.file.as_ref().and_then(|f| f.dns_entries().ok()),
        }
    }
}

/// `key`, as the cache file keeps it.
fn file_key((server, name, ty, subnet): &AnswerKey) -> String {
    let subnet = subnet.map(|s| s.to_string()).unwrap_or_default();
    format!("{}\0{}\0{}\0{}", server, name, ty, subnet)
}

/// How long `response` may be kept, as sing-box has it: a negative answer
/// (no answer records) for its SOA's TTL or MINIMUM, whichever is less;
/// otherwise the shortest TTL of its records but zero, and 0, not kept,
/// when none has one.
pub(super) fn ttl_of(response: &Message) -> u32 {
    if response.answers().is_empty() {
        for record in response.name_servers() {
            if let RData::SOA(soa) = &record.data {
                return record.ttl.min(soa.minimum);
            }
        }
    }
    response
        .answers()
        .iter()
        .chain(response.name_servers())
        .chain(&response.additionals)
        .filter(|r| r.record_type() != RecordType::OPT && r.ttl > 0)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
}

/// Gives every record of `message` the TTL `ttl`, as sing-box does, so
/// that none outlives the answer kept.
pub(super) fn set_ttl(message: &mut Message, ttl: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        if record.record_type() != RecordType::OPT {
            record.ttl = ttl;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, Record};
    use std::str::FromStr;

    fn key(name: &str) -> AnswerKey {
        ("s".into(), name.into(), 1, None)
    }

    fn answer(ttls: &[u32]) -> Message {
        let name = Name::from_str("a.example.").unwrap();
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name.clone(), RecordType::A));
        for (i, ttl) in ttls.iter().enumerate() {
            m.add_answer(Record::from_rdata(
                name.clone(),
                *ttl,
                RData::A(A::new(10, 0, 0, i as u8)),
            ));
        }
        m
    }

    fn negative(soa_ttl: u32, minimum: u32) -> Message {
        let mut m = answer(&[]);
        let zone = Name::from_str("example.").unwrap();
        m.add_authority(Record::from_rdata(
            zone.clone(),
            soa_ttl,
            RData::SOA(SOA::new(zone.clone(), zone, 1, 2, 3, 4, minimum)),
        ));
        m
    }

    #[test]
    fn the_ttl_is_the_shortest_or_the_soas() {
        assert_eq!(ttl_of(&answer(&[300, 60, 0])), 60);
        assert_eq!(ttl_of(&negative(900, 30)), 30);
        assert_eq!(ttl_of(&negative(20, 30)), 20);
        // No records and no SOA: not kept.
        assert_eq!(ttl_of(&answer(&[])), 0);
        let mut m = answer(&[300, 60]);
        set_ttl(&mut m, 7);
        assert!(m.answers().iter().all(|r| r.ttl == 7));
    }

    fn cache(disable_expire: bool, optimistic: Option<Duration>) -> Answers {
        Answers::new(
            NonZeroUsize::new(4).unwrap(),
            disable_expire,
            optimistic,
            None,
        )
    }

    fn age(answers: &Answers, key: &AnswerKey, by: Duration) {
        let mut entries = answers.state.lock().unwrap();
        let (_, expires) = entries.entries.get_mut(key).unwrap();
        *expires -= by;
    }

    #[test]
    fn an_answer_is_given_until_it_expires_with_what_is_left_of_its_ttl() {
        let answers = cache(false, None);
        let k = key("a");
        answers.put(k.clone(), &answer(&[60]), 60, answers.generation());
        age(&answers, &k, Duration::from_secs(20));
        let Cached::Fresh(m) = answers.get(&k, 9) else {
            panic!("fresh")
        };
        assert_eq!(m.id(), 9);
        assert!((39..=40).contains(&m.answers()[0].ttl));
        age(&answers, &k, Duration::from_secs(41));
        assert!(matches!(answers.get(&k, 9), Cached::Missing));
        // Gone for good.
        assert!(matches!(answers.get(&k, 9), Cached::Missing));
        answers.put(k.clone(), &answer(&[]), 0, answers.generation());
        assert!(matches!(answers.get(&k, 9), Cached::Missing));
        assert_eq!(
            answers.stats(),
            CacheStats {
                entries: 0,
                capacity: 4,
                hits: 1,
                stale_hits: 0,
                misses: 3,
                stored: None,
            }
        );
    }

    #[test]
    fn an_answer_is_kept_as_its_bytes_and_each_hit_reads_its_own() {
        let answers = cache(false, None);
        let k = key("a");
        let sent = answer(&[60, 300]);
        answers.put(k.clone(), &sent, 60, answers.generation());
        {
            let entries = answers.state.lock().unwrap();
            let (bytes, _) = entries.entries.peek(&k).unwrap();
            assert_eq!(&bytes[..], &sent.to_vec().unwrap()[..]);
        }
        // Each hit has its own id and TTL; the bytes kept stay as sent.
        let Cached::Fresh(first) = answers.get(&k, 9) else {
            panic!("fresh")
        };
        assert_eq!(first.id(), 9);
        assert!(first.answers().iter().all(|r| (59..=60).contains(&r.ttl)));
        age(&answers, &k, Duration::from_secs(30));
        let Cached::Fresh(second) = answers.get(&k, 5) else {
            panic!("fresh")
        };
        assert_eq!(second.id(), 5);
        assert!(second.answers().iter().all(|r| (29..=30).contains(&r.ttl)));
        assert_eq!(second.answers().len(), 2);
        let entries = answers.state.lock().unwrap();
        assert_eq!(
            &entries.entries.peek(&k).unwrap().0[..],
            &sent.to_vec().unwrap()[..]
        );
    }

    #[test]
    fn bytes_that_do_not_read_are_missed_and_forgotten() {
        let answers = cache(false, None);
        let k = key("a");
        answers.state.lock().unwrap().entries.put(
            k.clone(),
            (
                Arc::from(&[1u8, 2, 3][..]),
                Instant::now() + Duration::from_secs(60),
            ),
        );
        assert!(matches!(answers.get(&k, 1), Cached::Missing));
        assert!(!answers.state.lock().unwrap().entries.contains(&k));
        assert_eq!(answers.stats().misses, 1);
        assert_eq!(answers.stats().hits, 0);
    }

    #[test]
    fn optimistic_gives_an_expired_answer_within_its_timeout() {
        let answers = cache(false, Some(Duration::from_secs(3600)));
        let k = key("a");
        answers.put(k.clone(), &answer(&[60]), 60, answers.generation());
        age(&answers, &k, Duration::from_secs(120));
        let Cached::Stale(m) = answers.get(&k, 1) else {
            panic!("stale")
        };
        assert_eq!(m.answers()[0].ttl, 1);
        assert!(answers.start_refresh(&k, answers.generation()));
        assert!(!answers.start_refresh(&k, answers.generation()));
        answers.refreshed(&k, answers.generation());
        assert!(answers.start_refresh(&k, answers.generation()));
        age(&answers, &k, Duration::from_secs(3600));
        assert!(matches!(answers.get(&k, 1), Cached::Missing));
    }

    #[test]
    fn without_expiry_an_answer_stays_until_cleared() {
        let answers = cache(true, None);
        let k = key("a");
        answers.put(k.clone(), &answer(&[60]), 60, answers.generation());
        age(&answers, &k, Duration::from_secs(3600));
        assert!(matches!(answers.get(&k, 1), Cached::Fresh(_)));
        answers.clear();
        assert!(matches!(answers.get(&k, 1), Cached::Missing));
    }

    #[test]
    fn a_flush_revokes_old_writes_without_replacing_new_answers() {
        let answers = cache(false, None);
        let k = key("a");
        let old = answers.generation();
        answers.clear();
        answers.put(k.clone(), &answer(&[60]), 60, old);
        assert!(matches!(answers.get(&k, 1), Cached::Missing));
        answers.put(k.clone(), &answer(&[60, 60]), 60, answers.generation());
        answers.put(k.clone(), &answer(&[60]), 60, old);
        let Cached::Fresh(kept) = answers.get(&k, 1) else {
            panic!("new answer")
        };
        assert_eq!(kept.answers().len(), 2);
    }

    #[test]
    fn an_old_refresh_cannot_claim_or_release_a_new_generations_slot() {
        let answers = cache(false, Some(Duration::from_secs(60)));
        let k = key("a");
        let old = answers.generation();
        assert!(answers.start_refresh(&k, old));
        answers.clear();
        assert_eq!(answers.refreshing(), 0);
        assert!(!answers.start_refresh(&k, old));
        let new = answers.generation();
        assert!(answers.start_refresh(&k, new));
        answers.refreshed(&k, old);
        assert_eq!(answers.refreshing(), 1);
        assert!(!answers.start_refresh(&k, new));
        answers.refreshed(&k, new);
        assert_eq!(answers.refreshing(), 0);
        assert!(answers.start_refresh(&k, new));
    }

    fn wait_until(mut ready: impl FnMut() -> bool) {
        let limit = Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(Instant::now() < limit, "cache writer did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_pending_disk_clear_blocks_old_loads_then_restores_new_disk_hits() {
        use crate::runtime::cache_file::tests::{enabled, env, with_writes_paused};
        let dir = std::env::temp_dir().join(format!(
            "sail-dns-cache-generation-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let env = env(&dir);
        let mut options = enabled();
        options.store_dns = true;
        env.cache_file.replace(Some(&options), &env).unwrap().keep();
        let file = env.cache_file.get().unwrap();
        let answers = Answers::new(
            NonZeroUsize::new(4).unwrap(),
            false,
            None,
            Some(file.clone()),
        );
        let k = key("a");
        let disk_key = file_key(&k);
        answers.put(k.clone(), &answer(&[60]), 60, answers.generation());
        wait_until(|| file.load_dns(&disk_key).unwrap().is_some());
        for _ in 0..2 {
            let old = answers.generation();
            with_writes_paused(&file, || {
                answers.clear();
                // The real database still has the old answer. clear/get must
                // neither wait on this transaction nor load that old answer.
                assert!(file.load_dns(&disk_key).unwrap().is_some());
                assert!(matches!(answers.get(&k, 1), Cached::Missing));
                answers.put(k.clone(), &answer(&[60]), 60, old);
                assert!(matches!(answers.get(&k, 1), Cached::Missing));
                answers.put(k.clone(), &answer(&[60, 60]), 60, answers.generation());
                assert!(matches!(answers.get(&k, 1), Cached::Fresh(_)));
            });
            wait_until(|| {
                let done = answers.state.lock().unwrap().file_cleared.clone().unwrap();
                done.load(Ordering::Acquire)
                    && file.load_dns(&disk_key).unwrap().is_some_and(|(bytes, _)| {
                        Message::from_vec(&bytes).unwrap().answers().len() == 2
                    })
            });
            // Force an LRU miss without another flush: disk loads resume.
            answers.state.lock().unwrap().entries.clear();
            let Cached::Fresh(kept) = answers.get(&k, 7) else {
                panic!("fresh from disk")
            };
            assert_eq!(kept.answers().len(), 2);
        }
        drop(answers);
        drop(file);
        env.cache_file.replace(None, &env).unwrap().keep();
        // Closing drains the queue, so a late old write cannot reappear on restart.
        env.cache_file.replace(Some(&options), &env).unwrap().keep();
        let file = env.cache_file.get().unwrap();
        let (bytes, _) = file.load_dns(&disk_key).unwrap().unwrap();
        assert_eq!(Message::from_vec(&bytes).unwrap().answers().len(), 2);
        drop(file);
        env.cache_file.replace(None, &env).unwrap().keep();
        std::fs::remove_dir_all(dir).unwrap();
    }

    async fn delayed_answer_after_flush(network_change: bool, optimistic: bool) {
        use super::super::DnsClient;
        use crate::control::events::DnsSource;
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::atomic::AtomicUsize;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let held = if optimistic { 2 } else { 1 };
        let server = tokio::spawn(async move {
            let mut seen = Some(seen_tx);
            let mut release = Some(release_rx);
            let mut data = [0u8; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut data).await.unwrap();
                let count = observed.fetch_add(1, Ordering::SeqCst) + 1;
                let request = Message::from_vec(&data[..n]).unwrap();
                let ip = if count > held { 8 } else { 7 };
                let mut response = Message::new(request.id(), MessageType::Response, OpCode::Query);
                for q in request.queries() {
                    response.add_query(q.clone());
                    response.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A::new(10, 0, 0, ip)),
                    ));
                }
                if count == held {
                    seen.take().unwrap().send(()).unwrap();
                    release.take().unwrap().await.unwrap();
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let config = crate::config::Config::from_json(&serde_json::json!({
            "dns": { "strategy": "ipv4_only", "timeout": "3s", "optimistic": { "enabled": optimistic, "timeout": "1h" }, "servers": [
                { "type": "udp", "tag": "s", "server": "127.0.0.1", "server_port": port }
            ] }
        }).to_string()).unwrap();
        let env = crate::runtime::RuntimeEnv::default();
        let client = DnsClient::new(&config.dns, Default::default(), &env)
            .unwrap()
            .into_arc();
        let host = "a.example";
        if optimistic {
            assert_eq!(
                client.lookup(host).await.unwrap(),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]
            );
            age(&client.answers, &key(host), Duration::from_secs(120));
        }
        let mut events = env.events.dns_exchanges();
        let pending_client = client.clone();
        let pending = tokio::spawn(async move { pending_client.lookup(host).await });
        tokio::time::timeout(Duration::from_secs(5), seen_rx)
            .await
            .unwrap()
            .unwrap();
        if network_change {
            client.network_changed().await;
        } else {
            client.clear_cache();
        }
        release_tx.send(()).unwrap();
        assert_eq!(
            pending.await.unwrap().unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]
        );
        if optimistic {
            // Exchanged is emitted after the background answer attempted its
            // cache write, so the next assertion is not a timing guess.
            tokio::time::timeout(Duration::from_secs(5), async {
                while events.recv().await.unwrap().source != DnsSource::Exchanged {}
            })
            .await
            .unwrap();
        }
        let fresh = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8))];
        assert_eq!(client.lookup(host).await.unwrap(), fresh);
        assert_eq!(calls.load(Ordering::SeqCst), held + 1);
        assert_eq!(client.lookup(host).await.unwrap(), fresh);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            held + 1,
            "new result should be cached"
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cache_clear_rejects_late_udp_answers() {
        delayed_answer_after_flush(false, false).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_network_change_rejects_late_udp_answers() {
        delayed_answer_after_flush(true, false).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cache_clear_rejects_late_optimistic_refresh_answers() {
        delayed_answer_after_flush(false, true).await;
    }
}
