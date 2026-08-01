// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who is actually connected, published by the process that knows.
//!
//! The Stratum front holds the sockets, so it is the only place in the
//! system with a first-hand answer to "is this device online?".
//! Everything else infers, and every inference is wrong somewhere:
//!
//! - `client_entity` with `deletedAt IS NULL` means "registered **and**
//!   submitted an accepted share within the last five minutes", because
//!   the dead-client cron retires anything quieter than that. A slow
//!   miner is therefore indistinguishable from a dead one.
//! - A Stratum connect/disconnect event describes **one** session. A
//!   worker with several sessions (a rental source rotating rigs, an SV2
//!   connection with several channels) produces events that say nothing
//!   about the others, and a process that restarted has seen none of
//!   them at all.
//!
//! So the front publishes the set directly. [`LiveSessionRegistry`]
//! wraps the session-persistence hook, keeps the live
//! `(address, worker)` set in memory with a per-device session refcount,
//! and mirrors it into Redis under a key of its own. Readers take the
//! union across every front's key.
//!
//! Two properties make it safe to trust:
//!
//! - **A dead front disappears by itself.** Each key carries a TTL that
//!   only the owning process refreshes, so a front that is killed stops
//!   claiming its miners are online without anyone having to notice.
//! - **A reader that sees no fronts at all concludes nothing.** An empty
//!   union is indistinguishable from "the fronts have not published
//!   yet", so [`RedisLiveSessions`] reports the lookup as unavailable
//!   rather than reporting every miner on the pool as offline.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bp_share_hook::SharedSessionPersistence;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Key prefix; one key per front process.
const LIVE_PREFIX: &str = "device:live:";

/// How often the whole set is republished. Also bounds how stale a
/// reader's answer can be.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(20);

/// Key lifetime. A front that stops republishing drops out of the union
/// after this; generous enough that one slow tick is not an outage.
const LIVE_TTL_SECS: u64 = 90;

fn member(address: &str, worker: &str) -> String {
    format!("{address}\u{1f}{worker}")
}

/// Always present, filtered out on read.
///
/// Redis deletes a set the moment its last member is removed, so without
/// this a front whose last miner disconnects would vanish from the union
/// — and a reader seeing no keys at all correctly refuses to conclude
/// anything, so the pool would go blind exactly when someone went
/// offline. The tombstone keeps "this front is alive and holds nothing"
/// distinguishable from "no front is publishing".
const PRESENT: &str = "\u{1f}present";

/// Live sessions held by this process, mirrored to Redis.
///
/// Decorates a [`SharedSessionPersistence`]: every register/deregister
/// still reaches the inner implementation, and the set is maintained
/// alongside it.
pub(crate) struct LiveSessionRegistry {
    inner: Arc<dyn SharedSessionPersistence>,
    state: Mutex<RegistryState>,
    /// Unique per process, so two fronts never overwrite each other.
    key: String,
    redis: ConnectionManager,
}

#[derive(Default)]
struct RegistryState {
    /// `(address, worker)` → the session ids holding it open. A device
    /// leaves the set when its LAST session does, which is the whole
    /// point: one rig of a rental source rotating out is not an outage.
    devices: HashMap<(String, String), HashSet<String>>,
    /// `session_id` → the device it belongs to. Deregistration only
    /// carries the session id, so the mapping has to be kept here.
    sessions: HashMap<String, (String, String)>,
}

/// What recording a session changed about the live set.
#[derive(Debug)]
struct Added {
    /// This is the device's FIRST session — it just became live.
    became_live: bool,
    /// The session used to hold this OTHER device and was its last
    /// holder, so that one just went away.
    vacated: Option<(String, String)>,
}

impl RegistryState {
    /// Record a session for a device.
    fn add(&mut self, session_id: &str, device: (String, String)) -> Added {
        let previous = self.sessions.insert(session_id.to_string(), device.clone());
        // One connection may authorize more than once, and the second
        // authorize may carry a different worker name — SV1's authorize
        // handler is unconditional. Releasing what the session moved off
        // is not optional: the holder set is the only thing that can ever
        // drop a device, and a stale entry in it is unreachable forever.
        let vacated = match previous {
            Some(previous) if previous != device => self.release(session_id, &previous),
            _ => None,
        };
        let holders = self.devices.entry(device).or_default();
        holders.insert(session_id.to_string());
        Added {
            became_live: holders.len() == 1,
            vacated,
        }
    }

    /// Drop a session. Returns the device only when that was its LAST
    /// session — one rig of a rental source rotating out must not take
    /// the whole worker offline.
    fn remove(&mut self, session_id: &str) -> Option<(String, String)> {
        let device = self.sessions.remove(session_id)?;
        self.release(session_id, &device)
    }

    /// Take `session_id` out of `device`'s holders, reporting the device
    /// when it held the last one.
    fn release(&mut self, session_id: &str, device: &(String, String)) -> Option<(String, String)> {
        let holders = self.devices.get_mut(device)?;
        holders.remove(session_id);
        if holders.is_empty() {
            self.devices.remove(device);
            Some(device.clone())
        } else {
            None
        }
    }
}

impl LiveSessionRegistry {
    pub(crate) fn new(
        inner: Arc<dyn SharedSessionPersistence>,
        redis: ConnectionManager,
        front_id: &str,
    ) -> Self {
        Self {
            inner,
            state: Mutex::new(RegistryState::default()),
            key: format!("{LIVE_PREFIX}{front_id}"),
            redis,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot(&self) -> Vec<String> {
        self.lock()
            .devices
            .keys()
            .map(|(a, w)| member(a, w))
            .collect()
    }

    /// Republish the whole set and refresh the TTL.
    ///
    /// Built in a scratch key and renamed into place: a reader must never
    /// catch this mid-write, because an empty or half-filled set reads as
    /// "these miners are gone" and would fire an outage notification for
    /// every one of them.
    async fn publish(&self) {
        let members = self.snapshot();
        let mut conn = self.redis.clone();
        let scratch = format!("{}:next", self.key);

        let result: redis::RedisResult<()> = async {
            let _: () = conn.del(&scratch).await?;
            let _: () = conn.sadd(&scratch, PRESENT).await?;
            for chunk in members.chunks(500) {
                let _: () = conn.sadd(&scratch, chunk).await?;
            }
            let _: () = conn.expire(&scratch, LIVE_TTL_SECS as i64).await?;
            let _: () = conn.rename(&scratch, &self.key).await?;
            Ok(())
        }
        .await;

        if let Err(err) = result {
            // The key keeps its old contents and its old TTL. If this
            // keeps failing the front drops out of the union and readers
            // stop concluding anything, which is the safe direction.
            warn!(%err, key = self.key, "live-sessions: publish failed");
        }
    }
}

#[async_trait]
impl SharedSessionPersistence for LiveSessionRegistry {
    async fn register_session(
        &self,
        session_id: &str,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
    ) {
        let added = self
            .lock()
            .add(session_id, (address.to_string(), worker.to_string()));
        if let Some((address, worker)) = added.vacated {
            let mut conn = self.redis.clone();
            if let Err(err) = conn
                .srem::<_, _, ()>(&self.key, member(&address, &worker))
                .await
            {
                warn!(%err, "live-sessions: releasing a re-registered session's previous device failed");
            }
        }
        if added.became_live {
            let mut conn = self.redis.clone();
            // Incremental so a fresh connect is visible before the next
            // republish; the republish is what heals any drift.
            // The tombstone rides along so a key created here, before
            // the first republish, also survives its last SREM.
            //
            // One MULTI/EXEC, not two commands: when this call is what
            // creates the key, a SADD that lands without its EXPIRE
            // leaves a key that never expires — and since the front id
            // is a fresh UUID per process, no later process ever writes
            // that key again. It would claim its miners are online
            // forever, which is exactly what the TTL exists to prevent.
            let queued: redis::RedisResult<()> = redis::pipe()
                .atomic()
                .sadd(&self.key, &[member(address, worker), PRESENT.to_string()])
                .ignore()
                .expire(&self.key, LIVE_TTL_SECS as i64)
                .ignore()
                .query_async(&mut conn)
                .await;
            if let Err(err) = queued {
                warn!(%err, "live-sessions: incremental add failed");
            }
        }
        self.inner
            .register_session(session_id, address, worker, user_agent)
            .await;
    }

    async fn deregister_session(&self, session_id: &str) {
        let emptied = self.lock().remove(session_id);
        if let Some((address, worker)) = emptied {
            let mut conn = self.redis.clone();
            if let Err(err) = conn
                .srem::<_, _, ()>(&self.key, member(&address, &worker))
                .await
            {
                warn!(%err, "live-sessions: incremental remove failed");
            }
        }
        self.inner.deregister_session(session_id).await;
    }
}

/// Handle for the republish task.
pub(crate) struct LiveSessionPublisherHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl LiveSessionPublisherHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "live-sessions: publisher join failed");
        }
    }
}

/// Republish this front's set on a fixed interval, which is also what
/// keeps its key alive.
pub(crate) fn spawn_publisher(registry: Arc<LiveSessionRegistry>) -> LiveSessionPublisherHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(PUBLISH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(
            interval_s = PUBLISH_INTERVAL.as_secs(),
            key = registry.key,
            "live-sessions: publishing this front's live set"
        );
        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                _ = tick.tick() => registry.publish().await,
            }
        }
        info!("live-sessions: publisher stopped");
    });
    LiveSessionPublisherHandle { cancel, task }
}

/// Reader side: the union of every front's live set.
#[derive(Clone)]
pub(crate) struct RedisLiveSessions {
    redis: ConnectionManager,
}

impl RedisLiveSessions {
    pub(crate) fn new(redis: ConnectionManager) -> Self {
        Self { redis }
    }

    /// Every `(address, worker)` any front currently holds open.
    ///
    /// `None` means **no front is publishing** — not "nothing is
    /// connected". The two are indistinguishable from here, and treating
    /// the second as the first would report the entire pool as offline
    /// the moment the publisher is behind or a deploy is mid-flight.
    pub(crate) async fn union(&self) -> Option<HashSet<(String, String)>> {
        let mut conn = self.redis.clone();
        let mut keys: Vec<String> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let scan: redis::RedisResult<(u64, Vec<String>)> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{LIVE_PREFIX}*"))
                .arg("COUNT")
                .arg(200)
                .query_async(&mut conn)
                .await;
            match scan {
                Ok((next, found)) => {
                    // Skip the scratch keys a republish builds in.
                    keys.extend(found.into_iter().filter(|k| !k.ends_with(":next")));
                    cursor = next;
                    if cursor == 0 {
                        break;
                    }
                }
                Err(err) => {
                    warn!(%err, "live-sessions: scan failed");
                    return None;
                }
            }
        }
        if keys.is_empty() {
            warn!("live-sessions: no front is publishing — drawing no conclusion");
            return None;
        }

        let mut out = HashSet::new();
        for key in keys {
            match conn.smembers::<_, Vec<String>>(&key).await {
                // Redis drops a set with its last member, and the
                // tombstone means a published key always has one — so
                // "empty" is not a front holding nothing, it is a key
                // that expired between the scan above and this read.
                // Folding it in as empty would silently drop everything
                // that front was carrying, and with a single front the
                // whole pool would read as offline.
                Ok(members) if members.is_empty() => {
                    warn!(
                        key,
                        "live-sessions: key vanished mid-read — drawing no conclusion"
                    );
                    return None;
                }
                Ok(members) => {
                    for m in members {
                        if let Some((address, worker)) = m.split_once('\u{1f}') {
                            if address.is_empty() {
                                continue; // the tombstone
                            }
                            out.insert((address.to_string(), worker.to_string()));
                        }
                    }
                }
                Err(err) => {
                    // A partial union would under-report and invent
                    // outages; better to retry on the next sweep.
                    warn!(%err, key, "live-sessions: read failed");
                    return None;
                }
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tokio::io::AsyncWriteExt;

    const REDIS_URL: &str = "redis://127.0.0.1:16379";
    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    /// Connect and take the index over — FLUSHDB on entry. For tests that
    /// assert on the union as a whole, which only means anything if no
    /// other front's key is present. There are only 16 Redis databases and
    /// every test target in this binary runs as a thread in one process,
    /// so an index taken here is taken from the whole binary; prefer
    /// [`connect_redis_or_skip_shared`] where the test can tolerate
    /// company.
    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let mut conn = connect_redis_or_skip_shared(db).await?;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.ok()?;
        Some(conn)
    }

    /// Connect without flushing. Safe to share an index, as long as the
    /// caller namespaces by its own front id and never asserts on
    /// anything but its own devices — flushing would buy no isolation
    /// there and would wipe whatever a sibling is mid-way through.
    async fn connect_redis_or_skip_shared(db: u8) -> Option<ConnectionManager> {
        let client = redis::Client::open(format!("{REDIS_URL}/{db}")).ok()?;
        tokio::time::timeout(StdDuration::from_secs(2), ConnectionManager::new(client))
            .await
            .ok()?
            .ok()
    }

    /// A no-op inner hook — the registry decorates the real persistence,
    /// and these tests are about the set it maintains alongside it.
    struct NoopPersistence;

    #[async_trait]
    impl SharedSessionPersistence for NoopPersistence {
        async fn register_session(&self, _: &str, _: &str, _: &str, _: Option<&str>) {}
        async fn deregister_session(&self, _: &str) {}
    }

    fn registry(redis: ConnectionManager, id: &str) -> LiveSessionRegistry {
        LiveSessionRegistry::new(Arc::new(NoopPersistence), redis, id)
    }

    /// The whole point of a refcount: a rental source's rigs rotate
    /// individually, and one of them leaving is not the worker going
    /// offline. Drives the real trait methods, not a re-implementation.
    #[tokio::test]
    async fn a_device_leaves_the_live_set_only_with_its_last_session() {
        let Some(redis) = connect_redis_or_skip(13).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reg = registry(redis.clone(), "front-a");
        let reader = RedisLiveSessions::new(redis);
        let device = (ADDR.to_string(), "mrr".to_string());

        for sid in ["s1", "s2", "s3"] {
            reg.register_session(sid, ADDR, "mrr", None).await;
        }
        assert!(reader.union().await.expect("published").contains(&device));

        for sid in ["s1", "s2"] {
            reg.deregister_session(sid).await;
            assert!(
                reader.union().await.expect("published").contains(&device),
                "{sid} was not the last session"
            );
        }

        reg.deregister_session("s3").await;
        let union = reader
            .union()
            .await
            .expect("the front is still alive, it just holds nothing");
        assert!(!union.contains(&device), "the last session closed");
        assert!(union.is_empty());
    }

    /// Every route that can CREATE this front's key has to leave a TTL on
    /// it. "A dead front disappears by itself" is the property the whole
    /// design rests on, and it is unrecoverable if it ever fails: the
    /// front id is a fresh UUID per process, so no later process writes
    /// that key again and nothing else ever cleans it — it would claim
    /// its miners are online forever.
    ///
    /// This pins the invariant, not the atomicity. That the SADD and the
    /// EXPIRE cannot be separated is argued from their being one
    /// MULTI/EXEC; a process dying between two awaits is not something a
    /// unit test can stage.
    #[tokio::test]
    async fn a_key_the_incremental_path_creates_always_expires() {
        // Shares DB 1 with the two socket tests: this one only ever reads
        // the TTL of its own key, so a sibling's key in the index is
        // irrelevant — and none of the three flushes.
        let Some(mut redis) = connect_redis_or_skip_shared(1).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        // No publish() first: this is the narrow case where a session
        // registers before the publisher's first tick, so the register is
        // what brings the key into existence. A key left by a previous run
        // would already have a TTL and make that vacuously true.
        let _: Result<(), _> = redis::cmd("DEL")
            .arg("device:live:front-fresh")
            .query_async::<()>(&mut redis)
            .await;
        let reg = registry(redis.clone(), "front-fresh");
        reg.register_session("s1", ADDR, "rig-a", None).await;

        let ttl: i64 = redis::cmd("TTL")
            .arg("device:live:front-fresh")
            .query_async(&mut redis)
            .await
            .expect("ttl");
        assert!(
            ttl > 0,
            "the key exists without a TTL ({ttl}) — a dead front would \
             claim these miners forever"
        );
    }

    /// No front publishing is NOT "nothing is connected". Reporting the
    /// second would fire an outage notification for every miner on the
    /// pool during a front deploy.
    #[tokio::test]
    async fn an_absent_publisher_is_unknown_not_empty() {
        let Some(redis) = connect_redis_or_skip(14).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reader = RedisLiveSessions::new(redis.clone());
        assert!(reader.union().await.is_none(), "nothing published yet");

        // A front with genuinely zero miners is a real, empty answer.
        let reg = registry(redis, "front-empty");
        reg.publish().await;
        let union = reader.union().await.expect("a front is publishing");
        assert!(
            union.is_empty(),
            "empty is a conclusion once someone says it"
        );
    }

    /// The republish must be atomic. A reader that catches it mid-write
    /// sees a partial set and reads every missing device as an outage —
    /// so this drives a reader concurrently with a republish loop and
    /// asserts the count is never anything but whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_republish_is_never_observed_partially() {
        let Some(redis) = connect_redis_or_skip(15).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reg = Arc::new(registry(redis.clone(), "front-b"));
        for i in 0..50 {
            reg.register_session(&format!("s{i}"), ADDR, &format!("rig{i}"), None)
                .await;
        }
        reg.publish().await;

        let stop = CancellationToken::new();
        let writer = {
            let reg = Arc::clone(&reg);
            let stop = stop.clone();
            tokio::spawn(async move {
                while !stop.is_cancelled() {
                    reg.publish().await;
                }
            })
        };

        let reader = RedisLiveSessions::new(redis);
        let mut observed_min = usize::MAX;
        for _ in 0..300 {
            if let Some(union) = reader.union().await {
                observed_min = observed_min.min(union.len());
            }
        }
        stop.cancel();
        let _ = writer.await;

        assert_eq!(
            observed_min, 50,
            "a reader saw a partial set — the republish is not atomic"
        );
    }

    /// Two fronts each publish their own key; a reader takes the union,
    /// and one front going away must not take the other's miners with it.
    #[tokio::test]
    async fn the_union_spans_fronts_and_survives_one_disappearing() {
        // DB 2, not 12: every test target in this binary runs as a thread
        // in one process and FLUSHDBs its index on entry, so two sharing
        // an index wipe each other. `cache_sync` already owns 12.
        let Some(mut redis) = connect_redis_or_skip(2).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let a = registry(redis.clone(), "front-1");
        let b = registry(redis.clone(), "front-2");
        a.register_session("s1", ADDR, "rig-a", None).await;
        b.register_session("s2", ADDR, "rig-b", None).await;
        a.publish().await;
        b.publish().await;

        let reader = RedisLiveSessions::new(redis.clone());
        let union = reader.union().await.expect("published");
        assert!(union.contains(&(ADDR.to_string(), "rig-a".to_string())));
        assert!(union.contains(&(ADDR.to_string(), "rig-b".to_string())));

        // Front 1 is killed — its key expires rather than being cleaned up.
        let _: () = redis::cmd("DEL")
            .arg("device:live:front-1")
            .query_async(&mut redis)
            .await
            .expect("del");
        let union = reader.union().await.expect("front 2 still publishes");
        assert!(
            !union.contains(&(ADDR.to_string(), "rig-a".to_string())),
            "the dead front stops claiming its miners"
        );
        assert!(
            union.contains(&(ADDR.to_string(), "rig-b".to_string())),
            "and takes nobody else with it"
        );
    }

    /// A key can expire between the SCAN that finds it and the SMEMBERS
    /// that reads it. `SMEMBERS` on a missing key answers with an empty
    /// set rather than an error, so counting that as a real answer drops
    /// everything the front was carrying — and with a single front, the
    /// whole pool reads as offline and every subscriber is paged.
    ///
    /// Driven concurrently because that window is one round-trip wide.
    /// The invariant is absolute rather than statistical: this front
    /// holds exactly one device the entire time, so an empty union is
    /// never a correct answer, no matter when the read lands.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_key_that_vanishes_mid_read_is_unknown_not_empty() {
        let Some(redis) = connect_redis_or_skip(3).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reg = Arc::new(registry(redis.clone(), "front-expiring"));
        reg.register_session("s1", ADDR, "rig-a", None).await;
        reg.publish().await;

        // Churn the key the way an expiry followed by the next republish
        // does: gone, then whole again.
        let stop = CancellationToken::new();
        let churn = {
            let reg = Arc::clone(&reg);
            let stop = stop.clone();
            let mut conn = redis.clone();
            tokio::spawn(async move {
                while !stop.is_cancelled() {
                    let _: Result<(), _> = redis::cmd("DEL")
                        .arg("device:live:front-expiring")
                        .query_async::<()>(&mut conn)
                        .await;
                    reg.publish().await;
                }
            })
        };

        let reader = RedisLiveSessions::new(redis);
        let mut empty_answers = 0usize;
        for _ in 0..2000 {
            if reader.union().await.is_some_and(|u| u.is_empty()) {
                empty_answers += 1;
            }
        }
        stop.cancel();
        let _ = churn.await;

        assert_eq!(
            empty_answers, 0,
            "a vanished key was read as 'this front holds nothing' — that \
             reports every miner it carried as offline"
        );
    }

    /// The member encoding has to survive a round trip — an address and
    /// a worker name are both free-form.
    #[test]
    fn members_round_trip() {
        let m = member("bcrt1qexample", "rig.1 with spaces");
        let (a, w) = m.split_once('\u{1f}').expect("separator survives");
        assert_eq!(a, "bcrt1qexample");
        assert_eq!(w, "rig.1 with spaces");
    }

    /// A deregister can arrive for a session that never registered (a
    /// connection dropped before authorize) — it must not panic or
    /// wrongly report a device gone.
    #[test]
    fn deregistering_an_unknown_session_is_a_no_op() {
        let mut state = RegistryState::default();
        assert!(state.remove("never-seen").is_none());
        assert!(state.devices.is_empty());
    }

    /// SV2 fires one `register_session` per channel opened, all carrying
    /// the SAME session id and the connection's locked worker. Re-recording
    /// an unchanged device must release nothing: a rental source opening
    /// its second channel would otherwise take its own worker offline —
    /// which is the exact spam this feature exists to stop.
    #[test]
    fn re_registering_the_same_device_releases_nothing() {
        let mut state = RegistryState::default();
        let device = (ADDR.to_string(), "mrr".to_string());

        assert!(state.add("s1", device.clone()).became_live);
        for _ in 0..4 {
            let again = state.add("s1", device.clone());
            assert!(
                again.vacated.is_none(),
                "an unchanged device must never be released"
            );
        }
        assert!(state.devices.contains_key(&device), "still held");
        assert_eq!(state.remove("s1"), Some(device));
        assert!(state.devices.is_empty(), "one deregister still ends it");
    }

    /// One SV1 connection may authorize more than once — `handle_authorize`
    /// is unconditional, so a proxy that switches worker names re-registers
    /// the SAME session id under a different device. The device it left
    /// must not keep a phantom holder: nothing will ever remove it, so the
    /// worker would be reported connected for the life of the process and
    /// could never go offline again.
    ///
    /// Asserted after a full republish, so this is about the registry's
    /// own state and not about a missed incremental SREM.
    #[tokio::test]
    async fn re_authorizing_under_a_new_worker_leaves_nothing_behind() {
        let Some(redis) = connect_redis_or_skip(4).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reg = registry(redis.clone(), "front-reauth");
        let reader = RedisLiveSessions::new(redis);

        reg.register_session("s1", ADDR, "rig-a", None).await;
        reg.register_session("s1", ADDR, "rig-b", None).await;
        reg.deregister_session("s1").await;
        reg.publish().await;

        let union = reader.union().await.expect("the front is still alive");
        assert!(
            union.is_empty(),
            "the connection is gone, so nothing may still be held: {union:?}"
        );
    }

    /// How the fake miner below hangs up.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Hangup {
        /// `shutdown()` first: the server reads EOF.
        Fin,
        /// `SO_LINGER(0)`, then close: the server's read fails with
        /// ECONNRESET. What a power cut, a yanked cable or a NAT timeout
        /// actually looks like on the wire.
        Reset,
    }

    impl Hangup {
        /// Own front key + own worker per mode, so the two tests below can
        /// share one Redis index instead of eating two of the sixteen.
        /// Neither asserts on the union as a whole — only on its own
        /// device — so a sibling's key in there is harmless.
        fn scope(self) -> (&'static str, &'static str) {
            match self {
                Hangup::Fin => ("front-hangup-fin", "rig-fin"),
                Hangup::Reset => ("front-hangup-reset", "rig-reset"),
            }
        }
    }

    /// The two tests below differ in exactly one thing — how the socket
    /// dies. Everything else is shared so that difference is the only
    /// candidate explanation when one passes and the other does not.
    ///
    /// Drives a real `StratumV1Server` over a real socket rather than the
    /// trait methods, because what is under test is not the registry: it
    /// is whether the SV1 connection's exit path reaches
    /// `deregister_session` on every route out of its loop.
    async fn device_leaves_the_live_set_after(hangup: Hangup, redis_db: u8) -> bool {
        let Some(redis) = connect_redis_or_skip_shared(redis_db).await else {
            eprintln!("redis unreachable — skipping");
            return true; // treated as "nothing to assert", see call sites
        };
        // A real regtest address — the SV1 authorize handler validates it
        // against the network before it emits `Authorized`.
        const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

        let (front_id, worker) = hangup.scope();
        // Drop only THIS test's key, not the whole index. A key left by a
        // previous run still has most of its 90 s TTL and would answer the
        // sync point below before the session has actually registered.
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(format!("{LIVE_PREFIX}{front_id}"))
            .query_async::<()>(&mut redis.clone())
            .await;
        let reg = Arc::new(registry(redis.clone(), front_id));
        let reader = RedisLiveSessions::new(redis);
        let device = (MINER_ADDR.to_string(), worker.to_string());

        let mut hooks = bp_stratum_v1::ServerHooks::no_op();
        hooks.session_persistence = Arc::new(bp_stratum_v1::Sv1SessionPersistenceAdapter::new(
            Arc::clone(&reg),
        ));

        // The template broadcast is deliberately never fed. Authorize does
        // not need a template — `apply_outcome` skips the post-authorize
        // notify when there is none — and this is about how the connection
        // ends, not about mining. `_template_tx` stays alive so the
        // server's receiver never closes.
        let (_template_tx, updates_rx) = tokio::sync::broadcast::channel(8);
        let server = bp_stratum_v1::StratumV1Server::spawn(
            bp_stratum_v1::ServerConfig::defaults_for(bitcoin::Network::Regtest),
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            hooks,
            bp_stratum_v1::SharedExtranonce::new(),
            Arc::new(bp_mining_job::MiningJobCache::new()),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let port_config = bp_stratum_v1::PortConfig::new(addr.port(), 1.0e-18);
        let accepting = server.clone();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            socket.set_nodelay(true).ok();
            accepting.accept_connection(socket, port_config);
        });

        // NOT split into halves: `OwnedWriteHalf` shuts the write side
        // down on drop, which turns every hangup into a clean FIN and
        // would make the Reset case silently test the Fin case.
        let mut miner = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the server");
        miner.set_nodelay(true).ok();
        if hangup == Hangup::Reset {
            socket2::SockRef::from(&miner)
                .set_linger(Some(StdDuration::ZERO))
                .expect("set_linger");
        }
        for line in [
            "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"fake-miner/1.0\"]}\n".to_string(),
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{MINER_ADDR}.{worker}\",\"x\"]}}\n"
            ),
        ] {
            miner
                .write_all(line.as_bytes())
                .await
                .expect("write to the server");
        }

        // Sync point: the responses are deliberately left unread, so the
        // live set is what says the session actually registered.
        assert!(
            wait_for_union(&reader, |u| u.contains(&device)).await,
            "the front never published the authorized session"
        );

        if hangup == Hangup::Fin {
            miner.shutdown().await.expect("half-close");
        }
        drop(miner);

        let left = wait_for_union(&reader, |u| !u.contains(&device)).await;
        server.shutdown().await;
        left
    }

    /// The baseline. A miner that closes cleanly leaves the live set —
    /// this is what makes the reset case below a statement about the
    /// reset and not about the harness.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cleanly_closed_connection_leaves_the_live_set() {
        assert!(
            device_leaves_the_live_set_after(Hangup::Fin, 1).await,
            "a clean close must deregister the session"
        );
    }

    /// A miner that vanishes without closing cleanly — power cut, NAT
    /// timeout, a yanked cable — resets the connection instead of sending
    /// a FIN. That is the most common way an unstable miner disconnects
    /// and precisely the case the offline notification exists for, so it
    /// has to reach the live set too. A session left behind here is
    /// permanent: nothing else can ever remove it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reset_connection_still_leaves_the_live_set() {
        assert!(
            device_leaves_the_live_set_after(Hangup::Reset, 1).await,
            "the reset connection never left the live set — that worker can \
             never be reported offline again"
        );
    }

    /// Poll the union until `pred` holds. Generous: the connection task
    /// has to notice the socket died and unwind before anything changes.
    async fn wait_for_union(
        reader: &RedisLiveSessions,
        pred: impl Fn(&HashSet<(String, String)>) -> bool,
    ) -> bool {
        for _ in 0..100 {
            if let Some(union) = reader.union().await {
                if pred(&union) {
                    return true;
                }
            }
            tokio::time::sleep(StdDuration::from_millis(50)).await;
        }
        false
    }
}
