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

impl RegistryState {
    /// Record a session for a device. Returns `true` when this is the
    /// device's FIRST session, i.e. it just became live.
    fn add(&mut self, session_id: &str, device: (String, String)) -> bool {
        self.sessions.insert(session_id.to_string(), device.clone());
        let holders = self.devices.entry(device).or_default();
        holders.insert(session_id.to_string());
        holders.len() == 1
    }

    /// Drop a session. Returns the device only when that was its LAST
    /// session — one rig of a rental source rotating out must not take
    /// the whole worker offline.
    fn remove(&mut self, session_id: &str) -> Option<(String, String)> {
        let device = self.sessions.remove(session_id)?;
        let holders = self.devices.get_mut(&device)?;
        holders.remove(session_id);
        if holders.is_empty() {
            self.devices.remove(&device);
            Some(device)
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
        let became_live = self
            .lock()
            .add(session_id, (address.to_string(), worker.to_string()));
        if became_live {
            let mut conn = self.redis.clone();
            // Incremental so a fresh connect is visible before the next
            // republish; the republish is what heals any drift.
            // The tombstone rides along so a key created here, before
            // the first republish, also survives its last SREM.
            if let Err(err) = conn
                .sadd::<_, _, ()>(&self.key, &[member(address, worker), PRESENT.to_string()])
                .await
            {
                warn!(%err, "live-sessions: incremental add failed");
            } else if let Err(err) = conn.expire::<_, ()>(&self.key, LIVE_TTL_SECS as i64).await {
                warn!(%err, "live-sessions: incremental expire failed");
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

    const REDIS_URL: &str = "redis://127.0.0.1:16379";
    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let client = redis::Client::open(format!("{REDIS_URL}/{db}")).ok()?;
        let mut conn =
            tokio::time::timeout(StdDuration::from_secs(2), ConnectionManager::new(client))
                .await
                .ok()?
                .ok()?;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.ok()?;
        Some(conn)
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
        let Some(mut redis) = connect_redis_or_skip(12).await else {
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
}
