// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who is actually connected, published by the front that holds the sockets:
//! everything else (share silence, connect events) only infers it. Mirrored to
//! Redis per front as a per-device session count and a session → device map;
//! each key has a TTL so a dead front drops out, and no fronts at all means "unknown".

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bp_client_live::{bounded, LiveReadError};
use bp_share_hook::SharedSessionPersistence;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Key prefix of the per-device count; one key per front process.
const LIVE_PREFIX: &str = "device:live:";

/// Key prefix of the per-session projection. Its own prefix so the `SCAN`
/// behind [`RedisLiveSessions::union`] never picks it up.
const SESSION_PREFIX: &str = "session:live:";

/// How often the whole set is republished. Also bounds how stale a
/// reader's answer can be.
const PUBLISH_INTERVAL: Duration = Duration::from_secs(20);

/// Key lifetime. A front that stops republishing drops out of the union
/// after this; generous enough that one slow tick is not an outage.
const LIVE_TTL_SECS: u64 = 90;

fn member(address: &str, worker: &str) -> String {
    format!("{address}\u{1f}{worker}")
}

/// Tombstone field, always present and filtered out on read. Redis drops a
/// hash with its last field, so this keeps "this front is alive and holds
/// nothing" distinguishable from "no front is publishing".
const PRESENT: &str = "\u{1f}present";

/// Live sessions held by this process, mirrored to Redis. Decorates a
/// [`SharedSessionPersistence`]; every call still reaches the inner one.
pub(crate) struct LiveSessionRegistry {
    inner: Arc<dyn SharedSessionPersistence>,
    state: Mutex<RegistryState>,
    /// Unique per process, so two fronts never overwrite each other.
    key: String,
    /// The per-session projection, same front id.
    session_key: String,
    redis: ConnectionManager,
}

/// One register/deregister as the per-session projection sees it.
enum SessionChange {
    /// The session is now held under this device (`member` encoding).
    Held(String, String),
    /// The session left.
    Released(String),
}

#[derive(Default)]
struct RegistryState {
    /// `(address, worker)` → the session ids holding it open. A device
    /// leaves only with its LAST session: one rig rotating out is not an outage.
    devices: HashMap<(String, String), HashSet<String>>,
    /// `session_id` → the device it belongs to. Deregistration only
    /// carries the session id, so the mapping has to be kept here.
    sessions: HashMap<String, (String, String)>,
}

/// The per-device projection: `member` → open session count.
type DeviceCounts = Vec<(String, usize)>;
/// The per-session projection: session id → `member` of its device.
type HeldSessions = Vec<(String, String)>;

/// Devices whose published session count has to be updated; zero means
/// gone. A count, not a flag: "one of three rigs is gone" differs from
/// "all three are gone" to the owner.
type Changed = Vec<((String, String), usize)>;

impl RegistryState {
    /// Record a session for a device.
    fn add(&mut self, session_id: &str, device: (String, String)) -> Changed {
        let previous = self.sessions.insert(session_id.to_string(), device.clone());
        // A connection may re-authorize under a different worker. Release
        // the old device: a stale holder entry would never be removed.
        let mut changed = Changed::new();
        if let Some(previous) = previous {
            if previous != device {
                changed.push(self.release(session_id, &previous));
            }
        }
        let holders = self.devices.entry(device.clone()).or_default();
        holders.insert(session_id.to_string());
        changed.push((device, holders.len()));
        changed
    }

    /// Drop a session, reporting the device's remaining session count
    /// (`0` = the last rig left).
    fn remove(&mut self, session_id: &str) -> Option<((String, String), usize)> {
        let device = self.sessions.remove(session_id)?;
        Some(self.release(session_id, &device))
    }

    fn release(
        &mut self,
        session_id: &str,
        device: &(String, String),
    ) -> ((String, String), usize) {
        let Some(holders) = self.devices.get_mut(device) else {
            return (device.clone(), 0);
        };
        holders.remove(session_id);
        let left = holders.len();
        if left == 0 {
            self.devices.remove(device);
        }
        (device.clone(), left)
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
            session_key: format!("{SESSION_PREFIX}{front_id}"),
            redis,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Both projections from one lock, so they agree.
    fn snapshot(&self) -> (DeviceCounts, HeldSessions) {
        let state = self.lock();
        let devices = state
            .devices
            .iter()
            .map(|((a, w), holders)| (member(a, w), holders.len()))
            .collect();
        let sessions = state
            .sessions
            .iter()
            .map(|(sid, (a, w))| (sid.clone(), member(a, w)))
            .collect();
        (devices, sessions)
    }

    /// Write one register/deregister through to both hashes. Tombstones and
    /// TTLs ride in the same MULTI: a key created without its expiry is never
    /// written again (fresh front id per start) and would claim its miners
    /// are online forever.
    async fn apply(&self, changed: Changed, session: SessionChange) {
        let mut conn = self.redis.clone();
        let mut pipe = redis::pipe();
        pipe.atomic().hset(&self.key, PRESENT, 0).ignore();
        pipe.hset(&self.session_key, PRESENT, 0).ignore();
        for ((address, worker), count) in &changed {
            let field = member(address, worker);
            if *count == 0 {
                pipe.hdel(&self.key, field).ignore();
            } else {
                pipe.hset(&self.key, field, *count).ignore();
            }
        }
        match session {
            SessionChange::Held(sid, device) => {
                pipe.hset(&self.session_key, sid, device).ignore();
            }
            SessionChange::Released(sid) => {
                pipe.hdel(&self.session_key, sid).ignore();
            }
        }
        pipe.expire(&self.key, LIVE_TTL_SECS as i64).ignore();
        pipe.expire(&self.session_key, LIVE_TTL_SECS as i64)
            .ignore();
        if let Err(err) = pipe.query_async::<()>(&mut conn).await {
            // The republish heals whatever this missed.
            warn!(%err, "live-sessions: incremental update failed");
        }
    }

    /// Republish both projections and refresh their TTLs. Built in a scratch
    /// key and renamed into place: a half-filled set read mid-write would
    /// report every missing miner as gone.
    async fn publish(&self) {
        let (devices, sessions) = self.snapshot();
        let mut conn = self.redis.clone();
        if let Err(err) = publish_hash(&mut conn, &self.key, &devices).await {
            // Repeated failure lets the key expire, so readers stop
            // concluding anything: the safe direction.
            warn!(%err, key = %self.key, "live-sessions: publish failed");
        }
        if let Err(err) = publish_hash(&mut conn, &self.session_key, &sessions).await {
            warn!(%err, key = %self.session_key, "live-sessions: publish failed");
        }
    }
}

/// Build `members` (plus the tombstone) in `<key>:next` and rename it
/// over `key`, so the swap is one atomic step for every reader.
async fn publish_hash<V: redis::ToRedisArgs + Send + Sync>(
    conn: &mut ConnectionManager,
    key: &str,
    members: &[(String, V)],
) -> redis::RedisResult<()> {
    let scratch = format!("{key}:next");
    let _: () = conn.del(&scratch).await?;
    let _: () = conn.hset(&scratch, PRESENT, 0).await?;
    for chunk in members.chunks(500) {
        let _: () = conn.hset_multiple(&scratch, chunk).await?;
    }
    let _: () = conn.expire(&scratch, LIVE_TTL_SECS as i64).await?;
    let _: () = conn.rename(&scratch, key).await?;
    Ok(())
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
        let changed = self
            .lock()
            .add(session_id, (address.to_string(), worker.to_string()));
        // Incremental so a fresh connect is visible before the next
        // republish; the republish is what heals any drift.
        self.apply(
            changed,
            SessionChange::Held(session_id.to_string(), member(address, worker)),
        )
        .await;
        self.inner
            .register_session(session_id, address, worker, user_agent)
            .await;
    }

    async fn deregister_session(&self, session_id: &str) {
        // Bound first so the guard drops before the await; an `if let`
        // would hold it across and the future would not be Send.
        let change = self.lock().remove(session_id);
        if let Some(change) = change {
            self.apply(
                vec![change],
                SessionChange::Released(session_id.to_string()),
            )
            .await;
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

    /// Open sessions per `(address, worker)`, summed across fronts.
    /// `None` means no front is publishing, not "nothing is connected":
    /// reading it as empty would report the whole pool offline mid-deploy.
    pub(crate) async fn union(&self) -> Option<HashMap<(String, String), usize>> {
        let keys = match self.scan_front_keys(LIVE_PREFIX).await {
            Ok(keys) => keys,
            Err(err) => {
                warn!(%err, "live-sessions: scan failed");
                return None;
            }
        };
        if keys.is_empty() {
            warn!("live-sessions: no front is publishing — drawing no conclusion");
            return None;
        }

        let mut conn = self.redis.clone();
        let mut out: HashMap<(String, String), usize> = HashMap::new();
        for key in keys {
            match bounded(conn.hgetall::<_, HashMap<String, usize>>(&key)).await {
                // The tombstone means a published key is never empty, so
                // empty is a key that expired since the scan. Folding it
                // in would drop everything that front was carrying.
                Ok(fields) if fields.is_empty() => {
                    warn!(
                        key,
                        "live-sessions: key vanished mid-read — drawing no conclusion"
                    );
                    return None;
                }
                Ok(fields) => {
                    for (field, count) in fields {
                        if let Some((address, worker)) = field.split_once('\u{1f}') {
                            if address.is_empty() {
                                continue; // the tombstone
                            }
                            // Summed: one worker may have rigs on several fronts.
                            *out.entry((address.to_string(), worker.to_string()))
                                .or_insert(0) += count;
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

    /// `session_id → (address, worker)` across fronts. `Err`: Redis could not
    /// be asked (the cron skips its tick). `Ok(None)`: no front publishes
    /// sessions, caller falls back. `Ok(Some)`: first-hand; an absent session
    /// is held by no front.
    pub(crate) async fn sessions(
        &self,
    ) -> Result<Option<HashMap<String, (String, String)>>, LiveReadError> {
        let keys = self.scan_front_keys(SESSION_PREFIX).await?;
        if keys.is_empty() {
            return Ok(None);
        }
        let mut conn = self.redis.clone();
        let mut out: HashMap<String, (String, String)> = HashMap::new();
        for key in keys {
            let fields: HashMap<String, String> = bounded(conn.hgetall(&key)).await?;
            if fields.is_empty() {
                // Expired since the scan; see `union`.
                warn!(
                    key,
                    "live-sessions: session key vanished mid-read — drawing no conclusion"
                );
                return Ok(None);
            }
            for (session_id, device) in fields {
                if session_id == PRESENT {
                    continue;
                }
                if let Some((address, worker)) = device.split_once('\u{1f}') {
                    out.insert(session_id, (address.to_string(), worker.to_string()));
                }
            }
        }
        Ok(Some(out))
    }

    /// Every front's key under `prefix`, minus republish scratch keys.
    async fn scan_front_keys(&self, prefix: &str) -> Result<Vec<String>, LiveReadError> {
        let mut conn = self.redis.clone();
        let mut keys: Vec<String> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next, found): (u64, Vec<String>) = bounded(
                redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(format!("{prefix}*"))
                    .arg("COUNT")
                    .arg(200)
                    .query_async(&mut conn),
            )
            .await?;
            keys.extend(found.into_iter().filter(|k| !k.ends_with(":next")));
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_test_support::{
        connect_redis_in_range_no_flush, connect_redis_in_range_or_skip, redis_db,
    };
    use std::time::Duration as StdDuration;
    use tokio::io::AsyncWriteExt;

    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    /// No-op inner hook: these tests are about the registry's own set.
    struct NoopPersistence;

    #[async_trait]
    impl SharedSessionPersistence for NoopPersistence {
        async fn register_session(&self, _: &str, _: &str, _: &str, _: Option<&str>) {}
        async fn deregister_session(&self, _: &str) {}
    }

    fn registry(redis: ConnectionManager, id: &str) -> LiveSessionRegistry {
        LiveSessionRegistry::new(Arc::new(NoopPersistence), redis, id)
    }

    /// A device stays live until its last session deregisters.
    #[tokio::test]
    async fn a_device_leaves_the_live_set_only_with_its_last_session() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 13).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reg = registry(redis.clone(), "front-a");
        let reader = RedisLiveSessions::new(redis);
        let device = (ADDR.to_string(), "mrr".to_string());

        for sid in ["s1", "s2", "s3"] {
            reg.register_session(sid, ADDR, "mrr", None).await;
        }
        assert!(reader
            .union()
            .await
            .expect("published")
            .contains_key(&device));

        for sid in ["s1", "s2"] {
            reg.deregister_session(sid).await;
            assert!(
                reader
                    .union()
                    .await
                    .expect("published")
                    .contains_key(&device),
                "{sid} was not the last session"
            );
        }

        reg.deregister_session("s3").await;
        let union = reader
            .union()
            .await
            .expect("the front is still alive, it just holds nothing");
        assert!(!union.contains_key(&device), "the last session closed");
        assert!(union.is_empty());
    }

    /// A key created by the incremental path carries a TTL.
    #[tokio::test]
    async fn a_key_the_incremental_path_creates_always_expires() {
        let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 9).await
        else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        // No publish() first, so the register creates the key; the connect
        // flushed the database, so no leftover key can satisfy this.
        let reg = registry(redis.clone(), "front-fresh");
        reg.register_session("s1", ADDR, "rig-a", None).await;

        for key in ["device:live:front-fresh", "session:live:front-fresh"] {
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(&mut redis)
                .await
                .expect("ttl");
            assert!(
                ttl > 0,
                "register_session left no TTL on {key} (TTL {ttl}: \
                 -1 = no expiry, -2 = no such key) — a dead front would claim \
                 these miners forever"
            );
        }
    }

    /// Session projection: unknown until published (device counts alone do not
    /// count), then first-hand, incremental writes included; re-authorize moves it.
    #[tokio::test]
    async fn held_sessions_are_unknown_until_a_front_publishes_them() {
        let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 29).await
        else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reader = RedisLiveSessions::new(redis.clone());
        assert!(
            reader.sessions().await.expect("redis up").is_none(),
            "nothing published yet"
        );

        // A front that publishes device counts but no sessions.
        let _: () = redis::pipe()
            .atomic()
            .hset("device:live:front-old", PRESENT, 0)
            .ignore()
            .hset("device:live:front-old", member(ADDR, "rig-old"), 1)
            .ignore()
            .expire("device:live:front-old", 90)
            .ignore()
            .query_async(&mut redis)
            .await
            .expect("old front");
        assert!(reader.union().await.is_some(), "the old front counts");
        assert!(
            reader.sessions().await.expect("redis up").is_none(),
            "counts alone say nothing about sessions"
        );

        let reg = registry(redis, "front-new");
        reg.register_session("s1", ADDR, "rig-a", None).await;
        let held = reader
            .sessions()
            .await
            .expect("redis up")
            .expect("a front now publishes sessions");
        assert_eq!(
            held.get("s1"),
            Some(&(ADDR.to_string(), "rig-a".to_string())),
            "visible from the incremental write, before any republish"
        );

        reg.register_session("s1", ADDR, "rig-b", None).await;
        let held = reader
            .sessions()
            .await
            .expect("redis up")
            .expect("published");
        assert_eq!(
            held.get("s1").map(|(_, w)| w.as_str()),
            Some("rig-b"),
            "a re-authorize moves the session to its new device"
        );

        reg.deregister_session("s1").await;
        reg.publish().await;
        let held = reader
            .sessions()
            .await
            .expect("redis up")
            .expect("the front is alive, it just holds nothing");
        assert!(held.is_empty(), "the session left: {held:?}");
    }

    /// No front publishing reads as unknown, not as "nothing is connected".
    #[tokio::test]
    async fn an_absent_publisher_is_unknown_not_empty() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 14).await else {
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

    /// A reader concurrent with republishing never sees a partial set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_republish_is_never_observed_partially() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 15).await else {
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

    /// The union spans fronts, and one front vanishing keeps the other's miners.
    #[tokio::test]
    async fn the_union_spans_fronts_and_survives_one_disappearing() {
        let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 2).await
        else {
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
        assert!(union.contains_key(&(ADDR.to_string(), "rig-a".to_string())));
        assert!(union.contains_key(&(ADDR.to_string(), "rig-b".to_string())));

        // Front 1 is killed — its key expires rather than being cleaned up.
        let _: () = redis::cmd("DEL")
            .arg("device:live:front-1")
            .query_async(&mut redis)
            .await
            .expect("del");
        let union = reader.union().await.expect("front 2 still publishes");
        assert!(
            !union.contains_key(&(ADDR.to_string(), "rig-a".to_string())),
            "the dead front stops claiming its miners"
        );
        assert!(
            union.contains_key(&(ADDR.to_string(), "rig-b".to_string())),
            "and takes nobody else with it"
        );
    }

    /// A key expiring between SCAN and HGETALL reads as unknown, never empty.
    /// The front holds one device throughout, so empty is never correct.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_key_that_vanishes_mid_read_is_unknown_not_empty() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 3).await else {
            eprintln!("redis unreachable — skipping");
            return;
        };
        let reg = Arc::new(registry(redis.clone(), "front-expiring"));
        reg.register_session("s1", ADDR, "rig-a", None).await;
        reg.publish().await;

        // Churn the key like an expiry followed by a republish.
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

    /// The member encoding round-trips free-form worker names.
    #[test]
    fn members_round_trip() {
        let m = member("bcrt1qexample", "rig.1 with spaces");
        let (a, w) = m.split_once('\u{1f}').expect("separator survives");
        assert_eq!(a, "bcrt1qexample");
        assert_eq!(w, "rig.1 with spaces");
    }

    /// Deregistering a never-registered session is a no-op.
    #[test]
    fn deregistering_an_unknown_session_is_a_no_op() {
        let mut state = RegistryState::default();
        assert!(state.remove("never-seen").is_none());
        assert!(state.devices.is_empty());
    }

    /// Re-registering the same session and device (one per SV2 channel)
    /// neither releases nor inflates the device.
    #[test]
    fn re_registering_the_same_device_releases_nothing() {
        let mut state = RegistryState::default();
        let device = (ADDR.to_string(), "mrr".to_string());

        assert_eq!(state.add("s1", device.clone()), vec![(device.clone(), 1)]);
        for _ in 0..4 {
            assert_eq!(state.add("s1", device.clone()), vec![(device.clone(), 1)]);
        }
        assert!(state.devices.contains_key(&device), "still held");
        assert_eq!(state.remove("s1"), Some((device, 0)));
        assert!(state.devices.is_empty(), "one deregister still ends it");
    }

    /// Re-authorizing under a new worker leaves no phantom holder on the old
    /// device (checked after a full republish).
    #[tokio::test]
    async fn re_authorizing_under_a_new_worker_leaves_nothing_behind() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 4).await else {
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
        let held = reader
            .sessions()
            .await
            .expect("redis up")
            .expect("the front is still alive");
        assert!(held.is_empty(), "nor may the session projection: {held:?}");
    }

    /// How the fake miner below hangs up.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Hangup {
        /// `shutdown()` first: the server reads EOF.
        Fin,
        /// `SO_LINGER(0)`, then close: the server's read fails with
        /// ECONNRESET, as after a power cut or NAT timeout.
        Reset,
    }

    impl Hangup {
        /// Own front key + worker per mode, so both tests share one Redis
        /// index. Safe only because neither flushes nor asserts on the
        /// union as a whole.
        fn scope(self) -> (&'static str, &'static str) {
            match self {
                Hangup::Fin => ("front-hangup-fin", "rig-fin"),
                Hangup::Reset => ("front-hangup-reset", "rig-reset"),
            }
        }
    }

    /// Shared body of the two hangup tests, which differ only in how the
    /// socket dies. A real `StratumV1Server` over a real socket: under test is
    /// whether every exit path of the connection reaches `deregister_session`.
    async fn device_leaves_the_live_set_after(hangup: Hangup, index: u8) -> bool {
        let Some(redis) = connect_redis_in_range_no_flush(redis_db::BLITZPOOL_BIN, index).await
        else {
            eprintln!("redis unreachable — skipping");
            return true; // treated as "nothing to assert", see call sites
        };
        // Authorize validates the address against the network.
        const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

        let (front_id, worker) = hangup.scope();
        // Drop only this test's key: a leftover from a previous run would
        // satisfy the sync point below before the session registered.
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(format!("{LIVE_PREFIX}{front_id}"))
            .query_async::<()>(&mut redis.clone())
            .await;
        let reg = Arc::new(registry(redis.clone(), front_id));
        let reader = RedisLiveSessions::new(redis);
        let device = (MINER_ADDR.to_string(), worker.to_string());

        let mut hooks = bp_stratum_v1::ServerHooks::no_op();
        hooks.session_persistence = Arc::clone(&reg) as _;

        // Templates are never fed: authorize does not need one. `_template_tx`
        // stays alive so the server's receiver never closes.
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

        // Not split into halves: `OwnedWriteHalf` sends FIN on drop, which
        // would turn the Reset case into the Fin case.
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

        // Sync point: responses stay unread; the live set shows registration.
        assert!(
            wait_for_union(&reader, |u| u.contains_key(&device)).await,
            "the front never published the authorized session"
        );

        if hangup == Hangup::Fin {
            miner.shutdown().await.expect("half-close");
        }
        drop(miner);

        let left = wait_for_union(&reader, |u| !u.contains_key(&device)).await;
        server.shutdown().await;
        left
    }

    /// Baseline: a cleanly closed connection leaves the live set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cleanly_closed_connection_leaves_the_live_set() {
        assert!(
            device_leaves_the_live_set_after(Hangup::Fin, 1).await,
            "a clean close must deregister the session"
        );
    }

    /// A reset connection (no FIN) also leaves the live set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reset_connection_still_leaves_the_live_set() {
        assert!(
            device_leaves_the_live_set_after(Hangup::Reset, 1).await,
            "the reset connection never left the live set — that worker can \
             never be reported offline again"
        );
    }

    /// Poll the union until `pred` holds; generous, as the connection task
    /// must notice the dead socket and unwind first.
    async fn wait_for_union(
        reader: &RedisLiveSessions,
        pred: impl Fn(&HashMap<(String, String), usize>) -> bool,
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
