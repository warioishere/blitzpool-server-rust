// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production wiring for [`bp_notifications::dispatcher::DeviceStatusGate`]:
//! liveness from the fronts, reported state persisted in Redis so a restart
//! neither repeats nor swallows a message, and a subscriber filter so work
//! scales with subscribers. In-process and Satellite events feed the same gate.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_cron_utils::SystemClock;
use bp_notifications::dispatcher::{
    DeviceGateConfig, DeviceKey, DeviceLiveness, DeviceLivenessLookup, DeviceNotice,
    DeviceStatusGate, NotificationDispatcher, ReportedStateStore,
};
use chrono::Utc;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use sqlx::PgPool;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::live_sessions::RedisLiveSessions;

/// How often due devices are resolved. Well below the shortest dwell so
/// the added latency is a rounding error on the configured grace, and
/// cheap: a tick with nothing due costs one map scan and no query.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// How often the subscribed-address set is refreshed.
const SUBSCRIBER_REFRESH: Duration = Duration::from_secs(60);

/// How far back the startup seed looks for recently-disconnected
/// devices.
const SEED_LOOKBACK: Duration = Duration::from_secs(60 * 60);

/// Concurrency for dispatching released messages: bounded HTTP fan-out,
/// but not serial, which would block the next sweep behind every
/// transport call.
const DISPATCH_CONCURRENCY: usize = 8;

/// Redis key prefix for the persisted reported state.
const REPORTED_PREFIX: &str = "device:status:reported:";

/// How long a persisted reported state survives without being rewritten.
/// Far longer than the 2 h `client_entity` hard-delete: this state, not
/// the table's `firstSeen`, carries "the subscriber already knows this
/// device" across restarts.
const REPORTED_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// The concrete gate the binary uses.
pub(crate) type Gate = DeviceStatusGate<SystemClock, FrontLiveness, RedisReportedState>;

/// Liveness from the fronts, first-seen from the database: only the process
/// holding the socket knows "connected right now" first-hand, and first-seen
/// is history no live process holds.
pub(crate) struct FrontLiveness {
    pool: PgPool,
    live: RedisLiveSessions,
}

#[async_trait]
impl DeviceLivenessLookup for FrontLiveness {
    async fn liveness(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, DeviceLiveness>> {
        // `None` means no front is publishing, NOT "nothing is connected";
        // the latter would report the whole pool offline during a front
        // deploy.
        let live = self.live.union().await?;

        let addresses: Vec<String> = keys.iter().map(|(a, _)| a.clone()).collect();
        let workers: Vec<String> = keys.iter().map(|(_, w)| w.clone()).collect();
        let first_seen: HashMap<DeviceKey, i64> =
            match bp_db::device_first_seen(&self.pool, &addresses, &workers).await {
                Ok(rows) => rows
                    .into_iter()
                    .map(|r| ((r.address, r.client_name), r.first_seen_ms))
                    .collect(),
                Err(err) => {
                    warn!(%err, "device-status gate: first-seen lookup failed — holding deadlines");
                    return None;
                }
            };

        Some(
            keys.iter()
                .filter_map(|key| {
                    // A pair the pool has no record of at all cannot be
                    // judged for novelty, so it is left out entirely and
                    // the gate treats it as absent.
                    first_seen.get(key).map(|first_seen_ms| {
                        (
                            key.clone(),
                            DeviceLiveness {
                                sessions: live.get(key).copied().unwrap_or(0),
                                first_seen_ms: *first_seen_ms,
                            },
                        )
                    })
                })
                .collect(),
        )
    }
}

/// Reported state persisted in Redis, one key per device with a TTL.
///
/// One key rather than a hash field so expiry prunes churned worker names
/// by itself.
pub(crate) struct RedisReportedState {
    redis: ConnectionManager,
}

fn redis_key(key: &DeviceKey) -> String {
    format!("{REPORTED_PREFIX}{}\u{1f}{}", key.0, key.1)
}

fn parse_redis_key(raw: &str) -> Option<DeviceKey> {
    let rest = raw.strip_prefix(REPORTED_PREFIX)?;
    let (address, worker) = rest.split_once('\u{1f}')?;
    Some((address.to_string(), worker.to_string()))
}

#[async_trait]
impl ReportedStateStore for RedisReportedState {
    async fn load(&self) -> HashMap<DeviceKey, usize> {
        let mut conn = self.redis.clone();
        let mut out = HashMap::new();
        let mut cursor: u64 = 0;
        loop {
            let scan: redis::RedisResult<(u64, Vec<String>)> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{REPORTED_PREFIX}*"))
                .arg("COUNT")
                .arg(500)
                .query_async(&mut conn)
                .await;
            let (next, keys) = match scan {
                Ok(v) => v,
                Err(err) => {
                    // Empty rather than fatal: costs one restart's worth
                    // of imprecision, not an outage.
                    warn!(%err, "device-status gate: reported-state scan failed — starting without it");
                    return out;
                }
            };
            for raw in keys {
                let Some(device) = parse_redis_key(&raw) else {
                    continue;
                };
                match conn.get::<_, Option<String>>(&raw).await {
                    Ok(Some(v)) => {
                        // Values are session counts; "online"/"offline"
                        // are the legacy form, still read so persisted
                        // keys stay valid.
                        let sessions = match v.as_str() {
                            "online" => 1,
                            "offline" => 0,
                            other => other.parse().unwrap_or(0),
                        };
                        out.insert(device, sessions);
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(%err, key = raw, "device-status gate: reported-state read failed");
                    }
                }
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        out
    }

    async fn store(&self, updates: &[(DeviceKey, usize)]) {
        if updates.is_empty() {
            return;
        }
        let mut conn = self.redis.clone();
        // Pipelined: a front restart resolves every supervised device at
        // once, and nothing is released until this returns. Not a MULTI:
        // the writes are independent and best-effort.
        let mut pipe = redis::pipe();
        for (key, sessions) in updates {
            pipe.set_ex(redis_key(key), *sessions, REPORTED_TTL_SECS)
                .ignore();
        }
        if let Err(err) = pipe.query_async::<()>(&mut conn).await {
            // Best-effort: losing this costs one duplicated or missing
            // message after a restart, not a wrong live decision.
            warn!(
                %err,
                count = updates.len(),
                "device-status gate: persisting reported state failed"
            );
        }
    }
}

/// Addresses with at least one device-status subscriber. Fails **open** until
/// loaded once, so a failing query cannot silence the whole pool.
#[derive(Clone)]
pub(crate) struct SubscribedAddresses {
    inner: Arc<RwLock<HashSet<String>>>,
    loaded: Arc<AtomicBool>,
}

impl SubscribedAddresses {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashSet::new())),
            loaded: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn contains(&self, address: &str) -> bool {
        if !self.loaded.load(Ordering::Acquire) {
            return true;
        }
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains(address)
    }

    /// Reload. Returns the addresses that are new since the previous
    /// successful load, so the caller can seed them; `None` means the
    /// query failed and the previous set was kept.
    async fn refresh(&self, pool: &PgPool) -> Option<Vec<String>> {
        match bp_db::find_device_notification_addresses(pool).await {
            Ok(addresses) => {
                let next: HashSet<String> = addresses
                    .into_iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
                let added: Vec<String> = next.difference(&guard).cloned().collect();
                *guard = next;
                drop(guard);
                self.loaded.store(true, Ordering::Release);
                Some(added)
            }
            Err(err) => {
                warn!(%err, "device-status gate: subscriber refresh failed — keeping previous set");
                None
            }
        }
    }
}

/// Build the gate plus the subscriber filter. One of each per process;
/// clone the handles into every producer.
pub(crate) fn build(
    cfg: DeviceGateConfig,
    pool: PgPool,
    redis: ConnectionManager,
) -> (Arc<Gate>, SubscribedAddresses) {
    let gate = Arc::new(DeviceStatusGate::new(
        cfg,
        SystemClock,
        FrontLiveness {
            pool,
            live: RedisLiveSessions::new(redis.clone()),
        },
        RedisReportedState { redis },
    ));
    (gate, SubscribedAddresses::new())
}

/// Handle for the sweeper task.
pub(crate) struct DeviceStatusGateHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl DeviceStatusGateHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "device-status gate: sweeper join failed");
        }
    }
}

/// Drive the gate: restore what previous processes already reported,
/// load the subscriber set, seed the watch list, then resolve and
/// dispatch on a fixed tick.
pub(crate) fn spawn(
    gate: Arc<Gate>,
    subscribers: SubscribedAddresses,
    dispatcher: Arc<NotificationDispatcher>,
    pool: PgPool,
) -> DeviceStatusGateHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        run_sweeper(gate, subscribers, dispatcher, pool, task_cancel).await;
        info!("device-status gate: sweeper stopped");
    });
    DeviceStatusGateHandle { cancel, task }
}

/// Await `fut` unless shutdown starts first; `None` means stop. Every sweeper
/// await goes through this, so an unreachable dependency cannot hold shutdown.
/// Dropping mid-flight is safe: no lock spans an await and state is
/// re-derived from the seed and the persisted reported state.
async fn until_cancelled<T>(cancel: &CancellationToken, fut: impl Future<Output = T>) -> Option<T> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        value = fut => Some(value),
    }
}

async fn run_sweeper(
    gate: Arc<Gate>,
    subscribers: SubscribedAddresses,
    dispatcher: Arc<NotificationDispatcher>,
    pool: PgPool,
    cancel: CancellationToken,
) {
    // Startup is cancellable too.
    if until_cancelled(&cancel, gate.restore_reported_state())
        .await
        .is_none()
    {
        return;
    }
    // Seeding waits for a loaded subscriber set; an address that gains its
    // first subscriber later is seeded then, or its devices would only be
    // learned from a future Stratum event.
    match until_cancelled(&cancel, subscribers.refresh(&pool)).await {
        None => return,
        Some(Some(added)) => {
            if until_cancelled(&cancel, seed_addresses(&gate, &pool, &added))
                .await
                .is_none()
            {
                return;
            }
        }
        Some(None) => {}
    }

    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut refresh = tokio::time::interval(SUBSCRIBER_REFRESH);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await; // the immediate first tick; already refreshed above

    info!(
        interval_s = SWEEP_INTERVAL.as_secs(),
        "device-status gate: sweeper started"
    );
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = refresh.tick() => {
                let Some(refreshed) = until_cancelled(&cancel, subscribers.refresh(&pool)).await
                else {
                    break;
                };
                if let Some(added) = refreshed {
                    if until_cancelled(&cancel, seed_addresses(&gate, &pool, &added))
                        .await
                        .is_none()
                    {
                        break;
                    }
                }
            }
            _ = tick.tick() => {
                let Some(notices) = until_cancelled(&cancel, gate.poll_due()).await else {
                    break;
                };
                if notices.is_empty() {
                    continue;
                }
                debug!(count = notices.len(), "device-status gate: releasing");
                dispatch(&dispatcher, notices, &cancel).await;
            }
        }
    }
}

/// Fan out released notices with bounded concurrency. Cancellation-aware: an
/// unreachable push endpoint can stretch a batch into minutes, and shutdown
/// must not wait behind it.
async fn dispatch(
    dispatcher: &Arc<NotificationDispatcher>,
    notices: Vec<DeviceNotice>,
    cancel: &CancellationToken,
) {
    let mut pending = JoinSet::new();
    let mut queue = notices.into_iter();
    loop {
        while pending.len() < DISPATCH_CONCURRENCY && !cancel.is_cancelled() {
            let Some(notice) = queue.next() else { break };
            let dispatcher = Arc::clone(dispatcher);
            pending.spawn(async move {
                dispatcher.notify_device_notice(&notice).await;
            });
        }
        if pending.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                // Stop starting new work and drop what is in flight. The
                // rest is re-derived after the restart, because the
                // reported state that makes it a transition is persisted.
                pending.shutdown().await;
                break;
            }
            joined = pending.join_next() => {
                if joined.is_none() {
                    break;
                }
            }
        }
    }
}

/// Seed the watch list for `addresses`: every device connected now or
/// disconnected within [`SEED_LOOKBACK`], since a miner that died during a
/// restart sends no further Stratum event.
async fn seed_addresses(gate: &Gate, pool: &PgPool, addresses: &[String]) {
    if addresses.is_empty() {
        return;
    }
    let since = Utc::now().timestamp_millis() - SEED_LOOKBACK.as_millis() as i64;
    match bp_db::device_watch_seed(pool, addresses, since).await {
        Ok(rows) => {
            let seeded = rows.len();
            gate.seed(rows.into_iter().filter_map(|(address, worker, ua)| {
                match AddressId::new(address) {
                    Ok(a) => Some((a, worker, ua)),
                    Err(err) => {
                        warn!(%err, "device-status gate: seed row has unparseable address");
                        None
                    }
                }
            }));
            info!(
                seeded,
                addresses = addresses.len(),
                "device-status gate: watch list seeded"
            );
        }
        Err(err) => {
            // Not fatal: the gate still learns about every device that
            // sends an event from here on. Only devices that died just
            // before this start would be missed.
            warn!(%err, "device-status gate: seeding failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    /// The filter passes everything until it has loaded once; after that,
    /// even an empty set filters.
    #[test]
    fn the_subscriber_filter_passes_everything_until_it_has_loaded() {
        let subs = SubscribedAddresses::new();
        assert!(subs.contains(ADDR), "unloaded must not filter");
        assert!(subs.contains("anything-at-all"));

        // A successful load of an EMPTY set is a real answer and does
        // filter — that is the difference the flag exists to record.
        subs.loaded.store(true, Ordering::Release);
        assert!(
            !subs.contains(ADDR),
            "loaded and empty means nobody wants it"
        );

        subs.inner.write().expect("lock").insert(ADDR.to_string());
        assert!(subs.contains(ADDR));
        assert!(!subs.contains("some-other-address"));
    }

    /// Cancellation wins over a dependency that never answers, and a live
    /// token passes the result through. Covers the primitive, not the
    /// wiring: that every await in `run_sweeper` uses it is checked by
    /// reading it.
    #[tokio::test]
    async fn a_hung_dependency_does_not_hold_shutdown() {
        let cancel = CancellationToken::new();
        let never = std::future::pending::<()>();

        let cancelling = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel.cancel();
            })
        };
        let outcome = tokio::time::timeout(Duration::from_secs(5), until_cancelled(&cancel, never))
            .await
            .expect("cancellation must win against a future that never resolves");
        assert!(outcome.is_none(), "cancelled means stop, not a value");
        let _ = cancelling.await;

        // And it stays a pass-through when nothing is shutting down.
        let live = CancellationToken::new();
        assert_eq!(
            until_cancelled(&live, std::future::ready(7)).await,
            Some(7),
            "a normal tick must still get its result"
        );
    }

    /// The Redis key has to survive a round trip — an address and a
    /// worker name are both free-form, so they are joined on a separator
    /// that cannot occur in either.
    #[test]
    fn reported_state_keys_round_trip() {
        let key = (ADDR.to_string(), "rig.1 with spaces".to_string());
        assert_eq!(parse_redis_key(&redis_key(&key)), Some(key));
        assert_eq!(parse_redis_key("device:status:reported:no-separator"), None);
        assert_eq!(parse_redis_key("some:other:key"), None);
    }
}
