// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production wiring for the device-status debounce.
//!
//! [`bp_notifications::dispatcher::DeviceStatusGate`] is transport- and
//! storage-agnostic; this module supplies the concrete pieces it needs
//! and the task that drives it:
//!
//! - [`FrontLiveness`] — the liveness answer. "Is it connected?" comes
//!   from the union of what the Stratum fronts publish (see
//!   [`crate::live_sessions`]); only "when did the pool first see this
//!   worker?", a historical fact, still comes from `client_entity`.
//! - [`RedisReportedState`] — what each subscriber was last told,
//!   persisted so a restart neither repeats an offline message nor
//!   swallows the matching return.
//! - [`SubscribedAddresses`] — which addresses have a device-status
//!   subscriber at all, so the state machine and the sweep scale with
//!   the number of *subscribers* rather than the number of miners. It
//!   fails **open**: until the set has been loaded successfully once,
//!   nothing is filtered, because a filter that has never seen its data
//!   would silently disable every notification on the pool.
//! - [`spawn`] — restores the reported state, seeds the watch list, then
//!   ticks: resolve what is due, dispatch what the gate releases.
//!
//! Both the in-process sink and the Satellite's stream consumer feed the
//! *same* gate instance, so a process that runs the front and the notify
//! role together debounces exactly like a split deployment.

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

/// Concurrency for dispatching released messages. Bounded so a large
/// batch cannot open an unbounded number of HTTP requests, but not
/// serial — a serial loop would block the next sweep behind a full
/// transport fan-out per address.
const DISPATCH_CONCURRENCY: usize = 8;

/// Redis key prefix for the persisted reported state.
const REPORTED_PREFIX: &str = "device:status:reported:";

/// How long a persisted reported state survives without being rewritten.
/// Comfortably longer than the 2 h `client_entity` hard-delete: this
/// state — not the table's `firstSeen`, which never outlives the
/// retention window — is what actually carries "the subscriber already
/// knows this device" across restarts.
const REPORTED_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// The concrete gate the binary uses.
pub(crate) type Gate = DeviceStatusGate<SystemClock, FrontLiveness, RedisReportedState>;

/// Liveness from the fronts, first-seen from the database.
///
/// The split is deliberate. Whether a device is connected **right now**
/// is only known first-hand by the process holding its socket, and every
/// database-derived answer conflates it with share activity. When the
/// pool first saw the worker is the opposite: a historical fact no live
/// process can reconstruct.
pub(crate) struct FrontLiveness {
    pool: PgPool,
    live: RedisLiveSessions,
}

#[async_trait]
impl DeviceLivenessLookup for FrontLiveness {
    async fn liveness(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, DeviceLiveness>> {
        // `None` here means no front is publishing, which is NOT the
        // same as "nothing is connected" — concluding the latter would
        // report the whole pool offline during a front deploy.
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
/// One key rather than a hash field so expiry prunes the space by itself
/// — a pool whose worker names churn would otherwise grow a hash that
/// nothing ever cleans.
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
                    // Empty rather than fatal: the gate then behaves as
                    // it did before persistence existed, which costs one
                    // restart's worth of imprecision, not an outage.
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
                        // Plain counts now; "online"/"offline" are what a
                        // process from before the count rule wrote, and a
                        // rolling upgrade still has to read them.
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
        // Pipelined, not one call per device: a front restart resolves
        // every supervised device at once, and nothing is released until
        // this returns. Deliberately NOT a MULTI — these writes are
        // independent and best-effort, so all-or-nothing would buy
        // nothing and only widen the failure.
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

/// Addresses with at least one device-status subscriber.
///
/// Fails **open**: `contains` answers `true` for everything until the
/// set has been loaded successfully at least once. The alternative — an
/// empty set that reads as "nobody is subscribed" — turns a single
/// failing query into a silent, pool-wide notification outage.
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

/// Await `fut` unless shutdown starts first; `None` means stop.
///
/// Every await the sweeper performs goes through this. [`dispatch`] was
/// already cancellable, but the Redis + Postgres round-trips in front of
/// it were not — so an unreachable dependency still parked the whole
/// deploy behind `task.await` with no timeout, and a process that gets
/// SIGKILLed for taking too long cannot run its own cleanup either. That
/// is exactly what making the drain cancellable was meant to avoid, so
/// the rest of the tick has to hold the same property.
///
/// Dropping a lookup or a store mid-flight is safe here: no lock is held
/// across an await, and the in-memory schedule dies with the process
/// anyway — it is rebuilt from the seed, and the reported state that
/// makes a transition a transition is persisted.
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
    // Startup is cancellable too: a process told to stop while a slow
    // restore is still in flight must not hold the deploy either.
    if until_cancelled(&cancel, gate.restore_reported_state())
        .await
        .is_none()
    {
        return;
    }
    // Seeding waits for a subscriber set that actually loaded, and any
    // address that gains its first subscriber later is seeded then —
    // otherwise its devices would only ever be learned from a future
    // Stratum event.
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

/// Fan out released notices with bounded concurrency.
///
/// Cancellation-aware on purpose: each notice is a subscription lookup
/// plus HTTP calls to Telegram / FCM / UnifiedPush with double-digit
/// second timeouts, so an unreachable push endpoint can stretch a big
/// batch into minutes. Without the check, shutdown would wait behind all
/// of it and the deploy would be SIGKILLed instead of stopping cleanly —
/// which is strictly worse, since a killed process cannot run its own
/// cleanup either.
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

/// Seed the watch list for `addresses` — every device under them that is
/// connected now, or was disconnected within [`SEED_LOOKBACK`].
///
/// This is what makes a restart survivable for a miner that died during
/// the deploy: it will not send another Stratum event, so without the
/// seed nothing would ever evaluate it again.
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

    /// The filter must not answer "nobody is subscribed" before it has
    /// ever seen its data. A single failing query at boot would
    /// otherwise drop every device event on the pool and disable the
    /// whole feature behind one WARN line — the dispatcher's own
    /// per-event subscription lookup, which this filter is an
    /// optimisation over, could never miss a subscriber.
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

    /// Shutdown must not wait on a dependency that never answers. The
    /// sweep is a Redis SCAN plus a Postgres query before the (already
    /// cancellable) dispatch, and `shutdown` joins the task with no
    /// timeout — so a hung Redis parked the deploy until the supervisor
    /// SIGKILLed it, and a killed process cannot run its own cleanup.
    ///
    /// This covers the primitive every await in the sweeper now goes
    /// through, not the wiring: that each call site uses it is verified by
    /// reading `run_sweeper`, because making the loop drivable from a test
    /// would mean threading a fake dispatcher through production types.
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
