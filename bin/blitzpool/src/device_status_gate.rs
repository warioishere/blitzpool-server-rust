// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production wiring for the device-status debounce.
//!
//! [`bp_notifications::dispatcher::DeviceStatusGate`] is transport- and
//! storage-agnostic; this module supplies the concrete pieces it needs
//! and the task that drives it:
//!
//! - [`PgDeviceLiveness`] — the liveness + first-seen answer, read from
//!   `client_entity`.
//! - [`SubscribedAddresses`] — which addresses have a device-status
//!   subscriber at all. Everything else is dropped before it reaches the
//!   gate, so the state machine, the seed and the sweep all scale with
//!   the number of *subscribers* rather than with the number of miners.
//! - [`spawn`] — seeds the watch list, then ticks: resolve what is due,
//!   dispatch what the gate releases.
//!
//! Both the in-process sink and the Satellite's stream consumer feed the
//! *same* gate instance, so a process that runs the front and the notify
//! role together debounces exactly like a split deployment.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_cron_utils::SystemClock;
use bp_notifications::dispatcher::{
    DeviceGateConfig, DeviceKey, DeviceLiveness, DeviceLivenessLookup, DeviceStatusGate,
    NotificationDispatcher,
};
use chrono::Utc;
use sqlx::PgPool;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// How often due devices are resolved. Well below the shortest dwell so
/// the added latency is a rounding error on the configured grace, and
/// cheap: a tick with nothing due costs one map scan and no query.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// How often the subscribed-address set is refreshed. A new subscriber
/// is picked up within this long; until then their devices are simply
/// not tracked, which costs at most one missed transition.
const SUBSCRIBER_REFRESH: Duration = Duration::from_secs(60);

/// How far back the startup seed looks for recently-disconnected
/// devices. Anything soft-deleted longer ago than this has either
/// already been reported or is long settled.
const SEED_LOOKBACK: Duration = Duration::from_secs(60 * 60);

/// Concurrency for the dispatch of released messages. Bounded so a large
/// batch cannot open an unbounded number of HTTP requests, but not
/// serial — a serial loop would block the next sweep behind a full
/// transport fan-out per address.
const DISPATCH_CONCURRENCY: usize = 8;

/// The concrete gate the binary uses.
pub(crate) type Gate = DeviceStatusGate<SystemClock, PgDeviceLiveness>;

/// Liveness lookup backed by `client_entity`.
pub(crate) struct PgDeviceLiveness {
    pool: PgPool,
}

#[async_trait]
impl DeviceLivenessLookup for PgDeviceLiveness {
    async fn liveness(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, DeviceLiveness>> {
        let addresses: Vec<String> = keys.iter().map(|(a, _)| a.clone()).collect();
        let workers: Vec<String> = keys.iter().map(|(_, w)| w.clone()).collect();
        match bp_db::device_liveness(&self.pool, &addresses, &workers).await {
            Ok(rows) => Some(
                rows.into_iter()
                    .map(|r| {
                        (
                            (r.address, r.client_name),
                            DeviceLiveness {
                                live: r.live_sessions > 0,
                                first_start_ms: r.first_start_ms,
                            },
                        )
                    })
                    .collect(),
            ),
            Err(err) => {
                // Deliberately `None`, not an empty map: an empty map
                // reads as "nothing is connected" and would fire an
                // offline notification for every due device.
                warn!(%err, "device-status gate: liveness lookup failed — holding deadlines");
                None
            }
        }
    }
}

/// Addresses with at least one device-status subscriber, refreshed
/// periodically. Cheap to clone; readers take the read lock only.
#[derive(Clone)]
pub(crate) struct SubscribedAddresses {
    inner: Arc<RwLock<HashSet<String>>>,
}

impl SubscribedAddresses {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub(crate) fn contains(&self, address: &str) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains(address)
    }

    fn snapshot(&self) -> Vec<String> {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// `true` when the set was actually reloaded. A failure keeps the
    /// previous set rather than dropping to empty — an empty set
    /// silently disables every notification — and the `false` tells the
    /// caller the seed cannot be trusted to have run yet.
    async fn refresh(&self, pool: &PgPool) -> bool {
        match bp_db::find_device_notification_addresses(pool).await {
            Ok(addresses) => {
                let set: HashSet<String> = addresses
                    .into_iter()
                    .map(|a| a.as_str().to_string())
                    .collect();
                let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
                *guard = set;
                true
            }
            Err(err) => {
                warn!(%err, "device-status gate: subscriber refresh failed — keeping previous set");
                false
            }
        }
    }
}

/// Build the gate plus the subscriber filter. One of each per process;
/// clone the handles into every producer.
pub(crate) fn build(cfg: DeviceGateConfig, pool: PgPool) -> (Arc<Gate>, SubscribedAddresses) {
    let gate = Arc::new(DeviceStatusGate::new(
        cfg,
        SystemClock,
        PgDeviceLiveness { pool },
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

/// Drive the gate: load the subscriber set, seed the watch list from the
/// database, then resolve and dispatch on a fixed tick.
///
/// The seed is what makes a restart survivable. Deadlines live only in
/// memory, so a miner that died during a deploy would otherwise never be
/// reported — it will not send another Stratum event to re-arm anything.
pub(crate) fn spawn(
    gate: Arc<Gate>,
    subscribers: SubscribedAddresses,
    dispatcher: Arc<NotificationDispatcher>,
    pool: PgPool,
) -> DeviceStatusGateHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        // Seeding is deferred until the subscriber set is both loaded and
        // non-empty. Doing it once, eagerly, would silently skip the seed
        // whenever the database is briefly unavailable at startup (the
        // set stays empty, the seed finds nothing, and nothing ever runs
        // it again) — and equally whenever the pool has no device
        // subscriber yet and gains one later.
        let mut seeded = false;
        if subscribers.refresh(&pool).await {
            seeded = seed_watch_list(&gate, &subscribers, &pool).await;
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
                _ = task_cancel.cancelled() => break,
                _ = refresh.tick() => {
                    let loaded = subscribers.refresh(&pool).await;
                    if loaded && !seeded {
                        seeded = seed_watch_list(&gate, &subscribers, &pool).await;
                    }
                }
                _ = tick.tick() => {
                    let notices = gate.poll_due().await;
                    if notices.is_empty() {
                        continue;
                    }
                    debug!(count = notices.len(), "device-status gate: releasing");
                    // Bounded concurrency rather than a serial await: one
                    // sweep after a restart can carry a notice per
                    // subscribed address, and each is a subscription
                    // lookup plus a transport fan-out. Serial, that burst
                    // blocks every following sweep behind it.
                    let mut pending = JoinSet::new();
                    let mut queue = notices.into_iter();
                    loop {
                        while pending.len() < DISPATCH_CONCURRENCY {
                            let Some(notice) = queue.next() else { break };
                            let dispatcher = Arc::clone(&dispatcher);
                            pending.spawn(async move {
                                dispatcher.notify_device_notice(&notice).await;
                            });
                        }
                        if pending.join_next().await.is_none() {
                            break;
                        }
                    }
                }
            }
        }
        info!("device-status gate: sweeper stopped");
    });
    DeviceStatusGateHandle { cancel, task }
}

/// Rebuild the watch list from `client_entity`: every device under a
/// subscribed address that is connected now, or was disconnected within
/// [`SEED_LOOKBACK`].
///
/// Returns `true` once the seed has actually happened, so the caller
/// stops retrying. An empty subscriber set is deliberately *not* a
/// success — there is nothing to seed yet, and the first subscriber to
/// appear should still get one.
async fn seed_watch_list(gate: &Gate, subscribers: &SubscribedAddresses, pool: &PgPool) -> bool {
    let addresses = subscribers.snapshot();
    if addresses.is_empty() {
        return false;
    }
    let since = Utc::now().timestamp_millis() - SEED_LOOKBACK.as_millis() as i64;
    match bp_db::device_watch_seed(pool, &addresses, since).await {
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
            true
        }
        Err(err) => {
            // Not fatal, and retried on the next subscriber refresh. Until
            // it succeeds the gate still learns about every device that
            // sends an event; only devices that died just before this
            // start would be missed.
            warn!(%err, "device-status gate: seeding failed — will retry");
            false
        }
    }
}
