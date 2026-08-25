// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background cron wiring — Phase 7.5.
//!
//! Spawns the 4 cron loops that are wireable today with the
//! foundation + engines + hooks state already constructed by
//! `boot.rs` / `engines.rs` / `hooks.rs`:
//!
//! 1. **`kill_dead_clients`** (every 60 s) — soft-deletes `client_entity`
//!    rows past the 5-minute birth grace whose `client:live:*` hash is
//!    gone. Catches sessions whose disconnect path didn't fire cleanly
//!    (network drop without a clean FIN). Candidates from
//!    `bp_db::find_stale_active_sessions`, verdict from Redis key
//!    existence, soft-delete via `bp_db::soft_delete_sessions`.
//! 2. **`invitation_expiry`** (hourly) — flips
//!    `pplns_group_invitation` rows from `pending → expired` past their
//!    `expiresAt`. Lives in `bp_group_mgmt_engine::cron`.
//! 3. **`join_request_expiry`** (daily) — same for stale
//!    `pplns_group_join_request` rows past 30 days. Same crate.
//! 4. **`network_difficulty`** (every 10 min) — polls mempool.space's
//!    `currentDifficulty`, persists it, and (when `[notifications.fcm]`
//!    is configured) fans out FCM pushes to subscribers on a change.
//!    Lives in `bp_notifications::cron::network_difficulty`.
//!
//! Phase 7.6 adds:
//!
//! 5. **`hourly_stats`** (hourly) — emits per-address `/stats` +
//!    `/show_workers` digests through whichever of the
//!    Telegram / ntfy adapters are configured. Only spawns when at
//!    least one of the two listener adapters is live (passed in
//!    through [`crate::listeners::ListenerHandles`]).
//!
//! Phase 7.7 adds the final cron:
//!
//! 6. **`best_difficulty`** (60 s) — scans `address_settings.bestDifficulty`
//!    for every push-subscribed address; when a value strictly
//!    increases over the in-memory baseline the cron fires a per-address
//!    best-diff push via the [`bp_notifications::dispatcher::NotificationDispatcher`].
//!    The tracker is seeded from the same scan source at spawn time so
//!    the first tick after a restart doesn't re-notify every cached best.
//!    Skipped when no dispatcher is available.
//!
//! ## Shutdown
//!
//! Every cron in this module returns a `tokio::sync::watch::Sender<bool>`
//! (the convention the existing cron-spawn helpers all use). Sending
//! `true` on the channel ends the loop after the current tick. The
//! aggregate [`CronHandles::shutdown`] sends `true` on all of them in
//! parallel and waits briefly for the loops to observe it before
//! returning — the worst case is one cron's tick-interval, but all
//! ticks short-circuit on the shutdown branch of their `tokio::select!`
//! so the actual delay is sub-millisecond.

use std::sync::Arc;
use std::time::Duration;

use bp_cron_utils::SystemClock;
use bp_group_mgmt_engine::cron::{spawn_invitation_expiry_cron, spawn_join_request_expiry_cron};
use bp_notifications::adapter::{NtfyAdapter, TelegramAdapter};
use bp_notifications::cron::best_difficulty::{
    spawn_best_difficulty_cron, BestDifficultyCronConfig,
};
use bp_notifications::cron::hourly_stats::{spawn_hourly_stats_cron, HourlyStatsCronConfig};
use bp_notifications::cron::network_difficulty::{
    spawn_network_difficulty_cron, NetworkDifficultyCronConfig,
};
use bp_notifications::dispatcher::NotificationDispatcher;
use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::boot::FoundationHandles;
use crate::hooks::ProductionHooks;
use crate::listeners::ListenerHandles;

/// Tick of the `kill_dead_clients` poller.
const KILL_DEAD_TICK: Duration = Duration::from_secs(60);

/// Staleness cutoff for the `kill_dead_clients` sweep — sessions whose
/// `updatedAt` is older than this become sweep CANDIDATES (the verdict
/// is their `client:live:*` key's existence). Also wired into the
/// session-persistence engine as the TTL of those hashes, so the two
/// clocks agree (see `engines::spawn_session_persistence`).
pub(crate) const STALE_CLIENT_TTL: Duration = Duration::from_secs(5 * 60);

/// Per-cron startup phase offsets (seconds) — picked as small prime
/// numbers so concurrent tick collisions across compound periods are
/// minimised. Adjust here if a new cron lands; aim for distinct
/// offsets within each (60 s, 60 min, 24 h) period family so two
/// crons in the same family never align on boot.
pub(crate) mod offsets {
    use std::time::Duration;
    pub(crate) const KILL_DEAD: Duration = Duration::from_secs(0);
    pub(crate) const STATS_SINK_FLUSH: Duration = Duration::from_secs(17);
    pub(crate) const OLD_STATS_CLEANUP: Duration = Duration::from_secs(7);
    pub(crate) const OLD_BLOCKS_CLEANUP: Duration = Duration::from_secs(13);
    pub(crate) const NETWORK_DIFFICULTY: Duration = Duration::from_secs(23);
    pub(crate) const HOURLY_STATS: Duration = Duration::from_secs(31);
    pub(crate) const BEST_DIFFICULTY: Duration = Duration::from_secs(37);
    pub(crate) const INVITATION_EXPIRY: Duration = Duration::from_secs(11);
    pub(crate) const JOIN_REQUEST_EXPIRY: Duration = Duration::from_secs(19);
    pub(crate) const STALE_PUSH_CLEANUP: Duration = Duration::from_secs(41);
}

// ─────────────────────────────────────────────────────────────────

/// Build an interval whose first tick fires at
/// `now + period + stagger` and every `period` after that. The
/// extra `+ period` matches the existing "skip the immediate fire"
/// pattern (`ticker.tick().await` discards the t=0 tick); using
/// `interval_at` lets us combine both into a single primitive
/// without an explicit pre-loop `sleep`.
fn staggered_interval(period: Duration, stagger: Duration) -> tokio::time::Interval {
    let start = tokio::time::Instant::now() + period + stagger;
    let mut t = tokio::time::interval_at(start, period);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    t
}

/// Aggregate of every Phase 7.5 cron handle. Each cron exposes its
/// own shutdown signal; [`Self::shutdown`] fires them all and awaits the
/// kill-dead-clients loop's `JoinHandle` (the other 3 crons run
/// detached on the tokio runtime).
pub(crate) struct CronHandles {
    inner: Option<Inner>,
}

struct Inner {
    // ── Maintenance crons — the `payout`/accounting role. DB upkeep + group
    //    lifecycle crons; no notification dispatcher.
    //    `None` when this process doesn't run maintenance (e.g. a `notify`-only
    //    process). ──
    /// Cancellation handle for the locally-spawned kill_dead_clients
    /// task. The cron helpers in `bp-group-mgmt-engine` /
    /// `bp-notifications` use `watch::Sender<bool>` (their internal
    /// convention); we use a `CancellationToken` here because the
    /// kill_dead_clients task is owned by this module directly.
    kill_dead_cancel: Option<CancellationToken>,
    kill_dead_join: Option<JoinHandle<()>>,
    /// Hourly stats-purge cron + matching daily rpc-block-purge cron.
    /// Same `CancellationToken` convention as kill_dead_clients.
    old_stats_cancel: Option<CancellationToken>,
    old_stats_join: Option<JoinHandle<()>>,
    old_blocks_cancel: Option<CancellationToken>,
    old_blocks_join: Option<JoinHandle<()>>,
    invitation_expiry_shutdown: Option<watch::Sender<bool>>,
    join_request_expiry_shutdown: Option<watch::Sender<bool>>,
    // ── Notification crons — the `notify` role. Push/digest fan-out via the
    //    dispatcher + adapters. `None` when this process doesn't run
    //    notifications (e.g. a `payout`-only process). ──
    network_difficulty_shutdown: Option<watch::Sender<bool>>,
    /// `Some` when at least one of Telegram / ntfy was configured
    /// (and therefore the hourly-stats cron has a fan-out path).
    /// `None` when both adapters were absent — cron is skipped at
    /// `spawn` and there's nothing to signal here.
    hourly_stats_shutdown: Option<watch::Sender<bool>>,
    /// `Some` when the dispatcher is wired (any push/Telegram/ntfy
    /// adapter present). `None` when the dispatcher was `None` at
    /// spawn — best-diff cron is skipped.
    best_difficulty_shutdown: Option<watch::Sender<bool>>,
    /// Whether the network-difficulty cron has any push adapter (FCM or
    /// UnifiedPush); if not, the cron still runs (keeps tracker row
    /// fresh) but no notifications fire. Used only by
    /// [`CronHandles::log_summary`] for an operator-visible note.
    network_difficulty_has_push: bool,
    /// Whether `hourly_stats` actually has Telegram / ntfy adapters.
    /// Used only for the summary line.
    hourly_stats_telegram: bool,
    hourly_stats_ntfy: bool,
    /// Weekly stale push-subscription hard-delete. Maintenance role. `None`
    /// when this process doesn't run maintenance.
    stale_push_cancel: Option<CancellationToken>,
    stale_push_join: Option<JoinHandle<()>>,
    /// Which cron groups this process actually spawned — for the summary line.
    ran_maintenance: bool,
    ran_notifications: bool,
}

impl CronHandles {
    /// Log a one-line summary of which crons are live. Called from
    /// `main.rs` right after `spawn`.
    pub(crate) fn log_summary(&self) {
        match &self.inner {
            None => info!("crons summary: not spawned"),
            Some(inner) => info!(
                maintenance = inner.ran_maintenance,
                kill_dead = inner.kill_dead_cancel.is_some(),
                old_stats_cleanup = inner.old_stats_cancel.is_some(),
                old_blocks_cleanup = inner.old_blocks_cancel.is_some(),
                invitation_expiry = inner.invitation_expiry_shutdown.is_some(),
                join_request_expiry = inner.join_request_expiry_shutdown.is_some(),
                stale_push_cleanup = inner.stale_push_cancel.is_some(),
                notifications = inner.ran_notifications,
                network_difficulty = inner.network_difficulty_shutdown.is_some(),
                network_difficulty_push = inner.network_difficulty_has_push,
                hourly_stats = inner.hourly_stats_shutdown.is_some(),
                hourly_stats_telegram = inner.hourly_stats_telegram,
                hourly_stats_ntfy = inner.hourly_stats_ntfy,
                best_difficulty = inner.best_difficulty_shutdown.is_some(),
                "crons summary"
            ),
        }
    }

    /// Send the shutdown signal to every cron and await the
    /// kill_dead_clients task's exit. Idempotent — calling twice is a
    /// no-op on the second pass because `inner` is taken.
    pub(crate) async fn shutdown(mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        // Maintenance group (cancel first so no tick fires mid-shutdown).
        if let Some(c) = inner.kill_dead_cancel {
            c.cancel();
        }
        if let Some(c) = inner.old_stats_cancel {
            c.cancel();
        }
        if let Some(c) = inner.old_blocks_cancel {
            c.cancel();
        }
        if let Some(c) = inner.stale_push_cancel {
            c.cancel();
        }
        if let Some(tx) = inner.invitation_expiry_shutdown {
            let _ = tx.send(true);
        }
        if let Some(tx) = inner.join_request_expiry_shutdown {
            let _ = tx.send(true);
        }
        // Notification group.
        if let Some(tx) = inner.network_difficulty_shutdown {
            let _ = tx.send(true);
        }
        if let Some(tx) = inner.hourly_stats_shutdown {
            let _ = tx.send(true);
        }
        if let Some(tx) = inner.best_difficulty_shutdown {
            let _ = tx.send(true);
        }
        // Only the locally-owned tasks (kill_dead + the cleanups)
        // are joinable here; the other crons are detached `tokio::spawn`s
        // inside their helpers, so sending `true` on their shutdown channel
        // ends their loop on the next select iteration (sub-millisecond).
        if let Some(join) = inner.kill_dead_join {
            if let Err(err) = join.await {
                warn!(%err, "crons: kill_dead_clients join failed");
            }
        }
        if let Some(join) = inner.old_stats_join {
            if let Err(err) = join.await {
                warn!(%err, "crons: old_stats_cleanup join failed");
            }
        }
        if let Some(join) = inner.old_blocks_join {
            if let Err(err) = join.await {
                warn!(%err, "crons: old_blocks_cleanup join failed");
            }
        }
        if let Some(join) = inner.stale_push_join {
            if let Err(err) = join.await {
                warn!(%err, "crons: stale_push_cleanup join failed");
            }
        }
    }
}

/// Spawn all background crons. Pulls the `PgPool` from
/// [`FoundationHandles`] and the FCM adapter (when configured) from
/// [`ProductionHooks`]. Cron tick + cutoff constants are hardcoded; if
/// an operator ever needs to tune these, add a `[cron]` block in
/// `bp-config` later.
///
/// `run_maintenance` (the `payout`/accounting role) gates the DB-upkeep + group
/// lifecycle crons; `run_notifications` (the `notify` role)
/// gates the push/digest crons. A process running both (e.g. the default
/// satellite back) spawns everything; a split process spawns only its group.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn(
    foundation: &FoundationHandles,
    hooks: &ProductionHooks,
    listeners: &ListenerHandles,
    dispatcher: Option<Arc<NotificationDispatcher>>,
    run_maintenance: bool,
    run_notifications: bool,
) -> CronHandles {
    let pool = foundation.db.pool().clone();

    // ── Maintenance group (accounting role) ──
    let (kill_dead_cancel, kill_dead_join) = if run_maintenance {
        let c = CancellationToken::new();
        let j = spawn_kill_dead_clients_loop(pool.clone(), foundation.redis.clone(), c.clone());
        (Some(c), Some(j))
    } else {
        (None, None)
    };
    let (old_stats_cancel, old_stats_join) = if run_maintenance {
        let c = CancellationToken::new();
        let j = spawn_old_stats_cleanup(pool.clone(), c.clone());
        (Some(c), Some(j))
    } else {
        (None, None)
    };
    let (old_blocks_cancel, old_blocks_join) = if run_maintenance {
        let c = CancellationToken::new();
        let j = spawn_old_blocks_cleanup(pool.clone(), c.clone());
        (Some(c), Some(j))
    } else {
        (None, None)
    };
    let (stale_push_cancel, stale_push_join) = if run_maintenance {
        let c = CancellationToken::new();
        let j = spawn_stale_push_cleanup(pool.clone(), c.clone());
        (Some(c), Some(j))
    } else {
        (None, None)
    };
    let invitation_expiry_shutdown = run_maintenance.then(|| {
        spawn_invitation_expiry_cron(pool.clone(), SystemClock, offsets::INVITATION_EXPIRY)
    });
    let join_request_expiry_shutdown = run_maintenance.then(|| {
        spawn_join_request_expiry_cron(pool.clone(), SystemClock, offsets::JOIN_REQUEST_EXPIRY)
    });
    // ── Notification group (notify role) ──
    let network_difficulty_has_push = hooks.fcm.is_some() || hooks.web_push.is_some();
    let network_difficulty_shutdown = if run_notifications {
        if !network_difficulty_has_push {
            info!(
                "crons.network_difficulty: spawned without push adapters — \
                 tracker row will stay fresh but no push notifications will fire"
            );
        }
        Some(spawn_network_difficulty_cron(
            NetworkDifficultyCronConfig {
                startup_offset: offsets::NETWORK_DIFFICULTY,
                ..NetworkDifficultyCronConfig::default()
            },
            pool.clone(),
            hooks.fcm.clone(),
            hooks.web_push.clone(),
        ))
    } else {
        None
    };

    let telegram_adapter: Option<Arc<TelegramAdapter>> = listeners.telegram_adapter();
    let ntfy_adapter: Option<Arc<NtfyAdapter>> = listeners.ntfy_adapter();
    let hourly_stats_telegram = telegram_adapter.is_some();
    let hourly_stats_ntfy = ntfy_adapter.is_some();
    // Skip the cron entirely when neither adapter exists: the hourly
    // digest would have nowhere to fan out and the per-row DB scan
    // would burn CPU for nothing.
    let hourly_stats_shutdown = if run_notifications && (hourly_stats_telegram || hourly_stats_ntfy)
    {
        Some(spawn_hourly_stats_cron(
            HourlyStatsCronConfig {
                startup_offset: offsets::HOURLY_STATS,
                ..HourlyStatsCronConfig::default()
            },
            pool.clone(),
            Some(foundation.redis.clone()),
            telegram_adapter,
            ntfy_adapter,
            listeners.chat_languages().unwrap_or_default(),
        ))
    } else {
        if run_notifications {
            info!("crons.hourly_stats: SKIPPED (no Telegram or ntfy adapter — nothing to fan out)");
        }
        None
    };

    let best_difficulty_shutdown = match (run_notifications, dispatcher) {
        (true, Some(dispatcher)) => Some(spawn_best_difficulty_cron(
            BestDifficultyCronConfig {
                startup_offset: offsets::BEST_DIFFICULTY,
                ..BestDifficultyCronConfig::default()
            },
            pool.clone(),
            dispatcher,
        )),
        (true, None) => {
            info!("crons.best_difficulty: SKIPPED (no dispatcher — no transport adapters)");
            None
        }
        (false, _) => None,
    };

    CronHandles {
        inner: Some(Inner {
            kill_dead_cancel,
            kill_dead_join,
            old_stats_cancel,
            old_stats_join,
            old_blocks_cancel,
            old_blocks_join,
            stale_push_cancel,
            stale_push_join,
            invitation_expiry_shutdown,
            join_request_expiry_shutdown,
            network_difficulty_shutdown,
            hourly_stats_shutdown,
            best_difficulty_shutdown,
            network_difficulty_has_push,
            hourly_stats_telegram,
            hourly_stats_ntfy,
            ran_maintenance: run_maintenance,
            ran_notifications: run_notifications,
        }),
    }
}

/// Dead-session sweep, 60 s tick. Tick fires after the first interval,
/// never immediately, so we don't race a just-spawned session that
/// hasn't had its first `updatedAt` write yet.
///
/// Two-step verdict since the live fields moved to Redis: `updatedAt`
/// is only stamped at birth/re-register/soft-delete, so age alone means
/// "past the birth grace", not "silent". A candidate is dead only when
/// its `client:live:*` hash is ALSO gone (no touch flush refreshed the
/// TTL for 5 minutes). ⚠️ Fail-open on Redis trouble: "cannot ask" must
/// skip the tick, never sweep — sweeping actively-hashing miners is the
/// exact bug the two-step shape exists to prevent.
fn spawn_kill_dead_clients_loop(
    pool: PgPool,
    redis: redis::aio::ConnectionManager,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = staggered_interval(KILL_DEAD_TICK, offsets::KILL_DEAD);
        info!("crons.kill_dead_clients: loop started");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("crons.kill_dead_clients: cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    let cutoff_ms =
                        Utc::now().timestamp_millis() - STALE_CLIENT_TTL.as_millis() as i64;
                    match sweep_dead_sessions_once(&pool, &redis, cutoff_ms).await {
                        Ok(0) => {}
                        Ok(n) => info!(
                            count = n,
                            cutoff_ms,
                            "crons.kill_dead_clients: swept dead sessions"
                        ),
                        Err(err) => warn!(
                            err,
                            cutoff_ms,
                            "crons.kill_dead_clients: sweep skipped (will retry on next tick)"
                        ),
                    }
                }
            }
        }
        info!("crons.kill_dead_clients: loop stopped");
    })
}

/// One sweep pass — candidates from PG, verdict from Redis, soft-delete
/// back into PG. Returns the number of sessions soft-deleted; any error
/// (PG or Redis) aborts the pass without sweeping anything.
async fn sweep_dead_sessions_once(
    pool: &PgPool,
    redis: &redis::aio::ConnectionManager,
    cutoff_ms: i64,
) -> Result<u64, String> {
    let candidates = bp_db::find_stale_active_sessions(pool, cutoff_ms)
        .await
        .map_err(|e| format!("candidates: {e}"))?;
    if candidates.is_empty() {
        return Ok(0);
    }
    let triples: Vec<(&str, &str, &str)> = candidates
        .iter()
        .map(|c| {
            (
                c.address.as_str(),
                c.client_name.as_str(),
                c.session_id.as_str(),
            )
        })
        .collect();
    let alive = bp_client_live::live_keys_exist(Some(redis), &triples)
        .await
        .map_err(|e| format!("live-key check: {e}"))?;
    let mut addresses = Vec::new();
    let mut client_names = Vec::new();
    let mut session_ids = Vec::new();
    for (c, alive) in candidates.iter().zip(alive) {
        if !alive {
            addresses.push(c.address.as_str().to_string());
            client_names.push(c.client_name.clone());
            session_ids.push(c.session_id.clone());
        }
    }
    if addresses.is_empty() {
        return Ok(0);
    }
    bp_db::soft_delete_sessions(pool, &addresses, &client_names, &session_ids)
        .await
        .map_err(|e| format!("soft-delete: {e}"))
}

// ─── Cleanup cron tasks (hourly stats purge + daily block purge) ──

const HOURLY_TICK: Duration = Duration::from_secs(60 * 60);
const DAILY_TICK: Duration = Duration::from_secs(24 * 60 * 60);
const WEEKLY_TICK: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// 90-day inactivity threshold: subscriptions whose `lastNotificationAt`
/// (or `createdAt` when never notified) is older than this are hard-deleted.
const STALE_PUSH_SUBSCRIPTION_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// 14-day cutoff for the per-(address, worker, session, slot) detail
/// tables — UI charts only render 1d/3d/7d windows.
const STATS_RETENTION: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// 2-hour cutoff for soft-deleted clients before hard-delete.
///
/// Was 24 h. Nothing needs the corpses that long: the device-status
/// gate's restart seed looks back `SEED_LOOKBACK` = 1 h, and the
/// "known device" decision is carried by the reported state in Redis
/// (7-day TTL), not by these rows. What the long window did do is bloat
/// the table — measured 2026-08-06 on prod: ~71k retained rows against
/// ~740 live ones, scattering the live rows over ~250 heap pages that
/// every bulk writer then re-logs as full-page writes.
const CLIENT_HARD_DELETE_RETENTION: Duration = Duration::from_secs(2 * 60 * 60);

/// Hourly cron: purge 14-day-old stats from the four per-session
/// tables + hard-delete soft-deleted clients older than 1 day.
pub(crate) fn spawn_old_stats_cleanup(pool: PgPool, cancel: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = staggered_interval(HOURLY_TICK, offsets::OLD_STATS_CLEANUP);
        info!("crons.old_stats_cleanup: loop started");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("crons.old_stats_cleanup: cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    let now = Utc::now().timestamp_millis();
                    let stats_cutoff = now - STATS_RETENTION.as_millis() as i64;
                    let hourly_cutoff =
                        (stats_cutoff / (60 * 60 * 1000)) * (60 * 60 * 1000);
                    let client_cutoff = now - CLIENT_HARD_DELETE_RETENTION.as_millis() as i64;

                    let mut totals: [(&str, u64); 6] = [
                        ("client_statistics", 0),
                        ("client_rejected_statistics", 0),
                        ("client_difficulty_statistics", 0),
                        ("pool_mode_hashrate", 0),
                        ("client_entity_hard_delete", 0),
                        ("email_verification_purge", 0),
                    ];
                    match bp_db::delete_old_client_statistics(&pool, stats_cutoff).await {
                        Ok(n) => totals[0].1 = n,
                        Err(err) => warn!(%err, "delete_old_client_statistics"),
                    }
                    match bp_db::delete_old_client_rejected_statistics(&pool, stats_cutoff).await {
                        Ok(n) => totals[1].1 = n,
                        Err(err) => warn!(%err, "delete_old_client_rejected_statistics"),
                    }
                    match bp_db::delete_old_client_difficulty_statistics(&pool, hourly_cutoff).await {
                        Ok(n) => totals[2].1 = n,
                        Err(err) => warn!(%err, "delete_old_client_difficulty_statistics"),
                    }
                    match bp_db::delete_old_pool_mode_hashrate(&pool, stats_cutoff).await {
                        Ok(n) => totals[3].1 = n,
                        Err(err) => warn!(%err, "delete_old_pool_mode_hashrate"),
                    }
                    match bp_db::delete_old_clients(&pool, client_cutoff).await {
                        Ok(n) => totals[4].1 = n,
                        Err(err) => warn!(%err, "delete_old_clients"),
                    }
                    match bp_db::delete_expired_email_verifications(&pool, now).await {
                        Ok(n) => totals[5].1 = n,
                        Err(err) => warn!(%err, "delete_expired_email_verifications"),
                    }
                    let total: u64 = totals.iter().map(|(_, n)| *n).sum();
                    if total > 0 {
                        info!(
                            client_statistics = totals[0].1,
                            client_rejected_statistics = totals[1].1,
                            client_difficulty_statistics = totals[2].1,
                            pool_mode_hashrate = totals[3].1,
                            client_entity_hard_delete = totals[4].1,
                            email_verification_purge = totals[5].1,
                            stats_cutoff,
                            hourly_cutoff,
                            client_cutoff,
                            "crons.old_stats_cleanup: purged"
                        );
                    }
                }
            }
        }
        info!("crons.old_stats_cleanup: loop stopped");
    })
}

/// Daily cron: purge all rpc_block_entity rows except the tip.
pub(crate) fn spawn_old_blocks_cleanup(pool: PgPool, cancel: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = staggered_interval(DAILY_TICK, offsets::OLD_BLOCKS_CLEANUP);
        info!("crons.old_blocks_cleanup: loop started");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("crons.old_blocks_cleanup: cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    match bp_db::delete_old_rpc_blocks(&pool).await {
                        Ok(0) => {}
                        Ok(n) => info!(count = n, "crons.old_blocks_cleanup: purged"),
                        Err(err) => warn!(%err, "delete_old_rpc_blocks"),
                    }
                }
            }
        }
        info!("crons.old_blocks_cleanup: loop stopped");
    })
}

/// Weekly cron: hard-DELETE push subscriptions that have had no activity
/// (no `lastNotificationAt` stamp, or stamp older than 90 days).
fn spawn_stale_push_cleanup(pool: PgPool, cancel: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = staggered_interval(WEEKLY_TICK, offsets::STALE_PUSH_CLEANUP);
        info!("crons.stale_push_cleanup: loop started");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("crons.stale_push_cleanup: cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    let cutoff_ms = Utc::now().timestamp_millis()
                        - STALE_PUSH_SUBSCRIPTION_TTL.as_millis() as i64;
                    match bp_db::delete_stale_push_subscriptions(&pool, cutoff_ms).await {
                        Ok(0) => {}
                        Ok(n) => info!(count = n, cutoff_ms, "crons.stale_push_cleanup: purged"),
                        Err(err) => warn!(%err, "delete_stale_push_subscriptions"),
                    }
                }
            }
        }
        info!("crons.stale_push_cleanup: loop stopped");
    })
}

#[cfg(test)]
mod sweep_tests {
    use super::sweep_dead_sessions_once;
    use bp_common::live_client_key::client_live_key;
    use bp_test_support::{connect_pg_or_skip, connect_redis_in_range_or_skip, redis_db};

    fn upsert(session: &str, address: &str) -> bp_db::ClientUpsert {
        bp_db::ClientUpsert {
            address: address.to_string(),
            client_name: "wkr".to_string(),
            session_id: session.to_string(),
            user_agent: None,
            start_time_ms: 1_700_000_000_000,
        }
    }

    async fn active(pool: &sqlx::PgPool, session: &str) -> bool {
        sqlx::query_scalar::<_, Option<i64>>(
            r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#,
        )
        .bind(session)
        .fetch_one(pool)
        .await
        .expect("row")
        .is_none()
    }

    /// The two-step verdict: of two equally stale birth rows, only the
    /// one WITHOUT a `client:live:*` key is swept — a live hash proves
    /// the session is still flushing touches, however old `updatedAt` is.
    #[tokio::test]
    async fn sweep_kills_only_sessions_without_a_live_key() {
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 17).await
        else {
            return;
        };
        let addr = "test_sweep_addr";
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(addr)
            .execute(&pool)
            .await;
        bp_db::upsert_client(&pool, &upsert("swpA0001", addr))
            .await
            .expect("seed A");
        bp_db::upsert_client(&pool, &upsert("swpB0001", addr))
            .await
            .expect("seed B");
        sqlx::query(r#"UPDATE client_entity SET "updatedAt" = 1000 WHERE address = $1"#)
            .bind(addr)
            .execute(&pool)
            .await
            .expect("age rows");
        // Session A has a live hash; B has none.
        let key = client_live_key(addr, "wkr", "swpA0001");
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg("hash_rate")
            .arg("1.0")
            .query_async(&mut redis)
            .await
            .expect("seed live key");
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(300i64)
            .query_async(&mut redis)
            .await
            .expect("ttl");

        sweep_dead_sessions_once(&pool, &redis, 2_000)
            .await
            .expect("sweep");

        assert!(
            active(&pool, "swpA0001").await,
            "live-keyed session survives"
        );
        assert!(!active(&pool, "swpB0001").await, "keyless session is swept");
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(addr)
            .execute(&pool)
            .await;
    }

    /// Fail-open: when Redis cannot be asked, the sweep must SKIP —
    /// "cannot ask" and "no key" are different answers, and confusing
    /// them sweeps actively-hashing miners (the exact bug the two-step
    /// shape exists to prevent).
    #[tokio::test]
    async fn sweep_skips_everything_when_redis_is_unreachable() {
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        // A manager built through a proxy that dies right after connect.
        let base =
            std::env::var("BP_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:16379".to_string());
        let upstream = base
            .trim_start_matches("redis://")
            .split('/')
            .next()
            .map(|hp| hp.rsplit('@').next().unwrap_or(hp).to_string())
            .expect("host:port");
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let port = listener.local_addr().expect("addr").port();
        // Track the per-connection forwarders too: aborting only the
        // accept loop leaves established connections ALIVE (the detached
        // copy task keeps forwarding), and a healthy connection answers
        // EXISTS — the exact opposite of the outage this test stages.
        let conns: std::sync::Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
            Default::default();
        let conns_in_loop = conns.clone();
        let accept = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let upstream = upstream.clone();
                let handle = tokio::spawn(async move {
                    if let Ok(mut out) = tokio::net::TcpStream::connect(&upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
                    }
                });
                conns_in_loop.lock().unwrap().push(handle);
            }
        });
        let client = redis::Client::open(format!("redis://127.0.0.1:{port}/0")).expect("client");
        let manager = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            redis::aio::ConnectionManager::new(client),
        )
        .await
        {
            Ok(Ok(m)) => m,
            _ => {
                eprintln!("test Redis unreachable — skipping");
                accept.abort();
                return;
            }
        };
        // Kill the proxy: the accept loop AND every live forwarder.
        accept.abort();
        for handle in conns.lock().unwrap().drain(..) {
            handle.abort();
        }

        let addr = "test_sweep_down_addr";
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(addr)
            .execute(&pool)
            .await;
        bp_db::upsert_client(&pool, &upsert("swpC0001", addr))
            .await
            .expect("seed");
        sqlx::query(r#"UPDATE client_entity SET "updatedAt" = 1000 WHERE address = $1"#)
            .bind(addr)
            .execute(&pool)
            .await
            .expect("age row");

        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sweep_dead_sessions_once(&pool, &manager, 2_000),
        )
        .await
        .expect("sweep must not hang");
        assert!(res.is_err(), "unreachable Redis must abort the pass");
        assert!(
            active(&pool, "swpC0001").await,
            "no session may be swept on a failed pass"
        );
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(addr)
            .execute(&pool)
            .await;
    }
}
