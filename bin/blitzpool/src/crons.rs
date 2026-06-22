// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background cron wiring — Phase 7.5.
//!
//! Spawns the 4 cron loops that are wireable today with the
//! foundation + engines + hooks state already constructed by
//! `boot.rs` / `engines.rs` / `hooks.rs`:
//!
//! 1. **`kill_dead_clients`** (every 60 s) — soft-deletes `client_entity`
//!    rows whose `updatedAt` is older than 5 minutes. Catches sessions
//!    whose disconnect path didn't fire cleanly (network drop without
//!    a clean FIN). Driven by `bp_db::client::kill_dead_clients`.
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

use bp_config::CapacityAlertConfig;
use bp_cron_utils::SystemClock;
use bp_db::{count_pplns_group_members_for_group, list_active_pplns_groups};
use bp_group_mgmt_engine::cron::{spawn_invitation_expiry_cron, spawn_join_request_expiry_cron};
use bp_notifications::adapter::{NtfyAdapter, SmtpAdapter, TelegramAdapter};
use bp_notifications::cron::best_difficulty::{
    spawn_best_difficulty_cron, BestDifficultyCronConfig,
};
use bp_notifications::cron::hourly_stats::{spawn_hourly_stats_cron, HourlyStatsCronConfig};
use bp_notifications::cron::network_difficulty::{
    spawn_network_difficulty_cron, NetworkDifficultyCronConfig,
};
use bp_notifications::dispatcher::NotificationDispatcher;
use bp_notifications::template::{render_capacity_alert, CapacityAlertContext, CapacityAlertLevel};
use bp_pplns::max_coinbase_outputs;
use bp_pplns_engine::window::WindowStore;
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

/// Staleness cutoff for the `kill_dead_clients` sweep — sessions
/// whose `updatedAt` is older than this are eligible for soft-delete.
const STALE_CLIENT_TTL: Duration = Duration::from_secs(5 * 60);

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
    pub(crate) const CAPACITY_MONITOR: Duration = Duration::from_secs(53);
}

/// Engine-side inputs for the capacity-monitor cron. Extracted from
/// the PPLNS engine by the caller (main.rs) so crons.rs doesn't
/// need to import the full engine type.
pub(crate) struct CapacityMonitorParams {
    /// Cloned window store from the PPLNS engine, `None` when PPLNS
    /// is disabled and only group-solo capacity needs monitoring.
    pub pplns_window: Option<WindowStore>,
    /// The configured coinbase weight budget — used to derive
    /// `max_coinbase_outputs`.
    pub coinbase_budget: u32,
    /// Whether the PPLNS fee output is present (consumes one output
    /// slot from the capacity ceiling).
    pub has_fee_output: bool,
}

// ─── Capacity monitor helpers ────────────────────────────────────

const CAPACITY_DAILY_REMINDER_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapLevel {
    Below,
    Warning,
    Urgent,
}

struct CapState {
    level: CapLevel,
    last_sent_ms: i64,
}

impl Default for CapState {
    fn default() -> Self {
        Self {
            level: CapLevel::Below,
            last_sent_ms: 0,
        }
    }
}

fn cap_level_for(percent: f64, warning: f64, urgent: f64) -> CapLevel {
    if percent >= urgent {
        CapLevel::Urgent
    } else if percent >= warning {
        CapLevel::Warning
    } else {
        CapLevel::Below
    }
}

/// State machine that decides whether to send a capacity alert.
fn cap_decide(prev: &CapState, new: CapLevel, now_ms: i64) -> Option<CapacityAlertLevel> {
    if prev.level == new {
        if new == CapLevel::Below {
            return None;
        }
        if now_ms - prev.last_sent_ms >= CAPACITY_DAILY_REMINDER_MS {
            return Some(match new {
                CapLevel::Warning => CapacityAlertLevel::Warning,
                CapLevel::Urgent => CapacityAlertLevel::Urgent,
                CapLevel::Below => unreachable!(),
            });
        }
        return None;
    }
    if new == CapLevel::Below {
        return Some(CapacityAlertLevel::Recovery);
    }
    if new == CapLevel::Urgent {
        return Some(CapacityAlertLevel::Urgent);
    }
    // new == Warning
    if prev.level == CapLevel::Urgent {
        return None; // stepping down — wait for full recovery
    }
    Some(CapacityAlertLevel::Warning)
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
/// own shutdown signal; [`shutdown`] fires them all and awaits the
/// kill-dead-clients loop's `JoinHandle` (the other 3 crons run
/// detached on the tokio runtime).
pub(crate) struct CronHandles {
    inner: Option<Inner>,
}

struct Inner {
    // ── Maintenance crons — the `payout`/accounting role. DB upkeep + group
    //    lifecycle + the operator capacity alert; no notification dispatcher.
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
    /// Hourly coinbase-capacity operator alert. `None` when not running
    /// maintenance, or smtp is not configured / `capacity_alert.enabled =
    /// false`.
    capacity_monitor_cancel: Option<CancellationToken>,
    capacity_monitor_join: Option<JoinHandle<()>>,
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
                capacity_monitor = inner.capacity_monitor_cancel.is_some(),
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
        if let Some(c) = inner.capacity_monitor_cancel {
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
        // Only the locally-owned tasks (kill_dead + the cleanups + capacity)
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
        if let Some(join) = inner.capacity_monitor_join {
            if let Err(err) = join.await {
                warn!(%err, "crons: capacity_monitor join failed");
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
/// lifecycle + capacity-alert crons; `run_notifications` (the `notify` role)
/// gates the push/digest crons. A process running both (monolith / co-located)
/// spawns everything; a split process spawns only its group.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn(
    foundation: &FoundationHandles,
    hooks: &ProductionHooks,
    listeners: &ListenerHandles,
    dispatcher: Option<Arc<NotificationDispatcher>>,
    cap_params: CapacityMonitorParams,
    cap_cfg: &CapacityAlertConfig,
    admin_email: Option<&str>,
    run_maintenance: bool,
    run_notifications: bool,
) -> CronHandles {
    let pool = foundation.db.pool().clone();

    // ── Maintenance group (accounting role) ──
    let (kill_dead_cancel, kill_dead_join) = if run_maintenance {
        let c = CancellationToken::new();
        let j = spawn_kill_dead_clients_loop(pool.clone(), c.clone());
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
    let (capacity_monitor_cancel, capacity_monitor_join) = 'cap: {
        if !run_maintenance {
            break 'cap (None, None);
        }
        let (Some(smtp), Some(email), true) = (hooks.smtp.clone(), admin_email, cap_cfg.enabled)
        else {
            info!(
                enabled = cap_cfg.enabled,
                smtp_ready = hooks.smtp.is_some(),
                admin_email_set = admin_email.is_some(),
                "crons.capacity_monitor: SKIPPED"
            );
            break 'cap (None, None);
        };
        if email.trim().is_empty() {
            info!("crons.capacity_monitor: SKIPPED (POOL_ADMIN_EMAIL is empty)");
            break 'cap (None, None);
        }
        let cancel = CancellationToken::new();
        let join = spawn_capacity_monitor(
            cap_params,
            pool.clone(),
            smtp,
            email.to_string(),
            cap_cfg.threshold,
            cap_cfg.urgent_threshold,
            cancel.clone(),
        );
        (Some(cancel), Some(join))
    };

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
            capacity_monitor_cancel,
            capacity_monitor_join,
            ran_maintenance: run_maintenance,
            ran_notifications: run_notifications,
        }),
    }
}

/// The `bp_db::kill_dead_clients` primitive is a one-shot fn, not a
/// spawned cron — so we wrap it in a 60 s tick loop here. Tick fires
/// after the first interval, never immediately, so we don't race a
/// just-spawned session that hasn't had its first `updatedAt` write
/// yet.
fn spawn_kill_dead_clients_loop(pool: PgPool, cancel: CancellationToken) -> JoinHandle<()> {
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
                    match bp_db::kill_dead_clients(&pool, cutoff_ms).await {
                        Ok(0) => {}
                        Ok(n) => info!(
                            count = n,
                            cutoff_ms,
                            "crons.kill_dead_clients: swept stale sessions"
                        ),
                        Err(err) => warn!(
                            %err,
                            cutoff_ms,
                            "crons.kill_dead_clients: sweep failed (will retry on next tick)"
                        ),
                    }
                }
            }
        }
        info!("crons.kill_dead_clients: loop stopped");
    })
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
/// 1-day cutoff for soft-deleted clients before hard-delete.
const CLIENT_HARD_DELETE_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

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

/// Hourly cron: email operator when PPLNS window or group-solo member
/// count approaches the coinbase output capacity ceiling.
///
/// Uses in-memory state for dedup (no Redis required); state resets on
/// restart which may cause one extra alert per restart — acceptable.
fn spawn_capacity_monitor(
    params: CapacityMonitorParams,
    pool: PgPool,
    smtp: Arc<SmtpAdapter>,
    admin_email: String,
    warning_threshold: f64,
    urgent_threshold: f64,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    use std::collections::HashMap;
    tokio::spawn(async move {
        let max = max_coinbase_outputs(params.coinbase_budget, params.has_fee_output);
        let checker = CapacityChecker {
            coinbase_budget: params.coinbase_budget,
            env_var: "PPLNS_COINBASE_WEIGHT_BUDGET".to_string(),
            warning_threshold,
            urgent_threshold,
            smtp,
            admin_email,
        };
        let mut states: HashMap<String, CapState> = HashMap::new();
        let mut ticker = staggered_interval(HOURLY_TICK, offsets::CAPACITY_MONITOR);
        info!(
            max,
            budget = params.coinbase_budget,
            "crons.capacity_monitor: loop started"
        );
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("crons.capacity_monitor: cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    let now_ms = Utc::now().timestamp_millis();

                    // PPLNS window check
                    if let Some(ref window) = params.pplns_window {
                        match window.read_window_by_address().await {
                            Ok(map) => {
                                checker
                                    .check("pplns", "PPLNS main pool", map.len() as u64, max, now_ms, &mut states)
                                    .await;
                            }
                            Err(err) => warn!(%err, "crons.capacity_monitor: read_window_by_address"),
                        }
                    }

                    // Group-solo member count check
                    match list_active_pplns_groups(&pool).await {
                        Ok(groups) => {
                            for group in groups.into_iter().filter(|g| g.active) {
                                match count_pplns_group_members_for_group(&pool, group.id).await {
                                    Ok(n) => {
                                        let key = format!("group:{}", group.id);
                                        let scope = format!(r#"Group "{}""#, group.name);
                                        checker.check(&key, &scope, n as u64, max, now_ms, &mut states).await;
                                    }
                                    Err(err) => warn!(%err, group_id = %group.id, "crons.capacity_monitor: count members"),
                                }
                            }
                        }
                        Err(err) => warn!(%err, "crons.capacity_monitor: list_active_pplns_groups"),
                    }
                }
            }
        }
        info!("crons.capacity_monitor: loop stopped");
    })
}

struct CapacityChecker {
    coinbase_budget: u32,
    env_var: String,
    warning_threshold: f64,
    urgent_threshold: f64,
    smtp: Arc<SmtpAdapter>,
    admin_email: String,
}

impl CapacityChecker {
    async fn check(
        &self,
        state_key: &str,
        scope: &str,
        current: u64,
        max: u64,
        now_ms: i64,
        states: &mut std::collections::HashMap<String, CapState>,
    ) {
        let percent = if max > 0 {
            current as f64 / max as f64
        } else {
            1.0
        };
        let new_level = cap_level_for(percent, self.warning_threshold, self.urgent_threshold);
        let prev = states.entry(state_key.to_string()).or_default();
        let Some(alert_level) = cap_decide(prev, new_level, now_ms) else {
            return;
        };
        let threshold = match new_level {
            CapLevel::Urgent => self.urgent_threshold,
            _ => self.warning_threshold,
        };
        let ctx = CapacityAlertContext {
            level: alert_level,
            scope: scope.to_string(),
            current,
            max,
            percent,
            threshold,
            coinbase_weight_budget: self.coinbase_budget as u64,
            env_var_name: self.env_var.clone(),
        };
        let content = render_capacity_alert(&ctx);
        match self.smtp.send_email(&self.admin_email, &content).await {
            Ok(()) => {
                info!(
                    scope,
                    %percent,
                    current,
                    max,
                    level = ?alert_level,
                    "crons.capacity_monitor: alert sent"
                );
                prev.level = new_level;
                prev.last_sent_ms = now_ms;
            }
            Err(err) => warn!(%err, scope, "crons.capacity_monitor: send_email failed"),
        }
    }
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
