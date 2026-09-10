// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background cron wiring — Phase 7.5.
//!
//! Spawns the 4 cron loops that are wireable today with the
//! foundation + engines + hooks state already constructed by
//! `boot.rs` / `engines.rs` / `hooks.rs`:
//!
//! 1. **`kill_dead_clients`** (every 60 s) — soft-deletes `client_entity`
//!    rows past the 5-minute birth grace whose session no front holds any
//!    more. Catches sessions whose disconnect path didn't fire cleanly
//!    (network drop without a clean FIN, a front that restarted). The
//!    verdict comes first-hand from the fronts' published live set
//!    (`crate::live_sessions`): a session a front still holds is alive
//!    whatever its share flow says. Only where no front publishes
//!    sessions does the older rule decide — `client:live:*` hash gone on
//!    two consecutive passes. Candidates from
//!    `bp_db::find_stale_active_sessions`, soft-delete via
//!    `bp_db::soft_delete_sessions`.
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
use crate::live_sessions::RedisLiveSessions;

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
/// `updatedAt` is only stamped at birth/re-register/soft-delete, so age
/// alone means "past the birth grace", not "dead". The verdict on a
/// candidate is the fronts' published live set first (a held session is
/// alive, full stop) and the `client:live:*` hash second, where no front
/// publishes sessions — see [`sweep_dead_sessions_once`]. ⚠️ Fail-open on
/// Redis trouble: "cannot ask" must skip the tick, never sweep — sweeping
/// connected miners is the exact bug this shape exists to prevent.
fn spawn_kill_dead_clients_loop(
    pool: PgPool,
    redis: redis::aio::ConnectionManager,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = staggered_interval(KILL_DEAD_TICK, offsets::KILL_DEAD);
        let mut strikes = StrikeSet::new();
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
                    match sweep_dead_sessions_once(&pool, &redis, cutoff_ms, &mut strikes).await {
                        Ok(o) if o.is_quiet() => {}
                        Ok(o) => info!(
                            swept = o.swept,
                            revived = o.revived,
                            cutoff_ms,
                            "crons.kill_dead_clients: reconciled sessions"
                        ),
                        Err(err) => {
                            // Start the two-observation rule over: what we
                            // learned before an outage is not evidence after it.
                            strikes.clear();
                            warn!(
                                err,
                                cutoff_ms,
                                "crons.kill_dead_clients: sweep skipped (will retry on next tick)"
                            );
                        }
                    }
                }
            }
        }
        info!("crons.kill_dead_clients: loop stopped");
    })
}

/// Session triples whose live key was missing on the previous tick.
/// Bounded by the candidate count, replaced wholesale every pass.
type StrikeSet = std::collections::HashSet<(String, String, String)>;

/// How far back the repair half looks for a session it should un-delete:
/// the whole life of a soft-deleted row. Past
/// [`CLIENT_HARD_DELETE_RETENTION`] the row is gone and there is nothing
/// left to un-delete; anything shorter is a window in which a wrong
/// soft-delete turns permanent. It was 15 minutes — measured 2026-09-10
/// on prod, a miner that paused ~70 min with its socket open was retired
/// and never revived. The query stays small either way — measured the
/// same day on prod: 120 rows soft-deleted in the last 20 minutes, 898
/// in the last two hours, against 712 active rows.
const REVIVE_LOOKBACK: Duration = CLIENT_HARD_DELETE_RETENTION;

/// What one reconcile pass did.
struct SweepOutcome {
    swept: u64,
    revived: u64,
}

impl SweepOutcome {
    fn is_quiet(&self) -> bool {
        self.swept == 0 && self.revived == 0
    }
}

/// One reconcile pass between the birth rows and the live hashes.
///
/// **Kill half.** Candidates come from PG (past the birth grace). The
/// verdict is first-hand where it can be: a session that a front still
/// holds — published by the process with the socket, see
/// `crate::live_sessions` — is alive, whatever its share flow says. That
/// is what keeps a miner that pauses with its connection open (standby
/// overnight, a slow rig) from being retired. Where no front publishes
/// sessions, the live key decides — and only a session whose key was
/// missing on TWO consecutive passes is swept. One observation is not
/// evidence: after a Redis restart the keyspace is legitimately empty
/// (the live hashes are deliberately excluded from the backup allowlist)
/// until the next touch flush repopulates it 30 s later, and a
/// single-observation sweep landing in that window would retire the
/// entire pool at once.
///
/// **Repair half.** A session soft-deleted within [`REVIVE_LOOKBACK`]
/// whose live hash has been written SINCE the soft-delete kept mining
/// through it, so the soft-delete was wrong and is undone. Only a live
/// session can satisfy that: a cleanly disconnected one stops touching,
/// so its `updated_at_ms` stays older than its `deletedAt` until the key
/// expires. This restores the self-healing the touch UPDATE used to
/// provide through `"deletedAt" = NULL`, which left with the hot writes.
///
/// Any error aborts the pass without sweeping anything — "cannot ask
/// Redis" and "no key" must never collapse into the same answer.
async fn sweep_dead_sessions_once(
    pool: &PgPool,
    redis: &redis::aio::ConnectionManager,
    cutoff_ms: i64,
    strikes: &mut StrikeSet,
) -> Result<SweepOutcome, String> {
    let swept = sweep_kill_half(pool, redis, cutoff_ms, strikes).await?;
    let revived = sweep_repair_half(pool, redis).await?;
    Ok(SweepOutcome { swept, revived })
}

async fn sweep_kill_half(
    pool: &PgPool,
    redis: &redis::aio::ConnectionManager,
    cutoff_ms: i64,
    strikes: &mut StrikeSet,
) -> Result<u64, String> {
    let candidates = bp_db::find_stale_active_sessions(pool, cutoff_ms)
        .await
        .map_err(|e| format!("candidates: {e}"))?;
    if candidates.is_empty() {
        strikes.clear();
        return Ok(0);
    }
    // `Err` is "cannot ask" and aborts the pass like any other Redis
    // failure; `None` is "no front publishes sessions" (a front on the
    // previous binary, a Redis just restarted) and leaves the key verdict
    // below in charge, which is all this cron had before.
    let held = RedisLiveSessions::new(redis.clone())
        .sessions()
        .await
        .map_err(|e| format!("front live set: {e}"))?;
    let alive = bp_client_live::live_keys_exist(Some(redis), &candidates)
        .await
        .map_err(|e| format!("live-key check: {e}"))?;

    let mut missing_now = StrikeSet::with_capacity(candidates.len());
    let mut addresses = Vec::new();
    let mut client_names = Vec::new();
    let mut session_ids = Vec::new();
    for (c, alive) in candidates.iter().zip(alive) {
        // A front holding this session under this very device needs no
        // second observation: the socket is open. The device has to
        // match, not only the id — an SV1 connection may re-authorize
        // under another worker name, and the row of the name it left
        // must still go.
        let held_by_a_front = held.as_ref().is_some_and(|h| {
            h.get(c.session_id.as_str())
                .is_some_and(|(a, w)| a == c.address.as_str() && *w == c.client_name)
        });
        if alive || held_by_a_front {
            continue;
        }
        let key = (
            c.address.as_str().to_string(),
            c.client_name.clone(),
            c.session_id.clone(),
        );
        // Second strike: missing now AND missing on the previous pass.
        if strikes.contains(&key) {
            addresses.push(key.0.clone());
            client_names.push(key.1.clone());
            session_ids.push(key.2.clone());
        }
        missing_now.insert(key);
    }
    *strikes = missing_now;

    if addresses.is_empty() {
        return Ok(0);
    }
    bp_db::soft_delete_sessions(pool, &addresses, &client_names, &session_ids)
        .await
        .map_err(|e| format!("soft-delete: {e}"))
}

async fn sweep_repair_half(
    pool: &PgPool,
    redis: &redis::aio::ConnectionManager,
) -> Result<u64, String> {
    let since_ms = Utc::now().timestamp_millis() - REVIVE_LOOKBACK.as_millis() as i64;
    let deleted = bp_db::find_recently_deleted_sessions(pool, since_ms)
        .await
        .map_err(|e| format!("deleted rows: {e}"))?;
    if deleted.is_empty() {
        return Ok(0);
    }
    let live = bp_client_live::live_fields_for_sessions(Some(redis), &deleted)
        .await
        .map_err(|e| format!("live-field check: {e}"))?;

    let mut addresses = Vec::new();
    let mut client_names = Vec::new();
    let mut session_ids = Vec::new();
    for (d, lf) in deleted.iter().zip(live) {
        // Touched after it was retired → it never stopped mining.
        let touched_after = lf
            .and_then(|lf| lf.updated_at_ms)
            .is_some_and(|ts| ts > d.deleted_at);
        if touched_after {
            addresses.push(d.address.as_str().to_string());
            client_names.push(d.client_name.clone());
            session_ids.push(d.session_id.clone());
        }
    }
    if addresses.is_empty() {
        return Ok(0);
    }
    let n = bp_db::revive_sessions(pool, &addresses, &client_names, &session_ids)
        .await
        .map_err(|e| format!("revive: {e}"))?;
    if n > 0 {
        warn!(
            count = n,
            "crons.kill_dead_clients: revived sessions that were mining through their soft-delete"
        );
    }
    Ok(n)
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
    use super::{sweep_dead_sessions_once, sweep_repair_half, StrikeSet};
    use bp_common::live_client_key::client_live_key;
    use bp_test_support::{connect_pg_or_skip, connect_redis_in_range_or_skip, redis_db};

    // ⚠️ Indices, not literals elsewhere in this binary: the
    // block-confirmation regtests claim 17–23 through named `DB_*`
    // constants, and `connect_redis_in_range_or_skip` FLUSHES the
    // database it opens — taking one of theirs wipes a money-path
    // regtest mid-run. Grep for `const DB_` as well as call sites
    // before picking a number.
    const DB_TWO_STRIKE: u8 = 24;
    const DB_KEY_RETURNS: u8 = 25;
    const DB_REVIVE: u8 = 26;
    const DB_FRONT_HOLDS: u8 = 27;
    const DB_FRONT_OTHER_WORKER: u8 = 28;

    /// A front that holds `session` under `(address, worker)`, written
    /// through the real registry so the test exercises the same
    /// incremental path a connect takes.
    async fn front_holding(
        redis: &redis::aio::ConnectionManager,
        front_id: &str,
        session: &str,
        address: &str,
        worker: &str,
    ) {
        use bp_share_hook::SharedSessionPersistence;
        struct Noop;
        #[async_trait::async_trait]
        impl SharedSessionPersistence for Noop {
            async fn register_session(&self, _: &str, _: &str, _: &str, _: Option<&str>) {}
            async fn deregister_session(&self, _: &str) {}
        }
        let reg = crate::live_sessions::LiveSessionRegistry::new(
            std::sync::Arc::new(Noop),
            redis.clone(),
            front_id,
        );
        reg.register_session(session, address, worker, None).await;
    }

    /// The kill half queries `client_entity` pool-wide, so two of these
    /// running at once would sweep each other's fixtures — one would
    /// then report the fail-open guard as broken when it is not.
    static SWEEP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn upsert(session: &str, address: &str) -> bp_db::ClientUpsert {
        bp_db::ClientUpsert {
            address: address.to_string(),
            client_name: "wkr".to_string(),
            session_id: session.to_string(),
            user_agent: None,
            start_time_ms: 1_700_000_000_000,
        }
    }

    async fn seed_aged(pool: &sqlx::PgPool, address: &str, session: &str) {
        bp_db::upsert_client(pool, &upsert(session, address))
            .await
            .expect("seed");
        sqlx::query(r#"UPDATE client_entity SET "updatedAt" = 1000 WHERE "sessionId" = $1"#)
            .bind(session)
            .execute(pool)
            .await
            .expect("age row");
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

    async fn cleanup(pool: &sqlx::PgPool, address: &str) {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(address)
            .execute(pool)
            .await;
    }

    async fn put_live_key(
        redis: &mut redis::aio::ConnectionManager,
        address: &str,
        session: &str,
        updated_at_ms: i64,
    ) {
        let key = client_live_key(address, "wkr", session);
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg("hash_rate")
            .arg("1.0")
            .arg("updated_at_ms")
            .arg(updated_at_ms)
            .query_async(redis)
            .await
            .expect("seed live key");
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(300i64)
            .query_async(redis)
            .await
            .expect("ttl");
    }

    /// The two-strike rule AND the verdict's selectivity in one pass
    /// pair: a missing key is not evidence on its own (pass 1 sweeps
    /// nothing), and on the second pass only the session that is still
    /// keyless dies — the live-keyed one survives however old its birth
    /// row is.
    #[tokio::test]
    async fn a_missing_key_sweeps_only_on_the_second_pass() {
        let _guard = SWEEP_LOCK.lock().await;
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        let Some(mut redis) =
            connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, DB_TWO_STRIKE).await
        else {
            return;
        };
        let addr = "test_sweep_addr";
        cleanup(&pool, addr).await;
        seed_aged(&pool, addr, "swpA0001").await;
        seed_aged(&pool, addr, "swpB0001").await;
        // A has a live hash, B has none.
        put_live_key(&mut redis, addr, "swpA0001", 1_700_000_000_000).await;

        let mut strikes = StrikeSet::new();
        let first = sweep_dead_sessions_once(&pool, &redis, 2_000, &mut strikes)
            .await
            .expect("first pass");
        assert_eq!(first.swept, 0, "one observation must not sweep anything");
        assert!(
            active(&pool, "swpB0001").await,
            "keyless session survives pass 1"
        );

        let second = sweep_dead_sessions_once(&pool, &redis, 2_000, &mut strikes)
            .await
            .expect("second pass");
        assert_eq!(second.swept, 1, "second consecutive miss sweeps");
        assert!(
            active(&pool, "swpA0001").await,
            "live-keyed session survives"
        );
        assert!(!active(&pool, "swpB0001").await, "keyless session is swept");

        cleanup(&pool, addr).await;
    }

    /// A key that reappears between the two passes clears the strike —
    /// this is the Redis-restart case, where the keyspace is briefly
    /// empty before the touch flush repopulates it.
    #[tokio::test]
    async fn a_key_that_comes_back_between_passes_is_never_swept() {
        let _guard = SWEEP_LOCK.lock().await;
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        let Some(mut redis) =
            connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, DB_KEY_RETURNS).await
        else {
            return;
        };
        let addr = "test_sweep_back_addr";
        cleanup(&pool, addr).await;
        seed_aged(&pool, addr, "swpD0001").await;

        let mut strikes = StrikeSet::new();
        // Pass 1: keyspace empty (as after a restart) → strike, no sweep.
        sweep_dead_sessions_once(&pool, &redis, 2_000, &mut strikes)
            .await
            .expect("first pass");
        assert!(active(&pool, "swpD0001").await);
        // The touch flush repopulates before the next tick.
        put_live_key(&mut redis, addr, "swpD0001", 1_700_000_000_000).await;
        sweep_dead_sessions_once(&pool, &redis, 2_000, &mut strikes)
            .await
            .expect("second pass");
        assert!(
            active(&pool, "swpD0001").await,
            "a session whose key came back must never be swept"
        );

        cleanup(&pool, addr).await;
    }

    /// The repair half: a session that kept mining THROUGH its
    /// soft-delete (its live hash was written after the stamp) is
    /// revived. The negative control is a session whose hash predates
    /// the stamp — a clean disconnect — which must stay retired.
    #[tokio::test]
    async fn a_session_that_mined_through_its_soft_delete_is_revived() {
        let _guard = SWEEP_LOCK.lock().await;
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        let Some(mut redis) =
            connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, DB_REVIVE).await
        else {
            return;
        };
        let addr = "test_revive_addr";
        cleanup(&pool, addr).await;
        seed_aged(&pool, addr, "rvvA0001").await;
        seed_aged(&pool, addr, "rvvB0001").await;
        bp_db::delete_client_for_session(&pool, "rvvA0001")
            .await
            .expect("retire A");
        bp_db::delete_client_for_session(&pool, "rvvB0001")
            .await
            .expect("retire B");
        let stamp: i64 =
            sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
                .bind("rvvA0001")
                .fetch_one(&pool)
                .await
                .expect("stamp");

        // A kept mining after the stamp; B's last share predates it.
        put_live_key(&mut redis, addr, "rvvA0001", stamp + 1_000).await;
        put_live_key(&mut redis, addr, "rvvB0001", stamp - 1_000).await;

        let revived = sweep_repair_half(&pool, &redis).await.expect("repair");
        assert!(revived >= 1, "the mining session must be revived");
        assert!(
            active(&pool, "rvvA0001").await,
            "session that mined through its soft-delete is back"
        );
        assert!(
            !active(&pool, "rvvB0001").await,
            "a cleanly disconnected session must stay retired"
        );

        cleanup(&pool, addr).await;
    }

    /// The front's word outranks the key. Three sessions past their
    /// birth grace, none of them touched: the one a front still holds
    /// survives both passes with no live key at all — that is a miner
    /// paused with its socket open — while the one nobody holds is
    /// swept on the second pass, and the one with a live key survives
    /// on the key alone, so the older verdict still stands behind the
    /// new one.
    ///
    /// Fails against the key-only verdict: the held session is swept.
    #[tokio::test]
    async fn a_session_a_front_still_holds_is_never_swept() {
        let _guard = SWEEP_LOCK.lock().await;
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        let Some(mut redis) =
            connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, DB_FRONT_HOLDS).await
        else {
            return;
        };
        let addr = "test_front_holds_addr";
        cleanup(&pool, addr).await;
        seed_aged(&pool, addr, "frtA0001").await; // held, no key
        seed_aged(&pool, addr, "frtB0001").await; // nobody holds it, no key
        seed_aged(&pool, addr, "frtC0001").await; // nobody holds it, live key
        front_holding(&redis, "front-holds", "frtA0001", addr, "wkr").await;
        put_live_key(&mut redis, addr, "frtC0001", 1_700_000_000_000).await;

        let mut strikes = StrikeSet::new();
        for pass in 1..=2 {
            sweep_dead_sessions_once(&pool, &redis, 2_000, &mut strikes)
                .await
                .expect("pass");
            assert!(
                active(&pool, "frtA0001").await,
                "pass {pass}: a session the front holds must not be swept, \
                 whatever its share flow"
            );
        }
        assert!(
            !active(&pool, "frtB0001").await,
            "the session no front holds is swept on the second pass"
        );
        assert!(
            active(&pool, "frtC0001").await,
            "a live key still counts where the front says nothing"
        );

        cleanup(&pool, addr).await;
    }

    /// Held is not enough: the front has to hold the session under the
    /// row's own device. An SV1 connection can re-authorize under a new
    /// worker name, and the row of the name it left is dead even though
    /// its session id is very much alive.
    ///
    /// Fails against a match on the session id alone.
    #[tokio::test]
    async fn a_session_held_under_another_worker_is_swept() {
        let _guard = SWEEP_LOCK.lock().await;
        let Some(pool) = connect_pg_or_skip().await else {
            return;
        };
        let Some(redis) =
            connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, DB_FRONT_OTHER_WORKER).await
        else {
            return;
        };
        let addr = "test_front_other_addr";
        cleanup(&pool, addr).await;
        seed_aged(&pool, addr, "frtD0001").await; // row says worker "wkr"
        front_holding(&redis, "front-other", "frtD0001", addr, "renamed").await;

        let mut strikes = StrikeSet::new();
        for _ in 1..=2 {
            sweep_dead_sessions_once(&pool, &redis, 2_000, &mut strikes)
                .await
                .expect("pass");
        }
        assert!(
            !active(&pool, "frtD0001").await,
            "the row of the worker name the session left must be swept"
        );

        cleanup(&pool, addr).await;
    }

    /// Fail-open: when Redis cannot be asked, the sweep must SKIP —
    /// "cannot ask" and "no key" are different answers, and confusing
    /// them sweeps actively-hashing miners.
    #[tokio::test]
    async fn sweep_skips_everything_when_redis_is_unreachable() {
        let _guard = SWEEP_LOCK.lock().await;
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
        // Track the forwarders too: aborting only the accept loop leaves
        // established connections ALIVE, and a healthy connection answers
        // EXISTS — the opposite of the outage this test stages.
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
        accept.abort();
        for handle in conns.lock().unwrap().drain(..) {
            handle.abort();
        }

        let addr = "test_sweep_down_addr";
        cleanup(&pool, addr).await;
        seed_aged(&pool, addr, "swpC0001").await;

        // Two passes: even the strike bookkeeping must not advance on a
        // pass that could not observe anything.
        let mut strikes = StrikeSet::new();
        for _ in 0..2 {
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                sweep_dead_sessions_once(&pool, &manager, 2_000, &mut strikes),
            )
            .await
            .expect("sweep must not hang");
            assert!(res.is_err(), "unreachable Redis must abort the pass");
        }
        assert!(
            active(&pool, "swpC0001").await,
            "no session may be swept on a failed pass"
        );

        cleanup(&pool, addr).await;
    }
}
