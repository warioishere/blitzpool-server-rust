// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngine` — top-level wiring of the Group-Solo
//! service-engine.
//!
//! Owns the Postgres pool, Redis-backed `GroupRoundStore`,
//! `DistributionBuilder` (with its in-flight cache), and
//! `GroupResetRunner` plus its per-group calendar-aligned cron
//! tasks.
//!
//! Public API:
//!
//! - `record_share` / `record_reject` — hot-path; called per
//!   accepted / rejected share after the stratum layer has resolved
//!   mode = Group-Solo + group_id for the address.
//! - `build_distribution` — called by the template-build path with
//!   the prospective finder's address.
//! - `on_block_found` — called when a Group-Solo finder wins a block.
//!   Writes the payout history from the block's OWN coinbase, resets
//!   the round (Variant A — preserves `lastAcceptedShareAt`), drops
//!   the group's snapshots, invalidates the distribution cache.
//! - `manual_reset` — admin-triggerable wrapper.
//! - `shutdown` — flips the cancel watch so background tasks exit.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bp_common::{AddressId, InvalidAddressError, Sats};
use bp_cron_utils::SystemClock;
use bp_db::{find_group, DbError, PplnsGroupRow};
use bp_group_mgmt::group::{window_duration_ms, PayoutMode, RoundResetPreset};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::{watch, Mutex as TokioMutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{ConfigError, GroupSoloEngineConfig};
use crate::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError, DistributionResult,
};
use crate::history::{
    apply_distribution, ApplyDistributionResult, AuditRow, GroupPayoutRowType, LedgerError,
};
use crate::reset::{spawn_per_group_task, GroupResetRunner, ResetError, ResetSchedule};

use crate::round::snapshot::{delete_all_for_group, delete_snapshot_for};
use crate::round::{GroupRoundStore, RoundError, WINDOW_BUCKET_MS};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("round: {0}")]
    Round(#[from] RoundError),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("payout history: {0}")]
    Ledger(#[from] LedgerError),
    #[error("reset: {0}")]
    Reset(#[from] ResetError),
    #[error("distribution: {0}")]
    Distribution(Arc<DistributionError>),
    #[error("snapshot missing for group {group_id} finder {finder_address} block {block_height}")]
    SnapshotMissing {
        group_id: Uuid,
        finder_address: String,
        block_height: i32,
    },
    #[error(
        "no snapshot for group {group_id} finder {finder_address} under the winning job's payout \
         list — the block needs an operator reprocess"
    )]
    SnapshotMissingForPayouts {
        group_id: Uuid,
        finder_address: String,
    },
    #[error(
        "snapshot reward mismatch for group {group_id}: snapshot={snapshot_reward} block={actual_reward}"
    )]
    SnapshotRewardMismatch {
        group_id: Uuid,
        snapshot_reward: u64,
        actual_reward: u64,
    },
    #[error(
        "group {group_id} block {block_height} coinbase pays {actual_reward} sats, less than \
         the {subsidy} sat subsidy the block was entitled to — it forfeited money, so nothing \
         about it is trustworthy enough to book unattended"
    )]
    RevenueBelowSubsidy {
        group_id: Uuid,
        block_height: i32,
        actual_reward: u64,
        subsidy: u64,
    },
    #[error("on_block_found already in flight for group {group_id}")]
    BlockFoundInProgress { group_id: Uuid },
    #[error("invalid address in snapshot: {0}")]
    Address(#[from] InvalidAddressError),
}

impl EngineError {
    /// Would retrying this ever succeed?
    ///
    /// The confirmation watcher re-applies a pending block on every
    /// tick and only drops it once the apply returns `Ok`. That is
    /// right for a database blip and wrong for a verdict: a snapshot
    /// that expired, a coinbase that burned its own subsidy or an
    /// address that will not parse produce the SAME failure forever,
    /// so retrying them is an infinite loop that hides the block
    /// behind a repeating warning instead of surfacing it once.
    ///
    /// Terminal here does not mean the block is lost — it means no
    /// automatic path can book it, and the operator reprocess reads
    /// the block's own coinbase off the chain rather than the parked
    /// blob.
    pub fn is_terminal(&self) -> bool {
        match self {
            EngineError::Config(_)
            | EngineError::SnapshotMissing { .. }
            | EngineError::SnapshotMissingForPayouts { .. }
            | EngineError::SnapshotRewardMismatch { .. }
            | EngineError::RevenueBelowSubsidy { .. }
            | EngineError::Address(_) => true,
            // Infrastructure, and the per-group in-flight guard — all
            // of these clear on their own.
            EngineError::Redis(_)
            | EngineError::Round(_)
            | EngineError::Db(_)
            | EngineError::Ledger(_)
            | EngineError::Reset(_)
            | EngineError::Distribution(_)
            | EngineError::BlockFoundInProgress { .. } => false,
        }
    }
}

#[derive(Clone)]
pub struct GroupSoloEngine {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    round: GroupRoundStore,
    distribution_builder: DistributionBuilder,
    reset_runner: GroupResetRunner<SystemClock>,
    config: GroupSoloEngineConfig,
    cancel_tx: watch::Sender<bool>,
    /// Live per-group round-reset cron tasks, keyed by group id. Each has its
    /// own cancel channel so [`GroupSoloEngine::reschedule_group`] can tear
    /// down + re-arm a single group on a settings change without touching the
    /// others. `shutdown` signals all of them.
    reset_tasks: StdMutex<HashMap<Uuid, ResetTask>>,
    /// Per-group `on_block_found` re-entrancy guard. `tokio::sync::Mutex`
    /// because the hot path awaits PG + Redis inside the critical
    /// section.
    block_found_in_progress: TokioMutex<HashSet<Uuid>>,
    /// Hot-path cache of each group's payout mode + window length, so
    /// `record_share` doesn't hit Postgres per accepted share. The mode is
    /// immutable (set at creation); the window length is editable, so the
    /// entry carries a short TTL ([`MODE_CACHE_TTL`]) and is re-read on expiry.
    mode_cache: StdMutex<HashMap<Uuid, CachedGroupMode>>,
    /// Per-group highest time-bucket for which a windowed `record_share`
    /// already triggered a trim. The window only sheds whole buckets at hour
    /// boundaries, so trimming on every share would spend a Redis round-trip
    /// that is a no-op ~99% of the time. We trim only when a share opens a
    /// *new* bucket (≈ once/hour/group); the payout read path still trims with
    /// real wall-clock, so this only bounds Redis between reads, never affects
    /// correctness. (An out-of-order older share never lowers the watermark.)
    window_trim_watermark: StdMutex<HashMap<Uuid, i64>>,
}

/// Cached payout mode + window length for one group. `window_ms` is 0 for
/// [`PayoutMode::Prop`] (unused there).
#[derive(Clone, Copy)]
struct CachedGroupMode {
    mode: PayoutMode,
    window_ms: i64,
    expires_at: Instant,
}

/// TTL for [`Inner::mode_cache`]. Short enough that a window-length edit takes
/// effect within a minute (and the mode never changes), cheap enough that the
/// hot share path almost always hits the cache.
const MODE_CACHE_TTL: Duration = Duration::from_secs(60);

/// How often the block-found snapshot read is retried before the block is given
/// up on. That read is the only thing standing between a found block and its
/// booking, and the caller does not retry — a connection reset mid-reconnect
/// would otherwise cost the block.
const SNAPSHOT_READ_RETRIES: u32 = 3;
/// Backoff between those attempts, multiplied by the attempt number.
const SNAPSHOT_READ_BACKOFF: Duration = Duration::from_millis(80);

/// Decide whether a windowed share in `bucket_id` should trigger a trim, given
/// the highest bucket already trimmed (`watermark`, `None` if never). Trim on
/// the first share of a group (cold start catches up any aging) and whenever a
/// share opens a strictly-newer bucket; skip same-bucket and out-of-order older
/// shares. Pure so the boundary logic is unit-testable without Redis.
fn should_trim_on_bucket(watermark: Option<i64>, bucket_id: i64) -> bool {
    match watermark {
        Some(last) => bucket_id > last,
        None => true,
    }
}

/// `(PayoutMode, window_ms)` to use when the per-share mode lookup hits a DB
/// error. The mode is immutable, so a cached entry — even an expired one —
/// still carries the correct mode; reusing it keeps a `Window` group's shares
/// flowing into the window aggregate during a transient DB blip instead of
/// silently misrouting them to the PROP keys (where the window read never sees
/// them). `Prop` is only the cold fallback for a group never resolved. Pure so
/// the "never misroute on a transient error" rule is unit-testable.
fn mode_on_lookup_error(cached: Option<CachedGroupMode>) -> (PayoutMode, i64) {
    match cached {
        Some(c) => (c.mode, c.window_ms),
        None => (PayoutMode::Prop, 0),
    }
}

/// Derive `(PayoutMode, window_ms)` from a group row. `window_ms` reinterprets
/// the reset-cadence config as a sliding-window length (see
/// [`bp_group_mgmt::group::window_duration_ms`]); it is 0 for PROP groups.
pub(crate) fn group_mode_from_row(g: &PplnsGroupRow) -> (PayoutMode, i64) {
    let mode = PayoutMode::parse_or_default(&g.payout_mode);
    let window_ms = match mode {
        PayoutMode::Prop => 0,
        PayoutMode::Window => {
            let preset = g
                .round_reset_preset
                .as_deref()
                .and_then(RoundResetPreset::parse);
            let interval = g
                .round_reset_interval_days
                .and_then(|d| u32::try_from(d).ok());
            window_duration_ms(preset, interval)
        }
    };
    (mode, window_ms)
}

/// A running per-group round-reset cron + its dedicated cancel channel.
struct ResetTask {
    cancel: watch::Sender<bool>,
    #[allow(dead_code)] // retained so the task isn't detached/lost; cancel drives exit
    join: JoinHandle<()>,
}

/// Spawn a per-group reset cron with its own cancel channel.
fn spawn_reset_task(runner: GroupResetRunner<SystemClock>, schedule: ResetSchedule) -> ResetTask {
    let (cancel, cancel_rx) = watch::channel(false);
    let join = spawn_per_group_task(runner, schedule, cancel_rx);
    ResetTask { cancel, join }
}

impl GroupSoloEngine {
    /// Validate config, wire dependencies, and spawn a per-group
    /// calendar-reset cron for every active group with a configured
    /// preset.
    pub async fn spawn(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, true).await
    }

    /// Core-mode constructor: same wiring, but *without* the per-group
    /// round-reset cron. The Core only reads the round window and builds
    /// distributions (`build_distribution`, which still writes the
    /// snapshot key); the round-resetting cron runs on the Satellite.
    /// `record_share` is unaffected and unused on the Core (the share
    /// path produces to the stream instead).
    pub async fn spawn_core(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, false).await
    }

    async fn spawn_inner(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        background_tasks: bool,
    ) -> Result<Self, EngineError> {
        let config = config.try_new()?;
        let round = GroupRoundStore::new(redis);
        let dist_cfg = DistributionConfig::from_engine_config(&config);
        let distribution_builder = DistributionBuilder::new(pool.clone(), round.clone(), dist_cfg);
        let clock = Arc::new(SystemClock);
        let reset_runner = GroupResetRunner::new(pool.clone(), round.clone(), clock.clone());

        let (cancel_tx, _cancel_rx) = watch::channel(false);

        // Core mode (`background_tasks == false`) skips the cron: the
        // per-group round-reset mutates rounds, which is the Satellite's
        // job. `reset_tasks` stays empty so `reschedule_group` remains a
        // safe no-op-add.
        let mut reset_tasks: HashMap<Uuid, ResetTask> = HashMap::new();
        if background_tasks {
            // Spawn a per-group reset cron for every active group with a
            // configured preset, retaining each task (with its own cancel) so a
            // later `reschedule_group` can re-arm a single group at runtime.
            for schedule in load_active_schedules(&pool).await? {
                let group_id = schedule.group_id;
                reset_tasks.insert(group_id, spawn_reset_task(reset_runner.clone(), schedule));
            }
        }

        info!(
            min_payout_sats = config.min_payout_sats.0,
            fee_percent = config.fee_percent,
            background_tasks,
            "group-solo-engine spawned"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                pool,
                round,
                distribution_builder,
                reset_runner,
                config,
                cancel_tx,
                reset_tasks: StdMutex::new(reset_tasks),
                block_found_in_progress: TokioMutex::new(HashSet::new()),
                mode_cache: StdMutex::new(HashMap::new()),
                window_trim_watermark: StdMutex::new(HashMap::new()),
            }),
        })
    }

    /// (Re-)schedule a single group's round-reset cron from its current row —
    /// the runtime entry point bin/blitzpool's `apply_round_reset_config` hook
    /// calls on a `PATCH /settings` save: tear down any existing task, then arm
    /// a fresh one unless the group is dissolved/inactive or has no (valid)
    /// preset. Cheap + synchronous (the work is a watch-signal + a `tokio::spawn`).
    pub fn reschedule_group(&self, group: &PplnsGroupRow) {
        let mut tasks = self
            .inner
            .reset_tasks
            .lock()
            .expect("reset_tasks mutex poisoned");
        // Always tear down the old task first (handles preset/TZ/interval change).
        if let Some(old) = tasks.remove(&group.id) {
            let _ = old.cancel.send(true);
        }
        // Don't re-arm for dissolved / inactive groups.
        if group.dissolved_at.is_some() || !group.active {
            info!(group_id = %group.id, "round-reset cron unscheduled (group dissolved/inactive)");
            return;
        }
        // Window-mode groups never calendar-reset (the window self-trims); the
        // reset config is reinterpreted as the window length, so leave the cron
        // unscheduled regardless of preset.
        if PayoutMode::parse_or_default(&group.payout_mode) == PayoutMode::Window {
            info!(group_id = %group.id, "round-reset cron unscheduled (window payout mode)");
            return;
        }
        let interval = group
            .round_reset_interval_days
            .and_then(|i| u32::try_from(i).ok());
        match ResetSchedule::from_row_fields(
            group.id,
            group.round_reset_preset.as_deref(),
            group.round_reset_timezone.as_deref(),
            interval,
        ) {
            Ok(Some(schedule)) => {
                tasks.insert(
                    group.id,
                    spawn_reset_task(self.inner.reset_runner.clone(), schedule),
                );
                info!(
                    group_id = %group.id,
                    preset = ?group.round_reset_preset,
                    interval_days = ?group.round_reset_interval_days,
                    "round-reset cron (re)scheduled from settings change"
                );
            }
            // No preset (cleared) → stay unscheduled.
            Ok(None) => {
                info!(group_id = %group.id, "round-reset cron unscheduled (no preset)");
            }
            Err(e) => warn!(
                group_id = %group.id,
                error = %e,
                "reschedule_group: invalid reset schedule; left unscheduled"
            ),
        }
    }

    /// Resolve a group's `(PayoutMode, window_ms)`, caching the result for the
    /// hot share path. A cache miss reads the `pplns_group` row once. On a DB
    /// error we fall back to the last cached entry **even if expired** — the
    /// mode is immutable so its mode is still correct, and a stale `window_ms`
    /// only over-/under-trims on the record path (the read path always re-trims
    /// with a fresh `window_ms`, so payouts are unaffected). Routing a Window
    /// group's shares to the PROP keys during a DB blip would instead drop them
    /// from the window aggregate for good, so PROP is only the cold fallback for
    /// a group we have never resolved. Neither error fallback is cached.
    async fn resolve_group_mode(&self, group_id: Uuid) -> (PayoutMode, i64) {
        let cached = {
            let cache = self.inner.mode_cache.lock().expect("mode_cache poisoned");
            cache.get(&group_id).copied()
        };
        if let Some(c) = cached {
            if c.expires_at > Instant::now() {
                return (c.mode, c.window_ms);
            }
        }
        let (mode, window_ms) = match find_group(&self.inner.pool, group_id).await {
            Ok(Some(g)) => group_mode_from_row(&g),
            Ok(None) => (PayoutMode::Prop, 0),
            Err(e) => {
                // Prefer the last-known (immutable) mode over PROP so a transient
                // DB error can't misroute a Window group's shares into the PROP
                // aggregate, where they'd be invisible to the window payout.
                if cached.is_some() {
                    warn!(%group_id, error = %e,
                        "group payout-mode lookup failed — reusing last-known mode (not re-cached)");
                } else {
                    warn!(%group_id, error = %e,
                        "group payout-mode lookup failed and no cached mode — defaulting to PROP");
                }
                return mode_on_lookup_error(cached);
            }
        };
        self.inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .insert(
                group_id,
                CachedGroupMode {
                    mode,
                    window_ms,
                    expires_at: Instant::now() + MODE_CACHE_TTL,
                },
            );
        (mode, window_ms)
    }

    /// Drop the cached `(PayoutMode, window_ms)` for a group so the next share
    /// re-reads it from Postgres. Call this after a settings edit that changes
    /// the round-reset cadence: the cadence is reinterpreted as the window
    /// length, so a stale cache would keep the record-path trim using the OLD
    /// length for up to [`MODE_CACHE_TTL`]. On a window *grow* that stale-small
    /// length would over-trim and permanently drop a bucket the new (larger)
    /// window should keep, so we invalidate eagerly. (The mode itself is
    /// immutable; only the window length can move.)
    pub fn invalidate_mode_cache(&self, group_id: Uuid) {
        self.inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .remove(&group_id);
    }

    /// Record-path trim gate for a windowed share: returns `true` (and bumps
    /// the watermark) only when `timestamp_ms` falls in a strictly-newer
    /// hour-bucket than the last one we trimmed for this group — see
    /// [`should_trim_on_bucket`]. A short `StdMutex`-guarded map lookup, far
    /// cheaper than the Redis round-trip it gates.
    fn advance_trim_watermark(&self, group_id: Uuid, timestamp_ms: i64) -> bool {
        let bucket_id = timestamp_ms.div_euclid(WINDOW_BUCKET_MS);
        let mut marks = self
            .inner
            .window_trim_watermark
            .lock()
            .expect("window_trim_watermark poisoned");
        if should_trim_on_bucket(marks.get(&group_id).copied(), bucket_id) {
            marks.insert(group_id, bucket_id);
            true
        } else {
            false
        }
    }

    /// Hot path: an accepted Group-Solo share. Caller has resolved
    /// `group_id` (via the mode-gate adapter in `hooks.rs`).
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        group_id: Uuid,
        address: &str,
        difficulty: f64,
        timestamp_ms: i64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        // PROP appends to the single round aggregate; Window appends into the
        // share's time bucket and self-trims (using the share's own accept
        // time as "now" so an idle group still bounds its window).
        let (mode, window_ms) = self.resolve_group_mode(group_id).await;
        let applied = match mode {
            PayoutMode::Prop => {
                self.inner
                    .round
                    .record_share(share_id, &group_key, address, difficulty, timestamp_ms)
                    .await?
            }
            PayoutMode::Window => {
                let applied = self
                    .inner
                    .round
                    .record_share_windowed(share_id, &group_key, address, difficulty, timestamp_ms)
                    .await?;
                // Trim only when this share opens a new hour-bucket — the window
                // sheds whole buckets at hour boundaries, so per-share trimming
                // would be a no-op Redis round-trip ~99% of the time. The payout
                // read path trims with real wall-clock regardless, so this only
                // bounds Redis between reads.
                if applied && self.advance_trim_watermark(group_id, timestamp_ms) {
                    self.inner
                        .round
                        .trim_window(&group_key, timestamp_ms, window_ms)
                        .await?;
                }
                applied
            }
        };
        if !applied {
            // Deduped redelivery: the round already counts this share, so
            // the best-share check + cache-invalidate would be redundant.
            return Ok(());
        }
        // Best-share update is best-effort; the round wipes on
        // block-found, so a missed update is cosmetic.
        if let Err(e) = self
            .inner
            .round
            .update_best_share_if_better(&group_key, address, difficulty, timestamp_ms)
            .await
        {
            warn!(
                %group_id,
                address,
                error = %e,
                "best-share update failed (cosmetic; round wipes on block-found)"
            );
        }
        // Distribution depends on (round + balances); a new share
        // changes the round. Drop the whole cache (keyed by triple),
        // safer than invalidating only one (group, reward, finder)
        // tuple — the round has changed for all of them.
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// Per-rejected-share counter.
    pub async fn record_reject(
        &self,
        group_id: Uuid,
        address: &str,
        shares: f64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        self.inner
            .round
            .record_reject(&group_key, address, shares)
            .await?;
        Ok(())
    }

    /// Build the current distribution for `(group_id, reward, finder)`.
    pub async fn build_distribution(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<Arc<DistributionResult>, EngineError> {
        self.inner
            .distribution_builder
            .build(group_id, block_reward_sats, finder_address)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Look up the WEIGHT snapshot the found block's coinbase was built
    /// from, so the Core can stamp it into the block-found event.
    ///
    /// `weights_fingerprint` is the identity of the winning job's payout
    /// list, carried on the job the share was built on. The build that
    /// produced that list stored its snapshot under it, and nothing else
    /// writes that key.
    ///
    /// It must NOT rebuild the distribution here. `record_share`
    /// invalidates the in-flight cache, so a single share landing between
    /// job issue and block-found makes a rebuild run against a moved
    /// round — measured on a two-member group as 187.5 M/125 M at job
    /// time versus 31.25 M/281.25 M at block-found. The coinbase pays the
    /// first pair. Missing snapshot → typed error, so the block is booked
    /// by an operator rather than booked wrong.
    pub async fn weight_snapshot_for_block_found(
        &self,
        group_id: Uuid,
        finder_address: &AddressId,
        weights_fingerprint: &[u8; 32],
    ) -> Result<bp_coinbase_snapshot::StoredWeightSnapshot, EngineError> {
        let mut conn = self.inner.round.connection_for_snapshot();
        let group_key = group_id.to_string();
        // Retry a transient Redis failure rather than discarding the
        // block; the caller has no retry of its own. A genuinely missing
        // snapshot (`Ok(None)`) is NOT retried — it will not appear.
        let mut attempt = 0;
        loop {
            match crate::round::snapshot::read_weight_snapshot_for(
                &mut conn,
                &group_key,
                weights_fingerprint,
            )
            .await
            {
                Ok(Some(s)) => return Ok(s),
                Ok(None) => {
                    return Err(EngineError::SnapshotMissingForPayouts {
                        group_id,
                        finder_address: finder_address.as_str().to_string(),
                    })
                }
                Err(e) if attempt < SNAPSHOT_READ_RETRIES => {
                    warn!(
                        error = %e,
                        %group_id,
                        attempt,
                        "group-solo weight-snapshot read failed — retrying before giving up"
                    );
                    attempt += 1;
                    tokio::time::sleep(SNAPSHOT_READ_BACKOFF * attempt).await;
                }
                Err(e) => return Err(EngineError::Redis(e)),
            }
        }
    }

    /// Apply a Group-Solo found block: write its payout history from the
    /// block's OWN coinbase, then move the round on.
    ///
    /// There is no settlement step. Group-Solo publishes every member it
    /// can pay and lets the rest fall to the pool output
    /// ([`bp_pplns::WithheldValue::ToPool`]), so a published member is
    /// paid exactly their claim and a withheld one is owed nothing. What
    /// the coinbase paid is the whole truth, and these rows record it.
    ///
    /// `snapshot` is therefore only used for the sanity checks below —
    /// the amounts come from `actual`. Per-group re-entrancy guard;
    /// idempotent across restarts via the
    /// `(groupId, blockHeight, address)` UNIQUE constraint.
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
        finder_address: &AddressId,
        snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        weights_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        {
            let mut in_flight = self.inner.block_found_in_progress.lock().await;
            if in_flight.contains(&group_id) {
                return Err(EngineError::BlockFoundInProgress { group_id });
            }
            in_flight.insert(group_id);
        }
        let result = self
            .on_block_found_inner(
                group_id,
                block_height,
                actual,
                finder_address,
                snapshot,
                weights_fingerprint,
            )
            .await;
        self.inner
            .block_found_in_progress
            .lock()
            .await
            .remove(&group_id);
        result
    }

    async fn on_block_found_inner(
        &self,
        group_id: Uuid,
        block_height: i32,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
        finder_address: &AddressId,
        snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        weights_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        let group_key = group_id.to_string();

        // 1. Snapshot source: event-carried, else the fingerprint key,
        //    else the per-(group, finder) key (tests / manual path).
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                let mut conn = self.inner.round.connection_for_snapshot();
                let read = match weights_fingerprint.filter(|fp| fp != &[0u8; 32]) {
                    Some(fp) => {
                        crate::round::snapshot::read_weight_snapshot_for(&mut conn, &group_key, &fp)
                            .await?
                    }
                    None => {
                        crate::round::snapshot::read_weight_snapshot(
                            &mut conn,
                            &group_key,
                            finder_address.as_str(),
                        )
                        .await?
                    }
                };
                read.ok_or(EngineError::SnapshotMissing {
                    group_id,
                    finder_address: finder_address.as_str().to_string(),
                    block_height,
                })?
            }
        };

        // The one hard gate: a coinbase that pays less than its own
        // subsidy destroyed money it was entitled to. Nothing healthy
        // produces that — not mempool drift, not a stale projection
        // base, not a job-declaring client's own template.
        let subsidy =
            bp_share::block_subsidy_sats(block_height, self.inner.config.subsidy_halving_interval);
        if actual.total_value_sats < subsidy {
            error!(
                %group_id,
                subsidy,
                actual_reward = actual.total_value_sats,
                block_height,
                "group-solo block coinbase pays less than the block subsidy — refusing to book"
            );
            return Err(EngineError::RevenueBelowSubsidy {
                group_id,
                block_height,
                actual_reward: actual.total_value_sats,
                subsidy,
            });
        }
        // Drift off the projection base is an ALARM, not a gate. The
        // rows below are transcribed from the block's own coinbase, so
        // they are right at any revenue — the reference is only what the
        // distribution happened to be built against.
        if !bp_share::reward_within_band(snapshot.reference_revenue_sats, actual.total_value_sats) {
            warn!(
                %group_id,
                reference_reward = snapshot.reference_revenue_sats,
                actual_reward = actual.total_value_sats,
                block_height,
                "group-solo block revenue far off the distribution's reference — booking it from \
                 the real coinbase, but the job source is worth a look"
            );
        }

        // 2. Mode + reset gate (one row read), and the round state for
        //    the sharesInRound audit fields. Read BEFORE any reset wipes
        //    it; in Window mode this trims + reads the sliding window.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let (mode, window_ms, reset_on_block) = match find_group(&self.inner.pool, group_id).await {
            Ok(Some(g)) => {
                let (mode, window_ms) = group_mode_from_row(&g);
                (mode, window_ms, g.reset_round_on_block)
            }
            Ok(None) => (PayoutMode::Prop, 0, false),
            Err(e) => {
                warn!(%group_id, error = %e,
                    "group row read failed in on_block_found — defaulting to PROP / no reset");
                (PayoutMode::Prop, 0, false)
            }
        };
        let round_by_addr = self
            .inner
            .round
            .read_payout_shares(&group_key, mode, now_ms, window_ms)
            .await?;
        let total_shares_in_round: f64 = round_by_addr.values().sum();
        let total_shares_i64 = total_shares_in_round.round() as i64;

        let audit_rows = history_rows_from_coinbase(
            group_id,
            &snapshot,
            actual,
            &round_by_addr,
            total_shares_i64,
        );

        // 3. Write the history, 4. move the round on, 5. drop the
        //    snapshots this block consumed, 6. drop the build cache.
        let outcome = apply_distribution(
            &self.inner.pool,
            group_id,
            block_height,
            &audit_rows,
            now_ms,
        )
        .await?;

        if mode == PayoutMode::Window {
            info!(%group_id,
                "group-solo: window mode — no per-block round reset (window self-trims by age)");
        } else if reset_on_block {
            if let Err(e) = self.inner.round.reset_for_block_found(&group_key).await {
                warn!(%group_id, error = %e, "round.reset_for_block_found failed — non-fatal");
            }
        } else {
            info!(%group_id,
                "group-solo: per-block round reset disabled (resetRoundOnBlock=false) — \
                 round accumulates until calendar/manual reset");
        }

        let mut conn = self.inner.round.connection_for_snapshot();
        if let Err(e) = delete_all_for_group(&mut conn, &group_key).await {
            warn!(
                %group_id,
                error = %e,
                "delete_all_snapshots_for_group failed — non-fatal, TTL fallback"
            );
        }
        if let Some(fp) = weights_fingerprint {
            if let Err(e) = delete_snapshot_for(&mut conn, &group_key, &fp).await {
                warn!(
                    %group_id,
                    error = %e,
                    "delete_snapshot_for failed — non-fatal, TTL fallback"
                );
            }
        }
        self.inner.distribution_builder.invalidate_all();

        info!(
            %group_id,
            block_height,
            history_inserted = outcome.history_inserted,
            "group-solo on_block_found applied"
        );
        Ok(outcome)
    }
}

/// Transcribe one block's coinbase into payout-history rows.
///
/// The amounts come from `actual` — the block's own coinbase — and
/// nothing else. The snapshot contributes only the fee address (whose
/// output is the pool's, not a member's) and the member list used to
/// flag a payment the pool cannot account for. `round_by_addr` supplies
/// the PROP-round detail the UI shows next to each amount.
///
/// One row per paid address. A member the coinbase did not pay gets no
/// row: under [`bp_pplns::WithheldValue::ToPool`] they are owed nothing,
/// so there is nothing to record.
fn history_rows_from_coinbase(
    group_id: Uuid,
    snapshot: &bp_coinbase_snapshot::StoredWeightSnapshot,
    actual: &bp_coinbase_snapshot::ActualCoinbase,
    round_by_addr: &HashMap<String, f64>,
    total_shares_in_round: i64,
) -> Vec<AuditRow> {
    let t = actual.total_value_sats;
    let mut rows: Vec<AuditRow> = Vec::new();

    for (addr_str, paid) in &actual.paid_by_address {
        if *paid == 0 || *addr_str == snapshot.fee_address {
            // The pool output is the pool's fee plus whatever the
            // distribution withheld. It is not a member payout and does
            // not belong in a member's payout history.
            continue;
        }
        let Ok(address) = AddressId::new(addr_str.clone()) else {
            warn!(
                %group_id,
                address = %addr_str,
                paid,
                "group-solo history: coinbase paid an unparseable address — skipping the row"
            );
            continue;
        };
        if !snapshot.entries.iter().any(|e| &e.address == addr_str) {
            // Cannot happen for value outputs under positional
            // validation. Record it anyway — the chain paid it, so the
            // history has to show it — but say so loudly.
            warn!(
                %group_id,
                address = %addr_str,
                paid,
                "group-solo history: coinbase paid an address outside the distribution"
            );
        }
        rows.push(AuditRow {
            address,
            paid_sats: Sats(*paid as i64),
            percent: if t > 0 {
                (*paid as f64 / t as f64 * 100.0) as f32
            } else {
                0.0
            },
            shares_in_round: round_by_addr
                .get(addr_str)
                .map(|f| f.round() as i64)
                .unwrap_or(0),
            total_shares_in_round,
            row_type: GroupPayoutRowType::Coinbase,
        });
    }

    // `paid_by_address` iterates a map; the history table is keyed
    // `(groupId, blockHeight, address)` and a caller comparing two runs
    // should see the same order.
    rows.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
    rows
}

impl GroupSoloEngine {
    /// Manually trigger a scheduled reset for `group_id`. Returns
    /// `Ok(true)` if the reset fired, `Ok(false)` if it was
    /// debounce-skipped or custom-elapsed-gated.
    pub async fn manual_reset(&self, group_id: Uuid) -> Result<bool, EngineError> {
        self.inner
            .reset_runner
            .reset_scheduled(group_id)
            .await
            .map_err(EngineError::from)
    }

    /// Invalidate the distribution cache for one
    /// (group, reward, finder) triple.
    pub fn invalidate_distribution(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) {
        self.inner
            .distribution_builder
            .invalidate(group_id, block_reward_sats, finder_address);
    }

    /// Signal background tasks to exit. Best-effort. Flips the global cancel
    /// (dust-sweep + others) and signals each per-group reset cron's own
    /// cancel channel.
    pub fn shutdown(&self) {
        let _ = self.inner.cancel_tx.send(true);
        if let Ok(tasks) = self.inner.reset_tasks.lock() {
            for task in tasks.values() {
                let _ = task.cancel.send(true);
            }
        }
    }

    /// Number of live per-group round-reset cron tasks currently armed.
    /// Lets callers (and integration tests) observe `reschedule_group` /
    /// startup arming + teardown.
    pub fn reset_task_count(&self) -> usize {
        self.inner.reset_tasks.lock().map(|t| t.len()).unwrap_or(0)
    }

    // Accessors for hooks.rs / reader.rs.
    pub fn config(&self) -> &GroupSoloEngineConfig {
        &self.inner.config
    }

    pub fn pool(&self) -> &PgPool {
        &self.inner.pool
    }

    pub fn round(&self) -> &GroupRoundStore {
        &self.inner.round
    }
}

/// One `pplns_group` row's reset-config fields. Named to keep the
/// `query_as` row type from triggering `clippy::type_complexity`.
type ResetConfigRow = (Uuid, Option<String>, Option<String>, Option<i32>);

/// Read every active group with a configured reset preset and
/// turn its `pplns_group` row into a `ResetSchedule`. Skips rows
/// with invalid TZ / preset (logs + continues).
async fn load_active_schedules(pool: &PgPool) -> Result<Vec<ResetSchedule>, EngineError> {
    let rows: Vec<ResetConfigRow> = sqlx::query_as(
        // Window-mode groups reinterpret the reset config as a window length
        // and never calendar-reset — exclude them so no reset cron is armed.
        r#"SELECT id, "roundResetPreset", "roundResetTimezone", "roundResetIntervalDays"
           FROM pplns_group
           WHERE active = true
             AND "dissolvedAt" IS NULL
             AND "roundResetPreset" IS NOT NULL
             AND "payoutMode" <> 'window'"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| EngineError::Db(DbError::from(e)))?;

    let mut out = Vec::new();
    for (id, preset, tz, interval) in rows {
        let interval_u32 = interval.and_then(|i| u32::try_from(i).ok());
        match ResetSchedule::from_row_fields(id, preset.as_deref(), tz.as_deref(), interval_u32) {
            Ok(Some(sched)) => out.push(sched),
            Ok(None) => {} // silently-no-op: missing fields
            Err(e) => {
                warn!(group_id = %id, error = %e, "group reset schedule parse failed; skipping cron");
            }
        }
    }
    Ok(out)
}

// In a future iteration we can give `shutdown` proper join-handle
// tracking via a `Vec<JoinHandle<()>>` field on `Inner`. For now,
// background tasks self-terminate on cancel and the engine drops
// their handles immediately (`std::mem::drop` after `spawn_*`).
// Time-out on shutdown is the caller's concern.
const _SHUTDOWN_HOOK_DOC: Duration = Duration::from_secs(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_carries_source_variants() {
        fn _from_db(e: DbError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_round(e: RoundError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_ledger(e: LedgerError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_reset(e: ResetError) -> EngineError {
            EngineError::from(e)
        }
    }

    #[test]
    fn trim_watermark_gates_to_new_buckets_only() {
        // Cold start (no watermark) always trims — catches up aging on restart.
        assert!(should_trim_on_bucket(None, 100));
        // Same bucket → skip (the common per-share case within an hour).
        assert!(!should_trim_on_bucket(Some(100), 100));
        // Strictly-newer bucket → trim once for the boundary crossing.
        assert!(should_trim_on_bucket(Some(100), 101));
        // Out-of-order older share never lowers the watermark / re-trims.
        assert!(!should_trim_on_bucket(Some(100), 7));
    }

    #[test]
    fn lookup_error_reuses_cached_mode_never_misroutes_window() {
        // No cached entry → cold fallback is PROP (legacy default).
        assert_eq!(mode_on_lookup_error(None), (PayoutMode::Prop, 0));
        // A cached Window entry (even expired) is reused on a DB error, so the
        // group's shares keep flowing into the window — NOT the PROP keys.
        let win = CachedGroupMode {
            mode: PayoutMode::Window,
            window_ms: 7 * 24 * 60 * 60 * 1000,
            expires_at: Instant::now(),
        };
        assert_eq!(
            mode_on_lookup_error(Some(win)),
            (PayoutMode::Window, 7 * 24 * 60 * 60 * 1000)
        );
        // A cached PROP entry resolves to PROP, as expected.
        let prop = CachedGroupMode {
            mode: PayoutMode::Prop,
            window_ms: 0,
            expires_at: Instant::now(),
        };
        assert_eq!(mode_on_lookup_error(Some(prop)), (PayoutMode::Prop, 0));
    }

    #[test]
    fn block_found_in_progress_carries_group_id() {
        let g = Uuid::new_v4();
        let e = EngineError::BlockFoundInProgress { group_id: g };
        let s = format!("{e}");
        assert!(s.contains(&g.to_string()));
    }

    #[test]
    fn snapshot_missing_carries_finder() {
        let g = Uuid::new_v4();
        let e = EngineError::SnapshotMissing {
            group_id: g,
            finder_address: "bc1qfinder".to_string(),
            block_height: 9999,
        };
        let s = format!("{e}");
        assert!(s.contains("bc1qfinder"));
        assert!(s.contains("9999"));
    }

    #[test]
    fn snapshot_reward_mismatch_carries_both_rewards() {
        let g = Uuid::new_v4();
        let e = EngineError::SnapshotRewardMismatch {
            group_id: g,
            snapshot_reward: 312_500_000,
            actual_reward: 300_000_000,
        };
        let s = format!("{e}");
        assert!(s.contains("312500000"), "snapshot reward in message");
        assert!(s.contains("300000000"), "actual reward in message");
        assert!(s.contains(&g.to_string()), "group id in message");
    }
}
