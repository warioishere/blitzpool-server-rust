// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngine`: wires the round store, distribution builder and
//! per-group reset crons. `on_block_found` books the payout history from the
//! block's OWN coinbase, never from what the pool intended to pay.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bp_common::{AddressId, Sats};
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
    BuiltDistribution, DistributionBuilder, DistributionConfig, DistributionError,
};
use crate::history::{
    apply_distribution, ApplyDistributionResult, AuditRow, GroupPayoutRowType, LedgerError,
};
use crate::reset::{spawn_per_group_task, GroupResetRunner, ResetError, ResetSchedule};

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
}

impl EngineError {
    /// Errors that fail the same way on every retry, so the confirmation
    /// watcher surfaces them once instead of re-applying forever. The block
    /// is not lost: the operator reprocess books it from its own coinbase.
    pub fn is_terminal(&self) -> bool {
        match self {
            EngineError::Config(_) | EngineError::RevenueBelowSubsidy { .. } => true,
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
    /// Per-group reset crons, each with its own cancel channel so
    /// [`GroupSoloEngine::reschedule_group`] can re-arm one group alone.
    reset_tasks: StdMutex<HashMap<Uuid, ResetTask>>,
    /// Per-group `on_block_found` re-entrancy guard; async mutex because the
    /// critical section awaits PG + Redis.
    block_found_in_progress: TokioMutex<HashSet<Uuid>>,
    /// Keeps Postgres off the per-share path. The mode is immutable but the
    /// window length is editable, hence the short [`MODE_CACHE_TTL`].
    mode_cache: StdMutex<HashMap<Uuid, CachedGroupMode>>,
    /// Highest bucket already trimmed by the record path; buckets only age out
    /// whole, so trimming once per new bucket suffices. The payout read
    /// re-trims anyway, so this only bounds Redis and never affects correctness.
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

/// TTL for [`Inner::mode_cache`]: a window-length edit takes effect within a
/// minute while the share path almost always hits the cache.
const MODE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Trim on a group's first share (cold start catches up any aging) and when a
/// share opens a strictly newer bucket; skip same-bucket and older shares.
fn should_trim_on_bucket(watermark: Option<i64>, bucket_id: i64) -> bool {
    match watermark {
        Some(last) => bucket_id > last,
        None => true,
    }
}

/// Mode to use when the lookup hits a DB error. The mode is immutable, so even
/// an expired cache entry is right, and reusing it keeps a `Window` group's
/// shares out of the PROP keys the window read never sees.
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

    /// Core-mode constructor without the reset crons: the Core only builds
    /// distributions, and mutating rounds is the Satellite's job.
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

        let mut reset_tasks: HashMap<Uuid, ResetTask> = HashMap::new();
        if background_tasks {
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
                reset_tasks: StdMutex::new(reset_tasks),
                block_found_in_progress: TokioMutex::new(HashSet::new()),
                mode_cache: StdMutex::new(HashMap::new()),
                window_trim_watermark: StdMutex::new(HashMap::new()),
            }),
        })
    }

    /// Re-arm one group's reset cron from its current row after a settings
    /// save; the old task is always torn down first.
    pub fn reschedule_group(&self, group: &PplnsGroupRow) {
        let mut tasks = self
            .inner
            .reset_tasks
            .lock()
            .expect("reset_tasks mutex poisoned");
        if let Some(old) = tasks.remove(&group.id) {
            let _ = old.cancel.send(true);
        }
        if group.dissolved_at.is_some() || !group.active {
            info!(group_id = %group.id, "round-reset cron unscheduled (group dissolved/inactive)");
            return;
        }
        // A Window group's reset config is its window length, never a cron.
        match PayoutMode::parse_or_default(&group.payout_mode) {
            PayoutMode::Window => {
                info!(group_id = %group.id, "round-reset cron unscheduled (window payout mode)");
                return;
            }
            PayoutMode::Prop => {}
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

    /// Resolve a group's `(PayoutMode, window_ms)` through the cache. On a DB
    /// error the last entry is reused even if expired (see
    /// `mode_on_lookup_error`); neither fallback is cached.
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

    /// Call after a reset-cadence edit: on a window grow, a stale shorter
    /// length would make the record-path trim drop a bucket the larger window
    /// must keep.
    pub fn invalidate_mode_cache(&self, group_id: Uuid) {
        self.inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .remove(&group_id);
    }

    /// Bumps the watermark and returns `true` per [`should_trim_on_bucket`].
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

    /// Trim once per new bucket; only bounds Redis between payout reads.
    async fn trim_window_at_bucket_boundary(
        &self,
        group_id: Uuid,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<(), EngineError> {
        if self.advance_trim_watermark(group_id, now_ms) {
            self.inner
                .round
                .trim_window(&group_id.to_string(), now_ms, window_ms)
                .await?;
        }
        Ok(())
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
                // Trim against the share's own accept time so an idle group
                // still bounds its window.
                if applied {
                    self.trim_window_at_bucket_boundary(group_id, timestamp_ms, window_ms)
                        .await?;
                }
                applied
            }
        };
        if !applied {
            // Deduped redelivery: the round already counts this share.
            return Ok(());
        }
        // Best-effort: a missed best-share update is cosmetic.
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
        // A new share changes the round for every cached (group, reward,
        // finder) triple, so drop the whole distribution cache.
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// Count a rejected share. Window mode buckets it on wall-clock time: a
    /// reject carries no accept time, and the lane feeds only the stats view,
    /// so landing in a neighbouring bucket changes no payout.
    pub async fn record_reject(
        &self,
        group_id: Uuid,
        address: &str,
        shares: f64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        let (mode, window_ms) = self.resolve_group_mode(group_id).await;
        match mode {
            PayoutMode::Prop => {
                self.inner
                    .round
                    .record_reject(&group_key, address, shares)
                    .await?;
            }
            PayoutMode::Window => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                self.inner
                    .round
                    .record_reject_windowed(&group_key, address, shares, now_ms)
                    .await?;
                self.trim_window_at_bucket_boundary(group_id, now_ms, window_ms)
                    .await?;
            }
        }
        Ok(())
    }

    /// Kick flow: drop the address from the group's payout source
    /// (mode-aware, see [`GroupRoundStore::forget_member`]) and forget any
    /// distribution built on it. Returns the diff-1-weighted amount removed.
    pub async fn forget_member(&self, group_id: Uuid, address: &str) -> Result<f64, EngineError> {
        let (mode, _window_ms) = self.resolve_group_mode(group_id).await;
        let removed = self
            .inner
            .round
            .forget_member(&group_id.to_string(), address, mode)
            .await?;
        self.inner.distribution_builder.invalidate_all();
        Ok(removed)
    }

    /// Build the current distribution for `(group_id, reward, finder)`.
    pub async fn build_distribution(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<Arc<BuiltDistribution>, EngineError> {
        self.inner
            .distribution_builder
            .build(group_id, block_reward_sats, finder_address)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Book a found block from its OWN coinbase, then move the round on. No
    /// settlement: withheld value goes to the pool ([`bp_pplns::WithheldValue::ToPool`]),
    /// so what the coinbase paid is the whole truth. Idempotent via the
    /// `(groupId, blockHeight, address)` UNIQUE key.
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
    ) -> Result<ApplyDistributionResult, EngineError> {
        {
            let mut in_flight = self.inner.block_found_in_progress.lock().await;
            if in_flight.contains(&group_id) {
                return Err(EngineError::BlockFoundInProgress { group_id });
            }
            in_flight.insert(group_id);
        }
        let result = self
            .on_block_found_inner(group_id, block_height, actual)
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
    ) -> Result<ApplyDistributionResult, EngineError> {
        let group_key = group_id.to_string();

        if let Err(subsidy) =
            actual.check_subsidy(block_height, self.inner.config.subsidy_halving_interval)
        {
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
        // 2. Mode + reset gate, and the round state for the audit fields,
        //    read BEFORE any reset wipes it.
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

        let audit_rows =
            history_rows_from_coinbase(group_id, actual, &round_by_addr, total_shares_i64);

        // 3. Write the history, 4. move the round on, 5. drop the build cache.
        let outcome = apply_distribution(
            &self.inner.pool,
            group_id,
            block_height,
            &audit_rows,
            now_ms,
        )
        .await?;

        match mode {
            PayoutMode::Window => {
                info!(%group_id,
                    "group-solo: window mode — no per-block round reset (window self-trims by age)");
            }
            PayoutMode::Prop if reset_on_block => {
                if let Err(e) = self.inner.round.reset_for_block_found(&group_key).await {
                    warn!(%group_id, error = %e, "round.reset_for_block_found failed — non-fatal");
                }
            }
            PayoutMode::Prop => {
                info!(%group_id,
                    "group-solo: per-block round reset disabled (resetRoundOnBlock=false) — \
                     round accumulates until calendar/manual reset");
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

/// One history row per address the coinbase paid besides the pool output,
/// amounts only from `actual`. An unpaid member gets no row: under
/// [`bp_pplns::WithheldValue::ToPool`] they are owed nothing.
fn history_rows_from_coinbase(
    group_id: Uuid,
    actual: &bp_coinbase_snapshot::ActualCoinbase,
    round_by_addr: &HashMap<String, f64>,
    total_shares_in_round: i64,
) -> Vec<AuditRow> {
    let mut rows: Vec<AuditRow> = Vec::new();

    for (addr_str, paid) in &actual.paid_by_address {
        if *paid == 0 {
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
        rows.push(AuditRow {
            address,
            paid_sats: Sats(*paid as i64),
            percent: actual.percent_of_total(*paid),
            shares_in_round: round_by_addr
                .get(addr_str)
                .map(|f| f.round() as i64)
                .unwrap_or(0),
            total_shares_in_round,
            row_type: GroupPayoutRowType::Coinbase,
        });
    }

    // `paid_by_address` is a map; sort so two runs yield the same order.
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

    /// Signal each per-group reset cron to exit. Best-effort.
    pub fn shutdown(&self) {
        if let Ok(tasks) = self.inner.reset_tasks.lock() {
            for task in tasks.values() {
                let _ = task.cancel.send(true);
            }
        }
    }

    /// Number of armed per-group reset crons.
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

/// One `pplns_group` row's reset-config fields.
type ResetConfigRow = (Uuid, Option<String>, Option<String>, Option<i32>);

/// Reset schedules of every active PROP group with a preset; invalid rows
/// are logged and skipped.
async fn load_active_schedules(pool: &PgPool) -> Result<Vec<ResetSchedule>, EngineError> {
    let rows: Vec<ResetConfigRow> = sqlx::query_as(
        // A Window group's reset config is its window length, never a cron.
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

// Background tasks exit on cancel; `shutdown` does not join them, so a
// shutdown time-out is the caller's concern.
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
        assert!(should_trim_on_bucket(None, 100));
        assert!(!should_trim_on_bucket(Some(100), 100));
        assert!(should_trim_on_bucket(Some(100), 101));
        assert!(!should_trim_on_bucket(Some(100), 7));
    }

    #[test]
    fn lookup_error_reuses_cached_mode_never_misroutes_window() {
        assert_eq!(mode_on_lookup_error(None), (PayoutMode::Prop, 0));
        // An expired Window entry is still reused, never the PROP keys.
        let win = CachedGroupMode {
            mode: PayoutMode::Window,
            window_ms: 7 * 24 * 60 * 60 * 1000,
            expires_at: Instant::now(),
        };
        assert_eq!(
            mode_on_lookup_error(Some(win)),
            (PayoutMode::Window, 7 * 24 * 60 * 60 * 1000)
        );
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

    /// Every paid output besides the pool's becomes a row, the fee address
    /// mining as a member included; a 0-sat entry does not.
    #[test]
    fn history_rows_transcribe_every_paid_output_besides_the_pool() {
        const MEMBER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        const FEE_AS_MEMBER: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        const UNPAID: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let actual = bp_coinbase_snapshot::ActualCoinbase {
            paid_by_address: HashMap::from([
                (MEMBER.to_string(), 200_000_000),
                (FEE_AS_MEMBER.to_string(), 100_000_000),
                (UNPAID.to_string(), 0),
            ]),
            total_value_sats: 312_500_000,
        };
        let rows = history_rows_from_coinbase(Uuid::nil(), &actual, &HashMap::new(), 0);
        let paid: Vec<(&str, i64)> = rows
            .iter()
            .map(|r| (r.address.as_str(), r.paid_sats.0))
            .collect();
        assert_eq!(
            paid,
            vec![(FEE_AS_MEMBER, 100_000_000), (MEMBER, 200_000_000)],
            "the pool output is not in `paid_by_address`; everything else paid is a row"
        );
    }
}
