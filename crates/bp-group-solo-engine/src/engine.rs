// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngine` — top-level wiring of the Group-Solo
//! service-engine.
//!
//! Owns the Postgres pool, Redis-backed `GroupRoundStore`,
//! `DistributionBuilder` (with its in-flight cache),
//! `GroupDustSweepRunner` (daily 03:00 UTC dust-sweep cron), and
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
//! - `on_block_found` — called when a Group-Solo finder wins a
//!   block. Reads the snapshot persisted at template-build time,
//!   applies the ledger TX, resets the round (Variant A —
//!   preserves `lastAcceptedShareAt`), drops all per-finder
//!   snapshots, invalidates the distribution cache.
//! - `manual_sweep` / `manual_reset` — admin-triggerable wrappers.
//! - `shutdown` — flips the cancel watch so background tasks exit.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bp_common::{AddressId, InvalidAddressError, Sats};
use bp_cron_utils::SystemClock;
use bp_db::{
    find_all_pplns_group_balances_for_group, find_group, DbError, PplnsGroupBalanceRow,
    PplnsGroupRow,
};
use bp_pplns::CoinbaseDistributionEntry;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::{watch, Mutex as TokioMutex};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{ConfigError, GroupSoloEngineConfig};
use crate::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError, DistributionResult,
};
use crate::ledger::{
    apply_distribution, coinbase_row, pending_row, ApplyDistributionResult, AuditRow, BalanceWrite,
    LedgerError,
};
use crate::reset::{spawn_per_group_task, GroupResetRunner, ResetError, ResetSchedule};
use crate::round::snapshot::{delete_all_for_group, ParsedSnapshot, StoredSnapshot};
use crate::round::{GroupRoundStore, RoundError};
use crate::sweep::{spawn_daily_task, GroupDustSweepRunner, SweepError, SweepStats};

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
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("sweep: {0}")]
    Sweep(#[from] SweepError),
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
        "snapshot reward mismatch for group {group_id}: snapshot={snapshot_reward} block={actual_reward}"
    )]
    SnapshotRewardMismatch {
        group_id: Uuid,
        snapshot_reward: u64,
        actual_reward: u64,
    },
    #[error("on_block_found already in flight for group {group_id}")]
    BlockFoundInProgress { group_id: Uuid },
    #[error("invalid address in snapshot: {0}")]
    Address(#[from] InvalidAddressError),
}

#[derive(Clone)]
pub struct GroupSoloEngine {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    round: GroupRoundStore,
    distribution_builder: DistributionBuilder,
    sweep_runner: GroupDustSweepRunner<SystemClock>,
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
    /// Validate config, wire dependencies, spawn the dust-sweep
    /// background task, and spawn a per-group calendar-reset cron
    /// for every active group with a configured preset.
    pub async fn spawn(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, true).await
    }

    /// Core-mode constructor: same wiring, but *without* the background
    /// crons (dust-sweep + per-group round-reset). The Core only reads
    /// the round window and builds distributions (`build_distribution`,
    /// which still writes the snapshot key); all ledger-mutating and
    /// round-resetting crons run on the Satellite. `record_share` is
    /// unaffected and unused on the Core (the share path produces to the
    /// stream instead).
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
        let sweep_runner = GroupDustSweepRunner::new(
            pool.clone(),
            clock.clone(),
            config.min_payout_sats,
            config.dormant_balance_days,
        );
        let reset_runner = GroupResetRunner::new(pool.clone(), round.clone(), clock.clone());

        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Core mode (`background_tasks == false`) skips both crons: the
        // dust-sweep writes the ledger and the per-group round-reset
        // mutates rounds — both are the Satellite's job. `reset_tasks`
        // stays empty so `reschedule_group` remains a safe no-op-add.
        let mut reset_tasks: HashMap<Uuid, ResetTask> = HashMap::new();
        if background_tasks {
            std::mem::drop(spawn_daily_task(
                sweep_runner.clone(),
                config.dust_sweep_enabled,
                cancel_rx.clone(),
            ));

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
            dust_sweep_enabled = config.dust_sweep_enabled,
            dormant_balance_days = config.dormant_balance_days,
            background_tasks,
            "group-solo-engine spawned"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                pool,
                round,
                distribution_builder,
                sweep_runner,
                reset_runner,
                config,
                cancel_tx,
                reset_tasks: StdMutex::new(reset_tasks),
                block_found_in_progress: TokioMutex::new(HashSet::new()),
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
        let applied = self
            .inner
            .round
            .record_share(share_id, &group_key, address, difficulty, timestamp_ms)
            .await?;
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

    /// Freeze the exact distribution for `(group_id, reward, finder)` into a
    /// [`StoredSnapshot`] so the Core can stamp it into the block-found event.
    ///
    /// In the Core/Satellite split the per-(group, finder) Redis snapshot is
    /// overwritten by continuous template rebuilds before the async apply runs
    /// on the Satellite. Carrying the snapshot in the event makes Group-Solo
    /// self-contained (like PPLNS/Blockparty): the Core builds it at the
    /// block-found instant — freshest round, exact reward — and the apply
    /// consumes it via [`Self::on_block_found_with_snapshot`] instead of a
    /// second, raceable Redis read. Hits the in-flight cache, so a warm entry
    /// returns the exact template-time distribution without a recompute.
    pub async fn snapshot_for_block_found(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<StoredSnapshot, EngineError> {
        let dist = self
            .build_distribution(group_id, block_reward_sats, finder_address)
            .await?;
        Ok(StoredSnapshot::from_math(
            &dist.payouts,
            dist.block_reward_sats,
            &dist.considered_addresses,
            &dist.balance_after,
        ))
    }

    /// Apply a Group-Solo found block, reading the distribution snapshot from
    /// Redis (per-(group, finder) key). This is the fallback path: prefer
    /// [`Self::on_block_found_with_snapshot`] with the event-carried snapshot
    /// the front froze at block-found — the Redis key races with
    /// template-rebuild overwrites by the time the async apply runs. Per-group
    /// re-entrancy guard; idempotent across restarts via the
    /// `(groupId, blockHeight, address)` UNIQUE constraint.
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<ApplyDistributionResult, EngineError> {
        self.guarded_block_found(
            group_id,
            block_height,
            block_reward_sats,
            finder_address,
            None,
        )
        .await
    }

    /// Apply a Group-Solo found block from a snapshot carried in the
    /// block-found event (the Core froze it at the block-found instant — exact
    /// reward, freshest round). Race-free: no Redis snapshot read, so the
    /// continuous template-rebuild overwrites can't strip it out from under
    /// the async Satellite apply. Same re-entrancy guard + idempotency as
    /// [`Self::on_block_found`].
    pub async fn on_block_found_with_snapshot(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_reward_sats: u64,
        finder_address: &AddressId,
        snapshot: ParsedSnapshot,
    ) -> Result<ApplyDistributionResult, EngineError> {
        self.guarded_block_found(
            group_id,
            block_height,
            block_reward_sats,
            finder_address,
            Some(snapshot),
        )
        .await
    }

    /// Shared re-entrancy guard around the apply. `snapshot == None` reads it
    /// from Redis (fallback); `Some` uses the event-carried one.
    async fn guarded_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_reward_sats: u64,
        finder_address: &AddressId,
        snapshot: Option<ParsedSnapshot>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        // Per-group re-entrancy gate. `tokio::Mutex` because the
        // critical section is async.
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
                block_reward_sats,
                finder_address,
                snapshot,
            )
            .await;
        // Release the guard regardless of outcome.
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
        block_reward_sats: u64,
        finder_address: &AddressId,
        snapshot: Option<ParsedSnapshot>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        let group_key = group_id.to_string();

        // 1. Snapshot source: the event-carried one (frozen by the front at
        //    block-found, race-free) when present, else read the per-(group,
        //    finder) Redis key (fallback). A missing Redis snapshot is the
        //    operator's job — surface a typed error.
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                let mut conn = self.inner.round.connection_for_snapshot();
                crate::round::snapshot::read_snapshot(
                    &mut conn,
                    &group_key,
                    finder_address.as_str(),
                )
                .await?
                .ok_or(EngineError::SnapshotMissing {
                    group_id,
                    finder_address: finder_address.as_str().to_string(),
                    block_height,
                })?
            }
        };

        if snapshot.block_reward_sats != block_reward_sats {
            warn!(
                %group_id,
                snapshot_reward = snapshot.block_reward_sats,
                actual_reward = block_reward_sats,
                block_height,
                "group-solo snapshot reward mismatch — deleting stale snapshot, caller must retry"
            );
            let mut conn = self.inner.round.connection_for_snapshot();
            if let Err(e) = delete_all_for_group(&mut conn, &group_key).await {
                warn!(%group_id, error = %e, "delete_all_for_group failed during mismatch cleanup");
            }
            return Err(EngineError::SnapshotRewardMismatch {
                group_id,
                snapshot_reward: snapshot.block_reward_sats,
                actual_reward: block_reward_sats,
            });
        }

        // 2. Read current round state for sharesInRound / totalSharesInRound
        //    fields on audit rows (Group-Solo-specific). Done BEFORE
        //    the round reset wipes it.
        let round_by_addr = self.inner.round.read_by_address(&group_key).await?;
        let total_shares_in_round: f64 = round_by_addr.values().sum();
        let total_shares_i64 = total_shares_in_round.round() as i64;

        let now_ms = chrono::Utc::now().timestamp_millis();
        let (audit_rows, balance_writes) = self
            .build_writes_from_snapshot(group_id, &snapshot, &round_by_addr, total_shares_i64)
            .await?;

        // 3. Apply the ledger TX.
        let outcome = apply_distribution(
            &self.inner.pool,
            group_id,
            block_height,
            &audit_rows,
            &balance_writes,
            now_ms,
        )
        .await?;

        // 4. Reset the round ONLY when the group opted into per-block reset
        //    (`resetRoundOnBlock`). Default false: shares accumulate across
        //    blocks until a calendar preset or manual reset fires. Variant A
        //    preserves `last-accepted-share-at` for inactivity tracking. A
        //    failed flag read defaults to NO reset (the safe default — never
        //    silently wipe accumulated shares).
        let reset_on_block = match find_group(&self.inner.pool, group_id).await {
            Ok(Some(g)) => g.reset_round_on_block,
            Ok(None) => false,
            Err(e) => {
                warn!(%group_id, error = %e,
                    "group row read failed before reset gate — defaulting to no per-block reset");
                false
            }
        };
        if reset_on_block {
            if let Err(e) = self.inner.round.reset_for_block_found(&group_key).await {
                warn!(%group_id, error = %e, "round.reset_for_block_found failed — non-fatal");
            }
        } else {
            info!(%group_id,
                "group-solo: per-block round reset disabled (resetRoundOnBlock=false) — \
                 round accumulates until calendar/manual reset");
        }

        // 5. Drop all per-finder snapshots for this group.
        let mut conn = self.inner.round.connection_for_snapshot();
        if let Err(e) = delete_all_for_group(&mut conn, &group_key).await {
            warn!(
                %group_id,
                error = %e,
                "delete_all_snapshots_for_group failed — non-fatal, TTL fallback"
            );
        }

        // 6. Drop the distribution cache.
        self.inner.distribution_builder.invalidate_all();

        info!(
            %group_id,
            block_height,
            history_inserted = outcome.history_inserted,
            balances_affected = outcome.balances_affected,
            "group-solo on_block_found applied"
        );
        Ok(outcome)
    }

    async fn build_writes_from_snapshot(
        &self,
        group_id: Uuid,
        snapshot: &ParsedSnapshot,
        round_by_addr: &HashMap<String, f64>,
        total_shares_in_round: i64,
    ) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        // Pre-load existing balance rows for considered addresses so
        // we can compute new `totalPaidSats = existing + on_chain`
        // without N+1 reads. Read ALL rows (incl. `pendingSats = 0`): a
        // member fully paid on-chain has pending 0, and the pending-filtered
        // read would hide them, so their lifetime `totalPaidSats` would be
        // overwritten with the current block instead of accumulated.
        let existing_rows: Vec<PplnsGroupBalanceRow> =
            find_all_pplns_group_balances_for_group(&self.inner.pool, group_id).await?;
        let existing: HashMap<String, PplnsGroupBalanceRow> = existing_rows
            .into_iter()
            .map(|r| (r.address.as_str().to_string(), r))
            .collect();

        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let mut balance_writes: Vec<BalanceWrite> = Vec::new();
        let mut coinbase_addresses: HashSet<String> = HashSet::new();

        // The distribution can name the same address more than once:
        // Group-Solo emits the finder both as a dedicated bonus output
        // AND as their proportional share output. Both are valid on-chain
        // TxOuts, but the ledger keys on (address, groupId) — Postgres
        // rejects a second ON CONFLICT hit for the same key in one upsert,
        // and the history table's (groupId, blockHeight, address) UNIQUE
        // would silently drop the duplicate. Merge per-address (summing
        // sats + percent) so each address yields exactly one audit +
        // balance write. Order is kept stable for deterministic output.
        let mut order: Vec<String> = Vec::new();
        let mut merged: HashMap<String, CoinbaseDistributionEntry> = HashMap::new();
        for entry in &snapshot.distribution {
            let addr_str = entry.address.as_str().to_string();
            match merged.get_mut(&addr_str) {
                Some(acc) => {
                    acc.sats = Sats(acc.sats.0 + entry.sats.0);
                    acc.percent += entry.percent;
                }
                None => {
                    order.push(addr_str.clone());
                    merged.insert(addr_str, entry.clone());
                }
            }
        }

        for addr_str in &order {
            let entry = &merged[addr_str];
            let shares_in_round = round_by_addr
                .get(addr_str)
                .map(|f| f.round() as i64)
                .unwrap_or(0);
            audit_rows.push(coinbase_row(entry, shares_in_round, total_shares_in_round));
            coinbase_addresses.insert(addr_str.clone());

            let new_balance = snapshot
                .balance_after
                .get(addr_str)
                .copied()
                .or_else(|| existing.get(addr_str).map(|r| r.pending_sats.0))
                .unwrap_or(0);
            let prev_total_paid = existing
                .get(addr_str)
                .map(|r| r.total_paid_sats.0)
                .unwrap_or(0);
            balance_writes.push(BalanceWrite {
                address: entry.address.clone(),
                pending_sats: Sats(new_balance),
                total_paid_sats: Sats(prev_total_paid + entry.sats.0),
            });
        }

        // Pending rows: balance_after entries that didn't get a
        // coinbase output (sub-dust accumulators).
        for (addr_str, new_balance) in &snapshot.balance_after {
            if coinbase_addresses.contains(addr_str) {
                continue;
            }
            let addr_id = AddressId::new(addr_str.clone())?;
            let prev_balance = existing
                .get(addr_str)
                .map(|r| r.pending_sats.0)
                .unwrap_or(0);
            let delta = new_balance - prev_balance;
            audit_rows.push(pending_row(addr_id.clone(), Sats(delta)));

            let prev_total_paid = existing
                .get(addr_str)
                .map(|r| r.total_paid_sats.0)
                .unwrap_or(0);
            balance_writes.push(BalanceWrite {
                address: addr_id,
                pending_sats: Sats(*new_balance),
                total_paid_sats: Sats(prev_total_paid),
            });
        }

        Ok((audit_rows, balance_writes))
    }

    /// Run one manual dust-sweep tick.
    pub async fn manual_sweep(&self) -> Result<SweepStats, EngineError> {
        self.inner
            .sweep_runner
            .sweep()
            .await
            .map_err(EngineError::from)
    }

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
        r#"SELECT id, "roundResetPreset", "roundResetTimezone", "roundResetIntervalDays"
           FROM pplns_group
           WHERE active = true
             AND "dissolvedAt" IS NULL
             AND "roundResetPreset" IS NOT NULL"#,
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
        fn _from_sweep(e: SweepError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_reset(e: ResetError) -> EngineError {
            EngineError::from(e)
        }
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
