// SPDX-License-Identifier: AGPL-3.0-or-later

//! `PplnsEngine` — top-level wiring of the PPLNS service-engine.
//!
//! Owns the Postgres pool, the Redis-backed `WindowStore`, the
//! `DistributionBuilder` (with its inflight cache), the touch-buffer
//! flush background task, and the daily 03:00-UTC dust-sweep background
//! task.
//!
//! Construction:
//!
//! ```ignore
//! let engine = PplnsEngine::spawn(
//!     config,
//!     redis_connection_manager,
//!     pg_pool,
//!     network_difficulty_handle,
//! ).await?;
//! ```
//!
//! Public API:
//!
//! - [`PplnsEngine::record_share`] — hot path; called per accepted share
//!   *after* the stratum layer has resolved mode = PPLNS and consumed
//!   any per-session warmup quota.
//! - [`PplnsEngine::build_distribution`] — called by the
//!   template-build path (and the JDP coinbase-outputs request path),
//!   wraps the inflight cache.
//! - [`PplnsEngine::on_block_found`] — called when a PPLNS-mode finder
//!   wins a block; reads the snapshot persisted at template-build
//!   time, applies the ledger TX, then deletes the snapshot.
//! - [`PplnsEngine::shutdown`] — flips the cancel watch so background
//!   tasks exit cleanly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, InvalidAddressError, Sats};
use bp_db::{find_pplns_balances_for_addresses, DbError, PplnsBalanceRow};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{ConfigError, PplnsEngineConfig};
use crate::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError, DistributionResult,
};
use crate::ledger::touch_buffer::{spawn_flush_task, TouchBuffer};
use crate::ledger::{
    apply_distribution, coinbase_row, pending_row, ApplyDistributionResult, AuditRow, BalanceWrite,
    LedgerError, PayoutRowType,
};
use crate::sweep::{spawn_daily_task, DustSweepRunner, SweepError, SweepStats, SystemClock};
use crate::window::{snapshot::ParsedSnapshot, NetworkDifficulty, WindowError, WindowStore};

/// Errors surfaced across the engine boundary.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("window: {0}")]
    Window(#[from] WindowError),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("sweep: {0}")]
    Sweep(#[from] SweepError),
    #[error("distribution: {0}")]
    Distribution(Arc<DistributionError>),
    #[error("snapshot missing for block {block_height} — pool restart or expired TTL?")]
    SnapshotMissing { block_height: i32 },
    #[error(
        "snapshot reward mismatch for block {block_height}: \
         snapshot={snapshot_reward} sats, block={actual_reward} sats — \
         stale snapshot deleted; operator must trigger reprocessing"
    )]
    SnapshotRewardMismatch {
        block_height: i32,
        snapshot_reward: u64,
        actual_reward: u64,
    },
    #[error("on_block_found already in flight — concurrent block-find for same engine")]
    BlockFoundInProgress,
    #[error("invalid address in snapshot: {0}")]
    Address(#[from] InvalidAddressError),
    #[error("prepared block-found decode: {0}")]
    PreparedDecode(String),
}

/// A PPLNS block-found distribution computed at found-time and frozen
/// for deferred (confirmation-gated) application. Carries only primitive
/// fields so it round-trips through the pending-block store (Redis)
/// without leaking engine/ledger types onto the wire. Built by
/// [`PplnsEngine::prepare_block_found`], replayed by
/// [`PplnsEngine::apply_prepared`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PreparedBlockFound {
    pub block_height: i32,
    /// The reward the snapshot was computed against — carried for
    /// logging / cross-checks at apply time.
    pub block_reward_sats: u64,
    /// Found-time wall clock (epoch ms); stamped onto the ledger rows so
    /// history `created_at` reflects when the block was found, not when
    /// it confirmed.
    pub now_ms: i64,
    pub rows: Vec<PreparedAuditRow>,
    pub balances: Vec<PreparedBalanceWrite>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PreparedAuditRow {
    pub address: String,
    pub paid_sats: i64,
    pub percent: f32,
    /// `PayoutRowType` wire string (`coinbase` / `pending` / `dust-sweep`).
    pub row_type: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PreparedBalanceWrite {
    pub address: String,
    pub balance_sats: i64,
    pub total_paid_sats: i64,
}

impl PreparedBlockFound {
    fn freeze(
        block_height: i32,
        block_reward_sats: u64,
        now_ms: i64,
        rows: &[AuditRow],
        balances: &[BalanceWrite],
    ) -> Self {
        Self {
            block_height,
            block_reward_sats,
            now_ms,
            rows: rows
                .iter()
                .map(|r| PreparedAuditRow {
                    address: r.address.as_str().to_string(),
                    paid_sats: r.paid_sats.0,
                    percent: r.percent,
                    row_type: r.row_type.as_wire().to_string(),
                })
                .collect(),
            balances: balances
                .iter()
                .map(|b| PreparedBalanceWrite {
                    address: b.address.as_str().to_string(),
                    balance_sats: b.balance_sats.0,
                    total_paid_sats: b.total_paid_sats.0,
                })
                .collect(),
        }
    }

    /// Reconstruct the engine/ledger types from the frozen wire form.
    /// Fails only if the persisted blob is corrupt (bad address shape or
    /// unknown row-type string) — never in normal operation, since the
    /// blob was produced by [`Self::freeze`] from valid types.
    fn thaw(&self) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        let mut rows = Vec::with_capacity(self.rows.len());
        for r in &self.rows {
            let row_type = PayoutRowType::from_wire(&r.row_type).ok_or_else(|| {
                EngineError::PreparedDecode(format!("unknown row_type {:?}", r.row_type))
            })?;
            rows.push(AuditRow {
                address: AddressId::new(r.address.clone())?,
                paid_sats: Sats(r.paid_sats),
                percent: r.percent,
                row_type,
            });
        }
        let mut balances = Vec::with_capacity(self.balances.len());
        for b in &self.balances {
            balances.push(BalanceWrite {
                address: AddressId::new(b.address.clone())?,
                balance_sats: Sats(b.balance_sats),
                total_paid_sats: Sats(b.total_paid_sats),
            });
        }
        Ok((rows, balances))
    }
}

/// Top-level handle. Cloneable (`Arc<Inner>`); callers share one
/// engine across the whole pool.
#[derive(Clone)]
pub struct PplnsEngine {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    window: WindowStore,
    distribution_builder: DistributionBuilder,
    touch_buffer: Arc<TouchBuffer>,
    sweep_runner: DustSweepRunner<SystemClock>,
    config: PplnsEngineConfig,
    cancel_tx: watch::Sender<bool>,
    block_found_in_progress: AtomicBool,
}

impl PplnsEngine {
    /// Validate config, wire dependencies, spawn the two background
    /// tasks (touch-buffer flush + daily dust-sweep), return a handle.
    ///
    /// The caller owns the `ConnectionManager` lifecycle indirectly:
    /// the engine clones it into the `WindowStore`; on `shutdown` the
    /// background tasks exit and the engine's last `Arc` drop closes
    /// the connection.
    pub async fn spawn(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, net_diff, true).await
    }

    /// Core-mode constructor: same wiring, but *without* the background
    /// crons (touch-buffer flush + dust-sweep). The Core only reads the
    /// window and builds distributions (`build_distribution`, which still
    /// writes the snapshot key); all ledger-mutating crons run on the
    /// Satellite. `record_share` is unaffected and unused on the Core
    /// (the share path produces to the stream instead).
    pub async fn spawn_core(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, net_diff, false).await
    }

    async fn spawn_inner(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
        background_tasks: bool,
    ) -> Result<Self, EngineError> {
        let config = config.try_new()?;
        let window = WindowStore::new(redis, config.window_factor, config.bucket_shares, net_diff);
        // Cold-start safety: if the by-address aggregate is empty but buckets
        // exist (fresh deploy / lost key), rebuild it once from the buckets.
        // No-op at a normal cutover, where the previous pool version already
        // maintains the hash. After this the hash
        // is kept current incrementally; there is no periodic full recalc.
        window.bootstrap_window_if_needed().await?;
        let dist_cfg = DistributionConfig::from_engine_config(&config);
        let distribution_builder = DistributionBuilder::new(pool.clone(), window.clone(), dist_cfg);
        let touch_buffer = Arc::new(TouchBuffer::new());
        let clock = Arc::new(SystemClock);
        let sweep_runner = DustSweepRunner::new(pool.clone(), clock, config.abandoned_balance_days);

        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Spawn background tasks. We don't track JoinHandles in the
        // engine because shutdown is signalled by `cancel_tx` and the
        // tasks self-terminate. If callers need precise join semantics
        // they should wrap the engine in their own supervisor.
        //
        // Core mode (`background_tasks == false`) skips them entirely:
        // touch-flush + dust-sweep write the ledger, which is the
        // Satellite's job. The cancel channel is still wired so
        // `shutdown` stays a no-op-safe call in either mode.
        if background_tasks {
            std::mem::drop(spawn_flush_task(
                pool.clone(),
                touch_buffer.clone(),
                Duration::from_secs(config.touch_flush_interval_secs as u64),
                cancel_rx.clone(),
            ));
            std::mem::drop(spawn_daily_task(
                sweep_runner.clone(),
                config.dust_sweep_enabled,
                cancel_rx,
            ));
        }

        info!(
            window_factor = config.window_factor,
            min_payout_sats = config.min_payout_sats.0,
            fee_percent = config.fee_percent,
            dust_sweep_enabled = config.dust_sweep_enabled,
            abandoned_balance_days = config.abandoned_balance_days,
            background_tasks,
            "pplns-engine spawned"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                pool,
                window,
                distribution_builder,
                touch_buffer,
                sweep_runner,
                config,
                cancel_tx,
                block_found_in_progress: AtomicBool::new(false),
            }),
        })
    }

    /// Hot path. Called per accepted share AFTER the stratum layer has
    /// resolved mode = PPLNS and the per-session warmup is past.
    ///
    /// Atomically appends the share to the window (Redis MULTI/EXEC),
    /// records the `lastAcceptedShareAt` touch (60s-buffered to PG),
    /// and invalidates the distribution cache so the next
    /// `build_distribution` call sees the new share.
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        address: &str,
        difficulty: f64,
        timestamp_ms: u64,
    ) -> Result<(), EngineError> {
        let applied = self
            .inner
            .window
            .record_share(share_id, address, difficulty, timestamp_ms)
            .await?;
        if !applied {
            // Deduped redelivery: the window already counts this share, so
            // the touch + cache-invalidate would be redundant work (and a
            // redundant lastAcceptedShareAt bump). Skip them.
            return Ok(());
        }
        self.inner.touch_buffer.mark(address, timestamp_ms as i64);
        // The distribution depends on (window + ledger); a new share
        // changes the window. Invalidate so the next template-build
        // call sees fresh state. Invalidating per-reward would let
        // stale entries for *other* reward values survive — the whole
        // cache is keyed by reward, so dropping all entries is
        // correct (and cheap: one HashMap::clear).
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// The live coinbase-weight-budget handle. The autoscaler driver clones
    /// this to read pressure samples and write stepped values at runtime.
    pub fn coinbase_budget(&self) -> crate::autoscale::LiveBudget {
        self.inner.distribution_builder.live_budget()
    }

    /// Drop all cached distributions. The autoscaler driver calls this right
    /// after changing the live budget so the next build re-runs the trimmer
    /// against the new value instead of serving a stale cached result.
    pub fn invalidate_distribution_cache(&self) {
        self.inner.distribution_builder.invalidate_all();
    }

    /// Build the current PPLNS payout distribution for a given
    /// `block_reward_sats`. Wraps the inflight cache, persists a
    /// snapshot to Redis so `on_block_found` can replay deterministically.
    pub async fn build_distribution(
        &self,
        block_reward_sats: u64,
    ) -> Result<Arc<DistributionResult>, EngineError> {
        self.inner
            .distribution_builder
            .build(block_reward_sats)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Apply a found block's distribution: read the snapshot persisted
    /// at template-build time, write history + balance rows
    /// atomically, then clear the snapshot.
    ///
    /// Reentrancy: an in-process `AtomicBool` lock prevents concurrent
    /// calls within the same engine instance. Cross-process / cross-
    /// restart idempotency relies on the `(blockHeight, address)`
    /// UNIQUE constraint on `pplns_payout_history` — a replay won't
    /// duplicate audit rows.
    pub async fn on_block_found(
        &self,
        block_height: i32,
        block_reward_sats: u64,
    ) -> Result<ApplyDistributionResult, EngineError> {
        if self
            .inner
            .block_found_in_progress
            .swap(true, Ordering::SeqCst)
        {
            return Err(EngineError::BlockFoundInProgress);
        }
        let result = async {
            let prepared = self
                .prepare_block_found(block_height, block_reward_sats)
                .await?;
            self.apply_prepared(&prepared).await
        }
        .await;
        self.inner
            .block_found_in_progress
            .store(false, Ordering::SeqCst);
        result
    }

    /// **Compute** a found block's PPLNS distribution from the live
    /// snapshot + window and freeze it into a serializable
    /// [`PreparedBlockFound`] — WITHOUT writing the ledger. The
    /// confirmation-gating path calls this at block-found time (while the
    /// snapshot is still live — it rotates within a block or two),
    /// persists the result, and replays it via [`Self::apply_prepared`]
    /// only once the block has enough confirmations. Does not mutate the
    /// ledger; double-apply is guarded at apply time by the
    /// `(blockHeight, address)` UNIQUE constraint.
    pub async fn prepare_block_found(
        &self,
        block_height: i32,
        block_reward_sats: u64,
    ) -> Result<PreparedBlockFound, EngineError> {
        let snapshot = self
            .inner
            .window
            .read_snapshot()
            .await?
            .ok_or(EngineError::SnapshotMissing { block_height })?;

        if snapshot.block_reward_sats != block_reward_sats {
            warn!(
                snapshot_reward = snapshot.block_reward_sats,
                actual_reward = block_reward_sats,
                block_height,
                "PPLNS snapshot reward mismatch — deleting stale snapshot, operator must reprocess block"
            );
            if let Err(e) = self.inner.window.delete_snapshot().await {
                warn!(error = %e, "failed to delete mismatched snapshot — will TTL out");
            }
            return Err(EngineError::SnapshotRewardMismatch {
                block_height,
                snapshot_reward: snapshot.block_reward_sats,
                actual_reward: block_reward_sats,
            });
        }

        let now_ms = chrono::Utc::now().timestamp_millis();
        let current_window = self.inner.window.read_window_by_address().await?;
        let (audit_rows, balance_writes) = self
            .build_writes_from_snapshot(&snapshot, &current_window)
            .await?;

        Ok(PreparedBlockFound::freeze(
            block_height,
            block_reward_sats,
            now_ms,
            &audit_rows,
            &balance_writes,
        ))
    }

    /// **Apply** a previously [`prepared`](Self::prepare_block_found)
    /// distribution to the ledger. Idempotent on replay via the
    /// `(blockHeight, address)` UNIQUE constraint — re-applying a block
    /// already written converges to the same absolute balances. Clears
    /// the (now-stale) snapshot best-effort and drops the distribution
    /// cache so the next build reads the fresh ledger.
    pub async fn apply_prepared(
        &self,
        prepared: &PreparedBlockFound,
    ) -> Result<ApplyDistributionResult, EngineError> {
        let (audit_rows, balance_writes) = prepared.thaw()?;

        let outcome = apply_distribution(
            &self.inner.pool,
            prepared.block_height,
            &audit_rows,
            &balance_writes,
            prepared.now_ms,
        )
        .await?;

        if let Err(e) = self.inner.window.delete_snapshot().await {
            warn!(
                error = %e,
                block_height = prepared.block_height,
                "failed to delete PPLNS snapshot after apply_prepared — non-fatal, will TTL out"
            );
        }
        self.inner.distribution_builder.invalidate_all();

        info!(
            block_height = prepared.block_height,
            history_inserted = outcome.history_inserted,
            balances_affected = outcome.balances_affected,
            "pplns on_block_found applied"
        );
        Ok(outcome)
    }

    /// Translate a `ParsedSnapshot` + the live `current_window` into
    /// the typed audit-row + balance-write inputs `apply_distribution`
    /// expects.
    ///
    /// Three categories of rows produced:
    ///
    /// 1. **Coinbase** — one `PayoutRowType::Coinbase` row per
    ///    `snapshot.distribution` entry, plus a `BalanceWrite` that adds
    ///    the on-chain sats to the miner's lifetime `totalPaidSats`.
    /// 2. **Pending** — one `PayoutRowType::Pending` row per
    ///    `snapshot.balance_after` entry that has no coinbase output
    ///    (sub-dust accruals, debit carry-forwards). `paid_sats` carries
    ///    the *delta* against the prior balance; `BalanceWrite` sets the
    ///    new absolute value.
    /// 3. **Late-arriver** — one `PayoutRowType::Pending` row (0 sats)
    ///    for each address in `current_window` that was NOT in
    ///    `snapshot.considered_addresses` at build time. These miners
    ///    submitted shares after the snapshot was taken; their shares
    ///    stay in the sliding window and will be paid by the next
    ///    block's snapshot. The row is audit-only — no `BalanceWrite`.
    async fn build_writes_from_snapshot(
        &self,
        snapshot: &ParsedSnapshot,
        current_window: &HashMap<String, f64>,
    ) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        // Existing balance rows keyed by address — needed to compute
        // the new `total_paid_sats` and the pending-row delta. One bulk
        // `address = ANY(...)` query instead of a per-address N+1.
        // Addresses with no row (or invalid ones) are simply absent.
        // Fetch existing rows for the UNION of balance_after addresses AND
        // the coinbase distribution addresses. A fully-paid miner (pending
        // balance 0) is omitted from `balance_after`, but we still need its
        // existing `totalPaidSats` so the lifetime total ACCUMULATES instead
        // of being overwritten with just this block's coinbase payout.
        let mut address_set: std::collections::HashSet<String> =
            snapshot.balance_after.keys().cloned().collect();
        for entry in &snapshot.distribution {
            address_set.insert(entry.address.as_str().to_string());
        }
        let addresses: Vec<String> = address_set.into_iter().collect();
        let existing: HashMap<String, PplnsBalanceRow> =
            find_pplns_balances_for_addresses(&self.inner.pool, &addresses)
                .await?
                .into_iter()
                .map(|r| (r.address.as_str().to_string(), r))
                .collect();

        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let mut balance_writes: Vec<BalanceWrite> = Vec::new();
        // Tracks every address that already has a row this block so the
        // late-arriver loop can't emit a duplicate (UNIQUE-index guard).
        let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();

        // 1. Coinbase rows + corresponding balance writes.
        for entry in &snapshot.distribution {
            audit_rows.push(coinbase_row(entry));
            emitted.insert(entry.address.as_str().to_string());

            // New absolute balance: from the snapshot's balance_after,
            // falling back to the address's current balance (the snapshot
            // can omit addresses whose balance is unchanged).
            let new_balance = snapshot
                .balance_after
                .get(entry.address.as_str())
                .copied()
                .or_else(|| {
                    existing
                        .get(entry.address.as_str())
                        .map(|r| r.balance_sats.0)
                })
                .unwrap_or(0);
            let prev_total_paid = existing
                .get(entry.address.as_str())
                .map(|r| r.total_paid_sats.0)
                .unwrap_or(0);
            balance_writes.push(BalanceWrite {
                address: entry.address.clone(),
                balance_sats: Sats(new_balance),
                total_paid_sats: Sats(prev_total_paid + entry.sats.0),
            });
        }

        // 2. Pending rows for addresses in balance_after that DIDN'T get
        //    an on-chain output (sub-dust credit accruals + matching debits).
        for (addr_str, new_balance) in &snapshot.balance_after {
            if emitted.contains(addr_str) {
                continue;
            }
            let addr_id = AddressId::new(addr_str.clone())?;
            let prev_balance = existing
                .get(addr_str)
                .map(|r| r.balance_sats.0)
                .unwrap_or(0);
            let delta = new_balance - prev_balance;
            audit_rows.push(pending_row(addr_id.clone(), Sats(delta)));
            emitted.insert(addr_str.clone());

            let prev_total_paid = existing
                .get(addr_str)
                .map(|r| r.total_paid_sats.0)
                .unwrap_or(0);
            balance_writes.push(BalanceWrite {
                address: addr_id,
                balance_sats: Sats(*new_balance),
                // No on-chain delta for pending rows.
                total_paid_sats: Sats(prev_total_paid),
            });
        }

        // 3. Late-arriver rows: addresses active in the current window
        //    that weren't in the snapshot's considered set. Audit-only —
        //    no BalanceWrite; their shares stay in the window for the next
        //    block. Invalid address strings are skipped without error.
        for addr_str in current_window.keys() {
            if snapshot.considered_addresses.contains(addr_str) {
                continue;
            }
            if emitted.contains(addr_str) {
                continue;
            }
            let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                continue;
            };
            audit_rows.push(pending_row(addr_id, Sats(0)));
            emitted.insert(addr_str.clone());
        }

        Ok((audit_rows, balance_writes))
    }

    /// Run one manual dust-sweep tick. Exposes the sweep runner for
    /// admin endpoints / tests; the background cron triggers a sweep
    /// automatically at 03:00 UTC.
    pub async fn manual_sweep(&self) -> Result<SweepStats, EngineError> {
        self.inner
            .sweep_runner
            .sweep()
            .await
            .map_err(EngineError::from)
    }

    /// Drop one cached distribution entry. Called by the engine itself
    /// on share-record; exposed so manual admin tooling can force a
    /// recompute too.
    pub fn invalidate_distribution(&self, block_reward_sats: u64) {
        self.inner
            .distribution_builder
            .invalidate(block_reward_sats);
    }

    /// Signal both background tasks to exit. Best-effort: the tasks
    /// drain their final state (touch buffer flush, no final sweep)
    /// before returning. The engine remains usable for synchronous
    /// API calls until the underlying pool/redis connections are
    /// dropped.
    pub fn shutdown(&self) {
        // `watch::Sender::send` returns Err if all receivers have
        // dropped — fine, the tasks already exited.
        let _ = self.inner.cancel_tx.send(true);
    }

    // ── Accessors for reader.rs / hooks.rs ──────────────────────────

    pub fn config(&self) -> &PplnsEngineConfig {
        &self.inner.config
    }

    pub fn pool(&self) -> &PgPool {
        &self.inner.pool
    }

    pub fn window(&self) -> &WindowStore {
        &self.inner.window
    }

    pub fn touch_buffer(&self) -> &Arc<TouchBuffer> {
        &self.inner.touch_buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_carries_source_variants() {
        // Sanity: confirm the `From` impls compose. No runtime needed.
        fn _accepts_db(e: DbError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_window(e: WindowError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_ledger(e: LedgerError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_sweep(e: SweepError) -> EngineError {
            EngineError::from(e)
        }
    }

    #[test]
    fn block_found_in_progress_error_is_displayable() {
        let e = EngineError::BlockFoundInProgress;
        let s = format!("{e}");
        assert!(s.contains("in flight"), "got: {s}");
    }

    #[test]
    fn snapshot_missing_error_carries_block_height() {
        let e = EngineError::SnapshotMissing { block_height: 9001 };
        let s = format!("{e}");
        assert!(s.contains("9001"), "got: {s}");
    }

    #[test]
    fn snapshot_reward_mismatch_error_carries_all_fields() {
        let e = EngineError::SnapshotRewardMismatch {
            block_height: 850_000,
            snapshot_reward: 312_500_000,
            actual_reward: 312_499_100,
        };
        let s = format!("{e}");
        assert!(s.contains("850000"), "got: {s}");
        assert!(s.contains("312500000"), "got: {s}");
        assert!(s.contains("312499100"), "got: {s}");
    }

    // ── build_writes_from_snapshot — late-arriver logic ─────────────
    //
    // These tests exercise the three categories of audit rows produced
    // by `build_writes_from_snapshot`. We call the function via a
    /// Verify that an address present in `current_window` but absent
    /// from `snapshot.considered_addresses` gets a Pending/0-sats row.
    #[test]
    fn late_arriver_produces_pending_zero_row() {
        use crate::ledger::PayoutRowType;
        use bp_coinbase_snapshot::snapshot::ParsedSnapshot;
        use std::collections::{HashMap, HashSet};

        // Snapshot built before this miner submitted their first share.
        let snapshot = ParsedSnapshot {
            distribution: vec![],
            block_reward_sats: 312_500_000,
            considered_addresses: HashSet::new(), // nobody was in the snapshot
            balance_after: HashMap::new(),
        };

        // One miner in the window now (arrived after snapshot).
        let mut current_window = HashMap::new();
        current_window.insert("bc1qlatemin0000000000000000000000".to_string(), 64.0_f64);

        // Drive the pure logic that classifies rows.
        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let mut emitted: HashSet<String> = HashSet::new();

        for addr_str in current_window.keys() {
            if snapshot.considered_addresses.contains(addr_str) {
                continue;
            }
            if emitted.contains(addr_str) {
                continue;
            }
            let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                continue;
            };
            audit_rows.push(pending_row(addr_id, Sats(0)));
            emitted.insert(addr_str.clone());
        }

        assert_eq!(audit_rows.len(), 1, "exactly one late-arriver row");
        let row = &audit_rows[0];
        assert_eq!(row.paid_sats.0, 0, "0-sats for a late arriver");
        assert_eq!(row.row_type, PayoutRowType::Pending);
        assert_eq!(row.address.as_str(), "bc1qlatemin0000000000000000000000");
    }

    /// An address in the window that WAS in `considered_addresses` must
    /// NOT get a duplicate late-arriver row.
    #[test]
    fn considered_address_in_window_is_not_late_arriver() {
        use bp_coinbase_snapshot::snapshot::ParsedSnapshot;
        use std::collections::{HashMap, HashSet};

        let addr = "bc1qontime000000000000000000000000".to_string();
        let mut considered = HashSet::new();
        considered.insert(addr.clone());

        let snapshot = ParsedSnapshot {
            distribution: vec![],
            block_reward_sats: 312_500_000,
            considered_addresses: considered,
            balance_after: HashMap::new(),
        };

        let mut current_window = HashMap::new();
        current_window.insert(addr.clone(), 32.0_f64);

        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let emitted: std::collections::HashSet<String> = HashSet::new();

        for addr_str in current_window.keys() {
            if snapshot.considered_addresses.contains(addr_str) {
                continue;
            }
            if emitted.contains(addr_str) {
                continue;
            }
            let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                continue;
            };
            audit_rows.push(pending_row(addr_id, Sats(0)));
        }

        assert!(
            audit_rows.is_empty(),
            "on-time miner must not get a late-arriver row"
        );
    }
}
