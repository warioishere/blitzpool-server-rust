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
use tracing::{error, info, warn};

use crate::config::{ConfigError, PplnsEngineConfig};
use crate::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError, DistributionResult,
};
use crate::ledger::touch_buffer::{spawn_flush_task, TouchBuffer};
use crate::ledger::{
    apply_distribution, pending_row, ApplyDistributionResult, AuditRow, BalanceWrite, LedgerError,
    PayoutRowType,
};
use crate::sweep::{spawn_daily_task, DustSweepRunner, SweepError, SweepStats, SystemClock};
use crate::window::{snapshot::StoredWeightSnapshot, NetworkDifficulty, WindowError, WindowStore};
use bp_coinbase_snapshot::ActualCoinbase;
use bp_share::{block_subsidy_sats, claim_sats, reward_within_band};

/// How often a transient Redis failure on the block-found snapshot read is
/// retried before the block is given up on. That read is the only thing
/// standing between a found block and its payout, and the caller does not
/// retry — a connection reset mid-reconnect would otherwise cost the block.
const SNAPSHOT_READ_RETRIES: u32 = 3;
/// Backoff between those attempts, multiplied by the attempt number.
const SNAPSHOT_READ_BACKOFF: std::time::Duration = std::time::Duration::from_millis(80);

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
        "block {block_height} carried no payout fingerprint — the pool did not \
         build this coinbase (JD-client custom job), so there is no pool-side \
         distribution to book"
    )]
    NoPayoutFingerprint { block_height: i32 },
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
    #[error(
        "block {block_height} coinbase pays {actual_reward} sats, less than the \
         {subsidy} sat subsidy the block was entitled to — it forfeited money, so \
         nothing about it is trustworthy enough to book unattended"
    )]
    RevenueBelowSubsidy {
        block_height: i32,
        actual_reward: u64,
        subsidy: u64,
    },
    #[error(
        "block {block_height} already has payout-history rows — a redelivered \
         block-found must fail closed, not re-credit the ledger"
    )]
    AlreadyBooked { block_height: i32 },
    #[error("on_block_found already in flight — concurrent block-find for same engine")]
    BlockFoundInProgress,
    #[error("invalid address in snapshot: {0}")]
    Address(#[from] InvalidAddressError),
    #[error("prepared block-found decode: {0}")]
    PreparedDecode(String),
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
            | EngineError::NoPayoutFingerprint { .. }
            | EngineError::SnapshotRewardMismatch { .. }
            | EngineError::RevenueBelowSubsidy { .. }
            | EngineError::AlreadyBooked { .. }
            | EngineError::Address(_)
            | EngineError::PreparedDecode(_) => true,
            // Infrastructure, and the in-flight guard — all of these
            // clear on their own.
            EngineError::Redis(_)
            | EngineError::Window(_)
            | EngineError::Db(_)
            | EngineError::Ledger(_)
            | EngineError::Sweep(_)
            | EngineError::Distribution(_)
            | EngineError::BlockFoundInProgress => false,
        }
    }
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
    /// The payout-list fingerprint whose snapshot this was frozen from, if
    /// it came from one. Carried so the apply consumes exactly that key: a
    /// snapshot outliving its own block is what lets a redelivered event
    /// re-prepare against an already-credited ledger.
    #[serde(default)]
    pub payouts_fingerprint: Option<[u8; 32]>,
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
    /// The ledger row as it stood when this block was frozen, so the
    /// apply can re-base its movement onto whatever the row holds by
    /// the time the block confirms (see [`BalanceWrite::balance_before`]).
    /// `serde(default)` keeps blobs frozen before this field readable —
    /// they apply their absolute, exactly as they always did.
    #[serde(default)]
    pub balance_before_sats: Option<i64>,
    /// Baseline for `total_paid_sats` — see
    /// [`BalanceWrite::total_paid_before`]. `serde(default)` for blobs
    /// frozen before the field existed.
    #[serde(default)]
    pub total_paid_before_sats: Option<i64>,
}

impl PreparedBlockFound {
    fn freeze(
        block_height: i32,
        block_reward_sats: u64,
        now_ms: i64,
        rows: &[AuditRow],
        balances: &[BalanceWrite],
        payouts_fingerprint: Option<[u8; 32]>,
    ) -> Self {
        Self {
            block_height,
            block_reward_sats,
            now_ms,
            payouts_fingerprint,
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
                    balance_before_sats: b.balance_before.map(|s| s.0),
                    total_paid_before_sats: b.total_paid_before.map(|s| s.0),
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
                balance_before: b.balance_before_sats.map(Sats),
                total_paid_before: b.total_paid_before_sats.map(Sats),
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

    /// Re-base each balance write onto the row as it stands NOW.
    ///
    /// A confirmation-gated block freezes ABSOLUTE post-block balances
    /// at found-time and writes them `confirmation_depth` blocks later
    /// (default 3, ~30 min), and `bulk_upsert_pplns_balances` sets
    /// `balanceSats = EXCLUDED`. So every writer that touches a row in
    /// that window is undone by the apply.
    ///
    /// The block-found path already guards the writer it knew about —
    /// an earlier pending block, flushed before the next one freezes.
    /// The daily 03:00-UTC dust sweep is the other one: it pair-cancels
    /// an abandoned credit against an abandoned debit and deletes both
    /// rows. Landing the frozen absolute afterwards restored the credit
    /// while the debit stayed swept, leaving the ledger owing satoshis
    /// no one owed it — paid out of the miners' cut on the next block.
    ///
    /// So the movement, not the outcome, is what gets applied:
    /// `now + (frozen_after − frozen_before)`. Signed, unclamped — the
    /// PPLNS ledger carries debts. Same shape as Group-Solo's
    /// `resolve_new_balance`, which solved this for its own snapshots.
    async fn rebase_onto_current(
        &self,
        balance_writes: &mut [BalanceWrite],
        block_height: i32,
    ) -> Result<(), EngineError> {
        let rebasable: Vec<String> = balance_writes
            .iter()
            .filter(|b| b.balance_before.is_some() || b.total_paid_before.is_some())
            .map(|b| b.address.as_str().to_string())
            .collect();
        if rebasable.is_empty() {
            return Ok(());
        }
        let current: HashMap<String, (i64, i64)> =
            find_pplns_balances_for_addresses(&self.inner.pool, &rebasable)
                .await?
                .into_iter()
                .map(|r| {
                    (
                        r.address.as_str().to_string(),
                        (r.balance_sats.0, r.total_paid_sats.0),
                    )
                })
                .collect();

        for write in balance_writes.iter_mut() {
            // A row absent now reads as (0, 0) — the sweep deletes a row
            // it has zeroed, and re-basing onto 0 is what keeps that
            // deletion standing.
            let (now, now_total) = current
                .get(write.address.as_str())
                .copied()
                .unwrap_or((0, 0));

            // `totalPaidSats` is written absolutely by the same upsert,
            // so it needs the same treatment: apply the block's OWN
            // increment to whatever the row holds now. Without this a
            // second block maturing in the same pass reverts the first
            // one's increment and the lifetime-paid figure loses a block.
            if let Some(before_total) = write.total_paid_before {
                let paid_this_block = write.total_paid_sats.0 - before_total.0;
                let rebased_total = now_total + paid_this_block;
                if rebased_total != write.total_paid_sats.0 {
                    warn!(
                        address = write.address.as_str(),
                        block_height,
                        frozen_total_before = before_total.0,
                        frozen_total_after = write.total_paid_sats.0,
                        current_total = now_total,
                        rebased_total,
                        "pplns apply: totalPaidSats moved between freeze and apply — applying \
                         this block's increment to the current row"
                    );
                    write.total_paid_sats = Sats(rebased_total);
                }
            }

            let Some(before) = write.balance_before else {
                continue;
            };
            if now == before.0 {
                continue;
            }
            let rebased = now + (write.balance_sats.0 - before.0);
            warn!(
                address = write.address.as_str(),
                block_height,
                frozen_before = before.0,
                frozen_after = write.balance_sats.0,
                current = now,
                rebased,
                "pplns apply: the ledger row moved between freeze and apply — applying the \
                 block's movement to the current row rather than the frozen absolute"
            );
            write.balance_sats = Sats(rebased);
        }
        Ok(())
    }

    /// **Apply** a previously [`prepared`](Self::prepare_block_found)
    /// distribution to the ledger. Idempotent on replay via the
    /// `(blockHeight, address)` UNIQUE constraint. Clears the
    /// (now-stale) snapshot best-effort and drops the distribution
    /// cache so the next build reads the fresh ledger.
    ///
    /// The balance writes are RE-BASED first — see
    /// [`Self::rebase_onto_current`]. A gated block is computed at
    /// found-time and lands `confirmation_depth` blocks later, and the
    /// upsert is absolute, so without this anything that touched a row
    /// in between would be silently undone.
    pub async fn apply_prepared(
        &self,
        prepared: &PreparedBlockFound,
    ) -> Result<ApplyDistributionResult, EngineError> {
        let (audit_rows, mut balance_writes) = prepared.thaw()?;
        self.rebase_onto_current(&mut balance_writes, prepared.block_height)
            .await?;

        let outcome = apply_distribution(
            &self.inner.pool,
            prepared.block_height,
            &audit_rows,
            &balance_writes,
            prepared.now_ms,
        )
        .await?;

        // The weight snapshot is NOT consumed here: it legitimately
        // serves every block built from its distribution (settlement is
        // a delta from the REAL coinbase), and redelivery fails closed
        // at prepare time via the payout-history guard instead. It
        // expires by TTL.
        self.inner.distribution_builder.invalidate_all();

        info!(
            block_height = prepared.block_height,
            history_inserted = outcome.history_inserted,
            balances_affected = outcome.balances_affected,
            "pplns on_block_found applied"
        );
        Ok(outcome)
    }

    /// [`Self::on_block_found_for`] for the weight model: prepare from
    /// the REAL coinbase (claim − paid) and apply immediately. The
    /// ungated block-found arm; the confirmation-gated arm calls
    /// [`Self::prepare_block_found_scaled`] + [`Self::apply_prepared`]
    /// itself.
    pub async fn on_block_found_scaled(
        &self,
        block_height: i32,
        actual: &ActualCoinbase,
        payouts_fingerprint: Option<[u8; 32]>,
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
                .prepare_block_found_scaled(block_height, actual, payouts_fingerprint)
                .await?;
            self.apply_prepared(&prepared).await
        }
        .await;
        self.inner
            .block_found_in_progress
            .store(false, Ordering::SeqCst);
        result
    }

    /// [`Self::prepare_block_found_for`] for a job built from a WEIGHT
    /// distribution (schema-2 snapshot): settlement books
    /// `claim(T_actual) − actually_paid` per address, with both sides
    /// taken from the REAL coinbase of the found block. Correct for any
    /// revenue inside the settlement band — the pool's own templates
    /// and a JDC's independently-valued job settle through this one
    /// path.
    pub async fn prepare_block_found_scaled(
        &self,
        block_height: i32,
        actual: &ActualCoinbase,
        payouts_fingerprint: Option<[u8; 32]>,
    ) -> Result<PreparedBlockFound, EngineError> {
        let fingerprint = payouts_fingerprint
            .filter(|fp| fp != &[0u8; 32])
            .ok_or(EngineError::NoPayoutFingerprint { block_height })?;
        // Redelivery guard. A weight snapshot legitimately serves MANY
        // blocks (every job built between window changes shares one
        // fingerprint), so the v1 "apply consumes the snapshot" trick
        // cannot protect against a redelivered block-found here. What
        // identifies a booked block is its payout history: rows at this
        // height mean the ledger was already credited — refuse.
        if bp_db::payout_recorded_at_height(&self.inner.pool, block_height).await? {
            return Err(EngineError::AlreadyBooked { block_height });
        }
        // Same retry rationale as the schema-1 read above.
        let mut attempt = 0;
        let snapshot = loop {
            match self
                .inner
                .window
                .read_weight_snapshot_for(&fingerprint)
                .await
            {
                Ok(Some(s)) => break s,
                Ok(None) => return Err(EngineError::SnapshotMissing { block_height }),
                Err(e) if attempt < SNAPSHOT_READ_RETRIES => {
                    warn!(
                        error = %e,
                        block_height,
                        attempt,
                        "PPLNS weight-snapshot read failed — retrying before giving up on the block"
                    );
                    attempt += 1;
                    tokio::time::sleep(SNAPSHOT_READ_BACKOFF * attempt).await;
                }
                Err(e) => return Err(EngineError::Redis(e)),
            }
        };

        // The one hard gate: a coinbase that pays less than its own
        // subsidy destroyed money it was entitled to. No mempool drift,
        // no stale projection base and no job-declaring client's own
        // template can produce that, so it never fires on a healthy
        // block — and a block that DID do it is not one to book blind.
        let subsidy = block_subsidy_sats(block_height, self.inner.config.subsidy_halving_interval);
        if actual.total_value_sats < subsidy {
            error!(
                subsidy,
                actual_reward = actual.total_value_sats,
                block_height,
                "PPLNS block coinbase pays less than the block subsidy — refusing to book"
            );
            return Err(EngineError::RevenueBelowSubsidy {
                block_height,
                actual_reward: actual.total_value_sats,
                subsidy,
            });
        }
        // Drift off the projection base is an ALARM, not a gate. The
        // claims below come from the block's own coinbase, so they are
        // right at any revenue; refusing to book here used to leave the
        // balances this block already paid standing in the ledger, and
        // the next block paid them out a second time.
        if !reward_within_band(snapshot.reference_revenue_sats, actual.total_value_sats) {
            warn!(
                reference_reward = snapshot.reference_revenue_sats,
                actual_reward = actual.total_value_sats,
                block_height,
                "PPLNS block revenue far off the distribution's reference — booking it from the \
                 real coinbase, but the job source is worth a look"
            );
        }

        let now_ms = chrono::Utc::now().timestamp_millis();
        let current_window = self.inner.window.read_window_by_address().await?;
        let (audit_rows, balance_writes) = self
            .build_writes_from_weight_snapshot(&snapshot, &current_window, actual)
            .await?;

        Ok(PreparedBlockFound::freeze(
            block_height,
            actual.total_value_sats,
            now_ms,
            &audit_rows,
            &balance_writes,
            Some(fingerprint),
        ))
    }

    /// The weight-model settlement: per snapshot entry compute the
    /// claim from the raw inputs (`claim_sats(score, S, fee, T)`), read
    /// what the coinbase actually paid the address, and book the
    /// difference as a balance DELTA against the current ledger.
    ///
    /// Every case reduces to that one rule: an exactly-paid miner books
    /// `0`; a dust-pruned or blockspace-folded miner books the full
    /// claim as credit; a debt-carrying miner's claim pays the debt
    /// down; an overpaid miner (revenue drifted below the projection)
    /// books the overshoot as debt. The pool/fee output has no balance
    /// row — `T − Σ claims` is the pool's by construction.
    async fn build_writes_from_weight_snapshot(
        &self,
        snapshot: &StoredWeightSnapshot,
        current_window: &HashMap<String, f64>,
        actual: &ActualCoinbase,
    ) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        let t = actual.total_value_sats;
        let mut address_set: std::collections::HashSet<String> =
            snapshot.entries.iter().map(|e| e.address.clone()).collect();
        // Paid addresses outside the snapshot get audit rows too (they
        // can only be 0-value script matches or operator surprises —
        // logged below — but the lifetime totals must not miss them).
        address_set.extend(actual.paid_by_address.keys().cloned());
        address_set.remove(&snapshot.fee_address);
        let addresses: Vec<String> = address_set.into_iter().collect();
        let existing: HashMap<String, PplnsBalanceRow> =
            find_pplns_balances_for_addresses(&self.inner.pool, &addresses)
                .await?
                .into_iter()
                .map(|r| (r.address.as_str().to_string(), r))
                .collect();

        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let mut balance_writes: Vec<BalanceWrite> = Vec::new();
        let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();

        // The promises this distribution carried, recomputed exactly as
        // the build did. Subtracting them is what keeps the ledger from
        // inventing money: the coinbase paid those satoshis out of this
        // same pot, so a miner without a promise of its own earns a
        // share of the REST — charging it the full pot would credit it
        // the others' promises on every block.
        let extras_total = snapshot.extras_total();

        for entry in &snapshot.entries {
            if entry.address == snapshot.fee_address {
                // The fee address should never appear as a miner entry
                // (the builder routes the pool share via weight_P), but
                // if it does, its payment attribution is inseparable
                // from the pool output — skip rather than misbook.
                warn!(
                    address = %entry.address,
                    "weight settlement: fee address doubles as miner entry — skipping its row"
                );
                continue;
            }
            let claim = claim_sats(
                entry.score_weight,
                snapshot.score_total,
                snapshot.fee_ppm,
                t,
                extras_total,
            );
            let paid = actual
                .paid_by_address
                .get(&entry.address)
                .copied()
                .unwrap_or(0);
            let delta = claim - paid as i64;

            let current = existing
                .get(&entry.address)
                .map(|r| r.balance_sats.0)
                .unwrap_or(0);
            let prev_total_paid = existing
                .get(&entry.address)
                .map(|r| r.total_paid_sats.0)
                .unwrap_or(0);

            let addr_id = AddressId::new(entry.address.clone())?;
            if paid > 0 {
                audit_rows.push(AuditRow {
                    address: addr_id.clone(),
                    paid_sats: Sats(paid as i64),
                    percent: if t > 0 {
                        (paid as f64 / t as f64 * 100.0) as f32
                    } else {
                        0.0
                    },
                    row_type: PayoutRowType::Coinbase,
                });
            } else if delta != 0 {
                audit_rows.push(pending_row(addr_id.clone(), Sats(delta)));
            } else {
                // No payment, no ledger movement — nothing to record.
                continue;
            }
            emitted.insert(entry.address.clone());
            balance_writes.push(BalanceWrite {
                address: addr_id,
                balance_sats: Sats(current + delta),
                total_paid_sats: Sats(prev_total_paid + paid as i64),
                total_paid_before: Some(Sats(prev_total_paid)),
                balance_before: Some(Sats(current)),
            });
        }

        // Coinbase outputs paying an address the snapshot does not know.
        // With positional §7.1 validation this cannot happen for value-
        // carrying outputs; surface loudly if it ever does, and book the
        // payment into the lifetime total without inventing a claim.
        for (addr_str, paid) in &actual.paid_by_address {
            if *paid == 0 || emitted.contains(addr_str) || *addr_str == snapshot.fee_address {
                continue;
            }
            if !snapshot.entries.iter().any(|e| &e.address == addr_str) {
                warn!(
                    address = %addr_str,
                    paid,
                    "weight settlement: coinbase paid an address outside the distribution"
                );
                let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                    continue;
                };
                let current = existing
                    .get(addr_str)
                    .map(|r| r.balance_sats.0)
                    .unwrap_or(0);
                let prev_total_paid = existing
                    .get(addr_str)
                    .map(|r| r.total_paid_sats.0)
                    .unwrap_or(0);
                audit_rows.push(AuditRow {
                    address: addr_id.clone(),
                    paid_sats: Sats(*paid as i64),
                    percent: if t > 0 {
                        (*paid as f64 / t as f64 * 100.0) as f32
                    } else {
                        0.0
                    },
                    row_type: PayoutRowType::Coinbase,
                });
                emitted.insert(addr_str.clone());
                balance_writes.push(BalanceWrite {
                    address: addr_id,
                    balance_sats: Sats(current - *paid as i64),
                    total_paid_sats: Sats(prev_total_paid + *paid as i64),
                    total_paid_before: Some(Sats(prev_total_paid)),
                    balance_before: Some(Sats(current)),
                });
            }
        }

        // Late arrivers: active in the window, unknown to the snapshot.
        for addr_str in current_window.keys() {
            if emitted.contains(addr_str)
                || addr_str == &snapshot.fee_address
                || snapshot.entries.iter().any(|e| &e.address == addr_str)
            {
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
}
