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
//! ```no_run
//! # use bp_pplns_engine::{config::PplnsEngineConfig, engine::PplnsEngine};
//! # use bp_pplns_engine::window::NetworkDifficulty;
//! # async fn wire(
//! #     config: PplnsEngineConfig,
//! #     redis: redis::aio::ConnectionManager,
//! #     pg: sqlx::PgPool,
//! #     net_diff: NetworkDifficulty,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let engine = PplnsEngine::spawn(config, redis, pg, net_diff).await?;
//! # let _ = engine;
//! # Ok(()) }
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
use bp_db::{DbError, PplnsBalanceRow};
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
use crate::sweep::{spawn_daily_task, DustSweepRunner, SweepError, SystemClock};
use crate::window::{snapshot::StoredWeightSnapshot, NetworkDifficulty, WindowError, WindowStore};
use bp_coinbase_snapshot::ActualCoinbase;
use bp_share::{block_subsidy_sats, claim_sats, reward_within_band};

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
        "no snapshot under the winning job's payout list — the block needs an \
         operator reprocess from its own coinbase"
    )]
    SnapshotMissingForPayouts,
    #[error(
        "block {block_height} carried no payout fingerprint — the pool did not \
         build this coinbase (JD-client custom job), so there is no pool-side \
         distribution to book"
    )]
    NoPayoutFingerprint { block_height: i32 },
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
    #[error("on_block_found already in flight — concurrent block-find for same engine")]
    BlockFoundInProgress,
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
            | EngineError::SnapshotMissingForPayouts
            | EngineError::NoPayoutFingerprint { .. }
            | EngineError::RevenueBelowSubsidy { .. }
            | EngineError::Address(_) => true,
            // A ledger error is usually infrastructure, but one of them is a
            // verdict: a height that already carries a different block's
            // payout rows will still carry them next tick. `LedgerError`
            // owns that distinction so this engine and Group-Solo cannot
            // disagree about it.
            EngineError::Ledger(e) => e.is_terminal(),
            // Infrastructure, and the in-flight guard — all of these
            // clear on their own.
            EngineError::Redis(_)
            | EngineError::Window(_)
            | EngineError::Db(_)
            | EngineError::Sweep(_)
            | EngineError::Distribution(_)
            | EngineError::BlockFoundInProgress => false,
        }
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

    /// The empty-window answer for one asking miner — see
    /// [`crate::distribution::DistributionBuilder::build_bootstrap`].
    ///
    /// Only valid after [`Self::build_distribution`] answered
    /// [`bp_pplns::WeightBuildError::NoScoredMiners`]. The caller is the
    /// payout resolver, which is the only place that knows which miner is
    /// asking; the pool-wide JDP publisher must NOT use this — it builds
    /// one distribution for every job-declaring client at once and has
    /// nobody to name.
    pub async fn build_bootstrap_distribution(
        &self,
        block_reward_sats: u64,
        claimant: &AddressId,
    ) -> Result<Arc<DistributionResult>, EngineError> {
        self.inner
            .distribution_builder
            .build_bootstrap(block_reward_sats, claimant)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Look up the settlement inputs the found block's coinbase was built
    /// from, so the Core can stamp them into the block-found event.
    ///
    /// This exists for the same reason as Group-Solo's namesake, and it is
    /// resolved at the same moment: at the block-found instant, where the
    /// snapshot key is certainly still alive. The confirmation-gated apply
    /// runs `confirmation_depth` blocks later — about 20 minutes at depth 3,
    /// against a 20-minute [`crate::config::PplnsEngineConfig::snapshot_ttl_secs`]
    /// whose clock started when the winning JOB was built. Reading it only
    /// then loses the race about half the time, and losing it is not a
    /// delay: the inputs are gone from every store (the Redis→Postgres
    /// backup skips per-job snapshot keys on purpose), so what the
    /// withheld miners were owed can no longer be computed from anything.
    /// The block's own coinbase says who WAS paid, never what the unpaid
    /// were entitled to.
    ///
    /// `weights_fingerprint` is the identity of the winning job's payout
    /// list, carried on the job the share was built on. The build that
    /// produced that list stored its snapshot under it, and nothing else
    /// writes that key.
    pub async fn weight_snapshot_for_block_found(
        &self,
        weights_fingerprint: &[u8; 32],
    ) -> Result<StoredWeightSnapshot, EngineError> {
        let mut conn = self.inner.window.connection_for_snapshot();
        bp_coinbase_snapshot::resolve_snapshot_for_block_found(
            &mut conn,
            crate::window::snapshot_key_for,
            weights_fingerprint,
            "pplns",
        )
        .await?
        .ok_or(EngineError::SnapshotMissingForPayouts)
    }

    /// Apply a found block: settle `claim(T_actual) − paid` per address
    /// against the block's OWN coinbase, then write the payout history.
    ///
    /// `snapshot` is the distribution's settlement inputs. The Core
    /// resolves them at found-time and both paths carry them in — the
    /// confirmation-gated one in the parked blob, the immediate one
    /// straight through. `None` is the fallback for the case where that
    /// resolution failed (a Redis blip at the worst moment): the
    /// fingerprint is then read back here, which is a second chance, not
    /// the design.
    ///
    /// Idempotent on redelivery without a guard of its own:
    /// `pplns_payout_history` is UNIQUE on `(blockHeight, address)` and
    /// the balance upsert only runs when history rows were actually
    /// inserted, so a second delivery writes nothing and reports
    /// `history_inserted == 0`.
    pub async fn on_block_found(
        &self,
        block_height: i32,
        actual: &ActualCoinbase,
        snapshot: Option<StoredWeightSnapshot>,
        payouts_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        if self
            .inner
            .block_found_in_progress
            .swap(true, Ordering::SeqCst)
        {
            return Err(EngineError::BlockFoundInProgress);
        }
        let result = self
            .on_block_found_inner(block_height, actual, snapshot, payouts_fingerprint)
            .await;
        self.inner
            .block_found_in_progress
            .store(false, Ordering::SeqCst);
        result
    }

    async fn on_block_found_inner(
        &self,
        block_height: i32,
        actual: &ActualCoinbase,
        snapshot: Option<StoredWeightSnapshot>,
        payouts_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        // 1. Snapshot source: the blob the Core resolved at found-time,
        //    else a late read under the fingerprint. The late read is the
        //    fallback for a Redis blip at the found instant, not the
        //    design — by now the key has usually TTL'd out (see
        //    `weight_snapshot_for_block_found`).
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                let fingerprint = payouts_fingerprint
                    .filter(|fp| fp != &[0u8; 32])
                    .ok_or(EngineError::NoPayoutFingerprint { block_height })?;
                self.weight_snapshot_for_block_found(&fingerprint)
                    .await
                    .map_err(|e| match e {
                        // At apply time the missing key means the TTL won:
                        // report it as the block-scoped failure the
                        // operator reprocess keys off.
                        EngineError::SnapshotMissingForPayouts => {
                            EngineError::SnapshotMissing { block_height }
                        }
                        other => other,
                    })?
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
        // right at any revenue.
        if !reward_within_band(snapshot.reference_revenue_sats, actual.total_value_sats) {
            warn!(
                reference_reward = snapshot.reference_revenue_sats,
                actual_reward = actual.total_value_sats,
                block_height,
                "PPLNS block revenue far off the distribution's reference — booking it from the \
                 real coinbase, but the job source is worth a look"
            );
        }

        // 2. Settle. The balance write is absolute (`current + delta`), so
        //    `current` MUST be read under `FOR UPDATE` in the same
        //    transaction that writes it — otherwise the daily dust sweep,
        //    whose targets are exactly the balance-only entries a
        //    distribution carries, can commit between the two and have its
        //    work silently undone. The Redis window read stays OUTSIDE the
        //    transaction: it only decides which addresses get a 0-sat
        //    late-arriver audit row, and a Redis stall must not hold a PG
        //    transaction open.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let current_window = self.inner.window.read_window_by_address().await?;
        let addresses = Self::addresses_to_settle(&snapshot, actual);

        let mut tx = self.inner.pool.begin().await.map_err(LedgerError::from)?;
        let existing: HashMap<String, PplnsBalanceRow> =
            bp_db::find_pplns_balances_for_addresses_locked(&mut *tx, &addresses)
                .await?
                .into_iter()
                .map(|r| (r.address.as_str().to_string(), r))
                .collect();
        let (audit_rows, balance_writes) =
            Self::build_writes_from_weight_snapshot(&snapshot, &current_window, actual, &existing)?;
        let outcome =
            apply_distribution(&mut tx, block_height, &audit_rows, &balance_writes, now_ms).await?;
        tx.commit().await.map_err(LedgerError::from)?;

        // The weight snapshot is NOT consumed: it legitimately serves
        // every block built from its distribution (settlement is a delta
        // from the REAL coinbase). It expires by TTL.
        self.inner.distribution_builder.invalidate_all();

        info!(
            block_height,
            history_inserted = outcome.history_inserted,
            balances_affected = outcome.balances_affected,
            "pplns on_block_found applied"
        );
        Ok(outcome)
    }

    /// Every address this block settles, in the order the balance rows
    /// must be LOCKED.
    ///
    /// Sorted, and that is load-bearing: `FOR UPDATE` acquires row locks
    /// in the order the plan emits them, so a stable ordering here (and
    /// the matching `ORDER BY address` in the query) is what keeps two
    /// transactions touching the same two rows from deadlocking. The set
    /// used to come straight out of a `HashSet`, i.e. a different order
    /// every run.
    fn addresses_to_settle(
        snapshot: &StoredWeightSnapshot,
        actual: &ActualCoinbase,
    ) -> Vec<String> {
        let mut set: std::collections::HashSet<String> =
            snapshot.entries.iter().map(|e| e.address.clone()).collect();
        // Paid addresses outside the snapshot are settled too (they can
        // only be 0-value script matches or operator surprises — logged
        // in the builder — but the lifetime totals must not miss them).
        set.extend(actual.paid_by_address.keys().cloned());
        set.remove(&snapshot.fee_address);
        let mut addresses: Vec<String> = set.into_iter().collect();
        addresses.sort();
        addresses
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
    ///
    /// Pure: `existing` comes in already read and LOCKED by the caller's
    /// transaction. It used to do that read itself, from the pool and
    /// outside the writing transaction, which is precisely the window the
    /// dust sweep could commit into.
    fn build_writes_from_weight_snapshot(
        snapshot: &StoredWeightSnapshot,
        current_window: &HashMap<String, f64>,
        actual: &ActualCoinbase,
        existing: &HashMap<String, PplnsBalanceRow>,
    ) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        let t = actual.total_value_sats;

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
}
