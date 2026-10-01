// SPDX-License-Identifier: AGPL-3.0-or-later

//! `PplnsEngine`: wires the Postgres pool, the Redis window, the distribution
//! builder and the touch-flush and daily dust-sweep background tasks.
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
    BuiltDistribution, DistributionBuilder, DistributionConfig, DistributionError,
};
use crate::ledger::touch_buffer::{spawn_flush_task, TouchBuffer};
use crate::ledger::{
    apply_distribution, pending_row, ApplyDistributionResult, AuditRow, BalanceWrite, LedgerError,
    PayoutRowType,
};
use crate::sweep::{spawn_daily_task, DustSweepRunner, SystemClock};
use crate::window::{snapshot::StoredWeightSnapshot, NetworkDifficulty, WindowError, WindowStore};
use bp_coinbase_snapshot::ActualCoinbase;
use bp_share::{block_subsidy_sats, claim_sats};

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
    /// True when retrying can never succeed, so the confirmation watcher must stop
    /// re-applying and leave the block to the operator reprocess.
    pub fn is_terminal(&self) -> bool {
        match self {
            EngineError::Config(_)
            | EngineError::SnapshotMissing { .. }
            | EngineError::SnapshotMissingForPayouts
            | EngineError::NoPayoutFingerprint { .. }
            | EngineError::RevenueBelowSubsidy { .. }
            | EngineError::Address(_) => true,
            // `LedgerError` decides, so this engine and Group-Solo cannot disagree.
            EngineError::Ledger(e) => e.is_terminal(),
            EngineError::Redis(_)
            | EngineError::Window(_)
            | EngineError::Db(_)
            | EngineError::Distribution(_)
            | EngineError::BlockFoundInProgress => false,
        }
    }
}

/// Top-level handle, shared across the whole pool.
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
    /// Validate config, wire dependencies and spawn the ledger background tasks.
    pub async fn spawn(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, net_diff, true).await
    }

    /// Core-mode constructor without the background tasks: those write the
    /// ledger, which is the Satellite's job; the Core only builds distributions.
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
        let window = WindowStore::new(
            redis,
            config.window_factor,
            config.bucket_shares,
            net_diff,
            config.abandoned_balance_days,
        );
        window.bootstrap_window_if_needed().await?;
        // Must run before the first trim, or the age rule reads ids as 1970 and
        // drops the whole window. Not gated on `background_tasks`: the trim runs
        // wherever the share stream is consumed, which this constructor cannot see.
        window.restamp_legacy_bucket_scores().await?;
        let dist_cfg = DistributionConfig::from_engine_config(&config);
        let distribution_builder = DistributionBuilder::new(pool.clone(), window.clone(), dist_cfg);
        let touch_buffer = Arc::new(TouchBuffer::new());
        let clock = Arc::new(SystemClock);
        let sweep_runner = DustSweepRunner::new(pool.clone(), clock, config.abandoned_balance_days);

        let (cancel_tx, cancel_rx) = watch::channel(false);

        // JoinHandles are not tracked: the tasks exit on `cancel_tx`.
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
            // One field, not two: the window's age rule reads the same knob.
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

    /// Hot path, per accepted PPLNS share: append to the window, buffer the
    /// last-share touch and invalidate the distribution cache.
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
            // Deduped redelivery: the window already counts this share.
            return Ok(());
        }
        self.inner.touch_buffer.mark(address, timestamp_ms as i64);
        // The cache is keyed by reward, so a new share makes every entry stale.
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// The live coinbase-weight-budget handle. The autoscaler driver clones
    /// this to read pressure samples and write stepped values at runtime.
    pub fn coinbase_budget(&self) -> crate::autoscale::LiveBudget {
        self.inner.distribution_builder.live_budget()
    }

    /// Drop all cached distributions, so a changed live budget takes effect on the
    /// next build.
    pub fn invalidate_distribution_cache(&self) {
        self.inner.distribution_builder.invalidate_all();
    }

    /// Build (or serve cached) the PPLNS distribution for `block_reward_sats`; the
    /// build persists the snapshot `on_block_found` settles against.
    pub async fn build_distribution(
        &self,
        block_reward_sats: u64,
    ) -> Result<Arc<BuiltDistribution>, EngineError> {
        self.inner
            .distribution_builder
            .build(block_reward_sats)
            .await
            .map_err(EngineError::Distribution)
    }

    /// The empty-window answer for one asking miner, valid only after
    /// [`Self::build_distribution`] answered [`bp_pplns::WeightBuildError::NoScoredMiners`].
    /// Not for the pool-wide JDP publisher: it serves every client at once and
    /// has no miner to name. See [`crate::distribution::DistributionBuilder::build_bootstrap`].
    pub async fn build_bootstrap_distribution(
        &self,
        block_reward_sats: u64,
        claimant: &AddressId,
    ) -> Result<Arc<BuiltDistribution>, EngineError> {
        self.inner
            .distribution_builder
            .build_bootstrap(block_reward_sats, claimant)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Settlement inputs of the winning job's payout list, resolved at found-time
    /// like Group-Solo's namesake: the confirmed apply can outlast
    /// [`crate::config::PplnsEngineConfig::snapshot_ttl_secs`], and the coinbase alone
    /// cannot tell what the unpaid were owed.
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

    /// Settle `claim(T_actual) − paid` per address against the block's OWN coinbase.
    /// `snapshot` is `None` only when found-time resolution failed; the fingerprint is
    /// then read back as a second chance. Idempotent via
    /// [`crate::ledger::apply_distribution`]: a differing redelivery errors, never rebooks.
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
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                let fingerprint = payouts_fingerprint
                    .filter(|fp| fp != &[0u8; 32])
                    .ok_or(EngineError::NoPayoutFingerprint { block_height })?;
                self.weight_snapshot_for_block_found(&fingerprint)
                    .await
                    .map_err(|e| match e {
                        // At apply time the TTL won: report the block-scoped
                        // failure the operator reprocess keys off.
                        EngineError::SnapshotMissingForPayouts => {
                            EngineError::SnapshotMissing { block_height }
                        }
                        other => other,
                    })?
            }
        };

        // The one hard gate: no honest template pays less than its own subsidy,
        // so such a block is not booked blind.
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
        // The balance write is absolute, so `current` MUST be read `FOR UPDATE`
        // in the writing transaction, or a dust sweep committing in between is
        // undone. The window read stays outside: it only picks late-arriver rows,
        // and a Redis stall must not hold a PG transaction open.
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

        // The snapshot is not consumed: it serves every block built from its
        // distribution, and expires by TTL.
        self.inner.distribution_builder.invalidate_all();

        info!(
            block_height,
            history_inserted = outcome.history_inserted,
            balances_affected = outcome.balances_affected,
            "pplns on_block_found applied"
        );
        Ok(outcome)
    }

    /// Every address this block settles, sorted: together with the query's
    /// `ORDER BY address` this fixes the `FOR UPDATE` lock order, which keeps two
    /// transactions on the same rows from deadlocking.
    fn addresses_to_settle(
        snapshot: &StoredWeightSnapshot,
        actual: &ActualCoinbase,
    ) -> Vec<String> {
        let mut set: std::collections::HashSet<String> =
            snapshot.entries.iter().map(|e| e.address.clone()).collect();
        // Paid addresses outside the snapshot too: lifetime totals must not miss them.
        set.extend(actual.paid_by_address.keys().cloned());
        set.remove(&snapshot.fee_address);
        let mut addresses: Vec<String> = set.into_iter().collect();
        addresses.sort();
        addresses
    }

    /// Per snapshot entry, book `claim_sats(score, S, fee, T) − paid` as a balance
    /// delta: one rule covers exactly-paid, withheld, indebted and overpaid miners.
    /// The fee output has no balance row; `T − Σ claims` is the pool's by construction.
    /// `existing` must already be locked by the caller's transaction.
    fn build_writes_from_weight_snapshot(
        snapshot: &StoredWeightSnapshot,
        current_window: &HashMap<String, f64>,
        actual: &ActualCoinbase,
        existing: &HashMap<String, PplnsBalanceRow>,
    ) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        let t = actual.total_value_sats;
        let in_snapshot: std::collections::HashSet<&str> = snapshot
            .entries
            .iter()
            .map(|e| e.address.as_str())
            .collect();
        let paid_to = |address: &str| actual.paid_by_address.get(address).copied().unwrap_or(0);
        // Current balance and lifetime total; a missing row is zero on both.
        let row_of = |address: &str| {
            existing
                .get(address)
                .map_or((0, 0), |r| (r.balance_sats.0, r.total_paid_sats.0))
        };

        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let mut balance_writes: Vec<BalanceWrite> = Vec::new();

        // The coinbase paid the carried promises out of this same pot, so claims
        // are shares of the rest; using the full pot would invent money.
        let extras_total = snapshot.extras_total();

        for entry in &snapshot.entries {
            if entry.address == snapshot.fee_address {
                // Its payment is inseparable from the pool output: skip
                // rather than misbook.
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
            let paid = paid_to(&entry.address);
            let delta = claim - paid as i64;

            let addr_id = AddressId::new(entry.address.clone())?;
            if paid > 0 {
                audit_rows.push(AuditRow {
                    address: addr_id.clone(),
                    paid_sats: Sats(paid as i64),
                    percent: actual.percent_of_total(paid),
                    row_type: PayoutRowType::Coinbase,
                });
            } else if delta != 0 {
                audit_rows.push(pending_row(addr_id.clone(), Sats(delta)));
            } else {
                continue;
            }
            let (current, prev_total_paid) = row_of(&entry.address);
            balance_writes.push(BalanceWrite {
                address: addr_id,
                balance_sats: Sats(current + delta),
                total_paid_sats: Sats(prev_total_paid + paid as i64),
            });
        }

        // Outputs paying an address the snapshot does not know: book the payment
        // into the lifetime total without inventing a claim.
        for (addr_str, &paid) in &actual.paid_by_address {
            if paid == 0
                || *addr_str == snapshot.fee_address
                || in_snapshot.contains(addr_str.as_str())
            {
                continue;
            }
            warn!(
                address = %addr_str,
                paid,
                "weight settlement: coinbase paid an address outside the distribution"
            );
            let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                continue;
            };
            let (current, prev_total_paid) = row_of(addr_str);
            audit_rows.push(AuditRow {
                address: addr_id.clone(),
                paid_sats: Sats(paid as i64),
                percent: actual.percent_of_total(paid),
                row_type: PayoutRowType::Coinbase,
            });
            balance_writes.push(BalanceWrite {
                address: addr_id,
                balance_sats: Sats(current - paid as i64),
                total_paid_sats: Sats(prev_total_paid + paid as i64),
            });
        }

        // Late arrivers: active in the window, unknown to the snapshot, unpaid.
        for addr_str in current_window.keys() {
            if *addr_str == snapshot.fee_address
                || in_snapshot.contains(addr_str.as_str())
                || paid_to(addr_str) > 0
            {
                continue;
            }
            let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                continue;
            };
            audit_rows.push(pending_row(addr_id, Sats(0)));
        }

        Ok((audit_rows, balance_writes))
    }

    /// Signal the background tasks to exit; the touch buffer flushes once more.
    pub fn shutdown(&self) {
        // Err only when the tasks already exited.
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
    use bp_coinbase_snapshot::WeightSnapshotEntry;

    #[test]
    fn engine_error_carries_source_variants() {
        fn _accepts_db(e: DbError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_window(e: WindowError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_ledger(e: LedgerError) -> EngineError {
            EngineError::from(e)
        }
    }

    fn snap_entry(address: &str, score_weight: u64, balance_sats: i64) -> WeightSnapshotEntry {
        WeightSnapshotEntry {
            address: address.to_string(),
            score_weight,
            balance_sats,
            wire_weight: score_weight,
            dust_limit: 546,
        }
    }

    fn balance_row(address: &str, balance: i64, total_paid: i64) -> (String, PplnsBalanceRow) {
        let row = PplnsBalanceRow {
            address: AddressId::new(address.to_string()).unwrap(),
            balance_sats: Sats(balance),
            total_paid_sats: Sats(total_paid),
            updated_at: 0,
            last_accepted_share_at: None,
        };
        (address.to_string(), row)
    }

    /// Pins every branch of the settlement writes: exactly paid, withheld,
    /// overpaid, indebted, nothing owed, fee address as an entry, paid outside
    /// the snapshot (valid, invalid, zero, fee), late arrivers.
    #[test]
    fn settlement_writes_cover_every_branch() {
        const FEE: &str = "fee_addr";
        let snapshot = StoredWeightSnapshot {
            entries: vec![
                snap_entry("exact", 400, 0),
                snap_entry("withheld", 300, 0),
                snap_entry("overpaid", 200, 0),
                snap_entry("indebted", 100, -500),
                snap_entry("owed_nothing", 0, 0),
                snap_entry(FEE, 50, 0),
            ],
            weight_p: 10,
            fee_ppm: 10_000,
            fee_address: FEE.to_string(),
            reference_revenue_sats: 1_000_000,
            score_total: 1_050,
        };
        let paid = |pairs: &[(&str, u64)]| -> HashMap<String, u64> {
            pairs.iter().map(|(a, s)| (a.to_string(), *s)).collect()
        };
        let actual = ActualCoinbase {
            paid_by_address: paid(&[
                ("exact", 377_333),
                ("overpaid", 300_000),
                ("outsider", 1_000),
                ("bad address", 2_000),
                ("zero_outsider", 0),
                (FEE, 7_000),
            ]),
            pool_paid_sats: 10_000,
            total_value_sats: 1_000_000,
        };
        let window: HashMap<String, f64> = [
            ("exact", 1.0),
            ("late", 2.0),
            ("outsider", 3.0),
            (FEE, 4.0),
            ("bad late", 5.0),
            ("owed_nothing", 6.0),
            ("zero_outsider", 7.0),
        ]
        .iter()
        .map(|(a, d)| (a.to_string(), *d))
        .collect();
        let existing: HashMap<String, PplnsBalanceRow> = [
            balance_row("exact", 100, 5_000),
            balance_row("indebted", -500, 0),
            balance_row("outsider", 50, 10),
        ]
        .into_iter()
        .collect();

        let (audit, writes) =
            PplnsEngine::build_writes_from_weight_snapshot(&snapshot, &window, &actual, &existing)
                .expect("writes");

        // Snapshot entries come first, in snapshot order.
        let head: Vec<&str> = audit.iter().take(4).map(|r| r.address.as_str()).collect();
        assert_eq!(head, ["exact", "withheld", "overpaid", "indebted"]);

        let mut audit: Vec<String> = audit
            .iter()
            .map(|r| {
                format!(
                    "{} {} {:.4} {}",
                    r.address.as_str(),
                    r.paid_sats.0,
                    r.percent,
                    r.row_type.as_wire()
                )
            })
            .collect();
        audit.sort();
        let mut writes: Vec<String> = writes
            .iter()
            .map(|w| {
                format!(
                    "{} {} {}",
                    w.address.as_str(),
                    w.balance_sats.0,
                    w.total_paid_sats.0
                )
            })
            .collect();
        writes.sort();
        assert_eq!(
            audit,
            [
                "exact 377333 37.7333 coinbase",
                "indebted 94333 0.0000 pending",
                "late 0 0.0000 pending",
                "outsider 1000 0.1000 coinbase",
                "overpaid 300000 30.0000 coinbase",
                "withheld 283000 0.0000 pending",
                "zero_outsider 0 0.0000 pending",
            ],
            "audit rows"
        );
        assert_eq!(
            writes,
            [
                "exact 100 382333",
                "indebted 93833 0",
                "outsider -950 1010",
                "overpaid -111334 300000",
                "withheld 283000 0",
            ],
            "balance writes"
        );
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
