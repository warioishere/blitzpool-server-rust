// SPDX-License-Identifier: AGPL-3.0-or-later

//! `DistributionBuilder` — production-side wrapper around
//! `bp_pplns::build_coinbase_distribution`.
//!
//! Reads the current window from Redis (per-address aggregate hash),
//! loads the open-balance ledger rows from Postgres, calls the
//! pure-math distribution builder, then persists a snapshot into
//! `pplns:snapshot` so [`crate::ledger::apply_distribution`] can
//! replay the same distribution deterministically when the block is
//! found.
//!
//! Concurrent callers for the same `block_reward_sats` share one
//! computation via `bp_inflight_cache::InflightResultCache` (30s TTL
//! by default).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_db::{find_pplns_balances_with_open_balance, DbError, PplnsBalanceRow};
use bp_pplns::{
    build_coinbase_distribution, is_valid_payout_address, CoinbaseDistributionEntry,
    CoinbaseDistributionInput,
};
use sqlx::PgPool;
use thiserror::Error;
use tracing::warn;

use crate::autoscale::LiveBudget;
use crate::window::snapshot::StoredSnapshot;
use crate::window::{WindowError, WindowStore};
use bp_coinbase_snapshot::share_map_from_redis_hash;
use bp_inflight_cache::InflightResultCache;

/// Default cache TTL for `DistributionBuilder::build` (30 s).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

/// Errors surfaced by [`DistributionBuilder::build`].
///
/// `Default` is required so the in-flight cache can construct a
/// "leader-dropped" placeholder if the leader's compute task panics
/// (rare; surfaces as a CRITICAL operational event the caller logs).
#[derive(Debug, Default, Error)]
pub enum DistributionError {
    /// Placeholder used by the in-flight cache when the leader's
    /// compute task drops without publishing. Reaching this means a
    /// panic happened mid-build; the caller's recovery path is to
    /// retry the call.
    #[default]
    #[error("inflight leader dropped without publishing — retry")]
    LeaderDropped,
    #[error("window read: {0}")]
    Window(#[from] WindowError),
    #[error("redis snapshot write: {0}")]
    Snapshot(#[source] redis::RedisError),
    #[error("db: {0}")]
    Db(#[from] DbError),
}

/// Result of one distribution build. Cheap to clone-via-Arc because
/// the in-flight cache shares `Arc<DistributionResult>` across waiters.
#[derive(Clone, Debug)]
pub struct DistributionResult {
    /// Coinbase output list, in coinbase order (matters for byte-equal
    /// reconstruction at block-build time).
    pub payouts: Vec<CoinbaseDistributionEntry>,
    /// Every address that was in shares OR balances at build time.
    pub considered_addresses: HashSet<AddressId>,
    /// Absolute new ledger balances per address whose state changed.
    /// Applied as absolute UPSERT in [`crate::ledger::apply_distribution`].
    pub balance_after: HashMap<AddressId, Sats>,
    /// `block_reward_sats` this distribution was built for. The
    /// snapshot pins this so on-block-found can refuse to apply a
    /// stale snapshot whose reward disagrees with the actual coinbase.
    pub block_reward_sats: u64,
}

/// Knobs for the distribution path. Built from
/// [`crate::config::PplnsEngineConfig`] at engine startup. Most fields are
/// static; `coinbase_weight_budget` is a live [`LiveBudget`] handle so the
/// autoscaler can change it at runtime — every build reads the current value.
#[derive(Clone, Debug)]
pub struct DistributionConfig {
    pub fee_address: Option<AddressId>,
    pub fee_percent: f64,
    pub min_payout_sats: Sats,
    /// Live, runtime-mutable coinbase weight budget shared with the autoscaler.
    pub coinbase_weight_budget: LiveBudget,
    pub snapshot_ttl_secs: u32,
}

impl DistributionConfig {
    pub fn from_engine_config(cfg: &crate::config::PplnsEngineConfig) -> Self {
        Self {
            fee_address: cfg.fee_address.clone(),
            fee_percent: cfg.fee_percent,
            min_payout_sats: cfg.min_payout_sats,
            coinbase_weight_budget: LiveBudget::new(cfg.coinbase_weight_budget),
            snapshot_ttl_secs: cfg.snapshot_ttl_secs,
        }
    }
}

/// Orchestrator. Cheap to clone (each field is either an `Arc`-cheap
/// handle or `Clone`-cheap config).
#[derive(Clone)]
pub struct DistributionBuilder {
    pool: PgPool,
    window: WindowStore,
    config: DistributionConfig,
    cache: InflightResultCache<u64, DistributionResult, DistributionError>,
}

impl DistributionBuilder {
    pub fn new(pool: PgPool, window: WindowStore, config: DistributionConfig) -> Self {
        Self::with_cache_ttl(pool, window, config, DEFAULT_CACHE_TTL)
    }

    pub fn with_cache_ttl(
        pool: PgPool,
        window: WindowStore,
        config: DistributionConfig,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            pool,
            window,
            config,
            cache: InflightResultCache::new(cache_ttl),
        }
    }

    /// Build the current PPLNS distribution for `block_reward_sats`.
    /// Concurrent callers for the same reward share one compute.
    pub async fn build(
        &self,
        block_reward_sats: u64,
    ) -> Result<Arc<DistributionResult>, Arc<DistributionError>> {
        let pool = self.pool.clone();
        let window = self.window.clone();
        let config = self.config.clone();
        self.cache
            .get_or_compute(block_reward_sats, || async move {
                compute_distribution(&pool, &window, &config, block_reward_sats).await
            })
            .await
    }

    /// Invalidate the cache for a specific reward. Called by the
    /// engine on hot-path state changes (a new accepted share landed,
    /// a block was found, network difficulty changed).
    ///
    /// Common pattern: `invalidate_all` (drops every cached reward)
    /// because the window changed for *any* reward, not just one.
    pub fn invalidate(&self, block_reward_sats: u64) {
        self.cache.invalidate(&block_reward_sats);
    }

    pub fn invalidate_all(&self) {
        self.cache.clear();
    }

    /// The live coinbase-weight-budget handle this builder reads per build.
    /// The autoscaler driver clones it to observe pressure + write new values.
    pub fn live_budget(&self) -> LiveBudget {
        self.config.coinbase_weight_budget.clone()
    }
}

// ── Internals ────────────────────────────────────────────────────────

async fn compute_distribution(
    pool: &PgPool,
    window: &WindowStore,
    config: &DistributionConfig,
    block_reward_sats: u64,
) -> Result<DistributionResult, DistributionError> {
    // 1. Read window aggregate from Redis (HashMap<String, f64>).
    let window_raw = window.read_window_by_address().await?;

    // 2. Read open-balance ledger rows from PG.
    let open_balance_rows = find_pplns_balances_with_open_balance(pool).await?;

    // 3. Convert to bp_pplns inputs. Window addresses are raw strings
    //    — strings that fail `AddressId` validation are skipped with a
    //    warn (defensive: an upstream bug could have pushed an invalid
    //    address into Redis; better to skip its share than fail the
    //    whole distribution).
    let mut address_shares = share_map_from_redis_hash(
        &window_raw,
        "pplns distribution: skipping invalid address in window — likely from a buggy upstream",
    );
    let mut balances = open_balance_rows_to_balance_map(&open_balance_rows);

    // Defensive sanitize: drop any address that isn't a parseable
    // Bitcoin address before it reaches the coinbase builder. A single
    // unparseable window/ledger row (junk, migration artifact, or
    // seed-test data such as `synthseed*`) otherwise aborts the entire
    // coinbase build in `bp-mining-job` (its `address_to_script` is
    // fail-the-whole-tx), blocking every miner's job. Dropping the row
    // here is strictly safer — it's simply not paid this block and
    // stays in the ledger. See `bp_pplns::is_valid_payout_address`.
    let shares_before = address_shares.len();
    let balances_before = balances.len();
    address_shares.retain(|a, _| is_valid_payout_address(a.as_str()));
    balances.retain(|a, _| is_valid_payout_address(a.as_str()));
    let dropped = (shares_before - address_shares.len()) + (balances_before - balances.len());
    if dropped > 0 {
        warn!(
            dropped,
            shares_dropped = shares_before - address_shares.len(),
            balances_dropped = balances_before - balances.len(),
            "pplns distribution: dropped unparseable payout addresses before coinbase build"
        );
    }

    // 4. Build inputs + call pure math. Read the *live* budget here so a
    //    runtime autoscaler change takes effect on the next build.
    let input = CoinbaseDistributionInput {
        address_shares: &address_shares,
        balances: &balances,
        block_reward_sats: Sats(block_reward_sats as i64),
        fee_percent: config.fee_percent,
        fee_address: config.fee_address.as_ref(),
        coinbase_weight_budget: config.coinbase_weight_budget.get(),
        suppress_matching_debits: false, // PPLNS uses signed-ledger pair-symmetry
        min_payout_sats: Some(config.min_payout_sats),
        finder_bonus_sats: None, // finder-bonus is a Group-Solo feature
        finder_address: None,
    };
    let math = build_coinbase_distribution(input);

    // Feed the autoscaler: record this build's weight-budget pressure. The
    // no-shares fallback carries no telemetry and is skipped.
    if let Some(sample) = math.budget_telemetry {
        config.coinbase_weight_budget.record_sample(sample);
    }

    // 5. Persist snapshot so on-block-found can replay deterministically.
    let snapshot = StoredSnapshot::from_math(
        &math.payouts,
        block_reward_sats,
        &math.considered_addresses,
        &math.balance_after,
    );
    window
        .write_snapshot(&snapshot, config.snapshot_ttl_secs)
        .await
        .map_err(DistributionError::Snapshot)?;

    Ok(DistributionResult {
        payouts: math.payouts,
        considered_addresses: math.considered_addresses,
        balance_after: math.balance_after,
        block_reward_sats,
    })
}

fn open_balance_rows_to_balance_map(rows: &[PplnsBalanceRow]) -> HashMap<AddressId, Sats> {
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        out.insert(row.address.clone(), row.balance_sats);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_pplns::CoinbaseDistributionEntry;

    #[test]
    fn distribution_config_from_engine_config_carries_fields() {
        let engine_cfg = crate::config::PplnsEngineConfig {
            fee_address: Some(AddressId::new("bc1qfee0000000000000000000000000").unwrap()),
            fee_percent: 2.5,
            coinbase_weight_budget: 60_000,
            snapshot_ttl_secs: 1800,
            ..crate::config::PplnsEngineConfig::default()
        };

        let dist_cfg = DistributionConfig::from_engine_config(&engine_cfg);
        assert_eq!(
            dist_cfg.fee_address.as_ref().unwrap().as_str(),
            "bc1qfee0000000000000000000000000"
        );
        assert!((dist_cfg.fee_percent - 2.5).abs() < 1e-9);
        assert_eq!(dist_cfg.coinbase_weight_budget.get(), 60_000);
        assert_eq!(dist_cfg.snapshot_ttl_secs, 1800);
    }

    #[test]
    fn open_balance_rows_to_balance_map_preserves_signed_values() {
        let rows = vec![
            PplnsBalanceRow {
                address: AddressId::new("bc1qcredit").unwrap(),
                balance_sats: Sats(5_000),
                total_paid_sats: Sats(100_000),
                updated_at: 0,
                last_accepted_share_at: None,
            },
            PplnsBalanceRow {
                address: AddressId::new("bc1qdebit").unwrap(),
                balance_sats: Sats(-5_000),
                total_paid_sats: Sats(50_000),
                updated_at: 0,
                last_accepted_share_at: None,
            },
        ];
        let map = open_balance_rows_to_balance_map(&rows);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&AddressId::new("bc1qcredit").unwrap()].0, 5_000);
        assert_eq!(map[&AddressId::new("bc1qdebit").unwrap()].0, -5_000);
    }

    #[test]
    fn distribution_result_is_cloneable() {
        // The InflightResultCache shares Arc<DistributionResult> across
        // waiters; verify the type composes.
        let result = DistributionResult {
            payouts: vec![CoinbaseDistributionEntry {
                address: AddressId::new("bc1qfoo").unwrap(),
                percent: 100.0,
                sats: Sats(1_000),
            }],
            considered_addresses: HashSet::new(),
            balance_after: HashMap::new(),
            block_reward_sats: 312_500_000,
        };
        let cloned = result.clone();
        assert_eq!(cloned.block_reward_sats, 312_500_000);
        assert_eq!(cloned.payouts.len(), 1);
    }
}
