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
//! Two layers of `bp_inflight_cache::InflightResultCache` (30s TTL by
//! default):
//!
//! - **Built distributions**, keyed by `block_reward_sats` — concurrent
//!   callers for the same reward share one computation.
//! - **Window+ledger inputs**, keyed by `()` — concurrent callers for
//!   *different* rewards still share the Redis window read and the
//!   Postgres ledger query, since neither depends on the reward.
//!
//! The second layer is what keeps a burst of unrelated callers cheap.
//! The per-reward layer alone never dedups them: ext-0x0003 has every
//! JDC report its own `available_payout_value`, so N simultaneous
//! requests at a chain-tip change mean N distinct keys and, without the
//! inputs layer, N window reads plus N ledger queries in the same few
//! milliseconds.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_db::{find_pplns_balances_with_open_balance, DbError, PplnsBalanceRow};
use bp_mining_job::payouts_fingerprint_from_parts;
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
    /// The shared window+ledger load failed. Carries the underlying
    /// error's message rather than the error itself: the inputs cache
    /// hands back an `Arc<DistributionError>` shared across all waiters,
    /// which can't be unwrapped back into an owned error.
    #[error("distribution inputs: {0}")]
    Inputs(String),
}

/// The part of a distribution build that does NOT depend on
/// `block_reward_sats`: the current payout window and the open-balance
/// ledger, both already sanitized to parseable payout addresses.
///
/// Every concurrent build shares these — the weights are a property of
/// the window, not of the reward. Only the scaling to a concrete reward
/// (and the dust/trim decisions that follow from it) is per-build, which
/// is why this is cached separately: N concurrent builds for N distinct
/// rewards cost one Redis window read and one Postgres ledger query, not
/// N of each.
#[derive(Clone, Debug, Default)]
pub struct DistributionInputs {
    pub address_shares: HashMap<AddressId, f64>,
    pub balances: HashMap<AddressId, Sats>,
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
    /// Identity of `payouts` — the key this build's snapshot is stored
    /// under. Callers hand it down to whatever consumes the payout list
    /// (the Stratum job build), so a block-found can later ask for the
    /// distribution its own coinbase was built from instead of whatever
    /// the shared snapshot key happens to hold. See
    /// [`bp_mining_job::payouts_fingerprint`].
    pub payouts_fingerprint: [u8; 32],
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
    /// Reward-independent window+ledger inputs, shared across every
    /// concurrent build. Keyed by `()` — there is exactly one payout
    /// window — so the cache degenerates to "one load per invalidation
    /// epoch, deduped across all in-flight builds".
    inputs_cache: InflightResultCache<(), DistributionInputs, DistributionError>,
    /// How often the window+ledger load actually ran. Observability, and
    /// the assertion hook for the dedup tests.
    inputs_loads: Arc<AtomicU64>,
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
            inputs_cache: InflightResultCache::new(cache_ttl),
            inputs_loads: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Number of window+ledger loads performed so far. Under a burst of
    /// concurrent builds this stays far below the build count — that is
    /// the whole point of the inputs cache.
    pub fn inputs_loads(&self) -> u64 {
        self.inputs_loads.load(Ordering::Relaxed)
    }

    /// Build the current PPLNS distribution for `block_reward_sats`.
    /// Concurrent callers for the same reward share one compute; callers
    /// for *different* rewards still share the window+ledger read.
    pub async fn build(
        &self,
        block_reward_sats: u64,
    ) -> Result<Arc<DistributionResult>, Arc<DistributionError>> {
        let pool = self.pool.clone();
        let window = self.window.clone();
        let window_for_inputs = self.window.clone();
        let config = self.config.clone();
        let inputs_cache = self.inputs_cache.clone();
        let inputs_loads = self.inputs_loads.clone();
        self.cache
            .get_or_compute(block_reward_sats, || async move {
                let inputs = inputs_cache
                    .get_or_compute((), || async move {
                        inputs_loads.fetch_add(1, Ordering::Relaxed);
                        load_inputs(&pool, &window_for_inputs).await
                    })
                    .await
                    .map_err(|e| DistributionError::Inputs(e.to_string()))?;
                build_from_inputs(&inputs, &window, &config, block_reward_sats).await
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

    /// Drops the built distributions AND the shared window+ledger
    /// inputs. Both must go: the callers are state-change events (a
    /// share landed, the budget moved), and keeping stale inputs would
    /// just rebuild the same stale distribution.
    pub fn invalidate_all(&self) {
        self.cache.clear();
        self.inputs_cache.clear();
    }

    /// The live coinbase-weight-budget handle this builder reads per build.
    /// The autoscaler driver clones it to observe pressure + write new values.
    pub fn live_budget(&self) -> LiveBudget {
        self.config.coinbase_weight_budget.clone()
    }
}

// ── Internals ────────────────────────────────────────────────────────

/// Steps 1-3: the reward-independent half of a build — read the window
/// and the ledger, sanitize both. Shared by every concurrent build via
/// [`DistributionBuilder::inputs_cache`].
async fn load_inputs(
    pool: &PgPool,
    window: &WindowStore,
) -> Result<DistributionInputs, DistributionError> {
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

    Ok(DistributionInputs {
        address_shares,
        balances,
    })
}

/// Steps 4-5: scale the shared inputs to one concrete
/// `block_reward_sats`, run the pure math, persist the snapshot.
async fn build_from_inputs(
    inputs: &DistributionInputs,
    window: &WindowStore,
    config: &DistributionConfig,
    block_reward_sats: u64,
) -> Result<DistributionResult, DistributionError> {
    // 4. Build inputs + call pure math. Read the *live* budget here so a
    //    runtime autoscaler change takes effect on the next build.
    let input = CoinbaseDistributionInput {
        address_shares: &inputs.address_shares,
        balances: &inputs.balances,
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
    // Records the ledger state this distribution was computed against, so the
    // apply can write a delta instead of an absolute — see
    // `StoredSnapshot::balance_before`.
    let snapshot = StoredSnapshot::from_math_with_before(
        &math.payouts,
        block_reward_sats,
        &math.considered_addresses,
        &math.balance_after,
        &inputs.balances,
    );
    // Keyed by the payout list it distributes — the only snapshot written.
    // Nothing else writes this key, so it still holds THIS distribution when
    // the block that mined it is found, however many other builds ran in
    // between. A block-found that cannot name a key gets no distribution
    // rather than a stranger's.
    let payouts_fingerprint = payouts_fingerprint_from_parts(
        math.payouts
            .iter()
            .map(|p| (p.address.as_str(), p.sats.to_i64().max(0) as u64)),
    );
    window
        .write_snapshot_for(&payouts_fingerprint, &snapshot, config.snapshot_ttl_secs)
        .await
        .map_err(DistributionError::Snapshot)?;

    Ok(DistributionResult {
        payouts: math.payouts,
        considered_addresses: math.considered_addresses,
        balance_after: math.balance_after,
        block_reward_sats,
        payouts_fingerprint,
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
            payouts_fingerprint: [0u8; 32],
        };
        let cloned = result.clone();
        assert_eq!(cloned.block_reward_sats, 312_500_000);
        assert_eq!(cloned.payouts.len(), 1);
    }
}
