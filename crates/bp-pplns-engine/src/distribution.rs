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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_db::{find_pplns_balances_with_open_balance, DbError, PplnsBalanceRow};
use bp_pplns::{
    build_weight_distribution, is_valid_payout_address, WeightBuildError, WeightDistribution,
    WeightDistributionInput,
};
use sqlx::PgPool;
use thiserror::Error;
use tracing::warn;

use crate::autoscale::LiveBudget;
use crate::window::snapshot::StoredWeightSnapshot;
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
    /// The weight model has no distribution without a pool-output
    /// recipient — `pay_P` is structural (SV2 ext 0x0003 §4).
    #[error("no fee address configured — the weight model requires the pool-output recipient")]
    NoFeeAddress,
    #[error("weight build: {0}")]
    WeightBuild(#[from] WeightBuildError),
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
    /// The weight-native distribution (SV2 ext 0x0003 model): entries
    /// with settlement inputs + published wire weights, `weight_P`,
    /// fee, dust limits, and the weights fingerprint. Every consumer
    /// derives concrete satoshis from it via the §4 formula —
    /// [`WeightDistribution::payout_entries_at`] for the pool's own
    /// templates, the JDP publisher for `SetPayoutDistribution`.
    pub distribution: WeightDistribution,
    /// Did the schema-2 snapshot under `distribution.fingerprint`
    /// actually get written?
    ///
    /// `false` means this build succeeded but its snapshot did not
    /// land, so the fingerprint names a key that does not exist. The
    /// distribution is still correct and still becomes a coinbase —
    /// failing the build over a lost snapshot would hand the miner a
    /// solo job paying itself the whole block, which is far worse. But
    /// a caller that promises a found block will be booked
    /// automatically MUST NOT make that promise on a `false`.
    pub snapshot_written: bool,
}

impl DistributionResult {
    /// The snapshot key this build landed under (see
    /// [`bp_share::weights_fingerprint_from_parts`]). Threaded onto
    /// every job built from this distribution — a found block carries
    /// it back so settlement can read exactly these inputs.
    pub fn payouts_fingerprint(&self) -> [u8; 32] {
        self.distribution.fingerprint
    }
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

    /// Build the current PPLNS weight distribution against
    /// `reference_revenue_sats` (the pool's current template value —
    /// the projection base for balance boosts). Concurrent callers for
    /// the same reference share one compute; callers for *different*
    /// references still share the window+ledger read. Under the weight
    /// model there is normally exactly ONE live reference at a time —
    /// the reward-keyed cache is simply correct, not load-bearing.
    pub async fn build(
        &self,
        reference_revenue_sats: u64,
    ) -> Result<Arc<DistributionResult>, Arc<DistributionError>> {
        let pool = self.pool.clone();
        let window = self.window.clone();
        let window_for_inputs = self.window.clone();
        let config = self.config.clone();
        let inputs_cache = self.inputs_cache.clone();
        let inputs_loads = self.inputs_loads.clone();
        self.cache
            .get_or_compute(reference_revenue_sats, || async move {
                let inputs = inputs_cache
                    .get_or_compute((), || async move {
                        inputs_loads.fetch_add(1, Ordering::Relaxed);
                        load_inputs(&pool, &window_for_inputs).await
                    })
                    .await
                    .map_err(|e| DistributionError::Inputs(e.to_string()))?;
                build_from_inputs(&inputs, &window, &config, reference_revenue_sats).await
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

/// Steps 4-5: project the shared inputs into the weight model against
/// the reference revenue, persist the schema-2 snapshot.
async fn build_from_inputs(
    inputs: &DistributionInputs,
    window: &WindowStore,
    config: &DistributionConfig,
    reference_revenue_sats: u64,
) -> Result<DistributionResult, DistributionError> {
    // 4. Weight-native build. Read the *live* budget here so a runtime
    //    autoscaler change takes effect on the next build.
    let fee_address = config
        .fee_address
        .as_ref()
        .ok_or(DistributionError::NoFeeAddress)?;
    let distribution = build_weight_distribution(WeightDistributionInput {
        address_shares: &inputs.address_shares,
        balances: &inputs.balances,
        fee_percent: config.fee_percent,
        fee_address,
        coinbase_weight_budget: config.coinbase_weight_budget.get(),
        min_payout_sats: Some(config.min_payout_sats),
        finder_bonus_sats: None, // finder-bonus is a Group-Solo feature
        finder_address: None,
        reference_revenue_sats,
    })?;

    // Feed the autoscaler with this build's blockspace pressure.
    config
        .coinbase_weight_budget
        .record_sample(distribution.budget_telemetry);

    // 5. Persist the settlement inputs under the weights fingerprint.
    // Nothing else writes this key, so it still holds THIS distribution
    // when the block that mined it is found — and because settlement
    // books `claim(T_actual) − paid` as a delta, the snapshot serves
    // the pool's own templates and every JDC's job alike.
    //
    // A failed snapshot write must NOT fail the build. The distribution
    // itself is correct and is about to become a coinbase; returning
    // `Err` here sends `pplns_payouts` into its solo fallback, and that
    // miner is handed a job paying 100 % of the block to itself. Losing
    // the snapshot costs a manual reprocess if a block lands on this
    // job — losing the distribution costs the pool's miners the whole
    // block, irreversibly.
    let snapshot = StoredWeightSnapshot::from_distribution(&distribution);
    let snapshot_written = match window
        .write_weight_snapshot_for(
            &distribution.fingerprint,
            &snapshot,
            config.snapshot_ttl_secs,
        )
        .await
    {
        Ok(()) => true,
        Err(err) => {
            warn!(
                %err,
                reference_revenue_sats,
                "PPLNS weight-snapshot write failed — the coinbase distribution stands, \
                 but a block found on this job cannot be booked automatically and needs \
                 operator reprocessing"
            );
            false
        }
    };

    Ok(DistributionResult {
        distribution,
        snapshot_written,
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
        let shares = HashMap::from([(
            AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap(),
            1.0,
        )]);
        let balances = HashMap::new();
        let fee = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let distribution = build_weight_distribution(WeightDistributionInput {
            address_shares: &shares,
            balances: &balances,
            fee_percent: 1.5,
            fee_address: &fee,
            coinbase_weight_budget: 50_000,
            min_payout_sats: Some(Sats(5_000)),
            finder_bonus_sats: None,
            finder_address: None,
            reference_revenue_sats: 312_500_000,
        })
        .unwrap();
        let result = DistributionResult {
            distribution,
            snapshot_written: true,
        };
        let cloned = result.clone();
        assert_eq!(cloned.distribution.reference_revenue_sats, 312_500_000);
        assert_eq!(cloned.payouts_fingerprint(), result.payouts_fingerprint());
    }
}
