// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS around the shared weight build: Redis window plus Postgres balances,
//! snapshotted under `pplns:snapshot:<fingerprint>` so a found block settles
//! against them. The window+ledger inputs are cached apart from the reward, so
//! N rewards cost one read.

pub use bp_coinbase_snapshot::BuiltDistribution;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bp_coinbase_snapshot::{sanitize_and_build, BuildRequest};
use bp_common::{AddressId, Sats};
use bp_db::{find_pplns_balances_with_open_balance, PplnsBalanceRow};
use bp_pplns::WeightBuildError;
use sqlx::PgPool;
use thiserror::Error;
use tracing::{error, warn};

use crate::autoscale::LiveBudget;
use crate::window::snapshot::{write_weight_snapshot, StoredWeightSnapshot};
use crate::window::{WindowError, WindowStore};
use bp_coinbase_snapshot::share_map_from_redis_hash;
use bp_inflight_cache::InflightResultCache;

pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

/// Retries for a failed snapshot write before the job goes out without one;
/// a block found on this job can only be booked from this key.
const SNAPSHOT_WRITE_RETRIES: u32 = 2;
/// Backoff between those attempts, multiplied by the attempt number.
const SNAPSHOT_WRITE_BACKOFF: Duration = Duration::from_millis(40);

/// Errors surfaced by [`DistributionBuilder::build`]. `Default` exists so
/// the in-flight cache can build a placeholder when the leader panics.
#[derive(Debug, Default, Error)]
pub enum DistributionError {
    /// The in-flight leader dropped without publishing (a panic mid-build);
    /// the caller retries.
    #[default]
    #[error("inflight leader dropped without publishing — retry")]
    LeaderDropped,
    #[error("window read: {0}")]
    Window(#[from] WindowError),
    /// The shared window+ledger load failed. Only the message is carried:
    /// the cache shares one `Arc<DistributionError>` across all waiters.
    #[error("distribution inputs: {0}")]
    Inputs(String),
    /// The weight model has no distribution without a recipient for `pay_P`.
    #[error("no fee address configured — the weight model requires the pool-output recipient")]
    NoFeeAddress,
    #[error("weight build: {0}")]
    WeightBuild(#[from] WeightBuildError),
}

/// The reward-independent part of a build: the payout window and the
/// open-balance ledger, sanitized to parseable addresses. Weights belong to
/// the window, not the reward, so every concurrent build shares one load.
#[derive(Clone, Debug, Default)]
pub struct DistributionInputs {
    pub address_shares: HashMap<AddressId, f64>,
    pub balances: HashMap<AddressId, Sats>,
}

/// Knobs for the distribution path, from [`crate::config::PplnsEngineConfig`].
/// `coinbase_weight_budget` is a [`LiveBudget`] so the autoscaler can move it.
#[derive(Clone, Debug)]
pub struct DistributionConfig {
    pub fee_address: Option<AddressId>,
    pub fee_percent: f64,
    pub min_payout_sats: Sats,
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

#[derive(Clone)]
pub struct DistributionBuilder {
    pool: PgPool,
    window: WindowStore,
    config: DistributionConfig,
    cache: InflightResultCache<u64, BuiltDistribution, DistributionError>,
    /// Keyed by `()`: there is exactly one payout window.
    inputs_cache: InflightResultCache<(), DistributionInputs, DistributionError>,
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

    /// Window+ledger loads performed so far; the dedup tests assert on it.
    pub fn inputs_loads(&self) -> u64 {
        self.inputs_loads.load(Ordering::Relaxed)
    }

    /// Build the PPLNS weight distribution against `reference_revenue_sats`,
    /// the template value balance boosts are projected on.
    pub async fn build(
        &self,
        reference_revenue_sats: u64,
    ) -> Result<Arc<BuiltDistribution>, Arc<DistributionError>> {
        let pool = self.pool.clone();
        let window = self.window.clone();
        let window_for_inputs = self.window.clone();
        let config = self.config.clone();
        let inputs_cache = self.inputs_cache.clone();
        let inputs_loads = self.inputs_loads.clone();
        let built = self
            .cache
            .get_or_compute(reference_revenue_sats, || async move {
                let inputs = inputs_cache
                    .get_or_compute((), || async move {
                        inputs_loads.fetch_add(1, Ordering::Relaxed);
                        load_inputs(&pool, &window_for_inputs).await
                    })
                    .await
                    .map_err(|e| DistributionError::Inputs(e.to_string()))?;
                // No bootstrap claimant: this build is shared by every miner,
                // so an empty window surfaces as `NoScoredMiners` and
                // `build_bootstrap` resolves it per miner.
                build_from_inputs(&inputs, &window, &config, reference_revenue_sats, None).await
            })
            .await;
        // An empty window must not outlive its first share: drop the inputs,
        // so the bootstrap and the next build read the window again.
        if let Err(err) = &built {
            if matches!(
                **err,
                DistributionError::WeightBuild(WeightBuildError::NoScoredMiners)
            ) {
                self.inputs_cache.clear();
            }
        }
        built
    }

    /// The empty-window answer for ONE miner, uncached because a distribution
    /// naming one sole claimant must never reach another miner.
    /// Call only after [`Self::build`] answered
    /// [`bp_pplns::WeightBuildError::NoScoredMiners`], or it hands one miner the whole block.
    pub async fn build_bootstrap(
        &self,
        reference_revenue_sats: u64,
        claimant: &AddressId,
    ) -> Result<Arc<BuiltDistribution>, Arc<DistributionError>> {
        let pool = self.pool.clone();
        let window_for_inputs = self.window.clone();
        let inputs_loads = self.inputs_loads.clone();
        let inputs = self
            .inputs_cache
            .get_or_compute((), || async move {
                inputs_loads.fetch_add(1, Ordering::Relaxed);
                load_inputs(&pool, &window_for_inputs).await
            })
            .await
            .map_err(|e| Arc::new(DistributionError::Inputs(e.to_string())))?;
        build_from_inputs(
            &inputs,
            &self.window,
            &self.config,
            reference_revenue_sats,
            Some(claimant),
        )
        .await
        .map(Arc::new)
        .map_err(Arc::new)
    }

    /// Drops the built distributions AND the inputs; stale inputs would
    /// just rebuild the same stale distribution.
    pub fn invalidate_all(&self) {
        self.cache.clear();
        self.inputs_cache.clear();
    }

    /// The budget handle the autoscaler driver observes and writes.
    pub fn live_budget(&self) -> LiveBudget {
        self.config.coinbase_weight_budget.clone()
    }
}

// ── Internals ────────────────────────────────────────────────────────

/// The reward-independent half of a build. A window error propagates: the
/// window IS the shares and nothing may be invented. An unreadable ledger
/// only delays repayments, so the build goes on by score with zero balances,
/// which settlement recomputes exactly; failing would blank every PPLNS job.
async fn load_inputs(
    pool: &PgPool,
    window: &WindowStore,
) -> Result<DistributionInputs, DistributionError> {
    let window_raw = window.read_window_by_address().await?;

    let balances = match find_pplns_balances_with_open_balance(pool).await {
        Ok(rows) => open_balance_rows_to_balance_map(&rows),
        Err(err) => {
            error!(
                %err,
                "pplns distribution: ledger unreadable — building this distribution by SCORE \
                 ONLY. Standing balances are untouched and are repaid from a later block; a \
                 block found meanwhile still pays correctly and books. Fix the database."
            );
            HashMap::new()
        }
    };

    // An invalid window address is skipped, not fatal: one lost share beats
    // a failed distribution.
    Ok(DistributionInputs {
        address_shares: share_map_from_redis_hash(
            &window_raw,
            "pplns distribution: skipping invalid address in window — likely from a buggy upstream",
        ),
        balances,
    })
}

/// Project the shared inputs onto weights and persist the snapshot.
async fn build_from_inputs(
    inputs: &DistributionInputs,
    window: &WindowStore,
    config: &DistributionConfig,
    reference_revenue_sats: u64,
    bootstrap_claimant: Option<&AddressId>,
) -> Result<BuiltDistribution, DistributionError> {
    let fee_address = config
        .fee_address
        .as_ref()
        .ok_or(DistributionError::NoFeeAddress)?;
    let mut conn = window.connection_for_snapshot();
    let built = build_and_snapshot(
        BuildRequest {
            address_shares: inputs.address_shares.clone(),
            balances: inputs.balances.clone(),
            fee_address,
            fee_percent: config.fee_percent,
            min_payout_sats: config.min_payout_sats,
            coinbase_weight_budget: config.coinbase_weight_budget.get(),
            finder_bonus_ppm: 0, // finder-bonus is a Group-Solo feature
            finder_address: None,
            reference_revenue_sats,
            // PPLNS keeps withheld value inside the miners' cut and owes it
            // in `pplns_balance`, so a small miner accumulates to `min_payout`.
            withheld_value: bp_pplns::WithheldValue::ToOtherMiners,
            bootstrap_claimant,
            scope: "pplns",
        },
        &mut conn,
        config.snapshot_ttl_secs,
    )
    .await?;

    // Informational only: a failed write leaves the API without the count.
    let published = built.distribution.published().count();
    if let Err(err) = window
        .write_published_outputs(published, config.snapshot_ttl_secs)
        .await
    {
        warn!(%err, "pplns: published-output count write failed");
    }

    config
        .coinbase_weight_budget
        .record_sample(built.distribution.budget_telemetry);

    Ok(built)
}

fn open_balance_rows_to_balance_map(rows: &[PplnsBalanceRow]) -> HashMap<AddressId, Sats> {
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        out.insert(row.address.clone(), row.balance_sats);
    }
    out
}

/// Build, then persist the settlement inputs under the fingerprint. A failed
/// snapshot write does not fail the build: it costs a manual reprocess if a
/// block lands, a missing job costs every miner.
async fn build_and_snapshot(
    req: BuildRequest<'_>,
    conn: &mut redis::aio::ConnectionManager,
    ttl_secs: u32,
) -> Result<BuiltDistribution, WeightBuildError> {
    let distribution = sanitize_and_build(req)?;

    // Settlement books `claim(T_actual) − paid` from the real coinbase, so one
    // snapshot serves every job built from this distribution, JDC jobs included.
    let snapshot = StoredWeightSnapshot::from_distribution(&distribution);
    let key = crate::window::snapshot_key_for(&distribution.fingerprint);
    let bookable = write_with_retry(conn, &key, &snapshot, ttl_secs).await;

    Ok(BuiltDistribution {
        distribution,
        bookable,
    })
}

async fn write_with_retry(
    conn: &mut redis::aio::ConnectionManager,
    key: &str,
    snapshot: &StoredWeightSnapshot,
    ttl_secs: u32,
) -> bool {
    let mut attempt = 0;
    loop {
        match write_weight_snapshot(conn, key, snapshot, ttl_secs).await {
            Ok(()) => return true,
            Err(err) if attempt < SNAPSHOT_WRITE_RETRIES => {
                warn!(%err, attempt, "pplns: snapshot write failed — retrying");
                attempt += 1;
                tokio::time::sleep(SNAPSHOT_WRITE_BACKOFF * attempt).await;
            }
            Err(err) => {
                warn!(
                    %err,
                    key,
                    "pplns: snapshot write failed after retries — the coinbase distribution \
                     stands, but a block found on this job cannot be booked automatically and \
                     needs operator reprocessing from the block's own coinbase"
                );
                return false;
            }
        }
    }
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
}
