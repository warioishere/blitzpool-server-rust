// SPDX-License-Identifier: AGPL-3.0-or-later

//! `DistributionBuilder` — the Group-Solo side of the shared
//! build-and-snapshot path.
//!
//! Reads the group's round state from Redis (`by-address` hash) and
//! the group's per-group config row (`finder_bonus_ppm`) from the
//! `pplns_group` table, calls the shared weight builder with
//! [`WithheldValue::ToPool`], then persists a per-(group, finder)
//! snapshot.
//!
//! There is no ledger read: Group-Solo owes nothing between blocks.
//!
//! Concurrent callers for the same `(group_id, block_reward_sats,
//! finder_address)` triple share one compute via the in-flight cache
//! (30s TTL by default).
//! Different finders within the same group still compute
//! independently because every miner's session calls
//! `build_distribution` with their own address as the prospective
//! finder.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bp_coinbase_snapshot::{
    build_and_snapshot, share_map_from_redis_hash, BuildRequest, StoredWeightSnapshot,
};
use bp_common::{AddressId, Sats};
use bp_db::{find_group, DbError};
use bp_inflight_cache::InflightResultCache;
use bp_pplns::{WeightBuildError, WeightDistribution, WithheldValue};
use sqlx::PgPool;
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

use crate::round::snapshot::write_weight_snapshot;
use crate::round::{GroupRoundStore, RoundError};

/// Default cache TTL for `DistributionBuilder::build` (30 s).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Error)]
pub enum DistributionError {
    #[default]
    #[error("inflight leader dropped without publishing — retry")]
    LeaderDropped,
    #[error("round: {0}")]
    Round(#[from] RoundError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("group {group_id} not found in pplns_group")]
    GroupNotFound { group_id: Uuid },
    /// The weight model has no distribution without a pool-output
    /// recipient — `pay_P` is structural (SV2 ext 0x0003 §4).
    #[error("no fee address configured — the weight model requires the pool-output recipient")]
    NoFeeAddress,
    #[error("weight build: {0}")]
    WeightBuild(#[from] WeightBuildError),
}

/// Cache key — concurrent calls with the same triple share one compute.
type CacheKey = (Uuid, u64, String);

/// Result of one Group-Solo distribution build. Cloneable via `Arc`
/// in the in-flight cache.
#[derive(Clone, Debug)]
pub struct DistributionResult {
    pub group_id: Uuid,
    pub finder_address: AddressId,
    /// The weight-native distribution (SV2 ext 0x0003 model): entries
    /// with settlement inputs + published wire weights, `weight_P`, the
    /// finder bonus recorded for settlement, and the weights
    /// fingerprint. Concrete satoshis come from
    /// [`WeightDistribution::payout_entries_at`] at the caller's
    /// revenue.
    pub distribution: WeightDistribution,
    /// Did the schema-2 snapshot under the fingerprint actually get
    /// written (after retries)? `false` → the distribution still
    /// becomes a coinbase, but a block found on it cannot be booked
    /// automatically — never promise a booking on `false`.
    pub snapshot_written: bool,
}

impl DistributionResult {
    /// The snapshot key this build landed under.
    pub fn payouts_fingerprint(&self) -> [u8; 32] {
        self.distribution.fingerprint
    }
}

/// Engine-wide knobs for the distribution path. Per-group settings
/// (finder bonus) live in the DB row, NOT here.
#[derive(Clone, Debug)]
pub struct DistributionConfig {
    pub fee_address: Option<AddressId>,
    pub fee_percent: f64,
    pub min_payout_sats: Sats,
    pub coinbase_weight_budget: u32,
    pub snapshot_ttl_secs: u32,
}

impl DistributionConfig {
    pub fn from_engine_config(cfg: &crate::config::GroupSoloEngineConfig) -> Self {
        Self {
            fee_address: cfg.fee_address.clone(),
            fee_percent: cfg.fee_percent,
            min_payout_sats: cfg.min_payout_sats,
            coinbase_weight_budget: cfg.coinbase_weight_budget,
            snapshot_ttl_secs: cfg.snapshot_ttl_secs,
        }
    }
}

#[derive(Clone)]
pub struct DistributionBuilder {
    pool: PgPool,
    round: GroupRoundStore,
    config: DistributionConfig,
    cache: InflightResultCache<CacheKey, DistributionResult, DistributionError>,
}

impl DistributionBuilder {
    pub fn new(pool: PgPool, round: GroupRoundStore, config: DistributionConfig) -> Self {
        Self::with_cache_ttl(pool, round, config, DEFAULT_CACHE_TTL)
    }

    pub fn with_cache_ttl(
        pool: PgPool,
        round: GroupRoundStore,
        config: DistributionConfig,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            pool,
            round,
            config,
            cache: InflightResultCache::new(cache_ttl),
        }
    }

    /// Build the current Group-Solo distribution for a given
    /// `(group_id, block_reward_sats, finder_address)`. Concurrent
    /// callers for the same triple share one compute.
    pub async fn build(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<Arc<DistributionResult>, Arc<DistributionError>> {
        let key: CacheKey = (
            group_id,
            block_reward_sats,
            finder_address.as_str().to_string(),
        );
        let pool = self.pool.clone();
        let round = self.round.clone();
        let config = self.config.clone();
        let finder = finder_address.clone();
        self.cache
            .get_or_compute(key, move || async move {
                compute_distribution(&pool, &round, &config, group_id, block_reward_sats, &finder)
                    .await
            })
            .await
    }

    /// Invalidate the cache for one (group, reward, finder) triple.
    pub fn invalidate(&self, group_id: Uuid, block_reward_sats: u64, finder_address: &AddressId) {
        let key: CacheKey = (
            group_id,
            block_reward_sats,
            finder_address.as_str().to_string(),
        );
        self.cache.invalidate(&key);
    }

    pub fn invalidate_all(&self) {
        self.cache.clear();
    }
}

// ── Internals ────────────────────────────────────────────────────────

async fn compute_distribution(
    pool: &PgPool,
    round: &GroupRoundStore,
    config: &DistributionConfig,
    group_id: Uuid,
    block_reward_sats: u64,
    finder_address: &AddressId,
) -> Result<DistributionResult, DistributionError> {
    // 1. Per-group config: the finder bonus lives in the DB row, as a
    //    FRACTION of the miner cut (ppm) rather than a sats amount —
    //    a proportion is what §4 can pay exactly at any revenue.
    let group_row = find_group(pool, group_id)
        .await?
        .ok_or(DistributionError::GroupNotFound { group_id })?;
    let finder_bonus_ppm = group_row.finder_bonus_ppm.unwrap_or(0).max(0) as u32;

    // 2. Round state from Redis. Mode-aware: a PROP group reads its per-round
    //    aggregate; a Window group trims to the sliding window first, so the
    //    built distribution is always fenster-current (even for an idle group).
    let (mode, window_ms) = crate::engine::group_mode_from_row(&group_row);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let round_raw = round
        .read_payout_shares(&group_id.to_string(), mode, now_ms, window_ms)
        .await?;
    let address_shares = share_map_from_redis_hash(
        &round_raw,
        "group-solo distribution: skipping invalid address in round state",
    );

    // 3-5. No ledger to read: Group-Solo carries no balances (see the
    //      crate docs), so the empty map is what the shared builder
    //      expects from a mode that promises nothing across blocks.
    //      Sanitize, project onto weights and persist the snapshot are
    //      the one path both payout engines share.
    let fee_address = config
        .fee_address
        .as_ref()
        .ok_or(DistributionError::NoFeeAddress)?;
    let group_key = group_id.to_string();
    let mut conn_fp = round.connection_for_snapshot();
    let built = build_and_snapshot(
        BuildRequest {
            address_shares,
            balances: HashMap::new(),
            fee_address,
            fee_percent: config.fee_percent,
            min_payout_sats: config.min_payout_sats,
            coinbase_weight_budget: config.coinbase_weight_budget,
            finder_bonus_ppm,
            finder_address: Some(finder_address),
            // The prospective finder claims the block if the round turns
            // out to be empty. Every caller of `build_distribution`
            // already supplies them (the job path and the JDP tailored
            // push both build per-finder), and the in-flight cache is
            // keyed per-finder too, so a bootstrap distribution can never
            // be served to a different member.
            //
            // This is the mode where the empty round is ROUTINE rather
            // than exotic: `reset_for_block_found` / `reset_full` /
            // `manual_reset` all DEL the round's by-address hash, and
            // `read_by_address` has no bucket fallback to soften it.
            bootstrap_claimant: Some(finder_address),
            reference_revenue_sats: block_reward_sats,
            // Group-Solo: a member the coinbase cannot pay forfeits this
            // block and their share falls to the pool output. Nobody is
            // overpaid, so nothing has to be remembered until the next
            // block — which is what lets this mode run without a ledger.
            withheld_value: WithheldValue::ToPool,
            scope: "group-solo",
        },
        &mut conn_fp,
        |fp| crate::round::snapshot::key_for_fingerprint(&group_key, fp),
        config.snapshot_ttl_secs,
    )
    .await?;

    // The per-(group, finder) key is written alongside for the manual
    // reprocess path. Best-effort: the fingerprint key above is the one
    // a booking resolves, and it alone decides `snapshot_written`.
    let snapshot = StoredWeightSnapshot::from_distribution(&built.distribution);
    let mut conn_finder = round.connection_for_snapshot();
    if let Err(err) = write_weight_snapshot(
        &mut conn_finder,
        &group_key,
        finder_address.as_str(),
        &snapshot,
        config.snapshot_ttl_secs,
    )
    .await
    {
        warn!(%err, %group_id, "group-solo per-finder snapshot write failed");
    }

    Ok(DistributionResult {
        group_id,
        finder_address: finder_address.clone(),
        distribution: built.distribution,
        snapshot_written: built.snapshot_written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_pplns::{build_weight_distribution, WeightDistributionInput};

    #[test]
    fn distribution_config_from_engine_config_carries_fields() {
        let engine_cfg = crate::config::GroupSoloEngineConfig {
            fee_address: Some(AddressId::new("bc1qfee0000000000000000000000000").unwrap()),
            fee_percent: 1.5,
            coinbase_weight_budget: 60_000,
            snapshot_ttl_secs: 1800,
            ..crate::config::GroupSoloEngineConfig::default()
        };
        let dist_cfg = DistributionConfig::from_engine_config(&engine_cfg);
        assert_eq!(
            dist_cfg.fee_address.as_ref().unwrap().as_str(),
            "bc1qfee0000000000000000000000000"
        );
        assert!((dist_cfg.fee_percent - 1.5).abs() < 1e-9);
        assert_eq!(dist_cfg.coinbase_weight_budget, 60_000);
        assert_eq!(dist_cfg.snapshot_ttl_secs, 1800);
    }

    #[test]
    fn distribution_result_is_cloneable() {
        let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let fee = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let shares = HashMap::from([(finder.clone(), 2.0)]);
        let balances = HashMap::new();
        let distribution = build_weight_distribution(WeightDistributionInput {
            address_shares: &shares,
            balances: &balances,
            fee_percent: 1.0,
            fee_address: &fee,
            coinbase_weight_budget: 50_000,
            min_payout_sats: Some(Sats(5_000)),
            finder_bonus_ppm: 160_000,
            finder_address: Some(&finder),
            reference_revenue_sats: 312_500_000,
            withheld_value: WithheldValue::ToPool,
        })
        .unwrap();
        let r = DistributionResult {
            group_id: Uuid::new_v4(),
            finder_address: finder,
            distribution,
            snapshot_written: true,
        };
        let cloned = r.clone();
        assert_eq!(cloned.payouts_fingerprint(), r.payouts_fingerprint());
        assert_eq!(cloned.distribution.reference_revenue_sats, 312_500_000);
    }
}
