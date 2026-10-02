// SPDX-License-Identifier: AGPL-3.0-or-later

//! `DistributionBuilder`: the Group-Solo side of the shared weight build, with
//! [`WithheldValue::ToPool`], no ledger read and no snapshot, since Group-Solo
//! owes nothing between blocks and books a found block from its coinbase alone.
//! Builds are cached per `(group, reward, finder)` because each session is its
//! own prospective finder.

pub use bp_coinbase_snapshot::BuiltDistribution;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bp_coinbase_snapshot::{sanitize_and_build, share_map_from_redis_hash, BuildRequest};
use bp_common::{AddressId, Sats};
use bp_db::{find_group, DbError};
use bp_inflight_cache::InflightResultCache;
use bp_pplns::{WeightBuildError, WithheldValue};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

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

/// Engine-wide knobs for the distribution path. Per-group settings
/// (finder bonus) live in the DB row, NOT here.
#[derive(Clone, Debug)]
pub struct DistributionConfig {
    pub fee_address: Option<AddressId>,
    pub fee_percent: f64,
    pub min_payout_sats: Sats,
    pub coinbase_weight_budget: u32,
}

impl DistributionConfig {
    pub fn from_engine_config(cfg: &crate::config::GroupSoloEngineConfig) -> Self {
        Self {
            fee_address: cfg.fee_address.clone(),
            fee_percent: cfg.fee_percent,
            min_payout_sats: cfg.min_payout_sats,
            coinbase_weight_budget: cfg.coinbase_weight_budget,
        }
    }
}

#[derive(Clone)]
pub struct DistributionBuilder {
    pool: PgPool,
    round: GroupRoundStore,
    config: DistributionConfig,
    cache: InflightResultCache<CacheKey, BuiltDistribution, DistributionError>,
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
    ) -> Result<Arc<BuiltDistribution>, Arc<DistributionError>> {
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
) -> Result<BuiltDistribution, DistributionError> {
    // 1. Per-group config: the finder bonus lives in the DB row as a
    //    FRACTION of the miner cut (ppm), because a proportion is what §4
    //    can pay exactly at any revenue.
    let group_row = find_group(pool, group_id)
        .await?
        .ok_or(DistributionError::GroupNotFound { group_id })?;
    let finder_bonus_ppm = group_row.finder_bonus_ppm.unwrap_or(0).max(0) as u32;

    // 2. Round state from Redis. Mode-aware: a PROP group reads its per-round
    //    aggregate; a Window group trims to the sliding window first, so the
    //    built distribution is always current (even for an idle group).
    let (mode, window_ms) = crate::engine::group_mode_from_row(&group_row);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let round_raw = round
        .read_payout_shares(&group_id.to_string(), mode, now_ms, window_ms)
        .await?;
    let address_shares = share_map_from_redis_hash(
        &round_raw,
        "group-solo distribution: skipping invalid address in round state",
    );

    // 3. Group-Solo carries no balances, so the balance map is empty.
    let fee_address = config
        .fee_address
        .as_ref()
        .ok_or(DistributionError::NoFeeAddress)?;
    let distribution = sanitize_and_build(BuildRequest {
        address_shares,
        balances: HashMap::new(),
        fee_address,
        fee_percent: config.fee_percent,
        min_payout_sats: config.min_payout_sats,
        coinbase_weight_budget: config.coinbase_weight_budget,
        finder_bonus_ppm,
        finder_address: Some(finder_address),
        // An empty round is routine (every reset DELs the hash); builds
        // are per-finder, so a bootstrap distribution never reaches
        // another member.
        bootstrap_claimant: Some(finder_address),
        reference_revenue_sats: block_reward_sats,
        // A member the coinbase cannot pay forfeits to the pool output,
        // so nothing carries to the next block and no ledger is needed.
        withheld_value: WithheldValue::ToPool,
        scope: "group-solo",
    })?;

    // Booking needs only the coinbase, so every build is bookable.
    Ok(BuiltDistribution {
        distribution,
        bookable: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distribution_config_from_engine_config_carries_fields() {
        let engine_cfg = crate::config::GroupSoloEngineConfig {
            fee_address: Some(AddressId::new("bc1qfee0000000000000000000000000").unwrap()),
            fee_percent: 1.5,
            coinbase_weight_budget: 60_000,
            ..crate::config::GroupSoloEngineConfig::default()
        };
        let dist_cfg = DistributionConfig::from_engine_config(&engine_cfg);
        assert_eq!(
            dist_cfg.fee_address.as_ref().unwrap().as_str(),
            "bc1qfee0000000000000000000000000"
        );
        assert!((dist_cfg.fee_percent - 1.5).abs() < 1e-9);
        assert_eq!(dist_cfg.coinbase_weight_budget, 60_000);
    }
}
