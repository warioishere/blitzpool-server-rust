// SPDX-License-Identifier: AGPL-3.0-or-later

//! `DistributionBuilder` — production-side wrapper around
//! `bp_group_solo::build_group_solo_distribution`.
//!
//! Reads the group's round state from Redis (`by-address` hash),
//! the group's open balances from Postgres, and the group's
//! per-group config row (`finder_bonus_sats`) from the
//! `pplns_group` table. Calls the pure-math distribution builder
//! with `suppress_matching_debits = true` (Group-Solo never goes
//! negative), then persists a per-(group, finder) snapshot.
//!
//! Concurrent callers for the same `(group_id, block_reward_sats,
//! finder_address)` triple share one compute via the in-flight cache
//! (30s TTL by default).
//! Different finders within the same group still compute
//! independently because every miner's session calls
//! `build_distribution` with their own address as the prospective
//! finder.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bp_coinbase_snapshot::share_map_from_redis_hash;
use bp_common::{AddressId, Sats};
use bp_db::{find_group, find_pplns_group_balances_for_group, DbError, PplnsGroupBalanceRow};
use bp_inflight_cache::InflightResultCache;
use bp_pplns::{
    build_coinbase_distribution, is_valid_payout_address, CoinbaseDistributionEntry,
    CoinbaseDistributionInput,
};
use bp_share::payouts_fingerprint_from_parts;
use sqlx::PgPool;
use thiserror::Error;
use tracing::{error, warn};
use uuid::Uuid;

use crate::round::snapshot::{write_snapshot, write_snapshot_for, StoredSnapshot};
use crate::round::{GroupRoundStore, RoundError};

/// Default cache TTL for `DistributionBuilder::build` (30 s).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

/// How often the payout-list snapshot write is retried before the job goes out
/// without one. Kept small — this sits on the path that gates the first job
/// after a template change.
const SNAPSHOT_WRITE_RETRIES: u32 = 2;
/// Backoff between those attempts, multiplied by the attempt number.
const SNAPSHOT_WRITE_BACKOFF: Duration = Duration::from_millis(40);

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
}

/// Cache key — concurrent calls with the same triple share one compute.
type CacheKey = (Uuid, u64, String);

/// Result of one Group-Solo distribution build. Cloneable via `Arc`
/// in the in-flight cache.
#[derive(Clone, Debug)]
pub struct DistributionResult {
    pub group_id: Uuid,
    pub finder_address: AddressId,
    pub payouts: Vec<CoinbaseDistributionEntry>,
    pub considered_addresses: HashSet<AddressId>,
    /// Absolute new `pendingSats` per address whose state changed.
    /// Always `≥ 0` for Group-Solo.
    pub balance_after: HashMap<AddressId, Sats>,
    pub block_reward_sats: u64,
    /// Identity of `payouts` + the reward it was built over — the key this
    /// build's snapshot is stored under.
    ///
    /// The Stratum job build derives the same value independently from the
    /// `PayoutEntry` list it turns into the coinbase, and a found block carries
    /// it. That is what lets the block-found path ask for the distribution its
    /// own coinbase pays instead of building a fresh one against a round that
    /// has moved. See [`bp_share::payouts_fingerprint_from_parts`].
    pub payouts_fingerprint: [u8; 32],
    /// Did the snapshot under `payouts_fingerprint` actually get written?
    ///
    /// `false` means the build succeeded but its snapshot did not land (after
    /// retries), so the fingerprint names a key that does not exist. The
    /// distribution still becomes a coinbase — failing the build would hand the
    /// finder a solo job paying itself the group's block. But a caller that
    /// promises a found block will be booked automatically MUST NOT promise on a
    /// `false`; the booking would resolve to nothing.
    pub snapshot_written: bool,
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
    // 1. Per-group config: finder_bonus_sats lives in the DB row.
    let group_row = find_group(pool, group_id)
        .await?
        .ok_or(DistributionError::GroupNotFound { group_id })?;
    let finder_bonus_sats = group_row.finder_bonus_sats;

    // 2. Round state from Redis. Mode-aware: a PROP group reads its per-round
    //    aggregate; a Window group trims to the sliding window first, so the
    //    built distribution is always fenster-current (even for an idle group).
    let (mode, window_ms) = crate::engine::group_mode_from_row(&group_row);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let round_raw = round
        .read_payout_shares(&group_id.to_string(), mode, now_ms, window_ms)
        .await?;
    let mut address_shares = share_map_from_redis_hash(
        &round_raw,
        "group-solo distribution: skipping invalid address in round state",
    );

    // 3. Open balances for this group from PG.
    let balance_rows = find_pplns_group_balances_for_group(pool, group_id).await?;
    let mut balances = balance_rows_to_balance_map(&balance_rows);

    // Defensive sanitize (same as the PPLNS path): drop any address
    // that isn't a parseable Bitcoin address before it reaches the
    // coinbase builder. One unparseable round/ledger row would
    // otherwise abort the whole group coinbase build in `bp-mining-job`.
    let shares_before = address_shares.len();
    let balances_before = balances.len();
    address_shares.retain(|a, _| is_valid_payout_address(a.as_str()));
    balances.retain(|a, _| is_valid_payout_address(a.as_str()));
    let dropped = (shares_before - address_shares.len()) + (balances_before - balances.len());
    if dropped > 0 {
        warn!(
            %group_id,
            dropped,
            shares_dropped = shares_before - address_shares.len(),
            balances_dropped = balances_before - balances.len(),
            "group-solo distribution: dropped unparseable payout addresses before coinbase build"
        );
    }

    // 4. Build inputs + call pure math. `bp_group_solo::build_group_solo_distribution`
    //    is a thin wrapper over `bp_pplns::build_coinbase_distribution` that
    //    flips `suppress_matching_debits = true` and forwards finder
    //    fields, but it expects a `GroupRoundState` (in-process struct).
    //    Since we hold the round state in Redis, we call the underlying
    //    pure-math function directly with the same flag. Identical
    //    behavior, skips the round-state-construction round-trip.
    let input = CoinbaseDistributionInput {
        address_shares: &address_shares,
        balances: &balances,
        block_reward_sats: Sats(block_reward_sats as i64),
        fee_percent: config.fee_percent,
        fee_address: config.fee_address.as_ref(),
        coinbase_weight_budget: config.coinbase_weight_budget,
        suppress_matching_debits: true, // Group-Solo invariant
        min_payout_sats: Some(config.min_payout_sats),
        finder_bonus_sats,
        finder_address: Some(finder_address),
    };
    let math = build_coinbase_distribution(input);

    // 5. Persist the snapshot under the identity of the payout list it
    //    distributes. Nothing else writes that key, so it still holds THIS
    //    distribution when the block that mined it is found, however many
    //    rebuilds ran in between. The per-(group, finder) key is written
    //    alongside it for the manual reprocess path — it is last-writer-wins
    //    by design and no automatic apply reads it.
    // Records the ledger state this distribution was computed against, so the
    // apply can write a delta instead of an absolute. The snapshot is resolved
    // at block-found from the job that mined the block, which may be many
    // minutes old — an absolute write would silently roll back whatever moved
    // `pendingSats` since (a kick redistribution, a dust sweep, another block).
    let snapshot = StoredSnapshot::from_math_with_before(
        &math.payouts,
        block_reward_sats,
        &math.considered_addresses,
        &math.balance_after,
        &balances,
    );
    let payouts_fingerprint = payouts_fingerprint_from_parts(
        block_reward_sats,
        math.payouts
            .iter()
            .map(|p| (p.address.as_str(), p.sats.to_i64().max(0) as u64)),
    );
    let group_key = group_id.to_string();
    // Neither write may fail the build. The distribution itself is correct and
    // is about to become a coinbase; returning `Err` here sends
    // `group_solo_payouts` into its solo fallback, and that miner is handed a
    // job paying 100 % of the block to itself. Losing the snapshot costs a
    // manual reprocess if a block lands on this job — losing the distribution
    // costs the group the whole block.
    let mut conn_fp = round.connection_for_snapshot();
    let mut conn_finder = round.connection_for_snapshot();
    let (by_fingerprint, by_finder) = tokio::join!(
        write_snapshot_for_with_retry(
            &mut conn_fp,
            &group_key,
            &payouts_fingerprint,
            &snapshot,
            config.snapshot_ttl_secs,
        ),
        write_snapshot(
            &mut conn_finder,
            &group_key,
            finder_address.as_str(),
            &snapshot,
            config.snapshot_ttl_secs,
        ),
    );
    // The by-fingerprint write is the one a booking resolves, so it alone
    // decides whether this build may be vouched for.
    let snapshot_written = match by_fingerprint {
        Ok(()) => true,
        Err(err) => {
            error!(
                %err,
                %group_id,
                block_reward_sats,
                fingerprint = %hex::encode(payouts_fingerprint),
                "group-solo snapshot write failed after retries — the coinbase distribution \
                 stands, but a block found on this job cannot be booked automatically and needs \
                 operator reprocessing from the block's own coinbase"
            );
            false
        }
    };
    if let Err(err) = by_finder {
        warn!(%err, %group_id, "group-solo per-finder snapshot write failed");
    }

    Ok(DistributionResult {
        group_id,
        finder_address: finder_address.clone(),
        payouts: math.payouts,
        considered_addresses: math.considered_addresses,
        balance_after: math.balance_after,
        block_reward_sats,
        payouts_fingerprint,
        snapshot_written,
    })
}

/// Write the payout-list snapshot, retrying a transient Redis failure.
///
/// Two reasons this is worth retrying rather than logging once. The job it
/// belongs to is about to go out to a miner, and a block found on it can only
/// be booked from this key. And the write is `DEL` + `HSET` + `EXPIRE`: a
/// failure in the middle leaves the key *deleted*, so a build that would have
/// been a harmless no-op rewrite of an existing snapshot can destroy it. A
/// re-run repairs exactly that.
async fn write_snapshot_for_with_retry(
    conn: &mut redis::aio::ConnectionManager,
    group_key: &str,
    payouts_fingerprint: &[u8; 32],
    snapshot: &StoredSnapshot,
    ttl_secs: u32,
) -> Result<(), redis::RedisError> {
    let mut attempt = 0;
    loop {
        match write_snapshot_for(conn, group_key, payouts_fingerprint, snapshot, ttl_secs).await {
            Ok(()) => return Ok(()),
            Err(err) if attempt < SNAPSHOT_WRITE_RETRIES => {
                warn!(
                    %err,
                    group_id = group_key,
                    attempt,
                    "group-solo snapshot write failed — retrying"
                );
                attempt += 1;
                tokio::time::sleep(SNAPSHOT_WRITE_BACKOFF * attempt).await;
            }
            Err(err) => return Err(err),
        }
    }
}

fn balance_rows_to_balance_map(rows: &[PplnsGroupBalanceRow]) -> HashMap<AddressId, Sats> {
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        out.insert(row.address.clone(), row.pending_sats);
    }
    out
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
    fn balance_rows_to_map_preserves_pending_sats() {
        let rows = vec![PplnsGroupBalanceRow {
            address: AddressId::new("bc1qpending").unwrap(),
            group_id: Uuid::new_v4(),
            pending_sats: Sats(5_000),
            total_paid_sats: Sats(0),
            updated_at: 0,
            last_accepted_share_at: None,
        }];
        let map = balance_rows_to_balance_map(&rows);
        assert_eq!(map[&AddressId::new("bc1qpending").unwrap()].0, 5_000);
    }

    #[test]
    fn distribution_result_is_cloneable() {
        let r = DistributionResult {
            group_id: Uuid::new_v4(),
            finder_address: AddressId::new("bc1qfinder").unwrap(),
            payouts: vec![],
            considered_addresses: HashSet::new(),
            balance_after: HashMap::new(),
            block_reward_sats: 312_500_000,
            payouts_fingerprint: [0u8; 32],
            snapshot_written: true,
        };
        let cloned = r.clone();
        assert_eq!(cloned.block_reward_sats, 312_500_000);
    }
}
