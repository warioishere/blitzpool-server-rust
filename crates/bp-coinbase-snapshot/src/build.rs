// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one build-and-persist path both payout engines run.
//!
//! PPLNS and Group-Solo differ in where their share state comes from and
//! in what the weights mean — but between "here are the shares" and
//! "here is a distribution whose snapshot is on disk" they do the same
//! three things: drop unusable addresses, project onto weights, persist
//! the settlement inputs under the fingerprint.
//!
//! That middle stretch used to exist twice, and it drifted: one side
//! retried a failed snapshot write, the other gave up on the first
//! error. Both had had the same bug fixed separately once already
//! (PRs #5 and #6, a day apart). One copy is the point of this module.
//!
//! What deliberately stays with each engine: reading its own share
//! state, its in-flight cache (the cache key is genuinely per-mode), and
//! anything it does afterwards — the PPLNS autoscaler sample, the
//! Group-Solo per-finder snapshot key.

use std::collections::HashMap;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_pplns::{
    build_weight_distribution, is_valid_payout_address, WeightBuildError, WeightDistribution,
    WeightDistributionInput, WithheldValue,
};
use redis::aio::ConnectionManager;
use tracing::warn;

use crate::snapshot::{write_weight_snapshot, StoredWeightSnapshot};

/// How often a failed snapshot write is retried before the job goes out
/// without one.
///
/// Worth retrying rather than logging once: the job this belongs to is
/// about to go to a miner, and a block found on it can only be booked
/// from this key. The write is also `DEL` + `HSET` + `EXPIRE`, so a
/// failure in the middle leaves the key *deleted* — a build that would
/// have been a harmless rewrite of an existing snapshot can destroy one.
/// A re-run repairs exactly that.
const SNAPSHOT_WRITE_RETRIES: u32 = 2;
/// Backoff between those attempts, multiplied by the attempt number.
const SNAPSHOT_WRITE_BACKOFF: Duration = Duration::from_millis(40);

/// Everything the weight model needs that the two modes disagree on.
/// The share and balance maps come in by value because the sanitize pass
/// consumes them; both callers build them fresh per build anyway.
pub struct BuildRequest<'a> {
    pub address_shares: HashMap<AddressId, f64>,
    /// Signed ledger balances. Group-Solo passes an empty map — it keeps
    /// no ledger, so it promises nothing across blocks.
    pub balances: HashMap<AddressId, Sats>,
    pub fee_address: &'a AddressId,
    pub fee_percent: f64,
    pub min_payout_sats: Sats,
    pub coinbase_weight_budget: u32,
    /// Group-Solo's per-group finder bonus; 0 for PPLNS.
    pub finder_bonus_ppm: u32,
    pub finder_address: Option<&'a AddressId>,
    pub reference_revenue_sats: u64,
    pub withheld_value: WithheldValue,
    /// Prefix for the log lines, e.g. `"pplns"` / `"group-solo"`.
    pub scope: &'static str,
}

/// A built distribution plus whether its snapshot actually landed.
pub struct BuiltDistribution {
    pub distribution: WeightDistribution,
    /// `false` → the distribution still becomes a coinbase, but a block
    /// found on it cannot be booked automatically. Never promise a
    /// booking on `false`.
    pub snapshot_written: bool,
}

/// Sanitize, build, persist.
///
/// A failed snapshot write does NOT fail the build. The distribution is
/// correct and is about to become a coinbase; returning `Err` here sends
/// the caller into its solo fallback, and that miner is handed a job
/// paying the whole block to itself. Losing the snapshot costs a manual
/// reprocess if a block lands on this job — losing the distribution
/// costs the miners the block.
///
/// `snapshot_key` names the Redis key for a given fingerprint. It is a
/// closure rather than a ready-made key because the fingerprint only
/// exists once the distribution is built, and the two engines use
/// different key schemes (`pplns:snapshot:fp:…` vs
/// `groupsolo:{groupId}:snapshot:fp:…`).
///
/// Whatever this writes is read back by
/// [`crate::snapshot::resolve_snapshot_for_block_found`], through the
/// same seam. Change the key scheme here and it changes there; there is
/// no second place to forget.
pub async fn build_and_snapshot(
    mut req: BuildRequest<'_>,
    conn: &mut ConnectionManager,
    snapshot_key: impl FnOnce(&[u8; 32]) -> String,
    ttl_secs: u32,
) -> Result<BuiltDistribution, WeightBuildError> {
    // Drop anything that isn't a parseable Bitcoin address before it
    // reaches the coinbase builder. One unparseable row (junk, a
    // migration artifact, seed-test data) would otherwise abort the
    // whole coinbase build in `bp-mining-job` — its `address_to_script`
    // fails the entire transaction — and block every miner's job.
    // Dropping the row is strictly safer: it is simply not paid this
    // block, and for PPLNS it stays in the ledger.
    let shares_before = req.address_shares.len();
    let balances_before = req.balances.len();
    req.address_shares
        .retain(|a, _| is_valid_payout_address(a.as_str()));
    req.balances
        .retain(|a, _| is_valid_payout_address(a.as_str()));
    let shares_dropped = shares_before - req.address_shares.len();
    let balances_dropped = balances_before - req.balances.len();
    if shares_dropped + balances_dropped > 0 {
        warn!(
            scope = req.scope,
            shares_dropped,
            balances_dropped,
            "distribution: dropped unparseable payout addresses before the coinbase build"
        );
    }

    let distribution = build_weight_distribution(WeightDistributionInput {
        address_shares: &req.address_shares,
        balances: &req.balances,
        fee_percent: req.fee_percent,
        fee_address: req.fee_address,
        coinbase_weight_budget: req.coinbase_weight_budget,
        min_payout_sats: Some(req.min_payout_sats),
        finder_bonus_ppm: req.finder_bonus_ppm,
        finder_address: req.finder_address,
        reference_revenue_sats: req.reference_revenue_sats,
        withheld_value: req.withheld_value,
    })?;

    // Persist the settlement INPUTS under the weights fingerprint.
    // Nothing else writes that key, and because settlement books
    // `claim(T_actual) − paid` from the real coinbase, one snapshot
    // serves every job built from this distribution — the pool's own
    // templates and every JDC's alike.
    let snapshot = StoredWeightSnapshot::from_distribution(&distribution);
    let key = snapshot_key(&distribution.fingerprint);
    let snapshot_written = write_with_retry(conn, &key, &snapshot, ttl_secs, req.scope).await;

    Ok(BuiltDistribution {
        distribution,
        snapshot_written,
    })
}

async fn write_with_retry(
    conn: &mut ConnectionManager,
    key: &str,
    snapshot: &StoredWeightSnapshot,
    ttl_secs: u32,
    scope: &str,
) -> bool {
    let mut attempt = 0;
    loop {
        match write_weight_snapshot(conn, key, snapshot, ttl_secs).await {
            Ok(()) => return true,
            Err(err) if attempt < SNAPSHOT_WRITE_RETRIES => {
                warn!(%err, scope, attempt, "snapshot write failed — retrying");
                attempt += 1;
                tokio::time::sleep(SNAPSHOT_WRITE_BACKOFF * attempt).await;
            }
            Err(err) => {
                warn!(
                    %err,
                    scope,
                    key,
                    "snapshot write failed after retries — the coinbase distribution stands, \
                     but a block found on this job cannot be booked automatically and needs \
                     operator reprocessing from the block's own coinbase"
                );
                return false;
            }
        }
    }
}
