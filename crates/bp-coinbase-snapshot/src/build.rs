// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one build-and-persist path both payout engines run.
//!
//! PPLNS and Group-Solo differ in where their share state comes from and
//! in what the weights mean — but between "here are the shares" and
//! "here is a distribution whose snapshot is on disk" they do the same
//! three things: drop unusable addresses, project onto weights, persist
//! the settlement inputs under the fingerprint. Keeping that stretch in
//! one place keeps the modes from drifting apart.
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
/// A block found on this job can only be booked from this key. The write
/// is `DEL` + `HSET` + `EXPIRE`, so a failure in the middle leaves the key
/// deleted; a re-run repairs exactly that.
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
    /// Who claims the block when the share source turns out to be EMPTY.
    ///
    /// An empty source would pay the whole block to the pool output, so
    /// [`build_weight_distribution`] refuses it
    /// ([`WeightBuildError::NoScoredMiners`]). Shares only come from jobs,
    /// though, so a new group could then never mine its first share. The
    /// asking miner named here becomes the sole scored claimant; with an
    /// empty source nobody else holds a claim, and the pool still takes
    /// exactly its fee via `weight_P`.
    ///
    /// This applies only to a provably EMPTY source, never to a build that
    /// failed on a Redis/Postgres fault: there the window likely holds
    /// miners whose claims could not be read.
    ///
    /// `None` wherever no single miner is asking (the pool-wide JDP
    /// publisher builds for every job-declaring client at once), which
    /// publishes nothing instead.
    pub bootstrap_claimant: Option<&'a AddressId>,
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
/// A failed snapshot write does NOT fail the build: the distribution is
/// correct, and an `Err` would leave the miner without a job. A lost
/// snapshot costs a manual reprocess if a block lands on this job; a lost
/// distribution costs every miner their hashing time.
///
/// `snapshot_key` is a closure because the fingerprint only exists once
/// the distribution is built, and the engines use different key schemes
/// (`pplns:snapshot:fp:…` vs `groupsolo:{groupId}:snapshot:fp:…`).
///
/// Whatever this writes is read back by
/// [`crate::snapshot::resolve_snapshot_for_block_found`], so a key scheme
/// change here changes there too.
pub async fn build_and_snapshot(
    req: BuildRequest<'_>,
    conn: &mut ConnectionManager,
    snapshot_key: impl FnOnce(&[u8; 32]) -> String,
    ttl_secs: u32,
) -> Result<BuiltDistribution, WeightBuildError> {
    let scope = req.scope;
    let distribution = sanitize_and_build(req)?;

    // Persist the settlement INPUTS under the weights fingerprint.
    // Nothing else writes that key, and because settlement books
    // `claim(T_actual) − paid` from the real coinbase, one snapshot
    // serves every job built from this distribution — the pool's own
    // templates and every JDC's alike.
    let snapshot = StoredWeightSnapshot::from_distribution(&distribution);
    let key = snapshot_key(&distribution.fingerprint);
    let snapshot_written = write_with_retry(conn, &key, &snapshot, ttl_secs, scope).await;

    Ok(BuiltDistribution {
        distribution,
        snapshot_written,
    })
}

/// Sanitize the inputs and build the distribution, applying the
/// empty-source bootstrap. **Pure — no I/O**, which is the point: every
/// decision in here moves satoshis, and none of it should need a Redis to
/// be exercised. [`build_and_snapshot`] is this plus the persistence.
pub fn sanitize_and_build(
    mut req: BuildRequest<'_>,
) -> Result<WeightDistribution, WeightBuildError> {
    // Drop anything that isn't a parseable Bitcoin address: one
    // unparseable row would fail `address_to_script` in `bp-mining-job`
    // and with it every miner's job. The dropped row is simply not paid
    // this block, and for PPLNS it stays in the ledger.
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

    // Owned separately from `req` so the retry below can add the
    // bootstrap claimant while `build` still borrows the rest of the
    // request.
    let mut shares = std::mem::take(&mut req.address_shares);
    let build = |shares: &HashMap<AddressId, f64>| {
        build_weight_distribution(WeightDistributionInput {
            address_shares: shares,
            balances: &req.balances,
            fee_percent: req.fee_percent,
            fee_address: req.fee_address,
            coinbase_weight_budget: req.coinbase_weight_budget,
            min_payout_sats: Some(req.min_payout_sats),
            finder_bonus_ppm: req.finder_bonus_ppm,
            finder_address: req.finder_address,
            reference_revenue_sats: req.reference_revenue_sats,
            withheld_value: req.withheld_value,
        })
    };

    // Empty source → the builder refuses (see `bootstrap_claimant`), and
    // the claimant is scored instead. Keyed off the BUILDER's verdict, not
    // `address_shares.is_empty()`: it also drops non-finite / non-positive
    // weights and the fee address, and that predicate lives in one place.
    //
    // A nominal weight of 1.0 is scale-invariant, so the claimant holds
    // the whole score space and is paid `(1 − fee) · T`; the result is an
    // ordinary distribution settling at `delta ≈ 0`. With `score_total`
    // non-zero, a standing PPLNS credit projects and is paid this block.
    let distribution = match build(&shares) {
        Err(WeightBuildError::NoScoredMiners) => {
            let Some(claimant) = req.bootstrap_claimant else {
                // No miner to name (pool-wide JDP publisher): publish
                // nothing.
                return Err(WeightBuildError::NoScoredMiners);
            };
            warn!(
                scope = req.scope,
                claimant = claimant.as_str(),
                "distribution: share source holds no scored miner — bootstrapping this block to \
                 the asking miner. Expected for a new group or a fresh window; if it persists, \
                 the share stream is not reaching the round."
            );
            shares.insert(claimant.clone(), 1.0);
            // One retry, not a loop: the claimant is now scored, so a
            // second `NoScoredMiners` can only mean the builder dropped
            // it (unpayable address, or it IS the fee address) — and then
            // there is genuinely nobody to pay.
            build(&shares)?
        }
        other => other?,
    };
    Ok(distribution)
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

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    use bp_pplns::WeightDistribution;

    const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const OTHER: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const FEE: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    const T: u64 = 312_500_000;
    /// 1.5 % of `T`, the pool's whole entitlement on one block.
    const FEE_ONLY: u64 = T * 15_000 / 1_000_000;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("valid test address")
    }

    fn request<'a>(
        shares: HashMap<AddressId, f64>,
        balances: HashMap<AddressId, Sats>,
        fee: &'a AddressId,
        claimant: Option<&'a AddressId>,
    ) -> BuildRequest<'a> {
        BuildRequest {
            address_shares: shares,
            balances,
            fee_address: fee,
            fee_percent: 1.5,
            min_payout_sats: Sats(5_000),
            coinbase_weight_budget: 50_000,
            finder_bonus_ppm: 0,
            finder_address: None,
            reference_revenue_sats: T,
            withheld_value: WithheldValue::ToOtherMiners,
            bootstrap_claimant: claimant,
            scope: "test",
        }
    }

    fn paid_to(d: &WeightDistribution, address: &str) -> u64 {
        d.payout_entries_at(T)
            .expect("§4 vector")
            .iter()
            .filter(|(a, _)| a.as_str() == address)
            .map(|(_, s)| *s)
            .sum()
    }

    /// MONEY: with a claimant named, an empty share source pays the
    /// ASKING MINER and leaves the pool exactly its fee, never the whole
    /// block.
    #[test]
    fn an_empty_source_with_a_claimant_pays_that_miner_not_the_pool() {
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = sanitize_and_build(request(
            HashMap::new(),
            HashMap::new(),
            &fee,
            Some(&claimant),
        ))
        .expect("a named claimant must make an empty source buildable");

        assert!(
            paid_to(&d, FEE).abs_diff(FEE_ONLY) <= 2,
            "pool took {} where its fee is {FEE_ONLY}",
            paid_to(&d, FEE)
        );
        assert!(
            paid_to(&d, MINER).abs_diff(T - FEE_ONLY) <= 2,
            "the asking miner got {} of the {} the pool does not keep",
            paid_to(&d, MINER),
            T - FEE_ONLY
        );
        assert_eq!(
            d.payout_entries_at(T)
                .unwrap()
                .iter()
                .map(|(_, s)| *s)
                .sum::<u64>(),
            T,
            "Σ == T"
        );

        // And it settles flat, so a bootstrap block leaves no liability.
        let entry = d
            .entries
            .iter()
            .find(|e| e.address.as_str() == MINER)
            .expect("the claimant is an entry");
        let claim = bp_share::claim_sats(
            entry.score_weight,
            d.score_total,
            d.fee_ppm,
            T,
            d.extras_total,
        );
        assert!(
            (claim - paid_to(&d, MINER) as i64).abs() <= 2,
            "claim {claim} vs paid {} — a bootstrap block must not book a delta",
            paid_to(&d, MINER)
        );
    }

    /// With NO claimant the refusal stands (the pool-wide JDP publisher's
    /// case): nothing is published rather than a coinbase paying the pool
    /// 100 %.
    #[test]
    fn an_empty_source_without_a_claimant_stays_refused() {
        let fee = addr(FEE);
        assert_eq!(
            sanitize_and_build(request(HashMap::new(), HashMap::new(), &fee, None)),
            Err(WeightBuildError::NoScoredMiners)
        );
    }

    /// The claimant must never displace a real share source, or every
    /// miner would be handed the whole block on every job.
    #[test]
    fn a_populated_source_ignores_the_claimant() {
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = sanitize_and_build(request(
            HashMap::from([(addr(OTHER), 1.0)]),
            HashMap::new(),
            &fee,
            Some(&claimant),
        ))
        .expect("build");
        assert_eq!(d.entries.len(), 1, "only the real miner is an entry");
        assert_eq!(d.entries[0].address.as_str(), OTHER);
        assert_eq!(
            paid_to(&d, MINER),
            0,
            "the claimant must not be paid on a populated window"
        );
    }

    /// A source that is empty only AFTER sanitizing counts as empty: the
    /// bootstrap keys off the builder's verdict, not the raw map length.
    #[test]
    fn a_source_of_only_unpayable_addresses_bootstraps_too() {
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = sanitize_and_build(request(
            HashMap::from([(AddressId::new("synthseed800001").unwrap(), 100.0)]),
            HashMap::new(),
            &fee,
            Some(&claimant),
        ))
        .expect("junk-only source must bootstrap, not pay the pool");
        assert!(paid_to(&d, MINER).abs_diff(T - FEE_ONLY) <= 2);
    }

    /// A standing PPLNS credit on an empty window is PAID: its boost is
    /// `extra · score_total / divisor`, which needs the claimant scored to
    /// be non-zero.
    #[test]
    fn the_bootstrap_lets_a_standing_credit_be_paid() {
        const CREDIT: i64 = 10_000_000;
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = sanitize_and_build(request(
            HashMap::new(),
            HashMap::from([(addr(OTHER), Sats(CREDIT))]),
            &fee,
            Some(&claimant),
        ))
        .expect("build");

        assert!(
            paid_to(&d, OTHER).abs_diff(CREDIT as u64) <= 2,
            "the credit holder was paid {} of its {CREDIT} sat credit",
            paid_to(&d, OTHER)
        );
        // And the credit clears rather than being paid again next block.
        let entry = d
            .entries
            .iter()
            .find(|e| e.address.as_str() == OTHER)
            .expect("entry");
        let claim = bp_share::claim_sats(
            entry.score_weight,
            d.score_total,
            d.fee_ppm,
            T,
            d.extras_total,
        );
        let balance_after = entry.balance_sats + (claim - paid_to(&d, OTHER) as i64);
        assert!(
            balance_after.abs() <= 2,
            "the credit must settle to 0, left at {balance_after}"
        );
        // The pool still takes only its fee.
        assert!(paid_to(&d, FEE).abs_diff(FEE_ONLY) <= 2);
    }
}
