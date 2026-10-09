// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one weight build both payout engines run ([`build_with_bootstrap`]). One
//! copy keeps the modes from drifting; share sourcing, caching, persistence
//! and post-build steps stay per engine. Unusable addresses are dropped by
//! the builder itself.

use std::collections::HashMap;

use bp_common::{AddressId, Sats};
use bp_pplns::{
    build_weight_distribution, WeightBuildError, WeightDistribution, WeightDistributionInput,
    WithheldValue,
};
use tracing::warn;

/// Everything the weight model needs that the two modes disagree on.
/// The share map comes in by value because the bootstrap may add the
/// claimant to it; both callers build it fresh per build anyway.
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
    /// Sole scored claimant when the share source is provably EMPTY (never on a
    /// read fault), since [`WeightBuildError::NoScoredMiners`] would otherwise
    /// leave a new group unable to mine its first share. The pool still takes
    /// only its fee. `None` where no single miner asks: publishes nothing.
    pub bootstrap_claimant: Option<&'a AddressId>,
    /// Prefix for the log lines, e.g. `"pplns"` / `"group-solo"`.
    pub scope: &'static str,
}

/// A built distribution plus whether a block found on it can be booked.
#[derive(Clone, Debug)]
pub struct BuiltDistribution {
    pub distribution: WeightDistribution,
    /// `false` → the distribution still becomes a coinbase, but a block found
    /// on it cannot be booked automatically: its snapshot did not land, and the
    /// mode settles from it. Never promise a booking on `false`.
    pub bookable: bool,
}

impl BuiltDistribution {
    /// The payout list's identity ([`bp_share::weights_fingerprint_from_parts`])
    /// and, for a snapshot-backed build, its snapshot key.
    pub fn payouts_fingerprint(&self) -> [u8; 32] {
        self.distribution.fingerprint
    }
}

/// Build, applying the empty-source bootstrap. Pure, no I/O, so every
/// decision that moves satoshis is testable without Redis.
pub fn build_with_bootstrap(
    mut req: BuildRequest<'_>,
) -> Result<WeightDistribution, WeightBuildError> {
    // Owned apart from `req` so the retry can add the claimant while `build`
    // borrows the rest.
    let mut shares = std::mem::take(&mut req.address_shares);
    let build = |shares: &HashMap<AddressId, f64>| {
        build_weight_distribution(WeightDistributionInput {
            address_shares: shares,
            balances: &req.balances,
            fee_percent: req.fee_percent,
            fee_address: req.fee_address,
            coinbase_weight_budget: req.coinbase_weight_budget,
            min_payout_sats: req.min_payout_sats,
            finder_bonus_ppm: req.finder_bonus_ppm,
            finder_address: req.finder_address,
            reference_revenue_sats: req.reference_revenue_sats,
            withheld_value: req.withheld_value,
        })
    };

    // Keyed off the builder's verdict, not `is_empty()`: the builder also
    // drops bad weights and the fee address. Weight 1.0 gives the claimant the
    // whole score space, settling at `delta ≈ 0`, and a non-zero `score_total`
    // lets a standing PPLNS credit be paid.
    let distribution = match build(&shares) {
        Err(WeightBuildError::NoScoredMiners) => {
            let Some(claimant) = req.bootstrap_claimant else {
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
            // One retry: a second `NoScoredMiners` means the builder dropped
            // the claimant itself, and then there is nobody to pay.
            build(&shares)?
        }
        other => other?,
    };
    Ok(distribution)
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

    /// An empty source with a claimant pays that miner; the pool keeps only its fee.
    #[test]
    fn an_empty_source_with_a_claimant_pays_that_miner_not_the_pool() {
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = build_with_bootstrap(request(
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

    /// Without a claimant an empty source stays refused, never paying the pool 100 %.
    #[test]
    fn an_empty_source_without_a_claimant_stays_refused() {
        let fee = addr(FEE);
        assert_eq!(
            build_with_bootstrap(request(HashMap::new(), HashMap::new(), &fee, None)),
            Err(WeightBuildError::NoScoredMiners)
        );
    }

    /// The claimant never displaces a real share source.
    #[test]
    fn a_populated_source_ignores_the_claimant() {
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = build_with_bootstrap(request(
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

    /// A source empty only after the builder drops its unpayable addresses
    /// bootstraps too.
    #[test]
    fn a_source_of_only_unpayable_addresses_bootstraps_too() {
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = build_with_bootstrap(request(
            HashMap::from([(AddressId::new("synthseed800001").unwrap(), 100.0)]),
            HashMap::new(),
            &fee,
            Some(&claimant),
        ))
        .expect("junk-only source must bootstrap, not pay the pool");
        assert!(paid_to(&d, MINER).abs_diff(T - FEE_ONLY) <= 2);
    }

    /// A standing PPLNS credit on an empty window is paid and settles to 0.
    #[test]
    fn the_bootstrap_lets_a_standing_credit_be_paid() {
        const CREDIT: i64 = 10_000_000;
        let fee = addr(FEE);
        let claimant = addr(MINER);
        let d = build_with_bootstrap(request(
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
