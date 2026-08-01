// SPDX-License-Identifier: AGPL-3.0-or-later

//! Weight-native payout distribution (SV2 ext 0x0003).
//!
//! The distribution is the pool's payout state expressed the way the
//! extension speaks it (§3.1): relative integer weights per output plus
//! per-output dust limits, with every concrete satoshi amount derived
//! later as `floor(weight·T/W)` (§4) — by the pool for its own
//! templates, by a JDC for its declared jobs, and by the validator.
//!
//! Only two satoshi-denominated quantities exist in the pool's ledger
//! and cannot be weights by nature; both are projected into weight
//! space at build time against the current reference revenue and are
//! self-correcting at settlement (which books `earned(T_actual) −
//! actually_paid` from the raw inputs, not from these projections):
//!
//! 1. **balance repayment** — a signed sats debt becomes a weight
//!    boost/penalty on the miner's entry;
//! 2. **Group-Solo finder bonus** — a fixed sats bonus becomes a weight
//!    boost on the finder's entry.
//!
//! The pool's own policies map onto spec mechanics instead of bespoke
//! phases: `min_payout` is the per-output `dust_limit` (§3.1 — the JDC
//! prunes and the value flows to the pool output, to be credited back
//! as balance at settlement), and the coinbase blockspace budget is a
//! top-N cut whose folded weights move into `weight_P` (§3.1 blesses
//! `weight_P` carrying value held on behalf of unrepresented miners).

use std::collections::HashMap;

use bp_common::{AddressId, Sats};
use bp_share::weights_fingerprint_from_parts;

use crate::weight::{
    is_valid_payout_address, output_weight_for_address, BUDGET_SAFETY_MARGIN_WU,
    COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT,
    DEFAULT_COINBASE_WEIGHT_BUDGET, DUST_LIMIT_SATS,
};
use crate::BudgetTelemetry;

/// Integer score precision: share fractions are projected onto this
/// many parts. 10^12 keeps every miner above a 10^-12 pool fraction
/// exactly representable — below that a whole block pays < 0.001 sat,
/// genuinely nothing to account — while `Σ weights · T` stays far
/// inside u128 (§4's 128-bit intermediate bound).
pub const SCORE_PRECISION: u64 = 1_000_000_000_000;

/// One address in the distribution.
///
/// `score_weight` and `balance_sats` are the SETTLEMENT INPUTS — the
/// snapshot stores them and `earned(T_actual)` is recomputed from them
/// when a block is booked. `wire_weight` is the PUBLISHED weight
/// (score + projected balance/bonus boosts); `0` means the address has
/// no coinbase output this distribution (folded by the blockspace cut,
/// zero score with no positive balance, or a debt that swallowed the
/// score) but still settles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightEntry {
    pub address: AddressId,
    pub score_weight: u64,
    pub balance_sats: i64,
    pub wire_weight: u64,
    pub dust_limit: u32,
}

/// A built weight distribution: everything the publisher, the pool's
/// own coinbase build, and settlement need — in one deterministic,
/// fingerprinted value.
#[derive(Clone, Debug, PartialEq)]
pub struct WeightDistribution {
    /// Deterministic order: published entries first (wire weight desc,
    /// address asc — the §4 coinbase output order), then unpublished
    /// entries (address asc). The fingerprint is over this order.
    pub entries: Vec<WeightEntry>,
    /// `weight_P` (§3.1): the pool output's weight — fee share plus
    /// every weight folded by the blockspace cut. Always ≥ 1 (the §4
    /// residual needs a live pool output).
    pub weight_p: u64,
    /// Pool fee in parts-per-million of revenue (1 % = 10 000 ppm).
    pub fee_ppm: u32,
    /// Recipient of the pool output (`pool_payout` script source).
    pub fee_address: AddressId,
    /// Group-Solo finder bonus as recorded for settlement.
    pub finder_bonus: Option<(AddressId, u64)>,
    /// Revenue the balance/bonus boosts were projected against.
    pub reference_revenue_sats: u64,
    /// `S = Σ score_weight` — denominator of every settlement claim.
    pub score_total: u64,
    /// Settlement identity (see `bp_share::weights_fingerprint_from_parts`).
    pub fingerprint: [u8; 32],
    /// Blockspace pressure for the coinbase-budget autoscaler.
    pub budget_telemetry: BudgetTelemetry,
}

impl WeightDistribution {
    /// The published payout slice in §4 order (`wire_weight > 0`).
    pub fn published(&self) -> impl Iterator<Item = &WeightEntry> {
        self.entries.iter().filter(|e| e.wire_weight > 0)
    }

    /// `W = weight_P + Σ published wire weights` as the §4 denominator.
    pub fn wire_weight_total(&self) -> u128 {
        self.weight_p as u128
            + self
                .published()
                .map(|e| e.wire_weight as u128)
                .sum::<u128>()
    }
}

/// Inputs to one weight-distribution build.
pub struct WeightDistributionInput<'a> {
    /// Diff-1-weighted share sum per miner (window / round scores).
    pub address_shares: &'a HashMap<AddressId, f64>,
    /// Signed ledger balances at build time. Positive = pool owes the
    /// miner (boosts the wire weight); negative = miner owes the pool
    /// (shrinks it, floored at 0).
    pub balances: &'a HashMap<AddressId, Sats>,
    /// Pool fee percent, e.g. `1.5` for 1.5 %. Must be validated
    /// (`validate_fee_payout_budget`) before the build.
    pub fee_percent: f64,
    /// Pool output recipient. The weight model has no distribution
    /// without it — `pay_P` is structural (§4).
    pub fee_address: &'a AddressId,
    /// Max weight units for coinbase outputs. `0` falls back to
    /// `DEFAULT_COINBASE_WEIGHT_BUDGET`.
    pub coinbase_weight_budget: u32,
    /// Operational minimum on-chain output → per-output `dust_limit`.
    /// `None` falls back to `DUST_LIMIT_SATS`; always clamped ≥ it.
    pub min_payout_sats: Option<Sats>,
    /// Group-Solo finder bonus (both fields or nothing).
    pub finder_bonus_sats: Option<Sats>,
    pub finder_address: Option<&'a AddressId>,
    /// Current template revenue — the projection base for balance and
    /// bonus boosts. Must be non-zero (a pool with no template has
    /// nothing to distribute against).
    pub reference_revenue_sats: u64,
}

/// Why a weight distribution could not be built.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WeightBuildError {
    /// `reference_revenue_sats == 0` — boosts have no projection base.
    #[error("reference revenue is zero")]
    ZeroReferenceRevenue,
}

/// Build the weight distribution from the pool's native state.
///
/// Deterministic: same inputs → same entries, same order, same
/// fingerprint. All integer arithmetic; the only f64 step is the
/// share-fraction projection onto [`SCORE_PRECISION`].
pub fn build_weight_distribution(
    input: WeightDistributionInput<'_>,
) -> Result<WeightDistribution, WeightBuildError> {
    if input.reference_revenue_sats == 0 {
        return Err(WeightBuildError::ZeroReferenceRevenue);
    }
    let t_ref = input.reference_revenue_sats;

    let dust_limit: u32 = input
        .min_payout_sats
        .map(|s| s.0.max(DUST_LIMIT_SATS as i64) as u32)
        .unwrap_or(DUST_LIMIT_SATS as u32);

    // 1 % = 10_000 ppm. fee_percent is pre-validated to [0, 100].
    let fee_ppm = (input.fee_percent * 10_000.0).round() as u32;

    // ── Score projection ────────────────────────────────────────────
    // u_i = round(share_i / Σshares · SCORE_PRECISION). Scale-invariant
    // in the window's own units; miners below 1/SCORE_PRECISION of the
    // pool project to 0 and settle (to 0) without an output.
    let score_total_f64: f64 = input
        .address_shares
        .iter()
        .filter(|(a, s)| s.is_finite() && **s > 0.0 && is_valid_payout_address(a.as_str()))
        .map(|(_, s)| *s)
        .sum();

    struct Candidate {
        address: AddressId,
        score_weight: u64,
        balance_sats: i64,
        wire_weight: u64,
    }
    let mut candidates: HashMap<&AddressId, Candidate> = HashMap::new();
    for (address, shares) in input.address_shares {
        if !shares.is_finite() || *shares <= 0.0 || !is_valid_payout_address(address.as_str()) {
            continue;
        }
        let u = ((*shares / score_total_f64) * SCORE_PRECISION as f64).round() as u64;
        candidates.insert(
            address,
            Candidate {
                address: address.clone(),
                score_weight: u,
                balance_sats: 0,
                wire_weight: 0,
            },
        );
    }
    for (address, balance) in input.balances {
        if balance.0 == 0 || !is_valid_payout_address(address.as_str()) {
            continue;
        }
        candidates
            .entry(address)
            .or_insert_with(|| Candidate {
                address: address.clone(),
                score_weight: 0,
                balance_sats: 0,
                wire_weight: 0,
            })
            .balance_sats = balance.0;
    }

    let score_total: u64 = candidates.values().map(|c| c.score_weight).sum();

    // ── Fee weight ──────────────────────────────────────────────────
    // weight_P/W = fee fraction when no boosts are in play:
    // weight_P = S · f / (1 − f), in ppm integer math. 100 % fee is the
    // degenerate whole-revenue-to-pool distribution.
    let fee_weight: u64 = if fee_ppm >= 1_000_000 || score_total == 0 {
        0 // resolved below: no miner weights → weight_p floors at 1
    } else {
        ((score_total as u128 * fee_ppm as u128) / (1_000_000 - fee_ppm) as u128) as u64
    };

    // ── Boost projection (the two documented sats→weight sites) ─────
    // boost = sats · W₀ / T_ref against the pre-boost weight space.
    let w0 = (score_total as u128 + fee_weight as u128).max(1);
    let boost_for = |sats: i64| -> i128 { (sats as i128 * w0 as i128) / t_ref as i128 };

    let publish_all = fee_ppm < 1_000_000;
    for c in candidates.values_mut() {
        if !publish_all {
            c.wire_weight = 0;
            continue;
        }
        let wire = c.score_weight as i128 + boost_for(c.balance_sats);
        c.wire_weight = wire.clamp(0, u64::MAX as i128) as u64;
    }
    let finder_bonus: Option<(AddressId, u64)> = match (
        input.finder_bonus_sats,
        input.finder_address,
    ) {
        (Some(bonus), Some(finder))
            if bonus.0 > 0 && is_valid_payout_address(finder.as_str()) =>
        {
            let bonus_sats = bonus.0 as u64;
            if publish_all {
                let c = candidates.entry(finder).or_insert_with(|| Candidate {
                    address: finder.clone(),
                    score_weight: 0,
                    balance_sats: 0,
                    wire_weight: 0,
                });
                let wire = c.wire_weight as i128 + boost_for(bonus_sats as i64);
                c.wire_weight = wire.clamp(0, u64::MAX as i128) as u64;
            }
            Some((finder.clone(), bonus_sats))
        }
        _ => None,
    };

    // ── Deterministic order ─────────────────────────────────────────
    // Published (wire desc, address asc — the §4 coinbase order), then
    // unpublished (address asc). Fixed BEFORE the blockspace cut so
    // folding cannot reshuffle the fingerprinted order.
    let mut entries: Vec<Candidate> = candidates.into_values().collect();
    entries.sort_by(|a, b| {
        b.wire_weight
            .cmp(&a.wire_weight)
            .then_with(|| a.address.as_str().cmp(b.address.as_str()))
    });

    // ── Blockspace cut ──────────────────────────────────────────────
    // Greedy keep in published order while the real serialized weight
    // fits the budget; folded entries move their wire weight into
    // weight_P and settle off-chain (§3.1).
    let budget = if input.coinbase_weight_budget == 0 {
        DEFAULT_COINBASE_WEIGHT_BUDGET
    } else {
        input.coinbase_weight_budget
    };
    let effective_budget = budget.saturating_sub(BUDGET_SAFETY_MARGIN_WU);
    let fixed_overhead = COINBASE_BASE_WEIGHT
        + COINBASE_WITNESS_COMMITMENT_WEIGHT
        + COINBASE_OUTPUT_WEIGHT; // the pool_payout output, worst-case type
    let mut used_weight = fixed_overhead;
    let mut desired_weight = fixed_overhead;
    let mut folded_weight: u64 = 0;
    let mut trimmed_count: u32 = 0;
    for c in entries.iter_mut() {
        if c.wire_weight == 0 {
            continue;
        }
        let ow = output_weight_for_address(c.address.as_str());
        desired_weight = desired_weight.saturating_add(ow);
        if used_weight.saturating_add(ow) <= effective_budget {
            used_weight += ow;
        } else {
            folded_weight = folded_weight.saturating_add(c.wire_weight);
            c.wire_weight = 0;
            trimmed_count += 1;
        }
    }

    let weight_p = fee_weight.saturating_add(folded_weight).max(1);

    // Order can change where the cut zeroed wire weights mid-list:
    // restore the published-then-unpublished invariant (stable sort
    // keeps the relative order of both groups).
    entries.sort_by_key(|c| c.wire_weight == 0);

    let fingerprint = weights_fingerprint_from_parts(
        fee_ppm,
        finder_bonus
            .as_ref()
            .map(|(a, sats)| (a.as_str(), *sats)),
        entries
            .iter()
            .map(|c| (c.address.as_str(), c.score_weight, c.balance_sats, dust_limit)),
    );

    Ok(WeightDistribution {
        entries: entries
            .into_iter()
            .map(|c| WeightEntry {
                address: c.address,
                score_weight: c.score_weight,
                balance_sats: c.balance_sats,
                wire_weight: c.wire_weight,
                dust_limit,
            })
            .collect(),
        weight_p,
        fee_ppm,
        fee_address: input.fee_address.clone(),
        finder_bonus,
        reference_revenue_sats: t_ref,
        score_total,
        fingerprint,
        budget_telemetry: BudgetTelemetry {
            desired_weight,
            effective_budget,
            trimmed_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("valid test address")
    }

    const A1: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const A2: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    const A3: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    const FEE: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

    fn base_input<'a>(
        shares: &'a HashMap<AddressId, f64>,
        balances: &'a HashMap<AddressId, Sats>,
        fee_address: &'a AddressId,
    ) -> WeightDistributionInput<'a> {
        WeightDistributionInput {
            address_shares: shares,
            balances,
            fee_percent: 1.5,
            fee_address,
            coinbase_weight_budget: 50_000,
            min_payout_sats: Some(Sats(5_000)),
            finder_bonus_sats: None,
            finder_address: None,
            reference_revenue_sats: 312_500_000,
        }
    }

    /// `scores project to SCORE_PRECISION-scaled fractions`
    #[test]
    fn projects_share_fractions() {
        let shares = HashMap::from([(addr(A1), 30.0), (addr(A2), 10.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let w1 = d.entries.iter().find(|e| e.address.as_str() == A1).unwrap();
        let w2 = d.entries.iter().find(|e| e.address.as_str() == A2).unwrap();
        assert_eq!(w1.score_weight, 750_000_000_000);
        assert_eq!(w2.score_weight, 250_000_000_000);
        assert_eq!(d.score_total, SCORE_PRECISION);
        // No balances → wire weight == score weight.
        assert_eq!(w1.wire_weight, w1.score_weight);
    }

    /// `fee weight makes weight_P/W the fee fraction`
    #[test]
    fn fee_weight_is_the_fee_fraction() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let w = d.wire_weight_total();
        // weight_p / W ≈ 1.5 % (integer rounding).
        let ppm = (d.weight_p as u128 * 1_000_000 / w) as u32;
        assert!((14_999..=15_000).contains(&ppm), "fee ppm was {ppm}");
    }

    /// `positive balance boosts the wire weight by ≈ balance·W₀/T_ref`
    #[test]
    fn positive_balance_boosts_wire_weight() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::from([(addr(A1), Sats(31_250_000))]); // 10 % of T_ref
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let w1 = d.entries.iter().find(|e| e.address.as_str() == A1).unwrap();
        let w2 = d.entries.iter().find(|e| e.address.as_str() == A2).unwrap();
        // A1's boost ≈ 10 % of W₀ on top of its 50 % score.
        let boost = w1.wire_weight - w1.score_weight;
        let w0 = d.score_total + (d.weight_p);
        let expected = (31_250_000u128 * w0 as u128 / 312_500_000u128) as u64;
        assert!(
            boost.abs_diff(expected) <= 1,
            "boost {boost} vs expected {expected}"
        );
        assert_eq!(w2.wire_weight, w2.score_weight);
        assert_eq!(w1.balance_sats, 31_250_000);
    }

    /// `debt shrinks the wire weight, floored at 0, entry stays for settlement`
    #[test]
    fn debt_shrinks_wire_weight_floored_at_zero() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        // A1 owes more than its whole share is worth.
        let balances = HashMap::from([(addr(A1), Sats(-400_000_000))]);
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let w1 = d.entries.iter().find(|e| e.address.as_str() == A1).unwrap();
        assert_eq!(w1.wire_weight, 0, "debt-swallowed weight floors at 0");
        assert_eq!(w1.score_weight, SCORE_PRECISION / 2, "score kept for settlement");
        assert_eq!(w1.balance_sats, -400_000_000);
        assert!(d.published().all(|e| e.address.as_str() != A1));
    }

    /// `balance-only entry (no shares) is carried and boosted`
    #[test]
    fn balance_only_entry_is_published() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::from([(addr(A2), Sats(31_250_000))]);
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let w2 = d.entries.iter().find(|e| e.address.as_str() == A2).unwrap();
        assert_eq!(w2.score_weight, 0);
        assert!(w2.wire_weight > 0, "positive balance alone earns an output");
    }

    /// `finder bonus boosts the finder and is recorded for settlement`
    #[test]
    fn finder_bonus_boosts_and_records() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A3); // no shares of their own
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_sats = Some(Sats(50_000));
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();
        let wf = d.entries.iter().find(|e| e.address.as_str() == A3).unwrap();
        assert!(wf.wire_weight > 0);
        assert_eq!(d.finder_bonus, Some((addr(A3), 50_000)));
    }

    /// `blockspace cut folds smallest wire weights into weight_P`
    #[test]
    fn blockspace_cut_folds_into_weight_p() {
        let mut shares = HashMap::new();
        // 3 real addresses; budget sized so only 1 miner output fits.
        shares.insert(addr(A1), 10.0);
        shares.insert(addr(A2), 5.0);
        shares.insert(addr(A3), 1.0);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let mut input = base_input(&shares, &balances, &fee);
        // fixed_overhead = 328 + 188 + 172 = 688 (+200 margin). One
        // P2WPKH output = 124 WU → budget 1100: 688+124 fits ≤ 900? No —
        // effective 900, 688+124=812 fits, next (136) would be 948 > 900.
        input.coinbase_weight_budget = 1_100;
        let d = build_weight_distribution(input).unwrap();
        let published: Vec<_> = d.published().collect();
        assert_eq!(published.len(), 1, "only the largest fits");
        assert_eq!(published[0].address.as_str(), A1);
        assert_eq!(d.budget_telemetry.trimmed_count, 2);
        // Folded weights ended up in weight_P.
        let folded: u64 = d
            .entries
            .iter()
            .filter(|e| e.wire_weight == 0)
            .map(|e| e.score_weight)
            .sum();
        assert!(folded > 0);
        assert!(d.weight_p > folded, "weight_p = fee + folded wire weights");
    }

    /// `100 % fee → nothing published, weight_P alone`
    #[test]
    fn full_fee_publishes_nothing() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let mut input = base_input(&shares, &balances, &fee);
        input.fee_percent = 100.0;
        let d = build_weight_distribution(input).unwrap();
        assert_eq!(d.published().count(), 0);
        assert_eq!(d.weight_p, 1);
    }

    /// `no shares + no balances → empty entries, pool takes all`
    #[test]
    fn empty_inputs_yield_pool_only_distribution() {
        let shares = HashMap::new();
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        assert!(d.entries.is_empty());
        assert_eq!(d.weight_p, 1);
        assert_eq!(d.score_total, 0);
    }

    /// `zero reference revenue is refused`
    #[test]
    fn zero_reference_revenue_is_refused() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let mut input = base_input(&shares, &balances, &fee);
        input.reference_revenue_sats = 0;
        assert_eq!(
            build_weight_distribution(input),
            Err(WeightBuildError::ZeroReferenceRevenue)
        );
    }

    /// `junk addresses are dropped, not build-aborting`
    #[test]
    fn junk_addresses_are_dropped() {
        let shares = HashMap::from([
            (AddressId::new("synthseed800001").unwrap(), 100.0),
            (addr(A1), 1.0),
        ]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].address.as_str(), A1);
        assert_eq!(d.entries[0].score_weight, SCORE_PRECISION);
    }

    /// `deterministic: same inputs → same fingerprint and order`
    #[test]
    fn build_is_deterministic() {
        let shares = HashMap::from([(addr(A1), 3.0), (addr(A2), 2.0), (addr(A3), 1.0)]);
        let balances = HashMap::from([(addr(A2), Sats(-100)), (addr(A3), Sats(7_000))]);
        let fee = addr(FEE);
        let a = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let b = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        assert_eq!(a, b);
    }

    /// `fingerprint tracks settlement inputs, not the boost projection`
    #[test]
    fn fingerprint_ignores_reference_revenue() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::from([(addr(A1), Sats(10_000))]);
        let fee = addr(FEE);
        let a = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let mut input = base_input(&shares, &balances, &fee);
        input.reference_revenue_sats = 625_000_000; // different T_ref
        let b = build_weight_distribution(input).unwrap();
        assert_ne!(
            a.entries[0].wire_weight, b.entries[0].wire_weight,
            "different T_ref projects a different boost"
        );
        assert_eq!(
            a.fingerprint, b.fingerprint,
            "same settlement inputs → same snapshot identity"
        );
    }
}
