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
//! Both come out of the same pot they are paid from, so the score split
//! runs over `pot(T) − X` (with `X` the signed sum of all of them) on
//! BOTH sides — the published weights and the settlement claims. One
//! shared [`bp_share::project_extras`] resolves `X` for both, because
//! two sides splitting two different pots is how a ledger mints money.
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
    /// entries (address asc). NOT the fingerprint order, which is by
    /// address (this one moves with the reference revenue).
    pub entries: Vec<WeightEntry>,
    /// `weight_P` (§3.1): the pool output's weight — the fee over
    /// everything this block owes the miners, plus every weight owed
    /// but with no room in the coinbase (folded by the blockspace cut).
    /// A repayment is NOT in here: it moves between miners, since it is
    /// the other miners the debt is owed to. Always ≥ 1 (the §4
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
    /// `X` — the satoshi promises (balances + bonus) this distribution
    /// pays on top of the score split, after solvency capping. The
    /// score share is taken over `pot(T) − X`, never over the whole
    /// pot, both here and at settlement. Not part of the fingerprint:
    /// settlement recomputes it from the stored inputs.
    pub extras_total: i64,
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

    /// The concrete `(address, sats)` list this distribution yields at
    /// revenue `t`, in §4 coinbase order: the pool output (`pay_P`,
    /// absorbing rounding + dust) first, then the kept miner outputs.
    /// This is the pool's OWN coinbase build — the same §4 evaluation a
    /// JDC runs with its own template revenue.
    pub fn payout_entries_at(
        &self,
        t: u64,
    ) -> Result<Vec<(AddressId, u64)>, bp_share::WeightPayoutError> {
        let published: Vec<&WeightEntry> = self.published().collect();
        let weights: Vec<u64> = published.iter().map(|e| e.wire_weight).collect();
        let dusts: Vec<u32> = published.iter().map(|e| e.dust_limit).collect();
        let amounts = bp_share::compute_payout_amounts(self.weight_p, &weights, &dusts, t)?;
        let mut out = Vec::with_capacity(1 + published.len());
        out.push((self.fee_address.clone(), amounts.pool_pay));
        for (entry, pay) in published.iter().zip(&amounts.pays) {
            if let Some(sats) = pay {
                out.push((entry.address.clone(), *sats));
            }
        }
        Ok(out)
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
    /// `DEFAULT_COINBASE_WEIGHT_BUDGET`. The cut reserves the base
    /// transaction, the witness commitment and the pool output; a
    /// distribution that ever carries `additional_outputs` (§3.1, e.g.
    /// an OP_RETURN) must reserve those here too — they are appended to
    /// the same coinbase and a single ~50-byte one already outweighs the
    /// safety margin.
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
    /// The configured pool-output recipient is not a usable payout
    /// address. Fail here rather than publish a distribution whose pool
    /// output cannot be scripted: `pay_P` is structural (§4), so the
    /// failure would otherwise surface as an aborted coinbase build,
    /// taking down jobs for every miner on the pool instead of one
    /// output.
    #[error("fee address is not a valid payout address: {0}")]
    InvalidFeeAddress(String),
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
    if !is_valid_payout_address(input.fee_address.as_str()) {
        return Err(WeightBuildError::InvalidFeeAddress(
            input.fee_address.as_str().to_string(),
        ));
    }
    let t_ref = input.reference_revenue_sats;

    // Saturating, not truncating: `as u32` WRAPS, so a min_payout
    // entered in the wrong unit could land below the dust floor the
    // `.max()` exists to guarantee — 2^32 sats would become 0.
    let dust_limit: u32 = input
        .min_payout_sats
        .map(|s| s.0.clamp(DUST_LIMIT_SATS as i64, u32::MAX as i64) as u32)
        .unwrap_or(DUST_LIMIT_SATS as u32);

    // 1 % = 10_000 ppm. fee_percent is pre-validated to [0, 100].
    let fee_ppm = (input.fee_percent * 10_000.0).round() as u32;

    // ── Score projection ────────────────────────────────────────────
    // u_i = round(share_i / Σshares · SCORE_PRECISION). Scale-invariant
    // in the window's own units; miners below 1/SCORE_PRECISION of the
    // pool project to 0 and settle (to 0) without an output.
    // Summed in ADDRESS order, not `HashMap` order: f64 addition is not
    // associative and every map instance iterates differently, so a
    // HashMap-order sum makes the total — and with it a rounded score,
    // and with it the fingerprint — depend on which map object happened
    // to carry the shares. Unchanged pool state would then mint a new
    // settlement identity and age the live distribution out of the
    // acceptance window.
    // The fee address is NEVER a miner entry. It already receives the
    // pool output via `weight_P`, and settlement refuses to book a row
    // for it (its payment is inseparable from the pool output). Paying
    // it a second, miner-shaped output would hand out satoshis nothing
    // ever debits — a balance on that address would be paid out again
    // on every single block, forever.
    let is_fee = |a: &AddressId| a.as_str() == input.fee_address.as_str();

    let mut scored: Vec<(&AddressId, f64)> = input
        .address_shares
        .iter()
        .filter(|(a, s)| {
            s.is_finite() && **s > 0.0 && is_valid_payout_address(a.as_str()) && !is_fee(a)
        })
        .map(|(a, s)| (a, *s))
        .collect();
    scored.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    let score_total_f64: f64 = scored.iter().map(|(_, s)| *s).sum();

    struct Candidate {
        address: AddressId,
        score_weight: u64,
        balance_sats: i64,
        /// What this block owes AND pays the address: its score share
        /// of what the promises leave, plus its own promise. The only
        /// weight ever withheld from a miner is the one the blockspace
        /// cut folds away — see `weight_p` below.
        wire_weight: u64,
    }
    let mut candidates: HashMap<&AddressId, Candidate> = HashMap::new();
    for (address, shares) in &scored {
        let u = ((shares / score_total_f64) * SCORE_PRECISION as f64).round() as u64;
        candidates.insert(
            address,
            Candidate {
                address: (*address).clone(),
                score_weight: u,
                balance_sats: 0,
                wire_weight: 0,
            },
        );
    }
    for (address, balance) in input.balances {
        if balance.0 == 0 || !is_valid_payout_address(address.as_str()) || is_fee(address) {
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
    let publish_all = fee_ppm < 1_000_000;

    // The bonus is the one promise the pool PICKS rather than owes, so
    // it is the one that gives way when the promises outgrow the block
    // — and it must give way here, because the snapshot records the
    // capped figure and settlement can never recover the operator's
    // original one. A bonus configured before a halving, or against a
    // low-fee template, would otherwise swallow the whole score space:
    // the finder takes nearly the entire coinbase and every other group
    // member is dust-pruned to nothing.
    let balance_total: i64 = candidates
        .values()
        .map(|c| c.balance_sats as i128)
        .sum::<i128>()
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    let finder_bonus: Option<(AddressId, u64)> =
        match (input.finder_bonus_sats, input.finder_address) {
            (Some(bonus), Some(finder))
                if bonus.0 > 0 && is_valid_payout_address(finder.as_str()) =>
            {
                let headroom = bp_share::solvency_headroom_sats(balance_total, fee_ppm, t_ref);
                let bonus_sats = (bonus.0 as u64).min(headroom);
                if bonus_sats < dust_limit as u64 {
                    // Would be pruned on-chain anyway; recording it
                    // would make settlement pay a bonus no coinbase ever
                    // carried.
                    None
                } else {
                    if publish_all {
                        candidates.entry(finder).or_insert_with(|| Candidate {
                            address: finder.clone(),
                            score_weight: 0,
                            balance_sats: 0,
                            wire_weight: 0,
                        });
                    }
                    Some((finder.clone(), bonus_sats))
                }
            }
            _ => None,
        };

    let mut entries: Vec<Candidate> = candidates.into_values().collect();

    // ── Sats → weight projection ────────────────────────────────────
    //
    // Two quantities here are denominated in satoshis rather than in
    // shares: a miner's ledger balance and the finder bonus. Both are
    // promises to pay a FIXED amount on top of the score split, and the
    // weight model has exactly one way to say that — a boost on that
    // entry's weight.
    //
    // The scale is NOT `sats · S / pot`, because a boost lands in the
    // denominator as well: with `e_i = u_i + boost_i` and
    // `E = Σ e_i = S + Σ boost`, each entry is paid `e_i · pot / E`, so
    // raising one entry dilutes every entry including itself. Solving
    // for the boost that actually delivers `extra_i` on top of the
    // score split gives
    //
    //     boost_i = extra_i · S / (pot(t_ref) − X),   X = Σ extra_i
    //
    // since then `E = S · pot/(pot − X)` and therefore
    //
    //     paid_i = e_i · pot / E = (u_i/S)·(pot − X) + extra_i
    //
    // — the score share of what is LEFT after the promises, plus this
    // entry's own promise. Signs carry through unchanged, so a debt
    // shrinks the payout by exactly what is owed, and the settlement
    // claim (`bp_share::claim_sats`, same `X`) is the first term alone.
    // Scaling by `S/pot` instead delivers only `extra_i · (1 − u_i/S)`
    // — for a 50 % miner, half of what was promised.
    let extras = bp_share::extras_from_ledger(
        entries
            .iter()
            .map(|c| (c.address.as_str(), c.score_weight, c.balance_sats)),
        finder_bonus.as_ref().map(|(a, sats)| (a.as_str(), *sats)),
    );
    let projection = bp_share::project_extras(&extras, score_total, fee_ppm, t_ref);
    for (c, extra) in entries.iter_mut().zip(&projection.effective) {
        if !publish_all {
            c.wire_weight = 0;
            continue;
        }
        let boost = (*extra as i128 * score_total as i128) / projection.divisor as i128;
        c.wire_weight = (c.score_weight as i128 + boost).clamp(0, u64::MAX as i128) as u64;
    }

    // ── Deterministic order ─────────────────────────────────────────
    // Published (wire desc, address asc — the §4 coinbase order), then
    // unpublished (address asc). Fixed BEFORE the blockspace cut so
    // folding cannot reshuffle the fingerprinted order.
    entries.sort_by(|a, b| {
        b.wire_weight
            .cmp(&a.wire_weight)
            .then_with(|| a.address.as_str().cmp(b.address.as_str()))
    });

    // `E` — what this block owes the miners, read off before the cut
    // because the cut is the only thing that separates owed from paid.
    let total_entitlement: u128 = entries.iter().map(|c| c.wire_weight as u128).sum();

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
    let fixed_overhead =
        COINBASE_BASE_WEIGHT + COINBASE_WITNESS_COMMITMENT_WEIGHT + COINBASE_OUTPUT_WEIGHT; // the pool_payout output, worst-case type
    let mut used_weight = fixed_overhead;
    let mut desired_weight = fixed_overhead;
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
            c.wire_weight = 0;
            trimmed_count += 1;
        }
    }

    // ── Pool weight ─────────────────────────────────────────────────
    //
    // Two parts, and keeping them apart is what makes the configured
    // fee mean what it says:
    //
    // 1. The FEE, taken over what this block owes the miners in total
    //    (`E`), not over their bare scores. Because `W = E + weight_P`
    //    resolves to `E/(1 − f)`, the pool output is exactly `f·T`
    //    however large the credits being repaid are — a repayment is a
    //    redistribution WITHIN the miners' cut, as it was before the
    //    weight model, never a discount on the pool's fee.
    // 2. Everything the blockspace cut FOLDED: `E − Σ published`. A
    //    weight that is owed but has no room in the coinbase must land
    //    in the pool output, never silently leave `W`. Dropping it
    //    would inflate every remaining miner's share above their
    //    settlement claim, paying real satoshis against an IOU the pool
    //    can only collect from future blocks. Settlement books the
    //    folded miner's whole claim back as a balance credit.
    let published_total: u128 = entries.iter().map(|c| c.wire_weight as u128).sum();
    let withheld = total_entitlement.saturating_sub(published_total);
    let fee_weight: u128 = if fee_ppm >= 1_000_000 || total_entitlement == 0 {
        0 // no miner weights → weight_p floors at 1 and takes the block
    } else {
        (total_entitlement * fee_ppm as u128) / (1_000_000 - fee_ppm) as u128
    };
    let weight_p = fee_weight
        .saturating_add(withheld)
        .clamp(1, u64::MAX as u128) as u64;

    // Order can change where the cut zeroed wire weights mid-list:
    // restore the published-then-unpublished invariant (stable sort
    // keeps the relative order of both groups).
    entries.sort_by_key(|c| c.wire_weight == 0);

    // Hashed over an ADDRESS-ordered view, not the coinbase order above:
    // that order sorts by wire weight, and wire weights carry `t_ref`
    // through the balance boosts. Hashing it would smuggle the reference
    // revenue back into an identity that exists precisely so builds at
    // different revenues can share one settlement snapshot.
    let mut identity: Vec<&Candidate> = entries.iter().collect();
    identity.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
    let fingerprint = weights_fingerprint_from_parts(
        fee_ppm,
        input.fee_address.as_str(),
        finder_bonus.as_ref().map(|(a, sats)| (a.as_str(), *sats)),
        identity.iter().map(|c| {
            (
                c.address.as_str(),
                c.score_weight,
                c.balance_sats,
                dust_limit,
            )
        }),
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
        extras_total: projection.total,
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

    /// The build must not depend on which `HashMap` instance carried the
    /// shares. Every map gets its own hash seed, so identical contents
    /// iterate differently — and f64 addition is not associative, which
    /// is why the score total is summed in address order.
    #[test]
    fn build_is_independent_of_hashmap_iteration_order() {
        // Order-sensitive by construction: adding the large value first
        // absorbs both small ones, adding it last does not.
        let big = 1e16f64;
        assert_ne!(
            (big + 1.0) + 1.0,
            (1.0 + 1.0) + big,
            "fixture must actually be order-sensitive in f64"
        );
        let fee = addr(FEE);
        let balances = HashMap::new();
        let mut seen: Option<[u8; 32]> = None;
        // Fresh maps, each with its own iteration order.
        for _ in 0..32 {
            let shares = HashMap::from([(addr(A1), big), (addr(A2), 1.0), (addr(A3), 1.0)]);
            let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
            match seen {
                None => seen = Some(d.fingerprint),
                Some(first) => assert_eq!(
                    d.fingerprint, first,
                    "same inputs must produce one settlement identity"
                ),
            }
        }
    }

    /// The fee address must never receive a miner-shaped output. It is
    /// paid via `weight_P`, and settlement will not book a row for it —
    /// so a balance sitting on that address would be paid out on EVERY
    /// block while the ledger entry it came from is never reduced.
    #[test]
    fn fee_address_never_becomes_a_payable_entry() {
        let fee = addr(FEE);
        let balances = HashMap::from([(addr(FEE), Sats(10_000_000))]);
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        assert!(
            !d.entries.iter().any(|e| e.address.as_str() == FEE),
            "the fee address must not appear among the miner entries"
        );
        const T: u64 = 312_500_000;
        let paid = d.payout_entries_at(T).expect("§4 vector");
        // Exactly one output to the fee address: the pool output.
        assert_eq!(
            paid.iter().filter(|(a, _)| a.as_str() == FEE).count(),
            1,
            "fee address paid twice: {paid:?}"
        );
        assert_eq!(paid.iter().map(|(_, s)| *s).sum::<u64>(), T, "Σ == T");
    }

    /// Same for shares: a fee address that also mines is the pool
    /// mining to itself, and must not dilute the other miners' shares
    /// with an entry settlement will refuse to book.
    #[test]
    fn fee_address_with_shares_is_not_a_miner_entry() {
        let fee = addr(FEE);
        let balances = HashMap::new();
        let shares = HashMap::from([(addr(A1), 1.0), (addr(FEE), 1.0)]);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        assert!(!d.entries.iter().any(|e| e.address.as_str() == FEE));
        // A1 is the only miner left, so it holds the whole score space.
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].score_weight, SCORE_PRECISION);
    }

    /// The pool output is structural under §4, so an unusable fee
    /// address must fail the BUILD. Letting it through would abort the
    /// coinbase assembly instead, which blocks jobs for every miner on
    /// the pool rather than dropping one output.
    #[test]
    fn unusable_fee_address_fails_the_build() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        // Well-formed enough for `AddressId`, not a payable script.
        let bad = addr("bc1qtypo");
        assert!(matches!(
            build_weight_distribution(base_input(&shares, &balances, &bad)),
            Err(WeightBuildError::InvalidFeeAddress(_))
        ));
    }

    /// A fixed sats bonus configured before a halving — or against a
    /// low-fee template — must not let the finder take the block while
    /// every other group member is pruned to nothing.
    #[test]
    fn finder_bonus_is_capped_at_most_of_the_miner_cut() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_sats = Some(Sats(10_000_000_000)); // 32x the block
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        const T: u64 = 312_500_000;
        let published: Vec<&WeightEntry> = d.published().collect();
        let amounts = bp_share::compute_payout_amounts(
            d.weight_p,
            &published.iter().map(|e| e.wire_weight).collect::<Vec<_>>(),
            &published.iter().map(|e| e.dust_limit).collect::<Vec<_>>(),
            T,
        )
        .expect("§4 vector");
        let a2_paid = published
            .iter()
            .zip(&amounts.pays)
            .find(|(e, _)| e.address.as_str() == A2)
            .and_then(|(_, pay)| *pay);
        assert!(
            a2_paid.is_some_and(|s| s > 546),
            "the non-finder must still get a real output, got {a2_paid:?}"
        );
        // The recorded bonus is the capped one — settlement pays what
        // the coinbase actually carried.
        let (_, recorded) = d.finder_bonus.expect("bonus recorded");
        let miner_cut = T - (T * 15_000 / 1_000_000);
        assert_eq!(recorded, miner_cut * 95 / 100);
    }

    /// A bonus too small to survive dust-pruning is not recorded either:
    /// settlement must not credit a bonus no coinbase ever paid.
    #[test]
    fn sub_dust_finder_bonus_is_suppressed() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_sats = Some(Sats(100)); // below the 5_000 min_payout
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();
        assert_eq!(d.finder_bonus, None);
    }

    /// A min_payout too large for the dust-limit field must never wrap
    /// below the 546-sat floor — an operator entering sats where BTC
    /// was meant would otherwise turn dust-pruning off entirely.
    #[test]
    fn oversized_min_payout_saturates_instead_of_wrapping() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        for min_payout in [
            i64::from(u32::MAX) + 1, // wraps to 0 with a truncating cast
            i64::from(u32::MAX) + 547,
            i64::MAX,
        ] {
            let mut input = base_input(&shares, &balances, &fee);
            input.min_payout_sats = Some(Sats(min_payout));
            let d = build_weight_distribution(input).unwrap();
            assert_eq!(
                d.entries[0].dust_limit,
                u32::MAX,
                "min_payout {min_payout} must saturate, not wrap"
            );
        }
    }

    /// The configured fee is what the pool is paid, whatever the ledger
    /// owes the miners. A repayment is a redistribution WITHIN the
    /// miners' cut — never a discount on the pool's fee.
    #[test]
    fn accumulated_credit_never_dilutes_the_fee() {
        let fee = addr(FEE);
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        // Credits from nothing up to 1.5x the whole block: the ledger
        // can hold arbitrarily much after a long stretch without a block.
        for credit in [0i64, 31_250_000, 156_250_000, 468_750_000] {
            let balances = if credit == 0 {
                HashMap::new()
            } else {
                HashMap::from([(addr(A1), Sats(credit))])
            };
            let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
            let ppm = (d.weight_p as u128 * 1_000_000 / d.wire_weight_total()) as u32;
            assert!(
                (14_999..=15_000).contains(&ppm),
                "credit {credit} moved the fee to {ppm} ppm"
            );
        }
    }

    /// A debt is a claim the OTHER miners hold, not the pool's income.
    /// It exists because an earlier coinbase paid this miner out of
    /// their share, so collecting it has to reach them — and it does,
    /// through `X`: a negative `X` enlarges the pot every score is
    /// measured against, by exactly what is being repaid. The pool
    /// keeps its fee and not one satoshi more.
    #[test]
    fn debt_recovery_reaches_the_other_miners_not_the_pool() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        // A1 owes more than a whole block share is worth → pays nothing.
        let balances = HashMap::from([(addr(A1), Sats(-400_000_000))]);
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        assert_eq!(
            d.entries
                .iter()
                .find(|e| e.address.as_str() == A1)
                .unwrap()
                .wire_weight,
            0
        );

        const T: u64 = 312_500_000;
        let settled = settle(&d, T);
        // A2 is paid what it claims — the repayment is not a windfall
        // it would owe back, and not a credit it can never collect.
        assert!(
            settled[A2].delta.abs() <= 2,
            "A2: paid {} vs claim {}",
            settled[A2].paid,
            settled[A2].claim
        );
        // A1 pays nothing, so the whole claim goes against the debt —
        // and what it could not repay this block stays on the ledger.
        assert_eq!(settled[A1].paid, 0);
        assert!(settled[A1].delta > 0, "the claim works the debt off");
        assert!(
            -400_000_000 + settled[A1].delta < 0,
            "a debt larger than one block's share carries over"
        );
        // Fee only: the recovery went to A2, not into the pool output.
        let pool_pay = T as i64 - settled.values().map(|s| s.paid).sum::<i64>();
        let fee_only = (T as i64 * d.fee_ppm as i64) / 1_000_000;
        assert!(
            (pool_pay - fee_only).abs() <= 2,
            "pool got {pool_pay}, its fee is {fee_only} — the repayment leaked into the pool output"
        );
    }

    // ── The promise ↔ claim identity ────────────────────────────────
    //
    // Everything below nails down one equation. The coinbase pays
    //
    //     paid_i = (u_i/S)·(pot(T) − X) + extra_i
    //
    // and settlement claims the first term alone (plus the finder's own
    // bonus). At `T == t_ref` the difference is therefore exactly the
    // held balance, so the ledger clears and nobody else moves. Both
    // halves have to use the same `X` or the ledger mints money on
    // every block.

    /// One address's settlement line for a block paying `t`.
    #[derive(Debug)]
    struct Settled {
        paid: i64,
        claim: i64,
        delta: i64,
        balance_after: i64,
    }

    /// Settle a distribution against a coinbase that pays its §4 vector
    /// exactly — the same arithmetic both payout engines run.
    fn settle(d: &WeightDistribution, t: u64) -> HashMap<String, Settled> {
        let mut paid_by_address: HashMap<String, i64> = HashMap::new();
        for (address, sats) in d.payout_entries_at(t).expect("§4 vector").iter().skip(1) {
            *paid_by_address
                .entry(address.as_str().to_string())
                .or_insert(0) += *sats as i64;
        }
        d.entries
            .iter()
            .map(|e| {
                let bonus = match &d.finder_bonus {
                    Some((a, sats)) if *a == e.address => *sats as i64,
                    _ => 0,
                };
                let claim = bp_share::claim_sats(
                    e.score_weight,
                    d.score_total,
                    d.fee_ppm,
                    t,
                    d.extras_total,
                ) + bonus;
                let paid = paid_by_address
                    .get(e.address.as_str())
                    .copied()
                    .unwrap_or(0);
                let delta = claim - paid;
                (
                    e.address.as_str().to_string(),
                    Settled {
                        paid,
                        claim,
                        delta,
                        balance_after: e.balance_sats + delta,
                    },
                )
            })
            .collect()
    }

    /// A held credit must arrive in FULL. The projection has to account
    /// for the boost landing in the denominator too, or the miner gets
    /// only `credit · (1 − u_i/S)` of what the ledger promised — for a
    /// 50 % miner, half — and carries the rest forever.
    #[test]
    fn a_held_credit_is_paid_out_in_full() {
        const T: u64 = 312_500_000;
        const CREDIT: i64 = 10_000_000;
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::from([(addr(A1), Sats(CREDIT))]);
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let settled = settle(&d, T);
        assert!(
            (settled[A1].paid - settled[A1].claim - CREDIT).abs() <= 2,
            "A1 was paid {} on a claim of {} — the credit arrived only partly",
            settled[A1].paid,
            settled[A1].claim
        );
        assert!(
            settled[A1].balance_after.abs() <= 2,
            "the credit must be settled, balance left at {}",
            settled[A1].balance_after
        );
    }

    /// And nobody else may move for it. The miner with no balance is
    /// paid its score share of what the credit LEAVES and claims the
    /// same — charging it a share of the whole pot instead would credit
    /// it the other miner's repayment, on this block and every block
    /// after it.
    #[test]
    fn repaying_one_miner_leaves_the_others_flat() {
        const T: u64 = 312_500_000;
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::from([(addr(A1), Sats(10_000_000))]);
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let settled = settle(&d, T);
        assert!(
            settled[A2].delta.abs() <= 2,
            "A2 holds no balance yet moved by {} (paid {}, claim {})",
            settled[A2].delta,
            settled[A2].paid,
            settled[A2].claim
        );
    }

    /// The finder bonus is the same promise in a different wrapper: on
    /// the wire it is a weight boost, in the ledger a fixed sats
    /// entitlement, and the coinbase has to deliver it whole.
    #[test]
    fn the_finder_bonus_arrives_whole() {
        const T: u64 = 312_500_000;
        const BONUS: i64 = 50_000_000;
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_sats = Some(Sats(BONUS));
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();
        assert_eq!(d.finder_bonus, Some((addr(A1), BONUS as u64)));

        let settled = settle(&d, T);
        let share_of_the_rest = settled[A1].claim - BONUS;
        assert!(
            (settled[A1].paid - share_of_the_rest - BONUS).abs() <= 2,
            "the finder was paid {} on a score share of {share_of_the_rest} — \
             the bonus arrived only partly",
            settled[A1].paid
        );
        // Both members settle flat: the bonus was promised AND paid.
        for a in [A1, A2] {
            assert!(
                settled[a].delta.abs() <= 2,
                "{a} moved by {} on an exactly-paying block",
                settled[a].delta
            );
        }
    }

    /// The pool's books close on every block. Every satoshi it holds
    /// back from a claim is a satoshi it owes, and every satoshi it
    /// pays beyond one is a satoshi it is owed — so `Σ balances` after
    /// an exactly-paying block is zero, whatever the promises were and
    /// whatever revenue the block came in at. A projection and a claim
    /// formula computed from two different `X` would leave a residue
    /// here that grows block after block.
    #[test]
    fn the_ledger_closes_on_every_block() {
        let fee = addr(FEE);
        let finder = addr(A1);
        let shares = HashMap::from([(addr(A1), 3.0), (addr(A2), 1.0)]);
        for (label, balances, bonus, t) in [
            ("flat", HashMap::new(), None, 312_500_000u64),
            (
                "credit",
                HashMap::from([(addr(A1), Sats(10_000_000))]),
                None,
                312_500_000,
            ),
            (
                "debt",
                HashMap::from([(addr(A2), Sats(-7_000_000))]),
                None,
                312_500_000,
            ),
            ("bonus", HashMap::new(), Some(Sats(50_000_000)), 312_500_000),
            (
                // Revenue 20 % above the projection: individual members
                // move (the fixed bonus scales with the block, the
                // claim does not), but the books still close.
                "bonus + credit + rich block",
                HashMap::from([(addr(A2), Sats(4_000_000))]),
                Some(Sats(50_000_000)),
                375_000_000,
            ),
        ] {
            let mut input = base_input(&shares, &balances, &fee);
            input.finder_bonus_sats = bonus;
            input.finder_address = bonus.map(|_| &finder);
            let d = build_weight_distribution(input).unwrap();
            let settled = settle(&d, t);

            // The identity settlement books, read back from the parts.
            let before: i64 = d.entries.iter().map(|e| e.balance_sats).sum();
            let after: i64 = settled.values().map(|s| s.balance_after).sum();
            let claims: i64 = settled.values().map(|s| s.claim).sum();
            let paid: i64 = settled.values().map(|s| s.paid).sum();
            assert_eq!(after - before, claims - paid, "{label}: ledger movement");
            // The §4 integer floors leave a few satoshis in the pool
            // output; nothing beyond that may survive.
            assert!(
                after.abs() <= d.entries.len() as i64 + 2,
                "{label}: {after} sats of liability left standing after the block"
            );
        }
    }

    /// Promises larger than the block cannot all be kept: `pot − X` is
    /// the divisor of the whole projection, so it must stay positive.
    /// The bonus gives way first — it is the promise the pool picks
    /// rather than owes — and the RECORDED bonus is the reduced one,
    /// because settlement pays what the coinbase carried.
    #[test]
    fn promises_beyond_the_block_are_capped_to_a_payable_distribution() {
        const T: u64 = 312_500_000;
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::from([(addr(A2), Sats(20_000_000))]);
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_sats = Some(Sats(10_000_000_000)); // 32x the block
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        let pot = bp_share::miner_pot_sats(d.fee_ppm, T) as i64;
        assert!(
            d.extras_total < pot,
            "X = {} must stay below the pot {pot} — the projection divides by pot − X",
            d.extras_total
        );
        let (_, recorded) = d.finder_bonus.clone().expect("bonus recorded");
        assert_eq!(
            recorded as i64,
            pot * 95 / 100 - 20_000_000,
            "the recorded bonus is what the ledger's own claims leave"
        );
        // Still a payable distribution: the non-finder keeps a real
        // output rather than being pruned to nothing.
        let settled = settle(&d, T);
        assert!(
            settled[A2].paid > 546,
            "the non-finder must still get a real output, got {}",
            settled[A2].paid
        );
        // And it is a CONSISTENT one: the capped bonus is what both the
        // coinbase and the claim use, so an exactly-paying block clears
        // the ledger rather than leaving a residue behind the cap.
        for a in [A1, A2] {
            assert!(
                settled[a].balance_after.abs() <= 2,
                "{a} left holding {} under the solvency cap",
                settled[a].balance_after
            );
        }
    }

    /// `positive balance boosts the wire weight by balance·S/(pot − X)`
    #[test]
    fn positive_balance_boosts_wire_weight() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::from([(addr(A1), Sats(31_250_000))]); // 10 % of T_ref
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let w1 = d.entries.iter().find(|e| e.address.as_str() == A1).unwrap();
        let w2 = d.entries.iter().find(|e| e.address.as_str() == A2).unwrap();
        // The scale is the SCORE space over what the promises leave of
        // the miner cut — the boost has to cover its own dilution, so
        // the divisor is `pot − X`, not the pot and not `weight_p`
        // (which also carries whatever the blockspace cut folded).
        let boost = w1.wire_weight - w1.score_weight;
        let pot = bp_share::miner_pot_sats(d.fee_ppm, d.reference_revenue_sats) as u128;
        let expected =
            (31_250_000u128 * d.score_total as u128 / (pot - d.extras_total as u128)) as u64;
        assert_eq!(d.extras_total, 31_250_000);
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
        assert_eq!(
            w1.score_weight,
            SCORE_PRECISION / 2,
            "score kept for settlement"
        );
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

    /// `payout_entries_at: fee first, Σ == t, dust pruned`
    #[test]
    fn payout_entries_at_is_fee_first_and_exact() {
        let shares = HashMap::from([(addr(A1), 3.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let t = 312_500_000u64;
        let entries = d.payout_entries_at(t).unwrap();
        assert_eq!(entries[0].0, fee, "pool output first");
        let total: u64 = entries.iter().map(|(_, s)| s).sum();
        assert_eq!(total, t, "the §4 vector consumes exactly t");
        // 75/25 split (fee-diluted) in §4 order after the pool output.
        assert_eq!(entries[1].0, addr(A1));
        assert_eq!(entries[2].0, addr(A2));
        assert!(entries[1].1 > entries[2].1);
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

    /// The single-entry case above cannot reorder. With two miners whose
    /// wire weights CROSS as the reference revenue moves, the coinbase
    /// order flips — and the identity must not move with it, or every
    /// rebuild against a fresh template mints a new snapshot.
    #[test]
    fn fingerprint_survives_a_boost_driven_reorder() {
        let shares = HashMap::from([(addr(A1), 51.0), (addr(A2), 49.0)]);
        // A2 trails on shares but holds credit, so a small T_ref lifts
        // it past A1 while a large one leaves it behind.
        let balances = HashMap::from([(addr(A2), Sats(5_000_000))]);
        let fee = addr(FEE);
        let a = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let mut input = base_input(&shares, &balances, &fee);
        input.reference_revenue_sats = 50_000_000;
        let b = build_weight_distribution(input).unwrap();
        assert_ne!(
            a.entries[0].address, b.entries[0].address,
            "fixture must actually reorder the coinbase between the two revenues"
        );
        assert_eq!(
            a.fingerprint, b.fingerprint,
            "the coinbase order is not the settlement identity"
        );
    }
}
