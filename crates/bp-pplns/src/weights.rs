// SPDX-License-Identifier: AGPL-3.0-or-later

//! Weight-native payout distribution (SV2 ext 0x0003).
//!
//! The distribution is the pool's payout state in the extension's terms
//! (§3.1): relative integer weights per output plus per-output dust limits.
//! Every satoshi amount is derived later as `floor(weight·T/W)` (§4), by the
//! pool, by a JDC and by the validator alike.
//!
//! The only satoshi quantity in the ledger is a **balance repayment**: a
//! signed debt, projected into weight space against the reference revenue at
//! build time and booked exactly at settlement from the raw inputs. The
//! Group-Solo finder bonus is a proportion (`b = S·f/(1−f)` on the finder's
//! score weight), so it is exact at every revenue and has no entry in `X`.
//!
//! A repayment comes out of the pot it is paid from, so the score split runs
//! over `pot(T) − X` on both sides: the published weights and the settlement
//! claims. One shared [`bp_share::project_extras`] resolves `X` for both;
//! two sides splitting two different pots would mint money.
//!
//! The pool takes its fee and nothing more. `weight_P` is the fee over the
//! published weights only, because §4 pays the pool output the residual
//! (`pay_P = T − Σpay`). Under PPLNS an entry below `min_payout` or without
//! blockspace is withheld by dropping it from the published set, never by
//! moving its weight to the pool: the published miners carry the matching
//! debt and `Σ deltas = 0`. The wire `dust_limit` is therefore the consensus
//! floor ([`DUST_LIMIT_SATS`]), not the pool's operational threshold.

use std::collections::HashMap;

use bp_common::{AddressId, Sats};
use bp_share::weights_fingerprint_from_parts;

use crate::weight::{
    is_valid_payout_address, output_weight_for_address, BUDGET_SAFETY_MARGIN_WU,
    COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT,
    DEFAULT_COINBASE_WEIGHT_BUDGET, DUST_LIMIT_SATS, MAX_FINDER_BONUS_PPM,
};
use crate::BudgetTelemetry;

/// Integer score precision: share fractions are projected onto this
/// many parts. 10^12 represents every miner above a 10^-12 pool fraction
/// (below that a block pays < 0.001 sat) while `Σ weights · T` stays far
/// inside u128 (§4's 128-bit intermediate bound).
pub const SCORE_PRECISION: u64 = 1_000_000_000_000;

/// One address in the distribution.
///
/// `score_weight` and `balance_sats` are the settlement inputs: the
/// snapshot stores them and `earned(T_actual)` is recomputed from them
/// when a block is booked. `wire_weight` is the published weight
/// (score + projected balance boost); `0` means no coinbase output this
/// distribution (below `min_payout`, cut for blockspace, zero score with
/// no positive balance, or a debt that swallowed the score), but the
/// address still settles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightEntry {
    pub address: AddressId,
    pub score_weight: u64,
    pub balance_sats: i64,
    pub wire_weight: u64,
    /// §3.1 per-output dust limit: the consensus floor
    /// ([`DUST_LIMIT_SATS`]) for every entry. The pool's `min_payout`
    /// decides whether an entry is published at all instead, because a
    /// §4 prune would pay the pruned value to the pool output.
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
    /// `weight_P` (§3.1): the pool output's weight. Always carries the
    /// fee, never a repayment (a debt is owed to the other miners).
    /// Whether it also carries what this build withheld depends on
    /// [`WeightDistributionInput::withheld_value`]. Always ≥ 1 (the §4
    /// residual needs a live pool output).
    pub weight_p: u64,
    /// Pool fee in parts-per-million of revenue (1 % = 10 000 ppm).
    pub fee_ppm: u32,
    /// Recipient of the pool output (`pool_payout` script source).
    pub fee_address: AddressId,
    /// Revenue the balance boosts were projected against.
    pub reference_revenue_sats: u64,
    /// `S = Σ score_weight` — denominator of every settlement claim.
    pub score_total: u64,
    /// `X`: the satoshi promises (ledger balances; not the finder bonus,
    /// which is a proportion) paid on top of the score split, after
    /// solvency capping. The score share is taken over `pot(T) − X`, here
    /// and at settlement. Not part of the fingerprint: settlement
    /// recomputes it from the stored inputs.
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

/// Where the value of an entry that does NOT get a coinbase output goes.
///
/// An entry drops out of the coinbase two ways: its §4 amount falls below
/// the pool's `min_payout`, or the blockspace cut folds it away. Either
/// way its share of the block has to land somewhere, and that single
/// choice is the difference between a payout model that needs a ledger
/// and one that does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithheldValue {
    /// Spread over the miners who ARE published, who then owe the
    /// withheld miner the difference. The value never leaves the miners'
    /// cut, and the credit is repaid out of a later block — which is
    /// exactly the promise `pplns_balance` exists to remember. PPLNS.
    ToOtherMiners,
    /// Left in the §4 residual, i.e. paid to the pool output. The
    /// withheld miner is owed nothing afterwards and nobody was
    /// overpaid, so there is no difference for a ledger to carry.
    /// Every published miner is paid exactly their score share, unchanged
    /// by who dropped out. Group-Solo.
    ///
    /// The pool earns more than its fee on such a block, deliberately.
    /// Group-Solo rounds are short and the members are known to each
    /// other; carrying a balance between rounds buys a case the operator
    /// does not want at the price of the machinery that makes the pool
    /// hard to reason about.
    ToPool,
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
    /// Operational minimum on-chain output. Applied when the published
    /// set is chosen: an entry whose §4 amount at
    /// `reference_revenue_sats` would fall short is not published (and
    /// settles as credit instead). `None` falls back to
    /// `DUST_LIMIT_SATS`; always clamped ≥ it.
    pub min_payout_sats: Option<Sats>,
    /// Group-Solo finder bonus as a fraction of the miner cut, in
    /// parts-per-million (1 % = 10 000 ppm). `0` disables it. Clamped
    /// to [`MAX_FINDER_BONUS_PPM`].
    ///
    /// A PROPORTION, deliberately — see the derivation in the build. A
    /// fixed satoshi bonus cannot be paid exactly by a party using a
    /// different template revenue, and §4 gives every payer their own.
    pub finder_bonus_ppm: u32,
    pub finder_address: Option<&'a AddressId>,
    /// Current template revenue — the projection base for balance and
    /// bonus boosts. Must be non-zero (a pool with no template has
    /// nothing to distribute against).
    pub reference_revenue_sats: u64,
    /// Who receives what an unpublished entry would have been paid.
    /// See [`WithheldValue`] — this is the one knob that decides whether
    /// the mode needs a ledger.
    pub withheld_value: WithheldValue,
}

/// Why a weight distribution could not be built.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WeightBuildError {
    /// `reference_revenue_sats == 0` — boosts have no projection base.
    #[error("reference revenue is zero")]
    ZeroReferenceRevenue,
    /// The configured pool-output recipient is not a usable payout
    /// address. `pay_P` is structural (§4), so this fails the build
    /// rather than the coinbase assembly, which would stop jobs for every
    /// miner instead of one output.
    #[error("fee address is not a valid payout address: {0}")]
    InvalidFeeAddress(String),
    /// `Σ score_weight == 0`: nobody holds a share of this window/round,
    /// so there is no proportion to split the block by.
    ///
    /// Refused because the alternative pays the whole block to
    /// `fee_address`: nothing is published, `weight_P` floors at 1 and §4
    /// makes the pool output the residual, while settlement books nothing
    /// (every claim is 0). The same outcome
    /// [`crate::weight::MIN_COINBASE_WEIGHT_BUDGET`] rules out.
    ///
    /// Not the same condition as "nothing published": a 100 % fee or a
    /// `min_payout` above the whole block publish nothing on purpose and
    /// keep `score_total > 0`. This fires only for an empty share source
    /// (a new Group-Solo group, a group after a calendar reset, a fresh
    /// PPLNS window).
    ///
    /// A caller that knows which miner is asking retries with that miner
    /// as the sole claimant (see
    /// `bp_coinbase_snapshot::BuildRequest::bootstrap_claimant`); with
    /// nobody scored, nobody else is owed anything. A caller that does
    /// not know (the pool-wide JDP publisher) publishes nothing.
    #[error("no address holds a share — nothing to split the block by")]
    NoScoredMiners,
}

/// `weight_P` for a given published weight total: the fee, and only
/// the fee. Solving `weight_P / (weight_P + P) = f` gives
/// `weight_P = P·f/(1−f)`, so `W = P/(1−f)` and the §4 residual
/// `pay_P = T − Σ floor(w_i·T/W)` comes out at `f·T` — whatever the
/// published set is, and whatever promises its weights carry.
///
/// Floors at 1: §4 needs a live pool output, and with nothing published
/// (or a 100 % fee) the pool output is the whole coinbase.
fn pool_weight_for(published_total: u128, fee_ppm: u32) -> u64 {
    if fee_ppm >= 1_000_000 || published_total == 0 {
        return 1;
    }
    ((published_total * fee_ppm as u128) / (1_000_000 - fee_ppm) as u128).clamp(1, u64::MAX as u128)
        as u64
}

/// What §4 pays a `weight` at revenue `t`, given the published total it
/// sits in. The exact figure the coinbase will carry, so the
/// `min_payout` decision below is made on the number the miner would
/// actually receive rather than on an estimate of it.
fn payout_at(weight: u64, published_total: u128, fee_ppm: u32, t: u64) -> u64 {
    let w_total = published_total + pool_weight_for(published_total, fee_ppm) as u128;
    bp_share::mul_div_floor(weight, t, w_total)
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

    // The pool's operational threshold in satoshis. Kept as u64, not
    // narrowed to the u32 wire `dust_limit`, so an oversized min_payout
    // cannot wrap below the floor the `.max()` guarantees.
    let min_payout: u64 = input
        .min_payout_sats
        .map(|s| s.0.max(DUST_LIMIT_SATS as i64) as u64)
        .unwrap_or(DUST_LIMIT_SATS);

    // 1 % = 10_000 ppm. fee_percent is pre-validated to [0, 100].
    let fee_ppm = (input.fee_percent * 10_000.0).round() as u32;

    // ── Score projection ────────────────────────────────────────────
    // u_i = round(share_i / Σshares · SCORE_PRECISION). Scale-invariant
    // in the window's own units; miners below 1/SCORE_PRECISION of the
    // pool project to 0 and settle (to 0) without an output.
    // Summed in address order, not `HashMap` order: f64 addition is not
    // associative, so a map-order sum would let identical pool state
    // produce different scores and a new settlement fingerprint.
    // The fee address is never a miner entry: it is paid via `weight_P`
    // and settlement books no row for it, so a miner-shaped output to it
    // would pay satoshis that nothing debits.
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
        /// What this block pays the address: its score share of what the
        /// promises leave, plus its own promise.
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
    // Nobody holds a share: refuse rather than pay the whole block to the
    // pool output. See `WeightBuildError::NoScoredMiners` for why this is
    // the score total and not "nothing published". The finder bonus
    // (`S·f/(1−f)`) cannot lift a zero total, so checking before it is
    // equivalent.
    if score_total == 0 {
        return Err(WeightBuildError::NoScoredMiners);
    }
    let publish_all = fee_ppm < 1_000_000;

    // ── Finder bonus ────────────────────────────────────────────────
    //
    // A proportion of the miner cut, never a fixed satoshi amount: §4
    // pays every weight `w·T/W`, so a proportion is exact at every
    // revenue, including a job-declaring client's own template, while a
    // fixed amount would need a ledger to correct the difference.
    //
    // Solving `(u_f + b)/(S + b) = f + (1−f)·u_f/S` for the weight that
    // delivers the fraction `f` on top of the score split:
    //
    //     b = S · f / (1 − f)
    //
    // the same closed form `pool_weight_for` uses for the fee, because a
    // share has to survive its own dilution. It lands on the SCORE weight,
    // so it is part of the settlement claim by construction: no extra
    // term at settlement, no entry in `extras`, no solvency cap.
    let bonus_ppm = input.finder_bonus_ppm.min(MAX_FINDER_BONUS_PPM);
    if bonus_ppm > 0 && score_total > 0 {
        if let Some(finder) = input.finder_address {
            if is_valid_payout_address(finder.as_str()) && !is_fee(finder) {
                let boost = ((score_total as u128 * bonus_ppm as u128)
                    / (1_000_000 - bonus_ppm) as u128)
                    .min(u64::MAX as u128) as u64;
                if boost > 0 {
                    candidates
                        .entry(finder)
                        .or_insert_with(|| Candidate {
                            address: finder.clone(),
                            score_weight: 0,
                            balance_sats: 0,
                            wire_weight: 0,
                        })
                        .score_weight += boost;
                }
            }
        }
    }
    // Re-read AFTER the boost: the bonus is score weight now, so it is
    // in the denominator every claim is measured against.
    let score_total: u64 = candidates.values().map(|c| c.score_weight).sum();

    let mut entries: Vec<Candidate> = candidates.into_values().collect();

    // ── Sats → weight projection ────────────────────────────────────
    //
    // A ledger balance is a promise to pay a fixed amount on top of the
    // score split; the weight model expresses it as a boost on that
    // entry's weight.
    //
    // The scale is not `sats · S / pot`, because a boost lands in the
    // denominator as well: with `e_i = u_i + boost_i` and
    // `E = Σ e_i = S + Σ boost`, each entry is paid `e_i · pot / E`, so
    // raising one entry dilutes every entry including itself. Solving
    // for the boost that delivers `extra_i` on top of the score split
    // gives
    //
    //     boost_i = extra_i · S / (pot(t_ref) − X),   X = Σ extra_i
    //
    // since then `E = S · pot/(pot − X)` and therefore
    //
    //     paid_i = e_i · pot / E = (u_i/S)·(pot − X) + extra_i
    //
    // the score share of what is left after the promises, plus this
    // entry's own promise. Signs carry through, so a debt shrinks the
    // payout by exactly what is owed, and the settlement claim
    // (`bp_share::claim_sats`, same `X`) is the first term alone.
    let extras = bp_share::extras_from_ledger(
        entries
            .iter()
            .map(|c| (c.address.as_str(), c.score_weight, c.balance_sats)),
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

    // ── Operational payout threshold ────────────────────────────────
    //
    // `min_payout` decides who is published; it is not the §3.1
    // `dust_limit`, which makes every §4 evaluator prune an output after
    // the split is fixed and so sends the value to the pool output. See
    // `WithheldValue` for where the value goes in each mode.
    //
    // Smallest first: an entry's payout is monotonic in its wire weight,
    // so the first entry that clears the threshold clears it for every
    // larger one behind it.
    let full_total: u128 = entries.iter().map(|c| c.wire_weight as u128).sum();
    let mut published_total = full_total;
    for c in entries.iter_mut().rev() {
        if c.wire_weight == 0 {
            continue;
        }
        // The denominator this entry's payout is measured against.
        // `ToOtherMiners`: `W` follows the published set, so withholding
        // one entry raises what every remaining one is paid.
        // `ToPool`: withheld weight stays in `W` (added to `weight_P`
        // below), so a published entry's payout does not move when
        // another drops out; the shrinking total would understate it.
        let basis = match input.withheld_value {
            WithheldValue::ToOtherMiners => published_total,
            WithheldValue::ToPool => full_total,
        };
        if payout_at(c.wire_weight, basis, fee_ppm, t_ref) >= min_payout {
            break;
        }
        published_total -= c.wire_weight as u128;
        c.wire_weight = 0;
    }

    // ── Blockspace cut ──────────────────────────────────────────────
    // Greedy keep in published order while the real serialized weight
    // fits the budget; trimmed entries leave the published set and settle
    // off-chain (§3.1). Where their value goes is decided at `weight_p`.
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
    // In both modes this carries the fee: `W = P + weight_P` resolves to
    // `P/(1 − f)`, so the §4 residual pays the pool exactly `f·T` however
    // large the credits being repaid are. A repayment moves value within
    // the miners' cut, never into or out of the pool's fee.
    //
    // Whether the withheld weight is added on top is the difference
    // between the two modes.
    //
    // `ToOtherMiners` leaves it out: weight in `weight_P` would be cash
    // the pool keeps against a claim the other miners later repay. The
    // withheld share spreads over the published miners instead, and
    // settlement books that overpayment as the matching debt.
    //
    // `ToPool` adds it and takes the fee over the full total. That gives
    // `W = P_all/(1−f)`, so every published miner is paid exactly what
    // they would have been paid had nobody dropped out, and the withheld
    // share falls into the §4 residual. Nobody is over- or underpaid, so
    // there is nothing for a ledger to remember.
    let published_total: u128 = entries.iter().map(|c| c.wire_weight as u128).sum();
    let weight_p = match input.withheld_value {
        WithheldValue::ToOtherMiners => pool_weight_for(published_total, fee_ppm),
        WithheldValue::ToPool => {
            let withheld_total = (full_total - published_total).min(u64::MAX as u128) as u64;
            pool_weight_for(full_total, fee_ppm).saturating_add(withheld_total)
        }
    };

    // Order can change where the cut zeroed wire weights mid-list:
    // restore the published-then-unpublished invariant (stable sort
    // keeps the relative order of both groups).
    entries.sort_by_key(|c| c.wire_weight == 0);

    // Hashed over an address-ordered view, not the coinbase order: that
    // order follows wire weights, which carry `t_ref` through the balance
    // boosts, and builds at different revenues must share one settlement
    // identity.
    let mut identity: Vec<&Candidate> = entries.iter().collect();
    identity.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
    let fingerprint = weights_fingerprint_from_parts(
        fee_ppm,
        input.fee_address.as_str(),
        identity.iter().map(|c| {
            (
                c.address.as_str(),
                c.score_weight,
                c.balance_sats,
                DUST_LIMIT_SATS as u32,
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
                // The consensus floor, not `min_payout`: the threshold
                // was applied by withholding above, and publishing it here
                // would send withheld value into the §4 residual (the
                // pool output).
                dust_limit: DUST_LIMIT_SATS as u32,
            })
            .collect(),
        weight_p,
        fee_ppm,
        fee_address: input.fee_address.clone(),
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
            finder_bonus_ppm: 0,
            finder_address: None,
            reference_revenue_sats: 312_500_000,
            withheld_value: WithheldValue::ToOtherMiners,
        }
    }

    /// A distinct, valid P2WSH address per index — the worst-case output
    /// weight (172 WU), so the ceiling's own pessimistic assumption is the
    /// one being exercised.
    fn worst_case_addr(i: u32) -> String {
        use bitcoin::hashes::Hash as _;
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        let script = bitcoin::ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array(h));
        bitcoin::Address::from_script(&script, bitcoin::Network::Bitcoin)
            .expect("p2wsh script is addressable")
            .to_string()
    }

    /// MONEY / Group-Solo's ledger-free invariant: `max_coinbase_outputs`
    /// is what `GroupService` refuses a join against, so it MUST equal what
    /// the blockspace cut can actually publish. One too many and a member is
    /// admitted whose output the cut drops, and under `WithheldValue::ToPool`
    /// their share goes to the pool with no ledger to remember it.
    ///
    /// Checked against the builder, not the formula, at 0 % fee too: the
    /// pool output is structural under §4 and exists at every fee.
    #[test]
    fn the_member_ceiling_is_what_the_blockspace_cut_publishes() {
        for budget in [
            crate::weight::MIN_COINBASE_WEIGHT_BUDGET,
            1_500,
            2_000,
            5_000,
            10_000,
        ] {
            let ceiling = crate::weight::max_coinbase_outputs(budget) as usize;
            // Both fees must land on the same ceiling, because the pool
            // output exists either way.
            for fee_percent in [0.0, 1.5] {
                let fee = addr(FEE);
                // Exactly `ceiling` miners must ALL be published.
                let shares: HashMap<AddressId, f64> = (0..ceiling as u32)
                    .map(|i| (addr(&worst_case_addr(i)), 1.0))
                    .collect();
                let balances = HashMap::new();
                let d = build_weight_distribution(WeightDistributionInput {
                    coinbase_weight_budget: budget,
                    fee_percent,
                    // Every miner gets an equal 1/ceiling slice of a whole
                    // block, so `min_payout` never withholds anyone — the
                    // blockspace cut is the only thing that can trim here.
                    min_payout_sats: Some(Sats(546)),
                    ..base_input(&shares, &balances, &fee)
                })
                .unwrap();
                assert_eq!(
                    d.published().count(),
                    ceiling,
                    "budget {budget} at {fee_percent} % fee: the ceiling says {ceiling} \
                     members fit, the cut published {} — a member the pool admits and \
                     then cannot pay forfeits their whole share",
                    d.published().count()
                );
                assert_eq!(
                    d.budget_telemetry.trimmed_count, 0,
                    "budget {budget} at {fee_percent} %: nothing may be trimmed at the ceiling"
                );

                // And one more must NOT fit — otherwise the ceiling is
                // merely conservative and this test proves nothing.
                let shares: HashMap<AddressId, f64> = (0..=ceiling as u32)
                    .map(|i| (addr(&worst_case_addr(i)), 1.0))
                    .collect();
                let d = build_weight_distribution(WeightDistributionInput {
                    coinbase_weight_budget: budget,
                    fee_percent,
                    min_payout_sats: Some(Sats(546)),
                    ..base_input(&shares, &balances, &fee)
                })
                .unwrap();
                assert_eq!(
                    d.budget_telemetry.trimmed_count, 1,
                    "budget {budget} at {fee_percent} %: one past the ceiling must be \
                     trimmed, or the ceiling is not the real limit"
                );
            }
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

    /// And the same for the finder bonus. The bonus lands on a SCORE
    /// weight, and settlement skips any entry whose address is the fee
    /// address (`build_writes_from_weight_snapshot` logs and `continue`s
    /// on it). So a bonus boost on the fee address would be paid by the
    /// coinbase and debited by nothing — money created out of the
    /// ledger's blind spot, the same hole the balance and share guards
    /// above exist to close.
    ///
    /// The trade is deliberate: a pool mining Group-Solo to its own fee
    /// address forfeits the bonus rather than minting it.
    #[test]
    fn a_fee_address_finder_gets_no_bonus_boost() {
        let fee = addr(FEE);
        let balances = HashMap::new();
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 200_000; // 20 %
        input.finder_address = Some(&fee);
        let d = build_weight_distribution(input).unwrap();

        assert!(
            !d.entries.iter().any(|e| e.address.as_str() == FEE),
            "the bonus must not conjure a fee-address entry settlement refuses to book"
        );
        // The two miners keep the whole score space, split evenly — the
        // bonus was dropped, not silently redistributed to one of them.
        assert_eq!(d.entries.len(), 2);
        assert_eq!(d.entries[0].score_weight, d.entries[1].score_weight);
        const T: u64 = 312_500_000;
        let paid = d.payout_entries_at(T).expect("§4 vector");
        assert_eq!(
            paid.iter().filter(|(a, _)| a.as_str() == FEE).count(),
            1,
            "fee address must be paid exactly once — the pool output: {paid:?}"
        );
        assert_eq!(paid.iter().map(|(_, s)| *s).sum::<u64>(), T, "Σ == T");
    }

    /// The mirror case, so the guard above is pinned as a fee-address
    /// rule and not as "the bonus never applies": the same input with a
    /// normal finder must actually boost that finder.
    #[test]
    fn a_normal_finder_still_gets_the_bonus_boost() {
        let fee = addr(FEE);
        let balances = HashMap::new();
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 200_000; // 20 %
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        let score_of = |a: &str| {
            d.entries
                .iter()
                .find(|e| e.address.as_str() == a)
                .map(|e| e.score_weight)
                .expect("entry")
        };
        assert!(
            score_of(A1) > score_of(A2),
            "the finder must out-weigh an equal-share peer by the bonus"
        );
        // b = S·f/(1−f) on a 50/50 split: the finder ends up holding
        // f + (1−f)/2 = 60 % of the score space at f = 0.2.
        let total = score_of(A1) + score_of(A2);
        let finder_pct = score_of(A1) as f64 / total as f64;
        assert!(
            (finder_pct - 0.6).abs() < 1e-6,
            "expected the finder at 60 % of the score space, got {finder_pct}"
        );
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

    /// A configured bonus cannot swallow the block. As a PROPORTION it is
    /// bounded by construction (the operator cannot express "more than the
    /// pot"), and the ppm cap keeps even a typo inside
    /// [`MAX_FINDER_BONUS_PPM`].
    #[test]
    fn a_bonus_beyond_the_cap_is_clamped_and_leaves_the_others_paid() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 900_000; // 90 % — past the cap
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        const T: u64 = 312_500_000;
        let paid = d.payout_entries_at(T).expect("§4 vector");
        let of = |a: &str| -> u64 {
            paid.iter()
                .filter(|(addr, _)| addr.as_str() == a)
                .map(|(_, s)| *s)
                .sum()
        };
        let pot = bp_share::miner_pot_sats(d.fee_ppm, T) as f64;
        // Clamped to 50 %, so the finder takes half the pot plus half of
        // what is left (it holds 1 of 2 equal scores) = 75 %.
        let finder_share = of(A1) as f64 / pot;
        assert!(
            (finder_share - 0.75).abs() < 0.001,
            "finder took {finder_share} of the pot, expected the clamped 0.75"
        );
        assert!(
            of(A2) as f64 / pot > 0.24,
            "the non-finder keeps its quarter, got {}",
            of(A2)
        );
    }

    /// A proportional bonus is EXACT at every revenue, so a job-declaring
    /// client paying from its own template delivers the same bonus the
    /// pool would have.
    #[test]
    fn the_bonus_is_the_same_fraction_at_every_revenue() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0), (addr(A3), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 100_000; // 10 %
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        // 10 % off the top, then an equal third of the rest: 0.4.
        const T_REF: u64 = 312_500_000;
        for pct in [50u64, 75, 100, 125, 200, 400] {
            let t = T_REF * pct / 100;
            let paid = d.payout_entries_at(t).expect("§4 vector");
            let finder_paid: u64 = paid
                .iter()
                .filter(|(a, _)| a.as_str() == A1)
                .map(|(_, s)| *s)
                .sum();
            let pot = bp_share::miner_pot_sats(d.fee_ppm, t) as f64;
            let fraction = finder_paid as f64 / pot;
            assert!(
                (fraction - 0.4).abs() < 0.0001,
                "at T = {pct} % the finder got {fraction} of the pot, not 0.4"
            );
        }
    }

    /// A disabled bonus must leave the distribution byte-identical —
    /// including the settlement identity, which has no bonus slot of its
    /// own.
    #[test]
    fn a_disabled_bonus_changes_nothing() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let plain = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 0;
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();
        assert_eq!(d.score_total, plain.score_total);
        assert_eq!(d.fingerprint, plain.fingerprint);
    }

    /// A min_payout beyond the 32-bit wire field must never wrap, or an
    /// operator entering sats where BTC was meant would turn the threshold
    /// off. The threshold decides who is PUBLISHED, so a min_payout above
    /// the whole block leaves nobody publishable.
    #[test]
    fn oversized_min_payout_withholds_instead_of_wrapping() {
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
                d.published().count(),
                0,
                "min_payout {min_payout} exceeds the whole block, yet an output was published"
            );
            // The wire limit is the consensus floor and nothing else.
            assert_eq!(d.entries[0].dust_limit, DUST_LIMIT_SATS as u32);
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

    /// A debt is a claim the OTHER miners hold, not the pool's income, so
    /// collecting it has to reach them. It does through `X`: a negative
    /// `X` enlarges the pot every score is measured against by exactly
    /// what is repaid. The pool keeps its fee and nothing more.
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

    /// What the §4 vector pays each MINER address at revenue `t` — the
    /// pool output (always first) excluded.
    fn paid_map(d: &WeightDistribution, t: u64) -> HashMap<String, u64> {
        let mut out: HashMap<String, u64> = HashMap::new();
        for (address, sats) in d.payout_entries_at(t).expect("§4 vector").iter().skip(1) {
            *out.entry(address.as_str().to_string()).or_insert(0) += *sats;
        }
        out
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
                let claim = bp_share::claim_sats(
                    e.score_weight,
                    d.score_total,
                    d.fee_ppm,
                    t,
                    d.extras_total,
                );
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

    /// The bonus settles flat at EVERY revenue, not just at the one it
    /// was built against, so a job-declaring client paying from its own
    /// template is harmless.
    #[test]
    fn the_bonus_settles_flat_at_every_revenue() {
        const T_REF: u64 = 312_500_000;
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A1);
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 160_000; // 16 %
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        for pct in [75u64, 100, 125, 250] {
            let t = T_REF * pct / 100;
            let settled = settle(&d, t);
            for a in [A1, A2] {
                assert!(
                    settled[a].delta.abs() <= 2,
                    "at T = {pct} % {a} moved by {} — the bonus must not drift",
                    settled[a].delta
                );
            }
        }
    }

    /// The books close on every block: `Σ balances` after an exactly-paying
    /// block is zero, whatever the promises and the revenue. A projection
    /// and a claim computed from two different `X` would leave a residue
    /// here that grows block after block.
    #[test]
    fn the_ledger_closes_on_every_block() {
        let fee = addr(FEE);
        let finder = addr(A1);
        let shares = HashMap::from([(addr(A1), 3.0), (addr(A2), 1.0)]);
        for (label, balances, bonus, t) in [
            ("flat", HashMap::new(), 0u32, 312_500_000u64),
            (
                "credit",
                HashMap::from([(addr(A1), Sats(10_000_000))]),
                0,
                312_500_000,
            ),
            (
                "debt",
                HashMap::from([(addr(A2), Sats(-7_000_000))]),
                0,
                312_500_000,
            ),
            ("bonus", HashMap::new(), 160_000, 312_500_000),
            (
                // Revenue 20 % above the projection. The bonus is a
                // proportion and moves nobody; the held credit is a fixed
                // sats promise, so members move for that alone and the
                // books still close.
                "bonus + credit + rich block",
                HashMap::from([(addr(A2), Sats(4_000_000))]),
                160_000,
                375_000_000,
            ),
        ] {
            let mut input = base_input(&shares, &balances, &fee);
            input.finder_bonus_ppm = bonus;
            input.finder_address = (bonus > 0).then_some(&finder);
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

    /// A held BALANCE is a fixed sats promise, the one thing the weight
    /// model projects, so `pot − X` has to stay positive and the solvency
    /// scale has to fire.
    #[test]
    fn a_balance_beyond_the_block_is_scaled_to_a_payable_distribution() {
        const T: u64 = 312_500_000;
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        // Ten times the whole block, held as credit.
        let balances = HashMap::from([(addr(A2), Sats(3_000_000_000))]);
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();

        let pot = bp_share::miner_pot_sats(d.fee_ppm, T) as i64;
        assert!(
            d.extras_total < pot,
            "X = {} must stay below the pot {pot} — the projection divides by pot − X",
            d.extras_total
        );
        // Still payable: the member without a balance keeps a real output.
        let settled = settle(&d, T);
        assert!(
            settled[A1].paid > 546,
            "the other member must still get a real output, got {}",
            settled[A1].paid
        );
        // What the scale could not pay stays on the ledger rather than
        // vanishing — the credit holder is still owed the remainder.
        assert!(
            settled[A2].balance_after > 0,
            "the unpayable part of the credit must carry, got {}",
            settled[A2].balance_after
        );
    }

    // ── The pool is paid its fee, and only its fee ──────────────────
    //
    // A miner too small to be worth an output is withheld at build time,
    // not pruned by a §3.1 dust limit: a §4 prune hands the value to the
    // pool output (`pay_P = T − Σpay`) while settlement credits the miner,
    // and the other miners would repay that credit. Withholding keeps the
    // value inside the miners' cut: §4 gives it to the published miners
    // and settlement books the overpayment as debt against the withheld
    // miner's credit. The tests below pin each part of that.

    /// Shares that leave A3 just under the harness's 5 000-sat
    /// `min_payout` (~4 600 sats of a 312.5 M block), with A1 and A2 at
    /// a clean 3:1 so the redistribution is checkable by eye.
    fn dust_fixture() -> HashMap<AddressId, f64> {
        HashMap::from([
            (addr(A1), 3_000_000.0),
            (addr(A2), 1_000_000.0),
            (addr(A3), 60.0),
        ])
    }

    /// What A3 would have been paid had it been published — the amount
    /// under dispute in every test below.
    fn withheld_payout(d: &WeightDistribution, t: u64) -> i64 {
        let a3 = d.entries.iter().find(|e| e.address.as_str() == A3).unwrap();
        let total: u128 = d.entries.iter().map(|e| e.score_weight as u128).sum();
        (a3.score_weight as u128 * bp_share::miner_pot_sats(d.fee_ppm, t) as u128 / total) as i64
    }

    /// The pool output is the fee, not the fee plus a small miner's
    /// payout: that satoshi is owed to a miner.
    #[test]
    fn a_withheld_miner_never_lands_in_the_pool_output() {
        const T: u64 = 312_500_000;
        let shares = dust_fixture();
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();

        // The fixture has to actually withhold, or this proves nothing.
        let a3 = d.entries.iter().find(|e| e.address.as_str() == A3).unwrap();
        assert_eq!(a3.wire_weight, 0, "A3 must be below min_payout");
        assert!(a3.score_weight > 0, "and must still settle");
        assert_eq!(d.published().count(), 2);
        let withheld = withheld_payout(&d, T);
        assert!(
            (546..5_000).contains(&withheld),
            "fixture must sit between the consensus floor and min_payout, got {withheld}"
        );

        let paid = d.payout_entries_at(T).expect("§4 vector");
        assert_eq!(paid[0].0, fee, "pool output first");
        let pool_pay = paid[0].1 as i64;
        let fee_only = (T as i64 * d.fee_ppm as i64) / 1_000_000;
        // §4 floors every miner amount, and the leftovers land in the
        // pool output — one satoshi per published output at most.
        assert!(
            (pool_pay - fee_only).abs() <= 1 + d.published().count() as i64,
            "pool took {pool_pay} on a fee of {fee_only}: {} sats of miner money \
             (the withheld payout is {withheld})",
            pool_pay - fee_only
        );
    }

    /// And the withheld miner's share is not lost either — it goes to
    /// the miners who are published, in proportion to their scores.
    #[test]
    fn a_withheld_miner_share_is_redistributed_pro_rata() {
        const T: u64 = 312_500_000;
        let shares = dust_fixture();
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let settled = settle(&d, T);
        let withheld = withheld_payout(&d, T);

        // A1 holds 3/4 of the published score, A2 1/4.
        let published_score: i64 = d
            .published()
            .map(|e| e.score_weight as i64)
            .sum::<i64>()
            .max(1);
        for a in [A1, A2] {
            let score = d
                .entries
                .iter()
                .find(|e| e.address.as_str() == a)
                .unwrap()
                .score_weight as i64;
            let expected = withheld * score / published_score;
            let over = settled[a].paid - settled[a].claim;
            assert!(
                (over - expected).abs() <= 2,
                "{a} was paid {over} above its claim, expected {expected} \
                 of the {withheld} sats A3 left behind"
            );
        }
    }

    /// The other half of the same movement: what the published miners
    /// were paid over their claim they OWE, and the withheld miner is
    /// owed exactly that. The pool is not a party to it — the deltas
    /// cancel among the miners.
    #[test]
    fn the_redistribution_is_booked_as_matching_debits() {
        const T: u64 = 312_500_000;
        let shares = dust_fixture();
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let settled = settle(&d, T);
        let withheld = withheld_payout(&d, T);

        assert_eq!(settled[A3].paid, 0, "the withheld miner is not paid");
        assert!(
            (settled[A3].delta - withheld).abs() <= 2,
            "A3 was credited {} of the {withheld} sats it earned",
            settled[A3].delta
        );
        for a in [A1, A2] {
            assert!(
                settled[a].delta < 0,
                "{a} took a share of A3's payout and must owe it back, delta {}",
                settled[a].delta
            );
        }
        // Σ deltas is zero up to §4's integer floors: each of the two
        // published amounts and each of the three claims is a floor, and
        // those few satoshis are what the pool output absorbs.
        let sum: i64 = settled.values().map(|s| s.delta).sum();
        assert!(
            sum.abs() <= d.entries.len() as i64,
            "the miners' books do not close: {sum} sats left over"
        );
    }

    /// Over two blocks the whole thing has to come out flat: the miner
    /// crosses the threshold and is paid in full, the miners who
    /// pre-funded it are square again, and the pool has been paid its
    /// fee twice — no more.
    #[test]
    fn a_withheld_claim_is_paid_by_the_next_block_and_the_debts_clear() {
        const T: u64 = 312_500_000;
        let shares = dust_fixture();
        let fee = addr(FEE);

        // Block 1 — A3 under the threshold.
        let empty = HashMap::new();
        let first = build_weight_distribution(base_input(&shares, &empty, &fee)).unwrap();
        let settled_1 = settle(&first, T);
        let pool_1 = T as i64 - settled_1.values().map(|s| s.paid).sum::<i64>();
        assert_eq!(settled_1[A3].paid, 0);

        // Block 2 — carrying block 1's ledger forward.
        let balances: HashMap<AddressId, Sats> = settled_1
            .iter()
            .map(|(a, s)| (addr(a), Sats(s.balance_after)))
            .collect();
        let second = build_weight_distribution(base_input(&shares, &balances, &fee)).unwrap();
        let settled_2 = settle(&second, T);

        // A3's credit lifted it over the threshold, and it arrives
        // whole: this block's claim plus what block 1 owed it.
        assert!(
            second
                .entries
                .iter()
                .find(|e| e.address.as_str() == A3)
                .unwrap()
                .wire_weight
                > 0,
            "the held credit must lift A3 into the coinbase"
        );
        let expected = settled_2[A3].claim + balances[&addr(A3)].0;
        assert!(
            (settled_2[A3].paid - expected).abs() <= 2,
            "A3 was paid {} where its claim plus its {} sats of credit is {expected}",
            settled_2[A3].paid,
            balances[&addr(A3)].0
        );
        // Everyone is square: the debts A1 and A2 took on funding that
        // payout are worked off by the same block.
        for a in [A1, A2, A3] {
            assert!(
                settled_2[a].balance_after.abs() <= 2,
                "{a} still holds {} after the credit was paid out",
                settled_2[a].balance_after
            );
        }
        // And the pool was paid its fee, twice, over two blocks that
        // moved a miner's payout from one to the other.
        let pool_2 = T as i64 - settled_2.values().map(|s| s.paid).sum::<i64>();
        let fee_only = (T as i64 * first.fee_ppm as i64) / 1_000_000;
        assert!(
            (pool_1 + pool_2 - 2 * fee_only).abs() <= 6,
            "pool took {pool_1} + {pool_2} where its fee is {fee_only} per block"
        );
    }

    // ── The same tests, for a pool that keeps the overflow ───────────
    //
    // Group-Solo makes the opposite choice: a member the coinbase cannot
    // pay forfeits this block, and their share falls into the §4 residual,
    // i.e. to the pool. Nobody is overpaid or owed, which is why Group-Solo
    // runs without a ledger. That holds only if the published members are
    // paid EXACTLY what they would have been paid had nobody dropped out;
    // any difference would be a debt again.

    fn pool_keeps_overflow<'a>(
        shares: &'a HashMap<AddressId, f64>,
        balances: &'a HashMap<AddressId, Sats>,
        fee_address: &'a AddressId,
    ) -> WeightDistributionInput<'a> {
        WeightDistributionInput {
            withheld_value: WithheldValue::ToPool,
            ..base_input(shares, balances, fee_address)
        }
    }

    /// The load-bearing one. A1 and A2 are paid the same satoshi whether
    /// A3 is withheld or not — so the coinbase owes them nothing and they
    /// owe the pool nothing.
    #[test]
    fn withholding_does_not_move_the_other_members_payouts() {
        const T: u64 = 312_500_000;
        let balances = HashMap::new();
        let fee = addr(FEE);

        // Same shares; the only difference is whether A3 clears the bar.
        let shares = dust_fixture();
        let withheld = build_weight_distribution(pool_keeps_overflow(&shares, &balances, &fee))
            .expect("withheld build");
        let mut all_published_input = pool_keeps_overflow(&shares, &balances, &fee);
        all_published_input.min_payout_sats = Some(Sats(DUST_LIMIT_SATS as i64));
        let all_published =
            build_weight_distribution(all_published_input).expect("all-published build");

        // The fixture has to actually withhold, or this proves nothing.
        let a3 = withheld
            .entries
            .iter()
            .find(|e| e.address.as_str() == A3)
            .unwrap();
        assert_eq!(a3.wire_weight, 0, "A3 must be below min_payout");
        assert_eq!(withheld.published().count(), 2);
        assert_eq!(all_published.published().count(), 3);

        let paid_when_withheld = paid_map(&withheld, T);
        let paid_when_published = paid_map(&all_published, T);
        for a in [A1, A2] {
            assert_eq!(
                paid_when_withheld[a], paid_when_published[a],
                "{a} must be paid the same whether or not A3 dropped out"
            );
        }
    }

    /// And the value A3 left behind goes to the pool — the one place
    /// PPLNS refuses to put it.
    #[test]
    fn the_withheld_share_lands_in_the_pool_output() {
        const T: u64 = 312_500_000;
        let shares = dust_fixture();
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(pool_keeps_overflow(&shares, &balances, &fee)).unwrap();

        let withheld = withheld_payout(&d, T);
        assert!(
            (546..5_000).contains(&withheld),
            "fixture must sit between the consensus floor and min_payout, got {withheld}"
        );

        let paid = d.payout_entries_at(T).expect("§4 vector");
        assert_eq!(paid[0].0, fee, "pool output first");
        let pool_pay = paid[0].1 as i64;
        let fee_only = (T as i64 * d.fee_ppm as i64) / 1_000_000;
        assert!(
            (pool_pay - fee_only - withheld).abs() <= 1 + d.published().count() as i64,
            "pool took {pool_pay}; its fee is {fee_only} and A3 left {withheld} behind"
        );
    }

    /// Nothing to settle: every published member's claim equals what the
    /// coinbase paid it, and the withheld member's claim is what the pool
    /// kept — booked nowhere, by design.
    #[test]
    fn a_published_member_is_paid_exactly_its_claim() {
        const T: u64 = 312_500_000;
        let shares = dust_fixture();
        let balances = HashMap::new();
        let fee = addr(FEE);
        let d = build_weight_distribution(pool_keeps_overflow(&shares, &balances, &fee)).unwrap();
        let settled = settle(&d, T);

        for a in [A1, A2] {
            assert!(
                settled[a].delta.abs() <= 1,
                "{a} was paid {} against a claim of {} — a difference a ledger \
                 would have to carry",
                settled[a].paid,
                settled[a].claim
            );
        }
        assert_eq!(settled[A3].paid, 0, "the withheld member is not paid");
    }

    /// The blockspace cut is the second way out of the coinbase, and it
    /// has to land in the same place — a member cut for space must not
    /// silently raise what everyone else is paid either.
    #[test]
    fn blockspace_trimming_also_pays_the_pool_not_the_other_members() {
        const T: u64 = 312_500_000;
        let shares = HashMap::from([(addr(A1), 3.0), (addr(A2), 2.0), (addr(A3), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);

        let mut untrimmed = pool_keeps_overflow(&shares, &balances, &fee);
        untrimmed.min_payout_sats = Some(Sats(DUST_LIMIT_SATS as i64));
        let untrimmed = build_weight_distribution(untrimmed).expect("untrimmed");
        assert_eq!(untrimmed.published().count(), 3);

        // Budget for the fixed overhead plus two miner outputs.
        let mut trimmed = pool_keeps_overflow(&shares, &balances, &fee);
        trimmed.min_payout_sats = Some(Sats(DUST_LIMIT_SATS as i64));
        trimmed.coinbase_weight_budget = COINBASE_BASE_WEIGHT
            + BUDGET_SAFETY_MARGIN_WU
            + COINBASE_WITNESS_COMMITMENT_WEIGHT
            + 3 * COINBASE_OUTPUT_WEIGHT;
        let trimmed = build_weight_distribution(trimmed).expect("trimmed");
        assert_eq!(trimmed.published().count(), 2, "the cut must have fired");
        assert_eq!(trimmed.budget_telemetry.trimmed_count, 1);

        let paid_trimmed = paid_map(&trimmed, T);
        let paid_untrimmed = paid_map(&untrimmed, T);
        for (a, sats) in &paid_trimmed {
            assert_eq!(
                *sats, paid_untrimmed[a],
                "{a} must be paid the same whether or not another member was \
                 cut for blockspace"
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
        // the divisor is `pot − X`, not the pot and not `weight_p`.
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

    /// The bonus lands on the SCORE weight, not the wire weight — that
    /// is what makes it part of the settlement claim by construction,
    /// with no `+ bonus` term for settlement to remember.
    ///
    /// A finder with no shares of their own still earns their fraction:
    /// `b = S·f/(1−f)` does not depend on what they mined.
    #[test]
    fn the_bonus_is_score_weight_even_for_a_finder_with_no_shares() {
        let shares = HashMap::from([(addr(A1), 1.0), (addr(A2), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);
        let finder = addr(A3); // no shares of their own
        let mut input = base_input(&shares, &balances, &fee);
        input.finder_bonus_ppm = 200_000; // 20 %
        input.finder_address = Some(&finder);
        let d = build_weight_distribution(input).unwrap();

        let wf = d.entries.iter().find(|e| e.address.as_str() == A3).unwrap();
        assert!(wf.score_weight > 0, "the bonus IS score weight");
        assert!(wf.wire_weight > 0, "and buys a real output");
        // b = S·0.2/0.8 = S/4, so the finder holds 1/5 of the score space.
        assert_eq!(wf.score_weight * 5, d.score_total);
        // Nothing sats-denominated was recorded, so nothing is projected.
        assert_eq!(d.extras_total, 0);
    }

    /// The blockspace cut drops the smallest entries from the PUBLISHED
    /// set; it does not move their weight into `weight_P`. §4 pays
    /// `pay_P = T − Σpay`, so weight parked there would be cash the pool
    /// keeps while the ledger credits the cut miner. Kept inside the
    /// miners' cut, the share goes to the miners who still have an output,
    /// who carry the matching debt.
    #[test]
    fn blockspace_cut_drops_from_the_published_set_not_into_weight_p() {
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

        // `weight_P` is the fee over what is published, and nothing
        // more — the folded weights are far larger than it.
        let folded: u64 = d
            .entries
            .iter()
            .filter(|e| e.wire_weight == 0)
            .map(|e| e.score_weight)
            .sum();
        assert!(folded > 0);
        let published_total: u128 = published.iter().map(|e| e.wire_weight as u128).sum();
        assert_eq!(
            d.weight_p as u128,
            published_total * d.fee_ppm as u128 / (1_000_000 - d.fee_ppm) as u128,
            "weight_p must be the fee over the published weights alone"
        );
        assert!(
            d.weight_p < folded,
            "the folded weight ({folded}) is still sitting in weight_p ({})",
            d.weight_p
        );

        // So the pool is paid its fee and not the folded miners' money,
        // and the folded miners' claims are owed by the one who was
        // paid theirs.
        const T: u64 = 312_500_000;
        let settled = settle(&d, T);
        let pool_pay = T as i64 - settled.values().map(|s| s.paid).sum::<i64>();
        let fee_only = (T as i64 * d.fee_ppm as i64) / 1_000_000;
        assert!(
            (pool_pay - fee_only).abs() <= 2,
            "pool got {pool_pay}, its fee is {fee_only}"
        );
        assert!(settled[A1].delta < 0, "the paid miner owes the folded ones");
        for a in [A2, A3] {
            assert!(settled[a].delta > 0, "{a} must be credited its claim");
        }
        assert!(
            settled.values().map(|s| s.delta).sum::<i64>().abs() <= 2,
            "the debits must match the credits"
        );
    }

    /// The config floor and the blockspace cut have to agree. The
    /// smallest budget validation accepts must still publish an output
    /// — even when the miner brings the heaviest address type there is,
    /// because nothing stops one from joining a P2WPKH-only pool.
    ///
    /// One weight unit below it the cut publishes nothing, and §4 makes
    /// the pool output the residual: the pool takes the entire block
    /// while every miner books their full claim as credit. The floor
    /// exists to make that state unreachable.
    #[test]
    fn the_smallest_accepted_budget_still_publishes_a_worst_case_output() {
        use crate::weight::{validate_fee_payout_budget, MIN_COINBASE_WEIGHT_BUDGET};
        const P2TR: &str = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        assert_eq!(
            output_weight_for_address(P2TR),
            COINBASE_OUTPUT_WEIGHT,
            "the fixture must actually be the heaviest output type"
        );
        const T: u64 = 312_500_000;
        let shares = HashMap::from([(addr(P2TR), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);

        let mut input = base_input(&shares, &balances, &fee);
        input.coinbase_weight_budget = MIN_COINBASE_WEIGHT_BUDGET;
        let d = build_weight_distribution(input).unwrap();
        assert_eq!(
            d.published().count(),
            1,
            "the smallest accepted budget must fit one worst-case output"
        );
        assert_eq!(d.budget_telemetry.trimmed_count, 0);
        // And the pool is paid its fee, not the block.
        let paid = d.payout_entries_at(T).expect("§4 vector");
        let pool_pay = paid[0].1 as i64;
        let fee_only = (T as i64 * d.fee_ppm as i64) / 1_000_000;
        assert!(
            (pool_pay - fee_only).abs() <= 2,
            "pool took {pool_pay} on a fee of {fee_only}"
        );

        // One WU less: nothing published, pool takes everything.
        let mut starved = base_input(&shares, &balances, &fee);
        starved.coinbase_weight_budget = MIN_COINBASE_WEIGHT_BUDGET - 1;
        let starved = build_weight_distribution(starved).unwrap();
        assert_eq!(starved.published().count(), 0);
        assert_eq!(
            starved.payout_entries_at(T).expect("§4 vector")[0].1,
            T,
            "with nothing published the §4 residual is the whole block"
        );
        // …which is exactly why config validation has to refuse it.
        assert!(
            validate_fee_payout_budget(
                Some("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
                1.5,
                5_000,
                MIN_COINBASE_WEIGHT_BUDGET - 1
            )
            .is_err(),
            "a budget that publishes nothing must not pass validation"
        );
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

    /// MONEY: an empty share source must be REFUSED, not answered.
    ///
    /// A distribution with no entries is not a harmless empty answer:
    /// `pool_weight_for` floors `weight_P` at 1 and §4 makes the pool
    /// output the residual, so the whole block would go to `fee_address`
    /// while settlement books nothing (every claim is 0 at
    /// `score_total == 0`).
    ///
    /// Reachable without any fault: a brand-new Group-Solo group, a
    /// group whose members reconnect after a calendar reset, or a fresh
    /// PPLNS window.
    #[test]
    fn an_empty_share_source_is_refused_instead_of_paying_the_pool() {
        let shares = HashMap::new();
        let balances = HashMap::new();
        let fee = addr(FEE);
        assert_eq!(
            build_weight_distribution(base_input(&shares, &balances, &fee)),
            Err(WeightBuildError::NoScoredMiners)
        );
    }

    /// The same refusal when the ledger has entries but the WINDOW is
    /// empty — a standing credit is not a share and cannot carry the
    /// split: its boost is `extra · score_total / divisor` = 0 at
    /// `score_total == 0`, so it would get no output and the pool would
    /// take the block while the credit stays on the ledger.
    #[test]
    fn a_standing_credit_alone_does_not_carry_the_split() {
        let shares = HashMap::new();
        let balances = HashMap::from([(addr(A1), Sats(10_000_000))]);
        let fee = addr(FEE);
        assert_eq!(
            build_weight_distribution(base_input(&shares, &balances, &fee)),
            Err(WeightBuildError::NoScoredMiners)
        );
    }

    /// The guard is on the SCORE total, not on "nothing published", so
    /// it does not switch off two legitimate configurations: a 100 % fee
    /// and a `min_payout` above the whole block both publish nothing on
    /// purpose, keep `score_total > 0`, and must still build.
    #[test]
    fn withholding_on_purpose_is_not_an_empty_source() {
        let shares = HashMap::from([(addr(A1), 1.0)]);
        let balances = HashMap::new();
        let fee = addr(FEE);

        let mut full_fee = base_input(&shares, &balances, &fee);
        full_fee.fee_percent = 100.0;
        let d = build_weight_distribution(full_fee).expect("a 100 % fee is a valid configuration");
        assert_eq!(d.published().count(), 0);
        assert!(d.score_total > 0);

        let mut oversized = base_input(&shares, &balances, &fee);
        oversized.min_payout_sats = Some(Sats(i64::MAX));
        let d = build_weight_distribution(oversized).expect("an oversized min_payout still builds");
        assert_eq!(d.published().count(), 0);
        assert!(d.score_total > 0);
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

    /// With two miners whose wire weights CROSS as the reference revenue
    /// moves, the coinbase order flips, and the identity must not move
    /// with it, or every rebuild against a fresh template mints a new
    /// snapshot.
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
