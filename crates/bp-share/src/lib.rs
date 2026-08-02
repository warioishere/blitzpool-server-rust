// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share validation and difficulty math — pure, no I/O.
//!
//! Difficulty utilities within f64-precision tolerance of `1e-6` relative.
//!
//! Targets and hashes are 32-byte **little-endian** U256 — the on-wire
//! convention for both SV1 (after the edge byte-reversal) and SV2
//! (`SetTarget.maximum_target`). A hash *meets* a target iff
//! `hash ≤ target` when both are read MSB-first.

use std::cmp::Ordering;
use std::fmt;
use std::sync::LazyLock;

use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================================================================
// Constants
// ============================================================================

/// Mainnet difficulty-1 target as a U256.
///
/// BE hex: `0x00000000_ffff0000_00000000_00000000_00000000_00000000_00000000_00000000`
/// Decimal: `26959535291011309493156476344723991336010898738574164086137773096960`
static TRUE_DIFF_ONE: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"26959535291011309493156476344723991336010898738574164086137773096960",
        10,
    )
    .expect("TRUE_DIFF_ONE is a valid BigUint literal")
});

/// [`TRUE_DIFF_ONE`] as an `f64`. The value is `0xffff · 2^208`, i.e. only
/// 16 significant bits, so it is *exactly* representable as `f64` (the long
/// decimal literal rounds to the exact value — pinned by
/// `true_diff_one_f64_is_exact`). Used by the allocation-free `f64`
/// [`target_to_difficulty`].
const TRUE_DIFF_ONE_F64: f64 =
    26959535291011309493156476344723991336010898738574164086137773096960.0;

/// 2^256, used as the upper bound in SV2 hashrate-to-target.
static TWO_TO_256: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(1u8) << 256u32);

/// Inner scale used by `difficulty_to_target` to keep fractional difficulties
/// (e.g. 0.06 for CPU miners) integer-precise.
const DIFF_TO_TARGET_SCALE: u64 = 1_000_000;

// ============================================================================
// Difficulty
// ============================================================================

/// Pool-side share difficulty as a 64-bit float — the on-API representation
/// (`/api/info/shares`, per-client `bestDifficulty`, etc.).
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Difficulty(pub f64);

impl Difficulty {
    pub const ZERO: Difficulty = Difficulty(0.0);
    pub const ONE: Difficulty = Difficulty(1.0);

    pub fn as_f64(self) -> f64 {
        self.0
    }
}

impl fmt::Display for Difficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<f64> for Difficulty {
    fn from(v: f64) -> Self {
        Difficulty(v)
    }
}

impl From<Difficulty> for f64 {
    fn from(v: Difficulty) -> Self {
        v.0
    }
}

// ============================================================================
// Target
// ============================================================================

/// 32-byte mining target in little-endian U256 form.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target(pub [u8; 32]);

impl Target {
    /// Numerically largest target — trivially easy.
    pub const MAX: Target = Target([0xff; 32]);

    /// Difficulty-1 target.
    /// BE: `00 00 00 00 FF FF 00 00 ... 00`, LE: zeros with 0xFF at indices 26–27.
    pub const DIFF_ONE: Target = {
        let mut t = [0u8; 32];
        t[26] = 0xff;
        t[27] = 0xff;
        Target(t)
    };

    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Target(bytes)
    }

    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Target(bytes)
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_be_bytes(mut self) -> [u8; 32] {
        self.0.reverse();
        self.0
    }

    /// `true` iff `hash ≤ self`, both treated as LE U256.
    pub fn is_met_by_le(&self, hash_le: &[u8; 32]) -> bool {
        // MSB-first: in LE storage, the most-significant byte is at index 31.
        for i in (0..32).rev() {
            match hash_le[i].cmp(&self.0[i]) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        // hash == target → still meets (boundary inclusive).
        true
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display in BE hex (Bitcoin display order).
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..32).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

// ============================================================================
// Hashing
// ============================================================================

/// SHA256d (double-SHA256). Output is in "internal" LE byte order — i.e.
/// comparison with a `Target` in LE works directly without reversal.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

/// SHA256d over the concatenation of `parts`, streamed straight into the
/// hasher so the caller never allocates a joined buffer. Bit-identical to
/// `sha256d(&parts.concat())` — SHA-256 is a streaming hash, so feeding the
/// pieces one after another yields the same digest as hashing the whole.
///
/// Used on the per-share hot path to hash `coinbase_prefix + extranonce +
/// suffix` without the per-share `Vec` a concatenation would need.
pub fn sha256d_from_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let first = hasher.finalize();
    Sha256::digest(first).into()
}

/// Identity of a coinbase payout list: the block reward it was built against
/// plus its `(address, sats)` pairs in coinbase order.
///
/// This is the binding between a mined block and the payout accounting that
/// must be booked for it — the distribution snapshot is stored under this
/// value, and the block-found path recovers it from the job the winning share
/// was built on. It lives here, in the hashing leaf, so both sides can derive
/// it without the accounting crate having to depend on job assembly: the
/// payout engine hashes its distributor entries, the Stratum job build hashes
/// the `PayoutEntry` list it turns into the coinbase, and the two must agree
/// byte-for-byte.
///
/// Canonical, length-prefixed encoding so no two payout lists can alias:
/// `block_reward_sats` as 8 LE bytes, then per entry, in list order, `sats` as
/// 8 LE bytes, the address byte length as 4 LE bytes, then the address bytes.
/// Order is part of the identity — coinbase output order is. Streamed into the
/// hasher, so no allocation regardless of list length.
///
/// The reward is in the preimage because the list alone does not always imply
/// it: a list that leaves sats unclaimed would be the same list at two
/// different rewards, and the second build would take over the first one's
/// snapshot key.
pub fn payouts_fingerprint_from_parts<'a>(
    block_reward_sats: u64,
    payouts: impl IntoIterator<Item = (&'a str, u64)>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(block_reward_sats.to_le_bytes());
    for (address, sats) in payouts {
        hasher.update(sats.to_le_bytes());
        hasher.update((address.len() as u32).to_le_bytes());
        hasher.update(address.as_bytes());
    }
    let first = hasher.finalize();
    Sha256::digest(first).into()
}

// ============================================================================
// Weight-proportional payouts (SV2 ext 0x0003 §4)
// ============================================================================

/// `floor(weight · t / w_total)` with 128-bit intermediates.
///
/// SV2 ext 0x0003 §4 mandates ≥128-bit intermediate arithmetic:
/// `weight · t` reaches `(2^64−1)²  < 2^128`, so the product cannot
/// overflow, and the quotient is `≤ t`, so the `u64` cast is lossless.
/// `w_total` MUST be non-zero (§3.1: weight fields are non-0, so any
/// well-formed distribution has `W ≥ 1`).
pub fn mul_div_floor(weight: u64, t: u64, w_total: u128) -> u64 {
    debug_assert!(w_total > 0, "mul_div_floor: zero weight sum");
    ((weight as u128 * t as u128) / w_total) as u64
}

/// Why a payout-amount computation could not run.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WeightPayoutError {
    /// `weight_p + Σ weights == 0` — a distribution with no weight at
    /// all is malformed (§3.1 requires non-0 weight fields).
    #[error("zero weight sum")]
    ZeroWeightSum,
    /// `dust_limits` must parallel `weights` 1:1 (§3.1).
    #[error("dust_limits length {dust_limits} != payouts length {weights}")]
    DustLimitsLengthMismatch { weights: usize, dust_limits: usize },
}

/// The §4 payout amounts for one template revenue `t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutAmounts {
    /// Per input weight, in order: `Some(sats)` for a kept output,
    /// `None` where `floor(weight·t/W) < dust_limit` (dust-pruned, the
    /// output is omitted from the coinbase).
    pub pays: Vec<Option<u64>>,
    /// `pay_P = t − Σ pays` — the pool output's amount. Absorbs every
    /// integer-rounding remainder and all dust-pruned value; never
    /// dust-pruned itself (§4).
    pub pool_pay: u64,
}

/// Evaluate the SV2 ext 0x0003 §4 formulae:
///
/// ```text
/// W         = weight_p + Σ weights[i]
/// amount[i] = floor(weights[i] · t / W)
/// pay[i]    = amount[i]  if amount[i] ≥ dust_limits[i], else pruned
/// pay_P     = t − Σ pay[i]
/// ```
///
/// This single implementation serves every party we control: the
/// pool's own coinbase build (with the pool's template revenue), the
/// job-declaration validator (with the declared coinbase's total), and
/// tests standing in for a JDC.
pub fn compute_payout_amounts(
    weight_p: u64,
    weights: &[u64],
    dust_limits: &[u32],
    t: u64,
) -> Result<PayoutAmounts, WeightPayoutError> {
    if weights.len() != dust_limits.len() {
        return Err(WeightPayoutError::DustLimitsLengthMismatch {
            weights: weights.len(),
            dust_limits: dust_limits.len(),
        });
    }
    let w_total = weight_p as u128 + weights.iter().map(|w| *w as u128).sum::<u128>();
    if w_total == 0 {
        return Err(WeightPayoutError::ZeroWeightSum);
    }
    let mut paid_sum: u64 = 0;
    let pays = weights
        .iter()
        .zip(dust_limits)
        .map(|(w, dust)| {
            let amount = mul_div_floor(*w, t, w_total);
            (amount >= *dust as u64).then(|| {
                paid_sum += amount;
                amount
            })
        })
        .collect();
    Ok(PayoutAmounts {
        pays,
        pool_pay: t - paid_sum,
    })
}

/// Divergence band between a distribution's reference revenue and the
/// revenue a block actually pays: `|T_actual − T_ref| ≤ T_ref /
/// SETTLEMENT_BAND_DIVISOR` (±25 %). Mempool-fee drift between a
/// distribution publish and a found block lives comfortably inside
/// this.
///
/// This is an ALARM, not a booking gate. `T_ref` is only the base the
/// wire weights were projected against; settlement books `claim −
/// paid` from the block's own coinbase, and that identity holds at
/// every `T` (`Σ deltas = 0` for any `T_actual/T_ref`). Refusing to
/// book outside the band left the paid-out balances standing in the
/// ledger, so the next block paid them a second time — the drift is
/// worth an operator's attention, never a reason to lose the block.
/// The hard gate is [`block_subsidy_sats`].
pub const SETTLEMENT_BAND_DIVISOR: u64 = 4;

/// Is `t_actual` within the settlement band around `t_ref`?
pub fn reward_within_band(t_ref: u64, t_actual: u64) -> bool {
    let tolerance = t_ref / SETTLEMENT_BAND_DIVISOR;
    t_actual >= t_ref.saturating_sub(tolerance) && t_actual <= t_ref.saturating_add(tolerance)
}

/// The genesis block subsidy: 50 BTC.
pub const INITIAL_BLOCK_SUBSIDY_SATS: u64 = 5_000_000_000;

/// Blocks between subsidy halvings on mainnet — and on testnet3 and
/// testnet4, which share the schedule.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;

/// Blocks between subsidy halvings on regtest.
pub const REGTEST_SUBSIDY_HALVING_INTERVAL: u32 = 150;

/// The block subsidy at `height`, in satoshis — consensus' own rule:
/// 50 BTC halved once per `halving_interval` blocks, and 0 once the
/// shift would exhaust a 64-bit value.
///
/// This is the floor settlement gates on. A coinbase may always pay
/// LESS than subsidy + fees — the difference is simply destroyed — so
/// a total below the subsidy alone means the block forfeited money it
/// was entitled to. Nothing about mempool drift, a stale projection
/// base or a job-declaring client's own template can produce that,
/// which is what makes it the honest gate: it never fires on a healthy
/// block, and it is the one condition worth refusing to book on.
///
/// The interval is a PARAMETER rather than the mainnet constant
/// because regtest halves every 150 blocks. Hard-coding 210 000 would
/// make every regtest block past height 150 look like it had burned
/// part of its own subsidy — and the pool's own regtests mine well
/// past it.
///
/// Fails OPEN (returns 0, so no block is ever gated) on inputs that
/// cannot describe a real block: a negative height — the dust sweep
/// mints synthetic negative heights for its audit rows — and a zero
/// interval.
pub fn block_subsidy_sats(height: i32, halving_interval: u32) -> u64 {
    if height < 0 || halving_interval == 0 {
        return 0;
    }
    let halvings = height as u64 / halving_interval as u64;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_BLOCK_SUBSIDY_SATS >> halvings
}

/// `pot(t) = (1 − fee) · t` — the miners' cut of a block paying `t`.
/// Everything the weight model splits by score, and the base every
/// satoshi-denominated promise is measured against.
pub fn miner_pot_sats(fee_ppm: u32, t: u64) -> u64 {
    let miner_ppm = 1_000_000u128.saturating_sub(fee_ppm as u128);
    ((t as u128 * miner_ppm) / 1_000_000u128) as u64
}

/// Ceiling on `X` as a percentage of `pot(t_ref)`: the extras may
/// promise at most this much of the miners' cut, leaving the rest to be
/// split by score.
///
/// The divisor of the whole projection is `pot − X`, so an `X` at or
/// above the pot would divide by zero or flip the sign of every boost.
/// Five percent of headroom also keeps a distribution payable: with the
/// full pot promised away, every miner without a promise is pruned to
/// nothing.
const EXTRA_SOLVENCY_PERCENT: i128 = 95;

/// The largest FURTHER promise that still leaves the ledger solvent
/// against `reference_revenue_sats`, given the `committed` (signed)
/// sum of everything already promised.
///
/// A Group-Solo finder bonus MUST go through this before it reaches
/// [`project_extras`] and before it is recorded for settlement. It is
/// the one promise the pool picks freely rather than owes, so it is the
/// one that gives way first — and it is also the only promise whose
/// capping could never be reproduced later, because the snapshot
/// records the capped value and settlement cannot tell how large the
/// operator's original figure was.
pub fn solvency_headroom_sats(committed: i64, fee_ppm: u32, reference_revenue_sats: u64) -> u64 {
    let cap =
        miner_pot_sats(fee_ppm, reference_revenue_sats) as i128 * EXTRA_SOLVENCY_PERCENT / 100;
    (cap - committed as i128).clamp(0, u64::MAX as i128) as u64
}

/// The satoshi promises a weight distribution carries on top of the
/// pure score split, resolved against one reference revenue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraProjection {
    /// The effective extra per input entry, in input order: the value
    /// actually projected into weight space after the solvency scale
    /// and the per-address repayment floor.
    pub effective: Vec<i64>,
    /// `X = Σ effective` — signed. Every claim is measured against
    /// `pot − X`, so build and settlement MUST agree on it exactly.
    pub total: i64,
    /// `pot(t_ref) − X`, the projection divisor. Always ≥ 1.
    pub divisor: u128,
}

/// Fold a ledger and an optional finder bonus into the
/// `(score_weight, extra_sats)` pairs [`project_extras`] consumes.
///
/// Trivial, and shared anyway: the build reads the pairs off its
/// candidates and settlement off a stored snapshot, and the two must
/// agree to the satoshi about which entry carries the bonus.
pub fn extras_from_ledger<'a>(
    entries: impl IntoIterator<Item = (&'a str, u64, i64)>,
    finder_bonus: Option<(&str, u64)>,
) -> Vec<(u64, i64)> {
    entries
        .into_iter()
        .map(|(address, score_weight, balance_sats)| {
            let bonus = match finder_bonus {
                Some((finder, sats)) if finder == address => sats as i64,
                _ => 0,
            };
            (score_weight, balance_sats.saturating_add(bonus))
        })
        .collect()
}

/// Resolve the satoshi extras a distribution promises into the values
/// it can actually honour at `reference_revenue_sats`.
///
/// `entries` is `(score_weight, extra_sats)` per address, where
/// `extra_sats` is the SIGNED sum of everything that address is to
/// receive beyond its score share: its ledger balance (negative when it
/// owes the pool) plus, for a Group-Solo finder, the bonus.
///
/// Two things are enforced, in this order:
///
/// 1. **Solvency.** `X` above [`EXTRA_SOLVENCY_PERCENT`] of the pot
///    scales every extra down pro rata. The divisor `pot − X` has to
///    stay positive, and a promise larger than the block cannot be kept
///    however the weights are arranged.
/// 2. **Repayment floor.** A debt can only be collected out of the
///    payout it shrinks: once an address's weight would go negative
///    there is nothing left to take, so its extra is floored at
///    `−score_weight · (pot − X) / score_total` and the remainder stays
///    on the ledger for the next block. Without the floor the pool
///    weight goes negative and the block pays out more than it holds.
///
/// Deterministic and order-independent (a sum, a per-element scale and
/// a per-element floor), so settlement reproduces the build's `X` from
/// the stored snapshot without storing it. Note that a Group-Solo bonus
/// must be capped BEFORE it is passed in — settlement only ever sees
/// the capped value, so any scaling of the bonus itself would not be
/// reproducible from the snapshot.
pub fn project_extras(
    entries: &[(u64, i64)],
    score_total: u64,
    fee_ppm: u32,
    reference_revenue_sats: u64,
) -> ExtraProjection {
    let pot = miner_pot_sats(fee_ppm, reference_revenue_sats) as i128;
    if pot <= 0 {
        // Nothing can be promised out of an empty miner cut, in either
        // direction — and a claim measured against it must come out 0,
        // not as the mirror image of a debt nobody can be paid from.
        return ExtraProjection {
            effective: vec![0; entries.len()],
            total: 0,
            divisor: 1,
        };
    }
    let solvency_cap = pot * EXTRA_SOLVENCY_PERCENT / 100;
    let mut effective: Vec<i128> = entries.iter().map(|(_, extra)| *extra as i128).collect();

    scale_to_cap(&mut effective, solvency_cap);
    // Bound for the divisor: the floors below only ever RAISE an extra,
    // so from here `X` can only grow and `pot − X` only shrink. Without
    // it a ledger where every scoring address is beyond repayment has
    // no finite solution at all.
    let divisor_bound = (pot - sum(&effective)).max(1);
    apply_repayment_floors(&mut effective, entries, score_total, pot, divisor_bound);
    // Raising the floors gives satoshis back, which can push the
    // promises over the cap again. One more scale settles it, and it
    // cannot re-break the floors: a scale shrinks every promise while
    // `pot − X` grows, and a larger divisor is a looser floor.
    scale_to_cap(&mut effective, solvency_cap);

    let total = sum(&effective);
    ExtraProjection {
        effective: effective
            .into_iter()
            .map(|e| e.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
            .collect(),
        total: total.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
        // Derived from the FINAL `X` rather than from the solve below,
        // so the published boosts and the settlement claims are the two
        // halves of one identity and cannot drift apart.
        divisor: (pot - total).max(1) as u128,
    }
}

fn sum(values: &[i128]) -> i128 {
    values.iter().sum()
}

/// Scale every promise pro rata until they fit `cap`. A no-op unless
/// the ledger is insolvent against this block.
fn scale_to_cap(effective: &mut [i128], cap: i128) {
    let x = sum(effective);
    if x > cap {
        for e in effective.iter_mut() {
            *e = (*e * cap) / x;
        }
    }
}

/// Pin every debt that cannot be collected out of the payout it shrinks
/// to exactly what that payout is worth.
///
/// Solved rather than iterated: for a known set `F` of pinned addresses
/// the divisor follows in closed form from `D = pot − X` and
/// `X = Σ_{i∉F} extra_i − Σ_{i∈F} u_i·D/S`, and the set only grows
/// (pinning raises `X`, which shrinks `D`, which pins more) — so at
/// most one pass per address, and one or two in practice. Iterating the
/// floor instead converges only geometrically and stalls short of the
/// fixed point for a large debtor.
fn apply_repayment_floors(
    effective: &mut [i128],
    entries: &[(u64, i64)],
    score_total: u64,
    pot: i128,
    divisor_bound: i128,
) {
    if score_total == 0 {
        return;
    }
    let s = score_total as i128;
    let mut pinned = vec![false; effective.len()];
    let mut divisor = divisor_bound;
    for _ in 0..=effective.len() {
        let mut free_sum: i128 = 0;
        let mut pinned_score: i128 = 0;
        for (i, (score_weight, _)) in entries.iter().enumerate() {
            if pinned[i] {
                pinned_score += *score_weight as i128;
            } else {
                free_sum += effective[i];
            }
        }
        let denom = s - pinned_score;
        divisor = if denom > 0 {
            (((pot - free_sum) * s) / denom).clamp(1, divisor_bound)
        } else {
            // Every scoring address is beyond repayment: no finite
            // divisor satisfies all the floors, so take the loosest one
            // and let the caller's zero-clamp absorb the rest.
            divisor_bound
        };
        let mut grew = false;
        for (i, (score_weight, _)) in entries.iter().enumerate() {
            if pinned[i] || effective[i] >= 0 {
                continue;
            }
            if effective[i] < -((*score_weight as i128 * divisor) / s) {
                pinned[i] = true;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    for (i, (score_weight, _)) in entries.iter().enumerate() {
        if pinned[i] {
            effective[i] = -((*score_weight as i128 * divisor) / s);
        }
    }
}

/// A miner's settlement claim on a found block: its score share of
/// whatever the block's miner cut has left after the satoshi promises,
/// `floor(score_weight · (pot(t_actual) − extras_total) / score_total)`.
///
/// `extras_total` is `X` from [`project_extras`] — signed, and the same
/// value the published weights were projected against. Subtracting it
/// is what keeps the ledger from inventing money: the coinbase paid
/// those promises out of this very pot, so a member with no promise of
/// its own earns a share of the REST, not of the whole. Charging it the
/// full pot would credit every such member the promises of the others,
/// block after block.
///
/// The finder bonus is NOT added here — the caller owns that, because
/// only the caller knows which entry is the finder.
///
/// Settlement books `balance += claim − actually_paid` per address,
/// with `t_actual` and the paid amounts read from the REAL coinbase of
/// the found block, so the claim must come from the same raw inputs the
/// published weights were derived from, never from a projected wire
/// weight. Signed: promises exceeding the block's own miner cut (the
/// revenue came in far below the projection) make the residual claim
/// negative, and the difference is a debt like any other.
///
/// Integer-exact; the i128 product `score · pot` stays far below 2^127
/// for any real score precision and sat amount.
pub fn claim_sats(
    score_weight: u64,
    score_total: u64,
    fee_ppm: u32,
    t_actual: u64,
    extras_total: i64,
) -> i64 {
    if score_total == 0 {
        return 0;
    }
    let claimable = miner_pot_sats(fee_ppm, t_actual) as i128 - extras_total as i128;
    ((score_weight as i128 * claimable) / score_total as i128) as i64
}

/// Identity of a weight distribution: the settlement INPUTS, not any
/// concrete satoshi outcome.
///
/// The v1 [`payouts_fingerprint_from_parts`] hashes `(reward, sats)` —
/// an identity that only works when the coinbase pays those exact
/// sats. Under the weight model the same distribution legitimately
/// yields different satoshi vectors for different template revenues
/// (`floor(weight·T/W)`), so the identity must be the thing every
/// outcome is derived FROM: per address its integer score weight, its
/// ledger balance at build time, and its dust limit, plus the fee (in
/// parts-per-million) and an optional finder bonus. Settlement re-reads
/// exactly these inputs from the snapshot stored under this hash and
/// books `earned(T_actual) − actually_paid` per address.
///
/// `fee_address` IS in the preimage: it is the settlement recipient of
/// everything the coinbase withholds, and the snapshot stored under
/// this hash is read back to decide which row is the pool's rather than
/// a miner's. Two distributions that differ only there must not share a
/// key.
///
/// Deliberately NOT in the preimage: the published wire weights and
/// the reference revenue behind their balance boosts — distributions
/// that differ only there settle identically and may share a snapshot.
/// `weight_P` follows the same rule: settlement never reads it, since
/// what was actually paid comes from the block's own coinbase.
///
/// Canonical, domain-tagged, length-prefixed. Entry ORDER is part of
/// the identity, so the caller must supply a canonical order that does
/// not itself depend on an excluded input — address order. (The
/// coinbase output order is NOT canonical: it sorts by wire weight,
/// which carries the reference revenue through the balance boosts.)
pub fn weights_fingerprint_from_parts<'a>(
    fee_ppm: u32,
    fee_address: &str,
    finder_bonus: Option<(&'a str, u64)>,
    entries: impl IntoIterator<Item = (&'a str, u64, i64, u32)>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bp-weights-v2");
    hasher.update(fee_ppm.to_le_bytes());
    hasher.update((fee_address.len() as u32).to_le_bytes());
    hasher.update(fee_address.as_bytes());
    match finder_bonus {
        Some((address, sats)) => {
            hasher.update([1u8]);
            hasher.update((address.len() as u32).to_le_bytes());
            hasher.update(address.as_bytes());
            hasher.update(sats.to_le_bytes());
        }
        None => hasher.update([0u8]),
    }
    for (address, score_weight, balance_sats, dust_limit) in entries {
        hasher.update((address.len() as u32).to_le_bytes());
        hasher.update(address.as_bytes());
        hasher.update(score_weight.to_le_bytes());
        hasher.update(balance_sats.to_le_bytes());
        hasher.update(dust_limit.to_le_bytes());
    }
    let first = hasher.finalize();
    Sha256::digest(first).into()
}

// ============================================================================
// Share validation
// ============================================================================

/// Result of hashing a serialized block header and scoring its difficulty.
#[derive(Clone, Debug)]
pub struct ShareValidation {
    pub submission_hash: [u8; 32],
    pub submission_difficulty: Difficulty,
}

/// Hash an 80-byte block header and compute the share's submission
/// difficulty.
pub fn calculate_difficulty(header: &[u8]) -> ShareValidation {
    let hash = sha256d(header);
    let target = Target::from_le_bytes(hash);
    let diff = target_to_difficulty(&target);
    ShareValidation {
        submission_hash: hash,
        submission_difficulty: diff,
    }
}

// ============================================================================
// Difficulty ↔ Target conversion
// ============================================================================

/// Interpret 32 little-endian bytes as a non-negative integer and convert
/// to the nearest `f64`. Bytes beyond `f64`'s 53-bit mantissa fall below
/// precision — correct, since a difficulty only needs ~15 significant
/// digits — so the result carries a relative error on the order of `f64`
/// epsilon (`~1e-15`), far inside the module's documented `1e-6` tolerance.
fn le_bytes_to_f64(bytes: &[u8; 32]) -> f64 {
    // MSB-first (index 31 down to 0): acc·256 + byte.
    let mut acc = 0.0f64;
    for &b in bytes.iter().rev() {
        acc = acc * 256.0 + f64::from(b);
    }
    acc
}

fn le_bytes_to_biguint(bytes: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

fn biguint_to_le_bytes_32(n: &BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_le();
    if bytes.len() > 32 {
        // Saturated overflow — treat as MAX target.
        return [0xff; 32];
    }
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

/// Convert a target back to a floating-point difficulty:
/// `difficulty = TRUE_DIFF_ONE / target`, computed directly in `f64`.
///
/// `TRUE_DIFF_ONE` (≈ 2^224, 16 significant bits) over a 256-bit target
/// fits comfortably in `f64`'s ~15–16 significant digits, so no big-integer
/// arithmetic is needed — keeping this **allocation-free** on the
/// per-share validation hot path (it runs once per submitted share via
/// [`calculate_difficulty`]). Accuracy is pinned to the pre-existing
/// big-integer result within `1e-9` relative by
/// `prop_target_to_difficulty_matches_bigint_reference`.
pub fn target_to_difficulty(target: &Target) -> Difficulty {
    let divisor = le_bytes_to_f64(&target.0);
    if divisor == 0.0 {
        return Difficulty(f64::MAX);
    }
    Difficulty(TRUE_DIFF_ONE_F64 / divisor)
}

/// Convert a floating-point difficulty to a 32-byte LE target.
/// `target = floor(TRUE_DIFF_ONE / difficulty)`.
/// Invalid difficulties (≤ 0, NaN, infinite) saturate at `Target::MAX`.
///
/// Decomposes `diff` into integer + scaled-fractional BigUints so that
/// large difficulties (above ~1e10) do not lose precision via integer
/// overflow of the scaled intermediate value.
pub fn difficulty_to_target(diff: Difficulty) -> Target {
    if !diff.0.is_finite() || diff.0 <= 0.0 {
        return Target::MAX;
    }
    let int_part = diff.0.trunc();
    if int_part > u64::MAX as f64 {
        // Difficulty so high the target rounds to 0 anyway.
        return Target([0u8; 32]);
    }
    let int_big = BigUint::from(int_part as u64);
    let frac_part = diff.0 - int_part;
    let frac_int = (frac_part * DIFF_TO_TARGET_SCALE as f64).round() as u64;
    let diff_scaled_big = int_big * DIFF_TO_TARGET_SCALE + frac_int;
    if diff_scaled_big.is_zero() {
        return Target::MAX;
    }
    let target_big = (&*TRUE_DIFF_ONE * DIFF_TO_TARGET_SCALE) / diff_scaled_big;
    Target(biguint_to_le_bytes_32(&target_big))
}

// ============================================================================
// SV2 hashrate-to-target
// ============================================================================

/// SV2-spec target = (2^256 − h·s) / (h·s + 1)
/// where h = hashrate (H/s), s = 60 / sharesPerMinute.
pub fn hash_rate_to_target(hash_rate: f64, shares_per_minute: f64) -> Target {
    if !hash_rate.is_finite()
        || hash_rate <= 0.0
        || !shares_per_minute.is_finite()
        || shares_per_minute <= 0.0
    {
        return Target::MAX;
    }
    let seconds_per_share = 60.0 / shares_per_minute;
    let sh = (hash_rate * seconds_per_share).round();
    if !sh.is_finite() || sh <= 0.0 {
        return Target::MAX;
    }
    let sh_big = BigUint::from(sh as u64);
    if sh_big.is_zero() {
        return Target::MAX;
    }
    let numerator = &*TWO_TO_256 - &sh_big;
    let denominator = sh_big + 1u32;
    let target_big = numerator / denominator;
    let max_u256 = &*TWO_TO_256 - 1u32;
    let clamped = if target_big > max_u256 {
        max_u256
    } else {
        target_big
    };
    Target(biguint_to_le_bytes_32(&clamped))
}

pub fn hash_rate_to_difficulty(hash_rate: f64, shares_per_minute: f64) -> Difficulty {
    target_to_difficulty(&hash_rate_to_target(hash_rate, shares_per_minute))
}

// ============================================================================
// SV2 max-target clamp
// ============================================================================

/// Clamp `diff` upward so the resulting target does not exceed `max_target`.
/// SV2 spec §5.3.6: server MUST NOT assign a target above the client's
/// declared maximum.
pub fn clamp_difficulty_to_max_target(diff: Difficulty, max_target: &Target) -> Difficulty {
    let max_big = le_bytes_to_biguint(&max_target.0);
    if max_big.is_zero() {
        return diff;
    }
    let computed = difficulty_to_target(diff);
    let computed_big = le_bytes_to_biguint(&computed.0);
    if computed_big > max_big {
        let clamped = target_to_difficulty(max_target);
        if clamped.0.is_finite() && clamped.0 > 0.0 {
            return clamped;
        }
    }
    diff
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;

    fn biguint_to_le_target(n: &str) -> Target {
        let big = BigUint::parse_bytes(n.as_bytes(), 10).expect("valid BigUint literal");
        Target(biguint_to_le_bytes_32(&big))
    }

    /// The pre-C1 difficulty algorithm: scaled big-integer division then
    /// `to_f64`. Kept here as the reference the allocation-free `f64`
    /// [`target_to_difficulty`] is proven against
    /// (`prop_target_to_difficulty_matches_bigint_reference`).
    fn target_to_difficulty_bigint_reference(target: &Target) -> f64 {
        let divisor = BigUint::from_bytes_le(&target.0);
        if divisor.is_zero() {
            return f64::MAX;
        }
        const SCALE: u64 = 1_000_000_000_000_000;
        let scaled = (&*TRUE_DIFF_ONE * SCALE) / divisor;
        scaled.to_f64().unwrap_or(f64::MAX) / 1e15
    }

    #[test]
    fn sha256d_from_parts_matches_concatenation() {
        // Streaming the pieces into the hasher must be bit-identical to hashing
        // the joined buffer — the invariant the per-share hot path relies on.
        let parts: [&[u8]; 4] = [
            b"coinbase-prefix",
            &[0x01, 0x02, 0x03, 0x04],
            &[0xaa; 8],
            b"suffix-bytes",
        ];
        let mut joined = Vec::new();
        for p in parts {
            joined.extend_from_slice(p);
        }
        assert_eq!(sha256d_from_parts(&parts), sha256d(&joined));
        // Trivial single-part and empty cases hold too.
        assert_eq!(sha256d_from_parts(&[b"x"]), sha256d(b"x"));
        assert_eq!(sha256d_from_parts(&[]), sha256d(&[]));
    }

    #[test]
    fn true_diff_one_f64_is_exact() {
        // 0xffff · 2^208 — 16 significant bits, exactly representable.
        assert_eq!(TRUE_DIFF_ONE_F64, 65535.0 * 2.0f64.powi(208));
        // And it equals the big-integer constant converted to f64.
        assert_eq!(TRUE_DIFF_ONE_F64, TRUE_DIFF_ONE.to_f64().unwrap());
    }

    // ---- Target byte-order ----

    #[test]
    fn target_diff_one_le_layout() {
        let t = Target::DIFF_ONE;
        // BE: 00 00 00 00 FF FF 00 ... 00
        let be = t.to_be_bytes();
        assert_eq!(be[0..4], [0, 0, 0, 0]);
        assert_eq!(be[4..6], [0xff, 0xff]);
        assert_eq!(be[6..32], [0u8; 26]);
    }

    #[test]
    fn target_le_be_round_trip() {
        let be = [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let t = Target::from_be_bytes(be);
        assert_eq!(t, Target::DIFF_ONE);
        assert_eq!(t.to_be_bytes(), be);
    }

    #[test]
    fn target_display_is_be_hex() {
        let s = Target::DIFF_ONE.to_string();
        assert_eq!(
            s,
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
    }

    // ---- meets_target ----

    #[test]
    fn meets_target_strict_less_accepts() {
        let target = difficulty_to_target(Difficulty(1000.0));
        let mut easier = target.to_le_bytes();
        // Subtract 1 from the lowest non-zero byte → LE smaller.
        for byte in easier.iter_mut() {
            if *byte > 0 {
                *byte -= 1;
                break;
            }
        }
        assert!(target.is_met_by_le(&easier));
    }

    #[test]
    fn meets_target_strict_greater_rejects() {
        let target = difficulty_to_target(Difficulty(1000.0));
        let mut harder = target.to_le_bytes();
        for byte in harder.iter_mut() {
            if *byte < 0xff {
                *byte += 1;
                break;
            }
        }
        assert!(!target.is_met_by_le(&harder));
    }

    #[test]
    fn meets_target_boundary_inclusive() {
        let target = difficulty_to_target(Difficulty(1000.0));
        assert!(target.is_met_by_le(&target.to_le_bytes()));
    }

    #[test]
    fn meets_target_closes_float_precision_gap() {
        // Regression: a hash exactly at the target must be accepted by the
        // byte-exact is_met_by_le — that's the real acceptance rule, and it
        // closes any float round-trip gap. target_to_difficulty now rounds
        // to nearest (not floor), so the recomputed difficulty round-trips
        // to within tolerance of D in either direction rather than strictly
        // below it.
        for diff in [931.31, 1024.0, 65536.5, 1_000_000.0] {
            let target = difficulty_to_target(Difficulty(diff));
            assert!(target.is_met_by_le(&target.to_le_bytes()));
            let recomputed = target_to_difficulty(&target).0;
            let rel_err = (recomputed - diff).abs() / diff;
            assert!(
                rel_err < 1e-6,
                "recomputed {recomputed} vs orig {diff} (rel_err {rel_err})"
            );
        }
    }

    // ---- Frozen reference values ----

    #[test]
    fn target_to_difficulty_frozen_reference_values() {
        let cases = [
            (
                "26959535291011309493156476344723991336010898738574164086137773096960",
                1.0,
            ),
            (
                "269595352910113094931564763447239913360108987385741640861377730969",
                100.0,
            ),
            (
                "26314822148376095161694950068056604525144849915640960552599095263",
                1024.5,
            ),
            (
                "411363585318389756826776879392160021606281928354580833515995134",
                65537.0,
            ),
            (
                "26959535291011309493156476344723991336010898738574164086137773",
                1_000_000.0,
            ),
            (
                "336994191137641368664455954309049891700136234232177051",
                80_000_000_000_000.0,
            ),
        ];
        for (divisor, expected) in cases {
            let target = biguint_to_le_target(divisor);
            let actual = target_to_difficulty(&target).0;
            let rel_err = (actual - expected).abs() / expected;
            assert!(
                rel_err < 1e-9,
                "divisor {divisor}: expected {expected}, got {actual} (rel_err {rel_err})"
            );
        }
    }

    // ---- difficulty <-> target round-trip ----

    #[test]
    fn difficulty_to_target_then_back_round_trips() {
        // Covers production range (sub-unit CPU miners up to high-diff
        // ASIC rentals at ~1e14) plus the regression target where the
        // u64-cast path used to wrap.
        for diff in [0.06, 1.0, 10.0, 1000.0, 65537.0, 1_000_000.0, 1e10, 1e14] {
            let target = difficulty_to_target(Difficulty(diff));
            let back = target_to_difficulty(&target).0;
            let rel_err = (back - diff).abs() / diff;
            assert!(rel_err < 1e-6, "diff {diff} → {back} (rel_err {rel_err})");
        }
    }

    #[test]
    fn difficulty_to_target_handles_invalid_input() {
        assert_eq!(difficulty_to_target(Difficulty(0.0)), Target::MAX);
        assert_eq!(difficulty_to_target(Difficulty(-1.0)), Target::MAX);
        assert_eq!(difficulty_to_target(Difficulty(f64::NAN)), Target::MAX);
        assert_eq!(difficulty_to_target(Difficulty(f64::INFINITY)), Target::MAX);
    }

    #[test]
    fn target_zero_returns_max_difficulty() {
        let zero = Target([0u8; 32]);
        assert_eq!(target_to_difficulty(&zero).0, f64::MAX);
    }

    // ---- SV2 hashrate-to-target ----

    #[test]
    fn hash_rate_to_target_invalid_inputs_return_max() {
        assert_eq!(hash_rate_to_target(0.0, 6.0), Target::MAX);
        assert_eq!(hash_rate_to_target(-1.0, 6.0), Target::MAX);
        assert_eq!(hash_rate_to_target(1e12, 0.0), Target::MAX);
        assert_eq!(hash_rate_to_target(f64::NAN, 6.0), Target::MAX);
        assert_eq!(hash_rate_to_target(1e12, f64::INFINITY), Target::MAX);
    }

    #[test]
    fn hash_rate_to_difficulty_monotone_in_hashrate() {
        let a = hash_rate_to_difficulty(1e9, 6.0).0;
        let b = hash_rate_to_difficulty(1e10, 6.0).0;
        let c = hash_rate_to_difficulty(1e11, 6.0).0;
        assert!(a < b);
        assert!(b < c);
    }

    // ---- Clamp ----

    #[test]
    fn clamp_no_op_when_assigned_target_under_max() {
        // Hard maxTarget (diff 10_000), assigned target derived from diff 100 → easier
        // than max-target requires; clamp must lift diff up to satisfy spec.
        let max_target = difficulty_to_target(Difficulty(10_000.0));
        let result = clamp_difficulty_to_max_target(Difficulty(100.0), &max_target);
        assert!(result.0 >= 10_000.0, "expected clamp up, got {}", result.0);
    }

    #[test]
    fn clamp_passthrough_when_already_hard_enough() {
        let max_target = Target::MAX; // trivially easy max
        let result = clamp_difficulty_to_max_target(Difficulty(500.0), &max_target);
        assert_eq!(result.0, 500.0);
    }

    #[test]
    fn clamp_handles_zero_max_target() {
        // Zero max-target → treat as no constraint (pass through unchanged).
        let zero = Target([0u8; 32]);
        let result = clamp_difficulty_to_max_target(Difficulty(500.0), &zero);
        assert_eq!(result.0, 500.0);
    }

    #[test]
    fn clamp_combined_with_port_floor_sv2_invariant() {
        // SV2 invariant: after clamp + floor, assigned target must always be ≤ maxTarget.
        let trials: &[(f64, f64, f64)] = &[
            (1.0, 500.0, 100.0),
            (100.0, 500.0, 10_000.0),
            (50_000.0, 500.0, 1_000.0),
            (1.0, 1.0, 1.0),
            (10.0, 500.0, 500.0),
        ];
        for &(raw, floor, max_diff) in trials {
            let max_target = difficulty_to_target(Difficulty(max_diff));
            let clamped = clamp_difficulty_to_max_target(Difficulty(raw), &max_target);
            let assigned = if clamped.0 < floor {
                Difficulty(floor)
            } else {
                clamped
            };
            let assigned_target = difficulty_to_target(assigned);
            let assigned_big = le_bytes_to_biguint(&assigned_target.0);
            let max_big = le_bytes_to_biguint(&max_target.0);
            assert!(
                assigned_big <= max_big,
                "raw={raw} floor={floor} max_diff={max_diff}: assigned_target > max_target"
            );
        }
    }

    // ---- calculate_difficulty against a real header ----

    #[test]
    fn calculate_difficulty_genesis_block() {
        // Bitcoin mainnet genesis header (80 bytes hex). Use the hash check
        // as the primary assertion — that's what proves SHA256d + byte
        // order are right. The share-difficulty value follows from the
        // hash and is just sanity-checked to be in the expected range.
        let header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let header = hex::decode(header_hex).unwrap();
        let result = calculate_difficulty(&header);

        // Display order (BE) of genesis hash.
        let mut display_hash = result.submission_hash;
        display_hash.reverse();
        assert_eq!(
            hex::encode(display_hash),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );

        // Genesis *share* difficulty (≈ TRUE_DIFF_ONE / genesis_hash) is
        // ≈ 2536, NOT 1.0 — 1.0 would be if the hash hit the target
        // exactly; in fact it lands meaningfully below.
        let d = result.submission_difficulty.0;
        assert!(
            (2500.0..2600.0).contains(&d),
            "genesis share-difficulty out of expected ~2536 range: {d}"
        );
    }

    // ---- Difficulty serde ----

    #[test]
    fn difficulty_serde_transparent() {
        let d = Difficulty(1234.5);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "1234.5");
        let back: Difficulty = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    // ---- Property tests ----

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_round_trip_difficulty_in_typical_range(d in 1.0f64..1e12) {
            let t = difficulty_to_target(Difficulty(d));
            let back = target_to_difficulty(&t).0;
            let rel_err = (back - d).abs() / d;
            prop_assert!(rel_err < 1e-6, "d={d} back={back} rel_err={rel_err}");
        }

        #[test]
        fn prop_target_to_difficulty_matches_bigint_reference(target_le: [u8; 32]) {
            // Proves the f64 target_to_difficulty agrees with the pre-C1
            // scaled-big-integer algorithm within the module's 1e-9
            // tolerance, over arbitrary targets.
            let target = Target(target_le);
            let got = target_to_difficulty(&target).0;
            let want = target_to_difficulty_bigint_reference(&target);
            // Near-zero targets saturate to MAX in both; treat as equal.
            if want == f64::MAX || got == f64::MAX {
                prop_assert_eq!(want, got);
            } else {
                // The two agree to ~1e-5. The residual is the OLD method's
                // scaled-integer *truncation* (its error reaches ~4e-6 for
                // the smallest difficulties); the f64 method is in fact more
                // accurate — it matches the true frozen-reference values to
                // 1e-9 (`target_to_difficulty_frozen_reference_values`).
                let rel = (got - want).abs() / want;
                prop_assert!(rel < 1e-5, "target={:?} got={} want={} rel={}", target_le, got, want, rel);
            }
        }

        #[test]
        fn prop_meets_target_is_total_and_correct(hash_le: [u8; 32], target_le: [u8; 32]) {
            let target = Target(target_le);
            let result = target.is_met_by_le(&hash_le);
            // Cross-check against BigUint comparison.
            let hash_big = BigUint::from_bytes_le(&hash_le);
            let target_big = BigUint::from_bytes_le(&target_le);
            prop_assert_eq!(result, hash_big <= target_big);
        }

        #[test]
        fn prop_target_ord_matches_biguint_ord(a_le: [u8; 32], b_le: [u8; 32]) {
            let ta = Target(a_le);
            let tb = Target(b_le);
            let ba = BigUint::from_bytes_le(&a_le);
            let bb = BigUint::from_bytes_le(&b_le);
            prop_assert_eq!(ta.cmp(&tb), ba.cmp(&bb));
        }

        #[test]
        fn prop_clamp_never_softer_than_max_target(
            raw in 1.0f64..1e8,
            max_diff in 1.0f64..1e6,
        ) {
            let max_target = difficulty_to_target(Difficulty(max_diff));
            let clamped = clamp_difficulty_to_max_target(Difficulty(raw), &max_target);
            let assigned_target = difficulty_to_target(clamped);
            let a = le_bytes_to_biguint(&assigned_target.0);
            let m = le_bytes_to_biguint(&max_target.0);
            prop_assert!(a <= m, "assigned_target > max_target");
        }
    }

    // ---- Weight-proportional payouts (SV2 ext 0x0003 §4) ----

    /// `splits proportionally, remainder lands in pool_pay`
    #[test]
    fn payout_amounts_proportional_with_remainder_to_pool() {
        // weights 3:1, weight_p 1 → W = 5, t = 1000 → 600 / 200 / pool 200.
        let r = compute_payout_amounts(1, &[3, 1], &[546, 546], 1000).unwrap();
        assert_eq!(r.pays, vec![Some(600), None]); // 200 < 546 → pruned
        assert_eq!(r.pool_pay, 400); // pool weight share + pruned 200
    }

    /// `exact division leaves the pool exactly its own share`
    #[test]
    fn payout_amounts_exact_division() {
        let r = compute_payout_amounts(1, &[6, 3], &[1, 1], 1000).unwrap();
        assert_eq!(r.pays, vec![Some(600), Some(300)]);
        assert_eq!(r.pool_pay, 100);
    }

    /// `dust-prunes below the per-output limit, value flows to pool_pay`
    #[test]
    fn payout_amounts_dust_prune_all() {
        let r = compute_payout_amounts(1, &[1, 1, 1], &[600, 600, 600], 1000).unwrap();
        assert_eq!(r.pays, vec![None, None, None]); // each 250 < 600
        assert_eq!(r.pool_pay, 1000);
    }

    /// `t = 0 → every output pruned (or 0), pool_pay 0`
    #[test]
    fn payout_amounts_zero_revenue() {
        let r = compute_payout_amounts(1, &[5, 5], &[546, 546], 0).unwrap();
        assert_eq!(r.pays, vec![None, None]);
        assert_eq!(r.pool_pay, 0);
    }

    /// `u64::MAX weights and revenue do not overflow (u128 intermediates)`
    #[test]
    fn payout_amounts_max_bounds_no_overflow() {
        let w = u64::MAX;
        let r = compute_payout_amounts(w, &[w, w], &[1, 1], u64::MAX).unwrap();
        // Each weight is exactly 1/3 of W.
        assert_eq!(r.pays, vec![Some(u64::MAX / 3), Some(u64::MAX / 3)]);
        assert_eq!(
            r.pool_pay,
            u64::MAX - 2 * (u64::MAX / 3),
            "pool absorbs the rounding remainder"
        );
    }

    /// `zero weight sum is malformed (§3.1 non-0 weights)`
    #[test]
    fn payout_amounts_rejects_zero_weight_sum() {
        assert_eq!(
            compute_payout_amounts(0, &[], &[], 1000),
            Err(WeightPayoutError::ZeroWeightSum)
        );
    }

    /// `dust_limits must parallel weights`
    #[test]
    fn payout_amounts_rejects_length_mismatch() {
        assert_eq!(
            compute_payout_amounts(1, &[1, 2], &[546], 1000),
            Err(WeightPayoutError::DustLimitsLengthMismatch {
                weights: 2,
                dust_limits: 1
            })
        );
    }

    /// `Σ pays + pool_pay == t for arbitrary inputs`
    #[test]
    fn payout_amounts_always_consume_exactly_t() {
        for (wp, ws, t) in [
            (1u64, vec![7u64, 13, 29], 312_500_000u64),
            (999, vec![1], 1),
            (1, vec![u64::MAX], u64::MAX),
        ] {
            let dusts = vec![546u32; ws.len()];
            let r = compute_payout_amounts(wp, &ws, &dusts, t).unwrap();
            let paid: u64 = r.pays.iter().flatten().sum();
            assert_eq!(paid + r.pool_pay, t);
        }
    }

    /// `claim is the fee-reduced proportional share of the actual revenue`
    #[test]
    fn claim_sats_is_fee_reduced_proportional() {
        // 50 % of shares, 1.5 % fee, T = 1000 → floor(0.5·0.985·1000) = 492.
        assert_eq!(claim_sats(500, 1000, 15_000, 1000, 0), 492);
        // Zero fee → plain proportion.
        assert_eq!(claim_sats(500, 1000, 0, 1000, 0), 500);
        // 100 % fee → nothing.
        assert_eq!(claim_sats(500, 1000, 1_000_000, 1000, 0), 0);
        // No shares at all → nothing (guards the division).
        assert_eq!(claim_sats(0, 0, 0, 1000, 0), 0);
    }

    /// The promises the coinbase already paid out come off the pot
    /// BEFORE it is split by score — otherwise every member without a
    /// promise is credited a share of everyone else's.
    #[test]
    fn claim_sats_excludes_the_promised_extras() {
        // Half the shares, no fee, T = 1000, 200 promised away.
        assert_eq!(claim_sats(500, 1000, 0, 1000, 200), 400);
        // A net DEBT enlarges the pot: what one member repays is what
        // the others are owed.
        assert_eq!(claim_sats(500, 1000, 0, 1000, -200), 600);
        // Promises beyond the block's own miner cut leave a negative
        // residual, which is a debt like any other.
        assert_eq!(claim_sats(500, 1000, 0, 1000, 1400), -200);
    }

    /// `claim bounds: Σ claims ≤ t for any partition of score_total`
    #[test]
    fn claim_sats_never_overpays() {
        let total = 1_000_000_000_000u64; // SCORE_PRECISION-scale
        let parts = [499_999_999_999u64, 300_000_000_000, 200_000_000_001];
        let t = 312_500_000u64;
        let fee_ppm = 15_000;
        for extras in [0i64, 10_000_000, -10_000_000] {
            let sum: i64 = parts
                .iter()
                .map(|p| claim_sats(*p, total, fee_ppm, t, extras))
                .sum();
            let fee_floor = (t as u128 * fee_ppm as u128 / 1_000_000) as i64;
            // Σ claims is the pot minus the extras: the extras were
            // already paid out of the same coinbase.
            assert!(
                sum + fee_floor + extras <= t as i64,
                "claims + fee + extras exceeded revenue at extras={extras}"
            );
        }
    }

    // ---- extras projection ----

    /// Ordinary case: nothing to cap, `X` is the plain sum and the
    /// divisor is what is left of the pot.
    #[test]
    fn project_extras_passes_through_a_solvent_ledger() {
        let p = project_extras(&[(500, 10_000), (500, -4_000)], 1000, 0, 1_000_000);
        assert_eq!(p.effective, vec![10_000, -4_000]);
        assert_eq!(p.total, 6_000);
        assert_eq!(p.divisor, 1_000_000 - 6_000);
    }

    /// Promises above 95 % of the pot scale down pro rata, and the
    /// divisor survives — a distribution that divides by `pot − X` has
    /// no answer at all once `X` reaches the pot.
    #[test]
    fn project_extras_scales_an_insolvent_ledger_pro_rata() {
        let pot = 1_000_000i64;
        let p = project_extras(&[(500, 900_000), (500, 900_000)], 1000, 0, pot as u64);
        assert_eq!(p.total, pot * 95 / 100);
        assert_eq!(p.effective[0], p.effective[1], "scaled pro rata");
        assert!(p.divisor >= 1, "divisor stays positive");
        assert_eq!(p.divisor, (pot - p.total) as u128);
    }

    /// Scaling is idempotent, which is what lets settlement re-derive
    /// `X` from a snapshot that already holds capped values.
    #[test]
    fn project_extras_scaling_is_idempotent() {
        let first = project_extras(&[(500, 900_000), (500, 900_000)], 1000, 0, 1_000_000);
        let again = project_extras(
            &[(500, first.effective[0]), (500, first.effective[1])],
            1000,
            0,
            1_000_000,
        );
        assert_eq!(first.total, again.total);
        assert_eq!(first.effective, again.effective);
    }

    /// A debt is only collectable out of the payout it shrinks. Beyond
    /// that the weight would go negative, the pool weight with it, and
    /// the block would promise more than it holds — so the extra is
    /// floored and the rest waits for the next block.
    #[test]
    fn project_extras_floors_a_debt_at_what_the_payout_can_repay() {
        let pot = 1_000_000u64;
        let p = project_extras(&[(500, -10_000_000), (500, 0)], 1000, 0, pot);
        // Fixed point of `extra = −u·(pot − extra)/S` at u/S = 1/2:
        // extra = −pot, divisor = 2·pot.
        assert_eq!(p.effective[1], 0);
        assert_eq!(p.total, -(pot as i64));
        assert_eq!(p.divisor, 2 * pot as u128);
        // The floored extra leaves the debtor exactly zero weight.
        let boost = p.effective[0] as i128 * 1000 / p.divisor as i128;
        assert_eq!(500 + boost, 0, "wire weight lands exactly at zero");
    }

    /// A ledger of pure debt never triggers the solvency scale — the
    /// divisor only grows.
    #[test]
    fn project_extras_never_scales_a_net_debt() {
        let p = project_extras(&[(1000, -100)], 1000, 0, 1_000_000);
        assert_eq!(p.total, -100);
        assert_eq!(p.divisor, 1_000_100);
    }

    /// With no scores there is nothing to floor against; the projection
    /// must still terminate with a usable divisor.
    #[test]
    fn project_extras_without_scores_is_well_defined() {
        let p = project_extras(&[(0, -5_000)], 0, 0, 1_000_000);
        assert_eq!(p.total, -5_000);
        assert_eq!(p.divisor, 1_005_000);
    }

    // ---- weights fingerprint (v2) ----

    /// `identical inputs agree, any input change disagrees`
    #[test]
    fn weights_fingerprint_binds_every_input() {
        let base = || {
            weights_fingerprint_from_parts(
                15_000,
                "bc1qpool",
                Some(("bc1qfinder", 50_000)),
                [("bc1qa", 10, 5i64, 546u32), ("bc1qb", 20, -3, 546)],
            )
        };
        assert_eq!(base(), base());
        let fee = weights_fingerprint_from_parts(
            15_001,
            "bc1qpool",
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let fee_recipient = weights_fingerprint_from_parts(
            15_000,
            "bc1qotherpool",
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let bonus = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            None,
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let weight = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 11, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let balance = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 10, 6, 546), ("bc1qb", 20, -3, 546)],
        );
        let order = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            Some(("bc1qfinder", 50_000)),
            [("bc1qb", 20, -3, 546), ("bc1qa", 10, 5, 546)],
        );
        for other in [fee, fee_recipient, bonus, weight, balance, order] {
            assert_ne!(base(), other);
        }
    }

    /// `v2 never collides with v1 for byte-similar inputs (domain tag)`
    #[test]
    fn weights_fingerprint_is_domain_separated_from_v1() {
        let v1 = payouts_fingerprint_from_parts(1000, [("bc1qa", 600u64)]);
        let v2 = weights_fingerprint_from_parts(0, "bc1qpool", None, [("bc1qa", 600, 0i64, 0u32)]);
        assert_ne!(v1, v2);
    }

    // ── Block subsidy (the settlement gate) ─────────────────────────

    /// `the mainnet schedule halves on the interval boundary`
    #[test]
    fn subsidy_halves_on_the_interval_boundary() {
        const I: u32 = SUBSIDY_HALVING_INTERVAL;
        for (height, expect) in [
            (0i32, 5_000_000_000u64),
            (I as i32 - 1, 5_000_000_000),
            (I as i32, 2_500_000_000),
            (2 * I as i32 - 1, 2_500_000_000),
            (2 * I as i32, 1_250_000_000),
            // The epoch this pool actually runs in.
            (4 * I as i32, 312_500_000),
        ] {
            assert_eq!(
                block_subsidy_sats(height, I),
                expect,
                "subsidy at height {height}"
            );
        }
    }

    /// Regtest halves every 150 blocks, so the interval has to be a
    /// parameter: with the mainnet constant, every regtest block past
    /// 150 would look like it had burned part of its own subsidy and
    /// the settlement gate would refuse to book it.
    #[test]
    fn regtest_uses_its_own_shorter_schedule() {
        const R: u32 = REGTEST_SUBSIDY_HALVING_INTERVAL;
        assert_eq!(block_subsidy_sats(149, R), 5_000_000_000);
        assert_eq!(block_subsidy_sats(150, R), 2_500_000_000);
        assert_eq!(block_subsidy_sats(300, R), 1_250_000_000);
        // The regtest heights the pool's own harnesses mine at would be
        // over-estimated by a factor of 4 under the mainnet schedule.
        assert!(block_subsidy_sats(500, R) < block_subsidy_sats(500, SUBSIDY_HALVING_INTERVAL));
    }

    /// The subsidy runs out at the 33rd halving — 50 BTC is only about
    /// 2^32 satoshis, so the last payable one is a single sat. The 64
    /// guard is there for the SHIFT (`u64 >> 64` is undefined), not for
    /// the money, and it has to hold at the far end of the height type.
    #[test]
    fn subsidy_runs_out_and_the_shift_guard_holds() {
        const I: u32 = SUBSIDY_HALVING_INTERVAL;
        assert_eq!(block_subsidy_sats(32 * I as i32, I), 1);
        assert_eq!(block_subsidy_sats(33 * I as i32, I), 0);
        assert_eq!(block_subsidy_sats(i32::MAX, I), 0);
        // Regtest reaches the shift guard at a height a test could
        // plausibly mine to, so it must not panic there either.
        assert_eq!(
            block_subsidy_sats(64 * REGTEST_SUBSIDY_HALVING_INTERVAL as i32, 150),
            0
        );
    }

    /// The gate must fail OPEN on anything that cannot describe a real
    /// block — a floor computed from nonsense would refuse to book a
    /// perfectly good one. The dust sweep mints synthetic negative
    /// heights for its audit rows, so that case is not hypothetical.
    #[test]
    fn subsidy_fails_open_on_impossible_inputs() {
        assert_eq!(block_subsidy_sats(-1, SUBSIDY_HALVING_INTERVAL), 0);
        assert_eq!(block_subsidy_sats(i32::MIN, SUBSIDY_HALVING_INTERVAL), 0);
        assert_eq!(block_subsidy_sats(800_000, 0), 0);
    }

    /// The band is an alarm, not a gate — but it still has to describe
    /// the ±25 % it claims to.
    #[test]
    fn settlement_band_spans_a_quarter_either_way() {
        const T: u64 = 400_000_000;
        assert!(reward_within_band(T, 300_000_000));
        assert!(reward_within_band(T, 500_000_000));
        assert!(!reward_within_band(T, 299_999_999));
        assert!(!reward_within_band(T, 500_000_001));
    }
}
