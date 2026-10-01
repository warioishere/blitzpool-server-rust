// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share validation and difficulty math, pure and without I/O; difficulty
//! results hold to `1e-6` relative. Targets and hashes are 32-byte
//! little-endian U256, the wire form of SV1 (after the edge byte reversal)
//! and SV2; a hash meets a target iff `hash ≤ target`.

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

/// [`TRUE_DIFF_ONE`] as an `f64`: `0xffff · 2^208` has 16 significant bits,
/// so it is exact (pinned by `true_diff_one_f64_is_exact`).
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

    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Target(bytes)
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
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

/// `sha256d(&parts.concat())` without the joined buffer, for hashing the
/// coinbase pieces on the per-share hot path.
pub fn sha256d_from_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let first = hasher.finalize();
    Sha256::digest(first).into()
}

// ============================================================================
// Weight-proportional payouts (SV2 ext 0x0003 §4)
// ============================================================================

/// `floor(weight · t / w_total)` with the 128-bit intermediates ext 0x0003
/// §4 mandates; the quotient is `≤ t`, so the `u64` cast is lossless.
/// `w_total` MUST be non-zero (§3.1 weight fields are non-0).
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

/// The ext 0x0003 §4 formulae: `amount[i] = floor(weights[i]·t/W)`, pruned
/// below `dust_limits[i]`, and `pay_P = t − Σ pay[i]`. The one
/// implementation for the pool's coinbase build and the job-declaration
/// validator, so both compute identical amounts.
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

/// The genesis block subsidy: 50 BTC.
pub const INITIAL_BLOCK_SUBSIDY_SATS: u64 = 5_000_000_000;

/// Blocks between subsidy halvings on mainnet — and on testnet3 and
/// testnet4, which share the schedule.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;

/// Blocks between subsidy halvings on regtest.
pub const REGTEST_SUBSIDY_HALVING_INTERVAL: u32 = 150;

/// Consensus block subsidy at `height`: the floor settlement gates on, since
/// a coinbase below the subsidy alone forfeited money no healthy block
/// would. Fails open (0) on a negative height (the dust sweep's synthetic
/// rows) or zero interval; the interval is a parameter for regtest.
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

/// Ceiling on `X` as a percentage of `pot(t_ref)`. The projection divides by
/// `pot − X`, so `X ≥ pot` would divide by zero or flip every boost; the
/// headroom also keeps miners without a promise from being pruned to nothing.
const EXTRA_SOLVENCY_PERCENT: i128 = 95;

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

/// Folds a ledger into the pairs [`project_extras`] consumes. Trivial but
/// shared, because build and settlement must agree to the satoshi. The
/// Group-Solo finder bonus is score weight, not a satoshi extra.
pub fn extras_from_ledger<'a>(
    entries: impl IntoIterator<Item = (&'a str, u64, i64)>,
) -> Vec<(u64, i64)> {
    entries
        .into_iter()
        .map(|(_address, score_weight, balance_sats)| (score_weight, balance_sats))
        .collect()
}

/// Resolves signed per-address ledger extras into what the block can honour:
/// scaled pro rata to the solvency cap, and each debt floored at what its
/// own payout is worth (the rest stays on the ledger), else the block pays
/// out more than it holds. Deterministic, so settlement reproduces `X`.
pub fn project_extras(
    entries: &[(u64, i64)],
    score_total: u64,
    fee_ppm: u32,
    reference_revenue_sats: u64,
) -> ExtraProjection {
    let pot = miner_pot_sats(fee_ppm, reference_revenue_sats) as i128;
    if pot <= 0 {
        // An empty miner cut can carry no promise in either direction.
        return ExtraProjection {
            effective: vec![0; entries.len()],
            total: 0,
            divisor: 1,
        };
    }
    let solvency_cap = pot * EXTRA_SOLVENCY_PERCENT / 100;
    let mut effective: Vec<i128> = entries.iter().map(|(_, extra)| *extra as i128).collect();

    scale_to_cap(&mut effective, solvency_cap);
    // The floors only raise extras, so `pot − X` can only shrink from here;
    // the bound gives a fully-indebted ledger a finite solution.
    let divisor_bound = (pot - sum(&effective)).max(1);
    apply_repayment_floors(&mut effective, entries, score_total, pot, divisor_bound);
    // Floors can push promises over the cap again. One more scale settles
    // it without re-breaking the floors: a larger divisor is a looser floor.
    scale_to_cap(&mut effective, solvency_cap);

    let total = sum(&effective);
    ExtraProjection {
        effective: effective
            .into_iter()
            .map(|e| e.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
            .collect(),
        total: total.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
        // From the final `X`, so published boosts and settlement claims
        // cannot drift apart.
        divisor: (pot - total).max(1) as u128,
    }
}

fn sum(values: &[i128]) -> i128 {
    values.iter().sum()
}

/// Scales every promise pro rata to fit `cap`.
fn scale_to_cap(effective: &mut [i128], cap: i128) {
    let x = sum(effective);
    if x > cap {
        for e in effective.iter_mut() {
            *e = (*e * cap) / x;
        }
    }
}

/// Pins each uncollectable debt to what its payout is worth. Solved in
/// closed form per pinned set, which only grows, so at most one pass per
/// address; iterating the floor converges only geometrically and stalls
/// short of the fixed point for a large debtor.
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
            // Every scorer is beyond repayment: take the loosest divisor
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

/// Score share of the miner cut left after the promises `X` (from
/// [`project_extras`]): the coinbase paid `X` from this pot, so charging the
/// full pot would credit others' promises. Uses raw inputs, never wire
/// weights; negative when promises exceed the block's actual miner cut.
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

/// Hash of the settlement inputs (fee, `fee_address`, per-address score,
/// balance, dust limit), not of wire weights or revenue, which settle
/// identically. Entry order is hashed: pass address order, never coinbase
/// order (it sorts by wire weight).
pub fn weights_fingerprint_from_parts<'a>(
    fee_ppm: u32,
    fee_address: &str,
    entries: impl IntoIterator<Item = (&'a str, u64, i64, u32)>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bp-weights-v3");
    hasher.update(fee_ppm.to_le_bytes());
    hasher.update((fee_address.len() as u32).to_le_bytes());
    hasher.update(fee_address.as_bytes());
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

/// 32 little-endian bytes as the nearest `f64`; the ~1e-15 relative error is
/// far inside the module's `1e-6` tolerance.
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

/// `TRUE_DIFF_ONE / target` in plain `f64`, keeping the once-per-share call
/// from [`calculate_difficulty`] allocation-free. Accuracy is pinned by
/// `prop_target_to_difficulty_matches_bigint_reference`.
pub fn target_to_difficulty(target: &Target) -> Difficulty {
    let divisor = le_bytes_to_f64(&target.0);
    if divisor == 0.0 {
        return Difficulty(f64::MAX);
    }
    Difficulty(TRUE_DIFF_ONE_F64 / divisor)
}

/// `floor(TRUE_DIFF_ONE / difficulty)`; invalid difficulties give
/// `Target::MAX`. Integer and scaled fraction are split so large
/// difficulties do not overflow the scaled intermediate.
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

/// One-slot memo for [`difficulty_to_target`]: a session's difficulty
/// rarely changes, and keying on the exact f64 bits makes a hit
/// bit-identical to recomputing.
#[derive(Clone, Copy, Debug, Default)]
pub struct TargetMemo(Option<(u64, Target)>);

impl TargetMemo {
    pub fn target_for(&mut self, diff: Difficulty) -> Target {
        let key = diff.0.to_bits();
        if let Some((cached_key, cached_target)) = self.0 {
            if cached_key == key {
                return cached_target;
            }
        }
        let target = difficulty_to_target(diff);
        self.0 = Some((key, target));
        target
    }
}

// ============================================================================
// SV2 hashrate-to-target
// ============================================================================

/// SV2-spec target = (2^256 − h·s) / (h·s + 1)
/// where h = hashrate (H/s), s = 60 / sharesPerMinute.
fn hash_rate_to_target(hash_rate: f64, shares_per_minute: f64) -> Target {
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

    /// Big-integer reference that [`target_to_difficulty`] is checked against.
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
    fn target_display_is_be_hex() {
        // Difficulty-1 target: LE storage has 0xFF at indices 26–27.
        let mut le = [0u8; 32];
        le[26] = 0xff;
        le[27] = 0xff;
        let s = Target(le).to_string();
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
        // Acceptance is the byte-exact `is_met_by_le`, so a hash at the
        // target passes regardless of float round-trip error.
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
        // Sub-unit CPU miners up to ~1e14, where a u64 cast of the scaled
        // value would wrap.
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

    // ---- TargetMemo ----

    /// The memo matches uncached `difficulty_to_target` and recomputes on change.
    #[test]
    fn target_memo_matches_uncached_and_recomputes_on_change() {
        let mut memo = TargetMemo::default();
        for d in [1.0, 1024.0, 65535.0, 0.5, 1e9, 1234.5678] {
            let direct = difficulty_to_target(Difficulty(d));
            assert_eq!(
                memo.target_for(Difficulty(d)),
                direct,
                "diff {d}: memo != uncached"
            );
            // Immediate repeat is served from the slot — still equal.
            assert_eq!(
                memo.target_for(Difficulty(d)),
                direct,
                "diff {d}: repeat mismatch"
            );
        }
        let a = memo.target_for(Difficulty(1024.0));
        let b = memo.target_for(Difficulty(2048.0));
        assert_ne!(a, b, "distinct difficulties must map to distinct targets");
        assert_eq!(
            memo.target_for(Difficulty(1024.0)),
            difficulty_to_target(Difficulty(1024.0)),
            "re-selecting a prior difficulty must recompute correctly"
        );
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
        // Diff 100 is easier than the max target allows; clamp lifts it.
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
        // Mainnet genesis header; the hash proves SHA256d and byte order,
        // the difficulty is only range-checked.
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

        // The genesis hash lands well below the diff-1 target, so ≈ 2536.
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
            let target = Target(target_le);
            let got = target_to_difficulty(&target).0;
            let want = target_to_difficulty_bigint_reference(&target);
            // Near-zero targets saturate to MAX in both; treat as equal.
            if want == f64::MAX || got == f64::MAX {
                prop_assert_eq!(want, got);
            } else {
                // The residual is the reference's own scaled truncation.
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

    /// Promises already paid by the coinbase come off the pot before the
    /// score split.
    #[test]
    fn claim_sats_excludes_the_promised_extras() {
        // Half the shares, no fee, T = 1000, 200 promised away.
        assert_eq!(claim_sats(500, 1000, 0, 1000, 200), 400);
        // A net debt enlarges the pot.
        assert_eq!(claim_sats(500, 1000, 0, 1000, -200), 600);
        // Promises beyond the miner cut leave a negative residual (a debt).
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
            // The extras were paid out of the same coinbase.
            assert!(
                sum + fee_floor + extras <= t as i64,
                "claims + fee + extras exceeded revenue at extras={extras}"
            );
        }
    }

    // ---- extras projection ----

    /// A solvent ledger passes through unchanged.
    #[test]
    fn project_extras_passes_through_a_solvent_ledger() {
        let p = project_extras(&[(500, 10_000), (500, -4_000)], 1000, 0, 1_000_000);
        assert_eq!(p.effective, vec![10_000, -4_000]);
        assert_eq!(p.total, 6_000);
        assert_eq!(p.divisor, 1_000_000 - 6_000);
    }

    /// Promises above 95 % of the pot scale down pro rata; the divisor stays
    /// positive.
    #[test]
    fn project_extras_scales_an_insolvent_ledger_pro_rata() {
        let pot = 1_000_000i64;
        let p = project_extras(&[(500, 900_000), (500, 900_000)], 1000, 0, pot as u64);
        assert_eq!(p.total, pot * 95 / 100);
        assert_eq!(p.effective[0], p.effective[1], "scaled pro rata");
        assert!(p.divisor >= 1, "divisor stays positive");
        assert_eq!(p.divisor, (pot - p.total) as u128);
    }

    /// Scaling is idempotent, so settlement re-derives `X` from capped values.
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

    /// A debt is floored at what the debtor's payout can repay.
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

    /// A net debt never triggers the solvency scale.
    #[test]
    fn project_extras_never_scales_a_net_debt() {
        let p = project_extras(&[(1000, -100)], 1000, 0, 1_000_000);
        assert_eq!(p.total, -100);
        assert_eq!(p.divisor, 1_000_100);
    }

    /// Without scores the projection still yields a usable divisor.
    #[test]
    fn project_extras_without_scores_is_well_defined() {
        let p = project_extras(&[(0, -5_000)], 0, 0, 1_000_000);
        assert_eq!(p.total, -5_000);
        assert_eq!(p.divisor, 1_005_000);
    }

    // ---- weights fingerprint (v3) ----

    /// Identical inputs agree; any input change disagrees.
    #[test]
    fn weights_fingerprint_binds_every_input() {
        let base = || {
            weights_fingerprint_from_parts(
                15_000,
                "bc1qpool",
                [("bc1qa", 10, 5i64, 546u32), ("bc1qb", 20, -3, 546)],
            )
        };
        assert_eq!(base(), base());
        let fee = weights_fingerprint_from_parts(
            15_001,
            "bc1qpool",
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let fee_recipient = weights_fingerprint_from_parts(
            15_000,
            "bc1qotherpool",
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let weight = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            [("bc1qa", 11, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let balance = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            [("bc1qa", 10, 6, 546), ("bc1qb", 20, -3, 546)],
        );
        let order = weights_fingerprint_from_parts(
            15_000,
            "bc1qpool",
            [("bc1qb", 20, -3, 546), ("bc1qa", 10, 5, 546)],
        );
        for other in [fee, fee_recipient, weight, balance, order] {
            assert_ne!(base(), other);
        }
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

    /// Regtest uses its own 150-block halving schedule.
    #[test]
    fn regtest_uses_its_own_shorter_schedule() {
        const R: u32 = REGTEST_SUBSIDY_HALVING_INTERVAL;
        assert_eq!(block_subsidy_sats(149, R), 5_000_000_000);
        assert_eq!(block_subsidy_sats(150, R), 2_500_000_000);
        assert_eq!(block_subsidy_sats(300, R), 1_250_000_000);
        assert!(block_subsidy_sats(500, R) < block_subsidy_sats(500, SUBSIDY_HALVING_INTERVAL));
    }

    /// The subsidy runs out at the 33rd halving, and the 64-halving shift
    /// guard holds at the far end of the height type.
    #[test]
    fn subsidy_runs_out_and_the_shift_guard_holds() {
        const I: u32 = SUBSIDY_HALVING_INTERVAL;
        assert_eq!(block_subsidy_sats(32 * I as i32, I), 1);
        assert_eq!(block_subsidy_sats(33 * I as i32, I), 0);
        assert_eq!(block_subsidy_sats(i32::MAX, I), 0);
        // Regtest reaches the shift guard at a minable height.
        assert_eq!(
            block_subsidy_sats(64 * REGTEST_SUBSIDY_HALVING_INTERVAL as i32, 150),
            0
        );
    }

    /// Impossible inputs fail open, so a nonsense floor cannot block a booking.
    #[test]
    fn subsidy_fails_open_on_impossible_inputs() {
        assert_eq!(block_subsidy_sats(-1, SUBSIDY_HALVING_INTERVAL), 0);
        assert_eq!(block_subsidy_sats(i32::MIN, SUBSIDY_HALVING_INTERVAL), 0);
        assert_eq!(block_subsidy_sats(800_000, 0), 0);
    }
}
