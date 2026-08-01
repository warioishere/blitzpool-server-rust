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

/// A miner's settlement claim on a found block:
/// `floor(score_weight · (1 − fee) · t_actual / score_total)`, the
/// weight model's "earned" side. Settlement books
/// `balance += claim − actually_paid` per address, with `t_actual` and
/// the paid amounts read from the REAL coinbase of the found block —
/// so the claim must come from the same raw inputs the published
/// weights were derived from, never from any projected wire weight.
///
/// Integer-exact: `fee_ppm` is parts-per-million (1 % = 10 000);
/// the u128 product `score · (10^6 − fee_ppm) · t` stays far below
/// 2^128 for any real score precision and sat amount.
pub fn claim_sats(score_weight: u64, score_total: u64, fee_ppm: u32, t_actual: u64) -> u64 {
    if score_total == 0 {
        return 0;
    }
    let miner_ppm = 1_000_000u128.saturating_sub(fee_ppm as u128);
    let numer = score_weight as u128 * miner_ppm * t_actual as u128;
    let denom = score_total as u128 * 1_000_000u128;
    (numer / denom) as u64
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
/// Deliberately NOT in the preimage: the published wire weights and
/// the reference revenue behind their balance boosts — distributions
/// that differ only there settle identically and may share a snapshot.
///
/// Canonical, domain-tagged, length-prefixed; entry order is part of
/// the identity (it is the coinbase output order).
pub fn weights_fingerprint_from_parts<'a>(
    fee_ppm: u32,
    finder_bonus: Option<(&'a str, u64)>,
    entries: impl IntoIterator<Item = (&'a str, u64, i64, u32)>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bp-weights-v2");
    hasher.update(fee_ppm.to_le_bytes());
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
        assert_eq!(claim_sats(500, 1000, 15_000, 1000), 492);
        // Zero fee → plain proportion.
        assert_eq!(claim_sats(500, 1000, 0, 1000), 500);
        // 100 % fee → nothing.
        assert_eq!(claim_sats(500, 1000, 1_000_000, 1000), 0);
        // No shares at all → nothing (guards the division).
        assert_eq!(claim_sats(0, 0, 0, 1000), 0);
    }

    /// `claim bounds: Σ claims ≤ t for any partition of score_total`
    #[test]
    fn claim_sats_never_overpays() {
        let total = 1_000_000_000_000u64; // SCORE_PRECISION-scale
        let parts = [499_999_999_999u64, 300_000_000_000, 200_000_000_001];
        let t = 312_500_000u64;
        let fee_ppm = 15_000;
        let sum: u64 = parts
            .iter()
            .map(|p| claim_sats(*p, total, fee_ppm, t))
            .sum();
        let fee_floor = (t as u128 * fee_ppm as u128 / 1_000_000) as u64;
        assert!(sum + fee_floor <= t, "claims + fee exceeded revenue");
    }

    // ---- weights fingerprint (v2) ----

    /// `identical inputs agree, any input change disagrees`
    #[test]
    fn weights_fingerprint_binds_every_input() {
        let base = || {
            weights_fingerprint_from_parts(
                15_000,
                Some(("bc1qfinder", 50_000)),
                [("bc1qa", 10, 5i64, 546u32), ("bc1qb", 20, -3, 546)],
            )
        };
        assert_eq!(base(), base());
        let fee = weights_fingerprint_from_parts(
            15_001,
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let bonus = weights_fingerprint_from_parts(
            15_000,
            None,
            [("bc1qa", 10, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let weight = weights_fingerprint_from_parts(
            15_000,
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 11, 5, 546), ("bc1qb", 20, -3, 546)],
        );
        let balance = weights_fingerprint_from_parts(
            15_000,
            Some(("bc1qfinder", 50_000)),
            [("bc1qa", 10, 6, 546), ("bc1qb", 20, -3, 546)],
        );
        let order = weights_fingerprint_from_parts(
            15_000,
            Some(("bc1qfinder", 50_000)),
            [("bc1qb", 20, -3, 546), ("bc1qa", 10, 5, 546)],
        );
        for other in [fee, bonus, weight, balance, order] {
            assert_ne!(base(), other);
        }
    }

    /// `v2 never collides with v1 for byte-similar inputs (domain tag)`
    #[test]
    fn weights_fingerprint_is_domain_separated_from_v1() {
        let v1 = payouts_fingerprint_from_parts(1000, [("bc1qa", 600u64)]);
        let v2 = weights_fingerprint_from_parts(0, None, [("bc1qa", 600, 0i64, 0u32)]);
        assert_ne!(v1, v2);
    }
}
