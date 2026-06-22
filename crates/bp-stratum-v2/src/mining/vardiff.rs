// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vardiff for SV2 mining channels — two algorithms.
//!
//! - **Classic vardiff** (sliding 30-sample / 5-min window, shares-per-
//!   minute target, ±2× clamp, power-of-2 rounding, warmup, ckpool
//!   race-clamp) is shared with `bp-stratum-v1` via the
//!   [`bp_vardiff`] crate. Re-exported here so callers don't need a
//!   second `use` line. Used for **Standard** + **Extended** channels.
//!
//! - **JDC vardiff** ([`JdcVardiff`]) is SV2-specific — used when the
//!   miner is a Job-Declaration-Client (BraiinsOS, custom firmware
//!   that brings its own templates). The classic algorithm doesn't
//!   work for JDCs because the pool no longer sees the full share
//!   distribution: the JDC pre-filters shares against its own target
//!   and only forwards the ones that meet pool difficulty. Instead
//!   we count the shares we DO see in a fixed interval and adjust
//!   towards a target shares-per-minute.
//!
//! The JDC algorithm has three notable shapes vs classic vardiff:
//!
//! 1. **Deadband ratio**: only ratchet if the observed
//!    shares-per-minute is `≥ 2×` or `≤ 0.5×` the target. Avoids
//!    micro-oscillations from JDC pre-filtering noise.
//! 2. **Latest-submission cap**: the new difficulty is clamped to the
//!    most recent share's submission difficulty so the pool never
//!    over-shoots what the JDC has actually proven it can find.
//! 3. **Power-of-2 step** (lower / lower×1.5 / upper) — same step
//!    function as classic vardiff so per-channel diff transitions
//!    look the same on the wire.

pub use bp_vardiff::{
    Clock, SystemClock, TestClock, VarDiffEngine, VARDIFF_CACHE_SIZE, VARDIFF_CACHE_WINDOW_MS,
    VARDIFF_DEFAULT_MIN_DIFFICULTY, VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN, VARDIFF_DIFFICULTY_1,
    VARDIFF_SAMPLE_THRESHOLD, VARDIFF_SLOT_DURATION_MS, VARDIFF_WARMUP_MS,
};

/// Minimum number of shares observed in a check interval before the
/// JDC algorithm is allowed to make a decision.
pub const JDC_MIN_SHARES_PER_INTERVAL: u64 = 2;

/// Deadband: ratios `[low, high]` that produce no retarget. Anything
/// outside this band triggers a power-of-2-rounded step. Both inequalities
/// are STRICT, so the closed band is `(0.5, 2.0)` exclusive of
/// endpoints (a ratio of exactly 2.0 retargets, exactly 0.5 retargets).
pub const JDC_DEADBAND_LOW: f64 = 0.5;
pub const JDC_DEADBAND_HIGH: f64 = 2.0;

/// Outcome of [`JdcVardiff::check`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum JdcVardiffOutcome {
    /// Not enough shares, ratio in deadband, or arithmetic produced
    /// non-finite — caller should not send `SetTarget`.
    NoChange,
    /// Caller should ratchet `session_difficulty` to this value and
    /// fan out `SetTarget` (per-channel-clamped against the channel's
    /// `declared_max_target` at the call site).
    Retarget(f64),
}

/// Per-connection JDC vardiff state. Holds only the share-count
/// snapshot from the last check (the rest of the inputs come from the
/// channel state and the latest accepted-share difficulty).
///
/// The state is `&mut`-owned by the connection task; one instance per
/// JDC connection (irrespective of how many channels are open — only
/// the primary channel's accepted share count is snapshotted).
#[derive(Clone, Copy, Debug, Default)]
pub struct JdcVardiff {
    /// `acceptedShareCount` snapshot at the previous check.
    last_accepted_count: u64,
}

impl JdcVardiff {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run a JDC vardiff check.
    ///
    /// - `current_accepted_count`: the primary channel's
    ///   `accepted_share_count` at the time of the check.
    /// - `current_session_difficulty`: the connection's
    ///   `session_difficulty` (post-clamp; the value we'd be
    ///   ratcheting from).
    /// - `target_shares_per_minute`: per-port config; falls back to
    ///   `6.0` if non-finite or non-positive (falls back to default 6).
    /// - `interval_ms`: `difficultyCheckIntervalMs` from per-port
    ///   config — typically 60 000.
    /// - `latest_submission_difficulty`: the difficulty of the most
    ///   recent accepted share. The new diff is clamped to this so
    ///   the pool never asks for harder work than the JDC has
    ///   actually proven.
    ///
    /// Returns [`JdcVardiffOutcome::NoChange`] for no-op cases:
    /// fewer than [`JDC_MIN_SHARES_PER_INTERVAL`] shares since the
    /// last check, ratio inside the deadband, non-finite arithmetic,
    /// or the rounded step happens to equal the current diff.
    /// Otherwise [`JdcVardiffOutcome::Retarget(new_diff)`].
    ///
    /// Mutates `self.last_accepted_count` to the snapshot we just
    /// took — the next call will see only the deltas from this point
    /// on.
    pub fn check(
        &mut self,
        current_accepted_count: u64,
        current_session_difficulty: f64,
        target_shares_per_minute: f64,
        interval_ms: u64,
        latest_submission_difficulty: f64,
    ) -> JdcVardiffOutcome {
        let shares_this_interval = current_accepted_count.saturating_sub(self.last_accepted_count);
        self.last_accepted_count = current_accepted_count;

        if shares_this_interval < JDC_MIN_SHARES_PER_INTERVAL {
            return JdcVardiffOutcome::NoChange;
        }
        if interval_ms == 0 {
            return JdcVardiffOutcome::NoChange;
        }

        let interval_seconds = interval_ms as f64 / 1000.0;
        let shares_per_minute = (shares_this_interval as f64 / interval_seconds) * 60.0;
        let target_spm = if target_shares_per_minute.is_finite() && target_shares_per_minute > 0.0 {
            target_shares_per_minute
        } else {
            VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN
        };

        let ratio = shares_per_minute / target_spm;
        if !ratio.is_finite() || ratio <= 0.0 {
            return JdcVardiffOutcome::NoChange;
        }
        // Deadband: strict on both sides (`ratio < 2 && ratio > 0.5`).
        // At ratio == 2.0 or 0.5 we DO retarget.
        if ratio < JDC_DEADBAND_HIGH && ratio > JDC_DEADBAND_LOW {
            return JdcVardiffOutcome::NoChange;
        }

        let mut new_diff = current_session_difficulty * ratio;
        if !new_diff.is_finite() {
            return JdcVardiffOutcome::NoChange;
        }
        // Cap at the latest submission difficulty so we don't over-shoot.
        if latest_submission_difficulty.is_finite() && latest_submission_difficulty > 0.0 {
            new_diff = new_diff.min(latest_submission_difficulty);
        }
        if new_diff <= 0.0 {
            return JdcVardiffOutcome::NoChange;
        }

        let target_diff = match nearest_power_of_two_step(new_diff) {
            Some(d) => d,
            None => return JdcVardiffOutcome::NoChange,
        };
        if !target_diff.is_finite()
            || (target_diff - current_session_difficulty).abs() < f64::EPSILON
        {
            return JdcVardiffOutcome::NoChange;
        }
        JdcVardiffOutcome::Retarget(target_diff)
    }
}

/// Nearest-step rounding (lower / lower × 1.5 / upper). Equivalent to
/// `bp_vardiff::VarDiffEngine::nearest_difficulty_step` but exposed as
/// a free function since the JDC algorithm doesn't carry the engine's
/// configured floor (the JDC path doesn't apply a floor at all — the
/// per-channel `declared_max_target` clamp at the call site is the
/// only ceiling). Returns `None` for `val == 0.0` (guards against
/// `log2(0) = -Infinity`).
fn nearest_power_of_two_step(val: f64) -> Option<f64> {
    if val == 0.0 || !val.is_finite() {
        return None;
    }
    let exponent = val.log2().floor();
    let lower = 2_f64.powf(exponent);
    let middle = lower + lower / 2.0;
    let upper = lower * 2.0;
    let dl = (val - lower).abs();
    let dm = (val - middle).abs();
    let du = (val - upper).abs();
    let (mut best_val, mut best_d) = (lower, dl);
    if dm < best_d {
        best_val = middle;
        best_d = dm;
    }
    if du < best_d {
        best_val = upper;
    }
    Some(best_val)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — typical port config: 6 spm target, 60 s check interval.
    fn check(
        v: &mut JdcVardiff,
        accepted: u64,
        current_diff: f64,
        latest_submit: f64,
    ) -> JdcVardiffOutcome {
        v.check(accepted, current_diff, 6.0, 60_000, latest_submit)
    }

    /// Below `JDC_MIN_SHARES_PER_INTERVAL` (2) → no change.
    #[test]
    fn below_min_shares_per_interval_is_noop() {
        let mut v = JdcVardiff::new();
        assert_eq!(
            check(&mut v, 0, 1024.0, 1024.0),
            JdcVardiffOutcome::NoChange
        );
        // bumps last_accepted to 0; second call with 1 still under min.
        assert_eq!(
            check(&mut v, 1, 1024.0, 1024.0),
            JdcVardiffOutcome::NoChange
        );
    }

    /// Ratio inside the deadband (0.5, 2.0) exclusive → no change.
    /// At 6 spm target, 6 shares per minute → ratio = 1.0 → no change.
    #[test]
    fn ratio_inside_deadband_is_noop() {
        let mut v = JdcVardiff::new();
        // 6 shares in 60 s = 6 spm, ratio = 1.0.
        assert_eq!(
            check(&mut v, 6, 1024.0, 1024.0),
            JdcVardiffOutcome::NoChange
        );
    }

    /// Ratio at exact deadband boundary (2.0 or 0.5) → DOES retarget.
    /// The deadband uses strict `<` and `>` so equality falls through.
    #[test]
    fn ratio_at_exact_boundary_retargets() {
        let mut v = JdcVardiff::new();
        // 12 shares in 60 s = 12 spm, ratio = 2.0 (exactly at high
        // boundary). 1024 * 2.0 = 2048 = exact power of 2.
        assert_eq!(
            check(&mut v, 12, 1024.0, 4096.0),
            JdcVardiffOutcome::Retarget(2048.0)
        );
    }

    /// Above the high band (ratio ≥ 2): ratchet UP. Capped at
    /// latest_submission_difficulty.
    #[test]
    fn high_ratio_ratchets_up_capped_at_latest_submission() {
        let mut v = JdcVardiff::new();
        // 30 shares in 60 s = 30 spm, ratio = 5.0. Raw new_diff =
        // 1024 * 5 = 5120 — but cap at latest_submission = 3000 means
        // new_diff = 3000. Step(3000) bracket: lower=2048,
        // middle=3072, upper=4096. dist 3000 → 952, 72, 1096 → 3072.
        assert_eq!(
            check(&mut v, 30, 1024.0, 3000.0),
            JdcVardiffOutcome::Retarget(3072.0)
        );
    }

    /// Below the low band (ratio ≤ 0.5): ratchet DOWN.
    #[test]
    fn low_ratio_ratchets_down() {
        let mut v = JdcVardiff::new();
        // 2 shares in 60 s = 2 spm, ratio = 2/6 ≈ 0.333. new_diff =
        // 1024 * 0.333 ≈ 341.33. Step bracket lower=256, middle=384,
        // upper=512 → distance 85.33, 42.67, 170.67 → 384.
        let out = check(&mut v, 2, 1024.0, 1024.0);
        assert_eq!(out, JdcVardiffOutcome::Retarget(384.0));
    }

    /// Snapshot is per-call: subsequent invocations see only the
    /// delta since the previous one. After ratcheting, the next
    /// check with no new shares is a no-op.
    #[test]
    fn snapshot_is_delta_only() {
        let mut v = JdcVardiff::new();
        // First call: 30 shares, ratio = 5.0, raw new_diff = 5120,
        // capped at latest_submit = 2048 → step(2048) = 2048.
        // Sets last_accepted_count = 30.
        assert_eq!(
            check(&mut v, 30, 1024.0, 2048.0),
            JdcVardiffOutcome::Retarget(2048.0)
        );
        // Second call: no new shares since last call → 0 < min → noop.
        assert_eq!(
            check(&mut v, 30, 2048.0, 4096.0),
            JdcVardiffOutcome::NoChange
        );
    }

    /// Non-finite or non-positive `target_shares_per_minute` falls
    /// back to the default of 6.
    #[test]
    fn invalid_target_spm_falls_back_to_default() {
        let mut v = JdcVardiff::new();
        // 12 shares in 60 s with target=NaN (default 6) → ratio 2.0
        // → retarget exactly as if 6 had been passed.
        assert_eq!(
            v.check(12, 1024.0, f64::NAN, 60_000, 4096.0),
            JdcVardiffOutcome::Retarget(2048.0)
        );
    }

    /// Zero `interval_ms` → no-op (division by zero guard).
    #[test]
    fn zero_interval_is_noop() {
        let mut v = JdcVardiff::new();
        assert_eq!(
            v.check(30, 1024.0, 6.0, 0, 4096.0),
            JdcVardiffOutcome::NoChange
        );
    }

    /// If the rounded step happens to equal the current diff → no-op
    /// (otherwise we'd send a redundant `SetTarget`).
    #[test]
    fn equal_step_is_noop() {
        let mut v = JdcVardiff::new();
        // Construct a scenario where new_diff lands back at 1024:
        // 12 shares / 60s, ratio 2.0, current 1024 * 2 = 2048,
        // CAPPED at latest_submit = 1024 → 1024. step(1024) = 1024.
        // Since target_diff == current_session_difficulty → noop.
        assert_eq!(
            check(&mut v, 12, 1024.0, 1024.0),
            JdcVardiffOutcome::NoChange
        );
    }
}
