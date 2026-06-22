// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session VarDiff engine + ckpool-style race-window clamp.
//!
//! Pure-math leaf crate, std-only. Shared between [`bp-stratum-v1`] (which
//! sends the result as `mining.set_difficulty` JSON) and `bp-stratum-v2`
//! (which sends the result as a binary `SetTarget` frame on Standard /
//! Extended channels). The vardiff math is wire-format-agnostic — only
//! the framing layer differs.
//!
//! Originally lived in `bp-stratum-v1::vardiff`; extracted to its own
//! crate 2026-05-16 when bp-stratum-v2 was about to grow its own copy.
//!
//! Implements the per-session VarDiff algorithm (shares-per-minute
//! retarget) and the `effectiveJobDifficulty` helper used for the
//! ckpool-style race-window clamp. The same algorithm is used
//! pool-wide for the classic shares-per-minute retarget; SV2's
//! JD-client-specific share-count vardiff is a different algorithm
//! and lives in `bp-stratum-v2::mining::vardiff`.
//!
//! Two pieces:
//!
//! - [`VarDiffEngine`] tracks per-session live hashrate (10-minute slots,
//!   `(prev + current) * 2^32 / elapsed_seconds`) AND the sliding 5-min /
//!   30-sample submission cache used to retarget the session difficulty.
//!   `update_hash_rate` is called for every accepted share;
//!   `suggested_difficulty` is polled on a timer (default every 60 s).
//!
//! - [`effective_job_difficulty`] is the share-validation race-clamp:
//!   when a vardiff ratchet flips the session difficulty up, in-flight
//!   shares for jobs already issued at the OLD diff would otherwise be
//!   rejected as "Difficulty too low" even though the miner was working
//!   on exactly the target we'd given them. The clamp validates and
//!   credits those shares at `min(current, old)` so the miner gets paid
//!   for the work they actually did.
//!
//! The engine is owned `&mut` by its connection task — no internal locks.
//! A [`Clock`] trait makes the time source injectable so tests can pin
//! deterministic timestamps.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of submissions kept in the retarget sample cache.
pub const VARDIFF_CACHE_SIZE: usize = 30;

/// Sliding window for the submission cache. Older entries are dropped on
/// the next `update_hash_rate`.
pub const VARDIFF_CACHE_WINDOW_MS: u64 = 300_000;

/// Default vardiff floor when the caller passes a non-finite / non-positive
/// `min_difficulty`.
pub const VARDIFF_DEFAULT_MIN_DIFFICULTY: f64 = 0.00001;

/// Difficulty-1 hash count (`2^32`). Used to convert accepted-share
/// difficulty into hashrate (`sum * DIFFICULTY_1 / seconds`).
pub const VARDIFF_DIFFICULTY_1: f64 = 4_294_967_296.0;

/// Hashrate-slot length. 10-minute slots labeled by their end timestamp;
/// the engine only cares about transitions, so the constant is inlined
/// here rather than imported from `bp-stats`.
pub const VARDIFF_SLOT_DURATION_MS: u64 = 600_000;

/// Minimum samples before the retarget math is allowed to fire. Below
/// the threshold, the engine either waits or — past the warmup window —
/// emits a fallback target derived from `clientDifficulty / target`.
pub const VARDIFF_SAMPLE_THRESHOLD: usize = 5;

/// Initial warmup period during which under-sampled sessions are NOT
/// retargeted (return `None`). After this, the fallback formula kicks in.
pub const VARDIFF_WARMUP_MS: u64 = 60_000;

/// Default `target_shares_per_minute` fallback for misconfigured ports.
pub const VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN: f64 = 6.0;

// ── Clock ────────────────────────────────────────────────────────────

/// Monotonic-ish millisecond clock. Real-world impl wraps `SystemTime`;
/// tests use [`TestClock`] for deterministic advance.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// Wall-clock implementation. Returns `SystemTime::now()` as millis
/// since the UNIX epoch. The vardiff engine only ever uses time
/// differences, so a backwards step (NTP adjustment) at most produces a
/// stalled-retarget window — never panics.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Deterministic clock for tests. `now_ms` is held in an atomic so it can
/// be shared by reference; `advance` / `set` mutate it without an outer
/// lock.
#[derive(Debug)]
pub struct TestClock {
    now_ms: AtomicU64,
}

impl TestClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(start_ms),
        }
    }

    pub fn advance_ms(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn set_ms(&self, ms: u64) {
        self.now_ms.store(ms, Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Relaxed)
    }
}

// Blanket impl so `&TestClock` / `Arc<TestClock>` can be used directly.
impl<T: Clock + ?Sized> Clock for &T {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

impl<T: Clock + ?Sized> Clock for std::sync::Arc<T> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

// ── effective_job_difficulty ─────────────────────────────────────────

/// ckpool-style per-job difficulty clamp.
///
/// When a vardiff ratchet flips the session difficulty up, miner firmware
/// typically only applies the new target on the next `mining.notify` —
/// shares for jobs already in flight were legitimately computed against
/// the OLD target. Without this clamp those shares get rejected as
/// "Difficulty too low" even though the miner did what we told it to do.
///
/// Returns the difficulty to use for BOTH the validation `>=` check AND
/// downstream accounting (PPLNS recordShare, group-solo recordShare,
/// per-mode hashrate, share totals). Keeping these in lock-step prevents
/// the miner from getting credit at the post-ratchet diff for work they
/// actually did at the pre-ratchet diff.
///
/// `job_id_int = None` corresponds to a `parseInt` failure on the wire-
/// hex jobId (malformed submission); falls back to `currentDiff`.
///
/// `diff_change_job_id = None` means no ratchet has happened since the
/// session started — the clamp is inactive and `currentDiff` always wins.
pub fn effective_job_difficulty(
    job_id_int: Option<u64>,
    current_diff: f64,
    old_diff: f64,
    diff_change_job_id: Option<u64>,
) -> f64 {
    match (job_id_int, diff_change_job_id) {
        (None, _) => current_diff,
        (Some(_), None) => current_diff,
        (Some(jid), Some(boundary)) => {
            if jid < boundary {
                current_diff.min(old_diff)
            } else {
                current_diff
            }
        }
    }
}

// ── VarDiffEngine ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct Submission {
    time_ms: u64,
    difficulty: f64,
}

/// Per-session VarDiff state machine + hashrate accumulator.
///
/// **Two state stores**, both owned by `&mut self`:
///
/// - `submission_cache` — sliding 30-sample / 5-min window of accepted
///   shares' difficulty + arrival time. Drives the retarget math.
///   Stale-diff shares (clamped-via-`effective_job_difficulty`) MUST
///   be excluded with `is_current_diff = false`; mixing them pollutes
///   the rolling sum and oscillates the retarget.
///
/// - Hashrate accumulators — `shares` and `previous_shares` over
///   10-minute time slots, used to compute the displayed live hashrate
///   as `(prev + current) * 2^32 / elapsed_seconds`. ALL accepted shares
///   contribute here, including clamped ones — the user-facing hashrate
///   must reflect real work even during a vardiff race window.
pub struct VarDiffEngine<C: Clock> {
    clock: C,

    // Config
    target_shares_per_minute: f64,
    target_submission_per_second: f64,
    min_difficulty: f64,

    // Cache state
    submission_cache_start_ms: u64,
    submission_cache: VecDeque<Submission>,

    // Hashrate state
    hash_rate: f64,
    current_slot: Option<u64>,
    previous_slot_time_ms: u64,
    current_slot_time_ms: u64,
    previous_shares: f64,
    shares: f64,
}

impl<C: Clock> VarDiffEngine<C> {
    /// Construct with a clock + per-port config. `target_shares_per_minute`
    /// ≤ 0 falls back to [`VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN`]; a
    /// non-finite / non-positive `min_difficulty` falls back to
    /// [`VARDIFF_DEFAULT_MIN_DIFFICULTY`].
    pub fn new(clock: C, target_shares_per_minute: f64, min_difficulty: f64) -> Self {
        let target = if target_shares_per_minute > 0.0 && target_shares_per_minute.is_finite() {
            target_shares_per_minute
        } else {
            VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN
        };
        let min_difficulty = if min_difficulty.is_finite() && min_difficulty > 0.0 {
            min_difficulty
        } else {
            VARDIFF_DEFAULT_MIN_DIFFICULTY
        };
        let now = clock.now_ms();
        Self {
            clock,
            target_shares_per_minute: target,
            target_submission_per_second: 60.0 / target,
            min_difficulty,
            submission_cache_start_ms: now,
            submission_cache: VecDeque::with_capacity(VARDIFF_CACHE_SIZE + 1),
            hash_rate: 0.0,
            current_slot: None,
            previous_slot_time_ms: 0,
            current_slot_time_ms: 0,
            previous_shares: 0.0,
            shares: 0.0,
        }
    }

    /// Latest computed hashrate in hashes/second. Initially `0.0`; rises
    /// as shares accumulate within the current 10-minute slot.
    pub fn hash_rate(&self) -> f64 {
        self.hash_rate
    }

    /// Submission cache size — exposed for tests + diagnostics.
    pub fn cache_len(&self) -> usize {
        self.submission_cache.len()
    }

    /// `shares` accumulator for the current time slot — exposed for tests.
    /// Production callers should use [`hash_rate`] instead.
    pub fn current_shares(&self) -> f64 {
        self.shares
    }

    /// Record an accepted share. `target_difficulty` is the difficulty
    /// the share was actually credited at (post-clamp). `is_current_diff`
    /// MUST be `false` if the clamp moved the credit from the session's
    /// current diff to its OLD diff; this gates the submission-cache write
    /// so the retarget math stays clean.
    pub fn update_hash_rate(&mut self, target_difficulty: f64, is_current_diff: bool) {
        let now = self.clock.now_ms();
        let slot = slot_for(now);

        if is_current_diff {
            self.update_submission_cache(now, target_difficulty);
        }

        match self.current_slot {
            None => {
                // First share: pin the slot baseline.
                self.previous_slot_time_ms = now;
                self.current_slot_time_ms = now;
                self.current_slot = Some(slot);
                self.shares = target_difficulty;
            }
            Some(s) if s != slot => {
                // Crossing a slot boundary: rotate prev ← current,
                // restart current.
                self.previous_shares = self.shares;
                self.previous_slot_time_ms = self.current_slot_time_ms;
                self.current_slot_time_ms = now;
                self.current_slot = Some(slot);
                self.shares = target_difficulty;
            }
            Some(_) => {
                // Same slot: accumulate.
                self.shares += target_difficulty;
                if self.shares > 0.0 {
                    let elapsed_ms = now.saturating_sub(self.previous_slot_time_ms) as f64;
                    if elapsed_ms > 0.0 {
                        let seconds = elapsed_ms / 1000.0;
                        self.hash_rate =
                            (self.previous_shares + self.shares) * VARDIFF_DIFFICULTY_1 / seconds;
                    }
                }
            }
        }
    }

    fn update_submission_cache(&mut self, now: u64, difficulty: f64) {
        // Drop entries older than the sliding window via `front()` peek.
        while let Some(front) = self.submission_cache.front() {
            if now.saturating_sub(front.time_ms) > VARDIFF_CACHE_WINDOW_MS {
                self.submission_cache.pop_front();
            } else {
                break;
            }
        }
        // Cap by size.
        if self.submission_cache.len() >= VARDIFF_CACHE_SIZE {
            self.submission_cache.pop_front();
        }
        self.submission_cache.push_back(Submission {
            time_ms: now,
            difficulty,
        });
    }

    /// Compute the suggested next session difficulty given the miner's
    /// current diff. Returns:
    ///
    /// - `None` — no retarget recommended (insufficient samples + still
    ///   in warmup OR samples present but already inside the 2× clamp).
    /// - `Some(diff)` — a freshly-rounded power-of-2 target. Always
    ///   ≥ [`min_difficulty`]; never NaN / Infinity.
    ///
    /// Both branches funnel through `nearest_difficulty_step` (which floors
    /// at `min_difficulty`).
    pub fn suggested_difficulty(&self, client_difficulty: f64) -> Option<f64> {
        if self.submission_cache.len() < VARDIFF_SAMPLE_THRESHOLD {
            // Under-sampled: only retarget once the warmup window
            // has elapsed, in which case use the rough-fallback formula.
            let now = self.clock.now_ms();
            if now.saturating_sub(self.submission_cache_start_ms) > VARDIFF_WARMUP_MS {
                return self
                    .nearest_difficulty_step(client_difficulty / self.target_shares_per_minute);
            }
            return None;
        }

        let sum: f64 = self.submission_cache.iter().map(|s| s.difficulty).sum();
        let first_t = self.submission_cache.front().expect("≥ threshold").time_ms;
        let last_t = self.submission_cache.back().expect("≥ threshold").time_ms;
        let diff_seconds = last_t.saturating_sub(first_t) as f64 / 1000.0;
        if diff_seconds <= 0.0 {
            return None;
        }

        let difficulty_per_second = sum / diff_seconds;
        let target_difficulty = difficulty_per_second * self.target_submission_per_second;
        if !difficulty_per_second.is_finite() || !target_difficulty.is_finite() {
            return None;
        }

        // 2× clamp: only retarget if the observed rate is meaningfully
        // off from the configured target.
        if client_difficulty * 2.0 < target_difficulty
            || client_difficulty / 2.0 > target_difficulty
        {
            return self.nearest_difficulty_step(target_difficulty);
        }
        None
    }

    /// Round to the nearest power-of-2 step (lower / lower * 1.5 /
    /// upper). Floors at [`min_difficulty`]. Returns `None` for `val == 0`
    /// Guards against `log2(0) = -Infinity`.
    fn nearest_difficulty_step(&self, val: f64) -> Option<f64> {
        if val == 0.0 {
            return None;
        }
        if val < self.min_difficulty {
            return Some(self.min_difficulty);
        }
        let exponent = val.log2().floor();
        let lower = 2_f64.powf(exponent);
        let middle = lower + lower / 2.0;
        let upper = lower * 2.0;

        let dl = (val - lower).abs();
        let dm = (val - middle).abs();
        let du = (val - upper).abs();
        // Pick the nearest. Equal distances tie-break in declaration order
        // [lower, middle, upper].
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
}

/// 10-min slots labeled by their END timestamp. Same formula bp-stats uses
/// for its `SlotEnd::for_time` — we don't take a dep here, the engine only
/// cares about slot equality.
fn slot_for(timestamp_ms: u64) -> u64 {
    (timestamp_ms / VARDIFF_SLOT_DURATION_MS) * VARDIFF_SLOT_DURATION_MS + VARDIFF_SLOT_DURATION_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── effective_job_difficulty (5 spec cases) ──────────────────────────

    #[test]
    fn effective_diff_returns_current_when_no_ratchet_has_happened() {
        assert_eq!(
            effective_job_difficulty(Some(42), 100.0, 100.0, None),
            100.0
        );
    }

    #[test]
    fn effective_diff_clamps_for_jobs_issued_before_an_upward_ratchet() {
        // Ratchet from 100 → 200 at jobId 50. Job 49 = pre-ratchet → 100.
        assert_eq!(
            effective_job_difficulty(Some(49), 200.0, 100.0, Some(50)),
            100.0
        );
    }

    #[test]
    fn effective_diff_uses_current_at_or_after_boundary() {
        assert_eq!(
            effective_job_difficulty(Some(50), 200.0, 100.0, Some(50)),
            200.0
        );
        assert_eq!(
            effective_job_difficulty(Some(51), 200.0, 100.0, Some(50)),
            200.0
        );
    }

    #[test]
    fn effective_diff_also_clamps_on_downward_ratchet_symmetry() {
        // ckpool stratifier.c:6204-6205 — both directions use MIN.
        // MIN(100, 200) = 100 — share at 150 on an old job accepts.
        assert_eq!(
            effective_job_difficulty(Some(49), 100.0, 200.0, Some(50)),
            100.0
        );
    }

    #[test]
    fn effective_diff_falls_back_to_current_for_unparseable_job_id() {
        assert_eq!(
            effective_job_difficulty(None, 200.0, 100.0, Some(50)),
            200.0
        );
    }

    // ── nearest_difficulty_step ────────────────────────────────────────

    fn engine_with_clock(clock: TestClock, target: f64, min: f64) -> VarDiffEngine<TestClock> {
        VarDiffEngine::new(clock, target, min)
    }

    #[test]
    fn nearest_step_returns_power_of_two_bracket() {
        let e = engine_with_clock(TestClock::new(0), 6.0, 0.00001);
        // val = 1024 is exactly a power of 2 → that exact value.
        assert_eq!(e.nearest_difficulty_step(1024.0), Some(1024.0));
        // val = 1536 (= 1024 + 512) is the "middle" point → 1536.
        assert_eq!(e.nearest_difficulty_step(1536.0), Some(1536.0));
        // val = 2000 → between 1536 and 2048; closer to 2048.
        assert_eq!(e.nearest_difficulty_step(2000.0), Some(2048.0));
        // val = 1600 → between 1536 and 2048; closer to 1536.
        assert_eq!(e.nearest_difficulty_step(1600.0), Some(1536.0));
    }

    #[test]
    fn nearest_step_zero_returns_none() {
        let e = engine_with_clock(TestClock::new(0), 6.0, 0.00001);
        assert_eq!(e.nearest_difficulty_step(0.0), None);
    }

    #[test]
    fn nearest_step_below_min_returns_min() {
        let e = engine_with_clock(TestClock::new(0), 6.0, 500.0);
        assert_eq!(e.nearest_difficulty_step(0.1), Some(500.0));
        assert_eq!(e.nearest_difficulty_step(499.9), Some(500.0));
    }

    // ── construction validates target + min ───────────────────────────

    #[test]
    fn invalid_target_shares_per_minute_falls_back_to_default() {
        let e1 = VarDiffEngine::new(TestClock::new(0), 0.0, 0.00001);
        assert_eq!(e1.target_shares_per_minute, 6.0);
        let e2 = VarDiffEngine::new(TestClock::new(0), -5.0, 0.00001);
        assert_eq!(e2.target_shares_per_minute, 6.0);
        let e3 = VarDiffEngine::new(TestClock::new(0), f64::NAN, 0.00001);
        assert_eq!(e3.target_shares_per_minute, 6.0);
    }

    #[test]
    fn invalid_min_difficulty_falls_back_to_default() {
        let e1 = VarDiffEngine::new(TestClock::new(0), 6.0, 0.0);
        assert_eq!(e1.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY);
        let e2 = VarDiffEngine::new(TestClock::new(0), 6.0, f64::NAN);
        assert_eq!(e2.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY);
        let e3 = VarDiffEngine::new(TestClock::new(0), 6.0, -1.0);
        assert_eq!(e3.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY);
    }

    #[test]
    fn valid_min_difficulty_is_honored() {
        let e = VarDiffEngine::new(TestClock::new(0), 6.0, 500.0);
        assert_eq!(e.min_difficulty, 500.0);
    }

    // ── submission cache gating ───────────────────────────────────────

    #[test]
    fn current_diff_shares_enter_the_submission_cache() {
        let mut e = VarDiffEngine::new(TestClock::new(1_000), 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        assert_eq!(e.cache_len(), 1);
    }

    #[test]
    fn stale_diff_shares_are_excluded_from_the_submission_cache() {
        let mut e = VarDiffEngine::new(TestClock::new(1_000), 6.0, 0.00001);
        e.update_hash_rate(256.0, false);
        e.update_hash_rate(256.0, false);
        e.update_hash_rate(256.0, false);
        assert_eq!(e.cache_len(), 0);
    }

    #[test]
    fn stale_diff_shares_still_update_live_hashrate_share_sum() {
        let mut e = VarDiffEngine::new(TestClock::new(1_000), 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        let cache_before = e.cache_len();
        e.update_hash_rate(256.0, false);
        e.update_hash_rate(256.0, false);
        assert_eq!(e.cache_len(), cache_before, "no cache pollution");
        assert!(
            e.current_shares() > 1024.0,
            "hashrate share-sum must advance with stale-diff shares; got {}",
            e.current_shares()
        );
    }

    // ── submission cache capacity + sliding window ────────────────────

    #[test]
    fn cache_evicts_oldest_when_capacity_reached() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Push CACHE_SIZE + 5 entries, each 1s apart so the time window
        // doesn't drop any first.
        for _ in 0..(VARDIFF_CACHE_SIZE + 5) {
            e.update_hash_rate(1.0, true);
            clock.advance_ms(1_000);
        }
        assert_eq!(e.cache_len(), VARDIFF_CACHE_SIZE);
    }

    #[test]
    fn cache_drops_entries_older_than_window() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Three early shares.
        for _ in 0..3 {
            e.update_hash_rate(1.0, true);
            clock.advance_ms(1_000);
        }
        // Jump past the cache window (300s), then add one.
        clock.advance_ms(VARDIFF_CACHE_WINDOW_MS + 60_000);
        e.update_hash_rate(1.0, true);
        // Only the most recent entry remains; the three early ones were
        // dropped by the sliding-window check (their age > 300s).
        assert_eq!(e.cache_len(), 1);
    }

    // ── suggested_difficulty: warmup + fallback formula ───────────────

    #[test]
    fn under_sampled_within_warmup_returns_none() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // 3 samples (< 5), still within warmup.
        for _ in 0..3 {
            e.update_hash_rate(1024.0, true);
            clock.advance_ms(5_000);
        }
        assert!(e.suggested_difficulty(16384.0).is_none());
    }

    #[test]
    fn under_sampled_past_warmup_returns_fallback_step() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // 1 sample, then jump past warmup.
        e.update_hash_rate(1024.0, true);
        clock.advance_ms(VARDIFF_WARMUP_MS + 1_000);
        // Fallback: nearest_difficulty_step(clientDiff / target) =
        // step(16384 / 6) ≈ step(2730.67). 2048 < 2730.67 < 3072 (middle)
        // < 4096. Distance to 2048 = 682, to 3072 = 341, to 4096 = 1365.
        // → returns 3072.
        let suggested = e.suggested_difficulty(16384.0).unwrap();
        assert_eq!(suggested, 3072.0);
    }

    // ── suggested_difficulty: 2× clamp ────────────────────────────────

    fn populate_cache(
        e: &mut VarDiffEngine<&TestClock>,
        clock: &TestClock,
        count: usize,
        diff: f64,
    ) {
        for _ in 0..count {
            e.update_hash_rate(diff, true);
            clock.advance_ms(2_000);
        }
    }

    #[test]
    fn suggested_diff_is_none_when_observed_rate_inside_two_x_clamp() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // 30 samples at diff=1024 over 60s → diff_per_sec = 30*1024/60 ≈ 512.
        // target_submission_per_second = 60/6 = 10s.
        // target = 512 * 10 = 5120. clientDiff*2=10240 > 5120 > clientDiff/2=2560 → no retarget.
        populate_cache(&mut e, &clock, 30, 1024.0);
        let suggested = e.suggested_difficulty(5120.0);
        // Inside the 2× window → None.
        assert!(
            suggested.is_none() || (suggested.unwrap() - 5120.0).abs() < 1e-6,
            "expected None (inside clamp) or exact 5120 step, got {:?}",
            suggested
        );
    }

    #[test]
    fn suggested_diff_returns_step_when_far_below_target() {
        // Run rate of 30 * 0.1 / 60s = 0.05/sec; target = 0.05*10 = 0.5.
        // clientDifficulty = 16384 — clientDifficulty/2 = 8192 ≫ 0.5 → retarget.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        // step(0.5) — between 0.5 and 1.0 — bracket: lower=0.5, middle=0.75,
        // upper=1.0. Distance to 0.5 = 0, → 0.5.
        assert_eq!(suggested, 0.5);
    }

    #[test]
    fn suggested_diff_respects_configured_floor() {
        // Same low rate but a 500.0 floor → suggestion clamps to 500.0.
        // Verifies the "respects configured floor" behavior.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 500.0);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested >= 500.0, "got {}", suggested);
        assert_eq!(suggested, 500.0);
    }

    #[test]
    fn suggested_diff_without_floor_can_drop_below_one() {
        // Without a configured floor, suggestion can drop well below 500.
        // With min=default (0.00001), target=0.5 → returns 0.5.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested < 1.0, "got {}", suggested);
    }

    #[test]
    fn suggested_diff_zero_floor_falls_back_to_default() {
        // A floor of 0 falls back to the built-in default.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.0);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested < 1.0, "got {}", suggested);
    }

    #[test]
    fn suggested_diff_nan_floor_falls_back_to_default() {
        // A non-finite floor is rejected and the built-in default is used.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, f64::NAN);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested < 1.0, "got {}", suggested);
    }

    // ── hashrate accumulation ─────────────────────────────────────────

    #[test]
    fn hash_rate_is_zero_before_any_share() {
        let e: VarDiffEngine<TestClock> = VarDiffEngine::new(TestClock::new(0), 6.0, 0.00001);
        assert_eq!(e.hash_rate(), 0.0);
    }

    #[test]
    fn first_share_initializes_slot_but_keeps_hash_rate_zero() {
        // The first share sets `shares` but the hashrate computation only
        // kicks in on the SAME-SLOT accumulation branch, so hash_rate stays
        // 0 until the second share arrives.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        assert_eq!(e.hash_rate(), 0.0);
        assert_eq!(e.current_shares(), 1024.0);
    }

    #[test]
    fn second_same_slot_share_computes_hashrate() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        clock.advance_ms(1_000); // 1s later, same 10-min slot
        e.update_hash_rate(2048.0, true);
        // shares = 3072, prev = 0, elapsed = 1s.
        // hashrate = 3072 * 2^32 / 1 ≈ 1.32e13.
        let expected = 3072.0 * VARDIFF_DIFFICULTY_1 / 1.0;
        assert!(
            (e.hash_rate() - expected).abs() < 1.0,
            "expected ≈ {}, got {}",
            expected,
            e.hash_rate()
        );
    }

    #[test]
    fn crossing_slot_boundary_rotates_share_buckets() {
        let clock = TestClock::new(0);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Two shares in slot A.
        e.update_hash_rate(1024.0, true);
        clock.advance_ms(1_000);
        e.update_hash_rate(2048.0, true);
        assert_eq!(e.current_shares(), 3072.0);

        // Jump across a slot boundary (10 min).
        clock.advance_ms(VARDIFF_SLOT_DURATION_MS);
        e.update_hash_rate(512.0, true);
        // prev_shares = 3072 (from slot A), shares = 512 (slot B fresh).
        assert_eq!(e.current_shares(), 512.0);
    }
}
