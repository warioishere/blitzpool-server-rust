// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session VarDiff engine and race-window clamp, shared by SV1 and SV2.
//!
//! One estimator drives every retarget. Arrivals are counted against the
//! window's *exposure* `S = ∫dt/D(t)`, the share count a miner producing one
//! difficulty unit per second would have reached, so `r = arrivals / S` is
//! the rate in difficulty per second whatever difficulties the window spans.
//! The window always ends at *now*, so silence lowers the estimate by itself.
//! A window with fewer than [`VARDIFF_MIN_SHARES`] arrivals cannot measure a
//! rate, only bound it from above, and therefore only ever lowers the
//! difficulty. An assignment acted on a measured window starts a new one; a
//! thinner window carries over. A window's first arrival opens it and carries
//! no weight, dropping the silence before it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bp_common::HASHES_PER_DIFFICULTY_1;

// ── Constants ────────────────────────────────────────────────────────

/// Default vardiff floor when the caller passes a non-finite / non-positive
/// `min_difficulty`.
pub const VARDIFF_DEFAULT_MIN_DIFFICULTY: f64 = 0.00001;

/// Display-hashrate slot length (10 minutes).
pub const VARDIFF_SLOT_DURATION_MS: u64 = 600_000;

/// Default `target_shares_per_minute` fallback for misconfigured ports.
pub const VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN: f64 = 6.0;

/// Shortest window a retarget is decided on. It is measured in time, not in
/// shares, so neither two shares a millisecond apart nor a flood packing
/// thousands into one millisecond can collapse it.
pub const VARDIFF_MIN_WINDOW_MS: u64 = 60_000;

/// Arrivals a window needs before its rate counts as measured. Below this the
/// window only bounds the rate from above.
pub const VARDIFF_MIN_SHARES: u32 = 4;

/// Length of one window bucket. The window holds the current bucket and the
/// one before it, so a steady session decides on the last 5 to 10 minutes.
pub const VARDIFF_BUCKET_MS: u64 = 300_000;

/// Confidence constant `k = ln(1/α)` of the upper bound (3.0 is α = 5 %).
/// Zero arrivals over exposure `S` have probability `e^(-r·S)`, so
/// `r ≤ k / S`; with `n` arrivals the bound is taken as `(n + k) / S`,
/// within one power-of-two rung of the exact Poisson limit for `n < 4`.
pub const VARDIFF_CONFIDENCE_K: f64 = 3.0;

/// Cap on a single upward retarget, so a burst-inflated window (a JDC
/// flushing optimistic-mining shares) is measured once more before it is
/// trusted.
pub const VARDIFF_MAX_UP_STEP_FACTOR: f64 = 8.0;

/// Descent floor below the last difficulty the session sustained with a
/// measured window. A session that is gone rather than slow parks here,
/// bounding its share flood on return to 16× target rate.
pub const VARDIFF_SILENCE_MAX_DESCENT_FACTOR: f64 = 16.0;

/// Descent floor below the highest difficulty ever assigned, for a session
/// that has never sustained one. It only has to get the miner from *never*
/// to *occasionally*; looser costs a bigger flood when an idle session
/// returns at full power.
pub const VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR: f64 = 256.0;

// ── Clock ────────────────────────────────────────────────────────────

/// Injectable millisecond clock; tests use [`TestClock`]. Separate from
/// `bp_cron_utils::Clock`, which needs calendar time for aligned scheduling.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// Wall clock. The engine only uses differences; a backwards step drops the
/// retarget window (see [`VarDiffEngine::note_difficulty_assigned`]).
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

/// Deterministic clock for tests; atomic so it can be shared by reference.
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

/// Round a positive, finite difficulty UP to a power of two (callers guard
/// the rest). Powers of two because a translating proxy rounds to one for
/// SV1, so any other value books less than the miner works; upward because
/// a downstream that sent `UpdateChannel` ignores a lower one as an error.
pub fn round_up_to_power_of_two(val: f64) -> f64 {
    let lower = 2_f64.powf(val.log2().floor());
    // Tolerance keeps a power of two with floating-point dust on its rung.
    if val <= lower * (1.0 + 1e-9) {
        lower
    } else {
        lower * 2.0
    }
}

/// Per-job difficulty clamp: firmware applies a raised target only on the
/// next job, so in-flight shares are validated at the old one. The result
/// drives BOTH validation and all accounting, so a share is never credited
/// above the difficulty it was mined at.
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

/// One stretch of the retarget window.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    start_ms: u64,
    /// Arrivals, each weighted by its credited difficulty over the one in
    /// force, so a share validated at an older, lower difficulty counts for
    /// the work it carries.
    arrivals: f64,
    /// Unweighted arrival count including the window's opening arrival, for
    /// the [`VARDIFF_MIN_SHARES`] test.
    shares: u32,
    /// Closed exposure in seconds per difficulty unit.
    exposure: f64,
}

impl Bucket {
    fn empty(start_ms: u64) -> Self {
        Self {
            start_ms,
            arrivals: 0.0,
            shares: 0,
            exposure: 0.0,
        }
    }
}

/// The whole window as of one instant.
#[derive(Clone, Copy, Debug)]
struct Window {
    span_ms: u64,
    arrivals: f64,
    shares: u32,
    exposure: f64,
}

/// Per-session VarDiff state machine plus the display-hashrate accumulator.
/// The display hashrate never feeds a retarget.
pub struct VarDiffEngine<C: Clock> {
    clock: C,

    // Config
    target_share_interval_s: f64,
    min_difficulty: f64,

    // Retarget window. `difficulty` is the one in force since
    // `segment_start_ms`; the open segment's exposure is added at read time.
    difficulty: f64,
    segment_start_ms: u64,
    previous: Option<Bucket>,
    current: Bucket,

    // Descent anchors: the difficulty the last measured window was gathered
    // at, and the highest one ever assigned.
    sustained: Option<f64>,
    highest_assigned: f64,
    // What the window dropped at the last assignment measured, `None` if it
    // was too thin to measure. The up-step cap lifts only when it agrees.
    previous_measurement: Option<f64>,
    accepted_any: bool,
    // Whether the miner was ever given work. Without it there is nothing to
    // measure: no retarget and no silence evidence.
    has_work: bool,

    // Display hashrate, by 10-minute slot.
    hash_rate: f64,
    current_slot: Option<u64>,
    previous_slot_time_ms: u64,
    current_slot_time_ms: u64,
    previous_shares: f64,
    shares: f64,
}

impl<C: Clock> VarDiffEngine<C> {
    /// Construct with a clock, per-port config and the difficulty the session
    /// opens with. `target_shares_per_minute` ≤ 0 falls back to
    /// [`VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN`]; a non-finite / non-positive
    /// `min_difficulty` falls back to [`VARDIFF_DEFAULT_MIN_DIFFICULTY`], and
    /// such an `initial_difficulty` to the floor.
    pub fn new(
        clock: C,
        target_shares_per_minute: f64,
        min_difficulty: f64,
        initial_difficulty: f64,
    ) -> Self {
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
        let difficulty = if initial_difficulty.is_finite() && initial_difficulty > 0.0 {
            initial_difficulty
        } else {
            min_difficulty
        };
        let now = clock.now_ms();
        Self {
            clock,
            target_share_interval_s: 60.0 / target,
            min_difficulty,
            difficulty,
            segment_start_ms: now,
            previous: None,
            current: Bucket::empty(now),
            sustained: None,
            highest_assigned: difficulty,
            previous_measurement: None,
            accepted_any: false,
            has_work: false,
            hash_rate: 0.0,
            current_slot: None,
            previous_slot_time_ms: 0,
            current_slot_time_ms: 0,
            previous_shares: 0.0,
            shares: 0.0,
        }
    }

    /// Report a difficulty assignment by ANY route. A window that holds a
    /// measurement is spent once acted on, and dropping it is what lets the
    /// up-step cap bound a burst; what it measured is kept for the cap. A
    /// thinner window carries over: its evidence is all there is, and exposure
    /// already weighs it at the difficulty it was gathered at.
    ///
    /// Every entry point first drops the window if the clock stepped back
    /// past it, since arrivals would otherwise pile up against exposure that
    /// cannot grow until the clock catches up.
    pub fn note_difficulty_assigned(&mut self, difficulty: f64) {
        if !(difficulty.is_finite() && difficulty > 0.0) {
            return;
        }
        let now = self.clock.now_ms();
        self.drop_window_if_clock_stepped_back(now);
        self.close_segment(now);
        let window = self.window(now);
        // Only a window long enough to decide on counts as a measurement.
        self.previous_measurement = (window.shares >= VARDIFF_MIN_SHARES
            && window.span_ms >= VARDIFF_MIN_WINDOW_MS)
            .then(|| window.arrivals / window.exposure * self.target_share_interval_s);
        if window.shares >= VARDIFF_MIN_SHARES {
            self.start_window(now);
        }
        self.difficulty = difficulty;
        self.highest_assigned = self.highest_assigned.max(difficulty);
    }

    /// Report that the miner has work to mine. Until the first report the
    /// engine proposes nothing and gathers no silence; the first one starts
    /// the window, so time spent without work (no template yet, no payouts to
    /// build a job from) never reads as a miner that went quiet. Later reports
    /// change nothing.
    pub fn note_work_available(&mut self) {
        if !self.has_work {
            self.has_work = true;
            self.start_window(self.clock.now_ms());
        }
    }

    /// Record an accepted share at its credited (post-clamp) difficulty.
    pub fn note_share_accepted(&mut self, credited_difficulty: f64) {
        let now = self.clock.now_ms();
        self.accepted_any = true;
        self.record_arrival(now, credited_difficulty);
        self.record_display(now, credited_difficulty);
    }

    /// A share refused as stale, before it was hashed, after the duplicate
    /// check: the miner sent it as meeting the target on a job it was given,
    /// so it is an arrival at the difficulty in force, credited nowhere. An
    /// unknown-job share must NOT come here, since SV2 rejects it before any
    /// duplicate check and a resent one would inflate the rate; nor a
    /// duplicate or a below-target reject.
    pub fn note_stale_share(&mut self) {
        let now = self.clock.now_ms();
        self.record_arrival(now, self.difficulty);
    }

    /// Latest display hashrate in hashes/second; `0.0` until two shares
    /// landed in one slot.
    pub fn hash_rate(&self) -> f64 {
        self.hash_rate
    }

    /// Arrivals in the retarget window, for tests and diagnostics.
    pub fn window_shares(&self) -> u32 {
        self.previous.map_or(0, |b| b.shares) + self.current.shares
    }

    /// Highest difficulty the window's evidence is consistent with, or `None`
    /// before any work, once a share was accepted, or while the window is too
    /// short or already measured. Lets a caller weigh a declared hashrate against observation:
    /// "no share yet" alone is normal for a fresh proxy channel; a long
    /// silence that rules the number out is not.
    pub fn silence_implied_max_difficulty(&self) -> Option<f64> {
        if self.accepted_any || !self.has_work {
            return None;
        }
        let window = self.window(self.clock.now_ms());
        if window.span_ms < VARDIFF_MIN_WINDOW_MS || window.shares >= VARDIFF_MIN_SHARES {
            return None;
        }
        self.upper_bound_difficulty(&window)
    }

    /// Next difficulty for the session, or `None` for no retarget. A result is
    /// a power of two or `min_difficulty`, never NaN or infinite.
    pub fn suggested_difficulty(&self, client_difficulty: f64) -> Option<f64> {
        if !self.has_work {
            return None;
        }
        let window = self.window(self.clock.now_ms());
        if window.span_ms < VARDIFF_MIN_WINDOW_MS {
            return None;
        }
        if window.shares < VARDIFF_MIN_SHARES {
            // Too few arrivals to measure; the bound can only argue for less.
            let candidate = self.nearest_difficulty_step(self.upper_bound_difficulty(&window)?)?;
            return (candidate < client_difficulty).then_some(candidate);
        }
        let measured = window.arrivals / window.exposure * self.target_share_interval_s;
        let target = self.cap_up_step(measured.max(self.descent_floor()), client_difficulty);
        if !target.is_finite() {
            return None;
        }
        // 2× deadband.
        if client_difficulty * 2.0 < target || client_difficulty / 2.0 > target {
            return self.nearest_difficulty_step(target);
        }
        None
    }

    fn record_arrival(&mut self, now: u64, credited_difficulty: f64) {
        // A share is only ever mined on work.
        self.has_work = true;
        self.drop_window_if_clock_stepped_back(now);
        if self.window_shares() == 0 {
            // The first arrival opens a fresh window and carries no weight:
            // its work was done before the window began, and dropping the
            // silence before it keeps a miner that only just started from
            // being measured against time it may not have been mining.
            self.start_window(now);
            self.current.shares = 1;
            return;
        }
        self.current.arrivals += credited_difficulty / self.difficulty;
        self.current.shares += 1;
        if now.saturating_sub(self.current.start_ms) >= VARDIFF_BUCKET_MS {
            // The arrival closes the bucket it was mined in. A bucket too thin
            // to measure on its own absorbs the one before it instead of
            // replacing it, so a miner slower than one share per bucket still
            // gathers a measurement.
            self.close_segment(now);
            let closed = self.current;
            self.previous = Some(match self.previous {
                Some(older) if closed.shares < VARDIFF_MIN_SHARES => Bucket {
                    start_ms: older.start_ms,
                    arrivals: older.arrivals + closed.arrivals,
                    shares: older.shares + closed.shares,
                    exposure: older.exposure + closed.exposure,
                },
                _ => closed,
            });
            self.current = Bucket::empty(now);
        }
        if self.window_shares() >= VARDIFF_MIN_SHARES {
            self.sustained = Some(self.difficulty);
        }
    }

    fn drop_window_if_clock_stepped_back(&mut self, now: u64) {
        if now < self.segment_start_ms {
            self.start_window(now);
        }
    }

    /// Drop the window and start an empty one at `now`.
    fn start_window(&mut self, now: u64) {
        self.previous = None;
        self.current = Bucket::empty(now);
        self.segment_start_ms = now;
    }

    /// Fold the open segment's exposure into the current bucket and restart
    /// it at `now`.
    fn close_segment(&mut self, now: u64) {
        self.current.exposure += self.open_exposure(now);
        self.segment_start_ms = now;
    }

    fn open_exposure(&self, now: u64) -> f64 {
        (now.saturating_sub(self.segment_start_ms) as f64 / 1000.0) / self.difficulty
    }

    fn window(&self, now: u64) -> Window {
        let current = Window {
            span_ms: now.saturating_sub(self.current.start_ms),
            arrivals: self.current.arrivals,
            shares: self.current.shares,
            exposure: self.current.exposure + self.open_exposure(now),
        };
        match self.previous {
            None => current,
            Some(previous) => Window {
                span_ms: now.saturating_sub(previous.start_ms),
                arrivals: previous.arrivals + current.arrivals,
                shares: previous.shares + current.shares,
                exposure: previous.exposure + current.exposure,
            },
        }
    }

    /// The upper-bound difficulty `(n + k) / S · τ` (see
    /// [`VARDIFF_CONFIDENCE_K`]), floored by [`Self::descent_floor`]; `None`
    /// if it overflows.
    fn upper_bound_difficulty(&self, window: &Window) -> Option<f64> {
        let raw = (window.arrivals + VARDIFF_CONFIDENCE_K) / window.exposure
            * self.target_share_interval_s;
        raw.is_finite().then(|| raw.max(self.descent_floor()))
    }

    /// Lowest difficulty a descent may reach. A LOWER bound, so the
    /// power-of-two round-up that follows cannot violate it.
    fn descent_floor(&self) -> f64 {
        match self.sustained {
            Some(sustained) => sustained / VARDIFF_SILENCE_MAX_DESCENT_FACTOR,
            None => self.highest_assigned / VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR,
        }
    }

    /// Cap an upward retarget at [`VARDIFF_MAX_UP_STEP_FACTOR`] × current,
    /// snapped down to a power of two because the rounding that follows goes
    /// UP. The cap lifts when the window dropped at the last assignment
    /// measured past it too: two windows in a row agreeing is a proven jump
    /// (a proxy attaching a farm), not a burst, and must not be rationed at
    /// 8× per interval.
    fn cap_up_step(&self, target: f64, client_difficulty: f64) -> f64 {
        let cap = client_difficulty * VARDIFF_MAX_UP_STEP_FACTOR;
        if !(cap.is_finite() && cap > 0.0) {
            return target;
        }
        // Largest rung not exceeding the cap; `nearest_difficulty_step` leaves
        // an exact power of two alone, so the result stays capped.
        let capped_rung = 2_f64.powf(cap.log2().floor());
        if self.previous_measurement.is_some_and(|m| m >= capped_rung) {
            target
        } else {
            target.min(capped_rung)
        }
    }

    /// Round UP to a power of two, floored at `min_difficulty`; `None` for 0.
    fn nearest_difficulty_step(&self, val: f64) -> Option<f64> {
        if val == 0.0 {
            return None;
        }
        if val < self.min_difficulty {
            return Some(self.min_difficulty);
        }
        Some(round_up_to_power_of_two(val))
    }

    fn record_display(&mut self, now: u64, credited_difficulty: f64) {
        let slot = slot_for(now);
        match self.current_slot {
            None => {
                self.previous_slot_time_ms = now;
                self.current_slot_time_ms = now;
                self.current_slot = Some(slot);
                self.shares = credited_difficulty;
            }
            Some(s) if s != slot => {
                self.previous_shares = self.shares;
                self.previous_slot_time_ms = self.current_slot_time_ms;
                self.current_slot_time_ms = now;
                self.current_slot = Some(slot);
                self.shares = credited_difficulty;
                // Recompute across the gap, so the first share after a silence
                // does not quote the pre-silence rate.
                let elapsed_ms = now.saturating_sub(self.previous_slot_time_ms);
                let work = self.previous_shares + self.shares;
                if elapsed_ms > 0 && work > 0.0 {
                    self.hash_rate = slot_hashrate(work, elapsed_ms);
                }
            }
            Some(_) => {
                self.shares += credited_difficulty;
                let elapsed_ms = now.saturating_sub(self.previous_slot_time_ms);
                if self.shares > 0.0 && elapsed_ms > 0 {
                    self.hash_rate = slot_hashrate(self.previous_shares + self.shares, elapsed_ms);
                }
            }
        }
    }
}

/// 10-min slots labeled by their END timestamp.
fn slot_for(timestamp_ms: u64) -> u64 {
    (timestamp_ms / VARDIFF_SLOT_DURATION_MS) * VARDIFF_SLOT_DURATION_MS + VARDIFF_SLOT_DURATION_MS
}

/// Hashes/second from credited difficulty over a span; 0.0 for a zero span.
fn slot_hashrate(work: f64, span_ms: u64) -> f64 {
    if span_ms == 0 {
        return 0.0;
    }
    work * HASHES_PER_DIFFICULTY_1 / (span_ms as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── effective_job_difficulty ─────────────────────────────────────────

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
        // Both directions use MIN.
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

    // ── helpers ──────────────────────────────────────────────────────────

    /// A 6 shares/min engine (target gap 10 s) opening at `initial`, with
    /// work from the start.
    fn engine(clock: &TestClock, initial: f64) -> VarDiffEngine<&TestClock> {
        let mut e = VarDiffEngine::new(clock, 6.0, 0.00001, initial);
        e.note_work_available();
        e
    }

    /// One closed-loop cycle: tick, ask, APPLY and report the proposal.
    fn cycle(
        e: &mut VarDiffEngine<&TestClock>,
        clock: &TestClock,
        tick_ms: u64,
        diff: &mut f64,
    ) -> bool {
        clock.advance_ms(tick_ms);
        match e.suggested_difficulty(*diff) {
            Some(next) => {
                *diff = next;
                e.note_difficulty_assigned(next);
                true
            }
            None => false,
        }
    }

    /// 30 shares at 1024, 10 s apart: an on-target session at 1024.
    fn fill_equilibrium(e: &mut VarDiffEngine<&TestClock>, clock: &TestClock) {
        for _ in 0..30 {
            clock.advance_ms(10_000);
            e.note_share_accepted(1024.0);
        }
    }

    /// Deterministic miner of `rate` difficulty/s for `duration_ms`, at the
    /// difficulty in force, at most `max_per_s` shares per second, with a
    /// vardiff check every `tick_ms` whose proposal is applied. Returns every
    /// difficulty assigned.
    fn mine_closed_loop(
        e: &mut VarDiffEngine<&TestClock>,
        clock: &TestClock,
        diff: &mut f64,
        rate: f64,
        max_per_s: f64,
        duration_ms: u64,
        tick_ms: u64,
    ) -> Vec<f64> {
        let mut assigned = Vec::new();
        let mut owed = 0.0;
        let end = clock.now_ms() + duration_ms;
        while clock.now_ms() < end {
            clock.advance_ms(1_000);
            owed += (rate / *diff).min(max_per_s);
            while owed >= 1.0 {
                e.note_share_accepted(*diff);
                owed -= 1.0;
            }
            if clock.now_ms().is_multiple_of(tick_ms) {
                if let Some(next) = e.suggested_difficulty(*diff) {
                    *diff = next;
                    e.note_difficulty_assigned(next);
                    assigned.push(next);
                }
            }
        }
        assigned
    }

    // ── nearest_difficulty_step ────────────────────────────────────────

    /// Pins: every rung is a power of two, rounded up.
    #[test]
    fn nearest_step_returns_only_powers_of_two() {
        let clock = TestClock::new(0);
        let e = engine(&clock, 1.0);
        assert_eq!(e.nearest_difficulty_step(1024.0), Some(1024.0));
        assert_eq!(e.nearest_difficulty_step(2048.0), Some(2048.0));
        // No 1.5x rung, and always UP.
        assert_eq!(e.nearest_difficulty_step(1536.0), Some(2048.0));
        assert_eq!(e.nearest_difficulty_step(1100.0), Some(2048.0));
        assert_eq!(e.nearest_difficulty_step(2000.0), Some(2048.0));

        for probe in [3.0, 100.0, 950.3, 2887.8, 5000.0, 1e6] {
            let step = e.nearest_difficulty_step(probe).expect("a rung");
            assert_eq!(
                step,
                2_f64.powf(step.log2().round()),
                "step {step} for {probe} is not a power of two"
            );
            assert!(step >= probe, "step {step} is below the requested {probe}");
            assert!(step < probe * 2.0, "step {step} overshoots {probe}");
        }
    }

    #[test]
    fn nearest_step_zero_returns_none() {
        let clock = TestClock::new(0);
        assert_eq!(engine(&clock, 1.0).nearest_difficulty_step(0.0), None);
    }

    #[test]
    fn nearest_step_below_min_returns_min() {
        let clock = TestClock::new(0);
        let e = VarDiffEngine::new(&clock, 6.0, 500.0, 1024.0);
        assert_eq!(e.nearest_difficulty_step(0.1), Some(500.0));
        assert_eq!(e.nearest_difficulty_step(499.9), Some(500.0));
    }

    // ── construction validates its inputs ─────────────────────────────

    #[test]
    fn invalid_target_shares_per_minute_falls_back_to_default() {
        // Default 6 shares/min → a 10 s target gap.
        for bad in [0.0, -5.0, f64::NAN] {
            let e = VarDiffEngine::new(TestClock::new(0), bad, 0.00001, 1.0);
            assert_eq!(e.target_share_interval_s, 10.0, "target {bad}");
        }
    }

    #[test]
    fn invalid_min_difficulty_falls_back_to_default() {
        for bad in [0.0, f64::NAN, -1.0] {
            let e = VarDiffEngine::new(TestClock::new(0), 6.0, bad, 1.0);
            assert_eq!(
                e.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY,
                "min {bad}"
            );
        }
        let e = VarDiffEngine::new(TestClock::new(0), 6.0, 500.0, 1024.0);
        assert_eq!(e.min_difficulty, 500.0);
    }

    #[test]
    fn invalid_initial_difficulty_falls_back_to_the_floor() {
        for bad in [0.0, f64::NAN, -1.0, f64::INFINITY] {
            let e = VarDiffEngine::new(TestClock::new(0), 6.0, 500.0, bad);
            assert_eq!(e.difficulty, 500.0, "initial {bad}");
        }
    }

    // ── display hashrate ──────────────────────────────────────────────

    #[test]
    fn hash_rate_is_zero_before_any_share() {
        let clock = TestClock::new(0);
        assert_eq!(engine(&clock, 1024.0).hash_rate(), 0.0);
    }

    #[test]
    fn first_share_initializes_slot_but_keeps_hash_rate_zero() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1024.0);
        e.note_share_accepted(1024.0);
        assert_eq!(e.hash_rate(), 0.0);
        assert_eq!(e.shares, 1024.0);
    }

    #[test]
    fn second_same_slot_share_computes_hashrate() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1024.0);
        e.note_share_accepted(1024.0);
        clock.advance_ms(1_000); // same 10-min slot
        e.note_share_accepted(2048.0);
        let expected = 3072.0 * HASHES_PER_DIFFICULTY_1 / 1.0;
        assert!(
            (e.hash_rate() - expected).abs() < 1.0,
            "expected ≈ {expected}, got {}",
            e.hash_rate()
        );
    }

    #[test]
    fn crossing_slot_boundary_rotates_share_buckets() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1024.0);
        e.note_share_accepted(1024.0);
        clock.advance_ms(1_000);
        e.note_share_accepted(2048.0);
        assert_eq!(e.shares, 3072.0);
        clock.advance_ms(VARDIFF_SLOT_DURATION_MS);
        e.note_share_accepted(512.0);
        assert_eq!(e.previous_shares, 3072.0);
        assert_eq!(e.shares, 512.0);
    }

    /// The first share after a silent slot recomputes over the gap instead
    /// of quoting the pre-silence rate.
    #[test]
    fn the_first_share_after_a_silent_slot_recomputes_the_display_rate() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1024.0);
        e.note_share_accepted(1024.0);
        clock.advance_ms(1_000);
        e.note_share_accepted(2048.0);
        let busy = e.hash_rate();
        clock.advance_ms(3_600_000);
        e.note_share_accepted(512.0);
        let expected = 3584.0 * HASHES_PER_DIFFICULTY_1 / 3601.0;
        assert!(
            (e.hash_rate() - expected).abs() < 1.0,
            "expected ≈ {expected}, got {} (busy rate was {busy})",
            e.hash_rate()
        );
    }

    // ── the window ────────────────────────────────────────────────────

    /// Nothing is decided on less than a minute of evidence.
    #[test]
    fn no_retarget_inside_the_minimum_window() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1.0);
        // One share per second at difficulty 1: ten times the target rate.
        e.note_share_accepted(1.0); // opens the window at t = 0
        for _ in 0..59 {
            clock.advance_ms(1_000);
            e.note_share_accepted(1.0);
        }
        assert_eq!(e.suggested_difficulty(1.0), None, "59 s is not a window");
        clock.advance_ms(1_000);
        e.note_share_accepted(1.0);
        assert!(
            e.suggested_difficulty(1.0).is_some_and(|d| d > 1.0),
            "60 s of 10× the target rate must raise"
        );
    }

    /// Pins the measurement on an on-target session: it holds.
    #[test]
    fn an_on_target_session_holds() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1024.0);
        fill_equilibrium(&mut e, &clock);
        assert_eq!(e.suggested_difficulty(1024.0), None);
    }

    /// Two shares close together cannot raise the difficulty, however close:
    /// two arrivals are below [`VARDIFF_MIN_SHARES`], so they only bound the
    /// rate from above.
    #[test]
    fn two_close_shares_cannot_raise_the_difficulty() {
        for gap_ms in [1u64, 200, 500, 5_000, 30_000] {
            let clock = TestClock::new(0);
            let mut e = engine(&clock, 1024.0);
            clock.advance_ms(61_000);
            e.note_share_accepted(1024.0);
            clock.advance_ms(gap_ms);
            e.note_share_accepted(1024.0);
            for wait_ms in [0u64, 1_000, 60_000] {
                clock.advance_ms(wait_ms);
                let proposed = e.suggested_difficulty(1024.0);
                assert!(
                    proposed.is_none_or(|p| p < 1024.0),
                    "gap {gap_ms} ms, +{wait_ms} ms: proposed {proposed:?} from 1024"
                );
            }
        }
    }

    /// A flood packing dozens of shares into each millisecond still has a
    /// span: the window is measured in time, not in shares.
    #[test]
    fn a_flood_in_millisecond_clumps_still_retargets() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1.0);
        for _ in 0..=61 {
            for _ in 0..40 {
                e.note_share_accepted(1.0); // 40 shares in the same millisecond
            }
            clock.advance_ms(1_000);
        }
        // 2440 credited arrivals over ~61 s at difficulty 1 → target ≈ 400,
        // capped on the first raise at 8×.
        assert_eq!(e.suggested_difficulty(1.0), Some(8.0));
        e.note_difficulty_assigned(8.0);
        for _ in 0..=61 {
            for _ in 0..40 {
                e.note_share_accepted(8.0);
            }
            clock.advance_ms(1_000);
        }
        // The proving interval is spent: the measured 3200 goes through.
        assert_eq!(e.suggested_difficulty(8.0), Some(4096.0));
    }

    /// A 1 PH/s channel that opened at difficulty 1 reaches its equilibrium
    /// rung, without overshooting it, while the pool can only process a
    /// fraction of its share flood.
    #[test]
    fn a_petahash_channel_opened_at_difficulty_one_converges() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1.0);
        let mut diff = 1.0;
        let rate = 1e15 / HASHES_PER_DIFFICULTY_1;
        let equilibrium = rate * 10.0; // ≈ 2.33e6
        let assigned = mine_closed_loop(&mut e, &clock, &mut diff, rate, 2_000.0, 480_000, 60_000);
        assert!(
            assigned.iter().all(|d| *d <= 2.0 * equilibrium),
            "overshot the equilibrium {equilibrium}: {assigned:?}"
        );
        assert!(
            (equilibrium / 2.0..=2.0 * equilibrium).contains(&diff),
            "did not converge within 8 minutes: {assigned:?}"
        );
    }

    /// A window with fewer than [`VARDIFF_MIN_SHARES`] arrivals is too thin
    /// for a point estimate: one share in its first minute reads an on-target
    /// miner as six times too slow. It may only lower to its upper bound.
    #[test]
    fn a_thin_window_cannot_drive_a_descent_below_its_upper_bound() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1024.0);
        clock.advance_ms(5_000);
        e.note_share_accepted(1024.0); // opens the window
        clock.advance_ms(30_000);
        e.note_share_accepted(1024.0); // an unlucky first minute: one more
        clock.advance_ms(30_000);
        assert_eq!(
            e.suggested_difficulty(1024.0),
            None,
            "one arrival in a minute must not lower an on-target 1024 session"
        );
    }

    /// The window holds the last 5 to 10 minutes, not the whole session, so
    /// a session that ran for hours still answers a real slowdown promptly.
    #[test]
    fn a_long_running_session_follows_a_slowdown_promptly() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1024.0);
        let mut diff = 1024.0;
        let steady = mine_closed_loop(&mut e, &clock, &mut diff, 102.4, 1e9, 3 * 3_600_000, 60_000);
        assert!(
            steady.is_empty(),
            "precondition: three steady hours hold: {steady:?}"
        );
        // The rig drops to a quarter of its rate for good.
        let after = mine_closed_loop(&mut e, &clock, &mut diff, 25.6, 1e9, 20 * 60_000, 60_000);
        assert!(
            diff <= 512.0,
            "still at {diff} 20 minutes into a 4× slowdown: {after:?}"
        );
    }

    // ── scenarios the engine must survive ─────────────────────────────

    /// The wall clock steps back an hour under a steady session. Arrivals
    /// must not pile up against exposure frozen until the clock catches up:
    /// the session stays within a rung of its equilibrium throughout.
    #[test]
    fn a_backwards_clock_step_cannot_raise_a_steady_session() {
        let clock = TestClock::new(10_000_000);
        let mut e = engine(&clock, 1024.0);
        let mut diff = 1024.0;
        let steady = mine_closed_loop(&mut e, &clock, &mut diff, 102.4, 1e9, 1_800_000, 60_000);
        assert!(
            steady.is_empty(),
            "precondition: on target holds: {steady:?}"
        );
        clock.set_ms(clock.now_ms() - 3_600_000);
        let after = mine_closed_loop(&mut e, &clock, &mut diff, 102.4, 1e9, 7_200_000, 60_000);
        assert!(
            after.iter().all(|d| *d <= 2048.0) && (512.0..=2048.0).contains(&diff),
            "a clock step moved an on-target 1024 session: {after:?}"
        );
    }

    /// A rig that keeps only 1/3000 of its rate shares so rarely at the
    /// 16× floor that no single bucket holds a measurement. The window keeps
    /// gathering until it does, so the session reaches its new equilibrium
    /// instead of parking at the floor.
    #[test]
    fn a_three_thousandfold_slowdown_reaches_the_new_equilibrium() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1_048_576.0);
        let mut diff = 1_048_576.0;
        let full = 104_857.6;
        let steady = mine_closed_loop(&mut e, &clock, &mut diff, full, 1e9, 3_600_000, 60_000);
        assert!(
            steady.is_empty(),
            "precondition: on target holds: {steady:?}"
        );
        let equilibrium = 1_048_576.0 / 3000.0; // ≈ 350
        let after = mine_closed_loop(
            &mut e,
            &clock,
            &mut diff,
            full / 3000.0,
            1e9,
            6 * 3_600_000,
            60_000,
        );
        assert!(
            (equilibrium / 2.0..=2.0 * equilibrium).contains(&diff),
            "parked at {diff} six hours into the slowdown, equilibrium {equilibrium}: {after:?}"
        );
        assert!(
            after.windows(2).all(|w| w[1] <= w[0]),
            "a slowdown must only ever lower: {after:?}"
        );
    }

    /// A raise from outside (`UpdateChannel`, `mining.suggest_difficulty`) is
    /// no measurement, so it does not lift the up-step cap: a flush right
    /// after it is capped like any other.
    #[test]
    fn an_external_raise_does_not_lift_the_cap_for_a_burst() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 2.0);
        let mut diff = 2.0;
        // True rate 0.4 difficulty/s: equilibrium 4. Measured at 2 first.
        let _ = mine_closed_loop(&mut e, &clock, &mut diff, 0.4, 1e9, 600_000, 60_000);
        e.note_difficulty_assigned(4.0); // the external raise
        diff = 4.0;
        clock.advance_ms(5_000);
        for _ in 0..300 {
            e.note_share_accepted(4.0); // the flush, in one millisecond
        }
        let assigned = mine_closed_loop(&mut e, &clock, &mut diff, 0.4, 1e9, 1_800_000, 60_000);
        assert!(
            assigned.iter().all(|d| *d <= 32.0),
            "a flush after an external raise went past 8×: {assigned:?}"
        );
    }

    /// A burst followed within the same millisecond by an external raise
    /// leaves a window with shares but no span: no measurement, so it cannot
    /// lift the cap for the next burst.
    #[test]
    fn a_window_without_span_is_no_measurement_for_the_cap() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 4.0);
        clock.advance_ms(10_000);
        for _ in 0..300 {
            e.note_share_accepted(4.0);
        }
        e.note_difficulty_assigned(8.0); // e.g. UpdateChannel, same millisecond
        clock.advance_ms(1_000);
        for _ in 0..300 {
            e.note_share_accepted(8.0); // a second flush
        }
        clock.advance_ms(60_000);
        let proposed = e
            .suggested_difficulty(8.0)
            .expect("a flushed window must raise");
        assert!(
            proposed <= 64.0,
            "the second flush went past 8×: {proposed}"
        );
    }

    /// A miner without work cannot be judged, and the time it spent without
    /// work is not silence once work arrives: an hour with no template must
    /// not walk the difficulty down the moment the first job goes out.
    #[test]
    fn time_without_work_is_not_silence() {
        let clock = TestClock::new(0);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001, 1_048_576.0);
        clock.advance_ms(3_600_000);
        assert_eq!(
            e.suggested_difficulty(1_048_576.0),
            None,
            "no work, no retarget"
        );
        assert_eq!(
            e.silence_implied_max_difficulty(),
            None,
            "no work, no evidence"
        );

        e.note_work_available();
        clock.advance_ms(30_000);
        assert_eq!(
            e.suggested_difficulty(1_048_576.0),
            None,
            "the hour without work was counted as silence"
        );
        clock.advance_ms(31_000);
        assert!(
            e.suggested_difficulty(1_048_576.0)
                .is_some_and(|d| d < 1_048_576.0),
            "a minute of silence with work must still descend"
        );
    }

    // ── the upper bound ───────────────────────────────────────────────

    /// A session that advertises 10× its real hashrate and lands no share
    /// reaches a difficulty it can hit within a handful of cycles.
    #[test]
    fn a_declining_miner_is_rescued_before_its_first_share() {
        let assigned = 100_000.0;
        let reachable = 10_000.0;
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, assigned);
        let mut diff = assigned;
        let mut cycles_to_reachable = None;
        for i in 0..15 {
            let before = diff;
            cycle(&mut e, &clock, 60_000, &mut diff);
            assert!(diff <= before, "descent must be monotone (cycle {i})");
            if cycles_to_reachable.is_none() && diff <= reachable {
                cycles_to_reachable = Some(i + 1);
            }
        }
        let cycles = cycles_to_reachable.expect("must reach a difficulty the miner can hit");
        assert!(cycles <= 5, "took {cycles} cycles to become reachable");
    }

    /// Whether a quiet minute is evidence depends on how many shares that
    /// minute was supposed to carry.
    #[test]
    fn quiet_is_judged_against_the_expected_share_rate() {
        // 0.6 shares/min → a 100 s mean gap. 90 s of quiet is ordinary.
        let clock = TestClock::new(1_000);
        let mut sparse = VarDiffEngine::new(&clock, 0.6, 0.00001, 4096.0);
        sparse.note_work_available();
        let mut diff = 4096.0;
        assert!(
            !cycle(&mut sparse, &clock, 90_000, &mut diff),
            "90 s without a share on a 0.6/min port is normal spacing, not evidence"
        );

        // 15 shares/min → a 4 s mean gap. The same 90 s is ~22 missed gaps.
        let clock = TestClock::new(1_000);
        let mut dense = VarDiffEngine::new(&clock, 15.0, 0.00001, 4096.0);
        dense.note_work_available();
        let mut diff = 4096.0;
        assert!(
            cycle(&mut dense, &clock, 90_000, &mut diff),
            "90 s without a share on a 15/min port is overwhelming evidence"
        );
        assert!(diff < 4096.0);
    }

    /// Exposure accumulates across ticks and assignments, so the descent
    /// does not depend on the check interval.
    #[test]
    fn descent_does_not_depend_on_the_check_interval() {
        let mut results = Vec::new();
        for (tick_ms, ticks) in [(30_000u64, 24u32), (60_000, 12), (240_000, 3)] {
            let clock = TestClock::new(1_000);
            let mut e = engine(&clock, 1_048_576.0);
            let mut diff = 1_048_576.0;
            for _ in 0..ticks {
                cycle(&mut e, &clock, tick_ms, &mut diff);
            }
            results.push((tick_ms, diff));
        }
        // Same 12 minutes of silence, three cadences: within one rung.
        let reference = results[0].1;
        for (tick_ms, got) in &results {
            assert!(
                *got <= reference * 2.0 && *got >= reference / 2.0,
                "tick {tick_ms} ms landed at {got}, reference {reference}"
            );
        }
    }

    /// A bound that rounds back onto the rung in force proposes nothing, and
    /// the descent does not stall there, because exposure keeps growing.
    #[test]
    fn a_bound_that_rounds_onto_the_current_rung_waits_and_then_crosses() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 65_536.0);
        let mut diff = 65_536.0;
        assert!(cycle(&mut e, &clock, 61_000, &mut diff));
        let after_first = diff;
        assert!(after_first < 65_536.0);

        // Poll faster than evidence accrues.
        assert!(
            !cycle(&mut e, &clock, 10_000, &mut diff),
            "a sub-rung proposal must not be emitted"
        );
        assert_eq!(diff, after_first);

        let mut moved = false;
        for _ in 0..10 {
            if cycle(&mut e, &clock, 10_000, &mut diff) {
                moved = true;
                break;
            }
        }
        assert!(moved, "descent stalled on its own rung");
        assert!(diff < after_first);
    }

    /// Zero arrivals are evidence of *less* hashrate, at any current
    /// difficulty, however long the wait.
    #[test]
    fn the_bound_never_proposes_an_increase() {
        let clock = TestClock::new(1_000);
        let e = engine(&clock, 1024.0);
        clock.advance_ms(61_000);
        for elapsed in [0u64, 1_000, 60_000, 600_000, 86_400_000] {
            clock.advance_ms(elapsed);
            for client in [0.001, 1.0, 1024.0, 65_536.0, 1e9] {
                if let Some(p) = e.suggested_difficulty(client) {
                    assert!(
                        p < client,
                        "proposed {p} from {client} after {elapsed} ms of silence"
                    );
                }
            }
        }
    }

    /// A session that never sustained a difficulty parks at the highest one
    /// assigned / 256 and holds, instead of sinking to `min_difficulty` and
    /// flooding on return.
    #[test]
    fn descent_parks_at_the_no_share_bound() {
        let clock = TestClock::new(1_000);
        let opening = 1_048_576.0;
        let mut e = engine(&clock, opening);
        let mut diff = opening;
        for _ in 0..200 {
            cycle(&mut e, &clock, 60_000, &mut diff);
        }
        // The floor is a LOWER bound: the first rung at or above it.
        assert_eq!(diff, opening / VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR);
        clock.advance_ms(86_400_000);
        assert_eq!(
            e.suggested_difficulty(diff),
            None,
            "parked must stay parked"
        );
    }

    /// `min_difficulty` still wins when it is the higher floor.
    #[test]
    fn descent_respects_the_configured_floor() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 500.0, 1_048_576.0);
        e.note_work_available();
        e.note_difficulty_assigned(65_536.0);
        let mut diff = 65_536.0;
        for _ in 0..200 {
            cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert!(
            diff >= 500.0,
            "descended to {diff}, below the configured 500"
        );
    }

    /// The no-share floor tracks the highest difficulty ever assigned, so a
    /// later raise keeps it relative to the difficulty in force, and a
    /// lowering does not drag it down.
    #[test]
    fn the_descent_floor_follows_a_later_raise() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 16_384.0);
        e.note_difficulty_assigned(500_000.0); // e.g. mining.suggest_difficulty
        let mut diff = 500_000.0;
        for _ in 0..400 {
            cycle(&mut e, &clock, 60_000, &mut diff);
        }
        let floor = 500_000.0 / VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR;
        assert!(diff >= floor, "parked at {diff}, below the bound {floor}");
        assert!(
            diff <= floor * 2.0,
            "parked at {diff}, a rung above {floor}"
        );
    }

    /// A missed lowering descends too little, never too much: exposure is
    /// computed at the difficulty the engine believes in.
    #[test]
    fn a_missed_assignment_hook_errs_toward_descending_too_little() {
        let clock = TestClock::new(0);
        let stale_high = engine(&clock, 1024.0);
        let clock2 = TestClock::new(0);
        let mut truthful = engine(&clock2, 1024.0);
        truthful.note_difficulty_assigned(64.0);

        clock.advance_ms(300_000);
        clock2.advance_ms(300_000);
        match (
            stale_high.suggested_difficulty(64.0),
            truthful.suggested_difficulty(64.0),
        ) {
            (Some(m), Some(t)) => assert!(m >= t, "missed: {m}, told: {t}"),
            (None, _) => {}
            (Some(m), None) => panic!("missed hook proposed {m} where the truth held"),
        }
    }

    /// The bound a caller weighs a declared hashrate against survives every
    /// descent step. A translator re-sends its claim on a timer, and evidence
    /// lost at each step would let that re-send undo the descent each time.
    #[test]
    fn silence_evidence_survives_each_descent_step() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1_048_576.0);
        assert_eq!(
            e.silence_implied_max_difficulty(),
            None,
            "no evidence at t = 0"
        );
        let mut diff = 1_048_576.0;
        let mut last_ceiling = f64::INFINITY;
        let mut steps = 0;
        for _ in 0..12 {
            clock.advance_ms(60_000);
            let ceiling = e
                .silence_implied_max_difficulty()
                .expect("a minute of silence and more is evidence");
            assert!(
                ceiling <= last_ceiling,
                "evidence shrank: {last_ceiling} → {ceiling}"
            );
            if let Some(next) = e.suggested_difficulty(diff) {
                diff = next;
                e.note_difficulty_assigned(next);
                steps += 1;
                let after = e
                    .silence_implied_max_difficulty()
                    .expect("an assignment must not erase the silence evidence");
                assert!(
                    after <= diff,
                    "right after the step to {diff} the evidence allows {after}"
                );
            }
            last_ceiling = ceiling;
        }
        assert!(
            steps >= 3,
            "precondition: the descent moved ({steps} steps)"
        );

        // An accepted share ends the question for good.
        e.note_share_accepted(diff);
        assert_eq!(e.silence_implied_max_difficulty(), None);
    }

    // ── silence after a measured window ──────────────────────────────

    /// A measured session goes fully silent: it descends monotonically,
    /// not before the deadband allows it, parks within a rung of the 16×
    /// bound below the difficulty it sustained, and stays there.
    #[test]
    fn silence_descends_monotonically_and_parks_at_the_bound() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1024.0);
        fill_equilibrium(&mut e, &clock);

        let mut diff = 1024.0;
        let mut first_step = None;
        for i in 0..240 {
            let before = diff;
            if cycle(&mut e, &clock, 60_000, &mut diff) {
                first_step.get_or_insert(i);
                assert!(diff < before, "descent must be monotone: {before} → {diff}");
            }
        }
        // The measured rate halves once the window doubles: ~300 s of silence
        // on top of the ~290 s it was measured over.
        assert!(
            first_step.is_some_and(|i| i >= 4),
            "eased before the deadband allows it: first step at check {first_step:?}"
        );
        let floor = 1024.0 / VARDIFF_SILENCE_MAX_DESCENT_FACTOR;
        assert!(
            (floor..=2.0 * floor).contains(&diff),
            "must park within a rung of {floor}, got {diff}"
        );
        for _ in 0..60 {
            clock.advance_ms(60_000);
            assert_eq!(e.suggested_difficulty(diff), None, "must stay parked");
        }
    }

    /// Stale and unknown-job shares are arrivals: a session whose shares all
    /// come back stale at its usual cadence holds. Without them the same
    /// silence descends.
    #[test]
    fn stale_shares_hold_a_silent_session() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1024.0);
        fill_equilibrium(&mut e, &clock);
        let mut diff = 1024.0;
        for i in 0..180 {
            clock.advance_ms(10_000);
            e.note_stale_share();
            if i % 6 == 5 {
                assert!(
                    !cycle(&mut e, &clock, 0, &mut diff),
                    "a session sending stale shares at its cadence must hold (t+{}s), went to {diff}",
                    (i + 1) * 10
                );
            }
        }

        // Control: the same 30 minutes in silence descend.
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1024.0);
        fill_equilibrium(&mut e, &clock);
        let mut diff = 1024.0;
        for _ in 0..30 {
            cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert!(diff < 1024.0, "control: silence must descend");
    }

    /// The window without a share is dropped by the first arrival, so a
    /// miner that starts late is not measured against the silence before.
    #[test]
    fn the_first_share_after_a_descent_is_not_diluted_by_the_silence() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1_048_576.0);
        let mut diff = 1_048_576.0;
        for _ in 0..60 {
            cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert_eq!(diff, 4096.0, "precondition: parked at the no-share bound");

        // A miner attaches that sustains 4096 on target: one share per 10 s.
        for _ in 0..7 {
            clock.advance_ms(10_000);
            e.note_share_accepted(4096.0);
        }
        assert_eq!(
            e.suggested_difficulty(4096.0),
            None,
            "an on-target miner must hold, not be read as slower than it is"
        );
    }

    // ── the up-step cap ───────────────────────────────────────────────

    /// A JDC flushing optimistic-mining shares lands a burst. The first raise
    /// is capped at 8×; the assignment spends the burst, so it cannot drive a
    /// second, uncapped raise, and the session comes back to its rate.
    #[test]
    fn a_burst_is_capped_once_and_cannot_ratchet_on() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 4.0);
        let mut diff = 4.0;
        clock.advance_ms(10_000);
        for _ in 0..300 {
            e.note_share_accepted(4.0); // the flush, in one millisecond
        }
        // True rate 0.4 difficulty/s: equilibrium 4.
        let assigned = mine_closed_loop(&mut e, &clock, &mut diff, 0.4, 1e9, 1_800_000, 60_000);
        assert_eq!(
            assigned.first(),
            Some(&32.0),
            "first raise capped at 8×: {assigned:?}"
        );
        assert!(
            assigned.iter().all(|d| *d <= 32.0),
            "the burst drove a second raise: {assigned:?}"
        );
        assert!(diff <= 8.0, "did not come back to its rate: {assigned:?}");
    }

    /// The cap survives the ladder: a raw cap of 384 (`client = 48`) would
    /// round up to 512, past 8×.
    #[test]
    fn up_step_cap_survives_the_power_of_two_ladder() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 48.0);
        e.note_share_accepted(4.0);
        for _ in 0..61 {
            clock.advance_ms(1_000);
            for _ in 0..10 {
                e.note_share_accepted(48.0);
            }
        }
        let proposed = e
            .suggested_difficulty(48.0)
            .expect("a 100× window must raise");
        assert!(
            proposed <= 48.0 * VARDIFF_MAX_UP_STEP_FACTOR,
            "{proposed} exceeds 8× 48"
        );
        assert_eq!(
            proposed,
            2_f64.powf(proposed.log2().round()),
            "not a power of two"
        );
    }

    /// The cap charges a proving interval once, not per 8×: a genuine 128×
    /// rate jump reaches equilibrium within two raises.
    #[test]
    fn a_proven_raise_is_not_rationed_at_eight_times_per_interval() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 512.0);
        let mut diff = 512.0;
        let rate = 512.0 / 10.0 * 128.0;
        let assigned = mine_closed_loop(&mut e, &clock, &mut diff, rate, 1e9, 600_000, 60_000);
        let equilibrium = 512.0 * 128.0;
        assert!(
            diff >= equilibrium / 2.0 && diff <= equilibrium * 2.0,
            "parked at {diff}, wanted ~{equilibrium}: {assigned:?}"
        );
        let raises_to_reach = assigned
            .iter()
            .position(|d| *d >= equilibrium / 2.0)
            .map(|i| i + 1);
        assert!(
            raises_to_reach.is_some_and(|n| n <= 2),
            "took more than two raises to follow a proven jump: {assigned:?}"
        );
    }

    // ── steady state ──────────────────────────────────────────────────

    /// A healthy miner with jittered arrivals (uniform 2–18 s gaps plus a 45 s
    /// outlier now and then), checked after every share and mid-gap, is never
    /// retargeted. Deterministic LCG. Exponential gaps do retarget an
    /// on-target session now and then; this pins the low-variance case.
    #[test]
    fn jittered_steady_state_is_unperturbed() {
        let clock = TestClock::new(0);
        let mut e = engine(&clock, 1024.0);
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut t_ms: u64 = 0;
        for i in 0..300u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (seed >> 33) % 1000;
            // The 45 s outliers are the tail a naive trigger mistakes for
            // silence.
            let gap_ms = if i % 37 == 0 { 45_000 } else { 2_000 + r * 16 };
            t_ms += gap_ms;
            clock.set_ms(t_ms);
            e.note_share_accepted(1024.0);
            assert_eq!(e.suggested_difficulty(1024.0), None, "after share #{i}");
            clock.set_ms(t_ms + gap_ms / 2);
            assert_eq!(
                e.suggested_difficulty(1024.0),
                None,
                "mid-gap after share #{i}"
            );
            clock.set_ms(t_ms);
        }
    }

    /// A session eased down after a silence resumes at 1/10 of its rate: it
    /// never snaps back to the pre-silence difficulty and settles near the
    /// throttled equilibrium.
    #[test]
    fn recovery_converges_without_a_sawtooth() {
        let clock = TestClock::new(1_000);
        let mut e = engine(&clock, 1024.0);
        fill_equilibrium(&mut e, &clock);
        let mut diff = 1024.0;
        for _ in 0..120 {
            cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert!((64.0..=128.0).contains(&diff), "parked, got {diff}");

        // Back at 10.24 difficulty/s: equilibrium ≈ 102.
        let assigned = mine_closed_loop(&mut e, &clock, &mut diff, 10.24, 1e9, 3_600_000, 60_000);
        assert!(
            assigned.iter().all(|d| *d < 1024.0),
            "snapped back to the pre-silence difficulty: {assigned:?}"
        );
        assert!(
            (48.0..=256.0).contains(&diff),
            "must settle near the throttled equilibrium, got {diff}: {assigned:?}"
        );
    }
}
