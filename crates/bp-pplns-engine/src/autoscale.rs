//! Coinbase-budget autoscaler — the pure control core.
//!
//! Decides, from a stream of weight-budget utilization samples, whether to
//! step the live `coinbase_weight_budget` up or down. No IO, no async, no
//! wall-clock: time is passed in as a monotonic seconds counter so the whole
//! state machine is deterministic and exhaustively unit-testable. The driving
//! task (in the binary) supplies real telemetry + real time and carries out
//! the [`AutoscaleDecision`] via the race-safe `set_budget` coupling.
//!
//! ## Anti-hopping
//!
//! Five overlapping dampers keep the budget from flapping:
//!
//! 1. **Hysteresis deadband** — separate `up_threshold` (e.g. 0.85) and
//!    `down_threshold` (e.g. 0.50). Between them: do nothing, reset streaks.
//! 2. **Stepwise** — multiply/divide by `step_factor` (e.g. 1.15); never a
//!    continuous chase of the target.
//! 3. **Step geometry** — with the recommended params one step can never land
//!    across the opposite threshold (0.85/1.15 = 0.74 and 0.50·1.15 = 0.58 both
//!    sit inside the deadband), so a single jump never re-arms the reverse
//!    direction. Validated in tests.
//! 4. **Debounce** — the trigger must hold for `up_debounce` / `down_debounce`
//!    consecutive samples (asymmetric: quick up, lazy down).
//! 5. **Cooldown** — no two changes within `cooldown_secs`.
//!
//! Persistence across restarts (so a reboot doesn't reset to the floor and
//! re-climb — itself a form of hopping) lives in the driver, not here.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bp_pplns::BudgetTelemetry;

/// Shared, live-mutable coinbase weight budget plus the most-recent pressure
/// sample. Cloneable handle (`Arc` inside) shared between two sides:
///
/// - the **distribution builder** reads [`get`](LiveBudget::get) once per
///   template build and records each [`BudgetTelemetry`] via
///   [`record_sample`](LiveBudget::record_sample);
/// - the **autoscaler driver task** polls [`latest_sample`](LiveBudget::latest_sample)
///   and writes the new value via [`set`](LiveBudget::set) after coupling it to
///   bitcoin-core's reservation.
///
/// All reads/writes are `Relaxed` atomics (the budget is a single advisory
/// scalar — no ordering relationship to protect) plus a tiny mutex for the
/// `Copy` sample.
#[derive(Clone, Debug)]
pub struct LiveBudget {
    inner: Arc<LiveBudgetInner>,
}

#[derive(Debug)]
struct LiveBudgetInner {
    budget: AtomicU32,
    sample_seq: AtomicU64,
    last_sample: Mutex<Option<BudgetTelemetry>>,
}

impl LiveBudget {
    pub fn new(initial: u32) -> Self {
        Self {
            inner: Arc::new(LiveBudgetInner {
                budget: AtomicU32::new(initial),
                sample_seq: AtomicU64::new(0),
                last_sample: Mutex::new(None),
            }),
        }
    }

    /// Current live budget. Read by the distribution builder per template.
    pub fn get(&self) -> u32 {
        self.inner.budget.load(Ordering::Relaxed)
    }

    /// Overwrite the live budget. Written by the autoscaler driver; the driver
    /// is responsible for the race-safe ordering vs. bitcoin-core's reservation
    /// and for invalidating the distribution cache afterwards.
    pub fn set(&self, value: u32) {
        self.inner.budget.store(value, Ordering::Relaxed);
    }

    /// Record the latest pressure sample (called after each build that
    /// produced telemetry). Bumps the sequence so the driver can tell a new
    /// sample from a repeat.
    pub fn record_sample(&self, sample: BudgetTelemetry) {
        *self
            .inner
            .last_sample
            .lock()
            .expect("LiveBudget sample mutex poisoned") = Some(sample);
        self.inner.sample_seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Monotonic count of samples recorded so far. The driver uses this to
    /// skip ticks where no fresh distribution was built (quiet pool).
    pub fn sample_seq(&self) -> u64 {
        self.inner.sample_seq.load(Ordering::Relaxed)
    }

    /// The most recent pressure sample, if any has been recorded.
    pub fn latest_sample(&self) -> Option<BudgetTelemetry> {
        *self
            .inner
            .last_sample
            .lock()
            .expect("LiveBudget sample mutex poisoned")
    }
}

/// Tunables for [`Autoscaler`]. All ratios are fractions of the trim
/// threshold (`effective_budget`). Validated by the config layer before
/// construction; the autoscaler itself trusts these.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AutoscaleParams {
    /// Hard lower bound — the budget never drops below this (TOML seed/floor).
    pub floor: u32,
    /// Hard upper bound — the budget never rises above this (operator ceiling).
    pub ceiling: u32,
    /// Scale **up** when utilization ≥ this (e.g. 0.85 = "15% before trim").
    pub up_threshold: f64,
    /// Scale **down** when utilization ≤ this (e.g. 0.50).
    pub down_threshold: f64,
    /// Multiplicative step (e.g. 1.15 → +15% up, ÷1.15 down). Must be > 1.0.
    pub step_factor: f64,
    /// Consecutive over-threshold samples required before stepping up.
    pub up_debounce: u32,
    /// Consecutive under-threshold samples required before stepping down.
    pub down_debounce: u32,
    /// Minimum seconds between two budget changes.
    pub cooldown_secs: u64,
}

/// What the driver should do after an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoscaleDecision {
    /// No change this observation.
    Hold,
    /// Apply this new budget (already clamped to `[floor, ceiling]` and
    /// guaranteed different from the current value). The driver couples it to
    /// bitcoin-core's reservation in the race-safe order.
    SetBudget(u32),
}

/// The control state machine. Feed it [`observe`](Autoscaler::observe) once per
/// sampling tick; it tracks streaks + cooldown and emits an
/// [`AutoscaleDecision`].
#[derive(Clone, Debug)]
pub struct Autoscaler {
    params: AutoscaleParams,
    current_budget: u32,
    up_streak: u32,
    down_streak: u32,
    /// Seconds-timestamp of the last applied change; `None` until the first.
    last_change_secs: Option<u64>,
}

impl Autoscaler {
    /// Start at `initial_budget` (the persisted/seed value, already clamped by
    /// the caller). No change can fire until `cooldown_secs` after the first
    /// observation that would otherwise trigger — there is no artificial
    /// startup cooldown, but `last_change_secs` is `None` so the first eligible
    /// trigger is free.
    pub fn new(params: AutoscaleParams, initial_budget: u32) -> Self {
        Self {
            params,
            current_budget: initial_budget,
            up_streak: 0,
            down_streak: 0,
            last_change_secs: None,
        }
    }

    /// Current live budget the autoscaler believes is in effect.
    pub fn current_budget(&self) -> u32 {
        self.current_budget
    }

    /// Force the believed-current budget (e.g. driver reconciled a persisted
    /// value at boot, or a manual override landed). Resets streaks so the next
    /// decision starts from a clean slate.
    pub fn set_current_budget(&mut self, budget: u32) {
        self.current_budget = budget;
        self.up_streak = 0;
        self.down_streak = 0;
    }

    /// Feed one utilization sample taken at `now_secs` (monotonic). Returns the
    /// decision; on `SetBudget` the internal current-budget + cooldown are
    /// already advanced, so the driver just needs to apply it.
    pub fn observe(&mut self, utilization: f64, now_secs: u64) -> AutoscaleDecision {
        // 1. Streak bookkeeping (hysteresis deadband resets both).
        if utilization >= self.params.up_threshold {
            self.up_streak = self.up_streak.saturating_add(1);
            self.down_streak = 0;
        } else if utilization <= self.params.down_threshold {
            self.down_streak = self.down_streak.saturating_add(1);
            self.up_streak = 0;
        } else {
            self.up_streak = 0;
            self.down_streak = 0;
        }

        // 2. Cooldown gate — never change twice within cooldown_secs.
        if let Some(last) = self.last_change_secs {
            if now_secs.saturating_sub(last) < self.params.cooldown_secs {
                return AutoscaleDecision::Hold;
            }
        }

        // 3. Up has priority (pressure relief over space reclaim).
        if self.up_streak >= self.params.up_debounce && self.current_budget < self.params.ceiling {
            let next = self.stepped(true);
            if next != self.current_budget {
                return self.apply(next, now_secs);
            }
        }
        // 4. Down.
        if self.down_streak >= self.params.down_debounce && self.current_budget > self.params.floor
        {
            let next = self.stepped(false);
            if next != self.current_budget {
                return self.apply(next, now_secs);
            }
        }
        AutoscaleDecision::Hold
    }

    /// Compute the next budget one step `up` or down from current, clamped to
    /// `[floor, ceiling]`.
    fn stepped(&self, up: bool) -> u32 {
        let cur = self.current_budget as f64;
        let raw = if up {
            cur * self.params.step_factor
        } else {
            cur / self.params.step_factor
        };
        let rounded = raw.round();
        // Clamp into u32 range then into [floor, ceiling].
        let as_u32 = if rounded <= 0.0 {
            0
        } else if rounded >= u32::MAX as f64 {
            u32::MAX
        } else {
            rounded as u32
        };
        as_u32.clamp(self.params.floor, self.params.ceiling)
    }

    fn apply(&mut self, next: u32, now_secs: u64) -> AutoscaleDecision {
        self.current_budget = next;
        self.last_change_secs = Some(now_secs);
        // Fresh debounce required before the next move in either direction.
        self.up_streak = 0;
        self.down_streak = 0;
        AutoscaleDecision::SetBudget(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recommended production policy: 85% / 50% / ±15%, floor 50k, ceiling 400k.
    fn params() -> AutoscaleParams {
        AutoscaleParams {
            floor: 50_000,
            ceiling: 400_000,
            up_threshold: 0.85,
            down_threshold: 0.50,
            step_factor: 1.15,
            up_debounce: 3,
            down_debounce: 10,
            cooldown_secs: 300,
        }
    }

    #[test]
    fn holds_inside_deadband() {
        let mut a = Autoscaler::new(params(), 100_000);
        for t in 0..100 {
            assert_eq!(a.observe(0.70, t), AutoscaleDecision::Hold);
        }
        assert_eq!(a.current_budget(), 100_000);
    }

    #[test]
    fn steps_up_only_after_debounce() {
        let mut a = Autoscaler::new(params(), 100_000);
        // Two over-threshold samples: not yet (debounce = 3).
        assert_eq!(a.observe(0.90, 0), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 1), AutoscaleDecision::Hold);
        // Third trips it: 100_000 * 1.15 = 115_000.
        assert_eq!(a.observe(0.90, 2), AutoscaleDecision::SetBudget(115_000));
        assert_eq!(a.current_budget(), 115_000);
    }

    #[test]
    fn down_is_lazier_than_up() {
        let mut a = Autoscaler::new(params(), 100_000);
        // 9 low samples: still holding (down_debounce = 10).
        for t in 0..9 {
            assert_eq!(a.observe(0.30, t), AutoscaleDecision::Hold);
        }
        // 10th: 100_000 / 1.15 = 86_956.52 → 86_957.
        assert_eq!(a.observe(0.30, 9), AutoscaleDecision::SetBudget(86_957));
    }

    #[test]
    fn deadband_resets_streak_no_premature_step() {
        let mut a = Autoscaler::new(params(), 100_000);
        assert_eq!(a.observe(0.90, 0), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 1), AutoscaleDecision::Hold);
        // Dip into deadband resets the up-streak.
        assert_eq!(a.observe(0.70, 2), AutoscaleDecision::Hold);
        // Two more highs are NOT enough — streak restarted.
        assert_eq!(a.observe(0.90, 3), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 4), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 5), AutoscaleDecision::SetBudget(115_000));
    }

    #[test]
    fn cooldown_blocks_second_change() {
        let mut a = Autoscaler::new(params(), 100_000);
        for t in 0..3 {
            a.observe(0.90, t);
        }
        assert_eq!(a.current_budget(), 115_000); // changed at t=2
                                                 // Even with sustained pressure, no change before cooldown elapses.
                                                 // (Streaks keep accumulating during cooldown — pressure never let up.)
        for t in 3..302 {
            assert_eq!(a.observe(0.95, t), AutoscaleDecision::Hold);
        }
        // 300s after the change (t = 302): cooldown over and the streak built
        // up across the wait, so the first allowed tick fires immediately.
        // 115_000 * 1.15 = 132_250.
        assert_eq!(a.observe(0.95, 302), AutoscaleDecision::SetBudget(132_250));
    }

    #[test]
    fn clamps_at_ceiling() {
        let mut a = Autoscaler::new(params(), 390_000);
        let mut now = 0u64;
        // Drive up; should land on ceiling and then hold there forever.
        loop {
            let d = a.observe(0.99, now);
            now += 301; // skip past cooldown each time
            if let AutoscaleDecision::SetBudget(b) = d {
                if b == 400_000 {
                    break;
                }
            }
            assert!(now < 100_000, "should reach ceiling quickly");
        }
        // Pinned at ceiling: never exceeds it despite continued pressure.
        for i in 0..50u64 {
            let d = a.observe(0.99, now + i * 301);
            assert_eq!(d, AutoscaleDecision::Hold);
            assert_eq!(a.current_budget(), 400_000);
        }
    }

    #[test]
    fn clamps_at_floor() {
        let mut a = Autoscaler::new(params(), 55_000);
        let mut now = 0u64;
        loop {
            let d = a.observe(0.10, now);
            now += 301;
            if let AutoscaleDecision::SetBudget(b) = d {
                if b == 50_000 {
                    break;
                }
            }
            assert!(now < 100_000, "should reach floor quickly");
        }
        for i in 0..50u64 {
            let d = a.observe(0.10, now + i * 301);
            assert_eq!(d, AutoscaleDecision::Hold);
            assert_eq!(a.current_budget(), 50_000);
        }
    }

    /// The core anti-hopping guarantee: utilization oscillating right at the
    /// up-threshold must not produce a flip-flop. After one up-step the new
    /// utilization (old·1/step) lands in the deadband, so a realistic feedback
    /// loop settles instead of thrashing.
    #[test]
    fn no_hopping_when_oscillating_near_threshold() {
        let p = params();
        let mut a = Autoscaler::new(p, 100_000);
        let mut changes = 0;
        // Simulate a closed loop: demand is fixed; utilization = demand/budget.
        // Pick demand so we START just over the up-threshold.
        let demand = 0.86 * 100_000.0;
        for now in 0..1000u64 {
            let util = demand / a.current_budget() as f64;
            if let AutoscaleDecision::SetBudget(_) = a.observe(util, now) {
                changes += 1;
            }
        }
        // Exactly one up-step: 0.86 → after ×1.15, util = 0.86/1.15 = 0.748,
        // which is inside the deadband → no down-step, no further up. Settled.
        assert_eq!(changes, 1, "feedback loop must settle, not flap");
        assert_eq!(a.current_budget(), 115_000);
    }

    /// Step geometry invariant for the recommended params: one up-step from the
    /// up-threshold lands strictly inside the deadband (no reverse re-arm), and
    /// one down-step from the down-threshold likewise.
    #[test]
    fn step_geometry_keeps_jumps_inside_deadband() {
        let p = params();
        let after_up = p.up_threshold / p.step_factor; // 0.85/1.15
        assert!(after_up > p.down_threshold && after_up < p.up_threshold);
        let after_down = p.down_threshold * p.step_factor; // 0.50*1.15
        assert!(after_down > p.down_threshold && after_down < p.up_threshold);
    }

    #[test]
    fn set_current_budget_resets_streaks() {
        let mut a = Autoscaler::new(params(), 100_000);
        a.observe(0.90, 0);
        a.observe(0.90, 1);
        a.set_current_budget(200_000);
        assert_eq!(a.current_budget(), 200_000);
        // Streak was reset — needs a full fresh debounce.
        assert_eq!(a.observe(0.90, 2), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 3), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 4), AutoscaleDecision::SetBudget(230_000));
    }
}
