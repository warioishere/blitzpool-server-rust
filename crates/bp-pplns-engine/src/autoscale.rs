//! Pure control core of the coinbase-budget autoscaler: time is passed in, so
//! it is deterministic; the driver carries out the [`AutoscaleDecision`].
//! Against flapping: a hysteresis deadband, multiplicative steps that land
//! inside that deadband, asymmetric debounce, and a cooldown between changes.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bp_pplns::BudgetTelemetry;

/// Live coinbase weight budget plus the latest [`BudgetTelemetry`] sample,
/// shared by the distribution builder (reads, records) and the autoscaler
/// driver (polls, writes). `Relaxed` suffices: one advisory scalar.
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

    pub fn get(&self) -> u32 {
        self.inner.budget.load(Ordering::Relaxed)
    }

    /// The caller owns the ordering against bitcoin-core's reservation and
    /// the distribution cache invalidation afterwards.
    pub fn set(&self, value: u32) {
        self.inner.budget.store(value, Ordering::Relaxed);
    }

    /// Bumps the sequence so the driver can tell a new sample from a repeat.
    pub fn record_sample(&self, sample: BudgetTelemetry) {
        *self
            .inner
            .last_sample
            .lock()
            .expect("LiveBudget sample mutex poisoned") = Some(sample);
        self.inner.sample_seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Lets the driver skip ticks where no distribution was built.
    pub fn sample_seq(&self) -> u64 {
        self.inner.sample_seq.load(Ordering::Relaxed)
    }

    pub fn latest_sample(&self) -> Option<BudgetTelemetry> {
        *self
            .inner
            .last_sample
            .lock()
            .expect("LiveBudget sample mutex poisoned")
    }
}

/// Tunables for [`Autoscaler`]; ratios are fractions of `effective_budget`.
/// Validated by the config layer, trusted here.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AutoscaleParams {
    pub floor: u32,
    pub ceiling: u32,
    pub up_threshold: f64,
    pub down_threshold: f64,
    /// Multiply up, divide down. Must be > 1.0.
    pub step_factor: f64,
    /// Consecutive samples past the threshold before a step.
    pub up_debounce: u32,
    pub down_debounce: u32,
    pub cooldown_secs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoscaleDecision {
    Hold,
    /// Already clamped to `[floor, ceiling]` and different from the current value.
    SetBudget(u32),
}

/// The control state machine; feed it [`observe`](Autoscaler::observe) once per tick.
#[derive(Clone, Debug)]
pub struct Autoscaler {
    params: AutoscaleParams,
    current_budget: u32,
    up_streak: u32,
    down_streak: u32,
    last_change_secs: Option<u64>,
}

impl Autoscaler {
    /// `initial_budget` is already clamped by the caller. There is no startup
    /// cooldown: the first eligible trigger fires.
    pub fn new(params: AutoscaleParams, initial_budget: u32) -> Self {
        Self {
            params,
            current_budget: initial_budget,
            up_streak: 0,
            down_streak: 0,
            last_change_secs: None,
        }
    }

    pub fn current_budget(&self) -> u32 {
        self.current_budget
    }

    /// Force the believed budget (boot reconcile, manual override); resets streaks.
    pub fn set_current_budget(&mut self, budget: u32) {
        self.current_budget = budget;
        self.up_streak = 0;
        self.down_streak = 0;
    }

    /// Feed one sample at monotonic `now_secs`. On `SetBudget` the internal
    /// state is already advanced; the driver only applies it.
    pub fn observe(&mut self, utilization: f64, now_secs: u64) -> AutoscaleDecision {
        // The deadband resets both streaks.
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

        if let Some(last) = self.last_change_secs {
            if now_secs.saturating_sub(last) < self.params.cooldown_secs {
                return AutoscaleDecision::Hold;
            }
        }

        // Up first: relieving pressure beats reclaiming space.
        if self.up_streak >= self.params.up_debounce && self.current_budget < self.params.ceiling {
            let next = self.stepped(true);
            if next != self.current_budget {
                return self.apply(next, now_secs);
            }
        }
        if self.down_streak >= self.params.down_debounce && self.current_budget > self.params.floor
        {
            let next = self.stepped(false);
            if next != self.current_budget {
                return self.apply(next, now_secs);
            }
        }
        AutoscaleDecision::Hold
    }

    fn stepped(&self, up: bool) -> u32 {
        let cur = self.current_budget as f64;
        let raw = if up {
            cur * self.params.step_factor
        } else {
            cur / self.params.step_factor
        };
        let rounded = raw.round();
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
        assert_eq!(a.observe(0.90, 0), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 1), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 2), AutoscaleDecision::SetBudget(115_000));
        assert_eq!(a.current_budget(), 115_000);
    }

    #[test]
    fn down_is_lazier_than_up() {
        let mut a = Autoscaler::new(params(), 100_000);
        for t in 0..9 {
            assert_eq!(a.observe(0.30, t), AutoscaleDecision::Hold);
        }
        assert_eq!(a.observe(0.30, 9), AutoscaleDecision::SetBudget(86_957));
    }

    #[test]
    fn deadband_resets_streak_no_premature_step() {
        let mut a = Autoscaler::new(params(), 100_000);
        assert_eq!(a.observe(0.90, 0), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 1), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.70, 2), AutoscaleDecision::Hold);
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
        for t in 3..302 {
            assert_eq!(a.observe(0.95, t), AutoscaleDecision::Hold);
        }
        // The streak kept building during the cooldown, so the first allowed
        // tick fires.
        assert_eq!(a.observe(0.95, 302), AutoscaleDecision::SetBudget(132_250));
    }

    #[test]
    fn clamps_at_ceiling() {
        let mut a = Autoscaler::new(params(), 390_000);
        let mut now = 0u64;
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

    /// A closed loop starting just over the up-threshold settles after one step.
    #[test]
    fn no_hopping_when_oscillating_near_threshold() {
        let p = params();
        let mut a = Autoscaler::new(p, 100_000);
        let mut changes = 0;
        let demand = 0.86 * 100_000.0;
        for now in 0..1000u64 {
            let util = demand / a.current_budget() as f64;
            if let AutoscaleDecision::SetBudget(_) = a.observe(util, now) {
                changes += 1;
            }
        }
        assert_eq!(changes, 1, "feedback loop must settle, not flap");
        assert_eq!(a.current_budget(), 115_000);
    }

    /// One step from either threshold lands inside the deadband.
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
        assert_eq!(a.observe(0.90, 2), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 3), AutoscaleDecision::Hold);
        assert_eq!(a.observe(0.90, 4), AutoscaleDecision::SetBudget(230_000));
    }
}
