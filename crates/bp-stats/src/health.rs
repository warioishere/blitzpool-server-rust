// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-flusher consecutive-failure counter; the caller decides what to do
//! once the threshold trips.

use std::collections::HashMap;
use std::hash::Hash;

use crate::constants::FLUSH_FAILURE_WARN_THRESHOLD;

/// Outcome of [`FlushHealthMonitor::record_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushHealth {
    Healthy {
        consecutive_failures: u32,
    },
    /// The count just **crossed** the threshold: warn now, exactly once.
    JustCrossedThreshold {
        consecutive_failures: u32,
    },
    /// Already past the threshold; do not warn again.
    Degraded {
        consecutive_failures: u32,
    },
}

pub struct FlushHealthMonitor<F: Eq + Hash> {
    counts: HashMap<F, u32>,
    threshold: u32,
}

impl<F: Eq + Hash> Default for FlushHealthMonitor<F> {
    fn default() -> Self {
        Self::with_threshold(FLUSH_FAILURE_WARN_THRESHOLD)
    }
}

impl<F: Eq + Hash> FlushHealthMonitor<F> {
    pub fn with_threshold(threshold: u32) -> Self {
        Self {
            counts: HashMap::new(),
            threshold,
        }
    }

    pub fn record_success(&mut self, flusher: F) {
        self.counts.remove(&flusher);
    }

    pub fn record_failure(&mut self, flusher: F) -> FlushHealth {
        let count = self.counts.entry(flusher).or_insert(0);
        let prev = *count;
        *count = count.saturating_add(1);
        let new = *count;
        if prev < self.threshold && new >= self.threshold {
            FlushHealth::JustCrossedThreshold {
                consecutive_failures: new,
            }
        } else if new >= self.threshold {
            FlushHealth::Degraded {
                consecutive_failures: new,
            }
        } else {
            FlushHealth::Healthy {
                consecutive_failures: new,
            }
        }
    }

    pub fn consecutive_failures(&self, flusher: &F) -> u32 {
        self.counts.get(flusher).copied().unwrap_or(0)
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
    enum Flusher {
        PoolShares,
        ClientStats,
    }

    #[test]
    fn first_failures_are_healthy() {
        let mut m: FlushHealthMonitor<Flusher> = FlushHealthMonitor::default();
        assert_eq!(
            m.record_failure(Flusher::PoolShares),
            FlushHealth::Healthy {
                consecutive_failures: 1
            }
        );
        assert_eq!(
            m.record_failure(Flusher::PoolShares),
            FlushHealth::Healthy {
                consecutive_failures: 2
            }
        );
    }

    #[test]
    fn third_failure_crosses_threshold_exactly_once() {
        let mut m: FlushHealthMonitor<Flusher> = FlushHealthMonitor::default();
        m.record_failure(Flusher::PoolShares);
        m.record_failure(Flusher::PoolShares);
        let crossed = m.record_failure(Flusher::PoolShares);
        assert_eq!(
            crossed,
            FlushHealth::JustCrossedThreshold {
                consecutive_failures: 3
            }
        );
        // Subsequent failures are Degraded, not JustCrossed.
        assert_eq!(
            m.record_failure(Flusher::PoolShares),
            FlushHealth::Degraded {
                consecutive_failures: 4
            }
        );
    }

    #[test]
    fn success_resets_counter() {
        let mut m: FlushHealthMonitor<Flusher> = FlushHealthMonitor::default();
        m.record_failure(Flusher::PoolShares);
        m.record_failure(Flusher::PoolShares);
        m.record_success(Flusher::PoolShares);
        assert_eq!(m.consecutive_failures(&Flusher::PoolShares), 0);
        // Next failure starts fresh.
        assert_eq!(
            m.record_failure(Flusher::PoolShares),
            FlushHealth::Healthy {
                consecutive_failures: 1
            }
        );
    }

    #[test]
    fn per_flusher_isolation() {
        let mut m: FlushHealthMonitor<Flusher> = FlushHealthMonitor::default();
        m.record_failure(Flusher::PoolShares);
        m.record_failure(Flusher::PoolShares);
        m.record_failure(Flusher::PoolShares);
        // ClientStats is independent — still at 0.
        assert_eq!(m.consecutive_failures(&Flusher::ClientStats), 0);
        assert_eq!(
            m.record_failure(Flusher::ClientStats),
            FlushHealth::Healthy {
                consecutive_failures: 1
            }
        );
    }

    #[test]
    fn custom_threshold() {
        let mut m: FlushHealthMonitor<Flusher> = FlushHealthMonitor::with_threshold(2);
        m.record_failure(Flusher::PoolShares);
        let crossed = m.record_failure(Flusher::PoolShares);
        assert_eq!(
            crossed,
            FlushHealth::JustCrossedThreshold {
                consecutive_failures: 2
            }
        );
    }
}
