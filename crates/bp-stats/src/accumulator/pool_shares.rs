// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide accepted / rejected share difficulty per 10-min slot.

use parking_lot::Mutex;
use std::collections::HashMap;

use crate::buffer::{BufferRecord, RecordDeltaBuffer};
use crate::constants::MAX_REASONABLE_DIFFICULTY;
use crate::slot::TimeSlot;

/// Per-slot pool-shares counters. `accepted` and `rejected` are diff sums
/// (NOT raw share counts).
#[derive(Default, Clone, Debug, PartialEq)]
pub struct PoolSharesRecord {
    pub accepted: f64,
    pub rejected: f64,
}

impl BufferRecord for PoolSharesRecord {
    fn is_zero(&self) -> bool {
        self.accepted == 0.0 && self.rejected == 0.0
    }
    fn add_assign(&mut self, rhs: &Self) {
        self.accepted += rhs.accepted;
        self.rejected += rhs.rejected;
    }
    fn sub_assign_clamped(&mut self, rhs: &Self) -> bool {
        self.accepted -= rhs.accepted;
        self.rejected -= rhs.rejected;
        self.accepted <= 0.0 && self.rejected <= 0.0
    }
}

pub type PoolSharesSnapshot = HashMap<TimeSlot, PoolSharesRecord>;

pub struct PoolSharesAccumulator {
    inner: Mutex<RecordDeltaBuffer<TimeSlot, PoolSharesRecord>>,
}

impl Default for PoolSharesAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolSharesAccumulator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RecordDeltaBuffer::new()),
        }
    }

    /// Hot-path: record an accepted share's diff against the given slot.
    /// Non-finite or out-of-range values are silently discarded.
    pub fn add_accepted(&self, slot: TimeSlot, diff: f64) {
        if !diff.is_finite() || diff <= 0.0 || diff > MAX_REASONABLE_DIFFICULTY {
            return;
        }
        self.inner.lock().add(
            slot,
            &PoolSharesRecord {
                accepted: diff,
                rejected: 0.0,
            },
        );
    }

    pub fn add_rejected(&self, slot: TimeSlot, diff: f64) {
        if !diff.is_finite() || diff <= 0.0 || diff > MAX_REASONABLE_DIFFICULTY {
            return;
        }
        self.inner.lock().add(
            slot,
            &PoolSharesRecord {
                accepted: 0.0,
                rejected: diff,
            },
        );
    }

    pub fn drain(&self) -> PoolSharesSnapshot {
        self.inner.lock().drain()
    }

    pub fn confirm(&self, snapshot: &PoolSharesSnapshot) {
        self.inner.lock().confirm(snapshot);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(end: i64) -> TimeSlot {
        TimeSlot::from_millis(end)
    }

    #[test]
    fn add_then_drain_returns_summed_diff() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0);
        acc.add_accepted(slot(1_000), 50.0);
        acc.add_rejected(slot(1_000), 7.0);
        let snap = acc.drain();
        assert_eq!(
            snap.get(&slot(1_000)),
            Some(&PoolSharesRecord {
                accepted: 150.0,
                rejected: 7.0,
            })
        );
    }

    #[test]
    fn drain_is_non_clearing_until_confirm() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0);
        let _ = acc.drain();
        // Still in the buffer until confirm runs.
        assert_eq!(acc.len(), 1);
    }

    #[test]
    fn confirm_subtracts_and_drops_empty_buckets() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0);
        let snap = acc.drain();
        acc.confirm(&snap);
        assert!(acc.is_empty());
    }

    #[test]
    fn concurrent_adds_during_flush_survive_confirm() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0);
        let snap = acc.drain();
        // Concurrent write between drain and confirm.
        acc.add_accepted(slot(1_000), 25.0);
        acc.confirm(&snap);
        let residual = acc.drain();
        assert_eq!(residual.get(&slot(1_000)).map(|r| r.accepted), Some(25.0));
    }

    #[test]
    fn over_range_diff_is_discarded() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), MAX_REASONABLE_DIFFICULTY * 10.0);
        assert!(acc.is_empty());
    }

    #[test]
    fn non_finite_and_zero_diff_are_discarded() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), f64::NAN);
        acc.add_accepted(slot(1_000), f64::INFINITY);
        acc.add_accepted(slot(1_000), 0.0);
        acc.add_accepted(slot(1_000), -5.0);
        assert!(acc.is_empty());
    }

    #[test]
    fn multiple_slots_are_independent() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 10.0);
        acc.add_accepted(slot(2_000), 20.0);
        acc.add_rejected(slot(2_000), 1.0);
        let snap = acc.drain();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(&slot(1_000)).unwrap().accepted, 10.0);
        assert_eq!(snap.get(&slot(2_000)).unwrap().accepted, 20.0);
        assert_eq!(snap.get(&slot(2_000)).unwrap().rejected, 1.0);
    }
}
