// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide accepted / rejected share difficulty per 10-min slot.

use parking_lot::Mutex;
use std::collections::HashMap;

use super::share_max;
use crate::buffer::{BufferRecord, RecordDeltaBuffer};
use crate::slot::TimeSlot;

/// Per-slot pool-shares counters. `accepted` and `rejected` are diff sums
/// (NOT raw share counts); `max_difficulty` is the highest single accepted
/// share difficulty of the slot.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct PoolSharesRecord {
    pub accepted: f64,
    pub rejected: f64,
    pub max_difficulty: f64,
}

impl BufferRecord for PoolSharesRecord {
    fn is_zero(&self) -> bool {
        self.accepted == 0.0 && self.rejected == 0.0 && self.max_difficulty == 0.0
    }
    fn add_assign(&mut self, rhs: &Self) {
        self.accepted += rhs.accepted;
        self.rejected += rhs.rejected;
        self.max_difficulty = self.max_difficulty.max(rhs.max_difficulty);
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

    /// The credited `diff` goes into the sum, the difficulty actually solved
    /// into the slot maximum.
    pub fn add_accepted(&self, slot: TimeSlot, diff: f64, submission_difficulty: f64) {
        self.inner.lock().add(
            slot,
            &PoolSharesRecord {
                accepted: diff,
                rejected: 0.0,
                max_difficulty: share_max(submission_difficulty),
            },
        );
    }

    pub fn add_rejected(&self, slot: TimeSlot, diff: f64) {
        self.inner.lock().add(
            slot,
            &PoolSharesRecord {
                accepted: 0.0,
                rejected: diff,
                max_difficulty: 0.0,
            },
        );
    }

    /// Empty the accumulator for a flush.
    pub fn take(&self) -> PoolSharesSnapshot {
        self.inner.lock().take()
    }

    /// Hand back an unwritten [`Self::take`].
    pub fn restore(&self, snapshot: PoolSharesSnapshot) {
        self.inner.lock().restore(snapshot);
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
    fn add_then_take_returns_summed_diff() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0, 100.0);
        acc.add_accepted(slot(1_000), 50.0, 50.0);
        acc.add_rejected(slot(1_000), 7.0);
        let snap = acc.take();
        assert_eq!(
            snap.get(&slot(1_000)),
            Some(&PoolSharesRecord {
                accepted: 150.0,
                rejected: 7.0,
                max_difficulty: 100.0,
            })
        );
    }

    #[test]
    fn take_empties_the_accumulator() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0, 100.0);
        let _ = acc.take();
        assert!(acc.is_empty());
    }

    #[test]
    fn restore_adds_onto_writes_made_during_the_flush() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 100.0, 4_096.0);
        let snap = acc.take(); // the flush fails
        acc.add_accepted(slot(1_000), 25.0, 25.0);
        acc.restore(snap);
        let merged = acc.take();
        assert_eq!(merged[&slot(1_000)].accepted, 125.0);
        assert_eq!(
            merged[&slot(1_000)].max_difficulty,
            4_096.0,
            "a max never drops"
        );
    }

    #[test]
    fn multiple_slots_are_independent() {
        let acc = PoolSharesAccumulator::new();
        acc.add_accepted(slot(1_000), 10.0, 10.0);
        acc.add_accepted(slot(2_000), 20.0, 20.0);
        acc.add_rejected(slot(2_000), 1.0);
        let snap = acc.take();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(&slot(1_000)).unwrap().accepted, 10.0);
        assert_eq!(snap.get(&slot(2_000)).unwrap().accepted, 20.0);
        assert_eq!(snap.get(&slot(2_000)).unwrap().rejected, 1.0);
    }
}
