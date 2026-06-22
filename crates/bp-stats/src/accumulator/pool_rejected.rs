// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-slot per-reason pool-wide rejected counts (number of shares, not
//! diff sum).

use parking_lot::Mutex;
use std::collections::HashMap;

use crate::accumulator::RejectedReason;
use crate::buffer::NestedDeltaBuffer;
use crate::slot::TimeSlot;

pub type PoolRejectedSnapshot = HashMap<TimeSlot, HashMap<RejectedReason, f64>>;

pub struct PoolRejectedAccumulator {
    inner: Mutex<NestedDeltaBuffer<TimeSlot, RejectedReason>>,
}

impl Default for PoolRejectedAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolRejectedAccumulator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NestedDeltaBuffer::new()),
        }
    }

    /// Record `count` shares rejected against `(slot, reason)`. Typical
    /// hot-path call has `count = 1.0`.
    pub fn add(&self, slot: TimeSlot, reason: RejectedReason, count: f64) {
        if !count.is_finite() || count <= 0.0 {
            return;
        }
        self.inner.lock().add(slot, reason, count);
    }

    pub fn drain(&self) -> PoolRejectedSnapshot {
        self.inner.lock().drain()
    }

    pub fn confirm(&self, snapshot: &PoolRejectedSnapshot) {
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
    fn add_groups_by_reason_then_slot() {
        let acc = PoolRejectedAccumulator::new();
        acc.add(slot(1_000), RejectedReason::JobNotFound, 1.0);
        acc.add(slot(1_000), RejectedReason::JobNotFound, 1.0);
        acc.add(slot(1_000), RejectedReason::LowDifficulty, 1.0);
        acc.add(slot(2_000), RejectedReason::DuplicateShare, 1.0);
        let snap = acc.drain();
        assert_eq!(
            snap.get(&slot(1_000))
                .unwrap()
                .get(&RejectedReason::JobNotFound),
            Some(&2.0)
        );
        assert_eq!(
            snap.get(&slot(1_000))
                .unwrap()
                .get(&RejectedReason::LowDifficulty),
            Some(&1.0)
        );
        assert_eq!(
            snap.get(&slot(2_000))
                .unwrap()
                .get(&RejectedReason::DuplicateShare),
            Some(&1.0)
        );
    }

    #[test]
    fn confirm_drops_empty_slots() {
        let acc = PoolRejectedAccumulator::new();
        acc.add(slot(1_000), RejectedReason::JobNotFound, 5.0);
        let snap = acc.drain();
        acc.confirm(&snap);
        assert!(acc.is_empty());
    }
}
