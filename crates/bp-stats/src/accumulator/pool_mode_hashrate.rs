// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-slot per-mode pool hashrate, in difficulty-1 units.

use parking_lot::Mutex;
use std::collections::HashMap;

use bp_common::MiningMode;

use crate::buffer::NestedDeltaBuffer;
use crate::slot::TimeSlot;

pub type PoolModeHashrateSnapshot = HashMap<TimeSlot, HashMap<MiningMode, f64>>;

pub struct PoolModeHashrateAccumulator {
    inner: Mutex<NestedDeltaBuffer<TimeSlot, MiningMode>>,
}

impl Default for PoolModeHashrateAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolModeHashrateAccumulator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NestedDeltaBuffer::new()),
        }
    }

    pub fn add(&self, slot: TimeSlot, mode: MiningMode, diff: f64) {
        self.inner.lock().add(slot, mode, diff);
    }

    /// Empty the accumulator for a flush.
    pub fn take(&self) -> PoolModeHashrateSnapshot {
        self.inner.lock().take()
    }

    /// Hand back an unwritten [`Self::take`].
    pub fn restore(&self, snapshot: PoolModeHashrateSnapshot) {
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
    fn add_and_take_groups_by_slot_then_mode() {
        let acc = PoolModeHashrateAccumulator::new();
        acc.add(slot(1_000), MiningMode::Solo, 100.0);
        acc.add(slot(1_000), MiningMode::Pplns, 50.0);
        acc.add(slot(1_000), MiningMode::Solo, 25.0);
        acc.add(slot(2_000), MiningMode::GroupSolo, 7.0);
        let snap = acc.take();
        assert_eq!(
            snap.get(&slot(1_000)).unwrap().get(&MiningMode::Solo),
            Some(&125.0)
        );
        assert_eq!(
            snap.get(&slot(1_000)).unwrap().get(&MiningMode::Pplns),
            Some(&50.0)
        );
        assert_eq!(
            snap.get(&slot(2_000)).unwrap().get(&MiningMode::GroupSolo),
            Some(&7.0)
        );
    }

    #[test]
    fn take_empties_and_restore_hands_back() {
        let acc = PoolModeHashrateAccumulator::new();
        acc.add(slot(1_000), MiningMode::Solo, 100.0);
        let snap = acc.take();
        assert!(acc.is_empty());
        acc.restore(snap);
        assert_eq!(acc.len(), 1);
    }
}
