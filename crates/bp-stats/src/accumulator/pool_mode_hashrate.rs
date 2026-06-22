// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-slot per-mode pool hashrate, in difficulty-1 units.

use parking_lot::Mutex;
use std::collections::HashMap;

use bp_common::MiningMode;

use crate::buffer::NestedDeltaBuffer;
use crate::constants::MAX_REASONABLE_DIFFICULTY;
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

    /// Record `diff` worth of share against `(slot, mode)`. Non-finite or
    /// out-of-range values are silently discarded.
    pub fn add(&self, slot: TimeSlot, mode: MiningMode, diff: f64) {
        if !diff.is_finite() || diff <= 0.0 || diff > MAX_REASONABLE_DIFFICULTY {
            return;
        }
        self.inner.lock().add(slot, mode, diff);
    }

    pub fn drain(&self) -> PoolModeHashrateSnapshot {
        self.inner.lock().drain()
    }

    pub fn confirm(&self, snapshot: &PoolModeHashrateSnapshot) {
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
    fn add_and_drain_groups_by_slot_then_mode() {
        let acc = PoolModeHashrateAccumulator::new();
        acc.add(slot(1_000), MiningMode::Solo, 100.0);
        acc.add(slot(1_000), MiningMode::Pplns, 50.0);
        acc.add(slot(1_000), MiningMode::Solo, 25.0);
        acc.add(slot(2_000), MiningMode::GroupSolo, 7.0);
        let snap = acc.drain();
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
    fn confirm_drops_empty_slots() {
        let acc = PoolModeHashrateAccumulator::new();
        acc.add(slot(1_000), MiningMode::Solo, 100.0);
        let snap = acc.drain();
        acc.confirm(&snap);
        assert!(acc.is_empty());
    }

    #[test]
    fn over_range_and_non_finite_are_discarded() {
        let acc = PoolModeHashrateAccumulator::new();
        acc.add(
            slot(1_000),
            MiningMode::Solo,
            MAX_REASONABLE_DIFFICULTY * 2.0,
        );
        acc.add(slot(1_000), MiningMode::Solo, f64::NAN);
        acc.add(slot(1_000), MiningMode::Solo, 0.0);
        assert!(acc.is_empty());
    }
}
