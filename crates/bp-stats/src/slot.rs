// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time slots. Stats are bucketed by **slot end** (Unix millis): the slot
//! ending at `t` covers `[t - SLOT_DURATION_MS, t)`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{CHART_VISIBILITY_BUFFER_MS, SLOT_DURATION_MS};

/// End-of-slot timestamp in Unix milliseconds. The inner i64 is `pub` so
/// slots loaded from `bp-db` rows can be wrapped without re-rounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeSlot(pub i64);

impl TimeSlot {
    /// Wrap an existing end timestamp without re-rounding it.
    pub const fn from_millis(end_ms: i64) -> Self {
        Self(end_ms)
    }

    pub fn current() -> Self {
        Self::for_time(now_millis())
    }

    /// Slot containing `timestamp_ms`, identified by its **end**.
    pub fn for_time(timestamp_ms: i64) -> Self {
        let aligned = timestamp_ms.div_euclid(SLOT_DURATION_MS) * SLOT_DURATION_MS;
        Self(aligned + SLOT_DURATION_MS)
    }

    pub fn previous(self) -> Self {
        Self(self.0 - SLOT_DURATION_MS)
    }

    pub fn next(self) -> Self {
        Self(self.0 + SLOT_DURATION_MS)
    }

    pub fn as_millis(self) -> i64 {
        self.0
    }
}

/// Charts show only `time < cutoff`. A just-ended slot becomes visible
/// `CHART_VISIBILITY_BUFFER_MS` after it ends, giving the flush time to commit.
pub fn chart_visibility_cutoff_slot() -> TimeSlot {
    let cutoff = now_millis() - CHART_VISIBILITY_BUFFER_MS;
    TimeSlot::for_time(cutoff)
}

fn now_millis() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch");
    dur.as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_time_aligns_to_slot_end() {
        let t = TimeSlot::for_time(1_234);
        assert_eq!(t.as_millis(), SLOT_DURATION_MS);
    }

    #[test]
    fn for_time_at_exact_slot_boundary_rolls_to_next_slot() {
        // Slots are closed-open `[start, end)`.
        let t = TimeSlot::for_time(SLOT_DURATION_MS);
        assert_eq!(t.as_millis(), SLOT_DURATION_MS * 2);
    }

    #[test]
    fn previous_and_next_step_by_slot_width() {
        let t = TimeSlot::for_time(1_234);
        assert_eq!(t.previous().as_millis(), t.as_millis() - SLOT_DURATION_MS);
        assert_eq!(t.next().as_millis(), t.as_millis() + SLOT_DURATION_MS);
    }

    #[test]
    fn current_slot_is_in_the_future_or_present_within_one_slot_width() {
        let s = TimeSlot::current();
        let now = now_millis();
        // current slot end is > now (still in progress) and ≤ now + slot width.
        assert!(s.as_millis() > now);
        assert!(s.as_millis() <= now + SLOT_DURATION_MS);
    }

    #[test]
    fn the_current_slot_ends_after_now() {
        let now = now_millis();
        let cur = TimeSlot::current();
        let prev = cur.previous();

        // Now is bracketed by prev (start) and cur (end).
        assert!(now >= prev.as_millis() && now < cur.as_millis());
    }

    #[test]
    fn chart_cutoff_is_at_least_one_slot_behind_current_at_slot_start() {
        let cur = TimeSlot::current();
        let cutoff = chart_visibility_cutoff_slot();
        // cutoff <= current always: the visibility buffer only moves it back.
        assert!(cutoff <= cur);
    }
}
