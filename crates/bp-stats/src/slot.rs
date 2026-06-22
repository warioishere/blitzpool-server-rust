// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time-slot bookkeeping.
//!
//! All stats are bucketed by **slot end** timestamp (Unix millis). A 10-min
//! slot ending at `t` covers `[t - SLOT_DURATION_MS, t)`. Slots are
//! produced by floor-rounding `now` and adding one slot width.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{CHART_VISIBILITY_BUFFER_MS, SLOT_DURATION_MS};

/// Time slot — end-of-slot timestamp in Unix milliseconds.
///
/// Constructed via [`TimeSlot::current`], [`TimeSlot::for_time`] or
/// [`TimeSlot::from_millis`]. The inner i64 is `pub` so callers that
/// receive a slot from `bp-db` rows can wrap directly without going
/// through the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeSlot(pub i64);

impl TimeSlot {
    /// Wrap an existing Unix-millis end timestamp without re-rounding it.
    /// Used by code that loads slots from PG.
    pub const fn from_millis(end_ms: i64) -> Self {
        Self(end_ms)
    }

    /// Current slot for `now()`. Calls the system clock.
    pub fn current() -> Self {
        Self::for_time(now_millis())
    }

    /// Slot that contains `timestamp_ms`. Floor-rounds and adds one slot
    /// width so the result is the slot's **end**.
    pub fn for_time(timestamp_ms: i64) -> Self {
        let aligned = timestamp_ms.div_euclid(SLOT_DURATION_MS) * SLOT_DURATION_MS;
        Self(aligned + SLOT_DURATION_MS)
    }

    /// Previous slot relative to `self`.
    pub fn previous(self) -> Self {
        Self(self.0 - SLOT_DURATION_MS)
    }

    /// Next slot relative to `self`.
    pub fn next(self) -> Self {
        Self(self.0 + SLOT_DURATION_MS)
    }

    /// `true` if `self` is older than the current slot (i.e. fully past).
    pub fn is_complete(self) -> bool {
        self < Self::current()
    }

    /// `true` if `self` is the current (in-progress) slot.
    pub fn is_current(self) -> bool {
        self == Self::current()
    }

    /// Inner millis.
    pub fn as_millis(self) -> i64 {
        self.0
    }
}

/// The chart-visibility cutoff: chart consumers filter `time < cutoff`.
/// A just-ended slot only crosses the threshold once
/// `now >= slot_end + CHART_VISIBILITY_BUFFER_MS`, giving the flush a
/// fixed window to commit. Computed against system time.
pub fn chart_visibility_cutoff_slot() -> TimeSlot {
    let cutoff = now_millis() - CHART_VISIBILITY_BUFFER_MS;
    TimeSlot::for_time(cutoff)
}

fn now_millis() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch");
    // i128 → i64 conversion can't overflow until year 292 277 026 596 AD.
    dur.as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_time_aligns_to_slot_end() {
        // 10-min slot width = 600_000 ms. A timestamp at 1234 ms falls in
        // the slot ending at 600_000.
        let t = TimeSlot::for_time(1_234);
        assert_eq!(t.as_millis(), SLOT_DURATION_MS);
    }

    #[test]
    fn for_time_at_exact_slot_boundary_rolls_to_next_slot() {
        // Timestamp exactly at a slot boundary lands in the NEXT slot
        // (closed-open interval [start, end)).
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
        // current slot end is > now (we're still in it) and ≤ now + slot width.
        assert!(s.as_millis() > now);
        assert!(s.as_millis() <= now + SLOT_DURATION_MS);
    }

    #[test]
    fn is_complete_and_is_current() {
        let now = now_millis();
        let cur = TimeSlot::current();
        let prev = cur.previous();
        let future = cur.next();

        assert!(cur.is_current());
        assert!(!cur.is_complete());

        assert!(!prev.is_current());
        assert!(prev.is_complete());

        assert!(!future.is_current());
        assert!(!future.is_complete());

        // Sanity: now is bracketed by prev (start) and cur (end).
        assert!(now >= prev.as_millis() && now < cur.as_millis());
    }

    #[test]
    fn chart_cutoff_is_at_least_one_slot_behind_current_at_slot_start() {
        let cur = TimeSlot::current();
        let cutoff = chart_visibility_cutoff_slot();
        // cutoff <= current always — the visibility buffer can't push us
        // forward.
        assert!(cutoff <= cur);
    }
}
