// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time source ([`Clock`], steppable [`TestClock`]) and scheduling helpers
//! shared by the cron-driven engines.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

// ── Clock abstraction ──────────────────────────────────────────────

/// Time source returning `chrono::DateTime<Utc>`, unlike the epoch-ms
/// `bp-vardiff::Clock`, because cron scheduling is calendar-aligned.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Manually stepped clock; clones share one time.
#[derive(Clone)]
pub struct TestClock {
    now: Arc<Mutex<DateTime<Utc>>>,
}

impl TestClock {
    pub fn new(at: DateTime<Utc>) -> Self {
        Self {
            now: Arc::new(Mutex::new(at)),
        }
    }

    pub fn set(&self, at: DateTime<Utc>) {
        *self.now.lock().expect("test clock poisoned") = at;
    }

    pub fn advance(&self, delta: chrono::Duration) {
        let mut now = self.now.lock().expect("test clock poisoned");
        *now += delta;
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().expect("test clock poisoned")
    }
}

// ── next_3am_utc ───────────────────────────────────────────────────

/// The next 03:00 UTC strictly after `now`; at exactly 03:00 it returns
/// tomorrow's, so a loop cannot re-fire on clock jitter.
pub fn next_3am_utc(now: DateTime<Utc>) -> DateTime<Utc> {
    let today = NaiveDate::from_ymd_opt(now.year(), now.month(), now.day())
        .expect("naive-date from valid year/month/day");
    let three_am = NaiveTime::from_hms_opt(3, 0, 0).expect("3am is a valid time");
    let today_3am = Utc.from_utc_datetime(&NaiveDateTime::new(today, three_am));
    if today_3am > now {
        today_3am
    } else {
        today_3am + chrono::Duration::days(1)
    }
}

// ── BlockHeightGen ─────────────────────────────────────────────────

/// Strictly decreasing synthetic negative `blockHeight` (`-(unix_seconds)`)
/// for audit rows such as dust sweeps. They share the history tables'
/// `(blockHeight, …)` UNIQUE index, so they must collide neither with real
/// heights nor with each other on sub-second re-triggers.
#[derive(Debug, Default)]
pub struct BlockHeightGen {
    last: Mutex<Option<i32>>,
}

impl BlockHeightGen {
    pub fn new() -> Self {
        Self::default()
    }

    /// Next synthetic `blockHeight`; a re-call within the same second steps
    /// back from the previous value to stay unique.
    pub fn next(&self, now: DateTime<Utc>) -> i32 {
        let candidate = -(now.timestamp() as i32);
        let mut last = self.last.lock().expect("block-height-gen poisoned");
        let next = match *last {
            Some(prev) if candidate >= prev => prev - 1,
            _ => candidate,
        };
        *last = Some(next);
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(year: i32, month: u32, day: u32, hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
    }

    #[test]
    fn test_clock_stores_and_returns_set_time() {
        let t0 = at(2026, 5, 16, 12, 0);
        let c = TestClock::new(t0);
        assert_eq!(c.now(), t0);
        let t1 = at(2026, 5, 17, 3, 0);
        c.set(t1);
        assert_eq!(c.now(), t1);
    }

    #[test]
    fn test_clock_advance_works() {
        let c = TestClock::new(at(2026, 5, 16, 12, 0));
        c.advance(chrono::Duration::hours(5));
        assert_eq!(c.now(), at(2026, 5, 16, 17, 0));
    }

    #[test]
    fn test_clock_clone_shares_state() {
        let c1 = TestClock::new(at(2026, 5, 16, 12, 0));
        let c2 = c1.clone();
        c1.set(at(2026, 5, 17, 0, 0));
        assert_eq!(c2.now(), at(2026, 5, 17, 0, 0));
    }

    #[test]
    fn next_3am_before_returns_today() {
        let now = at(2026, 5, 16, 1, 30);
        assert_eq!(next_3am_utc(now), at(2026, 5, 16, 3, 0));
    }

    #[test]
    fn next_3am_after_returns_tomorrow() {
        let now = at(2026, 5, 16, 3, 30);
        assert_eq!(next_3am_utc(now), at(2026, 5, 17, 3, 0));
    }

    #[test]
    fn next_3am_exactly_at_3am_returns_tomorrow() {
        let now = at(2026, 5, 16, 3, 0);
        assert_eq!(next_3am_utc(now), at(2026, 5, 17, 3, 0));
    }

    #[test]
    fn next_3am_month_rollover() {
        let now = at(2026, 5, 31, 23, 59);
        assert_eq!(next_3am_utc(now), at(2026, 6, 1, 3, 0));
    }

    #[test]
    fn block_height_first_call_uses_neg_unix_seconds() {
        let gen = BlockHeightGen::new();
        let now = at(2026, 5, 16, 3, 0);
        let h = gen.next(now);
        assert_eq!(h, -(now.timestamp() as i32));
    }

    #[test]
    fn block_height_sub_second_re_trigger_steps_back() {
        let gen = BlockHeightGen::new();
        let now = at(2026, 5, 16, 3, 0);
        let h1 = gen.next(now);
        let h2 = gen.next(now);
        let h3 = gen.next(now);
        assert_eq!(h2, h1 - 1);
        assert_eq!(h3, h1 - 2);
    }

    #[test]
    fn block_height_advances_when_clock_advances() {
        let gen = BlockHeightGen::new();
        let t1 = at(2026, 5, 16, 3, 0);
        let t2 = t1 + chrono::Duration::seconds(5);
        let h1 = gen.next(t1);
        let h2 = gen.next(t2);
        assert!(h2 < h1);
        assert_eq!(h2, -(t2.timestamp() as i32));
    }
}
