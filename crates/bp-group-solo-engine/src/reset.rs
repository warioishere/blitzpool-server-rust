// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled round reset at 00:00 in the group's TZ per `roundResetPreset`
//! (daily, weekly on Monday, monthly on the 1st, or `custom` gated by
//! `roundResetIntervalDays`). One loop serves every group and reads the
//! groups from Postgres on each tick. The reset wipes the round's shares and
//! rejects and stamps `lastRoundResetAt`; the dedup set and each member's
//! last accepted share stay.

use std::sync::Arc;
use std::time::Duration;

use bp_cron_utils::Clock;
use bp_db::{
    find_group, list_active_pplns_groups, update_pplns_group_last_reset_at, DbError, PplnsGroupRow,
};
use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use bp_group_mgmt::group::{PayoutMode, RoundResetPreset};

use crate::round::{GroupRoundStore, RoundError};

/// A scheduled reset is skipped if `lastRoundResetAt` is this recent,
/// so a double fire cannot wipe twice.
pub const RESET_DEBOUNCE_MS: i64 = 60_000;

/// Slack on the `custom` elapsed-check: across DST a day is 23 h or 25 h,
/// so without it an N-day schedule could miss its Nth daily fire.
pub const DST_TOLERANCE_MS: i64 = 12 * 60 * 60 * 1000;

/// How often the reset loop reads the groups: while it runs and Postgres
/// answers, a reset fires within this interval of its 00:00.
pub const RESET_POLL_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ResetError {
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("round: {0}")]
    Round(#[from] RoundError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("group {group_id} not found")]
    GroupNotFound { group_id: Uuid },
    #[error("invalid IANA timezone: {0:?}")]
    InvalidTimezone(String),
    #[error("invalid round-reset preset: {0:?}")]
    InvalidPreset(String),
}

// ── Preset + schedule config ───────────────────────────────────────

/// One group's reset schedule, derived from its `pplns_group` row.
#[derive(Clone, Debug)]
pub struct ResetSchedule {
    pub preset: RoundResetPreset,
    pub timezone: Tz,
    /// Only meaningful for `Custom`.
    pub interval_days: Option<u32>,
}

impl ResetSchedule {
    /// Construct from raw DB-row fields. Returns `Ok(None)` when there is
    /// nothing to schedule: no preset, no timezone, or `custom` without an
    /// interval.
    pub fn from_row_fields(
        preset: Option<&str>,
        timezone: Option<&str>,
        interval_days: Option<u32>,
    ) -> Result<Option<Self>, ResetError> {
        let Some(preset_str) = preset else {
            return Ok(None);
        };
        let Some(tz_str) = timezone else {
            return Ok(None);
        };
        let preset = RoundResetPreset::parse(preset_str)
            .ok_or_else(|| ResetError::InvalidPreset(preset_str.to_string()))?;
        let tz: Tz = tz_str
            .parse()
            .map_err(|_| ResetError::InvalidTimezone(tz_str.to_string()))?;
        if preset == RoundResetPreset::Custom && interval_days.unwrap_or(0) < 1 {
            return Ok(None);
        }
        Ok(Some(Self {
            preset,
            timezone: tz,
            interval_days,
        }))
    }
}

/// The calendar schedule the reset loop uses for `group`: only for a not
/// dissolved Prop group (a Window group's preset is its window length).
/// `Ok(None)` when its preset, timezone or interval make no schedule.
pub fn scheduled_reset(group: &PplnsGroupRow) -> Result<Option<ResetSchedule>, ResetError> {
    if group.dissolved_at.is_some() {
        return Ok(None);
    }
    match group.payout_mode {
        PayoutMode::Window => Ok(None),
        PayoutMode::Prop => ResetSchedule::from_row_fields(
            group.round_reset_preset.as_deref(),
            group.round_reset_timezone.as_deref(),
            group
                .round_reset_interval_days
                .and_then(|i| u32::try_from(i).ok()),
        ),
    }
}

// ── Next-fire computation ───────────────────────────────────────────

/// Next reset strictly after `now`, computed in the schedule's TZ. For
/// `custom`, the first daily fire at or after
/// `last_reset_at + interval - DST_TOLERANCE`.
pub fn compute_next_fire(
    schedule: &ResetSchedule,
    last_reset_at_ms: Option<i64>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    let now_local = now.with_timezone(&schedule.timezone);
    let mut candidate = next_calendar_fire_local(&schedule.preset, now_local);
    if schedule.preset == RoundResetPreset::Custom {
        if let Some(last_ms) = last_reset_at_ms {
            let interval_ms = schedule.interval_days.unwrap_or(0) as i64 * 86_400_000;
            let earliest_ms = last_ms + interval_ms - DST_TOLERANCE_MS;
            for _ in 0..(schedule.interval_days.unwrap_or(1) as i64 + 2) {
                if candidate.timestamp_millis() >= earliest_ms {
                    break;
                }
                candidate = next_day_midnight(candidate);
            }
        }
    }
    candidate.with_timezone(&Utc)
}

/// Whether the schedule's next fire after `since` has arrived by `now`. Each
/// fire falls in exactly one window of consecutive loop ticks.
pub fn is_due(
    schedule: &ResetSchedule,
    last_reset_at_ms: Option<i64>,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    compute_next_fire(schedule, last_reset_at_ms, since) <= now
}

/// Next 00:00 local time for the given preset, strictly after `now`.
fn next_calendar_fire_local(preset: &RoundResetPreset, now: DateTime<Tz>) -> DateTime<Tz> {
    match preset {
        RoundResetPreset::Daily | RoundResetPreset::Custom => next_midnight(now),
        RoundResetPreset::Weekly => next_monday_midnight(now),
        RoundResetPreset::Monthly => next_month_first_midnight(now),
    }
}

fn next_midnight(now: DateTime<Tz>) -> DateTime<Tz> {
    let today_midnight = local_midnight(now);
    if today_midnight > now {
        today_midnight
    } else {
        next_day_midnight(today_midnight)
    }
}

/// Midnight of the next calendar date. Steps by date, not by 24 h: a
/// 25-hour DST fall-back day would otherwise land on 23:00 of the same date.
fn next_day_midnight(base: DateTime<Tz>) -> DateTime<Tz> {
    let next_date = base
        .date_naive()
        .succ_opt()
        .expect("a date before chrono's maximum has a successor");
    midnight_on(base.timezone(), next_date)
}

fn local_midnight(day: DateTime<Tz>) -> DateTime<Tz> {
    midnight_on(day.timezone(), day.date_naive())
}

/// 00:00 local on `date`. Where a DST jump skips midnight (Chile springs
/// forward at 24:00), the first valid minute after it; where a fall-back
/// repeats it, the earlier of the two.
fn midnight_on(tz: Tz, date: NaiveDate) -> DateTime<Tz> {
    for minute in 0..=120 {
        if let Some(s) = tz
            .with_ymd_and_hms(
                date.year(),
                date.month(),
                date.day(),
                minute / 60,
                minute % 60,
                0,
            )
            .earliest()
        {
            return s;
        }
    }
    // No IANA zone skips two hours at midnight; fall back to UTC midnight.
    tz.from_utc_datetime(&date.and_time(NaiveTime::MIN))
}

fn next_monday_midnight(now: DateTime<Tz>) -> DateTime<Tz> {
    let mut candidate = next_midnight(now);
    while candidate.weekday() != Weekday::Mon {
        candidate = next_day_midnight(candidate);
    }
    candidate
}

fn next_month_first_midnight(now: DateTime<Tz>) -> DateTime<Tz> {
    let mut candidate = next_midnight(now);
    while candidate.day() != 1 {
        candidate = next_day_midnight(candidate);
    }
    candidate
}

// ── Reset action ────────────────────────────────────────────────────

/// Resets across Redis + PG, which cannot share a transaction: Redis is
/// wiped first and the PG stamp comes last.
pub struct GroupResetRunner<C: Clock> {
    pool: PgPool,
    round: GroupRoundStore,
    clock: Arc<C>,
}

impl<C: Clock> GroupResetRunner<C> {
    pub fn new(pool: PgPool, round: GroupRoundStore, clock: Arc<C>) -> Self {
        Self { pool, round, clock }
    }

    /// Run one scheduled reset; `Ok(false)` when debounced or the custom
    /// interval has not elapsed.
    pub async fn reset_scheduled(&self, group_id: Uuid) -> Result<bool, ResetError> {
        let group = find_group(&self.pool, group_id)
            .await?
            .ok_or(ResetError::GroupNotFound { group_id })?;
        let now_ms = self.clock.now().timestamp_millis();

        if let Some(last) = group.last_round_reset_at {
            if now_ms - last < RESET_DEBOUNCE_MS {
                debug!(
                    %group_id,
                    last_ms = last,
                    now_ms,
                    "scheduled reset debounced — last fire < 60s ago"
                );
                return Ok(false);
            }
        }

        // Custom-preset elapsed check. The reset loop gates already
        // (`is_due`); this keeps a standalone invocation from firing too early.
        if let (Some(preset_str), Some(interval_days)) = (
            group.round_reset_preset.as_deref(),
            group.round_reset_interval_days,
        ) {
            if preset_str == "custom" && interval_days > 0 {
                let interval_ms = interval_days as i64 * 86_400_000;
                let due_threshold = interval_ms - DST_TOLERANCE_MS;
                let elapsed = group
                    .last_round_reset_at
                    .map(|l| now_ms - l)
                    .unwrap_or(i64::MAX);
                if elapsed < due_threshold {
                    debug!(
                        %group_id,
                        elapsed_ms = elapsed,
                        due_threshold_ms = due_threshold,
                        "custom-preset reset skipped — interval not elapsed"
                    );
                    return Ok(false);
                }
            }
        }

        let group_key = group_id.to_string();

        self.round.reset_for_calendar(&group_key).await?;
        // Stamp last so the debounce on the next tick reads the fresh value.
        update_pplns_group_last_reset_at(&self.pool, group_id, now_ms).await?;

        info!(%group_id, "group-solo scheduled round-reset applied");
        Ok(true)
    }

    /// Reset every group whose scheduled 00:00 fell in `(since, now]`. Each
    /// group's schedule comes from its current row, so a settings change or
    /// a dissolve applies here whichever process wrote it. `Err` only when
    /// the groups could not be read; a failed single reset is logged.
    pub async fn reset_due_groups(
        &self,
        since: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), ResetError> {
        for group in list_active_pplns_groups(&self.pool).await? {
            match scheduled_reset(&group) {
                Ok(Some(schedule)) => {
                    if is_due(&schedule, group.last_round_reset_at, since, now) {
                        if let Err(e) = self.reset_scheduled(group.id).await {
                            warn!(group_id = %group.id, error = %e, "round-reset firing failed");
                        }
                    }
                }
                Ok(None) => {}
                // Only a row the settings validator did not write gets here,
                // and the loop reads it every tick, hence debug.
                Err(e) => {
                    debug!(group_id = %group.id, error = %e, "invalid round-reset schedule; group skipped");
                }
            }
        }
        Ok(())
    }
}

// Manual Clone: the derive would require `C: Clone`.
impl<C: Clock> Clone for GroupResetRunner<C> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            round: self.round.clone(),
            clock: self.clock.clone(),
        }
    }
}

// ── Background loop ─────────────────────────────────────────────────

/// The one reset loop: every [`RESET_POLL_INTERVAL`] it resets the groups
/// whose 00:00 passed since the previous tick. A failed read of the groups
/// keeps that window open, so the next tick still sees its fires.
pub fn spawn_reset_loop<C: Clock>(
    runner: GroupResetRunner<C>,
    mut cancel_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!("group-solo round-reset loop started");
        let mut since = runner.clock.now();
        loop {
            if wait_or_cancel(RESET_POLL_INTERVAL, &mut cancel_rx).await {
                info!("group-solo round-reset loop stopped");
                return;
            }
            let now = runner.clock.now();
            match runner.reset_due_groups(since, now).await {
                Ok(()) => since = now,
                Err(e) => {
                    warn!(error = %e, "round-reset loop: reading the groups failed; retrying next tick");
                }
            }
        }
    })
}

async fn wait_or_cancel(wait: Duration, cancel_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(wait) => false,
        changed = cancel_rx.changed() => changed.is_err() || *cancel_rx.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use chrono_tz::{
        Europe::{Vienna, Zurich},
        UTC,
    };

    fn at_utc(year: i32, month: u32, day: u32, hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
    }

    fn schedule(preset: RoundResetPreset, tz: Tz, interval_days: Option<u32>) -> ResetSchedule {
        ResetSchedule {
            preset,
            timezone: tz,
            interval_days,
        }
    }

    /// `compute_next_fire` on its own thread, failed after a second instead
    /// of hanging the test run when it does not return.
    fn next_fire_or_fail(
        schedule: ResetSchedule,
        last_reset_at_ms: Option<i64>,
        now: DateTime<Utc>,
    ) -> DateTime<Utc> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(compute_next_fire(&schedule, last_reset_at_ms, now));
        });
        rx.recv_timeout(std::time::Duration::from_secs(1))
            .expect("compute_next_fire did not return")
    }

    fn at_utc_ms(s: &str) -> DateTime<Utc> {
        s.parse().expect("valid RFC 3339 instant")
    }

    // 2026-10-25 is a 25-hour day in Central Europe (CEST → CET). Every
    // preset has to step across it to the next calendar midnight.

    #[test]
    fn monthly_across_the_dst_fall_back_lands_on_the_first() {
        let now = at_utc_ms("2026-09-30T22:00:00.060Z"); // 1 Oct 00:00 Vienna
        let next = next_fire_or_fail(schedule(RoundResetPreset::Monthly, Vienna, None), None, now);
        assert_eq!(next, at_utc(2026, 10, 31, 23, 0)); // 1 Nov 00:00 CET
    }

    #[test]
    fn weekly_across_the_dst_fall_back_lands_on_monday() {
        let now = at_utc_ms("2026-10-18T22:00:00.060Z"); // Mon 19 Oct 00:00 Zurich
        let next = next_fire_or_fail(schedule(RoundResetPreset::Weekly, Zurich, None), None, now);
        assert_eq!(next, at_utc(2026, 10, 25, 23, 0)); // Mon 26 Oct 00:00 CET
    }

    #[test]
    fn daily_on_the_dst_fall_back_day_moves_to_the_next_day() {
        let now = at_utc_ms("2026-10-24T22:00:00.060Z"); // 25 Oct 00:00 Zurich
        let next = next_fire_or_fail(schedule(RoundResetPreset::Daily, Zurich, None), None, now);
        assert_eq!(next, at_utc(2026, 10, 25, 23, 0)); // 26 Oct 00:00 CET
    }

    #[test]
    fn custom_across_the_dst_fall_back_fires_at_local_midnight() {
        let last = at_utc_ms("2026-10-24T22:00:00Z"); // 25 Oct 00:00 Zurich
        let now = at_utc_ms("2026-10-24T22:00:00.060Z");
        let next = next_fire_or_fail(
            schedule(RoundResetPreset::Custom, Zurich, Some(1)),
            Some(last.timestamp_millis()),
            now,
        );
        assert_eq!(next, at_utc(2026, 10, 25, 23, 0)); // 26 Oct 00:00 CET
    }

    #[test]
    fn preset_from_wire_strings() {
        assert_eq!(
            RoundResetPreset::parse("daily").unwrap(),
            RoundResetPreset::Daily
        );
        assert_eq!(
            RoundResetPreset::parse("weekly").unwrap(),
            RoundResetPreset::Weekly
        );
        assert_eq!(
            RoundResetPreset::parse("monthly").unwrap(),
            RoundResetPreset::Monthly
        );
        assert_eq!(
            RoundResetPreset::parse("custom").unwrap(),
            RoundResetPreset::Custom
        );
        assert!(RoundResetPreset::parse("hourly").is_none());
    }

    #[test]
    fn reset_schedule_from_row_handles_missing_fields() {
        assert!(ResetSchedule::from_row_fields(None, Some("UTC"), None)
            .unwrap()
            .is_none());
        assert!(ResetSchedule::from_row_fields(Some("daily"), None, None)
            .unwrap()
            .is_none());
        assert!(
            ResetSchedule::from_row_fields(Some("custom"), Some("UTC"), Some(0))
                .unwrap()
                .is_none(),
        );
        let sched = ResetSchedule::from_row_fields(Some("daily"), Some("UTC"), None)
            .unwrap()
            .unwrap();
        assert_eq!(sched.preset, RoundResetPreset::Daily);
    }

    #[test]
    fn next_fire_daily_in_utc() {
        let s = schedule(RoundResetPreset::Daily, UTC, None);
        // At 12:00 UTC → next 00:00 UTC (tomorrow).
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 17, 0, 0));
    }

    #[test]
    fn next_fire_daily_in_zurich_tz() {
        let s = schedule(RoundResetPreset::Daily, Zurich, None);
        // CEST: 00:00 local is 22:00 UTC the day before.
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 16, 22, 0));
    }

    #[test]
    fn next_fire_weekly_lands_on_monday() {
        let s = schedule(RoundResetPreset::Weekly, UTC, None);
        // 2026-05-16 = Saturday. Next Monday = 2026-05-18.
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 18, 0, 0));
        let dt_local = next.with_timezone(&UTC);
        assert_eq!(dt_local.weekday(), Weekday::Mon);
    }

    #[test]
    fn next_fire_monthly_lands_on_first() {
        let s = schedule(RoundResetPreset::Monthly, UTC, None);
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 6, 1, 0, 0));
    }

    #[test]
    fn next_fire_custom_no_last_reset_fires_at_next_midnight() {
        let s = schedule(RoundResetPreset::Custom, UTC, Some(7));
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 17, 0, 0));
    }

    #[test]
    fn next_fire_custom_with_recent_last_reset_skips_until_interval_elapsed() {
        let s = schedule(RoundResetPreset::Custom, UTC, Some(7));
        let now = at_utc(2026, 5, 16, 12, 0);
        let last_ms = (now - ChronoDuration::days(2)).timestamp_millis();
        let next = compute_next_fire(&s, Some(last_ms), now);
        let last_dt = now - ChronoDuration::days(2);
        let earliest = last_dt + ChronoDuration::days(7) - ChronoDuration::hours(12);
        assert!(
            next >= earliest,
            "next ({next}) should be ≥ earliest-due ({earliest})"
        );
    }

    /// On a day without 00:00 (Chile springs forward at 24:00) the next fire
    /// is the following midnight; the precondition pins the gap exists.
    #[test]
    fn next_fire_on_a_day_without_midnight_does_not_panic() {
        use chrono_tz::America::Santiago;
        assert!(
            Santiago
                .with_ymd_and_hms(2026, 9, 6, 0, 0, 0)
                .single()
                .is_none(),
            "precondition: 2026-09-06 00:00 does not exist in America/Santiago"
        );
        let s = schedule(RoundResetPreset::Daily, Santiago, None);
        // 12:00 local on the gap day (UTC-3 after the jump).
        let now = at_utc(2026, 9, 6, 15, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 9, 7, 3, 0));
    }

    /// A 30 s tick window around 00:00 is due once, the next window is not.
    #[test]
    fn a_fire_is_due_in_exactly_one_tick_window() {
        let s = schedule(RoundResetPreset::Daily, UTC, None);
        let before = at_utc(2026, 5, 16, 23, 59) + ChronoDuration::seconds(40);
        let after = at_utc(2026, 5, 17, 0, 0) + ChronoDuration::seconds(10);
        let later = after + ChronoDuration::seconds(30);
        assert!(is_due(&s, None, before, after), "the window holding 00:00");
        assert!(!is_due(&s, None, after, later), "the following window");
        assert!(!is_due(
            &s,
            None,
            before - ChronoDuration::seconds(30),
            before
        ));
    }

    /// Weekly fires only on Monday: the same Tuesday window is due for a
    /// daily group and not for a weekly one.
    #[test]
    fn the_preset_on_the_row_decides_whether_a_window_is_due() {
        // 2026-05-19 is a Tuesday.
        let since = at_utc(2026, 5, 18, 23, 59) + ChronoDuration::seconds(40);
        let now = at_utc(2026, 5, 19, 0, 0) + ChronoDuration::seconds(10);
        let daily = schedule(RoundResetPreset::Daily, UTC, None);
        let weekly = schedule(RoundResetPreset::Weekly, UTC, None);
        assert!(is_due(&daily, None, since, now));
        assert!(!is_due(&weekly, None, since, now));
    }

    #[test]
    fn a_custom_window_is_due_only_once_the_interval_elapsed() {
        let s = schedule(RoundResetPreset::Custom, UTC, Some(3));
        let since = at_utc(2026, 5, 16, 23, 59) + ChronoDuration::seconds(40);
        let now = at_utc(2026, 5, 17, 0, 0) + ChronoDuration::seconds(10);
        let one_day_ago = at_utc(2026, 5, 16, 0, 0).timestamp_millis();
        let three_days_ago = at_utc(2026, 5, 14, 0, 0).timestamp_millis();
        assert!(!is_due(&s, Some(one_day_ago), since, now));
        assert!(is_due(&s, Some(three_days_ago), since, now));
    }

    fn group_row(
        preset: Option<&str>,
        payout_mode: &str,
        dissolved_at: Option<i64>,
    ) -> PplnsGroupRow {
        PplnsGroupRow {
            id: Uuid::new_v4(),
            name: "g".to_string(),
            creator_address: bp_common::AddressId::new("creator".to_string()).unwrap(),
            admin_token_hash: "hash".to_string(),
            created_at: 0,
            updated_at: 0,
            dissolved_at,
            round_reset_interval_days: None,
            round_reset_timezone: Some("UTC".to_string()),
            last_round_reset_at: None,
            finder_bonus_ppm: None,
            round_reset_preset: preset.map(str::to_string),
            is_public: false,
            reset_round_on_block: false,
            max_members: None,
            payout_mode: payout_mode.parse().unwrap(),
            coinbase_tag: None,
        }
    }

    /// The loop takes each group's schedule from its current row: a dissolved
    /// group, a cleared preset and a Window group have none.
    #[test]
    fn only_a_live_prop_group_with_a_preset_has_a_schedule() {
        assert!(scheduled_reset(&group_row(Some("daily"), "prop", None))
            .unwrap()
            .is_some());
        assert!(scheduled_reset(&group_row(Some("daily"), "prop", Some(1)))
            .unwrap()
            .is_none());
        assert!(scheduled_reset(&group_row(None, "prop", None))
            .unwrap()
            .is_none());
        assert!(scheduled_reset(&group_row(Some("daily"), "window", None))
            .unwrap()
            .is_none());
    }

    #[test]
    fn reset_runner_is_cloneable_without_c_clone_bound() {
        // Compile-time check: the manual Clone impl works for a non-Clone C.
        fn _accepts<C: Clock>(r: GroupResetRunner<C>) -> GroupResetRunner<C> {
            r.clone()
        }
    }
}
