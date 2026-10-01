// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled round-reset cron: fires at 00:00 in the group's TZ per
//! `roundResetPreset` (daily, weekly on Monday, monthly on the 1st, or
//! `custom` gated by `roundResetIntervalDays`). Wipes the full round except
//! the dedup set and stamps `lastRoundResetAt`.

use std::sync::Arc;
use std::time::Duration;

use bp_cron_utils::Clock;
use bp_db::{find_group, update_pplns_group_last_reset_at, DbError};
use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::round::snapshot::delete_all_for_group;
use crate::round::{GroupRoundStore, RoundError};

/// A scheduled reset is skipped if `lastRoundResetAt` is this recent,
/// so a double fire cannot wipe twice.
pub const RESET_DEBOUNCE_MS: i64 = 60_000;

/// Slack on the `custom` elapsed-check: across DST a day is 23 h or 25 h,
/// so without it an N-day cron could miss its Nth daily fire.
pub const DST_TOLERANCE_MS: i64 = 12 * 60 * 60 * 1000;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Daily,
    Weekly,
    Monthly,
    Custom,
}

impl Preset {
    pub fn from_wire(s: &str) -> Result<Self, ResetError> {
        match s {
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            "monthly" => Ok(Self::Monthly),
            "custom" => Ok(Self::Custom),
            other => Err(ResetError::InvalidPreset(other.to_string())),
        }
    }
}

/// Snapshot of one group's reset schedule, derived from its
/// `pplns_group` row at the time the cron task is spawned.
#[derive(Clone, Debug)]
pub struct ResetSchedule {
    pub group_id: Uuid,
    pub preset: Preset,
    pub timezone: Tz,
    /// Only meaningful for `Custom`.
    pub interval_days: Option<u32>,
}

impl ResetSchedule {
    /// Construct from raw DB-row fields. Returns `Ok(None)` when there is
    /// nothing to schedule: no preset, no timezone, or `custom` without an
    /// interval.
    pub fn from_row_fields(
        group_id: Uuid,
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
        let preset = Preset::from_wire(preset_str)?;
        let tz: Tz = tz_str
            .parse()
            .map_err(|_| ResetError::InvalidTimezone(tz_str.to_string()))?;
        if preset == Preset::Custom && interval_days.unwrap_or(0) < 1 {
            return Ok(None);
        }
        Ok(Some(Self {
            group_id,
            preset,
            timezone: tz,
            interval_days,
        }))
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
    if schedule.preset == Preset::Custom {
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

/// Next 00:00 local time for the given preset, strictly after `now`.
fn next_calendar_fire_local(preset: &Preset, now: DateTime<Tz>) -> DateTime<Tz> {
    match preset {
        Preset::Daily | Preset::Custom => next_midnight(now),
        Preset::Weekly => next_monday_midnight(now),
        Preset::Monthly => next_month_first_midnight(now),
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

        // Custom-preset elapsed check. The cron task gates already; this
        // keeps a standalone invocation from firing too early.
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

        self.round.reset_full(&group_key).await?;
        let mut conn = self.round.connection_for_snapshot();
        delete_all_for_group(&mut conn, &group_key).await?;
        // Stamp last so the debounce on the next tick reads the fresh value.
        update_pplns_group_last_reset_at(&self.pool, group_id, now_ms).await?;

        info!(%group_id, "group-solo scheduled round-reset applied");
        Ok(true)
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

// ── Background cron task ────────────────────────────────────────────

/// Spawn a per-group cron that sleeps to the next fire, resets, loops. The
/// schedule is captured at spawn, so a config change re-spawns the task.
pub fn spawn_per_group_task<C: Clock>(
    runner: GroupResetRunner<C>,
    schedule: ResetSchedule,
    mut cancel_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let group_id = schedule.group_id;
        info!(
            %group_id,
            preset = ?schedule.preset,
            tz = %schedule.timezone,
            interval_days = ?schedule.interval_days,
            "spawned group-solo round-reset cron"
        );
        loop {
            // Fresh lastResetAt so the next fire matches the runner's gates.
            let last_ms = match find_group(&runner.pool, group_id).await {
                Ok(Some(g)) => g.last_round_reset_at,
                Ok(None) => {
                    info!(%group_id, "group dissolved — round-reset cron exits");
                    return;
                }
                Err(e) => {
                    warn!(%group_id, error = %e, "round-reset cron: find_group failed; retrying in 60s");
                    if wait_or_cancel(Duration::from_secs(60), &mut cancel_rx).await {
                        return;
                    }
                    continue;
                }
            };
            let now = runner.clock.now();
            let next = compute_next_fire(&schedule, last_ms, now);
            let wait = (next - now).to_std().unwrap_or(Duration::from_secs(60));

            if wait_or_cancel(wait, &mut cancel_rx).await {
                info!(%group_id, "round-reset cron cancelled");
                return;
            }
            match runner.reset_scheduled(group_id).await {
                Ok(true) => {} // logged in runner
                Ok(false) => debug!(%group_id, "round-reset skipped by debounce / elapsed-gate"),
                Err(e) => warn!(%group_id, error = %e, "round-reset firing failed"),
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

    fn schedule(preset: Preset, tz: Tz, interval_days: Option<u32>) -> ResetSchedule {
        ResetSchedule {
            group_id: Uuid::new_v4(),
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
        let next = next_fire_or_fail(schedule(Preset::Monthly, Vienna, None), None, now);
        assert_eq!(next, at_utc(2026, 10, 31, 23, 0)); // 1 Nov 00:00 CET
    }

    #[test]
    fn weekly_across_the_dst_fall_back_lands_on_monday() {
        let now = at_utc_ms("2026-10-18T22:00:00.060Z"); // Mon 19 Oct 00:00 Zurich
        let next = next_fire_or_fail(schedule(Preset::Weekly, Zurich, None), None, now);
        assert_eq!(next, at_utc(2026, 10, 25, 23, 0)); // Mon 26 Oct 00:00 CET
    }

    #[test]
    fn daily_on_the_dst_fall_back_day_moves_to_the_next_day() {
        let now = at_utc_ms("2026-10-24T22:00:00.060Z"); // 25 Oct 00:00 Zurich
        let next = next_fire_or_fail(schedule(Preset::Daily, Zurich, None), None, now);
        assert_eq!(next, at_utc(2026, 10, 25, 23, 0)); // 26 Oct 00:00 CET
    }

    #[test]
    fn custom_across_the_dst_fall_back_fires_at_local_midnight() {
        let last = at_utc_ms("2026-10-24T22:00:00Z"); // 25 Oct 00:00 Zurich
        let now = at_utc_ms("2026-10-24T22:00:00.060Z");
        let next = next_fire_or_fail(
            schedule(Preset::Custom, Zurich, Some(1)),
            Some(last.timestamp_millis()),
            now,
        );
        assert_eq!(next, at_utc(2026, 10, 25, 23, 0)); // 26 Oct 00:00 CET
    }

    #[test]
    fn preset_from_wire_strings() {
        assert_eq!(Preset::from_wire("daily").unwrap(), Preset::Daily);
        assert_eq!(Preset::from_wire("weekly").unwrap(), Preset::Weekly);
        assert_eq!(Preset::from_wire("monthly").unwrap(), Preset::Monthly);
        assert_eq!(Preset::from_wire("custom").unwrap(), Preset::Custom);
        assert!(Preset::from_wire("hourly").is_err());
    }

    #[test]
    fn reset_schedule_from_row_handles_missing_fields() {
        let g = Uuid::new_v4();
        assert!(ResetSchedule::from_row_fields(g, None, Some("UTC"), None)
            .unwrap()
            .is_none());
        assert!(ResetSchedule::from_row_fields(g, Some("daily"), None, None)
            .unwrap()
            .is_none());
        assert!(
            ResetSchedule::from_row_fields(g, Some("custom"), Some("UTC"), Some(0))
                .unwrap()
                .is_none(),
        );
        let sched = ResetSchedule::from_row_fields(g, Some("daily"), Some("UTC"), None)
            .unwrap()
            .unwrap();
        assert_eq!(sched.preset, Preset::Daily);
    }

    #[test]
    fn next_fire_daily_in_utc() {
        let s = schedule(Preset::Daily, UTC, None);
        // At 12:00 UTC → next 00:00 UTC (tomorrow).
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 17, 0, 0));
    }

    #[test]
    fn next_fire_daily_in_zurich_tz() {
        let s = schedule(Preset::Daily, Zurich, None);
        // CEST: 00:00 local is 22:00 UTC the day before.
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 16, 22, 0));
    }

    #[test]
    fn next_fire_weekly_lands_on_monday() {
        let s = schedule(Preset::Weekly, UTC, None);
        // 2026-05-16 = Saturday. Next Monday = 2026-05-18.
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 18, 0, 0));
        let dt_local = next.with_timezone(&UTC);
        assert_eq!(dt_local.weekday(), Weekday::Mon);
    }

    #[test]
    fn next_fire_monthly_lands_on_first() {
        let s = schedule(Preset::Monthly, UTC, None);
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 6, 1, 0, 0));
    }

    #[test]
    fn next_fire_custom_no_last_reset_fires_at_next_midnight() {
        let s = schedule(Preset::Custom, UTC, Some(7));
        let now = at_utc(2026, 5, 16, 12, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 5, 17, 0, 0));
    }

    #[test]
    fn next_fire_custom_with_recent_last_reset_skips_until_interval_elapsed() {
        let s = schedule(Preset::Custom, UTC, Some(7));
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
        let s = schedule(Preset::Daily, Santiago, None);
        // 12:00 local on the gap day (UTC-3 after the jump).
        let now = at_utc(2026, 9, 6, 15, 0);
        let next = compute_next_fire(&s, None, now);
        assert_eq!(next, at_utc(2026, 9, 7, 3, 0));
    }

    #[test]
    fn reset_runner_is_cloneable_without_c_clone_bound() {
        // Compile-time check: the manual Clone impl works for a non-Clone C.
        fn _accepts<C: Clock>(r: GroupResetRunner<C>) -> GroupResetRunner<C> {
            r.clone()
        }
    }
}
