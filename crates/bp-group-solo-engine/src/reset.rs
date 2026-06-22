// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled round-reset cron — fires per `pplns_group.roundResetPreset`
//! + `roundResetTimezone` + `roundResetIntervalDays`.
//!
//! Presets (all fire at **00:00 in the group's TZ**):
//! - `daily`     — every day
//! - `weekly`    — Monday
//! - `monthly`   — 1st of month
//! - `custom`    — daily fire, gated by `roundResetIntervalDays`
//!
//! On fire, the runner wipes the full round state (shares zset,
//! counter, total, by-address, rejected-shares, best-share,
//! last-accepted-share-at, and all per-finder snapshots), deletes
//! every balance row for the group, and stamps `lastRoundResetAt`
//! to now. A 60-second guard on `lastRoundResetAt` prevents
//! scheduled-vs-scheduled double-fire.
//!
//! `chrono-tz` ships the IANA TZ database compiled into the binary,
//! so the calendar-boundary math is OS-independent. DST handling for
//! `custom` uses a 12 h tolerance to absorb 23 h / 25 h daily-fire
//! skew.

use std::sync::Arc;
use std::time::Duration;

use bp_cron_utils::Clock;
use bp_db::{
    delete_pplns_group_balances_for_group, find_group, update_pplns_group_last_reset_at, DbError,
};
use chrono::{DateTime, Datelike, Duration as ChronoDuration, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::round::snapshot::delete_all_for_group;
use crate::round::{GroupRoundStore, RoundError};

/// 60-second anti-double-fire guard: a scheduled reset is skipped if
/// the group was already reset within this window. Enforced via the
/// `lastRoundResetAt` gate.
pub const RESET_DEBOUNCE_MS: i64 = 60_000;

/// DST-tolerance window for `custom` preset elapsed-check: the
/// configured interval may shrink/grow by up to 12 h across a DST
/// transition. Without tolerance, a 7-day-interval cron that lands
/// 23.5 h after the 6th daily-fire wouldn't fire on the 7th.
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
    /// Only meaningful for `Custom` preset. `None` for the calendar
    /// presets.
    pub interval_days: Option<u32>,
}

impl ResetSchedule {
    /// Construct from raw DB-row fields. Returns `Ok(None)` if the
    /// group has no preset configured (silent silently-no-op case).
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

/// Compute the wall-clock UTC instant of the next scheduled reset
/// strictly after `now`. `now` is in UTC; the calendar boundaries
/// are computed in the schedule's TZ + converted back to UTC.
///
/// For calendar presets the result is the exact next calendar
/// boundary. For `custom`, it's the first daily-fire at or after
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
            // Step through daily fires until we find one ≥ earliest_ms.
            for _ in 0..(schedule.interval_days.unwrap_or(1) as i64 + 2) {
                if candidate.timestamp_millis() >= earliest_ms {
                    break;
                }
                candidate += ChronoDuration::days(1);
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
    let today_midnight = now
        .timezone()
        .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
        .single()
        .expect("today midnight unambiguous");
    if today_midnight > now {
        today_midnight
    } else {
        next_day_midnight(today_midnight)
    }
}

fn next_day_midnight(base: DateTime<Tz>) -> DateTime<Tz> {
    let step = base + ChronoDuration::days(1);
    // If 00:00 local is unambiguous (the common case), use it.
    if let Some(s) = step
        .timezone()
        .with_ymd_and_hms(step.year(), step.month(), step.day(), 0, 0, 0)
        .single()
    {
        return s;
    }
    // Spring-forward edge case: 00:00 doesn't exist in the local
    // calendar (rare TZs). Pick the next valid minute as fallback.
    for minute in 1..=120 {
        if let Some(s) = step
            .timezone()
            .with_ymd_and_hms(step.year(), step.month(), step.day(), 0, minute, 0)
            .single()
        {
            return s;
        }
    }
    // Theoretically unreachable for IANA TZs at 00:00. Best-effort.
    step
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

/// Composes the reset operation across Redis + PG. NOT a single TX
/// (Redis + PG can't be transactional together). Order minimises
/// partial-state risk: Redis state wiped first, then PG state, then
/// stamp.
pub struct GroupResetRunner<C: Clock> {
    pool: PgPool,
    round: GroupRoundStore,
    clock: Arc<C>,
}

impl<C: Clock> GroupResetRunner<C> {
    pub fn new(pool: PgPool, round: GroupRoundStore, clock: Arc<C>) -> Self {
        Self { pool, round, clock }
    }

    /// Run one scheduled reset for `group_id`. Returns `Ok(true)`
    /// when the reset fired, `Ok(false)` when it was skipped by the
    /// 60 s debounce guard.
    pub async fn reset_scheduled(&self, group_id: Uuid) -> Result<bool, ResetError> {
        let group = find_group(&self.pool, group_id)
            .await?
            .ok_or(ResetError::GroupNotFound { group_id })?;
        let now_ms = self.clock.now().timestamp_millis();

        // Debounce: a recent scheduled reset wins.
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

        // Custom-preset elapsed check (defence-in-depth — the cron
        // task SHOULD have gated already, but this lets the runner be
        // invoked as a standalone action without surprising the admin
        // by firing too early).
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

        // 1. Redis: wipe all round state INCLUDING last-accepted-share-at.
        self.round.reset_full(&group_key).await?;
        // 2. Redis: drop every per-finder snapshot for this group.
        let mut conn = self.round.connection_for_snapshot();
        delete_all_for_group(&mut conn, &group_key).await?;
        // 3. PG: delete all balance rows for the group (Variant-B
        //    "only active miners in this period get paid" semantics).
        delete_pplns_group_balances_for_group(&self.pool, group_id).await?;
        // 4. PG: stamp lastRoundResetAt so the 60s debounce on the
        //    next cron tick reads the fresh value.
        update_pplns_group_last_reset_at(&self.pool, group_id, now_ms).await?;

        info!(%group_id, "group-solo scheduled round-reset applied");
        Ok(true)
    }
}

// Manual Clone because the derive would require `C: Clone`. Same
// pattern as `InflightResultCache` — clone the Arc<C>.
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

/// Spawn a per-group cron task. The task sleeps until the next
/// scheduled fire (calendar-aligned in the group's TZ), runs the
/// reset, then loops. The schedule is captured at spawn time —
/// bin/blitzpool's wiring re-spawns the task on group config changes.
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
            // Look up the latest lastResetAt so the next-fire calc
            // matches the runner's debounce + custom-elapsed gates.
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
    use chrono_tz::{Europe::Zurich, UTC};

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
        // Zurich is UTC+1 in winter, UTC+2 in summer (CET/CEST). On
        // 2026-05-16 (CEST), 22:00 UTC = 00:00 next day local. So the
        // next 00:00 local strictly after 12:00 UTC = today's 22:00 UTC.
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
        // Last reset 2 days ago — must wait until 7d (minus 12h DST tolerance) elapses.
        let last_ms = (now - ChronoDuration::days(2)).timestamp_millis();
        let next = compute_next_fire(&s, Some(last_ms), now);
        // Earliest fire ≈ last + 7d - 12h. Daily candidates step
        // forward from next-midnight (2026-05-17 00:00) until we
        // cross the threshold.
        let last_dt = now - ChronoDuration::days(2);
        let earliest = last_dt + ChronoDuration::days(7) - ChronoDuration::hours(12);
        assert!(
            next >= earliest,
            "next ({next}) should be ≥ earliest-due ({earliest})"
        );
    }

    #[test]
    fn reset_runner_is_cloneable_without_c_clone_bound() {
        // Sanity: manual Clone impl works for non-Clone C generics.
        // We just verify the type compiles.
        fn _accepts<C: Clock>(r: GroupResetRunner<C>) -> GroupResetRunner<C> {
            r.clone()
        }
    }
}
