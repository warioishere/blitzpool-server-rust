// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only views of a group's round: for `bp-api` HTTP routes and the
//! Team notices in `bp-notifications`.

use bp_db::{find_group, PplnsGroupRow};
use bp_group_mgmt::group::{PayoutMode, RoundResetPreset};
use uuid::Uuid;

use crate::engine::{EngineError, GroupSoloEngine};
use crate::reset::scheduled_reset;
use crate::round::{BestShare, RoundStats};

impl GroupSoloEngine {
    pub fn reader(&self) -> ReaderView<'_> {
        ReaderView { engine: self }
    }
}

pub struct ReaderView<'a> {
    engine: &'a GroupSoloEngine,
}

/// Per-time-bucket sliding-window contribution for the timeline chart.
/// `buckets` is `(hour-bucket-id, addr → diff)` oldest→newest; empty for a
/// non-window group. `window_ms` is the window length (0 when not window).
#[derive(Clone, Debug, PartialEq)]
pub struct WindowTimeline {
    pub window_ms: i64,
    pub buckets: Vec<(i64, std::collections::HashMap<String, f64>)>,
}

impl ReaderView<'_> {
    /// Snapshot of one group's round state: per-address share contribution +
    /// totals + rejected counters. Mode-aware — a `Window`-mode group's
    /// per-address view is its trimmed sliding window, not the full history.
    pub async fn round_stats(&self, group_id: Uuid) -> Result<RoundStats, EngineError> {
        let (mode, window_ms) = match find_group(self.engine.pool(), group_id).await? {
            Some(g) => crate::engine::group_mode_from_row(&g),
            None => (PayoutMode::Prop, 0),
        };
        let now_ms = chrono::Utc::now().timestamp_millis();
        let stats = self
            .engine
            .round()
            .read_round_stats_for(&group_id.to_string(), mode, now_ms, window_ms)
            .await?;
        Ok(stats)
    }

    /// Best-difficulty share recorded in the current round. `None`
    /// if no shares yet (round just started).
    pub async fn best_difficulty(&self, group_id: Uuid) -> Result<Option<BestShare>, EngineError> {
        let best = self
            .engine
            .round()
            .read_best_share(&group_id.to_string())
            .await?;
        Ok(best)
    }

    /// Per-bucket per-address contribution of a `Window`-mode group, trimmed,
    /// oldest first. A non-window group or unknown id yields an empty timeline.
    pub async fn window_timeline(&self, group_id: Uuid) -> Result<WindowTimeline, EngineError> {
        let (mode, window_ms) = match find_group(self.engine.pool(), group_id).await? {
            Some(g) => crate::engine::group_mode_from_row(&g),
            None => (PayoutMode::Prop, 0),
        };
        match mode {
            PayoutMode::Window => {}
            PayoutMode::Prop => {
                return Ok(WindowTimeline {
                    window_ms: 0,
                    buckets: Vec::new(),
                });
            }
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let buckets = self
            .engine
            .round()
            .read_window_timeline(&group_id.to_string(), now_ms, window_ms)
            .await?;
        Ok(WindowTimeline { window_ms, buckets })
    }
}

/// When a group's round, and with it its best share, starts over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundReset {
    /// A Window group: its window never starts over (its preset is the
    /// window's length); its best share does on its own blocks when
    /// `best_on_block`.
    Window { best_on_block: bool },
    /// A Prop group: on its own blocks when `on_block`, and on the
    /// calendar schedule the reset cron runs, if any.
    Prop {
        on_block: bool,
        calendar: Option<CalendarReset>,
    },
}

/// A calendar reset, at midnight in the group's timezone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalendarReset {
    Daily,
    /// Mondays.
    Weekly,
    /// The 1st of each month.
    Monthly,
    EveryDays(u32),
}

/// The reset rule of `group`, from what the engine resets by: the payout
/// mode, `resetRoundOnBlock` (read in `on_block_found`) and
/// [`scheduled_reset`], the schedule a reset cron runs. Removing the member
/// who holds the best share also clears it (`forget_member`), outside any
/// rule.
pub fn round_reset(group: &PplnsGroupRow) -> RoundReset {
    match PayoutMode::parse_or_default(&group.payout_mode) {
        PayoutMode::Window => RoundReset::Window {
            best_on_block: group.reset_round_on_block,
        },
        PayoutMode::Prop => {
            let calendar = match scheduled_reset(group) {
                Ok(Some(s)) => match s.preset {
                    RoundResetPreset::Daily => Some(CalendarReset::Daily),
                    RoundResetPreset::Weekly => Some(CalendarReset::Weekly),
                    RoundResetPreset::Monthly => Some(CalendarReset::Monthly),
                    RoundResetPreset::Custom => s.interval_days.map(CalendarReset::EveryDays),
                },
                Ok(None) | Err(_) => None,
            };
            RoundReset::Prop {
                on_block: group.reset_round_on_block,
                calendar,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::AddressId;

    fn group(mode: &str, on_block: bool, preset: Option<&str>, days: Option<i32>) -> PplnsGroupRow {
        PplnsGroupRow {
            id: Uuid::nil(),
            name: "t".to_string(),
            creator_address: AddressId::new("bc1qcreator").unwrap(),
            admin_token_hash: String::new(),
            active: true,
            created_at: 0,
            updated_at: 0,
            dissolved_at: None,
            round_reset_interval_days: days,
            round_reset_hour_local: None,
            round_reset_timezone: Some("Europe/Zurich".to_string()),
            last_round_reset_at: None,
            finder_bonus_sats: None,
            finder_bonus_ppm: None,
            round_reset_preset: preset.map(str::to_string),
            is_public: false,
            reset_round_on_block: on_block,
            max_members: None,
            payout_mode: mode.to_string(),
            coinbase_tag: None,
        }
    }

    #[test]
    fn the_reset_rule_follows_mode_block_switch_and_schedule() {
        // A Window group's preset is its window length, not a reset.
        assert_eq!(
            round_reset(&group("window", true, Some("weekly"), None)),
            RoundReset::Window {
                best_on_block: true
            }
        );
        assert_eq!(
            round_reset(&group("prop", true, Some("weekly"), None)),
            RoundReset::Prop {
                on_block: true,
                calendar: Some(CalendarReset::Weekly)
            }
        );
        assert_eq!(
            round_reset(&group("prop", false, Some("custom"), Some(3))),
            RoundReset::Prop {
                on_block: false,
                calendar: Some(CalendarReset::EveryDays(3))
            }
        );
        assert_eq!(
            round_reset(&group("window", false, None, None)),
            RoundReset::Window {
                best_on_block: false
            }
        );
        // No cron runs for these: custom without an interval, no preset,
        // an unknown timezone, an inactive group.
        let none = RoundReset::Prop {
            on_block: false,
            calendar: None,
        };
        assert_eq!(
            round_reset(&group("prop", false, Some("custom"), None)),
            none
        );
        assert_eq!(round_reset(&group("prop", false, None, None)), none);
        let mut no_zone = group("prop", false, Some("daily"), None);
        no_zone.round_reset_timezone = Some("Mars/Olympus".to_string());
        assert_eq!(round_reset(&no_zone), none);
        let mut inactive = group("prop", false, Some("daily"), None);
        inactive.active = false;
        assert_eq!(round_reset(&inactive), none);
    }
}
