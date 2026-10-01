// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-shape validators and lifecycle predicates; pure, no I/O.

use crate::constants::{
    MAX_FINDER_BONUS_PPM, MAX_GROUP_NAME_LEN, MAX_RESET_INTERVAL_DAYS, MIN_GROUP_NAME_LEN,
    MIN_MEMBERS_ACTIVE, MS_PER_DAY,
};

// ─── Group name ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupNameError {
    #[error("group name must be {MIN_GROUP_NAME_LEN}–{MAX_GROUP_NAME_LEN} characters (got {0})")]
    BadLength(usize),
    #[error("group name must not contain control characters")]
    ControlChar,
}

/// Validated group name, built by [`GroupName::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupName(String);

impl GroupName {
    /// Trim leading/trailing ASCII whitespace, then validate length and
    /// reject control characters (`U+0000..=U+001F` and `U+007F`).
    pub fn new(raw: &str) -> Result<Self, GroupNameError> {
        let trimmed = raw.trim();
        if trimmed.len() < MIN_GROUP_NAME_LEN || trimmed.len() > MAX_GROUP_NAME_LEN {
            return Err(GroupNameError::BadLength(trimmed.len()));
        }
        if trimmed.chars().any(is_control_char) {
            return Err(GroupNameError::ControlChar);
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

fn is_control_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{001F}' | '\u{007F}')
}

// ─── Member role + active threshold ─────────────────────────────────────────

/// Membership role. Matches the `pplns_group_member.role` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberRole {
    Creator,
    Member,
}

impl MemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creator => "creator",
            Self::Member => "member",
        }
    }
}

/// A group is **active** iff its member count meets [`MIN_MEMBERS_ACTIVE`].
/// The stratum layer refuses Group-Solo connections for addresses in
/// inactive groups, so this predicate gates real money flow.
pub fn is_active(member_count: u32) -> bool {
    member_count >= MIN_MEMBERS_ACTIVE
}

// ─── Kick-eligibility ───────────────────────────────────────────────────────

/// Outcome of [`kick_eligibility`]. Differentiates "can be kicked" from
/// "still active" so the caller can produce a precise error message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KickEligibility {
    Eligible,
    StillActive {
        days_since_last_active: f64,
        required_days: u32,
    },
    /// Caller passed a creator role to a remove path that doesn't support
    /// it. Surfaced separately because the UI shows a different message.
    CannotKickCreator,
}

/// Whether a member may be removed. A creator never can (transfer or
/// dissolve first); `last_active_ms` is the latest accepted share, or
/// `joined_at` if the member never mined.
pub fn kick_eligibility(
    role: MemberRole,
    last_active_ms: i64,
    now_ms: i64,
    inactivity_threshold_days: u32,
) -> KickEligibility {
    if role == MemberRole::Creator {
        return KickEligibility::CannotKickCreator;
    }
    let elapsed_ms = (now_ms - last_active_ms).max(0);
    let days_since = elapsed_ms as f64 / MS_PER_DAY as f64;
    if days_since < inactivity_threshold_days as f64 {
        KickEligibility::StillActive {
            days_since_last_active: days_since,
            required_days: inactivity_threshold_days,
        }
    } else {
        KickEligibility::Eligible
    }
}

// ─── Round-reset configuration ──────────────────────────────────────────────

/// Round-reset cadence preset. Stored as a varchar in
/// `pplns_group.roundResetPreset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundResetPreset {
    /// Every day at 00:00 local time.
    Daily,
    /// Every Monday at 00:00 local time.
    Weekly,
    /// Every 1st of the month at 00:00 local time.
    Monthly,
    /// Every N days at 00:00 local time. Requires `interval_days`.
    Custom,
}

impl RoundResetPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "daily" => Self::Daily,
            "weekly" => Self::Weekly,
            "monthly" => Self::Monthly,
            "custom" => Self::Custom,
            _ => return None,
        })
    }
}

// ─── Payout mode ────────────────────────────────────────────────────────────

/// Per-group payout mode, **immutable** after creation (no live state
/// migration between modes). `Prop` pays PROP per round, wiped on block or
/// calendar/manual reset; `Window` pays the last N days of shares, with N
/// taken from the reset-cadence config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PayoutMode {
    #[default]
    Prop,
    Window,
}

impl PayoutMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prop => "prop",
            Self::Window => "window",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "prop" => Self::Prop,
            "window" => Self::Window,
            _ => return None,
        })
    }

    pub fn parse_or_default(s: &str) -> Self {
        Self::parse(s).unwrap_or_default()
    }
}

/// Default sliding-window length in days when a `Window`-mode group has no
/// reset-cadence config to reinterpret.
pub const DEFAULT_WINDOW_DAYS: u32 = 1;

/// Window length in days for [`PayoutMode::Window`], read from the reset
/// cadence config; missing or zero falls back to [`DEFAULT_WINDOW_DAYS`].
/// Changing it only trims more or less of the window, never migrates
/// state, so it stays editable in the PATCH path.
pub fn window_days(preset: Option<RoundResetPreset>, interval_days: Option<u32>) -> u32 {
    match preset {
        Some(RoundResetPreset::Daily) => 1,
        Some(RoundResetPreset::Weekly) => 7,
        Some(RoundResetPreset::Monthly) => 30,
        Some(RoundResetPreset::Custom) => interval_days
            .filter(|d| *d > 0)
            .unwrap_or(DEFAULT_WINDOW_DAYS),
        None => interval_days
            .filter(|d| *d > 0)
            .unwrap_or(DEFAULT_WINDOW_DAYS),
    }
}

pub fn window_duration_ms(preset: Option<RoundResetPreset>, interval_days: Option<u32>) -> i64 {
    window_days(preset, interval_days) as i64 * MS_PER_DAY
}

/// Validated round-reset configuration ready to persist on the group row.
/// `None` for `preset` means "scheduled resets disabled".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundResetConfig {
    pub preset: Option<RoundResetPreset>,
    /// Only with `preset == Some(Custom)`, in `1..=MAX_RESET_INTERVAL_DAYS`.
    pub interval_days: Option<u32>,
    /// IANA name, required with a preset; only non-empty is checked here.
    pub timezone: Option<String>,
    /// Share of the miner cut in ppm; 0 disables, capped at
    /// [`MAX_FINDER_BONUS_PPM`].
    pub finder_bonus_ppm: i32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoundResetError {
    #[error("intervalDays may only be set when preset='custom'")]
    IntervalWithoutCustomPreset,
    #[error("intervalDays must be in [1, {0}]")]
    IntervalOutOfRange(u32),
    #[error("timezone must be non-empty when a preset is set")]
    MissingTimezone,
    #[error("intervalDays must be set when preset='custom' (in [1, {MAX_RESET_INTERVAL_DAYS}])")]
    IntervalRequiredForCustom,
    #[error("finderBonusPpm must be in [0, {MAX_FINDER_BONUS_PPM}] ppm (got {0})")]
    FinderBonusOutOfRange(i32),
}

pub fn validate_round_reset(config: &RoundResetConfig) -> Result<(), RoundResetError> {
    if let Some(d) = config.interval_days {
        if config.preset != Some(RoundResetPreset::Custom) {
            return Err(RoundResetError::IntervalWithoutCustomPreset);
        }
        if !(1..=MAX_RESET_INTERVAL_DAYS).contains(&d) {
            return Err(RoundResetError::IntervalOutOfRange(MAX_RESET_INTERVAL_DAYS));
        }
    }

    if let Some(preset) = config.preset {
        match &config.timezone {
            Some(tz) if !tz.is_empty() => {}
            _ => return Err(RoundResetError::MissingTimezone),
        }
        if preset == RoundResetPreset::Custom && config.interval_days.is_none() {
            return Err(RoundResetError::IntervalRequiredForCustom);
        }
    }

    // Range check only: a ppm bonus's sat value depends on block revenue
    // and share spread, unknown here, so no `min_payout` check. A finder
    // whose whole weight is a small bonus can still be withheld by
    // `build_weight_distribution`.
    let bonus = config.finder_bonus_ppm;
    if !(0..=MAX_FINDER_BONUS_PPM).contains(&bonus) {
        return Err(RoundResetError::FinderBonusOutOfRange(bonus));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Group name ───────────────────────────────────────────────────

    #[test]
    fn name_too_short_rejected() {
        assert_eq!(GroupName::new("ab"), Err(GroupNameError::BadLength(2)));
    }

    #[test]
    fn name_too_long_rejected() {
        let s = "a".repeat(65);
        let len = s.len();
        assert_eq!(GroupName::new(&s), Err(GroupNameError::BadLength(len)));
    }

    #[test]
    fn name_with_control_char_rejected() {
        assert_eq!(GroupName::new("a\nb"), Err(GroupNameError::ControlChar));
        assert_eq!(GroupName::new("\x7fbad"), Err(GroupNameError::ControlChar));
    }

    #[test]
    fn name_trims_whitespace_before_validating() {
        let n = GroupName::new("  hello  ").expect("valid");
        assert_eq!(n.as_str(), "hello");
    }

    #[test]
    fn name_accepts_unicode() {
        let n = GroupName::new("Pool 🦀 Group").expect("valid");
        assert_eq!(n.as_str(), "Pool 🦀 Group");
    }

    // ── Active threshold ─────────────────────────────────────────────

    #[test]
    fn active_threshold_is_one() {
        // A group mines as soon as it has its creator; only an empty group is
        // inactive (MIN_MEMBERS_ACTIVE == 1).
        assert!(!is_active(0));
        assert!(is_active(1));
        assert!(is_active(2));
        assert!(is_active(100));
    }

    // ── Kick eligibility ─────────────────────────────────────────────

    #[test]
    fn creator_never_kickable() {
        let e = kick_eligibility(MemberRole::Creator, 0, 1_000 * MS_PER_DAY, 14);
        assert_eq!(e, KickEligibility::CannotKickCreator);
    }

    #[test]
    fn long_idle_member_is_eligible() {
        let last = 0;
        let now = 100 * MS_PER_DAY;
        let e = kick_eligibility(MemberRole::Member, last, now, 14);
        assert_eq!(e, KickEligibility::Eligible);
    }

    #[test]
    fn recently_active_member_blocked() {
        let last = 1_000 * MS_PER_DAY;
        let now = last + 7 * MS_PER_DAY;
        let e = kick_eligibility(MemberRole::Member, last, now, 14);
        match e {
            KickEligibility::StillActive {
                days_since_last_active,
                required_days,
            } => {
                assert!((days_since_last_active - 7.0).abs() < 0.001);
                assert_eq!(required_days, 14);
            }
            _ => panic!("expected StillActive"),
        }
    }

    #[test]
    fn negative_elapsed_clamped_to_zero() {
        // Pathological clock-skew case: last_active in the future.
        let last = 2_000 * MS_PER_DAY;
        let now = 1_000 * MS_PER_DAY;
        let e = kick_eligibility(MemberRole::Member, last, now, 14);
        match e {
            KickEligibility::StillActive {
                days_since_last_active,
                ..
            } => assert_eq!(days_since_last_active, 0.0),
            _ => panic!("expected StillActive"),
        }
    }

    #[test]
    fn exact_threshold_is_eligible() {
        // `>= threshold` is eligible.
        let last = 0;
        let now = 14 * MS_PER_DAY;
        let e = kick_eligibility(MemberRole::Member, last, now, 14);
        assert_eq!(e, KickEligibility::Eligible);
    }

    // ── Round-reset config ───────────────────────────────────────────

    fn ok_cfg() -> RoundResetConfig {
        RoundResetConfig {
            preset: Some(RoundResetPreset::Daily),
            interval_days: None,
            timezone: Some("Europe/Berlin".into()),
            finder_bonus_ppm: 0,
        }
    }

    #[test]
    fn round_reset_daily_with_tz_is_ok() {
        assert!(validate_round_reset(&ok_cfg()).is_ok());
    }

    #[test]
    fn round_reset_no_preset_no_tz_is_ok() {
        let cfg = RoundResetConfig {
            preset: None,
            interval_days: None,
            timezone: None,
            finder_bonus_ppm: 0,
        };
        assert!(validate_round_reset(&cfg).is_ok());
    }

    #[test]
    fn round_reset_preset_requires_timezone() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Weekly),
            interval_days: None,
            timezone: None,
            finder_bonus_ppm: 0,
        };
        assert_eq!(
            validate_round_reset(&cfg),
            Err(RoundResetError::MissingTimezone)
        );
    }

    #[test]
    fn round_reset_custom_requires_interval() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Custom),
            interval_days: None,
            timezone: Some("UTC".into()),
            finder_bonus_ppm: 0,
        };
        assert_eq!(
            validate_round_reset(&cfg),
            Err(RoundResetError::IntervalRequiredForCustom)
        );
    }

    #[test]
    fn round_reset_interval_without_custom_rejected() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Daily),
            interval_days: Some(3),
            timezone: Some("UTC".into()),
            finder_bonus_ppm: 0,
        };
        assert_eq!(
            validate_round_reset(&cfg),
            Err(RoundResetError::IntervalWithoutCustomPreset)
        );
    }

    #[test]
    fn round_reset_interval_out_of_range_rejected() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Custom),
            interval_days: Some(0),
            timezone: Some("UTC".into()),
            finder_bonus_ppm: 0,
        };
        assert_eq!(
            validate_round_reset(&cfg),
            Err(RoundResetError::IntervalOutOfRange(MAX_RESET_INTERVAL_DAYS))
        );

        let cfg2 = RoundResetConfig {
            preset: Some(RoundResetPreset::Custom),
            interval_days: Some(366),
            timezone: Some("UTC".into()),
            finder_bonus_ppm: 0,
        };
        assert_eq!(
            validate_round_reset(&cfg2),
            Err(RoundResetError::IntervalOutOfRange(MAX_RESET_INTERVAL_DAYS))
        );
    }

    #[test]
    fn round_reset_finder_bonus_negative_rejected() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_ppm = -1;
        assert_eq!(
            validate_round_reset(&cfg),
            Err(RoundResetError::FinderBonusOutOfRange(-1))
        );
    }

    #[test]
    fn round_reset_finder_bonus_above_cap_rejected() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_ppm = MAX_FINDER_BONUS_PPM + 1;
        assert_eq!(
            validate_round_reset(&cfg),
            Err(RoundResetError::FinderBonusOutOfRange(
                MAX_FINDER_BONUS_PPM + 1
            ))
        );
    }

    /// A tiny ppm bonus passes: there is no sat floor to check it against.
    #[test]
    fn round_reset_a_tiny_finder_bonus_is_accepted() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_ppm = 1; // 0.0001 %
        assert!(validate_round_reset(&cfg).is_ok());
    }

    #[test]
    fn round_reset_zero_bonus_always_allowed() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_ppm = 0;
        assert!(validate_round_reset(&cfg).is_ok());
    }

    // ── Payout mode ──────────────────────────────────────────────────

    #[test]
    fn payout_mode_default_is_prop() {
        assert_eq!(PayoutMode::default(), PayoutMode::Prop);
    }

    #[test]
    fn payout_mode_roundtrips_through_str() {
        for m in [PayoutMode::Prop, PayoutMode::Window] {
            assert_eq!(PayoutMode::parse(m.as_str()), Some(m));
        }
    }

    #[test]
    fn payout_mode_parse_rejects_unknown() {
        assert_eq!(PayoutMode::parse("bogus"), None);
        // Lenient variant falls back to Prop instead of erroring.
        assert_eq!(PayoutMode::parse_or_default("bogus"), PayoutMode::Prop);
        assert_eq!(PayoutMode::parse_or_default("window"), PayoutMode::Window);
    }

    // ── Window length reinterpretation ───────────────────────────────

    #[test]
    fn window_days_maps_presets() {
        assert_eq!(window_days(Some(RoundResetPreset::Daily), None), 1);
        assert_eq!(window_days(Some(RoundResetPreset::Weekly), None), 7);
        assert_eq!(window_days(Some(RoundResetPreset::Monthly), None), 30);
        assert_eq!(window_days(Some(RoundResetPreset::Custom), Some(5)), 5);
    }

    #[test]
    fn window_days_defaults_when_unset_or_zero() {
        assert_eq!(window_days(None, None), DEFAULT_WINDOW_DAYS);
        // Custom with a missing / zero interval falls back to the default.
        assert_eq!(
            window_days(Some(RoundResetPreset::Custom), None),
            DEFAULT_WINDOW_DAYS
        );
        assert_eq!(
            window_days(Some(RoundResetPreset::Custom), Some(0)),
            DEFAULT_WINDOW_DAYS
        );
    }

    #[test]
    fn window_duration_ms_is_days_times_one_day() {
        assert_eq!(
            window_duration_ms(Some(RoundResetPreset::Weekly), None),
            7 * MS_PER_DAY
        );
        assert_eq!(
            window_duration_ms(Some(RoundResetPreset::Custom), Some(3)),
            3 * MS_PER_DAY
        );
        assert_eq!(window_duration_ms(None, None), MS_PER_DAY);
    }
}
