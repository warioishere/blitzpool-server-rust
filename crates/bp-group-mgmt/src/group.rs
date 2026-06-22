// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-shape validators + lifecycle predicates.
//!
//! Pure logic only — no DB lookups, no Redis. The service-wiring layer
//! does the I/O and consults these functions for "is this OK?" answers.

use bp_common::Sats;

use crate::constants::{
    MAX_FINDER_BONUS_SATS, MAX_GROUP_NAME_LEN, MAX_RESET_INTERVAL_DAYS, MIN_GROUP_NAME_LEN,
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

/// Validated group name. Construct via [`GroupName::new`] (trims +
/// validates) or [`GroupName::from_trusted`] when the source is already
/// validated (e.g. a row read from `pplns_group.name`).
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

    /// Wrap a value already known to be valid (e.g. from a DB row).
    pub fn from_trusted(name: impl Into<String>) -> Self {
        Self(name.into())
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

/// Decide whether `address` may be removed from the group.
///
/// Pure function of three values:
///
/// - `role`: creators can never be kicked (must `transferCreator` or
///   `dissolveGroup` first).
/// - `last_active_ms`: timestamp of the address's most recent accepted
///   share (or `joined_at` if it never mined).
/// - `now_ms`: current wall-clock time.
/// - `inactivity_threshold_days`: pool config, typically
///   [`crate::constants::DEFAULT_KICK_INACTIVITY_DAYS`].
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

/// Validated round-reset configuration ready to persist on the group row.
/// `None` for `preset` means "scheduled resets disabled".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundResetConfig {
    pub preset: Option<RoundResetPreset>,
    /// Authoritative only when `preset == Some(Custom)`; cleared
    /// otherwise so debug logs aren't misleading. Always in
    /// `1..=MAX_RESET_INTERVAL_DAYS` when set.
    pub interval_days: Option<u32>,
    /// IANA timezone name (e.g. `Europe/Berlin`). Required when `preset`
    /// is set. Validation of the actual IANA shape is the service layer's
    /// job (depends on OS / chrono-tz); here we only enforce non-empty.
    pub timezone: Option<String>,
    /// 0 = disabled. Otherwise capped at [`MAX_FINDER_BONUS_SATS`].
    pub finder_bonus_sats: Sats,
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
    #[error("finderBonusSats must be in [0, {MAX_FINDER_BONUS_SATS}] sats (got {0})")]
    FinderBonusOutOfRange(i64),
    #[error("finderBonusSats below pool min payout ({min_payout}): {got}")]
    FinderBonusSubMinPayout { got: i64, min_payout: i64 },
}

/// Validate a `RoundResetConfig`. Pure — does not consult the DB.
///
/// `min_payout_sats` lets the caller reject configurations whose
/// `finder_bonus_sats` would silently be cleared at coinbase-build time
/// because it falls below the pool's dust floor — better to fail the
/// PATCH up front than confuse the admin with "I set 1000 sats but no
/// block paid it".
pub fn validate_round_reset(
    config: &RoundResetConfig,
    min_payout_sats: Sats,
) -> Result<(), RoundResetError> {
    // intervalDays only meaningful with Custom preset.
    if let Some(d) = config.interval_days {
        if config.preset != Some(RoundResetPreset::Custom) {
            return Err(RoundResetError::IntervalWithoutCustomPreset);
        }
        if !(1..=MAX_RESET_INTERVAL_DAYS).contains(&d) {
            return Err(RoundResetError::IntervalOutOfRange(MAX_RESET_INTERVAL_DAYS));
        }
    }

    // If a preset is set, we need timezone + (for Custom) intervalDays.
    if let Some(preset) = config.preset {
        match &config.timezone {
            Some(tz) if !tz.is_empty() => {}
            _ => return Err(RoundResetError::MissingTimezone),
        }
        if preset == RoundResetPreset::Custom && config.interval_days.is_none() {
            return Err(RoundResetError::IntervalRequiredForCustom);
        }
    }

    // Finder bonus bounds.
    let bonus = config.finder_bonus_sats.to_i64();
    if !(0..=MAX_FINDER_BONUS_SATS).contains(&bonus) {
        return Err(RoundResetError::FinderBonusOutOfRange(bonus));
    }
    let min = min_payout_sats.to_i64();
    if bonus > 0 && bonus < min {
        return Err(RoundResetError::FinderBonusSubMinPayout {
            got: bonus,
            min_payout: min,
        });
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
    fn active_threshold_is_two() {
        assert!(!is_active(0));
        assert!(!is_active(1));
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
            finder_bonus_sats: Sats(0),
        }
    }

    #[test]
    fn round_reset_daily_with_tz_is_ok() {
        assert!(validate_round_reset(&ok_cfg(), Sats(546)).is_ok());
    }

    #[test]
    fn round_reset_no_preset_no_tz_is_ok() {
        let cfg = RoundResetConfig {
            preset: None,
            interval_days: None,
            timezone: None,
            finder_bonus_sats: Sats(0),
        };
        assert!(validate_round_reset(&cfg, Sats(546)).is_ok());
    }

    #[test]
    fn round_reset_preset_requires_timezone() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Weekly),
            interval_days: None,
            timezone: None,
            finder_bonus_sats: Sats(0),
        };
        assert_eq!(
            validate_round_reset(&cfg, Sats(546)),
            Err(RoundResetError::MissingTimezone)
        );
    }

    #[test]
    fn round_reset_custom_requires_interval() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Custom),
            interval_days: None,
            timezone: Some("UTC".into()),
            finder_bonus_sats: Sats(0),
        };
        assert_eq!(
            validate_round_reset(&cfg, Sats(546)),
            Err(RoundResetError::IntervalRequiredForCustom)
        );
    }

    #[test]
    fn round_reset_interval_without_custom_rejected() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Daily),
            interval_days: Some(3),
            timezone: Some("UTC".into()),
            finder_bonus_sats: Sats(0),
        };
        assert_eq!(
            validate_round_reset(&cfg, Sats(546)),
            Err(RoundResetError::IntervalWithoutCustomPreset)
        );
    }

    #[test]
    fn round_reset_interval_out_of_range_rejected() {
        let cfg = RoundResetConfig {
            preset: Some(RoundResetPreset::Custom),
            interval_days: Some(0),
            timezone: Some("UTC".into()),
            finder_bonus_sats: Sats(0),
        };
        assert_eq!(
            validate_round_reset(&cfg, Sats(546)),
            Err(RoundResetError::IntervalOutOfRange(MAX_RESET_INTERVAL_DAYS))
        );

        let cfg2 = RoundResetConfig {
            preset: Some(RoundResetPreset::Custom),
            interval_days: Some(366),
            timezone: Some("UTC".into()),
            finder_bonus_sats: Sats(0),
        };
        assert_eq!(
            validate_round_reset(&cfg2, Sats(546)),
            Err(RoundResetError::IntervalOutOfRange(MAX_RESET_INTERVAL_DAYS))
        );
    }

    #[test]
    fn round_reset_finder_bonus_negative_rejected() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_sats = Sats(-1);
        assert_eq!(
            validate_round_reset(&cfg, Sats(546)),
            Err(RoundResetError::FinderBonusOutOfRange(-1))
        );
    }

    #[test]
    fn round_reset_finder_bonus_above_cap_rejected() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_sats = Sats(MAX_FINDER_BONUS_SATS + 1);
        assert_eq!(
            validate_round_reset(&cfg, Sats(546)),
            Err(RoundResetError::FinderBonusOutOfRange(
                MAX_FINDER_BONUS_SATS + 1
            ))
        );
    }

    #[test]
    fn round_reset_finder_bonus_below_min_payout_rejected() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_sats = Sats(100);
        let err = validate_round_reset(&cfg, Sats(546));
        match err {
            Err(RoundResetError::FinderBonusSubMinPayout { got, min_payout }) => {
                assert_eq!(got, 100);
                assert_eq!(min_payout, 546);
            }
            _ => panic!("expected FinderBonusSubMinPayout, got {err:?}"),
        }
    }

    #[test]
    fn round_reset_zero_bonus_always_allowed() {
        let mut cfg = ok_cfg();
        cfg.finder_bonus_sats = Sats(0);
        assert!(validate_round_reset(&cfg, Sats(10_000_000)).is_ok());
    }
}
