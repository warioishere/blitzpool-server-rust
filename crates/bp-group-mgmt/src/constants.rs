// SPDX-License-Identifier: AGPL-3.0-or-later

//! Activation, kick and expiry thresholds for groups, invitations and
//! join requests.

/// Members at or above which a group is active; the stratum layer refuses
/// Group-Solo connections for inactive groups. `1` lets a group mine with
/// just its creator.
pub const MIN_MEMBERS_ACTIVE: u32 = 1;

/// An admin can only remove a member idle for this many days. Must stay in
/// step with `blitzpool`'s hardcoded `group_service::KICK_INACTIVITY_DAYS`.
pub const DEFAULT_KICK_INACTIVITY_DAYS: u32 = 14;

/// Hard upper bound on the round-reset custom interval, in days.
pub const MAX_RESET_INTERVAL_DAYS: u32 = 365;

/// Cap on the finder bonus, ppm of the miner cut (50 %); past half the pot
/// the proportional split is meaningless, so more is a typo. Mirrors
/// `bp_pplns::MAX_FINDER_BONUS_PPM`, which is what the build clamps to.
pub const MAX_FINDER_BONUS_PPM: i32 = 500_000;

/// How long a directed invitation stays valid before auto-expiring.
pub const INVITATION_TTL_DAYS: u32 = 7;

/// How long an unanswered join-request lingers before the cron sweeps
/// it. The admin can still approve/reject during this window.
pub const JOIN_REQUEST_PENDING_EXPIRY_DAYS: u32 = 30;

/// Minimum allowed group-name length, inclusive.
pub const MIN_GROUP_NAME_LEN: usize = 3;

/// Maximum allowed group-name length, inclusive.
pub const MAX_GROUP_NAME_LEN: usize = 64;

/// Max characters for the optional join-request message body. Enforced
/// at the API boundary (DB column is plain `text`).
pub const MAX_JOIN_REQUEST_MESSAGE_LEN: usize = 500;

pub const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;
