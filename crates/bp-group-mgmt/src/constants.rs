// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tunable constants governing activation, kick, and expiry thresholds
//! across group management, invitations, and join requests.

/// Number of members at or above which a group becomes active. The
/// stratum layer refuses Group-Solo connections for addresses in
/// inactive groups (under this floor). `1` means a group mines as soon as
/// it has its creator: the coinbase is then built from that one member's
/// proportional share + the fee output (+ finder bonus when configured).
pub const MIN_MEMBERS_ACTIVE: u32 = 1;

/// Default kick-inactivity window. An admin can only remove a member
/// who hasn't submitted a share in this many days. Overridable per
/// pool via `GROUP_INACTIVITY_KICK_DAYS`.
pub const DEFAULT_KICK_INACTIVITY_DAYS: u32 = 14;

/// Hard upper bound on the round-reset custom interval, in days.
pub const MAX_RESET_INTERVAL_DAYS: u32 = 365;

/// Hard cap for the optional per-block finder-bonus output, in sats.
/// 1 BTC is already absurd as a per-block bonus on top of the
/// proportional split — anything bigger is almost certainly a config
/// typo and would strand more sats than a normal block reward.
pub const MAX_FINDER_BONUS_SATS: i64 = 100_000_000;

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

/// Ms in a day — convenience used by the kick-eligibility and expiry
/// predicates.
pub const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;
