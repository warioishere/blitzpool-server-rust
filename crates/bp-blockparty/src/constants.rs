// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty mode constants.

pub const MIN_PERCENT_BP: i32 = 100;

/// A sole admin member takes the whole miner cut.
pub const MAX_PERCENT_BP: i32 = 10_000;

/// Required sum of all members' `percentBp`, enforced by the service layer.
pub const TOTAL_PERCENT_BP: i32 = 10_000;

pub const NAME_MIN_LEN: usize = 3;
pub const NAME_MAX_LEN: usize = 64;
pub const EMAIL_MAX_LEN: usize = 320;

const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;

/// Share silence required before an active party may dissolve; covers a
/// rental refund and re-buy so a failed rental does not strand members.
pub const DISSOLVE_COOLDOWN_MS: i64 = 7 * MS_PER_DAY;

pub const DEFAULT_INVITATION_TTL_DAYS: i64 = 7;
