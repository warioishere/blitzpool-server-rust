// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty mode constants.

/// 1% — the smallest split an admin may assign to any single member.
pub const MIN_PERCENT_BP: i32 = 100;

/// 100% — used when the admin is the sole member (solo-rental).
pub const MAX_PERCENT_BP: i32 = 10_000;

/// Sum of all members' `percentBp` — must equal exactly 100% of the
/// miner cut. Enforced at the service layer; the distribution math
/// tolerates over/underpaying if invariant is violated (the residual
/// lands in the pool-fee output).
pub const TOTAL_PERCENT_BP: i32 = 10_000;

pub const NAME_MIN_LEN: usize = 3;
pub const NAME_MAX_LEN: usize = 64;
pub const EMAIL_MAX_LEN: usize = 320;

const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;

/// Required zero-share silence before an `active` party may be
/// dissolved. Covers the worst-case hashpower-rental refund + re-buy
/// turnaround so a failed rental does not strand the members.
pub const DISSOLVE_COOLDOWN_MS: i64 = 7 * MS_PER_DAY;

/// Default invitation TTL when the caller does not override.
pub const DEFAULT_INVITATION_TTL_DAYS: i64 = 7;
