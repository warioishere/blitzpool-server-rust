// SPDX-License-Identifier: AGPL-3.0-or-later

//! Join-request lifecycle. Mirrors `pplns_group_join_request` (DB).
//!
//! User-initiated request to join a public group. Lifecycle:
//!
//! ```text
//! Pending -> Approved   (admin clicks approve; membership created)
//!         -> Rejected   (admin clicks reject)
//!         -> Expired    (cron sweeps after PENDING_EXPIRY_DAYS)
//! ```
//!
//! The TTL is much longer than directed-invitation TTL (30 d vs 7 d)
//! because admins may not check the panel often.

use crate::constants::{
    JOIN_REQUEST_PENDING_EXPIRY_DAYS, MAX_JOIN_REQUEST_MESSAGE_LEN, MS_PER_DAY,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl JoinRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JoinRequestTransitionError {
    #[error("join request has already been decided")]
    AlreadyDecided,
    #[error("join request has expired")]
    Expired,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JoinRequestMessageError {
    #[error(
        "join-request message must be at most {MAX_JOIN_REQUEST_MESSAGE_LEN} characters (got {0})"
    )]
    TooLong(usize),
}

/// Validate the optional admin-facing message that the requester
/// attaches when creating a join-request. `None` is always OK; `Some`
/// strings are bounded to [`MAX_JOIN_REQUEST_MESSAGE_LEN`]. Empty
/// strings are accepted as "no message" — the service layer can choose
/// whether to store them as `NULL` or empty.
pub fn validate_message(message: Option<&str>) -> Result<(), JoinRequestMessageError> {
    if let Some(m) = message {
        if m.len() > MAX_JOIN_REQUEST_MESSAGE_LEN {
            return Err(JoinRequestMessageError::TooLong(m.len()));
        }
    }
    Ok(())
}

/// Cutoff used by the cron sweeper: rows created before
/// `now - PENDING_EXPIRY_DAYS` should be moved to `Expired`.
pub fn stale_cutoff_ms(now_ms: i64) -> i64 {
    now_ms - JOIN_REQUEST_PENDING_EXPIRY_DAYS as i64 * MS_PER_DAY
}

/// `true` if a row created at `created_at_ms` is past the staleness
/// window at `now_ms`.
pub fn is_stale(created_at_ms: i64, now_ms: i64) -> bool {
    created_at_ms <= stale_cutoff_ms(now_ms)
}

/// Validate that a join-request in state `current` can be moved to
/// `Approved` or `Rejected`. Both transitions have the same
/// preconditions (still pending, not stale).
pub fn can_decide(
    current: JoinRequestStatus,
    created_at_ms: i64,
    now_ms: i64,
) -> Result<(), JoinRequestTransitionError> {
    match current {
        JoinRequestStatus::Pending => {
            if is_stale(created_at_ms, now_ms) {
                Err(JoinRequestTransitionError::Expired)
            } else {
                Ok(())
            }
        }
        JoinRequestStatus::Approved | JoinRequestStatus::Rejected => {
            Err(JoinRequestTransitionError::AlreadyDecided)
        }
        JoinRequestStatus::Expired => Err(JoinRequestTransitionError::Expired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_as_str_roundtrips() {
        for s in [
            JoinRequestStatus::Pending,
            JoinRequestStatus::Approved,
            JoinRequestStatus::Rejected,
            JoinRequestStatus::Expired,
        ] {
            assert_eq!(JoinRequestStatus::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn message_none_ok() {
        assert!(validate_message(None).is_ok());
    }

    #[test]
    fn message_short_ok() {
        assert!(validate_message(Some("hi please let me join!")).is_ok());
    }

    #[test]
    fn message_empty_ok() {
        assert!(validate_message(Some("")).is_ok());
    }

    #[test]
    fn message_at_cap_ok() {
        let m = "a".repeat(MAX_JOIN_REQUEST_MESSAGE_LEN);
        assert!(validate_message(Some(&m)).is_ok());
    }

    #[test]
    fn message_over_cap_rejected() {
        let m = "a".repeat(MAX_JOIN_REQUEST_MESSAGE_LEN + 1);
        assert_eq!(
            validate_message(Some(&m)),
            Err(JoinRequestMessageError::TooLong(
                MAX_JOIN_REQUEST_MESSAGE_LEN + 1
            ))
        );
    }

    #[test]
    fn stale_cutoff_is_thirty_days_behind() {
        let now = 1_000 * MS_PER_DAY;
        let cutoff = stale_cutoff_ms(now);
        assert_eq!(now - cutoff, 30 * MS_PER_DAY);
    }

    #[test]
    fn is_stale_at_exact_cutoff() {
        let now = 1_000 * MS_PER_DAY;
        let created_old = stale_cutoff_ms(now);
        let created_new = created_old + 1;
        assert!(is_stale(created_old, now));
        assert!(!is_stale(created_new, now));
    }

    #[test]
    fn pending_recent_can_be_decided() {
        let now = 1_000 * MS_PER_DAY;
        let created = now - MS_PER_DAY;
        assert_eq!(can_decide(JoinRequestStatus::Pending, created, now), Ok(()));
    }

    #[test]
    fn pending_stale_cannot_be_decided() {
        let now = 1_000 * MS_PER_DAY;
        let created = stale_cutoff_ms(now) - 1;
        assert_eq!(
            can_decide(JoinRequestStatus::Pending, created, now),
            Err(JoinRequestTransitionError::Expired)
        );
    }

    #[test]
    fn already_decided_rejects_redo() {
        let now = 1_000 * MS_PER_DAY;
        let created = now - MS_PER_DAY;
        assert_eq!(
            can_decide(JoinRequestStatus::Approved, created, now),
            Err(JoinRequestTransitionError::AlreadyDecided)
        );
        assert_eq!(
            can_decide(JoinRequestStatus::Rejected, created, now),
            Err(JoinRequestTransitionError::AlreadyDecided)
        );
    }

    #[test]
    fn expired_status_rejects_decide() {
        let now = 1_000 * MS_PER_DAY;
        let created = now - MS_PER_DAY;
        assert_eq!(
            can_decide(JoinRequestStatus::Expired, created, now),
            Err(JoinRequestTransitionError::Expired)
        );
    }
}
