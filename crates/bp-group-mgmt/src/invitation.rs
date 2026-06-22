// SPDX-License-Identifier: AGPL-3.0-or-later

//! Invitation lifecycle types + status-transition validator.
//!
//! Mirrors `pplns_group_invitation` (DB). The two flavours of
//! invitation — `directed` (admin → specific address, single-use, emailed)
//! and `open` (admin → shareable link, multi-use) — share the status enum
//! but use different subsets of it (see [`InvitationStatus::Accepted`]).

use crate::constants::{INVITATION_TTL_DAYS, MS_PER_DAY};

/// One of the two invitation flavours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvitationKind {
    /// Admin specifies the recipient address up front; system emails a
    /// tokenized link; recipient accepts or declines. One-shot.
    Directed,
    /// Admin generates a TTL-limited shareable token; whoever holds it can
    /// claim it (multi-use until TTL or manual revoke).
    Open,
}

impl InvitationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directed => "directed",
            Self::Open => "open",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "directed" => Self::Directed,
            "open" => Self::Open,
            _ => return None,
        })
    }
}

/// Status of an invitation row. Lifecycle:
///
/// - **directed**: `Pending` → `Accepted` | `Declined` | `Expired`
/// - **open**:     `Pending` → `Revoked` | `Expired`
///   (no `Accepted` — open invites stay claimable until TTL/revoke).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
    Revoked,
}

impl InvitationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            "declined" => Self::Declined,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => return None,
        })
    }
}

/// Reason a transition was rejected. Surfaces in service-layer errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvitationTransitionError {
    #[error("invitation has expired")]
    Expired,
    #[error("invitation was already accepted")]
    AlreadyAccepted,
    #[error("invitation was declined")]
    AlreadyDeclined,
    #[error("invitation was revoked")]
    AlreadyRevoked,
    #[error("status transition not valid for {kind} invitations")]
    InvalidForKind { kind: InvitationKind },
}

impl std::fmt::Display for InvitationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Default invitation TTL as a millisecond delta from `created_at`.
pub fn invitation_ttl_ms() -> i64 {
    INVITATION_TTL_DAYS as i64 * MS_PER_DAY
}

/// `true` if the invitation row is past its `expires_at` at `now_ms`.
/// Used by both the cron sweeper and inline-on-read checks before
/// honouring an accept/decline.
pub fn is_expired(expires_at_ms: i64, now_ms: i64) -> bool {
    now_ms >= expires_at_ms
}

/// Compute `expires_at` for a freshly-created invitation, using the
/// default TTL.
pub fn expires_at(created_at_ms: i64) -> i64 {
    created_at_ms + invitation_ttl_ms()
}

/// Validate that an invitation in state `current` can be moved to
/// `Accepted`. Returns `Ok(())` for a clean `Pending → Accepted`; an
/// `Err(_)` for any other current status or when `kind == Open` (open
/// invites have no `Accepted` state).
pub fn can_accept(
    current: InvitationStatus,
    kind: InvitationKind,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), InvitationTransitionError> {
    if kind == InvitationKind::Open {
        return Err(InvitationTransitionError::InvalidForKind { kind });
    }
    match current {
        InvitationStatus::Accepted => Err(InvitationTransitionError::AlreadyAccepted),
        InvitationStatus::Declined => Err(InvitationTransitionError::AlreadyDeclined),
        InvitationStatus::Revoked => Err(InvitationTransitionError::AlreadyRevoked),
        InvitationStatus::Expired => Err(InvitationTransitionError::Expired),
        InvitationStatus::Pending => {
            if is_expired(expires_at_ms, now_ms) {
                Err(InvitationTransitionError::Expired)
            } else {
                Ok(())
            }
        }
    }
}

/// Validate that an invitation in state `current` can be moved to
/// `Declined`. Same semantics as [`can_accept`], specialised for the
/// decline path.
pub fn can_decline(
    current: InvitationStatus,
    kind: InvitationKind,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), InvitationTransitionError> {
    if kind == InvitationKind::Open {
        return Err(InvitationTransitionError::InvalidForKind { kind });
    }
    match current {
        InvitationStatus::Accepted => Err(InvitationTransitionError::AlreadyAccepted),
        InvitationStatus::Declined => Err(InvitationTransitionError::AlreadyDeclined),
        InvitationStatus::Revoked => Err(InvitationTransitionError::AlreadyRevoked),
        InvitationStatus::Expired => Err(InvitationTransitionError::Expired),
        InvitationStatus::Pending => {
            if is_expired(expires_at_ms, now_ms) {
                Err(InvitationTransitionError::Expired)
            } else {
                Ok(())
            }
        }
    }
}

/// Validate that an open invite can be revoked. Open-only —
/// directed invites can't be "revoked" (they're either still pending,
/// accepted, declined, or expired).
pub fn can_revoke(
    current: InvitationStatus,
    kind: InvitationKind,
) -> Result<(), InvitationTransitionError> {
    if kind == InvitationKind::Directed {
        return Err(InvitationTransitionError::InvalidForKind { kind });
    }
    match current {
        InvitationStatus::Pending => Ok(()),
        InvitationStatus::Revoked => Err(InvitationTransitionError::AlreadyRevoked),
        InvitationStatus::Expired => Err(InvitationTransitionError::Expired),
        InvitationStatus::Accepted | InvitationStatus::Declined => {
            Err(InvitationTransitionError::InvalidForKind { kind })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_is_seven_days_in_ms() {
        assert_eq!(invitation_ttl_ms(), 7 * 24 * 60 * 60 * 1000);
    }

    #[test]
    fn expires_at_is_created_at_plus_ttl() {
        let created = 1_000_000_000;
        let exp = expires_at(created);
        assert_eq!(exp - created, invitation_ttl_ms());
    }

    #[test]
    fn is_expired_uses_inclusive_now_ge_expires() {
        let exp = 1_000_000_000;
        assert!(!is_expired(exp, exp - 1));
        // Exactly at expires_at → expired (closed-open expiry contract).
        assert!(is_expired(exp, exp));
        assert!(is_expired(exp, exp + 1));
    }

    #[test]
    fn directed_pending_can_be_accepted_or_declined() {
        let exp = 1_000;
        let now = 500;
        assert_eq!(
            can_accept(
                InvitationStatus::Pending,
                InvitationKind::Directed,
                exp,
                now
            ),
            Ok(())
        );
        assert_eq!(
            can_decline(
                InvitationStatus::Pending,
                InvitationKind::Directed,
                exp,
                now
            ),
            Ok(())
        );
    }

    #[test]
    fn open_invitation_cannot_accept_or_decline() {
        let e1 = can_accept(InvitationStatus::Pending, InvitationKind::Open, 1_000, 500);
        let e2 = can_decline(InvitationStatus::Pending, InvitationKind::Open, 1_000, 500);
        assert!(matches!(
            e1,
            Err(InvitationTransitionError::InvalidForKind {
                kind: InvitationKind::Open
            })
        ));
        assert!(matches!(
            e2,
            Err(InvitationTransitionError::InvalidForKind {
                kind: InvitationKind::Open
            })
        ));
    }

    #[test]
    fn expired_pending_cannot_be_accepted() {
        let exp = 1_000;
        let now = 1_500;
        assert_eq!(
            can_accept(
                InvitationStatus::Pending,
                InvitationKind::Directed,
                exp,
                now
            ),
            Err(InvitationTransitionError::Expired)
        );
    }

    #[test]
    fn already_accepted_rejects_redo() {
        assert_eq!(
            can_accept(
                InvitationStatus::Accepted,
                InvitationKind::Directed,
                1_000,
                500
            ),
            Err(InvitationTransitionError::AlreadyAccepted)
        );
        assert_eq!(
            can_decline(
                InvitationStatus::Accepted,
                InvitationKind::Directed,
                1_000,
                500
            ),
            Err(InvitationTransitionError::AlreadyAccepted)
        );
    }

    #[test]
    fn directed_cannot_be_revoked() {
        assert!(matches!(
            can_revoke(InvitationStatus::Pending, InvitationKind::Directed),
            Err(InvitationTransitionError::InvalidForKind {
                kind: InvitationKind::Directed
            })
        ));
    }

    #[test]
    fn open_pending_revokable_once() {
        assert_eq!(
            can_revoke(InvitationStatus::Pending, InvitationKind::Open),
            Ok(())
        );
        assert_eq!(
            can_revoke(InvitationStatus::Revoked, InvitationKind::Open),
            Err(InvitationTransitionError::AlreadyRevoked)
        );
    }

    #[test]
    fn status_as_str_roundtrips() {
        for s in [
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
            InvitationStatus::Declined,
            InvitationStatus::Expired,
            InvitationStatus::Revoked,
        ] {
            assert_eq!(InvitationStatus::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn kind_as_str_roundtrips() {
        for k in [InvitationKind::Directed, InvitationKind::Open] {
            assert_eq!(InvitationKind::parse(k.as_str()), Some(k));
        }
    }

    #[test]
    fn from_str_returns_none_on_garbage() {
        assert_eq!(InvitationStatus::parse("nope"), None);
        assert_eq!(InvitationKind::parse("nope"), None);
    }
}
