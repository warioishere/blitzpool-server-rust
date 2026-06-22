// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BlockpartyStatus` — the party lifecycle FSM.
//!
//! Wire format matches the kebab-strings stored in the `status`
//! column: `draft` → `confirming` → `ready` → `active` → `dissolved`.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockpartyStatus {
    Draft,
    Confirming,
    Ready,
    Active,
    Dissolved,
}

impl BlockpartyStatus {
    /// Stable column value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Confirming => "confirming",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Dissolved => "dissolved",
        }
    }

    /// `true` for the two statuses that route shares into a Blockparty
    /// coinbase. Shares from any other status fall through to whatever
    /// mode resolves next (member can still mine in their own mode).
    pub const fn is_routable(self) -> bool {
        matches!(self, Self::Ready | Self::Active)
    }

    /// `true` for the two statuses where admin-side shares route 100%
    /// to the pool-fee address instead of falling through to solo. Keeps
    /// the admin from pocketing the entire reward via the solo fallback
    /// before all members confirm the split.
    pub const fn is_pending_fee_route(self) -> bool {
        matches!(self, Self::Draft | Self::Confirming)
    }

    /// `true` for the three statuses where the admin may add/remove
    /// members or change splits.
    pub const fn is_editable(self) -> bool {
        matches!(self, Self::Draft | Self::Confirming | Self::Ready)
    }
}

impl fmt::Display for BlockpartyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBlockpartyStatusError(pub String);

impl fmt::Display for ParseBlockpartyStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown blockparty status: {}", self.0)
    }
}

impl std::error::Error for ParseBlockpartyStatusError {}

impl FromStr for BlockpartyStatus {
    type Err = ParseBlockpartyStatusError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "draft" => Ok(Self::Draft),
            "confirming" => Ok(Self::Confirming),
            "ready" => Ok(Self::Ready),
            "active" => Ok(Self::Active),
            "dissolved" => Ok(Self::Dissolved),
            other => Err(ParseBlockpartyStatusError(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routable_only_ready_active() {
        assert!(!BlockpartyStatus::Draft.is_routable());
        assert!(!BlockpartyStatus::Confirming.is_routable());
        assert!(BlockpartyStatus::Ready.is_routable());
        assert!(BlockpartyStatus::Active.is_routable());
        assert!(!BlockpartyStatus::Dissolved.is_routable());
    }

    #[test]
    fn pending_fee_only_draft_confirming() {
        assert!(BlockpartyStatus::Draft.is_pending_fee_route());
        assert!(BlockpartyStatus::Confirming.is_pending_fee_route());
        assert!(!BlockpartyStatus::Ready.is_pending_fee_route());
        assert!(!BlockpartyStatus::Active.is_pending_fee_route());
        assert!(!BlockpartyStatus::Dissolved.is_pending_fee_route());
    }

    #[test]
    fn editable_excludes_active_and_dissolved() {
        assert!(BlockpartyStatus::Draft.is_editable());
        assert!(BlockpartyStatus::Confirming.is_editable());
        assert!(BlockpartyStatus::Ready.is_editable());
        assert!(!BlockpartyStatus::Active.is_editable());
        assert!(!BlockpartyStatus::Dissolved.is_editable());
    }

    #[test]
    fn roundtrip_via_str() {
        for s in ["draft", "confirming", "ready", "active", "dissolved"] {
            assert_eq!(BlockpartyStatus::from_str(s).unwrap().as_str(), s);
        }
        assert!(BlockpartyStatus::from_str("nope").is_err());
    }
}
