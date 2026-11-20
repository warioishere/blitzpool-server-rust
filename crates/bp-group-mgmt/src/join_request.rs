// SPDX-License-Identifier: AGPL-3.0-or-later

//! Join-request lifecycle for `pplns_group_join_request`: `Pending` →
//! `Approved` | `Rejected` | `Expired`. The expiry is far longer than an
//! invitation's because admins may not check the panel often.

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
}

/// A `status` text that names no [`JoinRequestStatus`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown join-request status {0:?}")]
pub struct UnknownJoinRequestStatus(pub String);

impl std::str::FromStr for JoinRequestStatus {
    type Err = UnknownJoinRequestStatus;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            other => Err(UnknownJoinRequestStatus(other.to_owned())),
        }
    }
}

#[cfg(feature = "sqlx")]
bp_common::impl_pg_text_enum!(JoinRequestStatus);

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
            assert_eq!(s.as_str().parse::<JoinRequestStatus>(), Ok(s));
        }
    }
}
