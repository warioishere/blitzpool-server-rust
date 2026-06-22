// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-layer error types. Wire-codes (`as_str()`) match the
//! strings surfaced in API error envelopes so the UI doesn't need
//! a translation table during cut-over.

use bp_db::DbError;

/// Errors thrown by [`crate::service::GroupService`]. Wire-codes are
/// stable so the existing UI error mapping keeps working.
#[derive(Debug, thiserror::Error)]
pub enum GroupServiceError {
    #[error("admin token required")]
    MissingToken,
    #[error("group not found")]
    NotFound,
    #[error("invalid admin token")]
    InvalidToken,
    #[error("group name must be 3–64 characters or contains control characters")]
    InvalidName,
    #[error("address is invalid or missing")]
    InvalidAddress,
    #[error("group name already in use")]
    NameTaken,
    #[error("address is already a member of another group")]
    AddressInGroup,
    #[error("address is already a member of a Blockparty — leave that party first")]
    AddressInBlockparty,
    #[error("address is already a member of this group")]
    AlreadyMember,
    #[error("address is not a member of this group")]
    NotMember,
    #[error("creator cannot be removed — transfer or dissolve first")]
    CreatorCannotBeRemoved,
    #[error("target address is already the creator")]
    AlreadyCreator,
    #[error("member has been active within the kick-inactivity window")]
    MemberStillActive {
        required_days: u32,
        actual_days: f64,
    },
    #[error("invalid intervalDays for the requested preset")]
    InvalidInterval,
    #[error("invalid roundResetPreset value")]
    InvalidPreset,
    #[error("invalid IANA timezone")]
    InvalidTimezone,
    #[error("invalid finderBonusSats (range / sub-minPayout)")]
    InvalidBonus,
    #[error("invalid maxMembers (must be an integer >= 2 or null)")]
    InvalidMaxMembers,
    #[error("group has reached its maximum number of members")]
    GroupFull,
    #[error("round-reset schedule is incomplete (missing timezone or interval)")]
    IncompleteSchedule,
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("token CSPRNG failure: {0}")]
    Token(#[from] bp_group_mgmt::TokenError),
}

impl GroupServiceError {
    /// Stable wire-code. The HTTP layer maps these to status codes;
    /// the UI surfaces them verbatim for localization.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingToken => "missing-token",
            Self::NotFound => "not-found",
            Self::InvalidToken => "invalid-token",
            Self::InvalidName => "invalid-name",
            Self::InvalidAddress => "invalid-address",
            Self::NameTaken => "name-taken",
            Self::AddressInGroup => "address-in-group",
            Self::AddressInBlockparty => "address-in-blockparty",
            Self::AlreadyMember => "already-member",
            Self::NotMember => "not-member",
            Self::CreatorCannotBeRemoved => "creator-cannot-be-removed",
            Self::AlreadyCreator => "already-creator",
            Self::MemberStillActive { .. } => "member-still-active",
            Self::InvalidInterval => "invalid-interval",
            Self::InvalidPreset => "invalid-preset",
            Self::InvalidTimezone => "invalid-timezone",
            Self::InvalidBonus => "invalid-bonus",
            Self::InvalidMaxMembers => "invalid-max-members",
            Self::GroupFull => "group-full",
            Self::IncompleteSchedule => "incomplete-schedule",
            Self::Db(_) => "internal-error",
            Self::Token(_) => "internal-error",
        }
    }
}

/// Errors thrown by [`crate::invitation::InvitationService`]. Wire-codes
/// are stable so the existing UI error mapping keeps working.
#[derive(Debug, thiserror::Error)]
pub enum InvitationServiceError {
    #[error("invitation not found")]
    NotFound,
    #[error("invitation already declined")]
    AlreadyDeclined,
    #[error("invitation accepted but member row missing — DB inconsistency")]
    Inconsistent,
    #[error("invitation expired")]
    Expired,
    #[error("group has been dissolved")]
    GroupDissolved,
    #[error("invitation for this address already pending")]
    InvitationPending,
    #[error("address has no verified email binding")]
    EmailNotVerified,
    #[error("address is invalid or missing")]
    InvalidAddress,
    #[error("address is already in another group")]
    AddressInGroup,
    #[error("address is already a member of this group")]
    AlreadyMember,
    #[error("invalid TTL preset")]
    InvalidTtl,
    #[error("link requires admin approval — submit a join request instead")]
    ApprovalRequired,
    #[error("required configuration is missing (POOL_BASE_URL)")]
    ConfigMissing,
    #[error("group-service error: {0}")]
    GroupService(#[from] GroupServiceError),
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("token CSPRNG failure: {0}")]
    Token(#[from] bp_group_mgmt::TokenError),
}

impl InvitationServiceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::AlreadyDeclined => "already-declined",
            Self::Inconsistent => "inconsistent",
            Self::Expired => "expired",
            Self::GroupDissolved => "group-dissolved",
            Self::InvitationPending => "invitation-pending",
            Self::EmailNotVerified => "email-not-verified",
            Self::InvalidAddress => "invalid-address",
            Self::AddressInGroup => "address-in-group",
            Self::AlreadyMember => "already-member",
            Self::InvalidTtl => "invalid-ttl",
            Self::ApprovalRequired => "approval-required",
            Self::ConfigMissing => "config-missing",
            // Surface the inner GroupServiceError code verbatim so the
            // UI sees the same vocabulary regardless of which service
            // tripped.
            Self::GroupService(e) => e.code(),
            Self::Db(_) | Self::Token(_) => "internal-error",
        }
    }
}

/// Errors thrown by [`crate::join_request::JoinRequestService`].
/// Wire-codes are stable so the existing UI error mapping keeps working.
#[derive(Debug, thiserror::Error)]
pub enum JoinRequestServiceError {
    #[error("group not found")]
    NotFound,
    #[error("address is invalid or missing")]
    InvalidAddress,
    #[error("address has no verified email binding")]
    EmailNotVerified,
    #[error("address is already a member of this group")]
    AlreadyMember,
    #[error("address is already in another group")]
    AddressInGroup,
    #[error("too many pending join requests for this address")]
    TooManyPending,
    #[error("recently-rejected — cooldown active")]
    RejectCooldown { hours_left: u32 },
    #[error("join request for this address already pending")]
    RequestPending,
    #[error("group has been dissolved")]
    GroupDissolved,
    #[error("group-service error: {0}")]
    GroupService(#[from] GroupServiceError),
    #[error("database error: {0}")]
    Db(#[from] DbError),
}

impl JoinRequestServiceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::InvalidAddress => "invalid-address",
            Self::EmailNotVerified => "email-not-verified",
            Self::AlreadyMember => "already-member",
            Self::AddressInGroup => "address-in-group",
            Self::TooManyPending => "too-many-pending",
            Self::RejectCooldown { .. } => "reject-cooldown",
            Self::RequestPending => "request-pending",
            Self::GroupDissolved => "group-dissolved",
            Self::GroupService(e) => e.code(),
            Self::Db(_) => "internal-error",
        }
    }
}
