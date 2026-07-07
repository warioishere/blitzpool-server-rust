// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-layer error model. Wire-codes (`code()`) are the stable
//! strings the bp-api HTTP-status layer maps to and the UI surfaces
//! verbatim. Same shape as [`bp_group_mgmt_engine::GroupServiceError`].

use bp_db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum BlockpartyServiceError {
    // ── Authn / authz ──────────────────────────────────────────────
    #[error("admin token required")]
    MissingToken,
    #[error("invalid admin token")]
    InvalidToken,
    #[error("member token required")]
    MissingMemberToken,
    #[error("invalid member token")]
    InvalidMemberToken,
    #[error("member not yet confirmed")]
    MemberNotConfirmed,

    // ── Lookup ─────────────────────────────────────────────────────
    #[error("blockparty not found")]
    NotFound,
    #[error("address is not a member of this blockparty")]
    NotMember,

    // ── Shape / validation ─────────────────────────────────────────
    #[error("group name must be 3–64 characters or contains control characters")]
    InvalidName,
    #[error("address is invalid or missing")]
    InvalidAddress,
    #[error("email is invalid or missing")]
    InvalidEmail,
    #[error("percentBp out of range (must be 100..=10000)")]
    InvalidPercent,
    #[error("splits must sum to exactly 10000 (= 100 % of miner cut)")]
    InvalidSplitsSum,
    #[error("operation not valid for the party's current status")]
    InvalidState,

    // ── Uniqueness / collision ─────────────────────────────────────
    #[error("blockparty name already in use")]
    NameTaken,
    #[error("admin address already runs another blockparty")]
    AdminAddressTaken,
    #[error("address is already a member of a blockparty")]
    AddressInBlockparty,
    #[error("address is already a member of a PPLNS group — leave that group first")]
    AddressInPplnsGroup,
    #[error("address has no verified email binding")]
    EmailNotVerified,

    // ── Lifecycle invariants ───────────────────────────────────────
    #[error("admin is already a member")]
    AdminCannotRejoin,
    #[error("admin cannot be removed — dissolve the blockparty instead")]
    AdminCannotBeRemoved,
    #[error("blockparty is not editable in its current status")]
    NotEditable,
    #[error("blockparty has no members")]
    NoMembers,
    #[error("dissolve cooldown active — wait for 7 days of share silence")]
    DissolveCooldown,

    // ── Wrapped lower-layer errors ─────────────────────────────────
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("token CSPRNG failure: {0}")]
    Token(#[from] bp_group_mgmt::TokenError),
}

impl BlockpartyServiceError {
    /// Stable wire-code. The HTTP layer maps these to status codes;
    /// the UI surfaces them verbatim.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingToken => "missing-token",
            Self::InvalidToken => "invalid-token",
            Self::MissingMemberToken => "missing-member-token",
            Self::InvalidMemberToken => "invalid-member-token",
            Self::MemberNotConfirmed => "member-not-confirmed",
            Self::NotFound => "not-found",
            Self::NotMember => "not-member",
            Self::InvalidName => "invalid-name",
            Self::InvalidAddress => "invalid-address",
            Self::InvalidEmail => "invalid-email",
            Self::InvalidPercent => "invalid-percent",
            Self::InvalidSplitsSum => "invalid-splits-sum",
            Self::InvalidState => "invalid-state",
            Self::NameTaken => "name-taken",
            Self::AdminAddressTaken => "admin-address-taken",
            Self::AddressInBlockparty => "address-in-blockparty",
            Self::AddressInPplnsGroup => "address-in-pplns-group",
            Self::EmailNotVerified => "email-not-verified",
            Self::AdminCannotRejoin => "admin-cannot-rejoin",
            Self::AdminCannotBeRemoved => "admin-cannot-be-removed",
            Self::NotEditable => "not-editable",
            Self::NoMembers => "no-members",
            Self::DissolveCooldown => "dissolve-cooldown",
            Self::Db(_) | Self::Token(_) => "internal-error",
        }
    }
}
