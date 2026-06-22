// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group management — pure logic for tokens, validators, lifecycle
//! predicates, and status transitions.
//!
//! ## Scope
//!
//! Everything in this crate is **synchronous, side-effect-free, and
//! database-unaware.** The service-wiring layer reads rows from PG,
//! consults the validators here, and writes back.
//!
//! ## Modules
//!
//! - [`constants`] — bounds, TTLs, and threshold defaults.
//! - [`token`] — admin-token + invitation-token generation, SHA-256
//!   hashing, and constant-time verification.
//! - [`group`] — group-name validation, [`group::MemberRole`],
//!   active-threshold predicate, kick-eligibility check, round-reset
//!   config validator.
//! - [`invitation`] — invitation [`invitation::InvitationStatus`] /
//!   [`invitation::InvitationKind`] enums and transition validators.
//! - [`join_request`] — join-request [`join_request::JoinRequestStatus`]
//!   enum, message validator, and staleness check.
//!
//! ## What's deferred (see `DEFERRED.md`)
//!
//! - DB-coupled service operations (`createGroup` / `addMember` /
//!   `removeMember` / `transferCreator` / `dissolveGroup` / etc.) →
//!   service-wiring crate (depends on `bp-db` write extension).
//! - Email sending (`emailService.sendInvitation`) → `bp-notifications`.
//! - Address-cache rebuild for `getGroupForAddress` → the
//!   `GroupMembershipReader` impl in service-wiring (the trait itself
//!   already lives in [`bp_mining_mode`](../../bp-mining-mode/index.html)).
//! - Cron schedules for invitation/join-request expiry → service-wiring.
//! - IANA timezone validation → service-wiring (depends on OS + a
//!   timezone crate; here we only enforce non-empty shape).

pub mod constants;
pub mod group;
pub mod invitation;
pub mod join_request;
pub mod token;

pub use constants::{
    DEFAULT_KICK_INACTIVITY_DAYS, INVITATION_TTL_DAYS, JOIN_REQUEST_PENDING_EXPIRY_DAYS,
    MAX_FINDER_BONUS_SATS, MAX_GROUP_NAME_LEN, MAX_JOIN_REQUEST_MESSAGE_LEN,
    MAX_RESET_INTERVAL_DAYS, MIN_GROUP_NAME_LEN, MIN_MEMBERS_ACTIVE, MS_PER_DAY,
};
pub use group::{
    is_active, kick_eligibility, validate_round_reset, GroupName, GroupNameError, KickEligibility,
    MemberRole, RoundResetConfig, RoundResetError, RoundResetPreset,
};
pub use invitation::{
    can_accept, can_decline, can_revoke, expires_at, invitation_ttl_ms, is_expired, InvitationKind,
    InvitationStatus, InvitationTransitionError,
};
pub use join_request::{
    can_decide, is_stale, stale_cutoff_ms, validate_message, JoinRequestMessageError,
    JoinRequestStatus, JoinRequestTransitionError,
};
pub use token::{AdminToken, InvitationToken, TokenError, TokenHash};
