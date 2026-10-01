// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group management pure logic: tokens, validators, lifecycle predicates
//! and status transitions. Synchronous, side-effect-free and DB-unaware;
//! DB work and IANA timezone validation live in the service layer, this
//! crate only checks the timezone is non-empty.

pub mod constants;
pub mod group;
pub mod invitation;
pub mod join_request;
pub mod token;

pub use constants::{
    DEFAULT_KICK_INACTIVITY_DAYS, JOIN_REQUEST_PENDING_EXPIRY_DAYS, MAX_FINDER_BONUS_PPM,
    MAX_GROUP_NAME_LEN, MAX_JOIN_REQUEST_MESSAGE_LEN, MAX_RESET_INTERVAL_DAYS, MIN_GROUP_NAME_LEN,
    MIN_MEMBERS_ACTIVE, MS_PER_DAY,
};
pub use group::{
    is_active, kick_eligibility, validate_round_reset, GroupName, GroupNameError, KickEligibility,
    MemberRole, RoundResetConfig, RoundResetError, RoundResetPreset,
};
pub use invitation::OPEN_INVITE_TYPE;
pub use join_request::{
    can_decide, is_stale, stale_cutoff_ms, validate_message, JoinRequestMessageError,
    JoinRequestStatus, JoinRequestTransitionError,
};
pub use token::{AdminToken, InvitationToken, TokenError, TokenHash};
