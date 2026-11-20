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
    JOIN_REQUEST_PENDING_EXPIRY_DAYS, KICK_INACTIVITY_DAYS, MAX_FINDER_BONUS_PPM,
    MAX_GROUP_NAME_LEN, MAX_JOIN_REQUEST_MESSAGE_LEN, MAX_RESET_INTERVAL_DAYS, MIN_GROUP_NAME_LEN,
    MS_PER_DAY,
};
pub use group::{
    validate_round_reset, GroupName, GroupNameError, MemberRole, RoundResetConfig, RoundResetError,
    RoundResetPreset,
};
pub use invitation::OPEN_INVITE_TYPE;
pub use join_request::JoinRequestStatus;
pub use token::{AdminToken, InvitationToken, TokenError, TokenHash};
