// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-management service layer — bridges the pure-domain
//! [`bp_group_mgmt`] validators with the DB writes from [`bp_db`] and
//! the engine-side Redis / cron hooks.
//!
//! Covers group lifecycle, membership, invitation, and join-request
//! orchestration.
//!
//! ## Why a separate crate?
//!
//! The companion [`bp_group_mgmt`] crate is pure validators + token
//! primitives + status enums — no `async`, no DB. The code that owns
//! the DB orchestration, the [`AddressCache`], and the Redis-cleanup
//! callbacks needs `tokio`, `sqlx`, and the cross-crate hook trait.
//! Mirrors the `bp_pplns` + `bp_pplns_engine` split.

pub mod cache;
pub mod cron;
pub mod email_hooks;
pub mod error;
pub mod hooks;
pub mod invitation;
pub mod join_request;
pub mod service;
mod util;

pub use cache::{AddressCache, GroupCacheEntry};
pub use cron::{
    expire_invitations_once, expire_join_requests_once, spawn_invitation_expiry_cron,
    spawn_join_request_expiry_cron,
};
pub use email_hooks::{
    CapturingEmailHooks, EmailHooks, InvitationEmailContext, JoinDecisionEmailContext,
    JoinDecisionOutcome, NoopEmailHooks,
};
pub use error::{GroupServiceError, InvitationServiceError, JoinRequestServiceError};
pub use hooks::{
    BlockpartyMembershipReader, GroupServiceHooks, MembershipChangeNotifier, NoopHooks,
};
pub use invitation::{
    DirectedInvitationCreated, InvitationService, InvitationServiceConfig, OpenInviteActive,
    OpenInviteCreated, OpenInvitePublicView, OpenInviteTtl, PendingForAddressView,
};
pub use join_request::{
    JoinRequestLimits, JoinRequestService, JoinRequestServiceConfig,
    PendingForAddressView as JoinRequestPendingForAddressView,
};
pub use service::{
    CreatorTransferResult, GroupCreateResult, GroupService, UpdateRoundResetSettings,
};
