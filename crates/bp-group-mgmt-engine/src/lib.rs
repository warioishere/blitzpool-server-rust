// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-management service layer: group lifecycle, membership,
//! invitations and join requests. It joins the pure [`bp_group_mgmt`]
//! validators (no async, no DB) with [`bp_db`] writes, the
//! [`AddressCache`] and the Redis / cron hooks.

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
    CapturingEmailHooks, EmailHooks, JoinDecisionEmailContext, JoinDecisionOutcome, NoopEmailHooks,
};
pub use error::{GroupServiceError, InvitationServiceError, JoinRequestServiceError};
pub use hooks::{
    BlockpartyMembershipReader, GroupServiceHooks, MembershipChangeNotifier, NoopHooks,
};
pub use invitation::{
    InvitationService, OpenInviteActive, OpenInviteCreated, OpenInvitePublicView, OpenInviteTtl,
};
pub use join_request::{
    JoinRequestLimits, JoinRequestService, JoinRequestServiceConfig,
    PendingForAddressView as JoinRequestPendingForAddressView,
};
pub use service::{
    CreatorTransferResult, GroupCreateResult, GroupService, UpdateRoundResetSettings,
};
