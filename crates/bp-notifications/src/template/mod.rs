// SPDX-License-Identifier: AGPL-3.0-or-later

//! Email-template rendering — pure functions producing
//! [`EmailContent`] triples (`subject`, `html`, `text`).
//!
//! Five template families for outbound email:
//!
//! - [`render_verification`] — email-binding confirmation
//! - [`render_invitation`] — payout-group invitation
//! - [`render_join_decision`] — public join-request approval / rejection
//! - [`render_binding_change`] — K1-lock attempted-takeover notice
//! - [`render_capacity_alert`] — coinbase-output capacity operator alert
//!
//! The render functions are pure: same context → same bytes. Recipient
//! email is **not** part of the context structs (the adapter layer
//! supplies `to:` when calling SMTP). The shell HTML, branding, and
//! escaping helpers are private to this module so the template surface
//! stays small and uniform.

mod binding_change;
mod capacity_alert;
mod content;
mod helpers;
mod invitation;
mod join_decision;
mod verification;

pub use binding_change::{render_binding_change, BindingChangeContext};
pub use capacity_alert::{render_capacity_alert, CapacityAlertContext, CapacityAlertLevel};
pub use content::EmailContent;
pub use invitation::{render_invitation, InvitationContext};
pub use join_decision::{render_join_decision, JoinDecision, JoinDecisionContext};
pub use verification::{render_verification, VerificationContext};
