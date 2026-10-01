// SPDX-License-Identifier: AGPL-3.0-or-later

//! Email-template rendering: pure functions producing [`EmailContent`].
//! The recipient is not part of any context; the SMTP adapter supplies `to:`.

mod binding_change;
mod content;
mod helpers;
mod join_decision;
mod verification;

pub use binding_change::{render_binding_change, BindingChangeContext};
pub use content::EmailContent;
pub use join_decision::{render_join_decision, JoinDecision, JoinDecisionContext};
pub use verification::{render_verification, VerificationContext};
