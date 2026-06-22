// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound-email hook trait. The invitation + join-request services
//! call into this for the three transactional email kinds (invitation
//! / approved / rejected). Production wiring routes through
//! `bp-notifications::adapter::smtp::SmtpAdapter` +
//! `bp-notifications::template::*`.
//!
//! Best-effort: failed sends are logged and swallowed by the caller.
//! We split this out so tests can swap in [`CapturingEmailHooks`] to
//! assert what would have been sent without standing up SMTP.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// Data passed to [`EmailHooks::send_invitation`] for a freshly-created
/// directed invitation. The hook owner is responsible for picking the
/// right template (`bp-notifications::template::invitation::*`) and
/// putting the URL together from `accept_url` (already includes the
/// hash-prefix `/#/invite/<token>` segment used by the SPA).
#[derive(Debug, Clone)]
pub struct InvitationEmailContext {
    pub to_email: String,
    pub address: String,
    pub group_name: String,
    pub inviter_address: String,
    pub accept_url: String,
    pub expires_at_ms: i64,
}

/// Data passed to [`EmailHooks::send_join_decision`] for approve /
/// reject paths. `outcome` is the discriminant the template uses.
#[derive(Debug, Clone)]
pub struct JoinDecisionEmailContext {
    pub to_email: String,
    pub address: String,
    pub group_name: String,
    pub outcome: JoinDecisionOutcome,
    pub group_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinDecisionOutcome {
    Approved,
    Rejected,
}

/// Outbound email hook. All methods are best-effort: implementations
/// should log + swallow errors instead of propagating them up the
/// admin-request path.
#[async_trait]
pub trait EmailHooks: Send + Sync {
    async fn send_invitation(&self, ctx: InvitationEmailContext);
    async fn send_join_decision(&self, ctx: JoinDecisionEmailContext);
}

/// No-op email sink. Used by Phase-7 wiring when SMTP isn't
/// configured + by integration tests where the SMTP fan-out is
/// out-of-scope.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEmailHooks;

#[async_trait]
impl EmailHooks for NoopEmailHooks {
    async fn send_invitation(&self, _ctx: InvitationEmailContext) {}
    async fn send_join_decision(&self, _ctx: JoinDecisionEmailContext) {}
}

/// In-memory capture sink for tests. Stores every send call in order
/// so assertions can inspect counts + payloads.
#[derive(Debug, Default, Clone)]
pub struct CapturingEmailHooks {
    pub invitations: Arc<Mutex<Vec<InvitationEmailContext>>>,
    pub decisions: Arc<Mutex<Vec<JoinDecisionEmailContext>>>,
}

impl CapturingEmailHooks {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn invitations_snapshot(&self) -> Vec<InvitationEmailContext> {
        self.invitations.lock().unwrap().clone()
    }
    pub fn decisions_snapshot(&self) -> Vec<JoinDecisionEmailContext> {
        self.decisions.lock().unwrap().clone()
    }
}

#[async_trait]
impl EmailHooks for CapturingEmailHooks {
    async fn send_invitation(&self, ctx: InvitationEmailContext) {
        self.invitations.lock().unwrap().push(ctx);
    }
    async fn send_join_decision(&self, ctx: JoinDecisionEmailContext) {
        self.decisions.lock().unwrap().push(ctx);
    }
}
