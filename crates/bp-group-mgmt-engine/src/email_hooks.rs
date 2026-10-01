// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound-email hook for invitation and join-decision mails. A trait so
//! tests can assert sends with [`CapturingEmailHooks`] without SMTP.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// Data for [`EmailHooks::send_invitation`]. `accept_url` already
/// includes the SPA's `/#/invite/<token>` segment.
#[derive(Debug, Clone)]
pub struct InvitationEmailContext {
    pub to_email: String,
    pub address: String,
    pub group_name: String,
    pub inviter_address: String,
    pub accept_url: String,
    pub expires_at_ms: i64,
}

/// Data for [`EmailHooks::send_join_decision`].
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

/// Best-effort: implementations log and swallow errors, so a failed mail
/// never fails the admin request.
#[async_trait]
pub trait EmailHooks: Send + Sync {
    async fn send_invitation(&self, ctx: InvitationEmailContext);
    async fn send_join_decision(&self, ctx: JoinDecisionEmailContext);
}

/// Used when SMTP isn't configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEmailHooks;

#[async_trait]
impl EmailHooks for NoopEmailHooks {
    async fn send_invitation(&self, _ctx: InvitationEmailContext) {}
    async fn send_join_decision(&self, _ctx: JoinDecisionEmailContext) {}
}

/// Test sink that records every send in order.
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
