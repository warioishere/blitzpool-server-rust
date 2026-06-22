// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound email hooks the `/api/email/*` controller calls into.
//! Covers the `sendVerification` / `sendBindingChangeAttempt` pair —
//! production wiring routes through
//! `bp-notifications::adapter::smtp::SmtpAdapter` +
//! the verification / binding-change templates.
//!
//! Best-effort: implementations should log + swallow errors instead
//! of propagating them up the register/verify path so a transient
//! SMTP outage doesn't block the user from a retry on a different
//! tab.

use async_trait::async_trait;

/// Email-send hooks. Both methods are best-effort.
#[async_trait]
pub trait EmailVerificationHooks: Send + Sync {
    /// Sent after `POST /api/email/register` succeeds — contains the
    /// verification link (`POOL_BASE_URL/#/email/verify/<token>`)
    /// the user clicks to confirm the binding.
    async fn send_verification(&self, ctx: VerificationContext);

    /// Sent when someone tries to re-register a different email for
    /// an address that already has a verified binding (FCFS lock).
    /// Goes to the EXISTING bound email so the rightful
    /// owner is warned about the attempt.
    async fn send_binding_change_attempt(&self, ctx: BindingChangeContext);
}

#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub to_email: String,
    pub address: String,
    pub verify_url: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct BindingChangeContext {
    pub to_email: String,
    pub address: String,
    pub attempted_email_masked: String,
}

/// No-op email sink. Default for AppState — every call quietly succeeds.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopVerificationHooks;

#[async_trait]
impl EmailVerificationHooks for NoopVerificationHooks {
    async fn send_verification(&self, _ctx: VerificationContext) {}
    async fn send_binding_change_attempt(&self, _ctx: BindingChangeContext) {}
}
