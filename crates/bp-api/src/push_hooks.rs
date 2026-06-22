// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound push-notification hooks the `/api/push/*` controller can
//! call into to validate or pre-warm tokens at registration time.
//!
//! The persistent state of a subscription (rows in
//! `push_subscription_entity`) is owned by `bp-db`; this trait is
//! only for *side-effects* that involve an external service —
//! optionally validating an FCM token with Firebase, or sending a
//! welcome Web-Push ping after registration. Both are best-effort.
//!
//! `bin/blitzpool` wires this to the FCM adapter + Web-Push adapter
//! from `bp-notifications`. The default is
//! [`NoopPushHooks`] so an `AppState` without push wiring still
//! serves the register/configure endpoints (they hit only the DB).

use async_trait::async_trait;

/// Push-related side-effect hooks. All methods best-effort.
#[async_trait]
pub trait PushHooks: Send + Sync {
    /// Called after a successful `/api/push/fcm/register` to give the
    /// FCM adapter a chance to validate the token against Firebase.
    /// An invalid token is logged + swallowed — the DB row stays
    /// (the cleanup cron will prune it on the next failed send).
    async fn validate_fcm_token(&self, _ctx: FcmRegisterContext) {}

    /// Called after a successful `/api/push/register` (UnifiedPush).
    /// The default is a no-op; a future deployment could send a
    /// one-line "welcome" Web-Push to
    /// confirm reachability before the first real event arrives.
    async fn on_unified_push_registered(&self, _ctx: UnifiedPushRegisterContext) {}
}

#[derive(Debug, Clone)]
pub struct FcmRegisterContext {
    pub address: String,
    pub token: String,
    pub platform: String,
}

#[derive(Debug, Clone)]
pub struct UnifiedPushRegisterContext {
    pub address: String,
    pub endpoint: String,
    pub platform: String,
}

/// No-op push sink. Default for `AppState` — every call quietly
/// succeeds without touching any external service.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPushHooks;

#[async_trait]
impl PushHooks for NoopPushHooks {}
