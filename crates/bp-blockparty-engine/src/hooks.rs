// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-cutting hooks the service relies on. The mode-collision check
//! against PplnsGroup is wired directly through a
//! [`bp_group_mgmt_engine::AddressCache`] handed to the service at
//! construction — no trait needed there.
//!
//! The remaining cross-cut is **verified-email lookup**: the invitee's
//! email is pulled from the verified-email-binding service so the admin
//! can never inject a bogus email. The hook abstracts that lookup so
//! tests can supply a stub instead of standing up the real email
//! verification pipeline.

use async_trait::async_trait;
use bp_common::AddressId;

/// Cross-crate dependency surface. Currently minimal: one lookup.
#[async_trait]
pub trait BlockpartyHooks: Send + Sync {
    /// Return the verified email-binding for `address`, or `None` if no
    /// binding exists / is unverified. Service callers gate `addMember`
    /// on a non-`None` return — bare addMember without verified email
    /// surfaces as [`crate::BlockpartyServiceError::EmailNotVerified`].
    async fn verified_email_for(&self, address: &AddressId) -> Option<String>;
}

/// Sentinel for tests + bring-up wiring: every address resolves to the
/// same canned email. Tests that don't care about the binding flow can
/// use this; tests that DO need to assert "missing email" branches
/// should supply a small `FnMut`-style stub instead.
#[derive(Debug, Clone)]
pub struct NoopHooks {
    pub canned_email: String,
}

impl Default for NoopHooks {
    fn default() -> Self {
        Self {
            canned_email: "stub@example.test".to_owned(),
        }
    }
}

#[async_trait]
impl BlockpartyHooks for NoopHooks {
    async fn verified_email_for(&self, _address: &AddressId) -> Option<String> {
        Some(self.canned_email.clone())
    }
}
