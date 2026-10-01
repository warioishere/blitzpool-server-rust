// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verified-email lookup. A member's email always comes from its verified
//! binding, so an admin can never inject one; the trait lets tests stub it.

use async_trait::async_trait;
use bp_common::AddressId;

#[async_trait]
pub trait BlockpartyHooks: Send + Sync {
    /// `None` when no verified binding exists.
    async fn verified_email_for(&self, address: &AddressId) -> Option<String>;
}

/// Resolves every address to the same canned email.
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
