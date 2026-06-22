// SPDX-License-Identifier: AGPL-3.0-or-later

//! Token primitives — generation, hashing, constant-time verification.
//!
//! Two token shapes:
//!
//! - **Admin tokens** prefixed with `GRP-` — handed to the group creator
//!   exactly once and used for every admin action (member add/remove,
//!   round-reset config update, dissolve, transfer). 24 bytes of CSPRNG
//!   entropy ≈ 192 bits.
//! - **Invitation tokens** without prefix — embedded in invitation /
//!   open-invite URLs. 32 bytes of CSPRNG entropy = 256 bits. The
//!   extra entropy reflects that invitation links are pasted into chat
//!   apps / forwarded by humans, so a slightly larger search space is
//!   worth the longer URL.
//!
//! Both are stored as **hashes** (`sha256` hex) in the DB; the plaintext
//! is only ever returned to the human-in-the-loop once. Verification is
//! constant-time via [`subtle::ConstantTimeEq`].

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Cleartext admin token — produced once at group creation / creator
/// transfer, returned to the human admin, never persisted.
#[derive(Debug, Clone)]
pub struct AdminToken(String);

/// Cleartext invitation token — embedded in `/#/invite/<token>` URLs.
#[derive(Debug, Clone)]
pub struct InvitationToken(String);

/// Hex-encoded SHA-256 of a token. What we store in PG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHash(String);

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("system CSPRNG unavailable: {0}")]
    Csprng(String),
}

impl AdminToken {
    /// Generate a fresh admin token. Returns the plaintext — caller
    /// must hash it before persisting and surface the plaintext to
    /// the human exactly once.
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = [0u8; 24];
        getrandom::getrandom(&mut bytes).map_err(|e| TokenError::Csprng(e.to_string()))?;
        Ok(Self(format!("GRP-{}", hex::encode(bytes))))
    }

    /// View the cleartext. Use sparingly — anything that persists or
    /// transmits this string outside the create / transfer response is
    /// a bug.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Take the cleartext out by value. Same caveat as [`Self::as_str`].
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Hash this token for persistence.
    pub fn hash(&self) -> TokenHash {
        TokenHash::of_str(&self.0)
    }
}

impl InvitationToken {
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| TokenError::Csprng(e.to_string()))?;
        Ok(Self(hex::encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn hash(&self) -> TokenHash {
        TokenHash::of_str(&self.0)
    }
}

impl TokenHash {
    /// SHA-256 over the UTF-8 bytes of `cleartext`, hex-encoded.
    pub fn of_str(cleartext: &str) -> Self {
        let mut h = Sha256::new();
        h.update(cleartext.as_bytes());
        Self(hex::encode(h.finalize()))
    }

    /// Constant-time check that `provided` hashes to the same value as
    /// `self`. Returns `false` on any length mismatch as a fast path,
    /// then compares byte-by-byte without short-circuiting.
    pub fn verifies(&self, provided: &str) -> bool {
        let candidate = Self::of_str(provided);
        if candidate.0.len() != self.0.len() {
            return false;
        }
        candidate.0.as_bytes().ct_eq(self.0.as_bytes()).into()
    }

    /// Inner hex string. Used by `bp-db` to set the column value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap an existing hex string read from the DB.
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_tokens_are_prefixed_and_unique() {
        let a = AdminToken::generate().expect("csprng");
        let b = AdminToken::generate().expect("csprng");
        assert!(a.as_str().starts_with("GRP-"));
        assert!(b.as_str().starts_with("GRP-"));
        assert_ne!(a.as_str(), b.as_str());
        // hex of 24 bytes is 48 chars; total length 52.
        assert_eq!(a.as_str().len(), "GRP-".len() + 48);
    }

    #[test]
    fn invitation_tokens_are_hex_64() {
        let t = InvitationToken::generate().expect("csprng");
        // 32 bytes → 64 hex chars; no prefix.
        assert_eq!(t.as_str().len(), 64);
        assert!(t.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_verifies_the_token_it_came_from() {
        let token = AdminToken::generate().expect("csprng");
        let hash = token.hash();
        assert!(hash.verifies(token.as_str()));
    }

    #[test]
    fn hash_rejects_different_token() {
        let a = AdminToken::generate().expect("csprng");
        let b = AdminToken::generate().expect("csprng");
        let ha = a.hash();
        assert!(!ha.verifies(b.as_str()));
    }

    #[test]
    fn hash_rejects_truncated_input() {
        let token = AdminToken::generate().expect("csprng");
        let hash = token.hash();
        let truncated = &token.as_str()[..token.as_str().len() - 1];
        assert!(!hash.verifies(truncated));
    }

    #[test]
    fn hash_rejects_extended_input() {
        let token = AdminToken::generate().expect("csprng");
        let hash = token.hash();
        let extended = format!("{}x", token.as_str());
        assert!(!hash.verifies(&extended));
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = TokenHash::of_str("GRP-abcdef");
        let h2 = TokenHash::of_str("GRP-abcdef");
        assert_eq!(h1, h2);
    }

    #[test]
    fn from_hex_roundtrip() {
        let h = TokenHash::of_str("hello");
        let restored = TokenHash::from_hex(h.as_str().to_string());
        assert_eq!(restored.as_str(), h.as_str());
        assert!(restored.verifies("hello"));
    }
}
