// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared utilities used by `GroupService`, `InvitationService`,
//! `JoinRequestService` and the expiry crons. Kept here so the services
//! agree on normalisation rules (bech32 lowercase) and clock semantics
//! (UTC epoch-ms).

use bp_common::AddressId;
use bp_db::PatchField;

use crate::error::GroupServiceError;

/// Normalise a Bitcoin address: trim whitespace, lowercase ONLY bech32 /
/// bech32m (`bc1` / `tb1` / `bcrt1` / `sb1` prefixes — case-insensitive
/// per BIP-173/350); legacy Base58 (P2PKH `1…` / `3…` / `m…` / `n…` /
/// `2…`) is case-sensitive and is preserved verbatim. Then validate the
/// shape via [`AddressId::new`].
///
/// Must agree byte-for-byte with the stratum-side normalizer
/// (`bp_mining_job::normalize_btc_address`) — group lookups otherwise
/// miss for miners whose address has mixed-case Base58.
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, GroupServiceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GroupServiceError::InvalidAddress);
    }
    let lower = trimmed.to_ascii_lowercase();
    let normalized = if lower.starts_with("bc1")
        || lower.starts_with("tb1")
        || lower.starts_with("bcrt1")
        || lower.starts_with("sb1")
    {
        lower
    } else {
        trimmed.to_string()
    };
    AddressId::new(normalized).map_err(|_| GroupServiceError::InvalidAddress)
}

/// Current UTC wall-clock in epoch-ms. Wrapped here so a future
/// test-clock hook is easy (most services accept `now_ms` as a
/// parameter, but a few cron paths use this directly).
pub(crate) fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Apply a closure to the `Set` variant of a [`PatchField`], leaving
/// `Untouched` + `Clear` alone. The default `Iterator::map` shadows this
/// when called inline, so we expose it through an explicit extension
/// trait that callers `use` in scope when they need it.
pub(crate) trait PatchFieldExt<T> {
    fn map_set<U>(self, f: impl FnOnce(T) -> U) -> PatchField<U>;
}

impl<T> PatchFieldExt<T> for PatchField<T> {
    fn map_set<U>(self, f: impl FnOnce(T) -> U) -> PatchField<U> {
        match self {
            PatchField::Untouched => PatchField::Untouched,
            PatchField::Clear => PatchField::Clear,
            PatchField::Set(v) => PatchField::Set(f(v)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_lowercased() {
        let a = normalize_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();
        assert_eq!(a.as_str(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let b = normalize_address("TB1qFooBarBaz").unwrap();
        assert_eq!(b.as_str(), "tb1qfoobarbaz");
        let c = normalize_address("BCRT1qFooBarBaz").unwrap();
        assert_eq!(c.as_str(), "bcrt1qfoobarbaz");
    }

    #[test]
    fn legacy_base58_case_preserved() {
        // P2PKH: case-sensitive checksum. Must NOT be lowercased.
        let a = normalize_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
        assert_eq!(a.as_str(), "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let b = normalize_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        assert_eq!(b.as_str(), "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    }

    #[test]
    fn whitespace_trimmed_then_prefix_checked() {
        let a = normalize_address("   BC1qabc   ").unwrap();
        assert_eq!(a.as_str(), "bc1qabc");
        let b = normalize_address("   1BvBMSEY   ").unwrap();
        assert_eq!(b.as_str(), "1BvBMSEY");
    }

    #[test]
    fn empty_rejected() {
        assert!(matches!(
            normalize_address(""),
            Err(GroupServiceError::InvalidAddress)
        ));
        assert!(matches!(
            normalize_address("   "),
            Err(GroupServiceError::InvalidAddress)
        ));
    }
}
