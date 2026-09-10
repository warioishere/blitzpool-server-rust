// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared utilities used by `GroupService`, `InvitationService`,
//! `JoinRequestService` and the expiry crons. Kept here so the services
//! agree on normalisation rules (bech32 lowercase) and clock semantics
//! (UTC epoch-ms).

use bp_common::AddressId;
use bp_db::PatchField;

use crate::error::GroupServiceError;

/// [`bp_common::normalized_address_id`] with the error mapped into this
/// crate's type.
///
/// The rule itself is NOT here. It used to be — a hand copy of the stratum-side
/// normalizer, carrying a doc comment that required byte-for-byte agreement
/// with it and no check that enforced that. Both copies are now callers of the
/// one implementation in `bp-common`, which every crate involved already
/// depends on. The only thing left to say locally is which error a rejection
/// becomes.
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, GroupServiceError> {
    bp_common::normalized_address_id(raw).map_err(|_| GroupServiceError::InvalidAddress)
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
