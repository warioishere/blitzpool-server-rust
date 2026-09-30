// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared utilities used by `GroupService`, `InvitationService`,
//! `JoinRequestService` and the expiry crons.

use bp_common::AddressId;
use bp_db::PatchField;

use crate::error::GroupServiceError;

/// [`AddressId::normalized`] with this crate's error type.
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, GroupServiceError> {
    AddressId::normalized(raw).map_err(|_| GroupServiceError::InvalidAddress)
}

/// Apply a closure to the `Set` variant of a [`PatchField`], leaving
/// `Untouched` + `Clear` alone. The default `Iterator::map` shadows this
/// when called inline, so it is exposed through an explicit extension
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
