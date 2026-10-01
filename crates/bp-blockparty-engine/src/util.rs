// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-private helpers.

use bp_common::AddressId;

use crate::error::BlockpartyServiceError;

/// [`AddressId::normalized`] with this crate's error type.
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, BlockpartyServiceError> {
    AddressId::normalized(raw).map_err(|_| BlockpartyServiceError::InvalidAddress)
}

#[cfg(test)]
mod tests {
    use super::normalize_address;
    use crate::error::BlockpartyServiceError;

    /// Pins the wrapper: the normalized value passes, a rejection becomes
    /// this crate's error.
    #[test]
    fn wraps_the_shared_normalizer_in_this_crates_error() {
        assert_eq!(
            normalize_address(" BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4 ")
                .unwrap()
                .as_str(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert!(matches!(
            normalize_address("   "),
            Err(BlockpartyServiceError::InvalidAddress)
        ));
    }
}
