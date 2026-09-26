// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-private helpers. The address normalizer is a local wrapper so
//! it can return a typed `BlockpartyServiceError` directly without a
//! `.map_err` roundtrip at every call site; the rule itself is
//! [`bp_common::normalize_btc_address`].

use bp_common::AddressId;

use crate::error::BlockpartyServiceError;

/// [`AddressId::normalized`] with this crate's error type.
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, BlockpartyServiceError> {
    AddressId::normalized(raw).map_err(|_| BlockpartyServiceError::InvalidAddress)
}

/// [`normalize_address`] for every path that puts an address INTO a party:
/// creation (the admin row), the admin's add, and the self-join link.
///
/// A Blockparty pays fixed addresses only. The payout resolver refuses a
/// distribution holding a rotating identity and serves the whole party no job
/// while that miner is connected, so admitting one here would stall every
/// member's mining on one enrolment. Refused at the door instead.
///
/// Not used by `remove_member`: an id enrolled before this check existed has
/// to stay removable.
pub(crate) fn normalize_enrolled_address(raw: &str) -> Result<AddressId, BlockpartyServiceError> {
    let address = normalize_address(raw)?;
    if bp_payout_descriptor::is_payout_id(address.as_str()) {
        return Err(BlockpartyServiceError::RotatingIdentity);
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::normalize_address;
    use crate::error::BlockpartyServiceError;

    /// The rule itself is tested in `bp_common`; this pins the wrapper's
    /// own job — the normalized value comes through, a rejection becomes
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
