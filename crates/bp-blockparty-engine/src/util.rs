// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-private helpers. Kept local rather than imported from
//! `bp_group_mgmt_engine::util` so the address normalizer can return
//! a typed `BlockpartyServiceError` directly without a `.map_err`
//! roundtrip at every call site.

use bp_common::AddressId;

use crate::error::BlockpartyServiceError;

/// Canonicalise a Bitcoin address and shape-validate: trim, lowercase ONLY
/// bech32/bech32m (`bc1`/`tb1`/`bcrt1`/`sb1` — case-insensitive per BIP-173/350),
/// and preserve case-sensitive legacy Base58 (`1…`/`3…`/…) verbatim.
///
/// Must agree byte-for-byte with `bp_mining_job::normalize_btc_address` and the
/// group-solo normalizer (replicated here rather than imported — bp-mining-job is
/// only a dev-dependency). The previous unconditional `to_ascii_lowercase`
/// corrupted Base58 case, so a signature-/email-verified legacy address never
/// matched the case-preserved row written by the verify path (and any Base58
/// coinbase output was built from a mangled address).
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, BlockpartyServiceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BlockpartyServiceError::InvalidAddress);
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
    AddressId::new(normalized).map_err(|_| BlockpartyServiceError::InvalidAddress)
}

/// Current UTC wall-clock in epoch-ms. Wrapped so a future test-clock
/// hook can swap implementations without touching every call site.
pub(crate) fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::normalize_address;

    #[test]
    fn preserves_base58_case_and_lowercases_bech32() {
        // Legacy Base58 is case-sensitive → MUST be preserved verbatim, so a
        // signature-/email-verified `1BvBM…` row is found by the gate (the bug
        // this fixes lowercased it to `1bvbm…` and missed).
        let base58 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert_eq!(normalize_address(base58).unwrap().as_str(), base58);
        let p2sh = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        assert_eq!(normalize_address(p2sh).unwrap().as_str(), p2sh);

        // bech32 is case-insensitive → canonicalise to lowercase, matching the
        // stratum/payout + group-solo normalizer byte-for-byte.
        assert_eq!(
            normalize_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
                .unwrap()
                .as_str(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );

        assert!(normalize_address("   ").is_err());
    }
}
