// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-private helpers. Kept local rather than imported from
//! `bp_group_mgmt_engine::util` so the address normalizer can return
//! a typed `BlockpartyServiceError` directly without a `.map_err`
//! roundtrip at every call site.

use bp_common::AddressId;

use crate::error::BlockpartyServiceError;

/// Trim + ASCII-lowercase (bech32 is case-insensitive; legacy Base58 is
/// already canonical-cased) and shape-validate.
pub(crate) fn normalize_address(raw: &str) -> Result<AddressId, BlockpartyServiceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BlockpartyServiceError::InvalidAddress);
    }
    AddressId::new(trimmed.to_ascii_lowercase()).map_err(|_| BlockpartyServiceError::InvalidAddress)
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
