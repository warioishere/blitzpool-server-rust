// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared persistence + ledger primitives for the coinbase-payout
//! engines (`bp-pplns-engine`, `bp-group-solo-engine`).
//!
//! - [`snapshot`] — the Redis-hash format + write/read/delete that bridges template-build-time coinbase distribution to block-found ledger application.
//! - [`share_map_from_redis_hash`] — the Redis share aggregate → validated distribution input.
//! - [`ledger`] — the row-type discriminator + apply-distribution result / error types.
//!
//! One copy keeps the wire format (stable across deploys) and the DB
//! row-type strings identical for both engines. Each engine keeps only
//! its mode-specific wrappers (PPLNS: a fixed key; Group-Solo:
//! per-(group, finder) keys + SCAN cleanup).

pub mod actual;
pub mod budget;
pub mod build;
pub mod ledger;
pub mod snapshot;

use std::collections::HashMap;

use bp_common::AddressId;
use tracing::warn;

pub use actual::ActualCoinbase;
pub use budget::{read_coinbase_budget, write_coinbase_budget, PPLNS_COINBASE_BUDGET_KEY};
pub use build::{build_and_snapshot, BuildRequest, BuiltDistribution};
pub use ledger::{ApplyDistributionResult, LedgerError, PayoutRowType};
pub use snapshot::{
    delete_snapshot, read_weight_snapshot, read_weight_snapshot_with_retry,
    resolve_snapshot_for_block_found, write_weight_snapshot, StoredWeightSnapshot,
    WeightSnapshotEntry,
};

/// Convert a Redis per-address share aggregate (`address → diff-1 sum`,
/// raw strings straight off `HGETALL`) into the validated
/// `HashMap<AddressId, f64>` the distribution math expects.
///
/// Both payout engines build their distribution input this way: PPLNS
/// from the sliding-window hash, Group-Solo from the per-round hash.
/// Entries whose address fails `AddressId` validation are skipped with
/// a warn: dropping that one share beats failing the whole
/// distribution. Non-positive diffs are skipped too.
///
/// `invalid_address_warning` is the engine-specific log line emitted on
/// a rejected address.
pub fn share_map_from_redis_hash(
    raw: &HashMap<String, f64>,
    invalid_address_warning: &str,
) -> HashMap<AddressId, f64> {
    let mut out = HashMap::with_capacity(raw.len());
    for (addr, diff) in raw {
        match AddressId::new(addr.clone()) {
            Ok(id) => {
                if *diff > 0.0 {
                    out.insert(id, *diff);
                }
            }
            Err(_) => {
                warn!(address = addr, "{invalid_address_warning}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_map_skips_invalid_addresses() {
        let mut raw = HashMap::new();
        raw.insert("bc1qfoo".to_string(), 100.0);
        raw.insert("".to_string(), 50.0); // invalid (empty)
        raw.insert("bc1qbar".to_string(), 25.0);
        raw.insert("x".repeat(100), 10.0); // too long for AddressId

        let shares = share_map_from_redis_hash(&raw, "test");
        assert_eq!(shares.len(), 2);
        assert!(shares.contains_key(&AddressId::new("bc1qfoo").unwrap()));
        assert!(shares.contains_key(&AddressId::new("bc1qbar").unwrap()));
    }

    #[test]
    fn share_map_skips_zero_or_negative_diff() {
        let mut raw = HashMap::new();
        raw.insert("bc1qfoo".to_string(), 0.0);
        raw.insert("bc1qbar".to_string(), -5.0);
        raw.insert("bc1qbaz".to_string(), 1.0);

        let shares = share_map_from_redis_hash(&raw, "test");
        assert_eq!(shares.len(), 1);
        assert!(shares.contains_key(&AddressId::new("bc1qbaz").unwrap()));
    }
}
