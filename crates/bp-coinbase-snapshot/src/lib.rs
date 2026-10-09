// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build and ledger primitives shared by the PPLNS and Group-Solo payout
//! engines, so the weight build, the decoded coinbase and the DB row-type
//! strings stay identical for both.

pub mod actual;
pub mod budget;
pub mod build;
pub mod ledger;

use std::collections::HashMap;

use bp_common::AddressId;
use tracing::warn;

pub use actual::ActualCoinbase;
pub use budget::{
    is_wrongtype, read_coinbase_budget, write_coinbase_budget, PPLNS_COINBASE_BUDGET_KEY,
};
pub use build::{build_with_bootstrap, BuildRequest, BuiltDistribution};
pub use ledger::{ApplyDistributionResult, LedgerError, PayoutRowType};

/// Redis per-address share aggregate (`address → diff-1 sum`) into the
/// validated distribution input. An invalid address is skipped with a warn
/// (dropping one share beats failing the whole distribution), as are
/// non-positive diffs.
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
