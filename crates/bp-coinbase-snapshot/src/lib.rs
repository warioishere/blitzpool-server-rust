// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared persistence + ledger primitives for the coinbase-payout
//! engines (`bp-pplns-engine`, `bp-group-solo-engine`).
//!
//! Both engines carried near-identical copies of:
//!
//! - [`snapshot`] — the Redis-hash format + write/read/delete that bridges template-build-time coinbase distribution to block-found ledger application.
//! - [`parse_entry`] — the share-zset entry parser.
//! - [`ledger`] — the row-type discriminator + apply-distribution result / error types.
//!
//! Consolidating them here keeps the wire format (stable across
//! deploy transitions) and the DB row-type strings as one source of
//! truth — a format change can no longer drift between the two engines.
//! Each engine keeps only its mode-specific wrappers (PPLNS: a fixed
//! key; Group-Solo: per-(group, finder) keys + SCAN cleanup).

pub mod actual;
pub mod budget;
pub mod build;
pub mod ledger;
pub mod paid_at_height;
pub mod snapshot;

use std::collections::HashMap;

use bp_common::AddressId;
use tracing::warn;

pub use actual::ActualCoinbase;
pub use budget::{read_coinbase_budget, write_coinbase_budget};
pub use build::{build_and_snapshot, BuildRequest, BuiltDistribution};
pub use ledger::{ApplyDistributionResult, LedgerError, PayoutRowType};
pub use paid_at_height::{
    InstalledResolver, PaidAtHeight, PaidAtHeightError, PayoutIdentityResolver, StaticPaidAddresses,
};
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
/// a warn (defensive — a buggy upstream could have pushed an invalid
/// address into Redis; better to drop that one share than fail the
/// whole distribution). Non-positive diffs are skipped too.
///
/// `invalid_address_warning` is the engine-specific log line emitted on
/// a rejected address (the only thing that differed between the two
/// copies).
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

/// Which of `keys` are paid by a **derived** script rather than by being an
/// address — one resolver call for the whole batch, for one distribution build.
///
/// Lives here because both engines' distribution builders need it and both would
/// otherwise have written it: PPLNS over its window plus the open-balance ledger,
/// Group-Solo over its round plus the finder. The two answers gate the same
/// filters in the same weight model, so there is one function.
///
/// **Only keys that are not already payable addresses are asked about.** That is
/// not an optimization for its own sake — the production resolver reads
/// `miner_identity`, and handing it every address in a PPLNS window would mean a
/// store lookup per literal miner on every inputs load. The filter is
/// [`bp_pplns::is_valid_payout_address`], the same predicate
/// [`bp_pplns::is_payable_payout_key`] tries first, so a key skipped here is a key
/// the weight model already accepts without help.
///
/// **It cannot fail.** [`PayoutIdentityResolver::derived_payout_keys`] returns no
/// `Result` by design: this runs on the job path, and one unresolvable key that
/// failed the load would fail `build_payout_outputs`, which serves **no job to any
/// connection sharing this payout set**. So an unresolvable key is absent from the
/// answer and its row is dropped — the same fate an unparseable address has always
/// had — and the shortfall is logged.
pub async fn resolve_derived_keys<'a, I>(
    identities: &InstalledResolver,
    keys: I,
    scope: &str,
) -> std::collections::HashSet<String>
where
    I: Iterator<Item = &'a AddressId>,
{
    let candidates: Vec<String> = keys
        .filter(|k| !bp_pplns::is_valid_payout_address(k.as_str()))
        .map(|k| k.as_str().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    if candidates.is_empty() {
        return std::collections::HashSet::new();
    }
    let derived = identities.get().derived_payout_keys(&candidates).await;
    if derived.len() < candidates.len() {
        // Not an error — see above. But it is the one place a rotating miner
        // loses a template's share, so it is said out loud. Counts only: the
        // resolver already logs per key, and it is the side that knows why.
        warn!(
            scope,
            asked = candidates.len(),
            resolved = derived.len(),
            "distribution inputs: some non-address ledger keys resolved to no payout identity — \
             their rows are dropped from this build"
        );
    }
    derived
}

/// Parse a share-zset entry string `<address>:<difficulty>:<timestamp>`
/// into `(address, difficulty)`. Returns `None` if the format doesn't
/// match.
///
/// The timestamp slot is kept in the wire format for diagnostic-tool
/// compatibility but the engines never read it back —
/// trim / round ordering is by zset score (the INCR counter), not
/// timestamp. A 2-segment entry is malformed (the trailing segment is a
/// shape guard). Negative / non-finite difficulties are rejected.
pub fn parse_entry(entry: &str) -> Option<(&str, f64)> {
    let mut parts = entry.splitn(3, ':');
    let addr = parts.next()?;
    let diff_str = parts.next()?;
    // We don't care about the timestamp slot but its existence is a
    // shape guard — a 2-segment entry is malformed.
    parts.next()?;
    if addr.is_empty() {
        return None;
    }
    let diff: f64 = diff_str.parse().ok()?;
    if !diff.is_finite() || diff < 0.0 {
        return None;
    }
    Some((addr, diff))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entry_well_formed() {
        let (addr, diff) = parse_entry("bc1qfoo:1234.5:1700000000000").unwrap();
        assert_eq!(addr, "bc1qfoo");
        assert!((diff - 1234.5).abs() < 1e-9);
    }

    #[test]
    fn parse_entry_two_segments_rejects() {
        assert!(parse_entry("bc1qfoo:1234.5").is_none());
    }

    #[test]
    fn parse_entry_empty_addr_rejects() {
        assert!(parse_entry(":1234:5678").is_none());
    }

    #[test]
    fn parse_entry_non_numeric_diff_rejects() {
        assert!(parse_entry("bc1qfoo:notnumber:5678").is_none());
    }

    #[test]
    fn parse_entry_negative_diff_rejects() {
        assert!(parse_entry("bc1qfoo:-1.0:5678").is_none());
    }

    #[test]
    fn parse_entry_nan_diff_rejects() {
        assert!(parse_entry("bc1qfoo:nan:5678").is_none());
    }

    #[test]
    fn parse_entry_address_with_colon_in_metadata_only_takes_first_three() {
        // Defensive: address slots shouldn't contain `:` (bech32 / base58
        // never include one) but splitn(3) means a 4th colon in the
        // timestamp slot wouldn't break parsing.
        let (addr, diff) = parse_entry("bc1qfoo:1.0:1700:0").unwrap();
        assert_eq!(addr, "bc1qfoo");
        assert!((diff - 1.0).abs() < 1e-9);
    }

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
