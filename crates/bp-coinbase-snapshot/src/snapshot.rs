// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-block coinbase-distribution snapshot, persisted to a Redis hash
//! so `on_block_found` mutates the ledger against the exact state
//! committed at template-build time, even across a pool restart.
//!
//! Wire format (stable across deploy transitions):
//!
//! - `blockRewardSats` — scalar
//! - `consideredAddresses` — pipe-`|`-separated string
//! - `distribution_count` / `balanceAfter_count` — array length scalars
//! - `d{i}_addr` / `d{i}_pct` / `d{i}_sats` — one triple per
//!   distribution entry
//! - `b{i}_addr` / `b{i}_sats` — one pair per balanceAfter entry
//!
//! Callers pass a fully-built `key`: PPLNS uses a fixed `pplns:snapshot`;
//! Group-Solo builds `groupsolo:{groupId}:snapshot:{finderAddress}`.

use std::collections::{HashMap, HashSet};

use bp_common::{AddressId, Sats};
use bp_pplns::CoinbaseDistributionEntry;
use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

/// Persistent form of a per-block coinbase distribution + matching
/// ledger deltas.
///
/// `balance_after` is signed: PPLNS uses positive = credit, negative =
/// debit, zero = settle; Group-Solo only ever emits non-negative values
/// (its `pendingSats` is `≥ 0`) but keeps the field signed for wire
/// compatibility. Applied as an absolute UPDATE in the block-found TX.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredSnapshot {
    /// Coinbase output list, in coinbase-order (matters for byte-equal
    /// reconstruction).
    pub distribution: Vec<CoinbaseDistributionEntry>,
    /// The coinbase reward this snapshot was built for. A mismatch at
    /// `on_block_found` time triggers a CRITICAL fallback recompute.
    pub block_reward_sats: u64,
    /// Every address that was in shares OR balances at build time, so
    /// `on_block_found` can distinguish late arrivers from sub-dust /
    /// trimmed miners.
    pub considered_addresses: Vec<String>,
    /// Absolute new balance per address that changed.
    pub balance_after: Vec<(String, i64)>,
}

impl StoredSnapshot {
    /// Build a snapshot from the output of
    /// `bp_pplns::build_coinbase_distribution` — the
    /// `AddressId`/`Sats` → `String`/`i64` lowering both payout engines
    /// do identically before persisting. `payouts` is borrowed (the
    /// caller still moves it into its in-memory result afterwards).
    pub fn from_math(
        payouts: &[CoinbaseDistributionEntry],
        block_reward_sats: u64,
        considered_addresses: &HashSet<AddressId>,
        balance_after: &HashMap<AddressId, Sats>,
    ) -> Self {
        Self {
            distribution: payouts.to_vec(),
            block_reward_sats,
            considered_addresses: considered_addresses
                .iter()
                .map(|a| a.as_str().to_string())
                .collect(),
            balance_after: balance_after
                .iter()
                .map(|(a, s)| (a.as_str().to_string(), s.0))
                .collect(),
        }
    }
}

/// Hydrated form returned by [`read_snapshot`]: `Set` / `HashMap` for
/// ergonomic call-site use; `distribution` stays a `Vec` because
/// coinbase-output order matters.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSnapshot {
    pub distribution: Vec<CoinbaseDistributionEntry>,
    pub block_reward_sats: u64,
    pub considered_addresses: HashSet<String>,
    pub balance_after: HashMap<String, i64>,
}

impl From<StoredSnapshot> for ParsedSnapshot {
    /// Hydrate the wire form (Vec-backed) into the call-site-ergonomic form
    /// (`HashSet`/`HashMap`). Used when the snapshot arrives in the
    /// block-found event instead of from a Redis read — same shape
    /// `read_snapshot` produces, so `on_block_found` is agnostic to the
    /// source.
    fn from(s: StoredSnapshot) -> Self {
        Self {
            distribution: s.distribution,
            block_reward_sats: s.block_reward_sats,
            considered_addresses: s.considered_addresses.into_iter().collect(),
            balance_after: s.balance_after.into_iter().collect(),
        }
    }
}

/// Persist a snapshot under `key` with `ttl_seconds`.
///
/// `DEL` before `HSET` guarantees the key has Hash type even if a
/// legacy STRING-typed snapshot survives from an earlier deploy
/// (otherwise the `HSET` would `WRONGTYPE`). Then `EXPIRE` to bound
/// staleness.
///
/// Three commands in sequence (not pipelined): the snapshot is written
/// at most once per block-template build, single-digit Hz at peak. The
/// extra RTTs are not worth a `MULTI/EXEC`.
pub async fn write_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
    snapshot: &StoredSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    // Build the field list. `HSET` accepts an array of (field, value)
    // pairs; we slot the scalars + arrays in a stable order so a
    // Redis-CLI dump shows fields in a consistent order.
    let mut fields: Vec<(String, String)> =
        Vec::with_capacity(4 + snapshot.distribution.len() * 3 + snapshot.balance_after.len() * 2);

    fields.push((
        "blockRewardSats".to_string(),
        snapshot.block_reward_sats.to_string(),
    ));
    fields.push((
        "consideredAddresses".to_string(),
        snapshot.considered_addresses.join("|"),
    ));
    fields.push((
        "distribution_count".to_string(),
        snapshot.distribution.len().to_string(),
    ));
    fields.push((
        "balanceAfter_count".to_string(),
        snapshot.balance_after.len().to_string(),
    ));

    for (i, entry) in snapshot.distribution.iter().enumerate() {
        fields.push((format!("d{i}_addr"), entry.address.as_str().to_string()));
        fields.push((format!("d{i}_pct"), entry.percent.to_string()));
        fields.push((format!("d{i}_sats"), entry.sats.0.to_string()));
    }

    for (i, (addr, sats)) in snapshot.balance_after.iter().enumerate() {
        fields.push((format!("b{i}_addr"), addr.clone()));
        fields.push((format!("b{i}_sats"), sats.to_string()));
    }

    let _: () = conn.del(key).await?;
    let _: () = conn.hset_multiple(key, &fields).await?;
    let _: () = conn.expire(key, ttl_seconds as i64).await?;
    Ok(())
}

/// Load + hydrate a snapshot, or return `Ok(None)` if the key is
/// missing or the stored payload is unparseable.
///
/// Unparseable values are logged via `tracing::warn!` rather than
/// returned as errors — a partially-corrupt snapshot is a CRITICAL
/// operational event but not one the engine should crash for; the
/// caller falls back to a recompute.
pub async fn read_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<ParsedSnapshot>, RedisError> {
    let hash: HashMap<String, String> = match conn.hgetall(key).await {
        Ok(h) => h,
        Err(e) if is_wrongtype(&e) => {
            // Legacy STRING-typed snapshot survives from pre-Hash
            // rollout, or a future deploy accidentally wrote the wrong
            // shape. Surface the WRONGTYPE as "missing" with a warning
            // rather than crashing.
            warn!(
                key,
                error = %e,
                "coinbase snapshot: legacy or wrong-typed key, treating as missing"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if hash.is_empty() {
        return Ok(None);
    }
    match parse_hash(&hash) {
        Some(parsed) => Ok(Some(parsed)),
        None => {
            warn!(
                key,
                "coinbase snapshot: failed to parse fields, treating as missing"
            );
            Ok(None)
        }
    }
}

/// Delete a snapshot key (called after `on_block_found` consumed it).
pub async fn delete_snapshot(conn: &mut ConnectionManager, key: &str) -> Result<(), RedisError> {
    let _: () = conn.del(key).await?;
    Ok(())
}

fn parse_hash(h: &HashMap<String, String>) -> Option<ParsedSnapshot> {
    let block_reward_sats: u64 = h.get("blockRewardSats")?.parse().ok()?;
    let dist_count: usize = h.get("distribution_count")?.parse().ok()?;
    let bal_count: usize = h.get("balanceAfter_count")?.parse().ok()?;

    let mut distribution = Vec::with_capacity(dist_count);
    for i in 0..dist_count {
        let addr_str = h.get(&format!("d{i}_addr"))?;
        let percent: f64 = h.get(&format!("d{i}_pct"))?.parse().ok()?;
        let sats: i64 = h.get(&format!("d{i}_sats"))?.parse().ok()?;
        let address = AddressId::new(addr_str.clone()).ok()?;
        distribution.push(CoinbaseDistributionEntry {
            address,
            percent,
            sats: Sats(sats),
        });
    }

    let mut balance_after = HashMap::with_capacity(bal_count);
    for i in 0..bal_count {
        let addr = h.get(&format!("b{i}_addr"))?.clone();
        let sats: i64 = h.get(&format!("b{i}_sats"))?.parse().ok()?;
        balance_after.insert(addr, sats);
    }

    let considered_addresses = h
        .get("consideredAddresses")
        .map(|s| {
            s.split('|')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string())
                .collect()
        })
        .unwrap_or_default();

    Some(ParsedSnapshot {
        distribution,
        block_reward_sats,
        considered_addresses,
        balance_after,
    })
}

/// Returns true if the error is a `WRONGTYPE` from Redis (legacy STRING
/// snapshot on a key that's expected to be a Hash).
fn is_wrongtype(e: &RedisError) -> bool {
    matches!(
        e.kind(),
        redis::ErrorKind::TypeError | redis::ErrorKind::ResponseError
    ) && e.to_string().contains("WRONGTYPE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hash_roundtrip() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "312500000".to_string());
        h.insert("distribution_count".to_string(), "2".to_string());
        h.insert("balanceAfter_count".to_string(), "1".to_string());
        h.insert(
            "consideredAddresses".to_string(),
            "bc1qfoo|bc1qbar|bc1qbaz".to_string(),
        );
        h.insert(
            "d0_addr".to_string(),
            "bc1qfoo0000000000000000000000000".to_string(),
        );
        h.insert("d0_pct".to_string(), "50.5".to_string());
        h.insert("d0_sats".to_string(), "156250000".to_string());
        h.insert(
            "d1_addr".to_string(),
            "bc1qbar0000000000000000000000000".to_string(),
        );
        h.insert("d1_pct".to_string(), "49.5".to_string());
        h.insert("d1_sats".to_string(), "156250000".to_string());
        h.insert(
            "b0_addr".to_string(),
            "bc1qbar0000000000000000000000000".to_string(),
        );
        h.insert("b0_sats".to_string(), "-1234".to_string());

        let parsed = parse_hash(&h).expect("parse ok");
        assert_eq!(parsed.block_reward_sats, 312_500_000);
        assert_eq!(parsed.distribution.len(), 2);
        assert_eq!(parsed.distribution[0].sats.0, 156_250_000);
        assert!((parsed.distribution[1].percent - 49.5).abs() < 1e-9);
        assert_eq!(parsed.balance_after.len(), 1);
        assert_eq!(
            parsed.balance_after["bc1qbar0000000000000000000000000"],
            -1234
        );
        assert_eq!(parsed.considered_addresses.len(), 3);
    }

    #[test]
    fn parse_hash_missing_scalar_returns_none() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "1".to_string());
        // distribution_count missing — should refuse to hydrate
        assert!(parse_hash(&h).is_none());
    }

    #[test]
    fn parse_hash_malformed_int_returns_none() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "not-a-number".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "0".to_string());
        assert!(parse_hash(&h).is_none());
    }

    #[test]
    fn parse_hash_empty_considered_addresses() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "100".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "0".to_string());
        h.insert("consideredAddresses".to_string(), String::new());
        let parsed = parse_hash(&h).unwrap();
        assert!(parsed.considered_addresses.is_empty());
    }

    #[test]
    fn from_math_lowers_addresses_and_sats_to_wire_form() {
        let a = AddressId::new("bc1qfoo0000000000000000000000000").unwrap();
        let b = AddressId::new("bc1qbar0000000000000000000000000").unwrap();
        let payouts = vec![CoinbaseDistributionEntry {
            address: a.clone(),
            percent: 100.0,
            sats: Sats(312_500_000),
        }];
        let considered: HashSet<AddressId> = [a.clone(), b.clone()].into_iter().collect();
        let mut balances = HashMap::new();
        balances.insert(b.clone(), Sats(-5_000));

        let snap = StoredSnapshot::from_math(&payouts, 312_500_000, &considered, &balances);
        assert_eq!(snap.block_reward_sats, 312_500_000);
        assert_eq!(snap.distribution.len(), 1);
        assert_eq!(snap.distribution[0].sats.0, 312_500_000);
        assert_eq!(snap.considered_addresses.len(), 2);
        assert_eq!(snap.balance_after.len(), 1);
        assert_eq!(snap.balance_after[0].0, "bc1qbar0000000000000000000000000");
        assert_eq!(snap.balance_after[0].1, -5_000);
    }

    #[test]
    fn parse_hash_signed_balance() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "100".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "2".to_string());
        h.insert(
            "b0_addr".to_string(),
            "bc1qcredit0000000000000000000000".to_string(),
        );
        h.insert("b0_sats".to_string(), "5000".to_string());
        h.insert(
            "b1_addr".to_string(),
            "bc1qdebit00000000000000000000000".to_string(),
        );
        h.insert("b1_sats".to_string(), "-5000".to_string());
        let parsed = parse_hash(&h).unwrap();
        let credit = parsed.balance_after["bc1qcredit0000000000000000000000"];
        let debit = parsed.balance_after["bc1qdebit00000000000000000000000"];
        // Ledger symmetry: signed pair sums to zero.
        assert_eq!(credit + debit, 0);
    }
}
