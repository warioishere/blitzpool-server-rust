// SPDX-License-Identifier: AGPL-3.0-or-later

//! Readers for the per-session live hashes (`client:live:*`).
//!
//! The write side lives in `bp-session-persistence` (touch flush +
//! hashrate sampler); the key/field schema both sides share is
//! [`bp_common::live_client_key`]. This crate is the ONE
//! implementation of "sum the live hashrate" — `bp-api` and
//! `bp-notifications` both call it, so the two can't drift apart the
//! way twin SQL aggregates could.
//!
//! Reading rules (the schema module explains why):
//!
//! - Every key has a TTL and prod Redis runs `volatile-lru`, so any key
//!   can be missing at any moment. A missing key or field is "no live
//!   data" and contributes 0 to a sum — but a derived 0 must never be
//!   written back to durable storage.
//! - A hash can be partial (only `hash_rate`): the sampler recreates an
//!   expired key with just that field.
//! - `NotConfigured` (no Redis handle) is an error, not a silent 0 —
//!   the caller decides whether its surface degrades to 0, an error
//!   text, or a 500, exactly as it did for a failed SQL query.

use std::collections::{HashMap, HashSet};

use bp_common::live_client_key::{CLIENT_LIVE_PREFIX, F_HASH_RATE, KEY_SEP, SCAN_PATTERN_ALL};
use bp_common::AddressId;
use redis::aio::ConnectionManager;

/// `HGET`s per pipeline round trip.
const FETCH_CHUNK: usize = 500;

#[derive(thiserror::Error, Debug)]
pub enum LiveReadError {
    /// The process has no Redis handle. Configuration state, not a
    /// runtime fault — but still an error so no caller can mistake
    /// "cannot know" for "zero hashrate".
    #[error("live store not configured (no Redis handle)")]
    NotConfigured,
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
}

/// The `address` component of a live key, or `None` for a key that
/// doesn't parse (foreign key caught by the pattern, truncated write).
fn address_of(key: &str) -> Option<&str> {
    key.strip_prefix(CLIENT_LIVE_PREFIX)?.split(KEY_SEP).next()
}

/// Full `SCAN` of the live keyspace. One pass regardless of how many
/// addresses the caller filters on afterwards — at pool scale
/// (~10³ sessions) that beats one `SCAN` per address.
async fn scan_live_keys(conn: &mut ConnectionManager) -> Result<Vec<String>, redis::RedisError> {
    let mut keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(SCAN_PATTERN_ALL)
            .arg("COUNT")
            .arg(200)
            .query_async(conn)
            .await?;
        keys.extend(batch);
        cursor = next;
        if cursor == 0 {
            return Ok(keys);
        }
    }
}

/// Pipelined `HGET hash_rate` over `keys`, summed per key's address
/// into `acc`. A key that expired between SCAN and HGET, or a partial
/// hash without the field yet, contributes nothing.
async fn accumulate_rates(
    conn: &mut ConnectionManager,
    keys: &[String],
    acc: &mut HashMap<String, f64>,
) -> Result<(), redis::RedisError> {
    for chunk in keys.chunks(FETCH_CHUNK) {
        let mut pipe = redis::pipe();
        for key in chunk {
            pipe.cmd("HGET").arg(key).arg(F_HASH_RATE);
        }
        let rates: Vec<Option<String>> = pipe.query_async(conn).await?;
        for (key, rate) in chunk.iter().zip(rates) {
            let (Some(addr), Some(rate)) = (address_of(key), rate) else {
                continue;
            };
            let Ok(rate) = rate.parse::<f64>() else {
                continue;
            };
            if let Some(sum) = acc.get_mut(addr) {
                *sum += rate;
            } else {
                acc.insert(addr.to_string(), rate);
            }
        }
    }
    Ok(())
}

/// Sum of the live hashrate across every session in the pool — the
/// replacement for the `SUM("hashRate") WHERE deletedAt IS NULL` SQL
/// aggregate ("active" is now key-liveness: the TTL rides the same
/// 5-minute clock the `kill_dead_clients` sweep used).
pub async fn pool_hashrate(redis: Option<&ConnectionManager>) -> Result<f64, LiveReadError> {
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let keys = scan_live_keys(&mut conn).await?;
    let mut acc = HashMap::new();
    accumulate_rates(&mut conn, &keys, &mut acc).await?;
    Ok(acc.values().sum())
}

/// Live hashrate per address for the supplied list. Every requested
/// address is present in the result (0.0 when it has no live session),
/// so callers can render a full member roster without re-checking.
pub async fn hashrate_by_address(
    redis: Option<&ConnectionManager>,
    addresses: &[AddressId],
) -> Result<HashMap<String, f64>, LiveReadError> {
    let mut acc: HashMap<String, f64> = addresses
        .iter()
        .map(|a| (a.as_str().to_string(), 0.0))
        .collect();
    if addresses.is_empty() {
        return Ok(acc);
    }
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let wanted: HashSet<&str> = addresses.iter().map(|a| a.as_str()).collect();
    let keys: Vec<String> = scan_live_keys(&mut conn)
        .await?
        .into_iter()
        .filter(|k| address_of(k).is_some_and(|a| wanted.contains(a)))
        .collect();
    accumulate_rates(&mut conn, &keys, &mut acc).await?;
    Ok(acc)
}

/// Sum of the live hashrate across the supplied addresses. Empty input
/// returns `0.0` without touching Redis (parity with the SQL reader it
/// replaces).
pub async fn hashrate_for_addresses(
    redis: Option<&ConnectionManager>,
    addresses: &[AddressId],
) -> Result<f64, LiveReadError> {
    if addresses.is_empty() {
        return Ok(0.0);
    }
    Ok(hashrate_by_address(redis, addresses).await?.values().sum())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::live_client_key::client_live_key;

    #[test]
    fn address_parses_out_of_a_live_key() {
        let key = client_live_key("bc1qaddr", "rig-a", "ab12cd34");
        assert_eq!(address_of(&key), Some("bc1qaddr"));
    }

    #[test]
    fn worker_and_session_never_leak_into_the_address() {
        // A worker name containing a colon must not confuse the parse —
        // only the unit separator splits components.
        let key = client_live_key("bc1qaddr", "rig:a:1", "sess");
        assert_eq!(address_of(&key), Some("bc1qaddr"));
    }

    #[test]
    fn foreign_keys_do_not_parse() {
        assert_eq!(address_of("pplns:window:total"), None);
    }

    #[tokio::test]
    async fn no_redis_handle_is_an_error_not_a_zero() {
        assert!(matches!(
            pool_hashrate(None).await,
            Err(LiveReadError::NotConfigured)
        ));
        let addr = AddressId::new("bc1qaddr").unwrap();
        assert!(matches!(
            hashrate_for_addresses(None, std::slice::from_ref(&addr)).await,
            Err(LiveReadError::NotConfigured)
        ));
        // The empty-input fast path never needs Redis — parity with the
        // SQL reader's early return.
        assert_eq!(hashrate_for_addresses(None, &[]).await.unwrap(), 0.0);
    }
}
