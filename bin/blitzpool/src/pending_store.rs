// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic Redis-backed pending-block store for confirmation-gated apply.
//!
//! A found block parks its frozen apply payload here (keyed by block hash)
//! instead of writing the ledger immediately; the confirmation watcher (see
//! [`crate::block_confirmation`]) applies it once the block reaches
//! `confirmation_depth` confirmations, or discards it if it orphaned. Both the
//! PPLNS ([`crate::pending_blocks`]) and Group-Solo
//! ([`crate::pending_group_solo_blocks`]) stores are thin wrappers over these
//! primitives — same Redis HASH layout (field = block hash, value = JSON),
//! different payload type + key, no duplicated put/remove/load logic.
//!
//! Entries are stored **without a TTL** so the `volatile-lru` eviction policy
//! (which only evicts keys that have an expiry) can never drop a pending apply
//! inside the confirmation window.

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use serde::{de::DeserializeOwned, Serialize};

/// Implemented by every pending payload so the watcher can read the block
/// hash (for `getblockheader`) + height (for logs) generically.
pub(crate) trait PendingBlockRef {
    fn block_hash(&self) -> &str;
    fn block_height(&self) -> i32;
}

/// Persist a pending entry under `key`, field = `block_hash` (idempotent —
/// same hash overwrites). No TTL.
pub(crate) async fn put_pending<T: Serialize>(
    conn: &mut ConnectionManager,
    key: &str,
    block_hash: &str,
    value: &T,
) -> Result<(), RedisError> {
    // Serialization can't fail for these plain types; treat a failure as a
    // programming error rather than poisoning the call signature.
    let json = serde_json::to_string(value).expect("serialize pending block");
    conn.hset::<_, _, _, ()>(key, block_hash, json).await
}

/// Drop a pending entry by hash (applied or orphaned). Idempotent.
pub(crate) async fn remove_pending(
    conn: &mut ConnectionManager,
    key: &str,
    block_hash: &str,
) -> Result<(), RedisError> {
    conn.hdel::<_, _, ()>(key, block_hash).await
}

/// Load every pending entry under `key`. A field whose JSON fails to parse
/// (corrupt / schema-drifted) is skipped, its hash returned in the second
/// tuple element so the caller can prune it.
pub(crate) async fn load_pending<T: DeserializeOwned>(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<(Vec<T>, Vec<String>), RedisError> {
    let map: std::collections::HashMap<String, String> = conn.hgetall(key).await?;
    let mut ok = Vec::with_capacity(map.len());
    let mut unparsable = Vec::new();
    for (hash, json) in map {
        match serde_json::from_str::<T>(&json) {
            Ok(v) => ok.push(v),
            Err(_) => unparsable.push(hash),
        }
    }
    Ok((ok, unparsable))
}
