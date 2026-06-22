// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-(group, finder) coinbase snapshot persistence.
//!
//! Each miner in a group writes their own snapshot keyed by their
//! address as the prospective finder (`groupsolo:{groupId}:snapshot:{finderAddress}`).
//! `on_block_found` reads the snapshot for the *actual* finder; if
//! missing or reward-mismatched, falls back to a recompute against the
//! current round state.
//!
//! The hash format + read/write/delete logic lives in
//! [`bp_coinbase_snapshot::snapshot`] (shared with PPLNS so the wire
//! format stays one source of truth). This module keeps only the
//! Group-Solo key scheme: per-(group, finder) keys plus the SCAN-based
//! group-wide cleanup.

use redis::{aio::ConnectionManager, AsyncCommands, AsyncIter, RedisError};

pub use bp_coinbase_snapshot::snapshot::{ParsedSnapshot, StoredSnapshot};

/// Build the snapshot key `groupsolo:{group_id}:snapshot:{finder_address}`.
pub fn key(group_id: &str, finder_address: &str) -> String {
    format!("groupsolo:{group_id}:snapshot:{finder_address}")
}

/// Build the SCAN-match pattern for ALL snapshots of one group —
/// used by [`delete_all_for_group`].
pub fn key_match_all(group_id: &str) -> String {
    format!("groupsolo:{group_id}:snapshot:*")
}

/// Persist a snapshot for one (group, finder) pair with `ttl_seconds` TTL.
pub async fn write_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
    snapshot: &StoredSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::write_snapshot(
        conn,
        &key(group_id, finder_address),
        snapshot,
        ttl_seconds,
    )
    .await
}

/// Load + hydrate one (group, finder) snapshot, or `None` if missing /
/// unparseable.
pub async fn read_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
) -> Result<Option<ParsedSnapshot>, RedisError> {
    bp_coinbase_snapshot::snapshot::read_snapshot(conn, &key(group_id, finder_address)).await
}

/// Delete one (group, finder) snapshot. Called by `on_block_found`
/// after the apply-distribution TX commits.
pub async fn delete_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::delete_snapshot(conn, &key(group_id, finder_address)).await
}

/// SCAN + DEL every snapshot for the group — used by the block-found
/// post-commit cleanup (other miners' snapshots are stale once a round
/// resets) and the kick / dissolve admin flows.
pub async fn delete_all_for_group(
    conn: &mut ConnectionManager,
    group_id: &str,
) -> Result<u64, RedisError> {
    let pattern = key_match_all(group_id);
    let mut conn_scan = conn.clone();
    let mut iter: AsyncIter<String> = conn_scan.scan_match(&pattern).await?;
    let mut to_delete: Vec<String> = Vec::new();
    while let Some(key) = iter.next_item().await {
        to_delete.push(key);
    }
    drop(iter);
    drop(conn_scan);

    if to_delete.is_empty() {
        return Ok(0);
    }
    let deleted: u64 = conn.del(&to_delete).await?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pattern_is_per_group_and_finder() {
        assert_eq!(key("g1", "bc1qfoo"), "groupsolo:g1:snapshot:bc1qfoo");
    }

    #[test]
    fn key_match_pattern_is_per_group() {
        assert_eq!(key_match_all("g1"), "groupsolo:g1:snapshot:*");
    }
}
