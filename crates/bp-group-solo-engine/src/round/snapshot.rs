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

/// Build the payout-list key `groupsolo:{group_id}:jobsnapshot:{hex}`.
///
/// Keyed by the identity of the distribution itself rather than by who might
/// find the block: the block-found path then asks for the distribution the
/// winning job's coinbase actually pays, instead of rebuilding one against a
/// round that has moved since.
///
/// Deliberately NOT under the `…:snapshot:` prefix. These keys belong to
/// individual live jobs, and every group-wide wipe ([`delete_all_for_group`],
/// the round-reset cron, a kick) would otherwise strip the distribution out
/// from under jobs that are still being mined — a block found on one of those
/// afterwards could not be booked at all. They are consumed one at a time by
/// the apply and otherwise bounded by their TTL.
pub fn key_for_fingerprint(group_id: &str, payouts_fingerprint: &[u8; 32]) -> String {
    format!(
        "groupsolo:{group_id}:jobsnapshot:{}",
        hex::encode(payouts_fingerprint)
    )
}

/// Build the SCAN-match pattern for ALL per-finder snapshots of one group —
/// used by [`delete_all_for_group`]. Does not cover the per-job payout-list
/// keys; see [`key_for_fingerprint`].
pub fn key_match_all(group_id: &str) -> String {
    format!("groupsolo:{group_id}:snapshot:*")
}

/// Build the SCAN-match pattern for every key of one group, per-finder and
/// per-job alike. Only for tearing a group down for good (dissolve), where no
/// job of that group can still be worth booking.
pub fn key_match_everything(group_id: &str) -> String {
    format!("groupsolo:{group_id}:*snapshot*")
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

/// Persist a snapshot under its payout-list identity with `ttl_seconds` TTL.
pub async fn write_snapshot_for(
    conn: &mut ConnectionManager,
    group_id: &str,
    payouts_fingerprint: &[u8; 32],
    snapshot: &StoredSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::write_snapshot(
        conn,
        &key_for_fingerprint(group_id, payouts_fingerprint),
        snapshot,
        ttl_seconds,
    )
    .await
}

/// Persist a schema-2 WEIGHT snapshot under the (group, finder) key.
pub async fn write_weight_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
    snapshot: &bp_coinbase_snapshot::StoredWeightSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::write_weight_snapshot(
        conn,
        &key(group_id, finder_address),
        snapshot,
        ttl_seconds,
    )
    .await
}

/// Persist a schema-2 WEIGHT snapshot under its weights fingerprint.
pub async fn write_weight_snapshot_for(
    conn: &mut ConnectionManager,
    group_id: &str,
    weights_fingerprint: &[u8; 32],
    snapshot: &bp_coinbase_snapshot::StoredWeightSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::write_weight_snapshot(
        conn,
        &key_for_fingerprint(group_id, weights_fingerprint),
        snapshot,
        ttl_seconds,
    )
    .await
}

/// Load the schema-2 WEIGHT snapshot for one weights fingerprint.
pub async fn read_weight_snapshot_for(
    conn: &mut ConnectionManager,
    group_id: &str,
    weights_fingerprint: &[u8; 32],
) -> Result<Option<bp_coinbase_snapshot::StoredWeightSnapshot>, RedisError> {
    bp_coinbase_snapshot::snapshot::read_weight_snapshot(
        conn,
        &key_for_fingerprint(group_id, weights_fingerprint),
    )
    .await
}

/// Load the schema-2 WEIGHT snapshot from the (group, finder) key.
pub async fn read_weight_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
) -> Result<Option<bp_coinbase_snapshot::StoredWeightSnapshot>, RedisError> {
    bp_coinbase_snapshot::snapshot::read_weight_snapshot(conn, &key(group_id, finder_address)).await
}

/// Load + hydrate the snapshot for one payout list, or `None` if missing /
/// unparseable.
pub async fn read_snapshot_for(
    conn: &mut ConnectionManager,
    group_id: &str,
    payouts_fingerprint: &[u8; 32],
) -> Result<Option<ParsedSnapshot>, RedisError> {
    bp_coinbase_snapshot::snapshot::read_snapshot(
        conn,
        &key_for_fingerprint(group_id, payouts_fingerprint),
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

/// Delete the payout-list snapshot the applied block consumed — and only that
/// one. Every other live job's key stays, so a second block found before the
/// next template rebuild still resolves; those are bounded by their TTL.
pub async fn delete_snapshot_for(
    conn: &mut ConnectionManager,
    group_id: &str,
    payouts_fingerprint: &[u8; 32],
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::delete_snapshot(
        conn,
        &key_for_fingerprint(group_id, payouts_fingerprint),
    )
    .await
}

/// SCAN + DEL every per-finder snapshot for the group — used by the block-found
/// post-commit cleanup (other miners' snapshots are stale once a round
/// resets) and the kick / dissolve admin flows.
pub async fn delete_all_for_group(
    conn: &mut ConnectionManager,
    group_id: &str,
) -> Result<u64, RedisError> {
    delete_matching(conn, &key_match_all(group_id)).await
}

/// SCAN + DEL every snapshot of the group, per-finder AND per-job. Only for
/// dissolve: it strips live jobs of their distribution, which is correct
/// exactly when the group is gone and no block of it can be booked anymore.
pub async fn delete_everything_for_group(
    conn: &mut ConnectionManager,
    group_id: &str,
) -> Result<u64, RedisError> {
    delete_matching(conn, &key_match_everything(group_id)).await
}

async fn delete_matching(conn: &mut ConnectionManager, pattern: &str) -> Result<u64, RedisError> {
    let mut conn_scan = conn.clone();
    let mut iter: AsyncIter<String> = conn_scan.scan_match(pattern).await?;
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

    /// The per-job keys must survive the group-wide per-finder wipe: they back
    /// jobs that are still being mined, and a block found on one of those after
    /// the wipe could not be booked at all.
    #[test]
    fn per_job_key_is_not_swept_by_the_per_finder_cleanup() {
        let fp = [0xabu8; 32];
        let job_key = key_for_fingerprint("g1", &fp);
        assert_eq!(
            job_key,
            format!("groupsolo:g1:jobsnapshot:{}", "ab".repeat(32))
        );

        let per_finder_prefix = key_match_all("g1").trim_end_matches('*').to_string();
        assert!(
            !job_key.starts_with(&per_finder_prefix),
            "{job_key} must NOT be swept by {per_finder_prefix}*"
        );
        // …while the per-finder key still is.
        assert!(key("g1", "bc1qfoo").starts_with(&per_finder_prefix));
    }

    /// Dissolve is the one wipe that must reach everything — the group is gone,
    /// so no job of it can still be worth booking.
    #[test]
    fn dissolve_pattern_reaches_both_key_kinds() {
        let pattern = key_match_everything("g1");
        assert_eq!(pattern, "groupsolo:g1:*snapshot*");
        // `groupsolo:g1:` + anything + `snapshot` + anything.
        let matches = |k: &str| {
            k.strip_prefix("groupsolo:g1:")
                .is_some_and(|rest| rest.contains("snapshot"))
        };
        assert!(matches(&key("g1", "bc1qfoo")));
        assert!(matches(&key_for_fingerprint("g1", &[0u8; 32])));
    }
}
