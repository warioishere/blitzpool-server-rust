// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo snapshot key scheme on top of [`bp_coinbase_snapshot::snapshot`].
//! Each snapshot is written per (group, finder) and again under its payout
//! fingerprint; `on_block_found` resolves the fingerprint key, because that is
//! what the winning job's coinbase was built from.

use redis::{aio::ConnectionManager, AsyncCommands, AsyncIter, RedisError};

/// Build the snapshot key `groupsolo:{group_id}:snapshot:{finder_address}`.
pub fn key(group_id: &str, finder_address: &str) -> String {
    format!("groupsolo:{group_id}:snapshot:{finder_address}")
}

/// Build the payout-list key `groupsolo:{group_id}:jobsnapshot:{hex}`.
/// Deliberately outside the `…:snapshot:` prefix: a group-wide wipe
/// ([`delete_all_for_group`]) must not strip the distribution from jobs still
/// being mined, or a block found on one could not be booked.
pub fn key_for_fingerprint(group_id: &str, payouts_fingerprint: &[u8; 32]) -> String {
    format!(
        "groupsolo:{group_id}:jobsnapshot:{}",
        hex::encode(payouts_fingerprint)
    )
}

/// SCAN pattern for all per-finder snapshots of one group; does not cover the
/// per-job keys (see [`key_for_fingerprint`]).
pub fn key_match_all(group_id: &str) -> String {
    format!("groupsolo:{group_id}:snapshot:*")
}

/// SCAN pattern for every snapshot key of one group. Only for dissolve, where
/// no job of the group can still be worth booking.
pub fn key_match_everything(group_id: &str) -> String {
    format!("groupsolo:{group_id}:*snapshot*")
}

/// Persist a WEIGHT snapshot under the (group, finder) key.
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

/// Load the WEIGHT snapshot for one weights fingerprint.
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

/// Load the WEIGHT snapshot from the (group, finder) key.
pub async fn read_weight_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
) -> Result<Option<bp_coinbase_snapshot::StoredWeightSnapshot>, RedisError> {
    bp_coinbase_snapshot::snapshot::read_weight_snapshot(conn, &key(group_id, finder_address)).await
}

/// Delete one (group, finder) snapshot.
pub async fn delete_snapshot(
    conn: &mut ConnectionManager,
    group_id: &str,
    finder_address: &str,
) -> Result<(), RedisError> {
    bp_coinbase_snapshot::snapshot::delete_snapshot(conn, &key(group_id, finder_address)).await
}

/// Delete only the payout-list snapshot the applied block consumed, so a second
/// block found before the next template rebuild still resolves.
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

/// SCAN + DEL every per-finder snapshot for the group; they are stale once a
/// round resets.
pub async fn delete_all_for_group(
    conn: &mut ConnectionManager,
    group_id: &str,
) -> Result<u64, RedisError> {
    delete_matching(conn, &key_match_all(group_id)).await
}

/// SCAN + DEL every snapshot of the group, per-job included. Only for
/// dissolve, the one case where stripping live jobs is correct.
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

    /// Per-job keys survive the group-wide per-finder wipe.
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

    /// The dissolve pattern reaches both key kinds.
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
