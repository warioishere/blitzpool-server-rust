// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo snapshot key scheme on top of [`bp_coinbase_snapshot::snapshot`].
//! Each snapshot is written under its payout fingerprint, because that is what
//! the winning job's coinbase was built from.

use redis::{aio::ConnectionManager, AsyncCommands, AsyncIter, RedisError};

/// Build the payout-list key `groupsolo:{group_id}:jobsnapshot:{hex}`. It
/// lives until its TTL, not until a booking or reset: jobs still being mined
/// need it, or a block found on one could not be booked. Only dissolve deletes it.
pub fn key_for_fingerprint(group_id: &str, payouts_fingerprint: &[u8; 32]) -> String {
    format!(
        "groupsolo:{group_id}:jobsnapshot:{}",
        hex::encode(payouts_fingerprint)
    )
}

/// SCAN pattern for every snapshot key of one group. Only for dissolve, where
/// no job of the group can still be worth booking.
pub fn key_match_everything(group_id: &str) -> String {
    format!("groupsolo:{group_id}:*snapshot*")
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

    /// The dissolve pattern reaches the per-job key.
    #[test]
    fn dissolve_pattern_reaches_the_per_job_key() {
        let job_key = key_for_fingerprint("g1", &[0xabu8; 32]);
        assert_eq!(
            job_key,
            format!("groupsolo:g1:jobsnapshot:{}", "ab".repeat(32))
        );
        let pattern = key_match_everything("g1");
        assert_eq!(pattern, "groupsolo:g1:*snapshot*");
        assert!(job_key
            .strip_prefix("groupsolo:g1:")
            .is_some_and(|rest| rest.contains("snapshot")));
    }
}
