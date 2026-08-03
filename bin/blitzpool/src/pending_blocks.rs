// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation-gated block-found store (Redis) — one shape for every
//! mode that books against a payout distribution.
//!
//! A found block parks its distribution here instead of writing the
//! ledger immediately. The confirmation watcher (see
//! [`crate::block_confirmation`]) applies it once the block reaches
//! `confirmation_depth`, and discards it if it orphaned — so an orphan,
//! or a candidate that never extends the chain (common on regtest, rare
//! on mainnet), never books a phantom.
//!
//! What is parked are the **inputs**, not a computed result: the
//! distribution's settlement inputs plus what the block's coinbase
//! actually paid. Both are immutable, so the apply recomputes from them
//! and lands on the same satoshis however long the wait was. Freezing a
//! computed result instead is what used to force a re-base pass over
//! every balance row at apply time; there is nothing to re-base now.
//!
//! ## Why Redis (not Postgres)
//!
//! The store must survive a pool restart inside the confirmation window
//! (else a restart loses the pending apply — the same drift the whole
//! feature prevents). Valkey is already AOF/RDB-persistent and holds the
//! payout window + snapshots, so this is consistent with the existing
//! trust model and needs no schema migration. Entries are stored
//! **without a TTL** so the `volatile-lru` eviction policy (which only
//! evicts keys that have an expiry) can never drop them.

use redis::{aio::ConnectionManager, RedisError};

use crate::pending_store::{put_pending, remove_pending, PendingBlockRef};

/// Redis HASH holding every not-yet-confirmed block-found.
pub(crate) const PENDING_KEY: &str = "pool:pending_blocks";

/// A block no automatic path can book is parked here rather than
/// deleted, so its frozen distribution survives for the operator.
pub(crate) const UNBOOKABLE_KEY: &str = "pool:unbookable_blocks";

/// Which group a Group-Solo block belongs to. Absent for PPLNS, whose
/// accounting is pool-wide.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingGroup {
    /// Group UUID string.
    pub group_id: String,
    /// Finder (winning miner) address.
    pub finder: String,
}

/// One frozen, not-yet-applied block-found.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingBlock {
    /// Block hash (hex, big-endian display order) — the confirmation
    /// watcher's `getblockheader` key.
    pub block_hash: String,
    /// Wall clock (epoch ms) when the block was found.
    pub found_at_ms: i64,
    /// Block height (chain tip + 1 at find time).
    pub block_height: i32,
    /// The distribution's settlement inputs.
    #[serde(default)]
    pub weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
    /// What the block's coinbase actually paid — settlement's ground
    /// truth. Without it there is nothing to settle against.
    #[serde(default)]
    pub actual_coinbase: Option<bp_coinbase_snapshot::ActualCoinbase>,
    /// The weights fingerprint the winning job carried.
    #[serde(default)]
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// `Some` → Group-Solo, `None` → PPLNS.
    #[serde(default)]
    pub group: Option<PendingGroup>,
}

impl PendingBlockRef for PendingBlock {
    fn block_hash(&self) -> &str {
        &self.block_hash
    }
    fn block_height(&self) -> i32 {
        self.block_height
    }
}

/// Persist a pending block (idempotent — the same hash overwrites).
pub(crate) async fn put_pending_block(
    conn: &mut ConnectionManager,
    pending: &PendingBlock,
) -> Result<(), RedisError> {
    put_pending(conn, PENDING_KEY, &pending.block_hash, pending).await
}

/// Drop a pending block by hash (applied or orphaned). Idempotent.
pub(crate) async fn remove_pending_block(
    conn: &mut ConnectionManager,
    block_hash: &str,
) -> Result<(), RedisError> {
    remove_pending(conn, PENDING_KEY, block_hash).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored blob must round-trip exactly — it is replayed into the
    /// ledger once the block confirms.
    #[test]
    fn pending_block_json_round_trip() {
        let pb = PendingBlock {
            block_hash: "00000000000000000001abcd".to_string(),
            found_at_ms: 1_779_000_000_000,
            block_height: 840_000,
            weight_snapshot: None,
            actual_coinbase: None,
            payouts_fingerprint: Some([7u8; 32]),
            group: Some(PendingGroup {
                group_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                finder: "bcrt1qfinder".to_string(),
            }),
        };
        let json = serde_json::to_string(&pb).unwrap();
        let back: PendingBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block_hash, pb.block_hash);
        assert_eq!(back.block_height, 840_000);
        assert_eq!(back.payouts_fingerprint, Some([7u8; 32]));
        let group = back.group.as_ref().expect("group context survives");
        assert_eq!(group.finder, "bcrt1qfinder");
        assert_eq!(back.block_hash(), "00000000000000000001abcd");
        assert_eq!(back.block_height(), 840_000);
    }

    /// A PPLNS blob carries no group context, and every optional field is
    /// `serde(default)` so its absence on the wire is not an error.
    #[test]
    fn pplns_blob_has_no_group_context() {
        let json = r#"{"block_hash":"ab","found_at_ms":1,"block_height":2}"#;
        let back: PendingBlock = serde_json::from_str(json).unwrap();
        assert!(back.group.is_none());
        assert!(back.weight_snapshot.is_none());
        assert!(back.actual_coinbase.is_none());
    }
}
