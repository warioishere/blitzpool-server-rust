// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation-gated PPLNS block-found store (Redis).
//!
//! When the pool finds a block, the PPLNS payout distribution is computed
//! and **frozen** at found-time (the live snapshot rotates within a block
//! or two) but NOT yet written to the ledger — the block must first reach
//! `confirmation_depth` confirmations, so a block that ends up orphaned
//! never drifts the internal pending-balance ledger. The frozen
//! distribution lives here, keyed by block hash, until the confirmation
//! watcher (see [`crate::block_confirmation`]) applies or discards it.
//!
//! ## Why Redis (not Postgres)
//!
//! The store must survive a pool restart inside the ~N-block confirmation
//! window (else a restart loses the pending apply — the same drift the
//! whole feature prevents). Valkey is already AOF/RDB-persistent and holds
//! the PPLNS window + snapshot, so this is consistent with the existing
//! trust model and needs no schema migration. The entries are stored
//! **without a TTL** so the `volatile-lru` eviction policy (which only
//! evicts keys that have an expiry) can never drop them.
//!
//! Layout: a single Redis HASH `pplns:pending_blocks`, field = block hash
//! (hex), value = JSON [`PendingBlock`].

use bp_pplns_engine::engine::PreparedBlockFound;
use redis::{aio::ConnectionManager, RedisError};

use crate::pending_store::{load_pending, put_pending, remove_pending, PendingBlockRef};

/// Redis HASH holding every not-yet-confirmed PPLNS block-found.
pub(crate) const PENDING_KEY: &str = "pplns:pending_blocks";

/// One frozen, not-yet-applied PPLNS block-found.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingBlock {
    /// Block hash (hex, big-endian display order) — the key the
    /// confirmation watcher passes to `getblockheader`.
    pub block_hash: String,
    /// Wall clock (epoch ms) when the block was found — diagnostics +
    /// a safety cap on how long an unresolved entry may linger.
    pub found_at_ms: i64,
    /// The PPLNS distribution frozen at found-time, replayed verbatim by
    /// `PplnsEngine::apply_prepared` once the block confirms.
    pub prepared: PreparedBlockFound,
}

impl PendingBlockRef for PendingBlock {
    fn block_hash(&self) -> &str {
        &self.block_hash
    }
    fn block_height(&self) -> i32 {
        self.prepared.block_height
    }
}

/// Persist a pending block (idempotent — same hash overwrites). No TTL.
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

/// Load every pending block. Used on each confirmation tick and on boot
/// to recover entries left over from a previous process. A field whose
/// JSON fails to parse (corrupt / schema-drifted) is skipped with its
/// hash returned in the second tuple element so the caller can prune it.
pub(crate) async fn load_pending_blocks(
    conn: &mut ConnectionManager,
) -> Result<(Vec<PendingBlock>, Vec<String>), RedisError> {
    load_pending(conn, PENDING_KEY).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_pplns_engine::engine::{PreparedAuditRow, PreparedBalanceWrite};

    /// The stored blob must round-trip exactly — it's what gets replayed
    /// into the ledger once the block confirms.
    #[test]
    fn pending_block_json_round_trip() {
        let pb = PendingBlock {
            block_hash: "00000000000000000001abcd".to_string(),
            found_at_ms: 1_779_000_000_000,
            prepared: PreparedBlockFound {
                block_height: 840_000,
                block_reward_sats: 312_500_000,
                now_ms: 1_779_000_000_000,
                rows: vec![PreparedAuditRow {
                    address: "bc1qexampleaddr".to_string(),
                    paid_sats: 5_000_000,
                    percent: 1.6,
                    row_type: "coinbase".to_string(),
                }],
                balances: vec![PreparedBalanceWrite {
                    address: "bc1qexampleaddr".to_string(),
                    balance_sats: 0,
                    total_paid_sats: 5_000_000,
                }],
            },
        };
        let json = serde_json::to_string(&pb).unwrap();
        let back: PendingBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block_hash, pb.block_hash);
        assert_eq!(back.found_at_ms, pb.found_at_ms);
        assert_eq!(back.prepared.block_height, 840_000);
        assert_eq!(back.prepared.rows.len(), 1);
        assert_eq!(back.prepared.rows[0].row_type, "coinbase");
        assert_eq!(back.prepared.balances[0].total_paid_sats, 5_000_000);
    }
}
