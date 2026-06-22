// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation-gated Group-Solo block-found store (Redis).
//!
//! Like the PPLNS store ([`crate::pending_blocks`]), a found Group-Solo block
//! parks its frozen distribution snapshot here instead of writing the ledger
//! immediately. The confirmation watcher applies it once the block reaches
//! `confirmation_depth` confirmations, and discards it if it orphaned — so an
//! orphan / a non-chain-extending candidate (common on regtest, rare on
//! mainnet) never books a phantom into the group ledger. The snapshot is the
//! exact distribution the coinbase was built from (frozen at block-found in the
//! event), so the apply is self-contained.
//!
//! Same Redis HASH layout as PPLNS via [`crate::pending_store`] — different key
//! + payload, no duplicated put/remove/load logic.

use bp_coinbase_snapshot::snapshot::StoredSnapshot;
use redis::{aio::ConnectionManager, RedisError};

use crate::pending_store::{put_pending, remove_pending, PendingBlockRef};

/// Redis HASH holding every not-yet-confirmed Group-Solo block-found.
pub(crate) const GS_PENDING_KEY: &str = "groupsolo:pending_blocks";

/// One frozen, not-yet-applied Group-Solo block-found.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingGroupSoloBlock {
    /// Block hash (hex, big-endian display order) — the confirmation watcher's
    /// `getblockheader` key.
    pub block_hash: String,
    /// Wall clock (epoch ms) when the block was found.
    pub found_at_ms: i64,
    /// Group UUID string.
    pub group_id: String,
    /// Finder (winning miner) address.
    pub finder: String,
    /// Block height (chain tip + 1 at find time).
    pub block_height: i32,
    /// Block-reward portion this coinbase claims.
    pub block_reward_sats: u64,
    /// The exact distribution the coinbase paid, frozen at find-time. Applied
    /// verbatim via `GroupSoloEngine::on_block_found_with_snapshot` once the
    /// block confirms.
    pub snapshot: StoredSnapshot,
}

impl PendingBlockRef for PendingGroupSoloBlock {
    fn block_hash(&self) -> &str {
        &self.block_hash
    }
    fn block_height(&self) -> i32 {
        self.block_height
    }
}

/// Persist a pending Group-Solo block (idempotent — same hash overwrites).
pub(crate) async fn put_pending_group_solo_block(
    conn: &mut ConnectionManager,
    pending: &PendingGroupSoloBlock,
) -> Result<(), RedisError> {
    put_pending(conn, GS_PENDING_KEY, &pending.block_hash, pending).await
}

/// Drop a pending Group-Solo block by hash (applied or orphaned). Idempotent.
pub(crate) async fn remove_pending_group_solo_block(
    conn: &mut ConnectionManager,
    block_hash: &str,
) -> Result<(), RedisError> {
    remove_pending(conn, GS_PENDING_KEY, block_hash).await
}

// `load_pending_group_solo_blocks` is unnecessary: the confirmation watcher's
// generic `collect_confirmed::<PendingGroupSoloBlock>` calls the generic
// `pending_store::load_pending` directly.

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::Sats;
    use bp_pplns::CoinbaseDistributionEntry;

    /// The stored blob must round-trip exactly — it's replayed into the ledger
    /// once the block confirms.
    #[test]
    fn pending_group_solo_block_json_round_trip() {
        let pb = PendingGroupSoloBlock {
            block_hash: "00000000deadbeef".to_string(),
            found_at_ms: 1_779_000_000_000,
            group_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            finder: "bcrt1qfinder".to_string(),
            block_height: 840_000,
            block_reward_sats: 312_500_000,
            snapshot: StoredSnapshot {
                distribution: vec![CoinbaseDistributionEntry {
                    address: bp_common::AddressId::new("bcrt1qfinder".to_string()).unwrap(),
                    percent: 100.0,
                    sats: Sats(312_500_000),
                }],
                block_reward_sats: 312_500_000,
                considered_addresses: vec!["bcrt1qfinder".to_string()],
                balance_after: vec![("bcrt1qfinder".to_string(), 0)],
            },
        };
        let json = serde_json::to_string(&pb).unwrap();
        let back: PendingGroupSoloBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block_hash, pb.block_hash);
        assert_eq!(back.group_id, pb.group_id);
        assert_eq!(back.finder, pb.finder);
        assert_eq!(back.block_height, 840_000);
        assert_eq!(back.block_reward_sats, 312_500_000);
        assert_eq!(back.snapshot, pb.snapshot);
        assert_eq!(back.block_hash(), "00000000deadbeef");
        assert_eq!(back.block_height(), 840_000);
    }
}
