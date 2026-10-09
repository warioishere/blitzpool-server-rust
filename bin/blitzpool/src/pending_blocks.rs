// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation-gated block-found store: [`crate::block_confirmation`]
//! applies a parked block at `confirmation_depth` and discards an orphan, so
//! no phantom is booked. Parked are the immutable **inputs** (settlement
//! inputs + what the coinbase paid), so the apply recomputes the same sats.
//! A blob is read only by the version that wrote it: a release that changes
//! this format deploys with the store empty, so there is no compatibility layer.

use bp_coinbase_snapshot::ActualCoinbase;
use bp_pplns_engine::window::snapshot::StoredWeightSnapshot;
use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::error;
use uuid::Uuid;

/// Redis HASH holding every not-yet-confirmed block-found. It must carry no
/// TTL: `volatile-lru` evicts only keys with an expiry, so this one survives.
pub(crate) const PENDING_KEY: &str = "pool:pending_blocks";

/// A block no automatic path can book is parked here rather than
/// deleted, so its frozen distribution survives for the operator.
pub(crate) const UNBOOKABLE_KEY: &str = "pool:unbookable_blocks";

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
    /// What the block's coinbase actually paid — settlement's ground truth.
    pub actual_coinbase: ActualCoinbase,
    /// Which engine settles the block, with what only that engine reads.
    pub settlement: PendingSettlement,
}

/// The booking mode of a parked block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PendingSettlement {
    Pplns {
        /// The distribution's settlement inputs, resolved at found-time;
        /// `None` when that failed, which nothing can book automatically.
        weight_snapshot: Option<StoredWeightSnapshot>,
    },
    GroupSolo {
        group_id: Uuid,
    },
    Blockparty {
        group_id: Uuid,
    },
}

impl PendingSettlement {
    /// Whether the mode books against a distribution the pool built, so a
    /// coinbase without one has nothing to book. Blockparty recomputes its
    /// split from the roster instead.
    pub(crate) fn needs_pool_distribution(&self) -> bool {
        match self {
            Self::Pplns { .. } | Self::GroupSolo { .. } => true,
            Self::Blockparty { .. } => false,
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Pplns { .. } => "pplns",
            Self::GroupSolo { .. } => "group-solo",
            Self::Blockparty { .. } => "blockparty",
        }
    }

    /// The group a group-mode block belongs to; PPLNS accounting is pool-wide.
    pub(crate) fn group_id(&self) -> Option<Uuid> {
        match self {
            Self::Pplns { .. } => None,
            Self::GroupSolo { group_id } | Self::Blockparty { group_id } => Some(*group_id),
        }
    }
}

/// Write `pending` into the HASH at `key`, field = block hash (idempotent —
/// the same hash overwrites). No TTL, so `volatile-lru` eviction (which
/// only touches keys with an expiry) can never drop it.
async fn put_at(
    conn: &mut ConnectionManager,
    key: &str,
    pending: &PendingBlock,
) -> Result<(), RedisError> {
    // Serialization can't fail for these plain types; treat a failure as a
    // programming error rather than poisoning the call signature.
    let json = serde_json::to_string(pending).expect("serialize pending block");
    conn.hset::<_, _, _, ()>(key, &pending.block_hash, json)
        .await
}

/// Persist a pending block in the not-yet-confirmed store.
pub(crate) async fn put_pending_block(
    conn: &mut ConnectionManager,
    pending: &PendingBlock,
) -> Result<(), RedisError> {
    put_at(conn, PENDING_KEY, pending).await
}

/// Copy a block no automatic path can book into [`UNBOOKABLE_KEY`]. The
/// caller removes it from the pending store only once this succeeded.
pub(crate) async fn park_unbookable_block(
    conn: &mut ConnectionManager,
    pending: &PendingBlock,
) -> Result<(), RedisError> {
    put_at(conn, UNBOOKABLE_KEY, pending).await
}

/// Drop a pending block by hash (applied, orphaned or moved
/// to the unbookable store). Idempotent.
pub(crate) async fn remove_pending_block(
    conn: &mut ConnectionManager,
    block_hash: &str,
) -> Result<(), RedisError> {
    conn.hdel::<_, _, ()>(PENDING_KEY, block_hash).await
}

/// How many blocks are parked under `key`; makes a non-empty
/// [`UNBOOKABLE_KEY`] visible to the operator.
pub(crate) async fn count_pending_at(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<u64, RedisError> {
    conn.hlen(key).await
}

/// Hashes of every block still awaiting confirmation; unparsable fields
/// included, since those are still parked too.
pub(crate) async fn pending_block_hashes(
    conn: &mut ConnectionManager,
) -> Result<std::collections::HashSet<String>, RedisError> {
    conn.hkeys(PENDING_KEY).await
}

/// Load every block in the pending store. A field that does not parse stays
/// where it is: it only exists after a deploy that broke the format rule
/// above, and the operator decides what it was.
pub(crate) async fn load_pending_blocks(
    conn: &mut ConnectionManager,
) -> Result<Vec<PendingBlock>, RedisError> {
    let map: std::collections::HashMap<String, String> = conn.hgetall(PENDING_KEY).await?;
    let mut ok = Vec::with_capacity(map.len());
    for (hash, json) in map {
        match serde_json::from_str::<PendingBlock>(&json) {
            Ok(v) => ok.push(v),
            Err(err) => error!(
                block_hash = %hash,
                %err,
                pending_key = PENDING_KEY,
                "pending block does not parse with this version — left in place, not settled"
            ),
        }
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored blob round-trips exactly, settlement mode included.
    #[test]
    fn pending_block_json_round_trip() {
        let group_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let pb = PendingBlock {
            block_hash: "00000000000000000001abcd".to_string(),
            found_at_ms: 1_779_000_000_000,
            block_height: 840_000,
            actual_coinbase: ActualCoinbase {
                paid_by_address: [("bc1qminer".to_string(), 600)].into(),
                total_value_sats: 1_000,
            },
            settlement: PendingSettlement::Blockparty { group_id },
        };
        let json = serde_json::to_string(&pb).unwrap();
        let back: PendingBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block_hash, pb.block_hash);
        assert_eq!(back.block_height, 840_000);
        assert_eq!(back.actual_coinbase, pb.actual_coinbase);
        assert!(matches!(
            back.settlement,
            PendingSettlement::Blockparty { group_id: g } if g == group_id
        ));
    }

    /// The reconcile check looks a block up by the hash the chain reports, so
    /// the store must key each parked block by exactly that hash.
    #[tokio::test]
    async fn a_parked_block_is_listed_by_its_hash_until_removed() {
        let Some(mut conn) = bp_test_support::connect_redis_in_range_or_skip(
            bp_test_support::redis_db::BLITZPOOL_BIN_2,
            1,
        )
        .await
        else {
            return;
        };
        let hash = "0000000000000000000201d3f0c2b6a2e7f1f0ad2b3c4d5e6f708192a3b4c5d6".to_string();
        put_pending_block(
            &mut conn,
            &PendingBlock {
                block_hash: hash.clone(),
                found_at_ms: 1_790_000_000_000,
                block_height: 900_000,
                actual_coinbase: ActualCoinbase {
                    paid_by_address: Default::default(),
                    total_value_sats: 0,
                },
                settlement: PendingSettlement::Pplns {
                    weight_snapshot: None,
                },
            },
        )
        .await
        .unwrap();
        assert_eq!(
            pending_block_hashes(&mut conn).await.unwrap(),
            [hash.clone()].into()
        );

        remove_pending_block(&mut conn, &hash).await.unwrap();
        assert!(pending_block_hashes(&mut conn).await.unwrap().is_empty());
    }
}
