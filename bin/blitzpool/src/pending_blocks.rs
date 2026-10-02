// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation-gated block-found store: [`crate::block_confirmation`]
//! applies a parked block at `confirmation_depth` and discards an orphan, so
//! no phantom is booked. Parked are the immutable **inputs** (settlement
//! inputs + what the coinbase paid), so the apply recomputes the same sats.

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};

/// Redis HASH holding every not-yet-confirmed block-found. It must carry no
/// TTL: `volatile-lru` evicts only keys with an expiry, so this one survives.
pub(crate) const PENDING_KEY: &str = "pool:pending_blocks";

/// A block no automatic path can book is parked here rather than
/// deleted, so its frozen distribution survives for the operator.
pub(crate) const UNBOOKABLE_KEY: &str = "pool:unbookable_blocks";

/// Which group a group-mode block belongs to. Absent for PPLNS, whose
/// accounting is pool-wide.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingGroup {
    /// Group UUID string.
    pub group_id: String,
    /// Defaults to Group-Solo, so a blob parked without the field still
    /// settles as the only group mode that existed then.
    #[serde(default)]
    pub kind: GroupKind,
}

/// The modes keyed by a group, as stored in a parked blob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GroupKind {
    #[default]
    GroupSolo,
    Blockparty,
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
    /// The distribution's settlement inputs; PPLNS only.
    #[serde(default)]
    pub weight_snapshot: Option<bp_pplns_engine::window::snapshot::StoredWeightSnapshot>,
    /// What the block's coinbase actually paid — settlement's ground
    /// truth. Without it there is nothing to settle against.
    #[serde(default)]
    pub actual_coinbase: Option<bp_coinbase_snapshot::ActualCoinbase>,
    /// The weights fingerprint the winning job carried.
    #[serde(default)]
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// `None` → PPLNS, else the group's [`GroupKind`]. Branch on
    /// [`PendingBlock::mode`], not on this field.
    #[serde(default)]
    pub group: Option<PendingGroup>,
}

/// Which engine settles a block. The stored shape stays `group: Option`:
/// parked blocks carry no TTL, so a format change would make the watcher
/// prune already-parked blocks as unparsable.
pub(crate) enum SettlementMode<'a> {
    Pplns,
    GroupSolo(&'a PendingGroup),
    Blockparty(&'a PendingGroup),
}

impl<'a> SettlementMode<'a> {
    pub(crate) fn of(group: Option<&'a PendingGroup>) -> Self {
        match group {
            None => Self::Pplns,
            Some(g) => match g.kind {
                GroupKind::GroupSolo => Self::GroupSolo(g),
                GroupKind::Blockparty => Self::Blockparty(g),
            },
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Pplns => "pplns",
            Self::GroupSolo(_) => "group-solo",
            Self::Blockparty(_) => "blockparty",
        }
    }
}

impl PendingBlock {
    pub(crate) fn mode(&self) -> SettlementMode<'_> {
        SettlementMode::of(self.group.as_ref())
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

/// Drop a pending block by hash (applied, orphaned, unparsable or moved
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

/// Load every block in the pending store. A field whose JSON fails to parse
/// (corrupt / schema-drifted) is skipped, its hash returned in the second
/// tuple element so the caller can prune it.
pub(crate) async fn load_pending_blocks(
    conn: &mut ConnectionManager,
) -> Result<(Vec<PendingBlock>, Vec<String>), RedisError> {
    let map: std::collections::HashMap<String, String> = conn.hgetall(PENDING_KEY).await?;
    let mut ok = Vec::with_capacity(map.len());
    let mut unparsable = Vec::new();
    for (hash, json) in map {
        match serde_json::from_str::<PendingBlock>(&json) {
            Ok(v) => ok.push(v),
            Err(_) => unparsable.push(hash),
        }
    }
    Ok((ok, unparsable))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored blob round-trips exactly.
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
                kind: GroupKind::Blockparty,
            }),
        };
        let json = serde_json::to_string(&pb).unwrap();
        let back: PendingBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block_hash, pb.block_hash);
        assert_eq!(back.block_height, 840_000);
        assert_eq!(back.payouts_fingerprint, Some([7u8; 32]));
        let group = back.group.as_ref().expect("group context survives");
        assert_eq!(group.group_id, "550e8400-e29b-41d4-a716-446655440000");
        assert!(matches!(back.mode(), SettlementMode::Blockparty(_)));
    }

    /// A Group-Solo blob parked with a finder and a weight snapshot still
    /// parses and settles as Group-Solo: parked blocks carry no TTL.
    #[test]
    fn a_group_solo_blob_with_finder_and_snapshot_still_parses() {
        let json = r#"{"block_hash":"ab","found_at_ms":1,"block_height":2,
            "weight_snapshot":{"entries":[],"score_total":0,"weight_p":1,"fee_ppm":15000,
              "fee_address":"bc1qfee","reference_revenue_sats":312500000},
            "group":{"group_id":"550e8400-e29b-41d4-a716-446655440000","finder":"bcrt1qf"}}"#;
        let back: PendingBlock = serde_json::from_str(json).unwrap();
        assert!(matches!(back.mode(), SettlementMode::GroupSolo(g)
            if g.group_id == "550e8400-e29b-41d4-a716-446655440000"));
    }

    /// A PPLNS blob without group or optional fields still parses.
    #[test]
    fn pplns_blob_has_no_group_context() {
        let json = r#"{"block_hash":"ab","found_at_ms":1,"block_height":2}"#;
        let back: PendingBlock = serde_json::from_str(json).unwrap();
        assert!(back.group.is_none());
        assert!(back.weight_snapshot.is_none());
        assert!(back.actual_coinbase.is_none());
    }
}
