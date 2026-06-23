// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-backed per-group round state.
//!
//! Key layout (`{groupId}` is the UUID of the `pplns_group` row):
//!
//! - `groupsolo:{groupId}:shares` — zset, score=counter, member=`addr:diff:ms`
//! - `groupsolo:{groupId}:counter` — monotonic INCR counter
//! - `groupsolo:{groupId}:total` — float string, Σ diff in round
//! - `groupsolo:{groupId}:by-address` — hash `addr → diff` aggregate
//! - `groupsolo:{groupId}:rejected-shares` — hash `addr → diff` rejected
//! - `groupsolo:{groupId}:last-accepted-share-at` — hash `addr → epoch_ms`
//! - `groupsolo:{groupId}:best-share` — hash `{address, difficulty, timestamp_ms}`
//! - `groupsolo:{groupId}:snapshot:{finder_address}` — see [`snapshot`]
//!
//! No trim — Group-Solo is a PROP round, not a windowed PPLNS. Two
//! reset paths exist:
//!
//! `reset_for_block_found` wipes shares, counter, total, by-address,
//! rejected-shares, best-share, and all per-finder snapshots, but
//! preserves `last-accepted-share-at` (PROP semantics: inactivity
//! clock survives across blocks).
//!
//! `reset_full` wipes everything including `last-accepted-share-at`.
//! Used by the scheduled (calendar-aligned) cron reset path. The
//! cron also DELETEs all `pplns_group_balance` rows for the group —
//! that's the engine-layer's job, not the round-store's.

pub mod snapshot;

use std::collections::HashMap;

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use thiserror::Error;

// ── Key helpers ─────────────────────────────────────────────────────

/// Produce the `groupsolo:{group_id}:{suffix}` key. `group_id` is
/// caller-provided (typically the UUID string of the `pplns_group`
/// row); we don't impose a shape so admin tooling can use a
/// well-known sentinel for tests.
fn key(group_id: &str, suffix: &str) -> String {
    format!("groupsolo:{group_id}:{suffix}")
}

pub fn key_shares(group_id: &str) -> String {
    key(group_id, "shares")
}
pub fn key_counter(group_id: &str) -> String {
    key(group_id, "counter")
}
pub fn key_total(group_id: &str) -> String {
    key(group_id, "total")
}
pub fn key_by_address(group_id: &str) -> String {
    key(group_id, "by-address")
}
pub fn key_rejected_shares(group_id: &str) -> String {
    key(group_id, "rejected-shares")
}
pub fn key_last_accepted_share_at(group_id: &str) -> String {
    key(group_id, "last-accepted-share-at")
}
pub fn key_best_share(group_id: &str) -> String {
    key(group_id, "best-share")
}
/// Dedup zset `share_id → counter` for exactly-once `record_share`,
/// per group. Capped to the newest [`DEDUP_KEEP`] ids by rank.
pub fn key_applied(group_id: &str) -> String {
    key(group_id, "applied")
}

/// How many recent `share_id`s the per-group dedup set retains. Mirrors
/// the PPLNS window horizon — only un-acked in-flight shares are ever
/// redelivered, so a few-thousand horizon is ample; 100k is negligible.
const DEDUP_KEEP: i64 = 100_000;

/// Atomic, optionally-idempotent append of one accepted Group-Solo share.
/// Round state is the per-address aggregate only (no per-share zset — PROP
/// needs sums, not individual shares). KEYS[1]=counter, [2]=total,
/// [3]=by-address, [4]=last-accepted-share-at, [5]=applied. ARGV[1]=difficulty
/// (string), [2]=address, [3]=timestamp_ms (string), [4]=share_id (empty ⇒
/// no dedup), [5]=keep-count. Same exactly-once contract as the PPLNS window:
/// with a `share_id`, a redelivered share is a no-op and the marker is
/// recorded in the same script, so a consumer crash between apply and ack
/// can't double-count the round. No trim — Group-Solo is a PROP round.
/// Returns 1 on append, 0 on a deduped no-op. (The counter is still INCR'd —
/// it scores the dedup marker zset.)
const RECORD_SHARE_LUA: &str = r#"
local has_dedup = ARGV[4] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[5], ARGV[4]) then
    return 0
end
local counter = redis.call('INCR', KEYS[1])
redis.call('INCRBYFLOAT', KEYS[2], ARGV[1])
redis.call('HINCRBYFLOAT', KEYS[3], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[4], ARGV[2], ARGV[3])
if has_dedup then
    redis.call('ZADD', KEYS[5], counter, ARGV[4])
    redis.call('ZREMRANGEBYRANK', KEYS[5], 0, -tonumber(ARGV[5]) - 1)
end
return 1
"#;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RoundError {
    #[error("redis: {0}")]
    Redis(#[from] RedisError),
    #[error("malformed share entry: {0:?}")]
    MalformedEntry(String),
}

// ── BestShare ──────────────────────────────────────────────────────

/// In-round best share for a group. Stored as a Redis hash.
#[derive(Clone, Debug, PartialEq)]
pub struct BestShare {
    pub address: String,
    pub difficulty: f64,
    pub timestamp_ms: i64,
}

// ── Aggregated round stats ─────────────────────────────────────────

/// Snapshot read used by `/api/pplns/groups/:groupId/round-stats`.
#[derive(Clone, Debug, PartialEq)]
pub struct RoundStats {
    pub total_shares: f64,
    pub total_rejected: f64,
    pub per_address: HashMap<String, f64>,
    pub rejected_per_address: HashMap<String, f64>,
}

// ── Store ──────────────────────────────────────────────────────────

/// Cheap to clone — `ConnectionManager` is `Arc`-backed.
#[derive(Clone)]
pub struct GroupRoundStore {
    conn: ConnectionManager,
}

impl GroupRoundStore {
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    // ── Hot path: record an accepted share ─────────────────────────

    /// Append one accepted share to the round, optionally exactly-once.
    ///
    /// Runs the whole append (total/by-address increments + the
    /// `last-accepted-share-at` touch, + the dedup-marker counter) as one
    /// indivisible Lua script ([`RECORD_SHARE_LUA`]) — same atomicity the old
    /// `MULTI/EXEC` gave. With a `Some(share_id)` it also dedups: a
    /// redelivered share whose id is still in the per-group dedup set is a
    /// no-op, and the marker is recorded in the same script. `None` keeps
    /// the plain append for direct round tests / admin tooling. No trim —
    /// Group-Solo is a PROP round, wiped on block-found.
    ///
    /// Returns `true` on a real append, `false` on a deduped no-op.
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        group_id: &str,
        address: &str,
        difficulty: f64,
        timestamp_ms: i64,
    ) -> Result<bool, RoundError> {
        let mut conn = self.conn.clone();

        let applied: i64 = redis::Script::new(RECORD_SHARE_LUA)
            .key(key_counter(group_id))
            .key(key_total(group_id))
            .key(key_by_address(group_id))
            .key(key_last_accepted_share_at(group_id))
            .key(key_applied(group_id))
            .arg(difficulty.to_string())
            .arg(address)
            .arg(timestamp_ms)
            .arg(share_id.unwrap_or(""))
            .arg(DEDUP_KEEP)
            .invoke_async(&mut conn)
            .await?;

        Ok(applied == 1)
    }

    /// Per-rejected-share counter for the address. `shares` is the
    /// diff-1-equivalent value the stratum layer reports per reject
    /// reason (typically 1.0).
    pub async fn record_reject(
        &self,
        group_id: &str,
        address: &str,
        shares: f64,
    ) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let _: f64 = conn
            .hincr(key_rejected_shares(group_id), address, shares)
            .await?;
        Ok(())
    }

    // ── Best-share update (fire-and-forget improvement check) ─────

    /// Read the current best share. Returns `None` if no shares have
    /// been recorded for this round yet.
    pub async fn read_best_share(&self, group_id: &str) -> Result<Option<BestShare>, RoundError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(key_best_share(group_id)).await?;
        if hash.is_empty() {
            return Ok(None);
        }
        let address = hash.get("address").cloned();
        let difficulty: Option<f64> = hash.get("difficulty").and_then(|v| v.parse().ok());
        let timestamp_ms: Option<i64> = hash.get("timestamp_ms").and_then(|v| v.parse().ok());
        match (address, difficulty, timestamp_ms) {
            (Some(a), Some(d), Some(t)) => Ok(Some(BestShare {
                address: a,
                difficulty: d,
                timestamp_ms: t,
            })),
            _ => Ok(None),
        }
    }

    /// Update the best-share record if `(address, difficulty,
    /// timestamp_ms)` strictly improves on the stored value. Returns
    /// `true` when the record was replaced. Compare-and-swap via
    /// Redis MULTI/EXEC + WATCH would be the strictly-correct
    /// pattern; for the round-best-share we accept the tiny race
    /// (two concurrent improvers, last write wins) — the round wipes
    /// on block-found anyway, and a stale-by-microseconds best-share
    /// is a cosmetic display issue, not a correctness one.
    pub async fn update_best_share_if_better(
        &self,
        group_id: &str,
        address: &str,
        difficulty: f64,
        timestamp_ms: i64,
    ) -> Result<bool, RoundError> {
        let current = self.read_best_share(group_id).await?;
        let is_improvement = match &current {
            None => true,
            Some(b) => difficulty > b.difficulty,
        };
        if !is_improvement {
            return Ok(false);
        }
        let mut conn = self.conn.clone();
        let fields: Vec<(&str, String)> = vec![
            ("address", address.to_string()),
            ("difficulty", difficulty.to_string()),
            ("timestamp_ms", timestamp_ms.to_string()),
        ];
        let _: () = conn
            .hset_multiple(key_best_share(group_id), &fields)
            .await?;
        Ok(true)
    }

    // ── Round-reset paths ──────────────────────────────────────────

    /// Block-found reset: wipe round state but preserve
    /// `last-accepted-share-at` (PROP semantics — inactivity clock
    /// survives). Caller drains snapshots separately via
    /// [`snapshot::delete_all_for_group`].
    pub async fn reset_for_block_found(&self, group_id: &str) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let keys = vec![
            key_counter(group_id),
            key_total(group_id),
            key_by_address(group_id),
            key_rejected_shares(group_id),
            key_best_share(group_id),
            // The dedup zset is scored by the per-group counter, which resets
            // here — so it MUST reset with the round. Leaving stale high-scored
            // entries would make `ZREMRANGEBYRANK` trim freshly-added low-scored
            // markers, breaking exactly-once on consumer-redelivery.
            key_applied(group_id),
        ];
        let _: i64 = conn.del(keys).await?;
        Ok(())
    }

    /// Scheduled (calendar-aligned) reset: wipe everything including
    /// `last-accepted-share-at`. Caller deletes the group's balance
    /// rows + per-finder snapshots separately.
    pub async fn reset_full(&self, group_id: &str) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let keys = vec![
            key_counter(group_id),
            key_total(group_id),
            key_by_address(group_id),
            key_rejected_shares(group_id),
            key_best_share(group_id),
            key_last_accepted_share_at(group_id),
            // Round-scoped dedup set — reset with the round (see
            // `reset_for_block_found`).
            key_applied(group_id),
        ];
        let _: i64 = conn.del(keys).await?;
        Ok(())
    }

    // ── Reads ──────────────────────────────────────────────────────

    /// Hot read of per-address contribution from the `by-address` hash
    /// (O(distinct miners)) — the authoritative round state. There is no
    /// per-share zset to fall back to: `record_share` maintains this hash on
    /// every accepted share, and it has the same AOF durability the zset had.
    pub async fn read_by_address(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, f64>, RoundError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(key_by_address(group_id)).await?;
        Ok(hash
            .into_iter()
            .filter_map(|(addr, diff_str)| {
                let diff: f64 = diff_str.parse().ok()?;
                if diff > 0.0 {
                    Some((addr, diff))
                } else {
                    None
                }
            })
            .collect())
    }

    pub async fn read_rejected(&self, group_id: &str) -> Result<HashMap<String, f64>, RoundError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(key_rejected_shares(group_id)).await?;
        Ok(hash
            .into_iter()
            .filter_map(|(addr, v)| v.parse::<f64>().ok().map(|d| (addr, d)))
            .collect())
    }

    pub async fn read_total(&self, group_id: &str) -> Result<f64, RoundError> {
        let mut conn = self.conn.clone();
        let s: Option<String> = conn.get(key_total(group_id)).await?;
        Ok(s.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0.0))
    }

    pub async fn read_last_accepted_share_at(
        &self,
        group_id: &str,
        address: &str,
    ) -> Result<Option<i64>, RoundError> {
        let mut conn = self.conn.clone();
        let v: Option<String> = conn
            .hget(key_last_accepted_share_at(group_id), address)
            .await?;
        Ok(v.as_deref().and_then(|s| s.parse().ok()))
    }

    /// Composed view used by `/api/pplns/groups/:groupId/round-stats`.
    pub async fn read_round_stats(&self, group_id: &str) -> Result<RoundStats, RoundError> {
        let by_address = self.read_by_address(group_id).await?;
        let rejected_map = self.read_rejected(group_id).await?;
        let total_shares: f64 = by_address.values().sum();
        let total_rejected: f64 = rejected_map.values().sum();
        Ok(RoundStats {
            total_shares,
            total_rejected,
            per_address: by_address,
            rejected_per_address: rejected_map,
        })
    }

    // ── Member operations (admin-triggered) ────────────────────────

    /// Subtract the address's contribution from the round (kick
    /// flow). Returns the diff-1-weighted amount removed so the
    /// caller can refund / redistribute as group policy dictates.
    /// Return a fresh `ConnectionManager` clone for snapshot writes /
    /// reads. The connection is multiplexed and cheap to clone;
    /// distribution.rs uses this to call `snapshot::write_snapshot`
    /// without holding the store's internal handle.
    pub fn connection_for_snapshot(&self) -> ConnectionManager {
        self.conn.clone()
    }

    pub async fn forget_member(&self, group_id: &str, address: &str) -> Result<f64, RoundError> {
        let mut conn = self.conn.clone();

        // 1. The member's round contribution IS their by-address aggregate —
        //    no per-share scan needed.
        let removed_diff: f64 = conn
            .hget::<_, _, Option<String>>(key_by_address(group_id), address)
            .await?
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|d| d.is_finite() && *d > 0.0)
            .unwrap_or(0.0);

        if removed_diff == 0.0 {
            return Ok(0.0);
        }

        // 2. Decrement total + drop the address's by-address / last-accepted
        //    slots + best-share if it referenced this address. Single pipeline
        //    for cross-key coherence (MULTI/EXEC not necessary because no
        //    concurrent caller mutates these for the same address during a
        //    kick — admin flow is serialized at the engine level).
        let mut pipe = redis::pipe();
        pipe.cmd("INCRBYFLOAT")
            .arg(key_total(group_id))
            .arg(-removed_diff)
            .ignore()
            .hdel(key_by_address(group_id), address)
            .ignore()
            .hdel(key_last_accepted_share_at(group_id), address)
            .ignore();
        pipe.query_async::<()>(&mut conn).await?;

        // Best-share: if it was for this address, delete (next share
        // sets a fresh one). Read-then-DEL is the simpler shape than
        // WATCH/CAS — losing a best-share record is cosmetic.
        if let Some(best) = self.read_best_share(group_id).await? {
            if best.address == address {
                let _: i64 = conn.del(key_best_share(group_id)).await?;
            }
        }

        Ok(removed_diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_helpers_format_correctly() {
        assert_eq!(key_shares("g1"), "groupsolo:g1:shares");
        assert_eq!(key_counter("g1"), "groupsolo:g1:counter");
        assert_eq!(key_total("g1"), "groupsolo:g1:total");
        assert_eq!(key_by_address("g1"), "groupsolo:g1:by-address");
        assert_eq!(key_rejected_shares("g1"), "groupsolo:g1:rejected-shares");
        assert_eq!(
            key_last_accepted_share_at("g1"),
            "groupsolo:g1:last-accepted-share-at"
        );
        assert_eq!(key_best_share("g1"), "groupsolo:g1:best-share");
    }

    #[test]
    fn key_helpers_support_uuid_group_id() {
        let g = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            key_shares(g),
            "groupsolo:550e8400-e29b-41d4-a716-446655440000:shares"
        );
    }

    #[test]
    fn round_stats_total_is_sum_of_per_address() {
        let mut per = HashMap::new();
        per.insert("a".to_string(), 30.0);
        per.insert("b".to_string(), 70.0);
        let stats = RoundStats {
            total_shares: per.values().sum(),
            total_rejected: 0.0,
            per_address: per,
            rejected_per_address: HashMap::new(),
        };
        assert!((stats.total_shares - 100.0).abs() < 1e-9);
        assert_eq!(stats.per_address.len(), 2);
    }

    #[test]
    fn best_share_partial_eq() {
        let a = BestShare {
            address: "bc1qfoo".to_string(),
            difficulty: 100.0,
            timestamp_ms: 1_700_000_000_000,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
