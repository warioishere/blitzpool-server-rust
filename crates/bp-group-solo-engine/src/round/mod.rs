// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-backed per-group round state under `groupsolo:{groupId}:*`.
//! A `Prop` group is a round a booked block takes its found-time state out
//! of; a `Window` group is a time-bucketed sliding window trimmed by age, of
//! which a booked block resets only the best share.
//! Every reset path keeps `applied` (see [`key_applied`]) so an un-ACKed batch is not reapplied.

use std::collections::HashMap;

use bp_group_mgmt::group::PayoutMode;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

// ── Key helpers ─────────────────────────────────────────────────────

/// Produce the `groupsolo:{group_id}:{suffix}` key. `group_id` is usually
/// the `pplns_group` row's UUID; no shape is imposed so tests and admin
/// tooling can use a sentinel.
fn key(group_id: &str, suffix: &str) -> String {
    format!("groupsolo:{group_id}:{suffix}")
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
/// Dedup zset `share_id → timestamp_ms` for exactly-once `record_share`,
/// capped to the newest `DEDUP_KEEP` ids. Scored by accept time, which stays
/// monotonic across round resets, so the set survives them and an un-ACKed
/// satellite batch is still deduped afterwards.
pub fn key_applied(group_id: &str) -> String {
    key(group_id, "applied")
}
/// Hashes of the blocks whose found-time state [`GroupRoundStore::settle_block`]
/// took out of the round, so each block does it once whatever order its
/// bookings and their retries run in.
pub fn key_settled_blocks(group_id: &str) -> String {
    key(group_id, "settled-blocks")
}
/// Σ diff-1 the group's accepted shares carry since its last block, in both
/// modes. A booked block takes its found-time share of it out; the calendar
/// reset and removing a member leave it alone, dissolving the group drops it.
pub fn key_shares_since_block(group_id: &str) -> String {
    key(group_id, "shares-since-block")
}
/// Count of calendar resets of the round. A block found before one has its
/// round taken out already, so its booking leaves the round alone.
pub fn key_round_generation(group_id: &str) -> String {
    key(group_id, "round-generation")
}

// ── Window-mode keys (PayoutMode::Window only) ──────────────────────
// Kept under the `groupsolo:{id}:` prefix so backup/restore covers them.
// The rejected lane feeds only round-stats and shares the accepted lane's
// trim, so the reject rate compares one period with itself.

/// The two sliding-window lanes of a `Window`-mode group. Same bucket /
/// index / aggregate layout, same trim; only the key suffixes differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowLane {
    /// Accepted work — feeds the payout distribution.
    Accepted,
    /// Rejected work — feeds only the round-stats view.
    Rejected,
}

impl WindowLane {
    const ALL: [WindowLane; 2] = [WindowLane::Accepted, WindowLane::Rejected];

    /// Index zset of live time-bucket ids.
    pub fn index_key(self, group_id: &str) -> String {
        match self {
            WindowLane::Accepted => key(group_id, "wbuckets"),
            WindowLane::Rejected => key(group_id, "wrbuckets"),
        }
    }

    /// Per-time-bucket `addr → Σdiff` hash key for bucket `bid`.
    pub fn bucket_key(self, group_id: &str, bid: i64) -> String {
        format!("{}{bid}", self.bucket_prefix(group_id))
    }

    /// Authoritative `addr → Σdiff` window aggregate.
    pub fn aggregate_key(self, group_id: &str) -> String {
        match self {
            WindowLane::Accepted => key(group_id, "window:by-address"),
            WindowLane::Rejected => key(group_id, "window:rejected"),
        }
    }

    /// Bucket-key prefix passed to the trim script so it can build the
    /// bucket key for each dropped bucket inside Lua.
    fn bucket_prefix(self, group_id: &str) -> String {
        match self {
            WindowLane::Accepted => key(group_id, "wbucket:"),
            WindowLane::Rejected => key(group_id, "wrbucket:"),
        }
    }
}

/// Index zset of live time-bucket ids for a `Window`-mode group.
pub fn key_window_buckets(group_id: &str) -> String {
    WindowLane::Accepted.index_key(group_id)
}
/// Per-time-bucket `addr → Σdiff` hash key for bucket `bid`.
pub fn key_window_bucket(group_id: &str, bid: i64) -> String {
    WindowLane::Accepted.bucket_key(group_id, bid)
}
/// Authoritative `addr → Σdiff` window aggregate for a `Window`-mode group.
pub fn key_window_by_address(group_id: &str) -> String {
    WindowLane::Accepted.aggregate_key(group_id)
}

/// Time-bucket granularity for the sliding window: 1 hour. Storage is
/// O(buckets × miners), not O(shares). A constant, not config, so bucket ids
/// stay stable across a window-length change.
pub const WINDOW_BUCKET_MS: i64 = 60 * 60 * 1000;

/// How many recent `share_id`s the per-group dedup set retains. Only
/// un-acked in-flight shares are ever redelivered, so this is ample.
const DEDUP_KEEP: i64 = 100_000;

/// Append one accepted share to the PROP round; returns 0 on a deduped no-op.
/// `KEYS` = by-address, last-accepted-share-at, applied, shares-since-block; `ARGV` =
/// difficulty, address, timestamp_ms, share_id (empty ⇒ no dedup), keep-count.
/// The dedup marker is written in the same script so a crash before ack cannot double-count.
const RECORD_SHARE_LUA: &str = r#"
local has_dedup = ARGV[4] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[3], ARGV[4]) then
    return 0
end
redis.call('HINCRBYFLOAT', KEYS[1], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[2], ARGV[2], ARGV[3])
redis.call('INCRBYFLOAT', KEYS[4], ARGV[1])
if has_dedup then
    redis.call('ZADD', KEYS[3], ARGV[3], ARGV[4])
    redis.call('ZREMRANGEBYRANK', KEYS[3], 0, -tonumber(ARGV[5]) - 1)
end
return 1
"#;

/// Window-mode twin of `RECORD_SHARE_LUA`, same dedup contract. `KEYS` = applied,
/// wbuckets, window:by-address, wbucket:{bid}, last-accepted-share-at,
/// shares-since-block; `ARGV` =
/// difficulty, address, share_id, keep-count, bucket_id, timestamp_ms.
/// Bucket, aggregate and index move together so a snapshot never sees a partial write.
const RECORD_SHARE_WINDOWED_LUA: &str = r#"
local has_dedup = ARGV[3] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[1], ARGV[3]) then
    return 0
end
redis.call('HINCRBYFLOAT', KEYS[4], ARGV[2], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[5], ARGV[5])
redis.call('HINCRBYFLOAT', KEYS[3], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[5], ARGV[2], ARGV[6])
redis.call('INCRBYFLOAT', KEYS[6], ARGV[1])
if has_dedup then
    redis.call('ZADD', KEYS[1], ARGV[6], ARGV[3])
    redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -tonumber(ARGV[4]) - 1)
end
return 1
"#;

/// Drop the oldest bucket if its id ≤ `ARGV[1]` and subtract it from the
/// aggregate; returns `{dropped, underflowed}`, the caller loops until 0.
/// Negative remainders are `HDEL`ed too (left in place they would swallow the
/// address's next shares) and counted so the skew is logged. Needs non-cluster Valkey.
const TRIM_WINDOW_LUA: &str = r#"
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0)
if #oldest < 1 then return {0, 0} end
local bid = oldest[1]
if tonumber(bid) > tonumber(ARGV[1]) then return {0, 0} end
local bkey = ARGV[2] .. bid
local flat = redis.call('HGETALL', bkey)
local underflowed = 0
for i = 1, #flat, 2 do
    local addr = flat[i]
    local d = tonumber(flat[i + 1]) or 0
    if d ~= 0 then
        local rem = tonumber(redis.call('HINCRBYFLOAT', KEYS[2], addr, -d))
        if rem then
            if rem < -1e-9 then
                underflowed = underflowed + 1
            end
            if rem < 1e-9 then
                redis.call('HDEL', KEYS[2], addr)
            end
        end
    end
end
redis.call('DEL', bkey)
redis.call('ZREM', KEYS[1], bid)
return {1, underflowed}
"#;

/// One consistent read of what a block covers: the payout aggregate, the
/// reject aggregate, the shares-since-block counter and the round generation.
/// `KEYS` = those four.
const READ_ROUND_AT_FIND_LUA: &str = r#"
return {
    redis.call('HGETALL', KEYS[1]),
    redis.call('HGETALL', KEYS[2]),
    redis.call('GET', KEYS[3]) or '0',
    redis.call('GET', KEYS[4]) or '0'
}
"#;

/// Take one block's found-time state out of the group, once per block hash.
/// `KEYS` = settled-blocks, by-address, rejected-shares, shares-since-block,
/// round-generation; `ARGV` = block hash, counter at the find, subtract-round
/// flag, round generation at the find, then `n` and `n` (address, diff) pairs
/// of round shares, then `m` and `m` pairs of rejects. The round is left
/// alone when a calendar reset came after the find. A remainder within float
/// noise of zero is removed, so a member removed since the find leaves
/// nothing behind.
const SETTLE_BLOCK_LUA: &str = r#"
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then
    return 0
end
local function spent(rem, d)
    return rem <= 1e-9 * math.max(1, math.abs(d))
end
local snap = tonumber(ARGV[2])
local left = tonumber(redis.call('INCRBYFLOAT', KEYS[4], -snap))
if spent(left, snap) then
    redis.call('DEL', KEYS[4])
end
local function subtract(key, at)
    local n = tonumber(ARGV[at])
    for j = 0, n - 1 do
        local addr = ARGV[at + 1 + 2 * j]
        local d = tonumber(ARGV[at + 2 + 2 * j])
        local rem = tonumber(redis.call('HINCRBYFLOAT', key, addr, -d))
        if spent(rem, d) then
            redis.call('HDEL', key, addr)
        end
    end
    return at + 1 + 2 * n
end
local same_round = (redis.call('GET', KEYS[5]) or '0') == ARGV[4]
if ARGV[3] == '1' and same_round then
    local next_at = subtract(KEYS[2], 5)
    subtract(KEYS[3], next_at)
end
redis.call('SADD', KEYS[1], ARGV[1])
return 1
"#;

/// Append one rejected share into its time bucket. `KEYS` = wrbuckets,
/// window:rejected, wrbucket:{bid}; `ARGV` = difficulty, address, bucket_id.
/// No dedup: rejects carry no share id and are never redelivered.
const RECORD_REJECT_WINDOWED_LUA: &str = r#"
redis.call('HINCRBYFLOAT', KEYS[3], ARGV[2], ARGV[1])
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[3])
redis.call('HINCRBYFLOAT', KEYS[2], ARGV[2], ARGV[1])
return 1
"#;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RoundError {
    #[error("redis: {0}")]
    Redis(#[from] RedisError),
}

// ── BestShare ──────────────────────────────────────────────────────

/// A group's best share, stored as a Redis hash. It starts over only at the
/// group's own block, when `resetRoundOnBlock` is set, and when the group is
/// dissolved.
#[derive(Clone, Debug, PartialEq)]
pub struct BestShare {
    pub address: String,
    pub difficulty: f64,
    pub timestamp_ms: i64,
}

// ── What a found block covers ──────────────────────────────────────

/// The group's state when one of its blocks was found: what booking that
/// block takes out of the round, so the shares mined while it waits for its
/// confirmations stay. Parked with the block. Known limits, not handled at
/// the pool's size: a second block of the group found before the first is
/// booked covers the first one's stretch too; the state is read when `payout`
/// handles the block-found event, so shares still on the share stream then
/// fall on the wrong side of the cut; a member removed and re-added before
/// the booking loses their new shares up to their found-time amount.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RoundAtFind {
    /// Per-address payout shares (the round, or the trimmed window).
    pub payout_shares: HashMap<String, f64>,
    /// Per-address rejected shares over the same period.
    pub rejected: HashMap<String, f64>,
    /// [`key_shares_since_block`] at the find.
    pub shares_since_block: f64,
    /// [`key_round_generation`] at the find.
    pub round_generation: u64,
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

    /// Append one accepted share to the round; `Some(share_id)` makes it
    /// exactly-once. Returns `false` on a deduped no-op.
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
            .key(key_by_address(group_id))
            .key(key_last_accepted_share_at(group_id))
            .key(key_applied(group_id))
            .key(key_shares_since_block(group_id))
            .arg(difficulty.to_string())
            .arg(address)
            .arg(timestamp_ms)
            .arg(share_id.unwrap_or(""))
            .arg(DEDUP_KEEP)
            .invoke_async(&mut conn)
            .await?;

        Ok(applied == 1)
    }

    // ── Window mode: time-bucketed sliding-window record/trim/read ──

    /// Window-mode [`Self::record_share`], same dedup contract. Does NOT trim;
    /// the caller runs [`Self::trim_window`] on the share's timestamp.
    pub async fn record_share_windowed(
        &self,
        share_id: Option<&str>,
        group_id: &str,
        address: &str,
        difficulty: f64,
        timestamp_ms: i64,
    ) -> Result<bool, RoundError> {
        let mut conn = self.conn.clone();
        let bucket_id = timestamp_ms.div_euclid(WINDOW_BUCKET_MS);

        let applied: i64 = redis::Script::new(RECORD_SHARE_WINDOWED_LUA)
            .key(key_applied(group_id))
            .key(key_window_buckets(group_id))
            .key(key_window_by_address(group_id))
            .key(key_window_bucket(group_id, bucket_id))
            .key(key_last_accepted_share_at(group_id))
            .key(key_shares_since_block(group_id))
            .arg(difficulty.to_string())
            .arg(address)
            .arg(share_id.unwrap_or(""))
            .arg(DEDUP_KEEP)
            .arg(bucket_id)
            .arg(timestamp_ms)
            .invoke_async(&mut conn)
            .await?;

        Ok(applied == 1)
    }

    /// Drop every bucket older than `window_ms` in both lanes. One bucket per
    /// script call keeps each Redis-blocking script small yet atomic per bucket.
    pub async fn trim_window(
        &self,
        group_id: &str,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<(), RoundError> {
        if window_ms <= 0 {
            return Ok(());
        }
        let now_bucket = now_ms.div_euclid(WINDOW_BUCKET_MS);
        let window_buckets = (window_ms / WINDOW_BUCKET_MS).max(1);
        // Keep buckets in (cutoff, now_bucket], i.e. exactly `window_buckets` of them.
        let cutoff_bucket = now_bucket - window_buckets;

        let mut conn = self.conn.clone();
        let trim = redis::Script::new(TRIM_WINDOW_LUA);
        for lane in WindowLane::ALL {
            let prefix = lane.bucket_prefix(group_id);
            loop {
                let (dropped, underflowed): (i64, i64) = trim
                    .key(lane.index_key(group_id))
                    .key(lane.aggregate_key(group_id))
                    .arg(cutoff_bucket)
                    .arg(&prefix)
                    .invoke_async(&mut conn)
                    .await?;
                if underflowed > 0 {
                    warn!(
                        group_id,
                        lane = ?lane,
                        underflowed,
                        "group-solo window trim: the aggregate went negative for \
                         {underflowed} address(es) — bucket and aggregate disagree, which a \
                         per-key Redis restore can produce. Those entries were removed."
                    );
                }
                if dropped == 0 {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Read the current window aggregate (`addr → diff-1 sum`) for a
    /// `Window`-mode group. Does NOT trim — call [`Self::trim_window`] first
    /// (the dispatcher [`Self::read_payout_shares`] does both).
    pub async fn read_window_by_address(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, f64>, RoundError> {
        self.read_window_aggregate(WindowLane::Accepted, group_id)
            .await
    }

    /// Read the rejected-lane window aggregate (`addr → diff-1 sum` of
    /// rejects still inside the window). Does NOT trim, same as
    /// [`Self::read_window_by_address`].
    pub async fn read_window_rejected(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, f64>, RoundError> {
        self.read_window_aggregate(WindowLane::Rejected, group_id)
            .await
    }

    async fn read_window_aggregate(
        &self,
        lane: WindowLane,
        group_id: &str,
    ) -> Result<HashMap<String, f64>, RoundError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(lane.aggregate_key(group_id)).await?;
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

    /// Mode-aware payout read, the single chokepoint for every payout/audit/stats
    /// reader. `Window` trims first so even an idle group's distribution is
    /// current at read time.
    pub async fn read_payout_shares(
        &self,
        group_id: &str,
        mode: PayoutMode,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<HashMap<String, f64>, RoundError> {
        match mode {
            PayoutMode::Prop => self.read_by_address(group_id).await,
            PayoutMode::Window => {
                self.trim_window(group_id, now_ms, window_ms).await?;
                self.read_window_by_address(group_id).await
            }
        }
    }

    /// Per-time-bucket, per-address contribution across the live window, for
    /// the `/api/pplns/groups/:id/window-timeline` chart. Trims first so the
    /// timeline matches the payout window, and returns `(bucket_id, map)`
    /// oldest→newest (`bucket_id` = `timestamp_ms / WINDOW_BUCKET_MS`).
    pub async fn read_window_timeline(
        &self,
        group_id: &str,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<Vec<(i64, HashMap<String, f64>)>, RoundError> {
        self.trim_window(group_id, now_ms, window_ms).await?;
        let mut conn = self.conn.clone();
        let bucket_ids: Vec<i64> = conn.zrange(key_window_buckets(group_id), 0, -1).await?;
        if bucket_ids.is_empty() {
            return Ok(Vec::new());
        }
        // One HGETALL per live bucket, pipelined into a single round-trip.
        let mut pipe = redis::pipe();
        for bid in &bucket_ids {
            pipe.hgetall(key_window_bucket(group_id, *bid));
        }
        let raw: Vec<HashMap<String, String>> = pipe.query_async(&mut conn).await?;
        Ok(bucket_ids
            .into_iter()
            .zip(raw)
            .map(|(bid, hash)| {
                let map = hash
                    .into_iter()
                    .filter_map(|(addr, v)| {
                        let d: f64 = v.parse().ok()?;
                        (d > 0.0).then_some((addr, d))
                    })
                    .collect();
                (bid, map)
            })
            .collect())
    }

    /// Delete all `Window`-mode keys for a group (every live bucket via the
    /// index zset, plus the index and aggregate). Part of both reset paths so
    /// a dissolve or scheduled reset cleans window state too.
    async fn delete_window_keys(
        &self,
        conn: &mut ConnectionManager,
        group_id: &str,
    ) -> Result<(), RoundError> {
        let mut keys: Vec<String> = Vec::new();
        for lane in WindowLane::ALL {
            let bucket_ids: Vec<i64> = conn.zrange(lane.index_key(group_id), 0, -1).await?;
            keys.extend(bucket_ids.iter().map(|bid| lane.bucket_key(group_id, *bid)));
            keys.push(lane.index_key(group_id));
            keys.push(lane.aggregate_key(group_id));
        }
        let _: i64 = conn.del(keys).await?;
        Ok(())
    }

    /// Per-rejected-share counter for the address of a PROP group. `shares`
    /// is the diff-1-equivalent value the stratum layer reports per reject
    /// reason (typically 1.0). Wiped with the round by both reset paths.
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

    /// Append one rejected share into its time bucket for a `Window`-mode
    /// group (`RECORD_REJECT_WINDOWED_LUA`). Does NOT trim — the caller trims
    /// via [`Self::trim_window`], which sheds both lanes together.
    pub async fn record_reject_windowed(
        &self,
        group_id: &str,
        address: &str,
        shares: f64,
        timestamp_ms: i64,
    ) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let bucket_id = timestamp_ms.div_euclid(WINDOW_BUCKET_MS);
        let lane = WindowLane::Rejected;
        let _: i64 = redis::Script::new(RECORD_REJECT_WINDOWED_LUA)
            .key(lane.index_key(group_id))
            .key(lane.aggregate_key(group_id))
            .key(lane.bucket_key(group_id, bucket_id))
            .arg(shares.to_string())
            .arg(address)
            .arg(bucket_id)
            .invoke_async(&mut conn)
            .await?;
        Ok(())
    }

    // ── Best-share update (fire-and-forget improvement check) ─────

    /// Read the current best share. Returns `None` if no shares have
    /// been recorded for this round yet.
    /// Start the best share over, as a block of a `resetRoundOnBlock` group
    /// does when it is found, unless that block is booked already: a
    /// redelivered block-found event then leaves the best set since alone.
    pub async fn reset_best_share_for(
        &self,
        group_id: &str,
        block_hash: &str,
    ) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let booked: bool = conn
            .sismember(key_settled_blocks(group_id), block_hash)
            .await?;
        if !booked {
            let _: i64 = conn.del(key_best_share(group_id)).await?;
        }
        Ok(())
    }

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

    /// Replace the best share if `difficulty` strictly improves on it. Not a
    /// compare-and-swap: concurrent improvers race, which is only cosmetic.
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

    /// What a block found now covers: the group's state now, read in one
    /// step. A `Window` group is trimmed first, as its payout read is.
    pub async fn read_round_at_find(
        &self,
        group_id: &str,
        mode: PayoutMode,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<RoundAtFind, RoundError> {
        let (payout_key, rejected_key) = match mode {
            PayoutMode::Prop => (key_by_address(group_id), key_rejected_shares(group_id)),
            PayoutMode::Window => {
                self.trim_window(group_id, now_ms, window_ms).await?;
                (
                    WindowLane::Accepted.aggregate_key(group_id),
                    WindowLane::Rejected.aggregate_key(group_id),
                )
            }
        };
        let mut conn = self.conn.clone();
        let (payout, rejected, counter, generation): (
            HashMap<String, String>,
            HashMap<String, String>,
            String,
            String,
        ) = redis::Script::new(READ_ROUND_AT_FIND_LUA)
            .key(payout_key)
            .key(rejected_key)
            .key(key_shares_since_block(group_id))
            .key(key_round_generation(group_id))
            .invoke_async(&mut conn)
            .await?;
        let positive = |m: HashMap<String, String>| -> HashMap<String, f64> {
            m.into_iter()
                .filter_map(|(addr, v)| {
                    v.parse::<f64>()
                        .ok()
                        .filter(|d| *d > 0.0)
                        .map(|d| (addr, d))
                })
                .collect()
        };
        Ok(RoundAtFind {
            payout_shares: positive(payout),
            rejected: positive(rejected),
            shares_since_block: counter.parse().unwrap_or(0.0),
            round_generation: generation.parse().unwrap_or(0),
        })
    }

    /// Take a booked block's found-time state out of the group: always its
    /// share of the shares-since-block counter, the round and rejects when
    /// `subtract_round`. Keeps
    /// `last-accepted-share-at` (the inactivity clock survives) and
    /// `applied`, so an un-ACKed satellite batch is not reapplied. `false`
    /// when this block hash was already settled.
    pub async fn settle_block(
        &self,
        group_id: &str,
        block_hash: &str,
        at_find: &RoundAtFind,
        subtract_round: bool,
    ) -> Result<bool, RoundError> {
        let flag = |on: bool| if on { "1" } else { "0" };
        let script = redis::Script::new(SETTLE_BLOCK_LUA);
        let mut invocation = script.prepare_invoke();
        invocation
            .key(key_settled_blocks(group_id))
            .key(key_by_address(group_id))
            .key(key_rejected_shares(group_id))
            .key(key_shares_since_block(group_id))
            .key(key_round_generation(group_id))
            .arg(block_hash)
            .arg(at_find.shares_since_block.to_string())
            .arg(flag(subtract_round))
            .arg(at_find.round_generation);
        for map in [&at_find.payout_shares, &at_find.rejected] {
            let pairs: Vec<(&String, &f64)> = if subtract_round {
                map.iter().collect()
            } else {
                Vec::new()
            };
            invocation.arg(pairs.len());
            for (addr, d) in pairs {
                invocation.arg(addr).arg(d.to_string());
            }
        }
        let mut conn = self.conn.clone();
        let settled: i64 = invocation.invoke_async(&mut conn).await?;
        Ok(settled == 1)
    }

    /// Scheduled (calendar-aligned) reset: the round starts over, including
    /// `last-accepted-share-at`. The best share and the shares since the
    /// last block stay; only the group's own block takes them out (see
    /// [`Self::settle_block`]).
    pub async fn reset_for_calendar(&self, group_id: &str) -> Result<(), RoundError> {
        self.wipe_round(group_id, false).await
    }

    /// Everything the group holds here, its best share and shares since the
    /// last block included: for a dissolved group.
    pub async fn reset_full(&self, group_id: &str) -> Result<(), RoundError> {
        self.wipe_round(group_id, true).await
    }

    async fn wipe_round(&self, group_id: &str, dissolve: bool) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let mut keys = vec![
            key_by_address(group_id),
            key_rejected_shares(group_id),
            key_last_accepted_share_at(group_id),
            // NOT `key_applied`: an un-ACKed satellite batch would otherwise
            // be reapplied into the fresh round on redelivery.
        ];
        if dissolve {
            keys.push(key_best_share(group_id));
            keys.push(key_shares_since_block(group_id));
            keys.push(key_settled_blocks(group_id));
            keys.push(key_round_generation(group_id));
        }
        let mut wipe = redis::pipe();
        wipe.atomic().del(keys).ignore();
        if !dissolve {
            // In the same step as the wipe: a block parked across this reset
            // finds its round gone already and must not subtract from the new one.
            wipe.incr(key_round_generation(group_id), 1).ignore();
        }
        let _: () = wipe.query_async(&mut conn).await?;
        self.delete_window_keys(&mut conn, group_id).await?;
        Ok(())
    }

    // ── Reads ──────────────────────────────────────────────────────

    /// Hot read of per-address contribution from the `by-address` hash
    /// (O(distinct miners)), the authoritative round state; `record_share`
    /// maintains it on every accepted share.
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

    /// Σ diff-1 since the group's last block (see [`key_shares_since_block`]);
    /// 0 before its first share.
    pub async fn read_shares_since_block(&self, group_id: &str) -> Result<f64, RoundError> {
        let mut conn = self.conn.clone();
        let v: Option<String> = conn.get(key_shares_since_block(group_id)).await?;
        Ok(v.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0.0))
    }

    pub async fn read_rejected(&self, group_id: &str) -> Result<HashMap<String, f64>, RoundError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(key_rejected_shares(group_id)).await?;
        Ok(hash
            .into_iter()
            .filter_map(|(addr, v)| v.parse::<f64>().ok().map(|d| (addr, d)))
            .collect())
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

    /// Mode-aware view for `/api/pplns/groups/:groupId/round-stats`. Accepted
    /// and rejected always cover the same period (one round, or one trimmed
    /// window), so the reject rate compares like with like.
    pub async fn read_round_stats_for(
        &self,
        group_id: &str,
        mode: PayoutMode,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<RoundStats, RoundError> {
        let by_address = self
            .read_payout_shares(group_id, mode, now_ms, window_ms)
            .await?;
        let rejected_map = match mode {
            PayoutMode::Prop => self.read_rejected(group_id).await?,
            PayoutMode::Window => self.read_window_rejected(group_id).await?,
        };
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

    /// Remove the address's contribution (kick flow) and return the removed
    /// diff-1 amount. The caller passes the mode because this store has no
    /// group row; cleaning only the PROP keys would leave a Window member in
    /// the coinbase until their buckets age out.
    pub async fn forget_member(
        &self,
        group_id: &str,
        address: &str,
        mode: PayoutMode,
    ) -> Result<f64, RoundError> {
        let mut conn = self.conn.clone();

        let removed_diff = match mode {
            PayoutMode::Prop => {
                let removed_diff =
                    read_hash_f64(&mut conn, key_by_address(group_id), address).await?;
                // A plain pipeline suffices: admin flows are serialized at the
                // engine level, so nothing else mutates this address meanwhile.
                let mut pipe = redis::pipe();
                pipe.hdel(key_by_address(group_id), address)
                    .ignore()
                    .hdel(key_rejected_shares(group_id), address)
                    .ignore();
                pipe.query_async::<()>(&mut conn).await?;
                removed_diff
            }
            PayoutMode::Window => {
                let removed_diff = read_hash_f64(
                    &mut conn,
                    WindowLane::Accepted.aggregate_key(group_id),
                    address,
                )
                .await?;
                // Every live bucket of both lanes, then the aggregates, so a
                // later trim decrements nothing for this address.
                let mut pipe = redis::pipe();
                for lane in WindowLane::ALL {
                    let bucket_ids: Vec<i64> = conn.zrange(lane.index_key(group_id), 0, -1).await?;
                    for bid in bucket_ids {
                        pipe.hdel(lane.bucket_key(group_id, bid), address).ignore();
                    }
                    pipe.hdel(lane.aggregate_key(group_id), address).ignore();
                }
                pipe.query_async::<()>(&mut conn).await?;
                removed_diff
            }
        };

        // Inactivity clock, and the best share if it belongs to this address
        // (cosmetic, so read-then-DEL is enough).
        let _: i64 = conn
            .hdel(key_last_accepted_share_at(group_id), address)
            .await?;
        if let Some(best) = self.read_best_share(group_id).await? {
            if best.address == address {
                let _: i64 = conn.del(key_best_share(group_id)).await?;
            }
        }

        Ok(removed_diff)
    }
}

/// One `addr → diff` field of a hash as a finite, positive number, else 0.
async fn read_hash_f64(
    conn: &mut ConnectionManager,
    key: String,
    field: &str,
) -> Result<f64, RoundError> {
    Ok(conn
        .hget::<_, _, Option<String>>(key, field)
        .await?
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|d| d.is_finite() && *d > 0.0)
        .unwrap_or(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_helpers_format_correctly() {
        assert_eq!(key_by_address("g1"), "groupsolo:g1:by-address");
        assert_eq!(key_rejected_shares("g1"), "groupsolo:g1:rejected-shares");
        assert_eq!(
            key_last_accepted_share_at("g1"),
            "groupsolo:g1:last-accepted-share-at"
        );
        assert_eq!(key_best_share("g1"), "groupsolo:g1:best-share");
        assert_eq!(
            key_shares_since_block("g1"),
            "groupsolo:g1:shares-since-block"
        );
        assert_eq!(key_settled_blocks("g1"), "groupsolo:g1:settled-blocks");
    }

    #[test]
    fn window_key_helpers_format_correctly() {
        assert_eq!(key_window_buckets("g1"), "groupsolo:g1:wbuckets");
        assert_eq!(key_window_bucket("g1", 42), "groupsolo:g1:wbucket:42");
        assert_eq!(
            key_window_by_address("g1"),
            "groupsolo:g1:window:by-address"
        );
        // The trim-script prefix must reproduce the bucket key for any id.
        let prefix = WindowLane::Accepted.bucket_prefix("g1");
        assert_eq!(format!("{prefix}42"), key_window_bucket("g1", 42));
        let rejected = WindowLane::Rejected;
        assert_eq!(rejected.index_key("g1"), "groupsolo:g1:wrbuckets");
        assert_eq!(rejected.bucket_key("g1", 42), "groupsolo:g1:wrbucket:42");
        assert_eq!(rejected.aggregate_key("g1"), "groupsolo:g1:window:rejected");
        assert_eq!(
            format!("{}42", rejected.bucket_prefix("g1")),
            rejected.bucket_key("g1", 42)
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
