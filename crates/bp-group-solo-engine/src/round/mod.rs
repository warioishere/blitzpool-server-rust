// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-backed per-group round state.
//!
//! Key layout (`{groupId}` is the UUID of the `pplns_group` row):
//!
//! - `groupsolo:{groupId}:counter` — unused; the reset paths delete it so
//!   stale keys do not linger.
//! - `groupsolo:{groupId}:total` — float string, Σ diff in round
//! - `groupsolo:{groupId}:by-address` — hash `addr → diff` aggregate
//! - `groupsolo:{groupId}:rejected-shares` — hash `addr → diff` rejected
//!   (PROP only — a `Window` group buckets its rejects, see below)
//! - `groupsolo:{groupId}:last-accepted-share-at` — hash `addr → epoch_ms`
//! - `groupsolo:{groupId}:best-share` — hash `{address, difficulty, timestamp_ms}`
//! - `groupsolo:{groupId}:snapshot:{finder_address}` — see [`snapshot`]
//!
//! A `Prop`-mode group (the default) is a PROP round with no trim. A
//! `Window`-mode group instead keeps a time-bucketed sliding window
//! (`wbuckets` / `wbucket:{bid}` / `window:by-address`) that trims itself by
//! age and never block-resets — see the window-mode keys + Lua below. Its
//! rejects live in a second lane of the same shape (`wrbuckets` /
//! `wrbucket:{bid}` / `window:rejected`), trimmed by the same window, so the
//! round-stats view divides rejected by accepted work of the SAME period.
//! The reset paths clean both layouts.
//!
//! Two reset paths (`Window` groups skip the per-block gate entirely):
//!
//! `reset_for_block_found` wipes total, by-address, rejected-shares,
//! best-share and all per-finder snapshots, but keeps
//! `last-accepted-share-at` (the inactivity clock survives across blocks)
//! and `applied` (the dedup set, see [`key_applied`]).
//!
//! `reset_full` (scheduled cron reset) also wipes `last-accepted-share-at`,
//! but still keeps `applied` so an un-ACKed satellite batch is not
//! reapplied into the fresh round.

pub mod snapshot;

use std::collections::HashMap;

use bp_group_mgmt::group::PayoutMode;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use thiserror::Error;
use tracing::warn;

// ── Key helpers ─────────────────────────────────────────────────────

/// Produce the `groupsolo:{group_id}:{suffix}` key. `group_id` is usually
/// the `pplns_group` row's UUID; no shape is imposed so tests and admin
/// tooling can use a sentinel.
fn key(group_id: &str, suffix: &str) -> String {
    format!("groupsolo:{group_id}:{suffix}")
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
/// Dedup zset `share_id → timestamp_ms` for exactly-once `record_share`,
/// per group. Capped to the newest `DEDUP_KEEP` ids by rank.
///
/// Scored by the share's own accept time: the score only orders the trim,
/// and a timestamp stays monotonic across round resets, so this set can
/// survive them (like PPLNS's `pplns:applied`). A dispatched but un-ACKed
/// satellite batch is then still deduped after a reset.
///
/// Slight disorder between producers is harmless at a 100 000-deep horizon.
pub fn key_applied(group_id: &str) -> String {
    key(group_id, "applied")
}

// ── Window-mode keys (PayoutMode::Window only) ──────────────────────
//
// A `Window`-mode group keeps its payout distribution in a sliding TIME
// window instead of a PROP round: time-bucketed (bucket id =
// `floor(now_ms / WINDOW_BUCKET_MS)`), trimmed by age, all under the
// `groupsolo:{id}:` prefix so backup/restore (SCAN MATCH `groupsolo:*`)
// covers it. Two lanes of identical shape:
//
// - `groupsolo:{id}:wbuckets` — zset, score = member = bucket id (FIFO by time)
// - `groupsolo:{id}:wbucket:{bid}` — hash `addr → Σdiff` for that time bucket
// - `groupsolo:{id}:window:by-address` — hash `addr → Σdiff`, the AUTHORITATIVE
//   window aggregate, maintained lock-step with the buckets in Lua
//
// and, for rejected work, `wrbuckets` / `wrbucket:{bid}` / `window:rejected`.
// The rejected lane feeds only the round-stats view, never a payout. It is
// trimmed by the same window so the reject rate compares one period with
// itself.
//
// `applied` (the dedup set) is shared with the PROP layout, so the
// exactly-once contract is identical across modes.

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

/// Atomic, optionally-idempotent append of one accepted Group-Solo share.
/// Round state is the per-address aggregate only (PROP needs sums, not
/// individual shares). `KEYS[1]`=total, `[2]`=by-address,
/// `[3]`=last-accepted-share-at, `[4]`=applied. `ARGV[1]`=difficulty (string),
/// `[2]`=address, `[3]`=timestamp_ms (string),
/// `[4]`=share_id (empty ⇒ no dedup), `[5]`=keep-count. With a `share_id`, a
/// redelivered share is a no-op and the marker is recorded in the same
/// script, so a consumer crash between apply and ack cannot double-count.
/// Returns 1 on append, 0 on a deduped no-op.
///
/// `timestamp_ms` is both the `last-accepted-share-at` value and the dedup
/// marker's score (see [`key_applied`]).
const RECORD_SHARE_LUA: &str = r#"
local has_dedup = ARGV[4] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[4], ARGV[4]) then
    return 0
end
redis.call('INCRBYFLOAT', KEYS[1], ARGV[1])
redis.call('HINCRBYFLOAT', KEYS[2], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[3], ARGV[2], ARGV[3])
if has_dedup then
    redis.call('ZADD', KEYS[4], ARGV[3], ARGV[4])
    redis.call('ZREMRANGEBYRANK', KEYS[4], 0, -tonumber(ARGV[5]) - 1)
end
return 1
"#;

/// Atomic, optionally-idempotent append of one accepted share into its TIME
/// bucket for a `Window`-mode group. `KEYS[1]`=applied (dedup zset),
/// `[2]`=wbuckets (index zset), `[3]`=window:by-address, `[4]`=wbucket:{bid},
/// `[5]`=last-accepted-share-at. `ARGV[1]`=difficulty (string), `[2]`=address,
/// `[3]`=share_id (empty ⇒ no dedup), `[4]`=dedup keep-count,
/// `[5]`=bucket_id,
/// `[6]`=timestamp_ms (also the dedup marker's score — see [`key_applied`]).
///
/// Bucket, window aggregate and index are updated indivisibly so a snapshot
/// taken mid-write cannot see a partial update. Same exactly-once contract
/// as `RECORD_SHARE_LUA`. Returns 1 on append, 0 on a deduped no-op.
const RECORD_SHARE_WINDOWED_LUA: &str = r#"
local has_dedup = ARGV[3] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[1], ARGV[3]) then
    return 0
end
redis.call('HINCRBYFLOAT', KEYS[4], ARGV[2], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[5], ARGV[5])
redis.call('HINCRBYFLOAT', KEYS[3], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[5], ARGV[2], ARGV[6])
if has_dedup then
    redis.call('ZADD', KEYS[1], ARGV[6], ARGV[3])
    redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -tonumber(ARGV[4]) - 1)
end
return 1
"#;

/// Drop the single oldest time bucket when it has aged out of the window.
/// `KEYS[1]`=wbuckets (index zset), `KEYS[2]`=window:by-address.
/// `ARGV[1]`=cutoff
/// bucket id (drop buckets with id ≤ cutoff), `ARGV[2]`=bucket-key prefix.
///
/// Decrements window:by-address by exactly the dropped bucket's per-address
/// contribution. Returns `{dropped, underflowed}`: `dropped` is 1 when a
/// bucket went and 0 when the oldest bucket is still within the window (or
/// none exist); the caller loops until it sees 0. Building the bucket key
/// inside the script is safe because Valkey runs single-instance, not cluster.
///
/// Near-zero AND negative remainders are `HDEL`ed, the same rule as the
/// PPLNS trim. A negative one means a bucket is ahead of the aggregate (the
/// per-key backup restores them from different instants); left in place it
/// would swallow the address's next shares. `underflowed` counts those
/// addresses so the skew is logged, not cleaned up silently.
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

/// Append one rejected share into its TIME bucket for a `Window`-mode group.
/// `KEYS[1]`=wrbuckets (index zset), `[2]`=window:rejected, `[3]`=wrbucket:{bid}.
/// `ARGV[1]`=difficulty (string), `[2]`=address, `[3]`=bucket_id.
///
/// No dedup (rejects carry no share id and are never redelivered) and no
/// `last-accepted` touch (a reject is not an accepted share).
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
    /// The whole append (total/by-address increments, the
    /// `last-accepted-share-at` touch, the dedup marker) runs as one Lua
    /// script (`RECORD_SHARE_LUA`). With `Some(share_id)` a redelivered
    /// share still in the dedup set is a no-op; `None` is the plain append
    /// for tests and admin tooling. No trim: a PROP round is wiped on
    /// block-found.
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

    // ── Window mode: time-bucketed sliding-window record/trim/read ──

    /// Append one accepted share into its time bucket for a `Window`-mode
    /// group, optionally exactly-once. The append runs as one indivisible Lua
    /// script (`RECORD_SHARE_WINDOWED_LUA`) with the same dedup contract as
    /// the PROP [`Self::record_share`]. Does NOT trim — the caller trims
    /// separately via [`Self::trim_window`] (on the same `now` as the share's
    /// timestamp). Returns `true` on a real append, `false` on a deduped no-op.
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

    /// Trim the sliding window: drop every time bucket older than
    /// `window_ms` relative to `now_ms`, in BOTH lanes (accepted and
    /// rejected — one window, one age). Idempotent — a no-op when the window
    /// is empty or all buckets are still fresh. One bucket per script call
    /// keeps each Redis-blocking script small while staying atomic per bucket.
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
        // Keep buckets in (cutoff, now_bucket]; drop ids ≤ cutoff. With a
        // 24-bucket window and now_bucket=N, that keeps N-23..=N (24 buckets).
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

    /// Mode-aware payout read, the single chokepoint every payout/audit/stats
    /// reader goes through so each sees the right distribution:
    ///
    /// - `Prop` → the per-round `by-address` aggregate ([`Self::read_by_address`]).
    /// - `Window` → trim to `[now_ms - window_ms, now_ms]` first (so even an
    ///   idle group's distribution is current at read time), then read the
    ///   window aggregate ([`Self::read_window_by_address`]).
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
    /// `true` when the record was replaced. Not a compare-and-swap: two
    /// concurrent improvers race and the last write wins, which is only a
    /// cosmetic display issue.
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

    /// Block-found reset: wipe round state but keep
    /// `last-accepted-share-at` (the inactivity clock survives). Caller
    /// drains snapshots separately via
    /// [`snapshot::delete_all_for_group`].
    pub async fn reset_for_block_found(&self, group_id: &str) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let keys = vec![
            key_total(group_id),
            key_by_address(group_id),
            key_rejected_shares(group_id),
            key_best_share(group_id),
            // `key_applied` (the dedup zset) is deliberately NOT here: a
            // satellite batch dispatched but not yet ACKed when the reset
            // lands would otherwise be reapplied into the fresh round on
            // redelivery. Its timestamp scores keep rank order across resets.
            // `key_counter` is unused and only cleared here.
            key_counter(group_id),
        ];
        let _: i64 = conn.del(keys).await?;
        // Window-mode keys are dynamic (one per live time bucket) — drop them
        // via the index zset. No-op for a PROP group (no window keys exist).
        self.delete_window_keys(&mut conn, group_id).await?;
        Ok(())
    }

    /// Scheduled (calendar-aligned) reset: wipe everything including
    /// `last-accepted-share-at`. Caller deletes the per-finder snapshots
    /// separately.
    pub async fn reset_full(&self, group_id: &str) -> Result<(), RoundError> {
        let mut conn = self.conn.clone();
        let keys = vec![
            key_total(group_id),
            key_by_address(group_id),
            key_rejected_shares(group_id),
            key_best_share(group_id),
            key_last_accepted_share_at(group_id),
            // NOT `key_applied`: see `reset_for_block_found`. The counter
            // key is unused and only cleared here.
            key_counter(group_id),
        ];
        let _: i64 = conn.del(keys).await?;
        // Window-mode keys (dynamic per-bucket) — drop them too so a dissolve
        // / scheduled full-wipe leaves no orphan window state behind.
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

    /// Mode-aware composed view for `/api/pplns/groups/:groupId/round-stats`.
    /// In `Window` mode both the per-address contribution and the rejected
    /// counters are the trimmed sliding window (the payout read below trims
    /// both lanes), so `rejected / (shares + rejected)` compares one period
    /// with itself. In `Prop` mode both are the round, wiped together.
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

    /// A `ConnectionManager` clone for snapshot writes/reads (multiplexed,
    /// cheap to clone).
    pub fn connection_for_snapshot(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// Subtract the address's contribution from the group (kick flow),
    /// mode-aware like [`Self::read_payout_shares`]: a PROP member leaves
    /// the round aggregate, a Window member leaves every live bucket of both
    /// lanes plus the two aggregates. Returns the diff-1-weighted amount
    /// removed from the payout source so the caller can log it; the rest of
    /// the group then splits proportionally between whoever is left.
    ///
    /// The mode comes from the caller because this store has no group row;
    /// cleaning only the PROP keys would leave a Window member in the
    /// coinbase until their buckets age out.
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
                if removed_diff > 0.0 {
                    pipe.cmd("INCRBYFLOAT")
                        .arg(key_total(group_id))
                        .arg(-removed_diff)
                        .ignore();
                }
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
    fn key_helpers_support_uuid_group_id() {
        let g = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            key_counter(g),
            "groupsolo:550e8400-e29b-41d4-a716-446655440000:counter"
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
