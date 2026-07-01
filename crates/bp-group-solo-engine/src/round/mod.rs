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
//! A `Prop`-mode group (the default) is a PROP round with no trim. A
//! `Window`-mode group instead keeps a time-bucketed sliding window
//! (`wbuckets` / `wbucket:{bid}` / `window:by-address`) that trims itself by
//! age and never block-resets — see the window-mode keys + Lua below. The
//! reset paths clean both layouts.
//!
//! Two reset paths exist (PROP semantics; `Window` groups skip the per-block
//! gate entirely):
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

use bp_group_mgmt::group::PayoutMode;
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

// ── Window-mode keys (PayoutMode::Window only) ──────────────────────
//
// A `Window`-mode group keeps its payout distribution in a sliding TIME
// window instead of a single PROP round. Layout mirrors the count-bucketed
// PPLNS window but is **time-bucketed** (bucket id = `floor(now_ms /
// WINDOW_BUCKET_MS)`) and trimmed by AGE, all under the per-group
// `groupsolo:{id}:` prefix so backup/restore (SCAN MATCH `groupsolo:*`)
// covers it automatically:
//
// - `groupsolo:{id}:wbuckets` — zset, score = member = bucket id (FIFO by time)
// - `groupsolo:{id}:wbucket:{bid}` — hash `addr → Σdiff` for that time bucket
// - `groupsolo:{id}:window:by-address` — hash `addr → Σdiff`, the AUTHORITATIVE
//   window aggregate, maintained lock-step with the buckets in Lua
//
// `counter` + `applied` (the dedup set) are reused from the PROP layout so the
// exactly-once contract is identical across modes.

/// Index zset of live time-bucket ids for a `Window`-mode group.
pub fn key_window_buckets(group_id: &str) -> String {
    key(group_id, "wbuckets")
}
/// Per-time-bucket `addr → Σdiff` hash key for bucket `bid`.
pub fn key_window_bucket(group_id: &str, bid: i64) -> String {
    key(group_id, &format!("wbucket:{bid}"))
}
/// Authoritative `addr → Σdiff` window aggregate for a `Window`-mode group.
pub fn key_window_by_address(group_id: &str) -> String {
    key(group_id, "window:by-address")
}

/// Bucket-key prefix passed to the trim script so it can build
/// `groupsolo:{id}:wbucket:{bid}` for each dropped bucket inside Lua.
fn window_bucket_prefix(group_id: &str) -> String {
    format!("groupsolo:{group_id}:wbucket:")
}

/// Time-bucket granularity for the sliding window: 1 hour. A 1-day window is
/// 24 buckets, a 30-day window 720 — storage is O(buckets × miners), not
/// O(shares). Fixed constant (not config) so the bucket math is stable across
/// a window-length change; the bound is enforced by being a `const`.
pub const WINDOW_BUCKET_MS: i64 = 60 * 60 * 1000;

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

/// Atomic, optionally-idempotent append of one accepted share into its TIME
/// bucket for a `Window`-mode group. KEYS[1]=counter, [2]=applied (dedup zset),
/// [3]=wbuckets (index zset), [4]=window:by-address, [5]=wbucket:{bid},
/// [6]=last-accepted-share-at. ARGV[1]=difficulty (string), [2]=address,
/// [3]=share_id (empty ⇒ no dedup), [4]=dedup keep-count, [5]=bucket_id,
/// [6]=timestamp_ms.
///
/// Aggregates the share into its time bucket + the window aggregate +
/// registers the bucket in the index zset, all indivisibly so a snapshot taken
/// mid-write can't see a partial update. Same exactly-once contract as the PROP
/// `RECORD_SHARE_LUA`: with a `share_id`, a redelivered share is a deduped
/// no-op. Returns 1 on append, 0 on a deduped no-op.
const RECORD_SHARE_WINDOWED_LUA: &str = r#"
local has_dedup = ARGV[3] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[2], ARGV[3]) then
    return 0
end
local counter = redis.call('INCR', KEYS[1])
redis.call('HINCRBYFLOAT', KEYS[5], ARGV[2], ARGV[1])
redis.call('ZADD', KEYS[3], ARGV[5], ARGV[5])
redis.call('HINCRBYFLOAT', KEYS[4], ARGV[2], ARGV[1])
redis.call('HSET', KEYS[6], ARGV[2], ARGV[6])
if has_dedup then
    redis.call('ZADD', KEYS[2], counter, ARGV[3])
    redis.call('ZREMRANGEBYRANK', KEYS[2], 0, -tonumber(ARGV[4]) - 1)
end
return 1
"#;

/// Drop the single oldest time bucket when it has aged out of the window.
/// KEYS[1]=wbuckets (index zset), KEYS[2]=window:by-address. ARGV[1]=cutoff
/// bucket id (drop buckets with id ≤ cutoff), ARGV[2]=bucket-key prefix.
///
/// Decrements window:by-address by exactly the dropped bucket's per-address
/// contribution, hDel-ing any address that hits ~0 so the aggregate doesn't
/// retain dead zero-fields. Returns 1 when a bucket was dropped, 0 when the
/// oldest bucket is still within the window (or none exist) — the caller loops
/// until it sees 0. Single-instance Valkey (not cluster), so building the
/// bucket key from a prefix inside the script is safe.
const TRIM_WINDOW_LUA: &str = r#"
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0)
if #oldest < 1 then return 0 end
local bid = oldest[1]
if tonumber(bid) > tonumber(ARGV[1]) then return 0 end
local bkey = ARGV[2] .. bid
local flat = redis.call('HGETALL', bkey)
for i = 1, #flat, 2 do
    local addr = flat[i]
    local d = tonumber(flat[i + 1]) or 0
    if d ~= 0 then
        local rem = tonumber(redis.call('HINCRBYFLOAT', KEYS[2], addr, -d))
        if rem and math.abs(rem) < 1e-9 then
            redis.call('HDEL', KEYS[2], addr)
        end
    end
end
redis.call('DEL', bkey)
redis.call('ZREM', KEYS[1], bid)
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

    // ── Window mode: time-bucketed sliding-window record/trim/read ──

    /// Append one accepted share into its time bucket for a `Window`-mode
    /// group, optionally exactly-once. The append runs as one indivisible Lua
    /// script ([`RECORD_SHARE_WINDOWED_LUA`]) with the same dedup contract as
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
            .key(key_counter(group_id))
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
    /// `window_ms` relative to `now_ms`. Idempotent — a no-op when the window
    /// is empty or all buckets are still fresh. Loops one bucket per script
    /// call (like the PPLNS window) so any single Redis-blocking script stays
    /// small while keeping per-bucket atomicity.
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
        let prefix = window_bucket_prefix(group_id);

        let mut conn = self.conn.clone();
        let trim = redis::Script::new(TRIM_WINDOW_LUA);
        loop {
            let dropped: i64 = trim
                .key(key_window_buckets(group_id))
                .key(key_window_by_address(group_id))
                .arg(cutoff_bucket)
                .arg(&prefix)
                .invoke_async(&mut conn)
                .await?;
            if dropped == 0 {
                break;
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
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(key_window_by_address(group_id)).await?;
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

    /// Mode-aware payout read — the single chokepoint every payout/audit/stats
    /// reader funnels through so it automatically sees the right distribution:
    ///
    /// - `Prop` → the per-round `by-address` aggregate ([`Self::read_by_address`]).
    /// - `Window` → trim the window to `[now_ms - window_ms, now_ms]` first
    ///   (so even an idle group's distribution is fenster-current at read time)
    ///   then read the window aggregate ([`Self::read_window_by_address`]).
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

    /// Per-time-bucket, per-address contribution across the live window —
    /// drives the `/api/pplns/groups/:id/window-timeline` chart. Trims first
    /// (so the timeline matches the payout window), reads every remaining
    /// bucket's `addr → diff` hash in a single pipelined round-trip, and
    /// returns `(bucket_id, map)` oldest→newest (`bucket_id` is hours-since-
    /// epoch, i.e. `timestamp_ms / WINDOW_BUCKET_MS`). Empty when the window
    /// has no live buckets.
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

    /// Delete all `Window`-mode keys for a group (every live time bucket via
    /// the index zset, plus the index zset + window aggregate). Folded into the
    /// reset paths so a dissolve / scheduled-reset cleans window state too,
    /// even though `Window` groups never hit the per-block reset gate.
    async fn delete_window_keys(
        &self,
        conn: &mut ConnectionManager,
        group_id: &str,
    ) -> Result<(), RoundError> {
        let bucket_ids: Vec<i64> = conn.zrange(key_window_buckets(group_id), 0, -1).await?;
        let mut keys: Vec<String> = bucket_ids
            .iter()
            .map(|bid| key_window_bucket(group_id, *bid))
            .collect();
        keys.push(key_window_buckets(group_id));
        keys.push(key_window_by_address(group_id));
        let _: i64 = conn.del(keys).await?;
        Ok(())
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
        // Window-mode keys are dynamic (one per live time bucket) — drop them
        // via the index zset. No-op for a PROP group (no window keys exist).
        self.delete_window_keys(&mut conn, group_id).await?;
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
        // Window-mode keys (dynamic per-bucket) — drop them too so a dissolve
        // / scheduled full-wipe leaves no orphan window state behind.
        self.delete_window_keys(&mut conn, group_id).await?;
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
    /// PROP-only convenience — equivalent to [`Self::read_round_stats_for`]
    /// with [`PayoutMode::Prop`]. Retained for callers/tests that don't carry
    /// a mode (a PROP group's window args are irrelevant).
    pub async fn read_round_stats(&self, group_id: &str) -> Result<RoundStats, RoundError> {
        self.read_round_stats_for(group_id, PayoutMode::Prop, 0, 0)
            .await
    }

    /// Mode-aware composed view for `/api/pplns/groups/:groupId/round-stats`.
    /// In `Window` mode the per-address contribution is the trimmed sliding
    /// window; the rejected counters stay a plain running tally (they don't
    /// feed payouts and there is no round to reset them against).
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
    fn window_key_helpers_format_correctly() {
        assert_eq!(key_window_buckets("g1"), "groupsolo:g1:wbuckets");
        assert_eq!(key_window_bucket("g1", 42), "groupsolo:g1:wbucket:42");
        assert_eq!(
            key_window_by_address("g1"),
            "groupsolo:g1:window:by-address"
        );
        // The trim-script prefix must reproduce the bucket key for any id.
        let prefix = window_bucket_prefix("g1");
        assert_eq!(format!("{prefix}42"), key_window_bucket("g1", 42));
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
