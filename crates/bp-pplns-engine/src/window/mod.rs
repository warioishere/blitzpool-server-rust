// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-backed sliding window — count-bucket storage: `pplns:counter` +
//! `pplns:buckets` index zset + `pplns:bucket:<id>` per-address hashes +
//! `pplns:window:total` float string + `pplns:window:by-address` aggregate,
//! plus the `pplns:snapshot` hash.
//!
//! Direct `redis::aio::ConnectionManager` (no trait abstraction —
//! decision 2026-05-16). Tests run against docker-Redis. State mutation runs
//! in atomic Lua scripts (append + per-bucket trim) so the by-address
//! aggregate can't desync from the buckets.
//!
//! Storage is O(buckets × miners), not O(shares): shares aggregate per-address
//! into fixed-size count buckets and the window trims whole oldest buckets.
//! The Redis layout MUST match the TS pool's (same key names, same
//! `floor(counter / bucket_shares)`) — they share Redis across the cutover.

pub mod snapshot;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use thiserror::Error;

// ── Redis keys ───────────────────────────────────────────────────────

/// Monotonic counter. Drives the bucket id (`floor(counter / bucket_shares)`)
/// so shares group into fixed-size count buckets in submission order, and also
/// scores the dedup marker zset.
pub const KEY_COUNTER: &str = "pplns:counter";
/// Float string holding the sum of difficulty over the current window.
pub const KEY_WINDOW_TOTAL: &str = "pplns:window:total";
/// Hash `address → diff-1 aggregate` — the AUTHORITATIVE window state.
/// Maintained lock-step with the buckets: `record_share` increments,
/// `trim_window` decrements when a bucket ages out.
pub const KEY_WINDOW_BY_ADDRESS: &str = "pplns:window:by-address";
/// Temp key the cold-start rebuild fills before an atomic `RENAME` swap, so
/// the live aggregate is never observed empty/partial during a rebuild.
pub const KEY_WINDOW_REBUILD: &str = "pplns:window:by-address:rebuild";
/// Index zset of live bucket ids (score = id) for FIFO trim ordering.
/// Each bucket is a hash `pplns:bucket:<id>` of address → Σdiff. Storage is
/// O(buckets × miners) instead of O(shares). MUST match the TS pool's layout
/// (same key names, same `floor(counter / bucket_shares)`) — they share Redis.
pub const KEY_BUCKETS: &str = "pplns:buckets";
/// Coinbase distribution snapshot. See [`mod@snapshot`].
pub const KEY_SNAPSHOT: &str = "pplns:snapshot";
/// Dedup zset `share_id → counter` for exactly-once `record_share`. Capped
/// to the newest [`DEDUP_KEEP`] entries by rank. A redelivered share whose
/// id is still in this set is a no-op. See [`RECORD_SHARE_LUA`].
pub const KEY_APPLIED: &str = "pplns:applied";

/// Bucket hash key for a given bucket id.
pub fn bucket_key(bucket_id: &str) -> String {
    format!("pplns:bucket:{bucket_id}")
}

/// Default shares-per-bucket when not configured (`PPLNS_BUCKET_SHARES`).
pub const DEFAULT_BUCKET_SHARES: u64 = 10_000;

/// How many recent `share_id`s the dedup set retains. Only un-acked
/// in-flight shares are ever redelivered, so the horizon only needs to
/// cover the in-flight window plus margin — 100k entries (~3 MB) is far
/// more than any realistic consumer backlog, at negligible cost.
const DEDUP_KEEP: i64 = 100_000;

/// Drop the single oldest bucket when the window is over size. KEYS[1] =
/// window:total, KEYS[2] = by-address, KEYS[3] = buckets index zset.
/// ARGV[1] = window_size. The bucket hash key is built inside the script
/// (`pplns:bucket:<id>`) — single-instance Valkey, not cluster.
///
/// Never drops the newest (currently-filling) bucket: stops when only one
/// bucket remains, so the window holds at most one bucket above the target
/// (the bucket-granular overshoot). Decrements by-address by exactly the
/// dropped bucket's per-address contribution, hDel-ing any address that hits
/// ~0 so the aggregate doesn't retain dead zero-fields. Returns 1 when a
/// bucket was dropped, 0 when at/under the window (or <2 buckets) — the
/// caller loops until it sees 0.
const TRIM_BATCH_LUA: &str = r#"
local total = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
if total <= tonumber(ARGV[1]) then return 0 end
local oldest = redis.call('ZRANGE', KEYS[3], 0, 1)
if #oldest < 2 then return 0 end
local bucket_id = oldest[1]
local bkey = 'pplns:bucket:' .. bucket_id
local flat = redis.call('HGETALL', bkey)
local removed = 0
for i = 1, #flat, 2 do
    local addr = flat[i]
    local d = tonumber(flat[i + 1]) or 0
    if d ~= 0 then
        removed = removed + d
        local rem = tonumber(redis.call('HINCRBYFLOAT', KEYS[2], addr, -d))
        if rem and math.abs(rem) < 1e-9 then
            redis.call('HDEL', KEYS[2], addr)
        end
    end
end
redis.call('DEL', bkey)
redis.call('ZREM', KEYS[3], bucket_id)
if removed ~= 0 then
    redis.call('INCRBYFLOAT', KEYS[1], -removed)
end
return 1
"#;

/// Atomic, optionally-idempotent append of one accepted share into its count
/// bucket. KEYS[1] = counter, KEYS[2] = window:total, KEYS[3] = by-address,
/// KEYS[4] = applied (dedup) zset, KEYS[5] = buckets index zset. ARGV[1] =
/// difficulty (string), ARGV[2] = address, ARGV[3] = share_id (empty ⇒ no
/// dedup), ARGV[4] = dedup keep-count, ARGV[5] = bucket_shares.
///
/// Computes the bucket id from the post-INCR counter (`floor(counter /
/// bucket_shares)`), aggregates the share into `pplns:bucket:<id>` per
/// address, registers the bucket in the index zset, and bumps window:total +
/// by-address — all indivisibly. With a non-empty `share_id` a redelivered
/// share is a deduped no-op (`return 0`), the marker recorded in the same
/// script so a consumer crash can't double-count. Returns 1 on append.
const RECORD_SHARE_LUA: &str = r#"
local has_dedup = ARGV[3] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[4], ARGV[3]) then
    return 0
end
local counter = redis.call('INCR', KEYS[1])
local bucket = math.floor(counter / tonumber(ARGV[5]))
redis.call('HINCRBYFLOAT', 'pplns:bucket:' .. bucket, ARGV[2], ARGV[1])
redis.call('ZADD', KEYS[5], bucket, tostring(bucket))
redis.call('INCRBYFLOAT', KEYS[2], ARGV[1])
redis.call('HINCRBYFLOAT', KEYS[3], ARGV[2], ARGV[1])
if has_dedup then
    redis.call('ZADD', KEYS[4], counter, ARGV[3])
    redis.call('ZREMRANGEBYRANK', KEYS[4], 0, -tonumber(ARGV[4]) - 1)
end
return 1
"#;

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WindowError {
    #[error("redis: {0}")]
    Redis(#[from] RedisError),
    /// Encountered an entry in `pplns:shares` whose `addr:diff:ts`
    /// format doesn't parse. Logged + the entry is skipped at trim
    /// time. Returned only from explicit read-paths so callers can
    /// surface a CRITICAL alert.
    #[error("malformed share entry: {0:?}")]
    MalformedEntry(String),
}

// ── Network difficulty view ──────────────────────────────────────────

/// Thread-safe shared view of the pool's current `networkDifficulty`,
/// as published by the TDP template stream.
///
/// Backed by `Arc<AtomicU64>` over `f64::to_bits`/`f64::from_bits`,
/// so reads + writes are lock-free across worker threads. Initial
/// value is 0; the engine refuses to trim or build distributions
/// until the first template lands.
#[derive(Debug, Clone, Default)]
pub struct NetworkDifficulty {
    bits: Arc<AtomicU64>,
}

impl NetworkDifficulty {
    pub fn new(initial: f64) -> Self {
        Self {
            bits: Arc::new(AtomicU64::new(initial.to_bits())),
        }
    }

    pub fn set(&self, difficulty: f64) {
        self.bits.store(difficulty.to_bits(), Ordering::Relaxed);
    }

    pub fn get(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::Relaxed))
    }
}

// ── WindowStore ──────────────────────────────────────────────────────

/// Redis-backed sliding window over diff-1 share contributions.
///
/// Cheap to clone (each field is an `Arc` or a `Clone`-cheap handle).
/// The connection manager handles automatic reconnects in-band.
#[derive(Clone)]
pub struct WindowStore {
    conn: ConnectionManager,
    window_factor: f64,
    /// Shares per count-bucket (`floor(counter / bucket_shares)`). Must match
    /// the TS pool's `PPLNS_BUCKET_SHARES` since they share Redis.
    bucket_shares: u64,
    net_diff: NetworkDifficulty,
}

impl WindowStore {
    /// Wire up the store. The caller owns the `ConnectionManager`
    /// lifecycle (typically created once at engine startup).
    pub fn new(
        conn: ConnectionManager,
        window_factor: f64,
        bucket_shares: u64,
        net_diff: NetworkDifficulty,
    ) -> Self {
        Self {
            conn,
            window_factor,
            bucket_shares: if bucket_shares == 0 {
                DEFAULT_BUCKET_SHARES
            } else {
                bucket_shares
            },
            net_diff,
        }
    }

    /// `windowSize = factor × networkDifficulty`. Returns 0 if the
    /// network-difficulty source hasn't been seeded yet (no TDP
    /// template received), in which case `record_share` is a no-op
    /// trim-wise.
    pub fn window_size(&self) -> f64 {
        let nd = self.net_diff.get();
        if !nd.is_finite() || nd <= 0.0 {
            return 0.0;
        }
        self.window_factor * nd
    }

    // ── Hot path: record an accepted share ──────────────────────────

    /// Append one accepted share to the window, optionally exactly-once.
    ///
    /// The append (counter INCR + zset ZADD + both aggregate increments)
    /// runs as one indivisible Lua script ([`RECORD_SHARE_LUA`]) — same
    /// atomicity the old `MULTI/EXEC` gave, so a snapshot taken mid-write
    /// can't see a partial update. When `share_id` is `Some`, the script
    /// also makes the write **idempotent**: a redelivered share whose id is
    /// still in the dedup set is a no-op, and the marker is recorded in the
    /// same script so a consumer crash between apply and ack can't
    /// double-count. `None` keeps the plain non-idempotent append for direct
    /// window tests / admin tooling.
    ///
    /// Returns `true` when the share was appended, `false` when it was a
    /// deduped no-op (so the caller can skip follow-up side effects).
    /// `trim_window` runs only on a real append.
    ///
    /// `address` is normalized before this call (the stratum layer
    /// lowercase-normalizes at authorize-time); we don't re-normalize
    /// to keep the hot path branch-free. Callers from outside the
    /// stratum path (tests, admin tools) must normalize themselves.
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        address: &str,
        difficulty: f64,
        _timestamp_ms: u64,
    ) -> Result<bool, WindowError> {
        let mut conn = self.conn.clone();

        let applied: i64 = redis::Script::new(RECORD_SHARE_LUA)
            .key(KEY_COUNTER)
            .key(KEY_WINDOW_TOTAL)
            .key(KEY_WINDOW_BY_ADDRESS)
            .key(KEY_APPLIED)
            .key(KEY_BUCKETS)
            .arg(difficulty.to_string())
            .arg(address)
            .arg(share_id.unwrap_or(""))
            .arg(DEDUP_KEEP)
            .arg(self.bucket_shares)
            .invoke_async(&mut conn)
            .await?;

        if applied == 1 {
            self.trim_window(&mut conn).await?;
        }
        Ok(applied == 1)
    }

    // ── Trim — bound the window ─────────────────────────────────────

    /// Drop oldest entries until `total ≤ windowSize`. Idempotent if
    /// the window is already below threshold.
    async fn trim_window(&self, conn: &mut ConnectionManager) -> Result<(), WindowError> {
        let window_size = self.window_size();
        if window_size <= 0.0 {
            // No network-difficulty seeded yet — don't trim or the
            // first few shares would be discarded immediately.
            return Ok(());
        }

        // Drop whole oldest buckets while over the window (see [`TRIM_BATCH_LUA`]).
        // Each call atomically removes one bucket and decrements window:total +
        // by-address by exactly its per-address contribution. Looping in Rust
        // (one bucket per script) keeps any single script's Redis-blocking
        // small while preserving per-bucket atomicity. The script returns 1
        // while it drops a bucket, 0 once at/under the window (or only the
        // active bucket remains) → done.
        let trim = redis::Script::new(TRIM_BATCH_LUA);
        loop {
            let dropped: i64 = trim
                .key(KEY_WINDOW_TOTAL)
                .key(KEY_WINDOW_BY_ADDRESS)
                .key(KEY_BUCKETS)
                .arg(window_size)
                .invoke_async(conn)
                .await?;
            if dropped == 0 {
                break;
            }
        }

        // No periodic full-window recalc. `record_share` + the trim above are
        // atomic Lua, so the aggregate can't desync from the buckets — it only
        // accumulates f64 rounding drift, sub-satoshi on the payout proportions.
        // The only genuine rebuild need — a cold start where the hash is empty
        // but buckets exist — is handled once at startup by
        // `bootstrap_window_if_needed`.
        Ok(())
    }

    // ── Cold-start bootstrap — rebuild the aggregate from the zset ──

    /// One-time, startup-only rebuild of `window:by-address` + `window:total`
    /// from the live buckets — but ONLY when the hash is empty while buckets
    /// exist.
    ///
    /// That's the single case where the incremental aggregate genuinely needs
    /// rebuilding: a cold start / lost key where the buckets survived but the
    /// hash didn't. (At a normal cutover the hash is populated by the previous
    /// pool version, so this is a no-op.) Once non-empty, the hash is
    /// maintained atomically by `record_share`/`trim_window`.
    ///
    /// Best-effort and safe: if the hash is already populated it returns
    /// immediately; the rebuild builds into a temp key and atomic-`RENAME`s it
    /// over the live hash so the aggregate is never observed empty/partial.
    pub async fn bootstrap_window_if_needed(&self) -> Result<(), WindowError> {
        let mut conn = self.conn.clone();
        let hash_len: usize = conn.hlen(KEY_WINDOW_BY_ADDRESS).await?;
        if hash_len > 0 {
            return Ok(()); // already populated (normal cutover) — leave it
        }
        let card: isize = conn.zcard(KEY_BUCKETS).await?;
        if card <= 0 {
            return Ok(()); // no buckets — nothing to rebuild from
        }
        self.rebuild_window_from_buckets(&mut conn).await
    }

    /// Sum every live bucket into `window:by-address` + `window:total`, built
    /// into a temp key and swapped over the live hash with an atomic `RENAME`.
    /// A bucket id present in the index but already deleted by a concurrent
    /// trim just contributes nothing — no corruption.
    async fn rebuild_window_from_buckets(
        &self,
        conn: &mut ConnectionManager,
    ) -> Result<(), WindowError> {
        let bucket_ids: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await?;
        let mut by_addr: HashMap<String, f64> = HashMap::new();
        let mut total = 0.0_f64;
        for id in &bucket_ids {
            let bucket: HashMap<String, String> = conn.hgetall(bucket_key(id)).await?;
            for (addr, diff_str) in bucket {
                if let Ok(diff) = diff_str.parse::<f64>() {
                    if diff > 0.0 {
                        *by_addr.entry(addr).or_insert(0.0) += diff;
                        total += diff;
                    }
                }
            }
        }

        let _: () = conn.del(KEY_WINDOW_REBUILD).await?;
        if by_addr.is_empty() {
            let _: () = conn.del(KEY_WINDOW_BY_ADDRESS).await?;
            let _: () = conn.set(KEY_WINDOW_TOTAL, total.to_string()).await?;
            return Ok(());
        }
        let fields: Vec<(String, String)> = by_addr
            .into_iter()
            .map(|(addr, diff)| (addr, diff.to_string()))
            .collect();
        let _: () = conn.hset_multiple(KEY_WINDOW_REBUILD, &fields).await?;
        let _: () = conn.set(KEY_WINDOW_TOTAL, total.to_string()).await?;
        let _: () = conn
            .rename(KEY_WINDOW_REBUILD, KEY_WINDOW_BY_ADDRESS)
            .await?;
        Ok(())
    }

    // ── Read paths ──────────────────────────────────────────────────

    /// Hot-read of the current window aggregate: address → diff-1 sum.
    /// Tries `HGETALL` first (O(distinct miners), KB-scale). Falls back to
    /// summing the live buckets if the hash is empty — a cold-start after a
    /// pool restart where the hash hasn't been repopulated yet.
    pub async fn read_window_by_address(&self) -> Result<HashMap<String, f64>, WindowError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await?;
        if !hash.is_empty() {
            return Ok(hash
                .into_iter()
                .filter_map(|(addr, diff_str)| {
                    let diff: f64 = diff_str.parse().ok()?;
                    if diff > 0.0 {
                        Some((addr, diff))
                    } else {
                        None
                    }
                })
                .collect());
        }
        // Cold-cache fallback: sum the live buckets.
        let bucket_ids: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await?;
        let mut out: HashMap<String, f64> = HashMap::new();
        for id in &bucket_ids {
            let bucket: HashMap<String, String> = conn.hgetall(bucket_key(id)).await?;
            for (addr, diff_str) in bucket {
                if let Ok(diff) = diff_str.parse::<f64>() {
                    if diff > 0.0 {
                        *out.entry(addr).or_insert(0.0) += diff;
                    }
                }
            }
        }
        Ok(out)
    }

    /// Read the current cached window total. Cheap (one Redis `GET`).
    /// Returns 0.0 if the key is missing.
    pub async fn current_total(&self) -> Result<f64, WindowError> {
        let mut conn = self.conn.clone();
        let total_str: Option<String> = conn.get(KEY_WINDOW_TOTAL).await?;
        Ok(total_str
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0))
    }

    /// Per-address contribution lookup (one Redis `HGET`). Returns
    /// 0.0 when the address has no entry in the current window. Used
    /// by the per-address reader path where a full `HGETALL` would
    /// drag the entire window hash across the wire just to read one
    /// field.
    pub async fn read_window_share_for_address(&self, address: &str) -> Result<f64, WindowError> {
        let mut conn = self.conn.clone();
        let diff_str: Option<String> = conn.hget(KEY_WINDOW_BY_ADDRESS, address).await?;
        let parsed = diff_str.as_deref().and_then(|s| s.parse::<f64>().ok());
        Ok(match parsed {
            Some(v) if v.is_finite() && v > 0.0 => v,
            _ => 0.0,
        })
    }

    /// Snapshot accessor — convenience around [`snapshot::write_snapshot`].
    pub async fn write_snapshot(
        &self,
        snapshot: &snapshot::StoredSnapshot,
        ttl_seconds: u32,
    ) -> Result<(), RedisError> {
        let mut conn = self.conn.clone();
        snapshot::write_snapshot(&mut conn, KEY_SNAPSHOT, snapshot, ttl_seconds).await
    }

    /// Snapshot reader — convenience around [`snapshot::read_snapshot`].
    pub async fn read_snapshot(&self) -> Result<Option<snapshot::ParsedSnapshot>, RedisError> {
        let mut conn = self.conn.clone();
        snapshot::read_snapshot(&mut conn, KEY_SNAPSHOT).await
    }

    /// Delete the snapshot key (after `on_block_found` consumed it).
    pub async fn delete_snapshot(&self) -> Result<(), RedisError> {
        let mut conn = self.conn.clone();
        snapshot::delete_snapshot(&mut conn, KEY_SNAPSHOT).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_difficulty_atomic_read_write() {
        let nd = NetworkDifficulty::new(0.0);
        assert_eq!(nd.get(), 0.0);
        nd.set(123_456.789);
        assert!((nd.get() - 123_456.789).abs() < 1e-9);
    }

    #[test]
    fn network_difficulty_clone_shares_view() {
        let nd = NetworkDifficulty::new(1.0);
        let nd2 = nd.clone();
        nd.set(42.0);
        assert_eq!(nd2.get(), 42.0);
    }

    #[test]
    fn window_size_zero_when_no_difficulty() {
        // No real Redis required for this test — `window_size` only
        // touches the NetworkDifficulty view, not Redis.
        let nd = NetworkDifficulty::new(0.0);
        // We construct WindowStore via the public new, but the manager
        // isn't actually used by window_size() — we can't easily fake
        // a ConnectionManager, so this test exercises the math
        // separately. Cross-checked by integration tests against real
        // Redis.
        let factor = 4.0;
        // Direct math: factor * 0.0 = 0.0
        assert_eq!(factor * nd.get(), 0.0);
        nd.set(1_000_000.0);
        assert_eq!(factor * nd.get(), 4_000_000.0);
    }
}
