// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-backed PPLNS sliding window in fixed-size count buckets, mutated only by atomic
//! Lua scripts so the by-address aggregate cannot desync from the buckets.
//! Sized in weight (unlike Group-Solo's time-sized `RoundStore`), with age as a second axis
//! in the index score. Touching the ageing rule in either window? Read the other.

pub mod snapshot;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use thiserror::Error;
use tracing::warn;

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
/// Index zset of live bucket ids. Score = epoch-ms of the bucket's FIRST share
/// (`ZADD NX`), so score order is FIFO order; since it is the opening time, the
/// trim never touches the bucket still being filled.
pub const KEY_BUCKETS: &str = "pplns:buckets";
/// Coinbase distribution snapshot. See [`mod@snapshot`].
pub const KEY_SNAPSHOT: &str = "pplns:snapshot";
/// How many miners the most recently built PPLNS coinbase pays, with the
/// snapshot's TTL so it lapses instead of going stale once no job is built.
pub const KEY_PUBLISHED_OUTPUTS: &str = "pplns:published_outputs";
/// Dedup zset `share_id → counter` for exactly-once `record_share`. Capped
/// to the newest `DEDUP_KEEP` entries by rank. A redelivered share whose
/// id is still in this set is a no-op. See `RECORD_SHARE_LUA`.
pub const KEY_APPLIED: &str = "pplns:applied";

/// Bucket hash key for a given bucket id.
pub fn bucket_key(bucket_id: &str) -> String {
    format!("pplns:bucket:{bucket_id}")
}

/// Default shares-per-bucket when `[pplns] bucket_shares` is not configured.
pub const DEFAULT_BUCKET_SHARES: u64 = 10_000;

/// Buckets one trim may drop, so one share on the hot path never pays for a whole
/// backlog; the next share resumes. The window can therefore sit over `windowSize`
/// for a few appends and a block found then settles against more weight. Deliberate:
/// an unbounded loop on the share path is worse.
const MAX_DROPS_PER_TRIM: usize = 64;

/// How many recent `share_id`s the dedup set retains. Only un-acked in-flight
/// shares are redelivered, so this only needs to exceed any realistic backlog.
const DEDUP_KEEP: i64 = 100_000;

/// Drop one bucket: the oldest when over size, or any past the age cutoff (the size
/// rule alone never fires on a small pool, so stopped miners would keep weight forever).
/// Ages by score range, not by the head, and never drops the bucket still filling.
/// Returns `{dropped, underflowed}`; underflow means bucket and aggregate disagree.
const TRIM_BATCH_LUA: &str = r#"
local total = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
local max_size = tonumber(ARGV[1]) or 0
local bucket_shares = tonumber(ARGV[3])

-- The bucket new shares are landing in. Never a candidate: it is still
-- filling, and its score is when it OPENED, which says nothing about the work
-- going into it right now.
local counter = tonumber(redis.call('GET', KEYS[4]) or '0') or 0
local active = tostring(math.floor(counter / bucket_shares))

local bucket_id = nil

-- Age rule, by score range. Anything before the cutoff qualifies wherever it
-- sits in the index; two entries are read so an active bucket in first place
-- does not hide the next candidate.
local aged = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', ARGV[2], 'LIMIT', 0, 2)
for i = 1, #aged do
    if aged[i] ~= active then bucket_id = aged[i] break end
end

-- Size rule, oldest first, same two-entry step-over.
if bucket_id == nil and max_size > 0 and total > max_size then
    local oldest = redis.call('ZRANGE', KEYS[3], 0, 1)
    for i = 1, #oldest do
        if oldest[i] ~= active then bucket_id = oldest[i] break end
    end
end

if bucket_id == nil then return {0, 0} end
local bkey = 'pplns:bucket:' .. bucket_id
local flat = redis.call('HGETALL', bkey)
local removed = 0
local underflowed = 0
for i = 1, #flat, 2 do
    local addr = flat[i]
    local d = tonumber(flat[i + 1]) or 0
    if d ~= 0 then
        removed = removed + d
        local rem = tonumber(redis.call('HINCRBYFLOAT', KEYS[2], addr, -d))
        if rem then
            if rem < -1e-9 then
                underflowed = underflowed + 1
            end
            -- Near-zero (f64 drift) AND negative (aggregate/bucket skew)
            -- both leave nothing payable behind.
            if rem < 1e-9 then
                redis.call('HDEL', KEYS[2], addr)
            end
        end
    end
end
redis.call('DEL', bkey)
redis.call('ZREM', KEYS[3], bucket_id)
if removed ~= 0 then
    redis.call('INCRBYFLOAT', KEYS[1], -removed)
end
return {1, underflowed}
"#;

/// Atomic, optionally idempotent append of one share into its count bucket; the
/// dedup marker is written in the same script so a consumer crash cannot double-count.
/// The index score is the share's own timestamp (a replayed backlog must not look new)
/// set with `NX`, so a re-used bucket id cannot give an old bucket a fresh lease.
const RECORD_SHARE_LUA: &str = r#"
local has_dedup = ARGV[3] ~= ''
if has_dedup and redis.call('ZSCORE', KEYS[4], ARGV[3]) then
    return 0
end
local counter = redis.call('INCR', KEYS[1])
local bucket = math.floor(counter / tonumber(ARGV[5]))
redis.call('HINCRBYFLOAT', 'pplns:bucket:' .. bucket, ARGV[2], ARGV[1])
redis.call('ZADD', KEYS[5], 'NX', ARGV[6], tostring(bucket))
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
}

// ── Network difficulty view ──────────────────────────────────────────

/// Shared view of the current network difficulty, read by [`WindowStore::window_size`].
/// The `payout` role has no TDP feed, so it is refreshed from `getmininginfo` on a timer.
/// A zero or negative value disables the size rule, so never write a failed reading.
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

/// Redis-backed sliding window over diff-1 share contributions. Cheap to clone.
#[derive(Clone)]
pub struct WindowStore {
    conn: ConnectionManager,
    window_factor: f64,
    /// Shares per bucket, never 0 ([`crate::config::PplnsEngineConfig::try_new`]);
    /// id = `floor(counter / bucket_shares)` over [`KEY_COUNTER`].
    /// ⛔ Only lower it, or change it against an empty window: raising it lands new
    /// shares in an existing bucket, whose old opening time then ages them out early.
    bucket_shares: u64,
    net_diff: NetworkDifficulty,
    /// Age rule for [`TRIM_BATCH_LUA`], in days, never 0 (same validation). Shares the
    /// `abandoned_balance_days` knob with the dust sweep: both mean "miner is gone".
    max_age_days: u32,
}

impl WindowStore {
    pub fn new(
        conn: ConnectionManager,
        window_factor: f64,
        bucket_shares: u64,
        net_diff: NetworkDifficulty,
        max_age_days: u32,
    ) -> Self {
        Self {
            conn,
            window_factor,
            bucket_shares,
            net_diff,
            max_age_days,
        }
    }

    /// Epoch-ms before which a bucket is too old, read fresh on every trim. A clock
    /// before the epoch makes it negative, which stops the age rule instead of
    /// declaring the whole window ancient.
    fn age_cutoff_ms(&self) -> i64 {
        crate::config::abandoned_cutoff_ms(bp_common::now_ms(), self.max_age_days)
    }

    /// `factor × networkDifficulty`, or 0 (size rule off) while
    /// [`NetworkDifficulty`] holds no usable reading.
    pub fn window_size(&self) -> f64 {
        let nd = self.net_diff.get();
        if !nd.is_finite() || nd <= 0.0 {
            return 0.0;
        }
        self.window_factor * nd
    }

    // ── Hot path: record an accepted share ──────────────────────────

    /// Append one accepted share atomically; with `share_id` set a redelivery is a
    /// no-op. Returns `false` for a deduped share. `address` must already be
    /// normalized (stratum does it at authorize time).
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        address: &str,
        difficulty: f64,
        timestamp_ms: u64,
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
            .arg(timestamp_ms)
            .invoke_async(&mut conn)
            .await?;

        if applied == 1 {
            self.trim_window(&mut conn).await?;
        }
        Ok(applied == 1)
    }

    // ── Trim — bound the window ─────────────────────────────────────

    /// Drop oldest entries until `total ≤ windowSize` and no bucket is older
    /// than the age cutoff, at most `MAX_DROPS_PER_TRIM` buckets per call.
    async fn trim_window(&self, conn: &mut ConnectionManager) -> Result<(), WindowError> {
        let window_size = self.window_size();
        let age_cutoff = self.age_cutoff_ms();

        // One bucket per script call keeps each Redis-blocking script small.
        let trim = redis::Script::new(TRIM_BATCH_LUA);
        for _ in 0..MAX_DROPS_PER_TRIM {
            let (dropped, underflowed): (i64, i64) = trim
                .key(KEY_WINDOW_TOTAL)
                .key(KEY_WINDOW_BY_ADDRESS)
                .key(KEY_BUCKETS)
                .key(KEY_COUNTER)
                .arg(window_size)
                // Preformatted: Lua renders a 13-digit number as `1.789e+12`,
                // which Redis rejects as a score bound.
                .arg(format!("({age_cutoff}"))
                .arg(self.bucket_shares)
                .invoke_async(conn)
                .await?;
            if underflowed > 0 {
                warn!(
                    underflowed,
                    "pplns window trim: the aggregate went negative for {underflowed} \
                     address(es) — bucket and aggregate disagree, which a per-key Redis \
                     restore can produce. Those addresses are out of the window until they \
                     earn back into it."
                );
            }
            if dropped == 0 {
                break;
            }
        }

        // No periodic recalc: append and trim are atomic, so the aggregate only
        // accumulates f64 drift.
        Ok(())
    }

    // ── Cold-start bootstrap — rebuild the aggregate from the zset ──

    /// Startup-only rebuild of the aggregate from the live buckets, only when the
    /// hash is empty while buckets exist (a lost key whose buckets survived).
    pub async fn bootstrap_window_if_needed(&self) -> Result<(), WindowError> {
        let mut conn = self.conn.clone();
        let hash_len: usize = conn.hlen(KEY_WINDOW_BY_ADDRESS).await?;
        if hash_len > 0 {
            return Ok(()); // already populated — leave it
        }
        let card: isize = conn.zcard(KEY_BUCKETS).await?;
        if card <= 0 {
            return Ok(()); // no buckets — nothing to rebuild from
        }
        self.rebuild_window_from_buckets(&mut conn).await
    }

    /// Built into a temp key and `RENAME`d over the live hash, so the aggregate is
    /// never observed partial. A bucket deleted by a concurrent trim contributes nothing.
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

    /// Current window aggregate (address → diff-1 sum), read from the
    /// authoritative hash.
    pub async fn read_window_by_address(&self) -> Result<HashMap<String, f64>, WindowError> {
        let mut conn = self.conn.clone();
        let hash: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await?;
        Ok(hash
            .into_iter()
            .filter_map(|(addr, diff_str)| {
                let diff: f64 = diff_str.parse().ok()?;
                (diff > 0.0).then_some((addr, diff))
            })
            .collect())
    }

    /// Cached window total; 0.0 if the key is missing.
    pub async fn current_total(&self) -> Result<f64, WindowError> {
        let mut conn = self.conn.clone();
        let total_str: Option<String> = conn.get(KEY_WINDOW_TOTAL).await?;
        Ok(total_str
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0))
    }

    /// One address's window contribution, 0.0 when absent.
    pub async fn read_window_share_for_address(&self, address: &str) -> Result<f64, WindowError> {
        let mut conn = self.conn.clone();
        let diff_str: Option<String> = conn.hget(KEY_WINDOW_BY_ADDRESS, address).await?;
        let parsed = diff_str.as_deref().and_then(|s| s.parse::<f64>().ok());
        Ok(match parsed {
            Some(v) if v.is_finite() && v > 0.0 => v,
            _ => 0.0,
        })
    }

    /// Redis handle for the snapshot write and the block-found read.
    /// Record how many miners the coinbase just built pays.
    pub async fn write_published_outputs(
        &self,
        count: usize,
        ttl_seconds: u32,
    ) -> Result<(), WindowError> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .set_ex(KEY_PUBLISHED_OUTPUTS, count, u64::from(ttl_seconds))
            .await?;
        Ok(())
    }

    /// How many miners the most recently built coinbase pays; `None` once no
    /// coinbase was built within the snapshot TTL.
    pub async fn read_published_outputs(&self) -> Result<Option<u32>, WindowError> {
        let mut conn = self.conn.clone();
        Ok(conn.get(KEY_PUBLISHED_OUTPUTS).await?)
    }

    pub fn connection_for_snapshot(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// The shared network-difficulty view this store trims against, handed out so
    /// the process that owns a Bitcoin RPC can keep it current.
    pub fn network_difficulty(&self) -> NetworkDifficulty {
        self.net_diff.clone()
    }
}

/// Redis key holding the snapshot for one payout-list fingerprint. Stays under
/// the `pplns:` prefix so the redis-state backup scope keeps covering it.
pub fn snapshot_key_for(payouts_fingerprint: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut key = String::with_capacity(KEY_SNAPSHOT.len() + 65);
    key.push_str(KEY_SNAPSHOT);
    key.push(':');
    for byte in payouts_fingerprint {
        let _ = write!(key, "{byte:02x}");
    }
    key
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
        // A `ConnectionManager` cannot be faked, so this checks the math directly.
        let nd = NetworkDifficulty::new(0.0);
        let factor = 4.0;
        assert_eq!(factor * nd.get(), 0.0);
        nd.set(1_000_000.0);
        assert_eq!(factor * nd.get(), 4_000_000.0);
    }
}
