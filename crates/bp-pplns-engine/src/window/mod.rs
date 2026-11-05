// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-backed PPLNS sliding window in fixed-size count buckets, mutated only by atomic
//! Lua scripts so the by-address aggregate cannot desync from the buckets.
//! Sized in weight (unlike Group-Solo's time-sized `RoundStore`). Besides the size rule, an
//! address that has submitted no share for `abandoned_balance_days` leaves the window with
//! all its weight ([`WindowStore::forget_inactive`]); an address that keeps mining keeps
//! every share until the size rule takes it. Touching the ageing rule in either window?
//! Read the other.

pub mod snapshot;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use thiserror::Error;
use tracing::{info, warn};

// ── Redis keys ───────────────────────────────────────────────────────

/// Monotonic counter. Drives the bucket id (`floor(counter / bucket_shares)`)
/// so shares group into fixed-size count buckets in submission order, and also
/// scores the dedup marker zset.
pub const KEY_COUNTER: &str = "pplns:counter";
/// Float string holding the sum of difficulty over the current window.
pub const KEY_WINDOW_TOTAL: &str = "pplns:window:total";
/// Hash `address → diff-1 aggregate` — the AUTHORITATIVE window state.
/// Maintained lock-step with the buckets: `record_share` increments,
/// `trim_window` decrements when a bucket is trimmed, `forget_inactive` when
/// an address leaves.
pub const KEY_WINDOW_BY_ADDRESS: &str = "pplns:window:by-address";
/// Temp key the cold-start rebuild fills before an atomic `RENAME` swap, so
/// the live aggregate is never observed empty/partial during a rebuild.
pub const KEY_WINDOW_REBUILD: &str = "pplns:window:by-address:rebuild";
/// Index zset of live bucket ids. Score = epoch-ms of the bucket's FIRST share
/// (`ZADD NX`), so score order is FIFO order for the size rule.
pub const KEY_BUCKETS: &str = "pplns:buckets";
/// Hash `address → epoch-ms of its latest share in the window`, kept with the
/// aggregate: `record_share` raises it, and an address leaves it together with
/// its last weight. [`WindowStore::forget_inactive`] judges inactivity on it.
pub const KEY_WINDOW_LAST_SHARE: &str = "pplns:window:last-share";
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

/// Drop the oldest bucket while the window is over size, never the bucket still
/// filling. An address whose last weight leaves with it leaves the last-share hash too.
/// Returns `{dropped, underflowed}`; underflow means bucket and aggregate disagree.
const TRIM_BATCH_LUA: &str = r#"
local total = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
local max_size = tonumber(ARGV[1]) or 0
local bucket_shares = tonumber(ARGV[2])

-- The bucket new shares are landing in. Never a candidate: it holds the
-- newest work, whatever its opening time sorts it among the others.
local counter = tonumber(redis.call('GET', KEYS[4]) or '0') or 0
local active = tostring(math.floor(counter / bucket_shares))

local bucket_id = nil

-- Oldest first; two entries are read so an active bucket in first place does
-- not hide the next candidate.
if max_size > 0 and total > max_size then
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
                redis.call('HDEL', KEYS[5], addr)
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
/// set with `NX`, so a later share never moves a bucket's opening time, which the size
/// rule's FIFO order and the last-share seeding rely on.
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
-- Raised, never lowered: a replayed older share says nothing about how
-- recently the address mined.
local seen = tonumber(redis.call('HGET', KEYS[6], ARGV[2]) or '0') or 0
if tonumber(ARGV[6]) > seen then
    redis.call('HSET', KEYS[6], ARGV[2], ARGV[6])
end
if has_dedup then
    redis.call('ZADD', KEYS[4], counter, ARGV[3])
    redis.call('ZREMRANGEBYRANK', KEYS[4], 0, -tonumber(ARGV[4]) - 1)
end
return 1
"#;

/// Remove one address from the window with all its weight, if its latest share is
/// still before the cutoff (re-checked here, so a share that landed since the caller
/// looked keeps it). Takes it out of every bucket, the aggregate, the total and the
/// last-share hash at once; a bucket left empty goes from the index.
/// Returns `{removed, aggregate, bucket_sum}`, the two sums as strings; they
/// disagree only when bucket and aggregate do.
const FORGET_INACTIVE_LUA: &str = r#"
local seen = tonumber(redis.call('HGET', KEYS[4], ARGV[1]) or '')
if seen == nil or seen >= tonumber(ARGV[2]) then
    return {0, '0', '0'}
end
local in_buckets = 0
local ids = redis.call('ZRANGE', KEYS[3], 0, -1)
for i = 1, #ids do
    local bkey = 'pplns:bucket:' .. ids[i]
    local d = redis.call('HGET', bkey, ARGV[1])
    if d then
        in_buckets = in_buckets + (tonumber(d) or 0)
        redis.call('HDEL', bkey, ARGV[1])
        if redis.call('HLEN', bkey) == 0 then
            redis.call('ZREM', KEYS[3], ids[i])
        end
    end
end
-- The aggregate is what the total sums, so the total drops by it.
local aggregate = tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '0') or 0
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('HDEL', KEYS[4], ARGV[1])
if aggregate ~= 0 then
    redis.call('INCRBYFLOAT', KEYS[1], -aggregate)
end
return {1, tostring(aggregate), tostring(in_buckets)}
"#;

/// Raise each `ARGV` pair's last-share time (address, epoch-ms) to at least the
/// given time, never lower it. Returns how many entries it wrote.
const RAISE_LAST_SHARE_LUA: &str = r#"
local raised = 0
for i = 1, #ARGV, 2 do
    local seen = tonumber(redis.call('HGET', KEYS[1], ARGV[i]) or '0') or 0
    if tonumber(ARGV[i + 1]) > seen then
        redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
        raised = raised + 1
    end
end
return raised
"#;

/// How often, in share time, the writer looks for inactive addresses. Inactivity is
/// counted in days, so a minute of lag changes nothing.
const INACTIVITY_CHECK_EVERY_MS: u64 = 60_000;

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
    /// shares in an existing bucket, whose old opening time then sorts them with the
    /// oldest work for the size rule.
    bucket_shares: u64,
    net_diff: NetworkDifficulty,
    /// Days without a share after which an address leaves the window, never 0
    /// (same validation). Shares the `abandoned_balance_days` knob with the dust
    /// sweep: both mean "miner is gone".
    inactive_days: u32,
    /// Share time of the last inactivity check, see [`INACTIVITY_CHECK_EVERY_MS`].
    last_inactivity_check_ms: Arc<AtomicU64>,
}

impl WindowStore {
    pub fn new(
        conn: ConnectionManager,
        window_factor: f64,
        bucket_shares: u64,
        net_diff: NetworkDifficulty,
        inactive_days: u32,
    ) -> Self {
        Self {
            conn,
            window_factor,
            bucket_shares,
            net_diff,
            inactive_days,
            last_inactivity_check_ms: Arc::new(AtomicU64::new(0)),
        }
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
            .key(KEY_WINDOW_LAST_SHARE)
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
            // The share is in; a failed check is retried on a later share.
            if let Err(err) = self.forget_inactive_if_due(timestamp_ms).await {
                warn!(%err, "pplns window: inactivity check failed");
            }
        }
        Ok(applied == 1)
    }

    // ── Inactivity — an address that stopped leaves with all its weight ──

    /// Runs [`Self::forget_inactive`] at most once per [`INACTIVITY_CHECK_EVERY_MS`]
    /// of share time. The clock is the share just recorded, not the wall clock, so a
    /// backlog replayed after downtime is judged in its own time and an address
    /// whose newer shares are still in the backlog is not taken for gone.
    async fn forget_inactive_if_due(&self, share_ms: u64) -> Result<(), WindowError> {
        let last = self.last_inactivity_check_ms.load(Ordering::Relaxed);
        if share_ms < last.saturating_add(INACTIVITY_CHECK_EVERY_MS) {
            return Ok(());
        }
        self.last_inactivity_check_ms
            .store(share_ms, Ordering::Relaxed);
        self.forget_inactive(share_ms).await
    }

    /// Takes every address whose latest share is more than `abandoned_balance_days`
    /// before `now_ms` out of the window, all its weight at once; what it held is
    /// then split among everyone else by the next distribution.
    pub async fn forget_inactive(&self, now_ms: u64) -> Result<(), WindowError> {
        let mut conn = self.conn.clone();
        let cutoff = crate::config::abandoned_cutoff_ms(now_ms as i64, self.inactive_days);
        let last_share: HashMap<String, String> = conn.hgetall(KEY_WINDOW_LAST_SHARE).await?;
        let script = redis::Script::new(FORGET_INACTIVE_LUA);
        for (address, seen) in last_share {
            if seen.parse::<i64>().is_ok_and(|seen| seen >= cutoff) {
                continue;
            }
            // One address per script call keeps each Redis-blocking script small.
            let (removed, aggregate, in_buckets): (i64, String, String) = script
                .key(KEY_WINDOW_TOTAL)
                .key(KEY_WINDOW_BY_ADDRESS)
                .key(KEY_BUCKETS)
                .key(KEY_WINDOW_LAST_SHARE)
                .arg(&address)
                .arg(cutoff)
                .invoke_async(&mut conn)
                .await?;
            if removed == 0 {
                continue;
            }
            let (aggregate, in_buckets) = (
                aggregate.parse::<f64>().unwrap_or(0.0),
                in_buckets.parse::<f64>().unwrap_or(0.0),
            );
            info!(
                address,
                last_share_ms = %seen,
                weight = aggregate,
                inactive_days = self.inactive_days,
                "pplns window: address left the window after its inactivity period"
            );
            if (aggregate - in_buckets).abs() > 1e-6 * aggregate.abs().max(1.0) {
                warn!(
                    address,
                    aggregate,
                    in_buckets,
                    "pplns window: the address's aggregate and its bucket entries disagreed \
                     — the total dropped by the aggregate"
                );
            }
        }
        Ok(())
    }

    /// Raises every aggregate address's last-share time to at least the opening
    /// time of the newest bucket it is in, which its latest share is no older
    /// than. Raise-only like `record_share`, so a share recorded meanwhile keeps
    /// its own time, and an entry left behind by a writer that kept none is
    /// brought up to the work the window holds. An address in no bucket and with
    /// no entry gets `now_ms`, so it leaves once inactive like any other.
    async fn seed_last_share(&self, conn: &mut ConnectionManager) -> Result<(), WindowError> {
        let in_window: Vec<String> = conn.hkeys(KEY_WINDOW_BY_ADDRESS).await?;
        if in_window.is_empty() {
            return Ok(());
        }
        let mut newest: HashMap<String, Option<f64>> = in_window
            .into_iter()
            .map(|address| (address, None))
            .collect();
        let buckets: Vec<(String, f64)> = conn.zrange_withscores(KEY_BUCKETS, 0, -1).await?;
        for chunk in buckets.chunks(500) {
            let mut pipe = redis::pipe();
            for (id, _) in chunk {
                pipe.hkeys(bucket_key(id));
            }
            let fields: Vec<Vec<String>> = pipe.query_async(conn).await?;
            for ((_, opened), addresses) in chunk.iter().zip(fields) {
                for address in addresses {
                    if let Some(seen) = newest.get_mut(&address) {
                        *seen = Some(seen.map_or(*opened, |seen| seen.max(*opened)));
                    }
                }
            }
        }
        let now_ms = bp_common::now_ms();
        let mut in_buckets: Vec<(String, i64)> = Vec::new();
        let mut in_none: Vec<String> = Vec::new();
        for (address, seen) in newest {
            match seen {
                Some(opened) => in_buckets.push((address, opened as i64)),
                None => in_none.push(address),
            }
        }
        let raise = redis::Script::new(RAISE_LAST_SHARE_LUA);
        let mut raised = 0_i64;
        for chunk in in_buckets.chunks(500) {
            let mut invocation = raise.key(KEY_WINDOW_LAST_SHARE);
            for (address, opened) in chunk {
                invocation.arg(address).arg(*opened);
            }
            raised += invocation.invoke_async::<i64>(conn).await?;
        }
        if !in_none.is_empty() {
            let mut pipe = redis::pipe();
            for address in &in_none {
                pipe.hset_nx(KEY_WINDOW_LAST_SHARE, address, now_ms)
                    .ignore();
            }
            let _: () = pipe.query_async(conn).await?;
        }
        if raised > 0 {
            info!(
                raised,
                "pplns window: last-share times raised to the newest bucket each address is in"
            );
        }
        Ok(())
    }

    // ── Trim — bound the window ─────────────────────────────────────

    /// Drop oldest buckets until `total ≤ windowSize`, at most
    /// `MAX_DROPS_PER_TRIM` per call.
    async fn trim_window(&self, conn: &mut ConnectionManager) -> Result<(), WindowError> {
        let window_size = self.window_size();

        // One bucket per script call keeps each Redis-blocking script small.
        let trim = redis::Script::new(TRIM_BATCH_LUA);
        for _ in 0..MAX_DROPS_PER_TRIM {
            let (dropped, underflowed): (i64, i64) = trim
                .key(KEY_WINDOW_TOTAL)
                .key(KEY_WINDOW_BY_ADDRESS)
                .key(KEY_BUCKETS)
                .key(KEY_COUNTER)
                .key(KEY_WINDOW_LAST_SHARE)
                .arg(window_size)
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

    /// Startup-only: rebuild the aggregate from the live buckets when the hash is
    /// empty while buckets exist (a lost key whose buckets survived), then give
    /// every address in it a last-share time (see `seed_last_share`).
    pub async fn bootstrap_window_if_needed(&self) -> Result<(), WindowError> {
        let mut conn = self.conn.clone();
        let hash_len: usize = conn.hlen(KEY_WINDOW_BY_ADDRESS).await?;
        let card: isize = conn.zcard(KEY_BUCKETS).await?;
        if hash_len == 0 && card > 0 {
            self.rebuild_window_from_buckets(&mut conn).await?;
        }
        self.seed_last_share(&mut conn).await
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
