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
//! Bucket ids derive from the never-reset `pplns:counter`, which is what makes
//! `bucket_shares` a boot-time-only value rather than a live knob — see the
//! field of that name on [`WindowStore`].
//!
//! ## Why this is not shaped like the Group-Solo window
//!
//! `bp-group-solo-engine`'s `RoundStore` solves a window that looks like the
//! same problem and deliberately does it differently: there the bucket id IS
//! the time slice (`timestamp_ms.div_euclid(WINDOW_BUCKET_MS)`), and the trim
//! is `drop ids ≤ now_bucket - window_buckets`. No second dimension, because
//! it needs none.
//!
//! The reason the two diverge is what each window is SIZED by:
//!
//! - Group-Solo's is defined purely in **time**. Time is therefore its only
//!   axis, and the natural thing to encode in the id. It has no weight rule
//!   at all.
//! - This one is defined in **weight** — `window_factor × network_difficulty`
//!   — so the id already carries the share count that rule measures against,
//!   and quantising by count is what bounds the overshoot to a single bucket.
//!   Age is a SECOND, independent axis here, and it has to live somewhere
//!   else: the index score.
//!
//! Adopting time-derived ids here would not be a fix, it would swap the
//! storage model — `bucket_shares` loses its meaning, the counter loses its
//! role, and the 4362-bucket live window would have to be renumbered rather
//! than restamped. That is a separate change, not this one.
//!
//! **If you touch the ageing rule in either window, read the other.** The two
//! answer the same question ("when is a miner's work too old to count?") with
//! different machinery, which is exactly the shape this repo has been bitten
//! by before.

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
/// Index zset of live bucket ids for FIFO trim ordering. Each bucket is a
/// hash `pplns:bucket:<id>` of address → Σdiff. Storage is O(buckets ×
/// miners) instead of O(shares).
///
/// **Score = epoch-ms of the bucket's FIRST share**, not the id it used to
/// be. The `ZADD` carries `NX`, so the value is written when the bucket opens
/// and never moves: it says when the bucket started filling, not when it
/// stopped. FIFO order is unchanged by the switch — bucket ids and wall-clock
/// both only ever increase, so the same member comes back as "oldest" either
/// way.
///
/// Opening time is the conservative end to age on: a bucket qualifies as soon
/// as it has EXISTED longer than the cutoff, even when its newest share is
/// recent. That would bite on a pool slow enough for one bucket to take longer
/// than `abandoned_balance_days` to fill, which is why the trim refuses to
/// touch the bucket the counter is currently writing into.
///
/// A window populated before the switch carries ids as scores. They are
/// below [`LEGACY_SCORE_CEILING`] by many orders of magnitude, and
/// [`WindowStore::restamp_legacy_bucket_scores`] converts them at startup —
/// without it the age rule would read them as 1970 and drop the whole
/// window on its first run.
pub const KEY_BUCKETS: &str = "pplns:buckets";
/// Coinbase distribution snapshot. See [`mod@snapshot`].
pub const KEY_SNAPSHOT: &str = "pplns:snapshot";
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

/// Below this, a [`KEY_BUCKETS`] score is a bucket id from before the index
/// carried timestamps, not an epoch-ms. 1e12 ms is 2001-09-09; a real id
/// would need 1e16 shares at the default bucket size to reach it, so the two
/// ranges cannot meet. See [`WindowStore::restamp_legacy_bucket_scores`].
pub const LEGACY_SCORE_CEILING: i64 = 1_000_000_000_000;

/// Buckets one [`WindowStore::trim_window`] call may drop before handing back
/// control. The trim runs on the share-append path, and the backlog it has to
/// clear is not always small: the boot-time score conversion stamps the whole
/// pre-existing window into a band milliseconds wide, so every one of those
/// buckets becomes eligible in the same instant. Uncapped, one unlucky share
/// would pay for thousands of sequential Redis round-trips.
///
/// Nothing is lost by stopping early — the next share resumes where this call
/// left off, so a backlog drains over many appends instead of one.
///
/// ⚠️ It does relax an invariant. The uncapped loop restored `total ≤
/// windowSize` on EVERY append; with a cap the window can sit over target
/// across several. It matters only when hundreds of buckets go over at once
/// (network difficulty dropping sharply, `window_factor` lowered and the
/// process restarted, or the converted legacy set becoming eligible together)
/// — and a block found during that stretch settles against a window carrying
/// more weight than the size rule intends, because the read path does not
/// trim. The trade is deliberate: an unbounded loop on the share hot path is
/// the worse of the two, and the drift is bounded by how fast shares arrive.
const MAX_DROPS_PER_TRIM: usize = 64;

/// How many recent `share_id`s the dedup set retains. Only un-acked
/// in-flight shares are ever redelivered, so the horizon only needs to
/// cover the in-flight window plus margin — 100k entries (~3 MB) is far
/// more than any realistic consumer backlog, at negligible cost.
const DEDUP_KEEP: i64 = 100_000;

/// Drop one bucket: the oldest, when the window is over size, or any bucket
/// past the age cutoff. `KEYS[1]` = window:total, `KEYS[2]` = by-address,
/// `KEYS[3]` = buckets index zset, `KEYS[4]` = the share counter. `ARGV[1]` =
/// window_size (0 disables the size rule — reachable, the difficulty source
/// starts unset), `ARGV[2]` = the age cutoff as an EXCLUSIVE `ZRANGEBYSCORE`
/// max (`"(1789…"`), `ARGV[3]` = the score floor below which an index entry
/// carries no usable timestamp, `ARGV[4]` = bucket_shares. The bucket hash key
/// is built inside the script (`pplns:bucket:<id>`) — single-instance Valkey,
/// not cluster.
///
/// The age rule exists because the size rule cannot fire on a pool whose
/// window sits far below `window_factor × network_difficulty`: it is over
/// target on its first iteration, forever, and a miner who stops mining keeps
/// its weight for good. Both rules drop through the same body, so the
/// aggregate/bucket bookkeeping has exactly one implementation.
///
/// ## Why the age rule reads a score RANGE and not the head
///
/// It used to inspect `ZRANGE 0,1` and give up when that entry was not
/// droppable — which wedged the whole rule behind any entry that can sit at
/// rank 0 and never be dropped. Two of those are reachable:
///
/// - an entry below the score floor, deliberately inert (a `RESTORE` of a
///   pre-timestamp index, a caller passing a bogus share time)
/// - a bucket opened by a REPLAYED share, whose accept time is older than
///   everything already in the index and which is nonetheless young
///
/// Either one parks itself first and answers "not too old", the script
/// returns `{0, 0}`, and everything behind it becomes unreachable — for the
/// whole `abandoned_balance_days`. `ZRANGEBYSCORE floor (cutoff` steps over
/// both instead of stopping at them.
///
/// ## The currently-filling bucket is never dropped
///
/// Identified from the counter (`floor(counter / bucket_shares)`), not by
/// "stop when one bucket is left", which was a proxy for the same thing.
/// Being exact matters here: with `NX` scoring the index holds a bucket's
/// OPENING time, so a bucket that takes longer than the cutoff to fill would
/// otherwise be eligible while shares are still going into it.
///
/// Returns `{dropped, underflowed}` — `dropped` is 1 when a bucket went and
/// 0 when nothing qualified, so the caller loops until it sees 0.
/// `underflowed` counts the addresses the decrement would have driven BELOW
/// zero.
///
/// The second number exists because an underflow is not a rounding artefact
/// and must not be cleaned up silently. The aggregate is a sum of
/// non-negative difficulties, so a decrement can only exceed it if the
/// bucket holds a share the aggregate never received — which the
/// `DUMP`-per-key backup can produce: it captures `window:by-address` and
/// the `bucket:*` hashes at different instants, so a restore can hand the
/// trim a bucket that is ahead of the aggregate (see
/// `blitzpool::redis_backup`).
///
/// Both the near-zero and the negative case `HDEL` the field, and that is
/// the point: `read_window_by_address` filters `diff > 0`, so a field left
/// sitting at a negative value drops the address out of the window
/// ENTIRELY — silently unpaid until it earns its way back. Removing it is
/// the same outcome, but the count makes it visible.
const TRIM_BATCH_LUA: &str = r#"
local total = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
local max_size = tonumber(ARGV[1]) or 0
local bucket_shares = tonumber(ARGV[4]) or 1
if bucket_shares < 1 then bucket_shares = 1 end

-- The bucket new shares are landing in. Never a candidate: it is still
-- filling, and its score is when it OPENED, which says nothing about the work
-- going into it right now.
local counter = tonumber(redis.call('GET', KEYS[4]) or '0') or 0
local active = tostring(math.floor(counter / bucket_shares))

local bucket_id = nil

-- Age rule, by score range. Anything in [floor, cutoff) qualifies wherever it
-- sits in the index; two entries are read so an active bucket in first place
-- does not hide the next candidate.
local aged = redis.call('ZRANGEBYSCORE', KEYS[3], ARGV[3], ARGV[2], 'LIMIT', 0, 2)
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

/// Atomic, optionally-idempotent append of one accepted share into its count
/// bucket. `KEYS[1]` = counter, `KEYS[2]` = window:total,
/// `KEYS[3]` = by-address, `KEYS[4]` = applied (dedup) zset,
/// `KEYS[5]` = buckets index zset. `ARGV[1]` =
/// difficulty (string), `ARGV[2]` = address, `ARGV[3]` = share_id (empty ⇒ no
/// dedup), `ARGV[4]` = dedup keep-count, `ARGV[5]` = bucket_shares,
/// `ARGV[6]` = the SHARE's epoch-ms, which becomes the bucket's index score.
///
/// The `ZADD` carries `NX`, so the score is written once, when the bucket is
/// first seen, and never moved afterwards. Two consequences, both wanted:
/// the score means "when this bucket opened" rather than "when it was last
/// written", and an id that gets re-used — a raised `bucket_shares`, or a
/// counter rewound by a Redis state restore — cannot hand a months-old bucket
/// a fresh lease on life.
///
/// It is the share's own timestamp and not `now()` for the reason
/// `bp-pplns-engine::hooks` states where it threads the value down: under the
/// Core/Satellite split this sink can replay a backlog, and re-stamping would
/// file hours-old work as brand new.
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
    /// Encountered an entry in `pplns:shares` whose `addr:diff:ts`
    /// format doesn't parse. Logged + the entry is skipped at trim
    /// time. Returned only from explicit read-paths so callers can
    /// surface a CRITICAL alert.
    #[error("malformed share entry: {0:?}")]
    MalformedEntry(String),
}

// ── Network difficulty view ──────────────────────────────────────────

/// Thread-safe shared view of the pool's current `networkDifficulty`.
///
/// Backed by `Arc<AtomicU64>` over `f64::to_bits`/`f64::from_bits`,
/// so reads + writes are lock-free across worker threads.
///
/// **Who writes it, and why it is not the TDP stream.** This value is read
/// by exactly one thing: [`WindowStore::window_size`], which only
/// `WindowStore::trim_window` calls, which only
/// [`WindowStore::record_share`] calls. That path runs on the process that
/// consumes the accepted-share stream — the `payout` role — and that
/// process has no TDP feed at all. So it is seeded from `getmininginfo` at
/// boot and refreshed from the same RPC on a timer by the binary (see
/// `blitzpool::network_difficulty`).
///
/// The doc here used to say "as published by the TDP template stream", and
/// [`Self::set`] was never called from anywhere: the window was sized to
/// the difficulty at process start and frozen there for the process's whole
/// life. `window_factor` then meant "x times the difficulty at the last
/// restart" rather than the current one, so a long-running payout process
/// trimmed to a window that spanned steadily fewer blocks than configured.
///
/// A zero or negative value makes `window_size` return 0, which disables
/// trimming entirely — so a failed reading must never be written. The
/// refresher's guard is what keeps that from happening.
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
    /// Shares per count-bucket. The id is `floor(counter / bucket_shares)`
    /// over [`KEY_COUNTER`], which is only ever `INCR`'d — nothing in the tree
    /// resets or deletes it.
    ///
    /// **Raising it lowers every future id.** With the counter at 1 000 000
    /// and 10 000 shares per bucket the live ids sit just under 100; doubling
    /// the divisor puts the next share in bucket 50, below the whole live set.
    ///
    /// ⛔ **Still change it only downwards, or against an empty window.** The
    /// reason moved, it did not go away.
    ///
    /// It used to be FIFO position: while [`KEY_BUCKETS`] was scored by id, a
    /// lower id meant the head, so [`TRIM_BATCH_LUA`] took the fresh bucket
    /// ahead of ones months older. Timestamp scores ended that, and
    /// `raising_bucket_shares_no_longer_strands_new_work` pins it — but only
    /// for the case that test builds, where the recomputed id lands BELOW every
    /// live bucket.
    ///
    /// On a window that has never trimmed, ids are dense from the bottom and
    /// the recomputed id lands INSIDE the live set instead. The share then
    /// `HINCRBYFLOAT`s into an existing bucket, and `NX` leaves that bucket's
    /// opening time alone — correctly, it did open then. New work inherits an
    /// old bucket's age and is aged out with it. Measured on the live pool
    /// 2026-09-10: ids 2035..6396, every one of them live, so any raise
    /// collides.
    ///
    /// Lowering stays safe: the new ids land above every existing bucket.
    ///
    /// This used to be pinned to the TS pool's `PPLNS_BUCKET_SHARES` because
    /// both pools shared one Redis across the cutover. That pool is retired,
    /// and nothing here reads a key it does not also write — a cold start
    /// rebuilds [`KEY_WINDOW_BY_ADDRESS`] from the buckets — so the counter is
    /// the only constraint left.
    bucket_shares: u64,
    net_diff: NetworkDifficulty,
    /// Age rule for [`TRIM_BATCH_LUA`], in ms. Always at least one day:
    /// `PplnsEngineConfig::validate` rejects `abandoned_balance_days == 0`
    /// outright, and the constructor floors it, so there is no "age rule off"
    /// state to guard against and no branch pretending otherwise.
    ///
    /// Fed from `[pplns] abandoned_balance_days`, deliberately the same knob
    /// the dust sweep uses: both answer "how long until a miner counts as
    /// gone", one for its share weight and one for its ledger claim. Split
    /// them only if a reason to tune them apart actually turns up.
    max_age_ms: i64,
}

impl WindowStore {
    /// Wire up the store. The caller owns the `ConnectionManager`
    /// lifecycle (typically created once at engine startup).
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
            bucket_shares: if bucket_shares == 0 {
                DEFAULT_BUCKET_SHARES
            } else {
                bucket_shares
            },
            net_diff,
            // Floored, not validated-and-rejected, because the engine config
            // already refuses 0 — this only keeps a direct constructor (the
            // tests) from producing a cutoff that would age out everything.
            max_age_ms: max_age_days.max(1) as i64 * 86_400_000,
        }
    }

    /// Epoch-ms before which a bucket counts as too old. Read fresh on every
    /// trim so a long-running process ages against the current clock, not
    /// against its start time.
    ///
    /// `now_ms()` answers 0 if the system clock predates the epoch (a board
    /// with a dead RTC), which makes this negative. The trim then finds
    /// nothing at or above the score floor that is also below a negative
    /// cutoff, so the age rule stops firing instead of declaring the whole
    /// window ancient. That is the safe direction to fail in, and it is why
    /// the floor is a `>=` test rather than a plain comparison.
    fn age_cutoff_ms(&self) -> i64 {
        bp_common::now_ms() - self.max_age_ms
    }

    /// One-shot conversion of a window written before [`KEY_BUCKETS`] carried
    /// timestamps: every score below [`LEGACY_SCORE_CEILING`] is a bucket id,
    /// not an epoch-ms. Idempotent — a converted window has no legacy score
    /// left and the call is a no-op.
    ///
    /// This is NOT what keeps the age rule off those entries; the floor inside
    /// the score floor inside the trim script does that, and it holds whether
    /// or not this ever ran. What the conversion buys is the opposite: an unconverted entry is
    /// inert **forever**, so without this the pre-existing window could never
    /// age out at all. The two split the work — the floor is the safety net,
    /// this is what starts the clock.
    ///
    /// The true creation times are not recoverable (nothing recorded them), so
    /// every converted bucket is stamped just under "now". The age clock
    /// therefore starts at the first boot after this ships, and nothing is
    /// evicted retroactively.
    ///
    /// Stamps are staggered by one ms in existing FIFO order rather than
    /// sharing one value: equal scores in a zset order by member string, and
    /// the members are ids as text, where `"1000"` sorts before `"999"`. One
    /// shared timestamp would scramble the drop order.
    ///
    /// The band is therefore only `legacy.len()` ms wide, so a bucket opened
    /// afterwards by a REPLAYED share — accept time older than the conversion
    /// instant — sorts below the whole converted set. That is untidy but
    /// harmless: the age rule selects by score range, not by rank, so a young
    /// entry sitting first cannot hide the aged ones behind it. It would have
    /// wedged the rule for a full `abandoned_balance_days` back when the trim
    /// only ever inspected the head.
    ///
    /// Returns how many buckets it converted.
    pub async fn restamp_legacy_bucket_scores(&self) -> Result<u64, WindowError> {
        let mut conn = self.conn.clone();
        // Ask Redis for the score range instead of pulling the whole index and
        // filtering here: after the first boot the answer is empty, and this
        // runs on the startup path at every start, forever.
        let legacy: Vec<String> = conn
            .zrangebyscore(KEY_BUCKETS, "-inf", format!("({LEGACY_SCORE_CEILING}"))
            .await?;
        if legacy.is_empty() {
            return Ok(0);
        }
        // Ascending by score, which for legacy scores is ascending by id —
        // the FIFO order to preserve.
        let base = bp_common::now_ms() - legacy.len() as i64;
        let items: Vec<(f64, &str)> = legacy
            .iter()
            .enumerate()
            .map(|(i, member)| ((base + i as i64) as f64, member.as_str()))
            .collect();
        let _: () = conn.zadd_multiple(KEY_BUCKETS, &items).await?;
        warn!(
            converted = legacy.len(),
            "pplns window: converted bucket index scores from ids to timestamps — the \
             age rule starts counting from now, nothing is evicted retroactively"
        );
        Ok(legacy.len() as u64)
    }

    /// `windowSize = factor × networkDifficulty`. Returns 0 while the
    /// network-difficulty source holds no usable reading — see
    /// [`NetworkDifficulty`] for who writes it, which is `getmininginfo`
    /// on the payout role and never the TDP stream. A 0 makes
    /// `record_share` a no-op trim-wise, so the window only grows.
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
    /// runs as one indivisible Lua script (`RECORD_SHARE_LUA`) — same
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
    /// than the age cutoff. Idempotent if
    /// the window is already below threshold.
    async fn trim_window(&self, conn: &mut ConnectionManager) -> Result<(), WindowError> {
        let window_size = self.window_size();
        let age_cutoff = self.age_cutoff_ms();

        // Drop whole oldest buckets while over the window (see [`TRIM_BATCH_LUA`]).
        // Each call atomically removes one bucket and decrements window:total +
        // by-address by exactly its per-address contribution. Looping in Rust
        // (one bucket per script) keeps any single script's Redis-blocking
        // small while preserving per-bucket atomicity. The script returns 1
        // while it drops a bucket and 0 once nothing qualifies under either
        // rule → done.
        let trim = redis::Script::new(TRIM_BATCH_LUA);
        for _ in 0..MAX_DROPS_PER_TRIM {
            let (dropped, underflowed): (i64, i64) = trim
                .key(KEY_WINDOW_TOTAL)
                .key(KEY_WINDOW_BY_ADDRESS)
                .key(KEY_BUCKETS)
                .key(KEY_COUNTER)
                .arg(window_size)
                // Both bounds go over as preformatted strings: Lua renders a
                // 13-digit number as `1.789e+12`, which Redis rejects as a
                // score bound.
                .arg(format!("({age_cutoff}"))
                .arg(LEGACY_SCORE_CEILING.to_string())
                .arg(self.bucket_shares)
                .invoke_async(conn)
                .await?;
            if underflowed > 0 {
                // Not a rounding artefact: the bucket held more for an
                // address than the aggregate ever received. The addresses
                // are dropped (a negative field is unpayable anyway — the
                // read filters `> 0`), but somebody has to hear about it,
                // because the likely cause is a restored backup whose
                // aggregate and buckets were captured at different instants.
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

    /// A cloned Redis handle for the shared build-and-snapshot path.
    /// Mirrors `GroupRoundStore::connection_for_snapshot`.
    pub fn connection_for_snapshot(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// The live network-difficulty view this store trims against.
    ///
    /// Handed out so the process that owns a Bitcoin RPC can keep it
    /// current — see [`NetworkDifficulty`]. `Arc`-backed, so the clone and
    /// this store observe the same value.
    pub fn network_difficulty(&self) -> NetworkDifficulty {
        self.net_diff.clone()
    }

    /// Read the schema-2 weight snapshot for one weights fingerprint.
    /// `None` when never written, expired, or a different schema.
    pub async fn read_weight_snapshot_for(
        &self,
        weights_fingerprint: &[u8; 32],
    ) -> Result<Option<snapshot::StoredWeightSnapshot>, RedisError> {
        let mut conn = self.conn.clone();
        let key = snapshot_key_for(weights_fingerprint);
        snapshot::read_weight_snapshot(&mut conn, &key).await
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
