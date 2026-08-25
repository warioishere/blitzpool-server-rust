// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis writer for the per-session live hashes (`client:live:*`).
//!
//! Mirrors the two `client_entity` hot-write paths into one Redis hash
//! per session (key schema in [`bp_common::live_client_key`]):
//!
//! - the touch flush ([`crate::touch_buffer`]) writes best/current
//!   difficulty, channel count and the last-seen timestamp, and
//!   **refreshes the TTL** — exactly the liveness role `updatedAt`
//!   plays in Postgres;
//! - the hashrate sampler ([`crate::hashrate_sampler`]) writes only
//!   `hash_rate` and sets the TTL **only when its HSET created the
//!   key** — the sampler keeps writing fades for up to 3 windows after
//!   the shares stop, and letting those writes refresh the TTL would
//!   extend a dead session's liveness past the touch-derived rule
//!   (mirror of `bulk_set_client_hashrate` deliberately not bumping
//!   `updatedAt`).
//!
//! Both writes are Lua scripts so HSET and EXPIRE land as one
//! indivisible step: prod Redis runs `volatile-lru`, where a key that
//! ever exists without a TTL is both immortal and un-evictable (same
//! guard as `device:live:*` and the coinbase snapshots).
//!
//! `best_difficulty` is max-merged against the stored value inside the
//! script. The touch buffer only maxes within one 30 s flush window, so
//! a plain HSET would let a later window regress the session's best;
//! Postgres gets the same cross-flush monotonicity from `GREATEST`.

use bp_common::live_client_key::client_live_key;
use hashbrown::HashMap;
use redis::aio::ConnectionManager;
use tokio::time::Duration;

use crate::touch_buffer::{TouchEntry, TouchKey};

/// Keys per script invocation. ~700 active sessions on prod today, so a
/// flush is 2 round trips; the cap keeps one EVAL's argument list (and
/// its blocking time on the server) bounded if the pool grows 10×.
const CHUNK: usize = 400;

/// Touch write. `ARGV[1]` = TTL seconds, then a stride of 4 per key:
/// best difficulty, current difficulty (empty string = "no sample", the
/// `Option::None` mirror of the SQL `COALESCE`), channel count,
/// last-seen epoch-ms.
const TOUCH_LIVE_LUA: &str = r#"
local ttl = tonumber(ARGV[1])
for i = 1, #KEYS do
    local base = 1 + (i - 1) * 4
    local key = KEYS[i]
    local best = tonumber(ARGV[base + 1])
    local prev = tonumber(redis.call('HGET', key, 'best_difficulty'))
    if prev and prev > best then
        best = prev
    end
    redis.call('HSET', key,
        'best_difficulty', tostring(best),
        'channel_count', ARGV[base + 3],
        'updated_at_ms', ARGV[base + 4])
    if ARGV[base + 2] ~= '' then
        redis.call('HSET', key, 'current_difficulty', ARGV[base + 2])
    end
    redis.call('EXPIRE', key, ttl)
end
return #KEYS
"#;

/// Sampler write. `ARGV[1]` = TTL seconds, then one hashrate per key.
/// The conditional EXPIRE is the immortal-key guard only: it fires when
/// this HSET created the key (TTL == -1), never to refresh a live one.
const HASHRATE_LIVE_LUA: &str = r#"
local ttl = tonumber(ARGV[1])
for i = 1, #KEYS do
    redis.call('HSET', KEYS[i], 'hash_rate', ARGV[i + 1])
    if redis.call('TTL', KEYS[i]) == -1 then
        redis.call('EXPIRE', KEYS[i], ttl)
    end
end
return #KEYS
"#;

/// One prepared script invocation: parallel key / argument lists (the
/// TTL is prepended at invoke time). Split out as data so the batch
/// layout is unit-testable without a Redis server.
struct Batch {
    keys: Vec<String>,
    args: Vec<String>,
}

/// Chunked touch batches, stride 4 (see [`TOUCH_LIVE_LUA`]).
fn build_touch_batches(snapshot: &HashMap<TouchKey, TouchEntry>) -> Vec<Batch> {
    let entries: Vec<(&TouchKey, &TouchEntry)> = snapshot.iter().collect();
    entries
        .chunks(CHUNK)
        .map(|chunk| {
            let mut keys = Vec::with_capacity(chunk.len());
            let mut args = Vec::with_capacity(chunk.len() * 4);
            for (k, v) in chunk {
                keys.push(client_live_key(&k.address, &k.client_name, &k.session_id));
                args.push(v.share_diff.to_string());
                args.push(v.current_diff.map(|d| d.to_string()).unwrap_or_default());
                args.push(v.channel_count.to_string());
                args.push(v.updated_at_ms.to_string());
            }
            Batch { keys, args }
        })
        .collect()
}

/// Chunked sampler batches, stride 1 (see [`HASHRATE_LIVE_LUA`]).
fn build_hashrate_batches(writes: &[(TouchKey, f64)]) -> Vec<Batch> {
    writes
        .chunks(CHUNK)
        .map(|chunk| {
            let mut keys = Vec::with_capacity(chunk.len());
            let mut args = Vec::with_capacity(chunk.len());
            for (k, rate) in chunk {
                keys.push(client_live_key(&k.address, &k.client_name, &k.session_id));
                args.push(rate.to_string());
            }
            Batch { keys, args }
        })
        .collect()
}

/// Shared store handle. `ConnectionManager` is `Clone` + internally
/// multiplexed, so the flush loops clone it per call like every other
/// Redis user in the workspace.
pub(crate) struct LiveSessionStore {
    conn: ConnectionManager,
    ttl_secs: i64,
    touch_script: redis::Script,
    hashrate_script: redis::Script,
}

impl LiveSessionStore {
    pub(crate) fn new(conn: ConnectionManager, ttl: Duration) -> Self {
        Self {
            conn,
            ttl_secs: ttl.as_secs().max(1) as i64,
            touch_script: redis::Script::new(TOUCH_LIVE_LUA),
            hashrate_script: redis::Script::new(HASHRATE_LIVE_LUA),
        }
    }

    async fn invoke(&self, script: &redis::Script, batch: &Batch) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        let mut invocation = script.prepare_invoke();
        invocation.arg(self.ttl_secs);
        for key in &batch.keys {
            invocation.key(key);
        }
        for arg in &batch.args {
            invocation.arg(arg);
        }
        let _: i64 = invocation.invoke_async(&mut conn).await?;
        Ok(())
    }

    /// Mirror one touch-flush snapshot into the live hashes. Stops at the
    /// first failed chunk — the next flush rewrites every field anyway
    /// (and `best_difficulty` is max-merged, so a rewrite can't regress).
    pub(crate) async fn write_touch_batch(
        &self,
        snapshot: &HashMap<TouchKey, TouchEntry>,
    ) -> Result<(), redis::RedisError> {
        for batch in build_touch_batches(snapshot) {
            self.invoke(&self.touch_script, &batch).await?;
        }
        Ok(())
    }

    /// Mirror one sampler pass into the live hashes.
    pub(crate) async fn write_hashrate_batch(
        &self,
        writes: &[(TouchKey, f64)],
    ) -> Result<(), redis::RedisError> {
        for batch in build_hashrate_batches(writes) {
            self.invoke(&self.hashrate_script, &batch).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::live_client_key::{
        F_BEST_DIFFICULTY, F_CHANNEL_COUNT, F_CURRENT_DIFFICULTY, F_HASH_RATE, F_UPDATED_AT_MS,
    };

    fn key(n: usize) -> TouchKey {
        TouchKey {
            address: format!("addr{n}"),
            client_name: "wkr".to_string(),
            session_id: "sess".to_string(),
        }
    }

    fn entry() -> TouchEntry {
        TouchEntry {
            share_diff: 100.5,
            current_diff: Some(64.0),
            channel_count: 2,
            updated_at_ms: 1_700_000_000_000,
        }
    }

    // The Lua bodies spell the field names as literals; this pins them to
    // the shared schema constants so neither side can drift alone.
    #[test]
    fn lua_field_names_match_the_shared_schema() {
        for field in [
            F_BEST_DIFFICULTY,
            F_CURRENT_DIFFICULTY,
            F_CHANNEL_COUNT,
            F_UPDATED_AT_MS,
        ] {
            assert!(
                TOUCH_LIVE_LUA.contains(&format!("'{field}'")),
                "touch script lost field {field}"
            );
        }
        assert!(HASHRATE_LIVE_LUA.contains(&format!("'{F_HASH_RATE}'")));
    }

    #[test]
    fn touch_batch_layout_is_stride_four_per_key() {
        let mut snap = HashMap::new();
        snap.insert(key(1), entry());
        let batches = build_touch_batches(&snap);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].keys.len(), 1);
        assert_eq!(
            batches[0].args,
            vec!["100.5", "64", "2", "1700000000000"],
            "stride must be best, current, channels, updated_at"
        );
    }

    #[test]
    fn absent_current_difficulty_encodes_as_empty_string() {
        let mut snap = HashMap::new();
        snap.insert(
            key(1),
            TouchEntry {
                current_diff: None,
                ..entry()
            },
        );
        let batches = build_touch_batches(&snap);
        assert_eq!(batches[0].args[1], "", "None sentinel is the empty string");
    }

    #[test]
    fn batches_chunk_at_the_cap() {
        let mut snap = HashMap::new();
        for n in 0..CHUNK + 1 {
            snap.insert(key(n), entry());
        }
        let batches = build_touch_batches(&snap);
        assert_eq!(batches.len(), 2, "CHUNK+1 entries need a second invocation");
        assert_eq!(batches[0].keys.len() + batches[1].keys.len(), CHUNK + 1);
        assert_eq!(batches[0].args.len(), batches[0].keys.len() * 4);

        let writes: Vec<(TouchKey, f64)> = (0..CHUNK + 1).map(|n| (key(n), 1.0)).collect();
        let batches = build_hashrate_batches(&writes);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].args.len(), batches[0].keys.len());
    }
}
