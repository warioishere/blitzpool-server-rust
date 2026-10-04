// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis writer for the per-session `client:live:*` hashes. Only the touch
//! flush refreshes the TTL (it is the liveness signal); the watchdog's zero
//! writes must not. HSET and EXPIRE run in one Lua script because under
//! `volatile-lru` a key without a TTL is immortal and un-evictable.

use bp_common::live_client_key::client_live_key;
use hashbrown::HashMap;
use redis::aio::ConnectionManager;
use tokio::time::Duration;

/// Upper bound for one script invocation: a manager mid-reconnect would
/// make the flush loops wait out its whole retry ladder instead of
/// failing fast and rebuffering.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

use crate::touch_buffer::{TouchEntry, TouchKey};

/// Keys per script invocation, bounding one EVAL's server blocking time.
const CHUNK: usize = 400;

/// Touch write. `ARGV[1]` = TTL seconds, then a stride of 5 per key:
/// best difficulty (max-merged with the stored one, so a later flush cannot
/// regress it), current difficulty and hashrate ("" keeps the stored value),
/// channel count, last-seen epoch-ms.
const TOUCH_LIVE_LUA: &str = r#"
local ttl = tonumber(ARGV[1])
for i = 1, #KEYS do
    local base = 1 + (i - 1) * 5
    local key = KEYS[i]
    -- No `or 0` fallback here on purpose: `tonumber` only yields nil
    -- for a string that is not a number at all ("abc", ""), and every
    -- argument is `f32::to_string()`, which always is one. Measured
    -- against this Redis: tonumber("inf") = inf, tonumber("NaN") = nan
    -- — neither is nil. Non-finite values are kept out one layer up, in
    -- `TouchBuffer::record`, because they would poison a reader's sums,
    -- not because they would break this script.
    local best = tonumber(ARGV[base + 1])
    local prev = tonumber(redis.call('HGET', key, 'best_difficulty'))
    if prev and prev > best then
        best = prev
    end
    redis.call('HSET', key,
        'best_difficulty', tostring(best),
        'channel_count', ARGV[base + 4],
        'updated_at_ms', ARGV[base + 5])
    if ARGV[base + 2] ~= '' then
        redis.call('HSET', key, 'current_difficulty', ARGV[base + 2])
    end
    if ARGV[base + 3] ~= '' then
        redis.call('HSET', key, 'hash_rate', ARGV[base + 3])
    end
    redis.call('EXPIRE', key, ttl)
end
return #KEYS
"#;

/// Watchdog write. `ARGV[1]` = TTL seconds, then one hashrate per key.
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

/// One prepared script invocation (TTL prepended at invoke time), kept as
/// data so the layout is testable without Redis.
struct Batch {
    keys: Vec<String>,
    args: Vec<String>,
}

/// Chunked touch batches, stride 5 (see [`TOUCH_LIVE_LUA`]).
fn build_touch_batches(snapshot: &HashMap<TouchKey, TouchEntry>) -> Vec<Batch> {
    let entries: Vec<(&TouchKey, &TouchEntry)> = snapshot.iter().collect();
    entries
        .chunks(CHUNK)
        .map(|chunk| {
            let mut keys = Vec::with_capacity(chunk.len());
            let mut args = Vec::with_capacity(chunk.len() * 5);
            for (k, v) in chunk {
                keys.push(client_live_key(&k.address, &k.client_name, &k.session_id));
                args.push(v.share_diff.to_string());
                args.push(v.current_diff.map(|d| d.to_string()).unwrap_or_default());
                args.push(v.hash_rate.map(|r| r.to_string()).unwrap_or_default());
                args.push(v.channel_count.to_string());
                args.push(v.updated_at_ms.to_string());
            }
            Batch { keys, args }
        })
        .collect()
}

/// Chunked watchdog batches, stride 1 (see [`HASHRATE_LIVE_LUA`]).
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
        match tokio::time::timeout(WRITE_TIMEOUT, invocation.invoke_async::<i64>(&mut conn)).await {
            Ok(result) => {
                result?;
                Ok(())
            }
            Err(_) => Err((redis::ErrorKind::Io, "live-store write timed out").into()),
        }
    }

    /// Mirror one touch-flush snapshot. Every chunk is attempted even after a
    /// failure, or the sessions behind it would miss their TTL refresh and be
    /// swept while still hashing; the first error is returned at the end.
    pub(crate) async fn write_touch_batch(
        &self,
        snapshot: &HashMap<TouchKey, TouchEntry>,
    ) -> Result<(), redis::RedisError> {
        self.invoke_all(&self.touch_script, build_touch_batches(snapshot))
            .await
    }

    /// Mirror one watchdog pass into the live hashes. Same all-chunks
    /// rule as [`Self::write_touch_batch`].
    pub(crate) async fn write_hashrate_batch(
        &self,
        writes: &[(TouchKey, f64)],
    ) -> Result<(), redis::RedisError> {
        self.invoke_all(&self.hashrate_script, build_hashrate_batches(writes))
            .await
    }

    async fn invoke_all(
        &self,
        script: &redis::Script,
        batches: Vec<Batch>,
    ) -> Result<(), redis::RedisError> {
        let mut first_err = None;
        for batch in batches {
            if let Err(e) = self.invoke(script, &batch).await {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::live_client_key::{
        F_BEST_DIFFICULTY, F_CHANNEL_COUNT, F_CURRENT_DIFFICULTY, F_HASH_RATE, F_UPDATED_AT_MS,
    };
    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};

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
            hash_rate: Some(5.0e12),
            channel_count: 2,
            updated_at_ms: 1_700_000_000_000,
        }
    }

    // The Lua field-name literals match the shared schema constants.
    #[test]
    fn lua_field_names_match_the_shared_schema() {
        for field in [
            F_BEST_DIFFICULTY,
            F_CURRENT_DIFFICULTY,
            F_HASH_RATE,
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
    fn touch_batch_layout_is_stride_five_per_key() {
        let mut snap = HashMap::new();
        snap.insert(key(1), entry());
        let batches = build_touch_batches(&snap);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].keys.len(), 1);
        assert_eq!(
            batches[0].args,
            vec!["100.5", "64", "5000000000000", "2", "1700000000000"],
            "stride must be best, current, hashrate, channels, updated_at"
        );
    }

    #[test]
    fn absent_current_difficulty_encodes_as_empty_string() {
        let mut snap = HashMap::new();
        snap.insert(
            key(1),
            TouchEntry {
                current_diff: None,
                hash_rate: None,
                ..entry()
            },
        );
        let batches = build_touch_batches(&snap);
        assert_eq!(batches[0].args[1], "", "None sentinel is the empty string");
        assert_eq!(batches[0].args[2], "", "None sentinel is the empty string");
    }

    /// A failing first chunk does not stop the second from being written.
    #[tokio::test]
    async fn a_failing_chunk_does_not_stop_the_later_ones() {
        let Some(mut conn) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 8).await
        else {
            return;
        };
        let mut snap = HashMap::new();
        for n in 0..=CHUNK {
            snap.insert(key(n), entry());
        }
        let batches = build_touch_batches(&snap);
        assert_eq!(batches.len(), 2, "fixture must span two chunks");
        // A string where the script wants a hash fails that chunk's EVAL.
        let poisoned = batches[0].keys[0].clone();
        let _: () = redis::cmd("SET")
            .arg(&poisoned)
            .arg("not-a-hash")
            .query_async(&mut conn)
            .await
            .expect("poison");

        let store = LiveSessionStore::new(conn.clone(), Duration::from_secs(300));
        let err = store.write_touch_batch(&snap).await;
        assert!(err.is_err(), "the failure is still reported to the caller");

        for k in &batches[1].keys {
            let written: i64 = redis::cmd("EXISTS")
                .arg(k)
                .query_async(&mut conn)
                .await
                .expect("exists");
            assert_eq!(
                written, 1,
                "second chunk must be written despite chunk 1 failing"
            );
        }
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
        assert_eq!(batches[0].args.len(), batches[0].keys.len() * 5);

        let writes: Vec<(TouchKey, f64)> = (0..CHUNK + 1).map(|n| (key(n), 1.0)).collect();
        let batches = build_hashrate_batches(&writes);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].args.len(), batches[0].keys.len());
    }
}
