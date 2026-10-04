// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one reader of the live session hashes (`client:live:*`, schema in
//! [`bp_common::live_client_key`]). Any key or field can be missing (TTL,
//! eviction) and counts as 0, but a derived 0 must never be written back to
//! durable storage. No Redis handle is an error, never a silent 0.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::time::Duration;

use bp_common::live_client_key::{
    self as live_key, SessionKey, CLIENT_LIVE_PREFIX, F_BEST_DIFFICULTY, F_HASH_RATE, KEY_SEP,
    SCAN_PATTERN_ALL,
};
use bp_common::AddressId;
use redis::aio::ConnectionManager;

/// `HGET`s per pipeline round trip.
const FETCH_CHUNK: usize = 500;

/// Upper bound for one Redis round-trip. A reconnecting `ConnectionManager`
/// would otherwise make callers wait out its retry ladder (minutes); every
/// consumer already handles "no answer", a hang is strictly worse.
pub const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(5);

/// Run one Redis round-trip under [`ROUND_TRIP_TIMEOUT`]; used by every
/// live read, including the binary's.
pub async fn bounded<T>(
    fut: impl Future<Output = Result<T, redis::RedisError>>,
) -> Result<T, LiveReadError> {
    match tokio::time::timeout(ROUND_TRIP_TIMEOUT, fut).await {
        Ok(result) => result.map_err(LiveReadError::from),
        Err(_) => Err(LiveReadError::Timeout(ROUND_TRIP_TIMEOUT)),
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LiveReadError {
    /// An error so no caller mistakes "cannot know" for zero hashrate.
    #[error("live store not configured (no Redis handle)")]
    NotConfigured,
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    /// Connection down or mid-reconnect; handle like any Redis error.
    #[error("redis round-trip exceeded {0:?}")]
    Timeout(Duration),
}

/// The `address` component of a live key, or `None` for a key that
/// doesn't parse (foreign key caught by the pattern, truncated write).
fn address_of(key: &str) -> Option<&str> {
    key.strip_prefix(CLIENT_LIVE_PREFIX)?.split(KEY_SEP).next()
}

/// Cursor-complete `SCAN MATCH pattern`. The sum readers scan everything
/// once and filter afterwards, which beats one `SCAN` per address.
async fn scan_keys(
    conn: &mut ConnectionManager,
    pattern: &str,
) -> Result<Vec<String>, LiveReadError> {
    let mut keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = bounded(
            redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(200)
                .query_async(conn),
        )
        .await?;
        keys.extend(batch);
        cursor = next;
        if cursor == 0 {
            return Ok(keys);
        }
    }
}

async fn scan_live_keys(conn: &mut ConnectionManager) -> Result<Vec<String>, LiveReadError> {
    scan_keys(conn, SCAN_PATTERN_ALL).await
}

/// Pipelined `HGET hash_rate` over `keys`, summed per key's address
/// into `acc`. A key that expired between SCAN and HGET, or a partial
/// hash without the field yet, contributes nothing.
async fn accumulate_rates(
    conn: &mut ConnectionManager,
    keys: &[String],
    acc: &mut HashMap<String, f64>,
) -> Result<(), LiveReadError> {
    for chunk in keys.chunks(FETCH_CHUNK) {
        let mut pipe = redis::pipe();
        for key in chunk {
            pipe.cmd("HGET").arg(key).arg(F_HASH_RATE);
        }
        let rates: Vec<Option<String>> = bounded(pipe.query_async(conn)).await?;
        for (key, rate) in chunk.iter().zip(rates) {
            let (Some(addr), Some(rate)) = (address_of(key), rate) else {
                continue;
            };
            let Ok(rate) = rate.parse::<f64>() else {
                continue;
            };
            if let Some(sum) = acc.get_mut(addr) {
                *sum += rate;
            } else {
                acc.insert(addr.to_string(), rate);
            }
        }
    }
    Ok(())
}

/// Live hashrate of the whole pool; the key's TTL is the liveness clock.
pub async fn pool_hashrate(redis: Option<&ConnectionManager>) -> Result<f64, LiveReadError> {
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let keys = scan_live_keys(&mut conn).await?;
    let mut acc = HashMap::new();
    accumulate_rates(&mut conn, &keys, &mut acc).await?;
    Ok(acc.values().sum())
}

/// Every requested address is in the result, 0.0 without a live session.
pub async fn hashrate_by_address(
    redis: Option<&ConnectionManager>,
    addresses: &[AddressId],
) -> Result<HashMap<String, f64>, LiveReadError> {
    let mut acc: HashMap<String, f64> = addresses
        .iter()
        .map(|a| (a.as_str().to_string(), 0.0))
        .collect();
    if addresses.is_empty() {
        return Ok(acc);
    }
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let wanted: HashSet<&str> = addresses.iter().map(|a| a.as_str()).collect();
    let keys: Vec<String> = scan_live_keys(&mut conn)
        .await?
        .into_iter()
        .filter(|k| address_of(k).is_some_and(|a| wanted.contains(a)))
        .collect();
    accumulate_rates(&mut conn, &keys, &mut acc).await?;
    Ok(acc)
}

/// Empty input returns `0.0` without touching Redis.
pub async fn hashrate_for_addresses(
    redis: Option<&ConnectionManager>,
    addresses: &[AddressId],
) -> Result<f64, LiveReadError> {
    if addresses.is_empty() {
        return Ok(0.0);
    }
    Ok(hashrate_by_address(redis, addresses).await?.values().sum())
}

/// So a purged miner stops reporting hashrate before the TTL. Best-effort:
/// a concurrent flush may rewrite a key, which then ages out normally.
pub async fn delete_address_live_keys(
    redis: Option<&ConnectionManager>,
    address: &AddressId,
) -> Result<u64, LiveReadError> {
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let keys = scan_keys(
        &mut conn,
        &live_key::scan_pattern_for_address(address.as_str()),
    )
    .await?;
    let mut deleted = 0u64;
    for chunk in keys.chunks(FETCH_CHUNK) {
        let mut cmd = redis::cmd("DEL");
        for key in chunk {
            cmd.arg(key);
        }
        let n: u64 = bounded(cmd.query_async(&mut conn)).await?;
        deleted += n;
    }
    Ok(deleted)
}

/// Session half of a best-difficulty reset, else every worker row keeps the
/// old value. `HDEL`, not `HSET 0`: a missing field means "no sample yet",
/// a 0 would render as a best of zero. A share landing mid-clear sets the
/// correct post-reset value anyway.
pub async fn clear_address_best_difficulty(
    redis: Option<&ConnectionManager>,
    address: &AddressId,
) -> Result<u64, LiveReadError> {
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let keys = scan_keys(
        &mut conn,
        &live_key::scan_pattern_for_address(address.as_str()),
    )
    .await?;
    let mut cleared = 0u64;
    for chunk in keys.chunks(FETCH_CHUNK) {
        let mut pipe = redis::pipe();
        for key in chunk {
            pipe.cmd("HDEL").arg(key).arg(F_BEST_DIFFICULTY);
        }
        let removed: Vec<u64> = bounded(pipe.query_async(&mut conn)).await?;
        cleared += removed.iter().sum::<u64>();
    }
    Ok(cleared)
}

/// Pipelined `EXISTS`, positionally aligned. The liveness sweep must SKIP
/// on an error, never sweep: "cannot ask Redis" is not "no key".
pub async fn live_keys_exist<S: SessionKey>(
    redis: Option<&ConnectionManager>,
    sessions: &[S],
) -> Result<Vec<bool>, LiveReadError> {
    if sessions.is_empty() {
        return Ok(Vec::new());
    }
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let mut out = Vec::with_capacity(sessions.len());
    for chunk in sessions.chunks(FETCH_CHUNK) {
        let mut pipe = redis::pipe();
        for s in chunk {
            pipe.cmd("EXISTS").arg(live_key::key_of(s));
        }
        let flags: Vec<bool> = bounded(pipe.query_async(&mut conn)).await?;
        out.extend(flags);
    }
    Ok(out)
}

/// The live half of one session. Missing fields default to 0 / `None`; a
/// wholly missing hash is `None` from [`live_fields_for_sessions`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LiveFields {
    pub hash_rate: f64,
    pub current_difficulty: Option<f64>,
    /// `None` on a watchdog-created partial hash — render as 1 channel.
    pub channel_count: Option<i32>,
    pub best_difficulty: f64,
    /// Epoch-ms of the freshest accepted share.
    pub updated_at_ms: Option<i64>,
}

fn parse_live_fields(pairs: Vec<(String, String)>) -> Option<LiveFields> {
    if pairs.is_empty() {
        return None;
    }
    let mut lf = LiveFields::default();
    for (field, value) in pairs {
        match field.as_str() {
            live_key::F_HASH_RATE => lf.hash_rate = value.parse().unwrap_or(0.0),
            live_key::F_CURRENT_DIFFICULTY => lf.current_difficulty = value.parse().ok(),
            live_key::F_CHANNEL_COUNT => lf.channel_count = value.parse().ok(),
            live_key::F_BEST_DIFFICULTY => lf.best_difficulty = value.parse().unwrap_or(0.0),
            live_key::F_UPDATED_AT_MS => lf.updated_at_ms = value.parse().ok(),
            _ => {}
        }
    }
    Some(lf)
}

/// Live fields per session, positionally aligned; `None` = no live hash.
/// Every "PG birth row + live fields" reader goes through here.
pub async fn live_fields_for_sessions<S: SessionKey>(
    redis: Option<&ConnectionManager>,
    sessions: &[S],
) -> Result<Vec<Option<LiveFields>>, LiveReadError> {
    if sessions.is_empty() {
        return Ok(Vec::new());
    }
    let mut conn = redis.ok_or(LiveReadError::NotConfigured)?.clone();
    let mut out = Vec::with_capacity(sessions.len());
    for chunk in sessions.chunks(FETCH_CHUNK) {
        let mut pipe = redis::pipe();
        for s in chunk {
            pipe.cmd("HGETALL").arg(live_key::key_of(s));
        }
        let hashes: Vec<Vec<(String, String)>> = bounded(pipe.query_async(&mut conn)).await?;
        out.extend(hashes.into_iter().map(parse_live_fields));
    }
    Ok(out)
}

/// The PG half of a session for the user-agent aggregation.
#[derive(Clone, Debug)]
pub struct UserAgentSessionRow {
    pub user_agent: Option<String>,
    pub address: String,
    pub worker: String,
    pub session_id: String,
}

impl SessionKey for UserAgentSessionRow {
    fn address(&self) -> &str {
        &self.address
    }
    fn worker(&self) -> &str {
        &self.worker
    }
    fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// One `GROUP BY userAgent` row, as `/api/info` and `/api/pplns` serialize.
#[derive(Clone, Debug)]
pub struct UserAgentAgg {
    pub user_agent: Option<String>,
    pub count: i64,
    pub best_difficulty: f64,
    pub total_hash_rate: f64,
}

/// Ordered by `count` descending. The NULL-user-agent group reports
/// `count = 0` but keeps its sums (`COUNT("userAgent")` semantics).
pub async fn aggregate_by_user_agent(
    redis: Option<&ConnectionManager>,
    rows: &[UserAgentSessionRow],
) -> Result<Vec<UserAgentAgg>, LiveReadError> {
    let live = live_fields_for_sessions(redis, rows).await?;
    Ok(group_user_agents(rows, &live))
}

/// The same grouping without live data, for when Redis is unreachable.
pub fn aggregate_offline(rows: &[UserAgentSessionRow]) -> Vec<UserAgentAgg> {
    let none: Vec<Option<LiveFields>> = vec![None; rows.len()];
    group_user_agents(rows, &none)
}

/// Pure half of [`aggregate_by_user_agent`], testable without Redis.
fn group_user_agents(
    rows: &[UserAgentSessionRow],
    live: &[Option<LiveFields>],
) -> Vec<UserAgentAgg> {
    let mut groups: HashMap<Option<&str>, UserAgentAgg> = HashMap::new();
    for (row, lf) in rows.iter().zip(live) {
        let entry = groups
            .entry(row.user_agent.as_deref())
            .or_insert_with(|| UserAgentAgg {
                user_agent: row.user_agent.clone(),
                count: 0,
                best_difficulty: 0.0,
                total_hash_rate: 0.0,
            });
        if row.user_agent.is_some() {
            entry.count += 1;
        }
        if let Some(lf) = lf {
            entry.total_hash_rate += lf.hash_rate;
            entry.best_difficulty = entry.best_difficulty.max(lf.best_difficulty);
        }
    }
    let mut out: Vec<UserAgentAgg> = groups.into_values().collect();
    // Tie-break by name: hashbrown's iteration order is seeded per
    // map, so equal counts would reshuffle between cache refreshes.
    out.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.user_agent.cmp(&b.user_agent))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::live_client_key::client_live_key;

    #[test]
    fn address_parses_out_of_a_live_key() {
        let key = client_live_key("bc1qaddr", "rig-a", "ab12cd34");
        assert_eq!(address_of(&key), Some("bc1qaddr"));
    }

    #[test]
    fn worker_and_session_never_leak_into_the_address() {
        // A worker name containing a colon must not confuse the parse —
        // only the unit separator splits components.
        let key = client_live_key("bc1qaddr", "rig:a:1", "sess");
        assert_eq!(address_of(&key), Some("bc1qaddr"));
    }

    #[test]
    fn foreign_keys_do_not_parse() {
        assert_eq!(address_of("pplns:window:total"), None);
    }

    #[test]
    fn live_fields_parse_tolerates_partial_hashes() {
        // Watchdog-created hash: only hash_rate.
        let lf = parse_live_fields(vec![("hash_rate".into(), "1234.5".into())]).unwrap();
        assert_eq!(lf.hash_rate, 1234.5);
        assert_eq!(
            lf.best_difficulty, 0.0,
            "absent best defaults like the PG column"
        );
        assert_eq!(lf.channel_count, None);
        // Empty hash = missing key (HGETALL on a missing key is empty).
        assert_eq!(parse_live_fields(vec![]), None);
        // Unknown fields are ignored, not an error.
        let lf = parse_live_fields(vec![
            ("best_difficulty".into(), "7.5".into()),
            ("some_future_field".into(), "x".into()),
        ])
        .unwrap();
        assert_eq!(lf.best_difficulty, 7.5);
    }

    #[test]
    fn user_agent_grouping_keeps_the_sql_count_semantics() {
        let row = |ua: Option<&str>, n: usize| UserAgentSessionRow {
            user_agent: ua.map(String::from),
            address: format!("addr{n}"),
            worker: "w".into(),
            session_id: format!("s{n}"),
        };
        let lf = |hr: f64, best: f64| {
            Some(LiveFields {
                hash_rate: hr,
                best_difficulty: best,
                ..Default::default()
            })
        };
        let rows = vec![
            row(Some("bitaxe"), 1),
            row(Some("bitaxe"), 2),
            row(None, 3),
            row(Some("nerdminer"), 4),
        ];
        // Session 2 has no live hash at all — counted, but contributes
        // no numbers (a PG-active row whose Redis key expired).
        let live = vec![lf(10.0, 5.0), None, lf(3.0, 9.0), lf(1.0, 1.0)];
        let out = group_user_agents(&rows, &live);
        assert_eq!(out.len(), 3);
        let bitaxe = out
            .iter()
            .find(|g| g.user_agent.as_deref() == Some("bitaxe"))
            .unwrap();
        assert_eq!(bitaxe.count, 2, "count counts rows, not live hashes");
        assert_eq!(bitaxe.total_hash_rate, 10.0);
        assert_eq!(bitaxe.best_difficulty, 5.0);
        let null_group = out.iter().find(|g| g.user_agent.is_none()).unwrap();
        assert_eq!(
            null_group.count, 0,
            "SQL COUNT(col) parity: NULL group counts 0"
        );
        assert_eq!(null_group.total_hash_rate, 3.0);
        assert_eq!(
            out[0].user_agent.as_deref(),
            Some("bitaxe"),
            "ordered by count DESC"
        );
    }

    #[tokio::test]
    async fn no_redis_handle_is_an_error_not_a_zero() {
        assert!(matches!(
            pool_hashrate(None).await,
            Err(LiveReadError::NotConfigured)
        ));
        let addr = AddressId::new("bc1qaddr").unwrap();
        assert!(matches!(
            hashrate_for_addresses(None, std::slice::from_ref(&addr)).await,
            Err(LiveReadError::NotConfigured)
        ));
        // The empty-input fast path never needs Redis.
        assert_eq!(hashrate_for_addresses(None, &[]).await.unwrap(), 0.0);
    }
}
