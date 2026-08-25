// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Dual-write integration tests for the `client:live:*` mirror: every
//! touch flush and sampler pass must land in BOTH Postgres and the
//! per-session Redis hash, with the TTL semantics the live store
//! promises (touch refreshes liveness, the sampler never does), and a
//! Redis outage must never touch the PG path.
//!
//! Needs `bp-test-pg` (15433) and `bp-test-redis` (16379) — every test
//! skips when a service is unreachable, so watch the passed-count.

use std::collections::HashMap;
use std::time::Duration;

use bp_common::live_client_key::{
    client_live_key, F_BEST_DIFFICULTY, F_CHANNEL_COUNT, F_CURRENT_DIFFICULTY, F_HASH_RATE,
    F_UPDATED_AT_MS,
};
use bp_session_persistence::{
    SessionPersistenceConfig, SessionPersistenceEngine, SessionPersistenceEngineHandle,
};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use bp_test_support::{connect_redis_in_range_or_skip, redis_db, redis_db_in_range};
use redis::aio::ConnectionManager;
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

async fn pg_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_PG_URL.to_string());
    match tokio::time::timeout(
        Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

async fn cleanup(pool: &PgPool, prefix: &str) {
    for sql in [
        r#"DELETE FROM client_entity WHERE address LIKE $1"#,
        r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#,
    ] {
        let _ = sqlx::query(sql)
            .bind(format!("{prefix}%"))
            .execute(pool)
            .await;
    }
}

async fn spawn_engine(pool: &PgPool, redis: ConnectionManager) -> SessionPersistenceEngineHandle {
    SessionPersistenceEngine::spawn(
        SessionPersistenceConfig::default(),
        pool.clone(),
        Some(redis),
    )
    .await
    .expect("spawn engine")
}

fn share<'a>(
    address: &'a str,
    worker: &'a str,
    session_id: &'a str,
    submission_difficulty: f64,
    effective_difficulty: f64,
    channel_count: u32,
) -> SharedAcceptedShare<'a> {
    SharedAcceptedShare {
        address,
        worker,
        session_id,
        effective_difficulty,
        submission_difficulty,
        user_agent: Some("bitaxe"),
        is_block_candidate: false,
        hash_rate: 0.0,
        channel_count,
        ts_ms: 0,
        share_id: "",
        mode: bp_share_hook::MiningMode::Solo,
        group_id: None,
    }
}

async fn hgetall(conn: &mut ConnectionManager, key: &str) -> HashMap<String, String> {
    redis::cmd("HGETALL")
        .arg(key)
        .query_async(conn)
        .await
        .expect("HGETALL")
}

async fn ttl(conn: &mut ConnectionManager, key: &str) -> i64 {
    redis::cmd("TTL")
        .arg(key)
        .query_async(conn)
        .await
        .expect("TTL")
}

/// One touch flush must land in both stores, and the Redis hash must
/// carry a TTL — a Lua body that lost its EXPIRE leaves TTL = -1, which
/// under prod's `volatile-lru` is an immortal, un-evictable key.
#[tokio::test]
async fn touch_flush_dual_writes_hash_and_ttl() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 0).await
    else {
        return;
    };
    let prefix = "test_lv_dual_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}alice");

    hook.register_session("sessL001", &address, "rig1", Some("bitaxe"))
        .await;
    handle.flush_births_now().await;
    sink.record_accepted(share(&address, "rig1", "sessL001", 100.5, 64.0, 2))
        .await;

    let rows = handle.flush_touches_now().await;
    assert_eq!(rows, 1, "touch flush must hit the born PG row");

    // PG got the touch.
    let best: f32 =
        sqlx::query_scalar(r#"SELECT "bestDifficulty" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessL001")
            .fetch_one(&pool)
            .await
            .expect("PG best");
    assert!((best - 100.5).abs() < 0.01, "PG bestDifficulty, got {best}");

    // Redis got the mirror.
    let key = client_live_key(&address, "rig1", "sessL001");
    let hash = hgetall(&mut redis, &key).await;
    assert_eq!(
        hash.get(F_BEST_DIFFICULTY).map(String::as_str),
        Some("100.5")
    );
    assert_eq!(
        hash.get(F_CURRENT_DIFFICULTY).map(String::as_str),
        Some("64")
    );
    assert_eq!(hash.get(F_CHANNEL_COUNT).map(String::as_str), Some("2"));
    let updated: i64 = hash
        .get(F_UPDATED_AT_MS)
        .expect("updated_at_ms present")
        .parse()
        .expect("updated_at_ms numeric");
    assert!(updated > 0, "updated_at_ms is a share timestamp");

    let t = ttl(&mut redis, &key).await;
    assert!(
        t > 0 && t <= 300,
        "touch write must set the liveness TTL, got {t}"
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// `best_difficulty` must be monotone ACROSS flushes. The touch buffer
/// only maxes within one flush window, so a plain HSET would let a
/// later window regress the stored best — the channel-count change in
/// the same flush is the positive control that the second write landed.
#[tokio::test]
async fn best_difficulty_is_monotone_across_flushes() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 1).await
    else {
        return;
    };
    let prefix = "test_lv_mono_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}bob");
    let key = client_live_key(&address, "rig1", "sessL002");

    hook.register_session("sessL002", &address, "rig1", None)
        .await;
    handle.flush_births_now().await;

    sink.record_accepted(share(&address, "rig1", "sessL002", 100.0, 64.0, 1))
        .await;
    handle.flush_touches_now().await;
    let hash = hgetall(&mut redis, &key).await;
    assert_eq!(hash.get(F_BEST_DIFFICULTY).map(String::as_str), Some("100"));

    // A later window whose best is LOWER must not regress the stored
    // best — while its other fields do overwrite.
    sink.record_accepted(share(&address, "rig1", "sessL002", 50.0, 64.0, 3))
        .await;
    handle.flush_touches_now().await;
    let hash = hgetall(&mut redis, &key).await;
    assert_eq!(
        hash.get(F_CHANNEL_COUNT).map(String::as_str),
        Some("3"),
        "second flush must have landed (latest-wins field)"
    );
    assert_eq!(
        hash.get(F_BEST_DIFFICULTY).map(String::as_str),
        Some("100"),
        "a lower later window must not regress best_difficulty"
    );

    // PG agrees via GREATEST.
    let best: f32 =
        sqlx::query_scalar(r#"SELECT "bestDifficulty" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessL002")
            .fetch_one(&pool)
            .await
            .expect("PG best");
    assert!((best - 100.0).abs() < 0.01, "PG GREATEST, got {best}");

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// The sampler's write must NOT extend a session's liveness — that is
/// the touch path's job, exactly as `bulk_set_client_hashrate`
/// deliberately does not bump `updatedAt` in PG. An unconditional
/// EXPIRE in the hashrate script would reset the 10 s TTL to 300.
#[tokio::test]
async fn hashrate_write_does_not_refresh_liveness() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 2).await
    else {
        return;
    };
    let prefix = "test_lv_nottl_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}carol");
    let key = client_live_key(&address, "rig1", "sessL003");

    hook.register_session("sessL003", &address, "rig1", None)
        .await;
    handle.flush_births_now().await;
    sink.record_accepted(share(&address, "rig1", "sessL003", 100.0, 512.0, 1))
        .await;
    handle.flush_touches_now().await;
    assert!(ttl(&mut redis, &key).await > 10, "touch set the full TTL");

    // Shrink the TTL, then let the sampler write its hashrate.
    let _: i64 = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(10i64)
        .query_async(&mut redis)
        .await
        .expect("EXPIRE");
    handle.sample_hashrate_now(60.0).await;

    let hash = hgetall(&mut redis, &key).await;
    let rate: f64 = hash
        .get(F_HASH_RATE)
        .expect("hash_rate written")
        .parse()
        .expect("hash_rate numeric");
    assert!(rate > 0.0, "sampler wrote a positive rate, got {rate}");
    let t = ttl(&mut redis, &key).await;
    assert!(
        (1..=10).contains(&t),
        "sampler must not extend liveness — TTL was ≤10, now {t}"
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// When the sampler's HSET CREATES the key (share landed after the hash
/// expired), the conditional EXPIRE must still fire — without it the
/// fresh key has no TTL and is immortal under `volatile-lru`. The
/// resulting hash is partial (only `hash_rate`); readers must tolerate
/// that, so the test pins it.
#[tokio::test]
async fn hashrate_write_on_fresh_key_sets_ttl() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 3).await
    else {
        return;
    };
    let prefix = "test_lv_fresh_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}dave");
    let key = client_live_key(&address, "rig1", "sessL004");

    // Feed the sampler but do NOT flush touches — the key must not exist.
    sink.record_accepted(share(&address, "rig1", "sessL004", 100.0, 512.0, 1))
        .await;
    assert_eq!(ttl(&mut redis, &key).await, -2, "key must not exist yet");

    handle.sample_hashrate_now(60.0).await;

    let hash = hgetall(&mut redis, &key).await;
    assert!(hash.contains_key(F_HASH_RATE), "sampler created the key");
    assert!(
        !hash.contains_key(F_CURRENT_DIFFICULTY),
        "sampler-created hash is partial by design"
    );
    let t = ttl(&mut redis, &key).await;
    assert!(
        t > 0,
        "a sampler-created key without TTL is immortal under volatile-lru, got {t}"
    );

    // The unflushed touch buffer would rebuffer into PG on shutdown's
    // final drain against a row that was never born — harmless, but
    // drain it consciously.
    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// A dead Redis must cost nothing but a warning: the PG touch flush has
/// to land and the call has to return. The connection is established
/// through a local TCP proxy that is killed after connect — a
/// `ConnectionManager` cannot be built against an address that never
/// accepted.
#[tokio::test]
async fn redis_down_does_not_break_pg_flush() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    // Resolve the real test-Redis address (for the proxy's upstream) and
    // this test's folded DB index.
    let base_url =
        std::env::var("BP_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:16379".to_string());
    let upstream = base_url
        .trim_start_matches("redis://")
        .split('/')
        .next()
        .map(|hp| hp.rsplit('@').next().unwrap_or(hp).to_string())
        .expect("host:port from BP_REDIS_URL");
    let db = redis_db_in_range(redis_db::SESSION_PERSISTENCE, 4).await;

    // Bidirectional byte proxy; killing it snaps every connection.
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind proxy listener: {e} — skipping");
            return;
        }
    };
    let port = listener.local_addr().expect("proxy addr").port();
    let conns: std::sync::Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Default::default();
    let conns_in_loop = conns.clone();
    let upstream_for_loop = upstream.clone();
    let accept_loop = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let upstream = upstream_for_loop.clone();
            let handle = tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(&upstream).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
            conns_in_loop.lock().unwrap().push(handle);
        }
    });

    let client =
        redis::Client::open(format!("redis://127.0.0.1:{port}/{db}")).expect("proxied client");
    let manager = match tokio::time::timeout(
        Duration::from_secs(2),
        redis::aio::ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(m)) => m,
        _ => {
            eprintln!("test Redis unreachable through proxy — skipping");
            accept_loop.abort();
            return;
        }
    };

    // Kill the proxy: from here every Redis command fails.
    accept_loop.abort();
    for handle in conns.lock().unwrap().drain(..) {
        handle.abort();
    }

    let prefix = "test_lv_down_";
    cleanup(&pool, prefix).await;
    let handle = spawn_engine(&pool, manager).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}erin");

    hook.register_session("sessL005", &address, "rig1", None)
        .await;
    handle.flush_births_now().await;
    sink.record_accepted(share(&address, "rig1", "sessL005", 100.0, 64.0, 1))
        .await;

    let rows = tokio::time::timeout(Duration::from_secs(10), handle.flush_touches_now())
        .await
        .expect("flush must not hang on a dead Redis");
    assert_eq!(rows, 1, "the PG touch must land although Redis is gone");

    let best: f32 =
        sqlx::query_scalar(r#"SELECT "bestDifficulty" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessL005")
            .fetch_one(&pool)
            .await
            .expect("PG best");
    assert!((best - 100.0).abs() < 0.01, "PG got the touch, got {best}");

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}
