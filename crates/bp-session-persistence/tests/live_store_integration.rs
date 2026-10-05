// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Integration tests for the `client:live:*` live store: touch refreshes
//! liveness, the hashrate watchdog never does, and a Redis outage never hangs a flush.
//! Needs `bp-test-pg` (15433) and `bp-test-redis` (16379); every test skips
//! when a service is unreachable, so watch the passed-count.

use std::collections::HashMap;
use std::time::Duration;

use bp_common::live_client_key::{
    client_live_key, F_CHANNEL_COUNT, F_CURRENT_DIFFICULTY, F_HASH_RATE, F_UPDATED_AT_MS,
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
        ts_ms: bp_common::now_ms(),
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

async fn row_best(pool: &PgPool, session_id: &str) -> f64 {
    sqlx::query_scalar(r#"SELECT "bestDifficulty" FROM client_entity WHERE "sessionId" = $1"#)
        .bind(session_id)
        .fetch_one(pool)
        .await
        .expect("session row")
}

async fn ttl(conn: &mut ConnectionManager, key: &str) -> i64 {
    redis::cmd("TTL")
        .arg(key)
        .query_async(conn)
        .await
        .expect("TTL")
}

/// A touch flush lands the best on the row and the rest in the session hash
/// with a TTL (none = immortal under `volatile-lru`).
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
    assert_eq!(rows, 1, "flush reports the session it wrote");

    assert_eq!(
        row_best(&pool, "sessL001").await,
        100.5,
        "the row got the best"
    );

    // Redis got the touch.
    let key = client_live_key(&address, "rig1", "sessL001");
    let hash = hgetall(&mut redis, &key).await;
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

/// `updated_at_ms` is the front's accept time, not this process's consume time.
#[tokio::test]
async fn a_late_consumed_share_keeps_its_acceptance_time() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 9).await
    else {
        return;
    };
    let prefix = "test_lv_late_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}alice");

    // Accepted a minute ago, consumed now.
    let accepted_at = bp_common::now_ms() - 60_000;
    sink.record_accepted(SharedAcceptedShare {
        ts_ms: accepted_at,
        ..share(&address, "rig1", "sessL009", 100.0, 64.0, 1)
    })
    .await;
    handle.flush_touches_now().await;

    let key = client_live_key(&address, "rig1", "sessL009");
    let updated: i64 = hgetall(&mut redis, &key)
        .await
        .get(F_UPDATED_AT_MS)
        .expect("updated_at_ms present")
        .parse()
        .expect("updated_at_ms numeric");
    assert_eq!(updated, accepted_at);

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// The shared reset zeroes the session bests of one address only; a lower
/// share then sets the best afresh.
#[tokio::test]
async fn a_reset_zeroes_one_addresss_session_bests() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 7).await else {
        return;
    };
    let prefix = "test_lv_clear_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let mine = format!("{prefix}alice");
    let other = format!("{prefix}bob");

    hook.register_session("sessC001", &mine, "rig1", Some("GMiner"))
        .await;
    hook.register_session("sessC002", &other, "rig1", Some("bitaxe"))
        .await;
    handle.flush_births_now().await;
    sink.record_accepted(share(&mine, "rig1", "sessC001", 100.5, 64.0, 2))
        .await;
    sink.record_accepted(share(&other, "rig1", "sessC002", 543.5, 32.0, 1))
        .await;
    handle.flush_touches_now().await;
    assert_eq!(
        row_best(&pool, "sessC001").await,
        100.5,
        "precondition: the session recorded a best to reset"
    );

    bp_db::reset_address_settings_best_difficulty(
        &pool,
        &bp_common::AddressId::new(mine.clone()).expect("address"),
    )
    .await
    .expect("reset");

    assert_eq!(
        row_best(&pool, "sessC001").await,
        0.0,
        "the reset zeroed it"
    );
    assert_eq!(
        row_best(&pool, "sessC002").await,
        543.5,
        "another miner's best is not collateral"
    );

    sink.record_accepted(share(&mine, "rig1", "sessC001", 7.25, 64.0, 2))
        .await;
    handle.flush_touches_now().await;
    assert_eq!(
        row_best(&pool, "sessC001").await,
        7.25,
        "post-reset the best rebuilds from the next share, not from the old high"
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// A lower later flush never lowers the row's best.
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
    assert_eq!(row_best(&pool, "sessL002").await, 100.0);

    sink.record_accepted(share(&address, "rig1", "sessL002", 50.0, 64.0, 3))
        .await;
    handle.flush_touches_now().await;
    assert_eq!(
        hgetall(&mut redis, &key)
            .await
            .get(F_CHANNEL_COUNT)
            .map(String::as_str),
        Some("3"),
        "second flush must have landed (latest-wins field)"
    );
    assert_eq!(
        row_best(&pool, "sessL002").await,
        100.0,
        "a lower later window must not regress the best"
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// A paused miner's live key expires; its session keeps the best.
#[tokio::test]
async fn a_session_keeps_its_best_when_its_live_key_expires() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 10).await
    else {
        return;
    };
    let prefix = "test_lv_pause_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}carl");
    let key = client_live_key(&address, "rig1", "sessL010");

    hook.register_session("sessL010", &address, "rig1", None)
        .await;
    handle.flush_births_now().await;
    sink.record_accepted(share(&address, "rig1", "sessL010", 123.0, 64.0, 1))
        .await;
    handle.flush_touches_now().await;

    // The key's TTL runs out during the pause.
    let _: i64 = redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut redis)
        .await
        .expect("DEL");
    let rows = bp_db::find_clients_by_address(
        &pool,
        &bp_common::AddressId::new(address.clone()).expect("address"),
    )
    .await
    .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].best_difficulty, 123.0,
        "the listed session keeps its best"
    );

    // Shares resume lower; the best stays.
    sink.record_accepted(share(&address, "rig1", "sessL010", 5.0, 64.0, 1))
        .await;
    handle.flush_touches_now().await;
    assert_eq!(row_best(&pool, "sessL010").await, 123.0);

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// The touch writes vardiff's rate; the watchdog's zero does not extend the TTL.
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
    sink.record_accepted(SharedAcceptedShare {
        hash_rate: 5.0e12,
        ..share(&address, "rig1", "sessL003", 100.0, 512.0, 1)
    })
    .await;
    handle.flush_touches_now().await;
    assert!(ttl(&mut redis, &key).await > 10, "touch set the full TTL");
    assert_eq!(
        hgetall(&mut redis, &key)
            .await
            .get(F_HASH_RATE)
            .map(String::as_str),
        Some("5000000000000"),
        "the touch wrote the share's vardiff rate"
    );

    // A share with vardiff's 0 keeps the stored rate.
    sink.record_accepted(share(&address, "rig1", "sessL003", 100.0, 512.0, 1))
        .await;
    handle.flush_touches_now().await;
    assert_eq!(
        hgetall(&mut redis, &key)
            .await
            .get(F_HASH_RATE)
            .map(String::as_str),
        Some("5000000000000"),
        "vardiff's 0 before its first estimate keeps the stored rate"
    );

    // Shrink the TTL, then let the watchdog zero the rate.
    let _: i64 = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(10i64)
        .query_async(&mut redis)
        .await
        .expect("EXPIRE");
    handle.zero_silent_hashrates_now(Duration::ZERO).await;

    assert_eq!(
        hgetall(&mut redis, &key)
            .await
            .get(F_HASH_RATE)
            .map(String::as_str),
        Some("0"),
        "the watchdog zeroed the silent session"
    );
    let t = ttl(&mut redis, &key).await;
    assert!(
        (1..=10).contains(&t),
        "the watchdog must not extend liveness — TTL was ≤10, now {t}"
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// A watchdog HSET that creates the key still sets a TTL; the hash holds only `hash_rate`.
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

    // Feed the watchdog but do NOT flush touches — the key must not exist.
    sink.record_accepted(share(&address, "rig1", "sessL004", 100.0, 512.0, 1))
        .await;
    assert_eq!(ttl(&mut redis, &key).await, -2, "key must not exist yet");

    handle.zero_silent_hashrates_now(Duration::ZERO).await;

    let hash = hgetall(&mut redis, &key).await;
    assert!(hash.contains_key(F_HASH_RATE), "watchdog created the key");
    assert!(
        !hash.contains_key(F_CURRENT_DIFFICULTY),
        "watchdog-created hash is partial by design"
    );
    let t = ttl(&mut redis, &key).await;
    assert!(
        t > 0,
        "a watchdog-created key without TTL is immortal under volatile-lru, got {t}"
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// A dead Redis costs only a warning: the flush returns and PG births still land.
/// A killed TCP proxy fakes the outage, since a `ConnectionManager` needs one connect.
#[tokio::test]
async fn redis_down_does_not_hang_the_flush() {
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
        bp_test_support::connection_manager(client),
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
    assert_eq!(
        rows, 0,
        "nothing written — the snapshot is rebuffered for retry"
    );

    // The PG birth path is untouched by the Redis outage.
    let born: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessL005")
            .fetch_one(&pool)
            .await
            .expect("birth row");
    assert_eq!(born, 1, "the birth landed although Redis is gone");

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// `bp_client_live`'s scans find and sum what the engine wrote (per address and pool-wide).
#[tokio::test]
async fn live_reader_agrees_with_the_writer() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(mut redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 5).await
    else {
        return;
    };
    let prefix = "test_lv_read_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let hook = handle.session_persistence_hook();
    let sink = handle.client_row_touch_sink();
    let addr_a = bp_common::AddressId::new(format!("{prefix}a")).unwrap();
    let addr_b = bp_common::AddressId::new(format!("{prefix}b")).unwrap();
    let addr_idle = bp_common::AddressId::new(format!("{prefix}idle")).unwrap();
    let per_session = 600.0 * 4_294_967_296.0 / 60.0;

    for (addr, sess) in [
        (&addr_a, "sessL006"),
        (&addr_a, "sessL007"),
        (&addr_b, "sessL008"),
    ] {
        hook.register_session(sess, addr.as_str(), "rig1", None)
            .await;
        sink.record_accepted(SharedAcceptedShare {
            hash_rate: per_session,
            ..share(addr.as_str(), "rig1", sess, 100.0, 600.0, 1)
        })
        .await;
    }
    handle.flush_births_now().await;
    handle.flush_touches_now().await;

    let a_sum = bp_client_live::hashrate_for_addresses(Some(&redis), std::slice::from_ref(&addr_a))
        .await
        .expect("read addr_a");
    assert!(
        (a_sum - 2.0 * per_session).abs() < 1.0,
        "addr_a sums its two sessions, got {a_sum}"
    );

    let by_addr = bp_client_live::hashrate_by_address(
        Some(&redis),
        &[addr_a.clone(), addr_b.clone(), addr_idle.clone()],
    )
    .await
    .expect("read by address");
    assert!((by_addr[addr_a.as_str()] - 2.0 * per_session).abs() < 1.0);
    assert!((by_addr[addr_b.as_str()] - per_session).abs() < 1.0);
    assert_eq!(
        by_addr[addr_idle.as_str()],
        0.0,
        "an address with no live session reads 0, not missing"
    );

    let pool_sum = bp_client_live::pool_hashrate(Some(&redis))
        .await
        .expect("pool sum");
    assert!(
        (pool_sum - 3.0 * per_session).abs() < 1.0,
        "pool-wide scan finds all three sessions, got {pool_sum}"
    );

    // The DEL guard: what the reader saw came from the writer, not from
    // leftovers — wipe and confirm the reader now reads 0.
    let _: i64 = redis::cmd("DEL")
        .arg(client_live_key(addr_a.as_str(), "rig1", "sessL006"))
        .arg(client_live_key(addr_a.as_str(), "rig1", "sessL007"))
        .arg(client_live_key(addr_b.as_str(), "rig1", "sessL008"))
        .query_async(&mut redis)
        .await
        .expect("DEL");
    assert_eq!(
        bp_client_live::pool_hashrate(Some(&redis))
            .await
            .expect("re-read"),
        0.0
    );

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}

/// `live_fields_for_sessions` returns what was written, `None` in place when unflushed.
#[tokio::test]
async fn composed_reader_returns_the_writers_fields_in_position() {
    let Some(pool) = pg_or_skip().await else {
        return;
    };
    let Some(redis) = connect_redis_in_range_or_skip(redis_db::SESSION_PERSISTENCE, 6).await else {
        return;
    };
    let prefix = "test_lv_comp_";
    cleanup(&pool, prefix).await;

    let handle = spawn_engine(&pool, redis.clone()).await;
    let sink = handle.client_row_touch_sink();
    let address = format!("{prefix}fred");

    sink.record_accepted(SharedAcceptedShare {
        hash_rate: 5.0e12,
        ..share(&address, "rig1", "sessL009", 100.5, 64.0, 2)
    })
    .await;
    handle.flush_touches_now().await;

    let live = bp_client_live::live_fields_for_sessions(
        Some(&redis),
        &[
            (address.as_str(), "rig1", "sessL009"),
            (address.as_str(), "rig1", "never-flushed"),
        ],
    )
    .await
    .expect("composed read");
    assert_eq!(live.len(), 2);
    let lf = live[0].as_ref().expect("flushed session has live fields");
    assert_eq!(lf.current_difficulty, Some(64.0));
    assert_eq!(lf.channel_count, Some(2));
    assert_eq!(lf.hash_rate, 5.0e12, "the share's vardiff rate");
    assert!(lf.updated_at_ms.is_some());
    assert_eq!(live[1], None, "unknown session stays None in position");

    handle.shutdown().await;
    cleanup(&pool, prefix).await;
}
