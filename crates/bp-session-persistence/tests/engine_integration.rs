// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end test for `SessionPersistenceEngine`: drives the
//! session-register/deregister hook + the best-difficulty
//! write-through and verifies PG state + cache state stay in sync.
//!
//! The best-difficulty sink implements `SharedAcceptedShareSink`, whose
//! `SharedAcceptedShare` view is a plain borrowed struct — so the real
//! `BestDifficultySink::record_accepted` can be driven directly here
//! (no `MiningJob`-private-field fixture needed). The lower-level
//! `upsert_address_best_difficulty` is still exercised on its own to
//! pin the PG compare-and-set guarantee independently of the cache.

use std::sync::Arc;
use std::time::Duration;

use bp_db::upsert_client;
use bp_session_persistence::{
    AddressSettingsCache, CachedAddressSettings, ClientDifficultyStatisticsSink,
    SessionPersistenceConfig, SessionPersistenceEngine,
};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::Mutex;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static ENGINE_LOCK: Mutex<()> = Mutex::const_new(());

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
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

#[tokio::test]
async fn engine_session_persistence_hook_writes_then_soft_deletes() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_eng_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let hook = handle.session_persistence_hook();
    let address = format!("{prefix}alice");

    hook.register_session("sessZ001", &address, "worker1", None)
        .await;

    let row = sqlx::query(
        r#"SELECT "deletedAt" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind(&address)
    .bind("worker1")
    .bind("sessZ001")
    .fetch_one(&pool)
    .await
    .expect("read after register");
    let del: Option<i64> = row.get("deletedAt");
    assert!(del.is_none(), "fresh row must not be soft-deleted");

    hook.deregister_session("sessZ001").await;

    let del2: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessZ001")
            .fetch_one(&pool)
            .await
            .expect("read after deregister");
    assert!(del2.is_some(), "deletedAt must be stamped post-deregister");

    cleanup(&pool, prefix).await;
}

#[tokio::test]
async fn engine_cache_is_lazily_populated_and_invalidated() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool)
        .await
        .expect("spawn engine");
    let cache = handle.cache();

    // Cold path: cache miss.
    assert!(cache.get("bc1q_eng_alice").await.is_none());

    // Warm cache directly (the hook would do this after a PG write).
    cache
        .set(
            "bc1q_eng_alice",
            CachedAddressSettings {
                best_difficulty: 1234.0,
                best_difficulty_user_agent: Some("bitaxe/4.0".to_string()),
            },
        )
        .await;
    assert_eq!(cache.len().await, 1);

    // Invalidate (used by /api/admin/settings endpoints).
    cache.invalidate("bc1q_eng_alice").await;
    assert_eq!(cache.len().await, 0);
}

#[tokio::test]
async fn engine_re_register_under_same_session_id_clears_soft_delete() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_reuse_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let hook = handle.session_persistence_hook();
    let address = format!("{prefix}bob");

    hook.register_session("sessY002", &address, "wkr", None)
        .await;
    hook.deregister_session("sessY002").await;
    // Same composite PK re-register: ON CONFLICT path clears deletedAt.
    hook.register_session("sessY002", &address, "wkr", None)
        .await;

    let del: Option<i64> = sqlx::query_scalar(
        r#"SELECT "deletedAt" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind(&address)
    .bind("wkr")
    .bind("sessY002")
    .fetch_one(&pool)
    .await
    .expect("read");
    assert!(del.is_none(), "re-register must clear soft-delete");

    cleanup(&pool, prefix).await;
}

#[tokio::test]
async fn engine_invalid_config_rejected() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let bad = SessionPersistenceConfig {
        address_cache_capacity: 0,
        ..Default::default()
    };
    let result = SessionPersistenceEngine::spawn(bad, pool).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn engine_handle_clone_shares_same_cache() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool)
        .await
        .expect("spawn");
    let handle_clone = handle.clone();
    let cache_a = handle.cache();
    let cache_b = handle_clone.cache();
    assert!(Arc::ptr_eq(&cache_a, &cache_b));
}

// ── best-difficulty write-through driven via the cache + bp-db ──────

#[tokio::test]
async fn best_difficulty_write_through_persists_to_pg_and_warms_cache() {
    // The full `record_accepted` path takes a `&ShareAccept` whose
    // private MiningJob fields are non-trivial to fixture. We drive the
    // semantic equivalent directly: check cache predicate → PG
    // compare-and-set → cache set. Same code path the hook uses.
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_bd_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let cache = handle.cache();
    let address = format!("{prefix}alice");
    let candidate = 250.0_f64;

    // Cache miss → proceed straight to PG.
    let n = bp_db::upsert_address_best_difficulty(&pool, &address, candidate, Some("bitaxe"))
        .await
        .expect("PG upsert");
    assert_eq!(n, 1);

    // After PG success, the hook warms the cache.
    cache
        .set(
            &address,
            CachedAddressSettings {
                best_difficulty: candidate,
                best_difficulty_user_agent: Some("bitaxe".to_string()),
            },
        )
        .await;

    let cached = cache.get(&address).await.expect("cache warm");
    assert_eq!(cached.best_difficulty, candidate);

    // Second share at LOWER diff → predicate stops at cache check, no PG hit.
    assert!(!cached.should_update(100.0), "lower must short-circuit");

    cleanup(&pool, prefix).await;
}

#[tokio::test]
async fn record_accepted_stamps_user_agent_into_best_difficulty_row() {
    // Drive the real `BestDifficultySink` hook with a share carrying a
    // firmware string and assert it reaches the PG
    // `bestDifficultyUserAgent` column + the warmed cache — the path
    // that was previously hardcoded to `None`.
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_bd_ua_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let sink = handle.best_difficulty_sink();
    let address = format!("{prefix}alice");

    sink.record_accepted(SharedAcceptedShare {
        address: &address,
        worker: "rig1",
        session_id: "sess-ua-1",
        user_agent: Some("bitaxe/4.0.2"),
        effective_difficulty: 1024.0,
        submission_difficulty: 5000.0,
        is_block_candidate: false,
        hash_rate: 0.0,
        channel_count: 1,
        ts_ms: 0,
        share_id: "",
        mode: bp_share_hook::MiningMode::Solo,
        group_id: None,
    })
    .await;

    let row = sqlx::query(
        r#"SELECT "bestDifficulty", "bestDifficultyUserAgent"
             FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(&address)
    .fetch_one(&pool)
    .await
    .expect("best-diff row exists");
    let bd: f64 = row.get("bestDifficulty");
    let ua: Option<String> = row.get("bestDifficultyUserAgent");
    assert!((bd - 5000.0).abs() < 0.01);
    assert_eq!(ua.as_deref(), Some("bitaxe/4.0.2"));

    // Warmed cache mirrors the firmware string.
    let cached = handle.cache().get(&address).await.expect("cache warm");
    assert_eq!(
        cached.best_difficulty_user_agent.as_deref(),
        Some("bitaxe/4.0.2")
    );

    cleanup(&pool, prefix).await;
}

#[tokio::test]
async fn best_difficulty_pg_compare_and_set_rejects_lower_candidate() {
    // Pin the PG-side guarantee independently of the cache: even if the
    // cache check were bypassed (race window), the PG CAS must reject.
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_cas_only_";
    cleanup(&pool, prefix).await;

    let address = format!("{prefix}race");
    // Seed via an upsert at high diff.
    bp_db::upsert_address_best_difficulty(&pool, &address, 1000.0, Some("v1"))
        .await
        .unwrap();
    // Concurrent lower candidate — PG must say no rows updated.
    let n = bp_db::upsert_address_best_difficulty(&pool, &address, 500.0, Some("v2"))
        .await
        .unwrap();
    assert_eq!(n, 0, "PG CAS: lower candidate rejected");

    let bd: f64 = sqlx::query_scalar(
        r#"SELECT "bestDifficulty" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(&address)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!((bd - 1000.0).abs() < 0.01);

    cleanup(&pool, prefix).await;
}

#[tokio::test]
async fn engine_shutdown_is_a_drop_no_op() {
    // Session-persistence has no background task — the engine is purely
    // synchronous write-through. Dropping the handle is safe.
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    {
        let _h = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool)
            .await
            .expect("spawn");
        // Goes out of scope here; no background task to clean up.
    }
    // Sleep tiny window: confirms no pending tasks panic.
    tokio::time::sleep(Duration::from_millis(20)).await;
}

// Avoid unused-import warnings for the cleanup-only test variants.
#[allow(dead_code)]
async fn _exhibit_upsert_client_path(pool: &PgPool) {
    use bp_db::ClientUpsert;
    let _ = upsert_client(
        pool,
        &ClientUpsert {
            address: "x".to_string(),
            client_name: "y".to_string(),
            session_id: "z".to_string(),
            user_agent: None,
            start_time_ms: 0,
            current_difficulty: None,
        },
    )
    .await;
}

/// `ClientDifficultyStatisticsSink` records the per-(address, worker,
/// hour-slot) MAX submission difficulty; a lower follow-up share leaves
/// the stored max untouched, and a higher one raises it.
#[tokio::test]
async fn diff_stats_sink_keeps_per_slot_maximum() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let address = "bcrt1qdiffstatsinktest00000000000000000000";
    let del = |p: PgPool| async move {
        let _ =
            sqlx::query(r#"DELETE FROM client_difficulty_statistics_entity WHERE address = $1"#)
                .bind(address)
                .execute(&p)
                .await;
    };
    del(pool.clone()).await;

    let sink = ClientDifficultyStatisticsSink::new(pool.clone());
    let share = |submission_difficulty: f64| SharedAcceptedShare {
        address,
        worker: "rig1",
        session_id: "sess-diff",
        effective_difficulty: 1024.0,
        submission_difficulty,
        user_agent: Some("bitaxe"),
        is_block_candidate: false,
        hash_rate: 0.0,
        channel_count: 1,
        ts_ms: 0,
        share_id: "",
        mode: bp_share_hook::MiningMode::Solo,
        group_id: None,
    };

    sink.record_accepted(share(1_000.0)).await; // first → max 1000
    sink.record_accepted(share(50_000.0)).await; // new max
    sink.record_accepted(share(2_000.0)).await; // below max → no change

    let row = sqlx::query(
        r#"SELECT MAX("maxDifficulty")::float8 AS m
               FROM client_difficulty_statistics_entity WHERE address = $1"#,
    )
    .bind(address)
    .fetch_one(&pool)
    .await
    .expect("query max");
    let max: f64 = row.try_get("m").expect("max column");
    assert!(
        (max - 50_000.0).abs() < 1.0,
        "expected per-slot max 50000, got {max}"
    );

    del(pool).await;
}
