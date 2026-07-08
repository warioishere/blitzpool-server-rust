// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end tests for `SessionPersistenceEngine`: the
//! session-register/deregister hook + the per-hour difficulty-stats sink,
//! verified against PG. (Best difficulty is no longer a per-share
//! write-through here — it's folded into the batched stats-sink flush.)

use std::time::Duration;

use bp_db::upsert_client;
use bp_session_persistence::{
    ClientDifficultyStatisticsSink, SessionPersistenceConfig, SessionPersistenceEngine,
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
        touch_flush_interval: Duration::ZERO,
        ..Default::default()
    };
    let result = SessionPersistenceEngine::spawn(bad, pool).await;
    assert!(result.is_err());
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
