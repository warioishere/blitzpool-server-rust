// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end tests for `SessionPersistenceEngine`: the
//! session-register/deregister hook + the per-hour difficulty-stats sink,
//! verified against PG. (Best difficulty is no longer a per-share
//! write-through here — it's folded into the batched stats-sink flush.)

use std::time::Duration;

use bp_db::upsert_client;
use bp_session_persistence::{SessionPersistenceConfig, SessionPersistenceEngine};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::Mutex;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static ENGINE_LOCK: Mutex<()> = Mutex::const_new(());

/// One accepted share for a session, with the fields the row-creating sink
/// reads. `effective_difficulty` is the vardiff target (what lands in
/// `currentDifficulty`), `submission_difficulty` the share's own value.
fn share_for<'a>(
    address: &'a str,
    worker: &'a str,
    session_id: &'a str,
) -> SharedAcceptedShare<'a> {
    SharedAcceptedShare {
        address,
        worker,
        session_id,
        effective_difficulty: 1_024.0,
        submission_difficulty: 2_048.0,
        user_agent: Some("bitaxe/test"),
        is_block_candidate: false,
        hash_rate: 0.0,
        channel_count: 1,
        ts_ms: 0,
        share_id: "",
        mode: bp_share_hook::MiningMode::Solo,
        group_id: None,
    }
}

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

/// The row's lifecycle, end to end, after it moved off the authorize path:
/// register writes NOTHING, the first accepted share creates the row, and the
/// teardown retires it.
///
/// The middle assertion is the one that matters — a connection that completes
/// the handshake and hangs up (measured on prod: 6 129 sessions/hour from 57
/// addresses, median lifetime 0.1 s) must not cost a single statement.
#[tokio::test]
async fn a_session_row_is_created_by_the_first_share_not_by_authorize() {
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
    let sink = handle.client_row_session_sink();
    let address = format!("{prefix}alice");

    hook.register_session("sessZ001", &address, "worker1", None)
        .await;

    let after_register: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessZ001")
            .fetch_one(&pool)
            .await
            .expect("count after register");
    assert_eq!(
        after_register, 0,
        "authorize must not write a row — that is the whole saving"
    );

    // A throwaway connection ends here, and must have cost nothing at all.
    hook.deregister_session("sessZ001").await;
    let after_probe: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessZ001")
            .fetch_one(&pool)
            .await
            .expect("count after probe teardown");
    assert_eq!(after_probe, 0, "a session that never mined leaves no row");

    // Now the same session mines.
    hook.register_session("sessZ001", &address, "worker1", None)
        .await;
    sink.record_accepted(share_for(&address, "worker1", "sessZ001"))
        .await;

    let del: Option<i64> = sqlx::query_scalar(
        r#"SELECT "deletedAt" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind(&address)
    .bind("worker1")
    .bind("sessZ001")
    .fetch_one(&pool)
    .await
    .expect("the first share must have created the row");
    assert!(del.is_none(), "a freshly mined session is not soft-deleted");

    hook.deregister_session("sessZ001").await;
    let del2: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessZ001")
            .fetch_one(&pool)
            .await
            .expect("read after deregister");
    assert!(
        del2.is_some(),
        "a session that DID mine must be retired on teardown"
    );

    cleanup(&pool, prefix).await;
}

/// Reconnect under the same composite PK still clears the soft-delete — the
/// behaviour is unchanged, only its trigger moved from the register to the
/// first share (`register_client`'s `ON CONFLICT … SET "deletedAt" = NULL`).
#[tokio::test]
async fn a_share_after_a_reconnect_clears_the_soft_delete() {
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
    let sink = handle.client_row_session_sink();
    let address = format!("{prefix}bob");

    hook.register_session("sessY002", &address, "wkr", None)
        .await;
    sink.record_accepted(share_for(&address, "wkr", "sessY002"))
        .await;
    hook.deregister_session("sessY002").await;

    let del_mid: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessY002")
            .fetch_one(&pool)
            .await
            .expect("read after teardown");
    assert!(del_mid.is_some(), "precondition: the row is soft-deleted");

    hook.register_session("sessY002", &address, "wkr", None)
        .await;
    sink.record_accepted(share_for(&address, "wkr", "sessY002"))
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
    assert!(
        del.is_none(),
        "a share after the reconnect must clear the soft-delete"
    );

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
///
/// Goes through the ENGINE since the sink was batched (2026-08-05): the sink
/// only merges into the buffer, and the row appears when the flush loop — or
/// the shutdown drain — writes it. So this now covers the whole chain
/// (record → coalesce → bulk upsert → row), including that `shutdown()`
/// does not discard the current window.
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

    // A long interval on purpose: the assertion must be satisfied by the
    // SHUTDOWN drain, not by a tick that happened to fire in between. A test
    // that passes only because a timer raced it would not pin the drain.
    let handle = SessionPersistenceEngine::spawn(
        SessionPersistenceConfig {
            diff_stat_flush_interval: Duration::from_secs(3_600),
            ..Default::default()
        },
        pool.clone(),
    )
    .await
    .expect("spawn engine");
    let sink = handle.client_difficulty_statistics_sink();
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

    // Nothing may be in the DB yet — the whole point of batching is that the
    // share path does not write. If this fires, the sink went inline again.
    let pending: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM client_difficulty_statistics_entity WHERE address = $1"#,
    )
    .bind(address)
    .fetch_one(&pool)
    .await
    .expect("count before flush");
    assert_eq!(
        pending, 0,
        "the share path must not write; the flush loop does"
    );

    handle.shutdown().await;

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
