// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end tests for `SessionPersistenceEngine`: the
//! session-register/deregister hook + the per-hour difficulty-stats sink,
//! verified against PG. (Best difficulty is no longer a per-share
//! write-through here — it's folded into the batched stats-sink flush.)

use std::time::Duration;

use bp_session_persistence::{SessionPersistenceConfig, SessionPersistenceEngine};
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

/// The full debounced life of a mining session: register writes NOTHING
/// (the anti-write half — under the old synchronous hook the row existed
/// here, so this assertion fails against that behaviour), the birth
/// flush writes the row with the values register captured, deregister
/// soft-deletes it.
#[tokio::test]
async fn engine_session_persistence_hook_debounces_then_soft_deletes() {
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

    hook.register_session("sessZ001", &address, "worker1", Some("bitaxe/2.7"))
        .await;

    // No row yet — authorize must not write. (The 5s birth ticker can't
    // race this: its first tick is a full interval away and the 15s
    // default debounce means it would find nothing due anyway.)
    let n: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
        .bind("sessZ001")
        .fetch_one(&pool)
        .await
        .expect("count after register");
    assert_eq!(
        n, 0,
        "authorize must not write a row — that is the whole saving"
    );

    // A tick honouring the 15s debounce also writes nothing for a
    // seconds-old session.
    handle.flush_due_births().await;
    assert_eq!(
        handle.pending_births(),
        1,
        "young session must stay pending"
    );

    // Force the birth (age check dropped) — the row must carry what
    // register captured, not defaults.
    handle.flush_births_now().await;
    let row = sqlx::query(
        r#"SELECT "deletedAt", "userAgent", "startTime", "firstSeen" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind(&address)
    .bind("worker1")
    .bind("sessZ001")
    .fetch_one(&pool)
    .await
    .expect("read after birth");
    let del: Option<i64> = row.get("deletedAt");
    let ua: Option<String> = row.get("userAgent");
    let start_time: i64 = row.get("startTime");
    let first_seen: Option<i64> = row.get("firstSeen");
    assert!(del.is_none(), "fresh row must not be soft-deleted");
    assert_eq!(ua.as_deref(), Some("bitaxe/2.7"), "userAgent from register");
    assert!(start_time > 0, "startTime is the authorize stamp");
    assert_eq!(
        first_seen,
        Some(start_time),
        "firstSeen = startTime on insert"
    );

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

/// The probe path and its negative control in one test: a session that
/// deregisters before its birth leaves NO row, while the surviving
/// control session from the same batch does get one — so a regression
/// that writes at authorize again fails the first half, and a filter
/// that drops everything fails the second.
#[tokio::test]
async fn a_probe_session_leaves_no_row_while_a_survivor_gets_one() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_probe_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let hook = handle.session_persistence_hook();
    let address = format!("{prefix}carol");

    // The probe: authorize + hang up, the measured 95 % case.
    hook.register_session("sessPRB1", &address, "probe", None)
        .await;
    hook.deregister_session("sessPRB1").await;
    // The survivor.
    hook.register_session("sessSRV1", &address, "rig", None)
        .await;

    handle.flush_births_now().await;

    let probe_rows: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessPRB1")
            .fetch_one(&pool)
            .await
            .expect("count probe");
    assert_eq!(probe_rows, 0, "a probe must never reach the table");

    let survivor_rows: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessSRV1")
            .fetch_one(&pool)
            .await
            .expect("count survivor");
    assert_eq!(survivor_rows, 1, "the surviving session must be born");

    cleanup(&pool, prefix).await;
}

/// A rental proxy re-registers the SAME session id under a second worker
/// name (documented live_sessions behaviour). Both workers must get
/// their row, and the one session teardown must retire both.
#[tokio::test]
async fn two_workers_on_one_session_both_get_rows_and_one_teardown_retires_both() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_twoworker_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let hook = handle.session_persistence_hook();
    let address = format!("{prefix}dave");

    hook.register_session("sessTW01", &address, "rig1", None)
        .await;
    hook.register_session("sessTW01", &address, "rig2", None)
        .await;
    handle.flush_births_now().await;

    let live: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM client_entity
           WHERE "sessionId" = $1 AND "deletedAt" IS NULL"#,
    )
    .bind("sessTW01")
    .fetch_one(&pool)
    .await
    .expect("count live");
    assert_eq!(live, 2, "one row per (address, worker) pair of the session");

    hook.deregister_session("sessTW01").await;

    let still_live: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM client_entity
           WHERE "sessionId" = $1 AND "deletedAt" IS NULL"#,
    )
    .bind("sessTW01")
    .fetch_one(&pool)
    .await
    .expect("count live after teardown");
    assert_eq!(
        still_live, 0,
        "the session-wide soft-delete covers both workers"
    );

    cleanup(&pool, prefix).await;
}

/// One poisoned entry (a `clientName` past the column's varchar(64),
/// which the SV1 path does not length-check) must not starve the healthy
/// rows in its batch, and must be dropped after its bounded retries —
/// the unbounded-retry version of this is exactly how the abandoned
/// upsert-touch design took the whole flush down.
#[tokio::test]
async fn a_poisoned_birth_row_is_isolated_and_dropped_after_bounded_retries() {
    let _guard = ENGINE_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_sp_poison_";
    cleanup(&pool, prefix).await;

    let handle = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool.clone())
        .await
        .expect("spawn engine");
    let hook = handle.session_persistence_hook();
    let address = format!("{prefix}eve");
    let oversized_worker = "w".repeat(65); // varchar(64) → 22001

    hook.register_session("sessPSN1", &address, &oversized_worker, None)
        .await;
    hook.register_session("sessOK01", &address, "healthy", None)
        .await;

    // Flush 1: bulk fails on the poisoned row, the per-row fallback
    // births the healthy one and rebuffers the poison (attempt 1).
    handle.flush_births_now().await;
    let healthy: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessOK01")
            .fetch_one(&pool)
            .await
            .expect("count healthy");
    assert_eq!(
        healthy, 1,
        "the healthy row must survive its poisoned batch"
    );
    assert_eq!(
        handle.pending_births(),
        1,
        "the poisoned row is rebuffered, not silently gone"
    );

    // Flushes 2 + 3: still failing → dropped at the attempt cap.
    handle.flush_births_now().await;
    assert_eq!(handle.pending_births(), 1, "attempt 2 keeps retrying");
    handle.flush_births_now().await;
    assert_eq!(
        handle.pending_births(),
        0,
        "a deterministic per-row failure must be dropped after its budget"
    );

    let poisoned: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessPSN1")
            .fetch_one(&pool)
            .await
            .expect("count poisoned");
    assert_eq!(poisoned, 0, "the over-long name never lands");

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
    handle.flush_births_now().await;
    hook.deregister_session("sessY002").await;
    // Same composite PK re-register: the birth's ON CONFLICT arm clears
    // deletedAt, exactly as the synchronous upsert did.
    hook.register_session("sessY002", &address, "wkr", None)
        .await;
    handle.flush_births_now().await;

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
    // Dropping the handle without `shutdown()` must not panic — the
    // background loops (birth/touch/sampler/diff-stat) just keep running
    // on their intervals until the runtime tears them down.
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    {
        let _h = SessionPersistenceEngine::spawn(SessionPersistenceConfig::default(), pool)
            .await
            .expect("spawn");
        // Goes out of scope here without an explicit shutdown.
    }
    // Sleep tiny window: confirms no pending tasks panic.
    tokio::time::sleep(Duration::from_millis(20)).await;
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
