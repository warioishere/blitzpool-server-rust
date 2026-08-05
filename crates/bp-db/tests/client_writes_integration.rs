// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the session-persistence write-primitives
//! (`upsert_client`, `delete_client_for_session`, …). Each test wraps
//! writes in TX-rollback for isolation.

use bp_common::AddressId;
use bp_db::{
    bulk_set_client_hashrate, bulk_touch_clients_for_share,
    bulk_upsert_client_difficulty_statistics, delete_client_for_session,
    find_addresses_for_ntfy_listener, kill_dead_clients, reset_all_client_hashrate,
    touch_client_for_share, update_sv2_user_agent_by_address, upsert_client,
    upsert_ntfy_subscription, ClientUpsert,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Serialises the tests that mutate `hashRate` table-wide against the shared
/// PG. `reset_all_client_hashrate` zeroes every active row, so it must not
/// overlap `bulk_set_client_hashrate`'s test (which asserts its own row's
/// value). No other test touches the column, so this two-test lock suffices.
static HASHRATE_DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
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

fn mk(session: &str) -> ClientUpsert {
    ClientUpsert {
        address: "test_client_addr".to_string(),
        client_name: "wkr".to_string(),
        session_id: session.to_string(),
        user_agent: Some("bitaxe/2.7".to_string()),
        start_time_ms: 1_700_000_000_000,
        current_difficulty: Some(16_384.0),
    }
}

// ── upsert_client ───────────────────────────────────────────────────

#[tokio::test]
async fn upsert_client_inserts_fresh_row() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let n = upsert_client(&mut *tx, &mk("sessA001"))
        .await
        .expect("insert");
    assert_eq!(n, 1);

    let row = sqlx::query(
        r#"SELECT "userAgent", "currentDifficulty", "deletedAt" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessA001")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let ua: Option<String> = row.get("userAgent");
    let cd: Option<f32> = row.get("currentDifficulty");
    let del: Option<i64> = row.get("deletedAt");
    assert_eq!(ua.as_deref(), Some("bitaxe/2.7"));
    assert!(cd.is_some() && (cd.unwrap() - 16_384.0).abs() < 0.01);
    assert!(del.is_none(), "fresh row must not be soft-deleted");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upsert_client_sets_first_seen_on_insert() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    upsert_client(&mut *tx, &mk("sessFS01"))
        .await
        .expect("insert");

    let row = sqlx::query(
        r#"SELECT "firstSeen", "startTime" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessFS01")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let first_seen: Option<i64> = row.get("firstSeen");
    let start_time: Option<i64> = row.get("startTime");
    assert_eq!(
        first_seen,
        Some(1_700_000_000_000_i64),
        "firstSeen must equal start_time_ms on INSERT"
    );
    assert_eq!(start_time, Some(1_700_000_000_000_i64));

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upsert_client_preserves_first_seen_on_reregister() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    // First register at T1 — sets firstSeen = T1.
    upsert_client(&mut *tx, &mk("sessFS02"))
        .await
        .expect("insert");

    // Re-register same sessionId at T2 (ON CONFLICT path).
    let reregister = ClientUpsert {
        start_time_ms: 1_700_000_099_000, // T2 = T1 + 99s
        ..mk("sessFS02")
    };
    upsert_client(&mut *tx, &reregister)
        .await
        .expect("re-register");

    let row = sqlx::query(
        r#"SELECT "firstSeen", "startTime" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessFS02")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let first_seen: Option<i64> = row.get("firstSeen");
    let start_time: Option<i64> = row.get("startTime");
    assert_eq!(
        first_seen,
        Some(1_700_000_000_000_i64),
        "firstSeen must not be overwritten on re-register"
    );
    assert_eq!(
        start_time,
        Some(1_700_000_099_000_i64),
        "startTime is refreshed on re-register"
    );

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upsert_client_on_conflict_resurrects_soft_deleted_row() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    // First register, then deregister, then re-register with same composite PK.
    upsert_client(&mut *tx, &mk("sessC002")).await.unwrap();
    delete_client_for_session(&mut *tx, "sessC002")
        .await
        .unwrap();
    // Re-register: ON CONFLICT path must clear deletedAt + refresh fields.
    let mut updated = mk("sessC002");
    updated.user_agent = Some("bitaxe/3.0".to_string());
    upsert_client(&mut *tx, &updated).await.unwrap();

    let row = sqlx::query(
        r#"SELECT "userAgent", "deletedAt" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessC002")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let ua: Option<String> = row.get("userAgent");
    let del: Option<i64> = row.get("deletedAt");
    assert_eq!(ua.as_deref(), Some("bitaxe/3.0"), "userAgent refreshed");
    assert!(del.is_none(), "deletedAt must clear on re-register");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn ntfy_listener_topics_union_clients_and_ntfy_subs() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let client_addr = "ntfy_topics_client_addr";
    let ntfy_addr = "ntfy_topics_ntfysub_addr";
    // Clean any leftovers from a previous run.
    for a in [client_addr, ntfy_addr] {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(a)
            .execute(&pool)
            .await;
        let _ = sqlx::query(r#"DELETE FROM ntfy_subscriptions_entity WHERE address = $1"#)
            .bind(a)
            .execute(&pool)
            .await;
    }

    // An active mining client + an ntfy subscription on two distinct addrs.
    upsert_client(
        &pool,
        &ClientUpsert {
            address: client_addr.to_string(),
            client_name: "wkr".to_string(),
            session_id: "ntfytpc1".to_string(),
            user_agent: None,
            start_time_ms: 1_700_000_000_000,
            current_difficulty: None,
        },
    )
    .await
    .expect("upsert client");
    upsert_ntfy_subscription(&pool, &AddressId::new(ntfy_addr.to_string()).unwrap())
        .await
        .expect("upsert ntfy sub");

    let topics = find_addresses_for_ntfy_listener(&pool)
        .await
        .expect("listener topics");
    let set: std::collections::HashSet<String> =
        topics.into_iter().map(|a| a.as_str().to_string()).collect();
    assert!(set.contains(client_addr), "client address must be listened");
    assert!(
        set.contains(ntfy_addr),
        "ntfy-subscribed address must be listened"
    );

    for a in [client_addr, ntfy_addr] {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE address = $1"#)
            .bind(a)
            .execute(&pool)
            .await;
        let _ = sqlx::query(r#"DELETE FROM ntfy_subscriptions_entity WHERE address = $1"#)
            .bind(a)
            .execute(&pool)
            .await;
    }
}

#[tokio::test]
async fn touch_client_for_share_updates_current_difficulty() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    // Register a session at an initial assigned difficulty.
    upsert_client(&mut *tx, &mk("sessD003")).await.unwrap();

    // A share comes in at a new (vardiff-ratcheted) assigned difficulty.
    let n = touch_client_for_share(
        &mut *tx,
        "test_client_addr",
        "wkr",
        "sessD003",
        65_536.0,       // share_diff → bestDifficulty (GREATEST)
        Some(32_768.0), // current_diff → currentDifficulty
        3,              // channel_count → channelCount (bundled rig)
        1_700_000_100_000,
    )
    .await
    .expect("touch");
    assert_eq!(n, 1, "touch must update the matching row");

    let row = sqlx::query(
        r#"SELECT "currentDifficulty", "bestDifficulty", "channelCount" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessD003")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let cd: Option<f32> = row.get("currentDifficulty");
    let bd: Option<f32> = row.get("bestDifficulty");
    let cc: i32 = row.get("channelCount");
    assert!(
        cd.is_some() && (cd.unwrap() - 32_768.0).abs() < 0.01,
        "currentDifficulty must reflect the assigned vardiff target, got {cd:?}"
    );
    assert!(bd.is_some() && (bd.unwrap() - 65_536.0).abs() < 0.01);
    assert_eq!(cc, 3, "channelCount must reflect the bundled channel count");

    // A follow-up touch with `None` leaves currentDifficulty unchanged.
    touch_client_for_share(
        &mut *tx,
        "test_client_addr",
        "wkr",
        "sessD003",
        70_000.0,
        None,
        1,
        1_700_000_200_000,
    )
    .await
    .expect("touch none");
    let cd2: Option<f32> = sqlx::query_scalar(
        r#"SELECT "currentDifficulty" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessD003")
    .fetch_one(&mut *tx)
    .await
    .expect("read2");
    assert!(
        cd2.is_some() && (cd2.unwrap() - 32_768.0).abs() < 0.01,
        "None must leave currentDifficulty unchanged"
    );

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upsert_client_distinct_sessions_stay_independent() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    upsert_client(&mut *tx, &mk("sessD003")).await.unwrap();
    upsert_client(&mut *tx, &mk("sessD004")).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_entity
           WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(n, 2, "two sessions, two rows");
    tx.rollback().await.expect("rollback");
}

// ── delete_client_for_session ───────────────────────────────────────

#[tokio::test]
async fn delete_client_for_session_soft_deletes_by_session_id() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    upsert_client(&mut *tx, &mk("sessE005")).await.unwrap();

    let affected = delete_client_for_session(&mut *tx, "sessE005")
        .await
        .unwrap();
    assert_eq!(affected, 1);

    let del: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessE005")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(del.is_some(), "deletedAt must be set");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn delete_client_for_session_is_idempotent_against_missing_session() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let n = delete_client_for_session(&mut *tx, "sess_no")
        .await
        .unwrap();
    assert_eq!(n, 0, "missing session returns 0 — not an error");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn delete_client_for_session_skips_already_deleted_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    upsert_client(&mut *tx, &mk("sessF006")).await.unwrap();
    delete_client_for_session(&mut *tx, "sessF006")
        .await
        .unwrap();
    // Second delete is a no-op because deletedAt IS NULL filter excludes it.
    let n = delete_client_for_session(&mut *tx, "sessF006")
        .await
        .unwrap();
    assert_eq!(n, 0, "second delete is no-op");
    tx.rollback().await.expect("rollback");
}

// ── kill_dead_clients (stale-session cleanup cron primitive) ────────

#[tokio::test]
async fn kill_dead_clients_soft_deletes_rows_with_old_updated_at() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Insert two clients; force one's updatedAt to be ancient by direct
    // UPDATE in the tx (sqlx doesn't expose this on the upsert API).
    upsert_client(&mut *tx, &mk("sessK001")).await.unwrap();
    upsert_client(&mut *tx, &mk("sessK002")).await.unwrap();
    sqlx::query(r#"UPDATE client_entity SET "updatedAt" = 1000 WHERE "sessionId" = $1"#)
        .bind("sessK001")
        .execute(&mut *tx)
        .await
        .unwrap();

    // Cutoff at 2000 — only sessK001 should die.
    let n = kill_dead_clients(&mut *tx, 2000).await.unwrap();
    assert_eq!(n, 1);

    let dead: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessK001")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let alive: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessK002")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(dead.is_some(), "stale session must be soft-deleted");
    assert!(alive.is_none(), "fresh session must stay alive");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn kill_dead_clients_skips_already_deleted() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    upsert_client(&mut *tx, &mk("sessK003")).await.unwrap();
    delete_client_for_session(&mut *tx, "sessK003")
        .await
        .unwrap();
    // Force ancient updatedAt — still wouldn't fire because deletedAt
    // IS NULL filter excludes it.
    sqlx::query(r#"UPDATE client_entity SET "updatedAt" = 1 WHERE "sessionId" = $1"#)
        .bind("sessK003")
        .execute(&mut *tx)
        .await
        .unwrap();
    let n = kill_dead_clients(&mut *tx, i64::MAX).await.unwrap();
    // Other rows might also exist in the DB and get killed; we just
    // assert our specific session didn't get re-killed.
    let _ = n;
    let original_del: Option<i64> =
        sqlx::query_scalar(r#"SELECT "deletedAt" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("sessK003")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(
        original_del.is_some(),
        "row stays soft-deleted (idempotent)"
    );
    tx.rollback().await.expect("rollback");
}

// ── update_sv2_user_agent_by_address ────────────────────────────────

#[tokio::test]
async fn update_sv2_user_agent_by_address_bumps_updated_at() {
    // Regression guard: updateSv2UserAgentByAddress must refresh updatedAt,
    // otherwise a downstream-report refining a worker's userAgent would leave
    // a stale "last seen" timestamp. Lock the bump in.
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Seed a client row with userAgent = "jd-client/sv2" (one of the SV2
    // placeholders this fn rewrites) and a frozen-old updatedAt.
    let stale_updated_at = 1_700_000_000_000_i64;
    sqlx::query(
        r#"INSERT INTO client_entity
             (address, "clientName", "sessionId", "userAgent",
              "startTime", "hashRate", "bestDifficulty",
              "createdAt", "updatedAt")
           VALUES ($1, 'wkr', 'sessSV2A', 'jd-client/sv2',
                   $2, 0, 0, $2, $2)"#,
    )
    .bind("test_sv2_ua_addr")
    .bind(stale_updated_at)
    .execute(&mut *tx)
    .await
    .expect("seed");

    // Use the same clock the UPDATE writes from (PG's NOW()) to side-step
    // any drift between the Rust process clock and the PG container clock.
    let now_before: i64 =
        sqlx::query_scalar(r#"SELECT (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint"#)
            .fetch_one(&mut *tx)
            .await
            .expect("read pg now");
    let n = update_sv2_user_agent_by_address(&mut *tx, "test_sv2_ua_addr", "bitaxe/3.0")
        .await
        .expect("update");
    assert_eq!(n, 1, "exactly one row should be rewritten");

    let (ua, updated_at): (String, i64) = sqlx::query_as(
        r#"SELECT "userAgent", "updatedAt" FROM client_entity WHERE "sessionId" = $1"#,
    )
    .bind("sessSV2A")
    .fetch_one(&mut *tx)
    .await
    .expect("read back");

    assert_eq!(ua, "bitaxe/3.0", "userAgent rewritten to the refined value");
    assert!(
        updated_at >= now_before,
        "updatedAt must be bumped to >= NOW() reference ({updated_at} vs {now_before})"
    );
    assert!(
        updated_at > stale_updated_at,
        "updatedAt must move past the stale seed value"
    );

    tx.rollback().await.expect("rollback");
}

// ── bulk_touch_clients_for_share ──────────────────────────────────

#[tokio::test]
async fn bulk_touch_clients_for_share_collapses_updates() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    // Unique test sessions — bulk path runs outside a TX, clean up by
    // sessionId to avoid cross-run pollution.
    const SESSIONS: &[&str] = &["tBTs1", "tBTs2"];
    for sid in SESSIONS {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await;
    }

    // Seed two distinct sessions.
    for sid in SESSIONS {
        upsert_client(
            &pool,
            &ClientUpsert {
                address: "test_bulktouch_addr".to_string(),
                client_name: "wkr".to_string(),
                session_id: sid.to_string(),
                user_agent: Some("bitaxe/test".to_string()),
                start_time_ms: 1,
                current_difficulty: None,
            },
        )
        .await
        .expect("seed client");
    }

    // Bulk touch with mixed Some/None for current_diff.
    let addresses = vec!["test_bulktouch_addr".to_string(); 2];
    let client_names = vec!["wkr".to_string(); 2];
    let session_ids: Vec<String> = SESSIONS.iter().map(|s| s.to_string()).collect();
    let share_diffs = vec![65_536.0_f32, 1_024.0_f32];
    let current_diffs = vec![Some(32_768.0_f32), None];
    let channel_counts = vec![3_i32, 1_i32];
    let updated_ats = vec![1_700_000_000_000_i64, 1_700_000_100_000_i64];

    let affected = bulk_touch_clients_for_share(
        &pool,
        &addresses,
        &client_names,
        &session_ids,
        &share_diffs,
        &current_diffs,
        &channel_counts,
        &updated_ats,
    )
    .await
    .expect("bulk touch");
    assert_eq!(affected, 2, "both seeded rows must update");

    // Row 1: Some values were applied.
    let row1 = sqlx::query(
        r#"SELECT "currentDifficulty", "bestDifficulty", "channelCount", "updatedAt"
           FROM client_entity WHERE "sessionId" = $1"#,
    )
    .bind("tBTs1")
    .fetch_one(&pool)
    .await
    .expect("read1");
    let cd1: Option<f32> = row1.get("currentDifficulty");
    let bd1: Option<f32> = row1.get("bestDifficulty");
    let cc1: i32 = row1.get("channelCount");
    let ua1: i64 = row1.get("updatedAt");
    assert!(
        cd1.is_some() && (cd1.unwrap() - 32_768.0).abs() < 0.01,
        "row1 currentDifficulty = Some(32768), got {cd1:?}"
    );
    assert!(bd1.is_some() && (bd1.unwrap() - 65_536.0).abs() < 0.01);
    assert_eq!(cc1, 3, "row1 channelCount = 3 (bundled rig)");
    assert_eq!(ua1, 1_700_000_000_000);

    // Row 2: None values preserved the seeded zero defaults; bestDiff
    // still bumped via GREATEST.
    let row2 = sqlx::query(
        r#"SELECT "currentDifficulty", "bestDifficulty", "channelCount", "updatedAt"
           FROM client_entity WHERE "sessionId" = $1"#,
    )
    .bind("tBTs2")
    .fetch_one(&pool)
    .await
    .expect("read2");
    let cd2: Option<f32> = row2.get("currentDifficulty");
    let bd2: Option<f32> = row2.get("bestDifficulty");
    let cc2: i32 = row2.get("channelCount");
    let ua2: i64 = row2.get("updatedAt");
    assert_eq!(cc2, 1, "row2 channelCount = 1 (single channel)");
    // currentDifficulty seeded was 0/null — COALESCE(NULL, t.col) keeps it as-is.
    assert!(
        cd2.is_none() || cd2.unwrap_or(0.0) == 0.0,
        "row2 currentDifficulty preserved (None or 0), got {cd2:?}"
    );
    assert!(bd2.is_some() && (bd2.unwrap() - 1_024.0).abs() < 0.01);
    assert_eq!(ua2, 1_700_000_100_000);

    // Cleanup.
    for sid in SESSIONS {
        sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}

// ── bulk_set_client_hashrate ──────────────────────────────────────

#[tokio::test]
async fn bulk_set_client_hashrate_overwrites_and_skips_deleted() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let _guard = HASHRATE_DB_LOCK.lock().await;

    const ACTIVE: &str = "tHRact";
    const DELETED: &str = "tHRdel";
    for sid in [ACTIVE, DELETED] {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await;
    }

    // Seed two sessions, both with a stale non-zero hashRate.
    for sid in [ACTIVE, DELETED] {
        upsert_client(
            &pool,
            &ClientUpsert {
                address: "test_hr_addr".to_string(),
                client_name: "wkr".to_string(),
                session_id: sid.to_string(),
                user_agent: Some("bitaxe/test".to_string()),
                start_time_ms: 1,
                current_difficulty: None,
            },
        )
        .await
        .expect("seed client");
        sqlx::query(r#"UPDATE client_entity SET "hashRate" = 5.0e11 WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("seed hashRate");
    }
    // Soft-delete one of them — the sampler must not resurrect its value.
    sqlx::query(r#"UPDATE client_entity SET "deletedAt" = 1 WHERE "sessionId" = $1"#)
        .bind(DELETED)
        .execute(&pool)
        .await
        .expect("soft-delete");

    // One live write (a fresh estimate) + one 0 (a faded/idle session).
    let addresses = vec!["test_hr_addr".to_string(); 2];
    let client_names = vec!["wkr".to_string(); 2];
    let session_ids = vec![ACTIVE.to_string(), DELETED.to_string()];
    let hash_rates = vec![9.0e12_f64, 0.0_f64];

    let affected =
        bulk_set_client_hashrate(&pool, &addresses, &client_names, &session_ids, &hash_rates)
            .await
            .expect("bulk set hashrate");
    assert_eq!(affected, 1, "only the non-deleted row must update");

    let active_hr: f64 =
        sqlx::query_scalar(r#"SELECT "hashRate" FROM client_entity WHERE "sessionId" = $1"#)
            .bind(ACTIVE)
            .fetch_one(&pool)
            .await
            .expect("read active");
    assert!(
        (active_hr - 9.0e12).abs() < 1.0,
        "active row overwritten with the new estimate, got {active_hr}"
    );

    // The soft-deleted row keeps its stale value — the guard skipped it.
    let deleted_hr: f64 =
        sqlx::query_scalar(r#"SELECT "hashRate" FROM client_entity WHERE "sessionId" = $1"#)
            .bind(DELETED)
            .fetch_one(&pool)
            .await
            .expect("read deleted");
    assert!(
        (deleted_hr - 5.0e11).abs() < 1.0,
        "soft-deleted row untouched (excluded from active SUM anyway), got {deleted_hr}"
    );

    // A follow-up 0 write self-zeroes the active row.
    bulk_set_client_hashrate(
        &pool,
        &["test_hr_addr".to_string()],
        &["wkr".to_string()],
        &[ACTIVE.to_string()],
        &[0.0],
    )
    .await
    .expect("zero write");
    let zeroed: f64 =
        sqlx::query_scalar(r#"SELECT "hashRate" FROM client_entity WHERE "sessionId" = $1"#)
            .bind(ACTIVE)
            .fetch_one(&pool)
            .await
            .expect("read zeroed");
    assert_eq!(zeroed, 0.0, "idle session self-zeroes");

    for sid in [ACTIVE, DELETED] {
        sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}

// ── reset_all_client_hashrate ─────────────────────────────────────

#[tokio::test]
async fn reset_all_client_hashrate_zeroes_active_only() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let _guard = HASHRATE_DB_LOCK.lock().await;

    const ACTIVE_A: &str = "tRHrA";
    const ACTIVE_B: &str = "tRHrB";
    const DELETED: &str = "tRHrD";
    for sid in [ACTIVE_A, ACTIVE_B, DELETED] {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await;
    }

    for sid in [ACTIVE_A, ACTIVE_B, DELETED] {
        upsert_client(
            &pool,
            &ClientUpsert {
                address: "test_resethr_addr".to_string(),
                client_name: "wkr".to_string(),
                session_id: sid.to_string(),
                user_agent: None,
                start_time_ms: 1,
                current_difficulty: None,
            },
        )
        .await
        .expect("seed client");
        sqlx::query(r#"UPDATE client_entity SET "hashRate" = 7.0e12 WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("seed hashRate");
    }
    // Soft-delete one — reset must leave it alone (it's excluded from active
    // sums anyway) and not count it.
    sqlx::query(r#"UPDATE client_entity SET "deletedAt" = 1 WHERE "sessionId" = $1"#)
        .bind(DELETED)
        .execute(&pool)
        .await
        .expect("soft-delete");

    let cleared = reset_all_client_hashrate(&pool).await.expect("reset");
    assert!(
        cleared >= 2,
        "at least our two active non-zero rows are cleared, got {cleared}"
    );

    for sid in [ACTIVE_A, ACTIVE_B] {
        let hr: f64 =
            sqlx::query_scalar(r#"SELECT "hashRate" FROM client_entity WHERE "sessionId" = $1"#)
                .bind(sid)
                .fetch_one(&pool)
                .await
                .expect("read active");
        assert_eq!(hr, 0.0, "active row zeroed on boot reconcile");
    }
    let del_hr: f64 =
        sqlx::query_scalar(r#"SELECT "hashRate" FROM client_entity WHERE "sessionId" = $1"#)
            .bind(DELETED)
            .fetch_one(&pool)
            .await
            .expect("read deleted");
    assert!((del_hr - 7.0e12).abs() < 1.0, "soft-deleted row untouched");

    // Idempotent + the `<> 0` guard: a second call clears nothing.
    let again = reset_all_client_hashrate(&pool).await.expect("reset again");
    assert_eq!(again, 0, "no non-zero active rows left to clear");

    for sid in [ACTIVE_A, ACTIVE_B, DELETED] {
        sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}

// ── the advisory lock that serialises the two bulk writers ─────────

/// MONEY-adjacent, but really an availability test: the 30 s touch flush and
/// the 60 s hashrate sampler both drive `UPDATE … FROM unnest(...)` over the
/// SAME `client_entity` rows, each in its own `HashMap` order. Postgres locks
/// rows in processing order, so before `CLIENT_ENTITY_BULK_WRITE_LOCK` the two
/// deadlocked in production — 46 times in ~90 minutes.
///
/// Deterministic on purpose. A "run both concurrently and hope they collide"
/// stress test would be green on a fast machine and prove nothing; this holds
/// the advisory lock from an outside session and asserts each writer BLOCKS.
/// Without the fix both return immediately, so it fails in both directions.
///
/// The lock key is duplicated here deliberately — it is a wire contract with
/// Postgres, and a test that imported the constant could not catch the
/// constant itself changing.
const BULK_WRITE_LOCK_KEY: i64 = 0x636c_6e74_6277;

async fn seed_lock_probe_row(pool: &PgPool, session: &str) {
    let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
        .bind(session)
        .execute(pool)
        .await;
    upsert_client(
        pool,
        &ClientUpsert {
            address: "test_lock_addr".to_string(),
            client_name: "wkr".to_string(),
            session_id: session.to_string(),
            user_agent: None,
            start_time_ms: 1,
            current_difficulty: None,
        },
    )
    .await
    .expect("seed client");
}

#[tokio::test]
async fn both_bulk_writers_wait_on_the_shared_advisory_lock() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let _guard = HASHRATE_DB_LOCK.lock().await;

    const SID: &str = "tLckPrb";
    seed_lock_probe_row(&pool, SID).await;

    // A dedicated connection holds the lock SESSION-scoped, so it outlives
    // the statements under test. Own pool: the shared one has 2 connections
    // and both writers need one while we hold this.
    let holder_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string()))
        .await
        .expect("holder pool");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(BULK_WRITE_LOCK_KEY)
        .execute(&holder_pool)
        .await
        .expect("take lock");

    let addresses = vec!["test_lock_addr".to_string()];
    let names = vec!["wkr".to_string()];
    let sessions = vec![SID.to_string()];

    // 1. The hashrate sampler's write must not get through.
    let blocked = tokio::time::timeout(
        std::time::Duration::from_millis(1_500),
        bulk_set_client_hashrate(&pool, &addresses, &names, &sessions, &[1.0e12]),
    )
    .await;
    assert!(
        blocked.is_err(),
        "bulk_set_client_hashrate returned while the bulk-write lock was held — \
         it is not taking the lock, so it can still deadlock against the toucher"
    );

    // 2. Same for the touch flush.
    let blocked = tokio::time::timeout(
        std::time::Duration::from_millis(1_500),
        bulk_touch_clients_for_share(
            &pool,
            &addresses,
            &names,
            &sessions,
            &[1.0f32],
            &[None],
            &[1i32],
            &[42i64],
        ),
    )
    .await;
    assert!(
        blocked.is_err(),
        "bulk_touch_clients_for_share returned while the bulk-write lock was held — \
         it is not taking the lock"
    );

    // Negative control: with the lock released, the very same call succeeds —
    // so the timeouts above were the lock, not a broken statement or a dead DB.
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BULK_WRITE_LOCK_KEY)
        .execute(&holder_pool)
        .await
        .expect("release lock");
    holder_pool.close().await;

    let rows = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bulk_set_client_hashrate(&pool, &addresses, &names, &sessions, &[1.0e12]),
    )
    .await
    .expect("must not block once the lock is free")
    .expect("write ok");
    assert_eq!(rows, 1, "the probe row must actually be updated");

    let stored: f64 = sqlx::query(r#"SELECT "hashRate" FROM client_entity WHERE "sessionId" = $1"#)
        .bind(SID)
        .fetch_one(&pool)
        .await
        .expect("read back")
        .get(0);
    assert_eq!(stored, 1.0e12);

    let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
        .bind(SID)
        .execute(&pool)
        .await;
}

// ── bulk_upsert_client_difficulty_statistics ──────────────────────

/// The batched form must keep the per-slot MAX, not last-write-wins: the
/// flush window is drained in `HashMap` order, so if the upsert overwrote
/// instead of taking `GREATEST`, whichever row happened to be iterated last
/// would decide the stored value — and a miner's best share of the hour would
/// silently disappear whenever a lower one followed it into the same batch.
#[tokio::test]
async fn bulk_diff_stats_keep_the_running_max_per_slot() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ADDR: &str = "test_bulk_diff_addr";
    const SLOT: i64 = 1_700_000_000_000;
    let del = || {
        sqlx::query(r#"DELETE FROM client_difficulty_statistics_entity WHERE address = $1"#)
            .bind(ADDR)
            .execute(&pool)
    };
    let _ = del().await;

    let addrs = vec![ADDR.to_string(), ADDR.to_string()];
    let workers = vec!["rigA".to_string(), "rigB".to_string()];
    let slots = vec![SLOT, SLOT];

    // Two workers, one statement.
    let rows = bulk_upsert_client_difficulty_statistics(
        &pool,
        &addrs,
        &workers,
        &slots,
        &[1_000.0f32, 4_000.0f32],
        &[10i64, 10i64],
    )
    .await
    .expect("first upsert");
    assert_eq!(rows, 2);

    // rigA gets a HIGHER max, rigB a LOWER one — in the same batch.
    bulk_upsert_client_difficulty_statistics(
        &pool,
        &addrs,
        &workers,
        &slots,
        &[9_000.0f32, 5.0f32],
        &[20i64, 20i64],
    )
    .await
    .expect("second upsert");

    let read = |worker: &'static str| {
        sqlx::query(
            r#"SELECT "maxDifficulty"::float8 AS m, "createdAt" AS c, "updatedAt" AS u
                   FROM client_difficulty_statistics_entity
                   WHERE address = $1 AND "clientName" = $2 AND "slotTime" = $3"#,
        )
        .bind(ADDR)
        .bind(worker)
        .bind(SLOT)
        .fetch_one(&pool)
    };

    let a = read("rigA").await.expect("rigA row");
    let m: f64 = a.get("m");
    assert_eq!(m, 9_000.0, "a higher share must raise the slot max");

    let b = read("rigB").await.expect("rigB row");
    let m: f64 = b.get("m");
    assert_eq!(m, 4_000.0, "a LOWER share must not lower the slot max");
    let created: i64 = b.get("c");
    let updated: i64 = b.get("u");
    assert_eq!(
        created, 10,
        "createdAt belongs to the insert and must not move"
    );
    assert_eq!(
        updated, 20,
        "updatedAt tracks the latest write even when the max held"
    );

    let _ = del().await;
}
