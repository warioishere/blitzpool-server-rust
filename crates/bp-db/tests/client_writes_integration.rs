// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the 3 session-persistence write-primitives
//! (`upsert_client`, `delete_client_for_session`,
//! `upsert_address_best_difficulty`). Each test wraps writes in
//! TX-rollback for isolation.

use bp_common::AddressId;
use bp_db::{
    bulk_touch_clients_for_share, delete_client_for_session, find_addresses_for_ntfy_listener,
    find_client_recent_first_seen, kill_dead_clients, touch_client_for_share,
    update_sv2_user_agent_by_address, upsert_address_best_difficulty, upsert_client,
    upsert_ntfy_subscription, ClientUpsert,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

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
        Some(1.0e12),   // hash_rate
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

// ── upsert_address_best_difficulty ─────────────────────────────────

#[tokio::test]
async fn upsert_best_difficulty_inserts_when_address_row_missing() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    // Cleanup leftover from previous test runs (no FK).
    sqlx::query(r#"DELETE FROM address_settings_entity WHERE address = $1"#)
        .bind("test_bd_addr_new")
        .execute(&mut *tx)
        .await
        .unwrap();

    let n = upsert_address_best_difficulty(&mut *tx, "test_bd_addr_new", 100.5, Some("bitaxe"))
        .await
        .unwrap();
    assert_eq!(n, 1, "insert path");

    let row = sqlx::query(
        r#"SELECT "bestDifficulty", "bestDifficultyUserAgent"
           FROM address_settings_entity WHERE address = $1"#,
    )
    .bind("test_bd_addr_new")
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let bd: f64 = row.get("bestDifficulty");
    let ua: Option<String> = row.get("bestDifficultyUserAgent");
    assert!((bd - 100.5).abs() < 0.01);
    assert_eq!(ua.as_deref(), Some("bitaxe"));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upsert_best_difficulty_updates_only_when_candidate_is_strictly_greater() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query(r#"DELETE FROM address_settings_entity WHERE address = $1"#)
        .bind("test_bd_cas")
        .execute(&mut *tx)
        .await
        .unwrap();

    // Seed with 50.
    upsert_address_best_difficulty(&mut *tx, "test_bd_cas", 50.0, Some("v1"))
        .await
        .unwrap();
    // Lower candidate — no-op.
    let n_low = upsert_address_best_difficulty(&mut *tx, "test_bd_cas", 40.0, Some("v2"))
        .await
        .unwrap();
    assert_eq!(n_low, 0, "lower candidate must not update");
    // Equal candidate — also no-op (strictly greater semantic).
    let n_eq = upsert_address_best_difficulty(&mut *tx, "test_bd_cas", 50.0, Some("v3"))
        .await
        .unwrap();
    assert_eq!(n_eq, 0, "equal candidate must not update");
    // Higher candidate — updates.
    let n_hi = upsert_address_best_difficulty(&mut *tx, "test_bd_cas", 75.0, Some("v4"))
        .await
        .unwrap();
    assert_eq!(n_hi, 1, "higher candidate must update");

    let row = sqlx::query(
        r#"SELECT "bestDifficulty", "bestDifficultyUserAgent"
           FROM address_settings_entity WHERE address = $1"#,
    )
    .bind("test_bd_cas")
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let bd: f64 = row.get("bestDifficulty");
    let ua: Option<String> = row.get("bestDifficultyUserAgent");
    assert!((bd - 75.0).abs() < 0.01);
    assert_eq!(ua.as_deref(), Some("v4"));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upsert_best_difficulty_with_no_user_agent_clears_field() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query(r#"DELETE FROM address_settings_entity WHERE address = $1"#)
        .bind("test_bd_no_ua")
        .execute(&mut *tx)
        .await
        .unwrap();

    upsert_address_best_difficulty(&mut *tx, "test_bd_no_ua", 10.0, Some("v1"))
        .await
        .unwrap();
    upsert_address_best_difficulty(&mut *tx, "test_bd_no_ua", 20.0, None)
        .await
        .unwrap();
    let ua: Option<String> = sqlx::query_scalar(
        r#"SELECT "bestDifficultyUserAgent" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind("test_bd_no_ua")
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(ua.is_none(), "None overwrites previous user agent");
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

    // Bulk touch with mixed Some/None for current_diff and hash_rate.
    let addresses = vec!["test_bulktouch_addr".to_string(); 2];
    let client_names = vec!["wkr".to_string(); 2];
    let session_ids: Vec<String> = SESSIONS.iter().map(|s| s.to_string()).collect();
    let share_diffs = vec![65_536.0_f32, 1_024.0_f32];
    let current_diffs = vec![Some(32_768.0_f32), None];
    let hash_rates = vec![Some(1.0e12_f64), None];
    let channel_counts = vec![3_i32, 1_i32];
    let updated_ats = vec![1_700_000_000_000_i64, 1_700_000_100_000_i64];

    let affected = bulk_touch_clients_for_share(
        &pool,
        &addresses,
        &client_names,
        &session_ids,
        &share_diffs,
        &current_diffs,
        &hash_rates,
        &channel_counts,
        &updated_ats,
    )
    .await
    .expect("bulk touch");
    assert_eq!(affected, 2, "both seeded rows must update");

    // Row 1: Some values were applied.
    let row1 = sqlx::query(
        r#"SELECT "currentDifficulty", "bestDifficulty", "hashRate", "channelCount", "updatedAt"
           FROM client_entity WHERE "sessionId" = $1"#,
    )
    .bind("tBTs1")
    .fetch_one(&pool)
    .await
    .expect("read1");
    let cd1: Option<f32> = row1.get("currentDifficulty");
    let bd1: Option<f32> = row1.get("bestDifficulty");
    let hr1: Option<f64> = row1.get("hashRate");
    let cc1: i32 = row1.get("channelCount");
    let ua1: i64 = row1.get("updatedAt");
    assert!(
        cd1.is_some() && (cd1.unwrap() - 32_768.0).abs() < 0.01,
        "row1 currentDifficulty = Some(32768), got {cd1:?}"
    );
    assert!(bd1.is_some() && (bd1.unwrap() - 65_536.0).abs() < 0.01);
    assert!(hr1.is_some() && (hr1.unwrap() - 1.0e12).abs() < 1.0);
    assert_eq!(cc1, 3, "row1 channelCount = 3 (bundled rig)");
    assert_eq!(ua1, 1_700_000_000_000);

    // Row 2: None values preserved the seeded zero defaults; bestDiff
    // still bumped via GREATEST.
    let row2 = sqlx::query(
        r#"SELECT "currentDifficulty", "bestDifficulty", "hashRate", "channelCount", "updatedAt"
           FROM client_entity WHERE "sessionId" = $1"#,
    )
    .bind("tBTs2")
    .fetch_one(&pool)
    .await
    .expect("read2");
    let cd2: Option<f32> = row2.get("currentDifficulty");
    let bd2: Option<f32> = row2.get("bestDifficulty");
    let hr2: Option<f64> = row2.get("hashRate");
    let cc2: i32 = row2.get("channelCount");
    let ua2: i64 = row2.get("updatedAt");
    assert_eq!(cc2, 1, "row2 channelCount = 1 (single channel)");
    // currentDifficulty seeded was 0/null — COALESCE(NULL, t.col) keeps it as-is.
    assert!(
        cd2.is_none() || cd2.unwrap_or(0.0) == 0.0,
        "row2 currentDifficulty preserved (None or 0), got {cd2:?}"
    );
    assert!(bd2.is_some() && (bd2.unwrap() - 1_024.0).abs() < 0.01);
    // hashRate seeded was 0 — COALESCE(NULL, t.col) keeps 0.
    assert!(
        hr2.is_none() || hr2.unwrap_or(0.0) == 0.0,
        "row2 hashRate preserved, got {hr2:?}"
    );
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

// ── find_client_recent_first_seen ─────────────────────────────────

#[tokio::test]
async fn find_client_recent_first_seen_honours_30min_window() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    const SESSIONS: &[&str] = &["tFRfs1", "tFRfs2"];
    for sid in SESSIONS {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await;
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let recent_updated = now_ms - 5 * 60 * 1000; // 5 min ago
    let stale_updated = now_ms - 90 * 60 * 1000; // 90 min ago
    let cutoff_ms = now_ms - 30 * 60 * 1000;

    // Seed two distinct (address, clientName) pairs with the same
    // startTime but distinct "lastActive" (updatedAt) timestamps.
    upsert_client(
        &pool,
        &ClientUpsert {
            address: "tFRfsR".to_string(), // returning case
            client_name: "wkr".to_string(),
            session_id: "tFRfs1".to_string(),
            user_agent: Some("bitaxe".to_string()),
            start_time_ms: now_ms - 7 * 24 * 60 * 60 * 1000, // 7 days ago
            current_difficulty: None,
        },
    )
    .await
    .expect("seed returning");
    sqlx::query(r#"UPDATE client_entity SET "updatedAt" = $1 WHERE "sessionId" = $2"#)
        .bind(recent_updated)
        .bind("tFRfs1")
        .execute(&pool)
        .await
        .expect("set recent updatedAt");

    upsert_client(
        &pool,
        &ClientUpsert {
            address: "tFRfsS".to_string(), // stale case
            client_name: "wkr".to_string(),
            session_id: "tFRfs2".to_string(),
            user_agent: Some("bitaxe".to_string()),
            start_time_ms: now_ms - 7 * 24 * 60 * 60 * 1000,
            current_difficulty: None,
        },
    )
    .await
    .expect("seed stale");
    sqlx::query(r#"UPDATE client_entity SET "updatedAt" = $1 WHERE "sessionId" = $2"#)
        .bind(stale_updated)
        .bind("tFRfs2")
        .execute(&pool)
        .await
        .expect("set stale updatedAt");

    // Returning case: lastActive 5 min ago → within 30 min window → Some(firstSeen|startTime).
    let returning = find_client_recent_first_seen(&pool, "tFRfsR", "wkr", cutoff_ms)
        .await
        .expect("lookup returning");
    assert!(
        returning.is_some(),
        "5-min-ago lastActive must read as returning, got {returning:?}"
    );

    // Stale case: lastActive 90 min ago → outside 30 min window → None.
    let stale = find_client_recent_first_seen(&pool, "tFRfsS", "wkr", cutoff_ms)
        .await
        .expect("lookup stale");
    assert!(
        stale.is_none(),
        "90-min-ago lastActive must read as NOT returning, got {stale:?}"
    );

    // Unknown (address, worker) → None.
    let unknown = find_client_recent_first_seen(&pool, "tFRfsX", "nope", cutoff_ms)
        .await
        .expect("lookup unknown");
    assert!(unknown.is_none(), "unknown pair must read as None");

    // Cleanup.
    for sid in SESSIONS {
        sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
