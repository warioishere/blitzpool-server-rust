// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the session-persistence write-primitives
//! (`upsert_client`, `delete_client_for_session`, …). Single-row tests
//! wrap writes in TX-rollback for isolation; the bulk writers own their
//! transaction (bulk-write lock), so their tests clean up by sessionId.

use bp_common::AddressId;
use bp_db::{
    bulk_upsert_client_difficulty_statistics, delete_client_for_session,
    find_addresses_for_ntfy_listener, find_stale_active_sessions, soft_delete_sessions,
    update_sv2_user_agent_by_address, upsert_client, upsert_ntfy_subscription, ClientUpsert,
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
        r#"SELECT "userAgent", "deletedAt" FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind("test_client_addr")
    .bind("wkr")
    .bind("sessA001")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let ua: Option<String> = row.get("userAgent");
    let del: Option<i64> = row.get("deletedAt");
    assert_eq!(ua.as_deref(), Some("bitaxe/2.7"));
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

// ── bulk_upsert_clients ─────────────────────────────────────────────

/// The birth flush's bulk form: N rows, mixed insert + conflict, mixed
/// Some/None `userAgent`, in one statement. Same statement as
/// `upsert_client`, so the column semantics above carry over; what this
/// pins is the array plumbing. Pool-level (the fn owns its transaction
/// for the bulk-write lock), so cleanup by sessionId instead of
/// TX-rollback.
#[tokio::test]
async fn bulk_upsert_clients_inserts_and_updates_in_one_statement() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const SESSIONS: &[&str] = &["tBUs1", "tBUs2"];
    for sid in SESSIONS {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await;
    }

    // Seed the first session, then soft-delete it — its bulk entry runs
    // the conflict arm; the second session's entry is a fresh insert.
    bp_db::bulk_upsert_clients(
        &pool,
        &[ClientUpsert {
            address: "test_bulkups_addr".to_string(),
            client_name: "wkr".to_string(),
            session_id: "tBUs1".to_string(),
            user_agent: Some("bitaxe/2.7".to_string()),
            start_time_ms: 1_700_000_000_000,
        }],
    )
    .await
    .expect("seed");
    delete_client_for_session(&pool, "tBUs1")
        .await
        .expect("soft-delete seed");

    let rows = [
        ClientUpsert {
            address: "test_bulkups_addr".to_string(),
            client_name: "wkr".to_string(),
            session_id: "tBUs1".to_string(),
            user_agent: Some("bitaxe/3.0".to_string()),
            start_time_ms: 1_700_000_099_000,
        },
        ClientUpsert {
            address: "test_bulkups_addr".to_string(),
            client_name: "wkr2".to_string(),
            session_id: "tBUs2".to_string(),
            user_agent: None,
            start_time_ms: 1_700_000_050_000,
        },
    ];
    let n = bp_db::bulk_upsert_clients(&pool, &rows)
        .await
        .expect("bulk upsert");
    assert_eq!(n, 2, "one conflict-update + one insert");

    let row1 = sqlx::query(
        r#"SELECT "userAgent", "deletedAt", "firstSeen" FROM client_entity
           WHERE "sessionId" = $1"#,
    )
    .bind("tBUs1")
    .fetch_one(&pool)
    .await
    .expect("read conflict row");
    let ua1: Option<String> = row1.get("userAgent");
    let del1: Option<i64> = row1.get("deletedAt");
    let fs1: Option<i64> = row1.get("firstSeen");
    assert_eq!(
        ua1.as_deref(),
        Some("bitaxe/3.0"),
        "conflict arm refreshes userAgent"
    );
    assert!(del1.is_none(), "conflict arm clears the soft-delete");
    assert_eq!(
        fs1,
        Some(1_700_000_000_000),
        "firstSeen survives the re-register"
    );

    let row2 =
        sqlx::query(r#"SELECT "userAgent", "firstSeen" FROM client_entity WHERE "sessionId" = $1"#)
            .bind("tBUs2")
            .fetch_one(&pool)
            .await
            .expect("read insert row");
    let ua2: Option<String> = row2.get("userAgent");
    let fs2: Option<i64> = row2.get("firstSeen");
    assert_eq!(ua2, None, "a NULL userAgent element must stay NULL");
    assert_eq!(
        fs2,
        Some(1_700_000_050_000),
        "firstSeen = startTime on insert"
    );

    for sid in SESSIONS {
        sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(sid)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}

/// An over-long `clientName` (varchar(64)) fails the WHOLE bulk
/// statement — and it surfaces as `DbError::Sqlx(sqlx::Error::Database)`.
/// The row-birth debounce keys its retry-or-drop decision on exactly
/// that variant, so this pins the classification against sqlx.
#[tokio::test]
async fn bulk_upsert_clients_oversized_name_fails_whole_batch_as_database_error() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const HEALTHY: &str = "tBUpsn";
    let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
        .bind(HEALTHY)
        .execute(&pool)
        .await;

    let rows = [
        ClientUpsert {
            address: "test_bulkups_addr".to_string(),
            client_name: "w".repeat(65),
            session_id: "tBUpsX".to_string(),
            user_agent: None,
            start_time_ms: 1,
        },
        ClientUpsert {
            address: "test_bulkups_addr".to_string(),
            client_name: "wkr".to_string(),
            session_id: HEALTHY.to_string(),
            user_agent: None,
            start_time_ms: 1,
        },
    ];
    let err = bp_db::bulk_upsert_clients(&pool, &rows)
        .await
        .expect_err("varchar(64) overflow must fail the statement");
    assert!(
        matches!(&err, bp_db::DbError::Sqlx(sqlx::Error::Database(_))),
        "a 22001 must classify as a database (row-specific) error, got: {err:?}"
    );

    let healthy_rows: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM client_entity WHERE "sessionId" = $1"#)
            .bind(HEALTHY)
            .fetch_one(&pool)
            .await
            .expect("count healthy");
    assert_eq!(
        healthy_rows, 0,
        "the statement is all-or-nothing — the healthy row rolls back with it; \
         per-row isolation is the caller's job (see bp-session-persistence)"
    );
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

// ── dead-session sweep primitives (candidates + verdict halves) ─────
//
// The sweep itself lives in bin/blitzpool and consults Redis between
// these two calls; the PG halves are pinned here: age selects
// CANDIDATES only, and the soft-delete hits exactly the given triples.

#[tokio::test]
async fn stale_sessions_become_candidates_and_only_named_ones_die() {
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

    // Cutoff at 2000 — only sessK001 is a candidate; the fresh session
    // must not even be OFFERED to the verdict step.
    let candidates = find_stale_active_sessions(&mut *tx, 2000).await.unwrap();
    assert!(
        candidates.iter().any(|c| c.session_id == "sessK001"),
        "ancient session must be a candidate"
    );
    assert!(
        !candidates.iter().any(|c| c.session_id == "sessK002"),
        "fresh session must not be a candidate (birth grace)"
    );

    // Verdict: soft-delete exactly the named triple.
    let n = soft_delete_sessions(
        &mut *tx,
        &["test_client_addr".to_string()],
        &["wkr".to_string()],
        &["sessK001".to_string()],
    )
    .await
    .unwrap();
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
    assert!(dead.is_some(), "named session must be soft-deleted");
    assert!(alive.is_none(), "unnamed session must stay alive");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn sweep_primitives_skip_already_deleted_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    upsert_client(&mut *tx, &mk("sessK003")).await.unwrap();
    delete_client_for_session(&mut *tx, "sessK003")
        .await
        .unwrap();
    // Force ancient updatedAt — still no candidate, because the
    // deletedAt IS NULL filter excludes it.
    sqlx::query(r#"UPDATE client_entity SET "updatedAt" = 1 WHERE "sessionId" = $1"#)
        .bind("sessK003")
        .execute(&mut *tx)
        .await
        .unwrap();
    let candidates = find_stale_active_sessions(&mut *tx, i64::MAX)
        .await
        .unwrap();
    assert!(
        !candidates.iter().any(|c| c.session_id == "sessK003"),
        "soft-deleted row must not be a candidate"
    );
    // And a soft-delete aimed at it is a no-op (deletedAt preserved).
    let n = soft_delete_sessions(
        &mut *tx,
        &["test_client_addr".to_string()],
        &["wkr".to_string()],
        &["sessK003".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(n, 0, "already-deleted row is skipped");
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
              "startTime", "createdAt", "updatedAt")
           VALUES ($1, 'wkr', 'sessSV2A', 'jd-client/sv2',
                   $2, $2, $2)"#,
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
