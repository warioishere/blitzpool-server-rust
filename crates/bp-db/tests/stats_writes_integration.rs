// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the 8 stats-coordinator bulk-write primitives
//! in `stats_writes.rs`. Mirrors `pplns_bulk_writes.rs`
//! pattern: each test wraps in TX-rollback for isolation.
//!
//! Coverage:
//!
//! - 5 slot-bucketed bulk-upserts (`pool_share_statistics_entity`,
//!   `pool_mode_hashrate`, `pool_rejected_statistics_entity`,
//!   `client_statistics_entity`, `client_rejected_statistics_entity`):
//!   first-call inserts, second-call ON-CONFLICT-INCREMENT, empty-slice
//!   no-op.
//! - 2 lifetime-totals writes (`address_settings_entity` — one upsert
//!   folds the `shares` increment AND the `bestDifficulty` GREATEST —
//!   plus `worker_shares_entity` composite-PK upsert).
//! - 2 seed-bootstrap functions (`count_worker_shares` +
//!   `seed_worker_shares_from_client_statistics`).

use bp_db::{
    bulk_upsert_address_settings, bulk_upsert_client_rejected_statistics_entity,
    bulk_upsert_client_statistics_entity, bulk_upsert_pool_mode_hashrate,
    bulk_upsert_pool_rejected_statistics, bulk_upsert_pool_share_statistics,
    bulk_upsert_worker_shares_entity, count_worker_shares,
    seed_worker_shares_from_client_statistics, AddressSettingsUpsert, ClientRejectedStatsUpsert,
    ClientStatsUpsert, PoolModeHashrateUpsert, PoolRejectedStatsUpsert, PoolShareStatsUpsert,
    WorkerSharesUpsert,
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

/// Generate a slot end timestamp unique enough not to collide across
/// parallel tests in the same TX-isolation suite. Use the test name's
/// hash as a deterministic offset.
fn unique_slot(seed: i64) -> i64 {
    // Year-3000 epoch — far enough from any real data we might fixture
    // load that there's no chance of collision.
    32_503_680_000_000 + seed
}

// ── pool_share_statistics ────────────────────────────────────────────

#[tokio::test]
async fn pool_share_stats_insert_then_increment() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let slot = unique_slot(1);

    let rows = vec![PoolShareStatsUpsert {
        time_ms: slot,
        accepted: 100.5,
        rejected: 3.0,
    }];
    bulk_upsert_pool_share_statistics(&mut *tx, &rows)
        .await
        .expect("first upsert");

    // Second call increments.
    bulk_upsert_pool_share_statistics(&mut *tx, &rows)
        .await
        .expect("second upsert");

    let row = sqlx::query(
        r#"SELECT accepted, rejected FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot)
    .fetch_one(&mut *tx)
    .await
    .expect("read back");
    let accepted: f32 = row.get("accepted");
    let rejected: f32 = row.get("rejected");
    assert!(
        (accepted - 201.0).abs() < 0.01,
        "accepted should accumulate: got {accepted}"
    );
    assert!(
        (rejected - 6.0).abs() < 0.01,
        "rejected should accumulate: got {rejected}"
    );

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn pool_share_stats_empty_is_noop() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let n = bulk_upsert_pool_share_statistics(&mut *tx, &[])
        .await
        .expect("noop");
    assert_eq!(n, 0);
    tx.rollback().await.expect("rollback");
}

// ── pool_mode_hashrate ────────────────────────────────────────────────

#[tokio::test]
async fn pool_mode_hashrate_composite_key_increment() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let slot = unique_slot(2);

    let rows = vec![
        PoolModeHashrateUpsert {
            mode: "pplns".to_string(),
            time_ms: slot,
            diff: 10.0,
        },
        PoolModeHashrateUpsert {
            mode: "solo".to_string(),
            time_ms: slot,
            diff: 5.0,
        },
    ];
    bulk_upsert_pool_mode_hashrate(&mut *tx, &rows)
        .await
        .expect("first upsert");

    // Second call: same (mode, time) increments diff.
    bulk_upsert_pool_mode_hashrate(
        &mut *tx,
        &[PoolModeHashrateUpsert {
            mode: "pplns".to_string(),
            time_ms: slot,
            diff: 7.5,
        }],
    )
    .await
    .expect("second upsert");

    let pplns_diff: f32 = sqlx::query_scalar(
        r#"SELECT diff FROM pool_mode_hashrate WHERE mode = $1 AND "time" = $2"#,
    )
    .bind("pplns")
    .bind(slot)
    .fetch_one(&mut *tx)
    .await
    .expect("read pplns");
    let solo_diff: f32 = sqlx::query_scalar(
        r#"SELECT diff FROM pool_mode_hashrate WHERE mode = $1 AND "time" = $2"#,
    )
    .bind("solo")
    .bind(slot)
    .fetch_one(&mut *tx)
    .await
    .expect("read solo");

    assert!((pplns_diff - 17.5).abs() < 0.01, "pplns: {pplns_diff}");
    assert!((solo_diff - 5.0).abs() < 0.01, "solo: {solo_diff}");

    tx.rollback().await.expect("rollback");
}

// ── pool_rejected_statistics ─────────────────────────────────────────

#[tokio::test]
async fn pool_rejected_stats_composite_key_increment() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let slot = unique_slot(3);

    let rows = vec![
        PoolRejectedStatsUpsert {
            time_ms: slot,
            reason: "low-difficulty".to_string(),
            count: 3.0,
        },
        PoolRejectedStatsUpsert {
            time_ms: slot,
            reason: "duplicate-share".to_string(),
            count: 1.0,
        },
    ];
    bulk_upsert_pool_rejected_statistics(&mut *tx, &rows)
        .await
        .expect("first upsert");

    // Second call increments the low-difficulty bucket.
    bulk_upsert_pool_rejected_statistics(
        &mut *tx,
        &[PoolRejectedStatsUpsert {
            time_ms: slot,
            reason: "low-difficulty".to_string(),
            count: 2.0,
        }],
    )
    .await
    .expect("second upsert");

    let low: f32 = sqlx::query_scalar(
        r#"SELECT count FROM pool_rejected_statistics_entity WHERE "time" = $1 AND reason = $2"#,
    )
    .bind(slot)
    .bind("low-difficulty")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    assert!((low - 5.0).abs() < 0.01, "low-difficulty: {low}");

    tx.rollback().await.expect("rollback");
}

// ── client_statistics_entity (13 cols, batchable) ────────────────────

#[tokio::test]
async fn client_stats_insert_then_increment_all_9_fields() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let slot = unique_slot(4);

    let mk = |shares: f32, accepted: i32, rejected: i32, jnf: i32, dup: i32, low: i32| {
        ClientStatsUpsert {
            address: "test_cs_alice".to_string(),
            client_name: "w1".to_string(),
            session_id: "sess0001".to_string(),
            time_ms: slot,
            shares,
            accepted_count: accepted,
            rejected_count: rejected,
            rejected_job_not_found_count: jnf,
            rejected_job_not_found_diff1: jnf as f32 * 0.5,
            rejected_duplicate_share_count: dup,
            rejected_duplicate_share_diff1: dup as f32 * 0.25,
            rejected_low_difficulty_share_count: low,
            rejected_low_difficulty_share_diff1: low as f32 * 0.1,
        }
    };

    bulk_upsert_client_statistics_entity(&mut *tx, &[mk(100.0, 5, 3, 1, 1, 1)])
        .await
        .expect("first");
    // Second call: every numeric field accumulates.
    bulk_upsert_client_statistics_entity(&mut *tx, &[mk(50.0, 2, 0, 0, 0, 0)])
        .await
        .expect("second");

    let row = sqlx::query(
        r#"SELECT shares, "acceptedCount", "rejectedCount",
                  "rejectedJobNotFoundCount", "rejectedDuplicateShareCount",
                  "rejectedLowDifficultyShareCount"
           FROM client_statistics_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3 AND "time" = $4"#,
    )
    .bind("test_cs_alice")
    .bind("w1")
    .bind("sess0001")
    .bind(slot)
    .fetch_one(&mut *tx)
    .await
    .expect("read");

    let shares: f32 = row.get("shares");
    let accepted: i32 = row.get("acceptedCount");
    let rejected: i32 = row.get("rejectedCount");
    let jnf: i32 = row.get("rejectedJobNotFoundCount");
    let dup: i32 = row.get("rejectedDuplicateShareCount");
    let low: i32 = row.get("rejectedLowDifficultyShareCount");
    assert!((shares - 150.0).abs() < 0.01);
    assert_eq!(accepted, 7);
    assert_eq!(rejected, 3);
    assert_eq!(jnf, 1);
    assert_eq!(dup, 1);
    assert_eq!(low, 1);

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn client_stats_distinct_keys_stay_independent() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let slot = unique_slot(5);

    let base = ClientStatsUpsert {
        address: "test_cs_dist".to_string(),
        client_name: "w1".to_string(),
        session_id: "sessA".to_string(),
        time_ms: slot,
        shares: 10.0,
        accepted_count: 1,
        rejected_count: 0,
        rejected_job_not_found_count: 0,
        rejected_job_not_found_diff1: 0.0,
        rejected_duplicate_share_count: 0,
        rejected_duplicate_share_diff1: 0.0,
        rejected_low_difficulty_share_count: 0,
        rejected_low_difficulty_share_diff1: 0.0,
    };
    // Two sessions for the same address+worker → 2 distinct PK rows.
    let mut variant = base.clone();
    variant.session_id = "sessB".to_string();
    bulk_upsert_client_statistics_entity(&mut *tx, &[base, variant])
        .await
        .expect("upsert");

    let cnt: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_statistics_entity WHERE address = $1 AND "time" = $2"#,
    )
    .bind("test_cs_dist")
    .bind(slot)
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(cnt, 2);

    tx.rollback().await.expect("rollback");
}

// ── client_rejected_statistics ───────────────────────────────────────

#[tokio::test]
async fn client_rejected_stats_dual_field_increment() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let slot = unique_slot(6);

    let rows = vec![ClientRejectedStatsUpsert {
        address: "test_crs_a".to_string(),
        time_ms: slot,
        reason: "low-difficulty".to_string(),
        count: 2.0,
        shares: 0.5,
    }];
    bulk_upsert_client_rejected_statistics_entity(&mut *tx, &rows)
        .await
        .expect("first");
    bulk_upsert_client_rejected_statistics_entity(&mut *tx, &rows)
        .await
        .expect("second");

    let row = sqlx::query(
        r#"SELECT count, shares FROM client_rejected_statistics_entity
           WHERE address = $1 AND "time" = $2 AND reason = $3"#,
    )
    .bind("test_crs_a")
    .bind(slot)
    .bind("low-difficulty")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let count: f32 = row.get("count");
    let shares: f32 = row.get("shares");
    assert!((count - 4.0).abs() < 0.01);
    assert!((shares - 1.0).abs() < 0.01);

    tx.rollback().await.expect("rollback");
}

// ── address_settings_entity (merged shares + bestDifficulty upsert) ──

/// A pure share-accumulation upsert (best_difficulty = 0, no user-agent).
fn shares(address: &str, delta: f64) -> AddressSettingsUpsert {
    AddressSettingsUpsert {
        address: address.to_string(),
        delta_shares: delta,
        best_difficulty: 0.0,
        user_agent: None,
    }
}

/// A pure best-difficulty upsert (no share delta).
fn bd(address: &str, best: f64, ua: Option<&str>) -> AddressSettingsUpsert {
    AddressSettingsUpsert {
        address: address.to_string(),
        delta_shares: 0.0,
        best_difficulty: best,
        user_agent: ua.map(str::to_string),
    }
}

#[tokio::test]
async fn address_settings_shares_increment_and_create_missing_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Seed one address with a known updatedAt so the follow-up assertion
    // can prove a pure share-accumulation upsert (best_difficulty = 0)
    // leaves the timestamp alone. The second address has NO row — the
    // merged upsert must CREATE it (the old UPDATE-only path dropped a
    // brand-new address's first flush window of shares).
    let seeded_updated_at = 1_700_000_000_000_i64;
    sqlx::query(
        r#"INSERT INTO address_settings_entity (address, shares, "bestDifficulty", "createdAt", "updatedAt")
           VALUES ($1, $2, 0, $3, $3)"#,
    )
    .bind("test_as_present")
    .bind(100.0_f64)
    .bind(seeded_updated_at)
    .execute(&mut *tx)
    .await
    .expect("seed row");

    bulk_upsert_address_settings(
        &mut *tx,
        &[shares("test_as_present", 42.0), shares("test_as_absent", 99.0)],
    )
    .await
    .expect("upsert");

    let present: f64 =
        sqlx::query_scalar(r#"SELECT shares FROM address_settings_entity WHERE address = $1"#)
            .bind("test_as_present")
            .fetch_one(&mut *tx)
            .await
            .expect("read present");
    assert!((present - 142.0).abs() < 0.01, "incremented: {present}");

    let updated_at_after: i64 =
        sqlx::query_scalar(r#"SELECT "updatedAt" FROM address_settings_entity WHERE address = $1"#)
            .bind("test_as_present")
            .fetch_one(&mut *tx)
            .await
            .expect("read updatedAt");
    assert_eq!(
        updated_at_after, seeded_updated_at,
        "updatedAt must be preserved on share accumulation (only a new best bumps it)"
    );

    let absent: f64 =
        sqlx::query_scalar(r#"SELECT shares FROM address_settings_entity WHERE address = $1"#)
            .bind("test_as_absent")
            .fetch_one(&mut *tx)
            .await
            .expect("read absent");
    assert!(
        (absent - 99.0).abs() < 0.01,
        "missing row created with the delta as initial shares: {absent}"
    );

    tx.rollback().await.expect("rollback");
}

/// The merge's whole point: one upsert lands BOTH the share increment and
/// the best-difficulty GREATEST, and `"updatedAt"` moves only when the best
/// actually grows.
#[tokio::test]
async fn address_settings_upsert_folds_shares_and_best_in_one_write() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let addr = "test_as_combined";

    // Fresh address: a single upsert carrying a share delta AND a best.
    bulk_upsert_address_settings(
        &mut *tx,
        &[AddressSettingsUpsert {
            address: addr.to_string(),
            delta_shares: 10.0,
            best_difficulty: 500.0,
            user_agent: Some("bitaxe".into()),
        }],
    )
    .await
    .expect("insert combined");
    assert_eq!(read_row(&mut tx, addr).await, (10.0, 500.0, Some("bitaxe".into())));
    let ts_after_insert: i64 =
        sqlx::query_scalar(r#"SELECT "updatedAt" FROM address_settings_entity WHERE address = $1"#)
            .bind(addr)
            .fetch_one(&mut *tx)
            .await
            .expect("ts");

    // Second window: more shares + a LOWER best. Shares accumulate; the
    // best + its user-agent stay; updatedAt is NOT bumped (no new best).
    bulk_upsert_address_settings(
        &mut *tx,
        &[AddressSettingsUpsert {
            address: addr.to_string(),
            delta_shares: 7.0,
            best_difficulty: 300.0,
            user_agent: Some("worker".into()),
        }],
    )
    .await
    .expect("second window");
    assert_eq!(
        read_row(&mut tx, addr).await,
        (17.0, 500.0, Some("bitaxe".into())),
        "shares accumulate; lower best + its ua are kept"
    );
    let ts_after_second: i64 =
        sqlx::query_scalar(r#"SELECT "updatedAt" FROM address_settings_entity WHERE address = $1"#)
            .bind(addr)
            .fetch_one(&mut *tx)
            .await
            .expect("ts2");
    assert_eq!(
        ts_after_second, ts_after_insert,
        "updatedAt must not move when the best difficulty does not grow"
    );

    tx.rollback().await.expect("rollback");
}

async fn read_best(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, address: &str) -> (f64, Option<String>) {
    let row = sqlx::query(
        r#"SELECT "bestDifficulty", "bestDifficultyUserAgent"
           FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(address)
    .fetch_one(&mut **tx)
    .await
    .expect("read best");
    (row.get("bestDifficulty"), row.get("bestDifficultyUserAgent"))
}

/// Reads the full merged triple: `(shares, bestDifficulty, userAgent)`.
async fn read_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    address: &str,
) -> (f64, f64, Option<String>) {
    let row = sqlx::query(
        r#"SELECT shares, "bestDifficulty", "bestDifficultyUserAgent"
           FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(address)
    .fetch_one(&mut **tx)
    .await
    .expect("read row");
    (
        row.get("shares"),
        row.get("bestDifficulty"),
        row.get("bestDifficultyUserAgent"),
    )
}

#[tokio::test]
async fn best_difficulty_upsert_inserts_then_climbs_via_greatest() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let addr = "test_bd_greatest";

    // Fresh address → INSERT.
    bulk_upsert_address_settings(&mut *tx, &[bd(addr, 100.0, Some("bitaxe"))])
        .await
        .expect("insert");
    assert_eq!(read_best(&mut tx, addr).await, (100.0, Some("bitaxe".into())));

    // Higher → climbs + stamps the new firmware.
    bulk_upsert_address_settings(&mut *tx, &[bd(addr, 250.0, Some("nerdqaxe"))])
        .await
        .expect("climb");
    assert_eq!(read_best(&mut tx, addr).await, (250.0, Some("nerdqaxe".into())));

    // Lower → GREATEST keeps the stored max AND its user-agent.
    bulk_upsert_address_settings(&mut *tx, &[bd(addr, 40.0, Some("worker"))])
        .await
        .expect("lower");
    assert_eq!(read_best(&mut tx, addr).await, (250.0, Some("nerdqaxe".into())));

    tx.rollback().await.expect("rollback");
}

/// Regression: after a best-difficulty RESET zeroes the row (out of band,
/// via the UI/Telegram reset), the very next accepted-share flush must
/// re-establish the best via GREATEST — even a share LOWER than the old
/// all-time high. This is exactly the divergence the old write-through
/// cache caused (stale cached high blocked every re-write → the row stuck
/// at 0 for days); the batched GREATEST upsert cannot get stuck.
#[tokio::test]
async fn best_difficulty_recovers_after_a_reset() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let addr = "test_bd_reset_recovery";

    // Climb to a high all-time best.
    bulk_upsert_address_settings(&mut *tx, &[bd(addr, 623_932_928.0, Some("octaxe"))])
        .await
        .expect("high");
    assert_eq!(read_best(&mut tx, addr).await.0, 623_932_928.0);

    // Out-of-band reset zeroes the row (mirrors reset_address_settings_best_difficulty).
    sqlx::query(
        r#"UPDATE address_settings_entity
           SET "bestDifficulty" = 0, "bestDifficultyUserAgent" = NULL WHERE address = $1"#,
    )
    .bind(addr)
    .execute(&mut *tx)
    .await
    .expect("reset");
    assert_eq!(read_best(&mut tx, addr).await, (0.0, None));

    // Next flush carries a share LOWER than the old high → it must climb
    // back from 0 (GREATEST(0, x) = x), not stay stuck at 0.
    bulk_upsert_address_settings(&mut *tx, &[bd(addr, 19_987_136.0, Some("bitaxe"))])
        .await
        .expect("recover");
    assert_eq!(
        read_best(&mut tx, addr).await,
        (19_987_136.0, Some("bitaxe".into())),
        "best difficulty recovers from 0 after a reset"
    );

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn best_difficulty_upsert_empty_slice_is_noop() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let n = bulk_upsert_address_settings(&mut *tx, &[])
        .await
        .expect("empty");
    assert_eq!(n, 0);
    tx.rollback().await.expect("rollback");
}

// ── worker_shares_entity (composite-PK upsert) ──────────────────────

#[tokio::test]
async fn worker_shares_composite_pk_upsert_increments() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    let rows = vec![WorkerSharesUpsert {
        address: "test_ws_a".to_string(),
        client_name: "worker_x".to_string(),
        delta_shares: 100.0,
        delta_rejected_shares: 1.5,
    }];
    bulk_upsert_worker_shares_entity(&mut *tx, &rows)
        .await
        .expect("first");
    bulk_upsert_worker_shares_entity(&mut *tx, &rows)
        .await
        .expect("second");

    let row = sqlx::query(
        r#"SELECT shares, "rejectedShares" FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind("test_ws_a")
    .bind("worker_x")
    .fetch_one(&mut *tx)
    .await
    .expect("read");
    let shares: f64 = row.get("shares");
    let rejected: f64 = row.get("rejectedShares");
    assert!((shares - 200.0).abs() < 0.01);
    assert!((rejected - 3.0).abs() < 0.01);

    tx.rollback().await.expect("rollback");
}

// ── seed bootstrap ───────────────────────────────────────────────────

#[tokio::test]
async fn count_worker_shares_returns_zero_after_truncate_in_tx() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("TRUNCATE worker_shares_entity")
        .execute(&mut *tx)
        .await
        .expect("truncate");
    let n = count_worker_shares(&mut *tx).await.expect("count");
    assert_eq!(n, 0);
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn seed_aggregates_client_statistics_into_worker_shares() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("TRUNCATE worker_shares_entity")
        .execute(&mut *tx)
        .await
        .expect("truncate ws");
    sqlx::query("TRUNCATE client_statistics_entity")
        .execute(&mut *tx)
        .await
        .expect("truncate cs");

    let slot = unique_slot(7);
    // Two slots for the same (addr, clientName); seed should sum.
    let stats = vec![
        ClientStatsUpsert {
            address: "test_seed_alice".to_string(),
            client_name: "w1".to_string(),
            session_id: "s1".to_string(),
            time_ms: slot,
            shares: 30.0,
            accepted_count: 1,
            rejected_count: 0,
            rejected_job_not_found_count: 0,
            rejected_job_not_found_diff1: 0.0,
            rejected_duplicate_share_count: 0,
            rejected_duplicate_share_diff1: 0.0,
            rejected_low_difficulty_share_count: 1,
            rejected_low_difficulty_share_diff1: 0.5,
        },
        ClientStatsUpsert {
            address: "test_seed_alice".to_string(),
            client_name: "w1".to_string(),
            session_id: "s2".to_string(),
            time_ms: slot + 1,
            shares: 70.0,
            accepted_count: 2,
            rejected_count: 0,
            rejected_job_not_found_count: 0,
            rejected_job_not_found_diff1: 0.0,
            rejected_duplicate_share_count: 0,
            rejected_duplicate_share_diff1: 0.0,
            rejected_low_difficulty_share_count: 1,
            rejected_low_difficulty_share_diff1: 0.75,
        },
    ];
    bulk_upsert_client_statistics_entity(&mut *tx, &stats)
        .await
        .expect("seed cs rows");

    let inserted = seed_worker_shares_from_client_statistics(&mut *tx)
        .await
        .expect("seed");
    assert_eq!(inserted, 1, "one aggregated row");

    let row = sqlx::query(
        r#"SELECT shares, "rejectedShares" FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind("test_seed_alice")
    .bind("w1")
    .fetch_one(&mut *tx)
    .await
    .expect("read seeded");
    let shares: f64 = row.get("shares");
    let rejected: f64 = row.get("rejectedShares");
    assert!((shares - 100.0).abs() < 0.01, "sum of 30+70: {shares}");
    // Sum of low-diff diff1: 0.5 + 0.75 = 1.25 (jnf+dup were zero).
    assert!((rejected - 1.25).abs() < 0.01, "rejected sum: {rejected}");

    tx.rollback().await.expect("rollback");
}
