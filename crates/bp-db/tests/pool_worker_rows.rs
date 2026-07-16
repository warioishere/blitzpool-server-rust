// SPDX-License-Identifier: AGPL-3.0-or-later

//! `find_pool_worker_rows_since` is the skinny projection behind
//! `/api/info/workers` (slot time + address + worker only). This test pins its
//! row set: it returns exactly the non-soft-deleted rows at or after `since`,
//! with the identity columns the in-process distinct-counting needs.

use std::collections::HashSet;

use bp_db::find_pool_worker_rows_since;
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

// Test-only skip diagnostics: the workspace denies `print_stderr` for
// production code, but printing why an integration test skipped (no local PG)
// is exactly what stderr is for here.
#[allow(clippy::print_stderr)]
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
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

#[tokio::test]
async fn skinny_reader_returns_active_rows_in_window() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    let base: i64 = 32_503_680_000_000; // far-future slot, no real-data collision
    let since = base;

    // (address, worker, session, time, deleted?)
    let seed: &[(&str, &str, &str, i64, Option<i64>)] = &[
        ("bp_pwr_X", "w1", "s1", base, None),           // in window
        ("bp_pwr_X", "w2", "s1", base + 600_000, None), // in window, later slot
        ("bp_pwr_Y", "w1", "s1", base, None),           // in window
        ("bp_pwr_OLD", "w1", "s1", base - 1, None),     // before since → excluded
        ("bp_pwr_DEL", "w1", "s1", base, Some(base)),   // soft-deleted → excluded
    ];
    for (addr, worker, session, time, deleted) in seed {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares, "deletedAt")
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(addr)
        .bind(worker)
        .bind(session)
        .bind(time)
        .bind(1.0_f32)
        .bind(deleted)
        .execute(&mut *tx)
        .await
        .expect("seed insert");
    }

    let got: HashSet<(String, String, i64)> = find_pool_worker_rows_since(&mut *tx, since)
        .await
        .expect("skinny reader")
        .into_iter()
        // Scope to this test's fixture so unrelated rows in the shared DB
        // (this runs in a rolled-back tx, but other data may pre-exist) don't
        // leak in.
        .filter(|r| r.address.starts_with("bp_pwr_"))
        .map(|r| (r.address, r.client_name, r.time))
        .collect();

    let expected: HashSet<(String, String, i64)> = HashSet::from([
        ("bp_pwr_X".into(), "w1".into(), base),
        ("bp_pwr_X".into(), "w2".into(), base + 600_000),
        ("bp_pwr_Y".into(), "w1".into(), base),
    ]);

    assert_eq!(
        got, expected,
        "skinny reader must return active in-window rows only (no OLD, no DEL)"
    );

    // tx dropped → rolls back, no DB pollution.
}
