// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pins `find_pool_worker_counts_since`: distinct counts per slot over the
//! non-soft-deleted rows at or after `since`.

use bp_db::{find_pool_worker_counts_since, PoolWorkerCounts};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

// Printing why an integration test skipped is what stderr is for here.
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

/// Distinct addresses and workers per slot, from active in-window rows only:
/// two sessions of one worker count once, a soft-deleted or earlier row not
/// at all.
#[tokio::test]
async fn worker_counts_are_distinct_and_skip_deleted_and_old_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Past every other fixture, so `time >= since` sees only these rows.
    let since: i64 = 9_000_000_000_000_000;
    let next = since + 600_000;

    // (address, worker, session, time, deleted?)
    let seed: &[(&str, &str, &str, i64, Option<i64>)] = &[
        ("bp_pwr_X", "w1", "s1", since, None),
        ("bp_pwr_X", "w1", "s2", since, None), // same worker, second session
        ("bp_pwr_X", "w2", "s3", since, None),
        ("bp_pwr_Y", "w1", "s4", since, None),
        ("bp_pwr_Y", "w1", "s5", next, None),
        ("bp_pwr_OLD", "w1", "s6", since - 1, None), // before since
        ("bp_pwr_DEL", "w1", "s7", since, Some(since)), // soft-deleted
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

    let mut got = find_pool_worker_counts_since(&mut *tx, since)
        .await
        .expect("counts");
    got.sort_by_key(|c| c.time);
    assert_eq!(
        got,
        vec![
            PoolWorkerCounts {
                time: since,
                addresses: 2,
                workers: 3,
            },
            PoolWorkerCounts {
                time: next,
                addresses: 1,
                workers: 1,
            },
        ]
    );

    // tx dropped → rolls back, no DB pollution.
}
