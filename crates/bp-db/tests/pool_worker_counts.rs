// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pins `find_pool_worker_counts_since` (distinct counts per slot over the
//! rows at or after `since`) and the row order of the multi-address reader.

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

/// Distinct addresses and workers per slot, from in-window rows only: two
/// sessions of one worker count once, an earlier row not at all.
#[tokio::test]
async fn worker_counts_are_distinct_and_skip_old_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Past every other fixture, so `time >= since` sees only these rows.
    let since: i64 = 9_000_000_000_000_000;
    let next = since + 600_000;

    // (address, worker, session, time)
    let seed: &[(&str, &str, &str, i64)] = &[
        ("bp_pwr_X", "w1", "s1", since),
        ("bp_pwr_X", "w1", "s2", since), // same worker, second session
        ("bp_pwr_X", "w2", "s3", since),
        ("bp_pwr_Y", "w1", "s4", since),
        ("bp_pwr_Y", "w1", "s5", next),
        ("bp_pwr_OLD", "w1", "s6", since - 1), // before since
    ];
    for (addr, worker, session, time) in seed {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares)
               VALUES ($1, $2, $3, $4, 1)"#,
        )
        .bind(addr)
        .bind(worker)
        .bind(session)
        .bind(time)
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

/// The multi-address reader returns address by address in the order given,
/// each by time, so sums over it add in the order one read per address did.
#[tokio::test]
async fn client_statistics_come_address_by_address_in_the_given_order() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let since: i64 = 9_100_000_000_000_000;
    let (a, b) = ("bp_csr_alice", "bp_csr_bob");
    let cleanup = || async {
        let _ = sqlx::query("DELETE FROM client_statistics_entity WHERE address IN ($1, $2)")
            .bind(a)
            .bind(b)
            .execute(&pool)
            .await;
    };
    cleanup().await;
    for (addr, time) in [
        (a, since + 600_000),
        (b, since),
        (a, since),
        (b, since + 600_000),
    ] {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares)
               VALUES ($1, 'w', 's1', $2, 1)"#,
        )
        .bind(addr)
        .bind(time)
        .execute(&pool)
        .await
        .expect("seed");
    }

    let order = |addresses: Vec<&'static str>| {
        let pool = pool.clone();
        async move {
            let ids: Vec<bp_common::AddressId> = addresses
                .iter()
                .map(|s| bp_common::AddressId::new(s.to_string()).unwrap())
                .collect();
            bp_db::find_client_statistics_since_for_addresses(&pool, &ids, since)
                .await
                .expect("read")
                .into_iter()
                .map(|r| (r.address.as_str().to_string(), r.time))
                .collect::<Vec<_>>()
        }
    };
    let b_then_a = order(vec![b, a]).await;
    let a_only = order(vec![a]).await;
    cleanup().await;

    assert_eq!(
        b_then_a,
        vec![
            (b.to_string(), since),
            (b.to_string(), since + 600_000),
            (a.to_string(), since),
            (a.to_string(), since + 600_000),
        ]
    );
    assert_eq!(
        a_only,
        vec![(a.to_string(), since), (a.to_string(), since + 600_000)]
    );
}
