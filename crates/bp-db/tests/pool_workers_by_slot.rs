// SPDX-License-Identifier: AGPL-3.0-or-later

//! Equivalence test for `count_pool_workers_by_slot`.
//!
//! `/api/info/workers` used to load every per-session `client_statistics_entity`
//! row for the window and count DISTINCT addresses / DISTINCT (address, worker)
//! per 10-min slot in memory. That was replaced with an in-SQL
//! `GROUP BY (time/slot)*slot` + `COUNT(DISTINCT …)`. This test seeds one fixed
//! dataset and asserts the SQL aggregation yields the **identical** per-slot map
//! as the old in-memory algorithm — including the tricky cases: same address
//! with several workers, same worker across several sessions, a soft-deleted
//! row that must be excluded, and a non-slot-aligned timestamp that must snap to
//! the same slot under both paths.
//!
//! The handler around the map (slot-boundary iteration + zero-fill + ISO labels)
//! is unchanged, so an identical map means an identical endpoint response.

use std::collections::{BTreeMap, HashSet};

use bp_db::count_pool_workers_by_slot;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
const SLOT_MS: i64 = 10 * 60 * 1000; // matches Range::slot_size_ms()

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

/// The same snap the API uses (`time_range::snap_to_slot`) and the SQL mirrors.
fn snap(t: i64, slot: i64) -> i64 {
    (t / slot) * slot
}

#[tokio::test]
async fn sql_aggregation_matches_in_memory_distinct_counts() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Two distinct, slot-aligned, far-future slots (no collision with real data).
    let slot_a: i64 = 32_503_680_000_000;
    let slot_b: i64 = slot_a + SLOT_MS;
    let since = slot_a - 1; // include both slots

    // (address, worker, session, time, deleted?) — deliberate overlaps:
    //   slot_a: addrX has w1 over two sessions (1 distinct worker) + w2 + a
    //           non-aligned w3 row that must snap into slot_a; addrY has w1.
    //           → addresses = {X, Y} = 2 ; workers = {X/w1, X/w2, X/w3, Y/w1} = 4
    //   a soft-deleted (addrZ, w9) in slot_a must NOT count.
    //   slot_b: only addrX/w1 → addresses = 1 ; workers = 1.
    let seed: &[(&str, &str, &str, i64, Option<i64>)] = &[
        ("bp_pws_X", "w1", "s1", slot_a, None),
        ("bp_pws_X", "w1", "s2", slot_a, None), // same addr+worker, new session
        ("bp_pws_X", "w2", "s1", slot_a, None), // same addr, new worker
        ("bp_pws_X", "w3", "s1", slot_a + 137_000, None), // non-aligned → snaps to slot_a
        ("bp_pws_Y", "w1", "s1", slot_a, None),
        ("bp_pws_Z", "w9", "s1", slot_a, Some(slot_a)), // soft-deleted → excluded
        ("bp_pws_X", "w1", "s1", slot_b, None),
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

    // ── Reference: the OLD in-memory algorithm, verbatim ──────────────
    let rows = sqlx::query(
        r#"SELECT address, "clientName" AS worker, "time" AS time
             FROM client_statistics_entity
            WHERE "deletedAt" IS NULL AND "time" >= $1"#,
    )
    .bind(since)
    .fetch_all(&mut *tx)
    .await
    .expect("read raw rows");

    let mut addrs_by_slot: BTreeMap<i64, HashSet<String>> = BTreeMap::new();
    let mut workers_by_slot: BTreeMap<i64, HashSet<(String, String)>> = BTreeMap::new();
    for r in &rows {
        let address: String = r.get("address");
        let worker: String = r.get("worker");
        let time: i64 = r.get("time");
        let k = snap(time, SLOT_MS);
        addrs_by_slot.entry(k).or_default().insert(address.clone());
        workers_by_slot.entry(k).or_default().insert((address, worker));
    }
    let expected: BTreeMap<i64, (i64, i64)> = addrs_by_slot
        .keys()
        .map(|&k| {
            (
                k,
                (
                    addrs_by_slot[&k].len() as i64,
                    workers_by_slot[&k].len() as i64,
                ),
            )
        })
        .collect();

    // ── New: the in-SQL aggregation under test ────────────────────────
    let actual: BTreeMap<i64, (i64, i64)> = count_pool_workers_by_slot(&mut *tx, since, SLOT_MS)
        .await
        .expect("count_pool_workers_by_slot")
        .into_iter()
        .map(|c| (c.slot, (c.addresses, c.workers)))
        .collect();

    // Sanity: the fixture exercises the cases we care about.
    assert_eq!(
        expected,
        BTreeMap::from([(slot_a, (2, 4)), (slot_b, (1, 1))]),
        "fixture sanity: slot_a=2 addrs/4 workers, slot_b=1/1"
    );

    // The actual point: SQL == in-memory, per slot.
    assert_eq!(actual, expected, "SQL per-slot counts must match in-memory");

    // tx dropped without commit → rolls back, no DB pollution.
}
