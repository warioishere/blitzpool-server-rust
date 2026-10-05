// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! `flush_once` against PG, one drain → upsert → confirm tick at a time.
//! `flush_once` takes a `PgPool`, not a transaction, so tests isolate via a
//! suite-wide mutex and prefix-based cleanup instead of rollback.

use std::sync::Arc;

use bp_common::{AddressId, MiningMode};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};
use bp_share_stats_sink::flush::{flush_once, Accumulators, FlushScope};
use bp_share_stats_sink::ShareStatsAcceptedSink;
use bp_stats::{ClientStatisticsKey, ClientStatisticsRecord, RejectedReason, TimeSlot};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::Mutex;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static FLUSH_TEST_LOCK: Mutex<()> = Mutex::const_new(());

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

fn fixture_slot() -> TimeSlot {
    // Year 3000-ish — far past any real fixture data.
    TimeSlot::from_millis(32_503_680_000_000 + 1)
}

async fn cleanup(pool: &PgPool, slot_time_ms: i64, addr_prefix: &str) {
    let _ = sqlx::query(r#"DELETE FROM pool_share_statistics_entity WHERE "time" = $1"#)
        .bind(slot_time_ms)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pool_mode_hashrate WHERE "time" = $1"#)
        .bind(slot_time_ms)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pool_rejected_statistics_entity WHERE "time" = $1"#)
        .bind(slot_time_ms)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM client_statistics_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM worker_shares_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
}

fn addr(s: &str) -> AddressId {
    AddressId::new(s.to_string()).unwrap()
}

#[tokio::test]
async fn flush_once_drains_all_seven_tables_to_pg() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = fixture_slot();
    let prefix = "test_flush_e2e_";
    cleanup(&pool, slot.as_millis(), prefix).await;

    // Seed an address_settings row so the assertion below sees an
    // increment on an existing total, not a fresh insert.
    sqlx::query(
        r#"INSERT INTO address_settings_entity (address, shares, "bestDifficulty")
           VALUES ($1, $2, 0)"#,
    )
    .bind(format!("{prefix}alice"))
    .bind(100.0_f64)
    .execute(&pool)
    .await
    .expect("seed addr row");

    // One accepted share credited at 10 but solved at 4096 (only the slot
    // maximum records that), plus one rejected.
    let accs = Arc::new(Accumulators::default());
    accs.pool_shares.add_accepted(slot, 10.0, 4096.0);
    accs.pool_shares.add_rejected(slot, 1.0);
    accs.pool_mode_hashrate.add(slot, MiningMode::Pplns, 10.0);
    accs.pool_rejected
        .add(slot, RejectedReason::LowDifficulty, 1.0);
    accs.client_statistics.add(
        ClientStatisticsKey {
            address: addr(&format!("{prefix}alice")),
            client_name: "worker1".to_string(),
            session_id: "sess0001".to_string(),
            slot,
        },
        &ClientStatisticsRecord {
            shares: 10.0,
            max_difficulty: 4096.0,
            ..Default::default()
        },
    );
    accs.share_totals
        .add(addr(&format!("{prefix}alice")), "worker1".to_string(), 10.0);
    flush_once(&pool, &accs, FlushScope::All).await;

    // Pool-shares row exists with the right values.
    let row = sqlx::query(
        r#"SELECT accepted, rejected, "maxDifficulty" FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("pool_share row");
    let accepted: f32 = row.get("accepted");
    let rejected: f32 = row.get("rejected");
    let pool_max: f32 = row.get("maxDifficulty");
    assert!((accepted - 10.0).abs() < 0.01);
    assert!((rejected - 1.0).abs() < 0.01);
    assert_eq!(pool_max, 4096.0);

    let client_max: f32 = sqlx::query_scalar(
        r#"SELECT "maxDifficulty" FROM client_statistics_entity
           WHERE address = $1 AND "time" = $2"#,
    )
    .bind(format!("{prefix}alice"))
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("client_statistics row");
    assert_eq!(client_max, 4096.0);

    // Pool-mode hashrate.
    let diff: f32 = sqlx::query_scalar(
        r#"SELECT diff FROM pool_mode_hashrate WHERE "time" = $1 AND mode = $2"#,
    )
    .bind(slot.as_millis())
    .bind("pplns")
    .fetch_one(&pool)
    .await
    .expect("pool_mode_hashrate row");
    assert!((diff - 10.0).abs() < 0.01);

    // Pool-rejected.
    let count: f32 = sqlx::query_scalar(
        r#"SELECT count FROM pool_rejected_statistics_entity
           WHERE "time" = $1 AND reason = $2"#,
    )
    .bind(slot.as_millis())
    .bind("LowDifficultyShare")
    .fetch_one(&pool)
    .await
    .expect("pool_rejected row");
    assert!((count - 1.0).abs() < 0.01);

    // Client-statistics: 1 row for the accepted share.
    let cs: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_statistics_entity WHERE address = $1 AND "time" = $2"#,
    )
    .bind(format!("{prefix}alice"))
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("count cs rows");
    assert!(cs >= 1);

    // Address settings — incremented from 100.0 to 110.0.
    let addr_shares: f64 =
        sqlx::query_scalar(r#"SELECT shares FROM address_settings_entity WHERE address = $1"#)
            .bind(format!("{prefix}alice"))
            .fetch_one(&pool)
            .await
            .expect("address_settings row");
    assert!((addr_shares - 110.0).abs() < 0.01);

    // Worker shares — composite-PK insert (row didn't exist before).
    let worker_shares: f64 = sqlx::query_scalar(
        r#"SELECT shares FROM worker_shares_entity WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind(format!("{prefix}alice"))
    .bind("worker1")
    .fetch_one(&pool)
    .await
    .expect("worker_shares row");
    assert!((worker_shares - 10.0).abs() < 0.01);

    cleanup(&pool, slot.as_millis(), prefix).await;
}

/// Pins that the flush folds the window's best difficulty into
/// `address_settings_entity` via GREATEST, inserting the row if missing.
#[tokio::test]
async fn flush_once_folds_best_difficulty_via_greatest() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_flush_bd_";
    let address = format!("{prefix}octaxe");
    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#)
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await;

    // No row yet: the flush inserts it at the window max.
    let accs = Arc::new(Accumulators::default());
    accs.best_difficulty
        .add(&addr(&address), 100.0, Some("bitaxe"));
    accs.best_difficulty
        .add(&addr(&address), 623_932_928.0, Some("octaxe")); // window max
    accs.best_difficulty
        .add(&addr(&address), 40.0, Some("worker")); // lower — ignored
    flush_once(&pool, &accs, FlushScope::All).await;

    let (best, ua): (f64, Option<String>) = {
        let row = sqlx::query(
            r#"SELECT "bestDifficulty", "bestDifficultyUserAgent"
               FROM address_settings_entity WHERE address = $1"#,
        )
        .bind(&address)
        .fetch_one(&pool)
        .await
        .expect("row inserted by flush");
        (
            row.get("bestDifficulty"),
            row.get("bestDifficultyUserAgent"),
        )
    };
    assert_eq!(best, 623_932_928.0, "flush persisted the window max");
    assert_eq!(ua.as_deref(), Some("octaxe"));

    // A later window with a LOWER max leaves the stored all-time best alone.
    let accs2 = Arc::new(Accumulators::default());
    accs2
        .best_difficulty
        .add(&addr(&address), 1_000.0, Some("bitaxe"));
    flush_once(&pool, &accs2, FlushScope::All).await;
    let best_after: f64 = sqlx::query_scalar(
        r#"SELECT "bestDifficulty" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(&address)
    .fetch_one(&pool)
    .await
    .expect("read");
    assert_eq!(
        best_after, 623_932_928.0,
        "GREATEST keeps the all-time high"
    );

    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#)
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn replay_idempotency_double_flush_doubles_counts() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = TimeSlot::from_millis(32_503_680_001_234);
    let prefix = "test_flush_replay_";
    cleanup(&pool, slot.as_millis(), prefix).await;

    // Flushes INCREMENT, so re-flushing an unconfirmed snapshot (PG
    // committed, confirm lost) double-counts it.
    let accs1 = Arc::new(Accumulators::default());
    accs1.pool_shares.add_accepted(slot, 5.0, 5.0);
    flush_once(&pool, &accs1, FlushScope::All).await;

    let accs2 = Arc::new(Accumulators::default());
    accs2.pool_shares.add_accepted(slot, 5.0, 5.0);
    flush_once(&pool, &accs2, FlushScope::All).await;

    let accepted: f32 = sqlx::query_scalar(
        r#"SELECT accepted FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("read");
    assert!(
        (accepted - 10.0).abs() < 0.01,
        "expected 10 from 2×5: {accepted}"
    );

    cleanup(&pool, slot.as_millis(), prefix).await;
}

/// A tick writes a client slot only once it ended, the shutdown drain
/// writes the open one too, and the next process adds onto that row.
#[tokio::test]
async fn client_slots_reach_pg_once_ended_and_the_drain_writes_the_rest() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let ended = TimeSlot::from_millis(32_503_680_600_000);
    let open = ended.next();
    let prefix = "test_flush_scope_";
    cleanup(&pool, ended.as_millis(), prefix).await;
    let key = |slot| ClientStatisticsKey {
        address: addr(&format!("{prefix}alice")),
        client_name: "rig".to_string(),
        session_id: "s1".to_string(),
        slot,
    };
    let shares = |s: f64| ClientStatisticsRecord {
        shares: s,
        ..Default::default()
    };
    let read = |slot: TimeSlot| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, f32>(
                r#"SELECT shares FROM client_statistics_entity
                   WHERE address = $1 AND "time" = $2"#,
            )
            .bind(format!("{prefix}alice"))
            .bind(slot.as_millis())
            .fetch_optional(&pool)
            .await
            .expect("read")
        }
    };

    let accs = Arc::new(Accumulators::default());
    accs.client_statistics.add(key(ended), &shares(10.0));
    accs.client_statistics.add(key(open), &shares(3.0));
    flush_once(&pool, &accs, FlushScope::Before(open)).await;
    assert_eq!(read(ended).await, Some(10.0), "the ended slot is written");
    assert_eq!(read(open).await, None, "the open slot waits for its end");

    // A second tick in the same slot writes nothing new.
    flush_once(&pool, &accs, FlushScope::Before(open)).await;
    assert_eq!(read(ended).await, Some(10.0), "written once, not twice");

    flush_once(&pool, &accs, FlushScope::All).await;
    assert_eq!(read(open).await, Some(3.0), "the shutdown drain writes it");

    // The next process books the rest of the open slot onto the same row.
    let accs2 = Arc::new(Accumulators::default());
    accs2.client_statistics.add(key(open), &shares(4.0));
    flush_once(&pool, &accs2, FlushScope::Before(open.next())).await;
    assert_eq!(
        read(open).await,
        Some(7.0),
        "the restart adds, not overwrites"
    );

    cleanup(&pool, ended.as_millis(), prefix).await;
}

/// A flush whose writes all fail hands every delta back, and the next
/// flush writes them: nothing is lost to an outage.
#[tokio::test]
async fn a_failed_flush_hands_everything_back_for_the_next_one() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = TimeSlot::from_millis(32_503_680_700_000);
    let prefix = "test_flush_restore_";
    cleanup(&pool, slot.as_millis(), prefix).await;
    let alice = addr(&format!("{prefix}alice"));

    let accs = Arc::new(Accumulators::default());
    accs.pool_shares.add_accepted(slot, 10.0, 64.0);
    accs.client_statistics.add(
        ClientStatisticsKey {
            address: alice.clone(),
            client_name: "rig".to_string(),
            session_id: "s1".to_string(),
            slot,
        },
        &ClientStatisticsRecord {
            shares: 10.0,
            max_difficulty: 64.0,
            ..Default::default()
        },
    );
    accs.share_totals
        .add(alice.clone(), "rig".to_string(), 10.0);
    accs.best_difficulty.add(&alice, 64.0, Some("bitaxe"));

    // A closed pool fails every statement.
    let dead = PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy(DEFAULT_URL)
        .expect("lazy pool");
    dead.close().await;
    flush_once(&dead, &accs, FlushScope::All).await;
    assert_eq!(
        accs.client_statistics.len(),
        1,
        "handed back after the failed write"
    );
    assert_eq!(
        accs.pool_shares.len(),
        1,
        "handed back after the failed write"
    );

    flush_once(&pool, &accs, FlushScope::All).await;
    let shares: f32 = sqlx::query_scalar(
        r#"SELECT shares FROM client_statistics_entity WHERE address = $1 AND "time" = $2"#,
    )
    .bind(alice.as_str())
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("client row written by the second flush");
    let accepted: f32 = sqlx::query_scalar(
        r#"SELECT accepted FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("pool row written by the second flush");
    let (total, best): (f64, f64) = sqlx::query_as(
        r#"SELECT shares, "bestDifficulty" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(alice.as_str())
    .fetch_one(&pool)
    .await
    .expect("address row written by the second flush");
    cleanup(&pool, slot.as_millis(), prefix).await;

    assert_eq!(shares, 10.0);
    assert_eq!(accepted, 10.0);
    assert_eq!((total, best), (10.0, 64.0));
}

/// A worker name with a NUL byte, which Postgres text rejects, neither
/// fails the flush nor holds back anyone else's rows.
#[tokio::test]
async fn a_nul_byte_in_a_worker_name_does_not_block_the_flush() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = TimeSlot::from_millis(32_503_680_800_000);
    let prefix = "test_flush_nul_";
    cleanup(&pool, slot.as_millis(), prefix).await;
    let alice = format!("{prefix}alice");
    let bob = format!("{prefix}bob");

    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsAcceptedSink::new(accs.clone());
    for (address, worker, ua) in [
        (alice.as_str(), "rig\0x", "bitaxe\0"),
        (bob.as_str(), "rig", "bitaxe"),
    ] {
        sink.record_accepted(SharedAcceptedShare {
            address,
            worker,
            session_id: "s1",
            effective_difficulty: 10.0,
            submission_difficulty: 64.0,
            user_agent: Some(ua),
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode: bp_common::MiningMode::Solo,
            group_id: None,
        })
        .await;
    }
    // Only the client rows are under test; keep the pool rows out of the real slot.
    accs.pool_shares.take();
    accs.pool_mode_hashrate.take();
    flush_once(&pool, &accs, FlushScope::All).await;

    let workers: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT address, "clientName" FROM worker_shares_entity
           WHERE address LIKE $1 ORDER BY address"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_all(&pool)
    .await
    .expect("read workers");
    let clients: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_statistics_entity WHERE address LIKE $1"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_one(&pool)
    .await
    .expect("read clients");
    let ua: Option<String> = sqlx::query_scalar(
        r#"SELECT "bestDifficultyUserAgent" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(&alice)
    .fetch_one(&pool)
    .await
    .expect("read ua");
    cleanup(&pool, slot.as_millis(), prefix).await;

    assert_eq!(
        workers,
        vec![
            (alice.clone(), "rig\u{FFFD}x".to_string()),
            (bob.clone(), "rig".to_string()),
        ]
    );
    assert_eq!(clients, 2, "both client rows written");
    assert_eq!(ua.as_deref(), Some("bitaxe\u{FFFD}"));
}
