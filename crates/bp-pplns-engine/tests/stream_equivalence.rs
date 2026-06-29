// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! T1 — accounting equivalence between the in-process sink path and the
//! Core→stream→Satellite path.
//!
//! The SAME share sequence (deterministic `share_id`s) driven
//!   (a) directly through `PplnsAcceptedShareSink`, and
//!   (b) through produce → Redis stream → drain into a *fresh*
//!       `PplnsAcceptedShareSink`
//! must leave **identical** PPLNS window state (per-address aggregate +
//! total). That proves the stream transport is accounting-neutral — the
//! core of the Core/Satellite correctness story.
//!
//! Two Redis DBs: engine A on one, engine B + the stream on another (the
//! stream's `t1:*` keys don't collide with the engine's `pplns:*` keys).
//! A huge network-difficulty keeps the window from trimming, so the
//! comparison is exact. Needs docker-Redis (16379) + PG (15433); skips
//! cleanly otherwise.

use std::sync::Arc;

use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::hooks::PplnsAcceptedShareSink;
use bp_pplns_engine::window::NetworkDifficulty;
use bp_share_hook::{MiningMode, SharedAcceptedShareOwned, SharedAcceptedShareSink};
use bp_share_stream::{AcceptedShareConsumer, AcceptedShareProducer};
use bp_test_support::{connect_pg_or_skip, connect_redis_or_skip};
use redis::aio::ConnectionManager;
use sqlx::PgPool;

const N: usize = 60;

/// Deterministic share sequence — 5 miners, varying difficulty, stable
/// `share_id`s so both paths feed identical inputs.
fn share_seq() -> Vec<SharedAcceptedShareOwned> {
    (0..N)
        .map(|i| SharedAcceptedShareOwned {
            address: format!("bc1qminer{}", i % 5),
            worker: format!("rig{}", i % 3),
            session_id: format!("sess{}", i % 4),
            effective_difficulty: 1.0 + (i % 7) as f64,
            submission_difficulty: 1000.0,
            user_agent: None,
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 1_700_000_000_000 + i as i64,
            share_id: format!("t:{i}"),
            mode: MiningMode::Pplns,
            group_id: None,
        })
        .collect()
}

async fn spawn_engine(conn: ConnectionManager, pool: PgPool) -> PplnsEngine {
    // Huge net-diff so the window never trims — all N shares retained,
    // exact comparison. Long touch-flush so neither engine writes PG
    // during the test (we compare only Redis window state).
    let net_diff = NetworkDifficulty::new(1_000_000.0);
    let config = PplnsEngineConfig {
        touch_flush_interval_secs: 3600,
        dust_sweep_enabled: false,
        ..PplnsEngineConfig::default()
    };
    PplnsEngine::spawn(config, conn, pool, net_diff)
        .await
        .expect("spawn pplns engine")
}

/// Read the comparable window state: per-address aggregate + total.
async fn window_state(engine: &PplnsEngine) -> (std::collections::HashMap<String, f64>, f64) {
    let by_addr = engine
        .window()
        .read_window_by_address()
        .await
        .expect("read_window_by_address");
    let total = engine
        .window()
        .current_total()
        .await
        .expect("current_total");
    (by_addr, total)
}

fn assert_windows_equal(
    a: &(std::collections::HashMap<String, f64>, f64),
    b: &(std::collections::HashMap<String, f64>, f64),
) {
    let (by_a, total_a) = a;
    let (by_b, total_b) = b;
    assert!(
        (total_a - total_b).abs() < 1e-9,
        "window total drift: in-process={total_a} stream={total_b}"
    );
    assert_eq!(
        by_a.len(),
        by_b.len(),
        "miner count differs: in-process={by_a:?} stream={by_b:?}"
    );
    for (addr, diff_a) in by_a {
        let diff_b = by_b.get(addr).copied().unwrap_or(f64::NAN);
        assert!(
            (diff_a - diff_b).abs() < 1e-9,
            "per-address drift for {addr}: in-process={diff_a} stream={diff_b}"
        );
    }
}

/// Drive `shares` through the stream into `sink`, draining until every
/// produced entry has been consumed (and acked).
async fn run_stream_path(
    conn: ConnectionManager,
    shares: &[SharedAcceptedShareOwned],
    extra_dups: &[SharedAcceptedShareOwned],
    sink: Arc<dyn SharedAcceptedShareSink>,
) {
    let key = "t1:pplns:accepted";
    let producer = AcceptedShareProducer::new(conn.clone(), key);
    let consumer = AcceptedShareConsumer::new(conn.clone(), key, "money", "c1");
    consumer.ensure_group().await.expect("ensure_group");

    for s in shares {
        producer.publish(s).await.expect("publish");
    }
    // Extra entries with already-seen share_ids — the engine must dedup them.
    for s in extra_dups {
        producer.publish(s).await.expect("publish dup");
    }

    let expected = shares.len() + extra_dups.len();
    let sinks = vec![sink];
    let mut drained = 0;
    while drained < expected {
        let n = consumer
            .drain_new(&sinks, 100, 1000)
            .await
            .expect("drain_new");
        assert!(
            n > 0,
            "stream stalled before draining all entries ({drained}/{expected})"
        );
        drained += n;
    }
}

#[tokio::test]
async fn in_process_and_stream_paths_leave_identical_pplns_window() {
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    let (Some(conn_a), Some(conn_b)) = (
        connect_redis_or_skip(11).await,
        connect_redis_or_skip(12).await,
    ) else {
        return;
    };

    let shares = share_seq();

    // ── Path A: in-process sink ──
    let engine_a = spawn_engine(conn_a, pool.clone()).await;
    let sink_a = PplnsAcceptedShareSink::new(engine_a.clone());
    for s in &shares {
        sink_a.record_accepted(s.as_view()).await;
    }
    let state_a = window_state(&engine_a).await;

    // ── Path B: produce → stream → drain into a fresh sink ──
    let engine_b = spawn_engine(conn_b.clone(), pool.clone()).await;
    let sink_b: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(PplnsAcceptedShareSink::new(engine_b.clone()));
    run_stream_path(conn_b, &shares, &[], sink_b).await;
    let state_b = window_state(&engine_b).await;

    assert_windows_equal(&state_a, &state_b);

    engine_a.shutdown();
    engine_b.shutdown();
}

#[tokio::test]
async fn duplicate_entries_in_the_stream_do_not_break_equivalence() {
    // The redelivery story end-to-end: re-published entries (same share_id)
    // must dedup inside the engine, so the stream window still matches the
    // in-process one exactly.
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    let (Some(conn_a), Some(conn_b)) = (
        connect_redis_or_skip(13).await,
        connect_redis_or_skip(14).await,
    ) else {
        return;
    };

    let shares = share_seq();

    let engine_a = spawn_engine(conn_a, pool.clone()).await;
    let sink_a = PplnsAcceptedShareSink::new(engine_a.clone());
    for s in &shares {
        sink_a.record_accepted(s.as_view()).await;
    }
    let state_a = window_state(&engine_a).await;

    // Path B publishes every share, PLUS duplicates of a few share_ids.
    let dups = vec![shares[0].clone(), shares[5].clone(), shares[37].clone()];
    let engine_b = spawn_engine(conn_b.clone(), pool.clone()).await;
    let sink_b: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(PplnsAcceptedShareSink::new(engine_b.clone()));
    run_stream_path(conn_b, &shares, &dups, sink_b).await;
    let state_b = window_state(&engine_b).await;

    assert_windows_equal(&state_a, &state_b);

    engine_a.shutdown();
    engine_b.shutdown();
}

/// One share with explicit id / mode / address / difficulty / ts_ms.
fn mk_share(
    share_id: &str,
    mode: MiningMode,
    address: &str,
    diff: f64,
    ts_ms: i64,
) -> SharedAcceptedShareOwned {
    SharedAcceptedShareOwned {
        address: address.to_string(),
        worker: "rig".to_string(),
        session_id: "sess".to_string(),
        effective_difficulty: diff,
        submission_difficulty: 1000.0,
        user_agent: None,
        is_block_candidate: false,
        hash_rate: 0.0,
        channel_count: 1,
        ts_ms,
        share_id: share_id.to_string(),
        mode,
        group_id: None,
    }
}

/// T8 — Core restart with epoch change mid-stream. `share_id` is
/// `{core_epoch}:{seq}` and `seq` resets to 0 each boot, so two boots emit
/// `1:0` and `2:0`. Both are distinct ids and must each apply once; a
/// redelivery of either dedups. Proves the epoch discriminator keeps a
/// post-restart `seq` from colliding with the previous boot's.
#[tokio::test]
async fn mixed_epoch_share_ids_apply_once_without_seq_collision() {
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    let Some(conn) = connect_redis_or_skip(5).await else {
        return;
    };

    let addr = "bc1qmixedepoch";
    let shares = vec![
        mk_share("1:0", MiningMode::Pplns, addr, 1.0, 1_700_000_000_000),
        mk_share("1:1", MiningMode::Pplns, addr, 1.0, 1_700_000_000_001),
        mk_share("2:0", MiningMode::Pplns, addr, 1.0, 1_700_000_000_002),
        mk_share("2:1", MiningMode::Pplns, addr, 1.0, 1_700_000_000_003),
    ];
    // Redelivery of one id from each epoch — must dedup, not double-count.
    let dups = vec![shares[0].clone(), shares[2].clone()];

    let engine = spawn_engine(conn.clone(), pool).await;
    let sink: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(PplnsAcceptedShareSink::new(engine.clone()));
    run_stream_path(conn, &shares, &dups, sink).await;

    let (by_addr, total) = window_state(&engine).await;
    // 4 distinct ids × diff 1.0; the 2 dups (1:0, 2:0) dedup → exactly 4.0.
    assert!(
        (total - 4.0).abs() < 1e-9,
        "mixed-epoch total {total} (want 4.0 — 1:0 and 2:0 must not collide, dups must dedup)"
    );
    assert!((by_addr.get(addr).copied().unwrap_or(0.0) - 4.0).abs() < 1e-9);

    engine.shutdown();
}

/// T9 — Disconnect-before-consume. A miner can disconnect (clearing any
/// Core gate) before the Satellite consumes its share; the share must still
/// be credited to the mode it was stamped with. Driving a mix of modes
/// through the PPLNS sink, only the `Pplns`-stamped shares land — the sink
/// reads `share.mode`, never a gate.
#[tokio::test]
async fn only_pplns_mode_shares_land_in_the_pplns_window() {
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    let Some(conn) = connect_redis_or_skip(6).await else {
        return;
    };

    let addr = "bc1qmodeonshare";
    let shares = vec![
        mk_share("m:0", MiningMode::Pplns, addr, 1.0, 1_700_000_000_000),
        mk_share("m:1", MiningMode::Solo, addr, 5.0, 1_700_000_000_001),
        mk_share("m:2", MiningMode::Pplns, addr, 1.0, 1_700_000_000_002),
        mk_share("m:3", MiningMode::GroupSolo, addr, 9.0, 1_700_000_000_003),
        mk_share("m:4", MiningMode::Pplns, addr, 1.0, 1_700_000_000_004),
    ];

    let engine = spawn_engine(conn.clone(), pool).await;
    let sink: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(PplnsAcceptedShareSink::new(engine.clone()));
    run_stream_path(conn, &shares, &[], sink).await;

    let (by_addr, total) = window_state(&engine).await;
    // Only the 3 Pplns shares (diff 1.0 each); the Solo (5.0) + GroupSolo
    // (9.0) shares are excluded by `share.mode`.
    assert!(
        (total - 3.0).abs() < 1e-9,
        "mode-on-share total {total} (want 3.0 — Solo/GroupSolo must be excluded)"
    );
    assert!((by_addr.get(addr).copied().unwrap_or(0.0) - 3.0).abs() < 1e-9);

    engine.shutdown();
}

/// T11 — ts_ms replay. The Satellite may consume a share minutes/hours after
/// it was accepted (outage + replay). The PPLNS `lastAcceptedShareAt` touch
/// must reflect the SHARE's accept time, not the consume time — otherwise a
/// replayed backlog would reset every miner's abandoned-balance clock.
#[tokio::test]
async fn pplns_touch_uses_share_time_not_consume_time() {
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    let Some(conn) = connect_redis_or_skip(7).await else {
        return;
    };

    let addr = "bc1qtsreplay";
    // A deliberately old accept time; consume happens "now" (~1.7e12+).
    let old_ts: i64 = 1_600_000_000_000;
    let shares = vec![mk_share("r:0", MiningMode::Pplns, addr, 1.0, old_ts)];

    let engine = spawn_engine(conn.clone(), pool).await;
    let sink: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(PplnsAcceptedShareSink::new(engine.clone()));
    run_stream_path(conn, &shares, &[], sink).await;

    let touched = engine.touch_buffer().drain();
    let entry = touched
        .iter()
        .find(|t| t.address == addr)
        .expect("address was touched");
    assert_eq!(
        entry.last_accepted_share_at_ms, old_ts,
        "touch must use the share's ts_ms, not consume time"
    );

    engine.shutdown();
}
