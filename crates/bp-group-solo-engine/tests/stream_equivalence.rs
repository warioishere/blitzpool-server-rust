// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! T1 — accounting equivalence for Group-Solo between the in-process sink
//! path and the Core→stream→Satellite path. Mirror of the PPLNS T1.
//!
//! The same Group-Solo share sequence (deterministic `share_id`s, one
//! group) driven (a) directly through `GroupSoloAcceptedShareSink` vs
//! (b) produce → Redis stream → drain into a fresh sink must leave
//! identical round state (per-address aggregate + total). Group-Solo is a
//! PROP round (no trim), so the comparison is exact by construction.
//!
//! Needs docker-Redis (16379) + PG (15433); skips cleanly otherwise.

use std::sync::Arc;

use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_group_solo_engine::hooks::GroupSoloAcceptedShareSink;
use bp_share_hook::{MiningMode, SharedAcceptedShareOwned, SharedAcceptedShareSink};
use bp_share_stream::{AcceptedShareConsumer, AcceptedShareProducer};
use bp_test_support::{connect_pg_or_skip, connect_redis_or_skip};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use uuid::Uuid;

const N: usize = 60;

/// Deterministic Group-Solo share sequence for one `group_id` — 5 miners,
/// varying difficulty, stable `share_id`s.
fn share_seq(group_id: Uuid) -> Vec<SharedAcceptedShareOwned> {
    let gid = group_id.to_string();
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
            mode: MiningMode::GroupSolo,
            group_id: Some(gid.clone()),
        })
        .collect()
}

async fn spawn_engine(conn: ConnectionManager, pool: PgPool) -> GroupSoloEngine {
    let config = GroupSoloEngineConfig {
        dust_sweep_enabled: false,
        ..GroupSoloEngineConfig::default()
    };
    GroupSoloEngine::spawn(config, conn, pool)
        .await
        .expect("spawn group-solo engine")
}

async fn round_state(
    engine: &GroupSoloEngine,
    group_key: &str,
) -> (std::collections::HashMap<String, f64>, f64) {
    let by_addr = engine
        .round()
        .read_by_address(group_key)
        .await
        .expect("read_by_address");
    let total = engine
        .round()
        .read_total(group_key)
        .await
        .expect("read_total");
    (by_addr, total)
}

fn assert_rounds_equal(
    a: &(std::collections::HashMap<String, f64>, f64),
    b: &(std::collections::HashMap<String, f64>, f64),
) {
    let (by_a, total_a) = a;
    let (by_b, total_b) = b;
    assert!(
        (total_a - total_b).abs() < 1e-9,
        "round total drift: in-process={total_a} stream={total_b}"
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

async fn run_stream_path(
    conn: ConnectionManager,
    shares: &[SharedAcceptedShareOwned],
    extra_dups: &[SharedAcceptedShareOwned],
    sink: Arc<dyn SharedAcceptedShareSink>,
) {
    let key = "t1:groupsolo:accepted";
    let producer = AcceptedShareProducer::new(conn.clone(), key);
    let consumer = AcceptedShareConsumer::new(conn.clone(), key, "money", "c1");
    consumer.ensure_group().await.expect("ensure_group");

    for s in shares {
        producer.publish(s).await.expect("publish");
    }
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
async fn in_process_and_stream_paths_leave_identical_group_solo_round() {
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    // DBs 0–15 only (valkey default); 12/13 here, 14/15 in the dup test.
    let (Some(conn_a), Some(conn_b)) = (
        connect_redis_or_skip(12).await,
        connect_redis_or_skip(13).await,
    ) else {
        return;
    };

    let group_id = Uuid::new_v4();
    let group_key = group_id.to_string();
    let shares = share_seq(group_id);

    // ── Path A: in-process sink ──
    let engine_a = spawn_engine(conn_a, pool.clone()).await;
    let sink_a = GroupSoloAcceptedShareSink::new(engine_a.clone());
    for s in &shares {
        sink_a.record_accepted(s.as_view()).await;
    }
    let state_a = round_state(&engine_a, &group_key).await;

    // ── Path B: produce → stream → drain into a fresh sink ──
    let engine_b = spawn_engine(conn_b.clone(), pool.clone()).await;
    let sink_b: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(GroupSoloAcceptedShareSink::new(engine_b.clone()));
    run_stream_path(conn_b, &shares, &[], sink_b).await;
    let state_b = round_state(&engine_b, &group_key).await;

    assert_rounds_equal(&state_a, &state_b);
}

#[tokio::test]
async fn duplicate_entries_in_the_stream_do_not_break_group_solo_equivalence() {
    let Some(pool) = connect_pg_or_skip().await else {
        return;
    };
    let (Some(conn_a), Some(conn_b)) = (
        connect_redis_or_skip(14).await,
        connect_redis_or_skip(15).await,
    ) else {
        return;
    };

    let group_id = Uuid::new_v4();
    let group_key = group_id.to_string();
    let shares = share_seq(group_id);

    let engine_a = spawn_engine(conn_a, pool.clone()).await;
    let sink_a = GroupSoloAcceptedShareSink::new(engine_a.clone());
    for s in &shares {
        sink_a.record_accepted(s.as_view()).await;
    }
    let state_a = round_state(&engine_a, &group_key).await;

    let dups = vec![shares[0].clone(), shares[5].clone(), shares[37].clone()];
    let engine_b = spawn_engine(conn_b.clone(), pool.clone()).await;
    let sink_b: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(GroupSoloAcceptedShareSink::new(engine_b.clone()));
    run_stream_path(conn_b, &shares, &dups, sink_b).await;
    let state_b = round_state(&engine_b, &group_key).await;

    assert_rounds_equal(&state_a, &state_b);
}
