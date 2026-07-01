// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! T4 — Core/Satellite split, gold-standard end-to-end against a real
//! regtest `bitcoin-node`.
//!
//! The other regtest block-submit tests record shares directly in-process
//! and prove a coinbase built from the engine's distribution is accepted by
//! bitcoin-core. This one proves the **split** path does the same:
//!
//! 1. The three miners' shares flow through the real Core→Satellite
//!    transport: Core producer `XADD`s → the Satellite consumer drains into
//!    the PPLNS engine's accept sink.
//! 2. **A Satellite restart mid-stream** with a crash-after-apply-before-ack:
//!    the un-acked entry is replayed on restart and the engine's per-`share_id`
//!    dedup makes the re-apply a no-op — exactly-once accounting survives the
//!    restart.
//! 3. The coinbase built from *that* (stream-fed, restart-survived)
//!    distribution is submitted to bitcoin-core, which must accept it (the
//!    chain tip advances).
//! 4. `on_block_found` applies the ledger.
//!
//! Skips cleanly when the `bitcoin-node` binary / Redis / PG aren't present.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_pplns::DEFAULT_MIN_PAYOUT_SATS;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::hooks::PplnsAcceptedShareSink;
use bp_pplns_engine::window::NetworkDifficulty;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_share_hook::{MiningMode, SharedAcceptedShareOwned, SharedAcceptedShareSink};
use bp_share_stream::{AcceptedShareConsumer, AcceptedShareProducer};
use bp_template_distribution::{TdpConfig, TdpHandle};
use sqlx::PgPool;

use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, connect_redis_or_skip, deterministic_p2wpkh_regtest,
    poll_for_height, wait_for_paired_template,
};

/// Logical DB for this test — distinct from the other regtest + window tests.
const REDIS_TEST_DB: u8 = 8;
const STREAM_KEY: &str = "t4:split:accepted";

fn mk_share(share_id: &str, address: &str, diff: f64) -> SharedAcceptedShareOwned {
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
        ts_ms: 1_700_000_000_000,
        share_id: share_id.to_string(),
        mode: MiningMode::Pplns,
        group_id: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_path_distribution_block_accepted_with_satellite_restart() {
    // ── Skip if the regtest node / Redis / PG aren't available ────
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping split e2e regtest — bitcoin-node not found at {} (set BITCOIN_NODE_PATH)",
            regtest_cfg.bitcoin_node_path.display()
        );
        return;
    }
    let Some(redis_conn) = connect_redis_or_skip(REDIS_TEST_DB).await else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // Distinct addresses from the sibling regtest tests (shared PG table).
    let addr_alice = deterministic_p2wpkh_regtest([0xa1; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0xb2; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0xc3; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0xfe; 32]);

    // The Satellite's PPLNS engine — full spawn (the satellite runs the
    // accounting + crons); its window is fed only through the stream.
    let net_diff = NetworkDifficulty::new(1_000.0);
    let engine = PplnsEngine::spawn(
        test_engine_config(&addr_fee),
        redis_conn.clone(),
        pg.clone(),
        net_diff,
    )
    .await
    .expect("PplnsEngine::spawn");

    // ── Core→Satellite share path with a restart mid-stream ───────
    let shares = vec![
        mk_share("t4:0", &addr_alice, 100.0),
        mk_share("t4:1", &addr_bob, 200.0),
        mk_share("t4:2", &addr_charlie, 300.0),
    ];
    let producer = AcceptedShareProducer::new(redis_conn.clone(), STREAM_KEY);
    for s in &shares {
        producer.publish(s).await.expect("core produce");
    }

    let sink: Arc<dyn SharedAcceptedShareSink> =
        Arc::new(PplnsAcceptedShareSink::new(engine.clone()));

    // First Satellite run: drain + apply + ack the first two shares.
    let c1 = AcceptedShareConsumer::new(redis_conn.clone(), STREAM_KEY, "money", "c1");
    c1.ensure_group().await.expect("ensure_group");
    let n = c1
        .drain_new(std::slice::from_ref(&sink), 2, 2000)
        .await
        .expect("drain_new");
    assert_eq!(n, 2, "first run consumes Alice + Bob");

    // Crash simulation: deliver the third share (Charlie) and APPLY it to the
    // engine, but die before the XACK — so it stays in the pending list.
    let pending = c1.read_new(10, 2000).await.expect("read_new charlie");
    assert_eq!(pending.len(), 1, "Charlie delivered to the PEL");
    for cs in &pending {
        sink.record_accepted(cs.share.as_view()).await;
    }
    drop(c1); // the "crash" — no ack issued

    // ── Satellite restart: same group+consumer replays the unacked entry ──
    let c2 = AcceptedShareConsumer::new(redis_conn.clone(), STREAM_KEY, "money", "c1");
    c2.ensure_group().await.expect("ensure_group after restart");
    let replayed = c2
        .drain_pending(std::slice::from_ref(&sink), 10)
        .await
        .expect("drain_pending");
    assert_eq!(
        replayed, 1,
        "the unacked Charlie share is replayed on restart"
    );
    // Nothing new left after the replay.
    let leftover = c2.read_new(10, 500).await.expect("read_new drained");
    assert!(leftover.is_empty(), "no entries left after restart-resume");

    // ── Exactly-once despite the redelivery: window has all 3, once ──
    let by_addr = engine
        .window()
        .read_window_by_address()
        .await
        .expect("read_window_by_address");
    assert_eq!(by_addr.len(), 3, "all three miners credited: {by_addr:?}");
    let total = engine.window().current_total().await.expect("total");
    assert!(
        (total - 600.0).abs() < 1e-9,
        "window total {total} (want 600 — Charlie's redelivery must dedup, not double-count to 900)"
    );

    // ── Boot bitcoin-core, mine past IBD, attach TDP, fresh template ──
    let node = RegtestNode::start_with(regtest_cfg)
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + maturity");
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    let mut rx = tdp.subscribe();
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if rx.recv().await.is_err() {
                break;
            }
        }
    })
    .await;
    node.generate_to_self(1)
        .await
        .expect("mine 1 more for a fresh NewTemplate");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── Distribution from the stream-fed Satellite engine ─────────
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(reward_sats)
        .await
        .expect("build_distribution");
    assert_eq!(
        dist.payouts.len(),
        4,
        "fee + 3 miners → 4 outputs, got {:?}",
        dist.payouts
            .iter()
            .map(|p| (p.address.as_str(), p.sats.0))
            .collect::<Vec<_>>()
    );
    let total_payout_sats: i64 = dist.payouts.iter().map(|p| p.sats.0).sum();
    assert_eq!(
        total_payout_sats as u64, reward_sats,
        "distribution sat sums must equal the reward (else bad-cb-amount)"
    );

    // ── Build the coinbase + brute-force a regtest-target nonce ───
    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|p| PayoutEntry {
            address: p.address.as_str().to_string(),
            sats: p.sats.0 as u64,
        })
        .collect();
    let coinbase_template = TdpCoinbaseTemplate {
        coinbase_prefix: &template.coinbase_prefix,
        coinbase_tx_version: template.coinbase_tx_version,
        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &template.coinbase_tx_outputs,
        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
        coinbase_tx_locktime: template.coinbase_tx_locktime,
    };
    let job = build_mining_job_from_tdp(
        Network::Regtest,
        &payouts,
        &coinbase_template,
        "split-e2e-regtest",
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job_from_tdp");
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let coinbase_txid = job.coinbase_txid_with_extranonce(&en1, &en2);
    let merkle_root = merkle_root_from_coinbase(&coinbase_txid, &template.merkle_path);
    let target = Target::from_le_bytes(prev_hash.target);
    let nonce = brute_force_nonce(
        template.version,
        &prev_hash.prev_hash,
        &merkle_root,
        prev_hash.header_timestamp,
        prev_hash.n_bits,
        &target,
    )
    .expect("find a regtest-target nonce within 1M tries");

    // ── Submit + assert bitcoin-core accepts the split-derived block ──
    let witness_coinbase = job.witness_coinbase_with_extranonce(&en1, &en2);
    let before_height = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        witness_coinbase,
    )
    .await
    .expect("submit_solution");
    let after = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .expect("bitcoin-core must accept the split-path coinbase (stuck tip = rejected)");
    assert_eq!(after, before_height + 1);

    // ── Satellite applies the block-found ledger ──────────────────
    let outcome = engine
        .on_block_found(after as i32, reward_sats)
        .await
        .expect("on_block_found");
    assert!(
        outcome.history_inserted >= 1,
        "block-found must write at least one ledger/audit row"
    );

    // ── Teardown ──────────────────────────────────────────────────
    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_pplns_state(&pg, &payouts).await;
}

async fn cleanup_pplns_state(pool: &PgPool, payouts: &[PayoutEntry]) {
    for p in payouts {
        let _ = sqlx::query("DELETE FROM pplns_payout_history WHERE address = $1")
            .bind(&p.address)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(&p.address)
            .execute(pool)
            .await;
    }
}

fn test_engine_config(fee_addr: &str) -> PplnsEngineConfig {
    PplnsEngineConfig {
        dust_sweep_enabled: false,
        touch_flush_interval_secs: 3_600,
        fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr valid")),
        fee_percent: 1.5,
        min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
        ..PplnsEngineConfig::default()
    }
}
