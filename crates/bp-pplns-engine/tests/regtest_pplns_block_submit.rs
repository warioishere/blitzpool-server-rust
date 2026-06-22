// SPDX-License-Identifier: AGPL-3.0-or-later

// Test-tooling skip messages need print_stderr.
#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! E2E: `PplnsEngine::build_distribution()` → multi-output coinbase →
//! `bitcoin-node` accepts the block.
//!
//! Closes the gap that the existing `bp-mining-job` and
//! `bp-stratum-v2` regtests left open: those test the coinbase-assembly
//! and SV2 submit paths with hand-built payout lists, but never
//! exercise the path where the PPLNS engine *itself* produces the
//! N-output distribution that goes into the coinbase. A subtle math bug
//! in the engine (rounding, dust-floor, fee subtraction, weight-budget
//! adaptive trim) would produce a coinbase whose `outputs[i].value`
//! sums don't match `coinbasevalue`, which bitcoin-core rejects with
//! `bad-cb-amount` — undetectable without an end-to-end regtest like
//! this one.
//!
//! Sequence:
//! 1. Bring up a real `bitcoin-node v31` regtest instance.
//! 2. Connect a fresh Redis logical DB + PG (test prefix-isolated).
//! 3. Spawn the PPLNS engine with the test infrastructure as backing.
//! 4. Seed the window with three miner addresses at different share
//!    weights (so the resulting distribution has three non-trivial
//!    percentages).
//! 5. Attach `TdpHandle`, drain the startup template pair, mine one
//!    block for a fresh template at the post-IBD tip.
//! 6. Call `build_distribution(coinbase_tx_value_remaining)` on the
//!    engine — get back the payout list it would put in the coinbase.
//! 7. Feed that payout list into `bp_mining_job::build_mining_job_from_tdp`,
//!    construct the witness coinbase with zero extranonces, brute-force
//!    a regtest-target nonce, submit via `TdpHandle::submit_solution`.
//! 8. Assert chain tip advances by one — proves bitcoin-core accepted
//!    the engine-built distribution.
//!
//! Test gating:
//! - Skips cleanly when bitcoin-node binary is missing.
//! - Skips cleanly when local Redis (16379) or PG (15433) is not up.

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
use bp_pplns_engine::window::NetworkDifficulty;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::{Difficulty, Target};
use bp_template_distribution::{NewTemplate, TdpConfig, TdpHandle, TemplateUpdate};
use sqlx::PgPool;
use tokio::sync::broadcast;

use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, connect_redis_or_skip, deterministic_p2wpkh_regtest,
    poll_for_height, wait_for_paired_template,
};

/// Reserved logical DB for this test — doesn't collide with the
/// existing window-integration tests (which take 0..=7).
const REDIS_TEST_DB: u8 = 9;
/// Separate logical DB for the non-empty-merkle-path variant so it can run
/// in parallel with the sibling test without colliding on FLUSHDB.
const REDIS_TEST_DB_TXS: u8 = 10;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_three_miner_distribution_block_accepted_by_core() {
    // ── Skip if bitcoin-node isn't installed ─────────────────────
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping PPLNS e2e regtest — bitcoin-node not found at {} \
             (set BITCOIN_NODE_PATH to override)",
            regtest_cfg.bitcoin_node_path.display()
        );
        return;
    }
    // ── Skip if Redis / PG aren't reachable ──────────────────────
    let Some(redis_conn) = connect_redis_or_skip(REDIS_TEST_DB).await else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // ── Three deterministic miner addresses + fee addr ────────────
    //
    // Production runs with a fee_address (1.5%) configured. Mirror
    // that so the engine's residuum path matches real-world behavior.
    let addr_alice = deterministic_p2wpkh_regtest([0x11; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x22; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0x33; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x99; 32]);

    // ── Spawn the PPLNS engine against the test backing ───────────
    //
    // `window_size = window_factor × network_difficulty`. With the
    // default `window_factor=4.0` and three seeded shares of 100, 200,
    // 300 (sum=600), the network-difficulty needs to be ≥ 150 for the
    // window to retain all three; we pick 1000 for comfortable
    // headroom so the trimmer doesn't drop our oldest entries before
    // `build_distribution` runs.
    let net_diff = NetworkDifficulty::new(1_000.0);
    let engine = PplnsEngine::spawn(
        test_engine_config(&addr_fee),
        redis_conn,
        pg.clone(),
        net_diff,
    )
    .await
    .expect("PplnsEngine::spawn");

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    engine
        .record_share(None, &addr_alice, 100.0, now_ms)
        .await
        .expect("seed share Alice");
    engine
        .record_share(None, &addr_bob, 200.0, now_ms)
        .await
        .expect("seed share Bob");
    engine
        .record_share(None, &addr_charlie, 300.0, now_ms)
        .await
        .expect("seed share Charlie");

    // ── Boot bitcoin-core + mine past IBD ─────────────────────────
    let node = RegtestNode::start_with(regtest_cfg)
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Attach TDP, drain startup pair, mine 1 for fresh template ──
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
        .expect("mine 1 more to force fresh NewTemplate");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── Build the engine's distribution for this template's reward ──
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(reward_sats)
        .await
        .expect("build_distribution");
    // Bit-exact shape: 3 seeded miners + fee_address configured →
    // exactly 4 coinbase outputs (1 fee + 3 share outputs).
    assert_eq!(
        dist.payouts.len(),
        4,
        "expected exactly 4 payouts (fee + 3 member shares) — got {}: {:?}",
        dist.payouts.len(),
        dist.payouts
            .iter()
            .map(|p| (p.address.as_str(), p.sats.0))
            .collect::<Vec<_>>(),
    );
    let fee_entries: Vec<&_> = dist
        .payouts
        .iter()
        .filter(|p| p.address.as_str() == addr_fee)
        .collect();
    assert_eq!(
        fee_entries.len(),
        1,
        "fee address must appear in exactly one output"
    );
    for miner in [&addr_alice, &addr_bob, &addr_charlie] {
        let n = dist
            .payouts
            .iter()
            .filter(|p| p.address.as_str() == miner)
            .count();
        assert_eq!(
            n, 1,
            "miner {miner} must appear in exactly one output (got {n})"
        );
    }
    // Sanity-check the sat sums: total of distribution outputs must
    // equal the reward we asked for, otherwise bitcoin-core would
    // reject with `bad-cb-amount` regardless of any other math.
    let total_payout_sats: i64 = dist.payouts.iter().map(|p| p.sats.0).sum();
    assert_eq!(
        total_payout_sats as u64, reward_sats,
        "distribution sat sums must equal reward — math drift would be \
         silently caught here before the coinbase even goes to core"
    );

    // ── Convert engine payouts → bp-mining-job PayoutEntry ────────
    //
    // `MiningJob` re-derives sat values from `percent × reward`
    // internally; passing percent here keeps the two layers in sync
    // (any rounding drift between engine and mining-job would show
    // up as `bad-cb-amount` on submit).
    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|p| PayoutEntry {
            address: p.address.as_str().to_string(),
            percent: p.percent,
        })
        .collect();

    // ── Build the MiningJob + brute-force a regtest-target nonce ──
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
        "pplns-e2e-regtest",
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
    .expect("must find a regtest-target-matching nonce within 1M tries");

    // ── Submit + assert chain tip advances ───────────────────────
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
        .expect(
            "bitcoin-core must accept the block — a stuck tip means the \
             engine-built distribution produced a coinbase the chain \
             rejected (sat-sum drift, dust output, malformed script, ...)",
        );
    assert_eq!(after, before_height + 1);

    // ── Teardown ─────────────────────────────────────────────────
    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_pplns_state(&pg, &payouts).await;
    // The Redis DB is FLUSHDB'd at the next test run's connect; nothing
    // to drain here. Wedging the shutdown signal lets the engine's
    // background tasks see `cancelled` and exit gracefully before the
    // test process exits.
    let _ = Difficulty(1.0); // silence "unused" if a refactor drops the import
}

/// E2E with a NON-EMPTY merkle path: fund the mempool with real wallet
/// transactions, wait for the TDP to emit a template that includes them
/// (so `merkle_path` is non-empty), build the coinbase, reconstruct the
/// root via `merkle_root_from_coinbase` over the real branch, and submit
/// to bitcoin-core.
///
/// The other block-submit regtests mine on an empty mempool, so their
/// `merkle_path` is empty and the merkle fold is the trivial identity
/// (root == coinbase txid). This is the only test that exercises the
/// merkle-branch combination loop end-to-end against real bitcoin-core —
/// a byte-order or sibling-concatenation bug in `merkle_root_from_coinbase`
/// would make the header's merkle root mismatch the block's transactions
/// and bitcoin-core would reject the submission (stuck tip).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_block_with_real_txs_nonempty_merkle_path_accepted_by_core() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping PPLNS non-empty-merkle regtest — bitcoin-node not found at {}",
            regtest_cfg.bitcoin_node_path.display()
        );
        return;
    }
    let Some(redis_conn) = connect_redis_or_skip(REDIS_TEST_DB_TXS).await else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // Distinct addresses from the sibling test (they share the PG table +
    // run in parallel threads).
    let addr_alice = deterministic_p2wpkh_regtest([0x44; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x55; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0x66; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x88; 32]);

    let net_diff = NetworkDifficulty::new(1_000.0);
    let engine = PplnsEngine::spawn(
        test_engine_config(&addr_fee),
        redis_conn,
        pg.clone(),
        net_diff,
    )
    .await
    .expect("PplnsEngine::spawn");

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    engine
        .record_share(None, &addr_alice, 100.0, now_ms)
        .await
        .expect("seed Alice");
    engine
        .record_share(None, &addr_bob, 200.0, now_ms)
        .await
        .expect("seed Bob");
    engine
        .record_share(None, &addr_charlie, 300.0, now_ms)
        .await
        .expect("seed Charlie");

    let node = RegtestNode::start_with(regtest_cfg)
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn");
    let mut rx = tdp.subscribe();
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if rx.recv().await.is_err() {
                break;
            }
        }
    })
    .await;
    // Fresh template at the post-IBD tip (mempool still empty here).
    node.generate_to_self(1)
        .await
        .expect("mine 1 for a fresh template");
    let (_empty_template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── Fund the mempool: several wallet txs so the next template carries
    //    a non-empty merkle path. The node's matured coinbase (from the
    //    101-block warmup) funds these sends. ──
    for _ in 0..4 {
        let dest = node.new_address("bech32").await.expect("dest address");
        node.wallet_call("sendtoaddress", serde_json::json!([dest, 0.01]))
            .await
            .expect("sendtoaddress");
    }

    // The tip hasn't moved (we didn't mine), so `prev_hash` still applies;
    // wait for the mempool-delta template that now includes our txs.
    let template = wait_for_template_with_txs(&mut rx).await;
    assert!(
        !template.merkle_path.is_empty(),
        "template built over a funded mempool must carry a non-empty merkle path"
    );

    // ── Engine distribution for this template's reward (subsidy + fees) ──
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(reward_sats)
        .await
        .expect("build_distribution");
    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|p| PayoutEntry {
            address: p.address.as_str().to_string(),
            percent: p.percent,
        })
        .collect();

    // ── Build coinbase, reconstruct the root over the NON-EMPTY branch ──
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
        "pplns-merkle-regtest",
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
    .expect("must find a regtest-target-matching nonce");

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
        .expect(
            "bitcoin-core must accept the block — a stuck tip with a non-empty merkle path \
             means the reconstructed merkle root didn't match the block's transactions \
             (merkle fold byte-order / sibling-order bug)",
        );
    assert_eq!(after, before_height + 1);

    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_pplns_state(&pg, &payouts).await;
}

/// Wait for a `NewTemplate` whose `merkle_path` is non-empty (i.e. built
/// over a mempool that contains at least one non-coinbase transaction).
async fn wait_for_template_with_txs(rx: &mut broadcast::Receiver<TemplateUpdate>) -> NewTemplate {
    let res = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match rx.recv().await {
                Ok(TemplateUpdate::NewTemplate(nt)) if !nt.merkle_path.is_empty() => return nt,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    panic!("TDP channel closed before a tx-bearing template arrived")
                }
            }
        }
    })
    .await;
    res.expect("TDP must emit a template with a non-empty merkle path within 20s")
}

async fn cleanup_pplns_state(pool: &PgPool, payouts: &[PayoutEntry]) {
    // Delete only the balance rows for the addresses the test seeded;
    // leaves any other lingering rows alone.
    for p in payouts {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(&p.address)
            .execute(pool)
            .await;
    }
}

fn test_engine_config(fee_addr: &str) -> PplnsEngineConfig {
    PplnsEngineConfig {
        // Disable the daily dust sweep + push the touch-buffer flush
        // out to an hour so neither background task fires during the
        // short test window.
        dust_sweep_enabled: false,
        touch_flush_interval_secs: 3_600,
        // Match production: PPLNS deployments always have a fee
        // address and a non-zero fee percent configured.
        fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr valid")),
        fee_percent: 1.5,
        min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
        ..PplnsEngineConfig::default()
    }
}

// Silence the unused `AddressId` import if a refactor drops the only
// call site above. Kept on the import list so future test cases that
// need it don't have to re-add.
#[allow(dead_code)]
fn _force_addr_id(_: AddressId) {}
