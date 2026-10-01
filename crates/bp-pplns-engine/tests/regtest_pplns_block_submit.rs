// SPDX-License-Identifier: AGPL-3.0-or-later

// Test-tooling skip messages need print_stderr.
#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! E2E: the PPLNS engine's own multi-output coinbase is accepted by
//! `bitcoin-node`; any math error that misses `coinbasevalue` shows up only
//! here, as `bad-cb-amount`. Skips without `bitcoin-node`, Redis or PG.

use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_pplns::DEFAULT_MIN_PAYOUT_SATS;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::window::NetworkDifficulty;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Difficulty;
use bp_template_distribution::{NewTemplate, TdpConfig, TdpHandle, TemplateUpdate};
use sqlx::PgPool;
use tokio::sync::broadcast;

use bp_test_support::{
    connect_pg_or_skip, connect_redis_in_range_or_skip, deterministic_p2wpkh_regtest,
    mine_and_submit_payouts, redis_db, wait_for_paired_template,
};

/// This binary's own numbering inside [`redis_db::RT_PPLNS_BLOCK_SUBMIT`];
/// the three numbers must be distinct from each other.
const REDIS_TEST_DB: u8 = 0;
const REDIS_TEST_DB_TXS: u8 = 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_three_miner_distribution_block_accepted_by_core() {
    // ── Skip if bitcoin-node isn't installed ─────────────────────
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping PPLNS e2e regtest — {}",
            regtest_cfg.unavailable_reason()
        );
        return;
    }
    // ── Skip if Redis / PG aren't reachable ──────────────────────
    let Some(redis_conn) =
        connect_redis_in_range_or_skip(redis_db::RT_PPLNS_BLOCK_SUBMIT, REDIS_TEST_DB).await
    else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // ── Three deterministic miner addresses + fee addr ────────────
    let addr_alice = deterministic_p2wpkh_regtest([0x11; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x22; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0x33; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x99; 32]);

    // ── Spawn the PPLNS engine against the test backing ───────────
    //
    // `window_size = 4 × network_difficulty` must hold the seeded 600.
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
    let entries = dist
        .distribution
        .payout_entries_at(reward_sats)
        .expect("§4 payout vector");
    assert_eq!(
        entries.len(),
        4,
        "expected exactly 4 payouts (pool + 3 member shares) — got {}: {:?}",
        entries.len(),
        entries
            .iter()
            .map(|(a, s)| (a.as_str(), *s))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        entries[0].0.as_str(),
        addr_fee,
        "the pool output leads the §4 order"
    );
    for miner in [&addr_alice, &addr_bob, &addr_charlie] {
        let n = entries.iter().filter(|(a, _)| a.as_str() == *miner).count();
        assert_eq!(
            n, 1,
            "miner {miner} must appear in exactly one output (got {n})"
        );
    }
    // `pay_P` absorbs the rounding, so the vector sums to the revenue.
    let total_payout_sats: u64 = entries.iter().map(|(_, s)| *s).sum();
    assert_eq!(
        total_payout_sats, reward_sats,
        "distribution sat sums must equal reward — math drift would be \
         silently caught here before the coinbase even goes to core"
    );

    let payouts: Vec<PayoutEntry> = entries
        .iter()
        .map(|(a, s)| PayoutEntry {
            address: a.as_str().to_string(),
            sats: *s,
        })
        .collect();

    let _accepted = mine_and_submit_payouts(
        &node,
        &tdp,
        &template,
        &prev_hash,
        &payouts,
        "pplns-e2e-regtest",
        [0u8; 32],
    )
    .await;

    // ── Teardown ─────────────────────────────────────────────────
    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_pplns_state(&pg, &payouts).await;
    let _ = Difficulty(1.0); // keeps the import used
}

/// Pins the merkle branch fold (byte order, sibling order) against
/// bitcoin-core; on an empty mempool the fold is the identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_block_with_real_txs_nonempty_merkle_path_accepted_by_core() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping PPLNS non-empty-merkle regtest — {}",
            regtest_cfg.unavailable_reason()
        );
        return;
    }
    let Some(redis_conn) =
        connect_redis_in_range_or_skip(redis_db::RT_PPLNS_BLOCK_SUBMIT, REDIS_TEST_DB_TXS).await
    else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // Distinct from the sibling test: same PG table, run in parallel.
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
    node.generate_to_self(1)
        .await
        .expect("mine 1 for a fresh template");
    let (_empty_template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── Fund the mempool so the next template has a merkle path ──
    for _ in 0..4 {
        let dest = node.new_address("bech32").await.expect("dest address");
        node.wallet_call("sendtoaddress", serde_json::json!([dest, 0.01]))
            .await
            .expect("sendtoaddress");
    }

    // The tip has not moved, so `prev_hash` still applies.
    let template = wait_for_template_with_txs(&mut rx).await;
    assert!(
        !template.merkle_path.is_empty(),
        "template built over a funded mempool must carry a non-empty merkle path"
    );

    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(reward_sats)
        .await
        .expect("build_distribution");
    let payouts: Vec<PayoutEntry> = dist
        .distribution
        .payout_entries_at(reward_sats)
        .expect("§4 payout vector")
        .iter()
        .map(|(a, s)| PayoutEntry {
            address: a.as_str().to_string(),
            sats: *s,
        })
        .collect();

    let _accepted = mine_and_submit_payouts(
        &node,
        &tdp,
        &template,
        &prev_hash,
        &payouts,
        "pplns-merkle-regtest",
        [0u8; 32],
    )
    .await;

    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_pplns_state(&pg, &payouts).await;
}

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
    for p in payouts {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(&p.address)
            .execute(pool)
            .await;
    }
}

fn test_engine_config(fee_addr: &str) -> PplnsEngineConfig {
    PplnsEngineConfig {
        // Neither background task may fire during the test.
        dust_sweep_enabled: false,
        touch_flush_interval_secs: 3_600,
        fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr valid")),
        fee_percent: 1.5,
        min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
        ..PplnsEngineConfig::default()
    }
}

// Keeps the `AddressId` import used.
#[allow(dead_code)]
fn _force_addr_id(_: AddressId) {}

fn coinbase_template_from(t: &NewTemplate) -> TdpCoinbaseTemplate<'_> {
    TdpCoinbaseTemplate {
        coinbase_prefix: &t.coinbase_prefix,
        coinbase_tx_version: t.coinbase_tx_version,
        coinbase_tx_input_sequence: t.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: t.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &t.coinbase_tx_outputs,
        coinbase_tx_outputs_count: t.coinbase_tx_outputs_count,
        coinbase_tx_locktime: t.coinbase_tx_locktime,
    }
}

const REDIS_TEST_DB_LEDGER: u8 = 2;

/// The ledger books exactly what the accepted coinbase paid, via the job's
/// fingerprint, even after a later build ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ledger_books_exactly_what_the_accepted_coinbase_paid() {
    use bitcoin::consensus::Decodable;

    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping PPLNS ledger-equality regtest — {}",
            regtest_cfg.unavailable_reason()
        );
        return;
    }
    let Some(redis_conn) =
        connect_redis_in_range_or_skip(redis_db::RT_PPLNS_BLOCK_SUBMIT, REDIS_TEST_DB_LEDGER).await
    else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    let addr_alice = deterministic_p2wpkh_regtest([0x41; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x42; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0x43; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x4f; 32]);
    let engine = PplnsEngine::spawn(
        test_engine_config(&addr_fee),
        redis_conn,
        pg.clone(),
        NetworkDifficulty::new(1_000.0),
    )
    .await
    .expect("PplnsEngine::spawn");
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    for (addr, weight) in [
        (&addr_alice, 100.0),
        (&addr_bob, 200.0),
        (&addr_charlie, 300.0),
    ] {
        engine
            .record_share(None, addr, weight, now_ms)
            .await
            .expect("seed share");
    }

    let node = RegtestNode::start_with(regtest_cfg)
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");
    let tdp = TdpHandle::spawn(TdpConfig::new(node.ipc_socket_path()).with_fee_threshold(1))
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

    // ── The build this block's coinbase is made from ──────────────
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(reward_sats)
        .await
        .expect("build_distribution");
    let fingerprint = dist.payouts_fingerprint();
    let payouts: Vec<PayoutEntry> = dist
        .distribution
        .payout_entries_at(reward_sats)
        .expect("§4 payout vector")
        .iter()
        .map(|(a, s)| PayoutEntry {
            address: a.as_str().to_string(),
            sats: *s,
        })
        .collect();

    // The fingerprint is the identity a found block books through.
    let coinbase_template = coinbase_template_from(&template);
    let job = build_mining_job_from_tdp(
        Network::Regtest,
        &payouts,
        &coinbase_template,
        "pplns-ledger-regtest",
        EXTRANONCE_SLOT_LEN,
        fingerprint,
    )
    .expect("build_mining_job_from_tdp");
    assert_eq!(
        job.payouts_fingerprint(),
        &fingerprint,
        "the job must carry the distribution's fingerprint verbatim"
    );

    // ── A later build at another reference shares the SAME snapshot and
    //    must not disturb the booking below ───────────────────────
    let jdc_style = engine
        .build_distribution(reward_sats - 997)
        .await
        .expect("jdc-style build");
    assert_eq!(jdc_style.payouts_fingerprint(), fingerprint);

    let accepted = mine_and_submit_payouts(
        &node,
        &tdp,
        &template,
        &prev_hash,
        &payouts,
        "pplns-ledger-regtest",
        fingerprint,
    )
    .await;

    // ── Book it from the REAL accepted coinbase ───────────────────
    let coinbase_tx =
        bitcoin::Transaction::consensus_decode(&mut accepted.witness_coinbase.as_slice())
            .expect("submitted coinbase must decode");
    let actual = bp_coinbase_snapshot::ActualCoinbase::from_coinbase(
        &coinbase_tx,
        bitcoin::Network::Regtest,
    );
    assert_eq!(actual.total_value_sats, reward_sats);
    let _prepared = engine
        .on_block_found(accepted.height as i32, &actual, None, Some(fingerprint))
        .await
        .expect("the mined job's own distribution must resolve for booking");

    // ── The ledger must match the coinbase the chain accepted ────
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"SELECT address, "paidSats" FROM pplns_payout_history
           WHERE "blockHeight" = $1 AND "rowType" = 'coinbase'"#,
    )
    .bind(accepted.height as i32)
    .fetch_all(&pg)
    .await
    .expect("read audit rows");
    assert!(!rows.is_empty(), "coinbase audit rows must exist");

    for (address, paid_sats) in &rows {
        let script = bp_mining_job::address_to_script(Network::Regtest, address)
            .expect("audit-row address must be a payable script");
        let matched = coinbase_tx.output.iter().any(|o| {
            o.script_pubkey.as_bytes() == script.as_bytes() && o.value.to_sat() == *paid_sats as u64
        });
        assert!(
            matched,
            "ledger claims {address} was paid {paid_sats} sat on-chain, but the \
             accepted coinbase has no such output — the booked distribution is \
             not the one this block paid"
        );
    }

    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
        .bind(accepted.height as i32)
        .execute(&pg)
        .await;
    cleanup_pplns_state(&pg, &payouts).await;
}
