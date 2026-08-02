// SPDX-License-Identifier: AGPL-3.0-or-later

// Test-tooling skip messages + the measured-figures summary need print_stderr.
#![allow(clippy::print_stderr)]

//! E2E: the pool is paid its fee and nothing else — proved over two
//! consecutive REAL blocks against a `bitcoin-node`.
//!
//! The sibling regtests prove a distribution the engine built is a
//! coinbase bitcoin-core accepts, and that the ledger books what that
//! coinbase paid. Neither of them asks the question this one does: when
//! the coinbase has no room for every miner, WHO ends up holding the
//! satoshis the withheld miner did not get?
//!
//! There are only two answers. Either the withheld weight is folded into
//! the pool output — then the pool holds cash against a claim the ledger
//! still owes, and that claim comes back out of a later block's miner cut,
//! i.e. the OTHER miners fund it while the pool keeps the money. Or the
//! withheld entry is simply dropped from the published set — then the §4
//! split hands its share to the miners who ARE published, settlement books
//! their overpayment as debt against the withheld miner's credit, and the
//! pool output stays at exactly `fee·T`.
//!
//! The pure-math layer pins the second answer in unit tests. This test
//! pins it against a chain: every satoshi checked here comes out of a
//! coinbase transaction bitcoin-core validated and built on, and every
//! balance comes out of the `pplns_balance` rows the engine wrote — not
//! out of any value the engine handed back.
//!
//! Sequence:
//! 1. Three miners at 3 000 000 / 1 000 000 / 60 diff-weighted shares,
//!    pool fee 1.5 %.
//! 2. The coinbase weight budget is sized (from the weight constants, not
//!    guessed) to hold exactly TWO miner outputs, so the smallest miner
//!    falls out of the published set — while its payout stays far above
//!    `min_payout`, which makes the blockspace budget the demonstrable
//!    cause.
//! 3. Block 1 is mined and submitted; the settlement runs against the
//!    ACTUAL coinbase of the accepted block.
//! 4. The budget is widened (what the coinbase-budget autoscaler does when
//!    a build reports `trimmed_count > 0`) and block 2 is mined on the same
//!    window — the withheld miner's credit now flows on-chain and the two
//!    debts clear.
//!
//! Test gating: skips cleanly when the `bitcoin-node` binary, Redis or PG
//! are not reachable — the same shape as every other regtest here, so CI
//! without a node stays green.

use std::time::Duration;

use bitcoin::consensus::Decodable;
use bitcoin::Network;
use bp_coinbase_snapshot::ActualCoinbase;
use bp_common::{AddressId, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_pplns::{
    output_weight_for_address, WeightDistribution, WeightEntry, BUDGET_SAFETY_MARGIN_WU,
    COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT,
    DEFAULT_MIN_PAYOUT_SATS,
};
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::window::NetworkDifficulty;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::{claim_sats, Target};
use bp_template_distribution::{NewTemplate, SetNewPrevHash, TdpConfig, TdpHandle};
use sqlx::PgPool;

use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, connect_redis_or_skip, deterministic_p2wpkh_regtest,
    poll_for_height, wait_for_paired_template,
};

/// Redis logical DB for this test. Cargo runs test binaries one after
/// another, so what matters is that no test in THIS binary shares it —
/// this file has exactly one test.
const REDIS_TEST_DB: u8 = 13;

/// Diff-1-weighted window shares. The 3:1 between the two large miners
/// makes the redistribution checkable by eye; the third miner is small
/// enough to be the one the blockspace cut drops, yet its share of a
/// 50-BTC regtest block (~74 000 sats) is more than ten times
/// `min_payout` — so it is demonstrably the BUDGET withholding it.
const SHARES_ALICE: f64 = 3_000_000.0;
const SHARES_BOB: f64 = 1_000_000.0;
const SHARES_CHARLIE: f64 = 60.0;

/// `window_size = window_factor (4) × network_difficulty`, and the seeded
/// shares sum to 4 000 060 — a small network difficulty would have the
/// window trimmer eat the fixture before the first build runs.
const NETWORK_DIFFICULTY: f64 = 10_000_000.0;

/// Blocks mined before the test's own two. Well past IBD/maturity, and
/// deliberately far from the ~101 the other regtests use: the two blocks
/// this one books land at heights nothing else in the workspace touches,
/// so a leftover `pplns_payout_history` row cannot trip the
/// already-booked guard. Still below regtest's 150-block halving, so both
/// blocks pay the full 50-BTC subsidy.
const WARMUP_BLOCKS: u32 = 120;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withheld_miner_is_funded_by_the_other_miners_not_by_the_pool() {
    // ── Skip if bitcoin-node / Redis / PG aren't available ────────
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping pool-neutral payout regtest — bitcoin-node not found at {} \
             (set BITCOIN_NODE_PATH to override)",
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

    // Own address prefix: seeds no other regtest in the workspace uses,
    // so the shared PG ledger cannot mix this test's rows with another's.
    let addr_alice = deterministic_p2wpkh_regtest([0x71; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x72; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0x73; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x7f; 32]);
    let miners = [
        addr_alice.clone(),
        addr_bob.clone(),
        addr_charlie.clone(),
        addr_fee.clone(),
    ];
    // Leftovers from an aborted earlier run would be read back as opening
    // balances and change every figure below.
    delete_balances(&pg, &miners).await;

    // ── The weight budget, computed from the constants ────────────
    //
    // The trimmer reserves the structural coinbase, the safety margin,
    // the witness commitment and the pool output first, then keeps miner
    // outputs greedily while they fit. Sizing the budget for exactly two
    // (three) miner outputs is therefore arithmetic, not a guessed number
    // — and it stays correct if a constant ever moves.
    let output_weight = output_weight_for_address(&addr_alice);
    for addr in [&addr_bob, &addr_charlie] {
        assert_eq!(
            output_weight_for_address(addr),
            output_weight,
            "the fixture assumes all three miners cost the same output weight"
        );
    }
    let fixed_overhead = COINBASE_BASE_WEIGHT
        + COINBASE_WITNESS_COMMITMENT_WEIGHT
        + COINBASE_OUTPUT_WEIGHT
        + BUDGET_SAFETY_MARGIN_WU;
    let budget_two_outputs = fixed_overhead + 2 * output_weight;
    let budget_three_outputs = fixed_overhead + 3 * output_weight;

    // ── Engine + the seeded window ────────────────────────────────
    let engine = PplnsEngine::spawn(
        test_engine_config(&addr_fee, budget_two_outputs),
        redis_conn,
        pg.clone(),
        NetworkDifficulty::new(NETWORK_DIFFICULTY),
    )
    .await
    .expect("PplnsEngine::spawn");
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    for (addr, weight) in [
        (&addr_alice, SHARES_ALICE),
        (&addr_bob, SHARES_BOB),
        (&addr_charlie, SHARES_CHARLIE),
    ] {
        engine
            .record_share(None, addr, weight, now_ms)
            .await
            .expect("seed share");
    }

    // ── Boot bitcoin-core, attach the TDP ─────────────────────────
    let node = RegtestNode::start_with(regtest_cfg)
        .await
        .expect("regtest start");
    node.generate_to_self(WARMUP_BLOCKS)
        .await
        .expect("mine the warmup for IBD-exit + coinbase maturity");

    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    // Subscribe BEFORE generating: the TDP broadcasts the startup pair
    // immediately, and a subscribe afterwards would miss the template the
    // next `generate_to_self` produces.
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
        .expect("mine 1 more to force a fresh NewTemplate");
    let (template_1, prev_hash_1) = wait_for_paired_template(&mut rx).await;

    // The two heights this test will book. Cleared up front: the ledger
    // refuses to book a height that already has payout rows, and a run
    // that died before its teardown would leave exactly that behind.
    let base_height = node.current_height().await.expect("current_height") as i32;
    let (height_1, height_2) = (base_height + 1, base_height + 2);
    delete_payout_history(&pg, &[height_1, height_2]).await;

    // ═══ Block 1 — the budget withholds the smallest miner ════════

    let reward_1 = template_1.coinbase_tx_value_remaining;
    let dist_1 = engine
        .build_distribution(reward_1)
        .await
        .expect("build_distribution");
    let weights_1 = &dist_1.distribution;
    let fingerprint_1 = dist_1.payouts_fingerprint();

    // The fixture only proves anything if the budget actually cut, and
    // cut the miner we think it cut. A third published entry here means
    // either the budget math drifted or the shared test ledger carries
    // foreign open balances that competed for the two output slots.
    let published_1: Vec<String> = weights_1
        .published()
        .map(|e| e.address.as_str().to_string())
        .collect();
    assert_eq!(
        published_1.len(),
        2,
        "the budget was sized for exactly two miner outputs, got {published_1:?}"
    );
    assert!(
        published_1.contains(&addr_alice) && published_1.contains(&addr_bob),
        "the two largest miners must be the published ones, got {published_1:?}"
    );
    // `trimmed_count` counts the BLOCKSPACE cut only. Asserting it is what
    // separates this scenario from a min_payout withholding, which would
    // zero the same wire weight for an entirely different reason.
    assert_eq!(
        weights_1.budget_telemetry.trimmed_count, 1,
        "the blockspace cut — not the min_payout threshold — must be what withholds the third miner"
    );
    let charlie_1 = entry_for(weights_1, &addr_charlie);
    assert_eq!(charlie_1.wire_weight, 0, "the withheld miner has no output");
    assert!(
        charlie_1.score_weight > 0,
        "and must still carry its score into settlement"
    );

    let payouts_1 = payout_entries(weights_1, reward_1);
    let (mined_height_1, coinbase_1) = mine_and_submit(
        &node,
        &tdp,
        &template_1,
        &prev_hash_1,
        &payouts_1,
        "pool-neutral-regtest",
    )
    .await;
    assert_eq!(mined_height_1 as i32, height_1);

    // Settlement input is the coinbase the chain accepted, decoded from
    // the bytes that were submitted — not a reconstruction of what the
    // pool meant to pay. That distinction is the point of this test.
    let coinbase_tx_1 = bitcoin::Transaction::consensus_decode(&mut coinbase_1.as_slice())
        .expect("the submitted coinbase must decode");
    let actual_1 = ActualCoinbase::from_coinbase(&coinbase_tx_1, Network::Regtest);
    assert_eq!(
        actual_1.total_value_sats, reward_1,
        "the accepted coinbase must pay out the whole template value"
    );

    let t_1 = actual_1.total_value_sats;
    let fee_ppm = weights_1.fee_ppm;
    let claim_1 = |address: &str| {
        claim_sats(
            entry_for(weights_1, address).score_weight,
            weights_1.score_total,
            fee_ppm,
            t_1,
            weights_1.extras_total,
        )
    };
    let paid_1 = |address: &str| actual_1.paid_by_address.get(address).copied().unwrap_or(0) as i64;

    // The withheld miner's payout must clear `min_payout` by a wide
    // margin — otherwise the operational threshold, not the budget, would
    // be the thing keeping it out of the coinbase and the scenario would
    // prove something else.
    let withheld_claim = claim_1(&addr_charlie);
    assert!(
        withheld_claim > DEFAULT_MIN_PAYOUT_SATS as i64,
        "the withheld miner's {withheld_claim} sats must be above the {DEFAULT_MIN_PAYOUT_SATS}-sat \
         min_payout, or the budget is not what withheld it"
    );

    // ── (2) The pool output is the fee, and only the fee ──────────
    //
    // The failure this catches: folding the withheld weight into
    // `weight_P`. §4 pays the pool output whatever the miner outputs
    // leave, so the pool would have taken `fee·T + withheld_claim` here —
    // ~74 000 sats of miner money on a single block — while the ledger
    // credited the withheld miner the same amount, to be repaid later out
    // of the other miners' cut.
    let fee_only_1 = (t_1 as i64 * fee_ppm as i64) / 1_000_000;
    let pool_pay_1 = actual_1.pool_paid_sats as i64;
    let rounding_slack_1 = 1 + published_1.len() as i64;
    assert!(
        (pool_pay_1 - fee_only_1).abs() <= rounding_slack_1,
        "the pool output took {pool_pay_1} sats where its fee is {fee_only_1} — \
         {} sats of miner money (the withheld miner is owed {withheld_claim})",
        pool_pay_1 - fee_only_1
    );

    // ── (3) The withheld miner: no output, full credit ────────────
    let charlie_script = bp_mining_job::address_to_script(Network::Regtest, &addr_charlie)
        .expect("miner address must be payable");
    assert!(
        !coinbase_tx_1
            .output
            .iter()
            .any(|o| o.script_pubkey.as_bytes() == charlie_script.as_bytes()),
        "the withheld miner must not appear in the accepted coinbase at all"
    );
    let balances_1 = read_balances(&pg, &[&addr_alice, &addr_bob, &addr_charlie]).await;
    assert_eq!(
        balances_1,
        [0, 0, 0],
        "the ledger must be untouched before the block is booked"
    );

    let prepared_1 = engine
        .prepare_block_found_scaled(height_1, &actual_1, Some(fingerprint_1))
        .await
        .expect("the mined job's own distribution must resolve for booking");
    engine
        .apply_prepared(&prepared_1)
        .await
        .expect("apply_prepared");

    // Read the WRITTEN state: what the engine returned is an intention,
    // `pplns_balance` is the ledger.
    let [bal_alice_1, bal_bob_1, bal_charlie_1] =
        read_balances(&pg, &[&addr_alice, &addr_bob, &addr_charlie]).await;
    assert_eq!(
        bal_charlie_1, withheld_claim,
        "the withheld miner must hold its whole claim as credit"
    );

    // ── (4) The published miners were overpaid, pro rata, and owe it ──
    //
    // The share the withheld miner did not get is not lost and does not
    // go to the pool: the §4 split spreads it over the published miners
    // in proportion to their scores, and settlement books the matching
    // debt. Both halves are checked, because either one alone would also
    // hold if the money had quietly gone somewhere else.
    let score_alice = entry_for(weights_1, &addr_alice).score_weight as i128;
    let score_bob = entry_for(weights_1, &addr_bob).score_weight as i128;
    let published_score = score_alice + score_bob;
    for (address, score, balance) in [
        (&addr_alice, score_alice, bal_alice_1),
        (&addr_bob, score_bob, bal_bob_1),
    ] {
        let over = paid_1(address) - claim_1(address);
        let expected = (withheld_claim as i128 * score / published_score) as i64;
        assert!(
            over > 0,
            "{address} must be paid above its own claim — it is carrying the withheld miner"
        );
        assert!(
            (over - expected).abs() <= 2,
            "{address} was paid {over} sats above its claim, expected {expected} of the \
             {withheld_claim} sats the withheld miner left behind"
        );
        assert_eq!(
            balance,
            claim_1(address) - paid_1(address),
            "{address} must carry exactly its overpayment as debt"
        );
        assert!(balance < 0, "{address} owes, so its balance is negative");
    }

    // ── (5) The books close: ledger movement == claims − paid ─────
    let ledger_movement_1 = bal_alice_1 + bal_bob_1 + bal_charlie_1;
    let claims_minus_paid_1: i64 = [&addr_alice, &addr_bob, &addr_charlie]
        .iter()
        .map(|a| claim_1(a) - paid_1(a))
        .sum();
    assert_eq!(
        ledger_movement_1, claims_minus_paid_1,
        "every satoshi the ledger moved must be a satoshi a claim went unpaid by"
    );

    // ═══ Block 2 — the same window, room for everyone ═════════════
    //
    // Widening the budget is what the coinbase-budget autoscaler does
    // when a build reports blockspace pressure (`trimmed_count > 0`), and
    // it is the only change between the two blocks: same window, same
    // shares, same fee.
    engine.coinbase_budget().set(budget_three_outputs);
    engine.invalidate_distribution_cache();

    let (template_2, prev_hash_2) = wait_for_paired_template(&mut rx).await;
    assert_ne!(
        prev_hash_2.prev_hash, prev_hash_1.prev_hash,
        "block 2 must be built on the tip block 1 created, not on a stale template"
    );
    let reward_2 = template_2.coinbase_tx_value_remaining;
    let dist_2 = engine
        .build_distribution(reward_2)
        .await
        .expect("build_distribution");
    let weights_2 = &dist_2.distribution;
    let fingerprint_2 = dist_2.payouts_fingerprint();
    assert_eq!(
        weights_2.budget_telemetry.trimmed_count, 0,
        "the widened budget must have room for every miner"
    );
    assert!(
        entry_for(weights_2, &addr_charlie).wire_weight > 0,
        "the credit the previous block left must buy the withheld miner an output"
    );

    let payouts_2 = payout_entries(weights_2, reward_2);
    let (mined_height_2, coinbase_2) = mine_and_submit(
        &node,
        &tdp,
        &template_2,
        &prev_hash_2,
        &payouts_2,
        "pool-neutral-regtest",
    )
    .await;
    assert_eq!(mined_height_2 as i32, height_2);

    let coinbase_tx_2 = bitcoin::Transaction::consensus_decode(&mut coinbase_2.as_slice())
        .expect("the submitted coinbase must decode");
    let actual_2 = ActualCoinbase::from_coinbase(&coinbase_tx_2, Network::Regtest);
    let t_2 = actual_2.total_value_sats;
    assert_eq!(t_2, reward_2);

    let claim_2 = |address: &str| {
        claim_sats(
            entry_for(weights_2, address).score_weight,
            weights_2.score_total,
            weights_2.fee_ppm,
            t_2,
            weights_2.extras_total,
        )
    };
    let paid_2 = |address: &str| actual_2.paid_by_address.get(address).copied().unwrap_or(0) as i64;

    let prepared_2 = engine
        .prepare_block_found_scaled(height_2, &actual_2, Some(fingerprint_2))
        .await
        .expect("the second block's distribution must resolve for booking");
    engine
        .apply_prepared(&prepared_2)
        .await
        .expect("apply_prepared");

    // ── (6) The credit is paid on-chain and the debts are gone ────
    //
    // A ledger that only ever accumulates credit is not pool-neutral, it
    // is a pool that never pays. The withheld miner has to receive its
    // claim PLUS the credit the previous block left it, and the two
    // miners who pre-funded that payout have to come out square.
    let expected_charlie_2 = claim_2(&addr_charlie) + bal_charlie_1;
    assert!(
        (paid_2(&addr_charlie) - expected_charlie_2).abs() <= ROUNDING_SLACK_SATS,
        "the previously withheld miner was paid {} where its claim plus the {bal_charlie_1} sats \
         of credit is {expected_charlie_2}",
        paid_2(&addr_charlie)
    );
    let [bal_alice_2, bal_bob_2, bal_charlie_2] =
        read_balances(&pg, &[&addr_alice, &addr_bob, &addr_charlie]).await;
    for (address, balance) in [
        (&addr_alice, bal_alice_2),
        (&addr_bob, bal_bob_2),
        (&addr_charlie, bal_charlie_2),
    ] {
        assert!(
            balance.abs() <= ROUNDING_SLACK_SATS,
            "{address} still holds {balance} sats after the block that was supposed to settle it"
        );
    }

    // ── (7) Two blocks, two fees — no more ────────────────────────
    let fee_only_2 = (t_2 as i64 * weights_2.fee_ppm as i64) / 1_000_000;
    let pool_pay_2 = actual_2.pool_paid_sats as i64;
    let pool_total = pool_pay_1 + pool_pay_2;
    let fee_total = fee_only_1 + fee_only_2;
    let published_2 = weights_2.published().count() as i64;
    assert!(
        (pool_total - fee_total).abs() <= 2 + published_1.len() as i64 + published_2,
        "over both blocks the pool took {pool_total} sats where its fee is {fee_total} — \
         the miners' money moved to the pool somewhere between them"
    );

    eprintln!(
        "pool-neutral payout regtest — blocks {height_1}/{height_2} accepted by bitcoin-core\n  \
         block 1: T={t_1} pool={pool_pay_1} (fee {fee_only_1}, +{}), published={published_1:?}\n  \
         block 1: alice paid {} claim {} balance {bal_alice_1} | bob paid {} claim {} balance \
         {bal_bob_1} | charlie paid {} claim {withheld_claim} balance {bal_charlie_1}\n  \
         block 2: T={t_2} pool={pool_pay_2} (fee {fee_only_2}, +{})\n  \
         block 2: alice paid {} balance {bal_alice_2} | bob paid {} balance {bal_bob_2} | \
         charlie paid {} balance {bal_charlie_2}",
        pool_pay_1 - fee_only_1,
        paid_1(&addr_alice),
        claim_1(&addr_alice),
        paid_1(&addr_bob),
        claim_1(&addr_bob),
        paid_1(&addr_charlie),
        pool_pay_2 - fee_only_2,
        paid_2(&addr_alice),
        paid_2(&addr_bob),
        paid_2(&addr_charlie),
    );

    // ── Teardown ─────────────────────────────────────────────────
    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    delete_payout_history(&pg, &[height_1, height_2]).await;
    delete_balances(&pg, &miners).await;
}

/// Satoshi slack allowed on the "everything settles" assertions. Every §4
/// amount, every claim and every balance boost is an integer floor, so a
/// handful of satoshis land in the pool output instead of a miner's
/// balance. Anything beyond that is a real leak, not rounding.
const ROUNDING_SLACK_SATS: i64 = 4;

fn test_engine_config(fee_addr: &str, coinbase_weight_budget: u32) -> PplnsEngineConfig {
    PplnsEngineConfig {
        // Neither background task may fire inside the test window: a dust
        // sweep would rewrite the very balances under assertion.
        dust_sweep_enabled: false,
        touch_flush_interval_secs: 3_600,
        fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr valid")),
        fee_percent: 1.5,
        min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
        coinbase_weight_budget,
        ..PplnsEngineConfig::default()
    }
}

/// The distribution's entry for `address`. Panics with the address in the
/// message — a missing entry means the build dropped a miner entirely,
/// which no assertion below could describe sensibly.
fn entry_for<'a>(distribution: &'a WeightDistribution, address: &str) -> &'a WeightEntry {
    distribution
        .entries
        .iter()
        .find(|e| e.address.as_str() == address)
        .unwrap_or_else(|| panic!("{address} must be an entry of the distribution"))
}

/// The §4 payout vector at `reward`, lowered into the coinbase builder's
/// input type.
fn payout_entries(distribution: &WeightDistribution, reward: u64) -> Vec<PayoutEntry> {
    distribution
        .payout_entries_at(reward)
        .expect("§4 payout vector")
        .iter()
        .map(|(address, sats)| PayoutEntry {
            address: address.as_str().to_string(),
            sats: *sats,
        })
        .collect()
}

/// Current `balanceSats` per address, `0` for an address with no row.
async fn read_balances<const N: usize>(pool: &PgPool, addresses: &[&str; N]) -> [i64; N] {
    let mut out = [0i64; N];
    for (slot, address) in out.iter_mut().zip(addresses) {
        let row: Option<(i64,)> =
            sqlx::query_as(r#"SELECT "balanceSats" FROM pplns_balance WHERE address = $1"#)
                .bind(address)
                .fetch_optional(pool)
                .await
                .expect("read pplns_balance");
        *slot = row.map(|r| r.0).unwrap_or(0);
    }
    out
}

async fn delete_balances(pool: &PgPool, addresses: &[String]) {
    for address in addresses {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(address)
            .execute(pool)
            .await;
    }
}

async fn delete_payout_history(pool: &PgPool, heights: &[i32]) {
    for height in heights {
        let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(height)
            .execute(pool)
            .await;
    }
}

/// Build the coinbase from `payouts`, grind a regtest-target nonce, submit
/// via the TDP and wait for the tip to rise. Returns the new height and the
/// exact witness-form coinbase bytes bitcoin-core accepted.
///
/// The tip assertion is not decoration: a coinbase whose outputs don't sum
/// to the template value, or that carries a dust output, is rejected with
/// no error the pool ever sees — the tip simply doesn't move.
async fn mine_and_submit(
    node: &RegtestNode,
    tdp: &TdpHandle,
    template: &NewTemplate,
    prev_hash: &SetNewPrevHash,
    payouts: &[PayoutEntry],
    pool_identifier: &str,
) -> (u32, Vec<u8>) {
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
        payouts,
        &coinbase_template,
        pool_identifier,
        EXTRANONCE_SLOT_LEN,
        [0u8; 32],
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

    let witness_coinbase = job.witness_coinbase_with_extranonce(&en1, &en2);
    let before_height = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        witness_coinbase.clone(),
    )
    .await
    .expect("submit_solution");

    let after = poll_for_height(node, before_height + 1, Duration::from_secs(20))
        .await
        .expect(
            "bitcoin-core must accept the block — a stuck tip means the \
             engine-built distribution produced a coinbase the chain rejected",
        );
    assert_eq!(after, before_height + 1);
    (after, witness_coinbase)
}
