// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! E2E: `GroupSoloEngine::build_distribution()` → multi-output coinbase
//! (incl. finder bonus) → `bitcoin-node` accepts the block.
//!
//! Companion to the PPLNS e2e in `bp-pplns-engine`. Verifies that the
//! group-solo distribution path — which has its own finder-bonus splice
//! on top of the share-weighted per-member split — produces a coinbase
//! whose outputs sum to the block reward and pass bitcoin-core's
//! consensus checks.
//!
//! Two failure modes this test would catch that the PG-only group-solo
//! integration tests cannot:
//!   - finder bonus subtraction off-by-one (bonus_sats not removed from
//!     the member pool before share-weighting → coinbase outputs sum to
//!     `reward + bonus`, `bad-cb-amount`)
//!   - finder address splice corrupted (e.g. wrong index, double-credit)
//!
//! Sequence: boot regtest, seed group row + three members in PG, seed
//! round shares in Redis, build distribution for the finder address,
//! feed payouts into MiningJob, submit, assert tip advances.

use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, Sats};
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_pplns::DEFAULT_MIN_PAYOUT_SATS;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, connect_redis_or_skip, deterministic_p2wpkh_regtest,
    poll_for_height, wait_for_paired_template,
};
use sqlx::PgPool;
use uuid::Uuid;

/// Distinct from the PPLNS e2e's `9` so the two can run in parallel.
const REDIS_TEST_DB: u8 = 10;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn group_solo_three_member_distribution_block_accepted_by_core() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping group-solo e2e regtest — bitcoin-node not found at {} \
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

    // ── Three deterministic regtest P2WPKH addresses + fee addr ──
    let addr_alice = deterministic_p2wpkh_regtest([0x11; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x22; 32]);
    let addr_charlie = deterministic_p2wpkh_regtest([0x33; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x99; 32]);

    // ── Seed group row + members in PG ──────────────────────────
    //
    // `pplns_group_member` has UNIQUE(address) — a prior failed run
    // could leave leftover rows that block re-seeding. Clean those
    // by address first (we own these deterministic addresses
    // per-test). `finder_bonus_sats` is non-trivial so the test
    // exercises the bonus-splice path (subtract bonus from pool
    // before share-weighting, credit back to the finder's output).
    cleanup_member_rows(&pg, &[&addr_alice, &addr_bob, &addr_charlie]).await;
    let group_id = Uuid::new_v4();
    let finder_bonus_sats: i64 = 1_000_000; // 0.01 BTC carve-out
    seed_group(&pg, group_id, &addr_alice, finder_bonus_sats).await;
    seed_member(&pg, group_id, &addr_alice).await;
    seed_member(&pg, group_id, &addr_bob).await;
    seed_member(&pg, group_id, &addr_charlie).await;

    // ── Spawn the engine + record per-member shares to Redis ─────
    let engine = GroupSoloEngine::spawn(
        test_engine_config(&addr_fee),
        redis_conn.clone(),
        pg.clone(),
    )
    .await
    .expect("GroupSoloEngine::spawn");

    let now_ms = chrono::Utc::now().timestamp_millis();
    engine
        .record_share(None, group_id, &addr_alice, 100.0, now_ms)
        .await
        .expect("seed share Alice");
    engine
        .record_share(None, group_id, &addr_bob, 200.0, now_ms)
        .await
        .expect("seed share Bob");
    engine
        .record_share(None, group_id, &addr_charlie, 300.0, now_ms)
        .await
        .expect("seed share Charlie");

    // ── Boot bitcoin-core + mine past IBD ────────────────────────
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

    // ── Pick a finder (Alice in this test). build_distribution uses
    //    the finder both for bonus crediting and for the cache key. ──
    let finder = AddressId::new(addr_alice.clone()).expect("finder addr valid");
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(group_id, reward_sats, &finder)
        .await
        .expect("build_distribution");
    // ── Exact-shape assertion ────────────────────────────────────
    //
    // For (group of 3 active members, fee_address set, finder bonus
    // > min_payout), the production distribution emits:
    //   1× fee output (fee_address)
    //   1× bonus output (finder address, sats == configured bonus)
    //   3× share outputs (one per kept active miner)
    //   → 5 total entries, with the finder appearing in TWO entries
    //     (the bonus output + its own share-weighted output).
    assert_eq!(
        dist.payouts.len(),
        5,
        "expected 5 payouts (fee + finder-bonus + 3 member shares) — got {}: {:?}",
        dist.payouts.len(),
        dist.payouts
            .iter()
            .map(|p| (p.address.as_str(), p.sats.0))
            .collect::<Vec<_>>(),
    );
    let finder_entries: Vec<&_> = dist
        .payouts
        .iter()
        .filter(|p| p.address.as_str() == addr_alice)
        .collect();
    assert_eq!(
        finder_entries.len(),
        2,
        "finder must appear in EXACTLY 2 outputs (bonus + share) — got {}",
        finder_entries.len()
    );
    let bonus_entry = finder_entries
        .iter()
        .find(|p| p.sats.0 == finder_bonus_sats)
        .copied()
        .unwrap_or_else(|| {
            panic!(
                "one of the finder outputs must equal the configured \
                 finder_bonus_sats ({finder_bonus_sats}); got {:?}",
                finder_entries.iter().map(|p| p.sats.0).collect::<Vec<_>>()
            )
        });
    assert_eq!(bonus_entry.sats.0, finder_bonus_sats);

    // Bit-exact: the distribution's sat sums must equal the reward.
    // Anything less means the engine silently burns satoshi every
    // block; anything more would be rejected by bitcoin-core as
    // `bad-cb-amount`.
    let total_payout_sats: i64 = dist.payouts.iter().map(|p| p.sats.0).sum();
    assert_eq!(
        total_payout_sats as u64, reward_sats,
        "distribution sat sum must EXACTLY equal reward — burning sats \
         per block is a production-code bug, not a test issue"
    );

    // ── Build the block + brute-force a regtest-target nonce ────
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
        "group-solo-e2e-regtest",
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
             group-solo distribution produced a coinbase the chain \
             rejected (finder-bonus math drift, dust output, ...)",
        );
    assert_eq!(after, before_height + 1);

    // ── Teardown ─────────────────────────────────────────────────
    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_group(&pg, group_id).await;
}

// ── Connection + seed helpers ───────────────────────────────────────

async fn seed_group(pool: &PgPool, group_id: Uuid, creator: &str, finder_bonus_sats: i64) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusSats")
           VALUES ($1, $2, $3, $4, true, 0, 0, false, $5)"#,
    )
    .bind(group_id)
    .bind(format!("e2e-grp-{group_id}"))
    .bind(creator)
    .bind(format!("hash-{group_id}"))
    .bind(finder_bonus_sats)
    .execute(pool)
    .await
    .expect("seed group row");
}

async fn seed_member(pool: &PgPool, group_id: Uuid, address: &str) {
    // `pplns_group_member`: integer `id` is a serial, `joinedAt` has a
    // default. Address is UNIQUE across the table (one membership per
    // address at a time), so the test uses fresh-per-test addresses.
    sqlx::query(
        r#"INSERT INTO pplns_group_member ("groupId", address, role)
           VALUES ($1, $2, 'member')"#,
    )
    .bind(group_id)
    .bind(address)
    .execute(pool)
    .await
    .expect("seed group member");
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    // ON DELETE CASCADE on member + balance + block_history FKs
    // means deleting the group cleans up the dependent rows.
    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(group_id)
        .execute(pool)
        .await;
}

async fn cleanup_member_rows(pool: &PgPool, addrs: &[&str]) {
    for a in addrs {
        let _ = sqlx::query("DELETE FROM pplns_group_member WHERE address = $1")
            .bind(*a)
            .execute(pool)
            .await;
    }
}

fn test_engine_config(fee_addr: &str) -> GroupSoloEngineConfig {
    GroupSoloEngineConfig {
        dust_sweep_enabled: false,
        // Match production: real Group-Solo deployments always run with
        // a fee address and a non-zero fee percent. With `None`/`0`,
        // the rounding residuum in `suppress_matching_debits` mode
        // accumulates into the would-be-fee bucket and is silently
        // dropped — that's an independent edge-case worth investigating
        // but it's not what this test should exercise.
        fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr valid")),
        fee_percent: 1.5,
        min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
        ..GroupSoloEngineConfig::default()
    }
}

// ── TDP + brute-force helpers (mirrored from sibling regtests) ──────
