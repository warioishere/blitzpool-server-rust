// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! E2E: Blockparty lifecycle from `create_group` through block-found
//! history-row idempotency, against a live bitcoin-core 31 regtest.
//!
//! Validates: routing-cache state transitions, coinbase shape from
//! `build_payouts`, bitcoin-core consensus acceptance, and the
//! `ON CONFLICT DO NOTHING` replay-safety on the history row.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_blockparty_engine::{BlockpartyHooks, BlockpartyService, BlockpartyServiceConfig};
use bp_common::{AddressId, Sats};
use bp_group_mgmt_engine::AddressCache as PplnsAddressCache;
use bp_mining_job::{
    build_block_header, build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry,
    TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, deterministic_p2wpkh_regtest, poll_for_height,
    wait_for_paired_template,
};
use sqlx::PgPool;

/// Hook that returns a canned email for every address — the verified-
/// email check is a cross-cut, not part of what this test exercises.
struct AllVerified;

#[async_trait]
impl BlockpartyHooks for AllVerified {
    async fn verified_email_for(&self, address: &AddressId) -> Option<String> {
        Some(format!("{}@regtest.example", address.as_str()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blockparty_two_member_block_accepted_by_core_and_history_idempotent() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping blockparty lifecycle regtest — bitcoin-node not found at {}",
            regtest_cfg.bitcoin_node_path.display()
        );
        return;
    }
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // ── Deterministic regtest addresses ──────────────────────────
    let addr_admin = deterministic_p2wpkh_regtest([0xa1; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0xb2; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0xfe; 32]);
    let name = format!("bp-regtest-lifecycle-{}", uuid::Uuid::new_v4());
    cleanup_member_rows(&pg, &[&addr_admin, &addr_bob]).await;

    // ── Construct service ────────────────────────────────────────
    let svc = Arc::new(BlockpartyService::new(
        pg.clone(),
        Arc::new(AllVerified),
        PplnsAddressCache::new(),
        BlockpartyServiceConfig {
            fee_address: Some(AddressId::new(addr_fee.clone()).expect("fee addr")),
            fee_percent: 2.0,
            min_payout_sats: Sats(5_000),
        },
    ));

    // ── Lifecycle: create → addMember → confirm → READY ─────────
    let create = svc
        .create_group(&name, &addr_admin, "admin@regtest.example", 6_000)
        .await
        .expect("create_group");
    assert_eq!(create.group.status, "draft");
    let group_id = create.group.id;

    svc.add_member(group_id, &addr_bob, 4_000, Some(&create.admin_token))
        .await
        .expect("add_member");
    let g = svc.get_group(group_id).await.unwrap().unwrap();
    assert_eq!(g.status, "confirming");

    svc.mark_member_confirmed(group_id, &AddressId::new(addr_bob.clone()).unwrap())
        .await
        .expect("mark_member_confirmed");
    let g = svc.get_group(group_id).await.unwrap().unwrap();
    assert_eq!(g.status, "ready", "READY after all members confirmed");

    // Routing-cache invariant: READY enables routing, kills pending-fee guard.
    let admin_addr_id = AddressId::new(addr_admin.clone()).unwrap();
    assert_eq!(
        svc.routable_group_id_for_admin(&admin_addr_id).await,
        Some(group_id)
    );
    assert!(svc.pending_party_fee_route(&admin_addr_id).await.is_none());

    // ── Boot bitcoin-core, attach TDP ────────────────────────────
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

    // ── Build distribution from the live service ─────────────────
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = svc
        .build_payouts(group_id, Sats(reward_sats as i64))
        .await
        .expect("build_payouts")
        .expect("group exists");

    // Sat-conservation: outputs sum exactly to reward.
    let total: i64 = dist.payouts.iter().map(|p| p.sats.0).sum();
    assert_eq!(
        total as u64, reward_sats,
        "blockparty payouts must sum exactly to reward — burning sats per block is a bug"
    );
    // Shape: 1 fee output + 2 member outputs (60/40 split, both above min_payout).
    assert_eq!(dist.payouts.len(), 3, "fee + 2 member outputs expected");

    // ── Build the block + brute-force regtest-target nonce ───────
    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|p| PayoutEntry {
            address: p.address.as_str().to_string(),
            percent: p.percent,
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
        "blockparty-lifecycle-regtest",
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
    .expect("must find a regtest-target nonce within 1M tries");

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
    let new_height = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .expect(
            "bitcoin-core must accept the block — a stuck tip means the blockparty \
             coinbase was rejected (dust output, fee mismatch, bad address script)",
        );
    assert_eq!(new_height, before_height + 1);

    // ── on_block_found: write history + verify idempotency ───────
    //
    // Synthesize a block_hash from the assembled header (same shape
    // the production block_sink computes via sha256d).
    let header_bytes = build_block_header(
        template.version as i32,
        0,
        &prev_hash.prev_hash,
        &merkle_root,
        prev_hash.header_timestamp,
        prev_hash.n_bits,
        nonce,
    );
    let mut hash = bp_share::sha256d(&header_bytes);
    hash.reverse();
    let block_hash_hex = hex::encode(hash);

    let first = svc
        .on_block_found(
            group_id,
            new_height as i32,
            &block_hash_hex,
            Sats(reward_sats as i64),
            dist.pool_fee_sats,
            &dist.splits,
            None,
        )
        .await
        .expect("on_block_found first call");
    assert!(first.is_some(), "first call must insert history row");
    let replay = svc
        .on_block_found(
            group_id,
            new_height as i32,
            &block_hash_hex,
            Sats(reward_sats as i64),
            dist.pool_fee_sats,
            &dist.splits,
            None,
        )
        .await
        .expect("on_block_found replay");
    assert!(
        replay.is_none(),
        "replay on the same (group_id, block_hash) must be a no-op (ON CONFLICT DO NOTHING)"
    );
    let history = svc.get_history(group_id).await.expect("get_history");
    assert_eq!(history.len(), 1, "exactly one history row after replay");

    // ── Teardown ─────────────────────────────────────────────────
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_group(&pg, &name).await;
}

// ─── Helpers (mirrored from sibling regtests) ─────────────────────

async fn cleanup_group(pool: &PgPool, name: &str) {
    let _ = sqlx::query("DELETE FROM blockparty_group WHERE name = $1")
        .bind(name)
        .execute(pool)
        .await;
}

async fn cleanup_member_rows(pool: &PgPool, addrs: &[&str]) {
    for a in addrs {
        let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
            .bind(*a)
            .execute(pool)
            .await;
    }
}
