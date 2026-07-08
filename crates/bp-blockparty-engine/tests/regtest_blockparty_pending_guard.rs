// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! E2E: pending-party fee-route guard.
//!
//! When an admin's party is still DRAFT / CONFIRMING (members haven't
//! confirmed their splits), the production resolver routes the admin's
//! coinbase to the pool-fee address — NOT to the admin — so the admin
//! cannot pocket a full block reward before members sign off.
//!
//! This regtest exercises the full guard end-to-end: build the
//! fee-route coinbase, mine a block at the regtest target, submit, and
//! assert bitcoin-core accepts it. Then promote the party to READY by
//! confirming the member and verify the guard turns off.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_blockparty_engine::{BlockpartyHooks, BlockpartyService, BlockpartyServiceConfig};
use bp_common::{AddressId, Sats};
use bp_group_mgmt_engine::AddressCache as PplnsAddressCache;
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, deterministic_p2wpkh_regtest, poll_for_height,
    wait_for_paired_template,
};
use sqlx::PgPool;

struct AllVerified;

#[async_trait]
impl BlockpartyHooks for AllVerified {
    async fn verified_email_for(&self, address: &AddressId) -> Option<String> {
        Some(format!("{}@regtest.example", address.as_str()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_party_admin_routes_block_to_pool_fee_accepted_by_core() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping pending-guard regtest — bitcoin-node not found at {}",
            regtest_cfg.bitcoin_node_path.display()
        );
        return;
    }
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    let addr_admin = deterministic_p2wpkh_regtest([0xc1; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0xc2; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0xcf; 32]);
    let name = format!("bp-regtest-pending-{}", uuid::Uuid::new_v4());
    cleanup_member_rows(&pg, &[&addr_admin, &addr_bob]).await;

    let fee_addr_id = AddressId::new(addr_fee.clone()).expect("fee addr");
    let svc = Arc::new(BlockpartyService::new(
        pg.clone(),
        Arc::new(AllVerified),
        PplnsAddressCache::new(),
        BlockpartyServiceConfig {
            fee_address: Some(fee_addr_id.clone()),
            fee_percent: 2.0,
            min_payout_sats: Sats(5_000),
        },
    ));

    // Create + add member but DON'T confirm Bob. Status: CONFIRMING.
    let create = svc
        .create_group(&name, &addr_admin, 6_000)
        .await
        .expect("create_group");
    svc.add_member(create.group.id, &addr_bob, 4_000, Some(&create.admin_token))
        .await
        .expect("add_member");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "confirming");

    // Guards: pending-fee-route active, normal routing dormant.
    let admin_id = AddressId::new(addr_admin.clone()).unwrap();
    let route = svc
        .pending_party_fee_route(&admin_id)
        .await
        .expect("pending-fee-route must be Some for CONFIRMING admin");
    assert_eq!(route.fee_address, fee_addr_id);
    assert_eq!(route.percent, 100);
    assert!(svc.routable_group_id_for_admin(&admin_id).await.is_none());

    // ── Boot bitcoin-core, attach TDP, build block with the
    //    fee-route coinbase, submit, verify core acceptance ──
    let node = RegtestNode::start_with(regtest_cfg)
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit");
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
    node.generate_to_self(1).await.expect("force NewTemplate");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    let payouts = vec![PayoutEntry {
        address: route.fee_address.into_inner(),
        sats: 5_000_000_000,
    }];
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
        "blockparty-pending-guard",
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job");

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
    .expect("regtest nonce within 1M tries");
    let witness_coinbase = job.witness_coinbase_with_extranonce(&en1, &en2);
    let before = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        witness_coinbase,
    )
    .await
    .expect("submit_solution");
    let after = poll_for_height(&node, before + 1, Duration::from_secs(20))
        .await
        .expect("bitcoin-core must accept the fee-route block");
    assert_eq!(after, before + 1);

    // ── Promote to READY by confirming Bob, verify guard turns off ──
    svc.mark_member_confirmed(create.group.id, &AddressId::new(addr_bob.clone()).unwrap())
        .await
        .expect("mark_member_confirmed");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "ready");
    assert!(
        svc.pending_party_fee_route(&admin_id).await.is_none(),
        "READY must turn off the pending-fee guard"
    );
    assert_eq!(
        svc.routable_group_id_for_admin(&admin_id).await,
        Some(create.group.id),
        "READY must enable the standard routing path"
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    cleanup_group(&pg, &name).await;
}

// ─── Helpers ──────────────────────────────────────────────────────

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
