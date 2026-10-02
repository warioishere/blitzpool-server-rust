// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! E2E regtest: what a Blockparty admin's coinbase pays before and after the
//! party is ready, with bitcoin-core validating each mined block so a coinbase
//! that only looks right cannot pass. Skipped when `bitcoin-node` or Postgres
//! is absent.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bp_blockparty_engine::{
    BlockpartyHooks, BlockpartyPayoutConfig, BlockpartyPayouts, BlockpartyService,
};
use bp_common::{AddressId, Sats};
use bp_group_mgmt_engine::AddressCache as PplnsAddressCache;
use bp_mining_job::PayoutEntry;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_template_distribution::{NewTemplate, SetNewPrevHash, TdpConfig, TdpHandle};
use bp_test_support::{
    cleanup_blockparty_rows, connect_pg_or_skip, deterministic_p2wpkh_regtest,
    mine_and_submit_payouts, wait_for_paired_template,
};
use sqlx::PgPool;

/// Every address has a verified email; the email gate is not under test.
struct AllVerified;

#[async_trait]
impl BlockpartyHooks for AllVerified {
    async fn verified_email_for(&self, address: &AddressId) -> Option<String> {
        Some(format!("{}@regtest.example", address.as_str()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blockparty_ready_party_pays_members_and_history_is_idempotent() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping blockparty lifecycle regtest — {}",
            regtest_cfg.unavailable_reason()
        );
        return;
    }
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // Distinct from the pending-guard test's: both run in parallel against
    // one Postgres, so each cleans only its own rows.
    let addr_admin = deterministic_p2wpkh_regtest([0xa1; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0xb2; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0xfe; 32]);
    let name = format!("bp-regtest-lifecycle-{}", uuid::Uuid::new_v4());
    cleanup_blockparty_rows(&pg, &[&addr_admin, &addr_bob]).await;

    let svc = service(&pg, &addr_fee).await;

    // ── Lifecycle: create → add_member → confirm → READY ────────
    let create = svc
        .create_group(&name, &addr_admin, 6_000)
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
    let (node, tdp, template, prev_hash) = boot_node_and_template(regtest_cfg).await;

    // ── Build distribution from the live service ─────────────────
    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = svc
        .payouts()
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

    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|p| PayoutEntry {
            address: p.address.as_str().to_string(),
            sats: p.sats.0 as u64,
        })
        .collect();
    let mined = mine_and_submit_payouts(
        &node,
        &tdp,
        &template,
        &prev_hash,
        &payouts,
        "blockparty-lifecycle-regtest",
        [0u8; 32],
    )
    .await;

    // ── on_block_found: write history + verify idempotency ───────
    let first = svc
        .payouts()
        .on_block_found(
            group_id,
            mined.height as i32,
            &mined.block_hash_hex,
            Sats(reward_sats as i64),
            dist.pool_fee_sats,
            &dist.splits,
            None,
        )
        .await
        .expect("on_block_found first call");
    assert!(first.is_some(), "first call must insert history row");
    let replay = svc
        .payouts()
        .on_block_found(
            group_id,
            mined.height as i32,
            &mined.block_hash_hex,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_party_admin_routes_block_to_pool_fee_accepted_by_core() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping pending-guard regtest — {}",
            regtest_cfg.unavailable_reason()
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
    cleanup_blockparty_rows(&pg, &[&addr_admin, &addr_bob]).await;

    let fee_addr_id = AddressId::new(addr_fee.clone()).expect("fee addr");
    let svc = service(&pg, &addr_fee).await;

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
    assert!(svc.routable_group_id_for_admin(&admin_id).await.is_none());

    // ── Mine the fee-route coinbase and make core validate it ────
    let (node, tdp, template, prev_hash) = boot_node_and_template(regtest_cfg).await;
    let payouts = vec![PayoutEntry {
        address: route.fee_address.into_inner(),
        // The template's own value, not a hardcoded subsidy, or core rejects
        // it as `bad-cb-amount`.
        sats: template.coinbase_tx_value_remaining,
    }];
    let _ = mine_and_submit_payouts(
        &node,
        &tdp,
        &template,
        &prev_hash,
        &payouts,
        "blockparty-pending-guard",
        [0u8; 32],
    )
    .await;

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

// ─── Shared driver ────────────────────────────────────────────────

async fn service(pg: &PgPool, fee_address: &str) -> Arc<BlockpartyService> {
    Arc::new(
        BlockpartyService::load(
            BlockpartyPayouts::new(
                pg.clone(),
                BlockpartyPayoutConfig {
                    fee_address: Some(AddressId::new(fee_address.to_string()).expect("fee addr")),
                    fee_percent: 2.0,
                    min_payout_sats: Sats(5_000),
                },
            ),
            Arc::new(AllVerified),
            PplnsAddressCache::new(),
        )
        .await
        .expect("load blockparty service"),
    )
}

/// Boot a regtest node past IBD + maturity, attach a `TdpHandle`, drain the
/// startup pair and force one fresh `NewTemplate` + `SetNewPrevHash`.
async fn boot_node_and_template(
    cfg: RegtestConfig,
) -> (RegtestNode, TdpHandle, NewTemplate, SetNewPrevHash) {
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
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
    (node, tdp, template, prev_hash)
}

async fn cleanup_group(pool: &PgPool, name: &str) {
    let _ = sqlx::query("DELETE FROM blockparty_group WHERE name = $1")
        .bind(name)
        .execute(pool)
        .await;
}
