// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: a server that subscribes after bitcoin-core's startup template
//! pair was broadcast still gets a current template, by replaying
//! `TdpHandle::current_snapshot`. The broadcast does not replay to late
//! subscribers, and production subscribes late.

use std::time::Duration;

use bitcoin::Network;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server};
use bp_template_distribution::{TdpConfig, TdpHandle};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_translator_bootstraps_current_template_from_late_snapshot() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV1 bootstrap-snapshot regtest — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    // ── Boot bitcoin-core + mine past IBD ─────────────────────────────
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Spawn TDP; its snapshot tap subscribes before the worker starts ──
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");

    // ── Production timing: let the bootstrap pair go out unheard ─────
    tokio::time::sleep(Duration::from_millis(500)).await;
    let snapshot = tdp.current_snapshot();
    assert!(
        snapshot.new_template.is_some(),
        "TdpHandle's internal tap must have captured the bootstrap \
         NewTemplate within 500ms of spawn"
    );
    assert!(
        snapshot.set_new_prev_hash.is_some(),
        "TdpHandle's internal tap must have captured the bootstrap \
         SetNewPrevHash within 500ms of spawn"
    );
    let snapshot_template_id = snapshot
        .new_template
        .as_ref()
        .expect("just asserted")
        .template_id;
    let snapshot_prev_hash_template_id = snapshot
        .set_new_prev_hash
        .as_ref()
        .expect("just asserted")
        .template_id;
    assert_eq!(
        snapshot_template_id, snapshot_prev_hash_template_id,
        "snapshot pair must be from the same template (sanity)"
    );

    // ── Subscribe late ───────────────────────────────────────────────
    let updates_rx = tdp.subscribe();
    let server_config = ServerConfig::defaults_for(Network::Regtest);
    let server = StratumV1Server::spawn(
        server_config,
        updates_rx,
        snapshot,
        Vec::new(),
        ServerHooks::no_op(),
        SharedExtranonce::new(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // ── A template must appear without mining another block ──────────
    let mut current = None;
    for _ in 0..40 {
        if let Some(t) = server.current_template() {
            current = Some(t);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let active = current.expect(
        "current_template must be populated from the TDP snapshot replay \
         (subscribe happened too late to catch the bootstrap broadcast). \
         A None here indicates StratumV1Server::spawn is no longer applying \
         the initial_snapshot to its assembler.",
    );
    assert_eq!(
        active.template_id, snapshot_template_id,
        "active template_id must match the snapshot we passed in"
    );

    server.shutdown().await;
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}
