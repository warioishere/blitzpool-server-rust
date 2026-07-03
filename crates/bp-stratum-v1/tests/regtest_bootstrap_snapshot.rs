// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression test: SV1 translator must bootstrap from the
//! [`bp_template_distribution::TdpHandle::current_snapshot`] when its
//! broadcast subscription installed AFTER bitcoin-core's startup
//! `NewTemplate + SetNewPrevHash` pair was already emitted.
//!
//! `tokio::sync::broadcast` does not replay messages to subscribers
//! that attach after the corresponding `send` — so production's
//! `spawn_tdp() → … boot init … → tdp.subscribe()` sequence drops the
//! startup pair on the floor. The TdpHandle has an internal tap that
//! subscribes BEFORE the worker thread starts, capturing the pair
//! into [`TemplateSnapshot`]; the SV1 translator's `spawn` now takes
//! that snapshot and replays it through the assembler so
//! `current_template` is populated immediately — without waiting for
//! another on-chain block.
//!
//! This test simulates the production race: spawn TDP, sleep long
//! enough for the worker thread to deliver the bootstrap pair to
//! `bridge_out`, THEN subscribe + snapshot, THEN spawn the SV1
//! server. Assert that `current_template()` is `Some` shortly after
//! — proving the snapshot path kicked in (no on-chain block needed).
//!
//! Without the snapshot path the test fails: `current_template`
//! stays `None` (no further TDP traffic until a real block, and on
//! regtest with `min_interval = 1` second the mempool monitor only
//! emits `NewTemplate(future=false)`, which alone never produces a
//! pairing in the assembler).
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not
//! installed at the host's default location or via `BITCOIN_NODE_PATH`.

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
            "skipping SV1 bootstrap-snapshot regtest — bitcoin-node not found at {} \
             (set BITCOIN_NODE_PATH to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // ── Boot bitcoin-core + mine past IBD ─────────────────────────────
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Spawn TDP. The handle's internal snapshot tap subscribes
    //    BEFORE the worker thread starts; bitcoin-core's bootstrap
    //    NewTemplate + SetNewPrevHash pair will land in the snapshot
    //    once `tdp.run()` is awake. ───────────────────────────────────
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");

    // ── Simulate production timing: don't subscribe immediately.
    //    Sleep long enough for bitcoin-core's bootstrap pair to be
    //    emitted into the broadcast (where, with no live subscriber,
    //    it would be lost) AND into the snapshot tap (where it
    //    survives). 500 ms is generous on regtest. ──────────────────
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

    // ── NOW subscribe — by this point the broadcast has long since
    //    sent its bootstrap pair into the void. Without the snapshot
    //    replay in `StratumV1Server::spawn`, the assembler stays
    //    empty until a fresh on-chain block. ───────────────────────
    let updates_rx = tdp.subscribe();
    let server_config = ServerConfig::defaults_for(Network::Regtest);
    let server = StratumV1Server::spawn(
        server_config,
        updates_rx,
        snapshot,
        // No alt streams — this test asserts the default-stream snapshot replay.
        Vec::new(),
        ServerHooks::no_op(),
        SharedExtranonce::new(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // ── Assert: current_template populated WITHOUT mining another
    //    block. With the bootstrap replay the translator pre-applies
    //    the snapshot pair to its assembler on entry → current_template
    //    is `Some` within a few hundred ms. Without it, this assertion
    //    fails (would only become `Some` after another block). ─────
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
