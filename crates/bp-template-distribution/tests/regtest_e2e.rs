// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test: spawn a regtest `bitcoin-node`, plug `TdpHandle`
//! against its IPC socket, mine blocks and verify we observe at least one
//! `NewTemplate` + `SetNewPrevHash` update on the outbound broadcast.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed
//! at the host's default location or via `BITCOIN_NODE_PATH`.

use std::time::Duration;

use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_template_distribution::{TdpConfig, TdpHandle, TemplateUpdate};
use tokio::sync::broadcast::error::RecvError;

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)]
async fn tdp_emits_new_template_after_block() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping TDP e2e — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // Start regtest and mine 101 blocks BEFORE attaching the TDP. Bitcoin
    // Core v31 makes IPC `createNewBlock` block while IBD is active; mining
    // a chain of recent-timestamp blocks first kicks IBD off.
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD-exit + coinbase maturity");

    // Now attach TDP. Use a very low fee threshold and short interval so
    // mempool-empty regtest still produces frequent templates.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");

    let mut rx = tdp.subscribe();

    // Trigger a NewPrevHash by mining another block. This forces the
    // upstream to emit a fresh NewTemplate followed by SetNewPrevHash.
    let new_tip = node
        .generate_to_self(1)
        .await
        .expect("mine 1 more to force new template");
    assert_eq!(new_tip, 102, "tip should advance to 102");

    // Drain updates until we see both NewTemplate and SetNewPrevHash, or
    // hit a 20 s budget.
    let mut saw_new_template = false;
    let mut saw_set_new_prev_hash = false;
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match rx.recv().await {
                Ok(TemplateUpdate::NewTemplate(t)) => {
                    assert!(t.version != 0, "template version must be set");
                    assert!(
                        !t.coinbase_prefix.is_empty(),
                        "coinbase_prefix must be non-empty"
                    );
                    saw_new_template = true;
                }
                Ok(TemplateUpdate::SetNewPrevHash(p)) => {
                    assert_ne!(p.prev_hash, [0u8; 32], "prev_hash must be set");
                    saw_set_new_prev_hash = true;
                }
                Ok(_) => continue,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => {
                    panic!("TDP broadcast closed before observing both updates");
                }
            }
            if saw_new_template && saw_set_new_prev_hash {
                return;
            }
        }
    })
    .await;

    assert!(saw_new_template, "expected at least one NewTemplate update");
    assert!(
        saw_set_new_prev_hash,
        "expected at least one SetNewPrevHash update after mining"
    );

    // The snapshot tap (a separate broadcast subscriber) must have stamped
    // `last_update_at` once it absorbed the same template/prev-hash pair.
    // This is what `/api/health` reads for TDP staleness — verify it gets
    // populated against real bitcoin-core, not just by the unit test of the
    // staleness decision. Poll briefly: the tap is a distinct subscriber so
    // it may lag our drain loop by a scheduler tick.
    let stamped = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tdp.current_snapshot().last_update_at.is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        stamped,
        "snapshot tap must stamp last_update_at after a real template arrives"
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

/// Reconnect path: kill the bitcoin-node mid-run (simulating a `bitcoind`
/// restart for a version upgrade), restart it at the SAME datadir (= same
/// IPC socket), and assert the `TdpHandle` worker reconnects on its own
/// and resumes emitting templates — without a pool restart.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)]
async fn tdp_reconnects_after_bitcoind_restart() {
    let base = RegtestConfig::default();
    if !base.is_available() {
        eprintln!(
            "skipping TDP reconnect e2e — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            base.bitcoin_node_path.display()
        );
        return;
    }

    // The TEST owns the datadir so it survives node1's shutdown and node2
    // reuses it (same chain, same IPC socket path). Manual cleanup at the
    // end — no tempfile dev-dep needed.
    let datadir = std::env::temp_dir().join(format!("bp-tdp-reconnect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir); // clean any stale leftover

    // ── Phase 1: node1 up, TDP attached, template flowing ─────────────
    let node1 =
        RegtestNode::start_with(RegtestConfig::default().with_external_datadir(datadir.clone()))
            .await
            .expect("node1 start");
    node1
        .generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    let socket = node1.ipc_socket_path();
    let tdp = TdpHandle::spawn(
        TdpConfig::new(&socket)
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            // Short backoff so the test doesn't wait long for the retry.
            .with_reconnect_backoff(Duration::from_millis(500)),
    )
    .expect("TdpHandle::spawn against node1 IPC");
    let mut rx = tdp.subscribe();

    node1
        .generate_to_self(1)
        .await
        .expect("mine 1 to force a pre-restart template");
    assert!(
        drain_until_new_template(&mut rx, Duration::from_secs(20)).await,
        "expected a NewTemplate before the restart"
    );

    // ── Phase 2: kill node1; datadir (caller-owned) survives ──────────
    node1.shutdown().await.expect("node1 shutdown");

    // Let the worker notice the dropped IPC and enter its reconnect loop
    // (it will fail to connect while the node is down and back off).
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Drain every PRE-restart template still buffered in the broadcast
    // channel AND assert the channel is still open. After this, any
    // NewTemplate seen below can only have come from the reconnected
    // worker — otherwise the test would false-positive on a stale buffered
    // template. A `Closed` here means the worker thread died (no reconnect).
    assert!(
        drain_all_open(&mut rx),
        "TDP broadcast must stay OPEN across a bitcoind restart — \
         a closed channel means the worker died instead of reconnecting"
    );

    // ── Phase 3: node2 at the SAME datadir/socket; TDP must reconnect ──
    let node2 =
        RegtestNode::start_with(RegtestConfig::default().with_external_datadir(datadir.clone()))
            .await
            .expect("node2 start (same datadir)");
    node2
        .generate_to_self(1)
        .await
        .expect("mine 1 on node2 to force a post-reconnect template");

    // Generous budget: reconnect backoff + node2 IBD-exit + template emit.
    let reconnected = drain_until_new_template(&mut rx, Duration::from_secs(40)).await;

    // Clean up before asserting so a failed assert still tears down.
    tdp.shutdown().ok();
    node2.shutdown().await.ok();
    let _ = std::fs::remove_dir_all(&datadir);

    assert!(
        reconnected,
        "TDP worker must reconnect to the restarted bitcoin-node and emit a fresh \
         NewTemplate — without a pool restart"
    );
}

/// Drain the broadcast until a `NewTemplate` arrives or `budget` elapses.
/// Returns `true` if a `NewTemplate` was seen.
async fn drain_until_new_template(
    rx: &mut tokio::sync::broadcast::Receiver<TemplateUpdate>,
    budget: Duration,
) -> bool {
    tokio::time::timeout(budget, async {
        loop {
            match rx.recv().await {
                Ok(TemplateUpdate::NewTemplate(_)) => return true,
                Ok(_) | Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Drain every currently-buffered message without blocking. Returns
/// `true` if the channel is still open (Empty/Lagged after draining),
/// `false` if it's Closed (worker thread gone). Used to discard
/// pre-restart templates so a later `recv` can only observe
/// post-reconnect ones.
fn drain_all_open(rx: &mut tokio::sync::broadcast::Receiver<TemplateUpdate>) -> bool {
    use tokio::sync::broadcast::error::TryRecvError;
    loop {
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Lagged(_)) => continue,
            Err(TryRecvError::Empty) => return true,
            Err(TryRecvError::Closed) => return false,
        }
    }
}
