// SPDX-License-Identifier: AGPL-3.0-or-later

//! `TdpHandle` against a real regtest `bitcoin-node`; skipped with a printed
//! warning when no `bitcoin-node` is found.

use std::time::Duration;

use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_template_distribution::{TdpConfig, TdpHandle, TemplateUpdate};
use tokio::sync::broadcast::error::RecvError;

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)]
async fn tdp_emits_new_template_after_block() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!("skipping TDP e2e — {}", cfg.unavailable_reason());
        return;
    }

    // IPC `createNewBlock` blocks during IBD; mining recent blocks first ends it.
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD-exit + coinbase maturity");

    // Low threshold and interval so an empty-mempool regtest still emits templates.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");

    let mut rx = tdp.subscribe();

    let new_tip = node
        .generate_to_self(1)
        .await
        .expect("mine 1 more to force new template");
    assert_eq!(new_tip, 102, "tip should advance to 102");

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

    // `/api/health` reads `last_update_at` for TDP staleness. Polled because the
    // snapshot tap is a separate subscriber and may lag this loop.
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

/// The worker reconnects on its own after bitcoind restarts on the same socket.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)]
async fn tdp_reconnects_after_bitcoind_restart() {
    let base = RegtestConfig::default();
    if !base.is_available() {
        eprintln!("skipping TDP reconnect e2e — {}", base.unavailable_reason());
        return;
    }

    // The test owns the datadir so node2 reuses node1's chain and IPC socket path.
    let datadir = std::env::temp_dir().join(format!("bp-tdp-reconnect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);

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

    node1.shutdown().await.expect("node1 shutdown");

    // Let the worker notice the dropped IPC and enter its reconnect loop.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Discard buffered pre-restart templates, so a NewTemplate below can only
    // come from the reconnected worker.
    assert!(
        drain_all_open(&mut rx),
        "TDP broadcast must stay OPEN across a bitcoind restart — \
         a closed channel means the worker died instead of reconnecting"
    );

    let node2 =
        RegtestNode::start_with(RegtestConfig::default().with_external_datadir(datadir.clone()))
            .await
            .expect("node2 start (same datadir)");
    node2
        .generate_to_self(1)
        .await
        .expect("mine 1 on node2 to force a post-reconnect template");

    // Covers reconnect backoff, node2's IBD exit and the template emit.
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

/// `true` once a `NewTemplate` arrives within `budget`.
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

/// Drains the buffer without blocking; `false` means the channel closed,
/// i.e. the worker thread is gone.
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
