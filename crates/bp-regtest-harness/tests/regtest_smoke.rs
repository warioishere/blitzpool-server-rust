// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end smoke test for the regtest harness itself. Skipped (with a
//! warning printed) when bitcoin-node is not installed on the host.

use std::time::Duration;

use bp_regtest_harness::{RegtestConfig, RegtestNode, MIN_BITCOIN_NODE_MAJOR};

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)] // skip-message is the whole point of the print
async fn spawn_mine_shutdown() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!("skipping regtest smoke test — {}", cfg.unavailable_reason());
        return;
    }

    let node = RegtestNode::start_with(cfg)
        .await
        .expect("regtest node should start");

    assert!(
        node.cookie_path().exists(),
        "cookie file should exist after startup"
    );
    assert!(
        node.ipc_socket_path().exists(),
        "IPC socket should exist after startup"
    );

    let rpc = node.bitcoin_rpc().expect("BitcoinRpc construction");
    let info = rpc
        .get_network_info()
        .await
        .expect("getnetworkinfo should succeed");
    // The running node must match what the `-version` gate vouched for.
    let min_version = u64::from(MIN_BITCOIN_NODE_MAJOR) * 10_000;
    assert!(
        info.version >= min_version,
        "harness reported this node available but it is {}, below v{MIN_BITCOIN_NODE_MAJOR}",
        info.version
    );

    let height = node
        .generate_to_self(5)
        .await
        .expect("generatetoaddress should succeed");
    assert!(height >= 5, "tip height should be at least 5, got {height}");

    // wait_for_height returns immediately when tip already meets target.
    node.wait_for_height(height, Duration::from_secs(2))
        .await
        .expect("wait_for_height ok when already at target");

    node.shutdown().await.expect("clean shutdown");
}
