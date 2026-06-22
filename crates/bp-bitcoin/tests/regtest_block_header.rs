// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: `BitcoinRpc::get_block_header` against a real `bitcoin-node`.
//!
//! This is the bitcoin-core-touching half of the confirmation-gated
//! block-found feature (the watcher in `bin/blitzpool` keys its
//! apply/discard decision entirely on `BlockHeaderInfo.confirmations`):
//!
//! - a buried block reports `confirmations >= depth`,
//! - an `invalidateblock`'d block reports `confirmations == -1` (the
//!   orphan signal the watcher discards on),
//! - an unknown hash surfaces Core's `-5` "Block not found".
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed.

use std::time::Duration;

use bp_bitcoin::{BitcoinRpc, BitcoinRpcConfig, RpcAuth, RpcError};
use bp_regtest_harness::{RegtestConfig, RegtestNode};

/// Build a `BitcoinRpc` pointed at the regtest node, authenticating with
/// the node's `.cookie` (`__cookie__:<secret>`).
fn rpc_for(node: &RegtestNode) -> BitcoinRpc {
    let cookie = std::fs::read_to_string(node.cookie_path()).expect("read regtest cookie");
    let (user, password) = cookie.split_once(':').expect("cookie is user:password");
    BitcoinRpc::new(BitcoinRpcConfig {
        url: node.rpc_url(),
        auth: RpcAuth::UserPassword {
            user: user.to_string(),
            password: password.to_string(),
        },
        timeout: Some(Duration::from_secs(10)),
    })
    .expect("construct BitcoinRpc")
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)]
async fn get_block_header_reports_confirmations_orphan_and_not_found() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping get_block_header regtest — bitcoin-node not found at {} (set \
             BITCOIN_NODE_PATH to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    let tip = node.generate_to_self(6).await.expect("mine 6 blocks");
    let rpc = rpc_for(&node);

    // ── Buried block: confirmations >= depth ──────────────────────────
    let buried_hash: String = serde_json::from_value(
        node.rpc_call("getblockhash", serde_json::json!([tip - 3]))
            .await
            .expect("getblockhash"),
    )
    .expect("hash is a string");
    let buried = rpc
        .get_block_header(&buried_hash)
        .await
        .expect("getblockheader on buried block");
    assert!(
        buried.confirmations >= 3,
        "block at tip-3 should have >= 3 confirmations, got {}",
        buried.confirmations
    );
    assert_eq!(buried.height, Some(u64::from(tip - 3)));

    // ── Unknown hash → Core error -5 (Block not found) ────────────────
    let bogus = "00".repeat(32);
    match rpc.get_block_header(&bogus).await {
        Err(RpcError::BitcoinCore(d)) => assert_eq!(
            d.code, -5,
            "unknown hash should be -5 Block not found, got {} ({})",
            d.code, d.message
        ),
        other => panic!("expected a -5 BitcoinCore error for an unknown hash, got {other:?}"),
    }

    // ── Orphan: invalidate the tip → its header reports confirmations -1 ─
    let tip_hash: String = serde_json::from_value(
        node.rpc_call("getblockhash", serde_json::json!([tip]))
            .await
            .expect("getblockhash tip"),
    )
    .expect("tip hash is a string");
    // `invalidateblock` returns `null`; the harness RPC caller rejects a
    // null result, but the side effect (marking the block invalid) still
    // takes effect on the node. Ignore the client-side parse quirk — the
    // `confirmations == -1` assertion below is the real check.
    let _ = node
        .rpc_call("invalidateblock", serde_json::json!([tip_hash]))
        .await;
    let orphaned = rpc
        .get_block_header(&tip_hash)
        .await
        .expect("getblockheader on invalidated block");
    assert_eq!(
        orphaned.confirmations, -1,
        "an invalidated (off-active-chain) block must report confirmations = -1, got {}",
        orphaned.confirmations
    );

    node.shutdown().await.expect("regtest clean shutdown");
}
