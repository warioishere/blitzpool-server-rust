// SPDX-License-Identifier: AGPL-3.0-or-later

//! BIP-54 (Consensus Cleanup) compliance for blocks the Rust pool mines
//! through the SV2 TDP path against a real `bitcoin-node v31`.
//!
//! Rust analogue of sv2-apps PR #453 (`integration-tests/tests/bip54_compliance.rs`).
//! BIP-54 requires that the coinbase transaction of every block:
//!   * have its `nLockTime` set to `block_height - 1`,
//!   * have its sole input's `nSequence` set to a non-final value (not `0xffffffff`), and
//!   * have a witness-stripped serialized size that is not exactly 64 bytes.
//!
//! The Rust pool sources its coinbase fields from Core's `NewTemplate` over
//! IPC. This test proves the full chain is BIP-54-compliant:
//!   1. Core 31's template provider emits `coinbase_tx_locktime = height-1`
//!      and a non-final `coinbase_tx_input_sequence`,
//!   2. the pool's [`build_mining_job_from_tdp`] preserves both fields in the
//!      coinbase bytes it constructs, and
//!   3. bitcoin-core accepts the resulting block.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed at
//! the host's default location or via `BITCOIN_NODE_PATH`.
//!
//! See <https://github.com/bitcoin/bips/blob/master/bip-0054.md>.

use std::time::Duration;

use bitcoin::consensus::Decodable;
use bitcoin::Network;
use bp_mining_job::{
    build_mining_job_from_tdp, check_coinbase_bip54, decode_bip34_height,
    merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{brute_force_nonce, poll_for_height, wait_for_paired_template};

const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn coinbase_from_core31_template_is_bip54_compliant_and_accepted() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping BIP-54 regtest — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // ── Boot bitcoin-core + mine past IBD ─────────────────────────────
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Attach TDP, drain startup pair, mine 1 for a fresh template ────
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
    node.generate_to_self(1)
        .await
        .expect("mine 1 more to trigger fresh NewTemplate");

    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // The block we are about to mine sits on top of the current tip; its
    // height is encoded in the coinbase scriptsig prefix (BIP-34).
    let block_height =
        decode_bip34_height(&template.coinbase_prefix).expect("template carries a BIP-34 height");

    // ── (1) Core 31's template fields are BIP-54-compliant ────────────
    assert_eq!(
        template.coinbase_tx_locktime,
        block_height - 1,
        "Core's NewTemplate must set coinbase_tx_locktime = height-1"
    );
    assert_ne!(
        template.coinbase_tx_input_sequence, 0xffff_ffff,
        "Core's NewTemplate must set a non-final coinbase_tx_input_sequence"
    );

    // ── Build the coinbase the pool way (passthrough of Core's fields) ─
    let payouts = vec![PayoutEntry {
        address: MINER_ADDR.to_string(),
        percent: 100.0,
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
        "bip54",
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job_from_tdp must succeed");

    // ── (2) The pool-built coinbase preserves the BIP-54 invariants ───
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let mut non_witness = Vec::new();
    non_witness.extend_from_slice(job.coinbase_prefix());
    non_witness.extend_from_slice(&en1);
    non_witness.extend_from_slice(&en2);
    non_witness.extend_from_slice(job.coinbase_suffix());

    // Library-level BIP-54 validation over the exact non-witness bytes.
    check_coinbase_bip54(&non_witness, block_height)
        .expect("pool-built coinbase must satisfy BIP-54");

    // Plus explicit parsed-field assertions (the PR #453 checks).
    let tx = bitcoin::Transaction::consensus_decode(&mut non_witness.as_slice())
        .expect("coinbase must round-trip through rust-bitcoin");
    assert!(tx.is_coinbase(), "first tx must be a coinbase");
    assert_eq!(
        tx.lock_time.to_consensus_u32(),
        block_height - 1,
        "coinbase nLockTime must equal block_height - 1"
    );
    assert_ne!(
        tx.input[0].sequence.0, 0xffff_ffff,
        "coinbase nSequence must not be 0xffffffff"
    );
    assert_ne!(
        non_witness.len(),
        64,
        "coinbase witness-stripped size must not be exactly 64 bytes"
    );

    // ── (3) bitcoin-core accepts the block ────────────────────────────
    let coinbase_hash = job.coinbase_txid_with_extranonce(&en1, &en2);
    let merkle_root = merkle_root_from_coinbase(&coinbase_hash, &template.merkle_path);
    let target = Target::from_le_bytes(prev_hash.target);
    let nonce = brute_force_nonce(
        template.version,
        &prev_hash.prev_hash,
        &merkle_root,
        prev_hash.header_timestamp,
        prev_hash.n_bits,
        &target,
    )
    .expect("must find a valid nonce within 1M tries on regtest");

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

    let after_height = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .expect("bitcoin-core must accept the BIP-54-compliant block");
    assert_eq!(
        after_height,
        before_height + 1,
        "chain must advance by exactly one block (got {after_height}, expected {})",
        before_height + 1
    );
    // We submitted exactly `non_witness` (witness-wrapped); acceptance at
    // height `block_height` proves those coinbase bytes — and thus the
    // asserted BIP-54 invariants — pass full consensus validation.
    assert_eq!(
        after_height, block_height,
        "accepted tip height must match the coinbase's BIP-34 height"
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

// ── Helpers (mirrors crates/bp-mining-job/tests/regtest_e2e.rs) ────────
