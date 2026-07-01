// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression test: SV2 Extended-channel block-submit must produce a
//! coinbase that bitcoin-core accepts.
//!
//! Until 2026-05-17, [`validate_submit_extended`] reconstructed the
//! coinbase as `ext_job.coinbase_prefix + channel.extranonce_prefix +
//! miner_extranonce + ext_job.coinbase_suffix` — but `ext_job.coinbase_prefix`
//! already bakes in `channel.extranonce_prefix` (see
//! `mining::client::apply_template_to_channel`, the Extended branch).
//! Result: 4 bytes of `extranonce_prefix` ended up duplicated in the
//! tx, and bitcoin-core's TDP `SubmitSolution` IPC rejected it with
//! `InvalidCoinbaseTx(OversizedVarInt)` — silently in production
//! because `TdpHandle::submit_solution` is fire-and-forget.
//!
//! Earlier `bp-stratum-v2/tests/regtest_extended.rs` validated the
//! Open / NewExtendedMiningJob handshake but explicitly skipped the
//! submit-shares path on a "transitivity via
//! `bp-mining-job/tests/regtest_e2e.rs`" argument. That argument was
//! wrong: `bp-mining-job`'s regtest uses
//! `MiningJob::witness_coinbase_with_extranonce` directly, which is a
//! different code path than `validate_submit_extended`. The SV2-Extended
//! submit-bytes were effectively never exercised against a real
//! bitcoin-core. This test closes that gap.
//!
//! The test goes end-to-end:
//!
//! 1. Boot a real `bitcoin-node v31` regtest instance.
//! 2. Wire up the actual `TdpHandle` against its IPC socket.
//! 3. Build a `MiningJob` from a fresh TDP template and stash it in an
//!    `ExtendedJob` exactly how `apply_template_to_channel` does in
//!    production (with `extranonce_prefix` baked into `coinbase_prefix`).
//! 4. Brute-force a nonce that beats the regtest target against the
//!    coinbase the miner would reconstruct from the wire frame.
//! 5. Call `validate_submit_extended` — the same function the IO layer
//!    calls when a real `SubmitSharesExtended` arrives.
//! 6. Take the resulting `ShareAccept.witness_coinbase` and submit it
//!    to bitcoin-core via `TdpHandle::submit_solution`.
//! 7. Assert that the chain tip actually advances by one block.
//!
//! With the bug, step 7 fails: bitcoin-core silently rejects the
//! malformed coinbase and the tip stays put. With the fix, the block
//! is accepted and the test passes.

use std::time::Duration;

use bitcoin::Network;
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::{sha256d, Difficulty, Target};
use bp_stratum_v2::mining::channel::ChannelState;
use bp_stratum_v2::mining::jobs::ExtendedJob;
use bp_stratum_v2::mining::submit::{
    validate_submit_extended, ExtendedChannelView, ShareValidation, SubmitSharesExtendedInput,
};
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{brute_force_nonce, poll_for_height, wait_for_paired_template};
use smallvec::SmallVec;

/// Regtest bech32 P2WPKH (BIP-173 zero-pubkey-hash test vector). The
/// block-submit path doesn't care if bitcoind's wallet knows the key —
/// it only needs a well-formed output script for the network.
const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// Default case — 8-byte miner extranonce → total 4+8=12 matches
/// the pool default `EXTRANONCE_SLOT_LEN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_8byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(8).await;
}

/// BitAxe case — 6-byte miner extranonce → total 4+6=10 ≠ 12. The
/// per-channel `MiningJob` is built with a 10-byte slot directly so
/// the scriptsig_len varint matches the wire bytes. Real miners
/// expect a correct varint and would compute a different share-hash
/// than ours otherwise — and the
/// block-submit-to-bitcoin-core path would also fail the consensus
/// parse with `OversizedVarInt`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_6byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(6).await;
}

async fn run_block_submit_case(miner_extranonce_size: u8) {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        // Use `tracing::warn!` instead of a stdout print so this skip
        // is visible in test logs without tripping clippy's
        // `print_stdout` / `print_stderr` lints (enforced by CI's
        // `-D warnings`).
        tracing::warn!(
            path = %cfg.bitcoin_node_path.display(),
            "skipping SV2 Extended block-submit regtest — bitcoin-node not found \
             (set BITCOIN_NODE_PATH to override)"
        );
        return;
    }

    // ── Boot bitcoin-core + mine past IBD ─────────────────────────────
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Attach TDP + drain the startup pair, then mine 1 for a fresh
    //    template at the post-mining tip ───────────────────────────────
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
        .expect("mine 1 to force fresh NewTemplate at current tip");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── Build the per-channel MiningJob the pool would issue ────────
    //
    // The Extended channel negotiates a total extranonce of
    // `extranonce_prefix.len + miner_extranonce_size`, so we build the
    // mining-job with that exact slot size baked into the scriptsig.
    // This mirrors what `apply_template_broadcast` does in production
    // (no post-hoc varint patching).
    let extranonce_prefix: Vec<u8> = vec![0xC0, 0xDE, 0xBA, 0xBE];
    let channel_id: u32 = 1;
    let job_id: u32 = 1;
    // Job-target must be trivial so the validator's per-share difficulty
    // gate passes — what we actually want to assert is the WIRE-bytes
    // bitcoin-core sees, not whether the brute-forced hash meets some
    // arbitrary pool diff. `1e-18` matches `regtest_extended.rs`.
    let job_difficulty = Difficulty(1.0e-18);
    let full_extranonce_size = extranonce_prefix.len() + miner_extranonce_size as usize;

    let coinbase_template = TdpCoinbaseTemplate {
        coinbase_prefix: &template.coinbase_prefix,
        coinbase_tx_version: template.coinbase_tx_version,
        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &template.coinbase_tx_outputs,
        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
        coinbase_tx_locktime: template.coinbase_tx_locktime,
    };
    let payouts = vec![PayoutEntry {
        address: MINER_ADDR.to_string(),
        sats: 5_000_000_000,
    }];
    let mining_job = build_mining_job_from_tdp(
        Network::Regtest,
        &payouts,
        &coinbase_template,
        "sv2-ext-regtest",
        full_extranonce_size,
    )
    .expect("build_mining_job_from_tdp");

    // ── Build the Extended channel + ExtendedJob exactly how
    //    `apply_template_to_channel` does — coinbase_prefix is the
    //    bytes BEFORE the extranonce slot (no extranonce_prefix
    //    baked in; SV2 spec says the miner appends
    //    channel.extranonce_prefix + own extranonce itself).
    let tx_prefix = mining_job.coinbase_prefix().to_vec();
    let tx_suffix = mining_job.coinbase_suffix().to_vec();

    let ext_job = ExtendedJob {
        coinbase_prefix: tx_prefix.clone(),
        coinbase_suffix: tx_suffix.clone(),
        merkle_path: template.merkle_path.clone(),
        version: template.version,
        prev_hash: prev_hash.prev_hash,
        n_bits: prev_hash.n_bits,
        min_ntime: prev_hash.header_timestamp,
        difficulty: job_difficulty,
        // Trivial pinned network difficulty → every share is a block candidate.
        network_difficulty: Difficulty(1.0e-18),
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        template_id: Some(template.template_id),
        created_at: 0,
        retired_at: None,
    };

    let mut channel = ChannelState::new_extended(
        channel_id,
        extranonce_prefix.clone(),
        miner_extranonce_size,
        job_difficulty,
        [0xFFu8; 32],
    );
    channel.extended_jobs.insert(job_id, ext_job.clone());

    // ── Brute-force a nonce against the regtest target ───────────────
    //
    // The miner reconstructs the coinbase as
    //   tx_prefix + channel.extranonce_prefix + miner_extranonce + tx_suffix
    // (per SRI's client/extended.rs::validate_share). We mirror that
    // here so the hash we brute-force matches what
    // `validate_submit_extended` computes.
    let miner_extranonce: SmallVec<[u8; 16]> =
        SmallVec::from_iter(std::iter::repeat_n(0u8, miner_extranonce_size as usize));
    let mut miner_coinbase = Vec::with_capacity(
        tx_prefix.len() + extranonce_prefix.len() + miner_extranonce.len() + tx_suffix.len(),
    );
    miner_coinbase.extend_from_slice(&tx_prefix);
    miner_coinbase.extend_from_slice(&extranonce_prefix);
    miner_coinbase.extend_from_slice(&miner_extranonce);
    miner_coinbase.extend_from_slice(&tx_suffix);

    let coinbase_txid = sha256d(&miner_coinbase);
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
    .expect("must find a regtest-target-matching nonce within 1M tries");

    // ── Drive the actual SV2 validator ───────────────────────────────
    let submission = SubmitSharesExtendedInput {
        channel_id,
        sequence_number: 1,
        job_id,
        nonce,
        version: template.version,
        ntime: prev_hash.header_timestamp,
        extranonce: miner_extranonce,
        tail_tlvs: Vec::new(),
    };
    let job_target = channel.target_for(job_difficulty);
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_prefix: &channel.extranonce_prefix,
        extranonce_size: channel.extranonce_size,
        job_target,
    };
    let validation = validate_submit_extended(
        &mut channel.submission_cache,
        &view,
        &submission,
        &ext_job,
        job_difficulty,
        /* now_ms = */ 0,
        /* ext_0x0002_negotiated = */ false,
        /* debug_share_logs = */ false,
    );
    let accept = match validation {
        ShareValidation::Accepted(a) => a,
        ShareValidation::Rejected(reject) => {
            panic!("validate_submit_extended rejected a regtest-target-matching share: {reject:?}")
        }
    };
    assert!(
        accept.is_block_candidate,
        "regtest target is trivial — every accepted share is a block candidate"
    );
    assert!(
        !accept.witness_coinbase.is_empty(),
        "block-candidate share must carry a witness_coinbase for submit_solution"
    );

    // ── Submit to bitcoin-core ───────────────────────────────────────
    let before_height = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        accept.witness_coinbase.clone(),
    )
    .await
    .expect("submit_solution IPC call");

    // ── Assert chain advanced ────────────────────────────────────────
    //
    // submit_solution is fire-and-forget — the only way to know
    // bitcoin-core accepted is to watch the tip. Without the fix,
    // the witness_coinbase contains 4 duplicated `extranonce_prefix`
    // bytes which break the varint parse; bitcoin-core silently
    // drops the submission and the height does NOT advance.
    let after = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .expect(
            "bitcoin-core must advance the chain after submit_solution — \
             a stuck tip indicates validate_submit_extended produced bytes \
             bitcoin-core rejected (the OversizedVarInt bug from 2026-05-17)",
        );
    assert_eq!(after, before_height + 1);

    // ── Clean teardown ───────────────────────────────────────────────
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

// ── Helpers (copy-of-the-helpers from bp-mining-job/tests/regtest_e2e.rs) ─
