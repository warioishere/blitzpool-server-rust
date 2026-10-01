// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 Extended-channel block submit must produce a coinbase bitcoin-core accepts.
//! `validate_submit_extended` builds that coinbase on its own path and
//! `TdpHandle::submit_solution` is fire-and-forget, so only a real node shows
//! whether the bytes are valid; the chain tip is the verdict.

use std::time::Duration;

use bitcoin::Network;
use bp_jobs_lifecycle::LifecycleConfig;
use bp_mining_job::{
    build_block_header, build_mining_job_from_tdp, merkle_root_from_coinbase,
    version_meets_consensus_floor, PayoutEntry, TdpCoinbaseTemplate,
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
use serde_json::{json, Value};
use smallvec::SmallVec;

/// Regtest bech32 P2WPKH (BIP-173 test vector); only a well-formed output
/// script is needed.
const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// nVersion bits 5–12, the eight bits BIP-323 adds on top of BIP-320's
/// sixteen; rolling only these separates "needs BIP-323" from BIP-320.
const BIP323_ONLY_VERSION_BITS: u32 = 0x0000_1fe0;

/// How long core gets to act on a submitted block. The reject path uses the
/// same budget so a slow acceptance cannot pass as "rejected".
const CORE_ACCEPT_BUDGET: Duration = Duration::from_secs(20);

/// 8-byte miner extranonce: total 12 matches the pool's `EXTRANONCE_SLOT_LEN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_8byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(8, 0, true).await;
}

/// 6-byte miner extranonce (total 10): the job's scriptSig length varint must
/// match the wire bytes, or core fails the parse with `OversizedVarInt`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_6byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(6, 0, true).await;
}

/// bitcoin-core accepts a block rolling the BIP-323-only bits and stores them;
/// this gates widening the advertised `version-rolling.mask`. One block cannot
/// trip the threshold-based unknown-softfork warning, so that is not proven.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_rolling_bip323_version_bits_is_accepted_by_bitcoin_core() {
    run_block_submit_case(8, BIP323_ONLY_VERSION_BITS, true).await;
}

/// Rolling bit 31 makes the version negative as an `i32`, below the consensus
/// floor: the pool accepts the share, core rejects the block `bad-version`.
/// Backs the `scope="unsubmittable"` metric, since the fire-and-forget submit
/// would lose such a block silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_below_consensus_version_floor_is_rejected_by_bitcoin_core() {
    run_block_submit_case(8, 1 << 31, false).await;
}

/// Rolling bit 30 keeps the version positive and core accepts the block:
/// submittability depends on the resulting version, not the rolled bits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_rolling_bit_30_stays_submittable() {
    run_block_submit_case(8, 1 << 30, true).await;
}

/// `rolled_version_bits` is XOR'd into the template version (`0` = no rolling).
/// `expect_block_accepted`: the tip rises and keeps the bits, or it stays put
/// while the node proves it still accepts blocks.
async fn run_block_submit_case(
    miner_extranonce_size: u8,
    rolled_version_bits: u32,
    expect_block_accepted: bool,
) {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        tracing::warn!(
            reason = %cfg.unavailable_reason(),
            "skipping SV2 Extended block-submit regtest"
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
    // Its scriptSig slot is `extranonce_prefix.len + miner_extranonce_size`.
    let extranonce_prefix: Vec<u8> = vec![0xC0, 0xDE, 0xBA, 0xBE];
    let channel_id: u32 = 1;
    let job_id: u32 = 1;
    // Trivial job target, so the share gate passes and the test is about
    // the bytes bitcoin-core sees.
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
        [0u8; 32],
    )
    .expect("build_mining_job_from_tdp");

    // ── Build the Extended channel + ExtendedJob: coinbase_prefix is the
    //    bytes BEFORE the extranonce slot; the miner appends
    //    channel.extranonce_prefix + its own extranonce.
    let tx_prefix = mining_job.coinbase_prefix().to_vec();
    let tx_suffix = mining_job.coinbase_suffix().to_vec();

    let ext_job = ExtendedJob {
        payouts_fingerprint: [0u8; 32],
        coinbase_prefix: tx_prefix.clone(),
        coinbase_suffix: tx_suffix.clone(),
        merkle_path: template.merkle_path.clone(),
        // Same prefix as the channel below: the validator splices the JOB's
        // copy into the coinbase.
        extranonce_prefix: extranonce_prefix.clone(),
        version: template.version,
        prev_hash: prev_hash.prev_hash,
        n_bits: prev_hash.n_bits,
        min_ntime: prev_hash.header_timestamp,
        difficulty: job_difficulty,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        template_id: Some(template.template_id),
        jdp_claims_the_block: false,
        created_at: 0,
        retired_at: None,
    };

    let mut channel = ChannelState::new_extended(
        channel_id,
        extranonce_prefix.clone(),
        miner_extranonce_size,
        job_difficulty,
        [0xFFu8; 32],
        LifecycleConfig::DEFAULT,
    );
    channel.extended_jobs.insert(job_id, ext_job.clone());

    // ── Brute-force a nonce against the regtest target ───────────────
    // Over the coinbase as the miner rebuilds it, so the hash matches what
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

    // The version the miner actually hashes; `ext_job.version` stays the
    // template's.
    let header_version = template.version ^ rolled_version_bits;

    // Pin which side of the consensus floor this case is on, so the
    // expectation is stated in terms of the rule core enforces.
    assert_eq!(
        version_meets_consensus_floor(header_version),
        expect_block_accepted,
        "case setup is inconsistent: header version 0x{header_version:08x} \
         (i32 {}) vs expect_block_accepted={expect_block_accepted}",
        header_version as i32
    );

    let nonce = brute_force_nonce(
        header_version,
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
        version: header_version,
        ntime: prev_hash.header_timestamp,
        extranonce: miner_extranonce,
        tlvs: Vec::new(),
    };
    let job_target = channel.target_for(job_difficulty);
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_size: channel.extranonce_size,
        job_target,
        job_lifecycle: *channel.standard_jobs.lifecycle(),
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
        header_version,
        prev_hash.header_timestamp,
        nonce,
        accept.witness_coinbase.clone(),
    )
    .await
    .expect("submit_solution IPC call");

    // ── What bitcoin-core did with it ────────────────────────────────
    // The tip shows acceptance but no rejection reason, so the reject branch
    // re-submits the same block over `submitblock` to read core's reason.
    if !expect_block_accepted {
        // Same budget as the accept path, see `CORE_ACCEPT_BUDGET`.
        let reached = poll_for_height(&node, before_height + 1, CORE_ACCEPT_BUDGET).await;
        assert!(
            reached.is_none(),
            "bitcoin-core accepted a block whose header version is \
             0x{header_version:08x} (i32 {}); the consensus floor in \
             `bp_mining_job::MIN_CONSENSUS_BLOCK_VERSION` is then wrong",
            header_version as i32
        );

        // Get the reason. The block is header + one coinbase only if the
        // template carries no transactions, so assert that.
        assert!(
            template.merkle_path.is_empty(),
            "this reconstruction assumes a coinbase-only template"
        );
        let header_bytes = build_block_header(
            header_version as i32,
            &prev_hash.prev_hash,
            &merkle_root,
            prev_hash.header_timestamp,
            prev_hash.n_bits,
            nonce,
        );
        let mut block = hex::encode(header_bytes);
        block.push_str("01"); // tx count varint
        block.push_str(&hex::encode(&accept.witness_coinbase));
        let reason = node
            .submit_block(&block)
            .await
            .expect("submitblock RPC")
            .unwrap_or_default();
        assert!(
            reason.contains("bad-version"),
            "core must reject this block *on version grounds*, not drop it \
             for some other reason; submitblock said {reason:?} for header \
             version 0x{header_version:08x}"
        );

        let still = node.current_height().await.expect("current_height");
        assert_eq!(
            still, before_height,
            "tip moved despite the block being rejected"
        );

        // Negative control: the node still accepts an ordinary block, so a
        // dead node cannot pass as "tip did not move".
        node.generate_to_self(1)
            .await
            .expect("node must still accept an ordinary block");
        let recovered = poll_for_height(&node, before_height + 1, CORE_ACCEPT_BUDGET)
            .await
            .expect("node must advance on a normally-mined block");
        assert_eq!(recovered, before_height + 1);
    } else {
        let after = poll_for_height(&node, before_height + 1, CORE_ACCEPT_BUDGET)
            .await
            .expect(
                "bitcoin-core must advance the chain after submit_solution — \
                 a stuck tip indicates validate_submit_extended produced bytes \
                 bitcoin-core rejected (the OversizedVarInt bug from 2026-05-17)",
            );
        assert_eq!(after, before_height + 1);

        // ── The version bits must have survived into the chain ───────
        // A path that swapped in the template's version would still be accepted.
        let block_hash = node
            .rpc_call("getblockhash", json!([after]))
            .await
            .expect("getblockhash")
            .as_str()
            .expect("block hash is a string")
            .to_string();
        let stored_version = node
            .rpc_call("getblockheader", json!([block_hash]))
            .await
            .expect("getblockheader")
            .get("version")
            .and_then(Value::as_i64)
            .expect("header version is a number") as u32;
        assert_eq!(
            stored_version, header_version,
            "bitcoin-core stored a different nVersion than was submitted — \
             the rolled bits (0x{rolled_version_bits:08x}) did not reach the \
             chain, so this run proves nothing about them"
        );

        // ── ...and core must not have flagged them ───────────────────
        // Only shows one such block raises nothing; the warning is threshold-based.
        let warnings = node
            .rpc_call("getblockchaininfo", json!([]))
            .await
            .expect("getblockchaininfo")
            .get("warnings")
            .cloned()
            .unwrap_or(Value::Null);
        // `warnings` is a string on older cores and an array from v25 on;
        // any other shape fails rather than skipping the check.
        let warning_text = match &warnings {
            Value::String(s) => s.clone(),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" | "),
            other => panic!("unexpected `warnings` shape from getblockchaininfo: {other}"),
        };
        assert!(
            !warning_text.to_lowercase().contains("unknown"),
            "bitcoin-core v31 raised an unknown-rules/version warning after a \
             block rolling 0x{rolled_version_bits:08x}: {warning_text:?}"
        );
    }

    // ── Clean teardown ───────────────────────────────────────────────
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}
