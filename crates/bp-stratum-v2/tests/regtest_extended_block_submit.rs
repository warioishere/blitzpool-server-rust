// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 Extended-channel block submit must produce a coinbase that
//! bitcoin-core accepts.
//!
//! `validate_submit_extended` builds the submitted coinbase itself, a
//! different path from `MiningJob::witness_coinbase_with_extranonce`, and
//! `TdpHandle::submit_solution` is fire-and-forget, so only a real node shows
//! whether the bytes are valid. End to end:
//!
//! 1. Boot a `bitcoin-node v31` regtest instance and attach `TdpHandle`.
//! 2. Build a `MiningJob` from a fresh TDP template and wrap it in an
//!    `ExtendedJob` the way the channel code does.
//! 3. Brute-force a nonce against the coinbase the miner reconstructs.
//! 4. Run `validate_submit_extended` and submit its `witness_coinbase` via
//!    `TdpHandle::submit_solution`.
//! 5. Assert the chain tip advances by one block (or, for the rejection
//!    cases, that it does not and why).

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

/// nVersion bits 5–12 — the eight bits BIP-323 adds on top of BIP-320's
/// sixteen. Rolling exactly these and nothing else is the one case that
/// separates "needs BIP-323" from "already legal under BIP-320".
const BIP323_ONLY_VERSION_BITS: u32 = 0x0000_1fe0;

/// How long core gets to act on a submitted block. The reject path uses the
/// same budget so a slow acceptance cannot pass as "rejected".
const CORE_ACCEPT_BUDGET: Duration = Duration::from_secs(20);

/// Default case — 8-byte miner extranonce → total 4+8=12 matches
/// the pool default `EXTRANONCE_SLOT_LEN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_8byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(8, 0, true).await;
}

/// BitAxe case — 6-byte miner extranonce → total 4+6=10 ≠ 12. The
/// per-channel `MiningJob` is built with a 10-byte slot so the scriptSig
/// length varint matches the wire bytes; otherwise share hashes diverge and
/// core fails the parse with `OversizedVarInt`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_6byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(6, 0, true).await;
}

/// A block rolling the eight nVersion bits BIP-323 adds over BIP-320 is
/// accepted by **bitcoin-core v31** (which predates BIP-323 masking), the
/// tip advances and the bits survive into the stored header. This gates
/// widening the advertised `version-rolling.mask`; the pool does not
/// validate rolled bits, so such shares already reach Core.
///
/// It does NOT prove Core never warns about unknown soft forks: that warning
/// is threshold-based over a retarget window, so one block only shows that
/// a single such block raises nothing on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_rolling_bip323_version_bits_is_accepted_by_bitcoin_core() {
    run_block_submit_case(8, BIP323_ONLY_VERSION_BITS, true).await;
}

/// A miner's rolling lands the header version **below the consensus
/// floor**, and bitcoin-core rejects the block with `bad-version`.
///
/// With this harness's template version of `0x20000000`, rolling bit 31
/// yields `0xA0000000` — negative as an `i32`, so below
/// `bp_mining_job::MIN_CONSENSUS_BLOCK_VERSION`.
///
/// Backs the `scope="unsubmittable"` metric bucket: the share is valid
/// proof-of-work and the pool **accepts** it (asserted below), while
/// `TdpHandle::submit_solution` is fire-and-forget, so such a block is lost
/// without anything reporting it.
///
/// ⚠️ The rule is about the **resulting version**, not about which bits
/// were rolled; see `sv2_block_rolling_bit_30_stays_submittable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_below_consensus_version_floor_is_rejected_by_bitcoin_core() {
    run_block_submit_case(8, 1 << 31, false).await;
}

/// Rolling bit 30 against this template yields `0x60000000`, a positive
/// version, and bitcoin-core **accepts** the block. Pins that
/// submittability cannot be classified from the rolled bits alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_rolling_bit_30_stays_submittable() {
    run_block_submit_case(8, 1 << 30, true).await;
}

/// `rolled_version_bits` is XOR'd into the template version to form the
/// header version the miner submits — i.e. exactly the `version_mask` that
/// `validate_submit_extended` derives. `0` means no version rolling.
///
/// `expect_block_accepted` selects which half of the assertion set runs:
/// the tip must rise and keep the rolled bits, or the tip must stay put
/// while the node proves it is still willing to accept blocks.
async fn run_block_submit_case(
    miner_extranonce_size: u8,
    rolled_version_bits: u32,
    expect_block_accepted: bool,
) {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        // `tracing::warn!` rather than a print, to satisfy clippy's print lints.
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
    //
    // The Extended channel's total extranonce is
    // `extranonce_prefix.len + miner_extranonce_size`, and the mining job is
    // built with exactly that slot size in the scriptSig.
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
    //
    // The miner reconstructs the coinbase as
    //   tx_prefix + channel.extranonce_prefix + miner_extranonce + tx_suffix
    // so the brute-forced hash matches what `validate_submit_extended`
    // computes.
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
    // expectation is stated in terms of the rule core enforces. The
    // validator takes `submission.version` verbatim; the accept branch reads
    // the stored version back out of the chain.
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
    //
    // submit_solution is fire-and-forget, so the tip is its only signal.
    // That proves acceptance but not a rejection *reason*, so the reject
    // branch re-submits the identical block over `submitblock`, which
    // answers with core's reason string.
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
        //
        // If anything on the path replaced the header version with the
        // template's, the block would still be accepted; this pins that the
        // rolled bits reached the chain.
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
        //
        // One block cannot trip a threshold-based versionbits warning, so a
        // clean result means only that a single such block raises nothing
        // on its own.
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
