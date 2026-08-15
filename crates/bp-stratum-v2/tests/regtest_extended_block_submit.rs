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

/// Regtest bech32 P2WPKH (BIP-173 zero-pubkey-hash test vector). The
/// block-submit path doesn't care if bitcoind's wallet knows the key —
/// it only needs a well-formed output script for the network.
const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// nVersion bits 5–12 — the eight bits BIP-323 adds on top of BIP-320's
/// sixteen. Rolling exactly these and nothing else is the one case that
/// separates "needs BIP-323" from "already legal under BIP-320".
const BIP323_ONLY_VERSION_BITS: u32 = 0x0000_1fe0;

/// How long core gets to act on a submitted block. Both the accept and the
/// reject path use it: a shorter budget on the reject side would turn a
/// merely slow acceptance into a passing "it was rejected".
const CORE_ACCEPT_BUDGET: Duration = Duration::from_secs(20);

/// Default case — 8-byte miner extranonce → total 4+8=12 matches
/// the pool default `EXTRANONCE_SLOT_LEN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_8byte_miner_extranonce_block_is_accepted_by_bitcoin_core() {
    run_block_submit_case(8, 0, true).await;
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
    run_block_submit_case(6, 0, true).await;
}

/// A miner rolls the eight nVersion bits BIP-323 adds and BIP-320 never
/// granted; the resulting block must still be accepted by **bitcoin-core
/// v31** — the version the pool runs in production, released before the
/// BIP-323 masking landed (that is milestone 32.0).
///
/// This is the gate on widening the advertised `version-rolling.mask`
/// ahead of the Core upgrade. The pool does not validate rolled version
/// bits in either protocol today, so such a share is already accepted and
/// already reaches Core; what was never checked is what Core does with it.
///
/// **What this proves:** bits 5–12 are not consensus-relevant — the block
/// is accepted, the tip advances, and the bits survive into the stored
/// header. No block is lost by rolling them.
///
/// **What this does NOT prove:** that Core never emits an unknown-soft-fork
/// warning. That warning is threshold-based over a retarget window, and one
/// block cannot reach any threshold. The assertion below therefore only
/// establishes that a *single* such block raises nothing on its own — which
/// is the production shape, since the pool's blocks are a negligible share
/// of any mainnet window. A node's warning state depends on the whole
/// network, not on us, so no regtest can answer that half.
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
/// This is the measurement behind the `scope="unsubmittable"` metric
/// bucket, and the reason that case is not merely "the miner's problem":
///
/// - the share is valid proof-of-work, and the pool **accepts** it
///   (asserted below) — the miner is credited and sees nothing wrong;
/// - `TdpHandle::submit_solution` is fire-and-forget, so the pool sees
///   nothing wrong either;
/// - the block is silently gone, and the loss lands only on the day such a
///   share happens to solve one.
///
/// ⚠️ The rule is about the **resulting version**, not about which bits
/// were rolled. An earlier version of this test claimed bits 29–31 were
/// structurally block-killing, from two measurements that both happened to
/// fit this one template. `sv2_block_rolling_bit_30_stays_submittable`
/// below is the case that refutes it and exists to keep it refuted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_block_below_consensus_version_floor_is_rejected_by_bitcoin_core() {
    run_block_submit_case(8, 1 << 31, false).await;
}

/// The refutation case. Rolling bit 30 against this template yields
/// `0x60000000` — a large positive version — and bitcoin-core **accepts**
/// the block.
///
/// It is here because a plausible-looking rule ("the top three version
/// bits are structural, rolling any of them kills the block") survived two
/// measurements and a written rationale before this case was ever tried.
/// Any future attempt to classify submittability from the rolled delta
/// alone fails here.
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
        // Use `tracing::warn!` instead of a stdout print so this skip
        // is visible in test logs without tripping clippy's
        // `print_stdout` / `print_stderr` lints (enforced by CI's
        // `-D warnings`).
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
        [0u8; 32],
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
        payouts_fingerprint: [0u8; 32],
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

    // The version the miner actually hashes. `ext_job.version` stays the
    // template's, so the validator derives `version_mask = header_version
    // ^ template.version` — the production algebra, not a test shortcut.
    let header_version = template.version ^ rolled_version_bits;

    // Pin which side of the consensus floor this case is on, so the
    // expectation below is stated in terms of the rule core enforces rather
    // than in terms of which bit happened to be rolled.
    //
    // Nothing here asserts `header_version ^ ext_job.version == rolled_bits`:
    // `ext_job.version` IS `template.version`, so that would be
    // `(a ^ b) ^ b == a` and pin nothing. The validator no longer derives a
    // mask at all — it takes `submission.version` verbatim — so the value
    // that matters is the one core ends up storing, which the accept branch
    // reads back out of the chain.
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
        header_version,
        prev_hash.header_timestamp,
        nonce,
        accept.witness_coinbase.clone(),
    )
    .await
    .expect("submit_solution IPC call");

    // ── What bitcoin-core did with it ────────────────────────────────
    //
    // submit_solution is fire-and-forget, so the tip is the only signal it
    // gives. That is enough to prove acceptance, but NOT enough to prove a
    // rejection *reason* — this very file documents another silent cause of
    // a stuck tip (the 2026-05-17 OversizedVarInt coinbase). The reject
    // branch therefore re-submits the identical block over `submitblock`,
    // which answers synchronously with core's own reason string.
    if !expect_block_accepted {
        // Same budget as the accept path below. A shorter one here would
        // be a false-pass window: on a loaded box core taking longer than
        // the budget to accept would read as "rejected".
        let reached = poll_for_height(&node, before_height + 1, CORE_ACCEPT_BUDGET).await;
        assert!(
            reached.is_none(),
            "bitcoin-core accepted a block whose header version is \
             0x{header_version:08x} (i32 {}); the consensus floor in \
             `bp_mining_job::MIN_CONSENSUS_BLOCK_VERSION` is then wrong",
            header_version as i32
        );

        // Now get the reason on the record. The template carries no
        // transactions on this harness, so the block is header + one
        // coinbase; assert that rather than assume it, since a non-empty
        // merkle path would make the bytes below a different block.
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

        // Negative control, in the same test: prove the node was alive and
        // willing the whole time. Without it, a node that died right after
        // `submit_solution` would produce the same "tip did not move"
        // reading and this test would pass for the wrong reason.
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
        // Without this, a rolled-bits case could pass while proving
        // nothing: if anything on the path (validator, TDP IPC, core's own
        // assembly) replaced the header version with the template's, the
        // block would still be accepted and the tip would still rise.
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
        // clean result here means "a single such block raises nothing on
        // its own", nothing stronger. It is still worth having: that IS the
        // production shape, and if core v31 ever did flag a lone
        // unknown-signalling block, this is where we would find out rather
        // than on prod after a found block.
        let warnings = node
            .rpc_call("getblockchaininfo", json!([]))
            .await
            .expect("getblockchaininfo")
            .get("warnings")
            .cloned()
            .unwrap_or(Value::Null);
        // `warnings` is a string on older cores and an array from v25 on.
        // Normalise rather than assume, so a shape change surfaces as a
        // failed assertion and not as a silently-skipped check.
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

// ── Helpers (copy-of-the-helpers from bp-mining-job/tests/regtest_e2e.rs) ─
