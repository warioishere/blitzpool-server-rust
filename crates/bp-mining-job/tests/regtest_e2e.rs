// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifies that the coinbase bytes produced by
//! [`bp_mining_job::build_mining_job_from_tdp`] are accepted by a real
//! `bitcoin-node v31` when submitted via the SV2 TDP `SubmitSolution` IPC
//! path.
//!
//! This is the **block-acceptance guarantee**: an SV1-translator pool
//! built on top of `bp-mining-job` is only useful if bitcoin-core
//! accepts the blocks it produces. The unit tests in `coinbase.rs`
//! prove the bytes parse as a valid `bitcoin::Transaction`; this test
//! proves they pass full consensus validation against an unmodified
//! bitcoin-core regtest node.
//!
//! Two cases:
//!
//! 1. **Single-output coinbase (no-fee)** — 100% to the miner. The
//!    coinbase ends up with 2 outputs total (miner + the TDP-provided
//!    witness-commitment OP_RETURN).
//! 2. **Fee-split coinbase (1.5% pool + 98.5% miner)** — three outputs,
//!    with the floor-rounding remainder lumped on `outs[0]` per
//!    [`bp_mining_job`]'s convention.
//!
//! Tests #3 (prefix/suffix round-trip) are already covered by the unit-level
//! `coinbase_with_extranonce_parses_as_valid_bitcoin_tx` test — and #4
//! (all 5 address types) is deferred as a follow-up since it needs a
//! wallet-side derivation step we don't currently expose.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed
//! at the host's default location or via `BITCOIN_NODE_PATH`.

use std::time::Duration;

use bitcoin::Network;
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, MiningJob, PayoutEntry,
    TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{
    brute_force_nonce, deterministic_p2wpkh_regtest, poll_for_height, wait_for_paired_template,
};

/// Two real regtest bech32 P2WPKH addresses. The block-validation path
/// doesn't care whether bitcoind's wallet knows the corresponding keys —
/// only that each output script is well-formed for the network.
///
/// `MINER_ADDR` is the BIP-173 test-vector address (P2WPKH of all-zero
/// pubkey hash); `FEE_ADDR` is its variant with an all-one pubkey hash —
/// constructed via `bitcoin::Address::p2wpkh` from a known
/// secp256k1::PublicKey to guarantee a valid bech32 checksum.
const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn single_output_coinbase_no_fee_accepted_by_core() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping v1-solo regtest — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let payouts = vec![PayoutEntry {
        address: MINER_ADDR.to_string(),
        percent: 100.0,
    }];
    run_block_acceptance_case(payouts, "v1-solo-nofee").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn fee_split_two_output_coinbase_accepted_by_core() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping v1-solo regtest — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // `DEV_FEE_PERCENT` default in the production pool.
    let fee_percent = 1.5;
    let fee_addr = deterministic_p2wpkh_regtest([0x42; 32]);
    let payouts = vec![
        PayoutEntry {
            address: fee_addr,
            percent: fee_percent,
        },
        PayoutEntry {
            address: MINER_ADDR.to_string(),
            percent: 100.0 - fee_percent,
        },
    ];
    run_block_acceptance_case(payouts, "v1-solo-fee").await;
}

/// Shared body for the two cases above — boots the regtest node + TDP,
/// builds the MiningJob with `payouts`, brute-forces a nonce against
/// the regtest target, submits via `TdpHandle::submit_solution`, and
/// asserts `bitcoin-node` height advanced by exactly one.
async fn run_block_acceptance_case(payouts: Vec<PayoutEntry>, pool_identifier: &str) {
    // ── Boot bitcoin-core + mine past IBD ─────────────────────────────
    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Attach TDP, drain the initial template, then mine 1 to force a
    // fresh template at the post-mining tip ──────────────────────────
    //
    // TDP emits a `NewTemplate` + `SetNewPrevHash` pair for the CURRENT
    // tip immediately on attach. If we keep that pair we'd submit a
    // block for an already-mined height — bitcoin-core silently rejects.
    // We deliberately consume the startup pair, then mine 1, then take
    // the next fresh pair.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn");
    let mut rx = tdp.subscribe();
    // Drain the startup pair (best-effort — bound to 500 ms).
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

    // ── Build MiningJob with our payouts ──────────────────────────────
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
        pool_identifier,
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job_from_tdp must succeed");

    // ── Brute-force a nonce that meets the regtest target ─────────────
    //
    // Regtest `n_bits = 0x207fffff` → target ≈ `0x7fffff << 232` ≈ 2^254.
    // Chance any random hash meets it is ~25 % → first or second nonce
    // typically hits. We allow up to 1 M tries as a safety bound.
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
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

    // ── Submit via TDP `SubmitSolution` ───────────────────────────────
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

    // ── Poll until height advances (or fail) ──────────────────────────
    //
    // submit_solution is fire-and-forget at the IPC layer — bitcoin-core
    // processes it asynchronously. Poll the chain tip with a generous
    // 5 s budget; on regtest acceptance is sub-second.
    let after_height = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .expect("bitcoin-core must accept the block");
    assert_eq!(
        after_height,
        before_height + 1,
        "bitcoin-core must advance the chain by exactly one block (got {after_height}, expected {})",
        before_height + 1,
    );

    // ── Verify the coinbase shape via rust-bitcoin parser ─────────────
    //
    // Sanity-check that the bytes we submitted decode as a valid
    // SegWit transaction with the expected number of outputs.
    {
        use bitcoin::consensus::Decodable;
        let non_witness = decode_non_witness_with_extranonce(&job, &en1, &en2);
        let tx = bitcoin::Transaction::consensus_decode(&mut non_witness.as_slice())
            .expect("coinbase must round-trip through rust-bitcoin");
        // payouts.len() user outputs + 1 TDP-provided witness commit.
        assert_eq!(
            tx.output.len(),
            payouts.len() + 1,
            "coinbase must have {} outputs (got {})",
            payouts.len() + 1,
            tx.output.len()
        );
    }

    // ── Clean teardown ────────────────────────────────────────────────
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Reconstruct the non-witness coinbase from `MiningJob`'s prefix +
/// extranonce slot + suffix. Used for the parser sanity check.
fn decode_non_witness_with_extranonce(job: &MiningJob, en1: &[u8; 4], en2: &[u8; 8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(job.coinbase_prefix().len() + 12 + job.coinbase_suffix().len());
    out.extend_from_slice(job.coinbase_prefix());
    out.extend_from_slice(en1);
    out.extend_from_slice(en2);
    out.extend_from_slice(job.coinbase_suffix());
    out
}

// ─── Test #4: 5-address-type coverage (P2PKH/P2SH/P2WPKH/P2WSH/P2TR) ───
//
// Exercises every branch of the address→script conversion in `bp-mining-job`
// against a real bitcoin-core regtest validator. 5 outputs × 20% each;
// bitcoind picks the address types natively for the first 4, P2WSH is
// wallet-side derived: get a real P2WPKH pubkey via `getaddressinfo`,
// wrap as the inner script of a P2WSH — the script doesn't need to be
// spendable, only well-formed.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn coinbase_with_all_5_address_types_accepted_by_core() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping 5-address-type regtest — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // ── Source addresses ─────────────────────────────────────────────
    let p2pkh = node
        .new_address("legacy")
        .await
        .expect("getnewaddress legacy");
    let p2sh = node
        .new_address("p2sh-segwit")
        .await
        .expect("getnewaddress p2sh-segwit");
    let p2wpkh = node
        .new_address("bech32")
        .await
        .expect("getnewaddress bech32");
    let p2tr = node
        .new_address("bech32m")
        .await
        .expect("getnewaddress bech32m");

    // P2WSH: wrap an inner P2WPKH script around a real on-chain pubkey
    // (P2WSH wrapping P2WPKH). The inner script doesn't need to be
    // spendable by anyone — coinbase outputs validate purely on script
    // well-formedness.
    let seed_addr = node
        .new_address("bech32")
        .await
        .expect("getnewaddress bech32 (seed for P2WSH)");
    let pubkey_hex = node
        .address_pubkey_hex(&seed_addr)
        .await
        .expect("getaddressinfo pubkey");
    let p2wsh = derive_p2wsh_via_inner_p2wpkh(&pubkey_hex);

    // ── Attach TDP, drain initial pair, mine 1 for fresh template ────
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
        .expect("mine 1 more for fresh template");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── 5 outputs × 20% ──────────────────────────────────────────────
    let payouts = vec![
        PayoutEntry {
            address: p2pkh.clone(),
            percent: 20.0,
        },
        PayoutEntry {
            address: p2sh.clone(),
            percent: 20.0,
        },
        PayoutEntry {
            address: p2wpkh.clone(),
            percent: 20.0,
        },
        PayoutEntry {
            address: p2wsh.clone(),
            percent: 20.0,
        },
        PayoutEntry {
            address: p2tr.clone(),
            percent: 20.0,
        },
    ];

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
        "all5",
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job_from_tdp must succeed for all 5 address types");

    // ── Sanity-check each output script decodes back to its source ────
    //
    // Catches a buggy `MiningJob` address→script branch (e.g. p2tr
    // branch emitting p2wpkh bytes). Parse the non-witness coinbase
    // bytes via rust-bitcoin + walk outputs.
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    {
        use bitcoin::consensus::Decodable;
        use bitcoin::{Address, Network as BNet};
        let non_witness = decode_non_witness_with_extranonce(&job, &en1, &en2);
        let tx = bitcoin::Transaction::consensus_decode(&mut non_witness.as_slice())
            .expect("coinbase must round-trip");
        // 5 payout outs + 1 TDP-provided witness-commitment OP_RETURN.
        assert_eq!(
            tx.output.len(),
            6,
            "coinbase must have 6 outputs (5 payouts + witness commitment)"
        );
        for (idx, (expected_addr, payout_addr)) in [
            (&p2pkh, "P2PKH"),
            (&p2sh, "P2SH"),
            (&p2wpkh, "P2WPKH"),
            (&p2wsh, "P2WSH"),
            (&p2tr, "P2TR"),
        ]
        .iter()
        .enumerate()
        {
            let script = &tx.output[idx].script_pubkey;
            let decoded = Address::from_script(script, BNet::Regtest)
                .unwrap_or_else(|e| panic!("output {idx} ({payout_addr}) script decode: {e}"));
            assert_eq!(
                decoded.to_string(),
                **expected_addr,
                "output {idx} ({payout_addr}) script must decode to original {expected_addr}"
            );
        }
    }

    // ── Brute-force a nonce + submit via TDP ─────────────────────────
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
    .expect("must find a valid nonce on regtest");

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
        .expect("bitcoin-core must accept the 5-address-type coinbase block");
    assert_eq!(
        after_height,
        before_height + 1,
        "chain must advance by exactly 1 (got {after_height}, expected {})",
        before_height + 1
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

/// Construct a P2WSH regtest address whose inner (redeem) script is a
/// P2WPKH for `pubkey_hex`.
fn derive_p2wsh_via_inner_p2wpkh(pubkey_hex: &str) -> String {
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::{opcodes, script::Builder, Address, KnownHrp};

    // Decode the compressed pubkey (33 bytes).
    let pubkey_bytes = (0..pubkey_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pubkey_hex[i..i + 2], 16).expect("valid hex from RPC"))
        .collect::<Vec<u8>>();
    assert_eq!(
        pubkey_bytes.len(),
        33,
        "pubkey from getaddressinfo must be 33-byte compressed"
    );

    // Inner P2WPKH script: `OP_0 <20-byte pubkey hash>`.
    let pubkey_hash = hash160::Hash::hash(&pubkey_bytes);
    let inner_p2wpkh = Builder::new()
        .push_opcode(opcodes::all::OP_PUSHBYTES_0)
        .push_slice(pubkey_hash.to_byte_array())
        .into_script();

    // P2WSH address: `OP_0 <32-byte sha256(inner_script)>` — `Address::p2wsh`
    // takes the inner script + an HRP, computes the sha256 commitment
    // internally.
    Address::p2wsh(&inner_p2wpkh, KnownHrp::Regtest).to_string()
}
