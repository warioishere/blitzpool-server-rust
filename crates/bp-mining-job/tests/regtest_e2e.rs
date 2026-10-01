// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block-acceptance guarantee: coinbases from
//! [`bp_mining_job::build_mining_job_from_tdp`] pass full consensus validation
//! in a real bitcoin-core regtest node via TDP `SubmitSolution`, for a single
//! output, a fee split and all five address types. Skipped without `bitcoin-node`.

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

/// BIP-173 test-vector regtest P2WPKH; validation only needs a well-formed script.
const MINER_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn single_output_coinbase_no_fee_accepted_by_core() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!("skipping v1-solo regtest — {}", cfg.unavailable_reason());
        return;
    }

    let payouts = vec![PayoutEntry {
        address: MINER_ADDR.to_string(),
        sats: 5_000_000_000,
    }];
    run_block_acceptance_case(payouts, "v1-solo-nofee").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn fee_split_two_output_coinbase_accepted_by_core() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!("skipping v1-solo regtest — {}", cfg.unavailable_reason());
        return;
    }

    let fee_percent = 1.5;
    let fee_addr = deterministic_p2wpkh_regtest([0x42; 32]);
    let payouts = vec![
        PayoutEntry::from_percent(fee_addr, fee_percent, 5_000_000_000),
        PayoutEntry::from_percent(MINER_ADDR, 100.0 - fee_percent, 5_000_000_000),
    ];
    run_block_acceptance_case(payouts, "v1-solo-fee").await;
}

/// Mines one block whose coinbase pays `payouts` and asserts core accepted it.
async fn run_block_acceptance_case(payouts: Vec<PayoutEntry>, pool_identifier: &str) {
    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    // The pair TDP emits on attach can be for an already-mined height,
    // which core silently rejects: drain it, mine one, take the next.
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
        [0u8; 32],
    )
    .expect("build_mining_job_from_tdp must succeed");

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

    // submit_solution is fire-and-forget; core processes it asynchronously.
    let after_height = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .expect("bitcoin-core must accept the block");
    assert_eq!(
        after_height,
        before_height + 1,
        "bitcoin-core must advance the chain by exactly one block (got {after_height}, expected {})",
        before_height + 1,
    );

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

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

/// Non-witness coinbase: prefix + extranonce slot + suffix.
fn decode_non_witness_with_extranonce(job: &MiningJob, en1: &[u8; 4], en2: &[u8; 8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(job.coinbase_prefix().len() + 12 + job.coinbase_suffix().len());
    out.extend_from_slice(job.coinbase_prefix());
    out.extend_from_slice(en1);
    out.extend_from_slice(en2);
    out.extend_from_slice(job.coinbase_suffix());
    out
}

// Every address→script branch, validated by core rather than the pool's own encoder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn coinbase_with_all_5_address_types_accepted_by_core() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping 5-address-type regtest — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

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

    // Coinbase outputs validate on well-formedness only; P2WSH need not be spendable.
    let seed_addr = node
        .new_address("bech32")
        .await
        .expect("getnewaddress bech32 (seed for P2WSH)");
    let pubkey_hex = node
        .address_pubkey_hex(&seed_addr)
        .await
        .expect("getaddressinfo pubkey");
    let p2wsh = derive_p2wsh_via_inner_p2wpkh(&pubkey_hex);

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

    let payouts = vec![
        PayoutEntry {
            address: p2pkh.clone(),
            sats: 1_000_000_000,
        },
        PayoutEntry {
            address: p2sh.clone(),
            sats: 1_000_000_000,
        },
        PayoutEntry {
            address: p2wpkh.clone(),
            sats: 1_000_000_000,
        },
        PayoutEntry {
            address: p2wsh.clone(),
            sats: 1_000_000_000,
        },
        PayoutEntry {
            address: p2tr.clone(),
            sats: 1_000_000_000,
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
        [0u8; 32],
    )
    .expect("build_mining_job_from_tdp must succeed for all 5 address types");

    // Each output script must decode back to its own source address.
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

    let pubkey_bytes = (0..pubkey_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pubkey_hex[i..i + 2], 16).expect("valid hex from RPC"))
        .collect::<Vec<u8>>();
    assert_eq!(
        pubkey_bytes.len(),
        33,
        "pubkey from getaddressinfo must be 33-byte compressed"
    );

    let pubkey_hash = hash160::Hash::hash(&pubkey_bytes);
    let inner_p2wpkh = Builder::new()
        .push_opcode(opcodes::all::OP_PUSHBYTES_0)
        .push_slice(pubkey_hash.to_byte_array())
        .into_script();

    Address::p2wsh(&inner_p2wpkh, KnownHrp::Regtest).to_string()
}
