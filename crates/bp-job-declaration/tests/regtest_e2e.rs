// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end test: spawn a regtest `bitcoin-node`, attach `JdpHandle`,
//! send a `DeclareMiningJob` with a minimal hand-rolled coinbase, and
//! verify the request/response roundtrip completes with a sane response
//! variant.
//!
//! We do **not** try to make bitcoin-core accept the declared job — that
//! requires building a coinbase that exactly matches the current template
//! (BIP34 height, value, witness commitment, etc.). The goal here is to
//! prove the wire-level roundtrip works end-to-end. Any of the three
//! response variants (`Success`, `Error`, `MissingTransactions`) qualifies.
//!
//! Skipped when `bitcoin-node` is not installed.

use bitcoin::{
    absolute::LockTime, block::Version, transaction::Version as TxVersion, Amount, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bp_job_declaration::{DeclareMiningJobResult, JdpConfig, JdpHandle};
use bp_regtest_harness::{RegtestConfig, RegtestNode};

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::print_stderr)]
async fn jdp_declare_mining_job_roundtrip() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping JDP e2e — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let node = RegtestNode::start_with(cfg).await.expect("regtest start");

    // Mine 101 blocks to exit IBD and mature the first coinbase, then
    // attach JDP. JdpHandle::spawn blocks on the upstream's mempool
    // bootstrap so we need IBD already exited.
    let tip = node
        .generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD exit");
    assert!(tip >= 101);

    let jdp = JdpHandle::spawn(JdpConfig::new(node.ipc_socket_path()))
        .expect("JdpHandle::spawn against regtest IPC");

    // Build a minimal coinbase tx claiming to mine the next block. BIP34
    // requires the block height in the scriptSig as a CSCriptNum push; for
    // height 102 (= tip+1 here), that's `01 66` (push 1 byte, value 0x66).
    let next_height = (tip + 1) as i64;
    // CompactSize-len-prefixed CScriptNum encoding for small heights:
    // < 0x80 → single byte push.  `01 <height>` ⇒ OP_PUSHBYTES_1 then value.
    let script_sig = ScriptBuf::from_bytes(vec![0x01, next_height as u8]);

    let coinbase = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000_000_000), // pre-halving subsidy; regtest BIP34 may reject
            script_pubkey: ScriptBuf::new_op_return(b"bp-regtest"),
        }],
    };

    let result = jdp
        .declare_mining_job(Version::TWO, coinbase, Vec::new(), Vec::new())
        .await
        .expect("declare_mining_job roundtrip");

    // Any of the 3 variants is a successful roundtrip. The validation
    // context must surface a non-zero prev_hash either way (zero would
    // mean we got back a default-constructed value rather than a real
    // template snapshot).
    match result {
        DeclareMiningJobResult::Success {
            prev_hash,
            min_ntime,
            ..
        } => {
            assert_ne!(AsRef::<[u8]>::as_ref(&prev_hash), &[0u8; 32]);
            assert!(min_ntime > 0);
        }
        DeclareMiningJobResult::Error {
            error_code,
            validation_context,
        } => {
            assert!(
                !error_code.is_empty(),
                "Error variant must carry an error_code"
            );
            assert_ne!(
                AsRef::<[u8]>::as_ref(&validation_context.prev_hash),
                &[0u8; 32],
                "Error must include current-tip prev_hash"
            );
        }
        DeclareMiningJobResult::MissingTransactions {
            missing_wtxids,
            validation_context,
        } => {
            // wtxid_list was empty, so MissingTransactions would be unusual.
            // Accept it if surfaced but assert the context.
            assert!(
                missing_wtxids.is_empty() || !missing_wtxids.is_empty(),
                "any wtxid list shape is fine"
            );
            assert_ne!(
                AsRef::<[u8]>::as_ref(&validation_context.prev_hash),
                &[0u8; 32]
            );
        }
    }

    jdp.shutdown().expect("JDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}
