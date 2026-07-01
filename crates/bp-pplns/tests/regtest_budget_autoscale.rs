// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: the coinbase-budget autoscaler's **race-safe core/trimmer
//! coupling**, proven end-to-end against a real `bitcoin-node v31` regtest.
//!
//! Unit tests cover the control state machine + the budget→reservation
//! derivation in isolation. What they *cannot* prove — and what this test
//! does — is that the coupling actually matters at the consensus layer:
//!
//! 1. Fill the regtest mempool to ~3.85 MWU so bitcoin-core's
//!    `block_reserved_weight` (set from the IPC coinbase-output constraint)
//!    becomes the *binding* limit on coinbase size.
//! 2. With a SMALL reservation (`B0`) and a coinbase larger than it, submit →
//!    bitcoin-core **rejects** (block weight > 4 MWU): the chain must NOT
//!    advance. This is exactly the catastrophic case the coupling prevents.
//! 3. Re-advertise a LARGER reservation (`B1`) via
//!    `TdpHandle::set_coinbase_constraints` — the autoscaler's INCREASE action
//!    — using the binary's own `tdp_constraint_for_budget` derivation
//!    (`f(N) = N.div_ceil(4) + 256`). bitcoin-core's next template then leaves
//!    room for the same coinbase.
//! 4. Submit the same-sized coinbase → bitcoin-core **accepts**: the chain
//!    advances by 1.
//!
//! The differential — identical coinbase, only the reservation changed — is
//! the proof: raising core's reservation FIRST (what `apply_budget` does on an
//! increase) is what keeps a found block valid.

use std::collections::HashMap;
use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_pplns::{build_coinbase_distribution, CoinbaseDistributionInput};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{
    NewTemplate, SetNewPrevHash, TdpCoinbaseConstraints, TdpConfig, TdpHandle, TemplateUpdate,
};
use bp_test_support::wait_for_any_paired_template as wait_for_paired_template;
use bp_test_support::{brute_force_nonce, poll_for_height};
use serde_json::json;
use tokio::sync::broadcast;

const FEE_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const TEST_NETWORK: Network = Network::Bitcoin;
const REGTEST_BLOCK_REWARD_SATS: i64 = 5_000_000_000;

/// SMALL initial reservation — the coinbase below exceeds it by MORE than one
/// filler-tx weight, so the granularity gap left below core's tx-selection cap
/// can't absorb the overflow (that gap was why an earlier, smaller overflow
/// still fit). Mirrors a pool whose budget lags its payout count.
const B0_BUDGET: u32 = 50_000;
/// LARGER reservation the autoscaler steps up to — big enough for the coinbase.
const B1_BUDGET: u32 = 280_000;
/// Trimmer budget used to BUILD the coinbase distribution: generous so all
/// `MINER_COUNT` outputs survive, yielding a ~249 kWU coinbase that lands
/// strictly between core's `B0` (~51 kWU) and `B1` (~281 kWU) reservations.
const DIST_BUDGET: u32 = 350_000;
/// P2WPKH payout outputs in the coinbase (~124 WU each → ~249 kWU; ~62 kB,
/// under the 64 kB `B064K` submit limit).
const MINER_COUNT: usize = 2_000;
/// Mempool fill target in virtual bytes. Block limit is 1 M vbytes (4 MWU);
/// fill above core's `B0` tx-selection cap (~987 k vbytes) so it binds.
const MEMPOOL_TARGET_VBYTES: u64 = 990_000;

/// `f(N)` — identical derivation to `bin/blitzpool`'s
/// `boot::tdp_constraint_for_budget` (kept in sync; the production path is the
/// single source, this mirrors it for the test).
fn tdp_constraint_for_budget(weight_budget: u32) -> TdpCoinbaseConstraints {
    TdpCoinbaseConstraints {
        max_additional_size: weight_budget.div_ceil(4).saturating_add(256),
        max_additional_sigops: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn autoscale_reservation_raise_turns_rejected_block_into_accepted() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping autoscale coupling regtest — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // `-fallbackfee` so wallet `sendmany` works without fee estimation
    // (regtest has no fee history); `-spendzeroconfchange`/large mempool
    // limits aren't needed because each fill tx spends a mature coinbase.
    let node = RegtestNode::start_with(
        RegtestConfig::default().with_extra_args(["-fallbackfee=0.0002".to_string()]),
    )
    .await
    .expect("regtest start");
    node.ensure_wallet().await.expect("wallet");
    // Mature coinbases to fund the mempool-fill txs (each fill tx ideally
    // spends an independent mature coinbase to avoid mempool-chain limits).
    node.generate_to_self(140)
        .await
        .expect("mine 140 for maturity + funding");

    // ── Build the payout distribution (generous budget → all kept) ──────
    let miners = generate_p2wpkh_miners(MINER_COUNT);
    let mut address_shares: HashMap<AddressId, f64> = HashMap::with_capacity(miners.len());
    for m in &miners {
        address_shares.insert(m.clone(), 1.0);
    }
    let balances: HashMap<AddressId, Sats> = HashMap::new();
    let fee_addr = AddressId::new(FEE_ADDR.to_string()).expect("fee addr");
    let dist = build_coinbase_distribution(CoinbaseDistributionInput {
        address_shares: &address_shares,
        balances: &balances,
        block_reward_sats: Sats(REGTEST_BLOCK_REWARD_SATS),
        fee_percent: 1.5,
        fee_address: Some(&fee_addr),
        coinbase_weight_budget: DIST_BUDGET,
        suppress_matching_debits: false,
        min_payout_sats: None,
        finder_bonus_sats: None,
        finder_address: None,
    });
    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|e| PayoutEntry {
            address: e.address.as_str().to_string(),
            sats: e.sats.0 as u64,
        })
        .collect();
    eprintln!("[autoscale] distribution kept {} outputs", payouts.len());

    // ── Attach TDP with the SMALL B0 reservation ───────────────────────
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(tdp_constraint_for_budget(B0_BUDGET)),
    )
    .expect("TdpHandle::spawn");

    // Capture the bootstrap prev-hash (current tip). `SetNewPrevHash` is only
    // emitted on a tip change, not on mempool deltas — and we never mine here,
    // so this prev-hash stays valid for every template we build below.
    let mut rx = tdp.subscribe();
    let (_boot, prev) = wait_for_paired_template(&mut rx).await;

    // ── Fill the mempool so the reservation binds ───────────────────────
    fill_mempool(&node, MEMPOOL_TARGET_VBYTES).await;

    // ── Template under B0 (mempool full) → coinbase → expect REJECT ─────
    // Subscribe fresh AFTER the fill, then nudge: the emission triggered by the
    // nudge happens *after* we're listening, so the captured template reflects
    // the now-full mempool (an earlier template would carry too few txs).
    let mut rx0 = tdp.subscribe();
    nudge_template(&node).await;
    let tpl0 = wait_for_new_template(&mut rx0).await;
    let (job0, cb_weight) = build_job(&payouts, &tpl0);
    eprintln!(
        "[autoscale] coinbase weight {cb_weight} WU; B0 reserved ~{} WU, B1 reserved ~{} WU",
        reserved_weight(B0_BUDGET),
        reserved_weight(B1_BUDGET)
    );
    assert!(
        cb_weight > reserved_weight(B0_BUDGET),
        "test setup: coinbase ({cb_weight}) must exceed B0 reservation ({}) to overflow",
        reserved_weight(B0_BUDGET)
    );
    assert!(
        cb_weight < reserved_weight(B1_BUDGET),
        "test setup: coinbase ({cb_weight}) must fit B1 reservation ({})",
        reserved_weight(B1_BUDGET)
    );

    let before = node.current_height().await.expect("height");
    submit(&tdp, &tpl0, &prev, &job0).await;
    let advanced = poll_for_height(&node, before + 1, Duration::from_secs(8)).await;
    assert!(
        advanced.is_none(),
        "bitcoin-core MUST reject the oversized coinbase under the small B0 reservation \
         (chain advanced to {advanced:?}; reservation coupling not exercised — is the mempool \
         full enough? target {MEMPOOL_TARGET_VBYTES} vbytes)"
    );
    eprintln!("[autoscale] B0: block correctly REJECTED (chain held at {before})");

    // ── Autoscaler INCREASE: raise core's reservation to B1 ─────────────
    // Raise the reservation, THEN subscribe + nudge so the captured template is
    // built under the new (B1) reservation — fewer mempool txs, more coinbase
    // room. Tip is unchanged (no block mined) → reuse `prev`.
    let c1 = tdp_constraint_for_budget(B1_BUDGET);
    tdp.set_coinbase_constraints(c1.max_additional_size, c1.max_additional_sigops)
        .await
        .expect("set_coinbase_constraints (raise to B1)");
    let mut rx1 = tdp.subscribe();
    nudge_template(&node).await;
    let tpl1 = wait_for_new_template(&mut rx1).await;
    let (job1, _cb_weight1) = build_job(&payouts, &tpl1);

    let before = node.current_height().await.expect("height");
    submit(&tdp, &tpl1, &prev, &job1).await;
    let after = poll_for_height(&node, before + 1, Duration::from_secs(20))
        .await
        .unwrap_or_else_panic(
            "bitcoin-core MUST accept the same coinbase once B1 reservation is advertised — \
             if this fails the raise/coupling didn't take effect",
        );
    assert_eq!(
        after,
        before + 1,
        "chain must advance by exactly 1 after the raise"
    );
    eprintln!("[autoscale] B1: same coinbase ACCEPTED (chain {before} → {after})");

    tdp.shutdown().ok();
    node.shutdown().await.ok();
}

// ── helpers ─────────────────────────────────────────────────────────────

/// core's `block_reserved_weight` for a given budget: `f(N).size * 4`.
fn reserved_weight(budget: u32) -> u32 {
    tdp_constraint_for_budget(budget)
        .max_additional_size
        .saturating_mul(4)
}

/// Build the SV1 mining job from a TDP template + payout list; return
/// `(job, coinbase_weight_wu)`.
fn build_job(payouts: &[PayoutEntry], tpl: &NewTemplate) -> (bp_mining_job::MiningJob, u32) {
    let coinbase_template = TdpCoinbaseTemplate {
        coinbase_prefix: &tpl.coinbase_prefix,
        coinbase_tx_version: tpl.coinbase_tx_version,
        coinbase_tx_input_sequence: tpl.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: tpl.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &tpl.coinbase_tx_outputs,
        coinbase_tx_outputs_count: tpl.coinbase_tx_outputs_count,
        coinbase_tx_locktime: tpl.coinbase_tx_locktime,
    };
    let job = build_mining_job_from_tdp(
        TEST_NETWORK,
        payouts,
        &coinbase_template,
        "autoscale-rt",
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job_from_tdp");
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let witness = job.witness_coinbase_with_extranonce(&en1, &en2);
    let non_witness = decode_non_witness_with_extranonce(&job, &en1, &en2);
    let weight = (non_witness.len() as u32)
        .saturating_mul(3)
        .saturating_add(witness.len() as u32);
    (job, weight)
}

/// Brute-force a nonce and submit the solution via TDP.
#[allow(clippy::print_stderr)]
async fn submit(
    tdp: &TdpHandle,
    tpl: &NewTemplate,
    prev: &SetNewPrevHash,
    job: &bp_mining_job::MiningJob,
) {
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let witness = job.witness_coinbase_with_extranonce(&en1, &en2);
    let coinbase_hash = job.coinbase_txid_with_extranonce(&en1, &en2);
    let merkle_root = merkle_root_from_coinbase(&coinbase_hash, &tpl.merkle_path);
    let target = Target::from_le_bytes(prev.target);
    let nonce = brute_force_nonce(
        tpl.version,
        &prev.prev_hash,
        &merkle_root,
        prev.header_timestamp,
        prev.n_bits,
        &target,
    )
    .expect("find nonce on regtest");
    // submit_solution may surface a rejected block as an Err; for the reject
    // assertion the height check is authoritative, so ignore the result.
    let _ = tdp
        .submit_solution(
            tpl.template_id,
            tpl.version,
            prev.header_timestamp,
            nonce,
            witness,
        )
        .await;
}

/// Fill the mempool with large multi-output txs until its virtual size reaches
/// `target_vbytes`. Each tx pays many distinct addresses a tiny amount.
#[allow(clippy::print_stderr)]
async fn fill_mempool(node: &RegtestNode, target_vbytes: u64) {
    // Generate a reusable pool of recipient addresses (unique within a tx).
    const OUTPUTS_PER_TX: usize = 1_000;
    let mut recipients = serde_json::Map::with_capacity(OUTPUTS_PER_TX);
    for _ in 0..OUTPUTS_PER_TX {
        let addr = node.new_address("bech32").await.expect("addr");
        recipients.insert(addr, json!(0.0001));
    }
    let amounts = serde_json::Value::Object(recipients);

    let mut iterations = 0;
    loop {
        let info = node
            .rpc_call("getmempoolinfo", json!([]))
            .await
            .expect("getmempoolinfo");
        let vbytes = info.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        if vbytes >= target_vbytes {
            eprintln!("[autoscale] mempool filled: {vbytes} vbytes ({iterations} txs)");
            break;
        }
        match node.wallet_call("sendmany", json!(["", amounts])).await {
            Ok(_) => {}
            Err(e) => {
                // Out of funds / chain-limit: mine a block to confirm + free
                // UTXOs would empty the mempool, so instead just stop and let
                // the assertion report if we under-filled.
                eprintln!("[autoscale] sendmany stopped after {iterations} txs: {e}");
                break;
            }
        }
        iterations += 1;
        if iterations > 60 {
            eprintln!("[autoscale] mempool fill hit iteration cap at {iterations} txs");
            break;
        }
    }
}

/// Send one small wallet tx so the mempool changes and the TDP emits a fresh
/// template (the worker re-templates on mempool/fee deltas, not on a fixed
/// timer that would fire on a quiescent mempool).
async fn nudge_template(node: &RegtestNode) {
    let addr = node.new_address("bech32").await.expect("nudge addr");
    let _ = node
        .wallet_call("sendtoaddress", json!([addr, 0.001]))
        .await;
}

/// Wait for the first `NewTemplate` emitted on a freshly-subscribed receiver.
/// Used after a mempool nudge / reservation change: on a fresh subscription the
/// first template the worker emits reflects the current mempool + reservation
/// (mempool-driven updates carry no fresh `SetNewPrevHash`, so we don't pair by
/// id here — the caller reuses the bootstrap prev-hash, valid until a block is
/// mined). Tolerates one broadcast lag.
async fn wait_for_new_template(rx: &mut broadcast::Receiver<TemplateUpdate>) -> NewTemplate {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(750), rx.recv()).await {
            Ok(Ok(TemplateUpdate::NewTemplate(t))) => return t,
            Ok(Ok(_)) => {}
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => {}
        }
    }
    panic!("no NewTemplate observed from TDP within deadline");
}

fn decode_non_witness_with_extranonce(
    job: &bp_mining_job::MiningJob,
    en1: &[u8; 4],
    en2: &[u8; 8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(job.coinbase_prefix().len() + 12 + job.coinbase_suffix().len());
    out.extend_from_slice(job.coinbase_prefix());
    out.extend_from_slice(en1);
    out.extend_from_slice(en2);
    out.extend_from_slice(job.coinbase_suffix());
    out
}

fn generate_p2wpkh_miners(n: usize) -> Vec<AddressId> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey, KnownHrp};
    let secp = Secp256k1::new();
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            seed[8..16].copy_from_slice(b"autoscal");
            seed[16..24].copy_from_slice(b"e-budget");
            seed[24..32].copy_from_slice(b"-regtest");
            let sk = SecretKey::from_slice(&seed).expect("non-zero seed");
            let pk = CompressedPublicKey(sk.public_key(&secp));
            AddressId::new(Address::p2wpkh(&pk, KnownHrp::Mainnet).to_string())
                .expect("valid P2WPKH address")
        })
        .collect()
}

/// Tiny extension trait: `Option::unwrap_or_else_panic(msg)` reads better than
/// `.unwrap_or_else(|| panic!(msg))` at the call site.
trait UnwrapOrPanic<T> {
    fn unwrap_or_else_panic(self, msg: &str) -> T;
}
impl<T> UnwrapOrPanic<T> for Option<T> {
    fn unwrap_or_else_panic(self, msg: &str) -> T {
        match self {
            Some(v) => v,
            None => panic!("{msg}"),
        }
    }
}
