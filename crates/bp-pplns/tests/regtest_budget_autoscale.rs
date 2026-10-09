// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pins that core's coinbase reservation decides block validity: with a full
//! mempool the same coinbase is rejected under a small reservation and
//! accepted once the autoscaler raises it, which is why `apply_budget` raises
//! core's reservation first. Also pins the cut telemetry the autoscaler reads.

use std::collections::HashMap;
use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_pplns::{
    build_weight_distribution, WeightDistribution, WeightDistributionInput, WithheldValue,
};
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
/// Regtest subsidy at the test height; the §4 revenue the coinbase is
/// evaluated at.
const REGTEST_BLOCK_REWARD_SATS: u64 = 5_000_000_000;

/// Small reservation; the coinbase exceeds it by more than one filler tx, so
/// the gap below core's tx-selection cap cannot absorb the overflow.
const B0_BUDGET: u32 = 50_000;
/// LARGER reservation the autoscaler steps up to — big enough for the coinbase.
const B1_BUDGET: u32 = 280_000;
/// Budget the distribution is built at: no output is cut, so the coinbase
/// lands strictly between the `B0` and `B1` reservations.
const DIST_BUDGET: u32 = 350_000;
/// P2WPKH outputs in the coinbase; stays under the 64 kB `B064K` submit limit.
const MINER_COUNT: usize = 2_000;
/// Mempool fill target, above core's `B0` tx-selection cap so it binds.
const MEMPOOL_TARGET_VBYTES: u64 = 990_000;

/// Must match `boot::tdp_constraint_for_budget` in `bin/blitzpool`.
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
            "skipping autoscale coupling regtest — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    // Regtest has no fee history, so `sendmany` needs `-fallbackfee`.
    let node = RegtestNode::start_with(
        RegtestConfig::default().with_extra_args(["-fallbackfee=0.0002".to_string()]),
    )
    .await
    .expect("regtest start");
    node.ensure_wallet().await.expect("wallet");
    // Independent mature coinbases fund the fill txs without mempool-chain limits.
    node.generate_to_self(140)
        .await
        .expect("mine 140 for maturity + funding");

    // ── Telemetry: the same demand under pressure vs with headroom ──────
    let miners = generate_p2wpkh_miners(MINER_COUNT);
    let fee_addr = AddressId::new(FEE_ADDR.to_string()).expect("fee addr");

    // At the small budget the §4 cut fires: the autoscaler's increase signal.
    let pressured = build_distribution(&miners, &fee_addr, B0_BUDGET);
    assert!(
        pressured.budget_telemetry.utilization() >= 1.0,
        "under-budget build must report utilization ≥ 1.0 (got {})",
        pressured.budget_telemetry.utilization()
    );
    assert!(
        pressured.budget_telemetry.trimmed_count > 0,
        "under-budget build must report a firing cut"
    );

    // At the generous budget nothing is cut: the steady-state signal.
    let dist = build_distribution(&miners, &fee_addr, DIST_BUDGET);
    assert!(
        dist.budget_telemetry.utilization() < 1.0,
        "generous build must report headroom (got {})",
        dist.budget_telemetry.utilization()
    );
    assert_eq!(
        dist.budget_telemetry.trimmed_count, 0,
        "generous build must not cut"
    );
    assert_eq!(
        dist.published().count(),
        MINER_COUNT,
        "all miners must survive the generous budget"
    );
    assert_eq!(
        pressured.budget_telemetry.desired_weight, dist.budget_telemetry.desired_weight,
        "desired_weight is a property of the demand, not the budget"
    );

    // ── The §4 payout vector the coinbase is built from ────────────────
    // Evaluated once at the subsidy so the coinbase is byte-identical under
    // both templates; claiming less than the due is valid, so only the
    // reservation decides accept vs reject.
    let entries = dist
        .payout_entries_at(REGTEST_BLOCK_REWARD_SATS)
        .expect("§4 payout vector");
    let total: u64 = entries.iter().map(|(_, s)| *s).sum();
    assert_eq!(
        total, REGTEST_BLOCK_REWARD_SATS,
        "the §4 vector must consume exactly T"
    );
    let payouts: Vec<PayoutEntry> = entries
        .iter()
        .map(|(a, s)| PayoutEntry {
            address: a.as_str().to_string(),
            sats: *s,
        })
        .collect();
    eprintln!(
        "[autoscale] distribution published {} outputs (incl. pool output)",
        payouts.len()
    );

    // ── Attach TDP with the SMALL B0 reservation ───────────────────────
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(tdp_constraint_for_budget(B0_BUDGET)),
    )
    .expect("TdpHandle::spawn");

    // Nothing is mined below, so this prev-hash stays valid for every template.
    let mut rx = tdp.subscribe();
    let (_boot, prev) = wait_for_paired_template(&mut rx).await;

    // ── Fill the mempool so the reservation binds ───────────────────────
    fill_mempool(&node, MEMPOOL_TARGET_VBYTES).await;

    // ── Template under B0 (mempool full) → coinbase → expect REJECT ─────
    // Subscribe after the fill, then nudge, so the template reflects the full mempool.
    let mut rx0 = tdp.subscribe();
    nudge_template(&node).await;
    let tpl0 = wait_for_new_template(&mut rx0).await;
    let (job0, cb_weight) = build_job(&payouts, &tpl0, dist.fingerprint);
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
    // Raise first, then subscribe + nudge so the template is built under B1.
    let c1 = tdp_constraint_for_budget(B1_BUDGET);
    tdp.set_coinbase_constraints(c1.max_additional_size, c1.max_additional_sigops)
        .await
        .expect("set_coinbase_constraints (raise to B1)");
    let mut rx1 = tdp.subscribe();
    nudge_template(&node).await;
    let tpl1 = wait_for_new_template(&mut rx1).await;
    let (job1, _cb_weight1) = build_job(&payouts, &tpl1, dist.fingerprint);

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

/// Build the §4 weight distribution, one share per miner.
fn build_distribution(
    miners: &[AddressId],
    fee_addr: &AddressId,
    coinbase_weight_budget: u32,
) -> WeightDistribution {
    let mut address_shares: HashMap<AddressId, f64> = HashMap::with_capacity(miners.len());
    for m in miners {
        address_shares.insert(m.clone(), 1.0);
    }
    let balances: HashMap<AddressId, Sats> = HashMap::new();
    build_weight_distribution(WeightDistributionInput {
        address_shares: &address_shares,
        balances: &balances,
        fee_percent: 1.5,
        fee_address: fee_addr,
        coinbase_weight_budget,
        min_payout_sats: bp_common::Sats(bp_pplns::DUST_LIMIT_SATS as i64),
        finder_bonus_ppm: 0,
        finder_address: None,
        reference_revenue_sats: REGTEST_BLOCK_REWARD_SATS,
        withheld_value: WithheldValue::ToOtherMiners,
    })
    .expect("build_weight_distribution")
}

/// core's `block_reserved_weight` for a given budget: `f(N).size * 4`.
fn reserved_weight(budget: u32) -> u32 {
    tdp_constraint_for_budget(budget)
        .max_additional_size
        .saturating_mul(4)
}

/// Returns `(job, coinbase_weight_wu)`.
fn build_job(
    payouts: &[PayoutEntry],
    tpl: &NewTemplate,
    fingerprint: [u8; 32],
) -> (bp_mining_job::MiningJob, u32) {
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
        fingerprint,
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
    // The height check is authoritative, not the submit result.
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

/// Fill the mempool with large multi-output txs up to `target_vbytes`.
#[allow(clippy::print_stderr)]
async fn fill_mempool(node: &RegtestNode, target_vbytes: u64) {
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
                // Mining to free UTXOs would empty the mempool; let the
                // assertion report an under-fill instead.
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

/// Send one small tx: the TDP worker re-templates on mempool deltas only.
async fn nudge_template(node: &RegtestNode) {
    let addr = node.new_address("bech32").await.expect("nudge addr");
    let _ = node
        .wallet_call("sendtoaddress", json!([addr, 0.001]))
        .await;
}

/// First `NewTemplate` on a fresh subscription. Mempool-driven updates carry
/// no `SetNewPrevHash`, so there is no pairing; the caller reuses its prev-hash.
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
