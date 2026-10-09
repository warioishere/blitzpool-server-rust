// SPDX-License-Identifier: AGPL-3.0-or-later

//! The PPLNS coinbase blockspace cut (ext 0x0003 §4) end to end against a
//! real `bitcoin-node` regtest: cut math, the §4 payout vector, and core
//! accepting the coinbase within `max_additional_size`, so the per-address
//! weight table must match real serialized output sizes.

use std::collections::HashMap;
use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};
use bp_pplns::{build_weight_distribution, WeightDistributionInput, WithheldValue};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::wait_for_any_paired_template as wait_for_paired_template;
use bp_test_support::{brute_force_nonce, poll_for_height};

/// Default coinbase weight budget used across all three scenarios (50 000 WU).
const BUDGET: u32 = 50_000;

/// Pool output recipient. Mainnet HRP because regtest P2TR addresses exceed
/// `AddressId`'s 62-char limit; the scripts carry no HRP, so regtest
/// validates them like mainnet scripts.
const FEE_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

/// Mainnet for address parsing; see [`FEE_ADDR`].
const TEST_NETWORK: Network = Network::Bitcoin;

/// Regtest block reward; as §4 reference revenue it only has to be non-zero
/// here, since no balances or finder bonus are in play.
const REGTEST_BLOCK_REWARD_SATS: u64 = 5_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_blockspace_cut_pure_p2wpkh_fits_about_396_in_budget_50000() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping PPLNS blockspace-cut regtest (pure P2WPKH) — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    let miners = generate_p2wpkh_miners(420);
    let (kept_count, coinbase_weight_wu) =
        run_trim_scenario(miners, "pure-p2wpkh-pplns", 420).await;

    // Worst-case-only accounting would cap near 285; 396 proves the
    // per-address 124 WU path fires.
    assert_eq!(
        kept_count, 396,
        "pure P2WPKH cut count drifted (expected 396, got {kept_count}) — \
         either the cut math changed or per-output weight constants changed"
    );
    assert_eq!(
        coinbase_weight_wu, 49_788,
        "pure P2WPKH coinbase weight drifted (expected 49788 WU, got {coinbase_weight_wu})"
    );
    // Pins the budget cap even if the exact equality above is loosened.
    assert!(
        coinbase_weight_wu <= BUDGET,
        "coinbase weight {coinbase_weight_wu} WU exceeded budget {BUDGET} WU"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_blockspace_cut_pure_p2tr_caps_at_about_285_in_budget_50000() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping PPLNS blockspace-cut regtest (pure P2TR) — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    let miners = generate_p2tr_miners(320);
    let (kept_count, coinbase_weight_wu) = run_trim_scenario(miners, "pure-p2tr-pplns", 320).await;

    assert_eq!(
        kept_count, 285,
        "pure P2TR cut count drifted (expected 285, got {kept_count})"
    );
    assert_eq!(
        coinbase_weight_wu, 49_696,
        "pure P2TR coinbase weight drifted (expected 49696 WU, got {coinbase_weight_wu})"
    );
    assert!(
        coinbase_weight_wu <= BUDGET,
        "coinbase weight {coinbase_weight_wu} WU exceeded budget {BUDGET} WU"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_blockspace_cut_mixed_5050_lands_between_extremes() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping PPLNS blockspace-cut regtest (mixed P2WPKH/P2TR) — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    let miners = generate_mixed_p2wpkh_p2tr_miners(350);
    let (kept_count, coinbase_weight_wu) = run_trim_scenario(miners, "mixed-pplns", 350).await;

    // Equal shares, so the §4 tie-break (address asc) keeps all 175 P2TR
    // (`bc1p…` < `bc1q…`) before 153 P2WPKH.
    assert_eq!(
        kept_count, 328,
        "mixed cut count drifted (expected 328, got {kept_count})"
    );
    assert_eq!(
        coinbase_weight_wu, 49_732,
        "mixed coinbase weight drifted (expected 49732 WU, got {coinbase_weight_wu})"
    );
    assert!(
        coinbase_weight_wu <= BUDGET,
        "coinbase weight {coinbase_weight_wu} WU exceeded budget {BUDGET} WU"
    );
}

// ── Scenario runner ─────────────────────────────────────────────────────

/// Runs one cut scenario through to a block core accepts. Returns
/// `(kept_count, coinbase_weight_wu)`; `kept_count` excludes the pool output.
#[allow(clippy::print_stderr)]
async fn run_trim_scenario(
    miners: Vec<AddressId>,
    pool_identifier: &str,
    pushed_count: usize,
) -> (usize, u32) {
    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    let mut address_shares: HashMap<AddressId, f64> = HashMap::with_capacity(miners.len());
    for miner in &miners {
        address_shares.insert(miner.clone(), 1.0);
    }
    let balances: HashMap<AddressId, Sats> = HashMap::new();
    let fee_addr = AddressId::new(FEE_ADDR.to_string()).expect("valid fee addr");

    let dist = build_weight_distribution(WeightDistributionInput {
        address_shares: &address_shares,
        balances: &balances,
        fee_percent: 1.5,
        fee_address: &fee_addr,
        coinbase_weight_budget: BUDGET,
        min_payout_sats: bp_common::Sats(bp_pplns::DUST_LIMIT_SATS as i64),
        finder_bonus_ppm: 0,
        finder_address: None,
        reference_revenue_sats: REGTEST_BLOCK_REWARD_SATS,
        withheld_value: WithheldValue::ToOtherMiners,
    })
    .expect("build_weight_distribution");

    // The cut must have fired, and telemetry must report it to the autoscaler.
    let kept_miner_count = dist.published().count();
    assert!(
        kept_miner_count < pushed_count,
        "cut did not fire: kept {kept_miner_count} of {pushed_count}"
    );
    assert!(
        dist.budget_telemetry.trimmed_count > 0,
        "telemetry must report the cut"
    );
    assert_eq!(
        kept_miner_count + dist.budget_telemetry.trimmed_count as usize,
        pushed_count,
        "kept + trimmed must cover every pushed miner"
    );
    assert!(
        dist.budget_telemetry.utilization() >= 1.0,
        "a firing cut implies utilization ≥ 1.0 (got {})",
        dist.budget_telemetry.utilization()
    );
    // Cut miners get no output but keep their settlement score.
    assert_eq!(
        dist.entries.len(),
        pushed_count,
        "every pushed miner must stay in the distribution for settlement"
    );
    let folded_count = dist.entries.iter().filter(|e| e.wire_weight == 0).count();
    assert_eq!(
        folded_count, dist.budget_telemetry.trimmed_count as usize,
        "exactly the trimmed miners are folded to wire_weight 0"
    );
    assert!(
        dist.entries
            .iter()
            .filter(|e| e.wire_weight == 0)
            .all(|e| e.score_weight > 0),
        "folded miners keep their settlement score"
    );
    eprintln!(
        "[{pool_identifier}] pushed {pushed_count} miners → kept {kept_miner_count} \
         on-chain (+ 1 pool output), folded {folded_count} into weight_P"
    );

    // ── Attach TDP, drain initial pair, mine 1 for fresh template ───────
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

    // ── The §4 evaluation at this template's revenue ────────────────────
    // Σ must equal T exactly, or core rejects with `bad-cb-amount`.
    let reward = template.coinbase_tx_value_remaining;
    let entries = dist.payout_entries_at(reward).expect("§4 payout vector");
    assert_eq!(entries[0].0, fee_addr, "the pool output leads the §4 order");
    assert_eq!(
        entries.len(),
        1 + kept_miner_count,
        "no dust pruning at regtest reward scale — every kept miner pays out"
    );
    let total: u64 = entries.iter().map(|(_, s)| *s).sum();
    assert_eq!(total, reward, "the §4 vector must consume exactly T");

    let payouts: Vec<PayoutEntry> = entries
        .iter()
        .map(|(a, s)| PayoutEntry {
            address: a.as_str().to_string(),
            sats: *s,
        })
        .collect();

    // ── Build MiningJob ─────────────────────────────────────────────────
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
        TEST_NETWORK,
        &payouts,
        &coinbase_template,
        pool_identifier,
        EXTRANONCE_SLOT_LEN,
        dist.fingerprint,
    )
    .expect("build_mining_job_from_tdp must succeed with the cut payouts");

    // ── Measure the actual serialised coinbase weight ───────────────────
    // BIP-141 weight = (non-witness × 3) + total.
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let witness_bytes = job.witness_coinbase_with_extranonce(&en1, &en2);
    let non_witness_bytes = decode_non_witness_with_extranonce(&job, &en1, &en2);
    let coinbase_weight_wu = (non_witness_bytes.len() as u32)
        .saturating_mul(3)
        .saturating_add(witness_bytes.len() as u32);
    eprintln!(
        "[{pool_identifier}] coinbase weight {coinbase_weight_wu} WU \
         (non-witness {} bytes, witness {} bytes) — budget {BUDGET} WU",
        non_witness_bytes.len(),
        witness_bytes.len()
    );

    // ── Brute-force a nonce + submit via TDP ────────────────────────────
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

    let before_height = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        witness_bytes,
    )
    .await
    .expect("submit_solution");

    let after_height = poll_for_height(&node, before_height + 1, Duration::from_secs(20))
        .await
        .unwrap_or_else(|| {
            panic!(
                "bitcoin-core must accept the cut coinbase ({pool_identifier}) — \
                 if this fails, the cut emitted bytes beyond `max_additional_size` \
                 or beyond what core can validate"
            );
        });
    assert_eq!(
        after_height,
        before_height + 1,
        "chain must advance by exactly 1"
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");

    (kept_miner_count, coinbase_weight_wu)
}

// ── Miner-list generators ───────────────────────────────────────────────

/// Generate `n` deterministic P2WPKH addresses from fixed seeds.
fn generate_p2wpkh_miners(n: usize) -> Vec<AddressId> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey, KnownHrp};
    let secp = Secp256k1::new();
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            // The fixed tag avoids the all-zero secret key, invalid in secp256k1.
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            seed[8..16].copy_from_slice(b"p2wpkh01");
            seed[16..24].copy_from_slice(b"pplns-tr");
            seed[24..32].copy_from_slice(b"immer-rt");
            let sk = SecretKey::from_slice(&seed).expect("non-zero seed");
            let pk = CompressedPublicKey(sk.public_key(&secp));
            // Mainnet HRP: see [`FEE_ADDR`] doc-comment for rationale.
            AddressId::new(Address::p2wpkh(&pk, KnownHrp::Mainnet).to_string())
                .expect("valid P2WPKH address")
        })
        .collect()
}

/// Generate `n` deterministic P2TR regtest addresses.
fn generate_p2tr_miners(n: usize) -> Vec<AddressId> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, KnownHrp, XOnlyPublicKey};
    let secp = Secp256k1::new();
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            seed[8..16].copy_from_slice(b"p2tr-tag");
            seed[16..24].copy_from_slice(b"pplns-tr");
            seed[24..32].copy_from_slice(b"immer-rt");
            let sk = SecretKey::from_slice(&seed).expect("non-zero seed");
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(
                &bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk),
            );
            // Mainnet HRP: see [`FEE_ADDR`] doc-comment for rationale.
            AddressId::new(Address::p2tr(&secp, xonly, None, KnownHrp::Mainnet).to_string())
                .expect("valid P2TR address")
        })
        .collect()
}

/// 50/50 mix — even-index = P2WPKH (124 WU), odd-index = P2TR (172 WU).
fn generate_mixed_p2wpkh_p2tr_miners(n: usize) -> Vec<AddressId> {
    let p2wpkh = generate_p2wpkh_miners(n.div_ceil(2));
    let p2tr = generate_p2tr_miners(n / 2);
    let mut mixed: Vec<AddressId> = Vec::with_capacity(n);
    for i in 0..n {
        if i % 2 == 0 {
            mixed.push(p2wpkh[i / 2].clone());
        } else {
            mixed.push(p2tr[i / 2].clone());
        }
    }
    mixed
}

// ── Helpers ─────────────────────────────────────────────────────────────

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
