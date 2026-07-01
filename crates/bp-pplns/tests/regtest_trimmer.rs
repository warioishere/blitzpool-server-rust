// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifies the PPLNS **adaptive coinbase-weight trimmer** end-to-end against a real
//! `bitcoin-node v31` regtest validator.
//!
//! Architecturally this closes the loop between three layers:
//!
//! 1. **Trimmer math** (`bp_pplns::distribution::build_coinbase_distribution`)
//!    — sorts eligible miners by target, greedily fits outputs into
//!    the configured `coinbase_weight_budget` using *actual per-address
//!    output weights* (124 WU for P2WPKH, 172 WU for P2TR), and
//!    redistributes the trimmed-total back to kept-active miners
//!    proportional to shares.
//! 2. **Bytes assembly** (`bp_mining_job::build_mining_job_from_tdp`)
//!    — feeds the resulting `Vec<PayoutEntry>` into a real TDP
//!    template + emits a SegWit-clean coinbase.
//! 3. **bitcoin-core acceptance** (`TdpHandle::submit_solution`) —
//!    proves the assembled coinbase fits within the IPC-advertised
//!    `CoinbaseOutputConstraints.max_additional_size` and core
//!    relays the block.
//!
//! ## Three scenarios:
//!
//! - **pure P2WPKH ~398/420 in budget 50 000** — adaptive logic uses
//!   124 WU per output (the actual P2WPKH cost), not the conservative
//!   172 WU upper bound. Available WU = `50000 - 200 (margin) - 328
//!   (base) - 188 (commit) - 124 (fee) = 49160`; floor(49160 / 124) =
//!   396 max miners. Push 420 → trim ≥ 24.
//! - **pure P2TR ~286/320 in budget 50 000** — P2TR outputs cost
//!   172 WU (= conservative constant). Available WU = `50000 - 200 -
//!   328 - 188 - 172 = 49112`; floor(49112 / 172) = 285 max. Push 320
//!   → trim ≥ 34.
//! - **50/50 P2WPKH/P2TR mix lands between the extremes** — per-pair
//!   cost ≈ 296 WU; max ~332 miners; push 350 → trim ~18.
//!
//! ## What this regtest guards that unit tests can't
//!
//! - **`max_additional_size` coupling** (bin/blitzpool's
//!   `coinbase_constraints_from_pplns_budget`) — bitcoin-core was told
//!   how much room to reserve based on `coinbase_weight_budget`; the
//!   trimmer's output must actually fit, or core rejects.
//! - **End-to-end SegWit block weight**: `total_block_weight ≤ 4 M`
//!   including the witness commitment + the coinbase witness.
//! - **Bytes-acceptance per address type** under realistic mix — the
//!   trimmer's per-address weight table (`output_weight_for_address`)
//!   must match the *actual* serialised output size, or budget
//!   accounting drifts from reality.
//!
//! Skipped (with a printed warning) when `bitcoin-node v31` isn't
//! installed at the host's default location or via `BITCOIN_NODE_PATH`.

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
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::wait_for_any_paired_template as wait_for_paired_template;
use bp_test_support::{brute_force_nonce, poll_for_height};

/// Default coinbase weight budget used across all three scenarios (50 000 WU).
const BUDGET: u32 = 50_000;

/// Pool fee output address (P2WPKH). The trimmer always emits the fee
/// output BEFORE the miner outputs, so it consumes one slot's worth of
/// weight from the budget. Use a P2WPKH (124 WU) for the fee output.
///
/// **Mainnet HRP** (not regtest): regtest P2TR addresses are 64 chars
/// long, which exceeds `AddressId`'s 62-char DB-column limit. P2WPKH +
/// P2TR scripts are network-independent (`OP_0 <hash>` / `OP_1 <xonly>`,
/// no hrp encoded in the script bytes), so bitcoin-core regtest
/// validates them identically to mainnet scripts. The mining-job
/// builder uses `Network::Bitcoin` for address parsing but the
/// resulting coinbase bytes are submitted to regtest, which accepts
/// any well-formed scriptPubKey.
const FEE_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

/// Network used for `build_mining_job_from_tdp` address parsing. See
/// [`FEE_ADDR`] for why mainnet (not regtest).
const TEST_NETWORK: Network = Network::Bitcoin;

/// Bitcoin-core regtest block reward (50 BTC at block 102 = 5_000_000_000 sats).
const REGTEST_BLOCK_REWARD_SATS: i64 = 5_000_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_adaptive_trim_pure_p2wpkh_fits_about_398_in_budget_50000() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping PPLNS trimmer regtest (pure P2WPKH) — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let miners = generate_p2wpkh_miners(420);
    let (kept_count, coinbase_weight_wu) =
        run_trim_scenario(miners, "pure-p2wpkh-pplns", 420).await;

    // Deterministic outcome of the adaptive trim against a fixed
    // 420-miner P2WPKH input with the production budget (50 000 WU)
    // and safety margin. The conservative-only formula would cap
    // around 286 — confirming the adaptive 124 WU/output path
    // actually fires would show kept_count well above that.
    assert_eq!(
        kept_count, 396,
        "pure P2WPKH adaptive trim count drifted (expected 396, got {kept_count}) — \
         either the trim math changed or per-output weight constants changed"
    );
    assert_eq!(
        coinbase_weight_wu, 49_788,
        "pure P2WPKH coinbase weight drifted (expected 49788 WU, got {coinbase_weight_wu})"
    );
    // Hard invariant kept as defense-in-depth — if the equality above
    // is loosened in a future refactor this still pins the budget cap.
    assert!(
        coinbase_weight_wu <= BUDGET,
        "coinbase weight {coinbase_weight_wu} WU exceeded budget {BUDGET} WU"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn pplns_adaptive_trim_pure_p2tr_caps_at_about_286_in_budget_50000() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping PPLNS trimmer regtest (pure P2TR) — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let miners = generate_p2tr_miners(320);
    let (kept_count, coinbase_weight_wu) = run_trim_scenario(miners, "pure-p2tr-pplns", 320).await;

    // Deterministic outcome — 320 P2TR miners (172 WU each), 50 000
    // WU budget less fixed weight + safety margin.
    assert_eq!(
        kept_count, 285,
        "pure P2TR adaptive trim count drifted (expected 285, got {kept_count})"
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
async fn pplns_adaptive_trim_mixed_5050_lands_between_extremes() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping PPLNS trimmer regtest (mixed P2WPKH/P2TR) — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let miners = generate_mixed_p2wpkh_p2tr_miners(350);
    let (kept_count, coinbase_weight_wu) = run_trim_scenario(miners, "mixed-pplns", 350).await;

    // Deterministic outcome — 350 alternating P2WPKH/P2TR miners
    // (avg 148 WU/output) fit between the pure-P2TR floor and the
    // pure-P2WPKH ceiling.
    assert_eq!(
        kept_count, 328,
        "mixed adaptive trim count drifted (expected 328, got {kept_count})"
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

/// Drive one trimmer-scenario end-to-end:
/// 1. Boot bitcoind regtest + mine past IBD.
/// 2. Build PPLNS `CoinbaseDistributionInput` from the miner list with
///    1 share each + the configured budget.
/// 3. Call `build_coinbase_distribution` → `Vec<CoinbaseDistributionEntry>`.
/// 4. Convert to `Vec<PayoutEntry>` + feed through TDP+MiningJob.
/// 5. Brute-force a nonce + submit_solution.
/// 6. Assert chain advanced + coinbase weight respected the budget.
///
/// Returns `(kept_count, coinbase_weight_wu)` for per-scenario assertions.
/// `kept_count` excludes the fee output.
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

    // PPLNS trimmer input — 1 share per miner = even split before trim.
    let mut address_shares: HashMap<AddressId, f64> = HashMap::with_capacity(miners.len());
    for miner in &miners {
        address_shares.insert(miner.clone(), 1.0);
    }
    let balances: HashMap<AddressId, Sats> = HashMap::new();
    let fee_addr = AddressId::new(FEE_ADDR.to_string()).expect("valid fee addr");

    let dist = build_coinbase_distribution(CoinbaseDistributionInput {
        address_shares: &address_shares,
        balances: &balances,
        block_reward_sats: Sats(REGTEST_BLOCK_REWARD_SATS),
        fee_percent: 1.5,
        fee_address: Some(&fee_addr),
        coinbase_weight_budget: BUDGET,
        suppress_matching_debits: false,
        min_payout_sats: None,
        finder_bonus_sats: None,
        finder_address: None,
    });

    // Count miner outputs excluding the fee (which always sits at index 0).
    let kept_miner_count = dist
        .payouts
        .iter()
        .filter(|p| p.address.as_str() != FEE_ADDR)
        .count();
    eprintln!(
        "[{pool_identifier}] pushed {pushed_count} miners → kept {kept_miner_count} \
         on-chain (+ 1 fee output)"
    );

    // Translate distribution → PayoutEntry list (the shape
    // `build_mining_job_from_tdp` consumes — address + percent).
    let payouts: Vec<PayoutEntry> = dist
        .payouts
        .iter()
        .map(|e| PayoutEntry {
            address: e.address.as_str().to_string(),
            sats: e.sats.0 as u64,
        })
        .collect();

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
    )
    .expect("build_mining_job_from_tdp must succeed with trimmed payouts");

    // ── Measure the actual serialised coinbase weight ───────────────────
    //
    // BIP-141 weight = (non-witness × 3) + total. The mining-job
    // `witness_coinbase_with_extranonce` produces the full SegWit bytes
    // (with witness reserved value), and `decode_non_witness_with_extranonce`
    // produces the marker-less form (= non-witness bytes).
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
                "bitcoin-core must accept the trimmer's coinbase ({pool_identifier}) — \
                 if this fails, the trimmer emitted bytes beyond `max_additional_size` \
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

/// Generate `n` deterministic P2WPKH regtest addresses derived from
/// fixed-byte secret-key seeds. The keys aren't spendable from any
/// wallet — coinbase output validity only depends on script
/// well-formedness, not key custody.
fn generate_p2wpkh_miners(n: usize) -> Vec<AddressId> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey, KnownHrp};
    let secp = Secp256k1::new();
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            // High-entropy seed: index in bytes 0..8 + a fixed tag in 8..32.
            // Avoids the all-zero secret key (invalid in secp256k1).
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

// ── Helpers (mirror bp-mining-job/tests/regtest_e2e.rs) ─────────────────

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
