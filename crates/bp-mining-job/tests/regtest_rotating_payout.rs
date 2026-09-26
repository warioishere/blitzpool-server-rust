// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: **a rotating identity is paid the script bitcoin-core derives** —
//! the Phase 3 gate.
//!
//! What makes this a gate rather than another coinbase test is where the
//! expected value comes from. `payout_script`'s `Rotating` arm runs
//! `miniscript`'s `at_derivation_index(H).script_pubkey()`; asserting that
//! against the pool's own second call to the same function would prove only that
//! `miniscript` is deterministic. So the expectation is taken from the node:
//!
//! ```text
//! bitcoin-cli deriveaddresses "wpkh(<xpub>/0/*)" [H, H]
//! ```
//!
//! Core parses the descriptor with its own implementation, derives with its own
//! BIP-32 code, and renders with its own bech32 encoder. If the pool's script at
//! height `H` renders to that address, then the pool and the network agree about
//! whose money it is — which is the only claim worth making about a coinbase
//! output. Same-code-both-sides proves nothing.
//!
//! `deriveaddresses` needs no wallet and no import: it is a pure descriptor
//! function on the node, reached through the harness's generic
//! [`RegtestNode::rpc_call`] passthrough.
//!
//! ## The two properties
//!
//! 1. **Independent derivation agreement**, plus block acceptance — the coinbase
//!    paying the derived script is submitted and bitcoin-core advances the tip.
//!    Acceptance alone would not be enough (a coinbase paying *any* well-formed
//!    script is accepted), and agreement alone would not be enough (a script
//!    Core can derive but not validate in a block is still a broken payout);
//!    together they are the claim.
//! 2. **Orphan reconvergence** — height indexing is only safe if re-mining
//!    height `H` pays the same script. That is one assertion, and it is the
//!    reason the index is the height and not a counter.
//!
//! ## Shown to fail without the thing they claim
//!
//! Measured 2026-08-11 against v31.1, by mutating `payout_script`'s `Rotating`
//! arm and re-running:
//!
//! | mutation | both tests |
//! |---|---|
//! | `script_at(block_height.wrapping_add(1))` | **FAILED** |
//! | `script_at(0)` (height-invariant) | **FAILED** |
//!
//! The second mutation is the one worth having measured: an earlier draft of the
//! orphan test compared Core's `deriveaddresses` to itself across the reorg, and
//! it passed under *both* mutations — the pool's derivation never entered the
//! comparison. It now builds the coinbase through
//! `build_mining_job_from_tdp` on each side, which is also what makes it notice a
//! wrong height chosen by the *job builder* rather than by `script_at`.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed at the
//! host's default location or via `BITCOIN_NODE_PATH`.

use std::time::Duration;

use bitcoin::Network;
use bp_mining_job::{
    build_mining_job_from_tdp, decode_bip34_height, merkle_root_from_coinbase, PayoutEntry,
    TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_payout_descriptor::RotatingPayout;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{TdpConfig, TdpHandle};
use bp_test_support::{brute_force_nonce, poll_for_height, wait_for_paired_template};

/// BIP-32 test vector 1's master public key, in its **testnet** spelling.
///
/// A **real** key with a real base58 checksum — `Xpub::from_str` rejects a
/// fabricated one, intake would refuse it, and every assertion below would then
/// be measuring the refusal path instead of a payout.
///
/// `tpub` and not the `xpub` of the same key because **bitcoin-core network-checks
/// the keys inside a descriptor** and refuses mainnet magic bytes on regtest:
/// `deriveaddresses` answers `-5: wpkh(): key 'xpub…' is not valid`. Measured
/// 2026-08-11 against v31.1. Two things follow, and only one of them is about
/// this test:
///
/// - This gate must use the network's own spelling, or the independent side of
///   the comparison never runs and the test fails for a reason that has nothing
///   to do with payouts.
/// - The pool is **more permissive than Core here**: `miniscript` and
///   `RotatingPayout::address_at` will happily render a regtest address from a
///   mainnet xpub, so a miner on a testnet/regtest deployment can be admitted
///   with a key Core would not have accepted in a descriptor. That is not a
///   money bug — the key is still the miner's, and the derived output is still
///   theirs to spend — but it is the reason this constant is not simply the
///   `xpub` used in `bp-payout-descriptor`'s own unit tests, and it is worth
///   knowing before anyone adds a network assertion to intake.
const XPUB: &str = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";

/// The pool's own derived address at `height`, from the node's `deriveaddresses`.
///
/// **The independent side of the gate.** `canonical` is the descriptor string
/// the pool would publish to a miner, and Core is asked for `[height, height]`
/// — a one-element range at exactly the index the coinbase used.
///
/// Core requires a checksum on the descriptor it is handed. `RotatingPayout`'s
/// canonical form already carries one (`miniscript` appends `#xxxxxxxx` in
/// `to_string()`), and passing it through verbatim is deliberate: if the two
/// implementations disagreed about the checksum, Core would reject the call and
/// this test would fail loudly rather than silently comparing something else.
async fn core_derived_address(node: &RegtestNode, canonical: &str, height: u32) -> String {
    let out = node
        .rpc_call(
            "deriveaddresses",
            serde_json::json!([canonical, [height, height]]),
        )
        .await
        .unwrap_or_else(|e| {
            panic!("deriveaddresses({canonical}, [{height},{height}]) must succeed on Core: {e}")
        });
    let arr = out
        .as_array()
        .unwrap_or_else(|| panic!("deriveaddresses must return an array, got {out}"));
    assert_eq!(
        arr.len(),
        1,
        "a [H,H] range is one address; got {} for height {height}",
        arr.len()
    );
    arr[0]
        .as_str()
        .expect("deriveaddresses element is a string")
        .to_string()
}

/// The address the pool's coinbase output at `height` actually pays, rendered
/// from the raw script bytes the payout path produced.
///
/// Rendered rather than compared as bytes so the comparison is against Core's
/// own string, with no re-encoding on this side beyond `rust-bitcoin`'s
/// `Address::from_script` — which is the same call `ActualCoinbase` uses to
/// decide who a found block paid.
fn address_of_output(script: &bitcoin::Script) -> String {
    bitcoin::Address::from_script(script, Network::Regtest)
        .expect("a derived P2WPKH output must render as a regtest address")
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn a_rotating_identity_is_paid_the_script_core_derives_and_the_block_is_accepted() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping rotating-payout regtest — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    // Intake, not a hand-built identity: `into_payout_identity` is the only route
    // from a validated descriptor into the payout path, so going through it is
    // what makes this test exercise production's identity rather than a fixture's.
    let rotating = RotatingPayout::from_xpub_str(XPUB).expect("the test-vector xpub must be valid");
    let canonical = rotating.canonical_descriptor().to_string();
    let payout_id = rotating.payout_id().as_str().to_string();
    let identity = rotating.into_payout_identity();
    assert!(
        identity.rotates(),
        "the fixture must be a rotating identity or this test proves nothing about rotation"
    );

    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn");
    let mut rx = tdp.subscribe();
    drain_startup_pair(&mut rx).await;
    node.generate_to_self(1)
        .await
        .expect("mine 1 more to trigger a fresh NewTemplate");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // The height the payout path will derive at, read the same way
    // `payout_height` reads it — out of Core's own pre-encoded BIP-34 push. Read
    // here too, rather than assumed to be `tip + 1`, because it is the number the
    // assertions below have to agree on and the coinbase is the authority on it.
    let height = decode_bip34_height(&template.coinbase_prefix)
        .expect("Core's template must carry a decodable BIP-34 height push");
    let tip = node.current_height().await.expect("current_height");
    assert_eq!(
        height,
        tip + 1,
        "the template's BIP-34 height must be the next block; a mismatch means the \
         derivation index and the block being mined have come apart"
    );

    let reward_sats = template.coinbase_tx_value_remaining;
    let payouts = vec![PayoutEntry {
        identity: identity.clone(),
        sats: reward_sats,
    }];
    let job = build_mining_job_from_tdp(
        Network::Regtest,
        &payouts,
        &coinbase_template_from(&template),
        "rotating-regtest",
        EXTRANONCE_SLOT_LEN,
        [0u8; 32],
    )
    .expect("a rotating identity must build a coinbase");

    // ── Property 1a: the pool's output is the address CORE derives ──────
    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let coinbase_bytes = job.witness_coinbase_with_extranonce(&en1, &en2);
    let coinbase_tx = decode_coinbase(&coinbase_bytes);
    // Output 0 is the payout: `build_mining_job_from_tdp` prepends the pool's
    // payouts ahead of the template's own outputs (the witness commitment).
    let paid = address_of_output(&coinbase_tx.output[0].script_pubkey);
    let expected = core_derived_address(&node, &canonical, height).await;
    eprintln!(
        "[rotating] height={height} payout_id={payout_id} pool_paid={paid} core_derived={expected}"
    );
    assert_eq!(
        paid, expected,
        "the coinbase must pay the script bitcoin-core derives from the same \
         descriptor at height {height} — the pool and the network disagreeing about \
         whose output this is means the miner's money went somewhere else"
    );
    // The negative control for the assertion above, in the same test: the
    // NEIGHBOURING height derives a DIFFERENT address. Without it, a
    // `payout_script` that ignored the height (or a descriptor that had lost its
    // wildcard) would satisfy the equality above at every height and the gate
    // would pass while rotation did not happen.
    let next = core_derived_address(&node, &canonical, height + 1).await;
    assert_ne!(
        expected, next,
        "consecutive heights must derive different addresses, or the identity is \
         not rotating and the assertion above holds for the wrong reason"
    );
    assert_ne!(
        paid, payout_id,
        "the coinbase must pay the DERIVED script, never the ledger key — paying \
         the `payout_id` is the confusion the PayoutIdentity sum type exists to \
         prevent, and it is unspendable"
    );

    // ── Property 1b: bitcoin-core accepts a block paying it ─────────────
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
    .expect("must find a regtest-target-matching nonce within 1M tries");

    let before = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        coinbase_bytes.clone(),
    )
    .await
    .expect("submit_solution");
    let after = poll_for_height(&node, before + 1, Duration::from_secs(20))
        .await
        .expect(
            "bitcoin-core must accept a block whose coinbase pays a descriptor-derived \
             script — a stuck tip means the derived output is not a valid payout",
        );
    assert_eq!(after, before + 1);
    assert_eq!(
        after, height,
        "the accepted block must be the height the payout was derived at"
    );

    // The accepted chain's own copy of the coinbase, not our submitted bytes:
    // this is what a settlement path would read back, and it is the last place
    // the derived script could differ from what the network recorded.
    let on_chain = coinbase_paid_addresses(&node, height).await;
    assert!(
        on_chain.iter().any(|a| a == &expected),
        "the block bitcoin-core stored must contain the derived output {expected}; \
         it has {on_chain:?}"
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

/// **Orphan reconvergence, in one assertion.**
///
/// Indexing derivation on the block height is only safe if a re-mine of height
/// `H` pays the same script — otherwise an orphan would leave the pool having
/// promised one output and the surviving chain recording another, and a
/// settlement keyed on the rendered address (`ActualCoinbase`) would not
/// recognise the miner it just paid.
///
/// Driven through a real reorg rather than by calling the derivation twice:
/// `invalidateblock` on the tip puts height `H` genuinely back up for grabs, and
/// a **fresh TDP template** is taken for the re-mine, so the height the pool
/// derives at comes from Core's new BIP-34 push and not from a variable this test
/// carried across.
///
/// The compared value is the **pool's** coinbase output both times, not Core's
/// `deriveaddresses` both times. That distinction is the test: measured
/// 2026-08-11, mutating `payout_script`'s `Rotating` arm to
/// `script_at(block_height + 1)` leaves a Core-vs-Core version of this test
/// passing (both sides shift together) while this version fails on the first
/// pre-orphan derivation. The independent check lives in the test above; what
/// this one adds is that the pool's own answer is *stable across a reorg*.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn re_mining_a_height_after_an_orphan_pays_the_same_derived_script() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping rotating-payout orphan regtest — {}",
            cfg.unavailable_reason()
        );
        return;
    }

    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101).await.expect("mine 101");

    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn");
    let mut rx = tdp.subscribe();
    drain_startup_pair(&mut rx).await;

    let identity = RotatingPayout::from_xpub_str(XPUB)
        .expect("valid xpub")
        .into_payout_identity();

    // ── Round 1: the pool's payout for the block about to be mined ──────
    node.generate_to_self(1).await.expect("advance the tip");
    let (t1, _) = wait_for_paired_template(&mut rx).await;
    let h1 = decode_bip34_height(&t1.coinbase_prefix).expect("BIP-34 height");
    let paid_before = pool_paid_address(&identity, &t1);

    // Orphan the tip that round 1's template builds ON, so that height `h1` is
    // genuinely unclaimed again. `invalidateblock` returns `null`, which the
    // harness's RPC caller reports as an error while the side effect still lands
    // — the rollback assertion below is the real check (same treatment as
    // `bp-bitcoin`'s `regtest_block_header`).
    let orphaned = block_hash_at(&node, h1 - 1).await;
    let _ = node
        .rpc_call("invalidateblock", serde_json::json!([orphaned.clone()]))
        .await;
    let rolled_back = node.current_height().await.expect("current_height");
    assert_eq!(
        rolled_back,
        h1 - 2,
        "invalidateblock must actually roll the tip back, or nothing was orphaned \
         and the re-derivation below is not measuring a reorg"
    );

    // ── Round 2: re-mine up to the same height on the new branch ────────
    // One block, not two: the roll-back left the tip at `h1 - 2`, and this puts a
    // NEW block at `h1 - 1` — so the next template is again for `h1`, now built on
    // a different parent.
    node.generate_to_self(1)
        .await
        .expect("re-mine the orphaned height");
    assert_ne!(
        block_hash_at(&node, h1 - 1).await,
        orphaned,
        "height {} must be a different block after the reorg",
        h1 - 1
    );
    // Wait for the template that is FOR `h1`, rather than taking the first pair to
    // arrive: the reorg itself emits templates (one for `h1 - 1` as the branch is
    // rolled back), and reading one of those would compare two different heights
    // while the assertion that catches it lives inside this helper.
    let t2 = wait_for_template_at_height(&mut rx, h1).await;
    let paid_after = pool_paid_address(&identity, &t2);

    eprintln!("[rotating-orphan] height={h1} paid {paid_before} → {paid_after}");

    // The one assertion this test exists for.
    assert_eq!(
        paid_before, paid_after,
        "height {h1} must be paid the same script after an orphan reconvergence — \
         this is the property that makes indexing on the height safe, and without \
         it a re-mined block pays a different script than the pool promised for \
         that height"
    );
    // …and it is still the script CORE derives, on the new branch too. Without
    // this, an implementation that returned some constant script would satisfy
    // the equality above.
    assert_eq!(
        paid_after,
        core_derived_address(
            &node,
            RotatingPayout::from_xpub_str(XPUB)
                .expect("valid xpub")
                .canonical_descriptor(),
            h1,
        )
        .await,
        "the re-derived script must still be bitcoin-core's derivation at height {h1}"
    );

    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

// ── helpers ──────────────────────────────────────────────────────────────

/// The address the pool's coinbase would pay `identity` on `template`.
///
/// The whole payout path, not `script_at` directly: the coinbase is built,
/// serialized with an extranonce, decoded, and output 0 read back. A test that
/// called `script_at` itself would not notice `build_mining_job_from_tdp`
/// deriving at the wrong height — which is exactly the class of bug the height
/// is indexed to avoid.
fn pool_paid_address(
    identity: &bp_common::PayoutIdentity,
    template: &bp_template_distribution::NewTemplate,
) -> String {
    let payouts = vec![PayoutEntry {
        identity: identity.clone(),
        sats: template.coinbase_tx_value_remaining,
    }];
    let job = build_mining_job_from_tdp(
        Network::Regtest,
        &payouts,
        &coinbase_template_from(template),
        "rotating-regtest",
        EXTRANONCE_SLOT_LEN,
        [0u8; 32],
    )
    .expect("a rotating identity must build a coinbase");
    let bytes = job.witness_coinbase_with_extranonce(&[0u8; 4], &[0u8; 8]);
    // Output 0 is the payout: `build_mining_job_from_tdp` prepends the pool's
    // payouts ahead of the template's own outputs (the witness commitment).
    address_of_output(&decode_coinbase(&bytes).output[0].script_pubkey)
}

/// Discard the attach-time template pair.
///
/// It describes the CURRENT tip, and a block built for an already-mined height is
/// silently rejected — so every test here mines one more block afterwards to
/// force a fresh `NewTemplate`.
async fn drain_startup_pair(
    rx: &mut tokio::sync::broadcast::Receiver<bp_template_distribution::TemplateUpdate>,
) {
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if rx.recv().await.is_err() {
                break;
            }
        }
    })
    .await;
}

/// The next paired template whose BIP-34 height is exactly `height`.
///
/// Height-targeted rather than "the first pair after the reorg" because a reorg
/// emits templates for the heights it rolls back through, and those arrive first.
/// The height comes out of the template's own coinbase push — the same source
/// `payout_height` uses — so the wait and the derivation cannot disagree.
async fn wait_for_template_at_height(
    rx: &mut tokio::sync::broadcast::Receiver<bp_template_distribution::TemplateUpdate>,
    height: u32,
) -> bp_template_distribution::NewTemplate {
    let deadline = Duration::from_secs(30);
    tokio::time::timeout(deadline, async {
        loop {
            let (t, _) = wait_for_paired_template(rx).await;
            match decode_bip34_height(&t.coinbase_prefix) {
                Some(h) if h == height => return t,
                _ => continue,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no template for height {height} within {deadline:?}"))
}

async fn block_hash_at(node: &RegtestNode, height: u32) -> String {
    serde_json::from_value(
        node.rpc_call("getblockhash", serde_json::json!([height]))
            .await
            .unwrap_or_else(|e| panic!("getblockhash({height}): {e}")),
    )
    .expect("a block hash is a string")
}

fn coinbase_template_from(t: &bp_template_distribution::NewTemplate) -> TdpCoinbaseTemplate<'_> {
    TdpCoinbaseTemplate {
        coinbase_prefix: &t.coinbase_prefix,
        coinbase_tx_version: t.coinbase_tx_version,
        coinbase_tx_input_sequence: t.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: t.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &t.coinbase_tx_outputs,
        coinbase_tx_outputs_count: t.coinbase_tx_outputs_count,
        coinbase_tx_locktime: t.coinbase_tx_locktime,
    }
}

fn decode_coinbase(bytes: &[u8]) -> bitcoin::Transaction {
    use bitcoin::consensus::Decodable;
    bitcoin::Transaction::consensus_decode(&mut &bytes[..])
        .expect("the submitted coinbase must decode as a transaction")
}

/// Every address the coinbase of block `height` pays, read back out of the
/// node's own block store.
async fn coinbase_paid_addresses(node: &RegtestNode, height: u32) -> Vec<String> {
    let hash: String = serde_json::from_value(
        node.rpc_call("getblockhash", serde_json::json!([height]))
            .await
            .expect("getblockhash"),
    )
    .expect("hash is a string");
    // Verbosity 2 inlines the transactions, so no second round-trip per tx.
    let block = node
        .rpc_call("getblock", serde_json::json!([hash, 2]))
        .await
        .expect("getblock verbosity 2");
    let coinbase = &block["tx"][0];
    coinbase["vout"]
        .as_array()
        .expect("coinbase vout array")
        .iter()
        .filter_map(|o| o["scriptPubKey"]["address"].as_str().map(|s| s.to_string()))
        .collect()
}
