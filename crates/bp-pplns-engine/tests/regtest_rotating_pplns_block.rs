// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Regtest: **a rotating miner is paid and booked through the whole PPLNS
//! path** — the Phase 4b gate, and the PPLNS form of the Phase 3 one in
//! `bp-mining-job/tests/regtest_rotating_payout.rs`.
//!
//! Phase 3 proved a rotating identity reaches a *Solo* coinbase. Solo has one
//! output and no ledger, so it could not show either of the two things PPLNS
//! adds:
//!
//! 1. **The distribution has to keep the row.** A `payout_id` is not an
//!    address, so `sanitize_and_build`'s payability retain drops it unless the
//!    build was told the key is payable. That retain runs *above* the score
//!    total, so a dropped row is not withheld — the other miners are simply
//!    paid its share while its ledger balance stands, and the pool then owes
//!    more than the block paid. Asserted here as a precondition
//!    (`is_payable_payout_key(payout_id, {}) == false`) plus the survival of
//!    the entry: the row is in the distribution *because* the installed
//!    resolver vouched for it, which is the Amendment-2 seam.
//! 2. **The ledger key is height-invariant, and the second block is what
//!    shows it.** Two found blocks at two heights pay two different derived
//!    addresses. If the ledger were keyed on what the coinbase paid, that
//!    would be two `pplns_balance` rows for one miner — each holding half of
//!    what it is owed, so neither clears `min_payout` on its own and the
//!    money never leaves. One row across both heights is the claim, and the
//!    two derived addresses being different is what makes it a claim at all
//!    (asserted, not assumed).
//!
//! The expected address comes from **bitcoin-core**, not from a second call to
//! the pool's own derivation:
//!
//! ```text
//! bitcoin-cli deriveaddresses "wpkh(<tpub>/0/*)" [H, H]
//! ```
//!
//! Core parses the descriptor, derives, and encodes with its own code. Same-code
//! -both-sides would only prove `miniscript` is deterministic.
//!
//! ## Shown to fail without the things it claims
//!
//! Measured 2026-08-11 against v31.1, by mutating the production code and
//! re-running this test:
//!
//! | mutation | result |
//! |---|---|
//! | `is_payable_payout_key` drops the `\|\| derived.contains(key)` arm | **FAILED** — the rotating row is gone from the distribution, and the two surviving miners are paid `3_283_333_333` / `1_641_666_666` instead of their `2_462_500_000` / `1_641_666_666`: the dropped miner's share, divided among the survivors, with the pool still taking exactly its 1.5 % |
//! | the outsider loop's `!paid_at.claims(addr)` back to the pre-Phase-4a `!snapshot.entries.contains(addr)` | **FAILED** — the derived address is booked as an outsider, so the miner is credited `2_462_500_000` under its `payout_id` and debited the same amount under a `bcrt1…` that moves every block |
//! | `addresses_to_settle` drops its `!paid_at.claims(addr)` filter | passed — that filter decides only which rows are LOCKED; the row itself is minted (or not) by the outsider loop above, which is where the second mutation bit |
//!
//! Skips cleanly when `bitcoin-node`, Redis or Postgres are unavailable — with a
//! printed line, which is the only reason the skip is visible under
//! `--nocapture`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use bp_coinbase_snapshot::{
    ActualCoinbase, PaidAtHeight, PaidAtHeightError, PayoutIdentityResolver,
};
use bp_common::{AddressId, PayoutIdentity, Sats};
use bp_mining_job::{
    build_mining_job_from_tdp, decode_bip34_height, merkle_root_from_coinbase, PayoutEntry,
    TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_payout_descriptor::RotatingPayout;
use bp_pplns::DEFAULT_MIN_PAYOUT_SATS;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::window::NetworkDifficulty;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Target;
use bp_template_distribution::{NewTemplate, TdpConfig, TdpHandle, TemplateUpdate};
use bp_test_support::{
    brute_force_nonce, connect_pg_or_skip, connect_redis_in_range_or_skip,
    deterministic_p2wpkh_regtest, poll_for_height, wait_for_paired_template,
};
use sqlx::PgPool;

/// BIP-32 test vector 1's master public key in its **testnet** spelling — the
/// same fixture, and for the same reason, as the Phase 3 gate: bitcoin-core
/// network-checks the keys inside a descriptor and answers
/// `-5: wpkh(): key 'xpub…' is not valid` on regtest, so a mainnet `xpub` would
/// make `deriveaddresses` fail and the independent side of the comparison would
/// never run.
const XPUB: &str = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";

/// This test's logical DB inside the binary's range.
// Index 20 inside `redis_db::RT_ROTATING_PPLNS_BLOCK`, which shares its base
// with `SESSION_PERSISTENCE` — see that constant for the occupied indices.
const REDIS_TEST_DB: u8 = 20;

/// The resolver `bin/blitzpool` installs, reduced to what a test can hold: a
/// map of the rotating identities it knows.
///
/// It is a stand-in for `PoolPaidAddresses` and deliberately shares its one
/// piece of real logic — `PaidAtHeight::resolve`, the crate's own
/// key→identity→address lowering — rather than deriving addresses itself. A test
/// double that did its own derivation would agree with the pool by construction
/// and the gate would measure nothing.
#[derive(Debug, Default)]
struct TestIdentities {
    rotating: HashMap<String, PayoutIdentity>,
}

impl TestIdentities {
    fn with(identity: PayoutIdentity) -> Self {
        let mut rotating = HashMap::new();
        rotating.insert(identity.payout_id().to_string(), identity);
        Self { rotating }
    }
}

#[async_trait::async_trait]
impl PayoutIdentityResolver for TestIdentities {
    async fn paid_at_height(
        &self,
        ledger_keys: &[String],
        height: u32,
    ) -> Result<PaidAtHeight, PaidAtHeightError> {
        // A key this does not know is its own address — the static case, and the
        // only other thing a PPLNS window holds.
        let identities: Vec<PayoutIdentity> = ledger_keys
            .iter()
            .map(|key| match self.rotating.get(key) {
                Some(identity) => identity.clone(),
                None => PayoutIdentity::static_address_verbatim(key.clone()),
            })
            .collect();
        PaidAtHeight::resolve(identities.iter(), Network::Regtest, height)
    }

    async fn derived_payout_keys(&self, ledger_keys: &[String]) -> HashSet<String> {
        ledger_keys
            .iter()
            .filter(|key| self.rotating.contains_key(*key))
            .cloned()
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rotating_pplns_miner_is_paid_the_script_core_derives_and_books_one_ledger_row() {
    let regtest_cfg = RegtestConfig::default();
    if !regtest_cfg.is_available() {
        eprintln!(
            "skipping rotating-PPLNS regtest — {}",
            regtest_cfg.unavailable_reason()
        );
        return;
    }
    let Some(redis_conn) = connect_redis_in_range_or_skip(
        bp_test_support::redis_db::RT_ROTATING_PPLNS_BLOCK,
        REDIS_TEST_DB,
    )
    .await
    else {
        return;
    };
    let Some(pg) = connect_pg_or_skip().await else {
        return;
    };

    // ── The rotating miner, through intake's own constructor ─────────────
    let rotating = RotatingPayout::from_xpub_str(XPUB).expect("the test-vector tpub must be valid");
    let canonical = rotating.canonical_descriptor().to_string();
    let payout_id = rotating.payout_id().as_str().to_string();
    let identity = rotating.into_payout_identity();

    // The preconditions that make everything below a measurement of the
    // rotating path rather than of an address that happens to work.
    assert!(
        !bp_pplns::is_valid_payout_address(&payout_id),
        "a payout_id must NOT parse as an address — if it did, the distribution \
         would keep this row for the ordinary reason and the resolver's vouching \
         would not be under test"
    );
    assert!(
        !bp_pplns::is_payable_payout_key(&payout_id, &HashSet::new()),
        "and with no derived set it is unpayable: this is exactly the row \
         `sanitize_and_build` drops, above the score total, handing its share to \
         the other miners"
    );

    let addr_alice = deterministic_p2wpkh_regtest([0x71; 32]);
    let addr_bob = deterministic_p2wpkh_regtest([0x72; 32]);
    let addr_fee = deterministic_p2wpkh_regtest([0x7f; 32]);

    // A previous run's rows are this test's biggest lie. The heights come from a
    // fresh regtest chain, so they repeat run to run: leftover
    // `pplns_payout_history` rows at those heights make `apply_distribution`
    // idempotent-skip (nothing inserted, so nothing booked) while every assertion
    // about *this* run's totals reads the old numbers. The Redis window is
    // FLUSHDB'd by `connect_redis_in_range_or_skip`; Postgres is not, so clear
    // the ledger side here and the per-height rows as each height is known.
    delete_balances(&pg, &[&payout_id, &addr_alice, &addr_bob]).await;

    let engine = PplnsEngine::spawn(
        test_engine_config(&addr_fee),
        redis_conn,
        pg.clone(),
        NetworkDifficulty::new(1_000.0),
    )
    .await
    .expect("PplnsEngine::spawn");
    assert!(
        engine.install_payout_identity_resolver(Arc::new(TestIdentities::with(identity.clone()))),
        "the resolver must install: without it the default StaticPaidAddresses \
         drops this miner from every distribution"
    );

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    for (key, weight) in [
        (&payout_id, 300.0),
        (&addr_alice, 200.0),
        (&addr_bob, 100.0),
    ] {
        engine
            .record_share(None, key, weight, now_ms)
            .await
            .expect("seed share");
    }

    // ── Node + template ─────────────────────────────────────────────────
    let node = RegtestNode::start_with(regtest_cfg)
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
    .expect("TdpHandle::spawn against regtest IPC");
    let mut rx = tdp.subscribe();
    drain_startup_pair(&mut rx).await;
    node.generate_to_self(1)
        .await
        .expect("mine 1 more to force a fresh NewTemplate");
    let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

    // ── Block 1 ─────────────────────────────────────────────────────────
    let first = mine_a_pplns_block(
        &engine, &node, &tdp, &pg, &template, &prev_hash, &payout_id, &identity, &canonical,
    )
    .await;

    // The ledger books the rotating miner under its LEDGER key, for what the
    // coinbase paid at the derived address — and nothing under that address.
    let history = history_rows(&pg, first.height).await;
    let booked = history
        .iter()
        .find(|(address, _)| address == &payout_id)
        .unwrap_or_else(|| panic!("no history row under the payout_id: {history:?}"));
    assert_eq!(
        booked.1 as u64, first.paid_sats,
        "the rotating miner's row must record what the block's own coinbase paid \
         at its derived address"
    );
    assert!(
        !history.iter().any(|(address, _)| address == &first.paid_to),
        "and nothing may be booked under the derived address {} — that row would \
         be a new one every block: {history:?}",
        first.paid_to
    );
    assert_eq!(
        balance_row_count(&pg, &payout_id).await,
        1,
        "one ledger row for the miner"
    );

    // ── Block 2, one height later ───────────────────────────────────────
    //
    // The submitted block moved the tip, so the next template is for `H + 1`.
    // Height-targeted rather than "the next pair", because the pair that arrives
    // first can still be the one built on the pre-submit tip.
    let (template2, prev_hash2) = wait_for_pair_at_height(&mut rx, first.height + 1).await;
    let second = mine_a_pplns_block(
        &engine,
        &node,
        &tdp,
        &pg,
        &template2,
        &prev_hash2,
        &payout_id,
        &identity,
        &canonical,
    )
    .await;

    assert_ne!(
        first.paid_to, second.paid_to,
        "the two blocks must pay two DIFFERENT derived addresses, or the \
         single-ledger-row assertion below holds for a miner that never rotated"
    );
    assert_eq!(second.height, first.height + 1);

    // **The carry-forward.** Two blocks, two paid addresses, one ledger row.
    assert_eq!(
        balance_row_count(&pg, &payout_id).await,
        1,
        "a rotating miner must keep ONE ledger row across blocks: a row per \
         derived address would split what it is owed into per-block fragments, \
         none of which clears min_payout"
    );
    assert_eq!(
        balance_row_count(&pg, &first.paid_to).await,
        0,
        "and no row under block 1's derived address"
    );
    assert_eq!(
        balance_row_count(&pg, &second.paid_to).await,
        0,
        "nor block 2's — this pair is the shape the ledger key exists to prevent"
    );

    let history2 = history_rows(&pg, second.height).await;
    assert!(
        history2.iter().any(|(address, _)| address == &payout_id),
        "block 2 books under the same key: {history2:?}"
    );
    let total_paid = total_paid_sats(&pg, &payout_id).await;
    assert_eq!(
        total_paid,
        (first.paid_sats + second.paid_sats) as i64,
        "and the lifetime total is both blocks' payments on the one row — which \
         is the number a payout threshold and every operator report read"
    );

    // ── Teardown ────────────────────────────────────────────────────────
    engine.shutdown();
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
    for height in [first.height, second.height] {
        let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(height as i32)
            .execute(&pg)
            .await;
    }
    delete_balances(
        &pg,
        &[
            &payout_id,
            &addr_alice,
            &addr_bob,
            &first.paid_to,
            &second.paid_to,
        ],
    )
    .await;
}

/// What one mined block leaves behind for the assertions.
struct MinedBlock {
    height: u32,
    /// The address the coinbase paid the rotating miner — bitcoin-core's own
    /// derivation at this height.
    paid_to: String,
    /// What that output was worth.
    paid_sats: u64,
}

/// Build this template's PPLNS distribution, cross-check the rotating miner's
/// output against Core's derivation, submit the block, and book it.
///
/// One helper for both blocks: the second block is the same path at a different
/// height, and writing it twice is how the two would drift.
#[allow(clippy::too_many_arguments)]
async fn mine_a_pplns_block(
    engine: &PplnsEngine,
    node: &RegtestNode,
    tdp: &TdpHandle,
    pg: &PgPool,
    template: &NewTemplate,
    prev_hash: &bp_template_distribution::SetNewPrevHash,
    payout_id: &str,
    identity: &PayoutIdentity,
    canonical: &str,
) -> MinedBlock {
    // The height the payout derives at, out of Core's own BIP-34 push — the same
    // source `payout_height` reads, so the assertions cannot disagree with the
    // coinbase about which block this is.
    let height = decode_bip34_height(&template.coinbase_prefix)
        .expect("Core's template must carry a decodable BIP-34 height push");

    // Core's derivation at this height. Read BEFORE the build, because the row it
    // names has to be gone before the build reads the ledger — see below.
    let expected = core_derived_address(node, canonical, height).await;

    // A previous run's rows are this test's biggest lie, and this is the delete
    // that matters most. `build_distribution` loads EVERY open-balance row in
    // `pplns_balance`, pool-wide, so a leftover balance under *this* height's
    // derived address (regtest heights repeat run to run, so it is the same
    // address every time) is picked up as an ordinary repayment and given its own
    // entry — at the very address the rotating miner is being paid. The coinbase
    // then holds two outputs there, `ActualCoinbase` sums them, and the sats no
    // longer match the one entry the distribution assigned the ledger key.
    //
    // Measured 2026-08-12 by seeding a 500_000-sat row at
    // `bcrt1qc4eel4d0af74rdsuphcjl669g7jq65jcgf56kg` (height 103's derivation)
    // and running with these two deletes moved back below the build, where they
    // used to be: FAILED at the booking precondition, `left: Some(2462749999)`
    // vs `right: Some(2462250000)`. Clearing it after the build does not help —
    // the extra output is already in the coinbase by then.
    //
    // This cannot weaken the "nothing is booked under the derived address"
    // assertions: those read the table AFTER `on_block_found`, and the second
    // mutation in the table at the top of this file shows they still bite.
    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
        .bind(height as i32)
        .execute(pg)
        .await;
    delete_balances(pg, &[&expected]).await;

    let reward_sats = template.coinbase_tx_value_remaining;
    let dist = engine
        .build_distribution(reward_sats)
        .await
        .expect("build_distribution");
    let fingerprint = dist.payouts_fingerprint();
    let entries = dist
        .distribution
        .payout_entries_at(reward_sats)
        .expect("§4 payout vector");

    // Gate 1: the row survived the payability retain. It could only have done so
    // through the installed resolver — the preconditions in the test body show
    // the key is unpayable without it.
    let claimed_sats = entries
        .iter()
        .find(|(a, _)| a.as_str() == payout_id)
        .map(|(_, sats)| *sats)
        .unwrap_or_else(|| {
            panic!(
                "the rotating miner must be in the distribution at height {height}; got {:?}",
                entries
                    .iter()
                    .map(|(a, s)| (a.as_str(), *s))
                    .collect::<Vec<_>>()
            )
        });

    // Lower the §4 entries to payouts. The ledger key that belongs to the
    // rotating miner becomes the rotating identity; everything else is an
    // address. This mirrors `bin/blitzpool`'s `weight_entries_to_payouts`, which
    // lives behind the binary and cannot be called from here.
    let payouts: Vec<PayoutEntry> = entries
        .iter()
        .map(|(address, sats)| PayoutEntry {
            identity: if address.as_str() == payout_id {
                identity.clone()
            } else {
                PayoutIdentity::static_address_verbatim(address.as_str().to_string())
            },
            sats: *sats,
        })
        .collect();

    let job = build_mining_job_from_tdp(
        Network::Regtest,
        &payouts,
        &coinbase_template_from(template),
        "rotating-pplns-regtest",
        EXTRANONCE_SLOT_LEN,
        fingerprint,
    )
    .expect("a distribution with a rotating miner must build a coinbase");

    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let coinbase_bytes = job.witness_coinbase_with_extranonce(&en1, &en2);
    let coinbase_tx = decode_coinbase(&coinbase_bytes);

    // Gate 2: the output is the address CORE derives at this height, for the sats
    // the distribution assigned the ledger key.
    let paid_sats = coinbase_tx
        .output
        .iter()
        .find(|o| address_of_output(&o.script_pubkey).as_deref() == Some(expected.as_str()))
        .map(|o| o.value.to_sat())
        .unwrap_or_else(|| {
            panic!(
                "no coinbase output pays Core's derivation {expected} at height {height}; \
                 outputs: {:?}",
                coinbase_tx
                    .output
                    .iter()
                    .map(|o| (address_of_output(&o.script_pubkey), o.value.to_sat()))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        paid_sats, claimed_sats,
        "the derived output must carry exactly the satoshis the distribution gave \
         the ledger key — a mismatch means the lowering paid the right script the \
         wrong amount"
    );
    assert!(
        !coinbase_tx.output.iter().any(|o| {
            address_of_output(&o.script_pubkey).as_deref() == Some(payout_id)
                || o.script_pubkey.as_bytes() == payout_id.as_bytes()
        }),
        "and no output may carry the payout_id itself — that output is unspendable"
    );
    eprintln!("[rotating-pplns] height={height} paid {expected} {paid_sats} sat");

    // ── Submit ──────────────────────────────────────────────────────────
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
    let after = poll_for_height(node, before + 1, Duration::from_secs(20))
        .await
        .expect(
            "bitcoin-core must accept a PPLNS block whose coinbase pays a \
             descriptor-derived script — a stuck tip means the derived output is not \
             a valid payout",
        );
    assert_eq!(after, height, "the accepted block is the derived height");

    // ── Book it, from the coinbase the chain accepted ───────────────────
    let actual = ActualCoinbase::from_coinbase(&coinbase_tx, Network::Regtest);
    assert_eq!(actual.total_value_sats, reward_sats);
    assert_eq!(
        actual.paid_by_address.get(&expected).copied(),
        Some(paid_sats),
        "precondition for the booking: the coinbase really paid the derived address"
    );
    assert!(
        !actual.paid_by_address.contains_key(payout_id),
        "and nothing is keyed on the ledger key — which is why settlement needs \
         the attribution at all"
    );
    engine
        .on_block_found(height as i32, &actual, None, Some(fingerprint))
        .await
        .expect("the mined job's own distribution must resolve and book");

    MinedBlock {
        height,
        paid_to: expected,
        paid_sats,
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// The pool's derived address at `height`, from the node's `deriveaddresses` —
/// the independent side of the gate. Needs no wallet: it is a pure descriptor
/// function on the node.
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
    assert_eq!(arr.len(), 1, "a [H,H] range is one address");
    arr[0]
        .as_str()
        .expect("deriveaddresses element is a string")
        .to_string()
}

/// `None` for an output no address renders from (the witness commitment), so a
/// coinbase can be scanned without unwrapping on it.
fn address_of_output(script: &bitcoin::Script) -> Option<String> {
    bitcoin::Address::from_script(script, Network::Regtest)
        .ok()
        .map(|a| a.to_string())
}

async fn history_rows(pool: &PgPool, height: u32) -> Vec<(String, i64)> {
    sqlx::query_as(
        r#"SELECT address, "paidSats" FROM pplns_payout_history
           WHERE "blockHeight" = $1 AND "rowType" = 'coinbase'"#,
    )
    .bind(height as i32)
    .fetch_all(pool)
    .await
    .expect("read audit rows")
}

/// Drop these ledger rows. Used at both ends: before the test, so a previous
/// run's rows cannot answer its questions, and after it, so the next test's
/// distribution build — which reads EVERY open balance in the table, pool-wide —
/// does not inherit this one's miners.
async fn delete_balances(pool: &PgPool, addresses: &[&str]) {
    for address in addresses {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(address)
            .execute(pool)
            .await;
    }
}

async fn balance_row_count(pool: &PgPool, address: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM pplns_balance WHERE address = $1")
        .bind(address)
        .fetch_one(pool)
        .await
        .expect("count balance rows")
        .0
}

async fn total_paid_sats(pool: &PgPool, address: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(r#"SELECT "totalPaidSats" FROM pplns_balance WHERE address = $1"#)
        .bind(address)
        .fetch_one(pool)
        .await
        .expect("read the ledger row")
        .0
}

/// Discard the attach-time template pair: it describes the CURRENT tip, and a
/// block built for an already-mined height is silently rejected.
async fn drain_startup_pair(rx: &mut tokio::sync::broadcast::Receiver<TemplateUpdate>) {
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
/// Height-targeted because a submitted block emits templates as the tip moves,
/// and taking the first pair can hand back one built for the height just mined —
/// which is rejected on submit and looks like a payout bug.
async fn wait_for_pair_at_height(
    rx: &mut tokio::sync::broadcast::Receiver<TemplateUpdate>,
    height: u32,
) -> (NewTemplate, bp_template_distribution::SetNewPrevHash) {
    let deadline = Duration::from_secs(30);
    tokio::time::timeout(deadline, async {
        loop {
            let pair = wait_for_paired_template(rx).await;
            match decode_bip34_height(&pair.0.coinbase_prefix) {
                Some(h) if h == height => return pair,
                _ => continue,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no template for height {height} within {deadline:?}"))
}

fn coinbase_template_from(t: &NewTemplate) -> TdpCoinbaseTemplate<'_> {
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

fn test_engine_config(fee_addr: &str) -> PplnsEngineConfig {
    PplnsEngineConfig {
        // No dust sweep and an hour-long touch flush: neither background task
        // may fire inside the test window.
        dust_sweep_enabled: false,
        touch_flush_interval_secs: 3_600,
        fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr valid")),
        fee_percent: 1.5,
        min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
        // Regtest halves every 150 blocks. The default is the mainnet interval,
        // under which the engine expects 50 BTC where regtest pays 25 and its
        // "coinbase pays less than the subsidy" guard REFUSES to book a healthy
        // block. This fixture books at height ~102 so it passes either way —
        // which is exactly why it is pinned rather than left to be rediscovered:
        // upstream 0d93a15 pinned every other booking fixture with the note
        // "Set here so the next one cannot inherit the trap", and this is the
        // next one.
        subsidy_halving_interval: bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
        ..PplnsEngineConfig::default()
    }
}
