// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared helpers for the regtest / integration test suites.
//!
//! These were previously copy-pasted (and had quietly drifted) across
//! ~15 `tests/` files. Centralising them here means a fix lands once.
//! This crate is only ever a `dev-dependency`.

#![allow(clippy::print_stderr)]

use std::time::Duration;

use bp_mining_job::build_block_header;
use bp_regtest_harness::RegtestNode;
use bp_share::Target;
use bp_template_distribution::{NewTemplate, SetNewPrevHash, TemplateUpdate};
use redis::aio::ConnectionManager;
use redis::Client;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tokio::sync::broadcast;

/// Default local test-service endpoints. Override with `BP_REDIS_URL` /
/// `BP_PG_URL`.
pub const REDIS_DEFAULT_URL: &str = "redis://127.0.0.1:16379";
pub const PG_DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Set this to turn every Redis/Postgres skip into a **failure**.
///
/// The skip default is right for CI-without-services and for a contributor
/// who has not started the containers. It is wrong for the run you intend
/// to believe, because a skipped test passes: `$?` cannot tell a suite that
/// exercised Postgres from one that never reached it.
///
/// Measured 2026-08-10, which is why this exists. The Docker daemon died
/// part-way through a full-suite run. Every Redis/Postgres test after that
/// point skipped, and the totals came out **identical** to the healthy run
/// — 2104 passed either way. Nothing in the exit code, the failure count or
/// the passed-count distinguished them; only `grep -c skipping` did, and
/// only because the run happened to use `--nocapture`. Checking the
/// containers before the run does not help either: they were up at the
/// start.
///
/// With this set, that outage is a red suite at the moment it happens,
/// naming the service and the URL.
pub const REQUIRE_SERVICES_ENV: &str = "BP_REQUIRE_TEST_SERVICES";

/// Whether an unreachable service must fail rather than skip.
fn services_required() -> bool {
    value_requires_services(std::env::var(REQUIRE_SERVICES_ENV).ok().as_deref())
}

/// Does this [`REQUIRE_SERVICES_ENV`] value ask for failures?
///
/// Split from the env read so the rule is testable: the workspace sets
/// `unsafe_code = "deny"` and Rust 1.85 made `set_var` unsafe, so a test
/// cannot mutate the environment to reach it (same constraint as
/// `bp_regtest_harness::config`).
///
/// Any value other than empty or `0` counts, so `=1` and `=true` both work
/// while `=0` stays an explicit opt-out — a half-set variable must not read
/// as "required" and then quietly fail a contributor's whole suite.
fn value_requires_services(value: Option<&str>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "0")
}

/// Report an unreachable service: skip by default, panic under
/// [`REQUIRE_SERVICES_ENV`].
///
/// Returns `None` so callers stay a one-line `?`/`else` at the top of a
/// test; it only ever returns in the skip case.
fn skip_or_fail<T>(reason: String) -> Option<T> {
    if let Some(line) = skip_decision(services_required(), reason) {
        eprintln!("{line}");
    }
    None
}

/// [`skip_or_fail`] with the decision passed in, so both branches can be
/// exercised without mutating the environment.
///
/// Returns the skip line rather than printing it. The verification protocol
/// counts `grep -c skipping` over the whole run and expects **0** on a
/// healthy one, so a unit test that reached an `eprintln!("… skipping")`
/// would put a permanent 3 in that count and quietly destroy the only
/// measurement that distinguishes a real run from a skipped one. Printing
/// stays in [`skip_or_fail`], which no test calls.
fn skip_decision(required: bool, reason: String) -> Option<String> {
    assert!(
        !required,
        "{reason}\n{REQUIRE_SERVICES_ENV} is set, so an unreachable service is a failure \
         rather than a skip. Start the services (`docker start bp-test-pg bp-test-redis`) \
         or unset it."
    );
    Some(format!("{reason} — skipping"))
}

/// Deterministic regtest P2WPKH address from a 32-byte secret-key seed —
/// a valid bech32 string with a correct checksum, no live `getnewaddress`.
pub fn deterministic_p2wpkh_regtest(seed: [u8; 32]) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey, Network};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed).expect("non-zero, in-curve seed");
    let pk = CompressedPublicKey(sk.public_key(&secp));
    Address::p2wpkh(&pk, Network::Regtest).to_string()
}

/// Grind a header nonce (0..1M) until its double-SHA256 meets `target`.
/// Returns `None` if no nonce in range works (regtest target is trivial,
/// so a hit is found almost immediately).
pub fn brute_force_nonce(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    timestamp: u32,
    bits: u32,
    target: &Target,
) -> Option<u32> {
    for nonce in 0..1_000_000u32 {
        let header = build_block_header(
            version as i32,
            prev_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        );
        let hash = bp_share::sha256d(&header);
        if target.is_met_by_le(&hash) {
            return Some(nonce);
        }
    }
    None
}

/// Poll the node's tip until it reaches `target_height` or `budget`
/// elapses.
pub async fn poll_for_height(
    node: &RegtestNode,
    target_height: u32,
    budget: Duration,
) -> Option<u32> {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if let Ok(h) = node.current_height().await {
            if h >= target_height {
                return Some(h);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// A block bitcoin-core accepted, and the bytes it accepted.
pub struct AcceptedBlock {
    /// The tip after acceptance — always `height_before + 1`.
    pub height: u32,
    /// Exactly the coinbase transaction core validated. Settlement tests
    /// read their expectations out of THIS, never out of what the pool
    /// intended to pay.
    pub witness_coinbase: Vec<u8>,
    /// Big-endian hex, the same shape the production block-sink computes.
    pub block_hash_hex: String,
}

/// Assemble the coinbase paying exactly `payouts` over `template`,
/// brute-force a nonce that meets the regtest target, submit it through
/// `tdp`, and require bitcoin-core to extend the chain by one.
///
/// This is the step every money regtest ends with, and it used to be
/// copy-pasted into each of them — two of the copies were byte-identical
/// down to the parameter list. It is one function because the failure it
/// reports is subtle and worth wording once: `submit_solution` is
/// fire-and-forget, so a coinbase whose outputs do not sum to the template
/// value, or that carries a dust output or a malformed script, is rejected
/// with no error the pool ever sees — the tip simply does not move.
///
/// `fingerprint` is the distribution's settlement identity, carried in the
/// job so a block found on it books through the distribution it actually
/// paid. Pass `[0u8; 32]` where the test does not settle.
///
/// Uses zero extranonces. Callers that need to vary them, that assert on
/// the assembled job before submitting, or that expect core to REJECT
/// (`regtest_budget_autoscale`) drive the pieces themselves.
pub async fn mine_and_submit_payouts(
    node: &RegtestNode,
    tdp: &bp_template_distribution::TdpHandle,
    template: &NewTemplate,
    prev_hash: &SetNewPrevHash,
    payouts: &[bp_mining_job::PayoutEntry],
    pool_identifier: &str,
    fingerprint: [u8; 32],
) -> AcceptedBlock {
    let coinbase_template = bp_mining_job::TdpCoinbaseTemplate {
        coinbase_prefix: &template.coinbase_prefix,
        coinbase_tx_version: template.coinbase_tx_version,
        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &template.coinbase_tx_outputs,
        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
        coinbase_tx_locktime: template.coinbase_tx_locktime,
    };
    let job = bp_mining_job::build_mining_job_from_tdp(
        bitcoin::Network::Regtest,
        payouts,
        &coinbase_template,
        pool_identifier,
        bp_mining_job::EXTRANONCE_SLOT_LEN,
        fingerprint,
    )
    .expect("build_mining_job_from_tdp");

    let en1 = [0u8; 4];
    let en2 = [0u8; 8];
    let coinbase_txid = job.coinbase_txid_with_extranonce(&en1, &en2);
    let merkle_root =
        bp_mining_job::merkle_root_from_coinbase(&coinbase_txid, &template.merkle_path);
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

    let witness_coinbase = job.witness_coinbase_with_extranonce(&en1, &en2);
    let before_height = node.current_height().await.expect("current_height");
    tdp.submit_solution(
        template.template_id,
        template.version,
        prev_hash.header_timestamp,
        nonce,
        witness_coinbase.clone(),
    )
    .await
    .expect("submit_solution");

    let height = poll_for_height(node, before_height + 1, Duration::from_secs(20))
        .await
        .unwrap_or_else(|| {
            panic!(
                "bitcoin-core must accept the block ({pool_identifier}) — a stuck tip at \
                 {before_height} means the coinbase was rejected: outputs not summing to \
                 the template value, a dust output, or a malformed script"
            )
        });
    assert_eq!(height, before_height + 1);

    let header_bytes = build_block_header(
        template.version as i32,
        &prev_hash.prev_hash,
        &merkle_root,
        prev_hash.header_timestamp,
        prev_hash.n_bits,
        nonce,
    );
    let mut hash = bp_share::sha256d(&header_bytes);
    hash.reverse();

    AcceptedBlock {
        height,
        witness_coinbase,
        block_hash_hex: hex_lower(&hash),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Wait for a paired **future** `NewTemplate` + matching `SetNewPrevHash`
/// (the strict variant — what fires on a tip change). Panics on timeout.
pub async fn wait_for_paired_template(
    rx: &mut broadcast::Receiver<TemplateUpdate>,
) -> (NewTemplate, SetNewPrevHash) {
    let res: Result<(NewTemplate, SetNewPrevHash), _> =
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut t: Option<NewTemplate> = None;
            loop {
                match rx.recv().await {
                    Ok(TemplateUpdate::NewTemplate(nt)) if nt.future_template => {
                        t = Some(nt);
                    }
                    Ok(TemplateUpdate::SetNewPrevHash(p)) => {
                        if let Some(ref nt) = t {
                            if nt.template_id == p.template_id {
                                let owned = t.take().expect("just checked");
                                return (owned, p);
                            }
                        }
                    }
                    _ => continue,
                }
            }
        })
        .await;
    res.expect("TDP must emit a paired NewTemplate + SetNewPrevHash within 10s")
}

/// Wait for ANY paired `NewTemplate` + matching `SetNewPrevHash`, without
/// requiring `future_template` (the loose variant used by the
/// mempool-delta / autoscale tests that re-template without a tip change).
/// Drop-in for the strict variant (same `(rx)` signature) — callers alias
/// it as `wait_for_paired_template`. 15s budget (superset of the 10s/15s
/// the old copies used).
pub async fn wait_for_any_paired_template(
    rx: &mut broadcast::Receiver<TemplateUpdate>,
) -> (NewTemplate, SetNewPrevHash) {
    let res: Result<(NewTemplate, SetNewPrevHash), _> =
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut new_template: Option<NewTemplate> = None;
            let mut prev_hash: Option<SetNewPrevHash> = None;
            loop {
                match rx.recv().await {
                    Ok(TemplateUpdate::NewTemplate(t)) => new_template = Some(t),
                    Ok(TemplateUpdate::SetNewPrevHash(p)) => prev_hash = Some(p),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => unreachable!("TDP channel closed"),
                }
                if let (Some(t), Some(p)) = (&new_template, &prev_hash) {
                    if t.template_id == p.template_id {
                        return (t.clone(), p.clone());
                    }
                }
            }
        })
        .await;
    res.expect("TDP must emit a paired NewTemplate + SetNewPrevHash before the timeout")
}

/// Clear every trace of a Blockparty admin address, so a test that owns
/// `addrs` can re-create its group from scratch.
///
/// Deletes from `blockparty_group` by admin address, NOT from
/// `blockparty_member` — `blockparty_member` has
/// `ON DELETE CASCADE` from `blockparty_group`, so removing the parent is
/// strictly more thorough than removing the child, and removing only the
/// child leaves the parent behind.
///
/// That difference was a permanent, cross-branch failure. Measured
/// 2026-08-10: the two blockparty regtests pick a **fixed** admin address
/// (`deterministic_p2wpkh_regtest([0xa1; 32])` /  `[0xc1; 32]`) and
/// `blockparty_group` has `UQ_blockparty_group_admin_address`, so one
/// interrupted run left an orphaned group row and every later run — on any
/// branch, including unmodified `main` — failed `create_group` with
/// `AdminAddressTaken` forever after. Cleaning by member address could not
/// help: the row holding the constraint was the one it did not touch.
///
/// The member address is still worth passing: a non-admin address may hold
/// `UQ_blockparty_member_address` under a group whose own admin is not in
/// `addrs`, which no `blockparty_group` delete would reach.
pub async fn cleanup_blockparty_rows(pool: &PgPool, addrs: &[&str]) {
    for a in addrs {
        // Parent first — cascades to blockparty_member, _invitation,
        // _join_link and _block_history for that group.
        let _ = sqlx::query(r#"DELETE FROM blockparty_group WHERE "adminAddress" = $1"#)
            .bind(*a)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
            .bind(*a)
            .execute(pool)
            .await;
    }
}

/// Per-test-binary logical-DB ranges.
///
/// `connect_redis_or_skip` **flushes** the DB it opens, so two tests
/// sharing one wipe each other's state mid-run. Everything in a `cargo
/// test` run is concurrent — tests within a binary and the binaries
/// themselves — so isolation has to hold across the whole workspace, not
/// just per file.
///
/// It did not. Measured 2026-08-03: **135 assignments on 16 databases**,
/// every one of them 6–12× overbooked. That is not a flake, it is an
/// arithmetic problem, and it cost two debugging rounds in one session:
/// a test green alone and red in the suite, twice, for two different
/// neighbours.
///
/// So each test binary owns `RANGE` consecutive databases and keeps its
/// own 0-based numbering inside them. A binary needs a distinct base
/// here; a test needs a number no sibling in the SAME binary uses.
pub mod redis_db {
    /// Databases per test binary. Wide enough for the largest one
    /// (`bp-group-solo-engine`'s `engine_integration`, 22 connects).
    pub const RANGE: u16 = 32;

    pub const BLITZPOOL_BIN: u16 = 0;
    pub const SHARE_STREAM: u16 = RANGE;
    pub const GS_DISTRIBUTION: u16 = 2 * RANGE;
    pub const GS_ENGINE: u16 = 3 * RANGE;
    pub const GS_RESET: u16 = 4 * RANGE;
    pub const GS_ROUND: u16 = 5 * RANGE;
    pub const GS_STREAM_EQUIV: u16 = 6 * RANGE;
    pub const PPLNS_DISTRIBUTION: u16 = 7 * RANGE;
    pub const PPLNS_ENGINE: u16 = 8 * RANGE;
    pub const PPLNS_STREAM_EQUIV: u16 = 9 * RANGE;
    pub const PPLNS_WINDOW: u16 = 10 * RANGE;

    // The regtest binaries. These used to call `connect_redis_or_skip` with a
    // RAW index (8, 9, 10, 11, 13) and so landed inside `BLITZPOOL_BIN`'s
    // range — `regtest_pplns_block_submit`'s 10 and
    // `regtest_group_solo_block_submit`'s 10 were literally the same database,
    // and both flush. Nothing ever broke because `cargo test` runs test
    // BINARIES one after another, so the collision partners were never awake
    // at the same time. That is a property of the runner, not of the tests:
    // `cargo-nextest` runs binaries concurrently and would surface all of it
    // at once.
    pub const RT_PPLNS_BLOCK_SUBMIT: u16 = 11 * RANGE;
    pub const RT_SPLIT_E2E: u16 = 12 * RANGE;
    pub const RT_POOL_NEUTRAL_PAYOUT: u16 = 13 * RANGE;
    pub const RT_GROUP_SOLO_BLOCK_SUBMIT: u16 = 14 * RANGE;

    /// `bp-session-persistence`'s `live_store_integration`. ⚠️ This is
    /// the LAST free 32-slice of the 512-DB test container
    /// (`15 * 32 + 31 = 511`) — the next binary that needs a base must
    /// recreate `bp-test-redis` with `--databases` raised past 512.
    ///
    /// ⚠️ Index **31** of this range is lent to TWO `bp-api` test
    /// binaries — `smoke.rs` and `custom_extranonce_guard.rs` — both
    /// NO-FLUSH and write-free, since their endpoints now need a live
    /// store to answer at all. Don't claim it for a session-persistence
    /// test, and don't add a write to either borrower without moving
    /// them apart first.
    pub const SESSION_PERSISTENCE: u16 = 15 * RANGE;
}

/// How many logical databases this Redis actually has.
///
/// Read once per process, because it decides where every test in it
/// lands. The local test container runs `valkey-server --databases 512`;
/// a stock server has 16, and **GitHub Actions service containers cannot
/// override a container's command**, so CI's Valkey has 16 and there is
/// no way to pass `--databases` to it as a service.
///
/// Rather than let that difference turn into a silent `SELECT` failure —
/// which `connect_redis_or_skip` would report as "Redis unreachable" and
/// **skip**, the exact failure mode that hid a whole suite earlier today
/// — the index is folded into whatever the server offers. On 512 every
/// binary is isolated; on 16 the folding lands tests back on top of each
/// other exactly as they were before, which is no worse than today.
async fn redis_database_count() -> u16 {
    static COUNT: tokio::sync::OnceCell<u16> = tokio::sync::OnceCell::const_new();
    *COUNT
        .get_or_init(|| async {
            let base =
                std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.to_string());
            let fallback = 16u16;
            let Ok(client) = Client::open(format!("{base}/0")) else {
                return fallback;
            };
            let Ok(Ok(mut conn)) =
                tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client)).await
            else {
                return fallback;
            };
            // `CONFIG GET databases` answers `["databases", "<n>"]`.
            match redis::cmd("CONFIG")
                .arg("GET")
                .arg("databases")
                .query_async::<Vec<String>>(&mut conn)
                .await
            {
                Ok(kv) => kv
                    .get(1)
                    .and_then(|v| v.parse::<u16>().ok())
                    .filter(|n| *n > 0)
                    .unwrap_or(fallback),
                Err(_) => fallback,
            }
        })
        .await
}

/// Connect to this binary's `test_db`-th logical database and `FLUSHDB`
/// it — see [`redis_db`] for why the base matters.
///
/// `base` is the binary's constant from [`redis_db`]; `test_db` is the
/// test's own number within it, which only has to be unique among that
/// binary's tests.
pub async fn connect_redis_in_range_or_skip(base: u16, test_db: u8) -> Option<ConnectionManager> {
    connect_redis_or_skip_raw(redis_db_in_range(base, test_db).await).await
}

/// Like [`connect_redis_in_range_or_skip`] but WITHOUT the `FLUSHDB`.
///
/// For the narrow case of sibling tests in one binary that deliberately
/// share an index: each namespaces its keys (by front id, by prefix) and
/// asserts only on its own, so flushing would buy no isolation and would
/// wipe whatever a sibling is halfway through.
///
/// Sharing is only safe *within* one binary, and only when every test on
/// that index agrees not to flush. Reach for [`connect_redis_in_range_or_skip`]
/// unless the sharing is deliberate — a flush arriving mid-test reads as an
/// impossible result (a key that was just written coming back missing), which
/// is a genuinely hard failure to place.
pub async fn connect_redis_in_range_no_flush(base: u16, test_db: u8) -> Option<ConnectionManager> {
    let index = redis_db_in_range(base, test_db).await;
    let url_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.to_string());
    let url = format!("{url_base}/{index}");
    let client = match Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => return skip_or_fail(format!("redis client open {url}: {e}")),
    };
    match tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client)).await {
        Ok(Ok(c)) => Some(c),
        Ok(Err(e)) => skip_or_fail(format!("redis connect {url}: {e}")),
        Err(_) => skip_or_fail(format!("redis connect timed out at {url}")),
    }
}

/// The raw logical-DB index for `test_db` inside `base`'s range, folded
/// into what this server actually has. For harnesses that build their own
/// connection and only need the number.
pub async fn redis_db_in_range(base: u16, test_db: u8) -> u16 {
    (base + test_db as u16) % redis_database_count().await
}

/// Connect to a Redis logical DB and `FLUSHDB` it. Returns `None`
/// (with a skip message) when Redis isn't reachable.
///
/// Prefer [`connect_redis_in_range_or_skip`]: this takes a RAW database
/// index, so two callers passing the same number wipe each other however
/// many databases the server has.
pub async fn connect_redis_or_skip(test_db: u8) -> Option<ConnectionManager> {
    connect_redis_or_skip_raw(test_db as u16).await
}

async fn connect_redis_or_skip_raw(test_db: u16) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.to_string());
    let url = format!("{base}/{test_db}");
    let client = match Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => return skip_or_fail(format!("redis client open {url}: {e}")),
    };
    let mut conn =
        match tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return skip_or_fail(format!("redis connect {url}: {e}")),
            Err(_) => return skip_or_fail(format!("redis connect timed out at {url}")),
        };
    if let Err(e) = redis::cmd("PING").query_async::<String>(&mut conn).await {
        return skip_or_fail(format!("redis PING {url} failed: {e}"));
    }
    if let Err(e) = redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await {
        return skip_or_fail(format!("redis FLUSHDB {url} failed: {e}"));
    }
    Some(conn)
}

/// Connect to the test Postgres. Returns `None` (with a skip message)
/// when PG isn't reachable.
pub async fn connect_pg_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_DEFAULT_URL.to_string());
    match tokio::time::timeout(
        Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => skip_or_fail(format!("PG connect {url}: {e}")),
        Err(_) => skip_or_fail(format!("PG connect timed out at {url}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The skip path must stay the default, or a contributor without the
    /// containers gets a wall of failures instead of skips.
    #[test]
    fn an_unset_or_zero_value_still_skips() {
        for value in [None, Some(""), Some("0")] {
            assert!(
                !value_requires_services(value),
                "{value:?} must not demand services"
            );
            let line = skip_decision(value_requires_services(value), "PG down".to_string());
            assert_eq!(
                line.as_deref(),
                Some("PG down — skipping"),
                "{value:?} must skip (and say so), not panic"
            );
        }
    }

    /// The point of the knob: with it set, an unreachable service is a
    /// FAILURE. Asserted through `skip_decision` rather than by re-deriving
    /// the rule, because the bug it guards against is a decision function
    /// that returns a skip no matter what — which no test of
    /// `value_requires_services` alone would catch.
    #[test]
    #[should_panic(expected = "BP_REQUIRE_TEST_SERVICES")]
    fn a_set_value_turns_an_unreachable_service_into_a_failure() {
        assert!(
            value_requires_services(Some("1")),
            "precondition: `1` must demand services, else the panic below proves nothing"
        );
        let _ = skip_decision(
            value_requires_services(Some("1")),
            "PG connect refused".to_string(),
        );
    }

    /// `=true` has to work too — nobody reads the docs for which truthy
    /// spelling was chosen, and a value that silently means "skip" would
    /// reinstate the exact failure this knob exists to catch.
    #[test]
    fn truthy_spellings_other_than_one_also_count() {
        for value in ["true", "yes", "always"] {
            assert!(
                value_requires_services(Some(value)),
                "`{value}` must demand services"
            );
        }
    }
}
