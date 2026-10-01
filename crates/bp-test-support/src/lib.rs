// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared helpers for the regtest / integration test suites, kept in one
//! place so a fix lands once. This crate is only ever a `dev-dependency`.

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

/// Overridden by `BP_REDIS_URL` / `BP_PG_URL`.
pub const REDIS_DEFAULT_URL: &str = "redis://127.0.0.1:16379";
pub const PG_DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Turns every Redis/Postgres skip into a failure. A skipped test passes, so
/// a run meant as evidence sets this to prove the services were reached.
pub const REQUIRE_SERVICES_ENV: &str = "BP_REQUIRE_TEST_SERVICES";

fn services_required() -> bool {
    value_requires_services(std::env::var(REQUIRE_SERVICES_ENV).ok().as_deref())
}

/// Any value but empty or `0` asks for failures. Split from the env read
/// because `set_var` is unsafe and the workspace denies unsafe code, so tests
/// cannot reach the rule through the environment.
fn value_requires_services(value: Option<&str>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "0")
}

/// Skip by default, panic under [`REQUIRE_SERVICES_ENV`].
fn skip_or_fail<T>(reason: String) -> Option<T> {
    if let Some(line) = skip_decision(services_required(), reason) {
        eprintln!("{line}");
    }
    None
}

/// [`skip_or_fail`] with the decision passed in. Returns the skip line instead
/// of printing it, so its own unit tests don't add to `grep -c skipping`.
fn skip_decision(required: bool, reason: String) -> Option<String> {
    assert!(
        !required,
        "{reason}\n{REQUIRE_SERVICES_ENV} is set, so an unreachable service is a failure \
         rather than a skip. Start the services (`docker start bp-test-pg bp-test-redis`) \
         or unset it."
    );
    Some(format!("{reason} — skipping"))
}

/// A valid regtest P2WPKH address without a live `getnewaddress`.
pub fn deterministic_p2wpkh_regtest(seed: [u8; 32]) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey, Network};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed).expect("non-zero, in-curve seed");
    let pk = CompressedPublicKey(sk.public_key(&secp));
    Address::p2wpkh(&pk, Network::Regtest).to_string()
}

/// Tries the first 1M nonces; enough for the trivial regtest target.
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
    pub height: u32,
    /// The coinbase core validated: settlement tests read expectations from
    /// this, never from what the pool intended to pay.
    pub witness_coinbase: Vec<u8>,
    /// Big-endian hex, the shape the production block-sink computes.
    pub block_hash_hex: String,
}

/// Mines `payouts` over `template` and requires the tip to move by one: a
/// rejected solution raises no error, the tip just stays. `fingerprint` is the
/// distribution's settlement identity (`[0u8; 32]` when the test does not
/// settle). Zero extranonces; tests expecting a reject drive the pieces themselves.
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

/// Waits for a future `NewTemplate` and its `SetNewPrevHash`, i.e. a tip change.
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

/// Like [`wait_for_paired_template`] without requiring `future_template`, for
/// tests that re-template without a tip change.
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

/// Deletes the group by admin address (cascading to its children), or a
/// leftover group from an interrupted run fails every later `create_group`
/// with `AdminAddressTaken`. The member delete covers addresses held in a
/// group whose admin is not in `addrs`.
pub async fn cleanup_blockparty_rows(pool: &PgPool, addrs: &[&str]) {
    for a in addrs {
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

/// Per-test-binary logical-DB ranges: connecting flushes the DB, so tests
/// sharing one wipe each other. A binary needs its own base here; a test needs
/// a number no sibling in the same binary uses.
pub mod redis_db {
    /// Wide enough for the largest binary's number of connects.
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

    // Regtest binaries get their own ranges too: `cargo-nextest` runs binaries
    // concurrently, so a shared index would be wiped by a neighbour's flush.
    pub const RT_PPLNS_BLOCK_SUBMIT: u16 = 11 * RANGE;
    pub const RT_SPLIT_E2E: u16 = 12 * RANGE;
    pub const RT_POOL_NEUTRAL_PAYOUT: u16 = 13 * RANGE;
    pub const RT_GROUP_SOLO_BLOCK_SUBMIT: u16 = 14 * RANGE;

    /// Index 31 of this range is lent to the no-flush, write-free `bp-api`
    /// binaries `smoke.rs` and `custom_extranonce_guard.rs`: don't claim it
    /// here, and don't add a write to either without moving them apart.
    pub const SESSION_PERSISTENCE: u16 = 15 * RANGE;

    /// The last slice of the 544-DB test container: the next binary needs
    /// `bp-test-redis` recreated with a larger `--databases`.
    pub const API: u16 = 16 * RANGE;
}

/// CI's Valkey service has only 16 databases and cannot be given
/// `--databases`. Indexes are folded into what the server offers, because a
/// failed `SELECT` would read as "Redis unreachable" and silently skip.
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

/// Flushes the DB. `base` is the binary's constant from [`redis_db`];
/// `test_db` only has to be unique among that binary's tests.
pub async fn connect_redis_in_range_or_skip(base: u16, test_db: u8) -> Option<ConnectionManager> {
    connect_redis_or_skip_raw(redis_db_in_range(base, test_db).await).await
}

/// Like [`connect_redis_in_range_or_skip`] without the flush, for sibling tests
/// in one binary that deliberately share an index with namespaced keys. Safe
/// only while every test on that index skips the flush.
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

/// For harnesses that build their own connection and only need the index.
pub async fn redis_db_in_range(base: u16, test_db: u8) -> u16 {
    (base + test_db as u16) % redis_database_count().await
}

/// Prefer [`connect_redis_in_range_or_skip`]: this flushes a raw index, so two
/// callers passing the same number wipe each other.
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

    /// Skipping stays the default for an unset or `0` value.
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

    /// With the variable set, an unreachable service fails the test.
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

    /// Any truthy spelling demands services.
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
