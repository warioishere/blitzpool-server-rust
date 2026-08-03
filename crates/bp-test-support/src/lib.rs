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
            0,
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
/// So each test binary owns [`RANGE`] consecutive databases and keeps its
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
    let client = Client::open(url.clone())
        .map_err(|e| eprintln!("redis client open {url}: {e} — skipping"))
        .ok()?;
    let mut conn =
        match tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                eprintln!("redis connect {url}: {e} — skipping");
                return None;
            }
            Err(_) => {
                eprintln!("redis connect timed out at {url} — skipping");
                return None;
            }
        };
    if redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("redis PING {url} failed — skipping");
        return None;
    }
    if redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("redis FLUSHDB {url} failed — skipping");
        return None;
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
        Ok(Err(e)) => {
            eprintln!("PG connect {url}: {e} — skipping");
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out at {url} — skipping");
            None
        }
    }
}
