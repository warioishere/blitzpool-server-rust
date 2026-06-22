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

/// Connect to a Redis logical DB and `FLUSHDB` it. Returns `None`
/// (with a skip message) when Redis isn't reachable.
pub async fn connect_redis_or_skip(test_db: u8) -> Option<ConnectionManager> {
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
