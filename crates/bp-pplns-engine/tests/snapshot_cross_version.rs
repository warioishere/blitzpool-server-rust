// SPDX-License-Identifier: AGPL-3.0-or-later

// Workspace denies print_stderr; the skip-when-no-Redis path is
// test-tooling output, not production logging, so the lint is
// genuinely off-target here.
#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Cross-version wire-format integration test for `pplns:snapshot`
//! Redis Hash.
//!
//! Addresses Audit-2026-05-16 finding **L-6**: the Rust snapshot
//! codec (`bp_pplns_engine::window::snapshot::{write_snapshot,
//! read_snapshot}`) claimed wire-format byte-compatibility but had no
//! test that pins the exact field-set + value-string-form — only
//! Rust-roundtrip tests of the parser.
//!
//! Mixed-deploy / cut-over scenario: a snapshot written by a previous
//! pool version sits in Redis and must be readable by Rust verbatim;
//! conversely a Rust-written snapshot must be parseable by a fallback
//! reader of the same shape. This test pins both directions against the
//! stable wire rules (scalar field names, `d{i}_*` / `b{i}_*` triples,
//! digit-only integer strings, shortest-roundtrip float strings).
//!
//! Test fixtures construct the exact field-strings (integer → digit-only;
//! f64 → Rust ryu shortest-roundtrip, which matches JS Number.toString
//! for the percent range 0-100 we use in practice). Each test uses its
//! own Redis logical DB (DB 8 onwards; window_integration uses 0-7) so
//! parallel cargo test runs don't interleave.

use bp_common::Sats;
use bp_pplns::CoinbaseDistributionEntry;
use bp_pplns_engine::window::snapshot::{read_snapshot, write_snapshot, StoredSnapshot};
use redis::{aio::ConnectionManager, AsyncCommands, Client};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379";
const SNAPSHOT_KEY: &str = "pplns:snapshot";

async fn connect_or_skip(test_db: u8) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let url = format!("{base}/{test_db}");
    let client = match Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis client open failed for {url}: {e} — skipping integration test");
            return None;
        }
    };
    let mut conn = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            eprintln!("redis connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("redis connect timed out at {url} — skipping integration test");
            return None;
        }
    };
    if redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("redis PING failed for {url} — skipping integration test");
        return None;
    }
    if let Err(e) = redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await {
        eprintln!("redis FLUSHDB failed: {e} — skipping integration test");
        return None;
    }
    Some(conn)
}

fn fixture_snapshot() -> StoredSnapshot {
    // 3-way distribution: pool-finder gets majority, two miners share
    // the rest. Plus a signed-ledger pair (credit + matching debit) so
    // the Σ = 0 invariant is observable. Realistic percent + sats
    // values that exercise the f64-to-string boundary.
    StoredSnapshot {
        distribution: vec![
            CoinbaseDistributionEntry {
                address: bp_common::AddressId::new(
                    "bc1qfinder000000000000000000000000".to_string(),
                )
                .unwrap(),
                percent: 50.0,
                sats: Sats(156_250_000),
            },
            CoinbaseDistributionEntry {
                address: bp_common::AddressId::new(
                    "bc1qminer1000000000000000000000000".to_string(),
                )
                .unwrap(),
                percent: 33.5,
                sats: Sats(104_687_500),
            },
            CoinbaseDistributionEntry {
                address: bp_common::AddressId::new(
                    "bc1qminer2000000000000000000000000".to_string(),
                )
                .unwrap(),
                percent: 16.5,
                sats: Sats(51_562_500),
            },
        ],
        block_reward_sats: 312_500_000,
        considered_addresses: vec![
            "bc1qfinder000000000000000000000000".to_string(),
            "bc1qminer1000000000000000000000000".to_string(),
            "bc1qminer2000000000000000000000000".to_string(),
            "bc1qabandoned00000000000000000000".to_string(),
        ],
        balance_after: vec![
            ("bc1qminer1000000000000000000000000".to_string(), 1_234),
            ("bc1qminer2000000000000000000000000".to_string(), -1_234),
        ],
    }
}

// ── Direction 1: Rust write → raw HGETALL → assert wire-format shape ─

#[tokio::test]
async fn rust_write_emits_ts_wire_format_field_set() {
    // Pins that Rust's `write_snapshot` produces the expected HSET field
    // layout: scalar field names, per-entry `d{i}_*` / `b{i}_*` triples,
    // and the expected value-string forms.
    let mut conn = match connect_or_skip(8).await {
        Some(c) => c,
        None => return,
    };
    let snap = fixture_snapshot();

    write_snapshot(&mut conn, SNAPSHOT_KEY, &snap, 60)
        .await
        .expect("rust write_snapshot ok");

    // Raw HGETALL to inspect the exact bytes Rust put on the wire.
    let raw: std::collections::HashMap<String, String> =
        conn.hgetall(SNAPSHOT_KEY).await.expect("hgetall");

    // ── Scalars: expected field names + value-strings. ───────────────
    assert_eq!(
        raw.get("blockRewardSats"),
        Some(&"312500000".to_string()),
        "blockRewardSats: integer serialized as digit-only string"
    );
    assert_eq!(
        raw.get("distribution_count"),
        Some(&"3".to_string()),
        "distribution_count: array length as string"
    );
    assert_eq!(
        raw.get("balanceAfter_count"),
        Some(&"2".to_string()),
        "balanceAfter_count: array length as string"
    );
    assert_eq!(
        raw.get("consideredAddresses"),
        Some(
            &"bc1qfinder000000000000000000000000|bc1qminer1000000000000000000000000|bc1qminer2000000000000000000000000|bc1qabandoned00000000000000000000"
                .to_string()
        ),
        "consideredAddresses: order-preserving, pipe-separated"
    );

    // ── Distribution triples ────────────────────────────────────────
    // d0: integer percent → "50" (no .0 suffix).
    // Rust f64::to_string() omits the decimal for integer-valued floats.
    assert_eq!(
        raw.get("d0_addr"),
        Some(&"bc1qfinder000000000000000000000000".to_string())
    );
    assert_eq!(
        raw.get("d0_pct"),
        Some(&"50".to_string()),
        "d0_pct: integer-valued float serializes without decimal suffix"
    );
    assert_eq!(raw.get("d0_sats"), Some(&"156250000".to_string()));

    // d1 + d2: fractional percent — Rust ryu shortest-roundtrip
    // matches JS Number.toString for percentages in 0..100 range
    // (both use IEEE-754 round-trip-shortest rules).
    assert_eq!(raw.get("d1_pct"), Some(&"33.5".to_string()));
    assert_eq!(raw.get("d2_pct"), Some(&"16.5".to_string()));

    // ── Signed-ledger pair: positive + negative integers ────────────
    assert_eq!(raw.get("b0_sats"), Some(&"1234".to_string()));
    assert_eq!(
        raw.get("b1_sats"),
        Some(&"-1234".to_string()),
        "negative sats: '-1234' via i64::to_string"
    );

    // ── Strict field-set: no extra or missing fields ─────────────────
    let expected_fields: std::collections::HashSet<&str> = [
        "blockRewardSats",
        "consideredAddresses",
        "distribution_count",
        "balanceAfter_count",
        "d0_addr",
        "d0_pct",
        "d0_sats",
        "d1_addr",
        "d1_pct",
        "d1_sats",
        "d2_addr",
        "d2_pct",
        "d2_sats",
        "b0_addr",
        "b0_sats",
        "b1_addr",
        "b1_sats",
    ]
    .into_iter()
    .collect();
    let actual_fields: std::collections::HashSet<&str> = raw.keys().map(String::as_str).collect();
    assert_eq!(
        actual_fields, expected_fields,
        "write_snapshot must emit exactly the expected field-set — no extras, no omissions"
    );
}

// ── Direction 2: literal HSET → Rust read_snapshot → assert hydrate ──

#[tokio::test]
async fn ts_style_hset_is_readable_by_rust() {
    // Simulates a snapshot written by an older pool version: build the
    // exact HSET field-list verbatim, then verify Rust's `read_snapshot`
    // hydrates correctly. Catches any field-name typo / value-format
    // divergence that the Rust-only roundtrip tests can't see.
    let mut conn = match connect_or_skip(9).await {
        Some(c) => c,
        None => return,
    };

    // Keep this field list literal — drift between Rust write_snapshot
    // and this fixture is the exact thing the test exists to catch.
    let ts_style_fields: Vec<(&str, String)> = vec![
        ("blockRewardSats", "312500000".to_string()),
        (
            "consideredAddresses",
            "bc1qfinder000000000000000000000000|bc1qminer1000000000000000000000000|bc1qminer2000000000000000000000000|bc1qabandoned00000000000000000000"
                .to_string(),
        ),
        ("distribution_count", "3".to_string()),
        ("balanceAfter_count", "2".to_string()),
        (
            "d0_addr",
            "bc1qfinder000000000000000000000000".to_string(),
        ),
        ("d0_pct", "50".to_string()),
        ("d0_sats", "156250000".to_string()),
        (
            "d1_addr",
            "bc1qminer1000000000000000000000000".to_string(),
        ),
        ("d1_pct", "33.5".to_string()),
        ("d1_sats", "104687500".to_string()),
        (
            "d2_addr",
            "bc1qminer2000000000000000000000000".to_string(),
        ),
        ("d2_pct", "16.5".to_string()),
        ("d2_sats", "51562500".to_string()),
        (
            "b0_addr",
            "bc1qminer1000000000000000000000000".to_string(),
        ),
        ("b0_sats", "1234".to_string()),
        (
            "b1_addr",
            "bc1qminer2000000000000000000000000".to_string(),
        ),
        ("b1_sats", "-1234".to_string()),
    ];

    let _: () = conn
        .hset_multiple(SNAPSHOT_KEY, &ts_style_fields)
        .await
        .expect("ts-style HSET ok");

    let parsed = read_snapshot(&mut conn, SNAPSHOT_KEY)
        .await
        .expect("read_snapshot ok")
        .expect("snapshot must hydrate");

    assert_eq!(parsed.block_reward_sats, 312_500_000);
    assert_eq!(parsed.distribution.len(), 3);
    assert_eq!(
        parsed.distribution[0].address.as_str(),
        "bc1qfinder000000000000000000000000"
    );
    assert_eq!(parsed.distribution[0].percent, 50.0);
    assert_eq!(parsed.distribution[0].sats.0, 156_250_000);
    assert_eq!(parsed.distribution[1].percent, 33.5);
    assert_eq!(parsed.distribution[2].percent, 16.5);

    assert_eq!(parsed.considered_addresses.len(), 4);
    assert!(parsed
        .considered_addresses
        .contains("bc1qabandoned00000000000000000000"));

    // Signed-ledger Σ = 0 invariant survives the wire-format hop.
    assert_eq!(parsed.balance_after.len(), 2);
    let credit = parsed.balance_after["bc1qminer1000000000000000000000000"];
    let debit = parsed.balance_after["bc1qminer2000000000000000000000000"];
    assert_eq!(credit + debit, 0, "signed-ledger pair must sum to zero");
}

// ── Direction 3: full roundtrip preserves all values ────────────────

#[tokio::test]
async fn rust_write_then_rust_read_roundtrip() {
    // Sanity floor: the same StoredSnapshot, written and read back
    // through Rust, produces identical hydrated values. Catches
    // regressions in either codec half independent of the wire-format
    // pinning above.
    let mut conn = match connect_or_skip(10).await {
        Some(c) => c,
        None => return,
    };
    let snap = fixture_snapshot();

    write_snapshot(&mut conn, SNAPSHOT_KEY, &snap, 60)
        .await
        .expect("write ok");
    let parsed = read_snapshot(&mut conn, SNAPSHOT_KEY)
        .await
        .expect("read ok")
        .expect("snapshot must hydrate");

    assert_eq!(parsed.block_reward_sats, snap.block_reward_sats);
    assert_eq!(parsed.distribution.len(), snap.distribution.len());
    for (rust, orig) in parsed.distribution.iter().zip(snap.distribution.iter()) {
        assert_eq!(rust.address.as_str(), orig.address.as_str());
        assert_eq!(rust.percent, orig.percent);
        assert_eq!(rust.sats, orig.sats);
    }
    assert_eq!(
        parsed.considered_addresses.len(),
        snap.considered_addresses.len()
    );
    for addr in &snap.considered_addresses {
        assert!(parsed.considered_addresses.contains(addr));
    }
    assert_eq!(parsed.balance_after.len(), snap.balance_after.len());
    for (addr, sats) in &snap.balance_after {
        assert_eq!(parsed.balance_after.get(addr), Some(sats));
    }
}

// ── Direction 5: second independent wire-format fixture ─────────────

#[tokio::test]
async fn ts_spec_fixture_bytewise_mirror() {
    // Second wire-format pinning point alongside `fixture_snapshot()`.
    // Uses different values:
    //   distribution: [(bc1qfee, 2%, 200), (bc1qalice, 98%, 9800)]
    //   blockRewardSats: 10000
    //   consideredAddresses: ['bc1qalice', 'bc1qbob']
    //   balanceAfter: [(bc1qalice, 50), (bc1qbob, -50)]
    //
    // We replay both directions (Rust write → assert field-strings, and
    // literal HSET → Rust read → hydrate) so any drift in either
    // codec half is caught against a second, independent fixture.
    //
    // Why it's worth carrying two fixtures: percent values differ
    // (50/33.5/16.5 vs 2/98), sats values differ (8-digit vs 4-digit),
    // and balance signs are flipped (alice-credit + bob-debit vs the
    // miner1/miner2 pair). If Rust's f64-to-string or i64-to-string
    // had a corner-case at a boundary touched by only ONE fixture,
    // the second would catch it.
    let mut conn = match connect_or_skip(12).await {
        Some(c) => c,
        None => return,
    };

    let snap = StoredSnapshot {
        distribution: vec![
            CoinbaseDistributionEntry {
                address: bp_common::AddressId::new("bc1qfee".to_string()).unwrap(),
                percent: 2.0,
                sats: Sats(200),
            },
            CoinbaseDistributionEntry {
                address: bp_common::AddressId::new("bc1qalice".to_string()).unwrap(),
                percent: 98.0,
                sats: Sats(9_800),
            },
        ],
        block_reward_sats: 10_000,
        considered_addresses: vec!["bc1qalice".to_string(), "bc1qbob".to_string()],
        balance_after: vec![("bc1qalice".to_string(), 50), ("bc1qbob".to_string(), -50)],
    };

    // ── Direction A: Rust write → assert field-strings literal ─────
    write_snapshot(&mut conn, SNAPSHOT_KEY, &snap, 60)
        .await
        .expect("rust write_snapshot ok");
    let raw: std::collections::HashMap<String, String> =
        conn.hgetall(SNAPSHOT_KEY).await.expect("hgetall");

    assert_eq!(raw.get("blockRewardSats"), Some(&"10000".to_string()));
    assert_eq!(raw.get("distribution_count"), Some(&"2".to_string()));
    assert_eq!(raw.get("balanceAfter_count"), Some(&"2".to_string()));
    assert_eq!(
        raw.get("consideredAddresses"),
        Some(&"bc1qalice|bc1qbob".to_string())
    );
    assert_eq!(raw.get("d0_addr"), Some(&"bc1qfee".to_string()));
    assert_eq!(raw.get("d0_pct"), Some(&"2".to_string()));
    assert_eq!(raw.get("d0_sats"), Some(&"200".to_string()));
    assert_eq!(raw.get("d1_addr"), Some(&"bc1qalice".to_string()));
    assert_eq!(raw.get("d1_pct"), Some(&"98".to_string()));
    assert_eq!(raw.get("d1_sats"), Some(&"9800".to_string()));
    assert_eq!(raw.get("b0_addr"), Some(&"bc1qalice".to_string()));
    assert_eq!(raw.get("b0_sats"), Some(&"50".to_string()));
    assert_eq!(raw.get("b1_addr"), Some(&"bc1qbob".to_string()));
    assert_eq!(
        raw.get("b1_sats"),
        Some(&"-50".to_string()),
        "negative sats: '-50' via i64::to_string"
    );

    // ── Direction B: literal HSET → Rust read → hydrate ───────────
    let _: () = redis::cmd("DEL")
        .arg(SNAPSHOT_KEY)
        .query_async(&mut conn)
        .await
        .expect("del ok");
    let ts_fields: Vec<(&str, String)> = vec![
        ("blockRewardSats", "10000".to_string()),
        ("consideredAddresses", "bc1qalice|bc1qbob".to_string()),
        ("distribution_count", "2".to_string()),
        ("balanceAfter_count", "2".to_string()),
        ("d0_addr", "bc1qfee".to_string()),
        ("d0_pct", "2".to_string()),
        ("d0_sats", "200".to_string()),
        ("d1_addr", "bc1qalice".to_string()),
        ("d1_pct", "98".to_string()),
        ("d1_sats", "9800".to_string()),
        ("b0_addr", "bc1qalice".to_string()),
        ("b0_sats", "50".to_string()),
        ("b1_addr", "bc1qbob".to_string()),
        ("b1_sats", "-50".to_string()),
    ];
    let _: () = conn
        .hset_multiple(SNAPSHOT_KEY, &ts_fields)
        .await
        .expect("ts hset ok");

    let parsed = read_snapshot(&mut conn, SNAPSHOT_KEY)
        .await
        .expect("read ok")
        .expect("hydrate ok");

    assert_eq!(parsed.block_reward_sats, 10_000);
    assert_eq!(parsed.distribution.len(), 2);
    assert_eq!(parsed.distribution[0].address.as_str(), "bc1qfee");
    assert_eq!(parsed.distribution[0].percent, 2.0);
    assert_eq!(parsed.distribution[0].sats.0, 200);
    assert_eq!(parsed.distribution[1].percent, 98.0);
    assert_eq!(parsed.distribution[1].sats.0, 9_800);
    assert_eq!(parsed.balance_after["bc1qalice"], 50);
    assert_eq!(parsed.balance_after["bc1qbob"], -50);
    assert_eq!(
        parsed.balance_after["bc1qalice"] + parsed.balance_after["bc1qbob"],
        0,
        "signed-ledger Σ = 0 invariant survives wire-format roundtrip"
    );
}

// ── Direction 4: empty distribution + empty balanceAfter ────────────

#[tokio::test]
async fn empty_distribution_and_balance_roundtrip() {
    // Edge-case: a snapshot built for a block where the window was
    // empty (cold pool) or fully sub-dust. consideredAddresses can
    // still be non-empty (in-flight miners). Both empty arrays must
    // roundtrip cleanly with count=0 fields and no d/b prefix fields.
    let mut conn = match connect_or_skip(11).await {
        Some(c) => c,
        None => return,
    };
    let snap = StoredSnapshot {
        distribution: vec![],
        block_reward_sats: 312_500_000,
        considered_addresses: vec!["bc1qsubdust0000000000000000000000".to_string()],
        balance_after: vec![],
    };

    write_snapshot(&mut conn, SNAPSHOT_KEY, &snap, 60)
        .await
        .expect("write ok");

    let raw: std::collections::HashMap<String, String> =
        conn.hgetall(SNAPSHOT_KEY).await.expect("hgetall");
    let expected_fields: std::collections::HashSet<&str> = [
        "blockRewardSats",
        "consideredAddresses",
        "distribution_count",
        "balanceAfter_count",
    ]
    .into_iter()
    .collect();
    let actual_fields: std::collections::HashSet<&str> = raw.keys().map(String::as_str).collect();
    assert_eq!(
        actual_fields, expected_fields,
        "empty distribution + empty balance_after must emit exactly the 4 scalar fields, no d{{i}}_* / b{{i}}_* entries"
    );
    assert_eq!(raw.get("distribution_count"), Some(&"0".to_string()));
    assert_eq!(raw.get("balanceAfter_count"), Some(&"0".to_string()));

    let parsed = read_snapshot(&mut conn, SNAPSHOT_KEY)
        .await
        .expect("read ok")
        .expect("hydrate ok");
    assert_eq!(parsed.distribution.len(), 0);
    assert_eq!(parsed.balance_after.len(), 0);
    assert_eq!(parsed.considered_addresses.len(), 1);
}
