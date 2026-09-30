// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end integration tests for `GroupSoloEngine` against
//! docker-Redis + docker-PG.

use bp_coinbase_snapshot::StoredWeightSnapshot;
use bp_common::AddressId;
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::engine::{EngineError, GroupSoloEngine};
use redis::{aio::ConnectionManager, Client};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Pool-output recipient. The weight model has no distribution without
/// one (§4: `pay_P` is structural), and it must be DISTINCT from every
/// miner address the tests use — a fee address doubling as a member
/// entry is skipped by the settlement.
const FEE_ADDR: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

struct Harness {
    engine: GroupSoloEngine,
    pool: PgPool,
    group_id: Uuid,
}

async fn spawn_or_skip(redis_db: u8, finder_bonus_ppm: Option<i32>) -> Option<Harness> {
    let pg_url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    // Fold this binary's local number into its own DB range — see
    // `bp_test_support::redis_db`.
    let redis_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::GS_ENGINE, redis_db).await;
    let redis_url = format!("{redis_base}/{redis_db}");

    let pool = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&pg_url),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            eprintln!("PG connect failed: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    };
    let client = match Client::open(redis_url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Redis client failed: {e} — skipping");
            return None;
        }
    };
    let conn = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            eprintln!("Redis connect failed: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("redis connect timed out (>2s) — skipping integration test");
            return None;
        }
    };
    // Deliberately NO FLUSHDB: every key is namespaced by the per-test
    // `group_id`, and several tests share a Redis database index, so a
    // flush would wipe state a sibling is still asserting on.

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id, finder_bonus_ppm).await;

    // No per-group reset cron is armed: the seeded group has no preset.
    let config = GroupSoloEngineConfig {
        fee_address: Some(AddressId::new(FEE_ADDR).unwrap()),
        ..GroupSoloEngineConfig::default()
    };
    let engine = match GroupSoloEngine::spawn(config, conn, pool.clone()).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine spawn failed: {e} — skipping");
            return None;
        }
    };

    Some(Harness {
        engine,
        pool,
        group_id,
    })
}

async fn seed_group(pool: &PgPool, group_id: Uuid, finder_bonus_ppm: Option<i32>) {
    // resetRoundOnBlock = true so the tests asserting a post-block round wipe
    // exercise that path; the default-false behavior has its own test.
    //
    // The bonus column MUST be the one the engine reads (`finderBonusPpm`);
    // any other leaves the engine reading NULL, and every bonus test here
    // would silently pass as a no-bonus test.
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusPpm", "resetRoundOnBlock")
           VALUES ($1, $2, 'test_eng_creator', $3, true, 0, 0, false, $4, true)"#,
    )
    .bind(group_id)
    .bind(format!("test-group-{group_id}"))
    .bind(format!("hash-{group_id}"))
    .bind(finder_bonus_ppm)
    .execute(pool)
    .await
    .expect("seed group");
}

/// Guard the PREMISE of a bonus test.
///
/// The drift tests assert that settlement comes out flat, which a
/// distribution with NO bonus satisfies too. Asserting the finder's share
/// of the score space first makes them fail when the fixture stops
/// carrying a bonus.
///
/// On an even split with a bonus of fraction `f`, the finder ends up
/// holding `f + (1 − f)/2` of the score space.
fn assert_finder_score_fraction(
    distribution: &bp_pplns::WeightDistribution,
    finder: &AddressId,
    expected: f64,
) {
    let total: u64 = distribution.entries.iter().map(|e| e.score_weight).sum();
    let finder_weight = distribution
        .entries
        .iter()
        .find(|e| e.address.as_str() == finder.as_str())
        .map(|e| e.score_weight)
        .expect("the finder must be in the distribution");
    let got = finder_weight as f64 / total as f64;
    assert!(
        (got - expected).abs() < 1e-6,
        "the fixture must actually carry the finder bonus: expected the \
         finder at {expected} of the score space, got {got}"
    );
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query(r#"DELETE FROM pplns_group_block_history WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group_balance WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group WHERE id = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
}

async fn drop_harness(h: Harness) {
    h.engine.shutdown();
    cleanup_group(&h.pool, h.group_id).await;
}

/// A coinbase that pays EXACTLY the distribution's §4 vector at
/// revenue `t` — the pool output first, then the kept miner outputs.
/// What every honestly-built Group-Solo job produces; settlement then
/// books `claim − paid` per address from it (small integer-rounding
/// deltas between the claim formula and the §4 weight path are
/// expected and correct).
fn actual_paying_exactly(
    dist: &bp_group_solo_engine::distribution::DistributionResult,
    t: u64,
) -> bp_coinbase_snapshot::ActualCoinbase {
    let entries = dist
        .distribution
        .payout_entries_at(t)
        .expect("§4 payout vector");
    let mut paid_by_address = std::collections::HashMap::new();
    for (address, sats) in entries.iter().skip(1) {
        *paid_by_address
            .entry(address.as_str().to_string())
            .or_insert(0u64) += sats;
    }
    bp_coinbase_snapshot::ActualCoinbase {
        paid_by_address,
        pool_paid_sats: entries[0].1,
        total_value_sats: t,
    }
}

// ── Test 1 — record_share appears in reader.round_stats ─────────────

#[tokio::test]
async fn record_share_then_round_stats_sees_it() {
    let h = match spawn_or_skip(0, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_share(None, h.group_id, "test_eng_a", 75.0, 1_700_000_000_001)
        .await
        .expect("ok");

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!((stats.total_shares - 75.0).abs() < 1e-9);
    assert!((stats.per_address["test_eng_a"] - 75.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test 2 — build_distribution returns payouts ────────────────────

#[tokio::test]
async fn build_distribution_returns_payouts_after_shares() {
    let h = match spawn_or_skip(1, None).await {
        Some(h) => h,
        None => return,
    };
    let a = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let b = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    h.engine
        .record_share(None, h.group_id, a.as_str(), 60.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, b.as_str(), 40.0, 1_700_000_000_002)
        .await
        .unwrap();

    let result = h
        .engine
        .build_distribution(h.group_id, 312_500_000, &a)
        .await
        .expect("ok");
    // Weight model: concrete sats come from `payout_entries_at`; the
    // build itself carries the §4 weights + the reference revenue.
    assert_eq!(result.distribution.reference_revenue_sats, 312_500_000);
    assert!(result.distribution.published().count() > 0);
    for addr in [&a, &b] {
        assert!(
            result
                .distribution
                .entries
                .iter()
                .any(|e| e.address == *addr),
            "share-holder must be in the distribution entries"
        );
    }

    drop_harness(h).await;
}

// ── Test 3 — on_block_found applies + resets round ─────────────────

#[tokio::test]
async fn on_block_found_applies_distribution_and_resets_round() {
    let h = match spawn_or_skip(2, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    let result = h
        .engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");

    // The block settles from the real §4 coinbase, resolved by the job's
    // weights fingerprint.
    let block_height = 9_995_001;
    let actual = actual_paying_exactly(&result, 312_500_000);
    let outcome = h
        .engine
        .on_block_found(
            h.group_id,
            block_height,
            &actual,
            &finder,
            None,
            Some(result.payouts_fingerprint()),
        )
        .await
        .expect("ok");
    assert!(outcome.history_inserted >= 1);

    // History row in PG.
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(block_height)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(count.0 >= 1);

    // Round reset (block-found variant) — by-address empty.
    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(stats.total_shares, 0.0, "round wiped on block-found");
    assert!(stats.per_address.is_empty());

    drop_harness(h).await;
}

// ── A block richer than the reference revenue settles flat ──────────
//
// A JD-client computes its coinbase amounts against ITS OWN template
// revenue. The finder bonus is a PROPORTION, so every weight is exact at
// every revenue and nothing can be overpaid or owed afterwards.

#[tokio::test]
async fn a_richer_block_leaves_nobody_owing() {
    // 16 % finder bonus.
    let h = match spawn_or_skip(12, Some(160_000)).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let other = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    const T_REF: u64 = 312_500_000;
    // What the JD-client's own template actually paid: 20 % richer.
    const T_ACTUAL: u64 = 375_000_000;
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, other.as_str(), 100.0, 1_700_000_000_002)
        .await
        .unwrap();
    let result = h
        .engine
        .build_distribution(h.group_id, T_REF, &finder)
        .await
        .expect("build");
    // 16 % bonus on an even two-way split → finder holds 0.16 + 0.42.
    assert_finder_score_fraction(&result.distribution, &finder, 0.58);

    h.engine
        .on_block_found(
            h.group_id,
            9_995_401,
            &actual_paying_exactly(&result, T_ACTUAL),
            &finder,
            None,
            Some(result.payouts_fingerprint()),
        )
        .await
        .expect("apply");

    // Both members are paid their exact §4 share of the RICHER block.
    let paid = actual_paying_exactly(&result, T_ACTUAL);
    let history = read_block_history(&h.pool, h.group_id, 9_995_401).await;
    for who in [&finder, &other] {
        let on_chain = paid
            .paid_by_address
            .get(who.as_str())
            .copied()
            .expect("member must be paid on a 20 %-richer block") as i64;
        assert_eq!(
            history.get(who.as_str()).copied(),
            Some(on_chain),
            "{} history row must transcribe the coinbase exactly",
            who.as_str()
        );
    }
    // And nothing was owed afterwards, because nothing can be.
    assert_eq!(count_group_balance_rows(&h.pool, h.group_id).await, 0);

    drop_harness(h).await;
}

/// `address → paidSats` from the payout history of one block. This is
/// the whole record Group-Solo keeps of a found block: there is no
/// balance table behind it.
async fn read_block_history(
    pool: &PgPool,
    group_id: Uuid,
    block_height: i32,
) -> std::collections::HashMap<String, i64> {
    sqlx::query_as::<_, (String, i64)>(
        r#"SELECT address, "paidSats" FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(group_id)
    .bind(block_height)
    .fetch_all(pool)
    .await
    .expect("read history")
    .into_iter()
    .collect()
}

/// How many `pplns_group_balance` rows this group has. Group-Solo writes
/// none — asserting zero is the sharpest statement of "no ledger", and
/// it fails loudly if a balance write ever creeps back in.
async fn count_group_balance_rows(pool: &PgPool, group_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
        .bind(group_id)
        .fetch_one(pool)
        .await
        .expect("count balances")
}

// ── Test 3b — snapshot-carried apply survives a Redis snapshot overwrite ──
//
// Template rebuilds overwrite the per-(group, finder) Redis snapshot before
// the async apply runs, so the block-found event carries the exact weight
// snapshot and the apply never re-reads Redis. Pins that the carried snapshot
// still settles the frozen job-time inputs after that churn.
#[tokio::test]
async fn snapshot_carried_apply_survives_redis_overwrite() {
    let h = match spawn_or_skip(11, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let reward = 312_500_000;

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();

    // The build the winning job's coinbase came from, and the identity the job
    // carries for it.
    let job = h
        .engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("job-time build ok");

    // Core stamps that exact weight snapshot into the event.
    let frozen = h
        .engine
        .weight_snapshot_for_block_found(h.group_id, &finder, &job.payouts_fingerprint())
        .await
        .expect("freeze snapshot ok");
    assert_eq!(frozen.reference_revenue_sats, reward);

    // Template churn: more shares + a DIFFERENT reward rebuild overwrite the
    // per-(group, finder) Redis snapshot key with a moved round, whose
    // fingerprint no longer matches this block's job.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 50.0, 1_700_000_000_002)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, reward + 999_999, &finder)
        .await
        .expect("churn rebuild ok");

    // The snapshot-carried apply ignores Redis and settles the frozen inputs
    // against the block's real §4 coinbase.
    let block_height = 9_995_010;
    let actual = actual_paying_exactly(&job, reward);
    let outcome = h
        .engine
        .on_block_found(
            h.group_id,
            block_height,
            &actual,
            &finder,
            Some(frozen),
            Some(job.payouts_fingerprint()),
        )
        .await
        .expect("snapshot-carried apply must succeed despite the Redis overwrite");
    assert!(outcome.history_inserted >= 1);

    // History row landed at the frozen reward, and the round reset.
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(block_height)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(count.0 >= 1);

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(stats.total_shares, 0.0, "round wiped on block-found");

    drop_harness(h).await;
}

// ── Test 3b2 — block-found resolves the job's distribution, never a rebuild ──
//
// A rebuild at block-found runs against a round that has moved since the job
// was issued, so the coinbase would pay one split and the history book
// another, and a fresh build passes the reward check by construction. The
// lookup by the winning job's payout-list identity must answer with the
// job-time distribution.
#[tokio::test]
async fn block_found_resolves_the_job_time_distribution_not_a_rebuild() {
    let h = match spawn_or_skip(13, None).await {
        Some(h) => h,
        None => return,
    };
    let a = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let b = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    let reward = 312_500_000;

    // Job time: A holds three quarters of the round.
    h.engine
        .record_share(None, h.group_id, a.as_str(), 300.0, 1)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, b.as_str(), 100.0, 2)
        .await
        .unwrap();
    let job = h
        .engine
        .build_distribution(h.group_id, reward, &a)
        .await
        .expect("job-time build ok");

    // One share lands between job issue and block-found — B overtakes A.
    h.engine
        .record_share(None, h.group_id, b.as_str(), 900.0, 3)
        .await
        .unwrap();

    // Precondition: the round really moved. The settlement identity hashes
    // the inputs, so a moved round means a different fingerprint.
    let rebuilt = h
        .engine
        .build_distribution(h.group_id, reward, &a)
        .await
        .expect("rebuild ok");
    assert_ne!(
        rebuilt.payouts_fingerprint(),
        job.payouts_fingerprint(),
        "the share must have moved the round, else this test proves nothing"
    );

    let snap = h
        .engine
        .weight_snapshot_for_block_found(h.group_id, &a, &job.payouts_fingerprint())
        .await
        .expect("the job's own distribution must resolve");
    assert_eq!(
        snap,
        StoredWeightSnapshot::from_distribution(&job.distribution),
        "block-found must book the settlement inputs the winning job's coinbase was built from"
    );

    drop_harness(h).await;
}

// ── Test 3b2b — an unknown payout list resolves to nothing ───────────
//
// The lookup must fail rather than substitute something: the per-(group,
// finder) key and a fresh build both answer with a split the block's coinbase
// did not pay. The caller turns this into "not booked, needs an operator": a
// wrong booking cannot be undone, a missing one can.
#[tokio::test]
async fn an_unknown_payout_list_resolves_to_nothing() {
    let h = match spawn_or_skip(16, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let reward = 312_500_000;

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    // A real distribution exists — but not under this fingerprint.
    h.engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("build ok");

    let err = h
        .engine
        .weight_snapshot_for_block_found(h.group_id, &finder, &[0x11u8; 32])
        .await
        .expect_err("an unknown payout list must not resolve to some other distribution");
    assert!(
        matches!(err, EngineError::SnapshotMissingForPayouts { .. }),
        "expected SnapshotMissingForPayouts, got {err:?}"
    );

    drop_harness(h).await;
}

// ── Test 3b4 — the apply consumes only its own payout-list snapshot ──
//
// Every member of a group mines a different job, and each job's distribution
// lives under its own key. Booking one block must not strip the others: a
// second block found before the next template rebuild has to resolve too, and
// under the confirmation gate this cleanup runs hours after the fact.
#[tokio::test]
async fn apply_deletes_only_the_payout_list_it_booked() {
    let h = match spawn_or_skip(17, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let other = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    let reward = 312_500_000;

    // Two members, so the payout list actually moves with the round — with a
    // single member every build is 100 % to the same address.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, other.as_str(), 100.0, 2)
        .await
        .unwrap();
    let booked = h
        .engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("build A");

    // A second, still-live job: another share moves the round, so the next
    // build lands under a different payout list.
    h.engine
        .record_share(None, h.group_id, other.as_str(), 900.0, 3)
        .await
        .unwrap();
    let still_live = h
        .engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("build B");
    assert_ne!(
        booked.payouts_fingerprint(),
        still_live.payouts_fingerprint(),
        "the two jobs must carry different payout lists, else this proves nothing"
    );

    h.engine
        .on_block_found(
            h.group_id,
            9_995_021,
            &actual_paying_exactly(&booked, reward),
            &finder,
            None,
            Some(booked.payouts_fingerprint()),
        )
        .await
        .expect("apply ok");

    // The booked one is gone — a redelivered event must not book it twice.
    assert!(
        h.engine
            .weight_snapshot_for_block_found(h.group_id, &finder, &booked.payouts_fingerprint())
            .await
            .is_err(),
        "the applied block's own payout list must be consumed"
    );
    // The other live job is untouched.
    h.engine
        .weight_snapshot_for_block_found(h.group_id, &finder, &still_live.payouts_fingerprint())
        .await
        .expect("a live job's distribution must survive another block's apply");

    drop_harness(h).await;
}

// ── Test 3c — resetRoundOnBlock=false leaves the round intact ──────
//
// The production default: a block-found does NOT wipe the round, so shares
// accumulate across blocks until a calendar preset / manual reset fires.
#[tokio::test]
async fn on_block_found_keeps_round_when_reset_flag_false() {
    let h = match spawn_or_skip(14, None).await {
        Some(h) => h,
        None => return,
    };
    // Flip to the production default (seed_group sets it true).
    sqlx::query(r#"UPDATE pplns_group SET "resetRoundOnBlock" = false WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("flag off");

    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    let dist = h
        .engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    h.engine
        .on_block_found(
            h.group_id,
            9_997_001,
            &actual_paying_exactly(&dist, 312_500_000),
            &finder,
            None,
            Some(dist.payouts_fingerprint()),
        )
        .await
        .expect("ok");

    // Ledger still booked the block...
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(9_997_001)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(count.0 >= 1, "block still booked");

    // ...but the round was NOT wiped — shares persist for the next block.
    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(
        stats.total_shares, 100.0,
        "round must persist when resetRoundOnBlock=false"
    );

    drop_harness(h).await;
}

// ── Test 3d — duplicate block-found does not double the history ──────
//
// A replayed / duplicate block-found for the same height (stream redelivery or
// a stale candidate at the same height) leaves the payout history exactly as
// the first delivery wrote it; the history dedupes via its UNIQUE.
#[tokio::test]
async fn duplicate_block_found_does_not_double_the_history() {
    let h = match spawn_or_skip(15, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let reward = 312_500_000;
    let height = 9_998_001;

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    let job = h
        .engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("job-time build ok");
    let snap = h
        .engine
        .weight_snapshot_for_block_found(h.group_id, &finder, &job.payouts_fingerprint())
        .await
        .expect("snapshot");
    let actual = actual_paying_exactly(&job, reward);

    // First apply.
    h.engine
        .on_block_found(
            h.group_id,
            height,
            &actual,
            &finder,
            Some(snap.clone()),
            Some(job.payouts_fingerprint()),
        )
        .await
        .expect("apply 1");
    let after_first = read_block_history(&h.pool, h.group_id, height).await;
    assert_eq!(after_first.len(), 1, "one member, one history row");
    assert!(after_first[finder.as_str()] > 0);

    // Replay the SAME block-found (duplicate event).
    h.engine
        .on_block_found(
            h.group_id,
            height,
            &actual,
            &finder,
            Some(snap),
            Some(job.payouts_fingerprint()),
        )
        .await
        .expect("apply 2 (replay) must not error");
    let after_replay = read_block_history(&h.pool, h.group_id, height).await;

    assert_eq!(
        after_first, after_replay,
        "a replayed block-found must leave the payout history exactly as the first \
         delivery wrote it"
    );

    // Exactly one history row for the (group, height) survived.
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2 AND address = $3"#,
    )
    .bind(h.group_id)
    .bind(height)
    .bind(finder.as_str())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "history deduped the replay");

    drop_harness(h).await;
}

// ── Test 4 — re-entrancy guard per group ───────────────────────────

#[tokio::test]
async fn on_block_found_re_entrancy_guard_per_group() {
    let h = match spawn_or_skip(3, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    let dist = h
        .engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    let fp = dist.payouts_fingerprint();
    let actual = actual_paying_exactly(&dist, 312_500_000);

    let engine1 = h.engine.clone();
    let engine2 = h.engine.clone();
    let gid = h.group_id;
    let finder1 = finder.clone();
    let finder2 = finder.clone();
    let actual1 = actual.clone();
    let actual2 = actual;
    let task1 = tokio::spawn(async move {
        engine1
            .on_block_found(gid, 9_995_002, &actual1, &finder1, None, Some(fp))
            .await
    });
    let task2 = tokio::spawn(async move {
        engine2
            .on_block_found(gid, 9_995_002, &actual2, &finder2, None, Some(fp))
            .await
    });

    let (r1, r2) = tokio::join!(task1, task2);
    let r1 = r1.unwrap();
    let r2 = r2.unwrap();
    let succeeded = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    let in_flight = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Err(EngineError::BlockFoundInProgress { .. })))
        .count();
    // Exactly one succeeds per (group_id, block_height); the other is either
    // blocked in-flight or sees SnapshotMissing because the first call
    // already consumed the snapshot.
    assert_eq!(succeeded, 1, "exactly one call succeeds");
    let other_handled = in_flight == 1
        || matches!(&r1, Err(EngineError::SnapshotMissing { .. }))
        || matches!(&r2, Err(EngineError::SnapshotMissing { .. }));
    assert!(
        other_handled,
        "second call is either re-entrancy-blocked or sees a cleared snapshot"
    );

    drop_harness(h).await;
}

// ── Test 6 — manual_reset triggers full wipe ───────────────────────

#[tokio::test]
async fn manual_reset_wipes_group_state() {
    let h = match spawn_or_skip(5, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_share(None, h.group_id, "test_eng_reset_a", 50.0, 1)
        .await
        .unwrap();

    let fired = h.engine.manual_reset(h.group_id).await.expect("ok");
    assert!(fired);

    // The round is what a reset wipes — there is nothing else to wipe.
    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(stats.total_shares, 0.0);

    drop_harness(h).await;
}

// ── Test 7 — record_reject is reflected in round_stats ─────────────

#[tokio::test]
async fn record_reject_updates_round_rejected_total() {
    let h = match spawn_or_skip(6, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_reject(h.group_id, "test_eng_rej", 3.0)
        .await
        .unwrap();
    h.engine
        .record_reject(h.group_id, "test_eng_rej", 2.0)
        .await
        .unwrap();

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!((stats.total_rejected - 5.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test 9 — finder bonus + finder shares land in ONE row ──────────
//
// When a group has `finderBonusPpm` set AND the finder also has shares
// this round, the §4 weight model folds the bonus into the finder's
// single weight: one bonus-inclusive coinbase output and one history row
// per address, correctly booked.
#[tokio::test]
async fn on_block_found_with_finder_bonus_merges_duplicate_outputs() {
    // 1.6 % of the miner cut.
    const BONUS_PPM: i32 = 16_000;
    let h = match spawn_or_skip(8, Some(BONUS_PPM)).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let other = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    // Finder + a second miner both contribute, so the finder earns a
    // proportional share ON TOP OF the bonus.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 70.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, other.as_str(), 30.0, 1_700_000_000_002)
        .await
        .unwrap();

    let reward = 312_500_000;
    let result = h
        .engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("build_distribution ok");

    // Exactly one finder output, sitting visibly ABOVE pro-rata (the folded
    // bonus), and the history booking exactly that.
    let entries = result
        .distribution
        .payout_entries_at(reward)
        .expect("§4 payout vector");
    let finder_outputs: Vec<u64> = entries
        .iter()
        .filter(|(a, _)| *a == finder)
        .map(|(_, s)| *s)
        .collect();
    assert_eq!(
        finder_outputs.len(),
        1,
        "finder must appear in EXACTLY one §4 output (bonus folded into the weight)"
    );
    let finder_sats = finder_outputs[0];
    let other_sats = entries
        .iter()
        .find(|(a, _)| *a == other)
        .map(|(_, s)| *s)
        .expect("peer must be paid");
    // Pin the ARITHMETIC, not just the direction: `finder > other · 7/3`
    // holds from integer-division rounding alone, even with no bonus.
    //
    // The bonus is a share of the miner cut taken off the top; the rest
    // splits 70/30. The two miner outputs ARE the miner cut, so deriving
    // the pot from them keeps this independent of the pool fee.
    let pot = (finder_sats + other_sats) as u128;
    let bonus_sats = pot * BONUS_PPM as u128 / 1_000_000;
    let expected_finder = bonus_sats + (pot - bonus_sats) * 7 / 10;
    let drift = (finder_sats as i128) - (expected_finder as i128);
    assert!(
        drift.abs() <= 4,
        "finder output must be bonus + 70 % of the remainder: \
         expected ≈{expected_finder}, got {finder_sats} (off by {drift}; \
         pot={pot}, bonus={bonus_sats}). A zero bonus lands ~{} short.",
        bonus_sats * 3 / 10
    );
    let expected_finder_sats = finder_sats as i64;

    let block_height = 9_995_008;
    let outcome = h
        .engine
        .on_block_found(
            h.group_id,
            block_height,
            &actual_paying_exactly(&result, reward),
            &finder,
            None,
            Some(result.payouts_fingerprint()),
        )
        .await
        .expect("on_block_found ok");
    assert!(outcome.history_inserted >= 1);

    // The history records that single bonus-inclusive output verbatim.
    let history = read_block_history(&h.pool, h.group_id, block_height).await;
    assert_eq!(
        history.get(finder.as_str()).copied(),
        Some(expected_finder_sats),
        "the finder's history row must be the single bonus-inclusive output"
    );

    // Exactly one history coinbase row for the finder for this block.
    let finder_history_rows: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2 AND address = $3"#,
    )
    .bind(h.group_id)
    .bind(block_height)
    .bind(finder.as_str())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        finder_history_rows.0, 1,
        "finder must have exactly one merged coinbase history row"
    );

    drop_harness(h).await;
}

// ── Test 8 — reader.best_difficulty after share ────────────────────

#[tokio::test]
async fn reader_best_difficulty_after_shares() {
    let h = match spawn_or_skip(7, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_share(None, h.group_id, "test_eng_best_a", 50.0, 1)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, "test_eng_best_b", 200.0, 2)
        .await
        .unwrap();

    let best = h
        .engine
        .reader()
        .best_difficulty(h.group_id)
        .await
        .expect("ok")
        .expect("some");
    assert_eq!(best.address, "test_eng_best_b");
    assert!((best.difficulty - 200.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test — reschedule_group arms / re-arms / tears down the reset cron ──

/// Build a `PplnsGroupRow` carrying only the fields `reschedule_group` reads.
fn reset_row(
    id: Uuid,
    active: bool,
    dissolved_at: Option<i64>,
    preset: Option<&str>,
    interval_days: Option<i32>,
    timezone: Option<&str>,
) -> bp_db::PplnsGroupRow {
    bp_db::PplnsGroupRow {
        id,
        name: format!("reset-{id}"),
        creator_address: AddressId::new("test_eng_creator".to_string()).unwrap(),
        admin_token_hash: "hash".to_string(),
        active,
        created_at: 0,
        updated_at: 0,
        dissolved_at,
        round_reset_interval_days: interval_days,
        round_reset_hour_local: None,
        round_reset_timezone: timezone.map(str::to_string),
        last_round_reset_at: None,
        finder_bonus_sats: None,
        finder_bonus_ppm: None,
        round_reset_preset: preset.map(str::to_string),
        is_public: false,
        reset_round_on_block: false,
        max_members: None,
        payout_mode: "prop".to_string(),
    }
}

#[tokio::test]
async fn reschedule_group_arms_and_tears_down_reset_cron() {
    let h = match spawn_or_skip(9, None).await {
        Some(h) => h,
        None => return,
    };
    let id = h.group_id;

    // The startup scan reads EVERY group in `pplns_group`, and concurrent
    // tests in this suite seed groups with presets, so an absolute count
    // races them. Measure this test's own effect as a delta from what the
    // engine armed at startup; only `reschedule_group` moves it afterwards.
    let base = h.engine.reset_task_count();

    // A valid preset arms exactly one cron.
    h.engine
        .reschedule_group(&reset_row(id, true, None, Some("daily"), None, Some("UTC")));
    assert_eq!(h.engine.reset_task_count(), base + 1);

    // A second valid config re-arms in place (old task torn down, one remains).
    h.engine.reschedule_group(&reset_row(
        id,
        true,
        None,
        Some("custom"),
        Some(7),
        Some("UTC"),
    ));
    assert_eq!(h.engine.reset_task_count(), base + 1);

    // Clearing the preset leaves the group unscheduled.
    h.engine
        .reschedule_group(&reset_row(id, true, None, None, None, None));
    assert_eq!(h.engine.reset_task_count(), base);

    // Re-arm, then dissolve → torn down again.
    h.engine
        .reschedule_group(&reset_row(id, true, None, Some("daily"), None, Some("UTC")));
    assert_eq!(h.engine.reset_task_count(), base + 1);
    h.engine.reschedule_group(&reset_row(
        id,
        true,
        Some(123),
        Some("daily"),
        None,
        Some("UTC"),
    ));
    assert_eq!(h.engine.reset_task_count(), base);

    // Re-arm, then deactivate → torn down.
    h.engine
        .reschedule_group(&reset_row(id, true, None, Some("daily"), None, Some("UTC")));
    assert_eq!(h.engine.reset_task_count(), base + 1);
    h.engine.reschedule_group(&reset_row(
        id,
        false,
        None,
        Some("daily"),
        None,
        Some("UTC"),
    ));
    assert_eq!(h.engine.reset_task_count(), base);

    drop_harness(h).await;
}

// ── Core-mode spawn — no startup reset crons, read path intact ─────
//
// `spawn_core` wires the same round-store + distribution builder but skips
// the per-group reset crons (mutating the round is the Satellite's job).
// Proven as a differential: a group with a valid `daily` preset makes the
// *full* engine arm one reset cron at startup, the *core* engine none, and
// `build_distribution` (the Core's job) still works on the core engine.
#[tokio::test]
async fn spawn_core_skips_startup_reset_crons() {
    let pool = match connect_pg_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let full_conn = match connect_redis_or_skip(20).await {
        Some(c) => c,
        None => return,
    };
    let core_conn = match connect_redis_or_skip(21).await {
        Some(c) => c,
        None => return,
    };

    let group_id = Uuid::new_v4();
    cleanup_group(&pool, group_id).await;
    seed_group_with_daily_reset(&pool, group_id).await;

    let config = || GroupSoloEngineConfig {
        // §4: the weight model requires the pool-output recipient.
        fee_address: Some(AddressId::new(FEE_ADDR).unwrap()),
        ..GroupSoloEngineConfig::default()
    };

    // Full engine: startup arms the seeded group's reset cron.
    let full = GroupSoloEngine::spawn(config(), full_conn, pool.clone())
        .await
        .expect("full spawn");
    assert!(
        full.reset_task_count() >= 1,
        "full engine arms the seeded group's daily reset cron at startup"
    );

    // Core engine: same group, startup arms nothing.
    let core = GroupSoloEngine::spawn_core(config(), core_conn, pool.clone())
        .await
        .expect("core spawn");
    assert_eq!(
        core.reset_task_count(),
        0,
        "core mode ran no startup reset crons"
    );

    // The Core's read path still produces a distribution.
    let addr = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    core.record_share(None, group_id, addr.as_str(), 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");
    let result = core
        .build_distribution(group_id, 312_500_000, &addr)
        .await
        .expect("build_distribution ok");
    assert_eq!(result.distribution.reference_revenue_sats, 312_500_000);
    assert!(result.distribution.published().count() > 0);
    assert!(result
        .distribution
        .entries
        .iter()
        .any(|e| e.address == addr));

    full.shutdown();
    core.shutdown();
    cleanup_group(&pool, group_id).await;
}

async fn connect_pg_or_skip() -> Option<PgPool> {
    let pg_url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&pg_url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        _ => {
            eprintln!("PG connect failed/timed out — skipping");
            None
        }
    }
}

/// Connect a flushed Redis logical DB, or `None` to skip.
async fn connect_redis_or_skip(redis_db: u8) -> Option<ConnectionManager> {
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let redis_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::GS_ENGINE, redis_db).await;
    let client = Client::open(format!("{redis_base}/{redis_db}")).ok()?;
    let mut conn = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        _ => {
            eprintln!("redis connect failed/timed out — skipping");
            return None;
        }
    };
    if redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("FLUSHDB failed — skipping");
        return None;
    }
    Some(conn)
}

async fn seed_group_with_daily_reset(pool: &PgPool, group_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusPpm",
              "roundResetPreset", "roundResetTimezone")
           VALUES ($1, $2, 'test_core_creator', $3, true, 0, 0, false, NULL,
                   'daily', 'UTC')"#,
    )
    .bind(group_id)
    .bind(format!("test-core-group-{group_id}"))
    .bind(format!("hash-core-{group_id}"))
    .execute(pool)
    .await
    .expect("seed group with daily reset");
}

// ── Window mode — engine record path trims aged-out buckets ─────────
//
// A 30h-old share and a fresh share into a window-mode group with a 1-day
// window, via the real `GroupSoloEngine::record_share`. The fresh share's
// bucket-boundary crossing fires the trim, and round-stats (which trims with
// wall-clock time) shows the old share gone and the fresh one kept.
// Now-relative timestamps keep the record-path and read-path trims in step.
#[tokio::test]
async fn window_mode_record_path_trims_aged_buckets() {
    let h = match spawn_or_skip(18, None).await {
        Some(h) => h,
        None => return,
    };
    // Flip the seeded group to window mode. The mode has no edit path, but the
    // engine resolves it on the first record, so this test-only UPDATE before
    // any share takes effect. No preset → 1-day window.
    sqlx::query(r#"UPDATE pplns_group SET "payoutMode" = 'window' WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("set window mode");

    let bkt = 3_600_000_i64; // 1h, matches WINDOW_BUCKET_MS
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let t_old = now - 30 * bkt; // 30h ago → outside the 24h window
    let t_new = now;

    h.engine
        .record_share(None, h.group_id, "bc1qold", 40.0, t_old)
        .await
        .expect("record old share");
    h.engine
        .record_share(None, h.group_id, "bc1qnew", 60.0, t_new)
        .await
        .expect("record fresh share");

    // round_stats is window-aware + trims with real wall-clock now.
    let stats = h
        .engine
        .reader()
        .round_stats(h.group_id)
        .await
        .expect("round stats");
    assert!(
        !stats.per_address.contains_key("bc1qold"),
        "30h-old share aged out of the 1-day window"
    );
    assert!(
        (stats.per_address.get("bc1qnew").copied().unwrap_or(0.0) - 60.0).abs() < 1e-9,
        "fresh share retained in the window"
    );

    drop_harness(h).await;
}

// ── Window mode — a reject is windowed like the share it stands next to ─
//
// Drives the real `GroupSoloEngine::record_reject` entry point for a
// window-mode group. The reject must reach round-stats through the trimmed
// reject lane, and the PROP running tally (`rejected-shares`) must stay
// empty: that tally never shrinks, so against a windowed share total it
// would not be a rate of anything.
#[tokio::test]
async fn window_mode_reject_is_windowed_not_tallied() {
    let h = match spawn_or_skip(20, None).await {
        Some(h) => h,
        None => return,
    };
    sqlx::query(r#"UPDATE pplns_group SET "payoutMode" = 'window' WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("set window mode");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    h.engine
        .record_share(None, h.group_id, "bc1qwin", 60.0, now)
        .await
        .expect("record share");
    h.engine
        .record_reject(h.group_id, "bc1qwin", 3.0)
        .await
        .expect("record reject");
    h.engine
        .record_reject(h.group_id, "bc1qwin", 2.0)
        .await
        .expect("record reject");

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!((stats.total_shares - 60.0).abs() < 1e-9);
    assert!(
        (stats.total_rejected - 5.0).abs() < 1e-9,
        "window-mode rejects reach round-stats via the reject lane (got {})",
        stats.total_rejected
    );
    // Negative control: the PROP tally was never written for this group.
    let tally = h
        .engine
        .round()
        .read_rejected(&h.group_id.to_string())
        .await
        .expect("read tally");
    assert!(
        tally.is_empty(),
        "window mode must not touch the PROP tally"
    );

    drop_harness(h).await;
}

// ── Window mode — a kick drops the member from the payout source ─────
//
// Drives the engine entry point the kick hook uses. The distribution reads
// `read_payout_shares`, and so does `round_stats`, so the member vanishing
// from round-stats is the member vanishing from the next coinbase.
#[tokio::test]
async fn window_mode_kick_drops_the_member_from_the_payout_source() {
    let h = match spawn_or_skip(21, None).await {
        Some(h) => h,
        None => return,
    };
    sqlx::query(r#"UPDATE pplns_group SET "payoutMode" = 'window' WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("set window mode");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    h.engine
        .record_share(None, h.group_id, "bc1qkicked", 30.0, now)
        .await
        .expect("record share");
    h.engine
        .record_share(None, h.group_id, "bc1qstays", 70.0, now)
        .await
        .expect("record share");
    let before = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!(
        before.per_address.contains_key("bc1qkicked"),
        "precondition: the member is in the window before the kick"
    );

    let removed = h
        .engine
        .forget_member(h.group_id, "bc1qkicked")
        .await
        .expect("forget");
    assert!((removed - 30.0).abs() < 1e-9);

    let after = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!(
        !after.per_address.contains_key("bc1qkicked"),
        "kicked member left the window payout source"
    );
    assert!((after.per_address["bc1qstays"] - 70.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Window mode — growing the window invalidates the stale mode cache ──
//
// The engine caches window_ms on the first share. After the operator grows
// the window (1 day → monthly = 30d), a stale 1d length would make the next
// record-path trim DELETE a 25h-old bucket the 30d window must keep, and no
// read can bring it back. `invalidate_mode_cache` (called by the API on every
// settings edit) drops the stale entry, so the next share re-reads 30d.
#[tokio::test]
async fn window_grow_invalidates_mode_cache_keeps_in_window_bucket() {
    let h = match spawn_or_skip(10, None).await {
        Some(h) => h,
        None => return,
    };
    // Window mode, no preset → 1-day window (see the trim test above).
    sqlx::query(r#"UPDATE pplns_group SET "payoutMode" = 'window' WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("set window mode");

    let bkt = 3_600_000_i64; // 1h, matches WINDOW_BUCKET_MS
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    // 25h ago: outside the 1-day window, well inside a 30-day window.
    let t_mid = now - 25 * bkt;

    // First share caches window_ms = 1 day. Its own record-path trim uses its
    // own (older) timestamp as "now", so it does not drop itself.
    h.engine
        .record_share(None, h.group_id, "bc1qmid", 40.0, t_mid)
        .await
        .expect("record 25h-old share");

    // Operator grows the window: monthly preset ⇒ 30-day window.
    sqlx::query(r#"UPDATE pplns_group SET "roundResetPreset" = 'monthly' WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("grow window to monthly");
    // The API fires this on every settings edit. With it, the next share
    // re-reads 30d; WITHOUT it, the stale 1d would over-trim.
    h.engine.invalidate_mode_cache(h.group_id);

    // Fresh share crosses a bucket boundary → its record-path trim fires. With
    // the cache invalidated it trims against the 30-day window and keeps bc1qmid.
    h.engine
        .record_share(None, h.group_id, "bc1qnew", 60.0, now)
        .await
        .expect("record fresh share");

    let stats = h
        .engine
        .reader()
        .round_stats(h.group_id)
        .await
        .expect("round stats");
    assert!(
        (stats.per_address.get("bc1qmid").copied().unwrap_or(0.0) - 40.0).abs() < 1e-9,
        "25h-old share kept after window grew to 30 days (stale 1d cache invalidated)"
    );
    assert!(
        (stats.per_address.get("bc1qnew").copied().unwrap_or(0.0) - 60.0).abs() < 1e-9,
        "fresh share present in the window"
    );

    drop_harness(h).await;
}

// ── The settlement gate: subsidy, not the reference revenue ────────
//
// What gets booked comes from the block's own coinbase and is right at any
// revenue, so revenue far off the reference still books; only a coinbase
// paying less than the block's own subsidy is refused.
//
// Heights sit in the current subsidy epoch (4 halvings → 312 500 000
// sats) so the gate is genuinely exercised.

/// A Group-Solo block paying far off the reference revenue still books,
/// each member at their exact share of the real coinbase.
#[tokio::test]
async fn a_group_block_far_off_the_reference_is_still_booked() {
    let h = match spawn_or_skip(19, Some(160_000)).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let other = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    const T_REF: u64 = 312_500_000;
    // 1.6 × the projection base, and well above the block subsidy, so the
    // one hard gate stays out of the way and the booking itself is what is
    // being measured.
    const T_ACTUAL: u64 = 500_000_000;
    let height: i32 = 840_801;
    // T_ACTUAL must be FAR off the projection base, or the test would pass
    // on a block that never exercised the drift.
    const _: () = assert!(
        T_ACTUAL > T_REF + T_REF / 4,
        "the fixture must pay far off the revenue it was built against"
    );

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, other.as_str(), 100.0, 1_700_000_000_002)
        .await
        .unwrap();
    let result = h
        .engine
        .build_distribution(h.group_id, T_REF, &finder)
        .await
        .expect("build");
    // 16 % bonus on an even two-way split → finder holds 0.16 + 0.42.
    assert_finder_score_fraction(&result.distribution, &finder, 0.58);

    h.engine
        .on_block_found(
            h.group_id,
            height,
            &actual_paying_exactly(&result, T_ACTUAL),
            &finder,
            None,
            Some(result.payouts_fingerprint()),
        )
        .await
        .expect("a block off the reference revenue must still book");

    // Both members are paid their exact share even 1.6× off the
    // reference: every weight is a proportion, so nothing is owed
    // afterwards at any revenue.
    let paid = actual_paying_exactly(&result, T_ACTUAL);
    let history = read_block_history(&h.pool, h.group_id, height).await;
    for who in [&finder, &other] {
        let on_chain = paid
            .paid_by_address
            .get(who.as_str())
            .copied()
            .expect("member must be paid") as i64;
        assert_eq!(
            history.get(who.as_str()).copied(),
            Some(on_chain),
            "{} history row must transcribe the coinbase at 1.6× the reference",
            who.as_str()
        );
    }
    assert_eq!(count_group_balance_rows(&h.pool, h.group_id).await, 0);

    drop_harness(h).await;
}

/// Group-Solo settlement refuses a coinbase paying less than the block's
/// own subsidy (money the block was entitled to is gone), and the error is
/// terminal so the confirmation watcher does not retry it forever.
#[tokio::test]
async fn a_group_coinbase_below_the_block_subsidy_is_refused() {
    let h = match spawn_or_skip(4, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    const T_REF: u64 = 312_500_000;
    let height: i32 = 840_802;
    let subsidy = bp_share::block_subsidy_sats(height, bp_share::SUBSIDY_HALVING_INTERVAL);
    assert_eq!(subsidy, 312_500_000, "fixture height must be in epoch 4");

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    let result = h
        .engine
        .build_distribution(h.group_id, T_REF, &finder)
        .await
        .expect("build");

    let err = h
        .engine
        .on_block_found(
            h.group_id,
            height,
            &actual_paying_exactly(&result, subsidy - 1),
            &finder,
            None,
            Some(result.payouts_fingerprint()),
        )
        .await
        .expect_err("a coinbase below the subsidy must not book");
    assert!(
        matches!(
            err,
            bp_group_solo_engine::engine::EngineError::RevenueBelowSubsidy { .. }
        ),
        "expected RevenueBelowSubsidy, got {err}"
    );
    assert!(
        err.is_terminal(),
        "the confirmation watcher must drop this rather than retry it every tick"
    );

    let booked: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(height)
    .fetch_one(&h.pool)
    .await
    .expect("count");
    assert_eq!(booked, 0, "nothing may be booked for a burned block");

    drop_harness(h).await;
}
