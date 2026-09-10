// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Integration tests for `miner_identity` — the stored payout identity.
//!
//! The subject is mostly the **`CHECK` constraint**, not the DAO. Rust already
//! makes a half-populated identity unrepresentable (`bp_common::PayoutIdentity`
//! is a sum type); the constraint is what extends that to everything else that
//! can write to this database — a psql session, an admin script, a future ORM.
//! So these tests write the bad rows *directly*, bypassing the DAO, because
//! going through the DAO would only re-test Rust.
//!
//! Per `CLAUDE.md`: these are Postgres-backed, so `connect_or_skip` makes them
//! **pass** when the container is down. Start it first
//! (`docker start bp-test-pg`), run with `--nocapture`, and read the
//! passed-count — a skipped test is indistinguishable from a passing one in
//! `$?`. New migrations are NOT applied to that container automatically:
//! `0014_add_miner_identity.sql` must be applied or every test here fails on
//! the missing relation.

use bp_db::{
    find_miner_identity, find_rotating_identities, upsert_rotating_identity,
    upsert_static_identity, KIND_ROTATING, KIND_STATIC,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// A real derived descriptor and its `payout_id`, so the widths under test are
/// the widths production sees.
const DESCRIPTOR: &str = "wpkh([00000000/84'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)#checksum";
const ROTATING_ID: &str = "xpbDvdXsU17hMXJncLySBtpKYsBPNZVX1AZmUcG8ccuQZz9";
const STATIC_ADDR: &str = "bc1qminerident0001test";
/// A second rotating id, so tests that both write a rotating row do not race —
/// they share one Postgres and `cargo test` runs them concurrently.
const OTHER_ROTATING_ID: &str = "xpbOtherRotatingIdForCoverageTest01";

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

async fn cleanup(pool: &PgPool, ids: &[&str]) {
    for id in ids {
        sqlx::query(r#"DELETE FROM miner_identity WHERE "payoutId" = $1"#)
            .bind(id)
            .execute(pool)
            .await
            .expect("cleanup delete");
    }
}

/// Raw insert, bypassing the DAO — this is how the constraint gets tested
/// against something the Rust types would never build.
async fn raw_insert(
    pool: &PgPool,
    payout_id: &str,
    kind: &str,
    address: Option<&str>,
    descriptor: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO miner_identity ("payoutId", kind, address, descriptor)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(payout_id)
    .bind(kind)
    .bind(address)
    .bind(descriptor)
    .execute(pool)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn a_static_identity_round_trips_with_no_descriptor() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool, &[STATIC_ADDR]).await;

    upsert_static_identity(&pool, STATIC_ADDR, 1_700_000_000_000)
        .await
        .expect("static upsert");

    let row = find_miner_identity(&pool, STATIC_ADDR)
        .await
        .expect("read")
        .expect("the row exists");
    assert_eq!(row.kind, KIND_STATIC);
    assert_eq!(row.address.as_deref(), Some(STATIC_ADDR));
    assert_eq!(
        row.descriptor, None,
        "a static identity has no descriptor — not an addr() sentinel, NULL"
    );
    // For a static identity the ledger key IS the address; nothing derives it.
    assert_eq!(row.payout_id, STATIC_ADDR);

    cleanup(&pool, &[STATIC_ADDR]).await;
}

#[tokio::test]
async fn a_rotating_identity_round_trips_with_no_address() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool, &[ROTATING_ID]).await;

    upsert_rotating_identity(&pool, ROTATING_ID, DESCRIPTOR, 1_700_000_000_000)
        .await
        .expect("rotating upsert");

    let row = find_miner_identity(&pool, ROTATING_ID)
        .await
        .expect("read")
        .expect("the row exists");
    assert_eq!(row.kind, KIND_ROTATING);
    assert_eq!(row.descriptor.as_deref(), Some(DESCRIPTOR));
    assert_eq!(
        row.address, None,
        "a rotating identity has no fixed address — that is the whole point"
    );
    // The descriptor is 130+ chars and lives in TEXT; only the ledger key is
    // bound by the identity shape. Both widths are read from
    // `bp_common::MAX_ADDRESS_LEN` rather than written as a literal, because the
    // number moved once already (62 → 90, `0015_widen_identity_columns.sql`) and
    // a literal here would have gone on claiming the old one.
    assert!(
        DESCRIPTOR.len() > bp_common::MAX_ADDRESS_LEN,
        "precondition: the descriptor must exceed the identity-column width, or \
         this test is not exercising the TEXT column"
    );
    assert!(
        ROTATING_ID.len() <= bp_common::MAX_ADDRESS_LEN,
        "the ledger key must fit varchar({})",
        bp_common::MAX_ADDRESS_LEN
    );

    let all = find_rotating_identities(&pool).await.expect("bulk read");
    assert!(
        all.iter().any(|r| r.payout_id == ROTATING_ID),
        "the rotating bulk read must find it"
    );
    assert!(
        all.iter().all(|r| r.kind == KIND_ROTATING),
        "the rotating bulk read must not return static rows"
    );

    cleanup(&pool, &[ROTATING_ID]).await;
}

/// **The constraint, in every direction it can be violated.**
///
/// This is the test that earns the `CHECK`. Each case is a row that Rust's sum
/// type cannot express but that any other writer to this database can, and each
/// must be refused by Postgres rather than stored and met later by a `match`
/// with no arm for it — or, worse, by coinbase assembly finding a rotating
/// identity with no descriptor to derive from.
///
/// Per `CLAUDE.md`'s *"a test that claims a safeguard must be shown to fail
/// without it"*: the two legitimate rows at the end are the negative control.
/// If the constraint were over-broad — refusing everything — the rejections
/// below would all still pass while the feature was entirely broken, and only
/// the accepted rows catch that.
#[tokio::test]
async fn the_check_constraint_refuses_every_half_populated_identity() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let ids = [
        "xpbCHK_rot_no_desc",
        "xpbCHK_rot_with_addr",
        "xpbCHK_static_no_addr",
        "xpbCHK_static_with_desc",
        "xpbCHK_both",
        "xpbCHK_unknown_kind",
        "xpbCHK_ok_static",
        "xpbCHK_ok_rotating",
    ];
    cleanup(&pool, &ids).await;

    let refused: [(&str, &str, Option<&str>, Option<&str>); 6] = [
        // A rotating identity with nothing to derive from. The one that would
        // reach coinbase assembly and have no script to produce.
        ("xpbCHK_rot_no_desc", KIND_ROTATING, None, None),
        // Rotating, but carrying a fixed address — two answers to "what does
        // this miner get paid".
        (
            "xpbCHK_rot_with_addr",
            KIND_ROTATING,
            Some("bc1qwrong"),
            None,
        ),
        // Static with no address to pay.
        ("xpbCHK_static_no_addr", KIND_STATIC, None, None),
        // Static, but carrying a descriptor — the `addr()`-sentinel shape this
        // design deliberately does not use.
        (
            "xpbCHK_static_with_desc",
            KIND_STATIC,
            None,
            Some(DESCRIPTOR),
        ),
        // Both populated: the ambiguity the sum type exists to prevent.
        (
            "xpbCHK_both",
            KIND_STATIC,
            Some("bc1qboth"),
            Some(DESCRIPTOR),
        ),
        // A kind no Rust `match` has an arm for.
        ("xpbCHK_unknown_kind", "banana", Some("bc1qbanana"), None),
    ];

    for (id, kind, address, descriptor) in refused {
        let err = raw_insert(&pool, id, kind, address, descriptor)
            .await
            .expect_err(&format!(
                "the CHECK must refuse ({kind}, address={address:?}, descriptor={descriptor:?})"
            ));
        let text = err.to_string();
        assert!(
            text.contains("CHK_miner_identity_kind_populated"),
            "refused for the wrong reason ({id}): {text}"
        );
    }

    // ── Negative control: the two legitimate shapes ARE accepted ──────
    // Without these, a constraint that rejected every row would pass every
    // assertion above.
    raw_insert(
        &pool,
        "xpbCHK_ok_static",
        KIND_STATIC,
        Some("bc1qfine"),
        None,
    )
    .await
    .expect("a well-formed static identity must be accepted");
    raw_insert(
        &pool,
        "xpbCHK_ok_rotating",
        KIND_ROTATING,
        None,
        Some(DESCRIPTOR),
    )
    .await
    .expect("a well-formed rotating identity must be accepted");

    cleanup(&pool, &ids).await;
}

/// Switching kinds cannot leave the other column populated — the upserts clear
/// it, and the CHECK would refuse the row if they did not.
#[tokio::test]
async fn switching_kind_clears_the_other_column() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ID: &str = "bc1qswitchkindtest01";
    cleanup(&pool, &[ID]).await;

    upsert_static_identity(&pool, ID, 1_700_000_000_000)
        .await
        .expect("static first");
    let before = find_miner_identity(&pool, ID)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(before.kind, KIND_STATIC);
    assert!(before.address.is_some(), "precondition: address populated");

    // Same ledger key, now rotating. Contrived — a real rotating id is derived
    // from its descriptor — but it is the write that must not half-apply.
    upsert_rotating_identity(&pool, ID, DESCRIPTOR, 1_700_000_001_000)
        .await
        .expect("switch to rotating");
    let after = find_miner_identity(&pool, ID)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(after.kind, KIND_ROTATING);
    assert_eq!(after.descriptor.as_deref(), Some(DESCRIPTOR));
    assert_eq!(
        after.address, None,
        "the stale address must be cleared, not left beside the descriptor"
    );
    assert!(after.updated_at > before.updated_at, "updatedAt must move");

    // And back again.
    upsert_static_identity(&pool, ID, 1_700_000_002_000)
        .await
        .expect("switch back to static");
    let back = find_miner_identity(&pool, ID)
        .await
        .expect("read")
        .expect("row");
    assert_eq!(back.kind, KIND_STATIC);
    assert_eq!(
        back.descriptor, None,
        "the stale descriptor must be cleared"
    );

    cleanup(&pool, &[ID]).await;
}

#[tokio::test]
async fn an_unknown_payout_id_reads_as_none() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    assert_eq!(
        find_miner_identity(&pool, "xpbNOSUCHIDENTITY0000")
            .await
            .expect("read"),
        None,
        "a missing identity is None, not a default — a default here would pay \
         somebody"
    );
}

/// **The rotating bulk read is the only read on the money path, and a static
/// miner is invisible to it whether or not the backfill covered them.**
///
/// The backfill in `0014_add_miner_identity.sql` copies `pplns_balance` only, so
/// a Solo miner with no pending balance and every Group-Solo member (that mode
/// keeps no ledger) have no row here. The migration's comment states the rule
/// that makes that safe: this table is read to discover that an identity
/// *rotates*, never to discover where to pay a static one.
///
/// So the two static miners below — one with a row, one without — must be
/// indistinguishable to `find_rotating_identities`. If a later phase inverts
/// this and starts resolving static payouts through this table, the miner
/// covered by the backfill keeps working and the one who was never in
/// `pplns_balance` stops being paid; this test is what makes that a failure now
/// rather than a support ticket then.
#[tokio::test]
async fn a_static_miner_is_absent_from_the_rotating_read_covered_by_the_backfill_or_not() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const BACKFILLED: &str = "bc1qbackfilled0001test";
    const NEVER_SEEN: &str = "bc1qneverinbalance01test";
    cleanup(&pool, &[BACKFILLED, OTHER_ROTATING_ID]).await;

    // One static miner has a row (as the backfill would have left it); the other
    // never got one. Neither is written for NEVER_SEEN — that is the point.
    upsert_static_identity(&pool, BACKFILLED, 1_700_000_000_000)
        .await
        .expect("static upsert");
    assert!(
        find_miner_identity(&pool, NEVER_SEEN)
            .await
            .expect("read")
            .is_none(),
        "precondition: the uncovered miner must have no row, or this test is \
         comparing a row against a row"
    );

    let rotating = find_rotating_identities(&pool).await.expect("bulk read");
    for addr in [BACKFILLED, NEVER_SEEN] {
        assert!(
            !rotating.iter().any(|r| r.payout_id == addr),
            "{addr} is static and must not appear in the rotating read"
        );
    }

    // Negative control: the read is not simply empty. A rotating identity IS
    // found, so "absent" above means absent-because-static.
    upsert_rotating_identity(&pool, OTHER_ROTATING_ID, DESCRIPTOR, 1_700_000_000_000)
        .await
        .expect("rotating upsert");
    let rotating = find_rotating_identities(&pool).await.expect("bulk read");
    assert!(
        rotating.iter().any(|r| r.payout_id == OTHER_ROTATING_ID),
        "the rotating read must find a rotating identity, or the assertions \
         above pass on an empty result"
    );

    cleanup(&pool, &[BACKFILLED, OTHER_ROTATING_ID]).await;
}
