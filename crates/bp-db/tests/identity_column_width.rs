// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! The identity columns are as wide as `bp_common::MAX_ADDRESS_LEN` says.
//!
//! Phase 5 of the payout-identity plan, and **not** part of that feature: the
//! break it closes is older than xpubs. Every identity column was
//! `character varying(62)` — exactly the width of a mainnet `bc1p…` taproot
//! address, with zero spare — so a **regtest** taproot address, which is 64
//! characters, could never be stored. `0015_widen_identity_columns.sql` took all
//! 32 of them to 90.
//!
//! Two claims live here, and neither can be checked from Rust alone:
//!
//! 1. Every column is wide enough. Asked of `information_schema` rather than
//!    against a copy of the migration's 32-name list, so a table added later
//!    with the old width is a failure here instead of a silent gap.
//! 2. A 64-character address survives a real write and read. With a negative
//!    control in the same test — the identical insert against a `varchar(62)`
//!    column — because otherwise a passing round-trip proves only that 64 bytes
//!    fit in *something*.
//!
//! Per `CLAUDE.md`: Postgres-backed, so `connect_or_skip` makes these **pass**
//! when the container is down. `docker start bp-test-pg`, run with
//! `--nocapture`, and read the passed-count. Migration 0015 is NOT applied to
//! that container automatically — without it test 1 names all 32 columns and
//! test 2 fails on the write.

use bp_common::MAX_ADDRESS_LEN;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// A real bech32m P2TR on regtest: `bcrt1p` + 52 data + 6 checksum = 64 chars.
/// The address this whole migration exists for.
const REGTEST_P2TR: &str = "bcrt1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusgm2jyk";

/// The columns the identity shape applies to, as a catalog predicate rather than
/// a list. `descriptor` is deliberately absent — it is `text`, and the shape
/// applies to the ledger key, never to the descriptor.
const IDENTITY_COLUMNS: &str = r#"
    SELECT table_name, column_name, character_maximum_length
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND data_type = 'character varying'
       AND column_name IN ('address', 'payoutId', 'minerAddress',
                           'creatorAddress', 'adminAddress')
     ORDER BY table_name, column_name
"#;

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

/// No identity column is narrower than the cap Rust enforces.
///
/// The two numbers have to agree in both directions: the Rust cap is what keeps
/// an over-long value from reaching a column, and the column width is what makes
/// the cap's number load-bearing rather than decorative. A column narrower than
/// the cap is a write that passes validation and then fails in the database.
#[tokio::test]
async fn every_identity_column_is_at_least_as_wide_as_the_rust_cap() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    let rows = sqlx::query(IDENTITY_COLUMNS)
        .fetch_all(&pool)
        .await
        .expect("read information_schema");

    // Precondition, so an empty result cannot pass as "all columns fine" — the
    // predicate finding nothing would mean the schema was never loaded.
    assert!(
        rows.len() >= 32,
        "precondition: expected the 32 identity columns 0015 widened, found {} \
         — is this container's schema loaded at all?",
        rows.len()
    );

    let narrow: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let len: i32 = r.get("character_maximum_length");
            (len < MAX_ADDRESS_LEN as i32).then(|| {
                format!(
                    "{}.{} is varchar({len})",
                    r.get::<String, _>("table_name"),
                    r.get::<String, _>("column_name"),
                )
            })
        })
        .collect();

    assert!(
        narrow.is_empty(),
        "{} identity column(s) cannot hold what bp_common accepts \
         (MAX_ADDRESS_LEN = {MAX_ADDRESS_LEN}); apply \
         0015_widen_identity_columns.sql:\n  {}",
        narrow.len(),
        narrow.join("\n  ")
    );
}

/// A 64-character regtest taproot address survives a write and a read — in a
/// money column and in the identity table — and would not have before 0011.
///
/// The `varchar(62)` control is what makes this more than a tautology. It is the
/// same value through the same driver into the same database, differing only in
/// the column width, and it must fail with SQLSTATE `22001`
/// (`string_data_right_truncation`) — the error every one of these columns used
/// to produce.
#[tokio::test]
async fn a_regtest_taproot_address_round_trips_through_the_widened_columns() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    assert_eq!(
        REGTEST_P2TR.len(),
        64,
        "precondition: the address under test must be 64 chars"
    );

    // ── negative control: the width these columns used to have ──────────
    //
    // A temporary table, so it is torn down with the connection and cannot
    // outlive a failure. Both statements run on **one** pooled connection,
    // because a TEMPORARY table is visible only to the session that made it —
    // handing the INSERT to a different connection gets `42P01 undefined_table`
    // and the control silently stops testing the width.
    let mut conn = pool.acquire().await.expect("acquire a connection");
    sqlx::query("CREATE TEMPORARY TABLE bp_width_control (address character varying(62))")
        .execute(&mut *conn)
        .await
        .expect("create control table");
    let control = sqlx::query("INSERT INTO bp_width_control (address) VALUES ($1)")
        .bind(REGTEST_P2TR)
        .execute(&mut *conn)
        .await;
    match control {
        Err(sqlx::Error::Database(e)) => assert_eq!(
            e.code().as_deref(),
            Some("22001"),
            "control must fail as right-truncation, not something else: {e}"
        ),
        Err(e) => panic!("control must fail in the database, not the driver: {e}"),
        Ok(_) => panic!(
            "control INSERT succeeded — a 64-char address fit a varchar(62) \
             column, so this test proves nothing about the widening"
        ),
    }

    // ── the real thing ──────────────────────────────────────────────────
    let cleanup = |p: PgPool| async move {
        sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(REGTEST_P2TR)
            .execute(&p)
            .await
            .expect("cleanup pplns_balance");
        sqlx::query(r#"DELETE FROM miner_identity WHERE "payoutId" = $1"#)
            .bind(REGTEST_P2TR)
            .execute(&p)
            .await
            .expect("cleanup miner_identity");
    };
    cleanup(pool.clone()).await;

    // A money column: this is where a payout balance for that address lives.
    sqlx::query(r#"INSERT INTO pplns_balance (address, "balanceSats") VALUES ($1, $2)"#)
        .bind(REGTEST_P2TR)
        .bind(12_345_i64)
        .execute(&pool)
        .await
        .expect("a 64-char address must store in pplns_balance");
    let (stored, sats): (String, i64) =
        sqlx::query_as(r#"SELECT address, "balanceSats" FROM pplns_balance WHERE address = $1"#)
            .bind(REGTEST_P2TR)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(
        stored, REGTEST_P2TR,
        "the address must come back byte-for-byte, not silently truncated"
    );
    assert_eq!(sats, 12_345, "and the balance with it");

    // And the identity table, where the same string is a static payout id.
    bp_db::upsert_static_identity(&pool, REGTEST_P2TR, 1_700_000_000_000)
        .await
        .expect("a 64-char address must store as a static identity");
    let row = bp_db::find_miner_identity(&pool, REGTEST_P2TR)
        .await
        .expect("read")
        .expect("the row exists");
    assert_eq!(row.payout_id, REGTEST_P2TR);
    assert_eq!(row.address.as_deref(), Some(REGTEST_P2TR));

    cleanup(pool).await;
}
