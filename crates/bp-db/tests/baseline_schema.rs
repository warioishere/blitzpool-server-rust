// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! `0000_baseline.sql`: the boot migrations build the schema on an empty
//! database, and leave a database that already has it untouched. Runs in
//! throwaway databases so the shared test schema is never touched.

use std::path::PathBuf;

use sqlx::migrate::Migrator;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

async fn connect(url: &str) -> Option<PgPool> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(url),
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

/// A fresh empty database; returns the admin pool (to drop it again), the
/// database's name and its URL.
async fn throwaway_db(tag: &str) -> Option<(PgPool, String, String)> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let admin = connect(&url).await?;
    let db = format!("bp_baseline_{tag}_{}", std::process::id());
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{db}" WITH (FORCE)"#).as_str())
        .await
        .unwrap();
    admin
        .execute(format!(r#"CREATE DATABASE "{db}""#).as_str())
        .await
        .unwrap();
    let base = url.rsplit_once('/').expect("db url has a path").0;
    Some((admin, db.clone(), format!("{base}/{db}")))
}

async fn drop_db(admin: &PgPool, db: &str) {
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{db}" WITH (FORCE)"#).as_str())
        .await
        .unwrap();
}

/// Tables, columns, constraints and indexes of `public`, one line each and
/// sorted: equal fingerprints mean the migration run left the schema alone.
async fn schema_fingerprint(pool: &PgPool) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT format('col %s.%s %s null=%s default=%s', table_name, column_name,
                      data_type, is_nullable, coalesce(column_default, '-'))
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations'
        UNION ALL
        SELECT format('con %s %s %s', conrelid::regclass, conname, pg_get_constraintdef(oid))
        FROM pg_constraint
        WHERE connamespace = 'public'::regnamespace
        UNION ALL
        SELECT format('idx %s', indexdef)
        FROM pg_indexes
        WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations'
        ORDER BY 1
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap();
    rows.into_iter().map(|(r,)| r).collect()
}

async fn public_tables(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = 'public' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn an_empty_database_boots_to_the_full_schema() {
    let Some((admin, db, db_url)) = throwaway_db("empty").await else {
        return;
    };

    // Negative control: the same migrations without the baseline fail on an
    // empty database, which is how every fresh deploy failed before it.
    let without_baseline =
        std::env::temp_dir().join(format!("bp-baseline-without-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&without_baseline);
    std::fs::create_dir_all(&without_baseline).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in std::fs::read_dir(&source).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("0000_") {
            std::fs::copy(&path, without_baseline.join(&name)).unwrap();
        }
    }
    let refused = connect(&db_url).await.expect("throwaway db");
    let err = bp_db::with_boot_policy(Migrator::new(without_baseline.as_path()).await.unwrap())
        .run(&refused)
        .await
        .expect_err("migrations alone cannot build the schema");
    refused.close().await;
    let _ = std::fs::remove_dir_all(&without_baseline);
    assert!(
        err.to_string().contains("does not exist"),
        "expected a missing base table, got: {err}"
    );
    drop_db(&admin, &db).await;
    admin
        .execute(format!(r#"CREATE DATABASE "{db}""#).as_str())
        .await
        .unwrap();

    // The production path.
    let pool = bp_db::Db::connect(&db_url).await.expect("throwaway db");
    pool.run_migrations()
        .await
        .expect("boot migrations on an empty database");

    let tables = public_tables(pool.pool()).await;
    for t in [
        "pplns_group",
        "pplns_balance",
        "blocks_entity",
        "client_statistics_entity",
        "blockparty_group",
        "pplns_custom_extranonce",
        "redis_state_backup",
    ] {
        assert!(tables.iter().any(|x| x == t), "{t} missing: {tables:?}");
    }
    // A column only a later migration adds (0009), and 0016's partial index:
    // the baseline is the state after 0016, not the TS pool's.
    let fp = schema_fingerprint(pool.pool()).await;
    assert!(fp
        .iter()
        .any(|l| l.starts_with("col pplns_group.finderBonusPpm ")));
    assert!(fp
        .iter()
        .any(|l| l.contains("UQ_blockparty_group_admin_address_live")));

    // A second boot has nothing to do.
    pool.run_migrations().await.expect("second boot");
    assert_eq!(schema_fingerprint(pool.pool()).await, fp);

    pool.close().await;
    drop_db(&admin, &db).await;
}

/// Prod's shape: every base table exists (built long before the baseline) and
/// `_sqlx_migrations` has no version 0. The baseline must record itself and
/// change nothing.
#[tokio::test]
async fn the_baseline_leaves_an_existing_schema_alone() {
    let Some((admin, db, db_url)) = throwaway_db("existing").await else {
        return;
    };
    let pool = bp_db::Db::connect(&db_url).await.expect("throwaway db");
    pool.run_migrations().await.expect("build the schema");
    let before = schema_fingerprint(pool.pool()).await;
    assert!(
        before.len() > 100,
        "precondition: a real schema, got {before:?}"
    );

    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 0")
        .execute(pool.pool())
        .await
        .unwrap();

    // Had the guard not skipped, the unguarded CREATE TABLEs inside it would
    // fail on the existing tables and this run would error.
    pool.run_migrations()
        .await
        .expect("the baseline runs against an existing schema");
    let recorded: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 0 AND success)",
    )
    .fetch_one(pool.pool())
    .await
    .unwrap();
    assert!(recorded, "version 0 must be recorded as applied");
    assert_eq!(schema_fingerprint(pool.pool()).await, before);

    pool.close().await;
    drop_db(&admin, &db).await;
}
