// SPDX-License-Identifier: AGPL-3.0-or-later

//! An older binary must still boot against a database a newer binary has
//! already migrated (`bp_db::with_boot_policy`). Runs in a throwaway database
//! so the shared test schema's migration table is never touched.

use std::path::{Path, PathBuf};

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{AssertSqlSafe, Executor};

fn migrations_dir(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bp-migration-boot-policy-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, sql) in files {
        std::fs::write(dir.join(name), sql).unwrap();
    }
    dir
}

async fn migrator(dir: &Path) -> Migrator {
    Migrator::new(dir).await.expect("read migrations")
}

#[tokio::test]
async fn an_older_binary_boots_after_a_newer_one_migrated() {
    let url = bp_test_support::pg_url();
    let Some(admin) = bp_test_support::connect_pg_url_or_skip(&url).await else {
        return;
    };
    let db = format!("bp_migration_boot_policy_{}", std::process::id());
    admin
        .execute(AssertSqlSafe(format!(r#"DROP DATABASE IF EXISTS "{db}""#)))
        .await
        .unwrap();
    admin
        .execute(AssertSqlSafe(format!(r#"CREATE DATABASE "{db}""#)))
        .await
        .unwrap();
    let base = url.rsplit_once('/').expect("db url has a path").0;
    let db_url = format!("{base}/{db}");
    let pool = bp_test_support::connect_pg_url_or_skip(&db_url)
        .await
        .expect("throwaway db");

    let first = ("1_first.sql", "CREATE TABLE a (x int);");
    let second = ("2_second.sql", "CREATE TABLE b (x int);");
    let newer = migrations_dir("newer", &[first, second]);
    let older = migrations_dir("older", &[first]);

    // The newer binary migrates first.
    bp_db::with_boot_policy(migrator(&newer).await)
        .run(&pool)
        .await
        .expect("newer binary migrates");

    // Negative control: sqlx's default refuses the unknown version 2. It
    // returns without releasing its advisory lock (at boot the process exits
    // and takes the lock along), so it gets a pool of its own, closed after.
    let refused = bp_test_support::connect_pg_url_or_skip(&db_url)
        .await
        .expect("throwaway db");
    let err = migrator(&older)
        .await
        .run(&refused)
        .await
        .expect_err("default policy must refuse");
    refused.close().await;
    assert!(matches!(err, MigrateError::VersionMissing(2)), "{err}");

    // The boot policy lets the older binary through.
    bp_db::with_boot_policy(migrator(&older).await)
        .run(&pool)
        .await
        .expect("older binary boots");

    pool.close().await;
    let _ = std::fs::remove_dir_all(&newer);
    let _ = std::fs::remove_dir_all(&older);
    admin
        .execute(AssertSqlSafe(format!(
            r#"DROP DATABASE IF EXISTS "{db}" WITH (FORCE)"#
        )))
        .await
        .unwrap();
}
