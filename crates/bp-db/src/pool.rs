// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connection pool wrapper + crate-level error type.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Cheap clone-able handle to the Postgres connection pool.
/// Internally `PgPool` is an `Arc`, so this just bumps a ref-count.
#[derive(Clone, Debug)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Connect to Postgres with sensible default pool sizing.
    pub async fn connect(database_url: &str) -> Result<Self, DbError> {
        Self::connect_with(database_url, DbConfig::default()).await
    }

    /// Connect with explicit pool configuration.
    pub async fn connect_with(database_url: &str, config: DbConfig) -> Result<Self, DbError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .idle_timeout(Some(config.idle_timeout))
            .test_before_acquire(true)
            .connect(database_url)
            .await?;
        Ok(Db { pool })
    }

    /// Apply pending migrations from `crates/bp-db/migrations`. sqlx holds an
    /// advisory lock while it runs, so every process may call this at boot;
    /// the first one applies the pending set.
    pub async fn run_migrations(&self) -> Result<(), DbError> {
        with_boot_policy(sqlx::migrate!()).run(&self.pool).await?;
        Ok(())
    }

    /// Borrow the underlying `sqlx::PgPool` for direct query execution.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Close the pool, draining all open connections.
    pub async fn close(&self) {
        self.pool.close().await
    }
}

/// Unknown applied migrations are ignored at boot: processes are deployed one
/// at a time, so a binary one release older must still start after a newer one
/// migrated. Hence every migration must not break that older binary: add,
/// don't rename; drop a column only once no running image reads it.
pub fn with_boot_policy(mut migrator: sqlx::migrate::Migrator) -> sqlx::migrate::Migrator {
    migrator.set_ignore_missing(true);
    migrator
}

/// Pool sizing + timeout knobs. Defaults are conservative for a single
/// blitzpool process; tune via env in `bp-config`.
#[derive(Clone, Copy, Debug)]
pub struct DbConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("address shape invalid: {0}")]
    Address(#[from] bp_common::InvalidAddressError),
    #[error("unknown mining mode: {0}")]
    Mode(#[from] bp_common::UnknownMiningModeError),
}

/// Take advisory lock `key` until the caller's transaction ends; the
/// `_xact_` variant releases on rollback too, so an error cannot leak it.
pub(crate) async fn take_xact_lock(conn: &mut sqlx::PgConnection, key: i64) -> Result<(), DbError> {
    sqlx::query!("SELECT pg_advisory_xact_lock($1)", key)
        .execute(conn)
        .await
        .map_err(DbError::from)?;
    Ok(())
}
