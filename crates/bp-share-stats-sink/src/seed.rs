// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-time one-shot seeding of `worker_shares_entity` from existing
//! `client_statistics_entity` rows.
//!
//! ## When it fires
//!
//! Only when `worker_shares_entity` is empty. The check + the seed
//! INSERT run in the same transaction so two simultaneous engine
//! spawns can't both populate (the second sees the row count and bails).
//! After cut-over against prod-DB this never fires (the original migration
//! already ran). On fresh staging / regtest-DB setups
//! it bootstraps the table so per-worker chart endpoints aren't blank.

use bp_db::{count_worker_shares, seed_worker_shares_from_client_statistics};
use sqlx::{PgConnection, PgPool};
use tracing::{info, instrument};

use crate::error::SinkError;

/// Check + seed under a caller-supplied connection / transaction. Used
/// by integration tests that wrap the call in a TX-rollback for isolation.
pub async fn seed_if_empty_with_executor(
    conn: &mut PgConnection,
) -> Result<Option<u64>, SinkError> {
    let existing = count_worker_shares(&mut *conn).await?;
    if existing > 0 {
        return Ok(None);
    }
    let inserted = seed_worker_shares_from_client_statistics(&mut *conn).await?;
    info!(rows_inserted = inserted, "worker_shares_entity seeded");
    Ok(Some(inserted))
}

/// Returns `Some(rows_inserted)` if the seed fired (table was empty),
/// `None` if no-op (table was already populated). Wrapped in a tx so the
/// "check + insert" pair stays atomic across concurrent spawns.
#[instrument(skip(pool), name = "stats_sink.seed_if_empty")]
pub async fn seed_if_empty(pool: &PgPool) -> Result<Option<u64>, SinkError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SinkError::Seed(format!("begin tx: {e}")))?;

    let outcome = seed_if_empty_with_executor(&mut tx).await?;
    if outcome.is_some() {
        tx.commit()
            .await
            .map_err(|e| SinkError::Seed(format!("commit seed tx: {e}")))?;
    } else {
        tx.rollback()
            .await
            .map_err(|e| SinkError::Seed(format!("rollback noop tx: {e}")))?;
    }
    Ok(outcome)
}
