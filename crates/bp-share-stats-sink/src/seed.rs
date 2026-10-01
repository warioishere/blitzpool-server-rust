// SPDX-License-Identifier: AGPL-3.0-or-later

//! Seeds an empty `worker_shares_entity` from `client_statistics_entity` at
//! boot, so per-worker charts are not blank on a fresh database.

use bp_db::{count_worker_shares, seed_worker_shares_from_client_statistics};
use sqlx::{PgConnection, PgPool};
use tracing::{info, instrument};

use crate::error::SinkError;

/// Check + seed on a caller-supplied connection, so tests can roll it back.
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

/// `Some(rows_inserted)` if the table was empty, else `None`. Check and
/// insert share one transaction so concurrent spawns cannot both seed.
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
