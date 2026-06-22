// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate error type. Distinguishes DB-layer errors (`DbError` flowing
//! up from `bp_db`) from configuration mistakes and the one-shot
//! seed-bootstrap path's specific failure mode.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("database error: {0}")]
    Db(#[from] bp_db::DbError),
    #[error("invalid sink configuration: {0}")]
    Config(String),
    #[error("worker_shares seed bootstrap failed: {0}")]
    Seed(String),
}
