// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("database error: {0}")]
    Db(#[from] bp_db::DbError),
    #[error("worker_shares seed bootstrap failed: {0}")]
    Seed(String),
}
