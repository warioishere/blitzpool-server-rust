// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionPersistenceError {
    #[error("database error: {0}")]
    Db(#[from] bp_db::DbError),
    #[error("invalid session-persistence configuration: {0}")]
    Config(String),
}
