// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thin wrappers around the two `bp-db` client-row primitives so the
//! hook impl in [`crate::hooks`] doesn't have to construct
//! `bp_db::ClientUpsert` directly.

use std::time::{SystemTime, UNIX_EPOCH};

use bp_db::{delete_client_for_session, upsert_client, ClientUpsert};
use sqlx::PgPool;

use crate::error::SessionPersistenceError;

/// Upsert a `client_entity` row for a freshly-authorized session.
/// `start_time_ms` defaults to system clock if `None`.
pub async fn register_client(
    pool: &PgPool,
    address: &str,
    client_name: &str,
    session_id: &str,
    user_agent: Option<&str>,
    start_time_ms: Option<i64>,
    current_difficulty: Option<f32>,
) -> Result<u64, SessionPersistenceError> {
    let row = ClientUpsert {
        address: address.to_string(),
        client_name: client_name.to_string(),
        session_id: session_id.to_string(),
        user_agent: user_agent.map(|s| s.to_string()),
        start_time_ms: start_time_ms.unwrap_or_else(now_ms),
        current_difficulty,
    };
    let n = upsert_client(pool, &row).await?;
    Ok(n)
}

/// Soft-delete the rows for `session_id`. Silently updates 0 rows if
/// the session doesn't exist — returning 0 is not an error.
pub async fn deregister_client(
    pool: &PgPool,
    session_id: &str,
) -> Result<u64, SessionPersistenceError> {
    let n = delete_client_for_session(pool, session_id).await?;
    Ok(n)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
