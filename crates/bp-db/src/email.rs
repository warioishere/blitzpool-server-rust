// SPDX-License-Identifier: AGPL-3.0-or-later

//! Email binding + verification tokens for the Group-Solo invite flow.
//!
//! - `pplns_address_email` — verified email per BTC address (PK address)
//! - `pplns_email_verification` — short-lived verification tokens (PK token)

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct AddressEmailRow {
    pub address: AddressId,
    pub email: String,
    /// Epoch-ms when the email was confirmed; `None` while pending.
    #[sqlx(rename = "verifiedAt")]
    pub verified_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
}

pub async fn find_address_email(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<AddressEmailRow>, DbError> {
    sqlx::query_as!(
        AddressEmailRow,
        r#"SELECT
            address AS "address!: AddressId",
            email AS "email!",
            "verifiedAt" AS "verified_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM pplns_address_email WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct EmailVerificationRow {
    pub token: String,
    pub address: AddressId,
    pub email: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: i64,
}

pub async fn find_email_verification(
    pool: &PgPool,
    token: &str,
) -> Result<Option<EmailVerificationRow>, DbError> {
    sqlx::query_as!(
        EmailVerificationRow,
        r#"SELECT
            token AS "token!",
            address AS "address!: AddressId",
            email AS "email!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!"
           FROM pplns_email_verification WHERE token = $1 LIMIT 1"#,
        token
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Writes for the AddressEmailService ──────────────────────────────

/// INSERT or UPDATE the `pplns_address_email` binding for an address.
/// Used by `verify(token)` once the user clicks the email link — the
/// verified-at timestamp is required (set to now-ms) to record that
/// this is a confirmed binding.
pub async fn upsert_address_email_verified(
    pool: &PgPool,
    address: &AddressId,
    email: &str,
    verified_at_ms: i64,
) -> Result<AddressEmailRow, DbError> {
    sqlx::query_as!(
        AddressEmailRow,
        r#"INSERT INTO pplns_address_email
             (address, email, "verifiedAt", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $3, $3)
           ON CONFLICT (address) DO UPDATE SET
             email = EXCLUDED.email,
             "verifiedAt" = EXCLUDED."verifiedAt",
             "updatedAt" = EXCLUDED."updatedAt"
           RETURNING
            address AS "address!: AddressId",
            email AS "email!",
            "verifiedAt" AS "verified_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!""#,
        address.as_str(),
        email,
        verified_at_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// INSERT a fresh verification token. The token PK + UNIQUE protects
/// against the rare collision; the upstream service deletes prior
/// pending tokens for the same address before calling this.
pub async fn insert_email_verification(
    pool: &PgPool,
    token: &str,
    address: &AddressId,
    email: &str,
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<EmailVerificationRow, DbError> {
    sqlx::query_as!(
        EmailVerificationRow,
        r#"INSERT INTO pplns_email_verification
             (token, address, email, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4, $5)
           RETURNING
            token AS "token!",
            address AS "address!: AddressId",
            email AS "email!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!""#,
        token,
        address.as_str(),
        email,
        created_at_ms,
        expires_at_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// DELETE every pending verification token for one address. Called
/// by `register(address, email)` before issuing a fresh token — only
/// the most recent token should ever be usable.
pub async fn delete_email_verifications_for_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM pplns_email_verification WHERE address = $1"#,
        address.as_str(),
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// DELETE one verification token by its PK. Called by `verify(token)`
/// after the binding upsert succeeds — consumes the token so reuse
/// returns `not-found`.
pub async fn delete_email_verification_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM pplns_email_verification WHERE token = $1"#,
        token,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Cron sweep: DELETE every verification token whose `expiresAt` is
/// past `now_ms`. Runs hourly. Returns the affected-row count for log lines.
pub async fn delete_expired_email_verifications(
    pool: &PgPool,
    now_ms: i64,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM pplns_email_verification WHERE "expiresAt" < $1"#,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
