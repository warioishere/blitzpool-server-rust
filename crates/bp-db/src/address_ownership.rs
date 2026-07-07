// SPDX-License-Identifier: AGPL-3.0-or-later

//! BTC address-ownership proof via message signature.
//!
//! - `pplns_ownership_challenge` — the short-lived exact message an address must
//!   sign (PK address; only the most recent challenge is valid).
//! - `pplns_address_ownership`   — the verified ownership binding (PK address).
//!
//! A generic "this address proved control of its key" primitive: consumed by the
//! group-invite eligibility gate (a 2nd option next to the verified email) and,
//! later, the custom-extranonce override auth gate.

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct OwnershipChallengeRow {
    pub address: AddressId,
    pub message: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Clone, Debug, FromRow)]
pub struct AddressOwnershipRow {
    pub address: AddressId,
    /// Signature family that verified: `bip322` | `bip137` | `electrum`.
    pub method: String,
    /// Resolved script type: `p2pkh` | `p2sh-p2wpkh` | `p2wpkh` | `p2tr`.
    #[sqlx(rename = "scriptType")]
    pub script_type: String,
    #[sqlx(rename = "verifiedAt")]
    pub verified_at: i64,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
}

/// INSERT-or-replace the pending challenge for an address. PK address, so a
/// re-request overwrites the old one — only the most recent is ever valid.
pub async fn upsert_ownership_challenge(
    pool: &PgPool,
    address: &AddressId,
    message: &str,
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<OwnershipChallengeRow, DbError> {
    sqlx::query_as!(
        OwnershipChallengeRow,
        r#"INSERT INTO pplns_ownership_challenge
             (address, message, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (address) DO UPDATE SET
             message = EXCLUDED.message,
             "createdAt" = EXCLUDED."createdAt",
             "expiresAt" = EXCLUDED."expiresAt"
           RETURNING
            address AS "address!: AddressId",
            message AS "message!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!""#,
        address.as_str(),
        message,
        created_at_ms,
        expires_at_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_ownership_challenge(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<OwnershipChallengeRow>, DbError> {
    sqlx::query_as!(
        OwnershipChallengeRow,
        r#"SELECT
            address AS "address!: AddressId",
            message AS "message!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!"
           FROM pplns_ownership_challenge WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// DELETE the pending challenge for an address. Called after a successful verify
/// (consume it) or when it has expired.
pub async fn delete_ownership_challenge(
    pool: &PgPool,
    address: &AddressId,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM pplns_ownership_challenge WHERE address = $1"#,
        address.as_str(),
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// INSERT-or-update the verified ownership binding for an address.
pub async fn upsert_address_ownership_verified(
    pool: &PgPool,
    address: &AddressId,
    method: &str,
    script_type: &str,
    verified_at_ms: i64,
) -> Result<AddressOwnershipRow, DbError> {
    sqlx::query_as!(
        AddressOwnershipRow,
        r#"INSERT INTO pplns_address_ownership
             (address, method, "scriptType", "verifiedAt", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $4, $4)
           ON CONFLICT (address) DO UPDATE SET
             method = EXCLUDED.method,
             "scriptType" = EXCLUDED."scriptType",
             "verifiedAt" = EXCLUDED."verifiedAt",
             "updatedAt" = EXCLUDED."updatedAt"
           RETURNING
            address AS "address!: AddressId",
            method AS "method!",
            "scriptType" AS "script_type!",
            "verifiedAt" AS "verified_at!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!""#,
        address.as_str(),
        method,
        script_type,
        verified_at_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_address_ownership(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<AddressOwnershipRow>, DbError> {
    sqlx::query_as!(
        AddressOwnershipRow,
        r#"SELECT
            address AS "address!: AddressId",
            method AS "method!",
            "scriptType" AS "script_type!",
            "verifiedAt" AS "verified_at!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM pplns_address_ownership WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// True when the address has a verified ownership binding. The shared read used
/// by both consumers (group-invite eligibility, custom-extranonce auth gate).
pub async fn is_address_ownership_verified(
    pool: &PgPool,
    address: &AddressId,
) -> Result<bool, DbError> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(
             SELECT 1 FROM pplns_address_ownership WHERE address = $1
           ) AS "exists!""#,
        address.as_str()
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Batch form of [`is_address_ownership_verified`]: given a set of addresses,
/// return the subset that has a signature-ownership proof — one query instead of
/// one per address (avoids an N+1 fan-out on the roster read paths). Empty input
/// short-circuits without a round-trip.
pub async fn addresses_with_ownership_proof(
    pool: &PgPool,
    addresses: &[String],
) -> Result<std::collections::HashSet<String>, DbError> {
    if addresses.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let rows = sqlx::query_scalar!(
        r#"SELECT address AS "address!"
           FROM pplns_address_ownership WHERE address = ANY($1)"#,
        addresses,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows.into_iter().collect())
}

/// True when the address is verified by EITHER a confirmed email binding
/// (`pplns_address_email.verifiedAt`) OR a signature ownership proof
/// (`pplns_address_ownership`). This is the unified onboarding gate — a joining
/// address must satisfy one of the two. Existing verified emails keep counting.
pub async fn is_address_verified(pool: &PgPool, address: &AddressId) -> Result<bool, DbError> {
    sqlx::query_scalar!(
        r#"SELECT (
             EXISTS(SELECT 1 FROM pplns_address_email WHERE address = $1 AND "verifiedAt" IS NOT NULL)
             OR EXISTS(SELECT 1 FROM pplns_address_ownership WHERE address = $1)
           ) AS "verified!""#,
        address.as_str()
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}
