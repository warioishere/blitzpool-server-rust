// SPDX-License-Identifier: AGPL-3.0-or-later

//! The pending signed challenge of an address proof: a short-lived message the
//! address signs, one per address and [`ChallengePurpose`]. Only the most
//! recent challenge of a purpose is valid.

use bp_common::AddressId;
use sqlx::postgres::PgPool;

use crate::DbError;

/// What a redeemed challenge grants. Keys the challenge next to the address,
/// so a request for one purpose never replaces the other's pending challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// The address-ownership proof.
    Ownership,
    /// The custom-extranonce bearer token.
    Extranonce,
}

impl ChallengePurpose {
    /// The `purpose` column value.
    fn as_str(self) -> &'static str {
        match self {
            ChallengePurpose::Ownership => "ownership",
            ChallengePurpose::Extranonce => "extranonce",
        }
    }
}

/// A pending challenge.
#[derive(Clone, Debug)]
pub struct AddressChallengeRow {
    pub message: String,
    pub expires_at: i64,
}

/// INSERT-or-replace the pending challenge of `purpose` for an address.
pub async fn upsert_address_challenge(
    pool: &PgPool,
    address: &AddressId,
    purpose: ChallengePurpose,
    message: &str,
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO address_challenge
             (address, purpose, message, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (address, purpose) DO UPDATE SET
             message = EXCLUDED.message,
             "createdAt" = EXCLUDED."createdAt",
             "expiresAt" = EXCLUDED."expiresAt""#,
        address.as_str(),
        purpose.as_str(),
        message,
        created_at_ms,
        expires_at_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

pub async fn find_address_challenge(
    pool: &PgPool,
    address: &AddressId,
    purpose: ChallengePurpose,
) -> Result<Option<AddressChallengeRow>, DbError> {
    sqlx::query_as!(
        AddressChallengeRow,
        r#"SELECT
            message AS "message!",
            "expiresAt" AS "expires_at!"
           FROM address_challenge WHERE address = $1 AND purpose = $2"#,
        address.as_str(),
        purpose.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// DELETE the pending challenge of `purpose` for an address: consumed after a
/// successful redeem, or expired.
pub async fn delete_address_challenge(
    pool: &PgPool,
    address: &AddressId,
    purpose: ChallengePurpose,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM address_challenge WHERE address = $1 AND purpose = $2"#,
        address.as_str(),
        purpose.as_str(),
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
