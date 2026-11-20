// SPDX-License-Identifier: AGPL-3.0-or-later

//! BTC address-ownership proof, the binding a redeemed
//! [`ChallengePurpose::Ownership`](crate::ChallengePurpose::Ownership)
//! challenge leaves. Gates Team and Blockparty onboarding, as an alternative
//! to a verified email.

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

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

/// True when the address has a verified ownership binding.
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

/// Batch form of [`is_address_ownership_verified`]: the subset of `addresses`
/// with a proof, in one query so roster reads avoid an N+1 fan-out.
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

/// How an address proved it is the miner's, the onboarding gate of every
/// Team and Blockparty path: a confirmed email binding or a signature
/// ownership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressVerification {
    /// A confirmed email; preferred when both exist, as rows keep the email.
    Email(String),
    /// A signature ownership proof and no confirmed email.
    Signature,
}

/// The address's [`AddressVerification`], `None` when it has neither.
pub async fn find_address_verification(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<AddressVerification>, DbError> {
    let row = sqlx::query!(
        r#"SELECT
             (SELECT email FROM pplns_address_email
               WHERE address = $1 AND "verifiedAt" IS NOT NULL) AS "email?",
             EXISTS(SELECT 1 FROM pplns_address_ownership WHERE address = $1) AS "signature!""#,
        address.as_str()
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(match (row.email, row.signature) {
        (Some(email), _) => Some(AddressVerification::Email(email)),
        (None, true) => Some(AddressVerification::Signature),
        (None, false) => None,
    })
}
