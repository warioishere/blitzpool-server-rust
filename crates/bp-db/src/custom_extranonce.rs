// SPDX-License-Identifier: AGPL-3.0-or-later

//! Customer-set extranonce prefix per worker.
//!
//! - `pplns_extranonce_challenge` — the short-lived message an address must sign
//!   to authorise ONE change, stored next to the exact change it authorises (PK
//!   address; only the most recent challenge is valid).
//! - `pplns_custom_extranonce`    — the applied override, read at channel-open.
//!
//! Authorisation is a FRESH signature per change. An existing
//! [`crate::is_address_ownership_verified`] row only proves the address signed at
//! some point in the past, which would let anyone post a change for any
//! previously-verified address — so `verify` re-checks a signature over the
//! stored message and confirms that message names this exact `(worker, prefix)`.
//!
//! `prefix` is the 4-byte extranonce prefix, a `u32` everywhere in the pool (see
//! `bp_common::extranonce`). Postgres has no unsigned integer type, so the column
//! is `bigint` with a `CHECK (prefix >= 0 AND prefix <= 4294967295)`. That check
//! is what makes the `bigint -> u32` narrowing below total; these helpers own the
//! conversion so no caller has to know the column is wider than the value.

use bp_common::AddressId;
use sqlx::postgres::PgPool;

use crate::DbError;

/// A pending, signature-authorised extranonce change.
#[derive(Clone, Debug)]
pub struct ExtranonceChallengeRow {
    pub address: AddressId,
    pub worker: String,
    /// The prefix the signed message authorises — compared against the apply
    /// request so a captured signature can't be replayed for a different value.
    pub prefix: u32,
    pub message: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// An applied extranonce override.
#[derive(Clone, Debug)]
pub struct CustomExtranonceRow {
    pub address: AddressId,
    pub worker: String,
    pub prefix: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

/// `bigint` column -> `u32`. Total because of the table's `prefix_u32` CHECK
/// constraint: the database rejects anything outside `0..=u32::MAX` on write, so
/// a row can't hold a value this would truncate.
fn prefix_to_u32(v: i64) -> u32 {
    v as u32
}

/// INSERT-or-replace the pending challenge for an address. PK address, so a
/// re-request overwrites the old one — only the most recent is ever valid.
pub async fn upsert_extranonce_challenge(
    pool: &PgPool,
    address: &AddressId,
    worker: &str,
    prefix: u32,
    message: &str,
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<ExtranonceChallengeRow, DbError> {
    let r = sqlx::query!(
        r#"INSERT INTO pplns_extranonce_challenge
             (address, worker, prefix, message, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (address) DO UPDATE SET
             worker = EXCLUDED.worker,
             prefix = EXCLUDED.prefix,
             message = EXCLUDED.message,
             "createdAt" = EXCLUDED."createdAt",
             "expiresAt" = EXCLUDED."expiresAt"
           RETURNING
            address AS "address!: AddressId",
            worker AS "worker!",
            prefix AS "prefix!",
            message AS "message!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!""#,
        address.as_str(),
        worker,
        i64::from(prefix),
        message,
        created_at_ms,
        expires_at_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(ExtranonceChallengeRow {
        address: r.address,
        worker: r.worker,
        prefix: prefix_to_u32(r.prefix),
        message: r.message,
        created_at: r.created_at,
        expires_at: r.expires_at,
    })
}

pub async fn find_extranonce_challenge(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<ExtranonceChallengeRow>, DbError> {
    let r = sqlx::query!(
        r#"SELECT
            address AS "address!: AddressId",
            worker AS "worker!",
            prefix AS "prefix!",
            message AS "message!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!"
           FROM pplns_extranonce_challenge WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)?;
    Ok(r.map(|r| ExtranonceChallengeRow {
        address: r.address,
        worker: r.worker,
        prefix: prefix_to_u32(r.prefix),
        message: r.message,
        created_at: r.created_at,
        expires_at: r.expires_at,
    }))
}

/// DELETE the pending challenge for an address. Called after a successful apply
/// (consume it) or when it has expired.
pub async fn delete_extranonce_challenge(
    pool: &PgPool,
    address: &AddressId,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM pplns_extranonce_challenge WHERE address = $1"#,
        address.as_str(),
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// INSERT-or-update the override for `(address, worker)`.
///
/// Can fail on the `UNIQUE (address, prefix)` constraint: one address must not
/// point two workers at the same prefix, because in Solo both hash the SAME
/// coinbase (the payout set is the address) and the prefix is then the only
/// thing partitioning their search space. Two *different* addresses may share a
/// prefix — different payouts mean a different coinbase, so their headers differ
/// regardless. The caller surfaces the constraint error as a domain error.
pub async fn upsert_custom_extranonce(
    pool: &PgPool,
    address: &AddressId,
    worker: &str,
    prefix: u32,
    now_ms: i64,
) -> Result<CustomExtranonceRow, DbError> {
    let r = sqlx::query!(
        r#"INSERT INTO pplns_custom_extranonce
             (address, worker, prefix, "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $4)
           ON CONFLICT (address, worker) DO UPDATE SET
             prefix = EXCLUDED.prefix,
             "updatedAt" = EXCLUDED."updatedAt"
           RETURNING
            address AS "address!: AddressId",
            worker AS "worker!",
            prefix AS "prefix!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!""#,
        address.as_str(),
        worker,
        i64::from(prefix),
        now_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(CustomExtranonceRow {
        address: r.address,
        worker: r.worker,
        prefix: prefix_to_u32(r.prefix),
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

pub async fn find_custom_extranonce(
    pool: &PgPool,
    address: &AddressId,
    worker: &str,
) -> Result<Option<CustomExtranonceRow>, DbError> {
    let r = sqlx::query!(
        r#"SELECT
            address AS "address!: AddressId",
            worker AS "worker!",
            prefix AS "prefix!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM pplns_custom_extranonce
           WHERE address = $1 AND worker = $2 LIMIT 1"#,
        address.as_str(),
        worker,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)?;
    Ok(r.map(|r| CustomExtranonceRow {
        address: r.address,
        worker: r.worker,
        prefix: prefix_to_u32(r.prefix),
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

/// DELETE the override for `(address, worker)` — the customer reverting to a
/// pool-allocated prefix. Returns the number of rows removed (0 if none).
pub async fn delete_custom_extranonce(
    pool: &PgPool,
    address: &AddressId,
    worker: &str,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM pplns_custom_extranonce WHERE address = $1 AND worker = $2"#,
        address.as_str(),
        worker,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Every override, for the stratum core's in-memory cache.
///
/// The core refreshes this periodically instead of hitting PG per connection:
/// the table holds a handful of rows (one paying customer), so a full read costs
/// one query per refresh regardless of how many miners are connected. The API
/// process writes; the core reads — they are separate processes, so a change
/// lands on the core within one refresh interval rather than instantly.
pub async fn all_custom_extranonces(pool: &PgPool) -> Result<Vec<CustomExtranonceRow>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT
            address AS "address!: AddressId",
            worker AS "worker!",
            prefix AS "prefix!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM pplns_custom_extranonce"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows
        .into_iter()
        .map(|r| CustomExtranonceRow {
            address: r.address,
            worker: r.worker,
            prefix: prefix_to_u32(r.prefix),
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}
