// SPDX-License-Identifier: AGPL-3.0-or-later

//! Customer-set extranonce prefix per worker. An address signs a one-time,
//! expiring challenge to be issued a bearer token; the token (stored only as a
//! SHA-256 hash, re-issue revokes) is the reusable credential. `prefix` is a
//! `u32` stored as `bigint` with a range CHECK, which makes the narrowing total.

use bp_common::AddressId;
use sqlx::postgres::PgPool;

use crate::DbError;

/// A pending token-issuance challenge (address-scoped, nonced, expiring).
#[derive(Clone, Debug)]
pub struct ExtranonceChallengeRow {
    pub address: AddressId,
    pub message: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// The issued token's hash for an address.
#[derive(Clone, Debug)]
pub struct ExtranonceTokenRow {
    pub address: AddressId,
    pub token_hash: String,
    pub created_at: i64,
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

// ── Token-issuance challenge ─────────────────────────────────────────

/// INSERT-or-replace the pending challenge for an address. PK address, so a
/// re-request overwrites the old one — only the most recent is ever valid.
pub async fn upsert_extranonce_challenge(
    pool: &PgPool,
    address: &AddressId,
    message: &str,
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<ExtranonceChallengeRow, DbError> {
    let r = sqlx::query!(
        r#"INSERT INTO pplns_extranonce_challenge
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
    .map_err(DbError::from)?;
    Ok(ExtranonceChallengeRow {
        address: r.address,
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
        message: r.message,
        created_at: r.created_at,
        expires_at: r.expires_at,
    }))
}

/// DELETE the pending challenge for an address. Called after a token is issued
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

// ── Bearer token ─────────────────────────────────────────────────────

/// INSERT-or-replace the token hash for an address. PK address, so re-issuing a
/// token overwrites (revokes) the previous one.
pub async fn upsert_extranonce_token(
    pool: &PgPool,
    address: &AddressId,
    token_hash: &str,
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO pplns_extranonce_token (address, "tokenHash", "createdAt")
           VALUES ($1, $2, $3)
           ON CONFLICT (address) DO UPDATE SET
             "tokenHash" = EXCLUDED."tokenHash",
             "createdAt" = EXCLUDED."createdAt""#,
        address.as_str(),
        token_hash,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

pub async fn find_extranonce_token(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<ExtranonceTokenRow>, DbError> {
    sqlx::query_as!(
        ExtranonceTokenRow,
        r#"SELECT
            address AS "address!: AddressId",
            "tokenHash" AS "token_hash!",
            "createdAt" AS "created_at!"
           FROM pplns_extranonce_token WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Applied override ─────────────────────────────────────────────────

/// Apply a batch of `(worker, prefix)` overrides for one address atomically.
/// `UNIQUE (address, prefix)` holds because two Solo workers of one address
/// hash the same coinbase and only the prefix splits their search space; the
/// check is deferred to COMMIT so swapping two workers' prefixes is allowed.
pub async fn upsert_custom_extranonces_batch(
    pool: &PgPool,
    address: &AddressId,
    entries: &[(String, u32)],
    now_ms: i64,
) -> Result<Vec<CustomExtranonceRow>, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::from)?;
    sqlx::query("SET CONSTRAINTS pplns_custom_extranonce_address_prefix_key DEFERRED")
        .execute(&mut *tx)
        .await
        .map_err(DbError::from)?;

    let mut out = Vec::with_capacity(entries.len());
    for (worker, prefix) in entries {
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
            i64::from(*prefix),
            now_ms,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(DbError::from)?;
        out.push(CustomExtranonceRow {
            address: r.address,
            worker: r.worker,
            prefix: prefix_to_u32(r.prefix),
            created_at: r.created_at,
            updated_at: r.updated_at,
        });
    }

    // The deferred UNIQUE check fires HERE — a real duplicate surfaces as a
    // commit error, and nothing has been written.
    tx.commit().await.map_err(DbError::from)?;
    Ok(out)
}

/// Every override this address has stored, ordered by worker. This is what
/// was persisted, not proof the prefix is in effect: that depends on the
/// core's channel gates, which this table does not reflect.
pub async fn find_custom_extranonces_for_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<CustomExtranonceRow>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT
            address AS "address!: AddressId",
            worker AS "worker!",
            prefix AS "prefix!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM pplns_custom_extranonce
           WHERE address = $1
           ORDER BY worker"#,
        address.as_str(),
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

/// Every override, for the stratum core's periodically refreshed cache; a
/// change written by the API reaches the core within one refresh interval.
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
