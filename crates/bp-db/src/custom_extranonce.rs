// SPDX-License-Identifier: AGPL-3.0-or-later

//! Customer-set extranonce prefix per worker, with a stored bearer token.
//!
//! - `pplns_extranonce_challenge` — the short-lived message an address signs to
//!   be issued a token (PK address, nonced + expiring, consumed on issue — so
//!   the signature itself is one-time and never a reusable credential).
//! - `pplns_extranonce_token`     — the issued token's hash (PK address).
//!   Re-issuing overwrites it, which revokes the previous token.
//! - `pplns_custom_extranonce`    — the applied override, read at channel-open.
//!
//! The token (not the signature) is the reusable credential: the customer signs
//! once to be issued a token, then presents that token on every headless
//! "set the EN for worker X" call. Only its SHA-256 hash is stored, mirroring
//! `pplns_group.adminTokenHash`.
//!
//! `prefix` is the 4-byte extranonce prefix, a `u32` everywhere in the pool (see
//! `bp_common::extranonce`). Postgres has no unsigned integer type, so the column
//! is `bigint` with a `CHECK (prefix >= 0 AND prefix <= 4294967295)`. That check
//! is what makes the `bigint -> u32` narrowing below total; these helpers own the
//! conversion so no caller has to know the column is wider than the value.

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

/// Apply a whole batch of `(worker, prefix)` overrides for ONE address
/// atomically — all rows land or none do.
///
/// Runs in a single transaction with the `UNIQUE (address, prefix)` check
/// **deferred to COMMIT**. That is what makes a *swap* possible: setting
/// `rig1` to `rig2`'s current prefix would otherwise collide with rig2's
/// still-unchanged row and abort the batch, even though the end state is
/// perfectly valid. Deferring moves the check to the end, where only the
/// final state matters — a genuine duplicate (two workers left on the same
/// prefix) still fails, and the error surfaces from `commit()`.
///
/// Returns the rows as written. The caller is responsible for rejecting
/// in-batch duplicates up front so it can name the offending worker; this
/// function's own guarantee is atomicity, not diagnosis.
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
