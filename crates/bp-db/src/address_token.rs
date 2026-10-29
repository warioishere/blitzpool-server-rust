// SPDX-License-Identifier: AGPL-3.0-or-later

//! Address-token revocation: per address key, the moment before which every
//! token issued for it is void.

use sqlx::postgres::PgPool;

use crate::DbError;

/// The moment before which tokens for `address_key` are void, if any.
pub async fn find_token_revoked_before(
    pool: &PgPool,
    address_key: &str,
) -> Result<Option<i64>, DbError> {
    let row = sqlx::query_scalar!(
        r#"SELECT "revokedBefore" FROM address_token_revocation WHERE "addressKey" = $1"#,
        address_key
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Move the moment for `address_key` up to `revoked_before`, never back.
pub async fn raise_token_revoked_before(
    pool: &PgPool,
    address_key: &str,
    revoked_before: i64,
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO address_token_revocation ("addressKey", "revokedBefore", "updatedAt")
           VALUES ($1, $2, $3)
           ON CONFLICT ("addressKey") DO UPDATE SET
             "revokedBefore" = GREATEST(
               address_token_revocation."revokedBefore", EXCLUDED."revokedBefore"
             ),
             "updatedAt" = EXCLUDED."updatedAt""#,
        address_key,
        revoked_before,
        now_ms
    )
    .execute(pool)
    .await?;
    Ok(())
}
