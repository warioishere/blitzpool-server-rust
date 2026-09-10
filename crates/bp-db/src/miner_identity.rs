// SPDX-License-Identifier: AGPL-3.0-or-later

//! `miner_identity` — the stored payout identity, one row per miner.
//!
//! The database half of `bp_common::PayoutIdentity`. `kind` is `'static'`
//! (pays a fixed address) or `'rotating'` (pays a script derived from a
//! descriptor at each block's height), and a `CHECK` constraint makes the
//! half-populated combinations unrepresentable — see
//! `crates/bp-db/migrations/0014_add_miner_identity.sql`.
//!
//! **Reads come back as [`MinerIdentityRow`], not as a `PayoutIdentity`.**
//! Converting here would put a second constructor for the sum type in the data
//! layer, and `bp-common` cannot depend on `miniscript` to validate a descriptor
//! (see `bp-payout-descriptor`). So the row is the raw shape and the caller runs
//! it through intake, which is the only thing that has ever validated a
//! descriptor. One validator, one constructor.

use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

/// The `kind` discriminant, spelled once.
///
/// A `&str` at each call site would let a typo insert a row that no Rust
/// `match` has an arm for — the CHECK would refuse it, but at the far end of a
/// write path rather than at compile time.
pub const KIND_STATIC: &str = "static";
pub const KIND_ROTATING: &str = "rotating";

/// One `miner_identity` row, verbatim.
///
/// `address` and `descriptor` are both `Option` because the table's `CHECK`
/// (not this struct) is what guarantees exactly one is populated. Mirroring
/// that as a Rust sum type here would mean re-deriving the discriminant from
/// which field is `Some` — and `CLAUDE.md` is explicit that reading a per-mode
/// field's `is_some()` as a mode test is the defect, not the design. Callers
/// `match` on [`Self::kind`].
#[derive(Clone, Debug, FromRow, PartialEq, Eq)]
pub struct MinerIdentityRow {
    /// The height-invariant ledger key. For `'static'` this is the address
    /// itself; for `'rotating'` it is `bp_payout_descriptor`'s `payout_id`.
    #[sqlx(rename = "payoutId")]
    pub payout_id: String,
    /// [`KIND_STATIC`] or [`KIND_ROTATING`].
    pub kind: String,
    /// Populated iff `kind == KIND_STATIC`.
    pub address: Option<String>,
    /// Populated iff `kind == KIND_ROTATING`. A wallet-watching capability —
    /// do not log it, and do not return it from an unauthenticated endpoint.
    pub descriptor: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
}

/// Point-read by ledger key.
pub async fn find_miner_identity(
    pool: &PgPool,
    payout_id: &str,
) -> Result<Option<MinerIdentityRow>, DbError> {
    let row = sqlx::query_as!(
        MinerIdentityRow,
        r#"SELECT
             "payoutId" AS "payout_id!",
             kind AS "kind!",
             address,
             descriptor,
             "createdAt" AS "created_at!",
             "updatedAt" AS "updated_at!"
           FROM miner_identity
           WHERE "payoutId" = $1"#,
        payout_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record a static identity: the ledger key IS the address.
///
/// Idempotent. The `UPDATE` clears `descriptor`, so a miner who moves from a
/// rotating identity back to a fixed address cannot leave a stale descriptor
/// behind — and could not even if it tried, because the CHECK forbids the row
/// that would result.
pub async fn upsert_static_identity(
    pool: &PgPool,
    address: &str,
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO miner_identity ("payoutId", kind, address, "createdAt", "updatedAt")
           VALUES ($1, 'static', $1, $2, $2)
           ON CONFLICT ("payoutId") DO UPDATE SET
             kind = 'static',
             address = EXCLUDED.address,
             descriptor = NULL,
             "updatedAt" = EXCLUDED."updatedAt""#,
        address,
        now_ms
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a rotating identity: `payout_id` is derived from the descriptor by
/// `bp_payout_descriptor`, which is also the only thing that has validated it.
///
/// This function does **not** validate the descriptor — it cannot, because
/// `bp-db` has no `miniscript` dependency and should not grow one. Passing an
/// unvalidated string here stores an identity that may panic at derivation, so
/// the only supported caller is one holding a `RotatingPayout`.
pub async fn upsert_rotating_identity(
    pool: &PgPool,
    payout_id: &str,
    descriptor: &str,
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO miner_identity ("payoutId", kind, descriptor, "createdAt", "updatedAt")
           VALUES ($1, 'rotating', $2, $3, $3)
           ON CONFLICT ("payoutId") DO UPDATE SET
             kind = 'rotating',
             descriptor = EXCLUDED.descriptor,
             address = NULL,
             "updatedAt" = EXCLUDED."updatedAt""#,
        payout_id,
        descriptor,
        now_ms
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Every rotating identity, for the payout path to resolve descriptors in bulk.
pub async fn find_rotating_identities(pool: &PgPool) -> Result<Vec<MinerIdentityRow>, DbError> {
    let rows = sqlx::query_as!(
        MinerIdentityRow,
        r#"SELECT
             "payoutId" AS "payout_id!",
             kind AS "kind!",
             address,
             descriptor,
             "createdAt" AS "created_at!",
             "updatedAt" AS "updated_at!"
           FROM miner_identity
           WHERE kind = 'rotating'"#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
