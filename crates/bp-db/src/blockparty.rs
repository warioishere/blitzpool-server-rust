// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty mining mode — group / member / invitation / block-history rows.
//!
//! - `blockparty_group` — UUID PK, status FSM (draft/confirming/ready/active/dissolved)
//! - `blockparty_member` — bigint PK, UNIQUE on address (pool-wide single membership)
//! - `blockparty_invitation` — token PK, partial unique on (groupId, address) WHERE status='pending'
//! - `blockparty_block_history` — bigint PK, UNIQUE (groupId, blockHash) for replay-safety

use bp_common::{AddressId, Sats};
use sqlx::{postgres::PgPool, types::Json, FromRow};
use uuid::Uuid;

use crate::DbError;

// ─── Group ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, FromRow)]
pub struct BlockpartyGroupRow {
    pub id: Uuid,
    pub name: String,
    #[sqlx(rename = "adminAddress")]
    pub admin_address: AddressId,
    #[sqlx(rename = "adminTokenHash")]
    pub admin_token_hash: String,
    pub status: String,
    #[sqlx(rename = "lastShareAt")]
    pub last_share_at: Option<i64>,
    #[sqlx(rename = "rentalProviderHint")]
    pub rental_provider_hint: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    #[sqlx(rename = "dissolvedAt")]
    pub dissolved_at: Option<i64>,
}

pub async fn find_blockparty_group<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<BlockpartyGroupRow>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        BlockpartyGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "adminAddress" AS "admin_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            status AS "status!",
            "lastShareAt" AS "last_share_at?",
            "rentalProviderHint" AS "rental_provider_hint?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?"
           FROM blockparty_group WHERE id = $1 LIMIT 1"#,
        id,
    )
    .fetch_optional(executor)
    .await
    .map_err(DbError::from)
}

pub async fn find_blockparty_group_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<BlockpartyGroupRow>, DbError> {
    sqlx::query_as!(
        BlockpartyGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "adminAddress" AS "admin_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            status AS "status!",
            "lastShareAt" AS "last_share_at?",
            "rentalProviderHint" AS "rental_provider_hint?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?"
           FROM blockparty_group WHERE name = $1 LIMIT 1"#,
        name,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_blockparty_group_by_admin_address(
    pool: &PgPool,
    admin_address: &AddressId,
) -> Result<Option<BlockpartyGroupRow>, DbError> {
    sqlx::query_as!(
        BlockpartyGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "adminAddress" AS "admin_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            status AS "status!",
            "lastShareAt" AS "last_share_at?",
            "rentalProviderHint" AS "rental_provider_hint?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?"
           FROM blockparty_group WHERE "adminAddress" = $1 LIMIT 1"#,
        admin_address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn list_blockparty_groups(pool: &PgPool) -> Result<Vec<BlockpartyGroupRow>, DbError> {
    sqlx::query_as!(
        BlockpartyGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "adminAddress" AS "admin_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            status AS "status!",
            "lastShareAt" AS "last_share_at?",
            "rentalProviderHint" AS "rental_provider_hint?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?"
           FROM blockparty_group ORDER BY "createdAt" ASC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn list_blockparty_groups_non_dissolved(
    pool: &PgPool,
) -> Result<Vec<BlockpartyGroupRow>, DbError> {
    sqlx::query_as!(
        BlockpartyGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "adminAddress" AS "admin_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            status AS "status!",
            "lastShareAt" AS "last_share_at?",
            "rentalProviderHint" AS "rental_provider_hint?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?"
           FROM blockparty_group WHERE status <> 'dissolved' ORDER BY "createdAt" ASC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_blockparty_group(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    admin_address: &AddressId,
    admin_token_hash: &str,
    status: &str,
    created_at: i64,
) -> Result<BlockpartyGroupRow, DbError> {
    sqlx::query_as!(
        BlockpartyGroupRow,
        r#"INSERT INTO blockparty_group
            (id, name, "adminAddress", "adminTokenHash", status, "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, $6)
           RETURNING
            id AS "id!",
            name AS "name!",
            "adminAddress" AS "admin_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            status AS "status!",
            "lastShareAt" AS "last_share_at?",
            "rentalProviderHint" AS "rental_provider_hint?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?""#,
        id,
        name,
        admin_address.as_str(),
        admin_token_hash,
        status,
        created_at,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn update_blockparty_group_status<'e, E>(
    executor: E,
    id: Uuid,
    status: &str,
    updated_at: i64,
) -> Result<(), DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"UPDATE blockparty_group
           SET status = $2, "updatedAt" = $3
           WHERE id = $1"#,
        id,
        status,
        updated_at,
    )
    .execute(executor)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

pub async fn update_blockparty_group_last_share_and_status(
    pool: &PgPool,
    id: Uuid,
    last_share_at: i64,
    status: &str,
    updated_at: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"UPDATE blockparty_group
           SET "lastShareAt" = $2, status = $3, "updatedAt" = $4
           WHERE id = $1"#,
        id,
        last_share_at,
        status,
        updated_at,
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

pub async fn update_blockparty_group_dissolved(
    pool: &PgPool,
    id: Uuid,
    dissolved_at: i64,
    updated_at: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"UPDATE blockparty_group
           SET status = 'dissolved', "dissolvedAt" = $2, "updatedAt" = $3
           WHERE id = $1"#,
        id,
        dissolved_at,
        updated_at,
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

pub async fn update_blockparty_group_rental_hint(
    pool: &PgPool,
    id: Uuid,
    hint: Option<&str>,
    updated_at: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"UPDATE blockparty_group
           SET "rentalProviderHint" = $2, "updatedAt" = $3
           WHERE id = $1"#,
        id,
        hint,
        updated_at,
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

// ─── Member ────────────────────────────────────────────────────────

#[derive(Clone, Debug, FromRow)]
pub struct BlockpartyMemberRow {
    pub id: i64,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    pub address: AddressId,
    pub email: String,
    #[sqlx(rename = "percentBp")]
    pub percent_bp: i32,
    pub role: String,
    #[sqlx(rename = "confirmedAt")]
    pub confirmed_at: Option<i64>,
    #[sqlx(rename = "memberTokenHash")]
    pub member_token_hash: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
}

pub async fn find_blockparty_member_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<BlockpartyMemberRow>, DbError> {
    sqlx::query_as!(
        BlockpartyMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            "percentBp" AS "percent_bp!",
            role AS "role!",
            "confirmedAt" AS "confirmed_at?",
            "memberTokenHash" AS "member_token_hash?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM blockparty_member WHERE address = $1 LIMIT 1"#,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_blockparty_member_in_group(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
) -> Result<Option<BlockpartyMemberRow>, DbError> {
    sqlx::query_as!(
        BlockpartyMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            "percentBp" AS "percent_bp!",
            role AS "role!",
            "confirmedAt" AS "confirmed_at?",
            "memberTokenHash" AS "member_token_hash?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM blockparty_member WHERE "groupId" = $1 AND address = $2 LIMIT 1"#,
        group_id,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn list_blockparty_members_for_group<'e, E>(
    executor: E,
    group_id: Uuid,
) -> Result<Vec<BlockpartyMemberRow>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        BlockpartyMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            "percentBp" AS "percent_bp!",
            role AS "role!",
            "confirmedAt" AS "confirmed_at?",
            "memberTokenHash" AS "member_token_hash?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM blockparty_member WHERE "groupId" = $1 ORDER BY id ASC"#,
        group_id,
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)
}

pub async fn list_all_blockparty_members(
    pool: &PgPool,
) -> Result<Vec<BlockpartyMemberRow>, DbError> {
    sqlx::query_as!(
        BlockpartyMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            "percentBp" AS "percent_bp!",
            role AS "role!",
            "confirmedAt" AS "confirmed_at?",
            "memberTokenHash" AS "member_token_hash?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!"
           FROM blockparty_member"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_blockparty_member(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
    email: &str,
    percent_bp: i32,
    role: &str,
    confirmed_at: Option<i64>,
    created_at: i64,
) -> Result<BlockpartyMemberRow, DbError> {
    sqlx::query_as!(
        BlockpartyMemberRow,
        r#"INSERT INTO blockparty_member
            ("groupId", address, email, "percentBp", role, "confirmedAt", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
           RETURNING
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            "percentBp" AS "percent_bp!",
            role AS "role!",
            "confirmedAt" AS "confirmed_at?",
            "memberTokenHash" AS "member_token_hash?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!""#,
        group_id,
        address.as_str(),
        email,
        percent_bp,
        role,
        confirmed_at,
        created_at,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn update_blockparty_member_percent_bp(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
    percent_bp: i32,
    updated_at: i64,
) -> Result<u64, DbError> {
    sqlx::query!(
        r#"UPDATE blockparty_member
           SET "percentBp" = $3, "updatedAt" = $4
           WHERE "groupId" = $1 AND address = $2"#,
        group_id,
        address.as_str(),
        percent_bp,
        updated_at,
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
    .map_err(DbError::from)
}

pub async fn update_blockparty_member_confirmed<'e, E>(
    executor: E,
    group_id: Uuid,
    address: &AddressId,
    confirmed_at: Option<i64>,
    member_token_hash: Option<&str>,
    updated_at: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"UPDATE blockparty_member
           SET "confirmedAt" = $3, "memberTokenHash" = $4, "updatedAt" = $5
           WHERE "groupId" = $1 AND address = $2"#,
        group_id,
        address.as_str(),
        confirmed_at,
        member_token_hash,
        updated_at,
    )
    .execute(executor)
    .await
    .map(|r| r.rows_affected())
    .map_err(DbError::from)
}

/// Clear `confirmedAt` + `memberTokenHash` so the next invitation
/// accept for this address mints a fresh persistent member token.
pub async fn reset_blockparty_member_onboarding(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
    updated_at: i64,
) -> Result<u64, DbError> {
    sqlx::query!(
        r#"UPDATE blockparty_member
           SET "confirmedAt" = NULL, "memberTokenHash" = NULL, "updatedAt" = $3
           WHERE "groupId" = $1 AND address = $2"#,
        group_id,
        address.as_str(),
        updated_at,
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
    .map_err(DbError::from)
}

pub async fn delete_blockparty_member(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
) -> Result<u64, DbError> {
    sqlx::query!(
        r#"DELETE FROM blockparty_member WHERE "groupId" = $1 AND address = $2"#,
        group_id,
        address.as_str(),
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
    .map_err(DbError::from)
}

// ─── Invitation ────────────────────────────────────────────────────

#[derive(Clone, Debug, FromRow)]
pub struct BlockpartyInvitationRow {
    pub token: String,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    pub address: AddressId,
    pub email: String,
    pub status: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: i64,
    #[sqlx(rename = "respondedAt")]
    pub responded_at: Option<i64>,
}

pub async fn find_blockparty_invitation_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<BlockpartyInvitationRow>, DbError> {
    sqlx::query_as!(
        BlockpartyInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?"
           FROM blockparty_invitation WHERE token = $1 LIMIT 1"#,
        token,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_blockparty_invitation_pending_for_group_address(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
) -> Result<Option<BlockpartyInvitationRow>, DbError> {
    sqlx::query_as!(
        BlockpartyInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?"
           FROM blockparty_invitation
           WHERE "groupId" = $1 AND address = $2 AND status = 'pending'
           LIMIT 1"#,
        group_id,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn list_blockparty_invitations_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Vec<BlockpartyInvitationRow>, DbError> {
    sqlx::query_as!(
        BlockpartyInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?"
           FROM blockparty_invitation WHERE "groupId" = $1 ORDER BY "createdAt" DESC"#,
        group_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_blockparty_invitation(
    pool: &PgPool,
    token: &str,
    group_id: Uuid,
    address: &AddressId,
    email: &str,
    created_at: i64,
    expires_at: i64,
) -> Result<BlockpartyInvitationRow, DbError> {
    sqlx::query_as!(
        BlockpartyInvitationRow,
        r#"INSERT INTO blockparty_invitation
            (token, "groupId", address, email, status, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4, 'pending', $5, $6)
           RETURNING
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?""#,
        token,
        group_id,
        address.as_str(),
        email,
        created_at,
        expires_at,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn update_blockparty_invitation_status(
    pool: &PgPool,
    token: &str,
    status: &str,
    responded_at: Option<i64>,
) -> Result<u64, DbError> {
    sqlx::query!(
        r#"UPDATE blockparty_invitation
           SET status = $2, "respondedAt" = $3
           WHERE token = $1"#,
        token,
        status,
        responded_at,
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
    .map_err(DbError::from)
}

// ─── Block history ─────────────────────────────────────────────────

/// Per-member payout snapshot recorded on block-found. Re-exported from
/// the pure-logic crate so the JSONB column type matches the engine's
/// output by construction.
pub use bp_blockparty::BlockpartySplitSnapshot;

#[derive(Clone, Debug, FromRow)]
pub struct BlockpartyBlockHistoryRow {
    pub id: i64,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    #[sqlx(rename = "blockHeight")]
    pub block_height: i32,
    #[sqlx(rename = "blockHash")]
    pub block_hash: String,
    #[sqlx(rename = "foundAt")]
    pub found_at: i64,
    #[sqlx(rename = "coinbaseValueSats")]
    pub coinbase_value_sats: Sats,
    #[sqlx(rename = "poolFeeSats")]
    pub pool_fee_sats: Sats,
    pub splits: Json<Vec<BlockpartySplitSnapshot>>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
}

pub async fn list_blockparty_block_history(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Vec<BlockpartyBlockHistoryRow>, DbError> {
    sqlx::query_as!(
        BlockpartyBlockHistoryRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            "blockHeight" AS "block_height!",
            "blockHash" AS "block_hash!",
            "foundAt" AS "found_at!",
            "coinbaseValueSats" AS "coinbase_value_sats!: Sats",
            "poolFeeSats" AS "pool_fee_sats!: Sats",
            splits AS "splits!: Json<Vec<BlockpartySplitSnapshot>>",
            "createdAt" AS "created_at!"
           FROM blockparty_block_history
           WHERE "groupId" = $1
           ORDER BY "blockHeight" DESC, id DESC"#,
        group_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_blockparty_block_history(
    pool: &PgPool,
    group_id: Uuid,
    block_height: i32,
    block_hash: &str,
    found_at: i64,
    coinbase_value_sats: Sats,
    pool_fee_sats: Sats,
    splits: &[BlockpartySplitSnapshot],
    created_at: i64,
) -> Result<Option<BlockpartyBlockHistoryRow>, DbError> {
    // ON CONFLICT DO NOTHING preserves replay-safety: a duplicate
    // (groupId, blockHash) returns 0 rows and the caller treats it as
    // a no-op rather than an error. The UNIQUE index on the pair is
    // the real authority.
    sqlx::query_as!(
        BlockpartyBlockHistoryRow,
        r#"INSERT INTO blockparty_block_history
            ("groupId", "blockHeight", "blockHash", "foundAt",
             "coinbaseValueSats", "poolFeeSats", splits, "createdAt")
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT ("groupId", "blockHash") DO NOTHING
           RETURNING
            id AS "id!",
            "groupId" AS "group_id!",
            "blockHeight" AS "block_height!",
            "blockHash" AS "block_hash!",
            "foundAt" AS "found_at!",
            "coinbaseValueSats" AS "coinbase_value_sats!: Sats",
            "poolFeeSats" AS "pool_fee_sats!: Sats",
            splits AS "splits!: Json<Vec<BlockpartySplitSnapshot>>",
            "createdAt" AS "created_at!""#,
        group_id,
        block_height,
        block_hash,
        found_at,
        coinbase_value_sats.0,
        pool_fee_sats.0,
        Json(splits) as _,
        created_at,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Self-service join link (one active link per group) ──────────────

#[derive(Clone, Debug, FromRow)]
pub struct BlockpartyJoinLinkRow {
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    pub token: String,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: i64,
}

/// INSERT-or-replace the single active join link for a group (PK groupId).
pub async fn upsert_blockparty_join_link(
    pool: &PgPool,
    group_id: Uuid,
    token: &str,
    expires_at: i64,
    created_at: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO blockparty_join_link ("groupId", token, "expiresAt", "createdAt")
           VALUES ($1, $2, $3, $4)
           ON CONFLICT ("groupId") DO UPDATE SET
             token = EXCLUDED.token,
             "expiresAt" = EXCLUDED."expiresAt",
             "createdAt" = EXCLUDED."createdAt""#,
        group_id,
        token,
        expires_at,
        created_at,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

pub async fn delete_blockparty_join_link(pool: &PgPool, group_id: Uuid) -> Result<u64, DbError> {
    let r = sqlx::query!(
        r#"DELETE FROM blockparty_join_link WHERE "groupId" = $1"#,
        group_id,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(r.rows_affected())
}

pub async fn find_blockparty_join_link_by_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<BlockpartyJoinLinkRow>, DbError> {
    sqlx::query_as!(
        BlockpartyJoinLinkRow,
        r#"SELECT
            "groupId" AS "group_id!",
            token AS "token!",
            "expiresAt" AS "expires_at!"
           FROM blockparty_join_link WHERE token = $1 LIMIT 1"#,
        token,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// The single active join link for a group (admin readback), or `None`.
pub async fn find_blockparty_join_link_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Option<BlockpartyJoinLinkRow>, DbError> {
    sqlx::query_as!(
        BlockpartyJoinLinkRow,
        r#"SELECT
            "groupId" AS "group_id!",
            token AS "token!",
            "expiresAt" AS "expires_at!"
           FROM blockparty_join_link WHERE "groupId" = $1 LIMIT 1"#,
        group_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}
