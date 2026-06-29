// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo group, members, balances, history, invitations, join-requests.
//!
//! - `pplns_group` — group config (UUID PK)
//! - `pplns_group_member` — auto-id row, UNIQUE on address (one membership per address pool-wide)
//! - `pplns_group_balance` — composite PK (address, groupId)
//! - `pplns_group_block_history` — UNIQUE (groupId, blockHeight, address)
//! - `pplns_group_invitation` — token PK + status FSM
//! - `pplns_group_join_request` — UUID PK + status FSM

use bp_common::{AddressId, Sats};
use sqlx::{postgres::PgPool, FromRow};
use uuid::Uuid;

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct PplnsGroupRow {
    pub id: Uuid,
    pub name: String,
    #[sqlx(rename = "creatorAddress")]
    pub creator_address: AddressId,
    /// SHA-256 hex of the admin token — used to authenticate admin-only
    /// endpoints. The plaintext token is shown to the creator exactly
    /// once at group creation time.
    #[sqlx(rename = "adminTokenHash")]
    pub admin_token_hash: String,
    pub active: bool,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    #[sqlx(rename = "dissolvedAt")]
    pub dissolved_at: Option<i64>,
    #[sqlx(rename = "roundResetIntervalDays")]
    pub round_reset_interval_days: Option<i32>,
    #[sqlx(rename = "roundResetHourLocal")]
    pub round_reset_hour_local: Option<i32>,
    #[sqlx(rename = "roundResetTimezone")]
    pub round_reset_timezone: Option<String>,
    #[sqlx(rename = "lastRoundResetAt")]
    pub last_round_reset_at: Option<i64>,
    /// Optional absolute-sats bonus emitted as its own coinbase output
    /// to the block-finder when the group's round produces a block.
    #[sqlx(rename = "finderBonusSats")]
    pub finder_bonus_sats: Option<Sats>,
    #[sqlx(rename = "roundResetPreset")]
    pub round_reset_preset: Option<String>,
    #[sqlx(rename = "isPublic")]
    pub is_public: bool,
    /// When true, the Group-Solo round is wiped on every block-found (legacy
    /// behavior). Default false: shares accumulate across blocks until a
    /// calendar preset or manual reset fires.
    #[sqlx(rename = "resetRoundOnBlock")]
    pub reset_round_on_block: bool,
    /// Hard member cap. NULL = no limit. Enforced at the add-member chokepoint
    /// (GroupService::add_member_without_admin) across every join path.
    #[sqlx(rename = "maxMembers")]
    pub max_members: Option<i32>,
    /// Payout mode — `"prop"` (classic per-round PROP, default) or `"window"`
    /// (continuously-sliding time window). Chosen at creation and immutable.
    /// Parsed via `bp_group_mgmt::group::PayoutMode::parse_or_default`.
    #[sqlx(rename = "payoutMode")]
    pub payout_mode: String,
}

pub async fn find_group(pool: &PgPool, id: Uuid) -> Result<Option<PplnsGroupRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "creatorAddress" AS "creator_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            active AS "active!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?",
            "roundResetIntervalDays" AS "round_reset_interval_days?",
            "roundResetHourLocal" AS "round_reset_hour_local?",
            "roundResetTimezone" AS "round_reset_timezone?",
            "lastRoundResetAt" AS "last_round_reset_at?",
            "finderBonusSats" AS "finder_bonus_sats?: Sats",
            "roundResetPreset" AS "round_reset_preset?",
            "isPublic" AS "is_public!",
            "resetRoundOnBlock" AS "reset_round_on_block!",
            "maxMembers" AS "max_members?",
            "payoutMode" AS "payout_mode!"
           FROM pplns_group WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PplnsGroupMemberRow {
    pub id: i32,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    pub address: AddressId,
    pub role: String,
    #[sqlx(rename = "joinedAt")]
    pub joined_at: i64,
}

pub async fn find_group_member(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PplnsGroupMemberRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!"
           FROM pplns_group_member WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Lookup the membership row by address. An address can be a
/// member of at most one group at a time (a UNIQUE on `address` in
/// the schema enforces this), so the return is `Option`.
pub async fn find_group_member_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<PplnsGroupMemberRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!"
           FROM pplns_group_member WHERE address = $1 LIMIT 1"#,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All members of a group. Used by `/group_members` and
/// `/group_status`. Returns rows ordered by `joinedAt ASC` so the
/// founder is listed first.
pub async fn find_pplns_group_members_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Vec<PplnsGroupMemberRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!"
           FROM pplns_group_member
           WHERE "groupId" = $1
           ORDER BY "joinedAt" ASC"#,
        group_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PplnsGroupBalanceRow {
    pub address: AddressId,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    #[sqlx(rename = "pendingSats")]
    pub pending_sats: Sats,
    #[sqlx(rename = "totalPaidSats")]
    pub total_paid_sats: Sats,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    #[sqlx(rename = "lastAcceptedShareAt")]
    pub last_accepted_share_at: Option<i64>,
}

pub async fn find_group_balance(
    pool: &PgPool,
    address: &AddressId,
    group_id: Uuid,
) -> Result<Option<PplnsGroupBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "groupId" AS "group_id!",
            "pendingSats" AS "pending_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_group_balance
           WHERE address = $1 AND "groupId" = $2 LIMIT 1"#,
        address.as_str(),
        group_id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PplnsGroupBlockHistoryRow {
    pub id: i32,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    #[sqlx(rename = "blockHeight")]
    pub block_height: i32,
    pub address: AddressId,
    #[sqlx(rename = "paidSats")]
    pub paid_sats: Sats,
    pub percent: f32,
    #[sqlx(rename = "sharesInRound")]
    pub shares_in_round: i64,
    #[sqlx(rename = "totalSharesInRound")]
    pub total_shares_in_round: i64,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "rowType")]
    pub row_type: String,
}

pub async fn find_group_block_history(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PplnsGroupBlockHistoryRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupBlockHistoryRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            "blockHeight" AS "block_height!",
            address AS "address!: AddressId",
            "paidSats" AS "paid_sats!: Sats",
            percent AS "percent!",
            "sharesInRound" AS "shares_in_round!",
            "totalSharesInRound" AS "total_shares_in_round!",
            "createdAt" AS "created_at!",
            "rowType" AS "row_type!"
           FROM pplns_group_block_history WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Most recent `limit` payout rows for a group, newest first. Powers
/// `/group_history`.
pub async fn find_recent_group_block_history(
    pool: &PgPool,
    group_id: Uuid,
    limit: i64,
) -> Result<Vec<PplnsGroupBlockHistoryRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupBlockHistoryRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            "blockHeight" AS "block_height!",
            address AS "address!: AddressId",
            "paidSats" AS "paid_sats!: Sats",
            percent AS "percent!",
            "sharesInRound" AS "shares_in_round!",
            "totalSharesInRound" AS "total_shares_in_round!",
            "createdAt" AS "created_at!",
            "rowType" AS "row_type!"
           FROM pplns_group_block_history
           WHERE "groupId" = $1
           ORDER BY "createdAt" DESC
           LIMIT $2"#,
        group_id,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

// ── Group-Solo bulk writes ──────────────────────────────────────────
//
// Consumer: `bp-group-solo-engine::ledger::apply_distribution` writes
// both `pplns_group_block_history` (audit log) and `pplns_group_balance`
// (unsigned-pending ledger) inside one PG transaction. Dust-sweep
// + scheduled-reset + member-kick paths use the single-row helpers.

/// Absolute upsert into `pplns_group_balance` — sets each row's
/// `pendingSats`, `totalPaidSats`, `updatedAt`, and (optionally)
/// `lastAcceptedShareAt` to the caller-provided values. Idempotent.
///
/// Composite PK is `(address, groupId)` so the same `address` can
/// belong to different groups simultaneously (e.g. an admin's address
/// in multiple groups they administer).
#[derive(Clone, Debug)]
pub struct GroupBalanceUpsert {
    pub address: String,
    pub group_id: Uuid,
    pub pending_sats: i64,
    pub total_paid_sats: i64,
    pub updated_at_ms: i64,
    /// When `Some`, the column is also overwritten. When `None`, the
    /// existing value is preserved on UPDATE / set to NULL on INSERT.
    /// When `Some`, `applyDistribution` writes
    /// `lastAcceptedShareAt = now` on every touched row.
    pub last_accepted_share_at_ms: Option<i64>,
}

pub async fn bulk_upsert_pplns_group_balances<'e, E>(
    executor: E,
    rows: &[GroupBalanceUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let group_ids: Vec<Uuid> = rows.iter().map(|r| r.group_id).collect();
    let pending: Vec<i64> = rows.iter().map(|r| r.pending_sats).collect();
    let totals: Vec<i64> = rows.iter().map(|r| r.total_paid_sats).collect();
    let updated: Vec<i64> = rows.iter().map(|r| r.updated_at_ms).collect();
    // For `lastAcceptedShareAt` we need a parallel array carrying
    // NULL for slots where the caller didn't specify one. sqlx's
    // `Option<i64>` array round-trips as PG `bigint[]` with NULLs.
    let last_at: Vec<Option<i64>> = rows.iter().map(|r| r.last_accepted_share_at_ms).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pplns_group_balance
             (address, "groupId", "pendingSats", "totalPaidSats", "updatedAt", "lastAcceptedShareAt")
           SELECT * FROM UNNEST(
             $1::text[], $2::uuid[], $3::bigint[], $4::bigint[], $5::bigint[], $6::bigint[]
           )
           ON CONFLICT (address, "groupId") DO UPDATE
           SET "pendingSats"          = EXCLUDED."pendingSats",
               "totalPaidSats"        = EXCLUDED."totalPaidSats",
               "updatedAt"            = EXCLUDED."updatedAt",
               "lastAcceptedShareAt"  = COALESCE(EXCLUDED."lastAcceptedShareAt",
                                                 pplns_group_balance."lastAcceptedShareAt")"#,
        &addresses,
        &group_ids,
        &pending,
        &totals,
        &updated,
        &last_at as &[Option<i64>],
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Bulk-insert block-history rows for one block-found. `ON CONFLICT
/// ("groupId", "blockHeight", address) DO NOTHING` gates replays.
/// `rowType` is the discriminator: `"coinbase"` / `"pending"` /
/// `"dust-sweep"`.
#[derive(Clone, Debug)]
pub struct GroupPayoutHistoryInsert {
    pub group_id: Uuid,
    pub block_height: i32,
    pub address: String,
    pub paid_sats: i64,
    pub percent: f32,
    pub shares_in_round: i64,
    pub total_shares_in_round: i64,
    pub row_type: String,
    pub created_at_ms: i64,
}

pub async fn bulk_insert_pplns_group_block_history<'e, E>(
    executor: E,
    rows: &[GroupPayoutHistoryInsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let group_ids: Vec<Uuid> = rows.iter().map(|r| r.group_id).collect();
    let heights: Vec<i32> = rows.iter().map(|r| r.block_height).collect();
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let paid: Vec<i64> = rows.iter().map(|r| r.paid_sats).collect();
    let percents: Vec<f32> = rows.iter().map(|r| r.percent).collect();
    let shares: Vec<i64> = rows.iter().map(|r| r.shares_in_round).collect();
    let totals: Vec<i64> = rows.iter().map(|r| r.total_shares_in_round).collect();
    let row_types: Vec<String> = rows.iter().map(|r| r.row_type.clone()).collect();
    let created: Vec<i64> = rows.iter().map(|r| r.created_at_ms).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pplns_group_block_history
             ("groupId", "blockHeight", address, "paidSats", percent,
              "sharesInRound", "totalSharesInRound", "rowType", "createdAt")
           SELECT * FROM UNNEST(
             $1::uuid[], $2::int[], $3::text[], $4::bigint[], $5::real[],
             $6::bigint[], $7::bigint[], $8::text[], $9::bigint[]
           )
           ON CONFLICT ("groupId", "blockHeight", address) DO NOTHING"#,
        &group_ids,
        &heights,
        &addresses,
        &paid,
        &percents,
        &shares,
        &totals,
        &row_types,
        &created,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// All `pplns_group_balance` rows for one group with a positive
/// `pendingSats`. Consumed by `bp-group-solo-engine::distribution`
/// when building a payout distribution — every member with an open
/// pending claim is folded into the math.
pub async fn find_pplns_group_balances_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Vec<PplnsGroupBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "groupId" AS "group_id!",
            "pendingSats" AS "pending_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_group_balance
           WHERE "groupId" = $1 AND "pendingSats" > 0"#,
        group_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// EVERY `pplns_group_balance` row for one group, including those with
/// `pendingSats = 0`. Consumed by `bp-group-solo-engine`'s block-found
/// apply to read each touched member's prior `totalPaidSats` so the
/// lifetime total accumulates. The `pendingSats > 0` filter on
/// [`find_pplns_group_balances_for_group`] is wrong for this use: a
/// member fully paid on-chain (pending = 0) would otherwise be invisible,
/// and their `totalPaidSats` would be overwritten with the current block
/// instead of summed across blocks.
pub async fn find_all_pplns_group_balances_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Vec<PplnsGroupBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "groupId" AS "group_id!",
            "pendingSats" AS "pending_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_group_balance
           WHERE "groupId" = $1"#,
        group_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Dust-sweep candidate rows: positive `pendingSats` below the
/// caller's `min_payout` floor, and `lastAcceptedShareAt` older than
/// `cutoff_ms`. Group-Solo's sweep is single-sided (no pair-cancel),
/// so this is the entire candidate set.
pub async fn find_pplns_group_balances_dormant(
    pool: &PgPool,
    min_payout: i64,
    cutoff_ms: i64,
) -> Result<Vec<PplnsGroupBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "groupId" AS "group_id!",
            "pendingSats" AS "pending_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_group_balance
           WHERE "pendingSats" > 0
             AND "pendingSats" < $1
             AND "lastAcceptedShareAt" IS NOT NULL
             AND "lastAcceptedShareAt" < $2"#,
        min_payout,
        cutoff_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Single-row UPDATE of `pendingSats` for one (address, groupId).
/// Preserves `totalPaidSats` and `updatedAt`. Used by the member-kick
/// redistribution path where survivors get their balance increased.
pub async fn update_pplns_group_balance_pending_sats<'e, E>(
    executor: E,
    address: &AddressId,
    group_id: Uuid,
    new_pending_sats: Sats,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_balance
           SET "pendingSats" = $1
           WHERE address = $2 AND "groupId" = $3"#,
        new_pending_sats.to_i64(),
        address.as_str(),
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// DELETE one (address, groupId) row. Used by dust-sweep when the
/// pending balance gets absorbed + by member-kick admin flow.
pub async fn delete_pplns_group_balance<'e, E>(
    executor: E,
    address: &AddressId,
    group_id: Uuid,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_group_balance WHERE address = $1 AND "groupId" = $2"#,
        address.as_str(),
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// DELETE all balance rows for one group. Used by the scheduled
/// round-reset cron's full-wipe path + dissolve-group admin flow.
pub async fn delete_pplns_group_balances_for_group<'e, E>(
    executor: E,
    group_id: Uuid,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_group_balance WHERE "groupId" = $1"#,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Upsert-increment: add `delta_sats` to `pendingSats` for
/// (address, groupId). Inserts a new row if none exists. Used by the
/// member-kick redistribution flow to credit remaining members with
/// the kicked member's accumulated pending balance.
pub async fn add_pplns_group_balance_pending<'e, E>(
    executor: E,
    address: &AddressId,
    group_id: Uuid,
    delta_sats: i64,
    now_ms: i64,
) -> Result<(), DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"INSERT INTO pplns_group_balance
               (address, "groupId", "pendingSats", "totalPaidSats", "updatedAt", "lastAcceptedShareAt")
           VALUES ($1, $2, $3, 0, $4, $4)
           ON CONFLICT (address, "groupId") DO UPDATE
           SET "pendingSats" = pplns_group_balance."pendingSats" + EXCLUDED."pendingSats",
               "lastAcceptedShareAt" = EXCLUDED."lastAcceptedShareAt",
               "updatedAt" = EXCLUDED."updatedAt""#,
        address.as_str(),
        group_id,
        delta_sats,
        now_ms,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// DELETE all `pplns_group_block_history` rows for one group. Called
/// when a group is dissolved to remove all ledger history.
pub async fn delete_pplns_group_block_history_for_group<'e, E>(
    executor: E,
    group_id: Uuid,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_group_block_history WHERE "groupId" = $1"#,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Stamp `lastRoundResetAt` on a `pplns_group` row. Called by the
/// scheduled cron after each fired reset; the 60s guard reads this
/// column to prevent double-fire.
pub async fn update_pplns_group_last_reset_at<'e, E>(
    executor: E,
    group_id: Uuid,
    last_reset_at_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group
           SET "lastRoundResetAt" = $1
           WHERE id = $2"#,
        last_reset_at_ms,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

#[derive(Clone, Debug, FromRow)]
pub struct PplnsGroupInvitationRow {
    pub token: String,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    /// Set for `directed` invitations; `None` for `open` invitations
    /// (anyone with the link can accept).
    pub address: Option<AddressId>,
    pub email: Option<String>,
    pub status: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: i64,
    #[sqlx(rename = "respondedAt")]
    pub responded_at: Option<i64>,
    #[sqlx(rename = "inviteType")]
    pub invite_type: String,
    #[sqlx(rename = "approvalRequired")]
    pub approval_required: bool,
}

pub async fn find_group_invitation(
    pool: &PgPool,
    token: &str,
) -> Result<Option<PplnsGroupInvitationRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address?: AddressId",
            email AS "email?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?",
            "inviteType" AS "invite_type!",
            "approvalRequired" AS "approval_required!"
           FROM pplns_group_invitation WHERE token = $1 LIMIT 1"#,
        token
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PplnsGroupJoinRequestRow {
    pub id: Uuid,
    #[sqlx(rename = "groupId")]
    pub group_id: Uuid,
    pub address: AddressId,
    pub email: String,
    pub message: Option<String>,
    pub status: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "decidedAt")]
    pub decided_at: Option<i64>,
    #[sqlx(rename = "decidedByAdminTokenHash")]
    pub decided_by_admin_token_hash: Option<String>,
}

pub async fn find_group_join_request(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<PplnsGroupJoinRequestRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupJoinRequestRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            message AS "message?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "decidedAt" AS "decided_at?",
            "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?"
           FROM pplns_group_join_request WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Group-mgmt service-layer writes ─────────────────────────────────
//
// Consumed by `bp-group-mgmt-engine`'s GroupService /
// PplnsGroupInvitationService / PplnsGroupJoinRequestService.

/// INSERT a freshly-built `pplns_group` row. `active = false` and
/// `isPublic = false` are set by the caller — a new group always starts
/// inactive (member count of 1 = creator alone) and private.
/// Returns the full row read back (so the caller can attach it to the
/// API response without a follow-up SELECT).
#[allow(clippy::too_many_arguments)]
pub async fn insert_pplns_group<'e, E>(
    executor: E,
    id: Uuid,
    name: &str,
    creator_address: &AddressId,
    admin_token_hash: &str,
    active: bool,
    is_public: bool,
    payout_mode: &str,
    now_ms: i64,
) -> Result<PplnsGroupRow, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PplnsGroupRow,
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "payoutMode")
           VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8)
           RETURNING
            id AS "id!",
            name AS "name!",
            "creatorAddress" AS "creator_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            active AS "active!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?",
            "roundResetIntervalDays" AS "round_reset_interval_days?",
            "roundResetHourLocal" AS "round_reset_hour_local?",
            "roundResetTimezone" AS "round_reset_timezone?",
            "lastRoundResetAt" AS "last_round_reset_at?",
            "finderBonusSats" AS "finder_bonus_sats?: Sats",
            "roundResetPreset" AS "round_reset_preset?",
            "isPublic" AS "is_public!",
            "resetRoundOnBlock" AS "reset_round_on_block!",
            "maxMembers" AS "max_members?",
            "payoutMode" AS "payout_mode!""#,
        id,
        name,
        creator_address.as_str(),
        admin_token_hash,
        active,
        now_ms,
        is_public,
        payout_mode,
    )
    .fetch_one(executor)
    .await
    .map_err(DbError::from)
}

/// Lookup a group row by its `name` — used by `createGroup` to enforce
/// the human-friendly uniqueness rule (dissolved groups don't count, so
/// a name can be re-used once the original is gone). Returns `Some` only
/// for non-dissolved groups.
pub async fn find_pplns_group_by_name_not_dissolved(
    pool: &PgPool,
    name: &str,
) -> Result<Option<PplnsGroupRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "creatorAddress" AS "creator_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            active AS "active!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?",
            "roundResetIntervalDays" AS "round_reset_interval_days?",
            "roundResetHourLocal" AS "round_reset_hour_local?",
            "roundResetTimezone" AS "round_reset_timezone?",
            "lastRoundResetAt" AS "last_round_reset_at?",
            "finderBonusSats" AS "finder_bonus_sats?: Sats",
            "roundResetPreset" AS "round_reset_preset?",
            "isPublic" AS "is_public!",
            "resetRoundOnBlock" AS "reset_round_on_block!",
            "maxMembers" AS "max_members?",
            "payoutMode" AS "payout_mode!"
           FROM pplns_group
           WHERE name = $1 AND "dissolvedAt" IS NULL
           LIMIT 1"#,
        name,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All non-dissolved groups, ordered by `createdAt ASC` (oldest first,
/// insertion order).
pub async fn list_active_pplns_groups(pool: &PgPool) -> Result<Vec<PplnsGroupRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupRow,
        r#"SELECT
            id AS "id!",
            name AS "name!",
            "creatorAddress" AS "creator_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            active AS "active!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?",
            "roundResetIntervalDays" AS "round_reset_interval_days?",
            "roundResetHourLocal" AS "round_reset_hour_local?",
            "roundResetTimezone" AS "round_reset_timezone?",
            "lastRoundResetAt" AS "last_round_reset_at?",
            "finderBonusSats" AS "finder_bonus_sats?: Sats",
            "roundResetPreset" AS "round_reset_preset?",
            "isPublic" AS "is_public!",
            "resetRoundOnBlock" AS "reset_round_on_block!",
            "maxMembers" AS "max_members?",
            "payoutMode" AS "payout_mode!"
           FROM pplns_group
           WHERE "dissolvedAt" IS NULL
           ORDER BY "createdAt" ASC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Count rows in `pplns_group_member` for one group. Drives the
/// `recomputeActive` path: a group is active once `count >=
/// MIN_MEMBERS_ACTIVE` (= 2 today).
pub async fn count_pplns_group_members_for_group<'e, E>(
    executor: E,
    group_id: Uuid,
) -> Result<i64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "count!" FROM pplns_group_member WHERE "groupId" = $1"#,
        group_id,
    )
    .fetch_one(executor)
    .await
    .map_err(DbError::from)?;
    Ok(row.count)
}

/// Single-column UPDATE of `pplns_group.active`. Idempotent. Returns
/// row count (0 or 1). `updatedAt` is also bumped so the row reflects
/// the activity change.
pub async fn update_pplns_group_active<'e, E>(
    executor: E,
    group_id: Uuid,
    active: bool,
    now_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group SET active = $1, "updatedAt" = $2 WHERE id = $3 AND "dissolvedAt" IS NULL"#,
        active,
        now_ms,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Apply a creator-transfer to the group row: rotate the admin-token
/// hash and the recorded `creatorAddress`. The member-role swap on
/// `pplns_group_member` is a separate call (see
/// [`update_pplns_group_member_role`]).
pub async fn update_pplns_group_creator_and_admin_token<'e, E>(
    executor: E,
    group_id: Uuid,
    new_creator_address: &AddressId,
    new_admin_token_hash: &str,
    now_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group
           SET "creatorAddress" = $1,
               "adminTokenHash" = $2,
               "updatedAt"      = $3
           WHERE id = $4"#,
        new_creator_address.as_str(),
        new_admin_token_hash,
        now_ms,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Partial-update DTO for `updateRoundResetConfig`.
///
/// - `Untouched` — column stays as is (field absent from request)
/// - `Clear` — column is set to NULL or zero (field explicitly null)
/// - `Set(value)` — column is overwritten (field set to a value)
///
/// `hour_local` is forced to 0 because calendar resets always fire at
/// midnight local time; we still allow the field as `PatchField::Set(0)`
/// so a future change is easy.
#[derive(Clone, Debug, Default)]
pub struct RoundResetConfigPatch {
    pub preset: PatchField<String>,
    pub interval_days: PatchField<i32>,
    pub timezone: PatchField<String>,
    pub hour_local: PatchField<i32>,
    pub finder_bonus_sats: PatchField<i64>,
    pub is_public: PatchField<bool>,
    pub reset_round_on_block: PatchField<bool>,
    pub max_members: PatchField<i32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PatchField<T> {
    #[default]
    Untouched,
    Clear,
    Set(T),
}

/// Apply the per-field round-reset config patch + `isPublic` toggle.
/// Builds a single UPDATE — fields tagged `Untouched` are skipped, the
/// other two states map to `column = NULL` / `column = value` via
/// `CASE WHEN $flag THEN $value ELSE column END` chains so we still
/// emit one SQL statement.
///
/// Returns the freshly-read row so callers can attach it directly
/// to the API response.
#[allow(clippy::too_many_arguments)]
pub async fn update_pplns_group_round_reset_config(
    pool: &PgPool,
    group_id: Uuid,
    patch: &RoundResetConfigPatch,
    now_ms: i64,
) -> Result<Option<PplnsGroupRow>, DbError> {
    // Each (write, clear, value) triple: write=true when CHANGE, clear=true
    // when set-to-NULL, otherwise existing column value preserved.
    let (preset_write, preset_clear, preset_value) = patch_triple_str(&patch.preset);
    let (interval_write, interval_clear, interval_value) = patch_triple_i32(&patch.interval_days);
    let (tz_write, tz_clear, tz_value) = patch_triple_str(&patch.timezone);
    let (hour_write, hour_clear, hour_value) = patch_triple_i32(&patch.hour_local);
    let (bonus_write, bonus_clear, bonus_value) = patch_triple_i64(&patch.finder_bonus_sats);
    let (public_write, _public_clear, public_value) = patch_triple_bool(&patch.is_public);
    let (reset_on_block_write, _reset_on_block_clear, reset_on_block_value) =
        patch_triple_bool(&patch.reset_round_on_block);
    let (max_write, max_clear, max_value) = patch_triple_i32(&patch.max_members);

    sqlx::query_as!(
        PplnsGroupRow,
        r#"UPDATE pplns_group
           SET
             "roundResetPreset"       = CASE WHEN $2  THEN (CASE WHEN $3  THEN NULL::varchar  ELSE $4::varchar  END) ELSE "roundResetPreset"       END,
             "roundResetIntervalDays" = CASE WHEN $5  THEN (CASE WHEN $6  THEN NULL::int      ELSE $7::int      END) ELSE "roundResetIntervalDays" END,
             "roundResetTimezone"     = CASE WHEN $8  THEN (CASE WHEN $9  THEN NULL::varchar  ELSE $10::varchar END) ELSE "roundResetTimezone"     END,
             "roundResetHourLocal"    = CASE WHEN $11 THEN (CASE WHEN $12 THEN NULL::int      ELSE $13::int     END) ELSE "roundResetHourLocal"    END,
             "finderBonusSats"        = CASE WHEN $14 THEN (CASE WHEN $15 THEN NULL::bigint   ELSE $16::bigint  END) ELSE "finderBonusSats"        END,
             "isPublic"               = CASE WHEN $17 THEN $18 ELSE "isPublic" END,
             "resetRoundOnBlock"      = CASE WHEN $19 THEN $20 ELSE "resetRoundOnBlock" END,
             "maxMembers"             = CASE WHEN $21 THEN (CASE WHEN $22 THEN NULL::int ELSE $23::int END) ELSE "maxMembers" END,
             "updatedAt"              = $24
           WHERE id = $1
           RETURNING
            id AS "id!",
            name AS "name!",
            "creatorAddress" AS "creator_address!: AddressId",
            "adminTokenHash" AS "admin_token_hash!",
            active AS "active!",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            "dissolvedAt" AS "dissolved_at?",
            "roundResetIntervalDays" AS "round_reset_interval_days?",
            "roundResetHourLocal" AS "round_reset_hour_local?",
            "roundResetTimezone" AS "round_reset_timezone?",
            "lastRoundResetAt" AS "last_round_reset_at?",
            "finderBonusSats" AS "finder_bonus_sats?: Sats",
            "roundResetPreset" AS "round_reset_preset?",
            "isPublic" AS "is_public!",
            "resetRoundOnBlock" AS "reset_round_on_block!",
            "maxMembers" AS "max_members?",
            "payoutMode" AS "payout_mode!""#,
        group_id,
        preset_write,
        preset_clear,
        preset_value,
        interval_write,
        interval_clear,
        interval_value,
        tz_write,
        tz_clear,
        tz_value,
        hour_write,
        hour_clear,
        hour_value,
        bonus_write,
        bonus_clear,
        bonus_value,
        public_write,
        public_value,
        reset_on_block_write,
        reset_on_block_value,
        max_write,
        max_clear,
        max_value,
        now_ms,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

fn patch_triple_str(f: &PatchField<String>) -> (bool, bool, String) {
    match f {
        PatchField::Untouched => (false, false, String::new()),
        PatchField::Clear => (true, true, String::new()),
        PatchField::Set(v) => (true, false, v.clone()),
    }
}
fn patch_triple_i32(f: &PatchField<i32>) -> (bool, bool, i32) {
    match f {
        PatchField::Untouched => (false, false, 0),
        PatchField::Clear => (true, true, 0),
        PatchField::Set(v) => (true, false, *v),
    }
}
fn patch_triple_i64(f: &PatchField<i64>) -> (bool, bool, i64) {
    match f {
        PatchField::Untouched => (false, false, 0),
        PatchField::Clear => (true, true, 0),
        PatchField::Set(v) => (true, false, *v),
    }
}
fn patch_triple_bool(f: &PatchField<bool>) -> (bool, bool, bool) {
    match f {
        PatchField::Untouched => (false, false, false),
        // `isPublic` is NOT NULL so Clear treated as Set(false).
        PatchField::Clear => (true, false, false),
        PatchField::Set(v) => (true, false, *v),
    }
}

/// Mark a group dissolved: stamp `dissolvedAt = now`, force `active =
/// false`, bump `updatedAt`. Idempotent — a second call is a no-op
/// because the WHERE clause guards against already-dissolved rows.
pub async fn update_pplns_group_dissolved<'e, E>(
    executor: E,
    group_id: Uuid,
    now_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group
           SET "dissolvedAt" = $1, active = false, "updatedAt" = $1
           WHERE id = $2 AND "dissolvedAt" IS NULL"#,
        now_ms,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── Members ─────────────────────────────────────────────────────────

/// INSERT a member row + RETURNING the read-back row (caller wants the
/// auto-generated `id` + the canonical `joinedAt` server-set default).
pub async fn insert_pplns_group_member<'e, E>(
    executor: E,
    group_id: Uuid,
    address: &AddressId,
    role: &str,
    now_ms: i64,
) -> Result<PplnsGroupMemberRow, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"INSERT INTO pplns_group_member
             ("groupId", address, role, "joinedAt")
           VALUES ($1, $2, $3, $4)
           RETURNING
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!""#,
        group_id,
        address.as_str(),
        role,
        now_ms,
    )
    .fetch_one(executor)
    .await
    .map_err(DbError::from)
}

/// DELETE one (`groupId`, `address`) member row. Returns row-count
/// (0 if not a member, 1 on success).
pub async fn delete_pplns_group_member<'e, E>(
    executor: E,
    group_id: Uuid,
    address: &AddressId,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_group_member WHERE "groupId" = $1 AND address = $2"#,
        group_id,
        address.as_str(),
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// DELETE all member rows for one group. Used by `dissolveInternal`
/// before flipping the group's `dissolvedAt` stamp.
pub async fn delete_pplns_group_members_for_group<'e, E>(
    executor: E,
    group_id: Uuid,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_group_member WHERE "groupId" = $1"#,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// UPDATE a member's `role` ("creator" / "member"). Used by
/// `transferCreator` to demote the outgoing creator + promote the
/// incoming one as two separate calls.
pub async fn update_pplns_group_member_role<'e, E>(
    executor: E,
    group_id: Uuid,
    address: &AddressId,
    new_role: &str,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_member
           SET role = $1
           WHERE "groupId" = $2 AND address = $3"#,
        new_role,
        group_id,
        address.as_str(),
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Lookup one (`groupId`, `address`) member row. Same shape as
/// [`find_group_member_by_address`] but filtered by group too — needed
/// for `transferCreator` / `removeMember` / `addMember` flows.
pub async fn find_pplns_group_member_in_group(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
) -> Result<Option<PplnsGroupMemberRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!"
           FROM pplns_group_member
           WHERE "groupId" = $1 AND address = $2
           LIMIT 1"#,
        group_id,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Lookup the creator member-row for a group. `transferCreator` reads
/// this to know whom to demote.
pub async fn find_pplns_group_creator_member(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Option<PplnsGroupMemberRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!"
           FROM pplns_group_member
           WHERE "groupId" = $1 AND role = 'creator'
           LIMIT 1"#,
        group_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All member rows pool-wide — drives the address-cache rebuild. The
/// caller pairs each row's `groupId` against [`list_active_pplns_groups`]
/// to mask out members of dissolved groups.
pub async fn find_all_pplns_group_members(
    pool: &PgPool,
) -> Result<Vec<PplnsGroupMemberRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupMemberRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            role AS "role!",
            "joinedAt" AS "joined_at!"
           FROM pplns_group_member"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Lenient member list for the boot-time routing-cache rebuild: returns raw
/// address STRINGS (not `AddressId`), so one malformed legacy address can't
/// fail the whole decode and crash boot. The caller parses each + skips the
/// invalid ones. Pairs with [`list_active_pplns_group_flags`].
pub async fn find_all_pplns_group_member_addresses(
    pool: &PgPool,
) -> Result<Vec<(uuid::Uuid, String)>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT "groupId" AS "group_id!", address AS "address!"
           FROM pplns_group_member"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.group_id, r.address)).collect())
}

/// Lenient `(group_id, active)` flags for non-dissolved groups — selects no
/// address column, so a bad `creatorAddress` can't fail the boot-time cache
/// rebuild. Mirrors [`list_active_pplns_groups`]'s `WHERE`.
pub async fn list_active_pplns_group_flags(
    pool: &PgPool,
) -> Result<Vec<(uuid::Uuid, bool)>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", active AS "active!"
           FROM pplns_group
           WHERE "dissolvedAt" IS NULL"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.active)).collect())
}

// ── Invitations ─────────────────────────────────────────────────────

/// INSERT a fresh invitation row. `inviteType` is `"directed"` for
/// admin-targeted invites (with `address` + `email`) and `"open"` for
/// shareable links (both `None`). Returns the read-back row.
#[allow(clippy::too_many_arguments)]
pub async fn insert_pplns_group_invitation<'e, E>(
    executor: E,
    token: &str,
    group_id: Uuid,
    address: Option<&AddressId>,
    email: Option<&str>,
    invite_type: &str,
    approval_required: bool,
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<PplnsGroupInvitationRow, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PplnsGroupInvitationRow,
        r#"INSERT INTO pplns_group_invitation
             (token, "groupId", address, email, status, "createdAt",
              "expiresAt", "inviteType", "approvalRequired")
           VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8)
           RETURNING
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address?: AddressId",
            email AS "email?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?",
            "inviteType" AS "invite_type!",
            "approvalRequired" AS "approval_required!""#,
        token,
        group_id,
        address.map(|a| a.as_str()),
        email,
        created_at_ms,
        expires_at_ms,
        invite_type,
        approval_required,
    )
    .fetch_one(executor)
    .await
    .map_err(DbError::from)
}

/// UPDATE the status + optional `respondedAt` of one invitation by
/// token. Returns row-count. Used by accept/decline/expire/revoke paths.
pub async fn update_pplns_group_invitation_status_by_token<'e, E>(
    executor: E,
    token: &str,
    new_status: &str,
    responded_at_ms: Option<i64>,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_invitation
           SET status = $1,
               "respondedAt" = COALESCE($2, "respondedAt")
           WHERE token = $3"#,
        new_status,
        responded_at_ms,
        token,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Hard-DELETE one invitation by token. Used by
/// `cancelInvitationByAddress` — admin removes a directed invitation
/// before the recipient acts on it (the cancellation isn't an audit
/// event worth keeping).
pub async fn delete_pplns_group_invitation_by_token<'e, E>(
    executor: E,
    token: &str,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_group_invitation WHERE token = $1"#,
        token,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Find one pending directed invitation for (`groupId`, `address`).
/// Used by `createInvitation` to enforce the "no double invite while
/// pending" rule + by `cancelInvitationByAddress` to locate the row.
pub async fn find_pplns_group_invitation_pending_directed(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
) -> Result<Option<PplnsGroupInvitationRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address?: AddressId",
            email AS "email?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?",
            "inviteType" AS "invite_type!",
            "approvalRequired" AS "approval_required!"
           FROM pplns_group_invitation
           WHERE "groupId" = $1
             AND address = $2
             AND status = 'pending'
             AND "inviteType" = 'directed'
           LIMIT 1"#,
        group_id,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All pending directed invitations for one group (admin panel). The
/// caller filters out past-`expiresAt` rows in-memory because the cron
/// will eventually flip those to `expired`.
pub async fn find_pplns_group_invitations_pending_for_group_directed(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Vec<PplnsGroupInvitationRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address?: AddressId",
            email AS "email?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?",
            "inviteType" AS "invite_type!",
            "approvalRequired" AS "approval_required!"
           FROM pplns_group_invitation
           WHERE "groupId" = $1
             AND status = 'pending'
             AND "inviteType" = 'directed'
           ORDER BY "createdAt" DESC"#,
        group_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// All pending directed invitations for one address — drives the
/// "you have pending invitations" banner on the public dashboard.
pub async fn find_pplns_group_invitations_pending_for_address_directed(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<PplnsGroupInvitationRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address?: AddressId",
            email AS "email?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?",
            "inviteType" AS "invite_type!",
            "approvalRequired" AS "approval_required!"
           FROM pplns_group_invitation
           WHERE address = $1
             AND status = 'pending'
             AND "inviteType" = 'directed'
           ORDER BY "createdAt" DESC"#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Find the active (`pending`, type=`open`) open-invite for a group,
/// newest first. Past-`expiresAt` rows are NOT filtered here so the
/// caller can decide whether to treat them as gone or auto-expire.
pub async fn find_pplns_group_active_open_invite_for_group(
    pool: &PgPool,
    group_id: Uuid,
) -> Result<Option<PplnsGroupInvitationRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupInvitationRow,
        r#"SELECT
            token AS "token!",
            "groupId" AS "group_id!",
            address AS "address?: AddressId",
            email AS "email?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "expiresAt" AS "expires_at!",
            "respondedAt" AS "responded_at?",
            "inviteType" AS "invite_type!",
            "approvalRequired" AS "approval_required!"
           FROM pplns_group_invitation
           WHERE "groupId" = $1
             AND status = 'pending'
             AND "inviteType" = 'open'
           ORDER BY "createdAt" DESC
           LIMIT 1"#,
        group_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Mark every pending open invite for `groupId` as `revoked` (single
/// statement). Used as the first half of `createOpenInvite`'s atomic
/// replace. Returns the affected-row count for logging.
pub async fn revoke_pending_open_invites_for_group<'e, E>(
    executor: E,
    group_id: Uuid,
    now_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_invitation
           SET status = 'revoked', "respondedAt" = $1
           WHERE "groupId" = $2 AND status = 'pending' AND "inviteType" = 'open'"#,
        now_ms,
        group_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Cron sweep: flip every `pending` invitation whose `expiresAt` is in
/// the past to `expired`. Returns affected-row count for the log line.
pub async fn expire_pending_pplns_group_invitations<'e, E>(
    executor: E,
    now_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_invitation
           SET status = 'expired'
           WHERE status = 'pending' AND "expiresAt" < $1"#,
        now_ms,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── Join-requests ───────────────────────────────────────────────────

/// INSERT a fresh join-request row. The `id` is server-generated
/// (`gen_random_uuid()` DEFAULT). Returns the read-back row. The
/// unique partial index on `(groupId, address) WHERE status='pending'`
/// makes a concurrent duplicate raise PG SQLSTATE `23505`; the caller
/// surfaces that as a `'request-pending'` service error.
#[allow(clippy::too_many_arguments)]
pub async fn insert_pplns_group_join_request<'e, E>(
    executor: E,
    group_id: Uuid,
    address: &AddressId,
    email: &str,
    message: Option<&str>,
    now_ms: i64,
) -> Result<PplnsGroupJoinRequestRow, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PplnsGroupJoinRequestRow,
        r#"INSERT INTO pplns_group_join_request
             ("groupId", address, email, message, status, "createdAt")
           VALUES ($1, $2, $3, $4, 'pending', $5)
           RETURNING
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            message AS "message?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "decidedAt" AS "decided_at?",
            "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?""#,
        group_id,
        address.as_str(),
        email,
        message,
        now_ms,
    )
    .fetch_one(executor)
    .await
    .map_err(DbError::from)
}

/// Find the pending join-request row by (`id`, `groupId`). Used by
/// approve/reject — the admin clicks a button keyed to the request ID
/// and we double-check the row still belongs to the group + is still
/// pending before mutating.
pub async fn find_pplns_group_join_request_pending_in_group(
    pool: &PgPool,
    request_id: Uuid,
    group_id: Uuid,
) -> Result<Option<PplnsGroupJoinRequestRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupJoinRequestRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            message AS "message?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "decidedAt" AS "decided_at?",
            "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?"
           FROM pplns_group_join_request
           WHERE id = $1 AND "groupId" = $2 AND status = 'pending'
           LIMIT 1"#,
        request_id,
        group_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Most recently-decided rejected request for (`groupId`, `address`).
/// Drives the 24h reject-cooldown check in `createJoinRequest`.
pub async fn find_pplns_group_join_request_most_recent_rejected(
    pool: &PgPool,
    group_id: Uuid,
    address: &AddressId,
) -> Result<Option<PplnsGroupJoinRequestRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupJoinRequestRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            message AS "message?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "decidedAt" AS "decided_at?",
            "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?"
           FROM pplns_group_join_request
           WHERE "groupId" = $1 AND address = $2 AND status = 'rejected'
           ORDER BY "decidedAt" DESC NULLS LAST
           LIMIT 1"#,
        group_id,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Count pending join-requests for one address across all groups.
/// Drives the `MAX_PENDING_PER_ADDRESS` rate-limit (default 10).
pub async fn count_pplns_group_join_requests_pending_for_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<i64, DbError> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "count!"
           FROM pplns_group_join_request
           WHERE address = $1 AND status = 'pending'"#,
        address.as_str(),
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(row.count)
}

/// Admin-facing list of join-requests for one group. When
/// `include_decided=true` the result also contains approved/rejected
/// rows for audit; otherwise only pending.
pub async fn list_pplns_group_join_requests_for_group(
    pool: &PgPool,
    group_id: Uuid,
    include_decided: bool,
) -> Result<Vec<PplnsGroupJoinRequestRow>, DbError> {
    if include_decided {
        sqlx::query_as!(
            PplnsGroupJoinRequestRow,
            r#"SELECT
                id AS "id!",
                "groupId" AS "group_id!",
                address AS "address!: AddressId",
                email AS "email!",
                message AS "message?",
                status AS "status!",
                "createdAt" AS "created_at!",
                "decidedAt" AS "decided_at?",
                "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?"
               FROM pplns_group_join_request
               WHERE "groupId" = $1
               ORDER BY "createdAt" DESC"#,
            group_id,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
    } else {
        sqlx::query_as!(
            PplnsGroupJoinRequestRow,
            r#"SELECT
                id AS "id!",
                "groupId" AS "group_id!",
                address AS "address!: AddressId",
                email AS "email!",
                message AS "message?",
                status AS "status!",
                "createdAt" AS "created_at!",
                "decidedAt" AS "decided_at?",
                "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?"
               FROM pplns_group_join_request
               WHERE "groupId" = $1 AND status = 'pending'
               ORDER BY "createdAt" DESC"#,
            group_id,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
    }
}

/// User-facing list of one address's own pending join-requests across
/// all groups — drives the "request pending" badge in the public
/// directory.
pub async fn list_pplns_group_join_requests_pending_for_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<PplnsGroupJoinRequestRow>, DbError> {
    sqlx::query_as!(
        PplnsGroupJoinRequestRow,
        r#"SELECT
            id AS "id!",
            "groupId" AS "group_id!",
            address AS "address!: AddressId",
            email AS "email!",
            message AS "message?",
            status AS "status!",
            "createdAt" AS "created_at!",
            "decidedAt" AS "decided_at?",
            "decidedByAdminTokenHash" AS "decided_by_admin_token_hash?"
           FROM pplns_group_join_request
           WHERE address = $1 AND status = 'pending'
           ORDER BY "createdAt" DESC"#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Apply an admin decision (`approved` / `rejected`) to one join-request:
/// stamp `decidedAt`, `decidedByAdminTokenHash`, and the new `status`.
/// Returns row-count.
pub async fn update_pplns_group_join_request_decision<'e, E>(
    executor: E,
    request_id: Uuid,
    new_status: &str,
    decided_at_ms: i64,
    decided_by_admin_token_hash: &str,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_join_request
           SET status = $1,
               "decidedAt" = $2,
               "decidedByAdminTokenHash" = $3
           WHERE id = $4"#,
        new_status,
        decided_at_ms,
        decided_by_admin_token_hash,
        request_id,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Cron sweep: flip every `pending` join-request whose `createdAt` is
/// older than `cutoff_ms` to `expired`. Returns affected-row count.
pub async fn expire_pending_pplns_group_join_requests<'e, E>(
    executor: E,
    cutoff_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_group_join_request
           SET status = 'expired'
           WHERE status = 'pending' AND "createdAt" < $1"#,
        cutoff_ms,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
