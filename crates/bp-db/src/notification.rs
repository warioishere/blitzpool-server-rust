// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notification subscriptions across Telegram, ntfy, and Web-Push / FCM.
//!
//! - `telegram_subscriptions_entity` — bot chats subscribed to a BTC address
//! - `ntfy_subscriptions_entity` — ntfy.sh + UnifiedPush mirrors
//! - `push_subscription_entity` — Web-Push (VAPID) + FCM tokens

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct TelegramSubscriptionRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub address: AddressId,
    #[sqlx(rename = "telegramChatId")]
    pub telegram_chat_id: i64,
    #[sqlx(rename = "bestDiffNotificationsEnabled")]
    pub best_diff_notifications_enabled: bool,
    #[sqlx(rename = "isDefault")]
    pub is_default: bool,
    #[sqlx(rename = "deviceNotificationsEnabled")]
    pub device_notifications_enabled: bool,
    #[sqlx(rename = "hourlyStatsEnabled")]
    pub hourly_stats_enabled: bool,
    #[sqlx(rename = "hourlyWorkersEnabled")]
    pub hourly_workers_enabled: bool,
}

pub async fn find_telegram_subscription(
    pool: &PgPool,
    id: i32,
) -> Result<Option<TelegramSubscriptionRow>, DbError> {
    sqlx::query_as!(
        TelegramSubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "telegramChatId" AS "telegram_chat_id!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "isDefault" AS "is_default!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM telegram_subscriptions_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All non-soft-deleted Telegram subscriptions for `address`. Multiple
/// chats can subscribe to the same address (e.g. owner + family),
/// hence `Vec`. Callers filter on `best_diff_notifications_enabled`
/// etc. in-memory — same single query handles every event-kind.
pub async fn find_telegram_subscriptions_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<TelegramSubscriptionRow>, DbError> {
    sqlx::query_as!(
        TelegramSubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "telegramChatId" AS "telegram_chat_id!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "isDefault" AS "is_default!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM telegram_subscriptions_entity
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// All Telegram subscriptions where the hourly cron should fire —
/// either `hourlyStatsEnabled` OR `hourlyWorkersEnabled` is true.
/// Used by [`crate::cron::hourly_stats`] to drive the per-chat
/// per-address hourly update loop.
pub async fn find_telegram_subscriptions_with_hourly_enabled(
    pool: &PgPool,
) -> Result<Vec<TelegramSubscriptionRow>, DbError> {
    sqlx::query_as!(
        TelegramSubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "telegramChatId" AS "telegram_chat_id!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "isDefault" AS "is_default!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM telegram_subscriptions_entity
           WHERE "deletedAt" IS NULL
             AND ("hourlyStatsEnabled" = true OR "hourlyWorkersEnabled" = true)"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// All non-soft-deleted Telegram subscriptions sharing a chat-id —
/// used to decide whether per-message text should disambiguate which
/// address the alert is for (more than one subscription on the chat).
pub async fn find_telegram_subscriptions_by_chat(
    pool: &PgPool,
    telegram_chat_id: i64,
) -> Result<Vec<TelegramSubscriptionRow>, DbError> {
    sqlx::query_as!(
        TelegramSubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "telegramChatId" AS "telegram_chat_id!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "isDefault" AS "is_default!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM telegram_subscriptions_entity
           WHERE "telegramChatId" = $1 AND "deletedAt" IS NULL"#,
        telegram_chat_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct NtfySubscriptionRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub address: AddressId,
    pub language: String,
    #[sqlx(rename = "bestDiffNotificationsEnabled")]
    pub best_diff_notifications_enabled: bool,
    #[sqlx(rename = "deviceNotificationsEnabled")]
    pub device_notifications_enabled: bool,
    #[sqlx(rename = "hourlyStatsEnabled")]
    pub hourly_stats_enabled: bool,
    #[sqlx(rename = "hourlyWorkersEnabled")]
    pub hourly_workers_enabled: bool,
}

pub async fn find_ntfy_subscription(
    pool: &PgPool,
    id: i32,
) -> Result<Option<NtfySubscriptionRow>, DbError> {
    sqlx::query_as!(
        NtfySubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            language AS "language!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM ntfy_subscriptions_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All ntfy subscriptions where the hourly cron should fire — either
/// `hourlyStatsEnabled` OR `hourlyWorkersEnabled` is true.
pub async fn find_ntfy_subscriptions_with_hourly_enabled(
    pool: &PgPool,
) -> Result<Vec<NtfySubscriptionRow>, DbError> {
    sqlx::query_as!(
        NtfySubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            language AS "language!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM ntfy_subscriptions_entity
           WHERE "deletedAt" IS NULL
             AND ("hourlyStatsEnabled" = true OR "hourlyWorkersEnabled" = true)"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Per-address ntfy subscription (topic is derived from address +
/// the deployment-wide `NTFY_TOPIC_PREFIX`, so a single row per
/// address — `address` carries a `UNIQUE` constraint upstream).
pub async fn find_ntfy_subscription_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<NtfySubscriptionRow>, DbError> {
    sqlx::query_as!(
        NtfySubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            language AS "language!",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "hourlyStatsEnabled" AS "hourly_stats_enabled!",
            "hourlyWorkersEnabled" AS "hourly_workers_enabled!"
           FROM ntfy_subscriptions_entity
           WHERE address = $1 AND "deletedAt" IS NULL
           LIMIT 1"#,
        address.as_str(),
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PushSubscriptionRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub address: AddressId,
    /// URL for UnifiedPush / Web-Push; FCM token string for FCM.
    pub endpoint: String,
    pub platform: String,
    #[sqlx(rename = "lastNotificationAt")]
    pub last_notification_at: Option<i64>,
    #[sqlx(rename = "bestDiffNotificationsEnabled")]
    pub best_diff_notifications_enabled: bool,
    #[sqlx(rename = "deviceNotificationsEnabled")]
    pub device_notifications_enabled: bool,
    #[sqlx(rename = "blockNotificationsEnabled")]
    pub block_notifications_enabled: bool,
    /// `"UNIFIED_PUSH"` or `"FCM"` (raw string kept — it's a stable
    /// 2-value enum but introducing a typed enum at this layer is
    /// over-engineering until a caller actually branches on it).
    #[sqlx(rename = "subscriptionType")]
    pub subscription_type: String,
    #[sqlx(rename = "networkDiffNotificationsEnabled")]
    pub network_diff_notifications_enabled: bool,
}

pub async fn find_push_subscription(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PushSubscriptionRow>, DbError> {
    sqlx::query_as!(
        PushSubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            endpoint AS "endpoint!",
            platform AS "platform!",
            "lastNotificationAt" AS "last_notification_at?",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "blockNotificationsEnabled" AS "block_notifications_enabled!",
            "subscriptionType" AS "subscription_type!",
            "networkDiffNotificationsEnabled" AS "network_diff_notifications_enabled!"
           FROM push_subscription_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All non-soft-deleted push subscriptions for `address`. Returns
/// both UNIFIED_PUSH and FCM entries in one query; caller filters by
/// `subscription_type` and the relevant `*_notifications_enabled` flag.
pub async fn find_push_subscriptions_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<PushSubscriptionRow>, DbError> {
    sqlx::query_as!(
        PushSubscriptionRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            endpoint AS "endpoint!",
            platform AS "platform!",
            "lastNotificationAt" AS "last_notification_at?",
            "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
            "deviceNotificationsEnabled" AS "device_notifications_enabled!",
            "blockNotificationsEnabled" AS "block_notifications_enabled!",
            "subscriptionType" AS "subscription_type!",
            "networkDiffNotificationsEnabled" AS "network_diff_notifications_enabled!"
           FROM push_subscription_entity
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Soft-delete a push subscription whose endpoint was rejected by the
/// upstream service as invalid (FCM `UNREGISTERED`/`INVALID_ARGUMENT`
/// or Web-Push 410 Gone). Idempotent — `affected = 0` is fine and
/// signals the row was already pruned.
pub async fn delete_push_subscription_by_endpoint(
    pool: &PgPool,
    address: &AddressId,
    endpoint: &str,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE push_subscription_entity
           SET "deletedAt" = $3, "updatedAt" = $3
           WHERE address = $1
             AND endpoint = $2
             AND "deletedAt" IS NULL"#,
        address.as_str(),
        endpoint,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Stamp `lastNotificationAt` after a successful send so the operator
/// dashboard can show "last reached at …". Best-effort — failures
/// are logged by the caller and not surfaced as adapter errors.
pub async fn update_push_subscription_last_notification(
    pool: &PgPool,
    id: i32,
    ts_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"UPDATE push_subscription_entity
           SET "lastNotificationAt" = $2, "updatedAt" = $2
           WHERE id = $1"#,
        id,
        ts_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// Idempotent upsert keyed by the `(address, endpoint, subscriptionType)`
/// UNIQUE index: on conflict only `platform` + `updatedAt` are touched
/// (the flags keep whatever the caller previously configured); on new row, all
/// four notification flags default to `true`. A soft-deleted row for
/// the same triple is reactivated (clears `deletedAt`).
pub async fn upsert_push_subscription(
    pool: &PgPool,
    address: &AddressId,
    endpoint: &str,
    platform: &str,
    subscription_type: &str,
) -> Result<PushSubscriptionRow, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    sqlx::query_as!(
        PushSubscriptionRow,
        r#"INSERT INTO push_subscription_entity (
                address, endpoint, platform, "subscriptionType",
                "bestDiffNotificationsEnabled", "deviceNotificationsEnabled",
                "blockNotificationsEnabled", "networkDiffNotificationsEnabled",
                "createdAt", "updatedAt"
            )
            VALUES ($1, $2, $3, $4, TRUE, TRUE, TRUE, TRUE, $5, $5)
            ON CONFLICT (address, endpoint, "subscriptionType") DO UPDATE
            SET platform = EXCLUDED.platform,
                "deletedAt" = NULL,
                "updatedAt" = $5
            RETURNING
                "deletedAt" AS "deleted_at?",
                "createdAt" AS "created_at!",
                "updatedAt" AS "updated_at!",
                id AS "id!",
                address AS "address!: AddressId",
                endpoint AS "endpoint!",
                platform AS "platform!",
                "lastNotificationAt" AS "last_notification_at?",
                "bestDiffNotificationsEnabled" AS "best_diff_notifications_enabled!",
                "deviceNotificationsEnabled" AS "device_notifications_enabled!",
                "blockNotificationsEnabled" AS "block_notifications_enabled!",
                "subscriptionType" AS "subscription_type!",
                "networkDiffNotificationsEnabled" AS "network_diff_notifications_enabled!""#,
        address.as_str(),
        endpoint,
        platform,
        subscription_type,
        now_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Soft-delete a specific push subscription identified by
/// `(address, endpoint, subscriptionType)`. Used by the FCM-specific
/// unregister path that must not touch a UnifiedPush row with the
/// same endpoint string. Idempotent: `affected = 0` is fine.
pub async fn delete_push_subscription_by_endpoint_and_type(
    pool: &PgPool,
    address: &AddressId,
    endpoint: &str,
    subscription_type: &str,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE push_subscription_entity
           SET "deletedAt" = $4, "updatedAt" = $4
           WHERE address = $1
             AND endpoint = $2
             AND "subscriptionType" = $3
             AND "deletedAt" IS NULL"#,
        address.as_str(),
        endpoint,
        subscription_type,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Soft-delete every push subscription for `address` across both
/// UnifiedPush and FCM types. Used by `/api/push/unregister` without
/// an `endpoint` field.
pub async fn delete_push_subscriptions_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE push_subscription_entity
           SET "deletedAt" = $2, "updatedAt" = $2
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Soft-delete every push subscription for `address` of a given type.
/// Used by `/api/push/fcm/unregister` without
/// a `token` field to wipe every FCM row for the address while keeping
/// any UnifiedPush rows intact.
pub async fn delete_push_subscriptions_by_address_and_type(
    pool: &PgPool,
    address: &AddressId,
    subscription_type: &str,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE push_subscription_entity
           SET "deletedAt" = $3, "updatedAt" = $3
           WHERE address = $1
             AND "subscriptionType" = $2
             AND "deletedAt" IS NULL"#,
        address.as_str(),
        subscription_type,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Update the four notification-preference flags for the row keyed by
/// `(address, endpoint)`. Each flag is `Option<bool>` — `None` means
/// "leave as-is" (a partial update that skips the unset fields).
/// Touches `updatedAt`. Returns the
/// number of rows affected; 0 when no matching active row exists.
pub async fn update_push_subscription_preferences(
    pool: &PgPool,
    address: &AddressId,
    endpoint: &str,
    best_diff: Option<bool>,
    device: Option<bool>,
    block: Option<bool>,
    network_diff: Option<bool>,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE push_subscription_entity
           SET "bestDiffNotificationsEnabled" =
                   COALESCE($3, "bestDiffNotificationsEnabled"),
               "deviceNotificationsEnabled" =
                   COALESCE($4, "deviceNotificationsEnabled"),
               "blockNotificationsEnabled" =
                   COALESCE($5, "blockNotificationsEnabled"),
               "networkDiffNotificationsEnabled" =
                   COALESCE($6, "networkDiffNotificationsEnabled"),
               "updatedAt" = $7
           WHERE address = $1
             AND endpoint = $2
             AND "deletedAt" IS NULL"#,
        address.as_str(),
        endpoint,
        best_diff,
        device,
        block,
        network_diff,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── Telegram subscription writes (bot command path) ──────────────────

/// Subscribe a Telegram `chat_id` to mining `address`. Idempotent:
/// re-subscribing un-soft-deletes an existing row instead of creating
/// a duplicate (the table has no UNIQUE on `(chat_id, address)` —
/// dedup lives in the service layer).
pub async fn upsert_telegram_subscription(
    pool: &PgPool,
    telegram_chat_id: i64,
    address: &AddressId,
) -> Result<i32, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    // The freshly subscribed address becomes this chat's default — clear
    // the flag on every other active row of the chat first.
    sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "isDefault" = false, "updatedAt" = $2
           WHERE "telegramChatId" = $1 AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    // Re-activate any soft-deleted row first; if no such row, INSERT.
    let revived = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "deletedAt" = NULL, "isDefault" = true, "updatedAt" = $3
           WHERE "telegramChatId" = $1 AND address = $2
           RETURNING id"#,
        telegram_chat_id,
        address.as_str(),
        now_ms,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)?;
    if let Some(row) = revived {
        return Ok(row.id);
    }
    let inserted = sqlx::query!(
        r#"INSERT INTO telegram_subscriptions_entity
           ("telegramChatId", address, "isDefault", "createdAt", "updatedAt")
           VALUES ($1, $2, true, $3, $3)
           RETURNING id"#,
        telegram_chat_id,
        address.as_str(),
        now_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(inserted.id)
}

/// Mark subscription `id` as the chat's default and clear the flag on
/// every other active row of the same chat, in one statement. Returns
/// the number of rows touched (0 if `id` doesn't belong to the chat).
pub async fn set_telegram_default_subscription(
    pool: &PgPool,
    telegram_chat_id: i64,
    id: i32,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "isDefault" = (id = $2), "updatedAt" = $3
           WHERE "telegramChatId" = $1 AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        id,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// If the chat has active subscriptions but none is flagged default,
/// promote the lowest-id active row. No-op when a default already
/// exists or no active rows remain. Returns `true` if it promoted one.
pub async fn promote_telegram_default_if_none(
    pool: &PgPool,
    telegram_chat_id: i64,
) -> Result<bool, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "isDefault" = true, "updatedAt" = $2
           WHERE id = (
               SELECT id FROM telegram_subscriptions_entity
               WHERE "telegramChatId" = $1 AND "deletedAt" IS NULL
               ORDER BY id ASC
               LIMIT 1
           )
           AND NOT EXISTS (
               SELECT 1 FROM telegram_subscriptions_entity
               WHERE "telegramChatId" = $1 AND "deletedAt" IS NULL AND "isDefault" = true
           )"#,
        telegram_chat_id,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected() > 0)
}

/// Soft-delete a Telegram subscription. `affected = 0` is fine
/// (already removed / never existed).
pub async fn delete_telegram_subscription_by_chat_address(
    pool: &PgPool,
    telegram_chat_id: i64,
    address: &AddressId,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "deletedAt" = $3, "updatedAt" = $3
           WHERE "telegramChatId" = $1
             AND address = $2
             AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        address.as_str(),
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Toggle the per-subscription `bestDiffNotificationsEnabled` flag.
pub async fn update_telegram_sub_best_diff_flag(
    pool: &PgPool,
    telegram_chat_id: i64,
    address: &AddressId,
    value: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "bestDiffNotificationsEnabled" = $3, "updatedAt" = $4
           WHERE "telegramChatId" = $1
             AND address = $2
             AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        address.as_str(),
        value,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Toggle the per-subscription `deviceNotificationsEnabled` flag.
pub async fn update_telegram_sub_device_flag(
    pool: &PgPool,
    telegram_chat_id: i64,
    address: &AddressId,
    value: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "deviceNotificationsEnabled" = $3, "updatedAt" = $4
           WHERE "telegramChatId" = $1
             AND address = $2
             AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        address.as_str(),
        value,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Set `hourlyStatsEnabled` and `hourlyWorkersEnabled` independently —
/// backs the `hr:stats` / `hr:workers` inline-menu toggles, which flip
/// one flag at a time. Returns the number of rows affected.
pub async fn set_telegram_hourly_flags(
    pool: &PgPool,
    telegram_chat_id: i64,
    address: &AddressId,
    stats: bool,
    workers: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "hourlyStatsEnabled" = $3,
               "hourlyWorkersEnabled" = $4,
               "updatedAt" = $5
           WHERE "telegramChatId" = $1
             AND address = $2
             AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        address.as_str(),
        stats,
        workers,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Set both `hourlyStatsEnabled` and `hourlyWorkersEnabled` in one
/// call — `/send_hourly on|off` always flips both together.
pub async fn update_telegram_sub_hourly_flags(
    pool: &PgPool,
    telegram_chat_id: i64,
    address: &AddressId,
    value: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE telegram_subscriptions_entity
           SET "hourlyStatsEnabled" = $3,
               "hourlyWorkersEnabled" = $3,
               "updatedAt" = $4
           WHERE "telegramChatId" = $1
             AND address = $2
             AND "deletedAt" IS NULL"#,
        telegram_chat_id,
        address.as_str(),
        value,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── ntfy subscription writes (bot command path) ──────────────────────

/// Upsert by `address` (the table has a UNIQUE on address). Existing
/// rows are touched (`updatedAt`) so the SSE listener knows the user
/// is still active even on re-subscribes; soft-deleted rows are
/// un-deleted.
pub async fn upsert_ntfy_subscription(pool: &PgPool, address: &AddressId) -> Result<i32, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let row = sqlx::query!(
        r#"INSERT INTO ntfy_subscriptions_entity
           (address, "createdAt", "updatedAt")
           VALUES ($1, $2, $2)
           ON CONFLICT (address) DO UPDATE
               SET "deletedAt" = NULL, "updatedAt" = $2
           RETURNING id"#,
        address.as_str(),
        now_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(row.id)
}

/// Soft-delete the ntfy subscription for `address`.
pub async fn delete_ntfy_subscription_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE ntfy_subscriptions_entity
           SET "deletedAt" = $2, "updatedAt" = $2
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Toggle `bestDiffNotificationsEnabled` on the ntfy sub.
pub async fn update_ntfy_sub_best_diff_flag(
    pool: &PgPool,
    address: &AddressId,
    value: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE ntfy_subscriptions_entity
           SET "bestDiffNotificationsEnabled" = $2, "updatedAt" = $3
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
        value,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Toggle `deviceNotificationsEnabled` on the ntfy sub.
pub async fn update_ntfy_sub_device_flag(
    pool: &PgPool,
    address: &AddressId,
    value: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE ntfy_subscriptions_entity
           SET "deviceNotificationsEnabled" = $2, "updatedAt" = $3
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
        value,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Set both hourly flags on the ntfy sub (`/send_hourly`).
pub async fn update_ntfy_sub_hourly_flags(
    pool: &PgPool,
    address: &AddressId,
    value: bool,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE ntfy_subscriptions_entity
           SET "hourlyStatsEnabled" = $2,
               "hourlyWorkersEnabled" = $2,
               "updatedAt" = $3
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
        value,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Persist the per-address ntfy language (`/deutsch` / `/english`).
pub async fn update_ntfy_sub_language(
    pool: &PgPool,
    address: &AddressId,
    language: &str,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE ntfy_subscriptions_entity
           SET language = $2, "updatedAt" = $3
           WHERE address = $1 AND "deletedAt" IS NULL"#,
        address.as_str(),
        language,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Distinct list of addresses that have at least one non-soft-deleted
/// push subscription — for the dispatcher's in-memory presence cache
/// bootstrap so the per-event fan-out can skip the 3-table lookup for
/// addresses we know have no subscribers.
pub async fn find_addresses_with_push_subscription(
    pool: &PgPool,
) -> Result<Vec<AddressId>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT DISTINCT address AS "address!: AddressId"
           FROM push_subscription_entity
           WHERE "deletedAt" IS NULL"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows.into_iter().map(|r| r.address).collect())
}

/// Weekly cleanup: hard-DELETE push subscriptions that have had no
/// activity for the given epoch-ms cutoff — subscriptions whose
/// `lastNotificationAt` is older than the cutoff, or whose
/// `lastNotificationAt` is NULL and whose `createdAt` is older than
/// the cutoff.
pub async fn delete_stale_push_subscriptions(
    pool: &PgPool,
    cutoff_ms: i64,
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"DELETE FROM push_subscription_entity
           WHERE ("lastNotificationAt" IS NULL AND "createdAt" < $1)
              OR "lastNotificationAt" < $1"#,
        cutoff_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Topic set for the inbound ntfy SSE listener: the union of every
/// active mining-client address and every active ntfy subscription.
/// Clients give actively-mining users a listened topic for their first
/// `/subscribe`; the ntfy side keeps explicit subscribers (incl.
/// non-clients) heard. Both filter `deletedAt IS NULL`.
pub async fn find_addresses_for_ntfy_listener(pool: &PgPool) -> Result<Vec<AddressId>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT address AS "address!: AddressId"
           FROM client_entity WHERE "deletedAt" IS NULL
           UNION
           SELECT address AS "address!: AddressId"
           FROM ntfy_subscriptions_entity WHERE "deletedAt" IS NULL"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows.into_iter().map(|r| r.address).collect())
}
