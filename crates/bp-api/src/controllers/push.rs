// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/push/*` — register/configure/unregister UnifiedPush + FCM push
//! subscriptions.
//!
//! All addresses must have an `address_settings_entity` row (the
//! "address has mined on this pool" gate) before they can register.
//! The status endpoint is the only un-gated read and is a passthrough
//! to `bp_db::find_push_subscriptions_by_address`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use bp_common::AddressId;
use bp_db::PushSubscriptionRow;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::ApiError;
use crate::push_hooks::{FcmRegisterContext, UnifiedPushRegisterContext};
use crate::state::SharedState;

const UNIFIED_PUSH: &str = "unified_push";
const FCM: &str = "fcm";
const MIN_FCM_TOKEN_LEN: usize = 100;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route("/api/push/info", get(info))
        .route("/api/push/register", post(register::<H, M>))
        .route("/api/push/unregister", post(unregister::<H, M>))
        .route("/api/push/status/:address", get(status::<H, M>))
        .route("/api/push/configure", post(configure::<H, M>))
        .route("/api/push/fcm/register", post(register_fcm::<H, M>))
        .route("/api/push/fcm/unregister", post(unregister_fcm::<H, M>))
}

// ─── GET /api/push/info ──────────────────────────────────────────

/// Static operator-documentation endpoint returning a deeply nested
/// JSON literal listing notification types, the HTTP method/body
/// catalogue, UnifiedPush + FCM setup instructions, examples and
/// rate-limit text. The UI uses this primarily to discover which
/// notification kinds and channels are supported. Lives as a single
/// inline `serde_json::Value` — no struct gain at this size.
async fn info() -> Json<Value> {
    Json(json!({
        "success": true,
        "version": "1.0.0",
        "description": "BlitzPool Push Notification API",
        "notificationTypes": [
            {
                "type": "best_difficulty",
                "description": "When miner achieves new personal best difficulty",
                "frequency": "Every 60 seconds if difficulty increased",
                "rateLimit": "No rate limiting - immediate on difficulty increase"
            },
            {
                "type": "device_status",
                "description": "When mining device goes online or offline",
                "frequency": "Real-time on connection/disconnection",
                "rateLimit": "No rate limiting"
            },
            {
                "type": "block_found",
                "description": "When address finds a valid block",
                "frequency": "Real-time when block is found",
                "rateLimit": "No rate limiting"
            }
        ],
        "methods": [
            {
                "method": "POST",
                "path": "/api/push/register",
                "description": "Register Unified Push endpoint (all notification types enabled by default). Requires address to have mined on this pool.",
                "body": {
                    "address": "bitcoin address (62 chars)",
                    "endpoint": "https://your-endpoint-url",
                    "platform": "optional identifier (default: unknown)"
                }
            },
            {
                "method": "POST",
                "path": "/api/push/fcm/register",
                "description": "Register FCM device token (all notification types enabled by default). Requires address to have mined on this pool.",
                "body": {
                    "address": "bitcoin address (62 chars)",
                    "token": "FCM device token (100+ chars)",
                    "platform": "optional: android|ios|web"
                }
            },
            {
                "method": "POST",
                "path": "/api/push/unregister",
                "description": "Remove Unified Push subscription",
                "body": {
                    "address": "bitcoin address",
                    "endpoint": "optional - specific endpoint to remove"
                }
            },
            {
                "method": "POST",
                "path": "/api/push/fcm/unregister",
                "description": "Remove FCM token",
                "body": {
                    "address": "bitcoin address",
                    "token": "optional - specific FCM token to remove"
                }
            },
            {
                "method": "POST",
                "path": "/api/push/configure",
                "description": "Update notification preferences",
                "body": {
                    "address": "bitcoin address",
                    "endpoint": "Unified Push URL or FCM token",
                    "bestDiffNotifications": "optional boolean",
                    "deviceNotifications": "optional boolean",
                    "blockNotifications": "optional boolean"
                }
            },
            {
                "method": "GET",
                "path": "/api/push/status/:address",
                "description": "Check subscription status and preferences",
                "response": "Subscription details and notification preferences"
            }
        ],
        "unifiedPush": {
            "description": "Privacy-focused decentralized push notifications",
            "setup": "Choose a Unified Push distributor (e.g., ntfy.sh, self-hosted)",
            "exampleEndpoints": [
                "https://ntfy.sh/my-mining-alerts",
                "https://push.example.com/up/abc123"
            ],
            "documentation": "https://unifiedpush.org/"
        },
        "fcm": {
            "description": "Firebase Cloud Messaging for native mobile apps",
            "setup": "Get FCM token from your mobile app using Firebase SDK",
            "tokenFormat": {
                "length": "100+ characters",
                "characters": "any valid FCM token format"
            },
            "documentation": "https://firebase.google.com/docs/cloud-messaging"
        },
        "examples": {
            "registerUnifiedPush": {
                "method": "POST /api/push/register",
                "body": {
                    "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    "endpoint": "https://ntfy.sh/my-blitzpool-alerts",
                    "platform": "ntfy"
                }
            },
            "registerFcm": {
                "method": "POST /api/push/fcm/register",
                "body": {
                    "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    "token": "eRx9R8tUVzBBNIH9_8HYKjd7fKQRx4XO3IvlB6HK2Ko:APA91bHLl_8-0j8I3xEqR4j9xVl_yD7Wjb4K5Z6Y1Xl0PqN",
                    "platform": "android"
                }
            },
            "enableNotifications": {
                "method": "POST /api/push/configure",
                "body": {
                    "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    "endpoint": "https://ntfy.sh/my-blitzpool-alerts",
                    "bestDiffNotifications": true,
                    "deviceNotifications": true,
                    "blockNotifications": true
                }
            }
        },
        "rateLimits": {
            "bestDiffNotifications": "No rate limiting - immediate on difficulty increase",
            "deviceNotifications": "No rate limiting - immediate on event",
            "blockNotifications": "No rate limiting - immediate on event"
        },
        "documentation": "/docs/PUSH_NOTIFICATIONS.md"
    }))
}

// ─── POST /api/push/register ─────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    address: Option<String>,
    endpoint: Option<String>,
    platform: Option<String>,
}

/// Response: `{success, subscription:{id, address, platform, createdAt}}`.
/// `createdAt` is ISO-8601 (UTC).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterResponse {
    success: bool,
    subscription: SubscriptionSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionSummary {
    id: i32,
    address: String,
    platform: String,
    created_at: String,
}

async fn register<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<RegisterBody>,
) -> Result<Json<RegisterResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let (address, endpoint) = require_address_and(body.address, body.endpoint, "endpoint")?;
    let platform = normalise_platform(body.platform, "unknown");
    validate_miner_address(&state, &address).await?;
    let row = bp_db::upsert_push_subscription(
        &state.pool,
        &address,
        endpoint.as_str(),
        platform.as_str(),
        UNIFIED_PUSH,
    )
    .await
    .map_err(|_| push_error("registration-failed", StatusCode::BAD_REQUEST))?;
    state
        .push_hooks
        .on_unified_push_registered(UnifiedPushRegisterContext {
            address: address.as_str().to_string(),
            endpoint: endpoint.clone(),
            platform: platform.clone(),
        })
        .await;
    Ok(Json(RegisterResponse {
        success: true,
        subscription: subscription_summary(&row),
    }))
}

// ─── POST /api/push/unregister ───────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnregisterBody {
    address: Option<String>,
    endpoint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OkResponse {
    success: bool,
}

async fn unregister<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<UnregisterBody>,
) -> Result<Json<OkResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_address(body.address)?;
    if let Some(endpoint) = body.endpoint.as_deref().filter(|e| !e.is_empty()) {
        bp_db::delete_push_subscription_by_endpoint(&state.pool, &address, endpoint)
            .await
            .map_err(|_| push_error("unregister-failed", StatusCode::BAD_REQUEST))?;
    } else {
        bp_db::delete_push_subscriptions_by_address(&state.pool, &address)
            .await
            .map_err(|_| push_error("unregister-failed", StatusCode::BAD_REQUEST))?;
    }
    Ok(Json(OkResponse { success: true }))
}

// ─── GET /api/push/status/:address ───────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    address: String,
    subscription_count: usize,
    subscriptions: Vec<StatusSubscription>,
    tracker: Option<TrackerInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusSubscription {
    id: i32,
    platform: String,
    endpoint: String,
    subscription_type: String,
    created_at: String,
    last_notification_at: Option<String>,
    best_diff_notifications_enabled: bool,
    device_notifications_enabled: bool,
    block_notifications_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrackerInfo {
    best_difficulty: u64,
    last_checked_at: String,
}

async fn status<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address.clone()).map_err(|_| ApiError::InvalidAddress)?;
    let subs = bp_db::find_push_subscriptions_by_address(&state.pool, &addr)
        .await
        .map_err(|_| push_error("status-failed", StatusCode::BAD_REQUEST))?;
    let tracker = bp_db::find_best_difficulty_tracker(&state.pool, &addr)
        .await
        .map_err(|_| push_error("status-failed", StatusCode::BAD_REQUEST))?;
    let subscriptions = subs
        .iter()
        .map(|s| StatusSubscription {
            id: s.id,
            platform: s.platform.clone(),
            endpoint: s.endpoint.clone(),
            subscription_type: s.subscription_type.clone(),
            created_at: format_iso_ms(s.created_at),
            last_notification_at: s.last_notification_at.map(format_iso_ms),
            best_diff_notifications_enabled: s.best_diff_notifications_enabled,
            device_notifications_enabled: s.device_notifications_enabled,
            block_notifications_enabled: s.block_notifications_enabled,
        })
        .collect::<Vec<_>>();
    Ok(Json(StatusResponse {
        address: addr.as_str().to_string(),
        subscription_count: subscriptions.len(),
        subscriptions,
        tracker: tracker.map(|t| TrackerInfo {
            best_difficulty: t.best_difficulty.floor() as u64,
            last_checked_at: format_iso_ms(t.last_checked_at),
        }),
    }))
}

// ─── POST /api/push/configure ────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigureBody {
    address: Option<String>,
    endpoint: Option<String>,
    best_diff_notifications: Option<bool>,
    device_notifications: Option<bool>,
    block_notifications: Option<bool>,
    network_diff_notifications: Option<bool>,
}

async fn configure<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<ConfigureBody>,
) -> Result<Json<OkResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let (address, endpoint) = require_address_and(body.address, body.endpoint, "endpoint")?;
    bp_db::update_push_subscription_preferences(
        &state.pool,
        &address,
        endpoint.as_str(),
        body.best_diff_notifications,
        body.device_notifications,
        body.block_notifications,
        body.network_diff_notifications,
    )
    .await
    .map_err(|_| push_error("configure-failed", StatusCode::BAD_REQUEST))?;
    Ok(Json(OkResponse { success: true }))
}

// ─── POST /api/push/fcm/register ─────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FcmRegisterBody {
    address: Option<String>,
    token: Option<String>,
    platform: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FcmRegisterResponse {
    success: bool,
    subscription_type: &'static str,
    subscription: SubscriptionSummary,
}

async fn register_fcm<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<FcmRegisterBody>,
) -> Result<Json<FcmRegisterResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let (address, token) = require_address_and(body.address, body.token, "token")?;
    let platform = normalise_platform(body.platform, "fcm");
    validate_miner_address(&state, &address).await?;
    if token.len() < MIN_FCM_TOKEN_LEN {
        return Err(push_error("invalid-fcm-token", StatusCode::BAD_REQUEST));
    }
    let row = bp_db::upsert_push_subscription(
        &state.pool,
        &address,
        token.as_str(),
        platform.as_str(),
        FCM,
    )
    .await
    .map_err(|_| push_error("registration-failed", StatusCode::BAD_REQUEST))?;
    state
        .push_hooks
        .validate_fcm_token(FcmRegisterContext {
            address: address.as_str().to_string(),
            token: token.clone(),
            platform: platform.clone(),
        })
        .await;
    Ok(Json(FcmRegisterResponse {
        success: true,
        subscription_type: "fcm",
        subscription: subscription_summary(&row),
    }))
}

// ─── POST /api/push/fcm/unregister ───────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FcmUnregisterBody {
    address: Option<String>,
    token: Option<String>,
}

async fn unregister_fcm<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<FcmUnregisterBody>,
) -> Result<Json<OkResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_address(body.address)?;
    if let Some(token) = body.token.as_deref().filter(|t| !t.is_empty()) {
        bp_db::delete_push_subscription_by_endpoint_and_type(&state.pool, &address, token, FCM)
            .await
            .map_err(|_| push_error("unregister-failed", StatusCode::BAD_REQUEST))?;
    } else {
        bp_db::delete_push_subscriptions_by_address_and_type(&state.pool, &address, FCM)
            .await
            .map_err(|_| push_error("unregister-failed", StatusCode::BAD_REQUEST))?;
    }
    Ok(Json(OkResponse { success: true }))
}

// ─── helpers ─────────────────────────────────────────────────────

fn subscription_summary(row: &PushSubscriptionRow) -> SubscriptionSummary {
    SubscriptionSummary {
        id: row.id,
        address: row.address.as_str().to_string(),
        platform: row.platform.clone(),
        created_at: format_iso_ms(row.created_at),
    }
}

fn parse_address(raw: Option<String>) -> Result<AddressId, ApiError> {
    let s = raw
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| push_error("missing-address", StatusCode::BAD_REQUEST))?;
    AddressId::new(s).map_err(|_| ApiError::InvalidAddress)
}

/// Pull the (address, secondary) pair out of an `Option<String>` body,
/// returning 400 with `"Missing required fields: address, <name>"` when
/// either is absent. Empty trimmed strings count as missing.
fn require_address_and(
    raw_address: Option<String>,
    raw_secondary: Option<String>,
    secondary_name: &'static str,
) -> Result<(AddressId, String), ApiError> {
    let address_str = raw_address
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let secondary = raw_secondary
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if address_str.is_none() || secondary.is_none() {
        let code: &'static str = match secondary_name {
            "endpoint" => "missing-fields-address-endpoint",
            "token" => "missing-fields-address-token",
            _ => "missing-fields",
        };
        return Err(push_error(code, StatusCode::BAD_REQUEST));
    }
    let address = AddressId::new(address_str.unwrap()).map_err(|_| ApiError::InvalidAddress)?;
    Ok((address, secondary.unwrap()))
}

fn normalise_platform(raw: Option<String>, fallback: &str) -> String {
    raw.map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

async fn validate_miner_address<H, M>(
    state: &SharedState<H, M>,
    address: &AddressId,
) -> Result<(), ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let row = bp_db::find_address_settings(&state.pool, address).await?;
    if row.is_none() {
        return Err(push_error("not-active-miner", StatusCode::FORBIDDEN));
    }
    Ok(())
}

fn push_error(code: &'static str, status: StatusCode) -> ApiError {
    ApiError::GroupService { code, status }
}

fn format_iso_ms(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}
