// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/share/*` — external-pool share submission + top-difficulty
//! leaderboard.
//!
//! POST validates: optional `x-api-key` header (when configured),
//! difficulty ≥ `MINIMUM_DIFFICULTY` (default 1 T), block-header
//! timestamp ≤ 10 min old. On success inserts the row + returns
//! `{success, calculatedDifficulty}`.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use bp_common::AddressId;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::SharedState;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route("/api/share/top-difficulties", get(top_difficulties::<H, M>))
        .route("/api/share", post(submit::<H, M>))
}

// ─── GET /api/share/top-difficulties ──────────────────────────────

/// Response: array of `{userAgent, time, externalPoolName, difficulty}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TopDiffEntry {
    user_agent: Option<String>,
    time: i64,
    external_pool_name: Option<String>,
    difficulty: f64,
}

async fn top_difficulties<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<Vec<TopDiffEntry>>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let rows = bp_db::find_external_share_top_difficulties(&state.pool).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| TopDiffEntry {
                user_agent: r.user_agent,
                time: r.time,
                external_pool_name: r.external_pool_name,
                difficulty: r.difficulty as f64,
            })
            .collect(),
    ))
}

// ─── POST /api/share ──────────────────────────────────────────────

/// Request body: `{worker, address, userAgent, externalPoolName, header}` —
/// all strings; `header` is hex of the 80-byte block header.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalShareBody {
    worker: String,
    address: String,
    user_agent: String,
    external_pool_name: String,
    header: String,
}

/// Response shape: `{success: true, calculatedDifficulty: <number>}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitResponse {
    success: bool,
    calculated_difficulty: f64,
}

async fn submit<H, M>(
    State(state): State<SharedState<H, M>>,
    headers: HeaderMap,
    Json(body): Json<ExternalShareBody>,
) -> Result<Json<SubmitResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Optional API-key check — when configured, must match. Reads
    // the expected key from `SHARE_SUBMISSION_API_KEY`. When unset,
    // accept any caller.
    if let Ok(expected) = std::env::var("SHARE_SUBMISSION_API_KEY") {
        if !expected.is_empty() {
            let provided = headers.get("x-api-key").and_then(|v| v.to_str().ok());
            if provided != Some(expected.as_str()) {
                return Err(ApiError::GroupService {
                    code: "unauthorized",
                    status: StatusCode::UNAUTHORIZED,
                });
            }
        }
    }

    // Decode the header bytes + compute difficulty using bp-share's
    // sha256d-then-target-to-diff helper.
    let header_bytes =
        hex::decode(&body.header).map_err(|_| ApiError::BadRequest("header must be valid hex"))?;
    if header_bytes.len() != 80 {
        return Err(ApiError::BadRequest("header must be 80 bytes"));
    }
    let validation = bp_share::calculate_difficulty(&header_bytes);
    let difficulty = validation.submission_difficulty.as_f64();

    // Minimum-difficulty gate. Default = 1 T (1e12).
    let min_difficulty = std::env::var("MINIMUM_DIFFICULTY")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(1_000_000_000_000.0);
    if difficulty < min_difficulty {
        return Err(ApiError::GroupService {
            code: "share-difficulty-too-low",
            status: StatusCode::UNAUTHORIZED,
        });
    }

    // Timestamp freshness — the timestamp lives at bytes 68..72 of
    // the 80-byte block header (little-endian u32, seconds-since-epoch).
    let header_ts_sec = u32::from_le_bytes([
        header_bytes[68],
        header_bytes[69],
        header_bytes[70],
        header_bytes[71],
    ]) as i64;
    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if header_ts_sec < now_sec - 10 * 60 {
        return Err(ApiError::GroupService {
            code: "share-timestamp-too-old",
            status: StatusCode::UNAUTHORIZED,
        });
    }

    let address = AddressId::new(body.address).map_err(|_| ApiError::InvalidAddress)?;
    bp_db::insert_external_share(
        &state.pool,
        &address,
        &body.worker,
        now_sec * 1000,
        difficulty as f32,
        Some(&body.user_agent),
        Some(&body.external_pool_name),
        &body.header,
    )
    .await?;

    Ok(Json(SubmitResponse {
        success: true,
        calculated_difficulty: difficulty,
    }))
}
