// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/pplns/invitations/*` — open-invite reader + accept endpoints.

use axum::{
    extract::{Path, State},
    response::Json,
    routing::{get, post},
    Router,
};
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route(
            "/api/pplns/invitations/open/:token",
            get(open_public::<H, M>),
        )
        .route(
            "/api/pplns/invitations/open/:token/accept",
            post(accept_open::<H, M>).layer(rate_limit::per_minute_layer(10)),
        )
}

// ─── writers ────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberCreatedResponse {
    address: String,
    role: String,
    /// ISO-8601 millisecond-precision timestamp.
    joined_at: String,
    group_id: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptOpenBody {
    address: String,
}

async fn accept_open<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
    Json(body): Json<AcceptOpenBody>,
) -> Result<Json<MemberCreatedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_invitation(&state)?;
    let member = svc
        .accept_open_invite(&token, &body.address)
        .await
        .map_err(invitation_to_api_error)?;
    Ok(Json(MemberCreatedResponse {
        address: member.address.as_str().to_string(),
        role: member.role,
        joined_at: crate::time_range::format_iso_ms(member.joined_at),
        group_id: member.group_id,
    }))
}

fn require_invitation<H, M>(
    state: &SharedState<H, M>,
) -> Result<&bp_group_mgmt_engine::InvitationService<H>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    state
        .invitation_service
        .as_deref()
        .ok_or(ApiError::Unavailable("invitation-service not wired"))
}

// ─── GET /api/invitations/open/:token ────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenInviteResponse {
    token: String,
    group_id: Uuid,
    group_name: String,
    /// ISO-8601 millisecond timestamp.
    expires_at: String,
    approval_required: bool,
}

async fn open_public<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
) -> Result<Json<OpenInviteResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_invitation(&state)?;
    let view = svc
        .get_open_invite_public(&token)
        .await
        .map_err(invitation_to_api_error)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(OpenInviteResponse {
        token: view.token,
        group_id: view.group_id,
        group_name: view.group_name,
        expires_at: crate::time_range::format_iso_ms(view.expires_at),
        approval_required: view.approval_required,
    }))
}

/// Map an `InvitationServiceError` to the `ApiError` wire-form. Public
/// reader endpoints rarely hit a service error other than internal
/// faults (most validation is for writer paths), but the mapping is
/// here so [`ApiError`] stays the single error surface.
pub(crate) fn invitation_to_api_error(e: bp_group_mgmt_engine::InvitationServiceError) -> ApiError {
    use axum::http::StatusCode;
    use bp_group_mgmt_engine::InvitationServiceError as I;
    let code: &'static str = match e.code() {
        "not-found" => "not-found",
        "already-declined" => "already-declined",
        "inconsistent" => "inconsistent",
        "expired" => "expired",
        "group-dissolved" => "group-dissolved",
        "invitation-pending" => "invitation-pending",
        "email-not-verified" => "email-not-verified",
        "invalid-address" => "invalid-address",
        "address-in-group" => "address-in-group",
        "already-member" => "already-member",
        "invalid-ttl" => "invalid-ttl",
        "approval-required" => "approval-required",
        "config-missing" => "config-missing",
        _ => "internal-error",
    };
    let status = match e {
        I::NotFound => StatusCode::NOT_FOUND,
        I::Expired
        | I::AlreadyDeclined
        | I::GroupDissolved
        | I::InvitationPending
        | I::AddressInGroup
        | I::AlreadyMember => StatusCode::CONFLICT,
        I::EmailNotVerified | I::ApprovalRequired => StatusCode::FORBIDDEN,
        I::InvalidAddress | I::InvalidTtl => StatusCode::BAD_REQUEST,
        I::ConfigMissing | I::Inconsistent => StatusCode::INTERNAL_SERVER_ERROR,
        I::GroupService(g) => return ApiError::from(g),
        I::Db(_) | I::Token(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ApiError::Invitation { code, status }
}
