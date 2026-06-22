// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/pplns/invitations/*` — directed + open invitation reader endpoints.
//!
//! Writer endpoints (accept/decline/open-accept) are in `controllers/groups.rs`.

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
            "/api/pplns/invitations/by-address/:address",
            get(by_address::<H, M>),
        )
        .route(
            "/api/pplns/invitations/open/:token",
            get(open_public::<H, M>),
        )
        .route(
            "/api/pplns/invitations/open/:token/accept",
            post(accept_open::<H, M>).layer(rate_limit::per_minute_layer(10)),
        )
        .route("/api/pplns/invitations/:token", get(get_token::<H, M>))
        .route(
            "/api/pplns/invitations/:token/accept",
            post(accept::<H, M>).layer(rate_limit::per_minute_layer(20)),
        )
        .route(
            "/api/pplns/invitations/:token/decline",
            post(decline::<H, M>).layer(rate_limit::per_minute_layer(20)),
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

async fn accept<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
) -> Result<Json<MemberCreatedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_invitation(&state)?;
    let member = svc.accept(&token).await.map_err(invitation_to_api_error)?;
    Ok(Json(MemberCreatedResponse {
        address: member.address.as_str().to_string(),
        role: member.role,
        joined_at: crate::time_range::format_iso_ms(member.joined_at),
        group_id: member.group_id,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OkResponse {
    ok: bool,
}

async fn decline<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
) -> Result<Json<OkResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_invitation(&state)?;
    svc.decline(&token).await.map_err(invitation_to_api_error)?;
    Ok(Json(OkResponse { ok: true }))
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
) -> Result<&bp_group_mgmt_engine::InvitationService<H, M>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    state
        .invitation_service
        .as_deref()
        .ok_or(ApiError::Unavailable("invitation-service not wired"))
}

// ─── GET /api/invitations/by-address/:address ────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingForAddressEntry {
    group_id: Uuid,
    group_name: String,
    inviter_address: String,
    masked_email: String,
    /// ISO-8601 millisecond timestamp.
    created_at: String,
    expires_at: String,
}

async fn by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<PendingForAddressEntry>>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_invitation(&state)?;
    let entries = svc
        .list_pending_for_address(&address)
        .await
        .map_err(invitation_to_api_error)?;
    Ok(Json(
        entries
            .into_iter()
            .map(|e| PendingForAddressEntry {
                group_id: e.group_id,
                group_name: e.group_name,
                inviter_address: e.inviter_address.as_str().to_string(),
                masked_email: e.masked_email,
                created_at: crate::time_range::format_iso_ms(e.created_at),
                expires_at: crate::time_range::format_iso_ms(e.expires_at),
            })
            .collect(),
    ))
}

// ─── GET /api/invitations/:token ─────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationByTokenResponse {
    token: String,
    group_id: Uuid,
    group_name: String,
    inviter_address: String,
    /// Populated for directed invites; `null` for open invitations
    /// (the row carries no pre-bound address).
    address: Option<String>,
    email: Option<String>,
    status: String,
    /// ISO-8601 millisecond timestamp.
    created_at: String,
    expires_at: String,
    responded_at: Option<String>,
}

async fn get_token<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
) -> Result<Json<InvitationByTokenResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_invitation(&state)?;
    let (invitation, group) = svc
        .get_by_token(&token)
        .await
        .map_err(invitation_to_api_error)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(InvitationByTokenResponse {
        token: invitation.token,
        group_id: group.id,
        group_name: group.name,
        inviter_address: group.creator_address.as_str().to_string(),
        address: invitation.address.map(|a| a.as_str().to_string()),
        email: invitation.email,
        status: invitation.status,
        created_at: crate::time_range::format_iso_ms(invitation.created_at),
        expires_at: crate::time_range::format_iso_ms(invitation.expires_at),
        responded_at: crate::time_range::format_iso_ms_opt(invitation.responded_at),
    }))
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
