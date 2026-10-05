// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/pplns/groups/*`. Admin-only routes sit behind
//! [`crate::middleware::admin_auth::require_admin`], with the service check
//! kept as defence-in-depth; where the token only shapes the response, the
//! handler checks it inline.

use std::collections::{BTreeMap, HashMap};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, patch, post},
    Extension, Router,
};
use bp_common::AddressId;
use bp_db::PatchField;
use bp_group_mgmt::group::{PayoutMode, RoundResetPreset};
use bp_group_mgmt_engine::{GroupService, OpenInviteTtl, UpdateRoundResetSettings};
use bp_group_solo_engine::reader::WindowTimeline;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::admin_auth::{require_admin, AdminAuth};
use crate::middleware::rate_limit;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::SharedState;
use crate::utils::{build_member_labels, member_id};

pub(crate) fn routes(state: SharedState) -> Router<SharedState> {
    // `route_layer` applies only to routes registered before it, so every
    // admin route must be added above the layer call.
    let admin_routes = Router::new()
        // ─── admin writers ───────────────────────────────────────
        .route("/api/pplns/groups/{id}/transfer", post(transfer))
        .route("/api/pplns/groups/{id}/settings", patch(update_settings))
        .route("/api/pplns/groups/{id}", delete(dissolve))
        .route(
            "/api/pplns/groups/{id}/invitations/open",
            post(create_open_invite)
                .layer(rate_limit::per_minute_layer(5))
                .delete(revoke_open_invite),
        )
        .route(
            "/api/pplns/groups/{id}/members/{address}",
            delete(remove_member),
        )
        .route(
            "/api/pplns/groups/{id}/join-requests/{req_id}/approve",
            post(approve_join_request),
        )
        .route(
            "/api/pplns/groups/{id}/join-requests/{req_id}/reject",
            post(reject_join_request),
        )
        .route_layer(axum::middleware::from_fn_with_state(state, require_admin));

    let public_routes = Router::new()
        .route("/api/pplns/groups/public", get(list_public))
        .route(
            "/api/pplns/groups/coinbase-capacity",
            get(coinbase_capacity),
        )
        .route(
            "/api/pplns/groups/join-requests/by-address/{address}",
            get(join_requests_by_address),
        )
        .route("/api/pplns/groups/public/{id}", get(public_one))
        .route("/api/pplns/groups/by-address/{address}", get(by_address))
        .route("/api/pplns/groups/membership/{address}", get(membership))
        .route("/api/pplns/groups/{id}/admin-check", get(admin_check))
        .route("/api/pplns/groups/{id}/hashrate", get(hashrate))
        .route("/api/pplns/groups/{id}/chart", get(group_chart))
        .route("/api/pplns/groups/{id}/accepted", get(group_accepted))
        .route("/api/pplns/groups/{id}/rejected", get(group_rejected))
        .route(
            "/api/pplns/groups/{id}/max-difficulty",
            get(group_max_difficulty),
        )
        .route("/api/pplns/groups/{id}/distribution", get(distribution))
        .route(
            "/api/pplns/groups/{id}/window-timeline",
            get(window_timeline),
        )
        .route(
            "/api/pplns/groups/{id}/best-difficulty",
            get(best_difficulty),
        )
        .route("/api/pplns/groups/{id}/history", get(history))
        .route(
            "/api/pplns/groups/{id}/invitations/open/active",
            get(open_invite_active),
        )
        .route(
            "/api/pplns/groups/{id}/join-requests",
            get(list_join_requests),
        )
        .route("/api/pplns/groups", post(create))
        .route(
            "/api/pplns/groups/public/{id}/join-request",
            post(create_join_request).layer(rate_limit::per_minute_layer(10)),
        )
        // Last, so the more specific paths above win the route-match.
        .route("/api/pplns/groups/{id}", get(by_id));

    admin_routes.merge(public_routes)
}

// ─── cache invalidation helpers ──────────────────────────────────

/// Called by every mutating endpoint so the next read is fresh, not TTL-old.
async fn invalidate_group_cache(state: &SharedState, id: Uuid) {
    let id_str = id.to_string();
    state.cache.invalidate_prefix("GROUP_PUBLIC_LIST").await;
    for prefix in [
        "GROUP_PUBLIC_DETAIL_",
        "GROUP_DETAIL_",
        "GROUP_HASHRATE_",
        "GROUP_CHART_",
        "GROUP_ACCEPTED_",
        "GROUP_REJECTED_",
        "GROUP_DISTRIBUTION_",
        "GROUP_BEST_DIFFICULTY_",
        "GROUP_MAX_DIFFICULTY_",
        "GROUP_WINDOW_TIMELINE_",
        "GROUP_HISTORY_",
        "GROUP_INVITATIONS_",
        "GROUP_JOIN_REQUESTS_",
        "GROUP_OPEN_INVITE_ACTIVE_",
    ] {
        let full = format!("{prefix}{id_str}");
        state.cache.invalidate_prefix(&full).await;
    }
    // The round-reset cadence doubles as the Window payout length, so the
    // engine's mode cache is dropped too; otherwise the trim would run on a
    // stale window length until its TTL.
    if let Some(engine) = state.group_solo.as_ref() {
        engine.invalidate_mode_cache(id);
    }
}

/// For membership changes, so the join-request lookup re-resolves immediately.
async fn invalidate_address_group_cache(state: &SharedState, address: &AddressId) {
    let jr = format!("GROUP_JOIN_REQUESTS_BY_ADDR_{}", address.as_str());
    state.cache.invalidate(&jr).await;
}

// ─── writer DTOs + handlers ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupBody {
    name: String,
    creator_address: String,
    /// `"prop"` (default) or `"window"`; immutable after creation.
    #[serde(default)]
    mode: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitialMember {
    address: String,
    role: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupResponse {
    #[serde(flatten)]
    summary: GroupSummary,
    /// Shown exactly once; only its hash is stored.
    admin_token: String,
    members: Vec<InitialMember>,
}

async fn create(
    State(state): State<SharedState>,
    Json(body): Json<CreateGroupBody>,
) -> Result<(StatusCode, Json<CreateGroupResponse>), ApiError> {
    // A group created here would route its members to a mode this pool
    // does not run.
    if state.group_solo.is_none() {
        return Err(ApiError::Unavailable("group-solo is disabled"));
    }
    let svc = require_group_service(&state)?;
    // Immutable, so validated up front.
    let mode = match body.mode.as_deref() {
        None => bp_group_mgmt::group::PayoutMode::Prop,
        Some(s) => bp_group_mgmt::group::PayoutMode::parse(s)
            .ok_or(ApiError::BadRequest("mode must be 'prop' or 'window'"))?,
    };
    let res = svc
        .create_group_with_mode(&body.name, &body.creator_address, mode)
        .await?;
    state.cache.invalidate_prefix("GROUP_PUBLIC_LIST").await;
    if let Ok(addr) = AddressId::new(body.creator_address.clone()) {
        invalidate_address_group_cache(&state, &addr).await;
    }
    let creator_address = res.group.creator_address.as_str().to_string();
    Ok((
        StatusCode::CREATED,
        Json(CreateGroupResponse {
            summary: GroupSummary::from(res.group),
            admin_token: res.admin_token,
            members: vec![InitialMember {
                address: creator_address,
                role: "creator",
            }],
        }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferBody {
    to_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferResponse {
    #[serde(flatten)]
    summary: GroupSummary,
    admin_token: String,
}

async fn transfer(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<TransferBody>,
) -> Result<Json<TransferResponse>, ApiError> {
    let svc = require_group_service(&state)?;
    let res = svc
        .transfer_creator(id, &body.to_address, Some(&auth.admin_token))
        .await?;
    invalidate_group_cache(&state, id).await;
    if let Ok(addr) = AddressId::new(body.to_address.clone()) {
        invalidate_address_group_cache(&state, &addr).await;
    }
    Ok(Json(TransferResponse {
        summary: GroupSummary::from(res.group),
        admin_token: res.admin_token,
    }))
}

/// `deny_unknown_fields`: an unknown key is a 400, not a 200 that silently
/// changed nothing.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateSettingsBody {
    /// Absent = untouched, a value = set, JSON `null` = clear.
    #[serde(default)]
    preset: Option<Option<String>>,
    #[serde(default)]
    interval_days: Option<Option<u32>>,
    #[serde(default)]
    timezone: Option<Option<String>>,
    #[serde(default)]
    finder_bonus_ppm: Option<Option<i32>>,
    #[serde(default)]
    is_public: Option<bool>,
    #[serde(default)]
    reset_round_on_block: Option<bool>,
    #[serde(default)]
    max_members: Option<Option<i64>>,
}

fn lift_patch<T: Clone, R>(field: &Option<Option<T>>, map: impl Fn(&T) -> R) -> PatchField<R> {
    match field {
        None => PatchField::Untouched,
        Some(None) => PatchField::Clear,
        Some(Some(v)) => PatchField::Set(map(v)),
    }
}

async fn update_settings(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<UpdateSettingsBody>,
) -> Result<Json<GroupSummary>, ApiError> {
    let svc = require_group_service(&state)?;
    // The finder bonus is a fraction of the miner cut, so it cannot exceed
    // the block by construction; its range check lives in the service layer.
    let preset = match &body.preset {
        None => PatchField::Untouched,
        Some(None) => PatchField::Clear,
        Some(Some(s)) => {
            PatchField::Set(RoundResetPreset::parse(s).ok_or(ApiError::GroupService {
                code: "invalid-preset",
                status: StatusCode::BAD_REQUEST,
            })?)
        }
    };
    let settings = UpdateRoundResetSettings {
        preset,
        interval_days: lift_patch(&body.interval_days, |d| *d),
        timezone: lift_patch(&body.timezone, |t| t.clone()),
        finder_bonus_ppm: lift_patch(&body.finder_bonus_ppm, |p| *p),
        is_public: match body.is_public {
            None => PatchField::Untouched,
            Some(v) => PatchField::Set(v),
        },
        reset_round_on_block: match body.reset_round_on_block {
            None => PatchField::Untouched,
            Some(v) => PatchField::Set(v),
        },
        max_members: lift_patch(&body.max_members, |v| *v as i32),
    };
    let row = svc
        .update_round_reset_config(id, settings, Some(&auth.admin_token))
        .await?;
    invalidate_group_cache(&state, id).await;
    Ok(Json(GroupSummary::from(row)))
}

/// Delegates to [`bp_share::block_subsidy_sats`], the function settlement
/// gates on, so there is one halving rule. Heights beyond `i32` clamp.
pub(crate) fn block_subsidy_sats(height: u64, network: bitcoin::Network) -> u64 {
    let interval = match network {
        bitcoin::Network::Regtest => bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
        _ => bp_share::SUBSIDY_HALVING_INTERVAL,
    };
    bp_share::block_subsidy_sats(height.min(i32::MAX as u64) as i32, interval)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupCoinbaseCapacity {
    /// Worst case: every output the heaviest standard type, plus the pool
    /// output slot.
    max_members: u64,
    /// Engine-wide, identical for every group.
    weight_budget: u32,
    /// The pool output consumes one member slot.
    has_fee_output: bool,
}

/// Uses [`max_coinbase_outputs`](bp_pplns_engine::max_coinbase_outputs), the
/// same ceiling `GroupService` refuses a join against. The autoscaled PPLNS
/// budget is a different one.
async fn coinbase_capacity(
    State(state): State<SharedState>,
) -> Result<Json<GroupCoinbaseCapacity>, ApiError> {
    let engine = state
        .group_solo
        .as_ref()
        .ok_or(ApiError::Unavailable("group-solo not wired"))?;
    let cfg = engine.config();
    Ok(Json(GroupCoinbaseCapacity {
        max_members: bp_pplns_engine::max_coinbase_outputs(cfg.coinbase_weight_budget),
        weight_budget: cfg.coinbase_weight_budget,
        // The pool output is structural, so reserved even at 0 % fee.
        has_fee_output: true,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DissolveResponse {
    dissolved: bool,
}

async fn dissolve(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<DissolveResponse>, ApiError> {
    let svc = require_group_service(&state)?;
    svc.dissolve_group(id, Some(&auth.admin_token)).await?;
    invalidate_group_cache(&state, id).await;
    Ok(Json(DissolveResponse { dissolved: true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOpenInviteBody {
    /// `"1h"` / `"24h"` / `"7d"` / `"30d"`.
    ttl: String,
    #[serde(default)]
    approval_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateOpenInviteResponse {
    token: String,
    expires_at: String,
    approval_required: bool,
    link: String,
}

async fn create_open_invite(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<CreateOpenInviteBody>,
) -> Result<(StatusCode, Json<CreateOpenInviteResponse>), ApiError> {
    let inv_svc = require_invitation_service(&state)?;
    let ttl = OpenInviteTtl::parse(&body.ttl).ok_or(ApiError::Invitation {
        code: "invalid-ttl",
        status: StatusCode::BAD_REQUEST,
    })?;
    let created = inv_svc
        .create_open_invite(id, ttl, Some(&auth.admin_token), body.approval_required)
        .await
        .map_err(crate::controllers::invitation::invitation_to_api_error)?;
    invalidate_group_cache(&state, id).await;
    let link = state
        .pool_base_url
        .as_deref()
        .map(|base| format!("{}/#/invite/open/{}", base, created.token))
        .unwrap_or_default();
    Ok((
        StatusCode::CREATED,
        Json(CreateOpenInviteResponse {
            token: created.token,
            expires_at: crate::time_range::format_iso_ms(created.expires_at),
            approval_required: created.approval_required,
            link,
        }),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenInviteRevokedResponse {
    revoked: bool,
}

async fn revoke_open_invite(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<OpenInviteRevokedResponse>, ApiError> {
    let inv_svc = require_invitation_service(&state)?;
    inv_svc
        .revoke_open_invite(id, Some(&auth.admin_token))
        .await
        .map_err(crate::controllers::invitation::invitation_to_api_error)?;
    invalidate_group_cache(&state, id).await;
    Ok(Json(OpenInviteRevokedResponse { revoked: true }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemovedResponse {
    removed: bool,
}

async fn remove_member(
    State(state): State<SharedState>,
    Path((id, address)): Path<(Uuid, String)>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<RemovedResponse>, ApiError> {
    let svc = require_group_service(&state)?;
    svc.remove_member(id, &address, Some(&auth.admin_token))
        .await?;
    invalidate_group_cache(&state, id).await;
    if let Ok(addr) = AddressId::new(address) {
        invalidate_address_group_cache(&state, &addr).await;
    }
    Ok(Json(RemovedResponse { removed: true }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovedResponse {
    approved: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectedResponse {
    rejected: bool,
}

async fn approve_join_request(
    State(state): State<SharedState>,
    Path((id, req_id)): Path<(Uuid, Uuid)>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<ApprovedResponse>, ApiError> {
    let jr_svc = require_join_request_service(&state)?;
    jr_svc
        .approve_request(id, req_id, Some(&auth.admin_token))
        .await
        .map_err(jr_to_api_error)?;
    invalidate_group_cache(&state, id).await;
    // The requester's address is unknown here, so invalidate broadly.
    state
        .cache
        .invalidate_prefix("GROUP_JOIN_REQUESTS_BY_ADDR_")
        .await;
    Ok(Json(ApprovedResponse { approved: true }))
}

async fn reject_join_request(
    State(state): State<SharedState>,
    Path((id, req_id)): Path<(Uuid, Uuid)>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<RejectedResponse>, ApiError> {
    let jr_svc = require_join_request_service(&state)?;
    jr_svc
        .reject_request(id, req_id, Some(&auth.admin_token))
        .await
        .map_err(jr_to_api_error)?;
    invalidate_group_cache(&state, id).await;
    state
        .cache
        .invalidate_prefix("GROUP_JOIN_REQUESTS_BY_ADDR_")
        .await;
    Ok(Json(RejectedResponse { rejected: true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateJoinRequestBody {
    address: String,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateJoinRequestResponse {
    id: Uuid,
    group_id: Uuid,
    status: String,
    created_at: String,
}

async fn create_join_request(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateJoinRequestBody>,
) -> Result<(StatusCode, Json<CreateJoinRequestResponse>), ApiError> {
    let svc = require_join_request_service(&state)?;
    let row = svc
        .create_join_request(id, &body.address, body.message.as_deref())
        .await
        .map_err(jr_to_api_error)?;
    invalidate_group_cache(&state, id).await;
    if let Ok(addr) = AddressId::new(body.address.clone()) {
        invalidate_address_group_cache(&state, &addr).await;
    }
    Ok((
        StatusCode::CREATED,
        Json(CreateJoinRequestResponse {
            id: row.id,
            group_id: row.group_id,
            status: row.status,
            created_at: crate::time_range::format_iso_ms(row.created_at),
        }),
    ))
}

// ─── helpers ──────────────────────────────────────────────────────

fn require_group_service(state: &SharedState) -> Result<&GroupService, ApiError> {
    state
        .group_service
        .as_deref()
        .ok_or(ApiError::Unavailable("group-service not wired"))
}

fn require_invitation_service(
    state: &SharedState,
) -> Result<&bp_group_mgmt_engine::InvitationService, ApiError> {
    state
        .invitation_service
        .as_deref()
        .ok_or(ApiError::Unavailable("invitation-service not wired"))
}

fn require_join_request_service(
    state: &SharedState,
) -> Result<&bp_group_mgmt_engine::JoinRequestService, ApiError> {
    state
        .join_request_service
        .as_deref()
        .ok_or(ApiError::Unavailable("join-request-service not wired"))
}

fn admin_token(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-admin-token").and_then(|v| v.to_str().ok())
}

/// `None` without the header, an error when it is wrong. Call BEFORE a cache
/// lookup keyed on the admin flag: a check inside the cached computation runs
/// only on a miss, so any token would read a real admin's cached body.
async fn verified_admin_token<'h>(
    state: &SharedState,
    id: Uuid,
    headers: &'h HeaderMap,
) -> Result<Option<&'h str>, ApiError> {
    let Some(token) = admin_token(headers) else {
        return Ok(None);
    };
    require_group_service(state)?
        .require_admin_token(id, Some(token))
        .await?;
    Ok(Some(token))
}

// ─── DTOs ────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupSummary {
    id: Uuid,
    name: String,
    /// Nulled on the public directory shapes, so anonymous viewers never see
    /// the creator's on-chain address.
    #[serde(skip_serializing_if = "Option::is_none")]
    creator_address: Option<String>,
    active: bool,
    created_at: String,
    round_reset_preset: Option<String>,
    round_reset_interval_days: Option<i32>,
    round_reset_timezone: Option<String>,
    finder_bonus_ppm: i32,
    last_round_reset_at: Option<String>,
    /// See [`next_reset_at`]; `None` without a usable schedule.
    next_reset_at: Option<String>,
    is_public: bool,
    reset_round_on_block: bool,
    /// Null = no limit.
    max_members: Option<i64>,
    /// `"prop"` or `"window"`; immutable.
    mode: String,
}

impl From<bp_db::PplnsGroupRow> for GroupSummary {
    fn from(r: bp_db::PplnsGroupRow) -> Self {
        // Window-mode groups never calendar-reset: their preset is the
        // sliding-window length, so there is no `nextResetAt` to advertise.
        let next_reset_at = match PayoutMode::parse_or_default(&r.payout_mode) {
            PayoutMode::Window => None,
            PayoutMode::Prop => next_reset_at(&r).map(crate::time_range::format_iso_ms),
        };
        Self {
            id: r.id,
            name: r.name,
            creator_address: Some(r.creator_address.as_str().to_string()),
            active: r.active,
            created_at: crate::time_range::format_iso_ms(r.created_at),
            round_reset_preset: r.round_reset_preset,
            round_reset_interval_days: r.round_reset_interval_days,
            round_reset_timezone: r.round_reset_timezone,
            finder_bonus_ppm: r.finder_bonus_ppm.unwrap_or(0),
            last_round_reset_at: r.last_round_reset_at.map(crate::time_range::format_iso_ms),
            next_reset_at,
            is_public: r.is_public,
            reset_round_on_block: r.reset_round_on_block,
            max_members: r.max_members.map(|v| v as i64),
            mode: r.payout_mode,
        }
    }
}

/// Computed by the reset cron's own
/// [`compute_next_fire`](bp_group_solo_engine::reset::compute_next_fire), so
/// the advertised instant is the one it fires at.
fn next_reset_at(r: &bp_db::PplnsGroupRow) -> Option<i64> {
    use bp_group_solo_engine::reset::{compute_next_fire, ResetSchedule};
    let schedule = ResetSchedule::from_row_fields(
        r.id,
        r.round_reset_preset.as_deref(),
        r.round_reset_timezone.as_deref(),
        r.round_reset_interval_days
            .and_then(|d| u32::try_from(d).ok()),
    )
    .ok()??;
    Some(compute_next_fire(&schedule, r.last_round_reset_at, chrono::Utc::now()).timestamp_millis())
}

// ─── GET /api/groups/public ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicListQuery {
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicListResponse {
    page: u32,
    page_size: u32,
    total: usize,
    items: Vec<PublicGroupEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicGroupEntry {
    #[serde(flatten)]
    summary: GroupSummary,
    member_count: usize,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_hashrate: f64,
}

async fn list_public(
    State(state): State<SharedState>,
    Query(q): Query<PublicListQuery>,
) -> Result<JsonBytes, ApiError> {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(50).clamp(1, 100);
    let key = format!("GROUP_PUBLIC_LIST_{page}_{page_size}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<PublicListResponse, _, ApiError>(
            key,
            TtlKind::GroupPublicList,
            async move {
                let svc = require_group_service(&s)?;
                let all_public: Vec<_> = svc
                    .list_groups()
                    .await?
                    .into_iter()
                    .filter(|g| g.is_public)
                    .collect();
                let total = all_public.len();
                let start = ((page - 1) as usize) * page_size as usize;
                let end = (start + page_size as usize).min(total);
                let slice = if start < total {
                    &all_public[start..end]
                } else {
                    &[][..]
                };
                // ONE live-hashrate read for the page: each read SCANs the
                // whole Redis keyspace, so per-group calls would multiply it.
                let mut rosters = Vec::with_capacity(slice.len());
                for g in slice {
                    rosters.push((g, svc.list_members(g.id).await?));
                }
                let everyone: Vec<AddressId> = rosters
                    .iter()
                    .flat_map(|(_, members)| members.iter().map(|m| m.address.clone()))
                    .collect();
                let by_address = crate::error::or_degraded(
                    bp_client_live::hashrate_by_address(s.redis.as_ref(), &everyone).await,
                    || zeroed(&everyone),
                )?;
                let mut items = Vec::with_capacity(rosters.len());
                for (g, members) in rosters {
                    let total_hashrate: f64 = members
                        .iter()
                        .map(|m| by_address.get(m.address.as_str()).copied().unwrap_or(0.0))
                        .sum();
                    let mut summary = GroupSummary::from(g.clone());
                    summary.creator_address = None; // never expose the creator publicly
                    items.push(PublicGroupEntry {
                        summary,
                        member_count: members.len(),
                        total_hashrate,
                    });
                }
                Ok(PublicListResponse {
                    page,
                    page_size,
                    total,
                    items,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/public/:id ──────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicGroupDetail {
    #[serde(flatten)]
    summary: GroupSummary,
    member_count: usize,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_hashrate: f64,
    recent_blocks: Vec<RecentBlock>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecentBlock {
    id: i32,
    group_id: Uuid,
    block_height: i32,
    created_at: String,
    /// Masked; the full address is never sent.
    address_label: String,
    paid_sats: i64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    shares_in_round: i64,
    total_shares_in_round: i64,
    row_type: String,
}

async fn public_one(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("GROUP_PUBLIC_DETAIL_{id}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<PublicGroupDetail, _, ApiError>(
            key,
            TtlKind::GroupPublicDetail,
            async move {
                let svc = require_group_service(&s)?;
                let group = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
                if !group.is_public {
                    return Err(ApiError::NotFound);
                }
                let members = svc.list_members(id).await?;
                let addrs: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
                let total_hashrate = crate::error::or_degraded(
                    bp_client_live::hashrate_for_addresses(s.redis.as_ref(), &addrs).await,
                    || 0.0,
                )?;
                let history = bp_db::find_recent_group_block_history(&s.pool, id, 20).await?;
                let mut summary = GroupSummary::from(group);
                summary.creator_address = None; // never expose the creator publicly
                Ok(PublicGroupDetail {
                    recent_blocks: history
                        .into_iter()
                        .map(|h| RecentBlock {
                            id: h.id,
                            group_id: h.group_id,
                            block_height: h.block_height,
                            created_at: crate::time_range::format_iso_ms(h.created_at),
                            address_label: bp_common::short_address(h.address.as_str()),
                            paid_sats: h.paid_sats.to_i64(),
                            percent: h.percent as f64,
                            shares_in_round: h.shares_in_round,
                            total_shares_in_round: h.total_shares_in_round,
                            row_type: h.row_type,
                        })
                        .collect(),
                    summary,
                    member_count: members.len(),
                    total_hashrate,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/:id ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ViewerQuery {
    /// Only flags the viewer's own row `isSelf`; never echoed for others.
    viewer: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDetailResponse {
    #[serde(flatten)]
    summary: GroupSummary,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_hashrate: f64,
    members: Vec<MemberEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberEntry {
    /// Opaque stable join key; the full address is never sent.
    member_id: String,
    /// Masked, unique within the group.
    address_label: String,
    /// Admin-token callers only, so a group id cannot harvest member addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// True only for the row matching `?viewer=`.
    is_self: bool,
    role: String,
    joined_at: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    hashrate: f64,
    /// Served here so the UI never needs a member's full address.
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    best_difficulty: f64,
    /// Earliest worker start (uptime basis); None when offline.
    #[serde(skip_serializing_if = "Option::is_none")]
    start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<String>,
    last_accepted_share_at: Option<String>,
    /// Admin-only and masked.
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// `"email"` or `"signature"`; admin-only, like `email`.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_via: Option<&'static str>,
}

async fn by_id(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<ViewerQuery>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError> {
    // Admin flag and viewer are both in the cache key, so neither view leaks
    // into the other.
    let is_admin = verified_admin_token(&state, id, &headers).await?.is_some();
    let viewer = q
        .viewer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let key = format!(
        "GROUP_DETAIL_{id}_{}_{}",
        if is_admin { "admin" } else { "pub" },
        viewer.as_deref().unwrap_or("none"),
    );
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<GroupDetailResponse, _, ApiError>(key, TtlKind::GroupDetail, async move {
            let svc = require_group_service(&s)?;
            let group = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
            let members = svc.list_members(id).await?;
            let addrs: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
            let per_addr_hashrate = crate::error::or_degraded(
                bp_client_live::hashrate_by_address(s.redis.as_ref(), &addrs).await,
                || zeroed(&addrs),
            )?;
            let total_hashrate: f64 = per_addr_hashrate.values().sum();
            let addr_strings: Vec<String> = addrs.iter().map(|a| a.as_str().to_string()).collect();
            let labels = build_member_labels(&addr_strings);
            let owned_signatures = if is_admin {
                bp_db::addresses_with_ownership_proof(&s.pool, &addr_strings).await?
            } else {
                std::collections::HashSet::new()
            };

            // Roster-wide session stats in two round trips, not two per member.
            let sessions =
                bp_db::find_active_sessions_for_addresses(&s.pool, &addr_strings).await?;
            let live = crate::error::or_degraded(
                bp_client_live::live_fields_for_sessions(s.redis.as_ref(), &sessions).await,
                || vec![None; sessions.len()],
            )?;
            let mut start_times: HashMap<&str, i64> = HashMap::new();
            let mut last_seen_by_address: HashMap<&str, i64> = HashMap::new();
            for (c, lf) in sessions.iter().zip(&live) {
                let addr = c.address.as_str();
                start_times
                    .entry(addr)
                    .and_modify(|t| *t = (*t).min(c.start_time))
                    .or_insert(c.start_time);
                if let Some(ts) = lf.as_ref().and_then(|lf| lf.updated_at_ms) {
                    last_seen_by_address
                        .entry(addr)
                        .and_modify(|t| *t = (*t).max(ts))
                        .or_insert(ts);
                }
            }

            let mut entries = Vec::with_capacity(members.len());
            for m in members {
                let addr_str = m.address.as_str();
                // Same policy as the kick-inactivity guard, so an active member
                // does not read "never mined" before the group's first block.
                let last_active = svc.member_last_active(id, &m.address).await;
                let email = bp_db::find_address_email(&s.pool, &m.address).await?;
                let email_out = match (is_admin, email.as_ref()) {
                    (true, Some(b)) => Some(crate::utils::mask_email(&b.email)),
                    _ => None,
                };
                // A verified email binding wins over a signature proof.
                let verified_via: Option<&'static str> = if is_admin {
                    if email.as_ref().and_then(|b| b.verified_at).is_some() {
                        Some("email")
                    } else if owned_signatures.contains(addr_str) {
                        Some("signature")
                    } else {
                        None
                    }
                } else {
                    None
                };
                let hashrate = per_addr_hashrate.get(addr_str).copied().unwrap_or(0.0);
                let start_time = start_times.get(addr_str).copied();
                let last_seen = last_seen_by_address.get(addr_str).copied().or(start_time);
                let best_difficulty = bp_db::find_address_settings(&s.pool, &m.address)
                    .await?
                    .map(|x| x.best_difficulty)
                    .unwrap_or(0.0);
                entries.push(MemberEntry {
                    member_id: member_id(id, addr_str),
                    address_label: labels
                        .get(addr_str)
                        .cloned()
                        .unwrap_or_else(|| bp_common::short_address(addr_str)),
                    address: is_admin.then(|| addr_str.to_string()),
                    is_self: viewer.as_deref() == Some(addr_str),
                    role: m.role,
                    joined_at: crate::time_range::format_iso_ms(m.joined_at),
                    hashrate,
                    best_difficulty,
                    start_time: start_time.map(crate::time_range::format_iso_ms),
                    last_seen: last_seen.map(crate::time_range::format_iso_ms),
                    last_accepted_share_at: last_active.map(crate::time_range::format_iso_ms),
                    email: email_out,
                    verified_via,
                });
            }
            let mut summary = GroupSummary::from(group);
            if !is_admin {
                // Pseudonymised like every member; the UI derives the creator
                // from the roster.
                summary.creator_address = None;
            }
            Ok(GroupDetailResponse {
                summary,
                total_hashrate,
                members: entries,
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

/// Degraded fallback in the shape `hashrate_by_address` returns.
fn zeroed(addrs: &[AddressId]) -> HashMap<String, f64> {
    addrs
        .iter()
        .map(|a| (a.as_str().to_string(), 0.0))
        .collect()
}

// ─── GET /api/groups/by-address/:address ─────────────────────────

async fn by_address(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let member = bp_db::find_group_member_by_address(&state.pool, &addr)
        .await?
        .ok_or(ApiError::NotFound)?;
    // The looked-up address is the viewer here.
    let viewer = Query(ViewerQuery {
        viewer: Some(addr.as_str().to_string()),
    });
    by_id(State(state), Path(member.group_id), viewer, headers).await
}

// ─── GET /api/pplns/groups/membership/:address ───────────────────

/// A cheap yes/no without the roster `by-address` computes. No status field:
/// a dissolve deletes the members, so a member's group is never dissolved.
#[derive(Serialize)]
#[serde(untagged)]
enum MembershipResponse {
    Member {
        #[serde(rename = "groupId")]
        group_id: Uuid,
        #[serde(rename = "groupName")]
        group_name: String,
        role: String,
    },
    None {
        // Always `None`, so the body is `{ "groupId": null }`.
        #[serde(rename = "groupId")]
        group_id: Option<Uuid>,
    },
}

async fn membership(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<MembershipResponse>, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let none = || Json(MembershipResponse::None { group_id: None });
    let Some(member) = bp_db::find_group_member_by_address(&state.pool, &addr).await? else {
        return Ok(none());
    };
    let Some(group) = require_group_service(&state)?
        .get_group(member.group_id)
        .await?
    else {
        return Ok(none());
    };
    Ok(Json(MembershipResponse::Member {
        group_id: group.id,
        group_name: group.name,
        role: member.role,
    }))
}

// ─── GET /api/pplns/groups/:id/admin-check ───────────────────────

/// 204 when `x-admin-token` is this group's admin token; 401 when missing or
/// wrong, 404 for an unknown or dissolved group. Nothing else is read.
async fn admin_check(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_group_service(&state)?
        .require_admin_token(id, admin_token(&headers))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── GET /api/groups/:id/hashrate ────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HashrateResponse {
    group_id: Uuid,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_hashrate: f64,
    members: Vec<MemberHashrate>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberHashrate {
    member_id: String,
    address_label: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    hashrate: f64,
}

async fn hashrate(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("GROUP_HASHRATE_{id}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<HashrateResponse, _, ApiError>(key, TtlKind::GroupHashrate, async move {
            let svc = require_group_service(&s)?;
            let _ = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
            let members = svc.list_members(id).await?;
            let addrs: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
            let per_addr = crate::error::or_degraded(
                bp_client_live::hashrate_by_address(s.redis.as_ref(), &addrs).await,
                || zeroed(&addrs),
            )?;
            let total_hashrate: f64 = per_addr.values().sum();
            let addr_strings: Vec<String> = addrs.iter().map(|a| a.as_str().to_string()).collect();
            let labels = build_member_labels(&addr_strings);
            Ok(HashrateResponse {
                group_id: id,
                total_hashrate,
                members: addrs
                    .into_iter()
                    .map(|a| MemberHashrate {
                        hashrate: per_addr.get(a.as_str()).copied().unwrap_or(0.0),
                        member_id: member_id(id, a.as_str()),
                        address_label: labels
                            .get(a.as_str())
                            .cloned()
                            .unwrap_or_else(|| bp_common::short_address(a.as_str())),
                    })
                    .collect(),
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/:id/distribution ────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DistributionResponse {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_shares: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_rejected: f64,
    per_address: Vec<DistributionEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DistributionEntry {
    member_id: String,
    address_label: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_shares: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_rejected: f64,
}

async fn distribution(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("GROUP_DISTRIBUTION_{id}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<DistributionResponse, _, ApiError>(
            key,
            TtlKind::GroupDistribution,
            async move {
                let engine = s
                    .group_solo
                    .as_deref()
                    .ok_or(ApiError::Unavailable("group-solo-engine not wired"))?;
                let stats = engine.reader().round_stats(id).await?;
                // Rejects come from the same round store, so both describe the
                // current round or window, not an all-time total.
                Ok(DistributionResponse {
                    total_shares: stats.per_address.values().sum(),
                    total_rejected: stats.total_rejected,
                    per_address: distribution_entries(
                        id,
                        stats.per_address,
                        stats.rejected_per_address,
                    ),
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

/// A reject-only address gets a zero-share row, so `total_rejected`
/// reconciles against the table.
fn distribution_entries(
    group_id: Uuid,
    per_address: HashMap<String, f64>,
    rejected_per_address: HashMap<String, f64>,
) -> Vec<DistributionEntry> {
    let total_shares: f64 = per_address.values().sum();
    let mut addresses: Vec<String> = per_address.keys().cloned().collect();
    addresses.extend(
        rejected_per_address
            .keys()
            .filter(|a| !per_address.contains_key(*a))
            .cloned(),
    );
    let labels = build_member_labels(&addresses);
    let mut entries: Vec<DistributionEntry> = addresses
        .into_iter()
        .map(|address| {
            let shares = per_address.get(&address).copied().unwrap_or(0.0);
            let percent = if total_shares > 0.0 {
                shares / total_shares * 100.0
            } else {
                0.0
            };
            DistributionEntry {
                member_id: member_id(group_id, &address),
                address_label: labels
                    .get(&address)
                    .cloned()
                    .unwrap_or_else(|| bp_common::short_address(&address)),
                total_shares: shares,
                percent,
                total_rejected: rejected_per_address.get(&address).copied().unwrap_or(0.0),
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        b.total_shares
            .partial_cmp(&a.total_shares)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    entries
}

// ─── GET /api/pplns/groups/:id/window-timeline ──────────────────
//
// Non-Window groups return an empty timeline, so the UI renders nothing.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowTimelineResponse {
    /// 0 for a non-Window group.
    window_days: i64,
    /// Biggest total first, for a stable stacking and colour order;
    /// pseudonymised.
    contributors: Vec<TimelineContributor>,
    /// Days with data only, oldest first.
    days: Vec<TimelineDay>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineContributor {
    member_id: String,
    address_label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineDay {
    /// Day start, UTC.
    date: String,
    /// Index-aligned to `contributors`.
    #[serde(serialize_with = "crate::time_range::ser_vec_f64_jsnum")]
    values: Vec<f64>,
}

/// Folds hour buckets into per-day sums; pure, so it tests without Redis.
fn build_window_timeline_response(
    group_id: Uuid,
    timeline: WindowTimeline,
) -> WindowTimelineResponse {
    // Mirrors `bp_group_solo_engine::round::WINDOW_BUCKET_MS` (1h buckets).
    const HOUR_MS: i64 = 60 * 60 * 1000;
    const DAY_MS: i64 = 24 * HOUR_MS;

    let mut per_day: BTreeMap<i64, HashMap<String, f64>> = BTreeMap::new();
    let mut totals: HashMap<String, f64> = HashMap::new();
    for (bucket_id, addr_map) in timeline.buckets {
        let day_start = (bucket_id * HOUR_MS).div_euclid(DAY_MS) * DAY_MS;
        let day = per_day.entry(day_start).or_default();
        for (addr, diff) in addr_map {
            *day.entry(addr.clone()).or_insert(0.0) += diff;
            *totals.entry(addr).or_insert(0.0) += diff;
        }
    }

    let mut addresses: Vec<String> = totals.keys().cloned().collect();
    addresses.sort_by(|a, b| {
        totals[b]
            .partial_cmp(&totals[a])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.cmp(b))
    });

    let days = per_day
        .into_iter()
        .map(|(day_start, addr_map)| TimelineDay {
            date: crate::time_range::format_iso_ms(day_start),
            values: addresses
                .iter()
                .map(|a| addr_map.get(a).copied().unwrap_or(0.0))
                .collect(),
        })
        .collect();

    let labels = build_member_labels(&addresses);
    let contributors = addresses
        .iter()
        .map(|a| TimelineContributor {
            member_id: member_id(group_id, a),
            address_label: labels
                .get(a)
                .cloned()
                .unwrap_or_else(|| bp_common::short_address(a)),
        })
        .collect();

    WindowTimelineResponse {
        window_days: timeline.window_ms / DAY_MS,
        contributors,
        days,
    }
}

async fn window_timeline(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("GROUP_WINDOW_TIMELINE_{id}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<WindowTimelineResponse, _, ApiError>(
            key,
            TtlKind::GroupDistribution,
            async move {
                let engine = s
                    .group_solo
                    .as_deref()
                    .ok_or(ApiError::Unavailable("group-solo-engine not wired"))?;
                let timeline = engine.reader().window_timeline(id).await?;
                Ok(build_window_timeline_response(id, timeline))
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/:id/best-difficulty ────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BestDifficultyResponse {
    best_difficulty: u64,
    /// Masked; the full address is never sent.
    address_label: Option<String>,
    /// `None` while the current round has no best yet.
    time: Option<String>,
}

async fn best_difficulty(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("GROUP_BEST_DIFFICULTY_{id}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<BestDifficultyResponse, _, ApiError>(
            key,
            TtlKind::GroupBestDifficulty,
            async move {
                let engine = s
                    .group_solo
                    .as_deref()
                    .ok_or(ApiError::Unavailable("group-solo-engine not wired"))?;
                // Zero shape, not 404, so the UI shows no error after a reset.
                let Some(best) = engine.reader().best_difficulty(id).await? else {
                    return Ok(BestDifficultyResponse {
                        best_difficulty: 0,
                        address_label: None,
                        time: None,
                    });
                };
                Ok(BestDifficultyResponse {
                    best_difficulty: best.difficulty.floor() as u64,
                    address_label: Some(bp_common::short_address(&best.address)),
                    time: Some(crate::time_range::format_iso_ms(best.timestamp_ms)),
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/:id/history ─────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    id: i32,
    group_id: Uuid,
    block_height: i32,
    created_at: String,
    /// Masked; the full address is never sent.
    address_label: String,
    paid_sats: i64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    shares_in_round: i64,
    total_shares_in_round: i64,
    row_type: String,
}

async fn history(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<HistoryQuery>,
) -> Result<JsonBytes, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let key = format!("GROUP_HISTORY_{id}_{limit}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<HistoryEntry>, _, ApiError>(key, TtlKind::GroupHistory, async move {
            let rows = bp_db::find_recent_group_block_history(&s.pool, id, limit).await?;
            Ok(rows
                .into_iter()
                .map(|h| HistoryEntry {
                    id: h.id,
                    group_id: h.group_id,
                    block_height: h.block_height,
                    created_at: crate::time_range::format_iso_ms(h.created_at),
                    address_label: bp_common::short_address(h.address.as_str()),
                    paid_sats: h.paid_sats.to_i64(),
                    percent: h.percent as f64,
                    shares_in_round: h.shares_in_round,
                    total_shares_in_round: h.total_shares_in_round,
                    row_type: h.row_type,
                })
                .collect())
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/:id/invitations/open/active (admin) ─────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenActiveResponse {
    active: bool,
    token: Option<String>,
    expires_at: Option<String>,
    created_at: Option<String>,
    approval_required: Option<bool>,
    link: Option<String>,
}

async fn open_invite_active(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError> {
    // Only the admin variant carries the token, so the cache key includes
    // `is_admin` to keep it from reaching a public viewer.
    let token = verified_admin_token(&state, id, &headers)
        .await?
        .map(str::to_string);
    let is_admin = token.is_some();
    let key = format!(
        "GROUP_OPEN_INVITE_ACTIVE_{id}_{}",
        if is_admin { "admin" } else { "pub" }
    );
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<OpenActiveResponse, _, ApiError>(
            key,
            TtlKind::GroupInvitations,
            async move {
                let inv_svc = require_invitation_service(&s)?;
                let active = inv_svc
                    .get_active_open_invite(id, token.as_deref())
                    .await
                    .map_err(crate::controllers::invitation::invitation_to_api_error)?;
                Ok(match active {
                    Some(a) => {
                        let link = s
                            .pool_base_url
                            .as_deref()
                            .map(|base| format!("{}/#/invite/open/{}", base, a.token));
                        OpenActiveResponse {
                            active: true,
                            link,
                            token: Some(a.token),
                            expires_at: Some(crate::time_range::format_iso_ms(a.expires_at)),
                            created_at: Some(crate::time_range::format_iso_ms(a.created_at)),
                            approval_required: Some(a.approval_required),
                        }
                    }
                    None => OpenActiveResponse {
                        active: false,
                        token: None,
                        expires_at: None,
                        created_at: None,
                        approval_required: None,
                        link: None,
                    },
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/:id/join-requests (admin) ───────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequestsQuery {
    #[serde(rename = "includeDecided")]
    include_decided: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequestEntry {
    id: Uuid,
    address: String,
    email: String,
    message: Option<String>,
    status: String,
    created_at: String,
    decided_at: Option<String>,
}

async fn list_join_requests(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<JoinRequestsQuery>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError> {
    let token = verified_admin_token(&state, id, &headers)
        .await?
        .map(str::to_string);
    let is_admin = token.is_some();
    let include_decided = q
        .include_decided
        .as_deref()
        .map(|s| s == "1" || s == "true")
        .unwrap_or(false);
    let key = format!(
        "GROUP_JOIN_REQUESTS_{id}_{}_{}",
        if is_admin { "admin" } else { "pub" },
        include_decided
    );
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<JoinRequestEntry>, _, ApiError>(
            key,
            TtlKind::GroupJoinRequests,
            async move {
                let svc = require_join_request_service(&s)?;
                let rows = svc
                    .list_for_group(id, token.as_deref(), include_decided)
                    .await
                    .map_err(jr_to_api_error)?;
                Ok(rows
                    .into_iter()
                    .map(|r| JoinRequestEntry {
                        id: r.id,
                        address: r.address.as_str().to_string(),
                        email: crate::utils::mask_email(&r.email),
                        message: r.message,
                        status: r.status,
                        created_at: crate::time_range::format_iso_ms(r.created_at),
                        decided_at: crate::time_range::format_iso_ms_opt(r.decided_at),
                    })
                    .collect())
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/groups/join-requests/by-address/:address ───────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddressJoinRequestEntry {
    group_id: Uuid,
    group_name: String,
    status: &'static str,
    created_at: String,
}

async fn join_requests_by_address(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("GROUP_JOIN_REQUESTS_BY_ADDR_{address}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<AddressJoinRequestEntry>, _, ApiError>(
            key,
            TtlKind::GroupJoinRequests,
            async move {
                let svc = require_join_request_service(&s)?;
                let entries = svc
                    .list_for_address(&address)
                    .await
                    .map_err(jr_to_api_error)?;
                Ok(entries
                    .into_iter()
                    .map(|e| AddressJoinRequestEntry {
                        group_id: e.group_id,
                        group_name: e.group_name,
                        status: "pending",
                        created_at: crate::time_range::format_iso_ms(e.created_at),
                    })
                    .collect())
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

fn jr_to_api_error(e: bp_group_mgmt_engine::JoinRequestServiceError) -> ApiError {
    use axum::http::StatusCode;
    use bp_group_mgmt_engine::JoinRequestServiceError as J;
    let code = e.code();
    let status = match e {
        J::NotFound => StatusCode::NOT_FOUND,
        J::AlreadyMember | J::AddressInGroup | J::RequestPending | J::GroupDissolved => {
            StatusCode::CONFLICT
        }
        J::EmailNotVerified | J::TooManyPending | J::RejectCooldown { .. } => StatusCode::FORBIDDEN,
        J::InvalidAddress => StatusCode::BAD_REQUEST,
        J::GroupService(g) => return ApiError::from(g),
        J::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ApiError::JoinRequest { code, status }
}

// ─── GET /api/groups/:id/chart + /accepted + /rejected ───────────
//
// Over the group's current members, on the per-address slot grid.

use crate::controllers::info::{
    client_reject_samples, rejected_by_reason_slots, RejectSlotsResponse,
};
use crate::time_range::{
    accepted_slot_data, chart_slot_boundaries, max_difficulty_slot_data, ChartPoint, Range,
    SlotDataResponse,
};

use crate::time_range::SLOT_SECONDS;
use bp_common::HASHES_PER_DIFFICULTY_1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRangeQuery {
    range: Option<String>,
}

async fn collect_group_member_addresses(
    state: &SharedState,
    id: Uuid,
) -> Result<Vec<AddressId>, ApiError> {
    let svc = require_group_service(state)?;
    let members = svc.list_members(id).await?;
    Ok(members.into_iter().map(|m| m.address).collect())
}

async fn group_chart(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_CHART_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::GroupChart, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let addrs = collect_group_member_addresses(&s, id).await?;
            // Sparse: only slots that received shares get a point.
            let mut slot_shares: std::collections::BTreeMap<i64, f64> =
                std::collections::BTreeMap::new();
            for a in &addrs {
                let rows =
                    bp_db::find_client_statistics_since_for_address(&s.pool, a, since).await?;
                for r in rows.iter().filter(|r| r.time < cutoff) {
                    *slot_shares.entry(r.time).or_insert(0.0) += r.shares as f64;
                }
            }
            Ok(slot_shares
                .into_iter()
                .map(|(t, shares)| ChartPoint {
                    label: crate::time_range::format_iso_ms(t),
                    data: (shares * HASHES_PER_DIFFICULTY_1 / SLOT_SECONDS).round(),
                })
                .collect())
        })
        .await?;
    Ok(JsonBytes(bytes))
}

async fn group_accepted(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_ACCEPTED_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::GroupAccepted, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let addrs = collect_group_member_addresses(&s, id).await?;
            let mut rows = Vec::new();
            for a in &addrs {
                rows.extend(
                    bp_db::find_client_statistics_since_for_address(&s.pool, a, since).await?,
                );
            }
            // Difficulty-weighted like the per-client endpoint, so it stays
            // flat at constant hashrate.
            Ok(accepted_slot_data(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.shares as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

async fn group_max_difficulty(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_MAX_DIFFICULTY_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::GroupAccepted, async move {
            let since = bp_common::now_ms() - range.window_ms();
            let addrs = collect_group_member_addresses(&s, id).await?;
            let rows =
                bp_db::find_max_difficulty_since_for_addresses(&s.pool, &addrs, since).await?;
            Ok(max_difficulty_slot_data(
                &chart_slot_boundaries(since),
                rows.into_iter().map(|(t, max)| (t, max as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

async fn group_rejected(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_REJECTED_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<RejectSlotsResponse, _, ApiError>(key, TtlKind::GroupRejected, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let addrs = collect_group_member_addresses(&s, id).await?;
            let mut rows = Vec::new();
            for a in &addrs {
                rows.extend(
                    bp_db::find_client_statistics_since_for_address(&s.pool, a, since).await?,
                );
            }
            Ok(rejected_by_reason_slots(
                &chart_slot_boundaries(since),
                rows.iter().flat_map(client_reject_samples),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

#[cfg(test)]
mod slot_json_tests {
    use super::*;

    const S: i64 = 600_000;
    const T0: i64 = 1_700_000_400_000;
    const BOUNDARIES: [i64; 3] = [T0, T0 + S, T0 + 2 * S];

    fn json<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    /// Members' rows add up per slot; a row at the visibility cutoff is dropped.
    #[test]
    fn group_accepted_json_is_unchanged() {
        let cutoff = T0 + 2 * S;
        let samples = vec![
            (T0, 1.5),
            (T0, 0.1_f32 as f64),
            (T0, 0.2_f32 as f64),
            (T0 + S, 2.0),
            (T0 + S + 123, 3.0),
            (T0 - S, 99.0),
            (cutoff, 5.0),
        ];
        assert_eq!(
            json(&accepted_slot_data(&BOUNDARIES[..2], samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"accepted":1.8000000044703484}},{"time":"2023-11-14T22:30:00.000Z","counts":{"accepted":5}}]}"#
        );
    }

    /// `/api/groups/:id/rejected` — same shape as the per-address endpoint.
    #[test]
    fn group_rejected_json_is_unchanged() {
        let samples = vec![
            (T0, ("job-not-found", 2.0, 0.25)),
            (T0, ("JobNotFound", 1.0, 1.5)),
            (T0, ("something-new", 3.0, 3.0)),
            (T0 + S + 7, ("Stale", 4.0, 0.1_f32 as f64)),
            (T0 + 3 * S, ("Stale", 50.0, 50.0)),
        ];
        assert_eq!(
            json(&rejected_by_reason_slots(&BOUNDARIES, samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"DuplicateShare":{"count":0,"diffMinusOne":0},"JobNotFound":{"count":3,"diffMinusOne":1.75},"LowDifficultyShare":{"count":0,"diffMinusOne":0},"NotSubscribed":{"count":0,"diffMinusOne":0},"OtherUnknown":{"count":3,"diffMinusOne":3},"Stale":{"count":0,"diffMinusOne":0},"UnauthorizedWorker":{"count":0,"diffMinusOne":0},"VersionRollingNotAllowed":{"count":0,"diffMinusOne":0}}},{"time":"2023-11-14T22:30:00.000Z","counts":{"DuplicateShare":{"count":0,"diffMinusOne":0},"JobNotFound":{"count":0,"diffMinusOne":0},"LowDifficultyShare":{"count":0,"diffMinusOne":0},"NotSubscribed":{"count":0,"diffMinusOne":0},"OtherUnknown":{"count":0,"diffMinusOne":0},"Stale":{"count":4,"diffMinusOne":0.10000000149011612},"UnauthorizedWorker":{"count":0,"diffMinusOne":0},"VersionRollingNotAllowed":{"count":0,"diffMinusOne":0}}},{"time":"2023-11-14T22:40:00.000Z","counts":{"DuplicateShare":{"count":0,"diffMinusOne":0},"JobNotFound":{"count":0,"diffMinusOne":0},"LowDifficultyShare":{"count":0,"diffMinusOne":0},"NotSubscribed":{"count":0,"diffMinusOne":0},"OtherUnknown":{"count":0,"diffMinusOne":0},"Stale":{"count":0,"diffMinusOne":0},"UnauthorizedWorker":{"count":0,"diffMinusOne":0},"VersionRollingNotAllowed":{"count":0,"diffMinusOne":0}}}]}"#
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use uuid::Uuid;

    fn parse_include_decided(s: Option<&str>) -> bool {
        s.map(|v| v == "1" || v == "true").unwrap_or(false)
    }

    /// Without `[group_solo]` no group can be created: its members would be
    /// routed to a mode this pool does not run.
    #[tokio::test]
    async fn creating_a_group_is_refused_while_group_solo_is_disabled() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1/unused")
            .expect("lazy pool");
        let state: SharedState = std::sync::Arc::new(crate::state::AppState::new(pool, "0.0.0"));
        assert!(
            state.group_solo.is_none(),
            "precondition: no Group-Solo engine"
        );
        let body = CreateGroupBody {
            name: "g".into(),
            creator_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            mode: None,
        };
        let Err(err) = create(State(state), Json(body)).await else {
            panic!("a group was created while Group-Solo is disabled");
        };
        assert!(
            matches!(err, ApiError::Unavailable("group-solo is disabled")),
            "got {err:?}"
        );
    }

    /// Every group-scoped cache key is dropped by a group mutation; a key
    /// left out serves the pre-change body until its TTL.
    #[tokio::test]
    async fn a_group_mutation_drops_every_group_scoped_cache_key() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1/unused")
            .expect("lazy pool");
        let state: SharedState = std::sync::Arc::new(crate::state::AppState::new(pool, "0.0.0"));
        let id = Uuid::new_v4();
        let keys: Vec<String> = [
            "GROUP_PUBLIC_DETAIL_",
            "GROUP_DETAIL_",
            "GROUP_HASHRATE_",
            "GROUP_CHART_",
            "GROUP_ACCEPTED_",
            "GROUP_REJECTED_",
            "GROUP_DISTRIBUTION_",
            "GROUP_BEST_DIFFICULTY_",
            "GROUP_HISTORY_",
            "GROUP_INVITATIONS_",
            "GROUP_JOIN_REQUESTS_",
            "GROUP_OPEN_INVITE_ACTIVE_",
            "GROUP_WINDOW_TIMELINE_",
        ]
        .iter()
        .map(|p| format!("{p}{id}"))
        .chain([format!("GROUP_MAX_DIFFICULTY_{id}_24h")])
        .collect();
        let cached = |key: String, v: u8| {
            let state = state.clone();
            async move {
                state
                    .cache
                    .get_or_fetch_secs(key, 600, async move { Ok::<_, ()>(v) })
                    .await
                    .unwrap()
            }
        };
        for key in &keys {
            cached(key.clone(), 1).await;
        }

        invalidate_group_cache(&state, id).await;

        for key in &keys {
            assert_eq!(&cached(key.clone(), 2).await[..], b"2", "{key} survived");
        }
    }

    /// An unknown `finderBonusSats` key is refused, not a silent no-op.
    #[test]
    fn settings_patch_refuses_the_retired_finder_bonus_sats() {
        let old_ui = r#"{"finderBonusSats": 50000000}"#;
        assert!(
            serde_json::from_str::<UpdateSettingsBody>(old_ui).is_err(),
            "a bonus write in the retired unit must fail loudly, not report success"
        );
    }

    /// Every body shape the UI sends, full and partial, still deserializes
    /// under `deny_unknown_fields`.
    #[test]
    fn settings_patch_accepts_every_shape_the_ui_sends() {
        for body in [
            r#"{"preset":"daily","intervalDays":null,"timezone":"Europe/Zurich",
                "finderBonusPpm":32000,"resetRoundOnBlock":true}"#,
            r#"{"maxMembers":25}"#,
            r#"{"isPublic":true}"#,
            r#"{"finderBonusPpm":null}"#,
            r#"{}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateSettingsBody>(body).is_ok(),
                "current-UI payload must still parse: {body}"
            );
        }
    }

    #[test]
    fn include_decided_accepts_one_and_true() {
        assert!(parse_include_decided(Some("1")));
        assert!(parse_include_decided(Some("true")));
    }

    #[test]
    fn include_decided_rejects_other_values() {
        assert!(!parse_include_decided(Some("false")));
        assert!(!parse_include_decided(Some("yes")));
        assert!(!parse_include_decided(None));
    }

    #[test]
    fn block_subsidy_follows_halving_schedule() {
        use bitcoin::Network;
        // Mainnet: 50 BTC pre-halving, 25 after 210_000, 6.25 after 630_000.
        assert_eq!(block_subsidy_sats(1, Network::Bitcoin), 50 * 100_000_000);
        assert_eq!(
            block_subsidy_sats(210_000, Network::Bitcoin),
            25 * 100_000_000
        );
        assert_eq!(
            block_subsidy_sats(630_000, Network::Bitcoin),
            625_000_000 // 6.25 BTC
        );
        // Regtest halves every 150 blocks: 50 → 25 at height 150.
        assert_eq!(block_subsidy_sats(149, Network::Regtest), 50 * 100_000_000);
        assert_eq!(block_subsidy_sats(150, Network::Regtest), 25 * 100_000_000);
        // Past 64 halvings the subsidy is 0 (no underflow/panic).
        assert_eq!(block_subsidy_sats(64 * 210_000, Network::Bitcoin), 0);
    }

    #[test]
    fn window_timeline_folds_hours_into_days_and_sorts_by_total() {
        const HOUR_MS: i64 = 60 * 60 * 1000;
        const DAY_MS: i64 = 24 * HOUR_MS;
        let a = "bc1qaaa".to_string();
        let b = "bc1qbbb".to_string();
        // Buckets 100 and 101 fall in day 4, bucket 130 in day 5.
        let timeline = WindowTimeline {
            window_ms: 30 * DAY_MS,
            buckets: vec![
                (100, HashMap::from([(a.clone(), 10.0), (b.clone(), 5.0)])),
                (101, HashMap::from([(a.clone(), 20.0)])),
                (130, HashMap::from([(a.clone(), 7.0), (b.clone(), 3.0)])),
            ],
        };
        let resp = build_window_timeline_response(Uuid::nil(), timeline);

        assert_eq!(resp.window_days, 30);
        // A (37) before B (8); short addresses are below the mask threshold.
        let labels: Vec<&str> = resp
            .contributors
            .iter()
            .map(|c| c.address_label.as_str())
            .collect();
        assert_eq!(labels, vec![a.as_str(), b.as_str()]);
        assert!(
            resp.contributors.iter().all(|c| !c.member_id.is_empty()),
            "every contributor gets an opaque memberId"
        );
        assert_eq!(resp.days.len(), 2, "two distinct calendar-day buckets");
        assert_eq!(resp.days[0].values, vec![30.0, 5.0]);
        assert_eq!(resp.days[1].values, vec![7.0, 3.0]);
        assert_eq!(
            resp.days[0].date,
            crate::time_range::format_iso_ms(4 * DAY_MS)
        );
        assert_eq!(
            resp.days[1].date,
            crate::time_range::format_iso_ms(5 * DAY_MS)
        );
    }

    #[test]
    fn window_timeline_empty_for_non_window_group() {
        let resp = build_window_timeline_response(
            Uuid::nil(),
            WindowTimeline {
                window_ms: 0,
                buckets: vec![],
            },
        );
        assert_eq!(resp.window_days, 0);
        assert!(resp.contributors.is_empty());
        assert!(resp.days.is_empty());
    }

    #[test]
    fn create_join_request_response_created_at_is_string() {
        let r = CreateJoinRequestResponse {
            id: Uuid::nil(),
            group_id: Uuid::nil(),
            status: "pending".into(),
            created_at: "2024-01-01T00:00:00.000Z".into(),
        };
        let v: Value = serde_json::to_value(&r).unwrap();
        assert!(v["createdAt"].is_string(), "createdAt must be a string");
    }

    #[test]
    fn address_join_request_created_at_is_string() {
        let e = AddressJoinRequestEntry {
            group_id: Uuid::nil(),
            group_name: "test".into(),
            status: "pending",
            created_at: "2024-01-01T00:00:00.000Z".into(),
        };
        let v: Value = serde_json::to_value(&e).unwrap();
        assert!(v["createdAt"].is_string(), "createdAt must be a string");
    }

    #[test]
    fn create_group_response_includes_members() {
        let g = GroupSummary {
            id: Uuid::nil(),
            name: "g".into(),
            creator_address: Some("bc1q".into()),
            active: false,
            created_at: "2024-01-01T00:00:00.000Z".into(),
            round_reset_preset: None,
            round_reset_interval_days: None,
            round_reset_timezone: None,
            finder_bonus_ppm: 0,
            last_round_reset_at: None,
            next_reset_at: None,
            is_public: false,
            reset_round_on_block: false,
            max_members: None,
            mode: "prop".into(),
        };
        let r = CreateGroupResponse {
            summary: g,
            admin_token: "tok".into(),
            members: vec![InitialMember {
                address: "bc1q".into(),
                role: "creator",
            }],
        };
        let v: Value = serde_json::to_value(&r).unwrap();
        assert!(v["members"].is_array(), "members must be present");
        let members = v["members"].as_array().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0]["role"], "creator");
    }

    #[test]
    fn public_group_entry_omits_creator_address() {
        let mut summary = GroupSummary {
            id: Uuid::nil(),
            name: "g".into(),
            creator_address: Some("bc1qcreator".into()),
            active: true,
            created_at: "2024-01-01T00:00:00.000Z".into(),
            round_reset_preset: None,
            round_reset_interval_days: None,
            round_reset_timezone: None,
            finder_bonus_ppm: 0,
            last_round_reset_at: None,
            next_reset_at: None,
            is_public: true,
            reset_round_on_block: false,
            max_members: None,
            mode: "prop".into(),
        };
        let authed: Value = serde_json::to_value(&summary).unwrap();
        assert_eq!(authed["creatorAddress"], "bc1qcreator");

        summary.creator_address = None;
        let entry = PublicGroupEntry {
            summary,
            member_count: 3,
            total_hashrate: 1.5,
        };
        let v: Value = serde_json::to_value(&entry).unwrap();
        assert!(
            v.get("creatorAddress").is_none(),
            "public group entry must not expose creatorAddress, got: {v}"
        );
        assert_eq!(v["name"], "g");
        assert_eq!(v["memberCount"], 3);
        assert_eq!(v["isPublic"], true);
    }

    #[test]
    fn distribution_entries_keep_a_reject_only_member_as_a_zero_share_row() {
        let gid = Uuid::nil();
        let per_address = HashMap::from([("bc1qAAAAAAAAA11111".to_string(), 75.0)]);
        let rejected = HashMap::from([
            ("bc1qAAAAAAAAA11111".to_string(), 5.0),
            ("bc1qBBBBBBBBB22222".to_string(), 9.0),
        ]);
        let rows = distribution_entries(gid, per_address, rejected);
        assert_eq!(rows.len(), 2, "the reject-only address gets a row");
        assert_eq!(rows[0].member_id, member_id(gid, "bc1qAAAAAAAAA11111"));
        assert_eq!(rows[0].total_shares, 75.0);
        assert_eq!(rows[0].percent, 100.0);
        assert_eq!(rows[0].total_rejected, 5.0);
        assert_eq!(rows[1].member_id, member_id(gid, "bc1qBBBBBBBBB22222"));
        assert_eq!(rows[1].total_shares, 0.0);
        assert_eq!(rows[1].percent, 0.0);
        assert_eq!(rows[1].total_rejected, 9.0);
        let rejected_sum: f64 = rows.iter().map(|r| r.total_rejected).sum();
        assert_eq!(rejected_sum, 14.0);
    }

    #[test]
    fn member_entry_hides_full_address_from_non_admin() {
        let e = MemberEntry {
            member_id: "abc123".into(),
            address_label: "bc1q...12345".into(),
            address: None, // non-admin / anonymous
            is_self: false,
            role: "member".into(),
            joined_at: "2024-01-01T00:00:00.000Z".into(),
            hashrate: 0.0,
            best_difficulty: 0.0,
            start_time: None,
            last_seen: None,
            last_accepted_share_at: None,
            email: None,
            verified_via: None,
        };
        let v: Value = serde_json::to_value(&e).unwrap();
        assert!(
            v.get("address").is_none(),
            "a non-admin caller must not receive the full address, got: {v}"
        );
        assert_eq!(v["memberId"], "abc123");
        assert_eq!(v["addressLabel"], "bc1q...12345");

        let admin = MemberEntry {
            address: Some("bc1qfulladdr".into()),
            ..e
        };
        let av: Value = serde_json::to_value(&admin).unwrap();
        assert_eq!(av["address"], "bc1qfulladdr");
    }

    #[test]
    fn group_detail_hides_creator_address_from_non_admin() {
        fn summary(creator: Option<String>) -> GroupSummary {
            GroupSummary {
                id: Uuid::nil(),
                name: "g".into(),
                creator_address: creator,
                active: true,
                created_at: "2024-01-01T00:00:00.000Z".into(),
                round_reset_preset: None,
                round_reset_interval_days: None,
                round_reset_timezone: None,
                finder_bonus_ppm: 0,
                last_round_reset_at: None,
                next_reset_at: None,
                is_public: true,
                reset_round_on_block: false,
                max_members: None,
                mode: "prop".into(),
            }
        }
        let non_admin = GroupDetailResponse {
            summary: summary(None),
            total_hashrate: 0.0,
            members: vec![],
        };
        let v: Value = serde_json::to_value(&non_admin).unwrap();
        assert!(
            v.get("creatorAddress").is_none(),
            "a non-admin by_id caller must not receive creatorAddress, got: {v}"
        );

        let admin = GroupDetailResponse {
            summary: summary(Some("bc1qcreator".into())),
            total_hashrate: 0.0,
            members: vec![],
        };
        let av: Value = serde_json::to_value(&admin).unwrap();
        assert_eq!(av["creatorAddress"], "bc1qcreator");
    }
}
