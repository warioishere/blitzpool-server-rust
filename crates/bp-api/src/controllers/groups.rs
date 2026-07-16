// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/pplns/groups/*` — group reader + writer endpoints.
//!
//! **Prefix note**: routes are mounted at `/api/pplns/groups/*`. UI
//! fetch URLs must match.
//!
//! **Admin-token auth**: the 12 routes that always require an admin
//! token sit behind a single
//! [`crate::middleware::admin_auth::require_admin`] tower middleware,
//! applied via `route_layer` on a dedicated sub-router. Handlers pull
//! the validated `AdminAuth` out of request extensions and pass the
//! token through to the service layer; the service-level
//! `require_admin_token` call becomes defence-in-depth.
//!
//! The three handlers where the token is *optional* (`by_id`,
//! `open_invite_active`, `list_join_requests` — token influences
//! response shape rather than gating access) keep the inline
//! `admin_token(&headers)` plus a per-handler conditional check.

use std::collections::{BTreeMap, HashMap};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, patch, post},
    Extension, Router,
};
use bp_common::{AddressId, Sats};
use bp_db::PatchField;
use bp_group_mgmt::group::{PayoutMode, RoundResetPreset};
use bp_group_mgmt_engine::{
    EmailHooks, GroupService, GroupServiceHooks, OpenInviteTtl, UpdateRoundResetSettings,
};
use bp_group_solo_engine::reader::WindowTimeline;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::admin_auth::{require_admin, AdminAuth};
use crate::middleware::rate_limit;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::SharedState;

pub(crate) fn routes<H, M>(state: SharedState<H, M>) -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Sub-router for routes that always require a valid `x-admin-token`
    // header. `route_layer` applies the middleware only to currently-
    // registered routes (no late routes will be added to this sub-
    // router after the layer call), so this is the canonical pattern
    // for per-route auth in axum 0.7.
    let admin_routes = Router::new()
        // ─── admin writers ───────────────────────────────────────
        .route("/api/pplns/groups/:id/transfer", post(transfer::<H, M>))
        .route(
            "/api/pplns/groups/:id/settings",
            patch(update_settings::<H, M>),
        )
        .route("/api/pplns/groups/:id", delete(dissolve::<H, M>))
        .route(
            // POST is rate-limited (5/min); DELETE sibling shares the path
            // but is added without the layer.
            "/api/pplns/groups/:id/invitations/open",
            post(create_open_invite::<H, M>)
                .layer(rate_limit::per_minute_layer(5))
                .delete(revoke_open_invite::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/members/:address",
            delete(remove_member::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/join-requests/:req_id/approve",
            post(approve_join_request::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/join-requests/:req_id/reject",
            post(reject_join_request::<H, M>),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            require_admin::<H, M>,
        ));

    let public_routes = Router::new()
        .route("/api/pplns/groups/public", get(list_public::<H, M>))
        .route(
            "/api/pplns/groups/finder-bonus-cap",
            get(finder_bonus_cap::<H, M>),
        )
        .route(
            "/api/pplns/groups/coinbase-capacity",
            get(coinbase_capacity::<H, M>),
        )
        .route(
            "/api/pplns/groups/join-requests/by-address/:address",
            get(join_requests_by_address::<H, M>),
        )
        .route("/api/pplns/groups/public/:id", get(public_one::<H, M>))
        .route(
            "/api/pplns/groups/by-address/:address",
            get(by_address::<H, M>),
        )
        .route("/api/pplns/groups/:id/hashrate", get(hashrate::<H, M>))
        .route("/api/pplns/groups/:id/chart", get(group_chart::<H, M>))
        .route(
            "/api/pplns/groups/:id/accepted",
            get(group_accepted::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/rejected",
            get(group_rejected::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/distribution",
            get(distribution::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/window-timeline",
            get(window_timeline::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/best-difficulty",
            get(best_difficulty::<H, M>),
        )
        .route("/api/pplns/groups/:id/history", get(history::<H, M>))
        .route(
            "/api/pplns/groups/:id/invitations/open/active",
            get(open_invite_active::<H, M>),
        )
        .route(
            "/api/pplns/groups/:id/join-requests",
            get(list_join_requests::<H, M>),
        )
        .route("/api/pplns/groups", post(create::<H, M>))
        .route(
            "/api/pplns/groups/public/:id/join-request",
            post(create_join_request::<H, M>).layer(rate_limit::per_minute_layer(10)),
        )
        // NB: this must come LAST so the more specific paths above
        // (`/public`, `/by-address/:addr`, `/join-requests/...`) win
        // the route-match.
        .route("/api/pplns/groups/:id", get(by_id::<H, M>));

    admin_routes.merge(public_routes)
}

// ─── cache invalidation helpers ──────────────────────────────────

/// Drop every cached `/api/groups/*` entry whose key references
/// `id` or the list / public-list pages. Called by every mutating
/// endpoint so the next read sees fresh data without waiting for
/// the TTL to roll.
async fn invalidate_group_cache<H, M>(state: &SharedState<H, M>, id: Uuid)
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
        "GROUP_HISTORY_",
        "GROUP_INVITATIONS_",
        "GROUP_JOIN_REQUESTS_",
        "GROUP_OPEN_INVITE_ACTIVE_",
    ] {
        let full = format!("{prefix}{id_str}");
        state.cache.invalidate_prefix(&full).await;
    }
    // The round-reset cadence doubles as the Window payout length; drop the
    // engine's per-share mode cache so an edit takes effect immediately instead
    // of letting the record-path trim run on the stale (possibly smaller)
    // window length for up to its TTL.
    if let Some(engine) = state.group_solo.as_ref() {
        engine.invalidate_mode_cache(id);
    }
}

/// Drop the address-keyed group entries for the supplied address.
/// Used when membership changes (transfer / remove_member / approve
/// join-request) so `GET /api/groups/by-address/:addr` and
/// `.../join-requests/by-address/:addr` re-resolve immediately.
async fn invalidate_address_group_cache<H, M>(state: &SharedState<H, M>, address: &AddressId)
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let key = format!("GROUP_BY_ADDRESS_{}", address.as_str());
    state.cache.invalidate_prefix(&key).await;
    let jr = format!("GROUP_JOIN_REQUESTS_BY_ADDR_{}", address.as_str());
    state.cache.invalidate(&jr).await;
}

// ─── writer DTOs + handlers ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupBody {
    name: String,
    creator_address: String,
    /// Payout mode, chosen once at creation and immutable thereafter:
    /// `"prop"` (default) or `"window"`. Absent ⇒ `"prop"`.
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
    /// Plaintext admin token — shown to the creator exactly once. The
    /// hash is stored on the group row; this string never goes back
    /// across the wire after the initial response.
    admin_token: String,
    members: Vec<InitialMember>,
}

async fn create<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<CreateGroupBody>,
) -> Result<(StatusCode, Json<CreateGroupResponse>), ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_group_service(&state)?;
    // Mode is immutable (no edit path) — validate it up front. Absent ⇒ prop.
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

async fn transfer<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<TransferBody>,
) -> Result<Json<TransferResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UpdateSettingsBody {
    /// `Some(value)` → set to value, `Some("clear")` interpreted via the
    /// patch helper. We just default to Untouched/Set semantics; clear
    /// is signalled by `null` (JSON null = clear).
    #[serde(default)]
    preset: Option<Option<String>>,
    #[serde(default)]
    interval_days: Option<Option<u32>>,
    #[serde(default)]
    timezone: Option<Option<String>>,
    #[serde(default)]
    finder_bonus_sats: Option<Option<i64>>,
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

async fn update_settings<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<UpdateSettingsBody>,
) -> Result<Json<GroupSummary>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_group_service(&state)?;
    // Set-time guard: a finder bonus above the current block subsidy is almost
    // certainly a mistake (e.g. 2 BTC when the subsidy is 3.125 and a halving
    // is near). The coinbase builder already clamps the bonus to the real
    // reward, so this never breaks a payout — it's an early, clear rejection.
    // Skipped when no bitcoin RPC is wired (the cap can't be determined).
    if let Some(Some(bonus)) = body.finder_bonus_sats {
        if bonus > 0 {
            if let Some(cap) = current_subsidy_ceiling_sats(&state).await {
                if bonus as u64 > cap {
                    return Err(ApiError::GroupService {
                        code: "finder-bonus-exceeds-subsidy",
                        status: StatusCode::BAD_REQUEST,
                    });
                }
            }
        }
    }
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
        finder_bonus_sats: lift_patch(&body.finder_bonus_sats, |s| Sats(*s)),
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

/// Block subsidy in sats for `height` on `network`, per the standard halving
/// schedule (regtest halves every 150 blocks, every other network every
/// 210_000). Fee-independent — the pure coinbase subsidy. Shared with the
/// next-block-reward endpoint (info.rs) to split coinbasevalue into
/// subsidy + fees.
pub(crate) fn block_subsidy_sats(height: u64, network: bitcoin::Network) -> u64 {
    let interval: u64 = match network {
        bitcoin::Network::Regtest => 150,
        _ => 210_000,
    };
    let halvings = height / interval;
    if halvings >= 64 {
        return 0;
    }
    (50u64 * 100_000_000) >> halvings
}

/// Current finder-bonus ceiling: the subsidy of the next block (chain tip + 1).
/// `None` when no bitcoin RPC is wired or the height read fails — the caller
/// then skips the set-time check (the coinbase builder still clamps the bonus).
async fn current_subsidy_ceiling_sats<H, M>(state: &SharedState<H, M>) -> Option<u64>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let rpc = state.bitcoin_rpc.as_ref()?;
    let tip = rpc.get_block_count().await.ok()?;
    Some(block_subsidy_sats(tip + 1, state.network))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinderBonusCap {
    /// Next-block height the subsidy is computed for.
    height: u64,
    /// Max sensible finder bonus = current block subsidy, in sats. The UI
    /// surfaces this as the input ceiling + hint.
    subsidy_sats: u64,
}

/// `GET /api/pplns/groups/finder-bonus-cap` — the current block subsidy, so the
/// admin UI can cap the finder-bonus input + show the limit.
async fn finder_bonus_cap<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<FinderBonusCap>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let rpc = state
        .bitcoin_rpc
        .as_ref()
        .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
    let height = rpc.get_block_count().await? + 1;
    Ok(Json(FinderBonusCap {
        height,
        subsidy_sats: block_subsidy_sats(height, state.network),
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupCoinbaseCapacity {
    /// Worst-case max members that fit in the group-solo coinbase weight
    /// budget. Pessimistic: assumes every output is the heaviest standard
    /// type (P2TR, 172 WU) and reserves the pool-fee output slot — real
    /// P2WPKH-heavy groups fit more. The UI shows a group's member count
    /// against this ceiling.
    max_members: u64,
    /// The fixed group-solo coinbase weight budget (WU) the ceiling derives
    /// from. Engine-wide, identical for every group.
    weight_budget: u32,
    /// Whether a pool fee output is reserved (it consumes one member slot).
    has_fee_output: bool,
}

/// `GET /api/pplns/groups/coinbase-capacity` — how many members fit in the
/// fixed group-solo coinbase weight budget. Global (the budget is engine-wide,
/// not per group), so the UI subtracts a group's own member count to show the
/// remaining headroom. Uses the shared, fee-output-correct
/// [`max_coinbase_outputs`](bp_pplns_engine::max_coinbase_outputs) so this
/// matches the operator capacity-alert ceiling exactly.
async fn coinbase_capacity<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<GroupCoinbaseCapacity>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let engine = state
        .group_solo
        .as_ref()
        .ok_or(ApiError::Unavailable("group-solo not wired"))?;
    let cfg = engine.config();
    let has_fee_output = cfg.fee_address.is_some() && cfg.fee_percent > 0.0;
    Ok(Json(GroupCoinbaseCapacity {
        max_members: bp_pplns_engine::max_coinbase_outputs(
            cfg.coinbase_weight_budget,
            has_fee_output,
        ),
        weight_budget: cfg.coinbase_weight_budget,
        has_fee_output,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DissolveResponse {
    dissolved: bool,
}

async fn dissolve<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<DissolveResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn create_open_invite<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
    Json(body): Json<CreateOpenInviteBody>,
) -> Result<(StatusCode, Json<CreateOpenInviteResponse>), ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn revoke_open_invite<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<OpenInviteRevokedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn remove_member<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, address)): Path<(Uuid, String)>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<RemovedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn approve_join_request<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, req_id)): Path<(Uuid, Uuid)>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<ApprovedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let jr_svc = require_join_request_service(&state)?;
    jr_svc
        .approve_request(id, req_id, Some(&auth.admin_token))
        .await
        .map_err(jr_to_api_error)?;
    invalidate_group_cache(&state, id).await;
    // Approver doesn't know the requester's address — broad-invalidate
    // any address-keyed join-request entries.
    state
        .cache
        .invalidate_prefix("GROUP_JOIN_REQUESTS_BY_ADDR_")
        .await;
    state.cache.invalidate_prefix("GROUP_BY_ADDRESS_").await;
    Ok(Json(ApprovedResponse { approved: true }))
}

async fn reject_join_request<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, req_id)): Path<(Uuid, Uuid)>,
    Extension(auth): Extension<AdminAuth>,
) -> Result<Json<RejectedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn create_join_request<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateJoinRequestBody>,
) -> Result<(StatusCode, Json<CreateJoinRequestResponse>), ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

fn require_group_service<H, M>(state: &SharedState<H, M>) -> Result<&GroupService<H>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    state
        .group_service
        .as_deref()
        .ok_or(ApiError::Unavailable("group-service not wired"))
}

fn require_invitation_service<H, M>(
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

fn require_join_request_service<H, M>(
    state: &SharedState<H, M>,
) -> Result<&bp_group_mgmt_engine::JoinRequestService<H, M>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    state
        .join_request_service
        .as_deref()
        .ok_or(ApiError::Unavailable("join-request-service not wired"))
}

/// Pluck the admin token from the `x-admin-token` header. Returns
/// `None` if absent — callers decide whether that's fatal (admin-only
/// endpoints) or just affects response shape (group lookups where
/// admins see unmasked emails).
fn admin_token(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-admin-token").and_then(|v| v.to_str().ok())
}

// ─── DTOs ────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupSummary {
    id: Uuid,
    name: String,
    /// The creator's payout address. Present on authenticated/address-scoped
    /// views (drives the "created by" line + the isCreator/admin gate), but
    /// nulled on the public directory shapes (`list_public` / `public_one`) so
    /// the creator's on-chain address is never exposed to anonymous viewers.
    #[serde(skip_serializing_if = "Option::is_none")]
    creator_address: Option<String>,
    active: bool,
    /// ISO-8601 (`Date.toISOString()` shape).
    created_at: String,
    round_reset_preset: Option<String>,
    round_reset_interval_days: Option<i32>,
    round_reset_timezone: Option<String>,
    finder_bonus_sats: i64,
    last_round_reset_at: Option<String>,
    /// Computed next-reset wall-clock (ISO), derived from the preset +
    /// timezone + interval by [`compute_next_reset_at`]. `None` when the
    /// group has no preset / no timezone (UI tiles then render a neutral
    /// "no schedule" state).
    next_reset_at: Option<String>,
    is_public: bool,
    reset_round_on_block: bool,
    /// Hard member cap; null = no limit. UI shows `current/max` when set.
    max_members: Option<i64>,
    /// Payout mode — `"prop"` or `"window"`. Immutable; the UI shows it
    /// read-only in the edit form and offers it only at creation.
    mode: String,
}

impl From<bp_db::PplnsGroupRow> for GroupSummary {
    fn from(r: bp_db::PplnsGroupRow) -> Self {
        // Window-mode groups never calendar-reset — the reset preset is the
        // sliding-window LENGTH, not a wipe. Don't advertise a phantom
        // `nextResetAt` (it made the UI show a countdown to a reset that never
        // fires); the UI renders the window length instead.
        let next_reset_at = if PayoutMode::parse_or_default(&r.payout_mode) == PayoutMode::Window {
            None
        } else {
            compute_next_reset_at(
                r.round_reset_preset.as_deref(),
                r.round_reset_timezone.as_deref(),
                r.round_reset_interval_days,
                r.last_round_reset_at,
            )
            .map(crate::time_range::format_slot_label)
        };
        Self {
            id: r.id,
            name: r.name,
            creator_address: Some(r.creator_address.as_str().to_string()),
            active: r.active,
            created_at: crate::time_range::format_slot_label(r.created_at),
            round_reset_preset: r.round_reset_preset,
            round_reset_interval_days: r.round_reset_interval_days,
            round_reset_timezone: r.round_reset_timezone,
            finder_bonus_sats: r.finder_bonus_sats.map(|s| s.to_i64()).unwrap_or(0),
            last_round_reset_at: r
                .last_round_reset_at
                .map(crate::time_range::format_slot_label),
            next_reset_at,
            is_public: r.is_public,
            reset_round_on_block: r.reset_round_on_block,
            max_members: r.max_members.map(|v| v as i64),
            mode: r.payout_mode,
        }
    }
}

/// Compute the next round-reset wall-clock as epoch milliseconds.
/// Returns `None` when the group has no preset, no timezone, the
/// timezone string fails to parse against the IANA database, or the
/// custom preset is missing `interval_days`.
fn compute_next_reset_at(
    preset: Option<&str>,
    timezone: Option<&str>,
    interval_days: Option<i32>,
    last_reset_at: Option<i64>,
) -> Option<i64> {
    use chrono::{Datelike, Duration, NaiveDate, TimeZone, Timelike, Utc, Weekday};
    use chrono_tz::Tz;

    let preset = preset?;
    let tz: Tz = timezone?.parse().ok()?;
    let now_utc = Utc::now();
    let now_local = now_utc.with_timezone(&tz);

    let next_midnight = |date: NaiveDate| -> Option<i64> {
        let naive = date.and_hms_opt(0, 0, 0)?;
        tz.from_local_datetime(&naive)
            .single()
            .map(|dt| dt.with_timezone(&Utc).timestamp_millis())
    };

    match preset {
        "daily" => next_midnight(now_local.date_naive() + Duration::days(1)),
        "weekly" => {
            let mut date = now_local.date_naive() + Duration::days(1);
            while date.weekday() != Weekday::Mon {
                date += Duration::days(1);
            }
            next_midnight(date)
        }
        "monthly" => {
            let (y, m) = if now_local.month() == 12 {
                (now_local.year() + 1, 1)
            } else {
                (now_local.year(), now_local.month() + 1)
            };
            let date = NaiveDate::from_ymd_opt(y, m, 1)?;
            next_midnight(date)
        }
        "custom" => {
            let days = interval_days?;
            if days < 1 {
                return None;
            }
            let interval_ms = (days as i64) * 86_400_000;
            // 4h DST tolerance — matches the gate inside the fireIfDue
            // path so the displayed and actual fire times agree.
            const DST_TOLERANCE_MS: i64 = 4 * 3_600_000;
            let earliest_ms = match last_reset_at {
                Some(last) => last + interval_ms - DST_TOLERANCE_MS,
                None => now_utc.timestamp_millis(),
            };
            let earliest_local = Utc
                .timestamp_millis_opt(earliest_ms)
                .single()?
                .with_timezone(&tz);
            let mut date = earliest_local.date_naive();
            if earliest_local.hour() > 0
                || earliest_local.minute() > 0
                || earliest_local.second() > 0
            {
                date += Duration::days(1);
            }
            next_midnight(date)
        }
        _ => None,
    }
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

async fn list_public<H, M>(
    State(state): State<SharedState<H, M>>,
    Query(q): Query<PublicListQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
                let mut items = Vec::with_capacity(slice.len());
                for g in slice {
                    let members = svc.list_members(g.id).await?;
                    let addrs: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
                    let total_hashrate = bp_db::sum_hashrate_for_addresses(&s.pool, &addrs).await?;
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
    /// ISO-8601.
    created_at: String,
    /// Masked payout address (never the full address).
    address_label: String,
    paid_sats: i64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    shares_in_round: i64,
    total_shares_in_round: i64,
    row_type: String,
}

async fn public_one<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
                let total_hashrate = bp_db::sum_hashrate_for_addresses(&s.pool, &addrs).await?;
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
                            created_at: crate::time_range::format_slot_label(h.created_at),
                            address_label: mask_address_tail(h.address.as_str(), 5),
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

// ─── member pseudonymisation ─────────────────────────────────────
//
// The group-detail endpoints are anonymous (a group id alone opens them), so
// they must never hand out a member's full payout address — the id would then
// be a scraper key for every member's on-chain address. Instead each member is
// exposed as an opaque `memberId` (the stable join key the UI uses across the
// detail endpoints) plus a masked `addressLabel` for display. The full address
// never leaves the server; the viewer's own row is flagged via `?viewer=`, and
// the UI already knows its own address (from the route) for the self-link.

/// Opaque, stable per-(group, member) id. Deterministic so every detail
/// endpoint produces the same id for the same member (the UI joins on it), and
/// one-way + group-scoped so it reveals neither the address nor cross-group
/// membership.
fn member_id(group_id: Uuid, address: &str) -> String {
    let mut h = Sha256::new();
    h.update(group_id.as_bytes());
    h.update([0u8]); // domain-separate the two fields
    h.update(address.as_bytes());
    hex::encode(&h.finalize()[..8]) // 64-bit → collision-free within a group
}

/// Masked address for display: first 4 + "..." + last `tail` chars, mirroring
/// the UI's `formatBtcAddress` (tail = 5). Returns the input unchanged when
/// it's too short to shorten.
fn mask_address_tail(address: &str, tail: usize) -> String {
    let a = address.trim();
    let n = a.chars().count();
    if n <= 4 + tail {
        return a.to_string();
    }
    let first: String = a.chars().take(4).collect();
    let last: String = a.chars().skip(n - tail).collect();
    format!("{first}...{last}")
}

/// Masked labels for a group's members, guaranteed unique within the group.
/// Base = last-5 (like the UI); if two members would collapse to the same
/// label, both are widened to last-9, which makes an intra-group visual
/// collision astronomically unlikely. (The `memberId` join is collision-free
/// regardless — this only keeps two rows from *looking* identical.)
fn build_member_labels(addresses: &[String]) -> HashMap<String, String> {
    let mut base_counts: HashMap<String, usize> = HashMap::new();
    for a in addresses {
        *base_counts.entry(mask_address_tail(a, 5)).or_insert(0) += 1;
    }
    let mut out = HashMap::with_capacity(addresses.len());
    for a in addresses {
        let base = mask_address_tail(a, 5);
        let label = if base_counts.get(&base).copied().unwrap_or(0) > 1 {
            mask_address_tail(a, 9)
        } else {
            base
        };
        out.insert(a.clone(), label);
    }
    out
}

// ─── GET /api/groups/:id ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ViewerQuery {
    /// The viewer's own address (already in the UI route). Only used to flag
    /// that member's row `isSelf` — never echoed back for other members.
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
    /// Masked address for display (first 4 + last 5, unique within the group).
    address_label: String,
    /// Full payout address — included ONLY for an admin-token-authenticated
    /// caller (the creator managing members). Absent for anonymous / member
    /// viewers, so a group id can't harvest member addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// True only for the row matching `?viewer=` — the UI uses it to link the
    /// viewer's own row to their address dashboard (it already knows the address
    /// from the route).
    is_self: bool,
    role: String,
    /// ISO-8601.
    joined_at: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    hashrate: f64,
    /// All-time best difficulty for the member (folded in so the UI no longer
    /// fetches per-member client info by full address).
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    best_difficulty: f64,
    /// Earliest worker start (uptime basis), ISO-8601; None when offline.
    #[serde(skip_serializing_if = "Option::is_none")]
    start_time: Option<String>,
    /// Most recent worker heartbeat, ISO-8601; None when never seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<String>,
    last_accepted_share_at: Option<String>,
    /// `None` when caller isn't admin OR when the address has no
    /// verified email binding; otherwise masked-or-unmasked depending
    /// on auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// How the member proved address ownership — `"email"` or `"signature"`.
    /// Admin-only (like `email`); `None` for non-admin callers or a member
    /// with no verification on record. Lets the admin roster show a
    /// "verified via signature" badge for email-less members.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_via: Option<&'static str>,
}

async fn by_id<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Query(q): Query<ViewerQuery>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Validate the admin token (if supplied) BEFORE cache lookup so a
    // bad token returns 401 instead of a stale cached body. The cache
    // key includes the `admin` flag so admin + non-admin views are
    // stored separately.
    let svc = require_group_service(&state)?;
    let token = admin_token(&headers);
    let is_admin = match token {
        None => false,
        Some(t) => match svc.require_admin_token(id, Some(t)).await {
            Ok(_) => true,
            Err(e) => return Err(e.into()),
        },
    };
    // Viewer's own address (from the UI route) — only ever used to flag their
    // own row `isSelf`; never echoed back for other members. Keyed into the
    // cache so the self-flag is per-viewer (anonymous viewers share "none").
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
            let total_hashrate = bp_db::sum_hashrate_for_addresses(&s.pool, &addrs).await?;
            let per_addr_hashrate = per_address_hashrate(&s.pool, &addrs).await?;
            let addr_strings: Vec<String> = addrs.iter().map(|a| a.as_str().to_string()).collect();
            let labels = build_member_labels(&addr_strings);
            // Batch the signature-ownership lookup (admin-only, for the
            // verified-via badge) into one query rather than one per member —
            // avoids an N+1 fan-out on the roster read.
            let owned_signatures = if is_admin {
                bp_db::addresses_with_ownership_proof(&s.pool, &addr_strings).await?
            } else {
                std::collections::HashSet::new()
            };

            let mut entries = Vec::with_capacity(members.len());
            for m in members {
                let addr_str = m.address.as_str();
                // Redis-first / PG-fallback — same policy as the kick-inactivity
                // guard, so an actively-mining member doesn't read "never mined"
                // before the group's first block-found stamps the durable balance.
                let last_active = svc.member_last_active(id, &m.address).await;
                let email = bp_db::find_address_email(&s.pool, &m.address).await?;
                // Admin sees a masked email (enough to tell "verified email
                // present" from "none"); non-admins get no email field.
                let email_out = match (is_admin, email.as_ref()) {
                    (true, Some(b)) => Some(crate::utils::mask_email(&b.email)),
                    _ => None,
                };
                // Verification method for the admin roster badge: a verified
                // email binding wins; otherwise a signature ownership proof.
                // Admin-only, same as `email`.
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
                // Per-member worker stats folded in server-side (best-diff /
                // uptime / last-seen) so the UI no longer fetches per-member
                // client info by full address.
                let clients = bp_db::find_clients_by_address(&s.pool, &m.address).await?;
                let start_time = clients.iter().map(|c| c.start_time).min();
                let last_seen = clients.iter().map(|c| c.updated_at).max();
                let best_difficulty = bp_db::find_address_settings(&s.pool, &m.address)
                    .await?
                    .map(|x| x.best_difficulty)
                    .unwrap_or(0.0);
                entries.push(MemberEntry {
                    member_id: member_id(id, addr_str),
                    address_label: labels
                        .get(addr_str)
                        .cloned()
                        .unwrap_or_else(|| mask_address_tail(addr_str, 5)),
                    address: is_admin.then(|| addr_str.to_string()),
                    is_self: viewer.as_deref() == Some(addr_str),
                    role: m.role,
                    joined_at: crate::time_range::format_slot_label(m.joined_at),
                    hashrate,
                    best_difficulty,
                    start_time: start_time.map(crate::time_range::format_slot_label),
                    last_seen: last_seen.map(crate::time_range::format_slot_label),
                    last_accepted_share_at: last_active.map(crate::time_range::format_slot_label),
                    email: email_out,
                    verified_via,
                });
            }
            let mut summary = GroupSummary::from(group);
            if !is_admin {
                // The creator is a member too and is pseudonymised in `entries`;
                // don't re-leak their full address via the flattened summary to
                // anonymous / member callers. Only an admin-token caller (the
                // creator managing the group) sees it. The UI derives
                // isCreator / "created by" from the member roster (isSelf +
                // role + addressLabel), so it needs no creatorAddress here.
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

/// Compute hashrate per address for the supplied list. We currently
/// fetch them one-by-one — fine for typical group sizes (<50 members);
/// follow-up bp-db helper for a bulk-fetch could replace this.
async fn per_address_hashrate(
    pool: &sqlx::PgPool,
    addrs: &[AddressId],
) -> Result<HashMap<String, f64>, ApiError> {
    let mut out = HashMap::with_capacity(addrs.len());
    for a in addrs {
        let hr = bp_db::sum_hashrate_for_addresses(pool, std::slice::from_ref(a)).await?;
        out.insert(a.as_str().to_string(), hr);
    }
    Ok(out)
}

// ─── GET /api/groups/by-address/:address ─────────────────────────

async fn by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let member = bp_db::find_group_member_by_address(&state.pool, &addr)
        .await?
        .ok_or(ApiError::NotFound)?;
    // The looked-up address is the viewer here (a member opening their own
    // group), so flag its row `isSelf`.
    let viewer = Query(ViewerQuery {
        viewer: Some(addr.as_str().to_string()),
    });
    by_id(State(state), Path(member.group_id), viewer, headers).await
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

async fn hashrate<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let key = format!("GROUP_HASHRATE_{id}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<HashrateResponse, _, ApiError>(key, TtlKind::GroupHashrate, async move {
            let svc = require_group_service(&s)?;
            let _ = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
            let members = svc.list_members(id).await?;
            let addrs: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
            let total_hashrate = bp_db::sum_hashrate_for_addresses(&s.pool, &addrs).await?;
            let per_addr = per_address_hashrate(&s.pool, &addrs).await?;
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
                            .unwrap_or_else(|| mask_address_tail(a.as_str(), 5)),
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

async fn distribution<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
                let total_shares: f64 = stats.per_address.values().sum();
                // Rejected shares are round-scoped — read from the same round
                // store as the accepted shares so both describe the current
                // round, not an all-time total.
                let total_rejected: f64 = stats.total_rejected;
                let rejected_by_addr = stats.rejected_per_address;
                let addr_strings: Vec<String> = stats.per_address.keys().cloned().collect();
                let labels = build_member_labels(&addr_strings);

                let mut entries: Vec<DistributionEntry> = stats
                    .per_address
                    .into_iter()
                    .map(|(address, shares)| {
                        let percent = if total_shares > 0.0 {
                            shares / total_shares * 100.0
                        } else {
                            0.0
                        };
                        let total_rejected_for_addr =
                            rejected_by_addr.get(&address).copied().unwrap_or(0.0);
                        DistributionEntry {
                            member_id: member_id(id, &address),
                            address_label: labels
                                .get(&address)
                                .cloned()
                                .unwrap_or_else(|| mask_address_tail(&address, 5)),
                            total_shares: shares,
                            percent,
                            total_rejected: total_rejected_for_addr,
                        }
                    })
                    .collect();
                entries.sort_by(|a, b| {
                    b.total_shares
                        .partial_cmp(&a.total_shares)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                Ok(DistributionResponse {
                    total_shares,
                    total_rejected,
                    per_address: entries,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/pplns/groups/:id/window-timeline ──────────────────
//
// Per-day, per-member contribution across the live sliding window. Drives the
// Window-mode "sliding window" chart (area / bar / heatmap) + the per-member
// share card. Non-Window groups return an empty timeline (`windowDays: 0`) so
// the UI simply renders nothing.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowTimelineResponse {
    /// Sliding-window length in days; 0 for a non-Window group.
    window_days: i64,
    /// Every contributor in the window, biggest total first (stable stacking +
    /// colour order). Pseudonymised — memberId is the series key, addressLabel
    /// the legend text; the full address is never sent.
    contributors: Vec<TimelineContributor>,
    /// One entry per calendar day that has data, oldest→newest.
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
    /// ISO-8601 day-start (UTC).
    date: String,
    /// Diff-weighted contribution per address, index-aligned to `addresses`.
    #[serde(serialize_with = "crate::time_range::ser_vec_f64_jsnum")]
    values: Vec<f64>,
}

/// Fold the per-hour-bucket timeline into per-day, per-address sums and shape
/// the response. Pure (no I/O) so it unit-tests without Redis.
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
            date: crate::time_range::format_slot_label(day_start),
            values: addresses
                .iter()
                .map(|a| addr_map.get(a).copied().unwrap_or(0.0))
                .collect(),
        })
        .collect();

    // Pseudonymise the series identity (index-aligned to each day's `values`).
    let labels = build_member_labels(&addresses);
    let contributors = addresses
        .iter()
        .map(|a| TimelineContributor {
            member_id: member_id(group_id, a),
            address_label: labels
                .get(a)
                .cloned()
                .unwrap_or_else(|| mask_address_tail(a, 5)),
        })
        .collect();

    WindowTimelineResponse {
        window_days: timeline.window_ms / DAY_MS,
        contributors,
        days,
    }
}

async fn window_timeline<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
    /// Masked submitter address (never the full address).
    address_label: Option<String>,
    /// ISO-8601 wall-clock of the share; `None` when the current
    /// round has no recorded best yet (post-block-found reset state).
    time: Option<String>,
}

async fn best_difficulty<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
                // Empty round returns the zero / null shape (NOT 404) so the
                // UI doesn't surface an error tile right after a reset.
                let Some(best) = engine.reader().best_difficulty(id).await? else {
                    return Ok(BestDifficultyResponse {
                        best_difficulty: 0,
                        address_label: None,
                        time: None,
                    });
                };
                Ok(BestDifficultyResponse {
                    best_difficulty: best.difficulty.floor() as u64,
                    address_label: Some(mask_address_tail(&best.address, 5)),
                    time: Some(crate::time_range::format_slot_label(best.timestamp_ms)),
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
    /// ISO-8601 timestamp the history row was written.
    created_at: String,
    /// Masked payout address (never the full address).
    address_label: String,
    paid_sats: i64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    shares_in_round: i64,
    total_shares_in_round: i64,
    row_type: String,
}

async fn history<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Query(q): Query<HistoryQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
                    created_at: crate::time_range::format_slot_label(h.created_at),
                    address_label: mask_address_tail(h.address.as_str(), 5),
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

async fn open_invite_active<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Admin and non-admin responses both omit the secret token when
    // the caller isn't an admin — key on `is_admin` so we don't leak
    // the admin variant to a public viewer via shared cache.
    let token = admin_token(&headers).map(|s| s.to_string());
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

async fn list_join_requests<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Query(q): Query<JoinRequestsQuery>,
    headers: HeaderMap,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let token = admin_token(&headers).map(|s| s.to_string());
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

async fn join_requests_by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
    let code: &'static str = match e.code() {
        "not-found" => "not-found",
        "invalid-address" => "invalid-address",
        "email-not-verified" => "email-not-verified",
        "already-member" => "already-member",
        "address-in-group" => "address-in-group",
        "too-many-pending" => "too-many-pending",
        "reject-cooldown" => "reject-cooldown",
        "request-pending" => "request-pending",
        "group-dissolved" => "group-dissolved",
        _ => "internal-error",
    };
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
// Aggregations across the current member list of the group. Each
// endpoint reads `client_statistics_entity` / `client_rejected_
// statistics_entity` rows for every member address in the configured
// time window and bins them into the same slot grid the per-address
// endpoints use.

use crate::time_range::{chart_slot_boundaries, ChartPoint, Range, SlotCounts, SlotDataResponse};

use crate::time_range::{DIFFICULTY_1, SLOT_SECONDS};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRangeQuery {
    range: Option<String>,
}

async fn collect_group_member_addresses<H, M>(
    state: &SharedState<H, M>,
    id: Uuid,
) -> Result<Vec<AddressId>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = require_group_service(state)?;
    let members = svc.list_members(id).await?;
    Ok(members.into_iter().map(|m| m.address).collect())
}

async fn group_chart<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_CHART_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::GroupChart, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let addrs = collect_group_member_addresses(&s, id).await?;
            // Sparse per-slot emission — sum each slot's shares across
            // member rows, emit one ChartPoint per slot that actually
            // received shares.
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
                    label: crate::time_range::format_slot_label(t),
                    data: (shares * DIFFICULTY_1 / SLOT_SECONDS).round(),
                })
                .collect())
        })
        .await?;
    Ok(JsonBytes(bytes))
}

async fn group_accepted<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_ACCEPTED_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::GroupAccepted, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let addrs = collect_group_member_addresses(&s, id).await?;
            let mut buckets: std::collections::BTreeMap<i64, f64> =
                std::collections::BTreeMap::new();
            for a in &addrs {
                let rows =
                    bp_db::find_client_statistics_since_for_address(&s.pool, a, since).await?;
                for r in rows.iter().filter(|r| r.time < cutoff) {
                    // Diff-1-weighted accepted shares (sum of share difficulty),
                    // matching the per-client `/accepted` endpoint — tracks work,
                    // not raw share count, so it stays flat at constant hashrate.
                    *buckets.entry(r.time).or_insert(0.0) += r.shares as f64;
                }
            }
            let boundaries: Vec<i64> = chart_slot_boundaries(since, range.slot_size_ms())
                .into_iter()
                .filter(|&b| b < cutoff)
                .collect();
            let slot_data: Vec<SlotCounts> = boundaries
                .iter()
                .map(|&b| {
                    let mut counts = std::collections::BTreeMap::new();
                    let sum: f64 = buckets
                        .iter()
                        .filter(|(k, _)| {
                            crate::time_range::bucket_key(**k, range.slot_size_ms()) == b
                        })
                        .map(|(_, v)| *v)
                        .sum();
                    counts.insert("accepted".into(), sum);
                    SlotCounts {
                        time: crate::time_range::format_slot_label(b),
                        counts,
                    }
                })
                .collect();
            Ok(SlotDataResponse { slot_data })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct GroupRejectCounts {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    count: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    diff_minus_one: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupRejectedSlot {
    time: String,
    counts: std::collections::BTreeMap<String, GroupRejectCounts>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupRejectedResponse {
    slot_data: Vec<GroupRejectedSlot>,
}

async fn group_rejected<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    Query(q): Query<GroupRangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("GROUP_REJECTED_{id}_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<GroupRejectedResponse, _, ApiError>(
            key,
            TtlKind::GroupRejected,
            async move {
                let now = crate::time_range::now_ms();
                let since = now - range.window_ms();
                let addrs = collect_group_member_addresses(&s, id).await?;
                let mut buckets: std::collections::BTreeMap<
                    i64,
                    std::collections::BTreeMap<String, GroupRejectCounts>,
                > = std::collections::BTreeMap::new();
                for a in &addrs {
                    let rows =
                        bp_db::find_client_rejected_statistics_since_for_address(&s.pool, a, since)
                            .await?;
                    for r in rows {
                        let k = crate::time_range::bucket_key(r.time, range.slot_size_ms());
                        let key = crate::controllers::info::normalise_reject_reason(&r.reason)
                            .to_string();
                        let entry = buckets.entry(k).or_default().entry(key).or_default();
                        entry.count += r.count as f64;
                        entry.diff_minus_one += r.shares as f64;
                    }
                }
                let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
                Ok(GroupRejectedResponse {
                    slot_data: boundaries
                        .iter()
                        .map(|&b| {
                            let mut counts: std::collections::BTreeMap<String, GroupRejectCounts> =
                                crate::controllers::info::REJECT_REASON_KEYS
                                    .iter()
                                    .map(|&k| (k.to_string(), GroupRejectCounts::default()))
                                    .collect();
                            if let Some(seen) = buckets.remove(&b) {
                                for (k, v) in seen {
                                    counts.insert(k, v);
                                }
                            }
                            GroupRejectedSlot {
                                time: crate::time_range::format_slot_label(b),
                                counts,
                            }
                        })
                        .collect(),
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use uuid::Uuid;

    fn parse_include_decided(s: Option<&str>) -> bool {
        s.map(|v| v == "1" || v == "true").unwrap_or(false)
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
        // Buckets 100 & 101 fall in day 4 (100/24 = 101/24 = 4); bucket 130 in
        // day 5. B contributes less than A overall.
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
        // A total 37 > B total 8 → A stacked/coloured first. The short test
        // addresses are below the mask threshold so their labels are verbatim.
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
        // Same-day hours summed; values index-aligned to [A, B].
        assert_eq!(resp.days[0].values, vec![30.0, 5.0]);
        assert_eq!(resp.days[1].values, vec![7.0, 3.0]);
        // Days are the two day-starts, oldest→newest.
        assert_eq!(
            resp.days[0].date,
            crate::time_range::format_slot_label(4 * DAY_MS)
        );
        assert_eq!(
            resp.days[1].date,
            crate::time_range::format_slot_label(5 * DAY_MS)
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
            finder_bonus_sats: 0,
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
            finder_bonus_sats: 0,
            last_round_reset_at: None,
            next_reset_at: None,
            is_public: true,
            reset_round_on_block: false,
            max_members: None,
            mode: "prop".into(),
        };
        // Authenticated/address-scoped views keep the creator address.
        let authed: Value = serde_json::to_value(&summary).unwrap();
        assert_eq!(authed["creatorAddress"], "bc1qcreator");

        // The public directory shape nulls it → the key must be absent entirely.
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
        // Other public fields are still present.
        assert_eq!(v["name"], "g");
        assert_eq!(v["memberCount"], 3);
        assert_eq!(v["isPublic"], true);
    }

    #[test]
    fn mask_address_tail_shows_first4_and_last_n() {
        let a = "bc1qxyzabcdefghijklmnop9k2p4";
        assert_eq!(mask_address_tail(a, 5), "bc1q...9k2p4");
        assert_eq!(mask_address_tail(a, 9), "bc1q...mnop9k2p4");
        // Too short to shorten → returned verbatim.
        assert_eq!(mask_address_tail("bc1qab", 5), "bc1qab");
        // Never contains the full middle of the address.
        assert!(!mask_address_tail(a, 5).contains("xyzabc"));
    }

    #[test]
    fn member_id_is_stable_group_scoped_and_opaque() {
        let g1 = Uuid::from_u128(1);
        let g2 = Uuid::from_u128(2);
        let a = "bc1qsomeaddressaaaa";
        // Deterministic.
        assert_eq!(member_id(g1, a), member_id(g1, a));
        // Group-scoped: same address, different group → different id.
        assert_ne!(member_id(g1, a), member_id(g2, a));
        // Different address → different id.
        assert_ne!(member_id(g1, a), member_id(g1, "bc1qsomeaddressbbbb"));
        // Opaque: doesn't leak the address, fixed 16-hex width.
        let id = member_id(g1, a);
        assert_eq!(id.len(), 16);
        assert!(!id.contains("address"));
    }

    #[test]
    fn build_member_labels_disambiguates_collisions() {
        // Same first-4 ("bc1q") AND same last-5 ("12345") → base labels collide
        // → both widened so two rows never render identically.
        let a = "bc1qAAAAAAAAA12345".to_string();
        let b = "bc1qBBBBBBBBB12345".to_string();
        let labels = build_member_labels(&[a.clone(), b.clone()]);
        assert_eq!(mask_address_tail(&a, 5), mask_address_tail(&b, 5)); // base collides
        assert_ne!(labels[&a], labels[&b], "colliding labels must be widened");
        // A non-colliding address keeps the short last-5 label.
        let c = "bc1qCCCCCCCCCC99999".to_string();
        let labels2 = build_member_labels(&[a, c.clone()]);
        assert_eq!(labels2[&c], mask_address_tail(&c, 5));
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

        // Admin variant (address = Some) carries the full address.
        let admin = MemberEntry {
            address: Some("bc1qfulladdr".into()),
            ..e
        };
        let av: Value = serde_json::to_value(&admin).unwrap();
        assert_eq!(av["address"], "bc1qfulladdr");
    }

    #[test]
    fn group_detail_hides_creator_address_from_non_admin() {
        // Mirrors by_id: the flattened summary's creatorAddress is nulled for
        // non-admin callers (the creator is a pseudonymised member in the
        // roster), and present only for an admin-token caller.
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
                finder_bonus_sats: 0,
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
