// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/blockparty/*` — Blockparty mining mode endpoints.
//!
//! Every mutation returns `{ "ok": true }` JSON rather than 204 NoContent
//! because the UI reads `response.ok === true` after parsing.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, patch, post},
    Router,
};
use bp_blockparty::BlockpartyStatus;
use bp_common::AddressId;
use bp_db::{
    BlockpartyBlockHistoryRow, BlockpartyGroupRow, BlockpartyInvitationRow, BlockpartyMemberRow,
    BlockpartySplitSnapshot,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::SharedState;

// ─── DTOs (camelCase JSON, ms-epoch i64 timestamps) ───────────────

/// Canonical public-facing group shape.
/// No `updatedAt`, no admin-token hash; `dissolvedAt` stays null until dissolve.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupPublicView {
    id: Uuid,
    name: String,
    admin_address: String,
    status: String,
    last_share_at: Option<i64>,
    created_at: i64,
    dissolved_at: Option<i64>,
    /// `null` rather than omitted when the hint is unset.
    rental_provider_hint: Option<String>,
}

impl GroupPublicView {
    fn from_row(r: &BlockpartyGroupRow) -> Self {
        Self {
            id: r.id,
            name: r.name.clone(),
            admin_address: r.admin_address.as_str().to_owned(),
            status: r.status.clone(),
            last_share_at: r.last_share_at,
            created_at: r.created_at,
            dissolved_at: r.dissolved_at,
            rental_provider_hint: r.rental_provider_hint.clone(),
        }
    }
}

/// Member shape emitted by `GET /:id` (public detail). Email is masked.
/// `confirmed: bool` is the only confirmation-state surface — `confirmedAt`
/// is never returned (UI binds on the bool).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberPublicView {
    address: String,
    email: String,
    percent_bp: i32,
    role: String,
    confirmed: bool,
}

impl MemberPublicView {
    fn from_row_masked(r: &BlockpartyMemberRow) -> Self {
        Self {
            address: r.address.as_str().to_owned(),
            email: mask_email(&r.email),
            percent_bp: r.percent_bp,
            role: r.role.clone(),
            confirmed: r.confirmed_at.is_some(),
        }
    }

    /// `member-view` variant: members see their own email unmasked but
    /// other members' emails masked.
    fn from_row_for_viewer(r: &BlockpartyMemberRow, viewer: &AddressId) -> Self {
        let own = r.address == *viewer;
        Self {
            address: r.address.as_str().to_owned(),
            email: if own {
                r.email.clone()
            } else {
                mask_email(&r.email)
            },
            percent_bp: r.percent_bp,
            role: r.role.clone(),
            confirmed: r.confirmed_at.is_some(),
        }
    }
}

/// Member shape embedded in the public invitation view: roster + splits
/// only, no contact details. The invitee sees who is in and at what
/// percentage before accepting.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteMemberView {
    address: String,
    percent_bp: i32,
    role: String,
    confirmed: bool,
}

impl InviteMemberView {
    fn from_row(r: &BlockpartyMemberRow) -> Self {
        Self {
            address: r.address.as_str().to_owned(),
            percent_bp: r.percent_bp,
            role: r.role.clone(),
            confirmed: r.confirmed_at.is_some(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationAdminView {
    token: String,
    address: String,
    email: String,
    status: String,
    created_at: i64,
    expires_at: i64,
    responded_at: Option<i64>,
}

impl InvitationAdminView {
    fn from_row(r: BlockpartyInvitationRow) -> Self {
        Self {
            token: r.token,
            address: r.address.into_inner(),
            email: mask_email(&r.email),
            status: r.status,
            created_at: r.created_at,
            expires_at: r.expires_at,
            responded_at: r.responded_at,
        }
    }
}

/// History row shape — drops `id`, `groupId`, `createdAt` from the
/// stored row (those are internal).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryRowView {
    block_height: i32,
    block_hash: String,
    found_at: i64,
    coinbase_value_sats: i64,
    pool_fee_sats: i64,
    splits: Vec<BlockpartySplitSnapshot>,
}

impl From<BlockpartyBlockHistoryRow> for HistoryRowView {
    fn from(r: BlockpartyBlockHistoryRow) -> Self {
        Self {
            block_height: r.block_height,
            block_hash: r.block_hash,
            found_at: r.found_at,
            coinbase_value_sats: r.coinbase_value_sats.0,
            pool_fee_sats: r.pool_fee_sats.0,
            splits: r.splits.0,
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────

/// `a***@e***.com` — see [`crate::utils::mask_email`] for the full
/// specification. Re-exported as a thin alias so call sites in this
/// controller don't need to change shape.
fn mask_email(email: &str) -> String {
    crate::utils::mask_email(email)
}

fn admin_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-blockparty-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

fn member_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-blockparty-member-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

fn require_blockparty<H, M>(
    state: &SharedState<H, M>,
) -> Result<&dyn bp_blockparty_engine::BlockpartyApi, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    state
        .blockparty
        .as_deref()
        .ok_or(ApiError::Unavailable("blockparty-service not wired"))
}

fn require_blockparty_invitations<H, M>(
    state: &SharedState<H, M>,
) -> Result<&dyn bp_blockparty_engine::BlockpartyInvitationApi, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    state
        .blockparty_invitations
        .as_deref()
        .ok_or(ApiError::Unavailable(
            "blockparty-invitation-service not wired",
        ))
}

fn normalize(addr: &str) -> Result<AddressId, ApiError> {
    AddressId::new(addr.trim().to_ascii_lowercase()).map_err(|_| ApiError::InvalidAddress)
}

/// JSON `{ "ok": true }` — used by every mutation handler (UI checks
/// `response.ok === true`).
#[derive(Serialize)]
struct Ok {
    ok: bool,
}

const OK: Ok = Ok { ok: true };

// ─── Router ────────────────────────────────────────────────────────

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    Router::new()
        // ── Reads ────────────────────────────────────────────────
        .route("/api/blockparty", get(list_groups::<H, M>))
        .route("/api/blockparty/public", get(list_groups_public::<H, M>))
        .route(
            "/api/blockparty/by-address/:address",
            get(by_address::<H, M>),
        )
        .route("/api/blockparty/:id", get(detail::<H, M>))
        .route("/api/blockparty/:id/history", get(history::<H, M>))
        .route(
            "/api/blockparty/:id/invitations",
            get(list_invitations::<H, M>),
        )
        .route(
            "/api/blockparty/:id/member-view/:address",
            get(member_view::<H, M>),
        )
        // ── Admin lifecycle ──────────────────────────────────────
        .route("/api/blockparty", post(create::<H, M>))
        .route("/api/blockparty/:id/splits", patch(update_splits::<H, M>))
        .route(
            "/api/blockparty/:id/rental-hint",
            patch(update_rental_hint::<H, M>),
        )
        .route("/api/blockparty/:id/members", post(add_member::<H, M>))
        .route(
            "/api/blockparty/:id/members/batch",
            post(add_members_batch::<H, M>),
        )
        .route(
            "/api/blockparty/:id/members/:address",
            delete(remove_member::<H, M>),
        )
        .route(
            "/api/blockparty/:id/members/:address/resend-invitation",
            post(resend_invitation::<H, M>),
        )
        .route(
            "/api/blockparty/:id/transition-confirming",
            post(transition_confirming::<H, M>),
        )
        .route("/api/blockparty/:id/dissolve", post(dissolve::<H, M>))
        .route(
            "/api/blockparty/:id/invitations/:token",
            delete(revoke_invitation::<H, M>),
        )
        // ── Member-token gated ───────────────────────────────────
        .route(
            "/api/blockparty/:id/members/:address/reconfirm",
            post(reconfirm_member::<H, M>),
        )
        // ── Invitation (public; token IS the auth) ───────────────
        .route("/api/blockparty/invite/:token", get(get_invitation::<H, M>))
        .route(
            "/api/blockparty/invite/:token/accept",
            post(accept_invitation::<H, M>),
        )
        .route(
            "/api/blockparty/invite/:token/decline",
            post(decline_invitation::<H, M>),
        )
}

// ─── Read handlers ─────────────────────────────────────────────────

async fn list_groups<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<Vec<GroupPublicView>>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let rows = svc.list_groups().await?;
    Ok(Json(rows.iter().map(GroupPublicView::from_row).collect()))
}

async fn list_groups_public<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<Vec<GroupPublicView>>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let rows = svc.list_groups_public().await?;
    Ok(Json(rows.iter().map(GroupPublicView::from_row).collect()))
}

/// `{ groupId: null }` when no party found for this address;
/// `{ groupId, groupName, status, role }` when matched. `untagged`
/// means serde picks the variant by the present fields rather than
/// inserting a discriminator.
#[derive(Serialize)]
#[serde(untagged)]
enum ByAddressResponse {
    Match {
        #[serde(rename = "groupId")]
        group_id: Uuid,
        #[serde(rename = "groupName")]
        group_name: String,
        status: String,
        role: Option<String>,
    },
    Empty {
        // Always `None` — emits `{ "groupId": null }`.
        #[serde(rename = "groupId")]
        group_id: Option<Uuid>,
    },
}

async fn by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<ByAddressResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let addr = normalize(&address)?;
    let Some(group_id) = svc.member_group_id(&addr).await else {
        return Ok(Json(ByAddressResponse::Empty { group_id: None }));
    };
    let Some(group) = svc.get_group(group_id).await? else {
        return Ok(Json(ByAddressResponse::Empty { group_id: None }));
    };
    let members = svc.list_members(group_id).await?;
    let role = members
        .iter()
        .find(|m| m.address == addr)
        .map(|m| m.role.clone());
    Ok(Json(ByAddressResponse::Match {
        group_id: group.id,
        group_name: group.name,
        status: group.status,
        role,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetailResponse {
    #[serde(flatten)]
    group: GroupPublicView,
    members: Vec<MemberPublicView>,
}

async fn detail<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DetailResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let group = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
    let members = svc.list_members(id).await?;
    Ok(Json(DetailResponse {
        group: GroupPublicView::from_row(&group),
        members: members
            .iter()
            .map(MemberPublicView::from_row_masked)
            .collect(),
    }))
}

async fn history<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<HistoryRowView>>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let rows = svc.get_history(id).await?;
    Ok(Json(rows.into_iter().map(HistoryRowView::from).collect()))
}

async fn list_invitations<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<InvitationAdminView>>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let inv = require_blockparty_invitations(&state)?;
    let rows = inv
        .list_for_group(id, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(InvitationAdminView::from_row)
            .collect(),
    ))
}

async fn member_view<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<DetailResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let viewer = normalize(&address)?;
    svc.verify_member_token(id, &viewer, member_token(&headers).as_deref())
        .await?;
    let group = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
    let members = svc.list_members(id).await?;
    Ok(Json(DetailResponse {
        group: GroupPublicView::from_row(&group),
        members: members
            .iter()
            .map(|m| MemberPublicView::from_row_for_viewer(m, &viewer))
            .collect(),
    }))
}

// ─── Admin lifecycle handlers ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    name: String,
    admin_address: String,
    admin_email: String,
    admin_percent_bp: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateResponse {
    group: GroupPublicView,
    /// Plaintext admin token — shown to the creator exactly once.
    admin_token: String,
    pool_fee_percent: f64,
}

async fn create<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<CreateBody>,
) -> Result<Json<CreateResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let res = svc
        .create_group(
            &body.name,
            &body.admin_address,
            &body.admin_email,
            body.admin_percent_bp,
        )
        .await?;
    Ok(Json(CreateResponse {
        group: GroupPublicView::from_row(&res.group),
        admin_token: res.admin_token,
        pool_fee_percent: res.pool_fee_percent,
    }))
}

async fn dissolve<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    svc.dissolve_group(id, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RentalHintBody {
    hint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RentalHintResponse {
    rental_provider_hint: Option<String>,
}

/// `PATCH /:id/rental-hint` — admin updates the free-form hint string.
/// Trims + truncates to 64 chars; stores `null` for blank/empty input.
async fn update_rental_hint<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<RentalHintBody>,
) -> Result<Json<RentalHintResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let rental_provider_hint = svc
        .update_rental_hint(id, body.hint.as_deref(), admin_token(&headers).as_deref())
        .await?;
    Ok(Json(RentalHintResponse {
        rental_provider_hint,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSplitsBody {
    splits: Vec<SplitUpdate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SplitUpdate {
    address: String,
    percent_bp: i32,
}

async fn update_splits<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateSplitsBody>,
) -> Result<Json<&'static Ok>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let mut updates = Vec::with_capacity(body.splits.len());
    for s in body.splits {
        updates.push((normalize(&s.address)?, s.percent_bp));
    }
    svc.update_splits(id, updates, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddMemberBody {
    address: String,
    percent_bp: i32,
    #[serde(default)]
    #[allow(dead_code)]
    email: Option<String>,
    #[serde(default)]
    ttl_days: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddMemberResponse {
    member: MemberPublicView,
    /// One-shot — admin shares this out-of-band with the member.
    invite_token: String,
}

async fn add_member<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<AddMemberBody>,
) -> Result<Json<AddMemberResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let inv = require_blockparty_invitations(&state)?;
    let token = admin_token(&headers);
    let member = svc
        .add_member(id, &body.address, body.percent_bp, token.as_deref())
        .await?;
    let invitation = inv
        .create_invitation(id, &body.address, body.ttl_days, token.as_deref())
        .await?;
    Ok(Json(AddMemberResponse {
        member: MemberPublicView {
            address: member.address.as_str().to_owned(),
            email: mask_email(&member.email),
            percent_bp: member.percent_bp,
            role: member.role,
            // Freshly added members are never auto-confirmed.
            confirmed: false,
        },
        invite_token: invitation.token,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchMembersBody {
    members: Option<Vec<BatchMemberInput>>,
    #[serde(default)]
    ttl_days: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchMemberInput {
    address: String,
    percent_bp: i32,
    #[serde(default)]
    #[allow(dead_code)]
    email: Option<String>,
}

/// Per-row result for `POST /:id/members/batch`.
/// `{ address, ok: true, inviteToken } | { address, ok: false, code, message }`
#[derive(Serialize)]
#[serde(untagged)]
enum BatchMemberResult {
    Ok {
        address: String,
        ok: bool, // always true
        #[serde(rename = "inviteToken")]
        invite_token: String,
    },
    Err {
        address: String,
        ok: bool, // always false
        code: &'static str,
        message: String,
    },
}

#[derive(Serialize)]
struct BatchMembersResponse {
    results: Vec<BatchMemberResult>,
}

async fn add_members_batch<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<BatchMembersBody>,
) -> Result<Json<BatchMembersResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let inv = require_blockparty_invitations(&state)?;
    let inputs = body.members.unwrap_or_default();
    if inputs.is_empty() {
        return Err(ApiError::BadRequest("no-members"));
    }
    let token = admin_token(&headers);
    // Process one-by-one — a single bad input returns a structured
    // partial result rather than rolling back valid invites.
    let mut results = Vec::with_capacity(inputs.len());
    for input in inputs {
        match process_batch_one(svc, inv, id, &input, body.ttl_days, token.as_deref()).await {
            Ok(invite_token) => results.push(BatchMemberResult::Ok {
                address: input.address,
                ok: true,
                invite_token,
            }),
            Err(err) => results.push(BatchMemberResult::Err {
                address: input.address,
                ok: false,
                code: err.code,
                message: err.message,
            }),
        }
    }
    Ok(Json(BatchMembersResponse { results }))
}

struct BatchErr {
    code: &'static str,
    message: String,
}

async fn process_batch_one(
    svc: &dyn bp_blockparty_engine::BlockpartyApi,
    inv: &dyn bp_blockparty_engine::BlockpartyInvitationApi,
    group_id: Uuid,
    input: &BatchMemberInput,
    ttl_days: Option<i64>,
    token: Option<&str>,
) -> Result<String, BatchErr> {
    let member = svc
        .add_member(group_id, &input.address, input.percent_bp, token)
        .await
        .map_err(|e| BatchErr {
            code: e.code(),
            message: e.to_string(),
        })?;
    let invitation = inv
        .create_invitation(group_id, member.address.as_str(), ttl_days, token)
        .await
        .map_err(|e| BatchErr {
            code: e.code(),
            message: e.to_string(),
        })?;
    Ok(invitation.token)
}

async fn remove_member<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    svc.remove_member(id, &address, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

#[derive(Serialize)]
struct ResendResponse {
    ok: bool,
    resent: bool,
}

async fn resend_invitation<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<ResendResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let inv = require_blockparty_invitations(&state)?;
    // The invitation service gates through admin-token-gated path
    // inside resend_invitation — safe to call directly.
    let r = inv
        .resend_invitation(id, &address, None, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(ResendResponse {
        ok: true,
        resent: r.resent,
    }))
}

#[derive(Serialize)]
struct TransitionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

async fn transition_confirming<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TransitionResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let _ = svc
        .transition_to_confirming(id, admin_token(&headers).as_deref())
        .await?;
    // Re-read so a recomputeStatus that auto-promoted CONFIRMING → READY
    // surfaces in the response. A group that vanished in the race window
    // yields an omitted status rather than a 404.
    let group = svc.get_group(id).await?;
    Ok(Json(TransitionResponse {
        status: group.map(|g| g.status),
    }))
}

async fn revoke_invitation<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, token_path)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let inv = require_blockparty_invitations(&state)?;
    inv.revoke(id, &token_path, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

// ─── Member-token gated ────────────────────────────────────────────

async fn reconfirm_member<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let addr = normalize(&address)?;
    svc.confirm_as_member(id, &addr, member_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

// ─── Public invitation handlers (token IS the auth) ───────────────

/// Public invitation view. `groupName` flattened in, `members[]` summary
/// embedded, `poolFeePercent` echoed back. Effective status replaces a
/// `pending` row with `expired` when `expiresAt` is in the past.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationView {
    token: String,
    group_id: Uuid,
    group_name: String,
    address: String,
    email: String,
    status: String,
    expires_at: i64,
    members: Vec<InviteMemberView>,
    pool_fee_percent: f64,
}

async fn get_invitation<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token_path): Path<String>,
) -> Result<Json<InvitationView>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let inv = require_blockparty_invitations(&state)?;
    let (invitation, group) =
        inv.get_by_token(&token_path)
            .await?
            .ok_or_else(|| ApiError::Blockparty {
                code: "invitation-not-found",
                status: StatusCode::NOT_FOUND,
            })?;
    let members = svc.list_members(group.id).await?;
    let effective_status = compute_effective_invitation_status(&invitation).to_owned();
    Ok(Json(InvitationView {
        token: invitation.token,
        group_id: invitation.group_id,
        group_name: group.name,
        address: invitation.address.into_inner(),
        email: invitation.email,
        status: effective_status,
        expires_at: invitation.expires_at,
        members: members.iter().map(InviteMemberView::from_row).collect(),
        pool_fee_percent: svc.pool_fee_percent(),
    }))
}

/// Returns `"expired"` for pending rows whose `expiresAt` is in the past.
fn compute_effective_invitation_status(row: &BlockpartyInvitationRow) -> &str {
    if row.status != "pending" {
        return row.status.as_str();
    }
    let now = chrono::Utc::now().timestamp_millis();
    if row.expires_at < now {
        "expired"
    } else {
        "pending"
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptResponse {
    ok: bool,
    /// Persistent member token — surfaces exactly once. `None` when
    /// the accept was idempotent (member already had a token).
    member_token: Option<String>,
}

async fn accept_invitation<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token_path): Path<String>,
) -> Result<Json<AcceptResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let inv = require_blockparty_invitations(&state)?;
    let r = inv.accept(&token_path).await?;
    Ok(Json(AcceptResponse {
        ok: true,
        member_token: r.member_token,
    }))
}

async fn decline_invitation<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token_path): Path<String>,
) -> Result<Json<&'static Ok>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let inv = require_blockparty_invitations(&state)?;
    inv.decline(&token_path).await?;
    Ok(Json(&OK))
}

// Silence the unused-variant warning on BlockpartyStatus import — it
// flows through the BlockpartyApi trait surface but isn't named here.
#[allow(dead_code)]
fn _status_ref(_: BlockpartyStatus) {}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin DTO serialized JSON shapes. The UI binds on field names + types —
    /// any unintended schema drift shows up as a test failure here.
    #[test]
    fn group_public_view_json_shape() {
        let row = BlockpartyGroupRow {
            id: Uuid::parse_str("219eba31-19ac-4f3c-b97a-f50ee3f02b96").unwrap(),
            name: "Blockparty XX".to_owned(),
            admin_address: AddressId::new("bc1qywnf55acqpxr0lekg2gmy2s46pzxqze99j0u9y").unwrap(),
            admin_token_hash: "internal".to_owned(),
            status: "active".to_owned(),
            last_share_at: Some(1_779_523_779_828),
            rental_provider_hint: None,
            created_at: 1_779_464_858_619,
            updated_at: 0, // never surfaced
            dissolved_at: None,
        };
        let dto = GroupPublicView::from_row(&row);
        let json = serde_json::to_value(&dto).expect("serialize");
        let expected: serde_json::Value = serde_json::from_str(
            r#"{
                "id": "219eba31-19ac-4f3c-b97a-f50ee3f02b96",
                "name": "Blockparty XX",
                "adminAddress": "bc1qywnf55acqpxr0lekg2gmy2s46pzxqze99j0u9y",
                "status": "active",
                "lastShareAt": 1779523779828,
                "createdAt": 1779464858619,
                "dissolvedAt": null,
                "rentalProviderHint": null
            }"#,
        )
        .unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn member_public_view_json_shape_masked() {
        let row = BlockpartyMemberRow {
            id: 42,
            group_id: Uuid::parse_str("219eba31-19ac-4f3c-b97a-f50ee3f02b96").unwrap(),
            address: AddressId::new("bc1q307hujcervvdfr73ntlam2f7w65j6gs9zcnf39").unwrap(),
            email: "mvogel@yahoo.ch".to_owned(),
            percent_bp: 2500,
            role: "member".to_owned(),
            confirmed_at: Some(1_779_464_900_000),
            member_token_hash: Some("internal".to_owned()),
            created_at: 0,
            updated_at: 0,
        };
        let dto = MemberPublicView::from_row_masked(&row);
        let json = serde_json::to_value(&dto).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{
                "address": "bc1q307hujcervvdfr73ntlam2f7w65j6gs9zcnf39",
                "email": "m***@y***.ch",
                "percentBp": 2500,
                "role": "member",
                "confirmed": true
            }"#,
        )
        .unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn by_address_empty_response_emits_only_group_id_null() {
        let resp = ByAddressResponse::Empty { group_id: None };
        let json = serde_json::to_value(&resp).unwrap();
        let expected: serde_json::Value = serde_json::from_str(r#"{"groupId": null}"#).unwrap();
        assert_eq!(
            json, expected,
            "by-address empty response must be only {{ groupId: null }}"
        );
    }

    #[test]
    fn by_address_match_response_shape() {
        let resp = ByAddressResponse::Match {
            group_id: Uuid::parse_str("219eba31-19ac-4f3c-b97a-f50ee3f02b96").unwrap(),
            group_name: "Blockparty XX".to_owned(),
            status: "active".to_owned(),
            role: Some("admin".to_owned()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{
                "groupId": "219eba31-19ac-4f3c-b97a-f50ee3f02b96",
                "groupName": "Blockparty XX",
                "status": "active",
                "role": "admin"
            }"#,
        )
        .unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn ok_response_is_literal_ok_true() {
        let json = serde_json::to_value(&OK).unwrap();
        assert_eq!(json, serde_json::json!({"ok": true}));
    }

    #[test]
    fn mask_email_cases() {
        assert_eq!(mask_email("alice@gmail.com"), "a***@g***.com");
        assert_eq!(mask_email("bob@joe.de"), "b***@j***.de");
        assert_eq!(mask_email("carol@example.co.uk"), "c***@e***.co.uk");
        assert_eq!(mask_email("alice@example.com"), "a***@e***.com");
        assert_eq!(mask_email("bob@sub.domain.net"), "b***@s***.domain.net");
        assert_eq!(mask_email("nodomain"), "***");
        assert_eq!(mask_email(""), "");
        assert_eq!(mask_email("@badleft.com"), "***");
        assert_eq!(mask_email("noright@"), "***");
        assert_eq!(mask_email("alice@nodot"), "a***@***");
    }
}
