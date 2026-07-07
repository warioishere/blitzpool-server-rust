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
    BlockpartyBlockHistoryRow, BlockpartyGroupRow, BlockpartyMemberRow, BlockpartySplitSnapshot,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::rate_limit;
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
    /// How the member proved ownership — `"email"` or `"signature"`. Lets the
    /// admin roster show a "verified via signature" badge for email-less
    /// members. `None` only for the (legacy) case of no verification on record.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_via: Option<&'static str>,
}

impl MemberPublicView {
    fn from_row_masked(r: &BlockpartyMemberRow, verified_via: Option<&'static str>) -> Self {
        Self {
            address: r.address.as_str().to_owned(),
            email: mask_email(&r.email),
            percent_bp: r.percent_bp,
            role: r.role.clone(),
            confirmed: r.confirmed_at.is_some(),
            verified_via,
        }
    }

    /// `member-view` variant: members see their own email unmasked but
    /// other members' emails masked.
    fn from_row_for_viewer(
        r: &BlockpartyMemberRow,
        viewer: &AddressId,
        verified_via: Option<&'static str>,
    ) -> Self {
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
            verified_via,
        }
    }
}

/// Verification method for a blockparty member — a non-empty snapshot email
/// (captured from a verified binding at join) reads as `"email"`; otherwise a
/// signature ownership proof reads as `"signature"`. `None` only for a member
/// with neither on record.
async fn member_verified_via<H, M>(
    state: &SharedState<H, M>,
    m: &BlockpartyMemberRow,
) -> Result<Option<&'static str>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    if !m.email.trim().is_empty() {
        return Ok(Some("email"));
    }
    if bp_db::is_address_ownership_verified(&state.pool, &m.address).await? {
        Ok(Some("signature"))
    } else {
        Ok(None)
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
        // NB: no public directory listing — blockparty is invite-only, so the
        // group id is not enumerable. Detail/by-address need the id up front.
        .route(
            "/api/blockparty/by-address/:address",
            get(by_address::<H, M>),
        )
        .route("/api/blockparty/:id", get(detail::<H, M>))
        .route("/api/blockparty/:id/history", get(history::<H, M>))
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
        .route(
            "/api/blockparty/:id/join-link",
            get(active_join_link::<H, M>)
                .post(create_join_link::<H, M>)
                .delete(revoke_join_link::<H, M>),
        )
        .route(
            // Public self-service join — throttled per client IP (matches the
            // group-solo open-invite accept). Covers both the POST join (DB
            // write + member-token mint) and the GET context (token probing).
            "/api/blockparty/join/:token",
            get(get_join_context::<H, M>)
                .post(join_via_link::<H, M>)
                .layer(rate_limit::per_minute_layer(10)),
        )
        .route(
            "/api/blockparty/:id/members/:address",
            delete(remove_member::<H, M>),
        )
        .route(
            "/api/blockparty/:id/transition-confirming",
            post(transition_confirming::<H, M>),
        )
        .route("/api/blockparty/:id/dissolve", post(dissolve::<H, M>))
        // ── Member-token gated ───────────────────────────────────
        .route(
            "/api/blockparty/:id/members/:address/reconfirm",
            post(reconfirm_member::<H, M>),
        )
}

// ─── Read handlers ─────────────────────────────────────────────────

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
    let mut member_views = Vec::with_capacity(members.len());
    for m in &members {
        let verified_via = member_verified_via(&state, m).await?;
        member_views.push(MemberPublicView::from_row_masked(m, verified_via));
    }
    Ok(Json(DetailResponse {
        group: GroupPublicView::from_row(&group),
        members: member_views,
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
    let mut member_views = Vec::with_capacity(members.len());
    for m in &members {
        let verified_via = member_verified_via(&state, m).await?;
        member_views.push(MemberPublicView::from_row_for_viewer(
            m,
            &viewer,
            verified_via,
        ));
    }
    Ok(Json(DetailResponse {
        group: GroupPublicView::from_row(&group),
        members: member_views,
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

// ─── Self-service join link ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinLinkBody {
    ttl_days: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinLinkResponse {
    token: String,
}

/// `POST /api/blockparty/:id/join-link` (admin) — create/replace the group's
/// single self-service join link. UI builds `/blockparty/join/<token>` from it.
async fn create_join_link<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<JoinLinkBody>,
) -> Result<Json<JoinLinkResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let token = svc
        .create_join_link(id, body.ttl_days, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(JoinLinkResponse { token }))
}

/// `DELETE /api/blockparty/:id/join-link` (admin) — revoke the join link.
async fn revoke_join_link<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    svc.revoke_join_link(id, admin_token(&headers).as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActiveJoinLinkResponse {
    active: bool,
    token: Option<String>,
    expires_at: Option<i64>,
}

/// `GET /api/blockparty/:id/join-link` (admin) — the group's active join link,
/// so the admin UI can re-display the shareable link + expiry without minting a
/// fresh one. `{ active: false }` when none / expired.
async fn active_join_link<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ActiveJoinLinkResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let active = svc
        .active_join_link(id, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(match active {
        Some((token, expires_at)) => ActiveJoinLinkResponse {
            active: true,
            token: Some(token),
            expires_at: Some(expires_at),
        },
        None => ActiveJoinLinkResponse {
            active: false,
            token: None,
            expires_at: None,
        },
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinContextResponse {
    group_id: Uuid,
    group_name: String,
    expires_at: i64,
}

/// `GET /api/blockparty/join/:token` (public) — the join landing page context.
async fn get_join_context<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
) -> Result<Json<JoinContextResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let (group, expires_at) = svc
        .join_link_group(&token)
        .await?
        .ok_or_else(|| ApiError::from(bp_blockparty_engine::BlockpartyServiceError::NotFound))?;
    Ok(Json(JoinContextResponse {
        group_id: group.id,
        group_name: group.name,
        expires_at,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinBody {
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinResponse {
    member_token: String,
    group_id: Uuid,
}

/// `POST /api/blockparty/join/:token` (public) — self-join. Address proves itself
/// (email OR signature); returns the one-shot member token + group id.
async fn join_via_link<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
    Json(body): Json<JoinBody>,
) -> Result<Json<JoinResponse>, ApiError>
where
    H: bp_group_mgmt_engine::GroupServiceHooks + 'static,
    M: bp_group_mgmt_engine::EmailHooks + 'static,
{
    let svc = require_blockparty(&state)?;
    let (member_token, group_id) = svc.join_via_link(&token, &body.address).await?;
    Ok(Json(JoinResponse {
        member_token,
        group_id,
    }))
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
        let dto = MemberPublicView::from_row_masked(&row, Some("email"));
        let json = serde_json::to_value(&dto).unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            r#"{
                "address": "bc1q307hujcervvdfr73ntlam2f7w65j6gs9zcnf39",
                "email": "m***@y***.ch",
                "percentBp": 2500,
                "role": "member",
                "confirmed": true,
                "verifiedVia": "email"
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
