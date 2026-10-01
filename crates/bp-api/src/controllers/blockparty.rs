// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/blockparty/*` — Blockparty mining mode endpoints.
//!
//! Every mutation returns `{ "ok": true }` JSON rather than 204 NoContent
//! because the UI reads `response.ok === true` after parsing.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, patch, post},
    Router,
};
use bp_common::AddressId;
use bp_db::{
    BlockpartyBlockHistoryRow, BlockpartyGroupRow, BlockpartyMemberRow, BlockpartySplitSnapshot,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;
use crate::utils::{build_member_labels, member_id};
use bp_group_mgmt_engine::OpenInviteTtl;

// ─── DTOs (camelCase JSON, ms-epoch i64 timestamps) ───────────────

/// Public group shape, without `updatedAt` or the admin-token hash.
/// `adminAddress` stays public on purpose: the party mines on it and members
/// point rented hashrate at it. Member payout addresses are what the roster
/// pseudonymises.
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
    /// When the admin requested member confirmation (button next to Save
    /// Splits). `null` → the member dashboard suppresses the confirm prompt.
    confirmation_requested_at: Option<i64>,
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
            confirmation_requested_at: r.confirmation_requested_at,
        }
    }
}

/// Member shape of `GET /:id` and `member-view`, pseudonymised like the
/// Group-Solo roster: opaque `memberId` + masked `addressLabel`, the full
/// address only for an admin-token caller. Otherwise one known on-chain member
/// address would open the whole roster via `by-address`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberPublicView {
    member_id: String,
    address_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// True only for the viewer's own row (`?viewer=` or the member-view
    /// address).
    is_self: bool,
    /// Masked, except the viewer's own in `member-view` (token-proven).
    email: String,
    percent_bp: i32,
    role: String,
    confirmed: bool,
    /// How the member proved ownership: `"email"` or `"signature"`; `None`
    /// when no verification is on record.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_via: Option<&'static str>,
}

/// Who is looking at a roster, and what that lets them see.
struct RosterViewer<'a> {
    /// Flags this member's row `isSelf`.
    address: Option<&'a AddressId>,
    /// Admin-token caller: full addresses.
    is_admin: bool,
    /// Member-token caller: their own email unmasked.
    own_email: bool,
}

fn member_views(
    group_id: Uuid,
    members: &[BlockpartyMemberRow],
    owned: &std::collections::HashSet<String>,
    viewer: &RosterViewer<'_>,
) -> Vec<MemberPublicView> {
    let addrs: Vec<String> = members
        .iter()
        .map(|m| m.address.as_str().to_owned())
        .collect();
    let labels = build_member_labels(&addrs);
    members
        .iter()
        .map(|m| {
            let addr = m.address.as_str();
            let is_self = viewer.address == Some(&m.address);
            MemberPublicView {
                member_id: member_id(group_id, addr),
                address_label: labels
                    .get(addr)
                    .cloned()
                    .unwrap_or_else(|| bp_common::short_address(addr)),
                address: viewer.is_admin.then(|| addr.to_owned()),
                is_self,
                email: if is_self && viewer.own_email {
                    m.email.clone()
                } else {
                    mask_email(&m.email)
                },
                percent_bp: m.percent_bp,
                role: m.role.clone(),
                confirmed: m.confirmed_at.is_some(),
                verified_via: verified_via_for(m, owned),
            }
        })
        .collect()
}

/// The email-less member addresses that have an ownership proof, in one
/// query instead of one per member.
async fn ownership_set_for_members(
    state: &SharedState,
    members: &[BlockpartyMemberRow],
) -> Result<std::collections::HashSet<String>, ApiError> {
    let addrs: Vec<String> = members
        .iter()
        .filter(|m| m.email.trim().is_empty())
        .map(|m| m.address.as_str().to_owned())
        .collect();
    Ok(bp_db::addresses_with_ownership_proof(&state.pool, &addrs).await?)
}

/// Verification method for a member given the pre-fetched ownership set — a
/// non-empty snapshot email reads as `"email"`; otherwise a signature proof
/// reads as `"signature"`. `None` when neither is on record.
fn verified_via_for(
    m: &BlockpartyMemberRow,
    owned: &std::collections::HashSet<String>,
) -> Option<&'static str> {
    if !m.email.trim().is_empty() {
        Some("email")
    } else if owned.contains(m.address.as_str()) {
        Some("signature")
    } else {
        None
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
/// specification.
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

fn require_blockparty(
    state: &SharedState,
) -> Result<&bp_blockparty_engine::BlockpartyService, ApiError> {
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

pub(crate) fn routes() -> Router<SharedState> {
    Router::new()
        // ── Reads ────────────────────────────────────────────────
        // NB: no public directory listing — blockparty is invite-only, so the
        // group id is not enumerable. Detail/by-address need the id up front.
        .route("/api/blockparty/by-address/:address", get(by_address))
        .route("/api/blockparty/:id", get(detail))
        .route("/api/blockparty/:id/history", get(history))
        .route("/api/blockparty/:id/admin-check", get(admin_check))
        .route("/api/blockparty/:id/member-view/:address", get(member_view))
        // ── Admin lifecycle ──────────────────────────────────────
        .route("/api/blockparty", post(create))
        .route("/api/blockparty/:id/splits", patch(update_splits))
        .route(
            "/api/blockparty/:id/request-confirmation",
            post(request_confirmation),
        )
        .route("/api/blockparty/:id/rental-hint", patch(update_rental_hint))
        .route(
            "/api/blockparty/:id/join-link",
            get(active_join_link)
                .post(create_join_link)
                .delete(revoke_join_link),
        )
        .route(
            // Public self-service join — throttled per client IP (matches the
            // group-solo open-invite accept). Covers both the POST join (DB
            // write + member-token mint) and the GET context (token probing).
            "/api/blockparty/join/:token",
            get(get_join_context)
                .post(join_via_link)
                .layer(rate_limit::per_minute_layer(10)),
        )
        .route(
            "/api/blockparty/:id/members/:address",
            delete(remove_member),
        )
        .route(
            "/api/blockparty/:id/transition-confirming",
            post(transition_confirming),
        )
        .route("/api/blockparty/:id/dissolve", post(dissolve))
        // ── Member-token gated ───────────────────────────────────
        .route(
            "/api/blockparty/:id/members/:address/reconfirm",
            post(reconfirm_member),
        )
}

// ─── Read handlers ─────────────────────────────────────────────────

/// `{ groupId: null }` when no party found for this address;
/// `{ groupId, groupName, status, role }` when matched.
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

async fn by_address(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<ByAddressResponse>, ApiError> {
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

#[derive(Deserialize)]
struct ViewerQuery {
    /// The viewer's own address (already in the UI route). Only flags that
    /// member's row `isSelf` — never echoed back for other members.
    viewer: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetailResponse {
    #[serde(flatten)]
    group: GroupPublicView,
    members: Vec<MemberPublicView>,
}

async fn detail(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(q): Query<ViewerQuery>,
    headers: HeaderMap,
) -> Result<Json<DetailResponse>, ApiError> {
    let svc = require_blockparty(&state)?;
    let token = admin_token(&headers);
    let is_admin = match token.as_deref() {
        None => false,
        Some(t) => {
            svc.require_admin_token(id, Some(t)).await?;
            true
        }
    };
    let viewer = q
        .viewer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize)
        .transpose()?;
    let group = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
    let members = svc.list_members(id).await?;
    let owned = ownership_set_for_members(&state, &members).await?;
    let viewer = RosterViewer {
        address: viewer.as_ref(),
        is_admin,
        own_email: false,
    };
    Ok(Json(DetailResponse {
        group: GroupPublicView::from_row(&group),
        members: member_views(id, &members, &owned, &viewer),
    }))
}

/// 204 when `x-blockparty-admin-token` is this party's admin token; 401 when
/// missing or wrong, 404 for an unknown or dissolved party. Same contract as
/// `GET /api/pplns/groups/:id/admin-check`.
async fn admin_check(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_blockparty(&state)?
        .require_admin_token(id, admin_token(&headers).as_deref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn history(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<HistoryRowView>>, ApiError> {
    let svc = require_blockparty(&state)?;
    let rows = svc.get_history(id).await?;
    Ok(Json(rows.into_iter().map(HistoryRowView::from).collect()))
}

async fn member_view(
    State(state): State<SharedState>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<DetailResponse>, ApiError> {
    let svc = require_blockparty(&state)?;
    let viewer = normalize(&address)?;
    svc.require_member_token(id, &viewer, member_token(&headers).as_deref())
        .await?;
    let group = svc.get_group(id).await?.ok_or(ApiError::NotFound)?;
    let members = svc.list_members(id).await?;
    let owned = ownership_set_for_members(&state, &members).await?;
    let roster_viewer = RosterViewer {
        address: Some(&viewer),
        is_admin: false,
        own_email: true,
    };
    Ok(Json(DetailResponse {
        group: GroupPublicView::from_row(&group),
        members: member_views(id, &members, &owned, &roster_viewer),
    }))
}

// ─── Admin lifecycle handlers ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    name: String,
    admin_address: String,
    admin_percent_bp: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateResponse {
    group: GroupPublicView,
    /// Plaintext admin token — shown to the creator exactly once.
    admin_token: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    pool_fee_percent: f64,
}

async fn create(
    State(state): State<SharedState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<CreateResponse>, ApiError> {
    let svc = require_blockparty(&state)?;
    let res = svc
        .create_group(&body.name, &body.admin_address, body.admin_percent_bp)
        .await?;
    Ok(Json(CreateResponse {
        group: GroupPublicView::from_row(&res.group),
        admin_token: res.admin_token,
        pool_fee_percent: res.pool_fee_percent,
    }))
}

/// `POST /api/blockparty/:id/request-confirmation` (admin) — signal that
/// members may now confirm their split (button next to Save Splits). Flips the
/// group's `confirmationRequestedAt` so the member dashboard starts surfacing
/// the confirm prompt.
async fn request_confirmation(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError> {
    let svc = require_blockparty(&state)?;
    svc.request_member_confirmation(id, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

async fn dissolve(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError> {
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
async fn update_rental_hint(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<RentalHintBody>,
) -> Result<Json<RentalHintResponse>, ApiError> {
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

async fn update_splits(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateSplitsBody>,
) -> Result<Json<&'static Ok>, ApiError> {
    let svc = require_blockparty(&state)?;
    let mut updates = Vec::with_capacity(body.splits.len());
    for s in body.splits {
        updates.push((normalize(&s.address)?, s.percent_bp));
    }
    svc.update_splits(id, &updates, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

// ─── Self-service join link ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinLinkBody {
    ttl: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinLinkResponse {
    token: String,
}

/// `POST /api/blockparty/:id/join-link` (admin) — create/replace the group's
/// single self-service join link. UI builds `/blockparty/join/<token>` from it.
async fn create_join_link(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<JoinLinkBody>,
) -> Result<Json<JoinLinkResponse>, ApiError> {
    let ttl = OpenInviteTtl::parse(&body.ttl).ok_or(ApiError::Invitation {
        code: "invalid-ttl",
        status: StatusCode::BAD_REQUEST,
    })?;
    let svc = require_blockparty(&state)?;
    let token = svc
        .create_join_link(id, ttl, admin_token(&headers).as_deref())
        .await?;
    Ok(Json(JoinLinkResponse { token }))
}

/// `DELETE /api/blockparty/:id/join-link` (admin) — revoke the join link.
async fn revoke_join_link(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
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
async fn active_join_link(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ActiveJoinLinkResponse>, ApiError> {
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
async fn get_join_context(
    State(state): State<SharedState>,
    Path(token): Path<String>,
) -> Result<Json<JoinContextResponse>, ApiError> {
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
async fn join_via_link(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    Json(body): Json<JoinBody>,
) -> Result<Json<JoinResponse>, ApiError> {
    let svc = require_blockparty(&state)?;
    let (member_token, group_id) = svc.join_via_link(&token, &body.address).await?;
    Ok(Json(JoinResponse {
        member_token,
        group_id,
    }))
}

async fn remove_member(
    State(state): State<SharedState>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError> {
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

async fn transition_confirming(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TransitionResponse>, ApiError> {
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

async fn reconfirm_member(
    State(state): State<SharedState>,
    Path((id, address)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<&'static Ok>, ApiError> {
    let svc = require_blockparty(&state)?;
    let addr = normalize(&address)?;
    svc.confirm_as_member(id, &addr, member_token(&headers).as_deref())
        .await?;
    Ok(Json(&OK))
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the DTOs' serialized JSON shapes, which the UI binds on by field
    /// name and type.
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
            confirmation_requested_at: None,
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
                "rentalProviderHint": null,
                "confirmationRequestedAt": null
            }"#,
        )
        .unwrap();
        assert_eq!(json, expected);
    }

    fn member_row(address: &str, email: &str) -> BlockpartyMemberRow {
        BlockpartyMemberRow {
            id: 42,
            group_id: Uuid::parse_str("219eba31-19ac-4f3c-b97a-f50ee3f02b96").unwrap(),
            address: AddressId::new(address).unwrap(),
            email: email.to_owned(),
            percent_bp: 2500,
            role: "member".to_owned(),
            confirmed_at: Some(1_779_464_900_000),
            member_token_hash: Some("internal".to_owned()),
            created_at: 0,
            updated_at: 0,
        }
    }

    const ALICE: &str = "bc1q307hujcervvdfr73ntlam2f7w65j6gs9zcnf39";
    const BOB: &str = "bc1qywnf55acqpxr0lekg2gmy2s46pzxqze99j0u9y";

    fn roster(viewer: &RosterViewer<'_>) -> Vec<serde_json::Value> {
        let gid = Uuid::parse_str("219eba31-19ac-4f3c-b97a-f50ee3f02b96").unwrap();
        let members = [
            member_row(ALICE, "mvogel@yahoo.ch"),
            member_row(BOB, "bob@example.com"),
        ];
        member_views(gid, &members, &Default::default(), viewer)
            .iter()
            .map(|v| serde_json::to_value(v).unwrap())
            .collect()
    }

    #[test]
    fn anonymous_roster_carries_no_full_address() {
        let alice = AddressId::new(ALICE).unwrap();
        let rows = roster(&RosterViewer {
            address: Some(&alice),
            is_admin: false,
            own_email: false,
        });
        let gid = Uuid::parse_str("219eba31-19ac-4f3c-b97a-f50ee3f02b96").unwrap();
        let expected: serde_json::Value = serde_json::json!({
            "memberId": member_id(gid, ALICE),
            "addressLabel": bp_common::short_address(ALICE),
            "isSelf": true,
            "email": "m***@y***.ch",
            "percentBp": 2500,
            "role": "member",
            "confirmed": true,
            "verifiedVia": "email"
        });
        assert_eq!(rows[0], expected);
        assert_eq!(rows[1]["isSelf"], false);
        for row in &rows {
            assert!(row.get("address").is_none(), "leaked: {row}");
            assert!(!row.to_string().contains(&ALICE[8..]), "leaked: {row}");
            assert!(!row.to_string().contains(&BOB[8..]), "leaked: {row}");
        }
    }

    #[test]
    fn member_view_unmasks_only_the_viewers_own_email() {
        let alice = AddressId::new(ALICE).unwrap();
        let rows = roster(&RosterViewer {
            address: Some(&alice),
            is_admin: false,
            own_email: true,
        });
        assert_eq!(rows[0]["email"], "mvogel@yahoo.ch");
        assert_eq!(rows[1]["email"], "b***@e***.com");
        assert!(rows.iter().all(|r| r.get("address").is_none()));
    }

    #[test]
    fn admin_roster_carries_full_addresses() {
        let rows = roster(&RosterViewer {
            address: None,
            is_admin: true,
            own_email: false,
        });
        assert_eq!(rows[0]["address"], ALICE);
        assert_eq!(rows[1]["address"], BOB);
        assert!(rows.iter().all(|r| r["isSelf"] == false));
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
