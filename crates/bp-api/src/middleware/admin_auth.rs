// SPDX-License-Identifier: AGPL-3.0-or-later

//! `x-admin-token` validation middleware.
//!
//! Mounted on routes whose path includes `:id` (= group UUID). The
//! middleware reads the token from the `x-admin-token` header, looks
//! up the addressed group via `GroupService::require_admin_token`,
//! and on success injects an [`AdminAuth`] request extension that
//! downstream handlers can pull out with `Extension(AdminAuth { .. })`
//! if they care about the validated group_id.
//!
//! On failure the middleware short-circuits with the appropriate
//! [`ApiError`]:
//! - missing/invalid header → 401 `missing-token`
//! - service not wired      → 503 `upstream-unavailable`
//! - service rejects token  → 401/404 per [`GroupServiceError`]
//!
//! `POST /api/pplns/groups/:id/...` paths are all protected with a
//! per-group admin-token guard; this middleware collapses that single
//! concern into one layer rather than repeating the
//! `GroupService::require_admin_token` call at every handler.

use std::collections::HashMap;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::SharedState;

/// Request extension inserted by [`require_admin`]. Handlers behind
/// the middleware can pull this out with the standard axum
/// `Extension<AdminAuth>` extractor when they need the validated
/// group_id or want to thread the token onward (the service-layer
/// methods still take `Option<&str>` and re-validate as defence-in-
/// depth — they aren't aware of the middleware).
#[derive(Clone, Debug)]
pub struct AdminAuth {
    pub group_id: Uuid,
    /// The token string as supplied in the `x-admin-token` header.
    /// Already validated against `group_id` by [`require_admin`].
    pub admin_token: String,
}

/// Tower middleware: pre-validate the `x-admin-token` header against
/// the `:id` path parameter using `GroupService::require_admin_token`.
///
/// Applied via `axum::middleware::from_fn_with_state(state.clone(),
/// require_admin::<H, M>)` on the admin-only sub-router. Reading
/// `Path<HashMap<String, String>>` here is intentional: the bound
/// routes have different path shapes (`:id`, `:id/members/:address`,
/// `:id/join-requests/:req_id/...`) so a typed `Path<Uuid>` would
/// reject the multi-segment ones. The handlers each still extract
/// their own typed `Path<…>`; axum's URL params are stored as a
/// shared extension and can be deserialised multiple times per
/// request.
pub async fn require_admin<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let svc = state
        .group_service
        .as_deref()
        .ok_or(ApiError::Unavailable("group-service not wired"))?;
    let group_id_str = params.get("id").ok_or(ApiError::NotFound)?;
    let group_id = Uuid::parse_str(group_id_str).map_err(|_| ApiError::NotFound)?;
    let token = request
        .headers()
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(ApiError::GroupService {
            code: "missing-token",
            status: StatusCode::UNAUTHORIZED,
        })?;
    svc.require_admin_token(group_id, Some(&token)).await?;
    request.extensions_mut().insert(AdminAuth {
        group_id,
        admin_token: token,
    });
    Ok(next.run(request).await)
}
