// SPDX-License-Identifier: AGPL-3.0-or-later

//! `x-admin-token` validation for the `/api/pplns/groups/:id/...` admin
//! routes, in one layer instead of a check in every handler. On success it
//! injects [`AdminAuth`]; on failure it answers with the [`ApiError`].

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

/// Request extension inserted by [`require_admin`]. The service methods
/// still re-validate the token as defence in depth.
#[derive(Clone, Debug)]
pub struct AdminAuth {
    pub group_id: Uuid,
    /// The token string as supplied in the `x-admin-token` header.
    /// Already validated against `group_id` by [`require_admin`].
    pub admin_token: String,
}

/// Validate the `x-admin-token` header against the `:id` path parameter.
/// Reads `Path<HashMap<..>>` because the bound routes have different path
/// shapes, which a typed `Path<Uuid>` would reject.
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
