// SPDX-License-Identifier: AGPL-3.0-or-later

//! `POST /api/address/password-link`: an address with a verified email gets
//! a link carrying the address and its token, sent to that email, so its holder can
//! set the address's first password in the UI sidecar. The answer is the
//! same whether or not the address has such an email, so the endpoint does
//! not reveal the binding.

use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::controllers::address_ownership::parse_supported_address;
use crate::controllers::email::email_error;
use crate::email_hooks::AddressAccessContext;
use crate::error::ApiError;
use crate::middleware::address_auth::ISSUED_TOKEN_TTL_MS;
use crate::middleware::{rate_limit, AddressAuth};
use crate::state::SharedState;

/// At most one link per address in this window, so a caller rotating IPs
/// cannot flood the bound inbox.
const PER_ADDRESS_COOLDOWN: Duration = Duration::from_secs(5 * 60);

static RECENTLY_SENT: Lazy<Cache<String, ()>> = Lazy::new(|| {
    Cache::builder()
        .time_to_live(PER_ADDRESS_COOLDOWN)
        .max_capacity(100_000)
        .build()
});

pub(crate) fn routes() -> Router<SharedState> {
    Router::new().route(
        // Rate-limited: 5 requests per minute per client IP.
        "/api/address/password-link",
        post(password_link).layer(rate_limit::per_minute_layer(5)),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordLinkBody {
    address: String,
}

#[derive(Serialize)]
struct PasswordLinkResponse {
    sent: bool,
}

async fn password_link(
    State(state): State<SharedState>,
    Json(body): Json<PasswordLinkBody>,
) -> Result<Json<PasswordLinkResponse>, ApiError> {
    let AddressAuth::Required(secret) = &state.address_auth else {
        return Err(email_error(
            "address-auth-disabled",
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    };
    if !state.email_enabled {
        return Err(email_error(
            "email-disabled",
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    let Some(base_url) = state.pool_base_url.as_deref() else {
        return Err(email_error(
            "config-missing",
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    };
    // A real address of the pool's network, so the link can carry it as a
    // plain path segment: its characters are all alphanumeric.
    let address = parse_supported_address(&body.address, state.network)?;

    let bound = bp_db::find_address_email(&state.pool, &address)
        .await?
        .filter(|b| b.verified_at.is_some());
    if let Some(binding) = bound {
        if !RECENTLY_SENT.contains_key(address.as_str()) {
            RECENTLY_SENT.insert(address.as_str().to_string(), ());
            let expires_at = bp_common::now_ms() + ISSUED_TOKEN_TTL_MS;
            let token = secret.issue(address.as_str(), expires_at);
            state
                .email_verification_hooks
                .send_address_access(AddressAccessContext {
                    to_email: binding.email,
                    address: address.as_str().to_string(),
                    access_url: format!(
                        "{}/#/address-access/{}/{token}",
                        base_url.trim_end_matches('/'),
                        address.as_str()
                    ),
                    expires_at_ms: expires_at,
                })
                .await;
        }
    }
    Ok(Json(PasswordLinkResponse { sent: true }))
}
