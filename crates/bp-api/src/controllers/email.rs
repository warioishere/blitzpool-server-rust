// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/email/*` — register-verify flow for address↔email bindings.
//!
//! The verified-email binding is the trust anchor for the whole
//! invitation flow (memory `feedback-bp-api-ts-100-percent-parity`),
//! so the JSON shapes here are part of the cut-over surface.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use base64::Engine;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};

use crate::email_hooks::{BindingChangeContext, VerificationContext};
use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;

const VERIFICATION_TTL_HOURS: i64 = 24;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route(
            // Rate-limited: 5 register attempts per minute per client IP.
            "/api/email/register",
            post(register::<H, M>).layer(rate_limit::per_minute_layer(5)),
        )
        .route("/api/email/verify/:token", get(verify::<H, M>))
        .route("/api/email/by-address/:address", get(by_address::<H, M>))
}

// ─── POST /api/email/register ────────────────────────────────────

/// Request: `{address, email}`. Response: `{ok, verificationSent}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    address: String,
    email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterResponse {
    ok: bool,
    verification_sent: bool,
}

async fn register<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<RegisterBody>,
) -> Result<Json<RegisterResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Canonicalise (lowercase bech32, preserve Base58) so the binding is keyed
    // identically to what every verification gate looks up — otherwise a
    // mixed-case Base58 / upper-case bech32 email binding would never match.
    let address = crate::utils::normalized_address_id(&body.address)
        .map_err(|_| email_error("invalid-address", StatusCode::BAD_REQUEST))?;
    let email = body.email.trim().to_ascii_lowercase();
    if !is_email_shape(&email) {
        return Err(email_error("invalid-email", StatusCode::BAD_REQUEST));
    }
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
    let base_url = base_url.trim_end_matches('/');

    // FCFS-lock — same address with a verified DIFFERENT email refuses
    // + notifies the bound email.
    if let Some(existing) = bp_db::find_address_email(&state.pool, &address).await? {
        if existing.verified_at.is_some() && !existing.email.eq_ignore_ascii_case(&email) {
            // Fire-and-forget the notification. Failure must NOT change
            // the refusal outcome.
            state
                .email_verification_hooks
                .send_binding_change_attempt(BindingChangeContext {
                    to_email: existing.email.clone(),
                    address: address.as_str().to_string(),
                    attempted_email_masked: mask_email(&email),
                })
                .await;
            return Err(email_error("already-bound", StatusCode::CONFLICT));
        }
    }

    // Drop any pending tokens for this address — only the most recent
    // is valid.
    bp_db::delete_email_verifications_for_address(&state.pool, &address).await?;

    let token = generate_token();
    let now = crate::time_range::now_ms();
    let expires_at = now + VERIFICATION_TTL_HOURS * 60 * 60 * 1000;
    bp_db::insert_email_verification(&state.pool, &token, &address, &email, now, expires_at)
        .await?;
    let verify_url = format!("{base_url}/#/email/verify/{token}");
    state
        .email_verification_hooks
        .send_verification(VerificationContext {
            to_email: email,
            address: address.as_str().to_string(),
            verify_url,
            expires_at_ms: expires_at,
        })
        .await;
    Ok(Json(RegisterResponse {
        ok: true,
        verification_sent: true,
    }))
}

// ─── GET /api/email/verify/:token ────────────────────────────────

/// Response: `{address, email, verifiedAt}` (verifiedAt is ISO).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    address: String,
    email: String,
    verified_at: String,
}

async fn verify<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(token): Path<String>,
) -> Result<Json<VerifyResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let pending = bp_db::find_email_verification(&state.pool, &token)
        .await?
        .ok_or_else(|| email_error("not-found", StatusCode::NOT_FOUND))?;
    let now = crate::time_range::now_ms();
    if pending.expires_at < now {
        bp_db::delete_email_verification_by_token(&state.pool, &token).await?;
        return Err(email_error("expired", StatusCode::GONE));
    }
    // Defense-in-depth FCFS-lock: refuse to overwrite a verified
    // binding with a different email even if a stale token squeaked
    // through.
    if let Some(existing) = bp_db::find_address_email(&state.pool, &pending.address).await? {
        if existing.verified_at.is_some() && !existing.email.eq_ignore_ascii_case(&pending.email) {
            bp_db::delete_email_verification_by_token(&state.pool, &token).await?;
            return Err(email_error("already-bound", StatusCode::CONFLICT));
        }
    }
    let saved =
        bp_db::upsert_address_email_verified(&state.pool, &pending.address, &pending.email, now)
            .await?;
    // Consume + clear stale tokens for the same address.
    bp_db::delete_email_verifications_for_address(&state.pool, &pending.address).await?;
    Ok(Json(VerifyResponse {
        address: saved.address.as_str().to_string(),
        email: saved.email,
        verified_at: crate::time_range::format_iso_ms(saved.verified_at.unwrap_or(now)),
    }))
}

// ─── GET /api/email/by-address/:address ──────────────────────────

/// Response: `{email: maskedOrNull, verifiedAt: isoOrNull}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ByAddressResponse {
    email: Option<String>,
    verified_at: Option<String>,
}

async fn by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<ByAddressResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Invalid address returns the empty shape since the lookup
    // naturally returns null (no 4xx on bad address). Canonicalise so the
    // lookup key matches the (canonical) stored binding.
    let Ok(addr) = crate::utils::normalized_address_id(&address) else {
        return Ok(Json(ByAddressResponse {
            email: None,
            verified_at: None,
        }));
    };
    let row = bp_db::find_address_email(&state.pool, &addr).await?;
    let Some(binding) = row.filter(|b| b.verified_at.is_some()) else {
        return Ok(Json(ByAddressResponse {
            email: None,
            verified_at: None,
        }));
    };
    Ok(Json(ByAddressResponse {
        email: Some(mask_email(&binding.email)),
        verified_at: binding.verified_at.map(crate::time_range::format_iso_ms),
    }))
}

// ─── helpers ────────────────────────────────────────────────────

fn email_error(code: &'static str, status: StatusCode) -> ApiError {
    // Reuse the GroupService error variant as a generic "wire-coded"
    // ApiError carrier. Status + code travel through to the JSON
    // envelope intact.
    ApiError::GroupService { code, status }
}

fn is_email_shape(s: &str) -> bool {
    // Sanity check: one @, dot in the domain. MX
    // validation happens at SMTP-send time.
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !local.contains(char::is_whitespace)
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.contains(char::is_whitespace)
}

fn mask_email(email: &str) -> String {
    crate::utils::mask_email(email)
}

fn generate_token() -> String {
    // 32 bytes = 256 bits, base64url-encoded → 43 chars (no padding),
    // URL-safe, fits in the 64-char `pplns_email_verification.token`
    // column with margin.
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
