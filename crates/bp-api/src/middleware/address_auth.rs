// SPDX-License-Identifier: AGPL-3.0-or-later

//! Address tokens for the routes that act for one address: deleting its
//! statistics, binding its email, and putting it into a Team or Blockparty.
//! The UI's session sidecar issues them with its `SESSION_TOKEN_SECRET`; a
//! token proves control of exactly one address until it expires.
//!
//! The format is the sidecar's and must stay byte-compatible with it:
//! `Authorization: Bearer <payload>.<sig>`, where `payload` is unpadded
//! base64url of the UTF-8 JSON `{"a": <address key>, "e": <expiry, epoch ms>}`
//! and `sig` is unpadded base64url of HMAC-SHA256 keyed with the secret over
//! the payload *string*. Account tokens (`acct` instead of `a`) prove no
//! address here.
//!
//! The check is on only with `[api.address_auth] enabled = true`, so a pool
//! without the sidecar keeps these routes open; enabled, the api does not
//! start without the secret.

use std::collections::HashMap;
use std::fmt;

use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::Response,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::ApiError;
use crate::state::{AppState, SharedState};

/// The HMAC key the sidecar signs address tokens with.
#[derive(Clone)]
pub struct AddressTokenSecret(String);

impl AddressTokenSecret {
    /// Trimmed as the sidecar trims it; a blank value is no secret.
    pub fn new(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| Self(trimmed.to_string()))
    }

    fn sign(&self, payload: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(payload.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// The address key `token` is bound to, if its signature holds and it
    /// has not expired at `now_ms`.
    fn token_address_key(&self, token: &str, now_ms: i64) -> Option<String> {
        let (payload, sig) = token.split_once('.')?;
        if payload.is_empty() {
            return None;
        }
        if !bool::from(sig.as_bytes().ct_eq(self.sign(payload).as_bytes())) {
            return None;
        }
        let json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        let expires_at = json.get("e")?.as_f64()?;
        if expires_at < now_ms as f64 {
            return None;
        }
        json.get("a")?.as_str().map(str::to_string)
    }
}

impl fmt::Debug for AddressTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressTokenSecret(..)")
    }
}

/// Whether the routes that act for one address require its token.
#[derive(Clone, Debug, Default)]
pub enum AddressAuth {
    /// Every request is let through.
    #[default]
    Off,
    /// Only a request carrying the address's token signed with this secret.
    Required(AddressTokenSecret),
}

/// The key a token names its address by, as the sidecar's `ownerOf` builds
/// it: the part before the first `.`, lowercased whole. Base58 is lowercased
/// too, so it is a lookup key and not an address.
pub fn address_key(address_or_worker: &str) -> String {
    address_or_worker
        .split('.')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let scheme = value.get(..6)?;
    let rest = &value[6..];
    if !scheme.eq_ignore_ascii_case("bearer") || !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

/// Pass only a request whose bearer token is bound to `target`.
pub fn authorize(
    secret: &AddressTokenSecret,
    headers: &HeaderMap,
    target: &str,
    now_ms: i64,
) -> Result<(), ApiError> {
    let bound = bearer(headers).and_then(|token| secret.token_address_key(token, now_ms));
    match bound {
        Some(key) if key == address_key(target) => Ok(()),
        _ => Err(ApiError::LoginRequired),
    }
}

/// [`authorize`] when the check is on, for a handler whose address comes in
/// the request body.
pub fn require_address_token(
    state: &AppState,
    headers: &HeaderMap,
    address: &str,
) -> Result<(), ApiError> {
    match &state.address_auth {
        AddressAuth::Off => Ok(()),
        AddressAuth::Required(secret) => authorize(secret, headers, address, bp_common::now_ms()),
    }
}

/// [`require_address_token`] against the `{address}` path parameter.
pub async fn require_address(
    State(state): State<SharedState>,
    Path(params): Path<HashMap<String, String>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let target = params.get("address").ok_or(ApiError::LoginRequired)?;
    require_address_token(&state, request.headers(), target)?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // Issued by the sidecar's own algorithm with this secret.
    const SECRET: &str = "test-secret-for-bp-api";
    const VALID: &str = "eyJhIjoiYmMxcXRva2VudmVjdG9yYWRkcmVzcyIsImUiOjQxMDI0NDQ4MDAwMDB9.bG_liAI04HABECVjbYh-FutN61qwWXhMmph4R6AZlts";
    const VALID_BASE58: &str = "eyJhIjoiMWJ2Ym1zZXlzdHdldHF0Zm41YXU0bTRnZmc3eGphbnZuMiIsImUiOjQxMDI0NDQ4MDAwMDB9.ZCOb5F4HvrtHwXDIJ6mLdvSMw-AlXQlrNPKLfr9kmss";
    const EXPIRED: &str = "eyJhIjoiYmMxcXRva2VudmVjdG9yYWRkcmVzcyIsImUiOjEwMDB9.7xQ1LDXx9V6e61DJIJ8v3RVwEgG221JRRJbzk2yDHwc";
    const ACCOUNT: &str = "eyJhY2N0IjoiMDJhYmMiLCJlIjo0MTAyNDQ0ODAwMDAwfQ.9RvDIeR-pfWTnaK1-gQv_gQdL-5Ou7qotLbNk-KDzBM";
    const ADDRESS: &str = "bc1qtokenvectoraddress";
    const NOW: i64 = 1_800_000_000_000;

    fn secret() -> AddressTokenSecret {
        AddressTokenSecret::new(SECRET).unwrap()
    }

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    fn passes(value: &str, target: &str) -> bool {
        authorize(&secret(), &headers(value), target, NOW).is_ok()
    }

    #[test]
    fn a_sidecar_token_passes_for_its_own_address_only() {
        assert!(passes(&format!("Bearer {VALID}"), ADDRESS));
        assert!(!passes(&format!("Bearer {VALID}"), "bc1qsomeoneelse"));
    }

    #[test]
    fn the_target_is_keyed_like_the_sidecar() {
        assert!(passes(
            &format!("Bearer {VALID_BASE58}"),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        ));
        assert!(passes(
            &format!("Bearer {VALID}"),
            "BC1QTOKENVECTORADDRESS.rig1"
        ));
        assert_eq!(address_key("1BvB.rig.x"), "1bvb");
    }

    #[test]
    fn expired_account_and_forged_tokens_fail() {
        assert!(!passes(&format!("Bearer {EXPIRED}"), ADDRESS));
        assert!(!passes(&format!("Bearer {ACCOUNT}"), "02abc"));
        let (payload, sig) = VALID.split_once('.').unwrap();
        let mut flipped = sig.to_string();
        flipped.replace_range(..1, if sig.starts_with('A') { "B" } else { "A" });
        assert!(!passes(&format!("Bearer {payload}.{flipped}"), ADDRESS));
        assert!(!passes(&format!("Bearer {payload}."), ADDRESS));
        assert!(!passes(&format!("Bearer {payload}"), ADDRESS));
    }

    #[test]
    fn a_token_signed_with_another_secret_fails() {
        let other = AddressTokenSecret::new("another-secret").unwrap();
        assert!(authorize(&other, &headers(&format!("Bearer {VALID}")), ADDRESS, NOW).is_err());
    }

    #[test]
    fn the_secret_is_trimmed_and_a_blank_one_is_none() {
        let padded = AddressTokenSecret::new(&format!("  {SECRET}\n")).unwrap();
        assert!(authorize(&padded, &headers(&format!("Bearer {VALID}")), ADDRESS, NOW).is_ok());
        assert!(AddressTokenSecret::new(" \t").is_none());
    }

    #[test]
    fn without_a_bearer_header_everything_fails() {
        assert!(authorize(&secret(), &HeaderMap::new(), ADDRESS, NOW).is_err());
        assert!(!passes(VALID, ADDRESS));
        assert!(!passes(&format!("Basic {VALID}"), ADDRESS));
        assert!(!passes(&format!("Bearer{VALID}"), ADDRESS));
    }

    #[test]
    fn the_scheme_is_case_insensitive_like_the_sidecar() {
        assert!(passes(&format!("bearer  {VALID} "), ADDRESS));
    }

    #[test]
    fn expiry_is_inclusive_like_the_sidecar() {
        let expires_at = 4_102_444_800_000;
        assert!(authorize(
            &secret(),
            &headers(&format!("Bearer {VALID}")),
            ADDRESS,
            expires_at
        )
        .is_ok());
        assert!(authorize(
            &secret(),
            &headers(&format!("Bearer {VALID}")),
            ADDRESS,
            expires_at + 1
        )
        .is_err());
    }
}
