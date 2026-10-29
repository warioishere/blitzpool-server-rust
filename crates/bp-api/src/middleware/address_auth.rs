// SPDX-License-Identifier: AGPL-3.0-or-later

//! Address tokens for the routes that act for one address: deleting its
//! statistics, binding its email, and putting it into a Team or Blockparty.
//! The UI's session sidecar issues them with its `SESSION_TOKEN_SECRET`; a
//! token proves control of exactly one address until it expires.
//!
//! The format is the sidecar's and must stay byte-compatible with it:
//! `Authorization: Bearer <payload>.<sig>`, where `payload` is unpadded
//! base64url of the UTF-8 JSON `{"a": <address key>, "e": <expiry, epoch ms>,
//! "i": <issued, epoch ms>}` and `sig` is unpadded base64url of HMAC-SHA256
//! keyed with the secret over the payload *string*. Account tokens (`acct`
//! instead of `a`) prove no address here.
//!
//! A token is void once the sidecar has revoked its address key from a
//! moment after the token's issue. The sidecar pushes that moment as a
//! revocation, signed the same way over `{"rv": <address key>, "b": <revoked
//! before, epoch ms>, "e": <expiry, epoch ms>}`.
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

/// How long a token this api issues stays valid.
pub const ISSUED_TOKEN_TTL_MS: i64 = 60 * 60 * 1000;

/// A token without an issue time counts as issued this long before it
/// expires: the sidecar's token lifetime, early on purpose so that a
/// revocation covers it.
const UNSTAMPED_TOKEN_AGE_MS: f64 = 7.0 * 24.0 * 60.0 * 60.0 * 1000.0;

/// The HMAC key the sidecar signs address tokens with.
#[derive(Clone)]
pub struct AddressTokenSecret(String);

impl AddressTokenSecret {
    /// Trimmed as the sidecar trims it; a blank value is no secret.
    pub fn new(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| Self(trimmed.to_string()))
    }

    /// An address token for `address`, issued at `issued_at_ms` and valid
    /// until `expires_at_ms`, the same string the sidecar issues for it.
    pub fn issue(&self, address: &str, issued_at_ms: i64, expires_at_ms: i64) -> String {
        let key = serde_json::Value::from(address_key(address)).to_string();
        let claims = format!(r#"{{"a":{key},"e":{expires_at_ms},"i":{issued_at_ms}}}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims);
        let sig = self.sign(&payload);
        format!("{payload}.{sig}")
    }

    fn sign(&self, payload: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(payload.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// The claims of `token`, if its signature holds and it has not expired
    /// at `now_ms`.
    fn claims(&self, token: &str, now_ms: i64) -> Option<serde_json::Value> {
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
        (expires_at >= now_ms as f64).then_some(json)
    }

    /// The address key `token` is bound to and when it was issued.
    fn token_address_key(&self, token: &str, now_ms: i64) -> Option<(String, i64)> {
        let json = self.claims(token, now_ms)?;
        let key = json.get("a")?.as_str()?.to_string();
        let issued_at = match json.get("i") {
            Some(i) => i.as_f64()?,
            None => json.get("e")?.as_f64()? - UNSTAMPED_TOKEN_AGE_MS,
        };
        Some((key, issued_at as i64))
    }

    /// The address key a revocation names and the moment before which its
    /// tokens are void.
    fn revocation(&self, token: &str, now_ms: i64) -> Option<(String, i64)> {
        let json = self.claims(token, now_ms)?;
        let key = json.get("rv")?.as_str()?;
        let revoked_before = json.get("b")?.as_f64()?;
        (!key.is_empty()).then(|| (key.to_string(), revoked_before as i64))
    }
}

impl fmt::Debug for AddressTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressTokenSecret(..)")
    }
}

/// Whether the routes that act for one address require its token.
#[derive(Clone, Debug)]
pub enum AddressAuth {
    /// Every request is let through. A configured secret still verifies the
    /// sidecar's revocations, so they hold once the check is turned on.
    Off(Option<AddressTokenSecret>),
    /// Only a request carrying the address's token signed with this secret.
    Required(AddressTokenSecret),
}

impl Default for AddressAuth {
    fn default() -> Self {
        Self::Off(None)
    }
}

impl AddressAuth {
    /// The sidecar's secret, whether or not the check is on.
    pub fn secret(&self) -> Option<&AddressTokenSecret> {
        match self {
            Self::Off(secret) => secret.as_ref(),
            Self::Required(secret) => Some(secret),
        }
    }
}

/// The key a token names its address by, as the sidecar's `ownerOf` builds
/// it: the part before the first `.`, trimmed around both cuts and lowercased
/// whole. Base58 is lowercased too, so it is a lookup key and not an address.
/// Trimmed like the handlers' normalization, so a padded address cannot pass
/// under one key and then be written under another.
pub fn address_key(address_or_worker: &str) -> String {
    address_or_worker
        .trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .trim()
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

/// The issue time of the request's bearer token, if it is bound to `target`.
/// Revocation is the caller's part: see [`require_address_token`].
pub fn authorize(
    secret: &AddressTokenSecret,
    headers: &HeaderMap,
    target: &str,
    now_ms: i64,
) -> Result<i64, ApiError> {
    let bound = bearer(headers).and_then(|token| secret.token_address_key(token, now_ms));
    match bound {
        Some((key, issued_at)) if key == address_key(target) => Ok(issued_at),
        _ => Err(ApiError::LoginRequired),
    }
}

/// The address key and revocation moment the request's bearer revocation
/// carries, if `secret` signed it and it has not expired.
pub fn revocation(
    secret: &AddressTokenSecret,
    headers: &HeaderMap,
    now_ms: i64,
) -> Option<(String, i64)> {
    bearer(headers).and_then(|token| secret.revocation(token, now_ms))
}

/// A token for `address` from the check's secret, valid for
/// [`ISSUED_TOKEN_TTL_MS`]; `None` while the check is off.
pub fn issue_address_token(state: &AppState, address: &str) -> Option<String> {
    match &state.address_auth {
        AddressAuth::Off(_) => None,
        AddressAuth::Required(secret) => {
            let now = bp_common::now_ms();
            Some(secret.issue(address, now, now + ISSUED_TOKEN_TTL_MS))
        }
    }
}

/// When the check is on: [`authorize`], then the token must not predate its
/// address key's revocation. An unreadable revocation list refuses.
pub async fn require_address_token(
    state: &AppState,
    headers: &HeaderMap,
    address: &str,
) -> Result<(), ApiError> {
    let AddressAuth::Required(secret) = &state.address_auth else {
        return Ok(());
    };
    let issued_at = authorize(secret, headers, address, bp_common::now_ms())?;
    let revoked_before =
        bp_db::find_token_revoked_before(&state.pool, &address_key(address)).await?;
    match revoked_before {
        Some(revoked_before) if issued_at < revoked_before => Err(ApiError::LoginRequired),
        _ => Ok(()),
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
    require_address_token(&state, request.headers(), target).await?;
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
    // {"a":ADDRESS,"e":4102444800000,"i":4101840000000}
    const STAMPED: &str = "eyJhIjoiYmMxcXRva2VudmVjdG9yYWRkcmVzcyIsImUiOjQxMDI0NDQ4MDAwMDAsImkiOjQxMDE4NDAwMDAwMDB9.zau-gB8Tz65HFZ6IbRjbckZ11OAoahcjFUsbWd9729I";
    // {"rv":ADDRESS,"b":4101840000000,"e":4102444800000}
    const REVOCATION: &str = "eyJydiI6ImJjMXF0b2tlbnZlY3RvcmFkZHJlc3MiLCJiIjo0MTAxODQwMDAwMDAwLCJlIjo0MTAyNDQ0ODAwMDAwfQ.1rcSopEwNuQXGxIOLh6OjL-44ZXHyXDxPLgxCXdU_Ic";
    const EXPIRES: i64 = 4_102_444_800_000;
    const ISSUED: i64 = 4_101_840_000_000;
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
    fn an_issued_token_is_the_sidecars_string() {
        assert_eq!(secret().issue(ADDRESS, ISSUED, EXPIRES), STAMPED);
    }

    #[test]
    fn a_token_carries_its_issue_time_or_counts_as_a_week_older_than_its_expiry() {
        let issued = |t: &str| authorize(&secret(), &headers(&format!("Bearer {t}")), ADDRESS, NOW);
        assert_eq!(issued(STAMPED).unwrap(), ISSUED);
        assert_eq!(issued(VALID).unwrap(), EXPIRES - 7 * 24 * 60 * 60 * 1000);
    }

    #[test]
    fn a_revocation_names_its_key_and_moment_and_is_no_address_token() {
        let h = headers(&format!("Bearer {REVOCATION}"));
        assert_eq!(
            revocation(&secret(), &h, NOW),
            Some((ADDRESS.to_string(), ISSUED))
        );
        assert_eq!(revocation(&secret(), &h, EXPIRES + 1), None, "expired");
        let other = AddressTokenSecret::new("another-secret").unwrap();
        assert_eq!(revocation(&other, &h, NOW), None, "another secret");
        assert!(!passes(&format!("Bearer {REVOCATION}"), ADDRESS));
        let h = headers(&format!("Bearer {STAMPED}"));
        assert_eq!(revocation(&secret(), &h, NOW), None);
    }

    #[test]
    fn an_issued_token_passes_for_its_address_until_it_expires() {
        let token = secret().issue("BC1QTOKENVECTORADDRESS.rig", NOW, NOW + 1);
        assert!(passes(&format!("Bearer {token}"), ADDRESS));
        assert!(!passes(&format!("Bearer {token}"), "bc1qsomeoneelse"));
        let stale = secret().issue(ADDRESS, NOW - 2, NOW - 1);
        assert!(!passes(&format!("Bearer {stale}"), ADDRESS));
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
    fn the_key_is_trimmed_around_both_cuts_like_the_sidecar() {
        assert_eq!(address_key("  BC1QTOKENVECTORADDRESS.rig "), ADDRESS);
        assert_eq!(address_key(" bc1qtokenvectoraddress .rig"), ADDRESS);
        assert!(passes(
            &format!("Bearer {VALID}"),
            " BC1QTOKENVECTORADDRESS "
        ));
    }

    /// A token whose key carries whitespace, as an untrimmed `ownerOf` could
    /// issue, opens nothing: no target keys to it.
    #[test]
    fn a_token_for_a_padded_key_passes_for_no_address() {
        let claims = format!(r#"{{"a":" {ADDRESS}","e":{EXPIRES},"i":{ISSUED}}}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims);
        let token = format!("{payload}.{}", secret().sign(&payload));
        for target in [ADDRESS, &format!(" {ADDRESS}"), &format!(" {ADDRESS} ")] {
            assert!(!passes(&format!("Bearer {token}"), target), "{target:?}");
        }
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
