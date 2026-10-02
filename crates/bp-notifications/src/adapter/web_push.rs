// SPDX-License-Identifier: AGPL-3.0-or-later

//! Web-Push / UnifiedPush adapter: a plain-text `title|body|tag` POST signed
//! with a VAPID JWT. Encrypted Web-Push is not possible because the stored
//! subscription carries only `endpoint`, no `p256dh`/`auth` keys. Without
//! VAPID keys it sends an unauthenticated plain POST.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::Serialize;
use tracing::warn;

use super::error::{AdapterError, AdapterResult};
use super::payload::PushPayload;

#[derive(Debug, Clone)]
pub struct VapidConfig {
    /// ECDSA P-256 private key as a raw base64url 32-byte scalar, no PEM
    /// wrapper, as standard VAPID key generators produce it.
    pub private_key_b64url: String,
    /// Public key as base64url-encoded uncompressed point
    /// (65 bytes, leading `0x04`). Goes verbatim into the
    /// `Authorization: vapid t=…,k=<this>` header.
    pub public_key_b64url: String,
    /// `mailto:` URL or `https://` URL identifying the sender — the
    /// `sub` JWT claim.
    pub subject: String,
}

#[derive(Debug, Clone)]
pub struct WebPushOutcome {
    /// `true` when the push service permanently rejected the endpoint
    /// (HTTP 404 or 410). Dispatcher soft-deletes the underlying
    /// subscription row.
    pub invalid_endpoint: bool,
    /// `true` when the send used VAPID, `false` for the plain-POST
    /// fallback path. Only here for diagnostics / metrics.
    pub used_vapid: bool,
}

pub struct WebPushAdapter {
    client: Client,
    vapid: Option<VapidKey>,
}

struct VapidKey {
    encoding_key: EncodingKey,
    public_key_b64url: String,
    subject: String,
}

impl WebPushAdapter {
    /// `true` when a valid VAPID key is loaded; `false` means every send
    /// goes via unauthenticated plain POST (no key configured, or the
    /// configured key failed its boot-time sign check).
    pub fn vapid_enabled(&self) -> bool {
        self.vapid.is_some()
    }

    /// `vapid = None` keeps the adapter alive but disables JWT
    /// signing — every send goes via plain POST.
    pub fn new(vapid: Option<VapidConfig>) -> AdapterResult<Self> {
        let client = bp_http::client_builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AdapterError::Config(format!("reqwest client build: {e}")))?;

        let vapid = match vapid {
            None => None,
            Some(cfg) => match build_vapid_key(cfg) {
                Ok(key) => Some(key),
                Err(e) => {
                    warn!(target: "bp_notifications::web_push", error = %e, "VAPID disabled — sending via plain POST");
                    None
                }
            },
        };
        Ok(Self { client, vapid })
    }

    /// Send `payload` (rendered as pipe-joined text) to a UnifiedPush
    /// `endpoint`. VAPID JWT is attached when configured; a VAPID
    /// failure falls back to a plain POST.
    pub async fn send(
        &self,
        endpoint: &str,
        payload: &PushPayload,
    ) -> AdapterResult<WebPushOutcome> {
        let body = payload.pipe_joined();

        if let Some(vapid) = &self.vapid {
            match self.try_vapid(endpoint, vapid, &body).await {
                Ok(outcome) => return Ok(outcome),
                Err(e) if vapid_failure_falls_back(&e) => {
                    warn!(target: "bp_notifications::web_push", endpoint, error = %e, "VAPID failed, falling back to plain POST");
                }
                Err(other) => return Err(other),
            }
        }

        let response = self
            .client
            .post(endpoint)
            .header("Content-Type", "text/plain")
            .body(body)
            .send()
            .await
            .map_err(|e| AdapterError::Transport(format!("plain POST: {e}")))?;
        classify_response(response, false).await
    }

    async fn try_vapid(
        &self,
        endpoint: &str,
        vapid: &VapidKey,
        body: &str,
    ) -> AdapterResult<WebPushOutcome> {
        let audience = audience_from_endpoint(endpoint)?;
        let jwt = mint_vapid_jwt(vapid, &audience)?;
        let auth = format!("vapid t={jwt},k={}", vapid.public_key_b64url);

        let response = self
            .client
            .post(endpoint)
            .header("Content-Type", "text/plain")
            .header("TTL", "3600")
            .header("Urgency", "high")
            .header("Authorization", auth)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| AdapterError::Transport(format!("VAPID POST: {e}")))?;
        classify_response(response, true).await
    }
}

/// VAPID errors that degrade to an unauthenticated plain POST (UnifiedPush /
/// ntfy accept it): a rejected JWT or a local minting failure. A `Transport`
/// failure is a real network error and is surfaced instead.
fn vapid_failure_falls_back(e: &AdapterError) -> bool {
    matches!(
        e,
        AdapterError::Auth(_) | AdapterError::Server(_) | AdapterError::Encoding(_)
    )
}

async fn classify_response(
    response: reqwest::Response,
    used_vapid: bool,
) -> AdapterResult<WebPushOutcome> {
    let status = response.status();
    if status.is_success() {
        return Ok(WebPushOutcome {
            invalid_endpoint: false,
            used_vapid,
        });
    }
    let code = status.as_u16();
    if code == 404 || code == 410 {
        return Ok(WebPushOutcome {
            invalid_endpoint: true,
            used_vapid,
        });
    }
    let snippet = response
        .text()
        .await
        .unwrap_or_else(|_| String::from("(body unreadable)"));
    match code {
        401 | 403 => Err(AdapterError::Auth(format!("web-push {code}: {snippet}"))),
        _ => Err(AdapterError::Server(format!("web-push {code}: {snippet}"))),
    }
}

/// Compute the VAPID `aud` claim — `scheme://host[:port]` — from
/// an endpoint URL. RFC 8292 §2 requires this to be the origin of
/// the push service, not the full path.
fn audience_from_endpoint(endpoint: &str) -> AdapterResult<String> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|e| AdapterError::Encoding(format!("endpoint URL: {e}")))?;
    let scheme = url.scheme();
    let host = url
        .host_str()
        .ok_or_else(|| AdapterError::Encoding("endpoint has no host".to_string()))?;
    let mut out = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    Ok(out)
}

fn mint_vapid_jwt(vapid: &VapidKey, audience: &str) -> AdapterResult<String> {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AdapterError::Encoding(format!("clock: {e}")))?
        .as_secs()
        + 12 * 3600;
    #[derive(Serialize)]
    struct Claims<'a> {
        aud: &'a str,
        exp: u64,
        sub: &'a str,
    }
    let claims = Claims {
        aud: audience,
        exp,
        sub: &vapid.subject,
    };
    jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &vapid.encoding_key)
        .map_err(|e| AdapterError::Encoding(format!("JWT encode: {e}")))
}

/// Build a usable [`VapidKey`] from raw base64url config. It test-signs
/// before returning, so a bad key degrades to plain POST at boot instead of
/// failing every live send.
fn build_vapid_key(cfg: VapidConfig) -> Result<VapidKey, String> {
    let der = raw_vapid_to_pkcs8_der(&cfg.private_key_b64url, &cfg.public_key_b64url)?;
    let key = VapidKey {
        encoding_key: EncodingKey::from_ec_der(&der),
        public_key_b64url: cfg.public_key_b64url,
        subject: cfg.subject,
    };
    mint_vapid_jwt(&key, "https://validation.invalid").map_err(|e| format!("test-sign: {e}"))?;
    Ok(key)
}

/// Encode a raw base64url P-256 VAPID key pair as PKCS#8 v1 DER, the form
/// ring's `EcdsaKeyPair::from_pkcs8` takes. ring checks the embedded public
/// key against the scalar, so both halves go in; P-256 lengths are fixed, so
/// the framing is constant bytes around the two key blobs.
fn raw_vapid_to_pkcs8_der(priv_b64url: &str, pub_b64url: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let priv_raw = URL_SAFE_NO_PAD
        .decode(priv_b64url)
        .map_err(|e| format!("private base64url: {e}"))?;
    if priv_raw.len() != 32 {
        return Err(format!(
            "expected 32-byte P-256 scalar, got {} bytes",
            priv_raw.len()
        ));
    }
    let pub_raw = URL_SAFE_NO_PAD
        .decode(pub_b64url)
        .map_err(|e| format!("public base64url: {e}"))?;
    if pub_raw.len() != 65 || pub_raw[0] != 0x04 {
        return Err(format!(
            "expected 65-byte uncompressed P-256 point (0x04…), got {} bytes",
            pub_raw.len()
        ));
    }
    // PKCS#8 PrivateKeyInfo whose OCTET STRING wraps the SEC1 ECPrivateKey
    // (version 1, private scalar, [1] public point).
    let mut der = Vec::with_capacity(138);
    der.extend_from_slice(&[
        0x30, 0x81, 0x87, // SEQUENCE, 135 bytes
        0x02, 0x01, 0x00, // INTEGER version = 0
        0x30, 0x13, // SEQUENCE (AlgorithmIdentifier), 19 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
        0x04, 0x6d, // OCTET STRING, 109 bytes
        0x30, 0x6b, // SEQUENCE (ECPrivateKey), 107 bytes
        0x02, 0x01, 0x01, // INTEGER version = 1
        0x04, 0x20, // OCTET STRING, 32 bytes
    ]);
    der.extend_from_slice(&priv_raw);
    der.extend_from_slice(&[
        0xa1, 0x44, // [1] EXPLICIT, 68 bytes
        0x03, 0x42, 0x00, // BIT STRING, 66 bytes (0 unused bits)
    ]);
    der.extend_from_slice(&pub_raw);
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience_extracts_origin() {
        assert_eq!(
            audience_from_endpoint("https://ntfy.sh/blitzpool-xyz").unwrap(),
            "https://ntfy.sh"
        );
        assert_eq!(
            audience_from_endpoint("https://example.com:8443/up?token=abc").unwrap(),
            "https://example.com:8443"
        );
    }

    #[test]
    fn audience_rejects_garbage() {
        assert!(audience_from_endpoint("not-a-url").is_err());
    }

    #[test]
    fn vapid_encoding_and_http_errors_fall_back_but_transport_does_not() {
        assert!(vapid_failure_falls_back(&AdapterError::Encoding(
            "JWT encode: InvalidEcdsaKey".into()
        )));
        assert!(vapid_failure_falls_back(&AdapterError::Auth("401".into())));
        assert!(vapid_failure_falls_back(&AdapterError::Server(
            "500".into()
        )));
        assert!(!vapid_failure_falls_back(&AdapterError::Transport(
            "connection reset".into()
        )));
    }

    #[test]
    fn invalid_vapid_key_disables_vapid_instead_of_erroring() {
        // Well-formed lengths, but the zero scalar does not match the public
        // point, so the boot-time test-sign fails and must degrade to plain POST.
        let zero = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let cfg = VapidConfig {
            private_key_b64url: zero,
            public_key_b64url:
                "BDXeBZOE3xWM9wbC7TkLThHb6ffEXshqlKkaxWNYDO-vz_0h5ni1SuqeB3pu_lrXUBBVzWbsedFyxDp1RxP7LgQ"
                    .to_string(),
            subject: "mailto:test@example.com".to_string(),
        };
        let adapter = WebPushAdapter::new(Some(cfg)).expect("adapter still builds");
        assert!(
            !adapter.vapid_enabled(),
            "an unsignable VAPID key must disable VAPID so sends use plain POST"
        );
    }

    #[test]
    fn no_vapid_config_runs_plain_post() {
        let adapter = WebPushAdapter::new(None).expect("adapter builds");
        assert!(!adapter.vapid_enabled());
    }

    #[test]
    fn valid_webpush_vapid_key_can_sign() {
        // A real P-256 pair: guards the DER construction, whose regression
        // would silently degrade a valid operator key to plain POST.
        let cfg = VapidConfig {
            private_key_b64url: "D3nWYHTrLXSWv94_WqRmfahAFMablsFixufvCNjc_Bc".to_string(),
            public_key_b64url:
                "BDXeBZOE3xWM9wbC7TkLThHb6ffEXshqlKkaxWNYDO-vz_0h5ni1SuqeB3pu_lrXUBBVzWbsedFyxDp1RxP7LgQ"
                    .to_string(),
            subject: "mailto:test@example.com".to_string(),
        };
        let adapter = WebPushAdapter::new(Some(cfg)).expect("adapter builds");
        assert!(
            adapter.vapid_enabled(),
            "a valid web-push VAPID key must be usable for signing"
        );
    }
}
