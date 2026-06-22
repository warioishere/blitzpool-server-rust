// SPDX-License-Identifier: AGPL-3.0-or-later

//! Web-Push / UnifiedPush adapter — VAPID-signed plain POST.
//!
//! End-to-end-encrypted Web-Push (which requires per-subscription
//! `p256dh` + `auth` keys) is not used; the `push_subscription_entity`
//! row only carries `endpoint`. Instead it ships a plain-text
//! `title|body|tag` body and authenticates the sender to the push
//! service via a VAPID JWT in the
//! `Authorization: vapid t=<jwt>,k=<pubkey>` header — that's what
//! UnifiedPush and ntfy.sh endpoints accept.
//!
//! If no VAPID keys are configured the adapter falls back to a
//! header-less plain POST (still works for self-hosted /
//! UnifiedPush distributors but loses authenticity).

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
    /// ECDSA P-256 private key as raw base64url-encoded bytes (32-byte
    /// scalar, no PEM wrapper) — the same format accepted by the
    /// web-push npm library and produced by standard VAPID key
    /// generators.
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
    /// `vapid = None` keeps the adapter alive but disables JWT
    /// signing — every send goes via plain POST.
    pub fn new(vapid: Option<VapidConfig>) -> AdapterResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AdapterError::Config(format!("reqwest client build: {e}")))?;

        let vapid = match vapid {
            None => None,
            Some(cfg) => {
                let der = raw_b64url_to_sec1_der(&cfg.private_key_b64url)
                    .map_err(|e| AdapterError::Config(format!("VAPID EC key: {e}")))?;
                let encoding_key = EncodingKey::from_ec_der(&der);
                Some(VapidKey {
                    encoding_key,
                    public_key_b64url: cfg.public_key_b64url,
                    subject: cfg.subject,
                })
            }
        };
        Ok(Self { client, vapid })
    }

    /// Send `payload` (rendered as pipe-joined text) to a UnifiedPush
    /// `endpoint`. VAPID JWT is attached when configured; on VAPID
    /// failure we transparently fall back to a plain POST.
    pub async fn send(
        &self,
        endpoint: &str,
        payload: &PushPayload,
    ) -> AdapterResult<WebPushOutcome> {
        let body = payload.pipe_joined();

        if let Some(vapid) = &self.vapid {
            match self.try_vapid(endpoint, vapid, &body).await {
                Ok(outcome) => return Ok(outcome),
                Err(AdapterError::Auth(msg)) | Err(AdapterError::Server(msg)) => {
                    warn!(target: "bp_notifications::web_push", endpoint, error = %msg, "VAPID failed, falling back to plain POST");
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

/// Convert a raw base64url-encoded P-256 private key scalar (32 bytes)
/// to SEC1 DER so `EncodingKey::from_ec_der` can consume it.
///
/// SEC1 layout (RFC 5915):
///   SEQUENCE { version=1, privateKey=<32 bytes>, [0] P-256 OID }
fn raw_b64url_to_sec1_der(b64url: &str) -> Result<Vec<u8>, String> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64url)
        .map_err(|e| format!("base64url decode: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "expected 32-byte P-256 scalar, got {} bytes",
            raw.len()
        ));
    }
    // Fixed DER prefix for SEC1 P-256: SEQUENCE(49) { version INTEGER 1,
    // privateKey OCTET STRING(32 bytes), [0] EXPLICIT OID P-256 }
    let mut der = Vec::with_capacity(51);
    der.extend_from_slice(&[
        0x30, 0x31, // SEQUENCE, 49 bytes
        0x02, 0x01, 0x01, // INTEGER version = 1
        0x04, 0x20, // OCTET STRING, 32 bytes
    ]);
    der.extend_from_slice(&raw);
    der.extend_from_slice(&[
        0xa0, 0x0a, // [0] EXPLICIT, 10 bytes
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
    ]);
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
}
