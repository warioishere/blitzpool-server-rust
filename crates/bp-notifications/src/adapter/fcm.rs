// SPDX-License-Identifier: AGPL-3.0-or-later

//! Firebase Cloud Messaging (FCM) v1 HTTP API adapter.
//!
//! Authenticates with the FCM endpoint via OAuth-2 access tokens
//! exchanged from a service-account JWT (RS256). Tokens are cached
//! in-process until 60 s before expiry, then transparently refreshed
//! on the next send.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::error::{AdapterError, AdapterResult};
use super::payload::PushPayload;

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
pub struct FcmServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    pub project_id: String,
}

impl FcmServiceAccount {
    /// Parse a service-account JSON file (the one downloaded from
    /// Firebase Console → Service Accounts → Generate Key).
    pub fn from_json(json: &str) -> AdapterResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| AdapterError::Config(format!("service-account JSON: {e}")))
    }
}

#[derive(Debug, Clone)]
pub struct FcmConfig {
    pub service_account: FcmServiceAccount,
}

/// Per-send outcome — `invalid_token=true` signals the dispatcher to
/// remove the dead subscription row.
#[derive(Debug, Clone)]
pub struct FcmOutcome {
    pub invalid_token: bool,
}

/// Cached OAuth token + expiry deadline.
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

pub struct FcmAdapter {
    client: Client,
    service_account: FcmServiceAccount,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
    send_url: String,
    /// Pre-built encoding key — RSA PEM parsing is non-trivial so we
    /// do it once at construction.
    encoding_key: EncodingKey,
}

impl FcmAdapter {
    pub fn new(config: FcmConfig) -> AdapterResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| AdapterError::Config(format!("reqwest client build: {e}")))?;
        let encoding_key = EncodingKey::from_rsa_pem(config.service_account.private_key.as_bytes())
            .map_err(|e| AdapterError::Config(format!("RSA PEM key: {e}")))?;
        let send_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            config.service_account.project_id
        );
        Ok(Self {
            client,
            service_account: config.service_account,
            cached_token: Arc::new(Mutex::new(None)),
            send_url,
            encoding_key,
        })
    }

    /// Mint or reuse the cached OAuth token. Refresh logic:
    /// regenerate the JWT, exchange for an access token, cache with
    /// the upstream `expires_in` minus a 60 s safety margin.
    async fn access_token(&self) -> AdapterResult<String> {
        let mut guard = self.cached_token.lock().await;
        if let Some(t) = guard.as_ref() {
            if t.expires_at > Instant::now() {
                return Ok(t.access_token.clone());
            }
        }

        let jwt = self.build_jwt()?;
        let response = self
            .client
            .post(&self.service_account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| AdapterError::Transport(format!("token exchange: {e}")))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| AdapterError::Transport(format!("token body: {e}")))?;
        if !status.is_success() {
            return Err(AdapterError::Auth(format!(
                "token exchange {}: {body}",
                status.as_u16()
            )));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }
        let parsed: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| AdapterError::Encoding(format!("token JSON: {e}")))?;

        let expires_at = Instant::now()
            + Duration::from_secs(
                parsed
                    .expires_in
                    .saturating_sub(TOKEN_REFRESH_SKEW.as_secs()),
            );
        *guard = Some(CachedToken {
            access_token: parsed.access_token.clone(),
            expires_at,
        });
        Ok(parsed.access_token)
    }

    fn build_jwt(&self) -> AdapterResult<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AdapterError::Encoding(format!("clock skew: {e}")))?
            .as_secs();

        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            scope: &'a str,
            aud: &'a str,
            iat: u64,
            exp: u64,
        }
        let claims = Claims {
            iss: &self.service_account.client_email,
            scope: FCM_SCOPE,
            aud: &self.service_account.token_uri,
            iat: now,
            exp: now + 3600,
        };

        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)
            .map_err(|e| AdapterError::Encoding(format!("JWT encode: {e}")))
    }

    /// Send a single push to one FCM token. Address is set on the
    /// `data{}` payload so the receiving app can route within a
    /// multi-address device.
    pub async fn send(
        &self,
        token: &str,
        address: &str,
        payload: &PushPayload,
    ) -> AdapterResult<FcmOutcome> {
        let access_token = self.access_token().await?;

        // Build the v1 API JSON envelope. We avoid building a strongly
        // typed Message struct because `data{}` is open-ended and the
        // android/apns blocks have a lot of optional fields we don't
        // use — direct json! macro stays readable.
        let mut data = serde_json::Map::new();
        data.insert(
            "type".into(),
            serde_json::Value::from(payload.kind.as_str()),
        );
        data.insert("address".into(), serde_json::Value::from(address));
        data.insert(
            "timestamp".into(),
            serde_json::Value::from(current_millis_string()),
        );
        // tag carries the per-event extra (formatted difficulty,
        // block-height, status); name it after the kind so the
        // receiver code reads naturally.
        let tag_field = match payload.kind {
            super::payload::PushKind::BestDifficulty | super::payload::PushKind::BlockFound => {
                "difficulty"
            }
            super::payload::PushKind::DeviceStatus => "status",
            super::payload::PushKind::NetworkDifficulty => "difficulty",
        };
        data.insert(
            tag_field.into(),
            serde_json::Value::from(payload.tag.clone()),
        );
        for (k, v) in &payload.extras {
            data.insert(k.clone(), serde_json::Value::from(v.clone()));
        }

        let body = serde_json::json!({
            "message": {
                "token": token,
                "notification": { "title": payload.title, "body": payload.body },
                "data": data,
                "android": {
                    "priority": "HIGH",
                    "notification": {
                        "sound": "default",
                        "channel_id": "blitzpool_notifications",
                    },
                },
                "apns": {
                    "payload": {
                        "aps": {
                            "sound": "default",
                            "badge": 1,
                            "content-available": 1,
                        }
                    }
                }
            }
        });

        let response = self
            .client
            .post(&self.send_url)
            .bearer_auth(&access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Transport(format!("FCM POST: {e}")))?;
        let status = response.status();
        if status.is_success() {
            return Ok(FcmOutcome {
                invalid_token: false,
            });
        }

        let body_text = response
            .text()
            .await
            .unwrap_or_else(|_| String::from("(body unreadable)"));
        let invalid = is_invalid_token_error(status.as_u16(), &body_text);
        if invalid {
            return Ok(FcmOutcome {
                invalid_token: true,
            });
        }
        Err(AdapterError::Server(format!(
            "FCM {}: {body_text}",
            status.as_u16()
        )))
    }
}

fn current_millis_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    now.to_string()
}

/// FCM v1 signals permanent token failure with either HTTP 404 +
/// `UNREGISTERED` or HTTP 400 + `INVALID_ARGUMENT`. We string-match
/// the `errorCode` field — robust enough for the two known shapes
/// and trivial to extend.
fn is_invalid_token_error(status: u16, body: &str) -> bool {
    if status == 404 {
        return true;
    }
    if status == 400 && (body.contains("UNREGISTERED") || body.contains("INVALID_ARGUMENT")) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_token_detects_404() {
        assert!(is_invalid_token_error(404, "{}"));
    }

    #[test]
    fn invalid_token_detects_400_unregistered() {
        let body = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
        assert!(is_invalid_token_error(400, body));
    }

    #[test]
    fn invalid_token_ignores_other_500s() {
        assert!(!is_invalid_token_error(500, "internal"));
        assert!(!is_invalid_token_error(503, "unavailable"));
    }

    #[test]
    fn invalid_token_ignores_400_without_errorcode() {
        assert!(!is_invalid_token_error(
            400,
            r#"{"error":{"code":400,"message":"bad request"}}"#
        ));
    }
}
