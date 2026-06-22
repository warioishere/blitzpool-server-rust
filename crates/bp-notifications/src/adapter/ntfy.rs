// SPDX-License-Identifier: AGPL-3.0-or-later

//! ntfy adapter — `POST {server}/{topic}` with `Content-Type:
//! text/plain` body.
//!
//! Topic naming: `{prefix}{address}` — prefix
//! is configurable (often `blitzpool-`), address is the BTC payout
//! address used as a stable per-user identifier. Subscribers point
//! their ntfy app at that topic out-of-band; there is no per-user
//! subscription row beyond the in-DB `ntfy_subscriptions_entity` that
//! tracks per-address language / hourly-toggle preferences.

use reqwest::Client;
use tracing::warn;

use super::error::{AdapterError, AdapterResult};

#[derive(Debug, Clone)]
pub struct NtfyConfig {
    /// Base URL — `https://ntfy.sh` or a self-hosted instance.
    pub server_url: String,
    /// Optional Bearer token. Self-hosted instances usually require
    /// auth; ntfy.sh public topics do not.
    pub access_token: Option<String>,
    /// Topic prefix prepended to the address (e.g. `"blitzpool-"`).
    pub topic_prefix: String,
}

pub struct NtfyAdapter {
    client: Client,
    config: NtfyConfig,
}

impl NtfyAdapter {
    pub fn new(config: NtfyConfig) -> AdapterResult<Self> {
        if config.server_url.trim().is_empty() {
            return Err(AdapterError::Config("NTFY_SERVER_URL is empty".to_string()));
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AdapterError::Config(format!("reqwest client build: {e}")))?;
        Ok(Self { client, config })
    }

    /// `{server}/{prefix}{address}`. Returned even when the address
    /// is empty so callers can debug topic-resolution easily.
    pub fn topic_url(&self, address: &str) -> String {
        let base = self.config.server_url.trim_end_matches('/');
        format!("{}/{}{}", base, self.config.topic_prefix, address)
    }

    /// Publish a plain-text message to the address-topic. `Tags: bot`
    /// is set so the SSE-listener in the follow-up Phase can ignore
    /// echoes of its own outbound traffic.
    pub async fn publish(&self, address: &str, message: &str) -> AdapterResult<()> {
        let url = self.topic_url(address);
        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .header("Tags", "bot")
            .body(message.to_string());
        if let Some(token) = &self.config.access_token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        let response = request
            .send()
            .await
            .map_err(|e| AdapterError::Transport(format!("ntfy POST: {e}")))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let code = status.as_u16();
        let snippet = response
            .text()
            .await
            .unwrap_or_else(|_| String::from("(body unreadable)"));
        match code {
            401 | 403 => Err(AdapterError::Auth(format!("ntfy {code}: {snippet}"))),
            429 => {
                warn!(target: "bp_notifications::ntfy", address, "ntfy rate-limited (429)");
                Err(AdapterError::Transport(format!("ntfy 429: {snippet}")))
            }
            _ => Err(AdapterError::Server(format!("ntfy {code}: {snippet}"))),
        }
    }
}
