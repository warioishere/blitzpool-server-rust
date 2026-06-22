// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal cookie-auth JSON-RPC helper for test orchestration. Intentionally
//! decoupled from `bp-bitcoin`, which only exposes auxiliary read-only RPCs;
//! this helper additionally needs `createwallet`, `getnewaddress`,
//! `generatetoaddress`, and `getblockchaininfo` — all wallet/control RPCs
//! that don't belong on the production-shape `BitcoinRpc` surface.

use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RegtestError;

#[derive(Serialize)]
struct RpcEnvelope<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcResponseError>,
}

#[derive(Deserialize, Debug)]
struct RpcResponseError {
    code: i64,
    message: String,
}

pub(crate) struct RpcCaller {
    client: Client,
    base_url: String,
    cookie_path: std::path::PathBuf,
}

impl RpcCaller {
    pub(crate) fn new(base_url: String, cookie_path: std::path::PathBuf) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client build cannot fail with these options");
        Self {
            client,
            base_url,
            cookie_path,
        }
    }

    pub(crate) async fn call(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, RegtestError> {
        let cookie = read_cookie(&self.cookie_path).await?;
        let body = RpcEnvelope {
            jsonrpc: "1.0",
            id: 1,
            method,
            params,
        };

        let response = self
            .client
            .post(&self.base_url)
            .basic_auth(&cookie.user, Some(&cookie.password))
            .json(&body)
            .send()
            .await
            .map_err(|e| RegtestError::Rpc {
                method,
                detail: format!("HTTP send failed: {e}"),
            })?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(|e| RegtestError::Rpc {
            method,
            detail: format!("HTTP read failed: {e}"),
        })?;

        // bitcoin-core returns 500 on RPC errors with a JSON body — handle
        // both 200 and 500 by parsing the envelope before raising on status.
        let parsed: RpcResponse =
            serde_json::from_slice(&bytes).map_err(|e| RegtestError::Rpc {
                method,
                detail: format!(
                    "non-JSON response (HTTP {}): {} — body: {:?}",
                    status.as_u16(),
                    e,
                    String::from_utf8_lossy(&bytes)
                        .chars()
                        .take(200)
                        .collect::<String>(),
                ),
            })?;

        if let Some(err) = parsed.error {
            return Err(RegtestError::Rpc {
                method,
                detail: format!("bitcoin-core RPC error {}: {}", err.code, err.message),
            });
        }

        parsed.result.ok_or_else(|| RegtestError::Rpc {
            method,
            detail: "missing both `result` and `error` in RPC response".into(),
        })
    }
}

struct Cookie {
    user: String,
    password: String,
}

async fn read_cookie(path: &Path) -> Result<Cookie, RegtestError> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| RegtestError::Rpc {
            method: "<cookie-read>",
            detail: format!("could not read cookie file {}: {e}", path.display()),
        })?;
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    let (user, password) = trimmed.split_once(':').ok_or_else(|| RegtestError::Rpc {
        method: "<cookie-parse>",
        detail: format!("cookie file {} missing ':' separator", path.display()),
    })?;
    Ok(Cookie {
        user: user.to_string(),
        password: password.to_string(),
    })
}
