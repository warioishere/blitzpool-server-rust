// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BitcoinRpc` — async JSON-RPC client wrapper.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::config::{BitcoinRpcConfig, RpcAuth};
use crate::error::{RpcError, RpcErrorDetail};
use crate::types::{BlockHeaderInfo, MiningInfo, NetworkInfo, PeerInfo};

/// Async JSON-RPC client to a Bitcoin Core node. Cheap to clone — shares
/// an underlying `reqwest::Client` connection pool.
#[derive(Clone, Debug)]
pub struct BitcoinRpc {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    http: reqwest::Client,
    config: BitcoinRpcConfig,
    request_id: AtomicU64,
}

impl BitcoinRpc {
    /// Build a client. Does NOT perform any network I/O — the first
    /// actual RPC call is when the connection (and auth) are exercised.
    pub fn new(config: BitcoinRpcConfig) -> Result<Self, RpcError> {
        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = config.timeout {
            builder = builder.timeout(timeout);
        }
        let http = builder.build()?;
        Ok(BitcoinRpc {
            inner: Arc::new(Inner {
                http,
                config,
                request_id: AtomicU64::new(0),
            }),
        })
    }

    pub async fn get_network_info(&self) -> Result<NetworkInfo, RpcError> {
        self.call("getnetworkinfo", serde_json::json!([])).await
    }

    /// Returns the raw `getnetworkinfo` result bytes exactly as Core sent
    /// them — no f64 round-trip, so number formatting is preserved verbatim.
    pub async fn get_network_info_raw(&self) -> Result<Box<serde_json::value::RawValue>, RpcError> {
        self.call("getnetworkinfo", serde_json::json!([])).await
    }

    pub async fn get_mining_info(&self) -> Result<MiningInfo, RpcError> {
        self.call("getmininginfo", serde_json::json!([])).await
    }

    /// Returns the raw `getmininginfo` result bytes exactly as Core sent them.
    pub async fn get_mining_info_raw(&self) -> Result<Box<serde_json::value::RawValue>, RpcError> {
        self.call("getmininginfo", serde_json::json!([])).await
    }

    pub async fn get_peer_info(&self) -> Result<Vec<PeerInfo>, RpcError> {
        self.call("getpeerinfo", serde_json::json!([])).await
    }

    /// Current chain-tip height. Used on the block-found hot path to
    /// derive the won-block's height (`prev_height + 1`) for
    /// `engine.on_block_found` and the dispatcher's block-found
    /// notification — the SV1/SV2 share-accept path doesn't carry
    /// height through its `ShareAccept` shape.
    pub async fn get_block_count(&self) -> Result<u64, RpcError> {
        self.call("getblockcount", serde_json::json!([])).await
    }

    /// Fetch a block header (`getblockheader <hash> true`). The
    /// block-found confirmation watcher uses the `confirmations` field to
    /// decide a found block's fate: `>= confirmation_depth` ⇒ confirmed
    /// (apply the frozen distribution), `< 0` ⇒ orphaned (discard).
    ///
    /// If the node doesn't know the hash at all it returns a
    /// `Block not found` error (code `-5`); the watcher treats that the
    /// same as orphaned — a hash the node can't place is, by definition,
    /// not on the active chain.
    pub async fn get_block_header(&self, block_hash: &str) -> Result<BlockHeaderInfo, RpcError> {
        self.call("getblockheader", serde_json::json!([block_hash, true]))
            .await
    }

    /// Submit a raw block hex to bitcoin-core via the `submitblock` RPC.
    ///
    /// Bitcoin Core's `submitblock` returns:
    /// - `null` on accepted (the block was added to / propagated by the
    ///   node);
    /// - a string error code on rejected (`"high-hash"`, `"bad-prevblk"`,
    ///   `"duplicate"`, etc. — see Bitcoin Core's
    ///   `validation::BlockValidationState` for the catalogue).
    ///
    /// This RPC is the **only** non-TDP block-submission path the pool
    /// uses, and it lives here as a deliberate exception to the
    /// TDP-direct architecture (`project-tdp-direct-architecture`).
    /// Used for the JDP-PushSolution orphan-protection path: when a JDC
    /// reports a block-found, the pool reconstructs
    /// the full block and submits it in parallel to the JDC's own
    /// submission. JDP-declared templates have no pool-side `template_id`,
    /// so `TdpHandle::submit_solution` (which requires one) is not
    /// usable for this path; the raw RPC is the only option short of
    /// re-architecting Bitcoin Core's IPC surface.
    pub async fn submit_block(&self, block_hex: String) -> Result<Option<String>, RpcError> {
        let raw: serde_json::Value = self
            .call_raw("submitblock", serde_json::json!([block_hex]))
            .await?;
        match raw {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(reason) => Ok(Some(reason)),
            other => Err(RpcError::BitcoinCore(RpcErrorDetail {
                code: 0,
                message: format!("unexpected submitblock result shape: {other}"),
            })),
        }
    }

    /// Variant of [`Self::call`] that surfaces a `null` result as
    /// `serde_json::Value::Null` instead of treating it as a missing
    /// field. `submitblock` is the lone caller — its "accepted" response
    /// is `{"result": null, ...}` which the standard envelope would
    /// otherwise reject as "neither result nor error".
    async fn call_raw(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let id = self.inner.request_id.fetch_add(1, Ordering::Relaxed);
        let request = RpcRequest {
            jsonrpc: "1.0",
            id,
            method,
            params,
        };
        let (user, password) = self.resolve_auth()?;
        let resp = self
            .inner
            .http
            .post(&self.inner.config.url)
            .basic_auth(user, Some(password))
            .json(&request)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RpcError::Unauthorized);
        }
        // See `call`: parse the JSON-RPC envelope regardless of HTTP status so
        // an application error code (returned with HTTP 500) surfaces as
        // `BitcoinCore`; fall back to the transport error only for a
        // non-envelope body.
        let status_err = resp.error_for_status_ref().err();
        let body = resp.bytes().await?;
        match serde_json::from_slice::<RawRpcResponse>(&body) {
            Ok(envelope) => {
                if let Some(err) = envelope.error {
                    return Err(RpcError::BitcoinCore(err));
                }
                // `null` result is a valid success signal here (submitblock).
                Ok(envelope.result.unwrap_or(serde_json::Value::Null))
            }
            Err(parse_err) => match status_err {
                Some(http) => Err(RpcError::Http(http)),
                None => Err(RpcError::Json(parse_err)),
            },
        }
    }

    /// Generic RPC entry point — escape hatch for callers that need a
    /// method not covered by the typed helpers above.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, RpcError> {
        let id = self.inner.request_id.fetch_add(1, Ordering::Relaxed);
        let request = RpcRequest {
            jsonrpc: "1.0",
            id,
            method,
            params,
        };

        let (user, password) = self.resolve_auth()?;
        let mut req = self
            .inner
            .http
            .post(&self.inner.config.url)
            .basic_auth(user, Some(password));
        req = req.json(&request);

        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RpcError::Unauthorized);
        }
        // bitcoin-core returns application errors (e.g. `-5 Block not found`)
        // with an HTTP 500 status AND the JSON-RPC error envelope in the
        // body. Parse the body regardless of status so the error `code`
        // surfaces as `BitcoinCore` instead of being buried as an opaque
        // HTTP error; only fall back to the transport error when the body
        // isn't a JSON-RPC envelope. (`error_for_status_ref` borrows, so it
        // doesn't consume the response before we read the body.)
        let status_err = resp.error_for_status_ref().err();
        let body = resp.bytes().await?;
        match serde_json::from_slice::<RpcResponse<T>>(&body) {
            Ok(RpcResponse { error: Some(e), .. }) => Err(RpcError::BitcoinCore(e)),
            Ok(RpcResponse {
                result: Some(r), ..
            }) => Ok(r),
            Ok(RpcResponse {
                result: None,
                error: None,
                ..
            }) => Err(RpcError::BitcoinCore(RpcErrorDetail {
                code: 0,
                message: "RPC envelope had neither result nor error".to_string(),
            })),
            Err(parse_err) => match status_err {
                Some(http) => Err(RpcError::Http(http)),
                None => Err(RpcError::Json(parse_err)),
            },
        }
    }

    fn resolve_auth(&self) -> Result<(String, String), RpcError> {
        match &self.inner.config.auth {
            RpcAuth::UserPassword { user, password } => Ok((user.clone(), password.clone())),
            RpcAuth::Cookie(path) => {
                let contents =
                    std::fs::read_to_string(path).map_err(|source| RpcError::CookieRead {
                        path: path.clone(),
                        source,
                    })?;
                let trimmed = contents.trim();
                let (user, password) =
                    trimmed
                        .split_once(':')
                        .ok_or_else(|| RpcError::CookieMalformed {
                            got: trimmed.to_string(),
                        })?;
                Ok((user.to_string(), password.to_string()))
            }
        }
    }
}

// ---- Internal JSON-RPC envelope types ----

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcErrorDetail>,
    #[allow(dead_code)]
    id: serde_json::Value,
}

/// Envelope variant that preserves a JSON `null` result as
/// [`serde_json::Value::Null`]. Used by [`BitcoinRpc::call_raw`] for
/// `submitblock`, whose "accepted" response is `result = null` — the
/// typed [`RpcResponse`] would map `null` to `Option::None` and lose
/// the distinction from an absent field.
#[derive(Deserialize)]
struct RawRpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcErrorDetail>,
    #[allow(dead_code)]
    id: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rpc_request_serializes_to_expected_shape() {
        let req = RpcRequest {
            jsonrpc: "1.0",
            id: 42,
            method: "getnetworkinfo",
            params: serde_json::json!([]),
        };
        let s = serde_json::to_string(&req).unwrap();
        // Order matters for bitcoind compatibility but `serde_json` keeps
        // struct field order from the type declaration.
        assert!(s.contains("\"jsonrpc\":\"1.0\""));
        assert!(s.contains("\"id\":42"));
        assert!(s.contains("\"method\":\"getnetworkinfo\""));
        assert!(s.contains("\"params\":[]"));
    }

    #[test]
    fn rpc_response_envelope_decodes_success() {
        let json = r#"{"result": {"answer": 42}, "error": null, "id": 1}"#;
        let env: RpcResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(env.error.is_none());
        assert_eq!(env.result.as_ref().unwrap()["answer"], 42);
    }

    #[test]
    fn rpc_response_envelope_decodes_error() {
        let json = r#"{"result": null, "error": {"code": -8, "message": "bad param"}, "id": 1}"#;
        let env: RpcResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        let e = env.error.unwrap();
        assert_eq!(e.code, -8);
        assert_eq!(e.message, "bad param");
    }

    #[test]
    fn cookie_auth_reads_well_formed_file() {
        let mut file = tempfile_in_default();
        file.write_all(b"__cookie__:abcdef1234567890\n").unwrap();
        let path = file_path(&file);
        let cfg = BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            auth: RpcAuth::Cookie(path),
            timeout: None,
        };
        let rpc = BitcoinRpc::new(cfg).unwrap();
        let (user, password) = rpc.resolve_auth().unwrap();
        assert_eq!(user, "__cookie__");
        assert_eq!(password, "abcdef1234567890");
    }

    #[test]
    fn cookie_auth_rejects_malformed_file() {
        let mut file = tempfile_in_default();
        file.write_all(b"no-colon-anywhere").unwrap();
        let path = file_path(&file);
        let cfg = BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            auth: RpcAuth::Cookie(path),
            timeout: None,
        };
        let rpc = BitcoinRpc::new(cfg).unwrap();
        let err = rpc.resolve_auth().unwrap_err();
        assert!(matches!(err, RpcError::CookieMalformed { .. }));
    }

    #[test]
    fn cookie_auth_reports_missing_file() {
        let cfg = BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            auth: RpcAuth::Cookie("/nonexistent/path/.cookie".into()),
            timeout: None,
        };
        let rpc = BitcoinRpc::new(cfg).unwrap();
        let err = rpc.resolve_auth().unwrap_err();
        assert!(matches!(err, RpcError::CookieRead { .. }));
    }

    // Tiny helpers — keep tests independent of `tempfile` crate.
    fn tempfile_in_default() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("bp-bitcoin-test-cookie-{}", rand_suffix()));
        std::fs::File::create(path).unwrap()
    }
    fn file_path(file: &std::fs::File) -> std::path::PathBuf {
        // Recover the path by re-opening via the fd's procfs entry on
        // Linux; non-portable but fine for our test env.
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap()
    }
    fn rand_suffix() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string()
    }
}
