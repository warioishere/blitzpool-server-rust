// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BitcoinRpc` — async JSON-RPC client wrapper.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::config::{BitcoinRpcConfig, RpcAuth};
use crate::error::{RpcError, RpcErrorDetail};
use crate::types::{BlockHeaderInfo, BlockTxids, DecodedTransaction, MiningInfo, NetworkInfo};

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
    /// Performs no network I/O; connection and auth are first exercised by
    /// the first RPC call.
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

    /// Current chain-tip height. The block-found path derives the won
    /// block's height from it, since `ShareAccept` carries no height.
    pub async fn get_block_count(&self) -> Result<u64, RpcError> {
        self.call("getblockcount", serde_json::json!([])).await
    }

    /// `getblockheader <hash> true`. The confirmation watcher reads
    /// `confirmations`: `>= confirmation_depth` confirms, `< 0` orphans.
    /// An unknown hash returns `-5 Block not found`, which the watcher also
    /// treats as orphaned: it is not on the active chain.
    pub async fn get_block_header(&self, block_hash: &str) -> Result<BlockHeaderInfo, RpcError> {
        self.call("getblockheader", serde_json::json!([block_hash, true]))
            .await
    }

    /// Block hash at `height` on the node's active chain.
    pub async fn get_block_hash(&self, height: u64) -> Result<String, RpcError> {
        self.call("getblockhash", serde_json::json!([height])).await
    }

    /// Txids of a block in order; `txids[0]` is the coinbase. Verbosity 1,
    /// because verbosity 2 would pull every transaction's full JSON.
    pub async fn get_block_txids(&self, block_hash: &str) -> Result<BlockTxids, RpcError> {
        self.call("getblock", serde_json::json!([block_hash, 1]))
            .await
    }

    /// Decode one transaction of a known block. Passing the block hash makes
    /// this work on a node without `txindex`.
    pub async fn get_raw_transaction_in_block(
        &self,
        txid: &str,
        block_hash: &str,
    ) -> Result<DecodedTransaction, RpcError> {
        self.call(
            "getrawtransaction",
            serde_json::json!([txid, true, block_hash]),
        )
        .await
    }

    /// `submitblock`: `None` when accepted, `Some(reason)` when rejected.
    /// The only non-TDP submission path, for JDP PushSolution: JDP-declared
    /// templates have no pool-side `template_id`, so
    /// `TdpHandle::submit_solution` cannot be used.
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

    /// Like [`Self::call`], but a `null` result is a success: `submitblock`
    /// answers "accepted" with `{"result": null}`, which `call` rejects as
    /// "neither result nor error".
    async fn call_raw(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let (envelope, _) = self.exchange(method, params).await?;
        Ok(envelope.result.unwrap_or(serde_json::Value::Null))
    }

    /// Generic RPC entry point for methods without a typed helper.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, RpcError> {
        let (envelope, status_err) = self.exchange(method, params).await?;
        match envelope.result {
            None | Some(serde_json::Value::Null) => Err(RpcError::BitcoinCore(RpcErrorDetail {
                code: 0,
                message: "RPC envelope had neither result nor error".to_string(),
            })),
            Some(value) => serde_json::from_value(value).map_err(|parse_err| match status_err {
                Some(http) => RpcError::Http(http),
                None => RpcError::Json(parse_err),
            }),
        }
    }

    /// One request; an error envelope is returned as `BitcoinCore`. Core sends
    /// application errors (e.g. `-5 Block not found`) with HTTP 500 and the
    /// envelope in the body, so the body is parsed regardless of status; the
    /// status error is only the fallback for a body that is not an envelope.
    async fn exchange(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<(RawRpcResponse, Option<reqwest::Error>), RpcError> {
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
        let status_err = resp.error_for_status_ref().err();
        let body = resp.bytes().await?;
        match serde_json::from_slice::<RawRpcResponse>(&body) {
            Ok(RawRpcResponse {
                error: Some(err), ..
            }) => Err(RpcError::BitcoinCore(err)),
            Ok(envelope) => Ok((envelope, status_err)),
            Err(parse_err) => Err(match status_err {
                Some(http) => RpcError::Http(http),
                None => RpcError::Json(parse_err),
            }),
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

/// The JSON-RPC response envelope, result left untyped.
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
        assert!(s.contains("\"jsonrpc\":\"1.0\""));
        assert!(s.contains("\"id\":42"));
        assert!(s.contains("\"method\":\"getnetworkinfo\""));
        assert!(s.contains("\"params\":[]"));
    }

    #[test]
    fn rpc_response_envelope_decodes_success() {
        let json = r#"{"result": {"answer": 42}, "error": null, "id": 1}"#;
        let env: RawRpcResponse = serde_json::from_str(json).unwrap();
        assert!(env.error.is_none());
        assert_eq!(env.result.as_ref().unwrap()["answer"], 42);
    }

    #[test]
    fn rpc_response_envelope_decodes_error() {
        let json = r#"{"result": null, "error": {"code": -8, "message": "bad param"}, "id": 1}"#;
        let env: RawRpcResponse = serde_json::from_str(json).unwrap();
        let e = env.error.unwrap();
        assert_eq!(e.code, -8);
        assert_eq!(e.message, "bad param");
    }

    #[test]
    fn cookie_auth_reads_well_formed_file() {
        let (mut file, path) = tempfile_in_default();
        file.write_all(b"__cookie__:abcdef1234567890\n").unwrap();
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
        let (mut file, path) = tempfile_in_default();
        file.write_all(b"no-colon-anywhere").unwrap();
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

    // Returns the path with the handle: `/proc/self/fd` does not exist on
    // macOS.
    fn tempfile_in_default() -> (std::fs::File, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("bp-bitcoin-test-cookie-{}", rand_suffix()));
        let file = std::fs::File::create(&path).unwrap();
        (file, path)
    }
    /// Unique per call across threads. The counter is needed because the
    /// macOS clock advances in 1µs steps.
    fn rand_suffix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// Pins that `rand_suffix` stays unique under thread contention.
    #[test]
    fn rand_suffix_is_unique_under_thread_contention() {
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| (0..64).map(|_| rand_suffix()).collect::<Vec<_>>()))
            .collect();
        let all: Vec<String> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("suffix thread"))
            .collect();
        let mut unique: Vec<&String> = all.iter().collect();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            all.len(),
            "rand_suffix collided: {} of {} values were distinct",
            unique.len(),
            all.len()
        );
    }
}
