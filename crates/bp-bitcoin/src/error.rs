// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type and JSON-RPC error envelope.

use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("failed to read cookie file at {path}: {source}")]
    CookieRead {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("cookie file malformed: expected `user:password`, got {got:?}")]
    CookieMalformed { got: String },
    #[error("JSON serialize/deserialize: {0}")]
    Json(#[from] serde_json::Error),
    /// Bitcoin Core returned a non-null `error` field in the JSON-RPC envelope.
    #[error("RPC error from bitcoin-core: {0}")]
    BitcoinCore(RpcErrorDetail),
    /// 401 from bitcoind — bad cookie or bad user/password.
    #[error("unauthorized — check cookie file or rpcuser/rpcpassword")]
    Unauthorized,
}

/// The `error` object inside a JSON-RPC response.
/// Code semantics mirror `src/rpc/protocol.h` in bitcoin-core
/// (e.g. -32601 for "method not found", -8 for "invalid parameter").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcErrorDetail {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for RpcErrorDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code {}: {}", self.code, self.message)
    }
}
