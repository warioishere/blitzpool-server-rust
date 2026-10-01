// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connection configuration + auth modes.

use std::path::PathBuf;

/// Where the RPC client connects to and how it authenticates.
#[derive(Clone, Debug)]
pub struct BitcoinRpcConfig {
    /// Base URL without trailing slash.
    pub url: String,
    pub auth: RpcAuth,
    /// Per-request timeout. `None` = `reqwest` default (~30s).
    pub timeout: Option<std::time::Duration>,
}

/// JSON-RPC authentication mode.
#[derive(Clone, Debug)]
pub enum RpcAuth {
    /// Cookie file path. Read on every connect because bitcoind rotates the
    /// cookie on restart.
    Cookie(PathBuf),
    /// Static credentials from `bitcoin.conf` (`rpcuser` / `rpcpassword`).
    UserPassword { user: String, password: String },
}
