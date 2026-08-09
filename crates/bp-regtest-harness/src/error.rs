// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum RegtestError {
    #[error(
        "bitcoin-node binary not found (searched $PATH and the usual tarball prefixes; last \
         tried {0}). Set BITCOIN_NODE_PATH, or install a bitcoin-core MULTIPROCESS build: the \
         harness needs the IPC-enabled `bitcoin-node`, not the legacy `bitcoind` that \
         Homebrew's `bitcoin` formula ships"
    )]
    BinaryNotFound(PathBuf),

    #[error("failed to spawn bitcoin-node: {0}")]
    Spawn(String),

    #[error("bitcoin-node exited during startup: status={0}")]
    ExitedDuringStartup(String),

    #[error("timed out waiting for {what} after {seconds}s")]
    Timeout { what: &'static str, seconds: u64 },

    #[error("RPC call '{method}' failed: {detail}")]
    Rpc {
        method: &'static str,
        detail: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not allocate a free TCP port: {0}")]
    PortAlloc(String),

    #[error("regtest harness has already been shut down")]
    AlreadyShutDown,
}
