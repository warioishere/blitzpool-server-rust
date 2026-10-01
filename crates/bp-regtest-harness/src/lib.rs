// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dev-only regtest harness: spawns the multiprocess `bitcoin-node` (not
//! `bitcoind`, which has no IPC) with SV2 IPC and exposes `node.sock`, RPC
//! and mining helpers. Found via [`discover_bitcoin_node`] or
//! `BITCOIN_NODE_PATH`; needs at least [`MIN_BITCOIN_NODE_MAJOR`].
//!
//! ```no_run
//! use bp_regtest_harness::{RegtestConfig, RegtestNode};
//! use std::time::Duration;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // Fast-skip if the binary isn't installed (e.g. on CI without bitcoin-core).
//! if !RegtestConfig::default().is_available() {
//!     return Ok(());
//! }
//! let node = RegtestNode::start().await?;
//! let height = node.generate_to_self(101).await?;
//! assert!(height >= 101);
//!
//! // Connect bp-template-distribution against node.ipc_socket_path() ...
//!
//! node.shutdown().await?;
//! # Ok(()) }
//! ```

mod config;
mod error;
mod node;
mod rpc;

pub use config::{
    discover_bitcoin_node, RegtestConfig, BITCOIN_NODE_PATH_ENV, DEFAULT_STARTUP_TIMEOUT_SECS,
    MIN_BITCOIN_NODE_MAJOR,
};
pub use error::RegtestError;
pub use node::RegtestNode;
