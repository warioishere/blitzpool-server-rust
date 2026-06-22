// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared regtest test harness for blitzpool-rust.
//!
//! Spawns `bitcoin-node` (the IPC-enabled v31 binary, **not** legacy
//! `bitcoind`) in regtest mode with SV2 IPC enabled, then exposes:
//!
//! - the UNIX-socket path for TDP/JDP connections (`node.sock`),
//! - a JSON-RPC URL + cookie file for auxiliary RPC calls,
//! - convenience helpers to mine blocks and wait for tip height.
//!
//! # Prerequisites
//!
//! - Bitcoin Core v31.0 installed locally. The harness defaults to
//!   `/home/warioishere/bitcoin-31.0/libexec/bitcoin-node`; override with
//!   the `BITCOIN_NODE_PATH` environment variable.
//! - System packages `capnproto` + `libcapnp-dev` are required at *build*
//!   time by `bitcoin_core_sv2` consumers (TDP / JDP crates) but the
//!   harness itself does not depend on them.
//!
//! # Usage
//!
//! ```ignore
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
//!
//! # Test-only scope
//!
//! This crate is dev-only — never linked into the production `blitzpool`
//! binary. Every consumer wires it under `[dev-dependencies]`.

mod config;
mod error;
mod node;
mod rpc;

pub use config::{
    RegtestConfig, BITCOIN_NODE_PATH_ENV, DEFAULT_BITCOIN_NODE_PATH, DEFAULT_STARTUP_TIMEOUT_SECS,
};
pub use error::RegtestError;
pub use node::RegtestNode;
