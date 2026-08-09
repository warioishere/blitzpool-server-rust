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
//! - Bitcoin Core **v31 or newer** with the multiprocess `bitcoin-node`
//!   binary installed locally. The harness finds it by searching `$PATH`
//!   and the usual tarball prefixes (see [`discover_bitcoin_node`]) — no
//!   path is hard-coded, so Linux and macOS both work out of the box. Set
//!   `BITCOIN_NODE_PATH` to name one explicitly; when set it is used
//!   verbatim and nothing else is searched, which is the knob to reach for
//!   when the node is a local build outside those prefixes.
//!
//!   The version floor is [`MIN_BITCOIN_NODE_MAJOR`] and it is enforced,
//!   not advisory: v31 moved `Init.makeMining` from `@2` to `@3`, and our
//!   capnp bindings call `@3`. So a v30 node spawns, serves RPC, creates
//!   `node.sock` — and then answers TDP startup with a capnp
//!   `Unimplemented`. Discovery reads `-version` and skips such a node with
//!   a message saying so.
//!
//!   Note `bitcoin-node` is NOT what Homebrew's `bitcoin` formula
//!   installs — that ships legacy `bitcoind`, which has no IPC. On macOS
//!   this binary comes from an upstream multiprocess tarball or a local
//!   build.
//! - System packages `capnproto` + `libcapnp-dev` are required at *build*
//!   time by `bitcoin_core_sv2` consumers (TDP / JDP crates) but the
//!   harness itself does not depend on them.
//!
//! # Usage
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
    discover_bitcoin_node, RegtestConfig, BITCOIN_NODE_PATH_ENV, DEFAULT_STARTUP_TIMEOUT_SECS,
    MIN_BITCOIN_NODE_MAJOR,
};
pub use error::RegtestError;
pub use node::RegtestNode;
