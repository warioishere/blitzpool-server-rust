// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bitcoin Core auxiliary JSON-RPC client.
//!
//! **Scope:** read-only "metadata" RPCs (`getnetworkinfo`,
//! `getmininginfo`, `getpeerinfo`) PLUS one deliberate exception —
//! `submitblock`. **Not** in this crate:
//!
//! - `getblocktemplate` — pool reads templates exclusively through
//!   TDP (`bp-template-distribution`).
//! - Block submission for pool-built templates — those go through
//!   `TdpHandle::submit_solution` (TDP-direct architecture).
//! - ZMQ block notifications — replaced by TDP `SetNewPrevHash`.
//!
//! ## The `submitblock` exception
//!
//! JDP-declared jobs (Job Declaration Protocol Full-Template mode)
//! are built by the JDC, not the pool — pool's bitcoin-core has no
//! `template_id` for them, so `TdpHandle::submit_solution` doesn't
//! work for the JDP-PushSolution orphan-protection path. The pool
//! must reconstruct the block bytes itself and submit them via the
//! classical `submitblock` RPC. See [`BitcoinRpc::submit_block`]
//! for the rationale + the bin's `jdp_hooks.rs` for the wiring.
//!
//! # Auth
//!
//! Supports two auth modes mirroring how miners typically run bitcoind:
//! - **Cookie file** (`-rpccookiefile=...` or `<datadir>/.cookie`) — used by
//!   regtest/local dev. The cookie file contains `__cookie__:<random-token>`.
//! - **User + password** — production `bitcoin.conf` with `rpcuser` /
//!   `rpcpassword`.
//!
//! # Async runtime
//!
//! Built on `reqwest` + `tokio`. The client is cheap to clone (internal
//! `reqwest::Client` shares a connection pool).

mod client;
mod config;
mod error;
mod types;

pub use client::BitcoinRpc;
pub use config::{BitcoinRpcConfig, RpcAuth};
pub use error::{RpcError, RpcErrorDetail};
pub use types::{
    BlockHeaderInfo, LocalAddress, MiningInfo, NetworkInfo, NetworkInfoNetwork, PeerInfo,
};
