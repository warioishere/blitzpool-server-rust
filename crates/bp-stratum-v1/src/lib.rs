// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V1 server — JSON-RPC parser/emitter, ckpool-style job lifecycle,
//! TDP→mining.notify translator, vardiff, share validator, per-connection
//! statemachine.
//!
//! Architecture notes:
//!
//! - **Multi-thread by default.** Per-connection task on the tokio
//!   multi-thread runtime; share validation runs inline (~µs hashes don't
//!   warrant `spawn_blocking`).
//! - **TDP is the upstream.** This crate consumes
//!   `bp_template_distribution::TdpHandle` for `NewTemplate` +
//!   `SetNewPrevHash` updates and translates them to SV1 `mining.notify`
//!   frames. There is no `getblocktemplate` polling.
//! - **Behavioural spec.** Frame shape, edge cases, vardiff cadence, and
//!   reject-strings follow the documented SV1 protocol behaviour, with
//!   `mining.notify[5..8]` in the 8-hex-padded ckpool form.

mod client;
mod config;
mod error;
mod frame;
mod hooks;
mod jobs;
mod notify;
mod server;
mod shared_adapter;
mod submit;

pub use config::{PortConfig, ServerConfig, DEFAULT_POOL_IDENTIFIER};
pub use error::StratumV1Error;
pub use frame::parse_request;
pub use hooks::{BlockSubmissionSink, PayoutResolver, ServerHooks};
pub use notify::{build_notify_frame, swap_endian_words, ActiveSV1Template};
pub use server::{SharedExtranonce, StratumV1Server};
pub use submit::ShareAccept;
