// SPDX-License-Identifier: AGPL-3.0-or-later

//! Job Declaration Protocol (JDP) — **core-side** wrapper.
//!
//! This crate bridges between the pool's runtime and bitcoin-core's SV2
//! IPC endpoint for JDP. It owns a single
//! [`bitcoin_core_sv2::unix_capnp::v31x::job_declaration_protocol::BitcoinCoreSv2JDP`]
//! instance on a dedicated OS thread (the underlying type is `!Send`) and
//! exposes a `Send + Clone` [`JdpHandle`] to the multi-threaded pool.
//!
//! # Scope
//!
//! - **In:** validate declared mining jobs against bitcoin-core's mempool
//!   and `checkBlock`, submit found-block solutions via `PushSolution`.
//! - **Out (intentionally):** the miner-facing JDP **server** (the
//!   downstream half of the protocol — accepting `DeclareMiningJob` from
//!   miners over Noise-encrypted TCP) lives in the `bp-stratum-v2` family
//!   This crate is the upstream half only.
//!
//! # Architecture
//!
//! ```text
//!  Pool runtime (multi-thread tokio)
//!  ────────────────────────────────────────────────────────
//!     bp-stratum-v2 (miner-facing JDP server)
//!       │ declare_mining_job()   │ push_solution()
//!       ▼                        ▼
//!     mpsc::Sender<WorkerMsg>  (each carries a oneshot::Sender for reply)
//!       │
//!  ─────┼─────────────────────────────────────────────────────
//!       │   bp-jdp-worker (dedicated OS thread)              │
//!       │   tokio::runtime + tokio::task::LocalSet            │
//!       │                                                     │
//!       │   bridge_in ── async_channel ──▶ BitcoinCoreSv2JDP  │
//!       │                                       │             │
//!       │   (DeclareMiningJob reply re-enters via embedded   │
//!       │    oneshot, then translated to DeclareMiningJobResult)
//!  ─────┼─────────────────────────────────────────────────────
//!                                │ Cap'n-Proto over UNIX socket
//!                                ▼
//!                          bitcoin-core v31.0
//! ```
//!
//! The same `CancellationToken` is observed by every internal task and by
//! `BitcoinCoreSv2JDP` itself. Dropping the last [`JdpHandle`] cancels and
//! joins the thread.
//!
//! See `memory/project-tdp-direct-architecture.md` for the bitcoin-core
//! integration rationale and `MIGRATION_PLAN.md` §4 step 7d for context.

mod config;
mod error;
mod handle;
mod message;
mod worker;

pub use config::{JdpConfig, DEFAULT_REQUEST_CAPACITY};
pub use error::JdpError;
pub use handle::JdpHandle;
pub use message::{DeclareMiningJobResult, PushSolutionRequest, ValidationContext};
