// SPDX-License-Identifier: AGPL-3.0-or-later

//! Template Distribution Protocol (TDP) client.
//!
//! This crate is an in-process bridge between bitcoin-core's SV2 IPC
//! endpoint and the rest of the Blitzpool runtime. It owns a single
//! [`bitcoin_core_sv2::template_distribution_protocol::BitcoinCoreSv2TDP`]
//! instance on a dedicated OS thread (the underlying type is `!Send`
//! because `capnp-rpc` is not `Send`) and exposes a `Send + Clone`
//! [`TdpHandle`] to the multi-threaded pool runtime.
//!
//! # Architecture
//!
//! ```text
//!  Pool runtime (multi-thread tokio)
//!  ────────────────────────────────────────────────────────
//!     bp-stratum-v1, bp-stratum-v2, bp-api, ...
//!       │ subscribe()           │ submit_solution(), …
//!       ▼                       ▼
//!     broadcast::Receiver   mpsc::Sender
//!       │                       │
//!  ─────┼───────────────────────┼───────────────────────────
//!       │   bp-tdp-worker (dedicated OS thread)            │
//!       │   tokio::runtime + tokio::task::LocalSet          │
//!       │                                                   │
//!       │   bridge_out ◀── async_channel ── BitcoinCoreSv2TDP
//!       │   bridge_in  ──▶ async_channel ──▶               │
//!  ──────────────────────────────────────────────────────────
//!                                │ Cap'n-Proto over UNIX socket
//!                                ▼
//!                          bitcoin-core v31.0
//! ```
//!
//! Cancellation flows through a single [`tokio_util::sync::CancellationToken`]
//! that the public handle holds and that every internal task observes.
//! Dropping the last [`TdpHandle`] clone cancels the worker and joins the
//! thread.
//!
//! # Scope
//!
//! - **In:** TDP message exchange (templates out, solutions and tx-data
//!   requests in), startup `CoinbaseOutputConstraints`, graceful shutdown.
//! - **Out:** SV1 `mining.notify` translation (lives in `bp-stratum-v1`),
//!   SV2 frame serialisation (`bp-stratum-v2`), JDP (`bp-job-declaration`,
//!   same topology pattern).
//!
//! See `memory/project-tdp-direct-architecture.md` for the rationale and
//! `MIGRATION_PLAN.md` §4 step 7b for the larger picture.

mod config;
mod error;
mod handle;
mod message;
mod tx_cache;
mod worker;

pub use config::{
    TdpCoinbaseConstraints, TdpConfig, DEFAULT_BROADCAST_CAPACITY, DEFAULT_FEE_THRESHOLD,
    DEFAULT_MIN_INTERVAL_SECS, DEFAULT_RECONNECT_BACKOFF_SECS, DEFAULT_SUBMIT_CAPACITY,
};
pub use error::TdpError;
pub use handle::TdpHandle;
pub use message::{
    apply_to_snapshot, bootstrap_assembler_from_snapshot, NewTemplate, RequestTransactionDataError,
    RequestTransactionDataSuccess, SetNewPrevHash, TdpRequest, TemplateAssembler, TemplateSnapshot,
    TemplateUpdate,
};
pub use tx_cache::{TemplateTxCache, DEFAULT_TEMPLATE_FIFO};
