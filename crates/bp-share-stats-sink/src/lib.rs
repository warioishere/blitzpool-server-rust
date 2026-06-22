// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide share statistics sink — coordinator-flush pattern.
//!
//! Wraps `bp-stats`'s 6 in-memory accumulators with a 60 s flush cron
//! that bulk-upserts to 7 PG tables (5 slot-bucketed stats tables +
//! `address_settings_entity.shares` lifetime totals + `worker_shares_entity`
//! per-worker cumulative counts).
//!
//! Mode-blind: every accepted / rejected share lands here regardless of
//! solo / PPLNS / group-solo. The Stratum-server composes this sink with
//! `bp-pplns-engine`'s and `bp-group-solo-engine`'s hooks via a
//! [`tokio::join!`]-style fan-out in `bin/blitzpool`.
//!
//! ## Modules
//!
//! - [`config`] — engine tunables (flush interval, batch size,
//!   slot-aligned flushes on/off).
//! - [`error`] — `SinkError` enum.
//! - [`flush`] — drain accumulators → build 7 bulk-upserts → confirm on
//!   success → update `FlushHealthMonitor`.
//! - [`seed`] — boot-time one-shot `seedIfEmpty` for `worker_shares_entity`
//!   (mirrors `WorkerSharesService.seedIfEmpty`).
//! - [`hooks`] — `AcceptedShareSink` + `RejectedShareSink` impls fan
//!   shares into the accumulators; block + session hooks are no-ops.
//! - [`reader`] — read-only handle for `/api/admin/stats-health`
//!   surface.
//! - [`engine`] — `ShareStatsEngine::spawn(...)` → handle + 60 s tick
//!   with slot-transition spot-flush.

pub mod config;
pub mod engine;
pub mod error;
pub mod flush;
pub mod hooks;
pub mod reader;
pub mod seed;

pub use seed::{seed_if_empty, seed_if_empty_with_executor};

pub use config::StatsSinkConfig;
pub use engine::{ShareStatsEngine, ShareStatsEngineHandle};
pub use error::SinkError;
pub use hooks::{ShareStatsAcceptedSink, ShareStatsRejectedSink};
pub use reader::ReaderView;
