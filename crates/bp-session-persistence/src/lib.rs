// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session client-row persistence + best-difficulty cache.
//!
//! Persists `client_entity` rows on authorize/disconnect + caches the
//! per-address best difficulty on the share hot-path. Decomposes into:
//!
//! - **[`hooks::SessionPersistenceHook`]** — `bp_stratum_v1::SessionPersistence`
//!   trait impl. On `register_session` (miner authorize), upserts a row
//!   into `client_entity`. On `deregister_session` (disconnect),
//!   soft-deletes by `sessionId`. Mode-blind: every authorize lands here.
//! - **[`hooks::BestDifficultySink`]** — `bp_stratum_v1::AcceptedShareSink`
//!   impl that tracks per-address best difficulty. On every accepted
//!   share, compares `accept.submission_difficulty` against the cached
//!   best; if higher, write-through to PG + cache.
//! - **[`address_settings_cache::InMemoryAddressSettingsCache`]** —
//!   in-process best-difficulty cache. A Redis-backed variant would be
//!   needed for multi-node deployments; we run a single pool node and
//!   chose the in-memory variant per user-confirmed scope 2026-05-16.
//! - **[`client_row`]** — thin wrappers around the two new `bp-db`
//!   primitives (`upsert_client`, `delete_client_for_session`).
//! - **[`engine::SessionPersistenceEngine`]** — `spawn(config, pool)` →
//!   handle exposing the cache + hooks-ready references.

pub mod address_settings_cache;
pub mod client_row;
pub mod config;
pub mod engine;
pub mod error;
mod hashrate_sampler;
pub mod hooks;
mod touch_buffer;

pub use address_settings_cache::{
    AddressSettingsCache, CachedAddressSettings, InMemoryAddressSettingsCache,
};
pub use config::SessionPersistenceConfig;
pub use engine::{SessionPersistenceEngine, SessionPersistenceEngineHandle};
pub use error::SessionPersistenceError;
pub use hooks::{BestDifficultySink, ClientDifficultyStatisticsSink, SessionPersistenceHook};
