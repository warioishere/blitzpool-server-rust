// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session client-row persistence + per-session difficulty stats.
//!
//! Persists `client_entity` rows on authorize/disconnect and records the
//! per-session difficulty statistics on the share hot-path. Best
//! difficulty is no longer handled here — it folds into the batched
//! stats-sink flush (`bp-share-stats-sink`), so there is no per-share
//! write-through cache to diverge after an out-of-band reset. Decomposes
//! into:
//!
//! - **[`hooks::SessionPersistenceHook`]** — `bp_stratum_v1::SessionPersistence`
//!   trait impl. On `register_session` (miner authorize), pends the
//!   session in the row-birth debounce — no statement; the row is born
//!   by the engine's flush once the session survives the debounce
//!   window. On `deregister_session` (disconnect), soft-deletes by
//!   `sessionId` — only if a row was born. Mode-blind: every authorize
//!   lands here.
//! - **[`hooks::ClientDifficultyStatisticsSink`]** — `bp-share-hook`
//!   accepted-share sink recording the per-(address, worker, hour-slot)
//!   MAX submission difficulty into `client_difficulty_statistics_entity`.
//! - **[`engine::SessionPersistenceEngine`]** — `spawn(config, pool)` →
//!   handle exposing the hooks-ready references.

pub mod config;
mod diff_stat_buffer;
pub mod engine;
pub mod error;
mod hashrate_sampler;
pub mod hooks;
mod row_debounce;
mod touch_buffer;

pub use config::SessionPersistenceConfig;
pub use engine::{SessionPersistenceEngine, SessionPersistenceEngineHandle};
pub use error::SessionPersistenceError;
pub use hooks::{ClientDifficultyStatisticsSink, SessionPersistenceHook};
