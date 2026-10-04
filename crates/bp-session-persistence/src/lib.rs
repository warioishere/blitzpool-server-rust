// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session `client_entity` rows, live `client:live:*` hashes and hourly
//! difficulty stats. The persisted best difficulty belongs to
//! `bp-share-stats-sink`, not to this crate.

pub mod config;
mod diff_stat_buffer;
pub mod engine;
pub mod error;
mod hashrate_watchdog;
pub mod hooks;
mod live_store;
mod row_debounce;
mod touch_buffer;

pub use config::SessionPersistenceConfig;
pub use engine::{SessionPersistenceEngine, SessionPersistenceEngineHandle};
pub use error::SessionPersistenceError;
pub use hooks::{ClientDifficultyStatisticsSink, SessionPersistenceHook};
