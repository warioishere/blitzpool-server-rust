// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session `client_entity` rows (birth, the session's best, soft-delete)
//! and the live `client:live:*` hashes. The per-address best belongs to
//! `bp-share-stats-sink`.

pub mod config;
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
pub use hooks::SessionPersistenceHook;
