// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide share statistics: in-memory accumulators flushed by a 60 s
//! wall-clock tick as bulk upserts into six PG tables; a client row is
//! written once its 10-minute slot ended.
//! Mode-blind: every accepted and rejected share lands here, whatever the
//! payout mode.

pub mod config;
pub mod engine;
pub mod flush;
pub mod hooks;

pub use config::StatsSinkConfig;
pub use engine::{ShareStatsEngine, ShareStatsEngineHandle};
pub use hooks::{ShareStatsAcceptedSink, ShareStatsRejectedSink};
