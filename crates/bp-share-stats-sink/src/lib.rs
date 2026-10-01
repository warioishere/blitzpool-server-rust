// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide share statistics: in-memory accumulators flushed every 60 s as
//! bulk upserts into seven PG tables.
//! Mode-blind: every accepted and rejected share lands here, whatever the
//! payout mode.

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
