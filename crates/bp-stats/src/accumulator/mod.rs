// SPDX-License-Identifier: AGPL-3.0-or-later

//! Domain-specific accumulators built on top of the generic buffers.
//!
//! Each accumulator owns a `Mutex<Buffer>` so the hot-path mutation
//! happens under a short lock with no `.await`. All `add_*` methods are
//! infallible (the share path must not throw) — over-range or non-finite
//! inputs are silently discarded with the calling layer responsible for
//! its own observability.

mod client_rejected;
mod client_statistics;
mod pool_mode_hashrate;
mod pool_rejected;
mod pool_shares;
mod share_totals;

pub use client_rejected::{ClientRejectedAccumulator, ClientRejectedKey, ClientRejectedSnapshot};
pub use client_statistics::{
    ClientStatisticsAccumulator, ClientStatisticsKey, ClientStatisticsRecord,
    ClientStatisticsSnapshot,
};
pub use pool_mode_hashrate::{PoolModeHashrateAccumulator, PoolModeHashrateSnapshot};
pub use pool_rejected::{PoolRejectedAccumulator, PoolRejectedSnapshot};
pub use pool_shares::{PoolSharesAccumulator, PoolSharesRecord, PoolSharesSnapshot};
pub use share_totals::{
    AddressTotalsSnapshot, ShareTotalsAccumulator, WorkerKey, WorkerTotalsSnapshot,
};

/// Categorisation of a rejected share. The string forms are written
/// verbatim to the `reason` column on `pool_rejected_statistics_entity`
/// and `client_rejected_statistics_entity` — they match the values the
/// frontend expects to see in `/api/info/rejected` per-slot counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RejectedReason {
    JobNotFound,
    DuplicateShare,
    LowDifficulty,
    /// Job entry existed but was retired past the network-jitter
    /// grace window. Distinct from `JobNotFound` (entry GC'd / never
    /// existed) so operators can tell normal block-transition churn
    /// from a real miner bug.
    Stale,
}

impl RejectedReason {
    /// Wire-form name as written to PG and emitted in the UI's
    /// per-reason chart series.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JobNotFound => "JobNotFound",
            Self::DuplicateShare => "DuplicateShare",
            Self::LowDifficulty => "LowDifficultyShare",
            Self::Stale => "Stale",
        }
    }
}

impl std::fmt::Display for RejectedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_reason_wire_strings_are_camel_case() {
        assert_eq!(RejectedReason::JobNotFound.as_str(), "JobNotFound");
        assert_eq!(RejectedReason::DuplicateShare.as_str(), "DuplicateShare");
        assert_eq!(RejectedReason::LowDifficulty.as_str(), "LowDifficultyShare");
        assert_eq!(RejectedReason::Stale.as_str(), "Stale");
    }
}
