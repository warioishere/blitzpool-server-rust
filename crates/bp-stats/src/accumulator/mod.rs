// SPDX-License-Identifier: AGPL-3.0-or-later

//! Domain accumulators on top of the generic buffers. Each holds a short,
//! await-free `Mutex`; `add_*` is infallible because the share path must not
//! fail. The stats sink drops out-of-range or non-finite difficulties before
//! they get here.

mod best_difficulty;
mod client_statistics;
mod pool_mode_hashrate;
mod pool_rejected;
mod pool_shares;
mod share_totals;

pub use best_difficulty::{BestDifficultyAccumulator, BestDifficultyEntry, BestDifficultySnapshot};
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

/// A share's contribution to a slot maximum: the difficulty it solved, or
/// nothing for a non-finite or non-positive value.
pub fn share_max(submission_difficulty: f64) -> f64 {
    if submission_difficulty.is_finite() && submission_difficulty > 0.0 {
        submission_difficulty
    } else {
        0.0
    }
}

/// Why a share was rejected. The string forms are stored verbatim in the
/// `reason` columns and read by the frontend, so they must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RejectedReason {
    JobNotFound,
    DuplicateShare,
    LowDifficulty,
    /// Job was retired past the network-jitter grace window. Kept apart from
    /// `JobNotFound` so block-transition churn is distinguishable from a miner bug.
    Stale,
    /// Version bits rolled outside the negotiated BIP-310 mask. Its own bucket
    /// because the proof-of-work may be fine: this is a miner ignoring what it
    /// negotiated, not a difficulty miss.
    VersionRollingNotAllowed,
}

impl RejectedReason {
    /// Name as stored in PG and shown in the UI's per-reason series.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JobNotFound => "JobNotFound",
            Self::DuplicateShare => "DuplicateShare",
            Self::LowDifficulty => "LowDifficultyShare",
            Self::Stale => "Stale",
            Self::VersionRollingNotAllowed => "VersionRollingNotAllowed",
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
        assert_eq!(
            RejectedReason::VersionRollingNotAllowed.as_str(),
            "VersionRollingNotAllowed"
        );
    }
}
