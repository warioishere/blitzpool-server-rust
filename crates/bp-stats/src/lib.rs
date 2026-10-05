// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process statistics buffers: the share path folds each share in with
//! `add_*`, and the flush takes what is due and restores it if the write
//! fails. Pure logic with no I/O, so the hot path never waits on a
//! database.

pub mod accumulator;
pub mod buffer;
pub mod constants;
pub mod slot;

pub use accumulator::{
    share_max, AddressTotalsSnapshot, BestDifficultyAccumulator, BestDifficultyEntry,
    BestDifficultySnapshot, ClientStatisticsAccumulator, ClientStatisticsKey,
    ClientStatisticsRecord, ClientStatisticsSnapshot, PoolModeHashrateAccumulator,
    PoolModeHashrateSnapshot, PoolRejectedAccumulator, PoolRejectedSnapshot, PoolSharesAccumulator,
    PoolSharesRecord, PoolSharesSnapshot, RejectedReason, ShareTotalsAccumulator, WorkerKey,
    WorkerTotalsSnapshot,
};
pub use buffer::{BufferRecord, NestedDeltaBuffer, NumberDeltaBuffer, RecordDeltaBuffer};
pub use constants::{CHART_VISIBILITY_BUFFER_MS, MAX_REASONABLE_DIFFICULTY, SLOT_DURATION_MS};
pub use slot::{chart_visibility_cutoff_slot, TimeSlot};
