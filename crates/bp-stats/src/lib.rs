// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide statistics accumulation — in-process buffers for the
//! hot-path-writes-periodic-bulk-flush pattern.
//!
//! ## Scope
//!
//! Pure logic. The crate owns no I/O — no Redis, no PG, no cron. The
//! stratum crates call `add_*` methods to fold a single share into the
//! right accumulator(s); the service-wiring coordinator calls
//! `drain_*` and `confirm_*` to flush to PG.
//!
//! ## Modules
//!
//! - [`slot`] — `TimeSlot` newtype + helpers (current slot, chart
//!   visibility cutoff, slot-end alignment).
//! - [`buffer`] — three generic primitives:
//!   [`buffer::SwapBuffer`], [`buffer::NumberDeltaBuffer`],
//!   [`buffer::NestedDeltaBuffer`], [`buffer::RecordDeltaBuffer`].
//! - [`accumulator`] — six domain types built on top of the buffers,
//!   each wrapping a `Mutex<…>` so `add_*` from the stratum path is
//!   thread-safe.
//! - [`health`] — `FlushHealthMonitor` counts consecutive flush failures
//!   per flusher and surfaces a one-shot threshold-crossing signal.
//!
//! The bulk-flush queries (PG `unnest(...)` upserts) and the cron schedule
//! are deferred to the service-wiring layer — see `DEFERRED.md`.

pub mod accumulator;
pub mod buffer;
pub mod constants;
pub mod health;
pub mod slot;

pub use accumulator::{
    AddressTotalsSnapshot, BestDifficultyAccumulator, BestDifficultyEntry, BestDifficultySnapshot,
    ClientRejectedAccumulator, ClientRejectedKey, ClientRejectedSnapshot,
    ClientStatisticsAccumulator, ClientStatisticsKey, ClientStatisticsRecord,
    ClientStatisticsSnapshot, PoolModeHashrateAccumulator, PoolModeHashrateSnapshot,
    PoolRejectedAccumulator, PoolRejectedSnapshot, PoolSharesAccumulator, PoolSharesRecord,
    PoolSharesSnapshot, RejectedReason, ShareTotalsAccumulator, WorkerKey, WorkerTotalsSnapshot,
};
pub use buffer::{
    BufferRecord, NestedDeltaBuffer, NumberDeltaBuffer, RecordDeltaBuffer, SwapBuffer,
};
pub use constants::{
    CHART_VISIBILITY_BUFFER, CHART_VISIBILITY_BUFFER_MS, FLUSH_FAILURE_WARN_THRESHOLD,
    MAX_REASONABLE_DIFFICULTY, SLOT_DURATION_MS,
};
pub use health::{FlushHealth, FlushHealthMonitor};
pub use slot::{chart_visibility_cutoff_slot, TimeSlot};
