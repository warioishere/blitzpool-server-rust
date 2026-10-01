// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vardiff for every SV2 channel: the [`bp_vardiff`] engine shared with SV1.
//! A JDC channel needs no separate controller: it forwards only shares meeting
//! the pool's target and runs no vardiff of its own, so the pool retargets it
//! like a direct miner.

pub use bp_vardiff::{
    Clock, SystemClock, TestClock, VarDiffEngine, VARDIFF_CACHE_SIZE, VARDIFF_CACHE_WINDOW_MS,
    VARDIFF_DEFAULT_MIN_DIFFICULTY, VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN,
    VARDIFF_SAMPLE_THRESHOLD, VARDIFF_SLOT_DURATION_MS, VARDIFF_WARMUP_MS,
};
