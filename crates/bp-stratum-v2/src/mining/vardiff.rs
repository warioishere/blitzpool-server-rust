// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vardiff for SV2 mining channels — one algorithm, re-exported.
//!
//! Every SV2 channel retargets through the classic engine in
//! [`bp_vardiff`] (sliding 30-sample / 5-min window, shares-per-minute
//! target, ±2× clamp, power-of-2 rounding, warmup, ckpool race-clamp),
//! shared with `bp-stratum-v1`. This module is the re-export so callers
//! don't need a second `use` line.
//!
//! **Standard**, **Extended** and **job-declaration** channels alike.
//!
//! A job-declaration client needs no separate controller: it forwards only
//! shares meeting the target the POOL assigned it, so the pool sees exactly
//! what a direct miner sends, and the estimator only needs that aggregate
//! arrival rate. A JDC runs no vardiff of its own on the pool-facing
//! channel (it only applies the pool's `SetTarget`), so the pool must
//! retarget it.

pub use bp_vardiff::{
    Clock, SystemClock, TestClock, VarDiffEngine, VARDIFF_CACHE_SIZE, VARDIFF_CACHE_WINDOW_MS,
    VARDIFF_DEFAULT_MIN_DIFFICULTY, VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN,
    VARDIFF_SAMPLE_THRESHOLD, VARDIFF_SLOT_DURATION_MS, VARDIFF_WARMUP_MS,
};
