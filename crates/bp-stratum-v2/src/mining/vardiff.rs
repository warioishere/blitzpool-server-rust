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
//! A second, JDC-specific controller used to live here: a share-COUNT
//! algorithm on a fixed interval, selected by an `is_jdc` channel flag.
//! It was removed because its premise does not hold. The reasoning was
//! that a job-declaration client pre-filters shares against its own
//! target, so the pool loses sight of the share distribution and cannot
//! estimate a rate. What the client actually filters against is the
//! target the POOL assigned it, forwarding only shares that meet it — so
//! what reaches us is exactly what a direct miner sends: shares at the
//! difficulty we set. The classic estimator only ever needed that
//! aggregate arrival rate; the per-miner distribution behind the client
//! was never an input. A JDC also runs no vardiff of its own on the
//! pool-facing channel — it only applies our `SetTarget` — so the pool
//! retargeting it is not optional.
//!
//! The count-based controller was also strictly weaker: one estimate per
//! CONNECTION rather than per channel (which SV2 difficulty is), counting
//! shares instead of summing their difficulty (wrong across a retarget,
//! where a channel's shares span two difficulties), and holding its last
//! output below two shares per interval. The `is_jdc` flag that selected
//! it was never set outside tests, so it never ran in production.

pub use bp_vardiff::{
    Clock, SystemClock, TestClock, VarDiffEngine, VARDIFF_CACHE_SIZE, VARDIFF_CACHE_WINDOW_MS,
    VARDIFF_DEFAULT_MIN_DIFFICULTY, VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN, VARDIFF_DIFFICULTY_1,
    VARDIFF_SAMPLE_THRESHOLD, VARDIFF_SLOT_DURATION_MS, VARDIFF_WARMUP_MS,
};
