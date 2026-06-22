// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared retire-not-clear job lifecycle math used by both
//! [`bp-stratum-v1`] (`JobRegistry` — global, hex-string keys, with
//! template-indirection) and [`bp-stratum-v2`] (per-channel
//! `extended_jobs: HashMap<u32, ExtendedJob>`).
//!
//! The pattern is the same in both protocols, the storage shapes are
//! different. This crate carries the **math + constants + classifier +
//! aging algorithm**; each consumer keeps its own storage struct and
//! exposes its own public API around the shared primitives.
//!
//! Originally lived in `bp-stratum-v1::jobs` and was duplicated in
//! `bp-stratum-v2::mining::jobs`; extracted 2026-05-16 (the same week
//! [`bp-vardiff`] was extracted) so both protocols keep their lifecycle
//! constants in lock-step. The default values are:
//!
//! | Field | Env var | Default | Reason |
//! |---|---|---|---|
//! | `grace_ms` | `STALE_GRACE_MS` / `SV2_STALE_GRACE_MS` | `5000` | Network-jitter absorption — shares against jobs retired ≤ 5 s ago are still credited |
//! | `retention_ms` | `JOB_RETENTION_MS` / `SV2_EXTENDED_JOB_RETENTION_MS` | `600000` | Retired entries past 10 min are GC-eligible |
//! | `min_retained` | `MIN_RETAINED` | `3` | Floor to protect the newest 3 entries from aging — guards startup-window where everything is fresh |
//!
//! Why retire-not-clear at all: previously the jobs map was wiped
//! synchronously on block change BEFORE broadcasting the new
//! `mining.notify` / `NewExtendedMiningJob`. In-flight shares for the
//! just-cleared old job got rejected with the wrong code
//! (`invalid-job-id` instead of `stale-share`). SV2 spec §5.3.14
//! distinguishes the two; SV1 has no separate stale code but still
//! benefits from accepting near-block-change shares with credit.
//!
//! ## Two primitives
//!
//! - [`classify`] — given a job's `retired_at` timestamp (or `None`),
//!   the current wall-clock, and a [`LifecycleConfig`], decide whether
//!   the job is `Active`, `StaleCreditable` (retired ≤ grace), or
//!   `StaleRejected` (retired > grace). Pure function, no allocation.
//!
//! - [`age_entries`] — generic over the storage map's key + value type,
//!   threads two closures (`get_creation` + `get_retired`) so the
//!   caller's value type can name the fields anything (SV1 uses
//!   `creation_ms` / `retired_at_ms`; SV2 uses `created_at` / `retired_at`).
//!   Two-tier deletion — primary (retired AND past retention) +
//!   defense-in-depth (non-retired AND past 2× retention) — both gated
//!   by the [`LifecycleConfig::min_retained`] floor.
//!
//! ## Why no retire helper
//!
//! Stamping `retired_at = Some(now)` on every entry that doesn't have
//! one is just `for entry in map.values_mut() { if get(entry).is_none()
//! { set(entry, now); } }`. Wrapping that in a generic two-closure
//! helper is more boilerplate than it saves. Each consumer writes the
//! 3-line loop directly with whichever field name they chose.

use std::collections::HashMap;
use std::hash::Hash;

// ── JobClassification ────────────────────────────────────────────────

/// Three-way share-validation outcome.
///
/// - `Active` — the job has not been retired; validate normally.
/// - `StaleCreditable` — retired ≤ [`LifecycleConfig::grace_ms`] ago;
///   validate normally + record as accepted.
/// - `StaleRejected` — retired beyond the grace window; reject.
///
/// SV1 wire-mapping (caller's job): `Active` / `StaleCreditable` →
/// success, `StaleRejected` → `mining.submit` error code 21
/// `Stale share`. SV2 wire-mapping: `Active` / `StaleCreditable` →
/// `SubmitSharesSuccess`, `StaleRejected` → `SubmitSharesError` with
/// code `stale-share` (NOT `invalid-job-id` — the job *was* known).
///
/// A genuinely missing entry (`HashMap::get` returns `None`) is the
/// caller's `invalid-job-id` case — only reachable after [`age_entries`]
/// has GC'd the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobClassification {
    Active,
    StaleCreditable,
    StaleRejected,
}

// ── LifecycleConfig ──────────────────────────────────────────────────

/// Lifecycle parameters. Consumers either use [`LifecycleConfig::DEFAULT`]
/// or build their own from a server config struct
/// (SV1 reads them out of `ServerConfig`; SV2 will read them out of env
/// vars when the bin/blitzpool wiring lands).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleConfig {
    /// Shares against a job retired ≤ this many ms ago are
    /// `StaleCreditable`.
    pub grace_ms: u64,
    /// Retired entries past this window are eligible for GC by
    /// [`age_entries`]. Subject to the [`Self::min_retained`] floor.
    pub retention_ms: u64,
    /// Newest-first floor: never delete below this many entries
    /// regardless of retired-status / age. Defends against the
    /// startup-window where everything is fresh and aging shouldn't fire.
    pub min_retained: usize,
}

impl LifecycleConfig {
    /// Default values: 5 s grace / 10 min retention / 3 entry floor.
    pub const DEFAULT: Self = Self {
        grace_ms: 5_000,
        retention_ms: 600_000,
        min_retained: 3,
    };
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ── classify ─────────────────────────────────────────────────────────

/// Classify a stored job by its `retired_at` timestamp. Pure function.
///
/// - `retired_at = None` → [`JobClassification::Active`]
/// - `now_ms - retired_at <= grace_ms` → [`JobClassification::StaleCreditable`]
///   (boundary inclusive)
/// - else → [`JobClassification::StaleRejected`]
pub fn classify(retired_at: Option<u64>, now_ms: u64, cfg: &LifecycleConfig) -> JobClassification {
    match retired_at {
        None => JobClassification::Active,
        Some(retired_at_ms) => {
            let age = now_ms.saturating_sub(retired_at_ms);
            if age <= cfg.grace_ms {
                JobClassification::StaleCreditable
            } else {
                JobClassification::StaleRejected
            }
        }
    }
}

// ── age_entries ──────────────────────────────────────────────────────

/// Generic two-tier age-out helper for any storage that holds entries
/// with a `created_at` and an optional `retired_at` timestamp.
///
/// The two `get_*` closures decouple this from any particular value
/// type so SV1 (`JobEntry`/`TemplateEntry` with `creation_ms` /
/// `retired_at_ms`) and SV2 (`ExtendedJob` with `created_at` /
/// `retired_at`) both call the same algorithm.
///
/// Algorithm:
///
/// 1. If `map.len() <= cfg.min_retained`, return — nothing eligible.
/// 2. Sort all keys newest-first by `get_creation`. Skip the first
///    `cfg.min_retained` (always protected).
/// 3. For each remaining candidate:
///    - **Primary**: if `get_retired(entry)` returns `Some(retired_at)`
///      AND `now_ms - retired_at > cfg.retention_ms` → delete.
///    - **Defense-in-depth**: else if `now_ms - get_creation(entry) >
///      2 * cfg.retention_ms` → delete. Catches clock jumps or missed
///      retire signals where a non-retired entry piles up far past
///      retention.
///
/// Cost: `O(N log N)` on the sort. N is typically `< 30` (a few minutes
/// of jobs per channel / per session).
pub fn age_entries<K, E, FCreation, FRetired>(
    map: &mut HashMap<K, E>,
    now_ms: u64,
    cfg: &LifecycleConfig,
    get_creation: FCreation,
    get_retired: FRetired,
) where
    K: Eq + Hash + Clone,
    FCreation: Fn(&E) -> u64,
    FRetired: Fn(&E) -> Option<u64>,
{
    if map.len() <= cfg.min_retained {
        return;
    }
    let mut keys_by_creation: Vec<(K, u64)> = map
        .iter()
        .map(|(k, e)| (k.clone(), get_creation(e)))
        .collect();
    keys_by_creation.sort_by_key(|kv| std::cmp::Reverse(kv.1));

    let twice_retention = cfg.retention_ms.saturating_mul(2);
    for (key, _) in keys_by_creation.into_iter().skip(cfg.min_retained) {
        let Some(entry) = map.get(&key) else { continue };
        if let Some(retired_at) = get_retired(entry) {
            if now_ms.saturating_sub(retired_at) > cfg.retention_ms {
                map.remove(&key);
                continue;
            }
        }
        if now_ms.saturating_sub(get_creation(entry)) > twice_retention {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LifecycleConfig {
        LifecycleConfig::DEFAULT
    }

    // ── classify ────────────────────────────────────────────────────

    #[test]
    fn classify_returns_active_when_not_retired() {
        assert_eq!(classify(None, 1_000, &cfg()), JobClassification::Active);
    }

    #[test]
    fn classify_creditable_at_zero_age() {
        assert_eq!(
            classify(Some(10_000), 10_000, &cfg()),
            JobClassification::StaleCreditable
        );
    }

    #[test]
    fn classify_creditable_at_exact_grace_boundary() {
        // The boundary is inclusive (`<=`).
        assert_eq!(
            classify(Some(10_000), 10_000 + cfg().grace_ms, &cfg()),
            JobClassification::StaleCreditable
        );
    }

    #[test]
    fn classify_rejected_one_ms_past_grace() {
        assert_eq!(
            classify(Some(10_000), 10_000 + cfg().grace_ms + 1, &cfg()),
            JobClassification::StaleRejected
        );
    }

    // ── LifecycleConfig::DEFAULT ───────────────────────────────────

    #[test]
    fn default_constants_match_ts_pool_env_defaults() {
        let d = LifecycleConfig::DEFAULT;
        assert_eq!(d.grace_ms, 5_000);
        assert_eq!(d.retention_ms, 600_000);
        assert_eq!(d.min_retained, 3);
    }

    // ── age_entries ─────────────────────────────────────────────────

    /// Test fixture mirroring the field shape of both consumer types.
    #[derive(Clone, Copy, Debug)]
    struct Entry {
        created_at: u64,
        retired_at: Option<u64>,
    }

    fn entry(created: u64, retired: Option<u64>) -> Entry {
        Entry {
            created_at: created,
            retired_at: retired,
        }
    }

    fn run_age(map: &mut HashMap<u32, Entry>, now: u64) {
        age_entries(map, now, &cfg(), |e| e.created_at, |e| e.retired_at);
    }

    #[test]
    fn age_entries_no_op_when_under_min_retained() {
        let mut map: HashMap<u32, Entry> = HashMap::new();
        for i in 0..3u32 {
            map.insert(i, entry(0, Some(0)));
        }
        run_age(&mut map, u64::MAX / 2);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn age_entries_respects_min_retained_floor() {
        let mut map: HashMap<u32, Entry> = HashMap::new();
        for i in 0..5u32 {
            map.insert(i, entry(1_000 + u64::from(i) * 1_000, Some(6_000)));
        }
        run_age(&mut map, 6_000 + cfg().retention_ms * 5);
        assert_eq!(map.len(), cfg().min_retained);
    }

    #[test]
    fn age_entries_keeps_retired_within_retention() {
        let mut map: HashMap<u32, Entry> = HashMap::new();
        for i in 0..5u32 {
            map.insert(i, entry(1_000 + u64::from(i) * 1_000, Some(3_000)));
        }
        run_age(&mut map, 3_000 + cfg().retention_ms - 1);
        assert_eq!(map.len(), 5, "still within retention window");
    }

    #[test]
    fn age_entries_keeps_non_retired_within_two_x_retention() {
        let mut map: HashMap<u32, Entry> = HashMap::new();
        for i in 0..5u32 {
            map.insert(i, entry(1_000 + u64::from(i) * 1_000, None));
        }
        run_age(&mut map, 1_000 + cfg().retention_ms + 100);
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn age_entries_falls_back_to_absolute_age_past_two_x_retention() {
        let mut map: HashMap<u32, Entry> = HashMap::new();
        for i in 0..5u32 {
            map.insert(i, entry(1_000 + u64::from(i) * 1_000, None));
        }
        run_age(&mut map, 1_000 + cfg().retention_ms * 3);
        assert_eq!(map.len(), cfg().min_retained);
    }

    /// Custom config to confirm the algorithm honours non-default values
    /// (a SV1 caller might tune via ServerConfig).
    #[test]
    fn age_entries_honours_custom_config() {
        let cfg = LifecycleConfig {
            grace_ms: 100,
            retention_ms: 500,
            min_retained: 1,
        };
        let mut map: HashMap<u32, Entry> = HashMap::new();
        // Two retired entries at t=0; one retained by min_retained=1,
        // the older one evicted at now=600 (past retention=500).
        map.insert(1, entry(0, Some(0)));
        map.insert(2, entry(1, Some(0)));
        age_entries(&mut map, 600, &cfg, |e| e.created_at, |e| e.retired_at);
        // The newer entry (created_at=1) is the floor-protected one.
        assert!(map.contains_key(&2));
        assert!(!map.contains_key(&1));
    }
}
