// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retire-not-clear job lifecycle shared by SV1 and SV2, so both keep their
//! lifecycle constants in lock-step. On a block change, in-flight shares for
//! the old job must still find it: SV2 answers `stale-share` rather than
//! `invalid-job-id`, and SV1 can credit shares arriving just after the change.

use std::collections::HashMap;
use std::hash::Hash;

// ── JobClassification ────────────────────────────────────────────────

/// Share-validation outcome. `StaleCreditable` (retired within
/// [`LifecycleConfig::grace_ms`]) is credited; `StaleRejected` maps to SV2
/// `stale-share`, not `invalid-job-id`, because the job was known. Only an
/// entry GC'd by [`age_entries`] is `invalid-job-id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobClassification {
    Active,
    StaleCreditable,
    StaleRejected,
}

// ── LifecycleConfig ──────────────────────────────────────────────────

/// Lifecycle parameters; only `retention_ms` is operator-set
/// (`[stratum] job_retention_ms`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleConfig {
    /// Shares against a job retired at most this many ms ago are credited,
    /// absorbing network jitter.
    pub grace_ms: u64,
    /// Retired entries past this window are eligible for GC by
    /// [`age_entries`], subject to [`Self::min_retained`].
    pub retention_ms: u64,
    /// The newest this-many entries are never aged out.
    pub min_retained: usize,
}

impl LifecycleConfig {
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

/// Classify a stored job by its `retired_at` timestamp; the grace boundary is
/// inclusive.
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

/// Age out entries retired longer than `retention_ms` ago, keeping the newest
/// `min_retained`. Entries never retired go after twice the retention, which
/// catches clock jumps and missed retire signals. The closures let SV1 and SV2
/// value types share the algorithm.
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

    /// The algorithm honours non-default config values.
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
