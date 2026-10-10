// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retire-not-clear job lifecycle shared by SV1 and SV2, so both keep their
//! lifecycle constants in lock-step. On a block change, in-flight shares for
//! the old job must still find it: SV2 answers `stale-share` rather than
//! `invalid-job-id`, and SV1 can credit shares arriving just after the change.
//! [`SeenShares`] keeps the duplicate guard alive for as long as that credit lasts.

use std::collections::{HashMap, HashSet};
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

// ── SeenShares ───────────────────────────────────────────────────────

/// Most header hashes [`SeenShares`] keeps per chain tip. Even at a vardiff
/// target of 60 shares/min that is over a day on one tip, so only a channel
/// whose difficulty the vardiff cannot raise gets here.
pub const MAX_SEEN_SHARES_PER_TIP: usize = 100_000;

/// Why [`SeenShares::check`] refused a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeenShareRefusal {
    /// This header hash was already accepted.
    Duplicate,
    /// The tip holds [`MAX_SEEN_SHARES_PER_TIP`] hashes. Evicting one would
    /// let its share be credited again, so nothing more is accepted.
    Full,
}

/// Header hashes of accepted shares, so one proof of work is credited once.
///
/// Keyed by the header hash, not by the submit fields: two job ids with the
/// same content hash to the same header, and that is the same work. Hashes are
/// grouped by the prev-hash they commit to. A tip change keeps the old group,
/// because shares on the old tip's jobs stay creditable for
/// [`LifecycleConfig::grace_ms`]; [`Self::on_tip`] drops a group only once it
/// has been replaced for longer than [`LifecycleConfig::retention_ms`].
/// Retention rather than grace, because credit runs `grace_ms` from each
/// job's own retirement, and a job can retire after the tip change (SV1
/// retires on the next registry pass).
#[derive(Clone, Debug, Default)]
pub struct SeenShares {
    tips: Vec<TipShares>,
}

#[derive(Clone, Debug)]
struct TipShares {
    prev_hash: [u8; 32],
    /// When another tip took over; `None` while this one is current.
    replaced_at_ms: Option<u64>,
    hashes: HashSet<[u8; 32]>,
}

impl SeenShares {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a share hashing to `hash` on a job built on `prev_hash` may be
    /// credited. Runs before the target check, so an exact resubmission is
    /// reported as a duplicate whatever the difficulty is by then.
    pub fn check(&self, prev_hash: &[u8; 32], hash: &[u8; 32]) -> Result<(), SeenShareRefusal> {
        let Some(tip) = self.tips.iter().find(|t| t.prev_hash == *prev_hash) else {
            return Ok(());
        };
        if tip.hashes.contains(hash) {
            return Err(SeenShareRefusal::Duplicate);
        }
        if tip.hashes.len() >= MAX_SEEN_SHARES_PER_TIP {
            return Err(SeenShareRefusal::Full);
        }
        Ok(())
    }

    /// Records an accepted share. Only a share that passed [`Self::check`]
    /// and every other check is recorded, so a rejected share never makes a
    /// later valid submission look like a duplicate.
    pub fn record(&mut self, prev_hash: [u8; 32], hash: [u8; 32]) {
        match self.tips.iter_mut().find(|t| t.prev_hash == prev_hash) {
            Some(tip) => {
                tip.hashes.insert(hash);
            }
            None => self.tips.push(TipShares {
                prev_hash,
                replaced_at_ms: None,
                hashes: HashSet::from([hash]),
            }),
        }
    }

    /// `prev_hash` is now the chain tip: every other group is stamped as
    /// replaced, and groups replaced longer than `retention_ms` (at least
    /// `grace_ms`) ago are dropped. A tip that comes back keeps its group,
    /// since its hashes still describe headers that can be resubmitted.
    pub fn on_tip(&mut self, prev_hash: &[u8; 32], now_ms: u64, cfg: &LifecycleConfig) {
        let keep_ms = cfg.retention_ms.max(cfg.grace_ms);
        self.tips.retain_mut(|t| {
            if t.prev_hash == *prev_hash {
                t.replaced_at_ms = None;
                return true;
            }
            let replaced_at = *t.replaced_at_ms.get_or_insert(now_ms);
            now_ms.saturating_sub(replaced_at) <= keep_ms
        });
    }

    /// Hashes held across all tips.
    pub fn len(&self) -> usize {
        self.tips.iter().map(|t| t.hashes.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.tips.iter().all(|t| t.hashes.is_empty())
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

    // ── SeenShares ──────────────────────────────────────────────────

    const TIP_A: [u8; 32] = [0xAA; 32];
    const TIP_B: [u8; 32] = [0xBB; 32];

    /// `check` then, if it passes, `record`: what a validator does for an
    /// accepted share.
    fn admit(seen: &mut SeenShares, tip: [u8; 32], h: [u8; 32]) -> Result<(), SeenShareRefusal> {
        seen.check(&tip, &h)?;
        seen.record(tip, h);
        Ok(())
    }

    fn hash(n: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&n.to_le_bytes());
        h
    }

    #[test]
    fn seen_shares_refuses_the_same_hash_twice() {
        let mut seen = SeenShares::new();
        assert_eq!(admit(&mut seen, TIP_A, hash(1)), Ok(()));
        assert_eq!(
            admit(&mut seen, TIP_A, hash(1)),
            Err(SeenShareRefusal::Duplicate)
        );
        assert_eq!(admit(&mut seen, TIP_A, hash(2)), Ok(()));
        assert_eq!(seen.len(), 2);
    }

    /// The replay window: a tip change keeps the old tip's hashes, because its
    /// jobs are still credited for `grace_ms`.
    #[test]
    fn seen_shares_keeps_a_replaced_tip_through_the_grace_window() {
        let mut seen = SeenShares::new();
        admit(&mut seen, TIP_A, hash(1)).unwrap();
        seen.on_tip(&TIP_B, 10_000, &cfg());
        assert_eq!(
            admit(&mut seen, TIP_A, hash(1)),
            Err(SeenShareRefusal::Duplicate),
            "a share accepted before the tip change must stay a duplicate after it"
        );
        seen.on_tip(&TIP_B, 10_000 + cfg().grace_ms + 1, &cfg());
        assert_eq!(
            admit(&mut seen, TIP_A, hash(1)),
            Err(SeenShareRefusal::Duplicate)
        );
    }

    #[test]
    fn seen_shares_drops_a_tip_replaced_longer_than_retention() {
        let mut seen = SeenShares::new();
        admit(&mut seen, TIP_A, hash(1)).unwrap();
        seen.on_tip(&TIP_B, 10_000, &cfg());
        seen.on_tip(&TIP_B, 10_000 + cfg().retention_ms, &cfg());
        assert_eq!(seen.len(), 1, "kept up to and including retention_ms");
        seen.on_tip(&TIP_B, 10_000 + cfg().retention_ms + 1, &cfg());
        assert!(seen.is_empty());
    }

    /// A second `on_tip` for the same new tip must not restart the clock.
    #[test]
    fn seen_shares_replaced_clock_starts_at_the_first_tip_change() {
        let mut seen = SeenShares::new();
        admit(&mut seen, TIP_A, hash(1)).unwrap();
        seen.on_tip(&TIP_B, 10_000, &cfg());
        seen.on_tip(&TIP_B, 10_000 + cfg().retention_ms / 2, &cfg());
        seen.on_tip(&TIP_B, 10_000 + cfg().retention_ms + 1, &cfg());
        assert!(seen.is_empty());
    }

    #[test]
    fn seen_shares_keeps_hashes_of_a_tip_that_comes_back() {
        let mut seen = SeenShares::new();
        admit(&mut seen, TIP_A, hash(1)).unwrap();
        seen.on_tip(&TIP_B, 10_000, &cfg());
        seen.on_tip(&TIP_A, 11_000, &cfg());
        seen.on_tip(&TIP_A, 11_000 + cfg().retention_ms + 1, &cfg());
        assert_eq!(
            admit(&mut seen, TIP_A, hash(1)),
            Err(SeenShareRefusal::Duplicate)
        );
    }

    /// A full tip refuses new hashes instead of evicting old ones, which would
    /// make the evicted shares creditable again.
    #[test]
    fn seen_shares_refuses_instead_of_evicting_when_full() {
        let mut seen = SeenShares::new();
        for n in 0..MAX_SEEN_SHARES_PER_TIP as u32 {
            admit(&mut seen, TIP_A, hash(n)).unwrap();
        }
        assert_eq!(
            admit(&mut seen, TIP_A, hash(u32::MAX)),
            Err(SeenShareRefusal::Full)
        );
        assert_eq!(
            admit(&mut seen, TIP_A, hash(0)),
            Err(SeenShareRefusal::Duplicate)
        );
        assert_eq!(
            admit(&mut seen, TIP_B, hash(u32::MAX)),
            Ok(()),
            "the cap is per tip"
        );
    }
}
