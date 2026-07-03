// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared `?range=` parsing + slot-bucket math for chart/timeseries
//! endpoints. The slot size is a fixed 10 minutes for every range — the
//! stats are stored at that resolution and surfaced natively, so a
//! longer range just returns more points (never coarser buckets).
//!
//! ## Range presets
//!
//! | range | window  | slot size | point count |
//! |-------|---------|-----------|-------------|
//! | `1d`  | 24h     | 10 min    | 144         |
//! | `3d`  | 72h     | 10 min    | 432         |
//! | `7d`  | 168h    | 10 min    | 1008        |
//! | `1m`  | 30 days | 10 min    | 4320        |
//!
//! Endpoints that don't take `range` (e.g. `/api/info/shares`) just
//! compute their own millis directly.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Day,
    ThreeDays,
    SevenDays,
    Month,
}

impl Range {
    /// Parse the `?range=` query param. Returns `BadRequest`-mapped
    /// `ApiError::InvalidQuery` on unknown values; default-callers
    /// should swallow that with `.unwrap_or(Range::Day)`.
    pub fn parse(s: Option<&str>) -> Result<Self, ApiError> {
        match s.unwrap_or("1d") {
            "1d" => Ok(Self::Day),
            "3d" => Ok(Self::ThreeDays),
            "7d" => Ok(Self::SevenDays),
            "1m" | "30d" => Ok(Self::Month),
            _ => Err(ApiError::InvalidQuery("range must be 1d|3d|7d|1m")),
        }
    }

    pub fn window_ms(self) -> i64 {
        const HOUR: i64 = 60 * 60 * 1000;
        const DAY: i64 = 24 * HOUR;
        match self {
            Self::Day => DAY,
            Self::ThreeDays => 3 * DAY,
            Self::SevenDays => 7 * DAY,
            Self::Month => 30 * DAY,
        }
    }

    /// Slot granularity is a fixed 10 minutes for every range — the
    /// stats are persisted in 10-min slots and the chart / accepted /
    /// worker endpoints surface them at that native resolution (longer
    /// ranges simply return more points). Coarser per-range bucketing
    /// would both drop resolution and, on the hashrate charts, inflate
    /// the value (the `* 2^32 / 600s` conversion assumes a 10-min slot).
    pub fn slot_size_ms(self) -> i64 {
        const MIN: i64 = 60 * 1000;
        10 * MIN
    }

    /// Short string for cache keys / log lines (`1d`, `3d`, `7d`,
    /// `1m`). Round-trips through `Range::parse`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Day => "1d",
            Self::ThreeDays => "3d",
            Self::SevenDays => "7d",
            Self::Month => "1m",
        }
    }
}

/// Snap `t_ms` down to the nearest multiple of `slot_size_ms`. Stable
/// — `t_ms` already aligned returns itself.
pub fn snap_to_slot(t_ms: i64, slot_size_ms: i64) -> i64 {
    if slot_size_ms <= 0 {
        return t_ms;
    }
    (t_ms / slot_size_ms) * slot_size_ms
}

/// Wrapper around [`slot_boundaries`] that uses the chart-visibility
/// cutoff as the upper bound, so the in-progress slot is hidden
/// until the flush mechanism has had at least
/// `CHART_VISIBILITY_BUFFER_MS` to commit its residual to PG.
pub fn chart_slot_boundaries(since_ms: i64, slot_size_ms: i64) -> Vec<i64> {
    let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
    slot_boundaries(since_ms, cutoff, slot_size_ms)
}

/// Chart-visibility cutoff in epoch milliseconds — exposed so chart
/// handlers can filter their raw DB rows against the same boundary
/// that [`chart_slot_boundaries`] uses.
pub fn chart_visibility_cutoff_ms() -> i64 {
    bp_stats::slot::chart_visibility_cutoff_slot().as_millis()
}

/// Generate slot-end boundaries for the window `[since_ms, until_ms)`.
/// Slots are end-labeled — the boundary at `14:00:00.000Z` represents
/// the slot covering `[13:50, 14:00)`. First boundary is the first
/// slot-end at or after `since_ms`; emission stops once a boundary
/// would reach or exceed `until_ms`.
pub fn slot_boundaries(since_ms: i64, until_ms: i64, slot_size_ms: i64) -> Vec<i64> {
    let mut out = Vec::new();
    if slot_size_ms <= 0 || since_ms >= until_ms {
        return out;
    }
    // First slot END at or after `since_ms`: floor(since / slot) * slot + slot.
    let mut t = snap_to_slot(since_ms, slot_size_ms) + slot_size_ms;
    while t < until_ms {
        out.push(t);
        t += slot_size_ms;
    }
    out
}

/// Bucket key for in-memory aggregation — the snapped slot start.
pub fn bucket_key(time_ms: i64, slot_size_ms: i64) -> i64 {
    snap_to_slot(time_ms, slot_size_ms)
}

/// Render a snapped slot timestamp as an ISO-8601 string with
/// millisecond precision and a trailing `Z`. UI consumers parse it
/// straight back into a Date.
pub fn format_slot_label(slot_ms: i64) -> String {
    format_iso_ms(slot_ms)
}

/// Render an epoch-ms timestamp as an ISO-8601 string with
/// millisecond precision and a trailing `Z`
/// (`"YYYY-MM-DDTHH:MM:SS.mmmZ"`).
pub fn format_iso_ms(ms: i64) -> String {
    use chrono::TimeZone;
    let dt = chrono::Utc
        .timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(chrono::Utc::now);
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Same as [`format_iso_ms`] but passes `None` through unchanged
/// (returns `null` for absent timestamps).
pub fn format_iso_ms_opt(ms: Option<i64>) -> Option<String> {
    ms.map(format_iso_ms)
}

// ─── shared constants ──────────────────────────────────────────────

/// 2^32 — converts share-difficulty sums to H/s.
pub const DIFFICULTY_1: f64 = 4_294_967_296.0;

/// 10-minute slot duration in seconds; divisor in hashrate conversion.
pub const SLOT_SECONDS: f64 = 600.0;

/// Staleness weight for a session's stored hashrate: `1.0` when the last share
/// is fresh, fading **linearly to 0** as `now_ms - updated_at_ms` reaches
/// `window_ms`. Mirrors the SQL decay in `bp_db::sum_active_pool_hashrate`, so a
/// miner that just went offline drops out of the reported total smoothly instead
/// of counting at its frozen last value until the dead-client sweep. Clamped to
/// `[0, 1]`; a non-positive window disables decay (weight `1.0`).
pub fn hashrate_decay_factor(now_ms: i64, updated_at_ms: i64, window_ms: i64) -> f64 {
    if window_ms <= 0 {
        return 1.0;
    }
    let staleness = (now_ms - updated_at_ms).max(0) as f64;
    (1.0 - staleness / window_ms as f64).clamp(0.0, 1.0)
}

/// Current Unix time in milliseconds.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ─── shared response shapes ────────────────────────────────────────

/// Serialize an `f64` as a JSON integer when the value has no
/// fractional part and fits in i64; otherwise as a JSON float.
pub fn ser_f64_jsnum<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.is_finite() && v.fract() == 0.0 && *v >= i64::MIN as f64 && *v <= i64::MAX as f64 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}

/// `Option<f64>` variant of [`ser_f64_jsnum`]: `None` → `null`,
/// `Some` → int-when-whole JSON number (matches the JS-number shape
/// the rest of the API emits).
pub fn ser_opt_f64_jsnum<S: serde::Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(x) => ser_f64_jsnum(x, s),
        None => s.serialize_none(),
    }
}

/// `BTreeMap<String, f64>` serializer applying [`ser_f64_jsnum`]
/// to every value so per-slot count maps emit ints when whole.
pub fn ser_count_map<S: serde::Serializer>(
    m: &BTreeMap<String, f64>,
    s: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = s.serialize_map(Some(m.len()))?;
    for (k, v) in m {
        let display = if v.is_finite()
            && v.fract() == 0.0
            && *v >= i64::MIN as f64
            && *v <= i64::MAX as f64
        {
            serde_json::Number::from(*v as i64)
        } else {
            serde_json::Number::from_f64(*v).unwrap_or_else(|| serde_json::Number::from(0))
        };
        map.serialize_entry(k, &display)?;
    }
    map.end()
}

/// Point on a hashrate-or-similar chart. `data` serialises as a JS
/// integer when whole so /api/info/chart emits clean number values.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChartPoint {
    pub label: String,
    #[serde(serialize_with = "ser_f64_jsnum")]
    pub data: f64,
}

/// One slot bucket of `{key → numeric}` counts. `time` is the
/// slot-end timestamp formatted as ISO-8601 with millisecond
/// precision and a trailing `Z` — the UI parses it straight back
/// into a Date.
#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct SlotCounts {
    pub time: String,
    #[serde(serialize_with = "ser_count_map")]
    pub counts: BTreeMap<String, f64>,
}

/// Wrapper around a `Vec<SlotCounts>` returned by the count-style
/// endpoints.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SlotDataResponse {
    pub slot_data: Vec<SlotCounts>,
}

/// Build a fully-populated chart by snapping every (time_ms, value)
/// sample into its slot, summing per slot, and returning one point per
/// boundary in `boundaries`. Slots with no samples render `0.0`.
pub fn aggregate_to_chart<I>(boundaries: &[i64], samples: I, slot_size_ms: i64) -> Vec<ChartPoint>
where
    I: IntoIterator<Item = (i64, f64)>,
{
    let mut buckets: BTreeMap<i64, f64> = boundaries.iter().map(|&b| (b, 0.0)).collect();
    for (t, v) in samples {
        let k = bucket_key(t, slot_size_ms);
        if let Some(slot) = buckets.get_mut(&k) {
            *slot += v;
        }
    }
    boundaries
        .iter()
        .map(|&b| ChartPoint {
            label: format_slot_label(b),
            data: buckets.get(&b).copied().unwrap_or(0.0),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashrate_decay_fades_linearly_over_the_window() {
        let w = 120_000; // 2 min
        let now = 1_000_000_000;
        // Fresh share → full weight.
        assert_eq!(hashrate_decay_factor(now, now, w), 1.0);
        // Halfway through the window → half weight.
        assert!((hashrate_decay_factor(now, now - 60_000, w) - 0.5).abs() < 1e-9);
        // At/after the window → zero (a departed miner drops out).
        assert_eq!(hashrate_decay_factor(now, now - w, w), 0.0);
        assert_eq!(hashrate_decay_factor(now, now - 10 * w, w), 0.0);
        // Clock skew (updated_at in the future) is clamped to full, not > 1.
        assert_eq!(hashrate_decay_factor(now, now + 5_000, w), 1.0);
        // A non-positive window disables decay.
        assert_eq!(hashrate_decay_factor(now, now - 999_999, 0), 1.0);
    }

    #[test]
    fn parse_range_defaults_to_day() {
        assert_eq!(Range::parse(None).unwrap(), Range::Day);
        assert_eq!(Range::parse(Some("1d")).unwrap(), Range::Day);
        assert_eq!(Range::parse(Some("3d")).unwrap(), Range::ThreeDays);
        assert_eq!(Range::parse(Some("7d")).unwrap(), Range::SevenDays);
        assert_eq!(Range::parse(Some("1m")).unwrap(), Range::Month);
        assert_eq!(Range::parse(Some("30d")).unwrap(), Range::Month);
    }

    /// Every range must surface native 10-min slots — no coarser
    /// per-range bucketing (keeps chart resolution + correct hashrate).
    #[test]
    fn slot_size_is_always_ten_minutes() {
        for r in [Range::Day, Range::ThreeDays, Range::SevenDays, Range::Month] {
            assert_eq!(
                r.slot_size_ms(),
                10 * 60 * 1000,
                "{r:?} must use 10-min slots"
            );
        }
        assert!(Range::parse(Some("forever")).is_err());
    }

    #[test]
    fn snap_to_slot_floors_to_boundary() {
        let slot = 600_000_i64; // 10 min
                                // Reference boundary used throughout this test — known multiple
                                // of `slot` (computed below so any future slot tweak still
                                // satisfies the multiplicity invariant).
        let base = (1_700_000_001_234_i64 / slot) * slot;
        // Anything between `base` and `base + slot - 1` snaps to `base`.
        assert_eq!(snap_to_slot(base, slot), base);
        assert_eq!(snap_to_slot(base + 1, slot), base);
        assert_eq!(snap_to_slot(base + slot - 1, slot), base);
        // The first ms above the slot boundary snaps to the next slot.
        assert_eq!(snap_to_slot(base + slot, slot), base + slot);
    }

    #[test]
    fn slot_boundaries_covers_window() {
        let slot = 600_000;
        // Window [0, 1_800_000) = three 10-min slots ending at
        // 600_000, 1_200_000, 1_800_000. The 1_800_000 boundary is
        // EXCLUDED because t < until.
        let boundaries = slot_boundaries(0, 1_800_000, slot);
        assert_eq!(boundaries, vec![600_000, 1_200_000]);
        // since=0, until=2*slot+1 → includes both slot ends within range.
        let boundaries = slot_boundaries(0, 2 * slot + 1, slot);
        assert_eq!(boundaries, vec![slot, 2 * slot]);
        // Empty window → empty list.
        assert!(slot_boundaries(1_000, 1_000, slot).is_empty());
    }

    #[test]
    fn aggregate_to_chart_sums_into_buckets() {
        let slot = 600_000;
        // Slot-END boundaries: data at time=slot-end belongs in
        // the bucket carrying that end timestamp.
        let boundaries = vec![slot, 2 * slot, 3 * slot];
        let samples = vec![
            (slot, 1.0),      // bucket key = slot (already aligned)
            (slot, 2.0),      // same bucket
            (2 * slot, 5.0),  // second bucket
            (4 * slot, 99.0), // outside the boundary list — dropped
        ];
        let chart = aggregate_to_chart(&boundaries, samples, slot);
        assert_eq!(chart[0].data, 3.0);
        assert_eq!(chart[1].data, 5.0);
        assert_eq!(chart[2].data, 0.0);
    }

    #[test]
    fn jsnum_serializers_emit_int_when_whole_else_float_and_null_for_none() {
        #[derive(serde::Serialize)]
        struct T {
            #[serde(serialize_with = "ser_f64_jsnum")]
            whole: f64,
            #[serde(serialize_with = "ser_f64_jsnum")]
            frac: f64,
            #[serde(serialize_with = "ser_opt_f64_jsnum")]
            opt_whole: Option<f64>,
            #[serde(serialize_with = "ser_opt_f64_jsnum")]
            opt_none: Option<f64>,
        }
        let json = serde_json::to_string(&T {
            whole: 1024.0,
            frac: 1024.5,
            opt_whole: Some(2048.0),
            opt_none: None,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"whole":1024,"frac":1024.5,"opt_whole":2048,"opt_none":null}"#
        );
    }
}
