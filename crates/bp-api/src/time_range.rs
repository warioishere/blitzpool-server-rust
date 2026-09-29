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
//! | `14d` | 336h    | 10 min    | 2016        |
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
    FourteenDays,
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
            "14d" => Ok(Self::FourteenDays),
            "1m" | "30d" => Ok(Self::Month),
            _ => Err(ApiError::InvalidQuery("range must be 1d|3d|7d|14d|1m")),
        }
    }

    pub fn window_ms(self) -> i64 {
        const HOUR: i64 = 60 * 60 * 1000;
        const DAY: i64 = 24 * HOUR;
        match self {
            Self::Day => DAY,
            Self::ThreeDays => 3 * DAY,
            Self::SevenDays => 7 * DAY,
            Self::FourteenDays => 14 * DAY,
            Self::Month => 30 * DAY,
        }
    }

    /// Short string for cache keys / log lines (`1d`, `3d`, `7d`,
    /// `14d`, `1m`). Round-trips through `Range::parse`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Day => "1d",
            Self::ThreeDays => "3d",
            Self::SevenDays => "7d",
            Self::FourteenDays => "14d",
            Self::Month => "1m",
        }
    }
}

/// Slot size of every chart: the stats are persisted in 10-min slots and
/// surfaced at that native resolution (longer ranges simply return more
/// points). Coarser bucketing would both drop resolution and, on the
/// hashrate charts, inflate the value (the `* 2^32 / 600s` conversion
/// assumes a 10-min slot).
const SLOT_MS: i64 = bp_stats::SLOT_DURATION_MS;

/// Snap `t_ms` down to the nearest slot boundary. Stable — `t_ms`
/// already aligned returns itself.
pub fn snap_to_slot(t_ms: i64) -> i64 {
    (t_ms / SLOT_MS) * SLOT_MS
}

/// Wrapper around [`slot_boundaries`] that uses the chart-visibility
/// cutoff as the upper bound, so the in-progress slot is hidden
/// until the flush mechanism has had at least
/// `CHART_VISIBILITY_BUFFER_MS` to commit its residual to PG.
pub fn chart_slot_boundaries(since_ms: i64) -> Vec<i64> {
    let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
    slot_boundaries(since_ms, cutoff)
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
pub fn slot_boundaries(since_ms: i64, until_ms: i64) -> Vec<i64> {
    let mut out = Vec::new();
    if since_ms >= until_ms {
        return out;
    }
    // First slot END at or after `since_ms`: floor(since / slot) * slot + slot.
    let mut t = snap_to_slot(since_ms) + SLOT_MS;
    while t < until_ms {
        out.push(t);
        t += SLOT_MS;
    }
    out
}

/// Fold `(time_ms, sample)` pairs into the slot grid: one accumulator per
/// boundary, in boundary order, starting from `T::default()`. A sample
/// belongs to the boundary its time snaps to; one that snaps to no
/// boundary is dropped.
pub fn fold_into_slots<T: Default, S>(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, S)>,
    mut add: impl FnMut(&mut T, S),
) -> Vec<(i64, T)> {
    let mut slots: BTreeMap<i64, T> = boundaries.iter().map(|&b| (b, T::default())).collect();
    for (t, sample) in samples {
        if let Some(acc) = slots.get_mut(&snap_to_slot(t)) {
            add(acc, sample);
        }
    }
    slots.into_iter().collect()
}

/// [`fold_into_slots`] summing the sample values; an empty slot is `0.0`.
pub fn sum_into_slots(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, f64)>,
) -> Vec<(i64, f64)> {
    fold_into_slots(boundaries, samples, |sum: &mut f64, v| *sum += v)
}

/// The `/accepted` shape: one `{"accepted": sum}` bucket per slot.
pub fn accepted_slot_data(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, f64)>,
) -> SlotDataResponse {
    SlotDataResponse::from_slots(sum_into_slots(boundaries, samples), |sum| {
        BTreeMap::from([("accepted".to_string(), sum)])
    })
}

/// The `/max-difficulty` shape: one `{"maxDifficulty": max}` bucket per
/// slot, the highest single share difficulty of the slot's rows; an empty
/// slot is `0`.
pub fn max_difficulty_slot_data(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, f64)>,
) -> SlotDataResponse {
    let slots = fold_into_slots(boundaries, samples, |max: &mut f64, v: f64| {
        *max = max.max(v)
    });
    SlotDataResponse::from_slots(slots, |max| {
        BTreeMap::from([("maxDifficulty".to_string(), max)])
    })
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

/// 10-minute slot duration in seconds; divisor in hashrate conversion.
pub const SLOT_SECONDS: f64 = SLOT_MS as f64 / 1000.0;

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

/// `f32` variant of [`ser_f64_jsnum`]: int-when-whole (via widening to
/// f64), else float. Used for the few f32 API fields.
pub fn ser_f32_jsnum<S: serde::Serializer>(v: &f32, s: S) -> Result<S::Ok, S::Error> {
    ser_f64_jsnum(&(*v as f64), s)
}

/// `Option<f32>` variant of [`ser_f32_jsnum`]: `None` → `null`.
pub fn ser_opt_f32_jsnum<S: serde::Serializer>(v: &Option<f32>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(x) => ser_f32_jsnum(x, s),
        None => s.serialize_none(),
    }
}

/// `Vec<f64>` serializer applying [`ser_f64_jsnum`] element-wise, so
/// chart value arrays emit ints when whole (no `.0` / JS-number badge).
pub fn ser_vec_f64_jsnum<S: serde::Serializer>(v: &[f64], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(v.len()))?;
    for x in v {
        let n = if x.is_finite()
            && x.fract() == 0.0
            && *x >= i64::MIN as f64
            && *x <= i64::MAX as f64
        {
            serde_json::Number::from(*x as i64)
        } else {
            serde_json::Number::from_f64(*x).unwrap_or_else(|| serde_json::Number::from(0))
        };
        seq.serialize_element(&n)?;
    }
    seq.end()
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

impl SlotDataResponse {
    /// One [`SlotCounts`] per folded slot, its counts built by `counts`.
    pub fn from_slots<T>(
        slots: Vec<(i64, T)>,
        mut counts: impl FnMut(T) -> BTreeMap<String, f64>,
    ) -> Self {
        Self {
            slot_data: slots
                .into_iter()
                .map(|(b, acc)| SlotCounts {
                    time: format_iso_ms(b),
                    counts: counts(acc),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_defaults_to_day() {
        assert_eq!(Range::parse(None).unwrap(), Range::Day);
        assert_eq!(Range::parse(Some("1d")).unwrap(), Range::Day);
        assert_eq!(Range::parse(Some("3d")).unwrap(), Range::ThreeDays);
        assert_eq!(Range::parse(Some("7d")).unwrap(), Range::SevenDays);
        assert_eq!(Range::parse(Some("14d")).unwrap(), Range::FourteenDays);
        assert_eq!(Range::parse(Some("1m")).unwrap(), Range::Month);
        assert_eq!(Range::parse(Some("30d")).unwrap(), Range::Month);
    }

    /// Every chart surfaces native 10-min slots — no coarser bucketing
    /// (keeps chart resolution + correct hashrate).
    #[test]
    fn slot_size_is_ten_minutes() {
        assert_eq!(SLOT_MS, 10 * 60 * 1000);
        assert!(Range::parse(Some("forever")).is_err());
    }

    #[test]
    fn snap_to_slot_floors_to_boundary() {
        let slot = SLOT_MS;
        // Reference boundary used throughout this test — a known multiple
        // of `slot`.
        let base = (1_700_000_001_234_i64 / slot) * slot;
        // Anything between `base` and `base + slot - 1` snaps to `base`.
        assert_eq!(snap_to_slot(base), base);
        assert_eq!(snap_to_slot(base + 1), base);
        assert_eq!(snap_to_slot(base + slot - 1), base);
        // The first ms above the slot boundary snaps to the next slot.
        assert_eq!(snap_to_slot(base + slot), base + slot);
    }

    #[test]
    fn slot_boundaries_covers_window() {
        let slot = SLOT_MS;
        // Window [0, 1_800_000) = three 10-min slots ending at
        // 600_000, 1_200_000, 1_800_000. The 1_800_000 boundary is
        // EXCLUDED because t < until.
        let boundaries = slot_boundaries(0, 1_800_000);
        assert_eq!(boundaries, vec![600_000, 1_200_000]);
        // since=0, until=2*slot+1 → includes both slot ends within range.
        let boundaries = slot_boundaries(0, 2 * slot + 1);
        assert_eq!(boundaries, vec![slot, 2 * slot]);
        // Empty window → empty list.
        assert!(slot_boundaries(1_000, 1_000).is_empty());
    }

    #[test]
    fn sum_into_slots_sums_into_buckets() {
        let slot = SLOT_MS;
        // Slot-END boundaries: data at time=slot-end belongs in
        // the bucket carrying that end timestamp.
        let boundaries = vec![slot, 2 * slot, 3 * slot];
        let samples = vec![
            (slot, 1.0),      // bucket key = slot (already aligned)
            (slot, 2.0),      // same bucket
            (2 * slot, 5.0),  // second bucket
            (4 * slot, 99.0), // outside the boundary list — dropped
        ];
        let sums = sum_into_slots(&boundaries, samples);
        assert_eq!(sums, vec![(slot, 3.0), (2 * slot, 5.0), (3 * slot, 0.0)]);
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
