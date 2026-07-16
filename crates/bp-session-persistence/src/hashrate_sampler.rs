// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live per-session hashrate sampler.
//!
//! Owns the `client_entity.hashRate` column. On every accepted share we
//! accumulate the share's **credited** difficulty (`effective_difficulty`)
//! into a persistent per-session bucket. Every `sample_interval`
//! (default 60 s) each bucket is turned into a hashrate estimate
//!
//! ```text
//! rate = Σ credited_diff × 2^32 / window_seconds
//! ```
//!
//! — the identical formula the hashrate chart applies per 10-min slot, so
//! the live figure and the chart agree. We then write a **2-sample moving
//! average** of the current + previous window's estimate:
//! `displayed = (prev + rate) / 2` (or `rate` alone for a session's very
//! first window). Over a 60 s window vardiff keeps ~10–15 shares, enough
//! that one window isn't dominated by share-arrival jitter; averaging two
//! windows smooths it to a ~2-min figure.
//!
//! Unlike the share-touch buffer (which drains its map every flush), this
//! map is **persistent**: a session that stops submitting stays tracked
//! and samples to 0, so the moving average fades a stopped miner to 0 over
//! two empty windows (R → R/2 → 0); the entry is kept one window longer to
//! re-write the 0 (a retry if the terminal write failed), then dropped.
//! That is what makes the reported hashrate self-zeroing and
//! reconnect-immune without waiting for `kill_dead_clients` to sweep the row.

use std::sync::{Arc, Mutex};

use bp_db::{bulk_set_client_hashrate, reset_all_client_hashrate};
use hashbrown::HashMap;
use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::touch_buffer::{TouchKey, TouchKeyRef};

/// Hashes per unit of difficulty-1 work (2^32). `Σdiff × this / seconds`
/// yields H/s. Matches `bp_api::time_range::DIFFICULTY_1`; duplicated here
/// so bp-session-persistence needn't depend on bp-api.
const HASH_PER_DIFFICULTY_1: f64 = 4_294_967_296.0;

/// Consecutive zero-share windows after which a faded session is dropped
/// from the map. The fade itself reaches 0 after two empty windows
/// (R → R/2 → 0); we keep the session for a third window that re-writes the
/// 0, so a transient DB failure on the terminal 0-write gets one automatic
/// retry before the entry is dropped (the entry going stale otherwise would
/// freeze a dead rig at R/2 until `kill_dead_clients` sweeps it).
const MAX_EMPTY_WINDOWS: u32 = 3;

/// Per-session sampling state. Persists across windows so a stopped
/// session can fade rather than freezing at its last value.
struct SessionSample {
    /// Credited difficulty accumulated in the current (open) window.
    diff_accum: f64,
    /// Previous window's hashrate estimate (H/s), or `None` before this
    /// session has completed its first window.
    prev_rate: Option<f64>,
    /// Number of consecutive completed windows with zero shares.
    empty_windows: u32,
}

/// Shared sampler. The share sink records into it on every accepted
/// share; the sample loop closes-and-writes it on every tick.
///
/// Locking is a plain `std::sync::Mutex`: neither `record` nor `sample`
/// holds the lock across an `.await` (the DB write happens after `sample`
/// has returned and released it), so an async mutex would be pure overhead
/// on the per-share path.
pub(crate) struct HashrateSampler {
    inner: Mutex<HashMap<TouchKey, SessionSample>>,
}

impl Default for HashrateSampler {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl HashrateSampler {
    /// Lock the map, recovering the guard on poison rather than panicking
    /// (see `TouchBuffer::guard` — a stray poison must not turn every
    /// subsequent share into a panic).
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<TouchKey, SessionSample>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add a share's credited difficulty to its session's open window.
    /// Non-finite / non-positive values are ignored (defensive — the
    /// accounting sinks already clamp, but this is the hashrate path's
    /// own guard against a corrupt sample poisoning the estimate).
    ///
    /// Takes a borrowed [`TouchKeyRef`] and allocates an owned key only
    /// when a session first appears; every later share in the window is a
    /// zero-allocation `get_mut` lookup.
    pub(crate) fn record(&self, key: TouchKeyRef<'_>, credited_diff: f64) {
        if !credited_diff.is_finite() || credited_diff <= 0.0 {
            return;
        }
        let mut guard = self.guard();
        if let Some(s) = guard.get_mut(&key) {
            s.diff_accum += credited_diff;
        } else {
            guard.insert(
                key.to_key(),
                SessionSample {
                    diff_accum: credited_diff,
                    prev_rate: None,
                    empty_windows: 0,
                },
            );
        }
    }

    /// Close the current window for every tracked session: compute its
    /// hashrate estimate over `window_secs`, apply the 2-sample moving
    /// average, advance the window state, and drop sessions that have
    /// fully faded to 0. Returns the `(key, hashrate)` writes to persist.
    /// One lock-pass; no `.await` while the lock is held.
    fn sample(&self, window_secs: f64) -> Vec<(TouchKey, f64)> {
        let window = window_secs.max(1.0);
        let mut guard = self.guard();
        let mut writes = Vec::with_capacity(guard.len());
        guard.retain(|key, s| {
            let rate = s.diff_accum * HASH_PER_DIFFICULTY_1 / window;
            let displayed = match s.prev_rate {
                Some(prev) => (prev + rate) / 2.0,
                None => rate,
            };
            writes.push((key.clone(), displayed));

            if s.diff_accum == 0.0 {
                s.empty_windows = s.empty_windows.saturating_add(1);
            } else {
                s.empty_windows = 0;
            }
            s.prev_rate = Some(rate);
            s.diff_accum = 0.0;

            // Fade reaches 0 at the second empty window; keep the session
            // for a third that re-writes the 0 (a free retry if the terminal
            // write failed), then drop.
            s.empty_windows < MAX_EMPTY_WINDOWS
        });
        writes
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.guard().len()
    }
}

/// One sample pass: close windows, then persist the writes in one bulk
/// UPDATE. On write failure the values are simply stale until the next
/// window overwrites them — a hashrate estimate is ephemeral, so (unlike
/// a best-difficulty sample) there's nothing to rebuffer.
async fn sample_and_write(sampler: &HashrateSampler, pool: &PgPool, window_secs: f64) {
    let writes = sampler.sample(window_secs);
    if writes.is_empty() {
        return;
    }
    let n = writes.len();
    let mut addresses = Vec::with_capacity(n);
    let mut client_names = Vec::with_capacity(n);
    let mut session_ids = Vec::with_capacity(n);
    let mut hash_rates = Vec::with_capacity(n);
    // Consume `writes` by value: `sample()` already cloned each key out of
    // the map, so move those Strings into the columnar vecs instead of
    // cloning them a second time.
    for (k, hr) in writes {
        addresses.push(k.address);
        client_names.push(k.client_name);
        session_ids.push(k.session_id);
        hash_rates.push(hr);
    }
    match bulk_set_client_hashrate(pool, &addresses, &client_names, &session_ids, &hash_rates).await
    {
        Ok(rows) => debug!(
            sampled = n,
            affected = rows,
            "hashrate sampler flushed live rates"
        ),
        Err(e) => warn!(
            error = %e,
            sampled = n,
            "hashrate sampler write failed; values stale until next window"
        ),
    }
}

/// Spawned sample loop. Ticks every `sample_interval` and divides each
/// window's accumulated work by the **actual wall-clock** elapsed since the
/// previous tick — measured with `Instant::now()`, not the tick deadline:
/// `tokio::Interval::tick()` returns the scheduled grid time, so after a
/// runtime stall that would understate elapsed and overstate the rate.
/// Missed ticks are skipped rather than burst-fired.
///
/// When `reconcile_on_boot` is set (the Front role — the sole hashRate
/// writer), it first zeroes any hashRate the previous process left in the
/// DB: the in-memory map starts empty, so a session that never reconnects
/// would otherwise keep its stale value (and stay summed into the pool
/// total) until `kill_dead_clients` sweeps it.
///
/// Returns when `shutdown_rx` resolves — no final flush, the values are
/// ephemeral and recomputed from live shares on the next boot.
pub(crate) async fn run_sample_loop(
    sampler: Arc<HashrateSampler>,
    pool: PgPool,
    sample_interval: Duration,
    reconcile_on_boot: bool,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    if reconcile_on_boot {
        match reset_all_client_hashrate(&pool).await {
            Ok(n) => debug!(
                cleared = n,
                "hashrate sampler: zeroed stale hashRate on boot"
            ),
            Err(e) => warn!(error = %e, "hashrate sampler: boot hashRate reset failed"),
        }
    }
    let start = Instant::now() + sample_interval;
    let mut ticker = tokio::time::interval_at(start, sample_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_tick = Instant::now();
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(last_tick).as_secs_f64();
                last_tick = now;
                sample_and_write(&sampler, &pool, elapsed).await;
            }
            _ = &mut shutdown_rx => {
                debug!("hashrate sample loop received shutdown");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kref() -> TouchKeyRef<'static> {
        TouchKeyRef {
            address: "addr",
            client_name: "wkr",
            session_id: "sess",
        }
    }

    fn rate_for(diff: f64, window_secs: f64) -> f64 {
        diff * HASH_PER_DIFFICULTY_1 / window_secs
    }

    #[test]
    fn first_window_shows_own_rate_then_moving_average() {
        let s = HashrateSampler::default();

        // Window 1: 600 credited diff over 60 s → its own rate (no prev).
        s.record(kref(), 600.0);
        let w1 = s.sample(60.0);
        let r1 = rate_for(600.0, 60.0);
        assert_eq!(w1.len(), 1);
        assert!(
            (w1[0].1 - r1).abs() < 1.0,
            "first window shows its own rate, got {} want {r1}",
            w1[0].1
        );

        // Window 2: 1200 diff → rate2, displayed = avg(rate1, rate2).
        s.record(kref(), 1200.0);
        let w2 = s.sample(60.0);
        let r2 = rate_for(1200.0, 60.0);
        assert!(
            (w2[0].1 - (r1 + r2) / 2.0).abs() < 1.0,
            "second window = avg(w1, w2), got {}",
            w2[0].1
        );

        // Window 3: 1200 diff again → avg(rate2, rate3) with rate3==rate2.
        s.record(kref(), 1200.0);
        let w3 = s.sample(60.0);
        assert!(
            (w3[0].1 - r2).abs() < 1.0,
            "third window = avg(w2, w3) = r2, got {}",
            w3[0].1
        );
    }

    #[test]
    fn idle_session_fades_then_retries_zero_before_drop() {
        let s = HashrateSampler::default();
        let r1 = rate_for(600.0, 60.0);

        s.record(kref(), 600.0);
        let _ = s.sample(60.0); // active window: prev = r1

        // Empty window 1 → (r1 + 0)/2, still tracked.
        let w = s.sample(60.0);
        assert!(
            (w[0].1 - r1 / 2.0).abs() < 1.0,
            "first idle window halves, got {}",
            w[0].1
        );
        assert_eq!(s.len(), 1, "tracked after one empty window");

        // Empty window 2 → 0, but kept one more window for the retry.
        let w = s.sample(60.0);
        assert_eq!(w[0].1, 0.0, "second idle window zeroes");
        assert_eq!(s.len(), 1, "kept for the terminal-0 retry window");

        // Empty window 3 → re-writes 0 (the free retry), then drops.
        let w = s.sample(60.0);
        assert_eq!(w[0].1, 0.0, "third idle window re-writes 0");
        assert_eq!(s.len(), 0, "dropped after the retry window");

        // Nothing left to write.
        assert!(
            s.sample(60.0).is_empty(),
            "no writes once the session is gone"
        );
    }

    #[test]
    fn resumed_share_clears_the_empty_counter() {
        let s = HashrateSampler::default();
        let r = rate_for(600.0, 60.0);

        s.record(kref(), 600.0);
        let _ = s.sample(60.0); // prev = r, empty = 0
        let _ = s.sample(60.0); // idle window 1 → r/2, empty = 1

        // A share lands before the second idle window → counter resets,
        // session survives instead of being dropped.
        s.record(kref(), 600.0);
        let w = s.sample(60.0);
        assert!(
            (w[0].1 - r / 2.0).abs() < 1.0,
            "recovers to avg(0, r) = r/2, got {}",
            w[0].1
        );
        assert_eq!(s.len(), 1, "still tracked — the gap didn't drop it");
    }

    #[test]
    fn ignores_nonpositive_and_nonfinite_diff() {
        let s = HashrateSampler::default();
        s.record(kref(), 0.0);
        s.record(kref(), -5.0);
        s.record(kref(), f64::NAN);
        s.record(kref(), f64::INFINITY);
        assert_eq!(
            s.len(),
            0,
            "invalid diffs must not create a tracked session"
        );
    }

    #[test]
    fn window_seconds_scale_the_rate() {
        let s = HashrateSampler::default();
        // Same accumulated diff over half the window → double the rate.
        s.record(kref(), 600.0);
        let w = s.sample(30.0);
        assert!(
            (w[0].1 - rate_for(600.0, 30.0)).abs() < 1.0,
            "rate divides by the actual window length, got {}",
            w[0].1
        );
    }
}
