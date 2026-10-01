// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live per-session hashrate (`hash_rate` in `client:live:*`): credited
//! difficulty × 2^32 / window, the same formula as the hashrate chart, shown
//! as a 2-window moving average. The map is persistent so a stopped session
//! fades to 0 (R → R/2 → 0) instead of freezing until the key's TTL.

use std::sync::{Arc, Mutex};

use hashbrown::HashMap;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use bp_common::HASHES_PER_DIFFICULTY_1;

use crate::live_store::LiveSessionStore;
use crate::touch_buffer::{TouchKey, TouchKeyRef};

/// Empty windows before a faded session is dropped. The fade reaches 0 after
/// two; the third re-writes the 0 so a failed terminal write gets a retry.
const MAX_EMPTY_WINDOWS: u32 = 3;

/// Per-session sampling state, kept across windows so a stopped session fades.
struct SessionSample {
    diff_accum: f64,
    /// Previous window's estimate (H/s); `None` before the first window.
    prev_rate: Option<f64>,
    empty_windows: u32,
}

/// Shared sampler: the share sink records, the sample loop closes windows.
/// A `std::sync::Mutex` suffices because the lock is never held across an
/// `.await`.
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
    /// Recovers from poison so one panic does not turn every later share
    /// into a panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<TouchKey, SessionSample>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add a share's credited difficulty to its session's open window;
    /// non-finite or non-positive values are ignored. Allocates an owned key
    /// only when a session first appears.
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

    /// Close every session's window, apply the moving average, drop fully
    /// faded sessions, and return the `(key, hashrate)` writes.
    fn sample(&self, window_secs: f64) -> Vec<(TouchKey, f64)> {
        let window = window_secs.max(1.0);
        let mut guard = self.guard();
        let mut writes = Vec::with_capacity(guard.len());
        guard.retain(|key, s| {
            let rate = s.diff_accum * HASHES_PER_DIFFICULTY_1 / window;
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

            s.empty_windows < MAX_EMPTY_WINDOWS
        });
        writes
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.guard().len()
    }
}

/// One sample pass into the Redis live hashes. A failed write is not
/// rebuffered: the estimate is ephemeral and the next window overwrites it.
/// No DEL after the drop: the sampler must not shorten liveness, only the
/// touch-derived TTL ends it.
pub(crate) async fn sample_and_write(
    sampler: &HashrateSampler,
    window_secs: f64,
    live: Option<&LiveSessionStore>,
) {
    let writes = sampler.sample(window_secs);
    if writes.is_empty() {
        return;
    }
    let Some(store) = live else {
        return;
    };
    match store.write_hashrate_batch(&writes).await {
        Ok(()) => debug!(
            sampled = writes.len(),
            "hashrate sampler flushed live rates"
        ),
        Err(e) => warn!(
            error = %e,
            sampled = writes.len(),
            "live-session hashrate write failed; values stale until next window"
        ),
    }
}

/// Sample loop. Divides by the wall-clock time since the last tick, not the
/// tick deadline, which after a runtime stall would overstate the rate.
/// No boot reconcile and no final flush: the values are ephemeral.
pub(crate) async fn run_sample_loop(
    sampler: Arc<HashrateSampler>,
    live: Option<Arc<LiveSessionStore>>,
    sample_interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
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
                sample_and_write(&sampler, elapsed, live.as_deref()).await;
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
        diff * HASHES_PER_DIFFICULTY_1 / window_secs
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
