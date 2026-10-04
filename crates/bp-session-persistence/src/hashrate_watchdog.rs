// SPDX-License-Identifier: AGPL-3.0-or-later

//! Zeroes the live `hash_rate` of a session that stopped sending shares. The
//! touch flush writes vardiff's rate only when a share arrives, so a session
//! that stays connected but silent would keep its last rate until the TTL.

use std::sync::{Arc, Mutex};

use hashbrown::HashMap;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::live_store::LiveSessionStore;
use crate::touch_buffer::{TouchKey, TouchKeyRef};

/// Silence after which a session's hashrate reads 0. At the vardiff target
/// of 15 shares/min a hashing session goes silent this long practically
/// never; it must stay well below the live TTL or the key expires first.
pub(crate) const SILENCE: Duration = Duration::from_secs(120);

/// Last share per session, stamped at consume time: a stream backlog after
/// a restart must not read as silence.
pub(crate) struct HashrateWatchdog {
    inner: Mutex<HashMap<TouchKey, Instant>>,
}

impl Default for HashrateWatchdog {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl HashrateWatchdog {
    /// Recovers from poison so one panic does not turn every later share
    /// into a panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<TouchKey, Instant>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Note a share. Allocates an owned key only when a session first appears.
    pub(crate) fn record(&self, key: TouchKeyRef<'_>, now: Instant) {
        let mut guard = self.guard();
        if let Some(last) = guard.get_mut(&key) {
            *last = now;
        } else {
            guard.insert(key.to_key(), now);
        }
    }

    /// Remove every session silent for at least `silence` and return the
    /// zero writes for them.
    fn take_silent(&self, now: Instant, silence: Duration) -> Vec<(TouchKey, f64)> {
        let mut silent = Vec::new();
        self.guard().retain(|key, last| {
            let quiet = now.saturating_duration_since(*last) >= silence;
            if quiet {
                silent.push((key.clone(), 0.0));
            }
            !quiet
        });
        silent
    }
}

/// One watchdog pass. A failed write is not retried: the rate then stands
/// until the key's TTL ends it.
pub(crate) async fn zero_silent(
    watchdog: &HashrateWatchdog,
    now: Instant,
    silence: Duration,
    live: Option<&LiveSessionStore>,
) {
    let writes = watchdog.take_silent(now, silence);
    let (false, Some(store)) = (writes.is_empty(), live) else {
        return;
    };
    match store.write_hashrate_batch(&writes).await {
        Ok(()) => debug!(
            zeroed = writes.len(),
            "hashrate watchdog zeroed silent sessions"
        ),
        Err(e) => warn!(
            error = %e,
            silent = writes.len(),
            "live-session hashrate zeroing failed; rates stand until the TTL"
        ),
    }
}

/// Watchdog loop. No final pass on shutdown: the TTL ends every key the
/// watchdog leaves behind.
pub(crate) async fn run_watchdog_loop(
    watchdog: Arc<HashrateWatchdog>,
    live: Option<Arc<LiveSessionStore>>,
    check_interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let start = Instant::now() + check_interval;
    let mut ticker = tokio::time::interval_at(start, check_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                zero_silent(&watchdog, Instant::now(), SILENCE, live.as_deref()).await;
            }
            _ = &mut shutdown_rx => {
                debug!("hashrate watchdog loop received shutdown");
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

    #[test]
    fn a_session_is_zeroed_once_after_the_silence_and_not_before() {
        let w = HashrateWatchdog::default();
        let t0 = Instant::now();
        w.record(kref(), t0);
        let one_s = Duration::from_secs(1);
        assert!(w.take_silent(t0 + SILENCE - one_s, SILENCE).is_empty());
        let writes = w.take_silent(t0 + SILENCE, SILENCE);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].1, 0.0);
        assert!(
            w.take_silent(t0 + SILENCE * 2, SILENCE).is_empty(),
            "forgotten after its zero"
        );
    }

    #[test]
    fn a_new_share_restarts_the_clock() {
        let w = HashrateWatchdog::default();
        let t0 = Instant::now();
        w.record(kref(), t0);
        w.record(kref(), t0 + Duration::from_secs(100));
        assert!(
            w.take_silent(t0 + SILENCE, SILENCE).is_empty(),
            "silent only 20 s since the latest share"
        );
    }
}
