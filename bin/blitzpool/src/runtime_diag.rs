// SPDX-License-Identifier: AGPL-3.0-or-later

//! Latency diagnostics (gated by `debug.submit_latency`) that tell apart the
//! causes of a slow per-share `XADD`: a late watchdog means a stalled runtime,
//! a slow `PING` means the shared `ConnectionManager`, neither means the
//! connection loop's own await context.

use std::time::Duration;

use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::warn;

const WATCHDOG_TICK: Duration = Duration::from_millis(100);
const PING_TICK: Duration = Duration::from_millis(500);
const SLOW: Duration = Duration::from_millis(50);

/// The probes run for the process lifetime; dropping the handles does not
/// abort them.
pub(crate) fn spawn(redis: ConnectionManager) -> (JoinHandle<()>, JoinHandle<()>) {
    (spawn_watchdog(), spawn_ping_probe(redis))
}

/// Lateness ≥ [`SLOW`] means no worker thread polled it in time.
fn spawn_watchdog() -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut next = Instant::now() + WATCHDOG_TICK;
        loop {
            tokio::time::sleep_until(next).await;
            let now = Instant::now();
            let late = now.saturating_duration_since(next);
            if late >= SLOW {
                warn!(
                    late_ms = late.as_millis() as u64,
                    "runtime stall — watchdog fired late (executor was not scheduling tasks)"
                );
            }
            next += WATCHDOG_TICK;
            // Re-sync when the next deadline is already past, so one stall
            // doesn't emit a burst of catch-up ticks.
            if next < now {
                next = now + WATCHDOG_TICK;
            }
        }
    })
}

fn spawn_ping_probe(mut redis: ConnectionManager) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PING_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let t0 = std::time::Instant::now();
            let res: redis::RedisResult<String> = redis::cmd("PING").query_async(&mut redis).await;
            let us = t0.elapsed().as_micros();
            match res {
                Ok(_) if us >= SLOW.as_micros() => {
                    warn!(us, "redis PING slow on the shared ConnectionManager");
                }
                Err(e) => warn!(error = %e, us, "redis PING failed"),
                _ => {}
            }
        }
    })
}
