// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-time latency diagnostics (gated by `debug.submit_latency`).
//!
//! Splits a slow per-share Redis `XADD` into two distinct causes:
//!
//! - **Runtime stall** — the tokio executor isn't scheduling tasks
//!   promptly (a blocking op holds a worker thread, or the runtime is
//!   effectively single-threaded under a CPU cap). Detected by a heartbeat
//!   that should fire every 100 ms; if it fires *late*, no worker polled it
//!   in time.
//! - **ConnectionManager / connection slow** — the shared Redis
//!   `ConnectionManager` round-trip itself is slow, independent of any
//!   connection loop. Detected by a periodic `PING` on that same handle.
//!
//! If the watchdog fires late at the same moments the XADD is slow → it's
//! the runtime. If `PING` is slow while the watchdog stays quiet → it's the
//! ConnectionManager/connection. If neither fires but the in-loop XADD is
//! still slow → the cause is specific to the connection-loop await context.

use std::time::Duration;

use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::warn;

const WATCHDOG_TICK: Duration = Duration::from_millis(100);
const PING_TICK: Duration = Duration::from_millis(500);
const SLOW: Duration = Duration::from_millis(50);

/// Spawn both probes. The returned handles run for the process lifetime
/// (dropping a `JoinHandle` does not abort the task); the caller keeps them
/// only to make ownership explicit.
pub(crate) fn spawn(redis: ConnectionManager) -> (JoinHandle<()>, JoinHandle<()>) {
    (spawn_watchdog(), spawn_ping_probe(redis))
}

/// Heartbeat: should fire every [`WATCHDOG_TICK`]. Lateness ≥ [`SLOW`]
/// means no worker thread polled it in time → executor starvation.
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
            // Re-sync if we fell so far behind that the next deadline is
            // already in the past, so one stall doesn't emit a burst of
            // catch-up ticks.
            if next < now {
                next = now + WATCHDOG_TICK;
            }
        }
    })
}

/// `PING` the shared `ConnectionManager` on a cadence; warn on slow
/// round-trips. Slow `PING` ⇒ the connection/manager itself is the
/// bottleneck (not the per-share connection loop).
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
