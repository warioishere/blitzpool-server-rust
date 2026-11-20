// SPDX-License-Identifier: AGPL-3.0-or-later

//! Periodic notification crons: network difficulty, best difficulty, Team
//! best and the hourly stats / workers digest. The two best crons announce a
//! best only when it rises past the baseline stored for it (`classify`).

pub mod best_difficulty;
pub mod hourly_stats;
pub mod network_difficulty;
pub mod team_best;

/// Runs `tick` every `interval`, the first time `interval + startup_offset`
/// after the spawn so crons of the same period do not line up, until `true`
/// is sent on the returned channel. A tick that overruns skips the missed
/// ones rather than catching up.
pub(crate) fn spawn_periodic<F, Fut>(
    name: &'static str,
    interval: std::time::Duration,
    startup_offset: std::time::Duration,
    mut tick: F,
) -> tokio::sync::watch::Sender<bool>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + interval + startup_offset;
        let mut ticker = tokio::time::interval_at(start, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(cron = name, "cron started");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => tick().await,
            }
        }
        tracing::info!(cron = name, "cron stopped");
    });
    shutdown_tx
}

/// What one best-versus-baseline comparison resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrackerAction {
    /// Announce the best (only a strict increase over a known baseline).
    pub(crate) notify: bool,
    /// Write the best back as the new baseline.
    pub(crate) upsert: bool,
}

/// Compare a current best against its stored baseline. Only a strict
/// increase over a known baseline notifies; a missing baseline is recorded
/// silently, and a lower best (a reset, or a round started over) moves the
/// baseline down silently.
pub(crate) fn classify(current: f64, tracked: Option<f64>) -> TrackerAction {
    match tracked {
        None => TrackerAction {
            notify: false,
            upsert: true,
        },
        Some(prev) if current > prev => TrackerAction {
            notify: true,
            upsert: true,
        },
        Some(prev) if current < prev => TrackerAction {
            notify: false,
            upsert: true,
        },
        Some(_) => TrackerAction {
            notify: false,
            upsert: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_initialises_silently_without_tracker() {
        let a = classify(100.0, None);
        assert!(a.upsert);
        assert!(!a.notify);
    }

    #[test]
    fn classify_notifies_on_strict_increase() {
        let a = classify(150.0, Some(100.0));
        assert!(a.upsert);
        assert!(a.notify);
    }

    #[test]
    fn classify_syncs_down_silently_on_decrease() {
        let a = classify(50.0, Some(100.0));
        assert!(a.upsert);
        assert!(!a.notify);
    }

    #[test]
    fn classify_noops_on_equal_value() {
        let a = classify(100.0, Some(100.0));
        assert!(!a.upsert);
        assert!(!a.notify);
    }
}
