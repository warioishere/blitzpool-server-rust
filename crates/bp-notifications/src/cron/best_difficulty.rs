// SPDX-License-Identifier: AGPL-3.0-or-later

//! Best-difficulty cron: notifies a subscribed address when its persisted
//! best rises past the `best_difficulty_tracker_entity` baseline. The tracker
//! is persisted so a restart does not re-notify and `/api/push/status` can
//! show the last-notified best.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bp_common::AddressId;
use bp_db::{
    find_address_settings_for_addresses, find_best_difficulty_scan_addresses,
    find_best_difficulty_trackers_for_addresses, upsert_best_difficulty_trackers,
};
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use super::classify;
use crate::dispatcher::NotificationDispatcher;

/// Configuration for the best-diff cron. Default tick is 60 s;
/// integration tests can dial it down.
#[derive(Debug, Clone)]
pub struct BestDifficultyCronConfig {
    pub tick_interval: Duration,
    /// Phase offset applied to the first tick so this cron doesn't
    /// align with other periodic jobs of the same period.
    pub startup_offset: Duration,
}

impl Default for BestDifficultyCronConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(60),
            startup_offset: Duration::ZERO,
        }
    }
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Spawn the cron loop.
pub fn spawn_best_difficulty_cron(
    config: BestDifficultyCronConfig,
    pool: PgPool,
    dispatcher: Arc<NotificationDispatcher>,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + config.tick_interval + config.startup_offset;
        let mut ticker = tokio::time::interval_at(start, config.tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(target: "bp_notifications::cron::best_difficulty", "cron started");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    if let Err(e) = run_once(&pool, &dispatcher).await {
                        warn!(target: "bp_notifications::cron::best_difficulty", error = %e, "tick failed");
                    }
                }
            }
        }
        info!(target: "bp_notifications::cron::best_difficulty", "cron stopped");
    });
    shutdown_tx
}

async fn run_once(pool: &PgPool, dispatcher: &NotificationDispatcher) -> Result<(), String> {
    let addresses = find_best_difficulty_scan_addresses(pool)
        .await
        .map_err(|e| format!("addresses read: {e}"))?;
    if addresses.is_empty() {
        return Ok(());
    }

    // Two bulk reads: the current bests and the tracker rows, the
    // notification baseline.
    let addr_strings: Vec<String> = addresses.iter().map(|a| a.as_str().to_string()).collect();
    let current_bests: Vec<(AddressId, f64)> =
        find_address_settings_for_addresses(pool, &addr_strings)
            .await
            .map_err(|e| format!("settings read: {e}"))?
            .into_iter()
            .map(|row| (row.address, row.best_difficulty))
            .collect();
    let tracked: HashMap<String, f64> =
        find_best_difficulty_trackers_for_addresses(pool, &addr_strings)
            .await
            .map_err(|e| format!("trackers read: {e}"))?
            .into_iter()
            .map(|row| (row.address.as_str().to_string(), row.best_difficulty))
            .collect();

    let mut upsert_addr: Vec<String> = Vec::new();
    let mut upsert_diff: Vec<f64> = Vec::new();
    let mut notify: Vec<(AddressId, f64)> = Vec::new();

    for (address, current) in current_bests {
        let action = classify(current, tracked.get(address.as_str()).copied());
        if action.upsert {
            upsert_addr.push(address.as_str().to_string());
            upsert_diff.push(current);
        }
        if action.notify {
            notify.push((address, current));
        }
    }

    if !upsert_addr.is_empty() {
        upsert_best_difficulty_trackers(pool, &upsert_addr, &upsert_diff, now_epoch_ms())
            .await
            .map_err(|e| format!("tracker upsert: {e}"))?;
    }
    for (address, current) in notify {
        dispatcher.notify_best_diff(&address, current).await;
    }
    Ok(())
}
