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
use tracing::warn;

use super::classify;
use crate::dispatcher::NotificationDispatcher;

const TICK: Duration = Duration::from_secs(60);

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Spawn the cron loop.
pub fn spawn_best_difficulty_cron(
    startup_offset: Duration,
    pool: PgPool,
    dispatcher: Arc<NotificationDispatcher>,
) -> watch::Sender<bool> {
    super::spawn_periodic("best_difficulty", TICK, startup_offset, move || {
        let (pool, dispatcher) = (pool.clone(), dispatcher.clone());
        async move {
            if let Err(e) = run_once(&pool, &dispatcher).await {
                warn!(target: "bp_notifications::cron::best_difficulty", error = %e, "tick failed");
            }
        }
    })
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
