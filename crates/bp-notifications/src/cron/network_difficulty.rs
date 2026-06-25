// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mempool-space network-difficulty poller.
//!
//! Every 10 min we hit `https://mempool.space/api/v1/mining/hashrate/3d`,
//! compare the `currentDifficulty` field to the persisted singleton row,
//! and on a relative change exceeding 0.01% persist + emit a
//! network-difficulty push to all FCM and UnifiedPush subscribers.

use std::sync::Arc;
use std::time::Duration;

use bp_db::{
    find_addresses_with_push_subscription, find_network_difficulty_tracker,
    upsert_network_difficulty_tracker,
};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::adapter::{FcmAdapter, PushKind, PushPayload, WebPushAdapter};

const MEMPOOL_API: &str = "https://mempool.space/api/v1/mining/hashrate/3d";

// 0.01% relative threshold — only notify when difficulty shifts meaningfully.
const DIFF_CHANGE_THRESHOLD: f64 = 0.0001;

/// Configuration for the network-difficulty cron. Default tick is
/// 10 min; an integration-test caller can drop it to a few seconds.
#[derive(Debug, Clone)]
pub struct NetworkDifficultyCronConfig {
    pub tick_interval: Duration,
    /// Phase offset applied to the first tick so this cron doesn't
    /// fire on the same boot-relative instant as other periodic jobs
    /// that share the same `tick_interval`.
    pub startup_offset: Duration,
}

impl Default for NetworkDifficultyCronConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(600),
            startup_offset: Duration::ZERO,
        }
    }
}

/// Spawn the cron loop. Returns a shutdown handle (drop or send `true`
/// to stop the loop after the next tick). The cron is gated on at
/// least one of `fcm` or `web_push` being present: without any push
/// adapter we still keep the tracker row fresh so other dashboards have
/// up-to-date data but emit no push notifications.
pub fn spawn_network_difficulty_cron(
    config: NetworkDifficultyCronConfig,
    pool: PgPool,
    fcm: Option<Arc<FcmAdapter>>,
    web_push: Option<Arc<WebPushAdapter>>,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
            Ok(c) => c,
            Err(e) => {
                warn!(target: "bp_notifications::cron::network_difficulty", error = %e, "client build failed");
                return;
            }
        };
        let start = tokio::time::Instant::now() + config.tick_interval + config.startup_offset;
        let mut ticker = tokio::time::interval_at(start, config.tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(target: "bp_notifications::cron::network_difficulty", "cron started");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    if let Err(e) = run_once(&client, &pool, fcm.as_deref(), web_push.as_deref()).await {
                        warn!(target: "bp_notifications::cron::network_difficulty", error = %e, "tick failed");
                    }
                }
            }
        }
        info!(target: "bp_notifications::cron::network_difficulty", "cron stopped");
    });
    shutdown_tx
}

async fn run_once(
    client: &Client,
    pool: &PgPool,
    fcm: Option<&FcmAdapter>,
    web_push: Option<&WebPushAdapter>,
) -> Result<(), String> {
    let new_diff = fetch_current_difficulty(client).await?;
    let previous = match find_network_difficulty_tracker(pool).await {
        Ok(opt) => opt.map(|row| row.current_difficulty),
        Err(e) => return Err(format!("tracker read: {e}")),
    };
    let now_ms = Utc::now().timestamp_millis();
    if let Err(e) = upsert_network_difficulty_tracker(pool, new_diff, now_ms).await {
        return Err(format!("tracker upsert: {e}"));
    }
    // Relative change must exceed 0.01% before we fan out.
    // On first boot (no previous value) or zero-difficulty we skip.
    let should_fan_out = match previous {
        Some(prev) if prev != 0.0 => (new_diff - prev).abs() / prev > DIFF_CHANGE_THRESHOLD,
        _ => false,
    };
    if should_fan_out {
        let old_diff = previous.expect("previous is Some when should_fan_out is true");
        if fcm.is_some() || web_push.is_some() {
            if let Err(e) = fan_out_change(pool, fcm, web_push, old_diff, new_diff, now_ms).await {
                warn!(target: "bp_notifications::cron::network_difficulty", error = %e, "fan-out");
            }
        }
    }
    Ok(())
}

async fn fetch_current_difficulty(client: &Client) -> Result<f64, String> {
    let response = client
        .get(MEMPOOL_API)
        .send()
        .await
        .map_err(|e| format!("mempool.space request: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("mempool.space {}", response.status().as_u16()));
    }
    #[derive(Deserialize)]
    struct ApiResponse {
        #[serde(rename = "currentDifficulty")]
        current_difficulty: f64,
    }
    let body: ApiResponse = response
        .json()
        .await
        .map_err(|e| format!("mempool.space body: {e}"))?;
    Ok(body.current_difficulty)
}

async fn fan_out_change(
    pool: &PgPool,
    fcm: Option<&FcmAdapter>,
    web_push: Option<&WebPushAdapter>,
    old_diff: f64,
    new_diff: f64,
    now_ms: i64,
) -> Result<(), String> {
    let addresses = find_addresses_with_push_subscription(pool)
        .await
        .map_err(|e| format!("addresses read: {e}"))?;
    if addresses.is_empty() {
        return Ok(());
    }

    let percent_change = (new_diff - old_diff) / old_diff * 100.0;
    let direction = if percent_change >= 0.0 {
        "Increased"
    } else {
        "Decreased"
    };
    let fmt_old = crate::format::format_number_suffix(old_diff);
    let fmt_new = crate::format::format_number_suffix(new_diff);
    let sign = if percent_change >= 0.0 { "+" } else { "" };

    let payload = PushPayload {
        kind: PushKind::NetworkDifficulty,
        title: format!("Network Difficulty {direction}"),
        body: format!("Changed from {fmt_old} to {fmt_new} ({sign}{percent_change:.2}%)"),
        tag: fmt_new.clone(),
        extras: vec![
            ("type".into(), "network_difficulty".into()),
            ("oldDifficulty".into(), old_diff.to_string()),
            ("newDifficulty".into(), new_diff.to_string()),
            ("percentChange".into(), percent_change.to_string()),
            ("formattedOldDifficulty".into(), fmt_old),
            ("formattedNewDifficulty".into(), fmt_new),
            ("timestamp".into(), now_ms.to_string()),
        ],
    };

    for address in addresses {
        let subs = match bp_db::find_push_subscriptions_by_address(pool, &address).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::cron::network_difficulty", error = %e, address = %address.as_str(), "subs lookup");
                continue;
            }
        };
        for sub in subs
            .into_iter()
            .filter(|s| s.network_diff_notifications_enabled)
        {
            let kind = sub.subscription_type.as_str();
            if kind.eq_ignore_ascii_case("fcm") {
                let Some(adapter) = fcm else { continue };
                match adapter
                    .send(&sub.endpoint, address.as_str(), &payload)
                    .await
                {
                    Ok(outcome) if outcome.invalid_token => {
                        let _ = bp_db::delete_push_subscription_by_endpoint(
                            pool,
                            &address,
                            &sub.endpoint,
                        )
                        .await;
                    }
                    Ok(_) => {
                        let _ = bp_db::update_push_subscription_last_notification(
                            pool,
                            sub.id,
                            Utc::now().timestamp_millis(),
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(target: "bp_notifications::cron::network_difficulty", error = %e, "FCM send");
                    }
                }
            } else if kind.eq_ignore_ascii_case("unified_push") {
                let Some(adapter) = web_push else { continue };
                match adapter.send(&sub.endpoint, &payload).await {
                    Ok(outcome) if outcome.invalid_endpoint => {
                        let _ = bp_db::delete_push_subscription_by_endpoint(
                            pool,
                            &address,
                            &sub.endpoint,
                        )
                        .await;
                    }
                    Ok(_) => {
                        let _ = bp_db::update_push_subscription_last_notification(
                            pool,
                            sub.id,
                            Utc::now().timestamp_millis(),
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(target: "bp_notifications::cron::network_difficulty", error = %e, "UnifiedPush send");
                    }
                }
            } else {
                warn!(target: "bp_notifications::cron::network_difficulty", kind, "unknown subscription_type — skipped");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_filters_tiny_changes() {
        // 0.005% change is below threshold
        let old = 100_000_000_000.0_f64;
        let new = old * 1.00005;
        let should = (new - old).abs() / old > DIFF_CHANGE_THRESHOLD;
        assert!(!should, "0.005% should not trigger fan-out");
    }

    #[test]
    fn threshold_passes_meaningful_changes() {
        // 0.5% change is above threshold
        let old = 100_000_000_000.0_f64;
        let new = old * 1.005;
        let should = (new - old).abs() / old > DIFF_CHANGE_THRESHOLD;
        assert!(should, "0.5% should trigger fan-out");
    }

    #[test]
    fn direction_label_matches_ts() {
        let old = 100.0_f64;
        assert_eq!(
            if (200.0_f64 - old) / old * 100.0 >= 0.0 {
                "Increased"
            } else {
                "Decreased"
            },
            "Increased"
        );
        assert_eq!(
            if (50.0_f64 - old) / old * 100.0 >= 0.0 {
                "Increased"
            } else {
                "Decreased"
            },
            "Decreased"
        );
    }

    #[test]
    fn payload_extras_keys_match_ts() {
        let percent_change = 2.5_f64;
        let old_diff = 80_000_000_000.0_f64;
        let new_diff = old_diff * 1.025;
        let now_ms = 1_700_000_000_000_i64;
        let fmt_old = crate::format::format_number_suffix(old_diff);
        let fmt_new = crate::format::format_number_suffix(new_diff);
        let sign = if percent_change >= 0.0 { "+" } else { "" };
        let direction = "Increased";

        let payload = PushPayload {
            kind: PushKind::NetworkDifficulty,
            title: format!("Network Difficulty {direction}"),
            body: format!("Changed from {fmt_old} to {fmt_new} ({sign}{percent_change:.2}%)"),
            tag: fmt_new.clone(),
            extras: vec![
                ("type".into(), "network_difficulty".into()),
                ("oldDifficulty".into(), old_diff.to_string()),
                ("newDifficulty".into(), new_diff.to_string()),
                ("percentChange".into(), percent_change.to_string()),
                ("formattedOldDifficulty".into(), fmt_old.clone()),
                ("formattedNewDifficulty".into(), fmt_new.clone()),
                ("timestamp".into(), now_ms.to_string()),
            ],
        };

        let keys: Vec<&str> = payload.extras.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"type"), "missing type");
        assert!(keys.contains(&"oldDifficulty"), "missing oldDifficulty");
        assert!(keys.contains(&"newDifficulty"), "missing newDifficulty");
        assert!(keys.contains(&"percentChange"), "missing percentChange");
        assert!(
            keys.contains(&"formattedOldDifficulty"),
            "missing formattedOldDifficulty"
        );
        assert!(
            keys.contains(&"formattedNewDifficulty"),
            "missing formattedNewDifficulty"
        );
        assert!(keys.contains(&"timestamp"), "missing timestamp");
        assert!(
            payload.title.contains("Increased"),
            "title should contain direction"
        );
        assert!(
            payload.body.starts_with("Changed from"),
            "body format mismatch"
        );
    }
}
