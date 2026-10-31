// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hourly stats / workers digest for Telegram and ntfy subscribers, rendered
//! by the same builders as the read commands, in each chat's stored language.

use std::sync::Arc;
use std::time::Duration;

use bp_db::{
    find_ntfy_subscriptions_with_hourly_enabled, find_telegram_subscriptions_with_hourly_enabled,
};
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::adapter::{NtfyAdapter, TelegramAdapter};
use crate::command::read::{build_show_workers, build_stats};
use crate::command::ChatLanguages;
use crate::dispatcher::settle_telegram_push;
use crate::format::Language;

#[derive(Debug, Clone)]
pub struct HourlyStatsCronConfig {
    pub tick_interval: Duration,
    /// Phase offset applied to the first tick so this cron doesn't
    /// align with other periodic jobs of the same period.
    pub startup_offset: Duration,
}

impl Default for HourlyStatsCronConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(3600),
            startup_offset: Duration::ZERO,
        }
    }
}

/// Spawn the cron loop. Either or both adapters may be `None`; in
/// that case the corresponding subscription set is skipped each tick.
pub fn spawn_hourly_stats_cron(
    config: HourlyStatsCronConfig,
    pool: PgPool,
    redis: Option<redis::aio::ConnectionManager>,
    telegram: Option<Arc<TelegramAdapter>>,
    ntfy: Option<Arc<NtfyAdapter>>,
    chat_languages: ChatLanguages,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + config.tick_interval + config.startup_offset;
        let mut ticker = tokio::time::interval_at(start, config.tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(target: "bp_notifications::cron::hourly_stats", "cron started");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    run_once(&pool, redis.as_ref(), telegram.as_deref(), ntfy.as_deref(), &chat_languages).await;
                }
            }
        }
        info!(target: "bp_notifications::cron::hourly_stats", "cron stopped");
    });
    shutdown_tx
}

async fn run_once(
    pool: &PgPool,
    redis: Option<&redis::aio::ConnectionManager>,
    telegram: Option<&TelegramAdapter>,
    ntfy: Option<&NtfyAdapter>,
    chat_languages: &ChatLanguages,
) {
    if let Some(adapter) = telegram {
        match find_telegram_subscriptions_with_hourly_enabled(pool).await {
            Ok(rows) => {
                for row in rows {
                    process_telegram_row(pool, redis, adapter, row, chat_languages).await;
                }
            }
            Err(e) => {
                warn!(target: "bp_notifications::cron::hourly_stats", error = %e, "telegram subs read");
            }
        }
    }
    if let Some(adapter) = ntfy {
        match find_ntfy_subscriptions_with_hourly_enabled(pool).await {
            Ok(rows) => {
                for row in rows {
                    process_ntfy_row(pool, redis, adapter, row).await;
                }
            }
            Err(e) => {
                warn!(target: "bp_notifications::cron::hourly_stats", error = %e, "ntfy subs read");
            }
        }
    }
}

async fn process_telegram_row(
    pool: &PgPool,
    redis: Option<&redis::aio::ConnectionManager>,
    adapter: &TelegramAdapter,
    sub: bp_db::TelegramSubscriptionRow,
    chat_languages: &ChatLanguages,
) {
    let lang = chat_languages.get(sub.telegram_chat_id).await;
    if sub.hourly_stats_enabled {
        let text = build_stats(pool, redis, lang, &sub.address).await;
        let sent = adapter.send_html(sub.telegram_chat_id, &text).await;
        settle_telegram_push(pool, sub.telegram_chat_id, "telegram-hourly-stats", sent).await;
    }
    if sub.hourly_workers_enabled {
        let text = build_show_workers(pool, redis, lang, &sub.address).await;
        let sent = adapter.send_html(sub.telegram_chat_id, &text).await;
        settle_telegram_push(pool, sub.telegram_chat_id, "telegram-hourly-workers", sent).await;
    }
}

async fn process_ntfy_row(
    pool: &PgPool,
    redis: Option<&redis::aio::ConnectionManager>,
    adapter: &NtfyAdapter,
    sub: bp_db::NtfySubscriptionRow,
) {
    let lang = Language::parse(&sub.language);
    let address = sub.address.as_str();
    if sub.hourly_stats_enabled {
        let text = build_stats(pool, redis, lang, &sub.address).await;
        if let Err(e) = adapter.publish(address, &text).await {
            warn!(target: "bp_notifications::cron::hourly_stats", error = %e, address, "ntfy stats publish");
        }
    }
    if sub.hourly_workers_enabled {
        let text = build_show_workers(pool, redis, lang, &sub.address).await;
        if let Err(e) = adapter.publish(address, &text).await {
            warn!(target: "bp_notifications::cron::hourly_stats", error = %e, address, "ntfy workers publish");
        }
    }
}
