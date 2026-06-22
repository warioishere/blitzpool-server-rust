// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hourly stats / workers cron (fires once an hour).
//!
//! Per tick:
//!
//! 1. Fetch all Telegram + ntfy subscriptions with either
//!    `hourlyStatsEnabled` or `hourlyWorkersEnabled` set.
//! 2. For each: reuse the existing read-command builders
//!    ([`build_stats`] / [`build_show_workers`]) to render per-language
//!    text, then push via the matching adapter.
//!
//! Language resolution:
//!
//! - ntfy uses the subscription row's `language` column.
//! - Telegram reads the per-chat in-memory language map shared from
//!   `CommandHandler` (the one `/deutsch` / `/english` write), so a
//!   chat's hourly digest matches the language it chose. Defaults to
//!   English for chats that never set one (the map is per-process, so a
//!   chat that hasn't issued a language command since the last restart
//!   falls back to the default).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bp_db::{
    find_ntfy_subscriptions_with_hourly_enabled, find_telegram_subscriptions_with_hourly_enabled,
};
use sqlx::PgPool;
use tokio::sync::{watch, Mutex};
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

use crate::adapter::{NtfyAdapter, TelegramAdapter};
use crate::command::read::{build_show_workers, build_stats};
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
    telegram: Option<Arc<TelegramAdapter>>,
    ntfy: Option<Arc<NtfyAdapter>>,
    chat_languages: Arc<Mutex<HashMap<i64, Language>>>,
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
                    run_once(&pool, telegram.as_deref(), ntfy.as_deref(), &chat_languages).await;
                }
            }
        }
        info!(target: "bp_notifications::cron::hourly_stats", "cron stopped");
    });
    shutdown_tx
}

async fn run_once(
    pool: &PgPool,
    telegram: Option<&TelegramAdapter>,
    ntfy: Option<&NtfyAdapter>,
    chat_languages: &Arc<Mutex<HashMap<i64, Language>>>,
) {
    if let Some(adapter) = telegram {
        match find_telegram_subscriptions_with_hourly_enabled(pool).await {
            Ok(rows) => {
                for row in rows {
                    process_telegram_row(pool, adapter, row, chat_languages).await;
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
                    process_ntfy_row(pool, adapter, row).await;
                }
            }
            Err(e) => {
                warn!(target: "bp_notifications::cron::hourly_stats", error = %e, "ntfy subs read");
            }
        }
    }
}

/// Resolve a chat's language from the shared in-memory map (written by
/// the `/deutsch` / `/english` command handler); chats that never set
/// one fall back to the default.
async fn resolve_telegram_language(
    chat_languages: &Arc<Mutex<HashMap<i64, Language>>>,
    chat_id: i64,
) -> Language {
    chat_languages
        .lock()
        .await
        .get(&chat_id)
        .copied()
        .unwrap_or_default()
}

async fn process_telegram_row(
    pool: &PgPool,
    adapter: &TelegramAdapter,
    sub: bp_db::TelegramSubscriptionRow,
    chat_languages: &Arc<Mutex<HashMap<i64, Language>>>,
) {
    let lang = resolve_telegram_language(chat_languages, sub.telegram_chat_id).await;
    if sub.hourly_stats_enabled {
        let text = build_stats(pool, lang, &sub.address).await;
        if let Err(e) = adapter.send_text(sub.telegram_chat_id, &text).await {
            warn!(target: "bp_notifications::cron::hourly_stats", error = %e, chat = sub.telegram_chat_id, "telegram stats send");
        }
    }
    if sub.hourly_workers_enabled {
        let text = build_show_workers(pool, lang, &sub.address).await;
        if let Err(e) = adapter.send_text(sub.telegram_chat_id, &text).await {
            warn!(target: "bp_notifications::cron::hourly_stats", error = %e, chat = sub.telegram_chat_id, "telegram workers send");
        }
    }
}

async fn process_ntfy_row(pool: &PgPool, adapter: &NtfyAdapter, sub: bp_db::NtfySubscriptionRow) {
    let lang = Language::parse(&sub.language);
    let address = sub.address.as_str();
    if sub.hourly_stats_enabled {
        let text = build_stats(pool, lang, &sub.address).await;
        if let Err(e) = adapter.publish(address, &text).await {
            warn!(target: "bp_notifications::cron::hourly_stats", error = %e, address, "ntfy stats publish");
        }
    }
    if sub.hourly_workers_enabled {
        let text = build_show_workers(pool, lang, &sub.address).await;
        if let Err(e) = adapter.publish(address, &text).await {
            warn!(target: "bp_notifications::cron::hourly_stats", error = %e, address, "ntfy workers publish");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_language_reads_shared_map_else_defaults() {
        let map: Arc<Mutex<HashMap<i64, Language>>> = Arc::new(Mutex::new(HashMap::new()));
        // Chat that set German via /deutsch.
        map.lock().await.insert(111, Language::De);

        assert_eq!(resolve_telegram_language(&map, 111).await, Language::De);
        // Chat that never set a language → default (English).
        assert_eq!(
            resolve_telegram_language(&map, 999).await,
            Language::default()
        );
    }
}
