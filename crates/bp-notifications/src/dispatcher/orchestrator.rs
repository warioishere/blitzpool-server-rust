// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;

use bp_common::AddressId;
use bp_db::{
    delete_push_subscription_by_endpoint, find_ntfy_subscription_by_address,
    find_push_subscriptions_by_address, find_telegram_subscriptions_by_address,
    find_telegram_subscriptions_by_chat, update_push_subscription_last_notification, DbError,
    NtfySubscriptionRow, PushSubscriptionRow, TelegramSubscriptionRow,
};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use sqlx::PgPool;
use tracing::{debug, warn};

use crate::command::ChatLanguageMap;

use super::config::DispatcherConfig;
use crate::adapter::{
    AdapterError, FcmAdapter, NtfyAdapter, PushKind, PushPayload, TelegramAdapter, WebPushAdapter,
};
use crate::format::{
    format_device_time, format_number_suffix, DeviceStatusArgs, DeviceStatusText, Language,
};

const PUSH_TYPE_UNIFIED: &str = "UNIFIED_PUSH";
const PUSH_TYPE_FCM: &str = "FCM";

/// Engine-side description of a worker connect / disconnect event. The
/// dispatcher converts this to per-language text and routes to whichever
/// subscribers want it.
#[derive(Debug, Clone)]
pub struct DeviceStatusEvent {
    pub address: AddressId,
    pub worker_name: Option<String>,
    pub user_agent: Option<String>,
    pub is_online: bool,
    pub is_returning: bool,
    pub timestamp: DateTime<Utc>,
}

/// Holds the four push-style adapters + the pool for subscription
/// lookups. Each adapter is optional so the dispatcher can be built
/// even when some transports are disabled (no FCM service account, no
/// Telegram bot token).
pub struct NotificationDispatcher {
    pool: PgPool,
    config: DispatcherConfig,
    telegram: Option<Arc<TelegramAdapter>>,
    ntfy: Option<Arc<NtfyAdapter>>,
    fcm: Option<Arc<FcmAdapter>>,
    web_push: Option<Arc<WebPushAdapter>>,
    chat_languages: ChatLanguageMap,
}

impl NotificationDispatcher {
    pub fn new(
        pool: PgPool,
        config: DispatcherConfig,
        telegram: Option<Arc<TelegramAdapter>>,
        ntfy: Option<Arc<NtfyAdapter>>,
        fcm: Option<Arc<FcmAdapter>>,
        web_push: Option<Arc<WebPushAdapter>>,
        chat_languages: ChatLanguageMap,
    ) -> Self {
        Self {
            pool,
            config,
            telegram,
            ntfy,
            fcm,
            web_push,
            chat_languages,
        }
    }

    // ── Public engine entry points ──────────────────────────────────

    /// `address` finds a block. Fans out short "Block found / Block
    /// gefunden" notifications to all Telegram + ntfy + push
    /// subscribers of that address.
    pub async fn notify_block_found(&self, address: &AddressId, height: u64, message: &str) {
        let (telegram_subs, ntfy_sub, push_subs) = self.load_subs(address).await;

        let mut tasks = Vec::new();
        if !telegram_subs.is_empty() {
            if let Some(adapter) = &self.telegram {
                tasks.push(Box::pin(send_telegram_block_found(
                    Arc::clone(adapter),
                    self.chat_languages.clone(),
                    telegram_subs,
                    height,
                    message.to_string(),
                )) as TaskFuture);
            }
        }
        if let (Some(sub), Some(adapter)) = (ntfy_sub.as_ref(), &self.ntfy) {
            tasks.push(Box::pin(send_ntfy_block_found(
                Arc::clone(adapter),
                sub.address.as_str().to_string(),
                height,
                message.to_string(),
            )) as TaskFuture);
        }
        let push_block: Vec<_> = push_subs
            .iter()
            .filter(|s| s.block_notifications_enabled)
            .cloned()
            .collect();
        if !push_block.is_empty() {
            tasks.push(Box::pin(send_push_block_found(
                self.clone_push_handles(),
                self.pool.clone(),
                address.clone(),
                push_block,
                height,
                message.to_string(),
            )) as TaskFuture);
        }

        join_all(tasks).await;
    }

    /// `address` just produced a new best-difficulty share. Caller is
    /// responsible for deciding this actually IS a new best (engines
    /// keep that state — dispatcher just sends).
    pub async fn notify_best_diff(&self, address: &AddressId, difficulty: f64) {
        if !self.config.best_diff_enabled {
            return;
        }
        let (telegram_subs, ntfy_sub, push_subs) = self.load_subs(address).await;
        let formatted = format_number_suffix(difficulty);

        let mut tasks = Vec::new();
        let telegram_best: Vec<_> = telegram_subs
            .iter()
            .filter(|s| s.best_diff_notifications_enabled)
            .cloned()
            .collect();
        if !telegram_best.is_empty() {
            if let Some(adapter) = &self.telegram {
                tasks.push(Box::pin(send_telegram_best_diff(
                    Arc::clone(adapter),
                    self.pool.clone(),
                    self.chat_languages.clone(),
                    address.clone(),
                    telegram_best,
                    formatted.clone(),
                )) as TaskFuture);
            }
        }
        if let (Some(sub), Some(adapter)) = (ntfy_sub.as_ref(), &self.ntfy) {
            if sub.best_diff_notifications_enabled {
                tasks.push(Box::pin(send_ntfy_best_diff(
                    Arc::clone(adapter),
                    sub.address.as_str().to_string(),
                    Language::parse(&sub.language),
                    formatted.clone(),
                )) as TaskFuture);
            }
        }
        let push_best: Vec<_> = push_subs
            .iter()
            .filter(|s| s.best_diff_notifications_enabled)
            .cloned()
            .collect();
        if !push_best.is_empty() {
            tasks.push(Box::pin(send_push_best_diff(
                self.clone_push_handles(),
                self.pool.clone(),
                address.clone(),
                push_best,
                difficulty,
                formatted,
            )) as TaskFuture);
        }

        join_all(tasks).await;
    }

    /// Worker on `address` connected or disconnected. Routes to
    /// Telegram + FCM (ntfy intentionally skipped — the topic model
    /// doesn't carry per-user device subscriptions cleanly).
    pub async fn notify_device_status(&self, event: &DeviceStatusEvent) {
        let (telegram_subs, _ntfy_sub, push_subs) = self.load_subs(&event.address).await;

        let mut tasks = Vec::new();
        let telegram_dev: Vec<_> = telegram_subs
            .iter()
            .filter(|s| s.device_notifications_enabled)
            .cloned()
            .collect();
        if !telegram_dev.is_empty() {
            if let Some(adapter) = &self.telegram {
                tasks.push(Box::pin(send_telegram_device_status(
                    Arc::clone(adapter),
                    self.pool.clone(),
                    self.chat_languages.clone(),
                    event.clone(),
                    telegram_dev,
                    self.config.timezone,
                )) as TaskFuture);
            }
        }
        // FCM device-status goes through the same push-subscription
        // table as the other types; UnifiedPush is intentionally NOT
        // notified for device-status events.
        let fcm_dev: Vec<_> = push_subs
            .iter()
            .filter(|s| s.subscription_type == PUSH_TYPE_FCM && s.device_notifications_enabled)
            .cloned()
            .collect();
        if !fcm_dev.is_empty() {
            if let Some(adapter) = &self.fcm {
                tasks.push(Box::pin(send_fcm_device_status(
                    Arc::clone(adapter),
                    self.pool.clone(),
                    event.clone(),
                    fcm_dev,
                    self.config.timezone,
                )) as TaskFuture);
            }
        }

        join_all(tasks).await;
    }

    // ── Internals ────────────────────────────────────────────────────

    async fn load_subs(
        &self,
        address: &AddressId,
    ) -> (
        Vec<TelegramSubscriptionRow>,
        Option<NtfySubscriptionRow>,
        Vec<PushSubscriptionRow>,
    ) {
        let (telegram_res, ntfy_res, push_res) = tokio::join!(
            find_telegram_subscriptions_by_address(&self.pool, address),
            find_ntfy_subscription_by_address(&self.pool, address),
            find_push_subscriptions_by_address(&self.pool, address),
        );
        let telegram = telegram_res.unwrap_or_else(|e: DbError| {
            warn!(target: "bp_notifications::dispatcher", error = %e, "telegram-subs lookup");
            Vec::new()
        });
        let ntfy = ntfy_res.unwrap_or_else(|e: DbError| {
            warn!(target: "bp_notifications::dispatcher", error = %e, "ntfy-sub lookup");
            None
        });
        let push = push_res.unwrap_or_else(|e: DbError| {
            warn!(target: "bp_notifications::dispatcher", error = %e, "push-subs lookup");
            Vec::new()
        });
        (telegram, ntfy, push)
    }

    fn clone_push_handles(&self) -> PushHandles {
        PushHandles {
            web_push: self.web_push.as_ref().map(Arc::clone),
            fcm: self.fcm.as_ref().map(Arc::clone),
        }
    }
}

#[derive(Clone)]
struct PushHandles {
    web_push: Option<Arc<WebPushAdapter>>,
    fcm: Option<Arc<FcmAdapter>>,
}

type TaskFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

// ── Send-funkctions per (transport, event-kind) ─────────────────────
//
// Each one resolves to `Future<Output = ()>` so the dispatcher can
// `join_all` them. Errors are logged and absorbed — failed subscribers
// don't take down the entire fan-out.

async fn send_telegram_block_found(
    adapter: Arc<TelegramAdapter>,
    chat_languages: ChatLanguageMap,
    subs: Vec<TelegramSubscriptionRow>,
    height: u64,
    message: String,
) {
    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let chat_languages = chat_languages.clone();
        let message = message.clone();
        async move {
            let lang = chat_language(&chat_languages, sub.telegram_chat_id).await;
            let text = if matches!(lang, Language::De) {
                format!("Block gefunden! Result: {message}, Höhe: {height}")
            } else {
                format!("Block found! Result: {message}, Height: {height}")
            };
            log_adapter_send(
                "telegram-block",
                adapter.send_text(sub.telegram_chat_id, &text).await,
            );
        }
    });
    join_all(tasks).await;
}

async fn send_telegram_best_diff(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguageMap,
    address: AddressId,
    subs: Vec<TelegramSubscriptionRow>,
    formatted: String,
) {
    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let pool = pool.clone();
        let chat_languages = chat_languages.clone();
        let formatted = formatted.clone();
        let address = address.clone();
        async move {
            let lang = chat_language(&chat_languages, sub.telegram_chat_id).await;
            let chat_count = count_chat_subscriptions(&pool, sub.telegram_chat_id).await;
            let include_address = chat_count > 1;
            let fmt_addr = format_address_short(address.as_str());
            let text = match (lang, include_address) {
                (Language::De, true) => format!(
                    "\u{1f3c6} Neue beste Difficulty für Adresse {fmt_addr}!\nWert: {formatted}"
                ),
                (Language::De, false) => {
                    format!("\u{1f3c6} Neue beste Difficulty für deine Adresse!\nWert: {formatted}")
                }
                (Language::En, true) => format!(
                    "\u{1f3c6} New best difficulty for address {fmt_addr}!\nValue: {formatted}"
                ),
                (Language::En, false) => {
                    format!("\u{1f3c6} New best difficulty for your address!\nValue: {formatted}")
                }
            };
            log_adapter_send(
                "telegram-best-diff",
                adapter.send_text(sub.telegram_chat_id, &text).await,
            );
        }
    });
    join_all(tasks).await;
}

async fn send_telegram_device_status(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguageMap,
    event: DeviceStatusEvent,
    subs: Vec<TelegramSubscriptionRow>,
    tz: chrono_tz::Tz,
) {
    let fmt_addr = format_address_short(event.address.as_str());
    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let pool = pool.clone();
        let chat_languages = chat_languages.clone();
        let event = event.clone();
        let fmt_addr = fmt_addr.clone();
        async move {
            let lang = chat_language(&chat_languages, sub.telegram_chat_id).await;
            let chat_count = count_chat_subscriptions(&pool, sub.telegram_chat_id).await;
            let include_address = chat_count > 1;
            let time_str = format_device_time(tz, event.timestamp, lang);
            let address_suffix_de = if include_address {
                Some(format!(" – Adresse {fmt_addr}"))
            } else {
                None
            };
            let address_suffix_en = if include_address {
                Some(format!(" – address {fmt_addr}"))
            } else {
                None
            };
            let suffix_str = match lang {
                Language::De => address_suffix_de.as_deref(),
                Language::En => address_suffix_en.as_deref(),
            };
            let text = DeviceStatusText::build(&DeviceStatusArgs {
                language: lang,
                time_formatted: &time_str,
                user_agent: event.user_agent.as_deref(),
                worker_name: event.worker_name.as_deref(),
                is_online: event.is_online,
                is_returning: event.is_returning,
                address_suffix: suffix_str,
            });
            log_adapter_send(
                "telegram-device",
                adapter
                    .send_text(sub.telegram_chat_id, text.pick(lang))
                    .await,
            );
        }
    });
    join_all(tasks).await;
}

async fn send_ntfy_block_found(
    adapter: Arc<NtfyAdapter>,
    address: String,
    height: u64,
    message: String,
) {
    let body = format!("Block found! Result: {message}, Height: {height}");
    log_adapter_send("ntfy-block", adapter.publish(&address, &body).await);
}

async fn send_ntfy_best_diff(
    adapter: Arc<NtfyAdapter>,
    address: String,
    lang: Language,
    formatted: String,
) {
    let body = match lang {
        Language::De => format!("\u{1f3c6} Neue beste Difficulty!\nWert: {formatted}"),
        Language::En => format!("\u{1f3c6} New best difficulty!\nValue: {formatted}"),
    };
    log_adapter_send("ntfy-best-diff", adapter.publish(&address, &body).await);
}

async fn send_push_block_found(
    handles: PushHandles,
    pool: PgPool,
    address: AddressId,
    subs: Vec<PushSubscriptionRow>,
    height: u64,
    message: String,
) {
    let difficulty = extract_difficulty_tag(&message);
    let payload = PushPayload {
        kind: PushKind::BlockFound,
        title: "New Block Found!".to_string(),
        body: format!("Block height {height}"),
        tag: difficulty,
        extras: vec![("height".into(), height.to_string())],
    };
    fan_push(handles, pool, address, subs, payload).await;
}

async fn send_push_best_diff(
    handles: PushHandles,
    pool: PgPool,
    address: AddressId,
    subs: Vec<PushSubscriptionRow>,
    difficulty: f64,
    formatted: String,
) {
    let payload = PushPayload {
        kind: PushKind::BestDifficulty,
        title: "New Best Difficulty!".to_string(),
        body: format!("Your best difficulty increased to {formatted}"),
        tag: formatted,
        extras: vec![
            ("difficulty".into(), difficulty.to_string()),
            ("formattedDifficulty".into(), String::new()), // filled in tag for compat
        ],
    };
    fan_push(handles, pool, address, subs, payload).await;
}

async fn send_fcm_device_status(
    adapter: Arc<FcmAdapter>,
    pool: PgPool,
    event: DeviceStatusEvent,
    subs: Vec<PushSubscriptionRow>,
    tz: chrono_tz::Tz,
) {
    // FCM device-status payload uses UTC + plain locale ("en-US").
    // Timezone is for telegram + ntfy paths.
    let _ = tz;
    let worker = event
        .worker_name
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());
    let agent = event
        .user_agent
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());
    // FCM uses a timezone-free UTC string.
    let time_str = event.timestamp.format("%m/%d/%y, %-I:%M %p").to_string();
    let title = if event.is_online {
        if event.is_returning {
            "Device Back Online"
        } else {
            "Device Online"
        }
    } else {
        "Device Offline"
    };
    let body = format!("{agent} ({worker}) at {time_str}");

    let payload = PushPayload {
        kind: PushKind::DeviceStatus,
        title: title.to_string(),
        body,
        tag: if event.is_online { "online" } else { "offline" }.to_string(),
        extras: vec![
            (
                "isReturning".into(),
                if event.is_returning { "true" } else { "false" }.to_string(),
            ),
            ("workerName".into(), worker),
            ("userAgent".into(), agent),
            (
                "timestamp".into(),
                event.timestamp.timestamp_millis().to_string(),
            ),
        ],
    };

    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let pool = pool.clone();
        let payload = payload.clone();
        let address = event.address.clone();
        async move {
            match adapter
                .send(&sub.endpoint, address.as_str(), &payload)
                .await
            {
                Ok(outcome) if outcome.invalid_token => {
                    soft_delete_push(&pool, &address, &sub.endpoint).await;
                }
                Ok(_) => {
                    bump_last_notification(&pool, sub.id).await;
                }
                Err(AdapterError::InvalidRecipient(_)) => {
                    soft_delete_push(&pool, &address, &sub.endpoint).await;
                }
                Err(e) => {
                    warn!(target: "bp_notifications::dispatcher", error = %e, "fcm device-status");
                }
            }
        }
    });
    join_all(tasks).await;
}

async fn fan_push(
    handles: PushHandles,
    pool: PgPool,
    address: AddressId,
    subs: Vec<PushSubscriptionRow>,
    payload: PushPayload,
) {
    let tasks = subs.into_iter().map(|sub| {
        let pool = pool.clone();
        let payload = payload.clone();
        let address = address.clone();
        let handles = handles.clone();
        async move {
            match sub.subscription_type.as_str() {
                PUSH_TYPE_UNIFIED => {
                    let Some(adapter) = handles.web_push else {
                        return;
                    };
                    match adapter.send(&sub.endpoint, &payload).await {
                        Ok(outcome) if outcome.invalid_endpoint => {
                            soft_delete_push(&pool, &address, &sub.endpoint).await;
                        }
                        Ok(_) => {
                            bump_last_notification(&pool, sub.id).await;
                        }
                        Err(AdapterError::InvalidRecipient(_)) => {
                            soft_delete_push(&pool, &address, &sub.endpoint).await;
                        }
                        Err(e) => {
                            warn!(target: "bp_notifications::dispatcher", error = %e, "unified push");
                        }
                    }
                }
                PUSH_TYPE_FCM => {
                    let Some(adapter) = handles.fcm else {
                        return;
                    };
                    match adapter.send(&sub.endpoint, address.as_str(), &payload).await {
                        Ok(outcome) if outcome.invalid_token => {
                            soft_delete_push(&pool, &address, &sub.endpoint).await;
                        }
                        Ok(_) => {
                            bump_last_notification(&pool, sub.id).await;
                        }
                        Err(AdapterError::InvalidRecipient(_)) => {
                            soft_delete_push(&pool, &address, &sub.endpoint).await;
                        }
                        Err(e) => {
                            warn!(target: "bp_notifications::dispatcher", error = %e, "fcm push");
                        }
                    }
                }
                other => {
                    debug!(target: "bp_notifications::dispatcher", kind = other, "unknown push subscription_type — ignored");
                }
            }
        }
    });
    join_all(tasks).await;
}

// ── Helpers ──────────────────────────────────────────────────────────

async fn chat_language(map: &ChatLanguageMap, chat_id: i64) -> Language {
    map.lock().await.get(&chat_id).copied().unwrap_or_default()
}

async fn count_chat_subscriptions(pool: &PgPool, chat_id: i64) -> usize {
    match find_telegram_subscriptions_by_chat(pool, chat_id).await {
        Ok(rows) => rows.len(),
        Err(e) => {
            warn!(target: "bp_notifications::dispatcher", error = %e, chat_id, "chat-subs lookup");
            0
        }
    }
}

fn format_address_short(address: &str) -> String {
    // First 4 chars + "..." + last 5 chars. For addresses ≤ 9 chars
    // return the full string.
    if address.len() <= 9 {
        return address.to_string();
    }
    let head: String = address.chars().take(4).collect();
    let tail: String = address
        .chars()
        .rev()
        .take(5)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}...{tail}")
}

fn extract_difficulty_tag(message: &str) -> String {
    // The BlockSubmitted hook formats its result message as `valid (158T)`
    // etc. Pull the bracketed token out for the data.difficulty field.
    let bytes = message.as_bytes();
    let mut start: Option<usize> = None;
    for (i, ch) in bytes.iter().enumerate() {
        if *ch == b'(' {
            start = Some(i + 1);
        } else if *ch == b')' {
            if let Some(s) = start {
                let candidate = &message[s..i];
                if candidate
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || matches!(c, 'K' | 'M' | 'G' | 'T'))
                {
                    return candidate.to_string();
                }
                start = None;
            }
        }
    }
    "Unknown".to_string()
}

async fn soft_delete_push(pool: &PgPool, address: &AddressId, endpoint: &str) {
    if let Err(e) = delete_push_subscription_by_endpoint(pool, address, endpoint).await {
        warn!(target: "bp_notifications::dispatcher", error = %e, "soft-delete push subscription");
    }
}

async fn bump_last_notification(pool: &PgPool, id: i32) {
    let now = Utc::now().timestamp_millis();
    if let Err(e) = update_push_subscription_last_notification(pool, id, now).await {
        warn!(target: "bp_notifications::dispatcher", error = %e, id, "bump lastNotificationAt");
    }
}

fn log_adapter_send(kind: &'static str, result: Result<(), AdapterError>) {
    if let Err(e) = result {
        warn!(target: "bp_notifications::dispatcher", adapter = kind, error = %e, "send failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_address_keeps_prefix_dots_suffix() {
        assert_eq!(
            format_address_short("bc1q1234567890abcdefxyz"),
            "bc1q...efxyz".to_string()
        );
    }

    #[test]
    fn short_address_passthrough_for_tiny_input() {
        assert_eq!(format_address_short("abc"), "abc");
        assert_eq!(format_address_short("123456789"), "123456789");
    }

    #[test]
    fn extract_difficulty_picks_bracketed_token() {
        assert_eq!(extract_difficulty_tag("valid (158T)"), "158T");
        assert_eq!(extract_difficulty_tag("rejected (12.5G)"), "12.5G");
    }

    #[test]
    fn extract_difficulty_returns_unknown_if_no_bracketed_match() {
        assert_eq!(extract_difficulty_tag("no parens here"), "Unknown");
        assert_eq!(extract_difficulty_tag("(not a difficulty)"), "Unknown");
    }
}
