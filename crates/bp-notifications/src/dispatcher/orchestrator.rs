// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;

use bp_common::{short_address, AddressId};
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

use crate::adapter::{
    AdapterError, FcmAdapter, NtfyAdapter, PushKind, PushPayload, TelegramAdapter, WebPushAdapter,
};
use crate::format::{
    format_device_time, format_number_suffix, DeviceAggregateArgs, DeviceAggregateText,
    DevicePartialArgs, DevicePartialText, DeviceStatusArgs, DeviceStatusText, Language,
};

use super::device_gate::{DeviceAggregate, DeviceNotice, DevicePartial};

// Canonical stored `subscriptionType` values (lowercase, as written by
// the `/api/push/*` register endpoints). Comparisons below are
// case-insensitive so a row stored in any casing still routes.
pub(crate) const PUSH_TYPE_UNIFIED: &str = "unified_push";
pub(crate) const PUSH_TYPE_FCM: &str = "fcm";

/// Timezone device-status timestamps are rendered in.
const DEVICE_TIMEZONE: chrono_tz::Tz = chrono_tz::Europe::Zurich;

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
    telegram: Option<Arc<TelegramAdapter>>,
    ntfy: Option<Arc<NtfyAdapter>>,
    fcm: Option<Arc<FcmAdapter>>,
    web_push: Option<Arc<WebPushAdapter>>,
    chat_languages: ChatLanguageMap,
}

impl NotificationDispatcher {
    pub fn new(
        pool: PgPool,
        telegram: Option<Arc<TelegramAdapter>>,
        ntfy: Option<Arc<NtfyAdapter>>,
        fcm: Option<Arc<FcmAdapter>>,
        web_push: Option<Arc<WebPushAdapter>>,
        chat_languages: ChatLanguageMap,
    ) -> Self {
        Self {
            pool,
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

    /// Send a device-status message the [`DeviceStatusGate`] has already
    /// confirmed; the production entry point.
    ///
    /// [`DeviceStatusGate`]: super::DeviceStatusGate
    pub async fn notify_device_notice(&self, notice: &DeviceNotice) {
        match notice {
            DeviceNotice::Single(event) => self.notify_device_status(event).await,
            DeviceNotice::Aggregate(agg) => self.notify_device_aggregate(agg).await,
            DeviceNotice::Partial(partial) => self.notify_device_partial(partial).await,
        }
    }

    /// Some of a worker's rigs are gone and the rest keep hashing. Only the
    /// wording differs from the other two: the owner of three rigs must not
    /// read "offline" when two are still working.
    pub async fn notify_device_partial(&self, partial: &DevicePartial) {
        self.notify_device(
            &partial.address,
            |adapter, pool, langs, subs| {
                Box::pin(send_telegram_device_partial(
                    adapter,
                    pool,
                    langs,
                    partial.clone(),
                    subs,
                ))
            },
            || device_partial_fcm_payload(partial),
            || device_partial_unified_payload(partial),
        )
        .await;
    }

    /// Several transitions on one address, collapsed into one message.
    /// Same transports and same per-subscriber filtering as the single
    /// form — only the rendered text differs.
    pub async fn notify_device_aggregate(&self, agg: &DeviceAggregate) {
        self.notify_device(
            &agg.address,
            |adapter, pool, langs, subs| {
                Box::pin(send_telegram_device_aggregate(
                    adapter,
                    pool,
                    langs,
                    agg.clone(),
                    subs,
                ))
            },
            || device_aggregate_fcm_payload(agg),
            || device_aggregate_unified_payload(agg),
        )
        .await;
    }

    /// Worker on `address` connected or disconnected. Routes to
    /// Telegram + FCM + UnifiedPush (ntfy intentionally skipped — the
    /// topic model doesn't carry per-user device subscriptions cleanly).
    pub async fn notify_device_status(&self, event: &DeviceStatusEvent) {
        self.notify_device(
            &event.address,
            |adapter, pool, langs, subs| {
                Box::pin(send_telegram_device_status(
                    adapter,
                    pool,
                    langs,
                    event.clone(),
                    subs,
                ))
            },
            || device_status_fcm_payload(event),
            || device_status_unified_payload(event),
        )
        .await;
    }

    /// Route one device notice to every device-enabled subscription. The two
    /// push transports do NOT share a payload: FCM turns `tag` into
    /// `data.status` and merges `extras`, while UnifiedPush flattens to
    /// `title|body|tag`. Payloads are built only for a transport with subscribers.
    async fn notify_device(
        &self,
        address: &AddressId,
        telegram: impl FnOnce(
            Arc<TelegramAdapter>,
            PgPool,
            ChatLanguageMap,
            Vec<TelegramSubscriptionRow>,
        ) -> TaskFuture,
        fcm_payload: impl FnOnce() -> PushPayload,
        unified_payload: impl FnOnce() -> PushPayload,
    ) {
        let (telegram_subs, _ntfy_sub, push_subs) = self.load_subs(address).await;

        let mut tasks = Vec::new();
        let telegram_dev: Vec<_> = telegram_subs
            .into_iter()
            .filter(|s| s.device_notifications_enabled)
            .collect();
        if !telegram_dev.is_empty() {
            if let Some(adapter) = &self.telegram {
                tasks.push(telegram(
                    Arc::clone(adapter),
                    self.pool.clone(),
                    self.chat_languages.clone(),
                    telegram_dev,
                ));
            }
        }
        let push_of = |kind: &str| -> Vec<PushSubscriptionRow> {
            push_subs
                .iter()
                .filter(|s| {
                    s.subscription_type.eq_ignore_ascii_case(kind) && s.device_notifications_enabled
                })
                .cloned()
                .collect()
        };
        let fcm_dev = push_of(PUSH_TYPE_FCM);
        if !fcm_dev.is_empty() {
            tasks.push(Box::pin(fan_push(
                self.clone_push_handles(),
                self.pool.clone(),
                address.clone(),
                fcm_dev,
                fcm_payload(),
            )) as TaskFuture);
        }
        let unified_dev = push_of(PUSH_TYPE_UNIFIED);
        if !unified_dev.is_empty() {
            tasks.push(Box::pin(fan_push(
                self.clone_push_handles(),
                self.pool.clone(),
                address.clone(),
                unified_dev,
                unified_payload(),
            )) as TaskFuture);
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

// ── Send functions per (transport, event-kind) ──────────────────────
// Errors are logged and absorbed so one failed subscriber does not take
// down the whole `join_all` fan-out.

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
            let fmt_addr = short_address(address.as_str());
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
) {
    let fmt_addr = short_address(event.address.as_str());
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
            let time_str = format_device_time(DEVICE_TIMEZONE, event.timestamp, lang);
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

async fn send_telegram_device_partial(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguageMap,
    partial: DevicePartial,
    subs: Vec<TelegramSubscriptionRow>,
) {
    let fmt_addr = short_address(partial.address.as_str());
    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let pool = pool.clone();
        let chat_languages = chat_languages.clone();
        let partial = partial.clone();
        let fmt_addr = fmt_addr.clone();
        async move {
            let lang = chat_language(&chat_languages, sub.telegram_chat_id).await;
            let chat_count = count_chat_subscriptions(&pool, sub.telegram_chat_id).await;
            let time_str = format_device_time(DEVICE_TIMEZONE, partial.timestamp, lang);
            let suffix = (chat_count > 1).then(|| match lang {
                Language::De => format!(" – Adresse {fmt_addr}"),
                Language::En => format!(" – address {fmt_addr}"),
            });
            let text = DevicePartialText::build(&DevicePartialArgs {
                language: lang,
                time_formatted: &time_str,
                worker_name: partial.worker_name.as_deref(),
                remaining: partial.remaining,
                before: partial.before,
                address_suffix: suffix.as_deref(),
            });
            log_adapter_send(
                "telegram-device-partial",
                adapter
                    .send_text(sub.telegram_chat_id, text.pick(lang))
                    .await,
            );
        }
    });
    join_all(tasks).await;
}

/// Push payload for a partial loss. `status` is deliberately neither
/// `online` nor `offline`, because the worker is neither gone nor unchanged;
/// the keys shipped clients read are all present, the counts added alongside.
fn device_partial_fcm_payload(partial: &DevicePartial) -> PushPayload {
    let time_str = partial.timestamp.format("%m/%d/%y, %-I:%M %p").to_string();
    let text = DevicePartialText::build(&DevicePartialArgs {
        language: Language::En,
        time_formatted: &time_str,
        worker_name: partial.worker_name.as_deref(),
        remaining: partial.remaining,
        before: partial.before,
        address_suffix: None,
    });
    PushPayload {
        kind: PushKind::DeviceStatus,
        title: "Device Status".to_string(),
        body: text.en,
        tag: "reduced".to_string(),
        extras: vec![
            ("isReturning".into(), "false".to_string()),
            (
                "workerName".into(),
                partial
                    .worker_name
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
            ),
            (
                "userAgent".into(),
                partial
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
            ),
            ("remaining".into(), partial.remaining.to_string()),
            ("before".into(), partial.before.to_string()),
            (
                "timestamp".into(),
                partial.timestamp.timestamp_millis().to_string(),
            ),
        ],
    }
}

/// UnifiedPush counterpart — same `title|body|` shape as the others.
fn device_partial_unified_payload(partial: &DevicePartial) -> PushPayload {
    let time_str = partial.timestamp.format("%m/%d/%y, %-I:%M %p").to_string();
    let text = DevicePartialText::build(&DevicePartialArgs {
        language: Language::En,
        time_formatted: &time_str,
        worker_name: partial.worker_name.as_deref(),
        remaining: partial.remaining,
        before: partial.before,
        address_suffix: None,
    });
    PushPayload {
        kind: PushKind::DeviceStatus,
        title: "Device Status".to_string(),
        body: text.en,
        tag: String::new(),
        extras: Vec::new(),
    }
}

async fn send_telegram_device_aggregate(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguageMap,
    agg: DeviceAggregate,
    subs: Vec<TelegramSubscriptionRow>,
) {
    let fmt_addr = short_address(agg.address.as_str());
    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let pool = pool.clone();
        let chat_languages = chat_languages.clone();
        let agg = agg.clone();
        let fmt_addr = fmt_addr.clone();
        async move {
            let lang = chat_language(&chat_languages, sub.telegram_chat_id).await;
            let chat_count = count_chat_subscriptions(&pool, sub.telegram_chat_id).await;
            let time_str = format_device_time(DEVICE_TIMEZONE, agg.timestamp, lang);
            let suffix = (chat_count > 1).then(|| match lang {
                Language::De => format!(" – Adresse {fmt_addr}"),
                Language::En => format!(" – address {fmt_addr}"),
            });
            let text = DeviceAggregateText::build(&DeviceAggregateArgs {
                language: lang,
                time_formatted: &time_str,
                went_offline: &agg.went_offline,
                came_back: &agg.came_back,
                first_seen: &agg.first_seen,
                reduced: &agg.reduced,
                address_suffix: suffix.as_deref(),
            });
            log_adapter_send(
                "telegram-device-agg",
                adapter
                    .send_text(sub.telegram_chat_id, text.pick(lang))
                    .await,
            );
        }
    });
    join_all(tasks).await;
}

/// Push payload for an aggregate. Carries the same key set as the single
/// device-status payload, because FCM turns `tag` into `data.status` and
/// merges `extras` verbatim: clients must not see a missing key just because
/// several workers moved at once. `mixed` only when the batch moved both ways.
fn device_aggregate_fcm_payload(agg: &DeviceAggregate) -> PushPayload {
    let time_str = agg.timestamp.format("%m/%d/%y, %-I:%M %p").to_string();
    let text = DeviceAggregateText::build(&DeviceAggregateArgs {
        language: Language::En,
        time_formatted: &time_str,
        went_offline: &agg.went_offline,
        came_back: &agg.came_back,
        first_seen: &agg.first_seen,
        reduced: &agg.reduced,
        address_suffix: None,
    });
    let online = agg.came_back.len() + agg.first_seen.len();
    let status = match (agg.went_offline.is_empty(), online == 0) {
        (false, true) => "offline",
        (true, false) => "online",
        _ => "mixed",
    };
    let workers: Vec<&str> = agg
        .went_offline
        .iter()
        .chain(agg.came_back.iter())
        .chain(agg.first_seen.iter())
        .map(String::as_str)
        .collect();
    PushPayload {
        kind: PushKind::DeviceStatus,
        title: "Device Status".to_string(),
        body: text.en,
        tag: status.to_string(),
        extras: vec![
            (
                "isReturning".into(),
                (!agg.came_back.is_empty()).to_string(),
            ),
            ("workerName".into(), workers.join(", ")),
            ("userAgent".into(), "Multiple".to_string()),
            ("wentOffline".into(), agg.went_offline.len().to_string()),
            ("cameOnline".into(), online.to_string()),
            (
                "timestamp".into(),
                agg.timestamp.timestamp_millis().to_string(),
            ),
        ],
    }
}

/// UnifiedPush counterpart; leaves the trailing `tag` field empty like the
/// single-event path, the `title|body|` shape existing clients parse.
fn device_aggregate_unified_payload(agg: &DeviceAggregate) -> PushPayload {
    let time_str = agg.timestamp.format("%m/%d/%y, %-I:%M %p").to_string();
    let text = DeviceAggregateText::build(&DeviceAggregateArgs {
        language: Language::En,
        time_formatted: &time_str,
        went_offline: &agg.went_offline,
        came_back: &agg.came_back,
        first_seen: &agg.first_seen,
        reduced: &agg.reduced,
        address_suffix: None,
    });
    PushPayload {
        kind: PushKind::DeviceStatus,
        title: "Device Status".to_string(),
        body: text.en,
        tag: String::new(),
        extras: Vec::new(),
    }
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

fn device_status_fcm_payload(event: &DeviceStatusEvent) -> PushPayload {
    // FCM device-status payload uses UTC + plain locale ("en-US");
    // `DEVICE_TIMEZONE` is for the telegram + ntfy paths.
    let worker = event
        .worker_name
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());
    let agent = event
        .user_agent
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());
    let (title, body) = device_status_title_body(event);

    PushPayload {
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
    }
}

/// Shared device-status title + body for the push transports (FCM +
/// UnifiedPush). Uses a UTC en-US short timestamp; the title encodes
/// online / back-online / offline. Both transports parse the same
/// `title|body|` shape, so this keeps them in lock-step.
fn device_status_title_body(event: &DeviceStatusEvent) -> (&'static str, String) {
    let worker = event.worker_name.as_deref().unwrap_or("Unknown");
    let agent = event.user_agent.as_deref().unwrap_or("Unknown");
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
    (title, format!("{agent} ({worker}) at {time_str}"))
}

fn device_status_unified_payload(event: &DeviceStatusEvent) -> PushPayload {
    let (title, body) = device_status_title_body(event);
    // Empty trailing tag → the wire body is `title|body|`, the shape
    // UnifiedPush device-status clients already parse.
    PushPayload {
        kind: PushKind::DeviceStatus,
        title: title.to_string(),
        body,
        tag: String::new(),
        extras: Vec::new(),
    }
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
            let kind = sub.subscription_type.as_str();
            if kind.eq_ignore_ascii_case(PUSH_TYPE_UNIFIED) {
                if let Some(adapter) = handles.web_push {
                    push_web(&adapter, &pool, &address, &sub, &payload, "unified push").await;
                }
            } else if kind.eq_ignore_ascii_case(PUSH_TYPE_FCM) {
                if let Some(adapter) = handles.fcm {
                    push_fcm(&adapter, &pool, &address, &sub, &payload, "fcm push").await;
                }
            } else {
                debug!(target: "bp_notifications::dispatcher", kind, "unknown push subscription_type — ignored");
            }
        }
    });
    join_all(tasks).await;
}

/// One FCM delivery: an invalid token soft-deletes the subscription, a sent
/// push stamps its last notification, any other error is logged as `what`.
pub(crate) async fn push_fcm(
    adapter: &FcmAdapter,
    pool: &PgPool,
    address: &AddressId,
    sub: &PushSubscriptionRow,
    payload: &PushPayload,
    what: &'static str,
) {
    match adapter.send(&sub.endpoint, address.as_str(), payload).await {
        Ok(outcome) if outcome.invalid_token => {
            soft_delete_push(pool, address, &sub.endpoint).await
        }
        Ok(_) => bump_last_notification(pool, sub.id).await,
        Err(e) => warn!(target: "bp_notifications::dispatcher", error = %e, "{what}"),
    }
}

/// [`push_fcm`] for a UnifiedPush endpoint.
pub(crate) async fn push_web(
    adapter: &WebPushAdapter,
    pool: &PgPool,
    address: &AddressId,
    sub: &PushSubscriptionRow,
    payload: &PushPayload,
    what: &'static str,
) {
    match adapter.send(&sub.endpoint, payload).await {
        Ok(outcome) if outcome.invalid_endpoint => {
            soft_delete_push(pool, address, &sub.endpoint).await
        }
        Ok(_) => bump_last_notification(pool, sub.id).await,
        Err(e) => warn!(target: "bp_notifications::dispatcher", error = %e, "{what}"),
    }
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
    fn extract_difficulty_picks_bracketed_token() {
        assert_eq!(extract_difficulty_tag("valid (158T)"), "158T");
        assert_eq!(extract_difficulty_tag("rejected (12.5G)"), "12.5G");
    }

    #[test]
    fn extract_difficulty_returns_unknown_if_no_bracketed_match() {
        assert_eq!(extract_difficulty_tag("no parens here"), "Unknown");
        assert_eq!(extract_difficulty_tag("(not a difficulty)"), "Unknown");
    }

    /// Push routing matches the stored lowercase `subscriptionType` in any casing.
    #[test]
    fn push_type_constants_lowercase_and_match_case_insensitively() {
        assert_eq!(PUSH_TYPE_UNIFIED, "unified_push");
        assert_eq!(PUSH_TYPE_FCM, "fcm");
        for v in ["unified_push", "UNIFIED_PUSH", "Unified_Push"] {
            assert!(
                v.eq_ignore_ascii_case(PUSH_TYPE_UNIFIED),
                "{v} should match unified"
            );
        }
        for v in ["fcm", "FCM", "Fcm"] {
            assert!(
                v.eq_ignore_ascii_case(PUSH_TYPE_FCM),
                "{v} should match fcm"
            );
        }
        assert!(!"ntfy".eq_ignore_ascii_case(PUSH_TYPE_UNIFIED));
    }

    fn device_event(is_online: bool, is_returning: bool) -> DeviceStatusEvent {
        DeviceStatusEvent {
            address: AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
                .expect("valid addr"),
            worker_name: Some("rig1".to_string()),
            user_agent: Some("bitaxe".to_string()),
            is_online,
            is_returning,
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("timestamp"),
        }
    }

    fn aggregate(offline: &[&str], back: &[&str]) -> DeviceAggregate {
        aggregate_full(offline, back, &[])
    }

    fn aggregate_full(offline: &[&str], back: &[&str], fresh: &[&str]) -> DeviceAggregate {
        DeviceAggregate {
            address: AddressId::new("bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l".to_string())
                .expect("valid address"),
            went_offline: offline.iter().map(|s| (*s).to_string()).collect(),
            came_back: back.iter().map(|s| (*s).to_string()).collect(),
            first_seen: fresh.iter().map(|s| (*s).to_string()).collect(),
            reduced: Vec::new(),
            timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("timestamp"),
        }
    }

    /// The FCM aggregate payload carries every data key the single form sends.
    #[test]
    fn aggregate_fcm_payload_keeps_the_single_events_data_keys() {
        let single = device_status_fcm_payload(&device_event(false, false));
        let agg = device_aggregate_fcm_payload(&aggregate(&["a", "b"], &[]));
        for (key, _) in &single.extras {
            assert!(
                agg.extras.iter().any(|(k, _)| k == key),
                "aggregate payload dropped `{key}`, which shipped clients read"
            );
        }
        assert_eq!(agg.tag, "offline", "one-way batch keeps a known status");
        assert_eq!(
            device_aggregate_fcm_payload(&aggregate(&["a"], &["b"])).tag,
            "mixed",
            "a two-way batch is explicitly neither"
        );
        assert_eq!(
            device_aggregate_fcm_payload(&aggregate(&[], &["b"])).tag,
            "online"
        );
        // A batch of nothing but first sightings is still "online" —
        // the tag describes direction, not novelty.
        assert_eq!(
            device_aggregate_fcm_payload(&aggregate_full(&[], &[], &["fresh"])).tag,
            "online"
        );
    }

    /// A brand-new miner is not reported as back online.
    #[test]
    fn aggregate_separates_first_sightings_from_returns() {
        let p = device_aggregate_fcm_payload(&aggregate_full(&[], &["back"], &["fresh"]));
        assert!(p.body.contains("1 worker back online (back)"), "{}", p.body);
        assert!(p.body.contains("1 new worker (fresh)"), "{}", p.body);
        let none_returned = device_aggregate_fcm_payload(&aggregate_full(&[], &[], &["a", "b"]));
        assert!(
            !none_returned.body.contains("back online"),
            "{}",
            none_returned.body
        );
        assert_eq!(
            none_returned
                .extras
                .iter()
                .find(|(k, _)| k == "isReturning")
                .map(|(_, v)| v.as_str()),
            Some("false")
        );
    }

    /// Pins both device-status payloads, the shapes shipped clients parse.
    #[test]
    fn device_status_payloads_keep_their_wire_shape() {
        let fcm = device_status_fcm_payload(&device_event(true, true));
        assert_eq!(fcm.title, "Device Back Online");
        assert_eq!(fcm.body, "bitaxe (rig1) at 11/14/23, 10:13 PM");
        assert_eq!(fcm.tag, "online");
        assert_eq!(
            fcm.extras,
            vec![
                ("isReturning".to_string(), "true".to_string()),
                ("workerName".to_string(), "rig1".to_string()),
                ("userAgent".to_string(), "bitaxe".to_string()),
                ("timestamp".to_string(), "1700000000000".to_string()),
            ]
        );
        assert_eq!(
            device_status_fcm_payload(&device_event(false, false)).tag,
            "offline"
        );

        let unified = device_status_unified_payload(&device_event(false, false));
        assert_eq!(unified.title, "Device Offline");
        assert_eq!(unified.body, "bitaxe (rig1) at 11/14/23, 10:13 PM");
        assert!(unified.tag.is_empty());
        assert!(unified.extras.is_empty());
    }

    /// The UnifiedPush aggregate keeps the empty trailing `tag` field.
    #[test]
    fn aggregate_unified_payload_keeps_the_empty_trailing_field() {
        let p = device_aggregate_unified_payload(&aggregate(&["a", "b"], &[]));
        assert!(p.tag.is_empty());
        assert!(p.extras.is_empty());
        assert!(p.body.contains("2 workers offline"), "body was: {}", p.body);
    }

    #[test]
    fn device_status_title_body_picks_title_and_formats_body() {
        assert_eq!(
            device_status_title_body(&device_event(true, false)).0,
            "Device Online"
        );
        assert_eq!(
            device_status_title_body(&device_event(true, true)).0,
            "Device Back Online"
        );
        assert_eq!(
            device_status_title_body(&device_event(false, false)).0,
            "Device Offline"
        );
        let (_, body) = device_status_title_body(&device_event(true, false));
        assert!(body.starts_with("bitaxe (rig1) at "), "body was: {body}");
    }

    #[test]
    fn device_status_unknown_worker_and_agent_default() {
        let mut ev = device_event(true, false);
        ev.worker_name = None;
        ev.user_agent = None;
        let (_, body) = device_status_title_body(&ev);
        assert!(
            body.starts_with("Unknown (Unknown) at "),
            "body was: {body}"
        );
    }
}
