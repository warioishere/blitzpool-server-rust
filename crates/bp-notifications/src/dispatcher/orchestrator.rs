// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;

use bp_common::{short_address, AddressId, MiningMode};
use bp_db::{
    delete_push_subscription_by_endpoint, delete_telegram_subscriptions_by_chat,
    find_address_email, find_ntfy_subscription_by_address, find_push_subscriptions_by_address,
    find_telegram_subscriptions_by_address, find_telegram_subscriptions_by_chat,
    update_push_subscription_last_notification, DbError, NtfySubscriptionRow, PushSubscriptionRow,
    TelegramSubscriptionRow,
};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use sqlx::PgPool;
use tracing::{debug, info, warn};

use crate::command::ChatLanguages;

use crate::adapter::{
    AdapterError, AdapterResult, FcmAdapter, NtfyAdapter, PushKind, PushPayload, SmtpAdapter,
    TelegramAdapter, WebPushAdapter,
};
use crate::format::html;
use crate::format::{
    format_device_time, format_number_suffix, format_sats, DeviceAggregateArgs,
    DeviceAggregateText, DevicePartialArgs, DevicePartialText, DeviceStatusArgs, DeviceStatusText,
    Language,
};
use crate::template::{render_join_request_admin, JoinRequestAdminContext};

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

/// Someone asked to join a Team; the notice goes to the Team's admin.
#[derive(Debug, Clone)]
pub struct JoinRequestNotice {
    pub admin_address: AddressId,
    pub requester_address: AddressId,
    pub group_name: String,
}

/// A found block, for the notices it sends.
#[derive(Debug, Clone)]
pub struct BlockFoundNotice {
    pub height: u64,
    pub mode: MiningMode,
    /// The address that mined the block.
    pub finder: AddressId,
    /// What the block's own coinbase pays each address; empty when the
    /// coinbase was not decoded.
    pub paid: Vec<(AddressId, u64)>,
}

/// One address a block notice goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockRecipient {
    address: AddressId,
    is_finder: bool,
    paid_sats: Option<u64>,
}

impl BlockFoundNotice {
    /// The finder first, then every other paid address once.
    fn recipients(&self) -> Vec<BlockRecipient> {
        let paid_to = |address: &AddressId| {
            self.paid
                .iter()
                .filter(|(a, _)| a == address)
                .map(|(_, sats)| *sats)
                .reduce(u64::saturating_add)
        };
        let mut out = vec![BlockRecipient {
            address: self.finder.clone(),
            is_finder: true,
            paid_sats: paid_to(&self.finder),
        }];
        for (address, _) in &self.paid {
            if out.iter().all(|r| &r.address != address) {
                out.push(BlockRecipient {
                    address: address.clone(),
                    is_finder: false,
                    paid_sats: paid_to(address),
                });
            }
        }
        out
    }
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
    chat_languages: ChatLanguages,
    /// Mails a Team admin who follows the Team on no push channel.
    smtp: Option<Arc<SmtpAdapter>>,
    /// Base of the links in a join-request notice; without it the notice
    /// carries no link and no mail goes out.
    pool_base_url: Option<String>,
}

impl NotificationDispatcher {
    pub fn new(
        pool: PgPool,
        telegram: Option<Arc<TelegramAdapter>>,
        ntfy: Option<Arc<NtfyAdapter>>,
        fcm: Option<Arc<FcmAdapter>>,
        web_push: Option<Arc<WebPushAdapter>>,
        chat_languages: ChatLanguages,
    ) -> Self {
        Self {
            pool,
            telegram,
            ntfy,
            fcm,
            web_push,
            chat_languages,
            smtp: None,
            pool_base_url: None,
        }
    }

    /// Lets a join-request notice reach an admin by mail and link the
    /// Team's admin panel.
    pub fn with_join_request_mail(
        mut self,
        smtp: Option<Arc<SmtpAdapter>>,
        pool_base_url: Option<String>,
    ) -> Self {
        self.smtp = smtp;
        self.pool_base_url = pool_base_url;
        self
    }

    // ── Public engine entry points ──────────────────────────────────

    /// A block was found. The finder and every address its coinbase pays
    /// hear about it on each channel they follow, the paid ones with their
    /// amount. Recipients go one after another, which keeps a large PPLNS
    /// payout list under Telegram's send rate.
    pub async fn notify_block_found(&self, notice: &BlockFoundNotice) {
        for recipient in notice.recipients() {
            self.notify_block_recipient(notice, &recipient).await;
        }
    }

    async fn notify_block_recipient(&self, notice: &BlockFoundNotice, recipient: &BlockRecipient) {
        let (telegram_subs, ntfy_sub, push_subs) = self.load_subs(&recipient.address).await;

        let mut tasks = Vec::new();
        let telegram_subs: Vec<_> = telegram_subs
            .into_iter()
            .filter(|s| s.block_notifications_enabled)
            .collect();
        if let (false, Some(adapter)) = (telegram_subs.is_empty(), &self.telegram) {
            tasks.push(Box::pin(send_telegram_block_found(
                Arc::clone(adapter),
                self.pool.clone(),
                self.chat_languages.clone(),
                telegram_subs,
                notice.clone(),
                recipient.clone(),
            )) as TaskFuture);
        }
        if let (Some(sub), Some(adapter)) = (ntfy_sub, &self.ntfy) {
            let body = block_found_text(Language::parse(&sub.language), notice, recipient);
            let adapter = Arc::clone(adapter);
            tasks.push(Box::pin(async move {
                log_adapter_send(
                    "ntfy-block",
                    adapter.publish(sub.address.as_str(), &body).await,
                );
            }) as TaskFuture);
        }
        let push_block: Vec<_> = push_subs
            .into_iter()
            .filter(|s| s.block_notifications_enabled)
            .collect();
        if !push_block.is_empty() {
            tasks.push(Box::pin(fan_push(
                self.clone_push_handles(),
                self.pool.clone(),
                recipient.address.clone(),
                push_block,
                block_found_push_payload(notice, recipient),
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

    /// Someone asked to join a Team. Every channel the admin follows the
    /// Team on, with its join-request switch on, gets a short notice; an
    /// admin on no channel at all gets a mail to their verified address.
    pub async fn notify_join_request(&self, notice: &JoinRequestNotice) {
        let (telegram_subs, ntfy_sub, push_subs) = self.load_subs(&notice.admin_address).await;
        let route = route_join_request(telegram_subs, ntfy_sub, push_subs, self.transports());
        let admin_url = self.pool_base_url.as_deref().map(|base| {
            format!(
                "{}/#/app/{}/payout-group/admin",
                base.trim_end_matches('/'),
                notice.admin_address.as_str()
            )
        });

        let mut tasks = Vec::new();
        if let (false, Some(adapter)) = (route.telegram.is_empty(), &self.telegram) {
            tasks.push(Box::pin(send_telegram_join_request(
                Arc::clone(adapter),
                self.pool.clone(),
                self.chat_languages.clone(),
                route.telegram,
                notice.group_name.clone(),
                admin_url.clone(),
            )) as TaskFuture);
        }
        if let (Some(sub), Some(adapter)) = (route.ntfy, &self.ntfy) {
            tasks.push(Box::pin(send_ntfy_join_request(
                Arc::clone(adapter),
                sub,
                notice.group_name.clone(),
                admin_url.clone(),
            )) as TaskFuture);
        }
        if !route.push.is_empty() {
            tasks.push(Box::pin(fan_push(
                self.clone_push_handles(),
                self.pool.clone(),
                notice.admin_address.clone(),
                route.push,
                join_request_push_payload(&notice.group_name),
            )) as TaskFuture);
        }
        if route.mail {
            if let (Some(smtp), Some(admin_url)) = (&self.smtp, admin_url) {
                tasks.push(Box::pin(send_mail_join_request(
                    Arc::clone(smtp),
                    self.pool.clone(),
                    notice.clone(),
                    admin_url,
                )) as TaskFuture);
            }
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
            ChatLanguages,
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

    fn transports(&self) -> Transports {
        Transports {
            telegram: self.telegram.is_some(),
            ntfy: self.ntfy.is_some(),
            fcm: self.fcm.is_some(),
            web_push: self.web_push.is_some(),
        }
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

/// Which transports this dispatcher can send on.
#[derive(Debug, Clone, Copy)]
struct Transports {
    telegram: bool,
    ntfy: bool,
    fcm: bool,
    web_push: bool,
}

/// Where a join-request notice goes.
#[derive(Debug)]
struct JoinRequestRoute {
    telegram: Vec<TelegramSubscriptionRow>,
    ntfy: Option<NtfySubscriptionRow>,
    push: Vec<PushSubscriptionRow>,
    mail: bool,
}

/// An admin who follows the Team on a channel this dispatcher can send on
/// gets the notice there, where that subscription's switch is on; a switch
/// turned off is a choice, not a reason to mail instead. Only an admin on no
/// such channel at all gets the mail.
fn route_join_request(
    telegram: Vec<TelegramSubscriptionRow>,
    ntfy: Option<NtfySubscriptionRow>,
    push: Vec<PushSubscriptionRow>,
    transports: Transports,
) -> JoinRequestRoute {
    let telegram: Vec<_> = if transports.telegram {
        telegram
    } else {
        Vec::new()
    };
    let ntfy = ntfy.filter(|_| transports.ntfy);
    let push: Vec<_> = push
        .into_iter()
        .filter(|sub| {
            let kind = sub.subscription_type.as_str();
            (kind.eq_ignore_ascii_case(PUSH_TYPE_FCM) && transports.fcm)
                || (kind.eq_ignore_ascii_case(PUSH_TYPE_UNIFIED) && transports.web_push)
        })
        .collect();
    let mail = telegram.is_empty() && ntfy.is_none() && push.is_empty();
    JoinRequestRoute {
        telegram: telegram
            .into_iter()
            .filter(|s| s.group_admin_notifications_enabled)
            .collect(),
        ntfy: ntfy.filter(|s| s.group_admin_notifications_enabled),
        push: push
            .into_iter()
            .filter(|s| s.group_admin_notifications_enabled)
            .collect(),
        mail,
    }
}

// ── Send functions per (transport, event-kind) ──────────────────────
// Errors are logged and absorbed so one failed subscriber does not take
// down the whole `join_all` fan-out.

async fn send_telegram_block_found(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
    subs: Vec<TelegramSubscriptionRow>,
    notice: BlockFoundNotice,
    recipient: BlockRecipient,
) {
    let (adapter, pool, chat_languages, notice, recipient) =
        (&adapter, &pool, &chat_languages, &notice, &recipient);
    let tasks = subs.into_iter().map(|sub| async move {
        let lang = chat_languages.get(sub.telegram_chat_id).await;
        let text = block_found_text(lang, notice, recipient);
        settle_telegram_push(
            pool,
            sub.telegram_chat_id,
            "telegram-block",
            adapter.send_html(sub.telegram_chat_id, &text).await,
        )
        .await;
    });
    join_all(tasks).await;
}

/// The block notice for one recipient: who found it, and what the coinbase
/// pays this address.
fn block_found_text(
    lang: Language,
    notice: &BlockFoundNotice,
    recipient: &BlockRecipient,
) -> String {
    let height = notice.height;
    let short = html::addr(&short_address(recipient.address.as_str()));
    let mode = match notice.mode {
        MiningMode::Solo => "Solo",
        MiningMode::Pplns => "PPLNS",
        MiningMode::GroupSolo => "Team",
        MiningMode::Blockparty => "Blockparty",
    };
    let head = match (lang, recipient.is_finder) {
        (Language::De, true) => format!(
            "{} · von deinem Miner ({mode})",
            html::title(Some("\u{1f389}"), &format!("Block {height} gefunden"))
        ),
        (Language::De, false) => html::title(
            Some("\u{1f389}"),
            &format!("{mode}-Block {height} gefunden"),
        ),
        (Language::En, true) => format!(
            "{} · by your miner ({mode})",
            html::title(Some("\u{1f389}"), &format!("Block {height} found"))
        ),
        (Language::En, false) => {
            html::title(Some("\u{1f389}"), &format!("{mode} block {height} found"))
        }
    };
    let detail = match (lang, recipient.paid_sats) {
        (Language::De, Some(sats)) => format!(
            "Die Coinbase zahlt {} an {short}, sofern der Block in der Chain bleibt. \
             Ausgeben lässt es sich nach 100 Bestätigungen.",
            html::bold(&format!("{} sats", format_sats(sats as i64)))
        ),
        (Language::De, None) => format!("Adresse: {short}"),
        (Language::En, Some(sats)) => format!(
            "The coinbase pays {} to {short} if the block stays in the chain. \
             It is spendable after 100 confirmations.",
            html::bold(&format!("{} sats", format_sats(sats as i64)))
        ),
        (Language::En, None) => format!("Address: {short}"),
    };
    format!("{head}\n\n{detail}")
}

async fn send_telegram_best_diff(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
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
            let lang = chat_languages.get(sub.telegram_chat_id).await;
            let chat_count = count_chat_subscriptions(&pool, sub.telegram_chat_id).await;
            let include_address = chat_count > 1;
            let fmt_addr = short_address(address.as_str());
            let title = match lang {
                Language::De => html::title(Some("\u{1f3c6}"), "Neue beste Difficulty"),
                Language::En => html::title(Some("\u{1f3c6}"), "New best difficulty"),
            };
            let title = if include_address {
                format!("{title} · {}", html::addr(&fmt_addr))
            } else {
                title
            };
            let value = match lang {
                Language::De => html::row("Wert", &formatted),
                Language::En => html::row("Value", &formatted),
            };
            let text = format!("{title}\n{value}");
            settle_telegram_push(
                &pool,
                sub.telegram_chat_id,
                "telegram-best-diff",
                adapter.send_html(sub.telegram_chat_id, &text).await,
            )
            .await;
        }
    });
    join_all(tasks).await;
}

async fn send_telegram_device_status(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
    event: DeviceStatusEvent,
    subs: Vec<TelegramSubscriptionRow>,
) {
    let (address, timestamp) = (event.address.clone(), event.timestamp);
    send_telegram_device(
        adapter,
        pool,
        chat_languages,
        &address,
        timestamp,
        subs,
        "telegram-device",
        |lang, time_formatted, address_suffix| {
            DeviceStatusText::build(&DeviceStatusArgs {
                language: lang,
                time_formatted,
                user_agent: event.user_agent.as_deref(),
                worker_name: event.worker_name.as_deref(),
                is_online: event.is_online,
                is_returning: event.is_returning,
                address_suffix,
            })
            .pick(lang)
            .to_string()
        },
    )
    .await;
}

/// One Telegram device notice per chat, in the chat's language and the pool's
/// timezone. The address is named only when the chat follows more than one.
#[allow(clippy::too_many_arguments)]
async fn send_telegram_device(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
    address: &AddressId,
    timestamp: DateTime<Utc>,
    subs: Vec<TelegramSubscriptionRow>,
    label: &'static str,
    render: impl Fn(Language, &str, Option<&str>) -> String,
) {
    let fmt_addr = short_address(address.as_str());
    let (adapter, pool, chat_languages, fmt_addr, render) =
        (&adapter, &pool, &chat_languages, &fmt_addr, &render);
    let tasks = subs.into_iter().map(|sub| async move {
        let lang = chat_languages.get(sub.telegram_chat_id).await;
        let chat_count = count_chat_subscriptions(pool, sub.telegram_chat_id).await;
        let time_str = format_device_time(DEVICE_TIMEZONE, timestamp, lang);
        let suffix = (chat_count > 1).then(|| match lang {
            Language::De => format!(" – Adresse {}", html::addr(fmt_addr)),
            Language::En => format!(" – address {}", html::addr(fmt_addr)),
        });
        let text = render(lang, &time_str, suffix.as_deref());
        settle_telegram_push(
            pool,
            sub.telegram_chat_id,
            label,
            adapter.send_html(sub.telegram_chat_id, &text).await,
        )
        .await;
    });
    join_all(tasks).await;
}

async fn send_telegram_device_partial(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
    partial: DevicePartial,
    subs: Vec<TelegramSubscriptionRow>,
) {
    send_telegram_device(
        adapter,
        pool,
        chat_languages,
        &partial.address,
        partial.timestamp,
        subs,
        "telegram-device-partial",
        |lang, time_formatted, address_suffix| {
            DevicePartialText::build(&DevicePartialArgs {
                language: lang,
                time_formatted,
                worker_name: partial.worker_name.as_deref(),
                remaining: partial.remaining,
                before: partial.before,
                address_suffix,
            })
            .pick(lang)
            .to_string()
        },
    )
    .await;
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
        body: html::to_plain(&text.en),
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
        body: html::to_plain(&text.en),
        tag: String::new(),
        extras: Vec::new(),
    }
}

async fn send_telegram_device_aggregate(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
    agg: DeviceAggregate,
    subs: Vec<TelegramSubscriptionRow>,
) {
    send_telegram_device(
        adapter,
        pool,
        chat_languages,
        &agg.address,
        agg.timestamp,
        subs,
        "telegram-device-agg",
        |lang, time_formatted, address_suffix| {
            DeviceAggregateText::build(&DeviceAggregateArgs {
                language: lang,
                time_formatted,
                went_offline: &agg.went_offline,
                came_back: &agg.came_back,
                first_seen: &agg.first_seen,
                reduced: &agg.reduced,
                address_suffix,
            })
            .pick(lang)
            .to_string()
        },
    )
    .await;
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
        body: html::to_plain(&text.en),
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
        body: html::to_plain(&text.en),
        tag: String::new(),
        extras: Vec::new(),
    }
}

async fn send_ntfy_best_diff(
    adapter: Arc<NtfyAdapter>,
    address: String,
    lang: Language,
    formatted: String,
) {
    let body = match lang {
        Language::De => format!(
            "{}\n{}",
            html::title(Some("\u{1f3c6}"), "Neue beste Difficulty"),
            html::row("Wert", &formatted)
        ),
        Language::En => format!(
            "{}\n{}",
            html::title(Some("\u{1f3c6}"), "New best difficulty"),
            html::row("Value", &formatted)
        ),
    };
    log_adapter_send("ntfy-best-diff", adapter.publish(&address, &body).await);
}

/// Push payload for a block notice. Title, body and `tag` (FCM's
/// `data.difficulty`) keep the shape shipped clients read; the amount rides
/// in `paidSats`.
fn block_found_push_payload(notice: &BlockFoundNotice, recipient: &BlockRecipient) -> PushPayload {
    let mut extras = vec![("height".into(), notice.height.to_string())];
    if let Some(sats) = recipient.paid_sats {
        extras.push(("paidSats".into(), sats.to_string()));
    }
    PushPayload {
        kind: PushKind::BlockFound,
        title: "New Block Found!".to_string(),
        body: format!("Block height {}", notice.height),
        tag: "Unknown".to_string(),
        extras,
    }
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

/// Names the Team, not the requester; the admin panel shows who asked.
fn join_request_push_payload(group_name: &str) -> PushPayload {
    PushPayload {
        kind: PushKind::GroupJoinRequest,
        title: "New join request".to_string(),
        body: format!("New join request in {group_name}"),
        tag: String::new(),
        extras: Vec::new(),
    }
}

/// The admin link shows as text, so the admin address in it does not stand
/// in the chat.
fn join_request_text(lang: Language, group_name: &str, admin_url: Option<&str>) -> String {
    let head = match lang {
        Language::De => format!(
            "{}\nTeam: {}",
            html::title(Some("\u{1f44b}"), "Neue Beitrittsanfrage"),
            html::bold(group_name)
        ),
        Language::En => format!(
            "{}\nTeam: {}",
            html::title(Some("\u{1f44b}"), "New join request"),
            html::bold(group_name)
        ),
    };
    match (lang, admin_url) {
        (_, None) => head,
        (Language::De, Some(url)) => format!("{head}\n{}", html::link(url, "Admin-Panel öffnen")),
        (Language::En, Some(url)) => format!("{head}\n{}", html::link(url, "Open the admin panel")),
    }
}

async fn send_telegram_join_request(
    adapter: Arc<TelegramAdapter>,
    pool: PgPool,
    chat_languages: ChatLanguages,
    subs: Vec<TelegramSubscriptionRow>,
    group_name: String,
    admin_url: Option<String>,
) {
    let tasks = subs.into_iter().map(|sub| {
        let adapter = Arc::clone(&adapter);
        let chat_languages = chat_languages.clone();
        let group_name = group_name.clone();
        let admin_url = admin_url.clone();
        let pool = pool.clone();
        async move {
            let lang = chat_languages.get(sub.telegram_chat_id).await;
            let text = join_request_text(lang, &group_name, admin_url.as_deref());
            settle_telegram_push(
                &pool,
                sub.telegram_chat_id,
                "telegram-join-request",
                adapter.send_html(sub.telegram_chat_id, &text).await,
            )
            .await;
        }
    });
    join_all(tasks).await;
}

async fn send_ntfy_join_request(
    adapter: Arc<NtfyAdapter>,
    sub: NtfySubscriptionRow,
    group_name: String,
    admin_url: Option<String>,
) {
    let body = join_request_text(
        Language::parse(&sub.language),
        &group_name,
        admin_url.as_deref(),
    );
    log_adapter_send(
        "ntfy-join-request",
        adapter.publish(sub.address.as_str(), &body).await,
    );
}

async fn send_mail_join_request(
    smtp: Arc<SmtpAdapter>,
    pool: PgPool,
    notice: JoinRequestNotice,
    admin_url: String,
) {
    let email = match find_address_email(&pool, &notice.admin_address).await {
        Ok(Some(row)) if row.verified_at.is_some() => row.email,
        Ok(_) => {
            debug!(target: "bp_notifications::dispatcher", "join request: admin has no verified email");
            return;
        }
        Err(e) => {
            warn!(target: "bp_notifications::dispatcher", error = %e, "join request: email lookup");
            return;
        }
    };
    let content = render_join_request_admin(&JoinRequestAdminContext {
        requester_address: notice.requester_address.as_str().to_string(),
        group_name: notice.group_name,
        admin_url,
    });
    log_adapter_send("mail-join-request", smtp.send_email(&email, &content).await);
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

async fn count_chat_subscriptions(pool: &PgPool, chat_id: i64) -> usize {
    match find_telegram_subscriptions_by_chat(pool, chat_id).await {
        Ok(rows) => rows.len(),
        Err(e) => {
            warn!(target: "bp_notifications::dispatcher", error = %e, chat_id, "chat-subs lookup");
            0
        }
    }
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

/// Log a failed Telegram push. A chat Telegram reports as gone loses its
/// subscriptions, so nothing is sent to it again.
pub(crate) async fn settle_telegram_push(
    pool: &PgPool,
    chat_id: i64,
    kind: &'static str,
    result: AdapterResult<()>,
) {
    match result {
        Ok(()) => {}
        Err(AdapterError::InvalidRecipient(reason)) => {
            match delete_telegram_subscriptions_by_chat(pool, chat_id).await {
                Ok(removed) => info!(
                    target: "bp_notifications::dispatcher",
                    chat_id, removed, %reason, "telegram chat gone, subscriptions removed"
                ),
                Err(e) => warn!(
                    target: "bp_notifications::dispatcher",
                    error = %e, chat_id, "telegram chat gone, removing subscriptions failed"
                ),
            }
        }
        Err(e) => {
            warn!(target: "bp_notifications::dispatcher", adapter = kind, chat_id, error = %e, "send failed")
        }
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

    fn addr(s: &str) -> AddressId {
        AddressId::new(s).unwrap()
    }

    /// The finder comes first even when its coinbase pays it nothing, and a
    /// script paid twice is one recipient with the sum.
    #[test]
    fn block_recipients_are_the_finder_and_every_paid_address() {
        let notice = BlockFoundNotice {
            height: 900_000,
            mode: MiningMode::Pplns,
            finder: addr("bc1qfinder"),
            paid: vec![
                (addr("bc1qalice"), 1_000),
                (addr("bc1qbob"), 2_000),
                (addr("bc1qalice"), 500),
            ],
        };
        assert_eq!(
            notice.recipients(),
            vec![
                BlockRecipient {
                    address: addr("bc1qfinder"),
                    is_finder: true,
                    paid_sats: None,
                },
                BlockRecipient {
                    address: addr("bc1qalice"),
                    is_finder: false,
                    paid_sats: Some(1_500),
                },
                BlockRecipient {
                    address: addr("bc1qbob"),
                    is_finder: false,
                    paid_sats: Some(2_000),
                },
            ]
        );
        let solo = BlockFoundNotice {
            mode: MiningMode::Solo,
            paid: vec![(addr("bc1qfinder"), 312_500_000)],
            ..notice
        };
        assert_eq!(
            solo.recipients(),
            vec![BlockRecipient {
                address: addr("bc1qfinder"),
                is_finder: true,
                paid_sats: Some(312_500_000),
            }]
        );
    }

    #[test]
    fn a_block_notice_names_the_finder_and_the_amount_in_one_language() {
        let notice = BlockFoundNotice {
            height: 973_944,
            mode: MiningMode::GroupSolo,
            finder: addr("bc1qfinderaddressxxxxxxxx"),
            paid: vec![(addr("bc1qmemberaddressxxxxxxxx"), 1_234_567)],
        };
        let [finder, member] = <[BlockRecipient; 2]>::try_from(notice.recipients()).unwrap();
        for text in [
            block_found_text(Language::De, &notice, &member),
            block_found_text(Language::En, &notice, &finder),
        ] {
            assert!(html::is_valid_telegram_html(&text), "{text}");
        }
        let de = html::to_plain(&block_found_text(Language::De, &notice, &member));
        assert!(de.contains("Team-Block 973944 gefunden"), "{de}");
        assert!(de.contains("1,234,567 sats"), "{de}");
        assert!(!de.contains("found"), "no English in the German text: {de}");
        let en = html::to_plain(&block_found_text(Language::En, &notice, &finder));
        assert!(en.contains("Block 973944 found · by your miner"), "{en}");
        assert_eq!(en.matches("973944").count(), 1, "{en}");
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

    const ADMIN: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    const ALL: Transports = Transports {
        telegram: true,
        ntfy: true,
        fcm: true,
        web_push: true,
    };

    fn telegram_sub(group_admin: bool) -> TelegramSubscriptionRow {
        TelegramSubscriptionRow {
            deleted_at: None,
            created_at: 0,
            updated_at: 0,
            id: 1,
            address: AddressId::new(ADMIN).unwrap(),
            telegram_chat_id: 7,
            best_diff_notifications_enabled: true,
            is_default: true,
            device_notifications_enabled: false,
            hourly_stats_enabled: false,
            hourly_workers_enabled: false,
            group_admin_notifications_enabled: group_admin,
            block_notifications_enabled: true,
        }
    }

    fn ntfy_sub(group_admin: bool) -> NtfySubscriptionRow {
        NtfySubscriptionRow {
            deleted_at: None,
            created_at: 0,
            updated_at: 0,
            id: 2,
            address: AddressId::new(ADMIN).unwrap(),
            language: "de".to_string(),
            best_diff_notifications_enabled: true,
            device_notifications_enabled: false,
            hourly_stats_enabled: false,
            hourly_workers_enabled: false,
            group_admin_notifications_enabled: group_admin,
        }
    }

    fn push_sub(kind: &str, group_admin: bool) -> PushSubscriptionRow {
        PushSubscriptionRow {
            deleted_at: None,
            created_at: 0,
            updated_at: 0,
            id: 3,
            address: AddressId::new(ADMIN).unwrap(),
            endpoint: "endpoint".to_string(),
            platform: "android".to_string(),
            last_notification_at: None,
            best_diff_notifications_enabled: true,
            device_notifications_enabled: true,
            block_notifications_enabled: true,
            subscription_type: kind.to_string(),
            network_diff_notifications_enabled: true,
            group_admin_notifications_enabled: group_admin,
        }
    }

    /// An admin on no channel gets the mail and nothing else.
    #[test]
    fn an_admin_on_no_channel_is_mailed() {
        let route = route_join_request(Vec::new(), None, Vec::new(), ALL);
        assert!(route.mail);
        assert!(route.telegram.is_empty() && route.ntfy.is_none() && route.push.is_empty());
    }

    /// Every channel with its switch on carries the notice, and no mail goes
    /// out next to it.
    #[test]
    fn every_switched_on_channel_carries_the_notice_without_a_mail() {
        let route = route_join_request(
            vec![telegram_sub(true)],
            Some(ntfy_sub(true)),
            vec![
                push_sub(PUSH_TYPE_FCM, true),
                push_sub(PUSH_TYPE_UNIFIED, true),
            ],
            ALL,
        );
        assert!(!route.mail);
        assert_eq!(route.telegram.len(), 1);
        assert!(route.ntfy.is_some());
        assert_eq!(route.push.len(), 2);
    }

    /// A switch turned off silences that channel and does not turn into a
    /// mail; the channel still on carries the notice.
    #[test]
    fn a_switched_off_channel_is_silent_and_sends_no_mail_instead() {
        let all_off = route_join_request(
            vec![telegram_sub(false)],
            Some(ntfy_sub(false)),
            vec![push_sub(PUSH_TYPE_FCM, false)],
            ALL,
        );
        assert!(
            !all_off.mail,
            "switching off is a choice, not a reason to mail"
        );
        assert!(all_off.telegram.is_empty() && all_off.ntfy.is_none() && all_off.push.is_empty());

        let one_on = route_join_request(
            vec![telegram_sub(false)],
            None,
            vec![push_sub(PUSH_TYPE_UNIFIED, true)],
            ALL,
        );
        assert!(one_on.telegram.is_empty());
        assert_eq!(one_on.push.len(), 1);
    }

    /// A subscription on a transport this process cannot send on does not
    /// count as a channel, so the admin is mailed instead of told nowhere.
    #[test]
    fn a_subscription_on_an_unconfigured_transport_falls_back_to_mail() {
        let none = Transports {
            telegram: false,
            ntfy: false,
            fcm: false,
            web_push: false,
        };
        let route = route_join_request(
            vec![telegram_sub(true)],
            Some(ntfy_sub(true)),
            vec![push_sub(PUSH_TYPE_FCM, true)],
            none,
        );
        assert!(route.mail);
        assert!(route.telegram.is_empty() && route.ntfy.is_none() && route.push.is_empty());

        let fcm_only = Transports { fcm: true, ..none };
        let route = route_join_request(
            Vec::new(),
            None,
            vec![
                push_sub(PUSH_TYPE_UNIFIED, true),
                push_sub(PUSH_TYPE_FCM, true),
            ],
            fcm_only,
        );
        assert!(!route.mail);
        assert_eq!(route.push.len(), 1);
        assert_eq!(route.push[0].subscription_type, PUSH_TYPE_FCM);
    }

    /// The app reads `title|body|` as title and body; a third non-empty part
    /// would be shown as a difficulty, also for a Team name holding a `|`.
    #[test]
    fn the_join_request_push_names_the_team_in_the_two_part_wire_shape() {
        assert_eq!(
            join_request_push_payload("PoolPals").pipe_joined(),
            "New join request|New join request in PoolPals|"
        );
        let wire = join_request_push_payload("A|B").pipe_joined();
        assert_eq!(wire.split('|').filter(|p| !p.is_empty()).count(), 2);
    }

    #[test]
    fn join_request_text_names_the_team_and_links_the_admin_panel_when_known() {
        let url = "https://blitzpool.example/#/app/bc1qadmin/payout-group/admin";
        let en = join_request_text(Language::En, "Pool<Pals>", Some(url));
        assert!(html::is_valid_telegram_html(&en), "{en}");
        assert!(
            !en.contains(">https://"),
            "the URL is no visible text: {en}"
        );
        assert_eq!(
            html::to_plain(&en),
            format!("\u{1f44b} New join request\nTeam: Pool<Pals>\nOpen the admin panel ({url})")
        );
        assert_eq!(
            html::to_plain(&join_request_text(Language::De, "PoolPals", None)),
            "\u{1f44b} Neue Beitrittsanfrage\nTeam: PoolPals"
        );
    }
}
