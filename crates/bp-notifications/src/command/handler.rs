// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dispatch a parsed [`Command`] against bp-db + the right adapter.
//!
//! The handler owns:
//!
//! - the `PgPool` (subscription reads + writes),
//! - an optional Telegram adapter (used when the originating transport
//!   is Telegram),
//! - an optional ntfy adapter (used when the originating transport is
//!   ntfy),
//! - an in-memory map of per-chat Telegram languages (chat-language is
//!   not persisted on the Telegram side — it lives for the process
//!   lifetime, shared with the hourly-stats cron).
//!
//! The two listener loops (`listener::telegram`, `listener::ntfy`)
//! parse incoming text via [`parse_command`] and call
//! [`CommandHandler::dispatch`] with the matching [`Transport`].

use std::collections::HashMap;
use std::sync::Arc;

use bp_common::AddressId;
use bp_db::{
    delete_ntfy_subscription_by_address, delete_telegram_subscription_by_chat_address,
    find_ntfy_subscription_by_address, find_telegram_subscriptions_by_chat,
    promote_telegram_default_if_none, reset_address_settings_best_difficulty,
    set_telegram_default_subscription, set_telegram_hourly_flags, update_ntfy_sub_best_diff_flag,
    update_ntfy_sub_device_flag, update_ntfy_sub_hourly_flags, update_ntfy_sub_language,
    update_telegram_sub_best_diff_flag, update_telegram_sub_device_flag,
    update_telegram_sub_hourly_flags, upsert_ntfy_subscription, upsert_telegram_subscription,
    TelegramSubscriptionRow,
};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};
use tracing::warn;

use super::parser::{
    parse_address_callback, parse_bestdiff_callback, parse_hourly_callback, AddressCallback,
    Command, FlagToggle, HourlyTarget, LanguageSwitch,
};
use super::read::format_address_short;
use crate::adapter::{
    AdapterError, AdapterResult, InlineButton, InlineKeyboard, NtfyAdapter, TelegramAdapter,
};
use crate::format::Language;

/// Shared, process-lifetime map of Telegram `chat_id` → chosen
/// [`Language`]. Owned by [`CommandHandler`] and handed to the
/// hourly-stats cron so both render in the chat's chosen language.
pub type ChatLanguageMap = Arc<Mutex<HashMap<i64, Language>>>;

/// Which transport the incoming command was received on. Doubles as
/// reply-sink: handler dispatches reply text to the matching adapter.
#[derive(Debug, Clone)]
pub enum Transport {
    Telegram { chat_id: i64 },
    Ntfy { address: AddressId },
}

/// Marker for callers that want to provide their own response sink
/// instead of going through the built-in [`Transport`] dispatch (e.g.
/// tests, or a future bp-bot-commands crate that owns its own
/// adapter handles).
pub trait ResponseSink: Send + Sync {
    fn transport_kind(&self) -> &'static str;
}

/// A `/bestdiff_reset` confirmation awaiting the user's yes/no tap,
/// keyed by `"chat_id:message_id"`. Expires so a stale prompt can't
/// reset much later.
struct PendingBestdiffReset {
    address: AddressId,
    expires_at_ms: i64,
}

pub struct CommandHandler {
    pool: PgPool,
    telegram: Option<Arc<TelegramAdapter>>,
    ntfy: Option<Arc<NtfyAdapter>>,
    pplns_engine: Option<Arc<bp_pplns_engine::engine::PplnsEngine>>,
    group_solo_engine: Option<Arc<bp_group_solo_engine::engine::GroupSoloEngine>>,
    chat_languages: Arc<Mutex<HashMap<i64, Language>>>,
    /// In-flight `/bestdiff_reset` confirmations, keyed `"chat:message"`.
    pending_bestdiff_resets: Arc<Mutex<HashMap<String, PendingBestdiffReset>>>,
    /// Signalled when an ntfy `/subscribe` or `/remove` changes the
    /// subscription set, so the SSE listener reconnects with the new
    /// topic list at once. `None` when no ntfy listener is wired.
    ntfy_reconnect: Option<Arc<Notify>>,
}

impl CommandHandler {
    /// Build a handler with only the adapter sinks wired — engine
    /// readers default to `None` (read commands fall back to the
    /// deferred-stub reply). Use [`Self::with_engines`] to attach
    /// engine handles.
    pub fn new(
        pool: PgPool,
        telegram: Option<Arc<TelegramAdapter>>,
        ntfy: Option<Arc<NtfyAdapter>>,
    ) -> Self {
        Self {
            pool,
            telegram,
            ntfy,
            pplns_engine: None,
            group_solo_engine: None,
            chat_languages: Arc::new(Mutex::new(HashMap::new())),
            pending_bestdiff_resets: Arc::new(Mutex::new(HashMap::new())),
            ntfy_reconnect: None,
        }
    }

    /// Attach the ntfy listener's reconnect signal so an ntfy
    /// `/subscribe` / `/remove` refreshes the SSE topic set immediately.
    pub fn with_ntfy_reconnect(mut self, reconnect: Arc<Notify>) -> Self {
        self.ntfy_reconnect = Some(reconnect);
        self
    }

    /// Nudge the ntfy listener to reconnect (no-op without a listener).
    fn signal_ntfy_reconnect(&self) {
        if let Some(n) = &self.ntfy_reconnect {
            n.notify_one();
        }
    }

    /// Attach engine-reader handles so the engine-driven read
    /// commands (`/pplns_status`, `/pplns_top`, `/group_status`,
    /// `/group_members`, `/show_workers`) can answer with live data
    /// instead of the "noch nicht verfügbar"-fallback. Returns the
    /// same handler for builder-style chaining at Phase-7 setup.
    pub fn with_engines(
        mut self,
        pplns: Option<Arc<bp_pplns_engine::engine::PplnsEngine>>,
        group_solo: Option<Arc<bp_group_solo_engine::engine::GroupSoloEngine>>,
    ) -> Self {
        self.pplns_engine = pplns;
        self.group_solo_engine = group_solo;
        self
    }

    /// Shared handle to the in-memory per-chat Telegram language map.
    /// The hourly-stats cron clones this so it renders each chat's
    /// digest in the language that chat picked via `/deutsch` /
    /// `/english` (same process, same map this handler writes).
    pub fn chat_languages(&self) -> ChatLanguageMap {
        self.chat_languages.clone()
    }

    /// Resolve language for the originating transport. Telegram is
    /// in-memory only (defaults to English on first contact). ntfy
    /// comes from `ntfy_subscriptions_entity.language`.
    async fn language(&self, transport: &Transport) -> Language {
        match transport {
            Transport::Telegram { chat_id } => self
                .chat_languages
                .lock()
                .await
                .get(chat_id)
                .copied()
                .unwrap_or_default(),
            Transport::Ntfy { address } => {
                match find_ntfy_subscription_by_address(&self.pool, address).await {
                    Ok(Some(row)) => Language::parse(&row.language),
                    _ => Language::default(),
                }
            }
        }
    }

    async fn set_language_in_memory(&self, chat_id: i64, lang: Language) {
        self.chat_languages.lock().await.insert(chat_id, lang);
    }

    async fn reply(&self, transport: &Transport, text: &str) -> AdapterResult<()> {
        match transport {
            Transport::Telegram { chat_id } => match &self.telegram {
                Some(adapter) => adapter.send_text(*chat_id, text).await,
                None => Err(AdapterError::Config(
                    "telegram adapter not configured".into(),
                )),
            },
            Transport::Ntfy { address } => match &self.ntfy {
                Some(adapter) => adapter.publish(address.as_str(), text).await,
                None => Err(AdapterError::Config("ntfy adapter not configured".into())),
            },
        }
    }

    /// Top-level entry point — parsed [`Command`] + originating
    /// transport. Internally resolves language, performs DB work,
    /// formats reply, and pushes via the matching adapter.
    pub async fn dispatch(&self, transport: &Transport, command: &Command) {
        let lang = self.language(transport).await;
        // Telegram inline-keyboard commands send their own message (with a
        // `reply_markup`) instead of a plain-text reply.
        if let Transport::Telegram { chat_id } = transport {
            match command {
                Command::ShowAddresses => {
                    self.send_address_keyboard(*chat_id, lang).await;
                    return;
                }
                Command::HourlyMenu => {
                    self.send_hourly_menu(*chat_id, lang).await;
                    return;
                }
                Command::BestDiffReset { address } => {
                    self.send_bestdiff_confirm(*chat_id, lang, address.as_deref())
                        .await;
                    return;
                }
                _ => {}
            }
        }
        let reply = match command {
            Command::Start => self.handle_start(transport, lang).await,
            Command::Help => help_text(lang).to_string(),
            Command::Subscribe { address } => self.handle_subscribe(transport, lang, address).await,
            Command::Remove { address } => self.handle_remove(transport, lang, address).await,
            Command::ShowAddresses => self.handle_show_addresses(transport, lang).await,
            Command::BestDiffToggle(toggle) => {
                self.handle_flag_toggle(transport, lang, FlagKind::BestDiff, *toggle)
                    .await
            }
            Command::DeviceToggle(toggle) => {
                self.handle_flag_toggle(transport, lang, FlagKind::Device, *toggle)
                    .await
            }
            Command::HourlyToggle(toggle) => {
                self.handle_flag_toggle(transport, lang, FlagKind::Hourly, *toggle)
                    .await
            }
            // Telegram opens the inline menu above (early return). Other
            // transports have no inline keyboard — point at the toggle.
            Command::HourlyMenu => match lang {
                Language::De => {
                    "Nutze /send_hourly on|off, um stündliche Berichte zu schalten.".to_string()
                }
                Language::En => "Use /send_hourly on|off to toggle hourly reports.".to_string(),
            },
            Command::BestDiffReset { address } => {
                self.handle_best_diff_reset(transport, lang, address.as_deref())
                    .await
            }
            Command::LanguageSwitch(switch) => {
                self.handle_language_switch(transport, *switch).await
            }
            Command::ReadDeferred(name) => self.handle_read_deferred(transport, lang, name).await,
            Command::Unknown => unknown_text(lang).to_string(),
        };

        if let Err(e) = self.reply(transport, &reply).await {
            warn!(target: "bp_notifications::command", error = %e, ?transport, "command reply failed");
        }
    }

    // ── Telegram inline-keyboard flows ──────────────────────────────

    /// Build the `/show_addresses` keyboard: one row per subscription —
    /// the address (⭐ on the current default) as a "set default"
    /// button plus a 🗑 "remove" button. Rows ordered by id for a
    /// stable layout across re-renders.
    fn build_address_keyboard(
        subs: &[TelegramSubscriptionRow],
        lang: Language,
    ) -> (String, InlineKeyboard) {
        let mut sorted: Vec<&TelegramSubscriptionRow> = subs.iter().collect();
        sorted.sort_by_key(|s| s.id);
        let keyboard: InlineKeyboard = sorted
            .iter()
            .map(|s| {
                let star = if s.is_default { "⭐ " } else { "" };
                vec![
                    InlineButton::new(
                        format!("{star}{}", format_address_short(s.address.as_str())),
                        format!("addr:set:{}", s.id),
                    ),
                    InlineButton::new("🗑", format!("addr:rm:{}", s.id)),
                ]
            })
            .collect();
        let text = match lang {
            Language::De => "Gespeicherte Adressen — tippe eine Adresse an, um sie als \
                 Standard zu setzen, 🗑 zum Entfernen.\n⭐ = Standard"
                .to_string(),
            Language::En => "Stored addresses — tap an address to set it as default, \
                 🗑 to remove.\n⭐ = default"
                .to_string(),
        };
        (text, keyboard)
    }

    /// Send the `/show_addresses` keyboard to a Telegram chat (or a
    /// "no addresses" note when the chat has none).
    async fn send_address_keyboard(&self, chat_id: i64, lang: Language) {
        let Some(adapter) = self.telegram.as_ref() else {
            return;
        };
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "show_addresses keyboard: read subs");
                let _ = adapter.send_text(chat_id, db_error_text(lang)).await;
                return;
            }
        };
        if subs.is_empty() {
            let _ = adapter.send_text(chat_id, no_addresses_text(lang)).await;
            return;
        }
        let (text, keyboard) = Self::build_address_keyboard(&subs, lang);
        if let Err(e) = adapter
            .send_message_with_keyboard(chat_id, &text, &keyboard)
            .await
        {
            warn!(target: "bp_notifications::command", error = %e, "show_addresses keyboard: send");
        }
    }

    /// Entry point for a Telegram `callback_query` (inline-button tap).
    /// Dispatches `addr:` taps to the address-keyboard flow; any other
    /// payload just stops the loading spinner. Always answers the query.
    pub async fn handle_telegram_callback(
        &self,
        callback_id: &str,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        data: Option<&str>,
    ) {
        let Some(adapter) = self.telegram.as_ref() else {
            return;
        };
        if let (Some(chat_id), Some(message_id), Some(data)) = (chat_id, message_id, data) {
            if let Some(cb) = parse_address_callback(data) {
                self.handle_address_callback(adapter, callback_id, chat_id, message_id, cb)
                    .await;
                return;
            }
            if let Some(target) = parse_hourly_callback(data) {
                self.handle_hourly_callback(adapter, callback_id, chat_id, message_id, target)
                    .await;
                return;
            }
            if let Some(confirm) = parse_bestdiff_callback(data) {
                self.handle_bestdiff_reset_callback(
                    adapter,
                    callback_id,
                    chat_id,
                    message_id,
                    confirm,
                )
                .await;
                return;
            }
        }
        // Unknown / unsupported callback → just stop the spinner.
        let _ = adapter.answer_callback_query(callback_id, None).await;
    }

    async fn handle_address_callback(
        &self,
        adapter: &TelegramAdapter,
        callback_id: &str,
        chat_id: i64,
        message_id: i64,
        cb: AddressCallback,
    ) {
        let lang = self.language(&Transport::Telegram { chat_id }).await;
        let de = matches!(lang, Language::De);
        let id = match cb {
            AddressCallback::SetDefault(id) | AddressCallback::Remove(id) => id,
        };
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "addr callback: read subs");
                let _ = adapter
                    .answer_callback_query(callback_id, Some(db_error_text(lang)))
                    .await;
                return;
            }
        };
        let Some(target) = subs.iter().find(|s| s.id == id) else {
            let _ = adapter
                .answer_callback_query(
                    callback_id,
                    Some(if de {
                        "Adresse nicht mehr vorhanden."
                    } else {
                        "Address no longer exists."
                    }),
                )
                .await;
            return;
        };
        let trimmed = format_address_short(target.address.as_str());
        match cb {
            AddressCallback::SetDefault(_) => {
                if target.is_default {
                    let toast = if de {
                        format!("{trimmed} ist schon Standard.")
                    } else {
                        format!("{trimmed} is already default.")
                    };
                    let _ = adapter
                        .answer_callback_query(callback_id, Some(&toast))
                        .await;
                    return;
                }
                if let Err(e) = set_telegram_default_subscription(&self.pool, chat_id, id).await {
                    warn!(target: "bp_notifications::command", error = %e, "addr callback: set default");
                    let _ = adapter
                        .answer_callback_query(callback_id, Some(db_error_text(lang)))
                        .await;
                    return;
                }
                let toast = if de {
                    format!("Standard: {trimmed}")
                } else {
                    format!("Default: {trimmed}")
                };
                let _ = adapter
                    .answer_callback_query(callback_id, Some(&toast))
                    .await;
            }
            AddressCallback::Remove(_) => {
                if let Err(e) = delete_telegram_subscription_by_chat_address(
                    &self.pool,
                    chat_id,
                    &target.address,
                )
                .await
                {
                    warn!(target: "bp_notifications::command", error = %e, "addr callback: remove");
                    let _ = adapter
                        .answer_callback_query(callback_id, Some(db_error_text(lang)))
                        .await;
                    return;
                }
                // Make sure the chat still has a default if rows remain.
                if let Err(e) = promote_telegram_default_if_none(&self.pool, chat_id).await {
                    warn!(target: "bp_notifications::command", error = %e, "addr callback: re-default");
                }
                let toast = if de {
                    format!("{trimmed} entfernt.")
                } else {
                    format!("{trimmed} removed.")
                };
                let _ = adapter
                    .answer_callback_query(callback_id, Some(&toast))
                    .await;
            }
        }
        // Re-render the keyboard in place (or collapse to a note if empty).
        let fresh = find_telegram_subscriptions_by_chat(&self.pool, chat_id)
            .await
            .unwrap_or_default();
        if fresh.is_empty() {
            let _ = adapter
                .edit_message_text(chat_id, message_id, no_addresses_text(lang), None)
                .await;
            return;
        }
        let (text, keyboard) = Self::build_address_keyboard(&fresh, lang);
        if let Err(e) = adapter
            .edit_message_text(chat_id, message_id, &text, Some(&keyboard))
            .await
        {
            warn!(target: "bp_notifications::command", error = %e, "addr callback: edit message");
        }
    }

    /// Build the hourly-reports toggle menu: one row with a stats and a
    /// workers button, each label showing the current on/off state.
    fn build_hourly_menu(stats: bool, workers: bool, lang: Language) -> (String, InlineKeyboard) {
        let (on, off) = match lang {
            Language::De => ("✅ AN", "❌ AUS"),
            Language::En => ("✅ ON", "❌ OFF"),
        };
        let stats_label = format!("Stats: {}", if stats { on } else { off });
        let workers_word = if matches!(lang, Language::De) {
            "Worker"
        } else {
            "Workers"
        };
        let workers_label = format!("{workers_word}: {}", if workers { on } else { off });
        let text = match lang {
            Language::De => "Stündliche Berichte — tippe zum Umschalten:".to_string(),
            Language::En => "Hourly reports — tap to toggle:".to_string(),
        };
        let keyboard = vec![vec![
            InlineButton::new(stats_label, "hr:stats"),
            InlineButton::new(workers_label, "hr:workers"),
        ]];
        (text, keyboard)
    }

    /// Send the hourly-reports menu to a Telegram chat, seeded from the
    /// chat's first subscription's current flags.
    async fn send_hourly_menu(&self, chat_id: i64, lang: Language) {
        let Some(adapter) = self.telegram.as_ref() else {
            return;
        };
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "hourly menu: read subs");
                let _ = adapter.send_text(chat_id, db_error_text(lang)).await;
                return;
            }
        };
        let Some(current) = subs.first() else {
            let _ = adapter.send_text(chat_id, no_addresses_text(lang)).await;
            return;
        };
        let (text, keyboard) = Self::build_hourly_menu(
            current.hourly_stats_enabled,
            current.hourly_workers_enabled,
            lang,
        );
        if let Err(e) = adapter
            .send_message_with_keyboard(chat_id, &text, &keyboard)
            .await
        {
            warn!(target: "bp_notifications::command", error = %e, "hourly menu: send");
        }
    }

    async fn handle_hourly_callback(
        &self,
        adapter: &TelegramAdapter,
        callback_id: &str,
        chat_id: i64,
        message_id: i64,
        target: HourlyTarget,
    ) {
        let lang = self.language(&Transport::Telegram { chat_id }).await;
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "hourly callback: read subs");
                let _ = adapter
                    .answer_callback_query(callback_id, Some(db_error_text(lang)))
                    .await;
                return;
            }
        };
        let Some(current) = subs.first() else {
            let _ = adapter
                .answer_callback_query(
                    callback_id,
                    Some(if matches!(lang, Language::De) {
                        "Keine Adresse gespeichert."
                    } else {
                        "No address stored."
                    }),
                )
                .await;
            return;
        };
        let mut stats = current.hourly_stats_enabled;
        let mut workers = current.hourly_workers_enabled;
        match target {
            HourlyTarget::Stats => stats = !stats,
            HourlyTarget::Workers => workers = !workers,
        }
        if let Err(e) =
            set_telegram_hourly_flags(&self.pool, chat_id, &current.address, stats, workers).await
        {
            warn!(target: "bp_notifications::command", error = %e, "hourly callback: update flags");
            let _ = adapter
                .answer_callback_query(callback_id, Some(db_error_text(lang)))
                .await;
            return;
        }
        let _ = adapter.answer_callback_query(callback_id, None).await;
        let (text, keyboard) = Self::build_hourly_menu(stats, workers, lang);
        if let Err(e) = adapter
            .edit_message_text(chat_id, message_id, &text, Some(&keyboard))
            .await
        {
            warn!(target: "bp_notifications::command", error = %e, "hourly callback: edit message");
        }
    }

    /// The yes/no confirmation keyboard for `/bestdiff_reset`.
    fn build_bestdiff_confirm_keyboard(lang: Language) -> InlineKeyboard {
        let de = matches!(lang, Language::De);
        vec![vec![
            InlineButton::new(
                if de {
                    "✅ Ja, zurücksetzen"
                } else {
                    "✅ Yes, reset"
                },
                "bdr:yes",
            ),
            InlineButton::new(if de { "❌ Abbrechen" } else { "❌ Cancel" }, "bdr:no"),
        ]]
    }

    /// Resolve the target address (explicit arg or the chat's default),
    /// then send a yes/no confirmation keyboard and record the pending
    /// reset keyed by `chat:message_id` with a 5-minute expiry.
    async fn send_bestdiff_confirm(&self, chat_id: i64, lang: Language, arg: Option<&str>) {
        let Some(adapter) = self.telegram.as_ref() else {
            return;
        };
        let address = match arg {
            Some(raw) => match parse_address(raw) {
                Some(a) => a,
                None => {
                    let _ = adapter.send_text(chat_id, invalid_address_text(lang)).await;
                    return;
                }
            },
            None => match self.origin_address(&Transport::Telegram { chat_id }).await {
                Some(a) => a,
                None => {
                    let _ = adapter.send_text(chat_id, no_addresses_text(lang)).await;
                    return;
                }
            },
        };
        let de = matches!(lang, Language::De);
        let trimmed = format_address_short(address.as_str());
        let text = if de {
            format!("Best Difficulty für {trimmed} wirklich zurücksetzen?")
        } else {
            format!("Really reset best difficulty for {trimmed}?")
        };
        let keyboard = Self::build_bestdiff_confirm_keyboard(lang);
        let message_id = match adapter
            .send_message_with_keyboard(chat_id, &text, &keyboard)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "bestdiff confirm: send");
                return;
            }
        };
        let expires_at_ms = chrono::Utc::now().timestamp_millis() + 5 * 60 * 1000;
        self.pending_bestdiff_resets.lock().await.insert(
            format!("{chat_id}:{message_id}"),
            PendingBestdiffReset {
                address,
                expires_at_ms,
            },
        );
    }

    async fn handle_bestdiff_reset_callback(
        &self,
        adapter: &TelegramAdapter,
        callback_id: &str,
        chat_id: i64,
        message_id: i64,
        confirm: bool,
    ) {
        let lang = self.language(&Transport::Telegram { chat_id }).await;
        let de = matches!(lang, Language::De);
        let key = format!("{chat_id}:{message_id}");
        let pending = self.pending_bestdiff_resets.lock().await.remove(&key);

        // Missing (already answered, or pool restarted) or past its TTL.
        let pending = match pending {
            Some(p) if p.expires_at_ms >= chrono::Utc::now().timestamp_millis() => p,
            _ => {
                let txt = if de {
                    "Anfrage abgelaufen."
                } else {
                    "Request expired."
                };
                let _ = adapter.answer_callback_query(callback_id, Some(txt)).await;
                let _ = adapter
                    .edit_message_text(chat_id, message_id, txt, None)
                    .await;
                return;
            }
        };
        let trimmed = format_address_short(pending.address.as_str());

        if !confirm {
            let _ = adapter
                .answer_callback_query(
                    callback_id,
                    Some(if de { "Abgebrochen." } else { "Cancelled." }),
                )
                .await;
            let txt = if de {
                format!("Reset abgebrochen — {trimmed}")
            } else {
                format!("Reset cancelled — {trimmed}")
            };
            let _ = adapter
                .edit_message_text(chat_id, message_id, &txt, None)
                .await;
            return;
        }

        if let Err(e) = reset_address_settings_best_difficulty(&self.pool, &pending.address).await {
            warn!(target: "bp_notifications::command", error = %e, "bestdiff confirm: reset");
            let _ = adapter
                .answer_callback_query(callback_id, Some(db_error_text(lang)))
                .await;
            return;
        }
        let _ = adapter
            .answer_callback_query(
                callback_id,
                Some(if de { "Zurückgesetzt." } else { "Reset." }),
            )
            .await;
        let txt = if de {
            format!("Best Difficulty zurückgesetzt — {trimmed}")
        } else {
            format!("Best difficulty reset — {trimmed}")
        };
        let _ = adapter
            .edit_message_text(chat_id, message_id, &txt, None)
            .await;
    }

    // ── Per-command handlers ────────────────────────────────────────

    async fn handle_start(&self, transport: &Transport, lang: Language) -> String {
        let mut intro = match lang {
            Language::De => {
                "Willkommen bei Blitz Pool!\nMit /subscribe <Adresse> abonnierst du eine Mining-Adresse. \
                 /help zeigt alle Befehle."
                    .to_string()
            }
            Language::En => {
                "Welcome to Blitz Pool!\nUse /subscribe <address> to follow a mining address. \
                 /help lists every command."
                    .to_string()
            }
        };
        if let Transport::Telegram { chat_id } = transport {
            if let Ok(subs) = find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                if !subs.is_empty() {
                    intro.push_str("\n\n");
                    intro.push_str(&list_addresses(
                        lang,
                        subs.iter().map(|s| s.address.as_str()),
                    ));
                }
            }
        }
        intro
    }

    async fn handle_subscribe(
        &self,
        transport: &Transport,
        lang: Language,
        address_str: &str,
    ) -> String {
        let Some(address) = parse_address(address_str) else {
            return invalid_address_text(lang).to_string();
        };
        match transport {
            Transport::Telegram { chat_id } => {
                match upsert_telegram_subscription(&self.pool, *chat_id, &address).await {
                    Ok(_) => subscribe_ok_text(lang, address.as_str()).to_string(),
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "telegram subscribe");
                        db_error_text(lang).to_string()
                    }
                }
            }
            Transport::Ntfy { .. } => {
                // ntfy `/subscribe` lands a row for the *target* address;
                // the user's own topic remains the origin where replies
                // go.
                match upsert_ntfy_subscription(&self.pool, &address).await {
                    Ok(_) => {
                        // New topic — refresh the SSE listener now.
                        self.signal_ntfy_reconnect();
                        subscribe_ok_text(lang, address.as_str()).to_string()
                    }
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "ntfy subscribe");
                        db_error_text(lang).to_string()
                    }
                }
            }
        }
    }

    async fn handle_remove(
        &self,
        transport: &Transport,
        lang: Language,
        address_str: &str,
    ) -> String {
        let Some(address) = parse_address(address_str) else {
            return invalid_address_text(lang).to_string();
        };
        let affected = match transport {
            Transport::Telegram { chat_id } => {
                delete_telegram_subscription_by_chat_address(&self.pool, *chat_id, &address).await
            }
            Transport::Ntfy { .. } => {
                delete_ntfy_subscription_by_address(&self.pool, &address).await
            }
        };
        match affected {
            Ok(n) if n > 0 => {
                // An ntfy topic may have dropped — refresh the listener.
                if matches!(transport, Transport::Ntfy { .. }) {
                    self.signal_ntfy_reconnect();
                }
                remove_ok_text(lang, address.as_str()).to_string()
            }
            Ok(_) => remove_missing_text(lang, address.as_str()).to_string(),
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "remove");
                db_error_text(lang).to_string()
            }
        }
    }

    async fn handle_show_addresses(&self, transport: &Transport, lang: Language) -> String {
        match transport {
            Transport::Telegram { chat_id } => {
                match find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                    Ok(subs) if !subs.is_empty() => {
                        list_addresses(lang, subs.iter().map(|s| s.address.as_str()))
                    }
                    Ok(_) => no_addresses_text(lang).to_string(),
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "show_addresses");
                        db_error_text(lang).to_string()
                    }
                }
            }
            Transport::Ntfy { address } => {
                match find_ntfy_subscription_by_address(&self.pool, address).await {
                    Ok(Some(_)) => list_addresses(lang, std::iter::once(address.as_str())),
                    Ok(None) => no_addresses_text(lang).to_string(),
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "ntfy show_addresses");
                        db_error_text(lang).to_string()
                    }
                }
            }
        }
    }

    async fn handle_flag_toggle(
        &self,
        transport: &Transport,
        lang: Language,
        flag: FlagKind,
        toggle: FlagToggle,
    ) -> String {
        let value = toggle.as_bool();
        let affected = match transport {
            Transport::Telegram { chat_id } => {
                // The user toggles on EVERY subscription bound to this
                // chat — the /subscribe_bestdiff command isn't
                // address-scoped.
                let subs = match find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "toggle: read subs");
                        return db_error_text(lang).to_string();
                    }
                };
                let mut total: u64 = 0;
                for sub in subs {
                    let res = match flag {
                        FlagKind::BestDiff => {
                            update_telegram_sub_best_diff_flag(
                                &self.pool,
                                *chat_id,
                                &sub.address,
                                value,
                            )
                            .await
                        }
                        FlagKind::Device => {
                            update_telegram_sub_device_flag(
                                &self.pool,
                                *chat_id,
                                &sub.address,
                                value,
                            )
                            .await
                        }
                        FlagKind::Hourly => {
                            update_telegram_sub_hourly_flags(
                                &self.pool,
                                *chat_id,
                                &sub.address,
                                value,
                            )
                            .await
                        }
                    };
                    match res {
                        Ok(n) => total = total.saturating_add(n),
                        Err(e) => {
                            warn!(target: "bp_notifications::command", error = %e, "telegram flag toggle");
                            return db_error_text(lang).to_string();
                        }
                    }
                }
                Ok(total)
            }
            Transport::Ntfy { address } => match flag {
                FlagKind::BestDiff => {
                    update_ntfy_sub_best_diff_flag(&self.pool, address, value).await
                }
                FlagKind::Device => update_ntfy_sub_device_flag(&self.pool, address, value).await,
                FlagKind::Hourly => update_ntfy_sub_hourly_flags(&self.pool, address, value).await,
            },
        };
        match affected {
            Ok(n) if n > 0 => flag_toggle_ok_text(lang, flag, value).to_string(),
            Ok(_) => no_addresses_text(lang).to_string(),
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "flag toggle");
                db_error_text(lang).to_string()
            }
        }
    }

    async fn handle_best_diff_reset(
        &self,
        transport: &Transport,
        lang: Language,
        target: Option<&str>,
    ) -> String {
        // ntfy resets the origin address immediately. (Telegram goes
        // through `send_bestdiff_confirm` — the yes/no inline keyboard —
        // and never reaches this handler; the arms below stay only for
        // a possible explicit-address Telegram path / exhaustiveness.)
        let candidates: Vec<AddressId> = match (transport, target) {
            (_, Some(addr)) => match parse_address(addr) {
                Some(a) => vec![a],
                None => return invalid_address_text(lang).to_string(),
            },
            (Transport::Telegram { chat_id }, None) => {
                match find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                    Ok(v) => v.into_iter().map(|s| s.address).collect(),
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "best_diff_reset: read subs");
                        return db_error_text(lang).to_string();
                    }
                }
            }
            (Transport::Ntfy { address }, None) => vec![address.clone()],
        };
        if candidates.is_empty() {
            return no_addresses_text(lang).to_string();
        }
        let mut count: u64 = 0;
        for addr in &candidates {
            match reset_address_settings_best_difficulty(&self.pool, addr).await {
                Ok(n) => count += n,
                Err(e) => {
                    warn!(target: "bp_notifications::command", error = %e, "best_diff_reset");
                    return db_error_text(lang).to_string();
                }
            }
        }
        best_diff_reset_text(lang, count).to_string()
    }

    async fn handle_language_switch(
        &self,
        transport: &Transport,
        switch: LanguageSwitch,
    ) -> String {
        let new_lang = match switch {
            LanguageSwitch::De => Language::De,
            LanguageSwitch::En => Language::En,
        };
        match transport {
            Transport::Telegram { chat_id } => {
                self.set_language_in_memory(*chat_id, new_lang).await;
            }
            Transport::Ntfy { address } => {
                if let Err(e) =
                    update_ntfy_sub_language(&self.pool, address, new_lang.as_str()).await
                {
                    warn!(target: "bp_notifications::command", error = %e, "ntfy language switch");
                    return db_error_text(new_lang).to_string();
                }
            }
        }
        language_switch_ok_text(new_lang).to_string()
    }

    /// Dispatch read-style commands recognised by the parser. Stateless
    /// commands are handled directly; engine-reader commands fan out to
    /// the optional engine readers, falling back to a "noch nicht
    /// konfiguriert" reply when the engine isn't wired in.
    async fn handle_read_deferred(
        &self,
        transport: &Transport,
        lang: Language,
        name: &'static str,
    ) -> String {
        match name {
            "/poolhashrate" => super::read::build_pool_hashrate(&self.pool, lang).await,
            "/difficulty" => super::read::build_current_difficulty(lang).await,
            "/next_difficulty" => super::read::build_next_difficulty(lang).await,
            "/stats" => match self.origin_address(transport).await {
                Some(addr) => super::read::build_stats(&self.pool, lang, &addr).await,
                None => need_address_text(lang).to_string(),
            },
            "/group_history" => match self.origin_address(transport).await {
                Some(addr) => super::read::build_group_history(&self.pool, lang, &addr).await,
                None => need_address_text(lang).to_string(),
            },
            "/pplns_status" => match (self.origin_address(transport).await, &self.pplns_engine) {
                (Some(addr), Some(engine)) => {
                    super::read::build_pplns_status(&self.pool, engine, lang, &addr).await
                }
                (None, _) => need_address_text(lang).to_string(),
                (_, None) => engine_unconfigured_text(lang, "PPLNS").to_string(),
            },
            "/pplns_top" => match &self.pplns_engine {
                Some(engine) => super::read::build_pplns_top(engine, lang).await,
                None => engine_unconfigured_text(lang, "PPLNS").to_string(),
            },
            "/group_status" => {
                match (
                    self.origin_address(transport).await,
                    &self.group_solo_engine,
                ) {
                    (Some(addr), Some(engine)) => {
                        super::read::build_group_status(&self.pool, engine, lang, &addr).await
                    }
                    (None, _) => need_address_text(lang).to_string(),
                    (_, None) => engine_unconfigured_text(lang, "Group-Solo").to_string(),
                }
            }
            "/group_members" => {
                match (
                    self.origin_address(transport).await,
                    &self.group_solo_engine,
                ) {
                    (Some(addr), Some(engine)) => {
                        super::read::build_group_members(&self.pool, engine, lang, &addr).await
                    }
                    (None, _) => need_address_text(lang).to_string(),
                    (_, None) => engine_unconfigured_text(lang, "Group-Solo").to_string(),
                }
            }
            "/show_workers" => match self.origin_address(transport).await {
                Some(addr) => super::read::build_show_workers(&self.pool, lang, &addr).await,
                None => need_address_text(lang).to_string(),
            },
            _ => deferred_text(lang, name),
        }
    }

    /// Resolve the contextual address for read commands. For ntfy the
    /// topic IS the address. For Telegram we walk the chat's
    /// subscriptions and pick the `is_default=true` row — if there's
    /// only one subscription the default-flag is implicit. Returns
    /// `None` when no candidate can be found, so the caller can
    /// emit the "please supply an address" reply.
    async fn origin_address(&self, transport: &Transport) -> Option<AddressId> {
        match transport {
            Transport::Ntfy { address } => Some(address.clone()),
            Transport::Telegram { chat_id } => {
                let subs = find_telegram_subscriptions_by_chat(&self.pool, *chat_id)
                    .await
                    .ok()?;
                if subs.is_empty() {
                    return None;
                }
                if subs.len() == 1 {
                    return Some(subs[0].address.clone());
                }
                subs.iter()
                    .find(|s| s.is_default)
                    .map(|s| s.address.clone())
            }
        }
    }
}

fn engine_unconfigured_text(lang: Language, engine_name: &str) -> String {
    match lang {
        Language::De => format!("{engine_name}-Engine ist auf diesem Pool nicht konfiguriert."),
        Language::En => format!("{engine_name} engine is not configured on this pool."),
    }
}

fn need_address_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Bitte gib eine Adresse an oder benutze ntfy mit deinem Adress-Topic.",
        Language::En => "Please supply an address, or use ntfy with your address topic.",
    }
}

#[derive(Debug, Clone, Copy)]
enum FlagKind {
    BestDiff,
    Device,
    Hourly,
}

fn parse_address(raw: &str) -> Option<AddressId> {
    AddressId::new(raw.trim()).ok()
}

// ── Per-language reply strings ───────────────────────────────────────

fn help_text(lang: Language) -> &'static str {
    match lang {
        Language::De => {
            "Verfügbare Befehle:\n\
            /start — Begrüssung + Status\n\
            /subscribe <Adresse> — Adresse abonnieren\n\
            /remove <Adresse> — Adresse entfernen\n\
            /show_addresses — abonnierte Adressen anzeigen\n\
            /subscribe_bestdiff on|off — Best-Diff-Benachrichtigungen\n\
            /device_notifications on|off — Geräte-Status\n\
            /send_hourly on|off — Stündliche Updates\n\
            /bestdiff_reset [<Adresse>] — Best-Diff zurücksetzen\n\
            /deutsch | /english — Sprache umschalten\n\
            /help — diese Hilfe"
        }
        Language::En => {
            "Available commands:\n\
            /start — welcome + status\n\
            /subscribe <address> — subscribe to mining address\n\
            /remove <address> — remove address\n\
            /show_addresses — list subscribed addresses\n\
            /subscribe_bestdiff on|off — best-difficulty notifications\n\
            /device_notifications on|off — device status\n\
            /send_hourly on|off — hourly updates\n\
            /bestdiff_reset [<address>] — reset stored best-difficulty\n\
            /deutsch | /english — switch language\n\
            /help — this help"
        }
    }
}

fn unknown_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Unbekannter Befehl. /help zeigt alle Befehle.",
        Language::En => "Unknown command. Use /help for the command list.",
    }
}

fn deferred_text(lang: Language, name: &str) -> String {
    match lang {
        Language::De => {
            format!("{name}: noch nicht verfügbar — Engine-Reader-Wiring noch ausstehend.")
        }
        Language::En => format!("{name}: not yet available — engine reader wiring is pending."),
    }
}

fn invalid_address_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Ungültige Adresse. Bitte BTC-Adresse ohne Leerzeichen angeben.",
        Language::En => "Invalid address. Please supply a BTC address without whitespace.",
    }
}

fn db_error_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Datenbank-Fehler, bitte später noch einmal versuchen.",
        Language::En => "Database error, please try again later.",
    }
}

fn subscribe_ok_text(lang: Language, address: &str) -> String {
    match lang {
        Language::De => format!("Adresse {address} abonniert. ✅"),
        Language::En => format!("Subscribed to address {address}. ✅"),
    }
}

fn remove_ok_text(lang: Language, address: &str) -> String {
    match lang {
        Language::De => format!("Adresse {address} entfernt."),
        Language::En => format!("Address {address} removed."),
    }
}

fn remove_missing_text(lang: Language, address: &str) -> String {
    match lang {
        Language::De => format!("Adresse {address} war nicht abonniert."),
        Language::En => format!("Address {address} was not subscribed."),
    }
}

fn no_addresses_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Keine Adressen abonniert.",
        Language::En => "No addresses subscribed.",
    }
}

fn list_addresses<'a>(lang: Language, addrs: impl Iterator<Item = &'a str>) -> String {
    let mut out = match lang {
        Language::De => "Abonnierte Adressen:".to_string(),
        Language::En => "Subscribed addresses:".to_string(),
    };
    for a in addrs {
        out.push_str("\n• ");
        out.push_str(a);
    }
    out
}

fn flag_toggle_ok_text(lang: Language, flag: FlagKind, value: bool) -> String {
    let on = value;
    match (lang, flag, on) {
        (Language::De, FlagKind::BestDiff, true) => {
            "Best-Diff-Benachrichtigungen aktiviert.".into()
        }
        (Language::De, FlagKind::BestDiff, false) => {
            "Best-Diff-Benachrichtigungen deaktiviert.".into()
        }
        (Language::De, FlagKind::Device, true) => "Geräte-Benachrichtigungen aktiviert.".into(),
        (Language::De, FlagKind::Device, false) => "Geräte-Benachrichtigungen deaktiviert.".into(),
        (Language::De, FlagKind::Hourly, true) => "Stündliche Updates aktiviert.".into(),
        (Language::De, FlagKind::Hourly, false) => "Stündliche Updates deaktiviert.".into(),
        (Language::En, FlagKind::BestDiff, true) => "Best-difficulty notifications enabled.".into(),
        (Language::En, FlagKind::BestDiff, false) => {
            "Best-difficulty notifications disabled.".into()
        }
        (Language::En, FlagKind::Device, true) => "Device notifications enabled.".into(),
        (Language::En, FlagKind::Device, false) => "Device notifications disabled.".into(),
        (Language::En, FlagKind::Hourly, true) => "Hourly updates enabled.".into(),
        (Language::En, FlagKind::Hourly, false) => "Hourly updates disabled.".into(),
    }
}

fn best_diff_reset_text(lang: Language, n: u64) -> String {
    match lang {
        Language::De => format!("Best-Diff für {n} Adresse(n) zurückgesetzt."),
        Language::En => format!("Best-difficulty reset for {n} address(es)."),
    }
}

fn language_switch_ok_text(new_lang: Language) -> &'static str {
    match new_lang {
        Language::De => "Sprache auf Deutsch umgestellt.",
        Language::En => "Language switched to English.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_rejects_blank_or_oversized() {
        assert!(parse_address("").is_none());
        assert!(parse_address("   ").is_none());
        assert!(parse_address(&"a".repeat(70)).is_none());
        assert!(parse_address("with space").is_none());
    }

    #[test]
    fn parse_address_accepts_basic_btc_address_shapes() {
        assert!(parse_address("bc1qexampleaddress").is_some());
        assert!(parse_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_some());
        assert!(parse_address("3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5").is_some());
    }

    #[test]
    fn help_text_includes_all_listed_commands_per_language() {
        let de = help_text(Language::De);
        let en = help_text(Language::En);
        for cmd in [
            "/start",
            "/subscribe",
            "/remove",
            "/show_addresses",
            "/subscribe_bestdiff",
            "/device_notifications",
            "/send_hourly",
            "/bestdiff_reset",
            "/deutsch",
            "/english",
            "/help",
        ] {
            assert!(de.contains(cmd), "missing {cmd} in de help");
            assert!(en.contains(cmd), "missing {cmd} in en help");
        }
    }

    #[test]
    fn flag_toggle_text_covers_all_six_combinations() {
        for flag in [FlagKind::BestDiff, FlagKind::Device, FlagKind::Hourly] {
            for val in [true, false] {
                for lang in [Language::De, Language::En] {
                    let s = flag_toggle_ok_text(lang, flag, val);
                    assert!(
                        !s.is_empty(),
                        "empty toggle text for {flag:?}/{val}/{lang:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn list_addresses_renders_bullets() {
        let s = list_addresses(Language::En, ["a", "b", "c"].into_iter());
        assert!(s.starts_with("Subscribed addresses:"));
        assert!(s.contains("\n• a"));
        assert!(s.contains("\n• b"));
        assert!(s.contains("\n• c"));
    }

    fn sub_row(id: i32, address: &str, is_default: bool) -> TelegramSubscriptionRow {
        TelegramSubscriptionRow {
            deleted_at: None,
            created_at: 0,
            updated_at: 0,
            id,
            address: AddressId::new(address).expect("addr"),
            telegram_chat_id: 1,
            best_diff_notifications_enabled: false,
            is_default,
            device_notifications_enabled: false,
            hourly_stats_enabled: false,
            hourly_workers_enabled: false,
        }
    }

    #[test]
    fn address_keyboard_marks_default_and_carries_callbacks() {
        // Out-of-order ids → builder must sort by id for a stable layout.
        let subs = vec![
            sub_row(2, "bc1qsecondaddressxxxxxx", false),
            sub_row(1, "bc1qfirstaddressxxxxxxx", true),
        ];
        let (text, kb) = CommandHandler::build_address_keyboard(&subs, Language::En);
        assert!(text.contains("default"));
        assert_eq!(kb.len(), 2);
        // Row 0 = id 1 (the default → ⭐), row 1 = id 2.
        assert!(kb[0][0].text.starts_with("⭐ "));
        assert_eq!(kb[0][0].callback_data, "addr:set:1");
        assert_eq!(kb[0][1].callback_data, "addr:rm:1");
        assert!(!kb[1][0].text.starts_with('⭐'));
        assert_eq!(kb[1][0].callback_data, "addr:set:2");
        assert_eq!(kb[1][1].callback_data, "addr:rm:2");
    }

    #[test]
    fn hourly_menu_reflects_flags_and_carries_callbacks() {
        let (_text, kb) = CommandHandler::build_hourly_menu(true, false, Language::En);
        assert_eq!(kb.len(), 1);
        assert_eq!(kb[0].len(), 2);
        assert_eq!(kb[0][0].callback_data, "hr:stats");
        assert_eq!(kb[0][1].callback_data, "hr:workers");
        assert!(kb[0][0].text.contains("ON"), "stats on: {}", kb[0][0].text);
        assert!(
            kb[0][1].text.contains("OFF"),
            "workers off: {}",
            kb[0][1].text
        );
        // German labels use AN/AUS + "Worker".
        let (_t, kb_de) = CommandHandler::build_hourly_menu(false, true, Language::De);
        assert!(kb_de[0][0].text.contains("AUS"));
        assert!(kb_de[0][1].text.starts_with("Worker:"));
        assert!(kb_de[0][1].text.contains("AN"));
    }

    #[test]
    fn bestdiff_confirm_keyboard_carries_yes_no_callbacks() {
        let kb = CommandHandler::build_bestdiff_confirm_keyboard(Language::En);
        assert_eq!(kb.len(), 1);
        assert_eq!(kb[0][0].callback_data, "bdr:yes");
        assert_eq!(kb[0][1].callback_data, "bdr:no");
        assert!(kb[0][0].text.contains("Yes"));
        assert!(kb[0][1].text.contains("Cancel"));
    }
}
