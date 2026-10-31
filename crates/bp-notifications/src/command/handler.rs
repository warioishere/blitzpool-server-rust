// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dispatch a parsed [`Command`] against bp-db and reply on the transport it came in on.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bitcoin::Network;
use bp_common::AddressId;
use bp_db::{
    delete_ntfy_subscription_by_address, delete_telegram_subscription_by_chat_address, find_group,
    find_group_member_by_address, find_ntfy_subscription_by_address,
    find_telegram_subscriptions_by_chat, promote_telegram_default_if_none,
    set_telegram_default_subscription, set_telegram_hourly_flags, update_ntfy_sub_best_diff_flag,
    update_ntfy_sub_device_flag, update_ntfy_sub_group_admin_flag, update_ntfy_sub_hourly_flags,
    update_ntfy_sub_language, update_ntfy_sub_team_best_flag, update_telegram_sub_best_diff_flag,
    update_telegram_sub_block_flag, update_telegram_sub_device_flag,
    update_telegram_sub_group_admin_flag, update_telegram_sub_team_best_flag,
    upsert_ntfy_subscription, upsert_telegram_subscription, TelegramSubscriptionRow,
};
use sqlx::PgPool;
use tokio::sync::{Mutex, Notify};
use tracing::warn;

use super::chat_language::ChatLanguages;
use super::encrypted_address::{
    looks_encrypted, open_encrypted_address, EncryptedAddressError, MessageKey,
};
use super::parser::{
    parse_address_callback, parse_settings_callback, AddressCallback, Command, FlagToggle,
    LanguageSwitch, ReadCommand, SettingsCallback, SettingsField, Switch,
};
use crate::adapter::{
    AdapterError, AdapterResult, InlineButton, InlineKeyboard, NtfyAdapter, TelegramAdapter,
};
use crate::format::html;
use crate::format::Language;
use bp_common::short_address;

/// Which transport the incoming command was received on. Doubles as
/// reply-sink: handler dispatches reply text to the matching adapter.
#[derive(Debug, Clone)]
pub enum Transport {
    Telegram { chat_id: i64 },
    Ntfy { address: AddressId },
}

/// How long a `/subscribe` question takes an answer.
const QUESTION_TTL_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy)]
struct OpenQuestion {
    message_id: i64,
    expires_at_ms: i64,
}

/// Where a plain Telegram message came from, for telling an answer to the
/// bot's question from ordinary chat.
#[derive(Debug, Clone, Copy)]
pub struct PlainMessage {
    pub chat_id: i64,
    /// A one-to-one chat with the bot.
    pub private: bool,
    /// The message this one replies to.
    pub reply_to: Option<i64>,
}

pub struct CommandHandler {
    pool: PgPool,
    /// Redis handle for the `client:live:*` hashrate reads
    /// (`/poolhashrate`, `/pplns_status`, `/team_status`). `None`
    /// degrades those to their error/0 fallbacks.
    redis: Option<redis::aio::ConnectionManager>,
    telegram: Option<Arc<TelegramAdapter>>,
    ntfy: Option<Arc<NtfyAdapter>>,
    pplns_engine: Option<Arc<bp_pplns_engine::engine::PplnsEngine>>,
    group_solo_engine: Option<Arc<bp_group_solo_engine::engine::GroupSoloEngine>>,
    /// The network an address must belong to before the bot stores or
    /// reads it.
    network: Network,
    chat_languages: ChatLanguages,
    /// The UI's base URL, for links into an address's dashboard.
    pool_base_url: Option<String>,
    /// Opens addresses sent encrypted; `None` refuses them.
    message_key: Option<Arc<MessageKey>>,
    /// The open `/subscribe` question of each chat: its message id and
    /// expiry in ms. A new question replaces the chat's old one.
    subscribe_questions: Arc<Mutex<HashMap<i64, OpenQuestion>>>,
    /// Signalled when an ntfy `/subscribe` or `/remove` changes the
    /// subscription set, so the SSE listener reconnects with the new
    /// topic list at once. `None` when no ntfy listener is wired.
    ntfy_reconnect: Option<Arc<Notify>>,
}

impl CommandHandler {
    /// Build a handler with only the adapter sinks wired — engine
    /// readers default to `None` (engine read commands fall back to a
    /// not-configured reply). Use [`Self::with_engines`] to attach
    /// engine handles.
    pub fn new(
        pool: PgPool,
        network: Network,
        telegram: Option<Arc<TelegramAdapter>>,
        ntfy: Option<Arc<NtfyAdapter>>,
    ) -> Self {
        Self {
            chat_languages: ChatLanguages::new(pool.clone()),
            pool,
            redis: None,
            telegram,
            ntfy,
            pplns_engine: None,
            group_solo_engine: None,
            network,
            pool_base_url: None,
            message_key: None,
            subscribe_questions: Arc::new(Mutex::new(HashMap::new())),
            ntfy_reconnect: None,
        }
    }

    /// Attach the UI's base URL, so `/bestdiff_reset` can link the
    /// dashboard.
    pub fn with_pool_base_url(mut self, pool_base_url: Option<String>) -> Self {
        self.pool_base_url = pool_base_url;
        self
    }

    /// Attach the key that opens encrypted addresses.
    pub fn with_message_key(mut self, key: Option<MessageKey>) -> Self {
        self.message_key = key.map(Arc::new);
        self
    }

    /// Attach the Redis handle the live-hashrate read commands need.
    pub fn with_redis(mut self, redis: Option<redis::aio::ConnectionManager>) -> Self {
        self.redis = redis;
        self
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
    /// commands (`/pplns_status`, `/pplns_top`, `/team_status`,
    /// `/team_members`, `/show_workers`) can answer with live data
    /// instead of the not-configured fallback. Builder-style.
    pub fn with_engines(
        mut self,
        pplns: Option<Arc<bp_pplns_engine::engine::PplnsEngine>>,
        group_solo: Option<Arc<bp_group_solo_engine::engine::GroupSoloEngine>>,
    ) -> Self {
        self.pplns_engine = pplns;
        self.group_solo_engine = group_solo;
        self
    }

    /// The Telegram chat languages this handler writes, for the senders
    /// that reply in them.
    pub fn chat_languages(&self) -> ChatLanguages {
        self.chat_languages.clone()
    }

    /// Resolve language for the originating transport: the chat's stored
    /// language for Telegram, `ntfy_subscriptions_entity.language` for ntfy.
    async fn language(&self, transport: &Transport) -> Language {
        match transport {
            Transport::Telegram { chat_id } => self.chat_languages.get(*chat_id).await,
            Transport::Ntfy { address } => {
                match find_ntfy_subscription_by_address(&self.pool, address).await {
                    Ok(Some(row)) => Language::parse(&row.language),
                    _ => Language::default(),
                }
            }
        }
    }

    async fn reply(&self, transport: &Transport, text: &str) -> AdapterResult<()> {
        match transport {
            Transport::Telegram { chat_id } => match &self.telegram {
                Some(adapter) => adapter.send_html(*chat_id, text).await,
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
                Command::ShowAddresses | Command::Remove { address: None } => {
                    self.send_address_keyboard(*chat_id, lang).await;
                    return;
                }
                Command::Settings(switch) => {
                    self.send_settings(*chat_id, lang, *switch).await;
                    return;
                }
                Command::Subscribe { address: None } => {
                    self.ask_for_address(*chat_id, lang).await;
                    return;
                }
                _ => {}
            }
        }
        let reply = match command {
            Command::Start => self.handle_start(transport, lang).await,
            Command::Help => super::help_text(lang),
            Command::Subscribe {
                address: Some(address),
            } => self.handle_subscribe(transport, lang, address).await,
            // Telegram asks for the address above (early return).
            Command::Subscribe { address: None } => subscribe_usage_text(lang).to_string(),
            Command::Remove {
                address: Some(address),
            } => self.handle_remove(transport, lang, address).await,
            // Telegram offers the address keyboard above (early return);
            // an ntfy topic removes itself by name.
            Command::Remove { address: None } => remove_usage_text(lang).to_string(),
            Command::ShowAddresses => self.handle_show_addresses(transport, lang).await,
            Command::Settings(switch) => match transport {
                Transport::Ntfy { address } => {
                    self.ntfy_settings_text(address, lang, *switch).await
                }
                Transport::Telegram { .. } => {
                    unreachable!("Telegram gets the settings keyboard above")
                }
            },
            Command::Toggle(switch, toggle) => {
                self.handle_flag_toggle(transport, lang, *switch, *toggle)
                    .await
            }
            Command::BestDiffReset { address } => {
                match self
                    .target_address(transport, lang, address.as_deref())
                    .await
                {
                    Ok(address) => {
                        best_diff_reset_text(lang, &address, self.pool_base_url.as_deref())
                    }
                    Err(reply) => reply,
                }
            }
            Command::LanguageSwitch(switch) => {
                self.handle_language_switch(transport, *switch).await
            }
            Command::Read(read, address) => {
                self.handle_read(transport, lang, *read, address.as_deref())
                    .await
            }
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
                        format!("{star}{}", short_address(s.address.as_str())),
                        format!("addr:set:{}", s.id),
                    ),
                    InlineButton::new("🗑", format!("addr:rm:{}", s.id)),
                ]
            })
            .collect();
        let text = match lang {
            Language::De => format!(
                "{}\nTipp eine Adresse an, um sie zur Standard-Adresse (⭐) zu machen, \
                 🗑 entfernt sie.",
                html::bold("Deine Adressen")
            ),
            Language::En => format!(
                "{}\nTap an address to make it the default (⭐), 🗑 removes it.",
                html::bold("Your addresses")
            ),
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
                let _ = adapter.send_html(chat_id, db_error_text(lang)).await;
                return;
            }
        };
        if subs.is_empty() {
            let _ = adapter.send_html(chat_id, no_address_text(lang)).await;
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

    /// Ask which address to subscribe; the answer comes back through
    /// [`Self::answer_telegram_question`].
    async fn ask_for_address(&self, chat_id: i64, lang: Language) {
        let Some(adapter) = self.telegram.as_ref() else {
            return;
        };
        let question = match lang {
            Language::De => {
                "Welche Adresse soll ich abonnieren? Antworte mit deiner Mining-Adresse."
            }
            Language::En => "Which address should I follow? Reply with your mining address.",
        };
        match adapter.send_question(chat_id, question, "bc1q...").await {
            Ok(message_id) => {
                let now = chrono::Utc::now().timestamp_millis();
                let mut open = self.subscribe_questions.lock().await;
                open.retain(|_, q| q.expires_at_ms > now);
                open.insert(
                    chat_id,
                    OpenQuestion {
                        message_id,
                        expires_at_ms: now + QUESTION_TTL_MS,
                    },
                );
            }
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "subscribe question: send")
            }
        }
    }

    /// A plain message that answers the chat's open `/subscribe` question
    /// subscribes the address it carries. In a private chat that is the
    /// next plain message, a reply or not; in a group only a reply to the
    /// question, so ordinary chat is not taken for an address. `false` when
    /// the message answers no open question.
    pub async fn answer_telegram_question(&self, message: PlainMessage, text: &str) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        let mut open = self.subscribe_questions.lock().await;
        let Some(question) = open.get(&message.chat_id).copied() else {
            return false;
        };
        let answers = match message.reply_to {
            Some(id) => id == question.message_id,
            None => message.private,
        };
        if !answers || question.expires_at_ms <= now {
            return false;
        }
        open.remove(&message.chat_id);
        drop(open);
        let address = text.split_whitespace().next().map(str::to_string);
        let command = Command::Subscribe { address };
        self.dispatch(
            &Transport::Telegram {
                chat_id: message.chat_id,
            },
            &command,
        )
        .await;
        true
    }

    /// Entry point for a Telegram `callback_query` (inline-button tap),
    /// dispatched by its prefix. Always answers the query.
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
            if let Some(cb) = parse_settings_callback(data) {
                self.handle_settings_callback(adapter, callback_id, chat_id, message_id, cb)
                    .await;
                return;
            }
        }
        // A tap on a button no flow above handles.
        let lang = match chat_id {
            Some(chat_id) => self.chat_languages.get(chat_id).await,
            None => Language::default(),
        };
        let _ = adapter
            .answer_callback_query(callback_id, Some(stale_button_text(lang)))
            .await;
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
                .answer_callback_query(callback_id, Some(address_gone_text(lang)))
                .await;
            return;
        };
        let trimmed = short_address(target.address.as_str());
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
                if let Err(e) = self
                    .remove_telegram_subscription(chat_id, &target.address)
                    .await
                {
                    warn!(target: "bp_notifications::command", error = %e, "addr callback: remove");
                    let _ = adapter
                        .answer_callback_query(callback_id, Some(db_error_text(lang)))
                        .await;
                    return;
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
                .edit_message_text(chat_id, message_id, no_address_text(lang), None)
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

    /// The `/settings` keyboard: per subscription a row naming the address
    /// (⭐ on the default), then its switches with their state. A Team
    /// switch only where it can fire: join requests for a Team's admin, the
    /// round best for a Team's member.
    fn build_settings_keyboard(
        subs: &[TelegramSubscriptionRow],
        lang: Language,
        roles: &TeamRoles,
    ) -> (String, InlineKeyboard) {
        let mut sorted: Vec<&TelegramSubscriptionRow> = subs.iter().collect();
        sorted.sort_by_key(|s| s.id);
        let mut keyboard: InlineKeyboard = Vec::new();
        for sub in sorted {
            let star = if sub.is_default { "⭐ " } else { "" };
            keyboard.push(vec![InlineButton::new(
                format!("{star}{}", short_address(sub.address.as_str())),
                SettingsCallback::Address(sub.id).data(),
            )]);
            let button = |field| {
                let mark = if settings_field_value(sub, field) {
                    "✅"
                } else {
                    "❌"
                };
                InlineButton::new(
                    format!("{mark} {}", settings_field_label(lang, field)),
                    SettingsCallback::Flip(sub.id, field).data(),
                )
            };
            let fields: Vec<SettingsField> = SettingsField::ALL
                .into_iter()
                .filter(|f| roles.offers(*f, &sub.address))
                .collect();
            for row in fields.chunks(3) {
                keyboard.push(row.iter().map(|field| button(*field)).collect());
            }
        }
        let text = match lang {
            Language::De => format!(
                "{}\nPro Adresse, tippen schaltet um: ✅ an, ❌ aus. \
                 ⭐ ist die Standard-Adresse.",
                html::bold("Benachrichtigungen")
            ),
            Language::En => format!(
                "{}\nPer address, a tap switches: ✅ on, ❌ off. \
                 ⭐ is the default address.",
                html::bold("Notifications")
            ),
        };
        (text, keyboard)
    }

    /// Send the `/settings` keyboard (or a "no addresses" note). Opened by a
    /// Team switch it first says so when no address can get that notice.
    async fn send_settings(&self, chat_id: i64, lang: Language, switch: Option<Switch>) {
        let Some(adapter) = self.telegram.as_ref() else {
            return;
        };
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "settings: read subs");
                let _ = adapter.send_html(chat_id, db_error_text(lang)).await;
                return;
            }
        };
        if subs.is_empty() {
            let _ = adapter.send_html(chat_id, no_address_text(lang)).await;
            return;
        }
        let addresses: Vec<AddressId> = subs.iter().map(|s| s.address.clone()).collect();
        let roles = match self.team_roles(&addresses).await {
            Ok(r) => r,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "settings: team roles");
                let _ = adapter.send_html(chat_id, db_error_text(lang)).await;
                return;
            }
        };
        if let Some(refusal) = switch.and_then(|s| roles.refusal(s, lang)) {
            let _ = adapter.send_html(chat_id, refusal).await;
            return;
        }
        let (text, keyboard) = Self::build_settings_keyboard(&subs, lang, &roles);
        if let Err(e) = adapter
            .send_message_with_keyboard(chat_id, &text, &keyboard)
            .await
        {
            warn!(target: "bp_notifications::command", error = %e, "settings: send");
        }
    }

    async fn handle_settings_callback(
        &self,
        adapter: &TelegramAdapter,
        callback_id: &str,
        chat_id: i64,
        message_id: i64,
        cb: SettingsCallback,
    ) {
        let lang = self.chat_languages.get(chat_id).await;
        let id = match cb {
            SettingsCallback::Address(id) | SettingsCallback::Flip(id, _) => id,
        };
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "settings callback: read subs");
                let _ = adapter
                    .answer_callback_query(callback_id, Some(db_error_text(lang)))
                    .await;
                return;
            }
        };
        // Only a subscription of this chat: the id comes from the button.
        let Some(sub) = subs.iter().find(|s| s.id == id) else {
            let _ = adapter
                .answer_callback_query(callback_id, Some(address_gone_text(lang)))
                .await;
            return;
        };
        let field = match cb {
            // The address row only labels the switches below it.
            SettingsCallback::Address(_) => {
                let _ = adapter.answer_callback_query(callback_id, None).await;
                return;
            }
            SettingsCallback::Flip(_, field) => field,
        };
        let value = !settings_field_value(sub, field);
        if let Err(e) = set_telegram_field(&self.pool, chat_id, sub, field, value).await {
            warn!(target: "bp_notifications::command", error = %e, "settings callback: update");
            let _ = adapter
                .answer_callback_query(callback_id, Some(db_error_text(lang)))
                .await;
            return;
        }
        let _ = adapter.answer_callback_query(callback_id, None).await;
        let fresh = find_telegram_subscriptions_by_chat(&self.pool, chat_id)
            .await
            .unwrap_or_default();
        let addresses: Vec<AddressId> = fresh.iter().map(|s| s.address.clone()).collect();
        let roles = self.team_roles(&addresses).await.unwrap_or_default();
        let (text, keyboard) = Self::build_settings_keyboard(&fresh, lang, &roles);
        if let Err(e) = adapter
            .edit_message_text(chat_id, message_id, &text, Some(&keyboard))
            .await
        {
            warn!(target: "bp_notifications::command", error = %e, "settings callback: edit message");
        }
    }

    /// The switches of the ntfy topic, as text: ntfy has no keyboard.
    async fn ntfy_settings_text(
        &self,
        address: &AddressId,
        lang: Language,
        switch: Option<Switch>,
    ) -> String {
        let roles = match self.team_roles(std::slice::from_ref(address)).await {
            Ok(r) => r,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "ntfy settings: team roles");
                return db_error_text(lang).to_string();
            }
        };
        if let Some(refusal) = switch.and_then(|s| roles.refusal(s, lang)) {
            return refusal.to_string();
        }
        let row = match find_ntfy_subscription_by_address(&self.pool, address).await {
            Ok(Some(row)) => row,
            Ok(None) => return no_address_text(lang).to_string(),
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "ntfy settings");
                return db_error_text(lang).to_string();
            }
        };
        let mark = |on: bool| if on { "✅" } else { "❌" };
        let line =
            |on: bool, field| format!("\n{} {}", mark(on), settings_field_label(lang, field));
        let short = short_address(address.as_str());
        let mut out = match lang {
            Language::De => format!(
                "{}\nSchalten mit /subscribe_bestdiff, /device_notifications, \
                 /team_requests, /team_bestdiff oder /send_hourly und on|off.\n",
                html::title_for(None, "Benachrichtigungen", &short)
            ),
            Language::En => format!(
                "{}\nSwitch with /subscribe_bestdiff, /device_notifications, \
                 /team_requests, /team_bestdiff or /send_hourly and on|off.\n",
                html::title_for(None, "Notifications", &short)
            ),
        };
        out.push_str(&line(
            row.best_diff_notifications_enabled,
            SettingsField::BestDiff,
        ));
        out.push_str(&line(
            row.device_notifications_enabled,
            SettingsField::Device,
        ));
        if roles.offers(SettingsField::TeamRequests, address) {
            out.push_str(&line(
                row.group_admin_notifications_enabled,
                SettingsField::TeamRequests,
            ));
        }
        if roles.offers(SettingsField::TeamBest, address) {
            out.push_str(&line(
                row.team_best_notifications_enabled,
                SettingsField::TeamBest,
            ));
        }
        out.push_str(&line(row.hourly_stats_enabled, SettingsField::HourlyStats));
        out.push_str(&line(
            row.hourly_workers_enabled,
            SettingsField::HourlyWorkers,
        ));
        out
    }

    // ── Per-command handlers ────────────────────────────────────────

    /// What the bot does, how to start, and the chat's addresses if it
    /// has any. A Telegram chat without one is told to `/subscribe`; an
    /// ntfy topic already is its address.
    async fn handle_start(&self, transport: &Transport, lang: Language) -> String {
        let subscribed: Vec<AddressId> = match transport {
            Transport::Telegram { chat_id } => {
                find_telegram_subscriptions_by_chat(&self.pool, *chat_id)
                    .await
                    .map(|subs| subs.into_iter().map(|s| s.address).collect())
                    .unwrap_or_default()
            }
            Transport::Ntfy { address } => vec![address.clone()],
        };
        let mut text = match lang {
            Language::De => format!(
                "{}\n\nIch melde dir, wenn ein Block gefunden wird, der deine Adresse \
                 bezahlt, und neue Best-Diffs. Auf Wunsch auch, wenn ein Miner offline \
                 geht.\n\n",
                html::bold("Willkommen bei Blitz Pool")
            ),
            Language::En => format!(
                "{}\n\nI tell you when a block is found that pays your address, and \
                 when you reach a new best difficulty. On request also when a miner goes \
                 offline.\n\n",
                html::bold("Welcome to Blitz Pool")
            ),
        };
        if subscribed.is_empty() {
            text.push_str(match lang {
                Language::De => "Tipp /subscribe, dann frag ich nach deiner Mining-Adresse. ",
                Language::En => "Tap /subscribe and I will ask for your mining address. ",
            });
        }
        text.push_str(match lang {
            Language::De => {
                "Mit /settings schaltest du die Meldungen pro Adresse, /help zeigt \
                 alle Befehle."
            }
            Language::En => {
                "/settings switches the notices per address, /help lists every \
                 command."
            }
        });
        if self.message_key.is_some() {
            text.push_str(&encryption_hint(lang));
        }
        if !subscribed.is_empty() {
            text.push_str("\n\n");
            text.push_str(&list_addresses(
                lang,
                subscribed.iter().map(AddressId::as_str),
            ));
        }
        text
    }

    async fn handle_subscribe(
        &self,
        transport: &Transport,
        lang: Language,
        address_str: &str,
    ) -> String {
        let address = match self.pool_address(lang, address_str) {
            Ok(a) => a,
            Err(reply) => return reply,
        };
        match transport {
            Transport::Telegram { chat_id } => {
                match upsert_telegram_subscription(&self.pool, *chat_id, &address).await {
                    Ok(_) => subscribe_ok_text(lang, &address).to_string(),
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
                        subscribe_ok_text(lang, &address).to_string()
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
        // Normalized like a stored row but not checked against the network,
        // so a stored row that is no address of it can still be removed.
        let address = match self.address_arg(lang, address_str) {
            Ok(raw) => {
                AddressId::normalized(&raw).map_err(|_| invalid_address_text(lang).to_string())
            }
            Err(reply) => Err(reply),
        };
        let address = match address {
            Ok(a) => a,
            Err(reply) => return reply,
        };
        let affected = match transport {
            Transport::Telegram { chat_id } => {
                self.remove_telegram_subscription(*chat_id, &address).await
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
                remove_ok_text(lang, &address).to_string()
            }
            Ok(_) => remove_missing_text(lang, &address).to_string(),
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "remove");
                db_error_text(lang).to_string()
            }
        }
    }

    /// Soft-delete one subscription of the chat; when it was the default,
    /// the lowest-id remaining one takes over.
    async fn remove_telegram_subscription(
        &self,
        chat_id: i64,
        address: &AddressId,
    ) -> Result<u64, bp_db::DbError> {
        let removed =
            delete_telegram_subscription_by_chat_address(&self.pool, chat_id, address).await?;
        promote_telegram_default_if_none(&self.pool, chat_id).await?;
        Ok(removed)
    }

    async fn handle_show_addresses(&self, transport: &Transport, lang: Language) -> String {
        match transport {
            Transport::Telegram { chat_id } => {
                match find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                    Ok(subs) if !subs.is_empty() => {
                        list_addresses(lang, subs.iter().map(|s| s.address.as_str()))
                    }
                    Ok(_) => no_address_text(lang).to_string(),
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "show_addresses");
                        db_error_text(lang).to_string()
                    }
                }
            }
            Transport::Ntfy { address } => {
                match find_ntfy_subscription_by_address(&self.pool, address).await {
                    Ok(Some(_)) => list_addresses(lang, std::iter::once(address.as_str())),
                    Ok(None) => no_address_text(lang).to_string(),
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
        switch: Switch,
        toggle: FlagToggle,
    ) -> String {
        let value = toggle.as_bool();
        if matches!(switch, Switch::TeamRequests | Switch::TeamBest) {
            let addresses = match transport {
                Transport::Ntfy { address } => vec![address.clone()],
                Transport::Telegram { chat_id } => {
                    match find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                        Ok(subs) => subs.into_iter().map(|s| s.address).collect(),
                        Err(e) => {
                            warn!(target: "bp_notifications::command", error = %e, "toggle: read subs");
                            return db_error_text(lang).to_string();
                        }
                    }
                }
            };
            match self.team_roles(&addresses).await {
                Ok(roles) if !addresses.is_empty() => {
                    if let Some(refusal) = roles.refusal(switch, lang) {
                        return refusal.to_string();
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(target: "bp_notifications::command", error = %e, "toggle: team roles");
                    return db_error_text(lang).to_string();
                }
            }
        }
        let affected = match transport {
            Transport::Telegram { chat_id } => {
                // A switch command covers every subscription of the chat;
                // /settings switches one address.
                let subs = match find_telegram_subscriptions_by_chat(&self.pool, *chat_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(target: "bp_notifications::command", error = %e, "toggle: read subs");
                        return db_error_text(lang).to_string();
                    }
                };
                let fields: &[SettingsField] = match switch {
                    Switch::BestDiff => &[SettingsField::BestDiff],
                    Switch::Device => &[SettingsField::Device],
                    Switch::TeamRequests => &[SettingsField::TeamRequests],
                    Switch::TeamBest => &[SettingsField::TeamBest],
                    Switch::Hourly => &[SettingsField::HourlyStats, SettingsField::HourlyWorkers],
                };
                let mut total: u64 = 0;
                for mut sub in subs {
                    for field in fields {
                        match set_telegram_field(&self.pool, *chat_id, &sub, *field, value).await {
                            Ok(n) => total = total.saturating_add(n),
                            Err(e) => {
                                warn!(target: "bp_notifications::command", error = %e, "telegram flag toggle");
                                return db_error_text(lang).to_string();
                            }
                        }
                        set_settings_field_value(&mut sub, *field, value);
                    }
                }
                Ok(total)
            }
            Transport::Ntfy { address } => match switch {
                Switch::BestDiff => {
                    update_ntfy_sub_best_diff_flag(&self.pool, address, value).await
                }
                Switch::Device => update_ntfy_sub_device_flag(&self.pool, address, value).await,
                Switch::Hourly => update_ntfy_sub_hourly_flags(&self.pool, address, value).await,
                Switch::TeamRequests => {
                    update_ntfy_sub_group_admin_flag(&self.pool, address, value).await
                }
                Switch::TeamBest => {
                    update_ntfy_sub_team_best_flag(&self.pool, address, value).await
                }
            },
        };
        match affected {
            Ok(n) if n > 0 => flag_toggle_ok_text(lang, switch, value).to_string(),
            Ok(_) => no_address_text(lang).to_string(),
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "flag toggle");
                db_error_text(lang).to_string()
            }
        }
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
                if let Err(e) = self.chat_languages.set(*chat_id, new_lang).await {
                    warn!(target: "bp_notifications::command", error = %e, "telegram language switch");
                    return db_error_text(new_lang).to_string();
                }
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

    /// Dispatch read-style commands recognised by the parser. A command
    /// about an address takes the one it was given, else the origin's; an
    /// engine command answers "not configured" when its engine isn't wired.
    async fn handle_read(
        &self,
        transport: &Transport,
        lang: Language,
        read: ReadCommand,
        arg: Option<&str>,
    ) -> String {
        let address = || self.target_address(transport, lang, arg);
        let redis = self.redis.as_ref();
        let result = match read {
            ReadCommand::PoolHashrate => Ok(super::read::build_pool_hashrate(redis, lang).await),
            ReadCommand::Difficulty => Ok(super::read::build_current_difficulty(lang).await),
            ReadCommand::NextDifficulty => Ok(super::read::build_next_difficulty(lang).await),
            ReadCommand::PplnsTop => match &self.pplns_engine {
                Some(engine) => Ok(super::read::build_pplns_top(engine, lang).await),
                None => Err(engine_unconfigured_text(lang, "PPLNS")),
            },
            ReadCommand::Stats => match address().await {
                Ok(addr) => Ok(super::read::build_stats(&self.pool, redis, lang, &addr).await),
                Err(reply) => Err(reply),
            },
            ReadCommand::ShowWorkers => match address().await {
                Ok(addr) => {
                    Ok(super::read::build_show_workers(&self.pool, redis, lang, &addr).await)
                }
                Err(reply) => Err(reply),
            },
            ReadCommand::TeamHistory => match address().await {
                Ok(addr) => Ok(super::read::build_group_history(&self.pool, lang, &addr).await),
                Err(reply) => Err(reply),
            },
            ReadCommand::BlockpartyStatus => match address().await {
                Ok(addr) => {
                    Ok(super::read::build_blockparty_status(&self.pool, redis, lang, &addr).await)
                }
                Err(reply) => Err(reply),
            },
            ReadCommand::PplnsStatus => match (&self.pplns_engine, address().await) {
                (None, _) => Err(engine_unconfigured_text(lang, "PPLNS")),
                (Some(_), Err(reply)) => Err(reply),
                (Some(engine), Ok(addr)) => {
                    Ok(super::read::build_pplns_status(redis, engine, lang, &addr).await)
                }
            },
            ReadCommand::TeamStatus => match (&self.group_solo_engine, address().await) {
                (None, _) => Err(engine_unconfigured_text(lang, team_mining_name(lang))),
                (Some(_), Err(reply)) => Err(reply),
                (Some(engine), Ok(addr)) => Ok(super::read::build_group_status(
                    &self.pool, redis, engine, lang, &addr,
                )
                .await),
            },
            ReadCommand::TeamMembers => match (&self.group_solo_engine, address().await) {
                (None, _) => Err(engine_unconfigured_text(lang, team_mining_name(lang))),
                (Some(_), Err(reply)) => Err(reply),
                (Some(engine), Ok(addr)) => {
                    Ok(super::read::build_group_members(&self.pool, engine, lang, &addr).await)
                }
            },
        };
        result.unwrap_or_else(|reply| reply)
    }

    /// Which of the given addresses are a member of a Team that is not
    /// dissolved, and which of those are its admin.
    async fn team_roles(&self, addresses: &[AddressId]) -> Result<TeamRoles, bp_db::DbError> {
        let mut roles = TeamRoles::default();
        for address in addresses {
            let Some(member) = find_group_member_by_address(&self.pool, address).await? else {
                continue;
            };
            let Some(group) = find_group(&self.pool, member.group_id).await? else {
                continue;
            };
            if group.dissolved_at.is_some() {
                continue;
            }
            roles.members.insert(address.clone());
            if group.creator_address == *address {
                roles.admins.insert(address.clone());
            }
        }
        Ok(roles)
    }

    /// An address argument as typed, or opened when it came encrypted.
    /// `Err` carries the reply that says what is wrong.
    fn address_arg(&self, lang: Language, raw: &str) -> Result<String, String> {
        if !looks_encrypted(raw) {
            return Ok(raw.to_string());
        }
        open_encrypted_address(self.message_key.as_deref(), raw)
            .map_err(|e| encrypted_address_text(lang, e))
    }

    /// An address argument as an address of the pool's network.
    fn pool_address(&self, lang: Language, raw: &str) -> Result<AddressId, String> {
        let raw = self.address_arg(lang, raw)?;
        bp_mining_job::parse_pool_address(self.network, &raw)
            .ok_or_else(|| invalid_address_text(lang).to_string())
    }

    /// The address a command acts on: the one it was given, else the
    /// origin's. `Err` carries the reply that explains what is missing.
    async fn target_address(
        &self,
        transport: &Transport,
        lang: Language,
        arg: Option<&str>,
    ) -> Result<AddressId, String> {
        if let Some(raw) = arg {
            return self.pool_address(lang, raw);
        }
        let chat_id = match transport {
            Transport::Ntfy { address } => return Ok(address.clone()),
            Transport::Telegram { chat_id } => *chat_id,
        };
        let subs = match find_telegram_subscriptions_by_chat(&self.pool, chat_id).await {
            Ok(subs) => subs,
            Err(e) => {
                warn!(target: "bp_notifications::command", error = %e, "origin address: read subs");
                return Err(db_error_text(lang).to_string());
            }
        };
        // The only subscription, else the default one.
        match subs.as_slice() {
            [] => Err(no_address_text(lang).to_string()),
            [only] => Ok(only.address.clone()),
            many => many
                .iter()
                .find(|s| s.is_default)
                .map(|s| s.address.clone())
                .ok_or_else(|| no_default_text(lang).to_string()),
        }
    }
}

/// The Team roles of a chat's addresses: who can get which Team notice.
#[derive(Default)]
struct TeamRoles {
    /// Members of a Team that is not dissolved: its round best.
    members: HashSet<AddressId>,
    /// Admins among them: their Team's join requests.
    admins: HashSet<AddressId>,
}

impl TeamRoles {
    /// Whether `/settings` shows `field` for `address`.
    fn offers(&self, field: SettingsField, address: &AddressId) -> bool {
        match field {
            SettingsField::TeamRequests => self.admins.contains(address),
            SettingsField::TeamBest => self.members.contains(address),
            SettingsField::Blocks
            | SettingsField::BestDiff
            | SettingsField::Device
            | SettingsField::HourlyStats
            | SettingsField::HourlyWorkers => true,
        }
    }

    /// The reply to a Team switch that no address of the chat can use.
    fn refusal(&self, switch: Switch, lang: Language) -> Option<&'static str> {
        match switch {
            Switch::TeamRequests if self.admins.is_empty() => Some(no_team_admin_text(lang)),
            Switch::TeamBest if self.members.is_empty() => Some(no_team_member_text(lang)),
            Switch::TeamRequests
            | Switch::TeamBest
            | Switch::BestDiff
            | Switch::Device
            | Switch::Hourly => None,
        }
    }
}

/// Write one switch of one Telegram subscription.
async fn set_telegram_field(
    pool: &PgPool,
    chat_id: i64,
    sub: &TelegramSubscriptionRow,
    field: SettingsField,
    value: bool,
) -> Result<u64, bp_db::DbError> {
    let address = &sub.address;
    match field {
        SettingsField::Blocks => {
            update_telegram_sub_block_flag(pool, chat_id, address, value).await
        }
        SettingsField::BestDiff => {
            update_telegram_sub_best_diff_flag(pool, chat_id, address, value).await
        }
        SettingsField::Device => {
            update_telegram_sub_device_flag(pool, chat_id, address, value).await
        }
        SettingsField::TeamRequests => {
            update_telegram_sub_group_admin_flag(pool, chat_id, address, value).await
        }
        SettingsField::TeamBest => {
            update_telegram_sub_team_best_flag(pool, chat_id, address, value).await
        }
        SettingsField::HourlyStats => {
            set_telegram_hourly_flags(pool, chat_id, address, value, sub.hourly_workers_enabled)
                .await
        }
        SettingsField::HourlyWorkers => {
            set_telegram_hourly_flags(pool, chat_id, address, sub.hourly_stats_enabled, value).await
        }
    }
}

fn settings_field_value(sub: &TelegramSubscriptionRow, field: SettingsField) -> bool {
    match field {
        SettingsField::Blocks => sub.block_notifications_enabled,
        SettingsField::BestDiff => sub.best_diff_notifications_enabled,
        SettingsField::Device => sub.device_notifications_enabled,
        SettingsField::TeamRequests => sub.group_admin_notifications_enabled,
        SettingsField::TeamBest => sub.team_best_notifications_enabled,
        SettingsField::HourlyStats => sub.hourly_stats_enabled,
        SettingsField::HourlyWorkers => sub.hourly_workers_enabled,
    }
}

fn set_settings_field_value(sub: &mut TelegramSubscriptionRow, field: SettingsField, value: bool) {
    let slot = match field {
        SettingsField::Blocks => &mut sub.block_notifications_enabled,
        SettingsField::BestDiff => &mut sub.best_diff_notifications_enabled,
        SettingsField::Device => &mut sub.device_notifications_enabled,
        SettingsField::TeamRequests => &mut sub.group_admin_notifications_enabled,
        SettingsField::TeamBest => &mut sub.team_best_notifications_enabled,
        SettingsField::HourlyStats => &mut sub.hourly_stats_enabled,
        SettingsField::HourlyWorkers => &mut sub.hourly_workers_enabled,
    };
    *slot = value;
}

fn settings_field_label(lang: Language, field: SettingsField) -> &'static str {
    match (lang, field) {
        (Language::De, SettingsField::Blocks) => "Blöcke",
        (Language::De, SettingsField::BestDiff) => "Best-Diff",
        (Language::De, SettingsField::Device) => "Geräte",
        (Language::De, SettingsField::TeamRequests) => "Team-Anfragen",
        (Language::De, SettingsField::TeamBest) => "Team-Best",
        (Language::De, SettingsField::HourlyStats) => "Stats stündl.",
        (Language::De, SettingsField::HourlyWorkers) => "Worker stündl.",
        (Language::En, SettingsField::Blocks) => "Blocks",
        (Language::En, SettingsField::BestDiff) => "Best diff",
        (Language::En, SettingsField::Device) => "Devices",
        (Language::En, SettingsField::TeamRequests) => "Team requests",
        (Language::En, SettingsField::TeamBest) => "Team best",
        (Language::En, SettingsField::HourlyStats) => "Hourly stats",
        (Language::En, SettingsField::HourlyWorkers) => "Hourly workers",
    }
}

fn engine_unconfigured_text(lang: Language, engine_name: &str) -> String {
    match lang {
        Language::De => format!("{engine_name}-Engine ist auf diesem Pool nicht konfiguriert."),
        Language::En => format!("{engine_name} engine is not configured on this pool."),
    }
}

/// The user-facing name of Group-Solo.
fn team_mining_name(lang: Language) -> &'static str {
    match lang {
        Language::De => "Team-Mining",
        Language::En => "Team Mining",
    }
}

// ── Per-language reply strings ───────────────────────────────────────

fn unknown_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Unbekannter Befehl. /help zeigt alle Befehle.",
        Language::En => "Unknown command. Use /help for the command list.",
    }
}

fn invalid_address_text(lang: Language) -> &'static str {
    match lang {
        Language::De => {
            "Das ist keine Bitcoin-Adresse dieses Pools. Schick sie so, wie sie \
             in deinem Miner steht, ohne Klammern, z.B. bc1q..."
        }
        Language::En => {
            "That is not a Bitcoin address of this pool. Send it as it stands \
             in your miner, without brackets, e.g. bc1q..."
        }
    }
}

fn subscribe_usage_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Schick /subscribe mit deiner Mining-Adresse, z.B. /subscribe bc1q...",
        Language::En => "Send /subscribe with your mining address, e.g. /subscribe bc1q...",
    }
}

fn remove_usage_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Schick /remove mit der Adresse, z.B. /remove bc1q...",
        Language::En => "Send /remove with the address, e.g. /remove bc1q...",
    }
}

/// Where to encrypt an address for the bot.
const ENCRYPTOR_URL: &str = "https://github.com/warioishere/blitzpool-message-encryptor-for-TG";

fn encryption_hint(lang: Language) -> String {
    match lang {
        Language::De => format!(
            "\n\n{}\nVerschlüssel sie im Dashboard unter {} oder mit dem Tool \
             {ENCRYPTOR_URL} und schick den Text statt der Adresse, z.B. nach /subscribe.",
            html::bold("Adresse lieber nicht im Klartext?"),
            html::bold("Telegram Bot")
        ),
        Language::En => format!(
            "\n\n{}\nEncrypt it in the dashboard under {} or with the tool \
             {ENCRYPTOR_URL} and send the text in place of the address, e.g. after /subscribe.",
            html::bold("Rather not show your address in plain text?"),
            html::bold("Telegram Bot")
        ),
    }
}

fn encrypted_address_text(lang: Language, error: EncryptedAddressError) -> String {
    let text = match (lang, error) {
        (Language::De, EncryptedAddressError::Incomplete { expected_len }) => {
            return format!(
                "Der verschlüsselte Text ist unvollständig angekommen. Kopier ihn ganz, er \
                 ist {expected_len} Zeichen lang und endet auf =."
            );
        }
        (Language::En, EncryptedAddressError::Incomplete { expected_len }) => {
            return format!(
                "The encrypted text arrived incomplete. Copy all of it: it is \
                 {expected_len} characters long and ends in =."
            );
        }
        (Language::De, EncryptedAddressError::NoKey) => {
            "Verschlüsselte Adressen kann dieser Pool gerade nicht lesen. Schick die \
             Adresse bitte unverschlüsselt."
        }
        (Language::De, EncryptedAddressError::Unreadable) => {
            "Die verschlüsselte Adresse lässt sich nicht öffnen. Verschlüssel sie neu \
             im Dashboard unter „Telegram Bot“ und schick den ganzen Text."
        }
        (Language::En, EncryptedAddressError::NoKey) => {
            "This pool cannot read encrypted addresses right now. Please send the \
             address unencrypted."
        }
        (Language::En, EncryptedAddressError::Unreadable) => {
            "The encrypted address cannot be opened. Encrypt it again in the \
             dashboard under “Telegram Bot” and send the whole text."
        }
    };
    text.to_string()
}

fn no_team_admin_text(lang: Language) -> &'static str {
    match lang {
        Language::De => {
            "Keine deiner Adressen ist Admin eines Teams. Beitrittsanfragen meldet der \
             Bot nur dem Admin des Teams."
        }
        Language::En => {
            "None of your addresses is the admin of a Team. The bot reports join \
             requests only to the Team's admin."
        }
    }
}

fn no_team_member_text(lang: Language) -> &'static str {
    match lang {
        Language::De => {
            "Keine deiner Adressen ist in einem Team. Den Bestwert der Team-Runde \
             meldet der Bot den Mitgliedern des Teams."
        }
        Language::En => {
            "None of your addresses is in a Team. The bot reports the best of a \
             Team's round to the Team's members."
        }
    }
}

/// Several subscriptions and none of them the default.
fn no_default_text(lang: Language) -> &'static str {
    match lang {
        Language::De => {
            "Du hast mehrere Adressen abonniert. Tipp bei /show_addresses eine an, \
             um sie zur Standard-Adresse zu machen, oder häng die Adresse an den Befehl an."
        }
        Language::En => {
            "You follow several addresses. Tap one in /show_addresses to make it \
             the default, or add the address to the command."
        }
    }
}

fn address_gone_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Adresse nicht mehr vorhanden.",
        Language::En => "Address no longer exists.",
    }
}

fn stale_button_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Dieses Menü gibt es nicht mehr, /settings zeigt die Einstellungen.",
        Language::En => "This menu is gone, /settings shows the settings.",
    }
}

fn db_error_text(lang: Language) -> &'static str {
    match lang {
        Language::De => "Datenbank-Fehler, bitte später noch einmal versuchen.",
        Language::En => "Database error, please try again later.",
    }
}

fn subscribe_ok_text(lang: Language, address: &AddressId) -> String {
    let address = html::addr(&short_address(address.as_str()));
    match lang {
        Language::De => {
            format!("✅ {address} abonniert.\nMit /settings schaltest du, was ich dir dazu melde.")
        }
        Language::En => {
            format!("✅ Following {address}.\n/settings switches what I tell you about it.")
        }
    }
}

fn remove_ok_text(lang: Language, address: &AddressId) -> String {
    let address = html::addr(&short_address(address.as_str()));
    match lang {
        Language::De => format!("{address} entfernt."),
        Language::En => format!("{address} removed."),
    }
}

fn remove_missing_text(lang: Language, address: &AddressId) -> String {
    let address = html::addr(&short_address(address.as_str()));
    match lang {
        Language::De => format!("{address} war nicht abonniert."),
        Language::En => format!("{address} was not followed."),
    }
}

/// No address given and none to fall back on.
fn no_address_text(lang: Language) -> &'static str {
    match lang {
        Language::De => {
            "Noch keine Adresse abonniert. /subscribe mit deiner Mining-Adresse abonniert \
             sie, oder häng die Adresse an den Befehl an, z.B. /stats bc1q..."
        }
        Language::En => {
            "No address subscribed yet. /subscribe with your mining address follows it, \
             or add the address to the command, e.g. /stats bc1q..."
        }
    }
}

/// The addresses, shortened like every address the bot shows.
fn list_addresses<'a>(lang: Language, addrs: impl Iterator<Item = &'a str>) -> String {
    let mut out = match lang {
        Language::De => html::bold("Abonnierte Adressen"),
        Language::En => html::bold("Followed addresses"),
    };
    for a in addrs {
        out.push_str("\n• ");
        out.push_str(&html::addr(&short_address(a)));
    }
    out
}

fn flag_toggle_ok_text(lang: Language, flag: Switch, value: bool) -> String {
    let on = value;
    match (lang, flag, on) {
        (Language::De, Switch::BestDiff, true) => "Best-Diff-Benachrichtigungen aktiviert.".into(),
        (Language::De, Switch::BestDiff, false) => {
            "Best-Diff-Benachrichtigungen deaktiviert.".into()
        }
        (Language::De, Switch::Device, true) => "Geräte-Benachrichtigungen aktiviert.".into(),
        (Language::De, Switch::Device, false) => "Geräte-Benachrichtigungen deaktiviert.".into(),
        (Language::De, Switch::Hourly, true) => "Stündliche Updates aktiviert.".into(),
        (Language::De, Switch::Hourly, false) => "Stündliche Updates deaktiviert.".into(),
        (Language::De, Switch::TeamRequests, true) => {
            "Benachrichtigungen über Team-Beitrittsanfragen aktiviert.".into()
        }
        (Language::De, Switch::TeamRequests, false) => {
            "Benachrichtigungen über Team-Beitrittsanfragen deaktiviert.".into()
        }
        (Language::De, Switch::TeamBest, true) => {
            "Benachrichtigungen über den Bestwert der Team-Runde aktiviert.".into()
        }
        (Language::De, Switch::TeamBest, false) => {
            "Benachrichtigungen über den Bestwert der Team-Runde deaktiviert.".into()
        }
        (Language::En, Switch::BestDiff, true) => "Best-difficulty notifications enabled.".into(),
        (Language::En, Switch::BestDiff, false) => "Best-difficulty notifications disabled.".into(),
        (Language::En, Switch::Device, true) => "Device notifications enabled.".into(),
        (Language::En, Switch::Device, false) => "Device notifications disabled.".into(),
        (Language::En, Switch::Hourly, true) => "Hourly updates enabled.".into(),
        (Language::En, Switch::Hourly, false) => "Hourly updates disabled.".into(),
        (Language::En, Switch::TeamRequests, true) => {
            "Team join-request notifications enabled.".into()
        }
        (Language::En, Switch::TeamRequests, false) => {
            "Team join-request notifications disabled.".into()
        }
        (Language::En, Switch::TeamBest, true) => {
            "Notifications of the Team round's best enabled.".into()
        }
        (Language::En, Switch::TeamBest, false) => {
            "Notifications of the Team round's best disabled.".into()
        }
    }
}

/// Resetting the best difficulty is a write for one address, so it happens
/// in the dashboard, behind that address's login; the bot only points there.
/// The link carries no address, so a group chat does not see it in full.
fn best_diff_reset_text(lang: Language, address: &AddressId, base_url: Option<&str>) -> String {
    let short = html::addr(&short_address(address.as_str()));
    let mut text = match lang {
        Language::De => format!(
            "Den Best-Diff von {short} setzt du im Dashboard zurück: Adresse öffnen, \
             einloggen, dann unter {}.",
            html::bold("Einstellungen")
        ),
        Language::En => format!(
            "Reset the best difficulty of {short} in the dashboard: open the address, \
             log in, then go to {}.",
            html::bold("Settings")
        ),
    };
    if let Some(base) = base_url {
        text.push('\n');
        text.push_str(base.trim_end_matches('/'));
    }
    text
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
    fn flag_toggle_text_covers_every_switch() {
        for flag in [
            Switch::BestDiff,
            Switch::Device,
            Switch::Hourly,
            Switch::TeamRequests,
        ] {
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

    /// Telegram refuses a message whose HTML it cannot parse, so every
    /// reply the handler writes must be valid HTML, in both languages.
    #[test]
    fn every_reply_is_valid_telegram_html() {
        let address = AddressId::new("bc1qtpa45phz26kays4hk63hcmxf9sty454wqjwcy8").unwrap();
        let subs = vec![sub_row(1, "bc1q<bc1q<odd>&address>", true)];
        for lang in [Language::De, Language::En] {
            let mut texts = vec![
                unknown_text(lang).to_string(),
                invalid_address_text(lang).to_string(),
                subscribe_usage_text(lang).to_string(),
                remove_usage_text(lang).to_string(),
                encryption_hint(lang),
                encrypted_address_text(lang, EncryptedAddressError::NoKey),
                encrypted_address_text(lang, EncryptedAddressError::Unreadable),
                encrypted_address_text(
                    lang,
                    EncryptedAddressError::Incomplete { expected_len: 684 },
                ),
                no_default_text(lang).to_string(),
                db_error_text(lang).to_string(),
                subscribe_ok_text(lang, &address),
                remove_ok_text(lang, &address),
                remove_missing_text(lang, &address),
                no_address_text(lang).to_string(),
                list_addresses(lang, ["bc1q<bc1q<odd>&address>"].into_iter()),
                best_diff_reset_text(lang, &address, Some("https://pool.example")),
                language_switch_ok_text(lang).to_string(),
                engine_unconfigured_text(lang, "PPLNS"),
                CommandHandler::build_address_keyboard(&subs, lang).0,
                CommandHandler::build_settings_keyboard(&subs, lang, &TeamRoles::default()).0,
                no_team_admin_text(lang).to_string(),
                no_team_member_text(lang).to_string(),
                super::super::help_text(lang),
            ];
            for switch in [
                Switch::BestDiff,
                Switch::Device,
                Switch::TeamRequests,
                Switch::TeamBest,
                Switch::Hourly,
            ] {
                for value in [true, false] {
                    texts.push(flag_toggle_ok_text(lang, switch, value));
                }
            }
            for text in texts {
                assert!(html::is_valid_telegram_html(&text), "{lang:?}: {text}");
            }
        }
    }

    #[test]
    fn subscribe_and_remove_replies_show_the_address_shortened() {
        let full = "bc1qtpa45phz26kays4hk63hcmxf9sty454wqjwcy8";
        let address = AddressId::new(full).unwrap();
        for lang in [Language::De, Language::En] {
            for text in [
                subscribe_ok_text(lang, &address),
                remove_ok_text(lang, &address),
                remove_missing_text(lang, &address),
            ] {
                assert!(
                    text.contains("bc1q...jwcy8") && !text.contains(full),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn list_addresses_shortens_each_address() {
        let full = "bc1qtpa45phz26kays4hk63hcmxf9sty454wqjwcy8";
        let s = list_addresses(Language::En, [full, "bc1qsecondaddressxxxxxx"].into_iter());
        assert!(html::is_valid_telegram_html(&s), "{s}");
        let s = html::to_plain(&s);
        assert!(s.starts_with("Followed addresses"), "{s}");
        assert!(s.contains("\n• bc1q...jwcy8"), "{s}");
        assert!(!s.contains(full), "{s}");
        assert_eq!(s.lines().count(), 3);
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
            group_admin_notifications_enabled: false,
            block_notifications_enabled: false,
            team_best_notifications_enabled: false,
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
    fn settings_keyboard_shows_each_switch_of_each_address() {
        let mut first = sub_row(2, "bc1qsecondaddressxxxxxx", false);
        first.hourly_workers_enabled = true;
        let subs = vec![first, sub_row(1, "bc1qfirstaddressxxxxxxx", true)];
        // Only the second address is in a Team, as its admin.
        let second = AddressId::new("bc1qsecondaddressxxxxxx").unwrap();
        let roles = TeamRoles {
            members: HashSet::from([second.clone()]),
            admins: HashSet::from([second]),
        };
        let (_text, kb) = CommandHandler::build_settings_keyboard(&subs, Language::En, &roles);
        // Per address: the address row and its switches, three a row,
        // ordered by id.
        assert_eq!(kb.len(), 7);
        assert!(kb[0][0].text.starts_with("⭐ "));
        assert_eq!(kb[0][0].callback_data, "st:1");
        // No Team switch for the address in no Team.
        let first_switches: Vec<&str> = kb[1]
            .iter()
            .chain(kb[2].iter())
            .map(|b| b.callback_data.as_str())
            .collect();
        assert_eq!(first_switches.len(), SettingsField::ALL.len() - 2);
        for field in [SettingsField::TeamRequests, SettingsField::TeamBest] {
            assert!(!first_switches.contains(&SettingsCallback::Flip(1, field).data().as_str()));
        }
        assert_eq!(kb[3][0].callback_data, "st:2");
        let switches: Vec<&InlineButton> = kb[4].iter().chain(&kb[5]).chain(&kb[6]).collect();
        assert_eq!((kb[4].len(), kb[5].len(), kb[6].len()), (3, 3, 1));
        assert_eq!(switches.len(), SettingsField::ALL.len());
        for (button, field) in switches.iter().zip(SettingsField::ALL) {
            assert_eq!(
                button.callback_data,
                SettingsCallback::Flip(2, field).data()
            );
            let on = field == SettingsField::HourlyWorkers;
            assert_eq!(button.text.starts_with('✅'), on, "{}", button.text);
        }
    }

    async fn subscribed_chat(pool: &PgPool, chat_id: i64, addresses: &[&str]) {
        sqlx::query(r#"DELETE FROM telegram_subscriptions_entity WHERE "telegramChatId" = $1"#)
            .bind(chat_id)
            .execute(pool)
            .await
            .unwrap();
        for a in addresses {
            upsert_telegram_subscription(pool, chat_id, &AddressId::new(*a).unwrap())
                .await
                .unwrap();
        }
    }

    /// Removing the default by command leaves another default, like the
    /// 🗑 button does; a chat that still has none is told how to pick one.
    #[tokio::test]
    async fn removing_the_default_by_command_keeps_a_default() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let chat_id = -7_700_101;
        let transport = Transport::Telegram { chat_id };
        let handler = CommandHandler::new(pool.clone(), Network::Bitcoin, None, None);
        let (a, b, c) = ("bc1qremovetesta", "bc1qremovetestb", "bc1qremovetestc");
        // The last subscribed address is the default.
        subscribed_chat(&pool, chat_id, &[a, b, c]).await;
        handler.handle_remove(&transport, Language::En, c).await;
        let origin = handler.target_address(&transport, Language::En, None).await;
        assert_eq!(origin.map(AddressId::into_inner), Ok(a.to_string()));

        sqlx::query(r#"UPDATE telegram_subscriptions_entity SET "isDefault" = false WHERE "telegramChatId" = $1"#)
            .bind(chat_id)
            .execute(&pool)
            .await
            .unwrap();
        let origin = handler.target_address(&transport, Language::En, None).await;
        assert_eq!(origin, Err(no_default_text(Language::En).to_string()));

        subscribed_chat(&pool, chat_id, &[]).await;
        let origin = handler.target_address(&transport, Language::En, None).await;
        assert_eq!(origin, Err(no_address_text(Language::En).to_string()));
    }

    /// Only a Team's creator, while the Team is not dissolved, admins it:
    /// `/team_requests` tells everyone else, and switches nothing for them.
    /// `/team_bestdiff` is for every member, and refused to an address in
    /// no Team.
    #[tokio::test]
    async fn team_switches_follow_the_team_role() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let (admin, member, outsider) = (
            AddressId::new("bc1qteamrequestadmin").unwrap(),
            AddressId::new("bc1qteamrequestmember").unwrap(),
            AddressId::new("bc1qteamrequestoutsider").unwrap(),
        );
        // A run that stopped before its cleanup leaves its Team behind.
        sqlx::query("DELETE FROM pplns_group_member WHERE address = ANY($1)")
            .bind(vec![admin.as_str(), member.as_str()])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pplns_group WHERE name LIKE 'bp-test-requests-%'")
            .execute(&pool)
            .await
            .unwrap();
        // Fresh topics: a soft-deleted row from an earlier run would come
        // back with its old switches.
        let everyone = [admin.clone(), member.clone(), outsider.clone()];
        let delete_topics = || {
            sqlx::query("DELETE FROM ntfy_subscriptions_entity WHERE address = ANY($1)")
                .bind(everyone.iter().map(AddressId::as_str).collect::<Vec<_>>())
                .execute(&pool)
        };
        delete_topics().await.unwrap();
        for address in &everyone {
            upsert_ntfy_subscription(&pool, address).await.unwrap();
        }
        let group_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now().timestamp_millis();
        bp_db::insert_pplns_group(
            &pool,
            group_id,
            &format!("bp-test-requests-{group_id}"),
            &admin,
            "hash",
            true,
            false,
            "prop",
            now,
        )
        .await
        .unwrap();
        for (address, role) in [(&admin, "creator"), (&member, "member")] {
            bp_db::insert_pplns_group_member(&pool, group_id, address, role, now)
                .await
                .unwrap();
        }
        let handler = CommandHandler::new(pool.clone(), Network::Bitcoin, None, None);
        let refused = no_team_admin_text(Language::En).to_string();
        let not_member = no_team_member_text(Language::En).to_string();
        let on = |address: &AddressId| Transport::Ntfy {
            address: address.clone(),
        };

        let roles = handler
            .team_roles(&[admin.clone(), member.clone(), outsider.clone()])
            .await
            .unwrap();
        assert_eq!(roles.admins, HashSet::from([admin.clone()]));
        assert_eq!(
            roles.members,
            HashSet::from([admin.clone(), member.clone()])
        );
        assert!(roles.offers(SettingsField::TeamBest, &member));
        assert!(!roles.offers(SettingsField::TeamRequests, &member));
        assert!(!roles.offers(SettingsField::TeamBest, &outsider));
        assert_eq!(
            handler
                .ntfy_settings_text(&outsider, Language::En, Some(Switch::TeamBest))
                .await,
            not_member
        );
        assert_eq!(
            handler
                .handle_flag_toggle(
                    &on(&outsider),
                    Language::En,
                    Switch::TeamBest,
                    FlagToggle::On
                )
                .await,
            not_member
        );
        // Each address sees the Team switches its role gives it.
        let label = |field| settings_field_label(Language::En, field);
        for (address, requests, best) in [
            (&admin, true, true),
            (&member, false, true),
            (&outsider, false, false),
        ] {
            let text = handler
                .ntfy_settings_text(address, Language::En, None)
                .await;
            assert_eq!(
                text.contains(label(SettingsField::TeamRequests)),
                requests,
                "{text}"
            );
            assert_eq!(
                text.contains(label(SettingsField::TeamBest)),
                best,
                "{text}"
            );
        }
        let team_best = || async {
            find_ntfy_subscription_by_address(&pool, &member)
                .await
                .unwrap()
                .unwrap()
                .team_best_notifications_enabled
        };
        assert!(team_best().await, "on before the switch");
        assert_eq!(
            handler
                .handle_flag_toggle(
                    &on(&member),
                    Language::En,
                    Switch::TeamBest,
                    FlagToggle::Off
                )
                .await,
            flag_toggle_ok_text(Language::En, Switch::TeamBest, false)
        );
        assert!(!team_best().await);
        assert_eq!(
            handler
                .handle_flag_toggle(
                    &on(&member),
                    Language::En,
                    Switch::TeamRequests,
                    FlagToggle::On
                )
                .await,
            refused
        );
        assert_eq!(
            handler
                .ntfy_settings_text(&member, Language::En, Some(Switch::TeamRequests))
                .await,
            refused
        );
        assert_ne!(
            handler
                .ntfy_settings_text(&admin, Language::En, Some(Switch::TeamRequests))
                .await,
            refused
        );

        bp_db::update_pplns_group_dissolved(&pool, group_id, now)
            .await
            .unwrap();
        let roles = handler
            .team_roles(std::slice::from_ref(&admin))
            .await
            .unwrap();
        assert!(roles.admins.is_empty() && roles.members.is_empty());

        bp_db::delete_pplns_group_members_for_group(&pool, group_id)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pplns_group WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await
            .unwrap();
        delete_topics().await.unwrap();
    }

    /// An address sent encrypted is subscribed once the key opens it;
    /// without the key the bot says it cannot read it. The welcome text
    /// mentions encryption only when the key is there.
    #[tokio::test]
    async fn an_encrypted_address_is_subscribed_with_the_key() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let chat_id = -7_700_401;
        let transport = Transport::Telegram { chat_id };
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let (key, encrypt) = super::super::encrypted_address::test_key();
        let sent = encrypt(address);
        subscribed_chat(&pool, chat_id, &[]).await;

        let without = CommandHandler::new(pool.clone(), Network::Bitcoin, None, None);
        assert_eq!(
            without
                .handle_subscribe(&transport, Language::En, &sent)
                .await,
            encrypted_address_text(Language::En, EncryptedAddressError::NoKey)
        );
        assert!(!without
            .handle_start(&transport, Language::De)
            .await
            .contains(ENCRYPTOR_URL));

        let with = CommandHandler::new(pool.clone(), Network::Bitcoin, None, None)
            .with_message_key(Some(key));
        let reply = with.handle_subscribe(&transport, Language::En, &sent).await;
        assert!(
            reply.contains("bc1q...8f3t4") && !reply.contains(address),
            "{reply}"
        );
        let stored: Vec<String> = find_telegram_subscriptions_by_chat(&pool, chat_id)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.address.into_inner())
            .collect();
        assert_eq!(stored, vec![address.to_string()]);
        assert!(with
            .handle_start(&transport, Language::De)
            .await
            .contains(ENCRYPTOR_URL));

        subscribed_chat(&pool, chat_id, &[]).await;
    }

    /// A chat without an address is told to subscribe; one with addresses
    /// sees them instead.
    #[tokio::test]
    async fn start_points_a_new_chat_at_subscribe() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let chat_id = -7_700_301;
        let transport = Transport::Telegram { chat_id };
        let handler = CommandHandler::new(pool.clone(), Network::Bitcoin, None, None);
        subscribed_chat(&pool, chat_id, &[]).await;
        let fresh = handler.handle_start(&transport, Language::De).await;
        assert!(html::is_valid_telegram_html(&fresh), "{fresh}");
        let fresh = html::to_plain(&fresh);
        assert!(fresh.contains("Tipp /subscribe"), "{fresh}");
        assert!(!fresh.contains("Abonnierte Adressen"), "{fresh}");

        subscribed_chat(&pool, chat_id, &["bc1qstarttestaddress"]).await;
        let known = handler.handle_start(&transport, Language::En).await;
        assert!(html::is_valid_telegram_html(&known), "{known}");
        let known = html::to_plain(&known);
        assert!(!known.contains("/subscribe"), "{known}");
        assert!(known.contains("\n• bc1q...dress"), "{known}");

        subscribed_chat(&pool, chat_id, &[]).await;
    }

    /// A private chat answers with its next plain message; a group only by
    /// replying to the question. An expired question takes no answer, and an
    /// answer is taken once.
    #[tokio::test]
    async fn an_answer_to_the_subscribe_question_subscribes() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let (private_chat, group_chat) = (7_700_201, -7_700_202);
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let handler = CommandHandler::new(pool.clone(), Network::Bitcoin, None, None);
        let subscribed = |chat_id: i64| {
            let pool = pool.clone();
            async move {
                find_telegram_subscriptions_by_chat(&pool, chat_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|s| s.address.into_inner())
                    .collect::<Vec<_>>()
            }
        };
        let ask = |chat_id: i64, expires_in: i64| {
            let handler = &handler;
            async move {
                let now = chrono::Utc::now().timestamp_millis();
                handler.subscribe_questions.lock().await.insert(
                    chat_id,
                    OpenQuestion {
                        message_id: 10,
                        expires_at_ms: now + expires_in,
                    },
                );
            }
        };
        let msg = |chat_id: i64, private: bool, reply_to: Option<i64>| PlainMessage {
            chat_id,
            private,
            reply_to,
        };
        for chat in [private_chat, group_chat] {
            subscribed_chat(&pool, chat, &[]).await;
        }

        // Private: no reply needed, a reply to another message is not it.
        ask(private_chat, QUESTION_TTL_MS).await;
        assert!(
            !handler
                .answer_telegram_question(msg(private_chat, true, Some(99)), address)
                .await
        );
        assert!(
            handler
                .answer_telegram_question(msg(private_chat, true, None), &format!("{address} x"))
                .await
        );
        assert_eq!(subscribed(private_chat).await, vec![address.to_string()]);
        assert!(
            !handler
                .answer_telegram_question(msg(private_chat, true, None), address)
                .await,
            "taken once"
        );

        // Group: only a reply to the question.
        ask(group_chat, QUESTION_TTL_MS).await;
        assert!(
            !handler
                .answer_telegram_question(msg(group_chat, false, None), address)
                .await
        );
        assert!(subscribed(group_chat).await.is_empty());
        assert!(
            handler
                .answer_telegram_question(msg(group_chat, false, Some(10)), address)
                .await
        );
        assert_eq!(subscribed(group_chat).await, vec![address.to_string()]);

        // Expired.
        subscribed_chat(&pool, private_chat, &[]).await;
        ask(private_chat, -1).await;
        assert!(
            !handler
                .answer_telegram_question(msg(private_chat, true, None), address)
                .await
        );
        assert!(subscribed(private_chat).await.is_empty());

        for chat in [private_chat, group_chat] {
            subscribed_chat(&pool, chat, &[]).await;
        }
    }

    #[test]
    fn bestdiff_reset_points_at_the_dashboard_without_the_address() {
        let address = AddressId::new("bc1qresetlinkaddress").unwrap();
        let text = best_diff_reset_text(Language::En, &address, Some("https://pool.example/"));
        assert!(text.ends_with("\nhttps://pool.example"), "{text}");
        assert!(!text.contains(address.as_str()), "{text}");
        assert!(!best_diff_reset_text(Language::De, &address, None).contains("http"));
    }
}
