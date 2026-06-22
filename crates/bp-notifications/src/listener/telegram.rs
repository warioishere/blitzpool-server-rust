// SPDX-License-Identifier: AGPL-3.0-or-later

//! Telegram long-poll loop.
//!
//! Calls `getUpdates` with a running `offset` so each update is
//! processed exactly once. Per-update text → [`parse_command`] →
//! [`CommandHandler::dispatch`]; inline-button taps arrive as
//! `callback_query` updates and go to
//! [`CommandHandler::handle_telegram_callback`].

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::command::{parse_command, CommandHandler, Transport};

#[derive(Debug, Clone)]
pub struct TelegramListenerConfig {
    /// Bot token — same token as the [`crate::adapter::TelegramAdapter`]
    /// uses for outbound. Could be pulled into a shared `TelegramConfig`
    /// later if both consumers grow.
    pub bot_token: String,
    /// Long-poll timeout in seconds (Telegram caps at 50; default 30).
    pub long_poll_timeout_seconds: u32,
}

impl TelegramListenerConfig {
    pub fn new(bot_token: String) -> Self {
        Self {
            bot_token,
            long_poll_timeout_seconds: 30,
        }
    }
}

/// Spawn the polling loop on the current tokio runtime. Returns a
/// shutdown handle — drop it (or send `true`) to stop the loop after
/// the next iteration. The loop is resilient to transient HTTP errors;
/// it sleeps 5 s and retries.
pub fn spawn_telegram_listener(
    config: TelegramListenerConfig,
    handler: Arc<CommandHandler>,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let client = match Client::builder()
            // `timeout` must outlast the long-poll timeout or we'll
            // cancel the poll prematurely; pad by 10 s.
            .timeout(Duration::from_secs(
                (config.long_poll_timeout_seconds as u64) + 10,
            ))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(target: "bp_notifications::listener::telegram", error = %e, "client build failed");
                return;
            }
        };
        let base = format!("https://api.telegram.org/bot{}", config.bot_token);
        let mut offset: i64 = 0;
        info!(target: "bp_notifications::listener::telegram", "polling started");
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                result = poll_once(&client, &base, offset, config.long_poll_timeout_seconds) => {
                    match result {
                        Ok(updates) => {
                            for update in updates {
                                if let Some(next) = process_update(&handler, update).await {
                                    if next > offset {
                                        offset = next;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(target: "bp_notifications::listener::telegram", error = %e, "poll failed, backing off");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
        }
        info!(target: "bp_notifications::listener::telegram", "polling stopped");
    });
    shutdown_tx
}

async fn poll_once(
    client: &Client,
    base: &str,
    offset: i64,
    timeout_secs: u32,
) -> Result<Vec<Update>, String> {
    let url = format!("{base}/getUpdates");
    let mut req = client
        .get(&url)
        .query(&[("timeout", timeout_secs as i64), ("offset", offset)]);
    // `callback_query` is in the allow-list so we acknowledge each
    // one and stop the spinner client-side. The actual per-button
    // flows (group-select keyboards, etc.) still need their own
    // dispatch path and are deferred.
    req = req.query(&[("allowed_updates", "[\"message\",\"callback_query\"]")]);

    let resp = req
        .send()
        .await
        .map_err(|e| format!("getUpdates request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("getUpdates status {}", resp.status().as_u16()));
    }
    let body: GetUpdatesResponse = resp
        .json()
        .await
        .map_err(|e| format!("getUpdates body: {e}"))?;
    if !body.ok {
        return Err(format!(
            "getUpdates ok=false: {}",
            body.description.unwrap_or_else(|| "no description".into())
        ));
    }
    Ok(body.result)
}

async fn process_update(handler: &CommandHandler, update: Update) -> Option<i64> {
    let next_offset = update.update_id + 1;
    if let Some(message) = update.message {
        if let Some(text) = message.text {
            let command = parse_command(&text);
            debug!(
                target: "bp_notifications::listener::telegram",
                chat_id = message.chat.id,
                ?command,
                "incoming command"
            );
            let transport = Transport::Telegram {
                chat_id: message.chat.id,
            };
            handler.dispatch(&transport, &command).await;
        }
    }
    if let Some(callback) = update.callback_query {
        debug!(
            target: "bp_notifications::listener::telegram",
            id = %callback.id,
            data = ?callback.data,
            "callback_query received"
        );
        // The handler answers the query (stops the spinner) and runs the
        // matching inline-keyboard flow via the Telegram adapter.
        let (chat_id, message_id) = match callback.message {
            Some(m) => (Some(m.chat.id), Some(m.message_id)),
            None => (None, None),
        };
        handler
            .handle_telegram_callback(&callback.id, chat_id, message_id, callback.data.as_deref())
            .await;
    }
    Some(next_offset)
}

#[derive(Debug, Deserialize)]
struct GetUpdatesResponse {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    result: Vec<Update>,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id: i64,
    message: Option<Message>,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct Message {
    chat: Chat,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    #[serde(default)]
    data: Option<String>,
    /// The message the inline keyboard is attached to — carries the
    /// `chat.id` + `message_id` needed to edit it in place.
    #[serde(default)]
    message: Option<CallbackMessage>,
}

#[derive(Debug, Deserialize)]
struct CallbackMessage {
    chat: Chat,
    message_id: i64,
}
