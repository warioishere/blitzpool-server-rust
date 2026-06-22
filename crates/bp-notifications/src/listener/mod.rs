// SPDX-License-Identifier: AGPL-3.0-or-later

//! Long-running inbound listeners — Telegram long-poll loop + ntfy
//! SSE listener. Both consume their respective transport and call
//! into [`crate::command::CommandHandler::dispatch`] for every command
//! they observe.

mod ntfy;
mod telegram;

pub use ntfy::{spawn_ntfy_listener, NtfyListenerConfig};
pub use telegram::{spawn_telegram_listener, TelegramListenerConfig};
