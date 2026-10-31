// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bot-command parsing + dispatch. Telegram and ntfy share one [`Command`]
//! surface; [`CommandHandler`] replies through the [`Transport`] the command
//! arrived on.

mod chat_language;
mod encrypted_address;
mod handler;
mod menu;
mod parser;
pub(crate) mod read;

pub use chat_language::ChatLanguages;
pub use encrypted_address::MessageKey;
pub use handler::{CommandHandler, PlainMessage, Transport};
pub(crate) use menu::help_text;
pub use menu::register_command_menu;
pub use parser::{
    parse_address_callback, parse_command, parse_settings_callback, AddressCallback, Command,
    FlagToggle, LanguageSwitch, ReadCommand, SettingsCallback, SettingsField, Switch,
};
