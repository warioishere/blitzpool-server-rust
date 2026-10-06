// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bot-command parsing + dispatch. Telegram and ntfy share one [`Command`]
//! surface; [`CommandHandler`] replies through the [`Transport`] the command
//! arrived on.

mod handler;
mod menu;
mod parser;
pub(crate) mod read;

pub use handler::{ChatLanguageMap, CommandHandler, Transport};
pub use menu::register_command_menu;
pub use parser::{
    parse_address_callback, parse_bestdiff_callback, parse_command, parse_hourly_callback,
    AddressCallback, Command, FlagToggle, HourlyTarget, LanguageSwitch,
};
