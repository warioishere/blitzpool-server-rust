// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parse the leading bot-command from a raw user message.
//!
//! Subscription-management commands: /start, /subscribe, /remove,
//! /show_addresses, /subscribe_bestdiff, /device_notifications,
//! /send_hourly, /bestdiff_reset, /deutsch, /english.
//!
//! Read commands (/stats, /show_workers, /poolhashrate, /difficulty,
//! /next_difficulty, /pplns_status, /group_status) require engine
//! readers — the parser recognises them and emits the
//! [`Command::ReadDeferred`] variant so the handler can return a polite
//! "noch nicht verfügbar" reply instead of "unbekannter Befehl".

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Start,
    /// `/subscribe <address>` — add a mining-address subscription.
    Subscribe {
        address: String,
    },
    /// `/remove <address>` — soft-delete a mining-address subscription.
    Remove {
        address: String,
    },
    ShowAddresses,
    /// `/subscribe_bestdiff on|off` — best-diff push toggle.
    BestDiffToggle(FlagToggle),
    /// `/device_notifications on|off` — device-status push toggle.
    DeviceToggle(FlagToggle),
    /// `/send_hourly on|off` — hourly stats + workers push toggle (both).
    HourlyToggle(FlagToggle),
    /// `/send_hourly` with no on|off arg — open the inline toggle menu.
    HourlyMenu,
    /// `/bestdiff_reset [<address>]` — set persisted best back to 0.
    BestDiffReset {
        address: Option<String>,
    },
    /// `/deutsch` or `/english` — switch reply language.
    LanguageSwitch(LanguageSwitch),
    /// `/help` or any unknown command — handler replies with usage.
    Help,
    /// Recognised read command that needs engine readers. Carries the
    /// command name for a "noch nicht verfügbar" diagnostic.
    ReadDeferred(&'static str),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagToggle {
    On,
    Off,
}

impl FlagToggle {
    pub fn as_bool(self) -> bool {
        matches!(self, FlagToggle::On)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageSwitch {
    De,
    En,
}

/// A parsed `addr:` inline-keyboard tap from the `/show_addresses`
/// keyboard. Carries the subscription row id the button referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressCallback {
    /// `addr:set:<id>` — make subscription `id` the chat's default.
    SetDefault(i32),
    /// `addr:rm:<id>` — remove subscription `id`.
    Remove(i32),
}

/// Parse an `addr:set:<id>` / `addr:rm:<id>` callback payload. Returns
/// `None` for any other shape (unknown action, non-numeric id, …).
pub fn parse_address_callback(data: &str) -> Option<AddressCallback> {
    let rest = data.strip_prefix("addr:")?;
    let (action, id_str) = rest.split_once(':')?;
    let id: i32 = id_str.parse().ok()?;
    match action {
        "set" => Some(AddressCallback::SetDefault(id)),
        "rm" => Some(AddressCallback::Remove(id)),
        _ => None,
    }
}

/// Which flag an `hr:` hourly-menu button toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HourlyTarget {
    Stats,
    Workers,
}

/// Parse an `hr:stats` / `hr:workers` hourly-menu callback payload.
pub fn parse_hourly_callback(data: &str) -> Option<HourlyTarget> {
    match data {
        "hr:stats" => Some(HourlyTarget::Stats),
        "hr:workers" => Some(HourlyTarget::Workers),
        _ => None,
    }
}

/// Parse a `bdr:yes` / `bdr:no` best-difficulty-reset confirmation tap.
/// `Some(true)` = confirm, `Some(false)` = cancel.
pub fn parse_bestdiff_callback(data: &str) -> Option<bool> {
    match data {
        "bdr:yes" => Some(true),
        "bdr:no" => Some(false),
        _ => None,
    }
}

const READ_COMMANDS: &[&str] = &[
    "/stats",
    "/show_workers",
    "/poolhashrate",
    "/difficulty",
    "/next_difficulty",
    "/pplns_status",
    "/group_status",
    "/pplns_top",
    "/group_members",
    "/group_history",
];

/// Parse the *first whitespace-delimited token* of `text` (case-insensitive)
/// as a command, and the remainder as its arguments. Returns
/// [`Command::Unknown`] when the first token doesn't start with `/`.
pub fn parse_command(text: &str) -> Command {
    let trimmed = text.trim();
    let mut iter = trimmed.split_whitespace();
    let head = match iter.next() {
        Some(s) => s,
        None => return Command::Unknown,
    };
    if !head.starts_with('/') {
        return Command::Unknown;
    }
    // Strip any `@BotName` suffix Telegram tacks onto commands in groups.
    let cmd = head.split('@').next().unwrap_or(head).to_ascii_lowercase();
    let arg = iter.next().unwrap_or("").trim();

    match cmd.as_str() {
        "/start" => Command::Start,
        "/help" => Command::Help,
        "/subscribe" => {
            if arg.is_empty() {
                Command::Unknown
            } else {
                Command::Subscribe {
                    address: arg.to_string(),
                }
            }
        }
        "/remove" => {
            if arg.is_empty() {
                Command::Unknown
            } else {
                Command::Remove {
                    address: arg.to_string(),
                }
            }
        }
        "/show_addresses" => Command::ShowAddresses,
        "/subscribe_bestdiff" => parse_toggle(arg)
            .map(Command::BestDiffToggle)
            .unwrap_or(Command::Unknown),
        "/device_notifications" => parse_toggle(arg)
            .map(Command::DeviceToggle)
            .unwrap_or(Command::Unknown),
        // `/send_hourly on|off` flips both flags; bare `/send_hourly`
        // (or any non-on|off arg) opens the inline toggle menu.
        "/send_hourly" => parse_toggle(arg)
            .map(Command::HourlyToggle)
            .unwrap_or(Command::HourlyMenu),
        "/bestdiff_reset" => Command::BestDiffReset {
            address: if arg.is_empty() {
                None
            } else {
                Some(arg.to_string())
            },
        },
        "/deutsch" => Command::LanguageSwitch(LanguageSwitch::De),
        "/english" => Command::LanguageSwitch(LanguageSwitch::En),
        other => {
            if let Some(name) = READ_COMMANDS.iter().find(|c| **c == other) {
                Command::ReadDeferred(name)
            } else {
                Command::Unknown
            }
        }
    }
}

fn parse_toggle(arg: &str) -> Option<FlagToggle> {
    match arg.to_ascii_lowercase().as_str() {
        "on" | "an" | "ein" | "true" | "1" => Some(FlagToggle::On),
        "off" | "aus" | "false" | "0" => Some(FlagToggle::Off),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_unknown() {
        assert_eq!(parse_command(""), Command::Unknown);
        assert_eq!(parse_command("   "), Command::Unknown);
    }

    #[test]
    fn no_slash_is_unknown() {
        assert_eq!(parse_command("hello"), Command::Unknown);
    }

    #[test]
    fn start_parses() {
        assert_eq!(parse_command("/start"), Command::Start);
        assert_eq!(parse_command("/START"), Command::Start);
        assert_eq!(parse_command("/start@MyBot"), Command::Start);
    }

    #[test]
    fn subscribe_needs_argument() {
        assert_eq!(parse_command("/subscribe"), Command::Unknown);
        assert_eq!(
            parse_command("/subscribe bc1qxyz"),
            Command::Subscribe {
                address: "bc1qxyz".to_string()
            }
        );
    }

    #[test]
    fn remove_needs_argument() {
        assert_eq!(parse_command("/remove"), Command::Unknown);
        assert_eq!(
            parse_command("/remove bc1qxyz"),
            Command::Remove {
                address: "bc1qxyz".to_string()
            }
        );
    }

    #[test]
    fn toggles_recognise_variants() {
        assert_eq!(
            parse_command("/subscribe_bestdiff on"),
            Command::BestDiffToggle(FlagToggle::On)
        );
        assert_eq!(
            parse_command("/subscribe_bestdiff OFF"),
            Command::BestDiffToggle(FlagToggle::Off)
        );
        assert_eq!(
            parse_command("/device_notifications an"),
            Command::DeviceToggle(FlagToggle::On)
        );
        assert_eq!(
            parse_command("/send_hourly aus"),
            Command::HourlyToggle(FlagToggle::Off)
        );
    }

    #[test]
    fn toggle_without_arg_is_unknown() {
        assert_eq!(parse_command("/subscribe_bestdiff"), Command::Unknown);
        assert_eq!(parse_command("/subscribe_bestdiff maybe"), Command::Unknown);
    }

    #[test]
    fn language_switch_parses() {
        assert_eq!(
            parse_command("/deutsch"),
            Command::LanguageSwitch(LanguageSwitch::De)
        );
        assert_eq!(
            parse_command("/english"),
            Command::LanguageSwitch(LanguageSwitch::En)
        );
    }

    #[test]
    fn bestdiff_reset_optional_address() {
        assert_eq!(
            parse_command("/bestdiff_reset"),
            Command::BestDiffReset { address: None }
        );
        assert_eq!(
            parse_command("/bestdiff_reset bc1qxyz"),
            Command::BestDiffReset {
                address: Some("bc1qxyz".to_string())
            }
        );
    }

    #[test]
    fn read_commands_are_marked_deferred() {
        assert_eq!(parse_command("/stats"), Command::ReadDeferred("/stats"));
        assert_eq!(
            parse_command("/poolhashrate"),
            Command::ReadDeferred("/poolhashrate")
        );
    }

    #[test]
    fn truly_unknown_command_is_unknown() {
        assert_eq!(parse_command("/banana"), Command::Unknown);
    }

    #[test]
    fn parses_address_callbacks() {
        assert_eq!(
            parse_address_callback("addr:set:7"),
            Some(AddressCallback::SetDefault(7))
        );
        assert_eq!(
            parse_address_callback("addr:rm:42"),
            Some(AddressCallback::Remove(42))
        );
        // Wrong prefix, unknown action, non-numeric id → None.
        assert_eq!(parse_address_callback("hr:stats"), None);
        assert_eq!(parse_address_callback("addr:flip:1"), None);
        assert_eq!(parse_address_callback("addr:set:abc"), None);
    }

    #[test]
    fn send_hourly_arg_toggles_else_opens_menu() {
        assert_eq!(
            parse_command("/send_hourly on"),
            Command::HourlyToggle(FlagToggle::On)
        );
        assert_eq!(
            parse_command("/send_hourly off"),
            Command::HourlyToggle(FlagToggle::Off)
        );
        assert_eq!(parse_command("/send_hourly"), Command::HourlyMenu);
        assert_eq!(parse_command("/send_hourly foo"), Command::HourlyMenu);
    }

    #[test]
    fn parses_hourly_callbacks() {
        assert_eq!(parse_hourly_callback("hr:stats"), Some(HourlyTarget::Stats));
        assert_eq!(
            parse_hourly_callback("hr:workers"),
            Some(HourlyTarget::Workers)
        );
        assert_eq!(parse_hourly_callback("hr:other"), None);
        assert_eq!(parse_hourly_callback("addr:set:1"), None);
    }

    #[test]
    fn parses_bestdiff_callbacks() {
        assert_eq!(parse_bestdiff_callback("bdr:yes"), Some(true));
        assert_eq!(parse_bestdiff_callback("bdr:no"), Some(false));
        assert_eq!(parse_bestdiff_callback("bdr:maybe"), None);
        assert_eq!(parse_bestdiff_callback("hr:stats"), None);
    }
}
