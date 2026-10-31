// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parse the leading bot-command from a raw user message. Read commands
//! (`/stats`, `/pplns_status`, ...) come out as [`Command::Read`], so the
//! handler alone decides how to answer them.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Start,
    /// `/subscribe [<address>]`: add a mining-address subscription; bare,
    /// explain how.
    Subscribe {
        address: Option<String>,
    },
    /// `/remove [<address>]`: soft-delete a mining-address subscription;
    /// bare, offer the stored addresses.
    Remove {
        address: Option<String>,
    },
    ShowAddresses,
    /// `/settings`, or a switch command without on|off (which one rides
    /// along): every switch of every subscribed address.
    Settings(Option<Switch>),
    /// A switch command with on|off, applied to every subscribed address.
    Toggle(Switch, FlagToggle),
    /// `/bestdiff_reset [<address>]`: a link to where that happens.
    BestDiffReset {
        address: Option<String>,
    },
    /// `/deutsch` or `/english` — switch reply language.
    LanguageSwitch(LanguageSwitch),
    Help,
    /// A command that answers with data about the pool or an address,
    /// with the address it was given, if any.
    Read(ReadCommand, Option<String>),
    Unknown,
}

/// What a switch command turns on or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    /// `/subscribe_bestdiff`
    BestDiff,
    /// `/device_notifications`
    Device,
    /// `/team_requests`: a Team admin's join-request notice.
    TeamRequests,
    /// `/team_bestdiff`: a Team member's notice of a new round best.
    TeamBest,
    /// `/send_hourly`: hourly stats and workers together.
    Hourly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadCommand {
    Stats,
    ShowWorkers,
    PoolHashrate,
    Difficulty,
    NextDifficulty,
    PplnsStatus,
    TeamStatus,
    PplnsTop,
    TeamMembers,
    TeamHistory,
    BlockpartyStatus,
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

/// One switch of one subscription in the `/settings` keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Blocks,
    BestDiff,
    Device,
    TeamRequests,
    TeamBest,
    HourlyStats,
    HourlyWorkers,
}

impl SettingsField {
    pub const ALL: [SettingsField; 7] = [
        SettingsField::Blocks,
        SettingsField::BestDiff,
        SettingsField::Device,
        SettingsField::TeamRequests,
        SettingsField::TeamBest,
        SettingsField::HourlyStats,
        SettingsField::HourlyWorkers,
    ];

    fn code(self) -> &'static str {
        match self {
            SettingsField::Blocks => "bk",
            SettingsField::BestDiff => "bd",
            SettingsField::Device => "dv",
            SettingsField::TeamRequests => "tr",
            SettingsField::TeamBest => "tb",
            SettingsField::HourlyStats => "hs",
            SettingsField::HourlyWorkers => "hw",
        }
    }
}

/// A `/settings` keyboard tap: `st:<id>` names subscription `id`,
/// `st:<id>:<field>` flips one of its switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCallback {
    Address(i32),
    Flip(i32, SettingsField),
}

impl SettingsCallback {
    pub fn data(self) -> String {
        match self {
            SettingsCallback::Address(id) => format!("st:{id}"),
            SettingsCallback::Flip(id, field) => format!("st:{id}:{}", field.code()),
        }
    }
}

pub fn parse_settings_callback(data: &str) -> Option<SettingsCallback> {
    let rest = data.strip_prefix("st:")?;
    let (id, field) = match rest.split_once(':') {
        Some((id, code)) => (
            id,
            Some(SettingsField::ALL.into_iter().find(|f| f.code() == code)?),
        ),
        None => (rest, None),
    };
    let id: i32 = id.parse().ok()?;
    Some(match field {
        Some(field) => SettingsCallback::Flip(id, field),
        None => SettingsCallback::Address(id),
    })
}

/// Parse the *first whitespace-delimited token* of `text` (case-insensitive)
/// as a command, and the next token as its argument. Returns
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
    let arg = iter.next().map(str::to_string);
    let read = |command| Command::Read(command, arg.clone());

    match cmd.as_str() {
        "/start" => Command::Start,
        "/help" => Command::Help,
        "/subscribe" => Command::Subscribe {
            address: arg.clone(),
        },
        "/remove" => Command::Remove {
            address: arg.clone(),
        },
        "/show_addresses" => Command::ShowAddresses,
        "/settings" => Command::Settings(None),
        "/subscribe_bestdiff" => switch_command(Switch::BestDiff, arg.as_deref()),
        "/device_notifications" => switch_command(Switch::Device, arg.as_deref()),
        "/team_requests" => switch_command(Switch::TeamRequests, arg.as_deref()),
        "/team_bestdiff" => switch_command(Switch::TeamBest, arg.as_deref()),
        "/send_hourly" => switch_command(Switch::Hourly, arg.as_deref()),
        "/bestdiff_reset" => Command::BestDiffReset {
            address: arg.clone(),
        },
        "/deutsch" => Command::LanguageSwitch(LanguageSwitch::De),
        "/english" => Command::LanguageSwitch(LanguageSwitch::En),
        "/stats" => read(ReadCommand::Stats),
        "/show_workers" => read(ReadCommand::ShowWorkers),
        "/poolhashrate" => read(ReadCommand::PoolHashrate),
        "/difficulty" => read(ReadCommand::Difficulty),
        "/next_difficulty" => read(ReadCommand::NextDifficulty),
        "/pplns_status" => read(ReadCommand::PplnsStatus),
        "/team_status" => read(ReadCommand::TeamStatus),
        "/pplns_top" => read(ReadCommand::PplnsTop),
        "/team_members" => read(ReadCommand::TeamMembers),
        "/team_history" => read(ReadCommand::TeamHistory),
        "/blockparty_status" => read(ReadCommand::BlockpartyStatus),
        _ => Command::Unknown,
    }
}

/// A switch command: on|off flips it, no argument opens the settings, and
/// anything else is not understood.
fn switch_command(switch: Switch, arg: Option<&str>) -> Command {
    match arg {
        None => Command::Settings(Some(switch)),
        Some(arg) => parse_toggle(arg)
            .map(|toggle| Command::Toggle(switch, toggle))
            .unwrap_or(Command::Unknown),
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
    fn subscribe_and_remove_take_an_optional_address() {
        assert_eq!(
            parse_command("/subscribe"),
            Command::Subscribe { address: None }
        );
        assert_eq!(
            parse_command("/subscribe bc1qxyz"),
            Command::Subscribe {
                address: Some("bc1qxyz".to_string())
            }
        );
        assert_eq!(parse_command("/remove"), Command::Remove { address: None });
        assert_eq!(
            parse_command("/remove bc1qxyz"),
            Command::Remove {
                address: Some("bc1qxyz".to_string())
            }
        );
    }

    #[test]
    fn toggles_recognise_variants() {
        assert_eq!(
            parse_command("/subscribe_bestdiff on"),
            Command::Toggle(Switch::BestDiff, FlagToggle::On)
        );
        assert_eq!(
            parse_command("/subscribe_bestdiff OFF"),
            Command::Toggle(Switch::BestDiff, FlagToggle::Off)
        );
        assert_eq!(
            parse_command("/device_notifications an"),
            Command::Toggle(Switch::Device, FlagToggle::On)
        );
        assert_eq!(
            parse_command("/send_hourly aus"),
            Command::Toggle(Switch::Hourly, FlagToggle::Off)
        );
        assert_eq!(
            parse_command("/team_requests off"),
            Command::Toggle(Switch::TeamRequests, FlagToggle::Off)
        );
        assert_eq!(
            parse_command("/team_requests on"),
            Command::Toggle(Switch::TeamRequests, FlagToggle::On)
        );
        assert_eq!(
            parse_command("/team_bestdiff off"),
            Command::Toggle(Switch::TeamBest, FlagToggle::Off)
        );
    }

    #[test]
    fn a_switch_without_argument_opens_the_settings() {
        for (cmd, switch) in [
            ("/settings", None),
            ("/subscribe_bestdiff", Some(Switch::BestDiff)),
            ("/device_notifications", Some(Switch::Device)),
            ("/team_requests", Some(Switch::TeamRequests)),
            ("/team_bestdiff", Some(Switch::TeamBest)),
            ("/send_hourly", Some(Switch::Hourly)),
        ] {
            assert_eq!(parse_command(cmd), Command::Settings(switch), "{cmd}");
        }
        assert_eq!(parse_command("/subscribe_bestdiff maybe"), Command::Unknown);
        assert_eq!(parse_command("/send_hourly foo"), Command::Unknown);
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
    fn read_commands_parse_as_read() {
        assert_eq!(
            parse_command("/stats"),
            Command::Read(ReadCommand::Stats, None)
        );
        assert_eq!(
            parse_command("/stats bc1qxyz"),
            Command::Read(ReadCommand::Stats, Some("bc1qxyz".to_string()))
        );
        assert_eq!(
            parse_command("/blockparty_status"),
            Command::Read(ReadCommand::BlockpartyStatus, None)
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
        assert_eq!(parse_address_callback("st:1"), None);
        assert_eq!(parse_address_callback("bdr:yes"), None);
        assert_eq!(parse_address_callback("addr:flip:1"), None);
        assert_eq!(parse_address_callback("addr:set:abc"), None);
    }

    #[test]
    fn settings_callbacks_round_trip() {
        for cb in [SettingsCallback::Address(7)]
            .into_iter()
            .chain(SettingsField::ALL.map(|f| SettingsCallback::Flip(42, f)))
        {
            assert_eq!(parse_settings_callback(&cb.data()), Some(cb));
            assert!(cb.data().len() <= 64, "Telegram's callback_data limit");
        }
        assert_eq!(parse_settings_callback("st:1:xx"), None);
        assert_eq!(parse_settings_callback("st:abc"), None);
        assert_eq!(parse_settings_callback("hr:stats"), None);
    }
}
