// SPDX-License-Identifier: AGPL-3.0-or-later

//! The bot's command list: the menu Telegram shows beside the input field,
//! and the `/help` reply. Telegram keeps the last menu it was given, so the
//! pool sends it at every start; an entry the parser does not know would
//! answer "unknown command" when tapped.

use crate::adapter::{AdapterResult, TelegramAdapter};
use crate::format::Language;

struct MenuEntry {
    command: &'static str,
    args: Args,
    de: &'static str,
    en: &'static str,
}

/// The argument `/help` shows after a command. Telegram's menu has no room
/// for it, so a switch names its on/off in the description as well.
#[derive(Clone, Copy)]
enum Args {
    None,
    Address,
    OptionalAddress,
    /// Without it the command opens `/settings`.
    OptionalOnOff,
}

impl Args {
    fn usage(self, lang: Language) -> &'static str {
        match (self, lang) {
            (Args::None, _) => "",
            (Args::Address, Language::De) => " ADRESSE",
            (Args::Address, Language::En) => " ADDRESS",
            (Args::OptionalAddress, Language::De) => " [ADRESSE]",
            (Args::OptionalAddress, Language::En) => " [ADDRESS]",
            (Args::OptionalOnOff, _) => " [on|off]",
        }
    }
}

const MENU: &[MenuEntry] = &[
    MenuEntry {
        command: "/start",
        args: Args::None,
        de: "Zeigt Willkommensnachricht",
        en: "Show welcome message",
    },
    MenuEntry {
        command: "/subscribe",
        args: Args::Address,
        de: "Benachrichtigung bei Blockhit aktivieren",
        en: "Enable block hit notifications",
    },
    MenuEntry {
        command: "/settings",
        args: Args::None,
        de: "Alle Benachrichtigungen pro Adresse schalten",
        en: "Switch every notification per address",
    },
    MenuEntry {
        command: "/subscribe_bestdiff",
        args: Args::OptionalOnOff,
        de: "Best-Diff-Benachrichtigungen, alle Adressen (on/off)",
        en: "Best-diff notifications, all addresses (on/off)",
    },
    MenuEntry {
        command: "/bestdiff_reset",
        args: Args::OptionalAddress,
        de: "Best-Diff zurücksetzen (Link ins Dashboard)",
        en: "Reset best difficulty (link to the dashboard)",
    },
    MenuEntry {
        command: "/device_notifications",
        args: Args::OptionalOnOff,
        de: "Geräte-Benachrichtigungen, alle Adressen (on/off)",
        en: "Device notifications, all addresses (on/off)",
    },
    MenuEntry {
        command: "/team_requests",
        args: Args::OptionalOnOff,
        de: "Team-Beitrittsanfragen als Admin, alle Adressen (on/off)",
        en: "Team join requests as admin, all addresses (on/off)",
    },
    MenuEntry {
        command: "/difficulty",
        args: Args::None,
        de: "Zeigt aktuelle Netzwerk-Difficulty",
        en: "Show current network difficulty",
    },
    MenuEntry {
        command: "/next_difficulty",
        args: Args::None,
        de: "Zeigt erwartete Änderung der Netzwerk-Difficulty",
        en: "Show expected network difficulty change",
    },
    MenuEntry {
        command: "/stats",
        args: Args::OptionalAddress,
        de: "Zeigt die Stats für deine Miner Adresse an",
        en: "Show stats for your miner address",
    },
    MenuEntry {
        command: "/show_workers",
        args: Args::OptionalAddress,
        de: "Zeigt Worker-Übersicht",
        en: "Show worker overview",
    },
    MenuEntry {
        command: "/send_hourly",
        args: Args::OptionalOnOff,
        de: "Stündliche Stats- und Worker-Berichte, alle Adressen (on/off)",
        en: "Hourly stats and worker reports, all addresses (on/off)",
    },
    MenuEntry {
        command: "/poolhashrate",
        args: Args::None,
        de: "Zeigt die aktuelle Pool-Hashrate",
        en: "Show current pool hashrate",
    },
    MenuEntry {
        command: "/pplns_status",
        args: Args::OptionalAddress,
        de: "PPLNS-Status für deine Adresse",
        en: "PPLNS status for your address",
    },
    MenuEntry {
        command: "/pplns_top",
        args: Args::None,
        de: "Top 10 Miner im PPLNS-Window",
        en: "Top 10 miners in PPLNS window",
    },
    MenuEntry {
        command: "/team_status",
        args: Args::OptionalAddress,
        de: "Status des Teams deiner Adresse",
        en: "Status of the team your address belongs to",
    },
    MenuEntry {
        command: "/blockparty_status",
        args: Args::OptionalAddress,
        de: "Status der Blockparty deiner Adresse",
        en: "Status of the Blockparty your address belongs to",
    },
    MenuEntry {
        command: "/team_members",
        args: Args::OptionalAddress,
        de: "Mitglieder deines Teams",
        en: "Members of your team",
    },
    MenuEntry {
        command: "/team_history",
        args: Args::OptionalAddress,
        de: "Block-Auszahlungen deines Teams",
        en: "Block payouts of your team",
    },
    MenuEntry {
        command: "/remove",
        args: Args::Address,
        de: "Adresse entfernen",
        en: "Remove address",
    },
    MenuEntry {
        command: "/show_addresses",
        args: Args::None,
        de: "Zeigt gespeicherte Adressen",
        en: "Show stored addresses",
    },
    MenuEntry {
        command: "/deutsch",
        args: Args::None,
        de: "Bot-Antworten auf Deutsch",
        en: "Bot replies in German",
    },
    MenuEntry {
        command: "/english",
        args: Args::None,
        de: "Bot replies in English",
        en: "Bot replies in English",
    },
    MenuEntry {
        command: "/help",
        args: Args::None,
        de: "Liste der Befehle",
        en: "List of commands",
    },
];

/// `(command without the slash, description)` pairs, as `setMyCommands`
/// takes them.
fn menu_for(lang: Language) -> Vec<(&'static str, &'static str)> {
    MENU.iter()
        .map(|e| {
            let description = match lang {
                Language::De => e.de,
                Language::En => e.en,
            };
            (e.command.trim_start_matches('/'), description)
        })
        .collect()
}

/// The `/help` reply: every menu entry with its argument.
pub(crate) fn help_text(lang: Language) -> String {
    let header = match lang {
        Language::De => "Verfügbare Befehle:",
        Language::En => "Available commands:",
    };
    let mut text = header.to_string();
    for entry in MENU {
        let description = match lang {
            Language::De => entry.de,
            Language::En => entry.en,
        };
        text.push_str(&format!(
            "\n{}{} — {description}",
            entry.command,
            entry.args.usage(lang)
        ));
    }
    text
}

/// Send the menu to Telegram: English as the default for every client
/// language, plus one list each for German and English clients.
pub async fn register_command_menu(adapter: &TelegramAdapter) -> AdapterResult<()> {
    adapter
        .set_my_commands(&menu_for(Language::En), None)
        .await?;
    adapter
        .set_my_commands(&menu_for(Language::De), Some("de"))
        .await?;
    adapter
        .set_my_commands(&menu_for(Language::En), Some("en"))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{parse_command, Command};

    /// Every menu entry is a command the bot answers, in each form `/help`
    /// gives for it.
    #[test]
    fn every_menu_entry_is_a_command_the_bot_knows() {
        const ADDRESS: &str = " bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        for entry in MENU {
            let forms: &[&str] = match entry.args {
                Args::None => &[""],
                Args::Address => &[ADDRESS],
                Args::OptionalAddress => &["", ADDRESS],
                Args::OptionalOnOff => &["", " on", " off"],
            };
            for arg in forms {
                let text = format!("{}{arg}", entry.command);
                assert_ne!(
                    parse_command(&text),
                    Command::Unknown,
                    "{text:?} is in the menu but the bot does not know it"
                );
            }
        }
    }

    #[test]
    fn help_lists_every_menu_entry_with_its_argument() {
        for lang in [Language::De, Language::En] {
            let help = help_text(lang);
            for entry in MENU {
                let line = format!("{}{} — ", entry.command, entry.args.usage(lang));
                assert!(
                    help.lines().any(|l| l.starts_with(&line)),
                    "{lang:?} help misses {line:?}:\n{help}"
                );
            }
            assert_eq!(help.lines().count(), MENU.len() + 1, "{lang:?}");
        }
        assert!(help_text(Language::De).contains("/subscribe ADRESSE — "));
        assert!(help_text(Language::En).contains("/bestdiff_reset [ADDRESS] — "));
    }

    /// Telegram's limits: 1-32 lowercase letters, digits or underscores per
    /// command, 1-256 characters per description, no command twice.
    #[test]
    fn the_menu_fits_telegram_limits() {
        let mut seen = std::collections::HashSet::new();
        for lang in [Language::De, Language::En] {
            for (command, description) in menu_for(lang) {
                assert!(
                    (1..=32).contains(&command.len())
                        && command
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "invalid command name {command:?}"
                );
                assert!(
                    (1..=256).contains(&description.chars().count()),
                    "description of {command} out of bounds"
                );
            }
        }
        for entry in MENU {
            assert!(seen.insert(entry.command), "{} listed twice", entry.command);
        }
    }
}
