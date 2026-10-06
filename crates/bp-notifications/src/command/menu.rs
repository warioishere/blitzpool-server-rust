// SPDX-License-Identifier: AGPL-3.0-or-later

//! The command menu Telegram shows beside the input field. Telegram keeps the
//! last list it was given, so the pool sends it at every start; an entry the
//! parser does not know would answer "unknown command" when tapped.

use crate::adapter::{AdapterResult, TelegramAdapter};
use crate::format::Language;

struct MenuEntry {
    command: &'static str,
    de: &'static str,
    en: &'static str,
}

const MENU: &[MenuEntry] = &[
    MenuEntry {
        command: "/start",
        de: "Zeigt Willkommensnachricht",
        en: "Show welcome message",
    },
    MenuEntry {
        command: "/subscribe",
        de: "Benachrichtigung bei Blockhit aktivieren",
        en: "Enable block hit notifications",
    },
    MenuEntry {
        command: "/subscribe_bestdiff",
        de: "Best-Diff Benachrichtigungen (on/off, Standard: on)",
        en: "Best-diff notifications (on/off, default: on)",
    },
    MenuEntry {
        command: "/bestdiff_reset",
        de: "Best-Diff zurücksetzen",
        en: "Reset best-diff counter",
    },
    MenuEntry {
        command: "/device_notifications",
        de: "Geräte-Benachrichtigungen (on/off)",
        en: "Device notifications (on/off)",
    },
    MenuEntry {
        command: "/difficulty",
        de: "Zeigt aktuelle Netzwerk-Difficulty",
        en: "Show current network difficulty",
    },
    MenuEntry {
        command: "/next_difficulty",
        de: "Zeigt erwartete Änderung der Netzwerk-Difficulty",
        en: "Show expected network difficulty change",
    },
    MenuEntry {
        command: "/stats",
        de: "Zeigt die Stats für deine Miner Adresse an",
        en: "Show stats for your miner address",
    },
    MenuEntry {
        command: "/show_workers",
        de: "Zeigt Worker-Übersicht",
        en: "Show worker overview",
    },
    MenuEntry {
        command: "/send_hourly",
        de: "Stündliche Stats/Worker-Berichte (Menü)",
        en: "Hourly stats/worker reports (menu)",
    },
    MenuEntry {
        command: "/poolhashrate",
        de: "Zeigt die aktuelle Pool-Hashrate",
        en: "Show current pool hashrate",
    },
    MenuEntry {
        command: "/pplns_status",
        de: "PPLNS-Status für deine Adresse",
        en: "PPLNS status for your address",
    },
    MenuEntry {
        command: "/pplns_top",
        de: "Top 10 Miner im PPLNS-Window",
        en: "Top 10 miners in PPLNS window",
    },
    MenuEntry {
        command: "/team_status",
        de: "Status des Teams deiner Adresse",
        en: "Status of the team your address belongs to",
    },
    MenuEntry {
        command: "/team_members",
        de: "Mitglieder deines Teams",
        en: "Members of your team",
    },
    MenuEntry {
        command: "/team_history",
        de: "Block-Auszahlungen deines Teams",
        en: "Block payouts of your team",
    },
    MenuEntry {
        command: "/remove",
        de: "Adresse entfernen",
        en: "Remove address",
    },
    MenuEntry {
        command: "/show_addresses",
        de: "Zeigt gespeicherte Adressen",
        en: "Show stored addresses",
    },
    MenuEntry {
        command: "/deutsch",
        de: "Bot-Antworten auf Deutsch",
        en: "Bot replies in German",
    },
    MenuEntry {
        command: "/english",
        de: "Bot replies in English",
        en: "Bot replies in English",
    },
    MenuEntry {
        command: "/help",
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

    /// Every menu entry is a command the bot answers. Commands that need an
    /// argument are tried with one, since the parser rejects them bare.
    #[test]
    fn every_menu_entry_is_a_command_the_bot_knows() {
        for entry in MENU {
            let recognised = ["", " on", " bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"]
                .iter()
                .any(|arg| parse_command(&format!("{}{arg}", entry.command)) != Command::Unknown);
            assert!(
                recognised,
                "{} is in the menu but the bot does not know it",
                entry.command
            );
        }
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
