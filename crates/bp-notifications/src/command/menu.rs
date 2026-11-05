// SPDX-License-Identifier: AGPL-3.0-or-later

//! The bot's command list: the menu Telegram shows beside the input field,
//! and the `/help` reply. Telegram keeps the last menu it was given, so the
//! pool sends it at every start; an entry the parser does not know would
//! answer "unknown command" when tapped.

use super::group::{group_access, group_topic, GroupAccess, GroupFollows};
use super::parse_command;
use crate::adapter::{AdapterResult, CommandScope, TelegramAdapter};
use crate::format::html;
use crate::format::Language;

struct MenuEntry {
    command: &'static str,
    section: Section,
    args: Args,
    de: &'static str,
    en: &'static str,
}

/// The heading a command stands under in `/help`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Addresses,
    Notifications,
    Queries,
    Other,
}

impl Section {
    /// The order of the menu and of `/help`.
    const ALL: [Section; 4] = [
        Section::Addresses,
        Section::Queries,
        Section::Notifications,
        Section::Other,
    ];

    /// Telegram's menu has no headings; the icon in front of each
    /// description groups it instead.
    fn icon(self) -> &'static str {
        match self {
            Section::Addresses => "\u{1f4cd}",
            Section::Queries => "\u{1f4ca}",
            Section::Notifications => "\u{1f514}",
            Section::Other => "\u{2699}\u{fe0f}",
        }
    }

    fn heading(self, lang: Language) -> &'static str {
        match (self, lang) {
            (Section::Addresses, Language::De) => "Adressen",
            (Section::Addresses, Language::En) => "Addresses",
            (Section::Notifications, Language::De) => "Benachrichtigungen",
            (Section::Notifications, Language::En) => "Notifications",
            (Section::Queries, Language::De) => "Abfragen",
            (Section::Queries, Language::En) => "Queries",
            (Section::Other, Language::De) => "Sonstiges",
            (Section::Other, Language::En) => "Other",
        }
    }
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
        section: Section::Addresses,
        args: Args::None,
        de: "Zeigt Willkommensnachricht",
        en: "Show welcome message",
    },
    MenuEntry {
        command: "/subscribe",
        section: Section::Addresses,
        args: Args::Address,
        de: "Adresse abonnieren",
        en: "Subscribe an address",
    },
    MenuEntry {
        command: "/show_addresses",
        section: Section::Addresses,
        args: Args::None,
        de: "Zeigt gespeicherte Adressen",
        en: "Show stored addresses",
    },
    MenuEntry {
        command: "/remove",
        section: Section::Addresses,
        args: Args::Address,
        de: "Adresse entfernen",
        en: "Remove address",
    },
    MenuEntry {
        command: "/stats",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Zeigt die Stats für deine Miner Adresse an",
        en: "Show stats for your miner address",
    },
    MenuEntry {
        command: "/show_workers",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Zeigt Worker-Übersicht",
        en: "Show worker overview",
    },
    MenuEntry {
        command: "/pplns_status",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "PPLNS-Status für deine Adresse",
        en: "PPLNS status for your address",
    },
    MenuEntry {
        command: "/pplns_top",
        section: Section::Queries,
        args: Args::None,
        de: "Top 10 Miner im PPLNS-Window",
        en: "Top 10 miners in PPLNS window",
    },
    MenuEntry {
        command: "/team_status",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Status des Teams deiner Adresse",
        en: "Status of the team your address belongs to",
    },
    MenuEntry {
        command: "/team_members",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Mitglieder deines Teams",
        en: "Members of your team",
    },
    MenuEntry {
        command: "/team_history",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Block-Auszahlungen deines Teams",
        en: "Block payouts of your team",
    },
    MenuEntry {
        command: "/blockparty_status",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Status der Blockparty deiner Adresse",
        en: "Status of the Blockparty your address belongs to",
    },
    MenuEntry {
        command: "/blockparty_members",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Mitglieder deiner Blockparty",
        en: "Members of your Blockparty",
    },
    MenuEntry {
        command: "/blockparty_history",
        section: Section::Queries,
        args: Args::OptionalAddress,
        de: "Letzte Blöcke deiner Blockparty",
        en: "Recent blocks of your Blockparty",
    },
    MenuEntry {
        command: "/poolhashrate",
        section: Section::Queries,
        args: Args::None,
        de: "Zeigt die aktuelle Pool-Hashrate",
        en: "Show current pool hashrate",
    },
    MenuEntry {
        command: "/difficulty",
        section: Section::Queries,
        args: Args::None,
        de: "Zeigt aktuelle Netzwerk-Difficulty",
        en: "Show current network difficulty",
    },
    MenuEntry {
        command: "/next_difficulty",
        section: Section::Queries,
        args: Args::None,
        de: "Zeigt erwartete Änderung der Netzwerk-Difficulty",
        en: "Show expected network difficulty change",
    },
    MenuEntry {
        command: "/settings",
        section: Section::Notifications,
        args: Args::None,
        de: "Alle Benachrichtigungen pro Adresse schalten",
        en: "Switch every notification per address",
    },
    MenuEntry {
        command: "/subscribe_bestdiff",
        section: Section::Notifications,
        args: Args::OptionalOnOff,
        de: "Best-Diff-Benachrichtigungen, alle Adressen (on/off)",
        en: "Best-diff notifications, all addresses (on/off)",
    },
    MenuEntry {
        command: "/bestdiff_reset",
        section: Section::Notifications,
        args: Args::OptionalAddress,
        de: "Best-Diff zurücksetzen (Link ins Dashboard)",
        en: "Reset best difficulty (link to the dashboard)",
    },
    MenuEntry {
        command: "/device_notifications",
        section: Section::Notifications,
        args: Args::OptionalOnOff,
        de: "Geräte-Benachrichtigungen, alle Adressen (on/off)",
        en: "Device notifications, all addresses (on/off)",
    },
    MenuEntry {
        command: "/send_hourly",
        section: Section::Notifications,
        args: Args::OptionalOnOff,
        de: "Stündliche Stats- und Worker-Berichte, alle Adressen (on/off)",
        en: "Hourly stats and worker reports, all addresses (on/off)",
    },
    MenuEntry {
        command: "/team_bestdiff",
        section: Section::Notifications,
        args: Args::OptionalOnOff,
        de: "Neuer Bestwert des Teams, alle Adressen (on/off)",
        en: "New best of the Team, all addresses (on/off)",
    },
    MenuEntry {
        command: "/team_requests",
        section: Section::Notifications,
        args: Args::OptionalOnOff,
        de: "Team-Beitrittsanfragen als Admin, alle Adressen (on/off)",
        en: "Team join requests as admin, all addresses (on/off)",
    },
    MenuEntry {
        command: "/help",
        section: Section::Other,
        args: Args::None,
        de: "Liste der Befehle",
        en: "List of commands",
    },
    MenuEntry {
        command: "/deutsch",
        section: Section::Other,
        args: Args::None,
        de: "Bot-Antworten auf Deutsch",
        en: "Bot replies in German",
    },
    MenuEntry {
        command: "/english",
        section: Section::Other,
        args: Args::None,
        de: "Bot replies in English",
        en: "Bot replies in English",
    },
];

/// Which chat a menu or `/help` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MenuView {
    Private,
    /// A group, and what its subscriptions follow.
    Group(GroupFollows),
}

/// The entries a chat sees: in a group only those [`group_access`] lets a
/// group use, and of the Team and Blockparty commands those it follows.
fn entries(view: MenuView) -> impl Iterator<Item = &'static MenuEntry> {
    MENU.iter().filter(move |e| match view {
        MenuView::Private => true,
        MenuView::Group(follows) => {
            let command = parse_command(e.command);
            let allowed = match group_access(&command) {
                GroupAccess::Anyone | GroupAccess::Admin => true,
                GroupAccess::PrivateOnly => false,
            };
            allowed && group_topic(&command).is_none_or(|topic| follows.shows(topic))
        }
    })
}

/// `(command without the slash, description)` pairs, as `setMyCommands`
/// takes them: section by section, each description after its section's
/// icon.
fn menu_for(lang: Language, view: MenuView) -> Vec<(&'static str, String)> {
    Section::ALL
        .into_iter()
        .flat_map(move |section| entries(view).filter(move |e| e.section == section))
        .map(|e| {
            let description = match lang {
                Language::De => e.de,
                Language::En => e.en,
            };
            (
                e.command.trim_start_matches('/'),
                format!("{} {description}", e.section.icon()),
            )
        })
        .collect()
}

/// The `/help` reply: every entry the chat sees with its argument, under its
/// section. Commands stay plain so Telegram keeps them tappable.
pub(crate) fn help_text(lang: Language, view: MenuView) -> String {
    let mut text = match lang {
        Language::De => html::bold("Befehle"),
        Language::En => html::bold("Commands"),
    };
    for section in Section::ALL {
        let mut lines = entries(view).filter(|e| e.section == section).peekable();
        if lines.peek().is_none() {
            continue;
        }
        text.push_str("\n\n");
        text.push_str(&html::bold(section.heading(lang)));
        for entry in lines {
            text.push_str(&format!("\n{}", help_line(entry, lang, view)));
        }
    }
    text
}

/// A group's commands take no address of their own, so its help shows none.
fn help_line(entry: &MenuEntry, lang: Language, view: MenuView) -> String {
    let description = match lang {
        Language::De => entry.de,
        Language::En => entry.en,
    };
    let usage = match (view, entry.args) {
        (MenuView::Group(_), Args::OptionalAddress) => "",
        (MenuView::Private | MenuView::Group(_), args) => args.usage(lang),
    };
    let usage = if usage.is_empty() {
        String::new()
    } else {
        format!(" <i>{}</i>", html::esc(usage.trim_start()))
    };
    format!("{}{usage} — {}", entry.command, html::esc(description))
}

fn pairs<'a>(menu: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    menu.iter().map(|(c, d)| (*c, d.as_str())).collect()
}

/// Send the menu to Telegram: once for private chats (the default scope)
/// and once with only what a group may use, for every group without a menu
/// of its own.
pub async fn register_command_menu(adapter: &TelegramAdapter) -> AdapterResult<()> {
    set_menu(adapter, CommandScope::Default, MenuView::Private).await?;
    set_menu(
        adapter,
        CommandScope::AllGroupChats,
        MenuView::Group(GroupFollows::default()),
    )
    .await
}

/// One group's own menu: the Team or Blockparty commands it follows.
pub(crate) async fn set_group_menu(
    adapter: &TelegramAdapter,
    chat_id: i64,
    follows: GroupFollows,
) -> AdapterResult<()> {
    set_menu(
        adapter,
        CommandScope::Chat(chat_id),
        MenuView::Group(follows),
    )
    .await
}

/// English as the default for every client language, plus one list each
/// for German and English clients.
async fn set_menu(
    adapter: &TelegramAdapter,
    scope: CommandScope,
    view: MenuView,
) -> AdapterResult<()> {
    let (en, de) = (menu_for(Language::En, view), menu_for(Language::De, view));
    adapter.set_my_commands(&pairs(&en), scope, None).await?;
    adapter
        .set_my_commands(&pairs(&de), scope, Some("de"))
        .await?;
    adapter
        .set_my_commands(&pairs(&en), scope, Some("en"))
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
    fn a_groups_help_shows_no_address_argument() {
        let view = MenuView::Group(GroupFollows {
            team: true,
            blockparty: true,
        });
        for lang in [Language::De, Language::En] {
            let help = help_text(lang, view);
            assert!(help.contains("/team_status"), "{help}");
            assert!(
                !help.contains("[ADDRESS]") && !help.contains("[ADRESSE]"),
                "{help}"
            );
        }
    }

    #[test]
    fn help_lists_every_menu_entry_with_its_argument() {
        for lang in [Language::De, Language::En] {
            let help = help_text(lang, MenuView::Private);
            for entry in MENU {
                let line = help_line(entry, lang, MenuView::Private);
                assert_eq!(
                    help.lines().filter(|l| *l == line).count(),
                    1,
                    "{lang:?} help misses {line:?}:\n{help}"
                );
            }
            assert!(crate::format::html::is_valid_telegram_html(&help), "{help}");
        }
        assert!(help_text(Language::De, MenuView::Private).contains("/subscribe <i>ADRESSE</i> — "));
        assert!(help_text(Language::En, MenuView::Private)
            .contains("/bestdiff_reset <i>[ADDRESS]</i> — "));
    }

    /// The menu goes section by section, each description behind its
    /// section's icon, in the order `MENU` lists them, so `/help` and the
    /// menu read alike.
    #[test]
    fn the_menu_is_grouped_by_section() {
        let menu = menu_for(Language::De, MenuView::Private);
        let listed: Vec<&str> = MENU
            .iter()
            .map(|e| e.command.trim_start_matches('/'))
            .collect();
        assert_eq!(menu.iter().map(|(c, _)| *c).collect::<Vec<_>>(), listed);
        for (entry, (_, description)) in MENU.iter().zip(&menu) {
            assert!(
                description.starts_with(entry.section.icon()),
                "{description}"
            );
        }
    }

    /// A group's menu and `/help` list only Team, Blockparty and the
    /// commands its admin follows addresses with.
    #[test]
    fn a_group_sees_only_team_and_blockparty_commands() {
        let menu: Vec<&str> = menu_for(Language::De, MenuView::Group(GroupFollows::default()))
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        assert_eq!(
            menu,
            vec![
                "start",
                "subscribe",
                "show_addresses",
                "remove",
                "team_status",
                "team_members",
                "team_history",
                "blockparty_status",
                "blockparty_members",
                "blockparty_history",
                "settings",
                "team_bestdiff",
                "help",
                "deutsch",
                "english",
            ]
        );
        let help = help_text(Language::En, MenuView::Group(GroupFollows::default()));
        assert!(help.contains("/team_status"), "{help}");
        assert!(!help.contains("/stats"), "{help}");
        assert!(crate::format::html::is_valid_telegram_html(&help), "{help}");
        // A group that follows a Team sees no Blockparty commands, and the
        // other way round.
        let team: Vec<&str> = menu_for(
            Language::En,
            MenuView::Group(GroupFollows {
                team: true,
                blockparty: false,
            }),
        )
        .into_iter()
        .map(|(c, _)| c)
        .collect();
        assert!(team.contains(&"team_status") && team.contains(&"team_bestdiff"));
        assert!(
            !team.iter().any(|c| c.starts_with("blockparty")),
            "{team:?}"
        );
        let party = help_text(
            Language::En,
            MenuView::Group(GroupFollows {
                team: false,
                blockparty: true,
            }),
        );
        assert!(
            party.contains("/blockparty_members") && !party.contains("/team_"),
            "{party}"
        );
        assert!(party.contains("/subscribe"), "{party}");
    }

    /// Telegram's limits: 1-32 lowercase letters, digits or underscores per
    /// command, 1-256 characters per description, no command twice.
    #[test]
    fn the_menu_fits_telegram_limits() {
        let mut seen = std::collections::HashSet::new();
        for lang in [Language::De, Language::En] {
            for (command, description) in
                [MenuView::Private, MenuView::Group(GroupFollows::default())]
                    .into_iter()
                    .flat_map(|v| menu_for(lang, v))
            {
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
