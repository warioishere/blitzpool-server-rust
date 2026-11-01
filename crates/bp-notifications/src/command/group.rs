// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the bot does in a Telegram group: Team and Blockparty only, and only
//! a group admin changes what the group follows. Personal commands stay in
//! the private chat, so nobody follows their own address in public.

use super::parser::{Command, ReadCommand, Switch};

/// Who sent a command in a group chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSender {
    User(i64),
    /// An administrator posting as the group itself (`sender_chat` is the
    /// group): only an administrator can.
    AnonymousAdmin,
    /// A message on behalf of another chat, such as a linked channel: no
    /// user to ask about, and no admin of this group.
    OtherChat,
}

/// What a command may do in a group chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupAccess {
    /// Every member.
    Anyone,
    /// A group administrator: it changes what the group follows.
    Admin,
    /// Not in a group: it is about one's own address.
    PrivateOnly,
}

pub(crate) fn group_access(command: &Command) -> GroupAccess {
    match command {
        Command::Start | Command::Help => GroupAccess::Anyone,
        Command::Read(read, _) => match read {
            ReadCommand::TeamStatus
            | ReadCommand::TeamMembers
            | ReadCommand::TeamHistory
            | ReadCommand::BlockpartyStatus => GroupAccess::Anyone,
            ReadCommand::Stats
            | ReadCommand::ShowWorkers
            | ReadCommand::PoolHashrate
            | ReadCommand::Difficulty
            | ReadCommand::NextDifficulty
            | ReadCommand::PplnsStatus
            | ReadCommand::PplnsTop => GroupAccess::PrivateOnly,
        },
        Command::Subscribe { .. }
        | Command::Remove { .. }
        | Command::ShowAddresses
        | Command::LanguageSwitch(_) => GroupAccess::Admin,
        Command::Settings(switch) => switch_access(*switch),
        Command::Toggle(switch, _) => switch_access(Some(*switch)),
        Command::BestDiffReset { .. } => GroupAccess::PrivateOnly,
        Command::Unknown => GroupAccess::PrivateOnly,
    }
}

/// `/settings`, or a switch command: the Team best for an admin, the
/// personal notices not at all.
fn switch_access(switch: Option<Switch>) -> GroupAccess {
    match switch {
        None | Some(Switch::TeamBest) => GroupAccess::Admin,
        Some(Switch::BestDiff | Switch::Device | Switch::TeamRequests | Switch::Hourly) => {
            GroupAccess::PrivateOnly
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::parse_command;

    #[test]
    fn a_group_reads_teams_and_its_admin_changes_what_it_follows() {
        for (text, access) in [
            ("/team_status", GroupAccess::Anyone),
            ("/blockparty_status", GroupAccess::Anyone),
            ("/help", GroupAccess::Anyone),
            ("/subscribe bc1q", GroupAccess::Admin),
            ("/remove", GroupAccess::Admin),
            ("/settings", GroupAccess::Admin),
            ("/team_bestdiff off", GroupAccess::Admin),
            ("/deutsch", GroupAccess::Admin),
            ("/stats", GroupAccess::PrivateOnly),
            ("/subscribe_bestdiff", GroupAccess::PrivateOnly),
            ("/send_hourly on", GroupAccess::PrivateOnly),
            ("/team_requests", GroupAccess::PrivateOnly),
            ("/bestdiff_reset", GroupAccess::PrivateOnly),
            ("/pplns_top", GroupAccess::PrivateOnly),
        ] {
            assert_eq!(group_access(&parse_command(text)), access, "{text}");
        }
    }
}
