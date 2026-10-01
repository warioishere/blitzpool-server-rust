// SPDX-License-Identifier: AGPL-3.0-or-later

use bp_common::MiningMode;
use uuid::Uuid;

/// Outcome of a mining-mode resolution for one address. Group-Solo and
/// Blockparty carry their group, so no consumer has to handle a group mode
/// without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningModeResult {
    Solo,
    Pplns,
    GroupSolo(Uuid),
    Blockparty(Uuid),
}

impl MiningModeResult {
    pub fn mode(self) -> MiningMode {
        match self {
            Self::Solo => MiningMode::Solo,
            Self::Pplns => MiningMode::Pplns,
            Self::GroupSolo(_) => MiningMode::GroupSolo,
            Self::Blockparty(_) => MiningMode::Blockparty,
        }
    }

    /// The group stamped onto shares and found blocks for this mode.
    pub fn group_id(self) -> Option<Uuid> {
        match self {
            Self::Solo | Self::Pplns => None,
            Self::GroupSolo(g) | Self::Blockparty(g) => Some(g),
        }
    }
}
