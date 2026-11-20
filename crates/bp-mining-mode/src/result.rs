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

    /// The inverse of [`Self::mode`] + [`Self::group_id`]: how a stream entry
    /// carries the mode. A group mode without its group, which no producer
    /// writes, fails the decode.
    pub fn from_parts(mode: MiningMode, group_id: Option<Uuid>) -> Result<Self, GroupMissing> {
        match (mode, group_id) {
            (MiningMode::Solo, _) => Ok(Self::Solo),
            (MiningMode::Pplns, _) => Ok(Self::Pplns),
            (MiningMode::GroupSolo, Some(g)) => Ok(Self::GroupSolo(g)),
            (MiningMode::Blockparty, Some(g)) => Ok(Self::Blockparty(g)),
            (MiningMode::GroupSolo | MiningMode::Blockparty, None) => Err(GroupMissing(mode)),
        }
    }
}

/// A group mode decoded without its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMissing(pub MiningMode);

impl std::fmt::Display for GroupMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mode {} without its group_id", self.0.as_str())
    }
}

impl std::error::Error for GroupMissing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_parts_inverts_mode_and_group_id() {
        let g = Uuid::from_u128(7);
        for r in [
            MiningModeResult::Solo,
            MiningModeResult::Pplns,
            MiningModeResult::GroupSolo(g),
            MiningModeResult::Blockparty(g),
        ] {
            assert_eq!(MiningModeResult::from_parts(r.mode(), r.group_id()), Ok(r));
        }
    }

    #[test]
    fn a_group_mode_without_its_group_fails() {
        for mode in [MiningMode::GroupSolo, MiningMode::Blockparty] {
            assert_eq!(
                MiningModeResult::from_parts(mode, None),
                Err(GroupMissing(mode))
            );
        }
    }
}
