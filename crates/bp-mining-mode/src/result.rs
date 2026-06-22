// SPDX-License-Identifier: AGPL-3.0-or-later

use bp_common::MiningMode;

/// Outcome of a mining-mode resolution for a single BTC address.
///
/// `group_id` is populated only when `mode == MiningMode::GroupSolo`. The
/// string carries the canonical UUID of the group (as written in the
/// `pplns_group` table) and matches the JSON contract surfaced by the
/// `/api/pplns/mode/:address` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningModeResult {
    pub mode: MiningMode,
    pub group_id: Option<String>,
}

impl MiningModeResult {
    pub fn solo() -> Self {
        Self {
            mode: MiningMode::Solo,
            group_id: None,
        }
    }

    pub fn pplns() -> Self {
        Self {
            mode: MiningMode::Pplns,
            group_id: None,
        }
    }

    pub fn group_solo(group_id: impl Into<String>) -> Self {
        Self {
            mode: MiningMode::GroupSolo,
            group_id: Some(group_id.into()),
        }
    }

    pub fn blockparty(group_id: impl Into<String>) -> Self {
        Self {
            mode: MiningMode::Blockparty,
            group_id: Some(group_id.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_expected_fields() {
        assert_eq!(MiningModeResult::solo().mode, MiningMode::Solo);
        assert!(MiningModeResult::solo().group_id.is_none());

        assert_eq!(MiningModeResult::pplns().mode, MiningMode::Pplns);
        assert!(MiningModeResult::pplns().group_id.is_none());

        let g = MiningModeResult::group_solo("grp-1");
        assert_eq!(g.mode, MiningMode::GroupSolo);
        assert_eq!(g.group_id.as_deref(), Some("grp-1"));
    }
}
