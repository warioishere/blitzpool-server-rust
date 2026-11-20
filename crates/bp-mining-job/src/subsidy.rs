// SPDX-License-Identifier: AGPL-3.0-or-later

//! The block-subsidy halving schedule per network.

/// Blocks between subsidy halvings on `network`: regtest halves every 150
/// blocks, every other network on the mainnet schedule. Settlement gates on
/// it and the API previews with it, so the two cannot disagree.
pub fn subsidy_halving_interval(network: bitcoin::Network) -> u32 {
    match network {
        bitcoin::Network::Regtest => bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
        _ => bp_share::SUBSIDY_HALVING_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins regtest's own halving schedule, without which regtest blocks past
    /// height 150 would be refused as underpaid.
    #[test]
    fn regtest_gets_its_own_halving_schedule() {
        assert_eq!(
            subsidy_halving_interval(bitcoin::Network::Regtest),
            bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL
        );
        for net in [
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Testnet4,
        ] {
            assert_eq!(
                subsidy_halving_interval(net),
                bp_share::SUBSIDY_HALVING_INTERVAL,
                "{net:?} shares the mainnet schedule"
            );
        }
        let regtest =
            bp_share::block_subsidy_sats(500, subsidy_halving_interval(bitcoin::Network::Regtest));
        assert_eq!(regtest, 625_000_000, "3 halvings in on regtest");
        assert!(
            regtest
                < bp_share::block_subsidy_sats(
                    500,
                    subsidy_halving_interval(bitcoin::Network::Bitcoin)
                ),
            "the mainnet schedule would over-state it and gate the block"
        );
    }
}
