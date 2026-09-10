// SPDX-License-Identifier: AGPL-3.0-or-later

//! What `network = "…"` in the config means to the libraries the pool wires up.
//!
//! One function per target enum, both exhaustive over [`bp_config::Network`],
//! in one file. That is not tidiness. The `bitcoin::Network` mapping existed
//! **four** times — plus the SRI conversion below, a fifth per-network mapping
//! of a different shape, which lived in [`crate::jdp_hooks`]. The four: a
//! `pub(crate) fn config_network_to_bitcoin` in [`crate::stratum_v2`], a
//! *private* `fn` of the same name in [`crate::stratum_v1`] (spelled against a
//! different import alias, so reading one of them told you nothing about the
//! other), and inline `match`es in [`crate::api_server`] and [`crate::jdp`] —
//! the `jdp` copy one line below a call into `stratum_v2`, i.e. written by
//! someone who had the shared function in scope. All four agreed on every
//! variant when they were collected, which is what `CLAUDE.md`'s opening
//! failure mode looks like on the day before it costs something. Note that a
//! plain `grep` finds three: the `stratum_v1` copy hides behind the alias, so
//! the count is only right if you read for the *concept* rather than the
//! spelling. The asymmetry was in the guards rather than the code:
//! `stratum_v1`'s copy was the only one with a test, and that test pinned three
//! of the four variants — `Testnet4`, the newest arm and the only one carrying a
//! judgement call, was the one it left out.
//!
//! Neither mapping was pushed down into `bp-config` beside the enum, because
//! that means a consensus library in a crate that parses TOML. The workspace has
//! already recorded that call for `bitcoin`-shaped dependencies in the root
//! manifest ("It is deliberately NOT a dependency of `bp-common`"), and
//! [`crate::payout_resolver`] states the positive form of it: the mapping
//! belongs at the wiring edge, which is this binary.

use bitcoin::Network as BitcoinNetwork;
use stratum_apps::tp_type::BitcoinNetwork as SriBitcoinNetwork;

/// The config network as `rust-bitcoin` sees it — the HRP and address byte set
/// every coinbase output is rendered against, so a wrong answer here is a
/// payout to an address on the wrong chain.
///
/// Exhaustive with no `_ =>` arm on purpose: a new `bp_config::Network` variant
/// must not silently inherit whichever byte set a wildcard happened to name.
pub(crate) fn config_network_to_bitcoin(n: bp_config::Network) -> BitcoinNetwork {
    match n {
        bp_config::Network::Mainnet => BitcoinNetwork::Bitcoin,
        // testnet4 shares the `tb` HRP + address byte set with
        // testnet3, so the bitcoin-crate's Testnet variant covers
        // both for address parsing / script generation purposes.
        // rust-bitcoin 0.32 doesn't have a dedicated Testnet4
        // variant yet.
        bp_config::Network::Testnet | bp_config::Network::Testnet4 => BitcoinNetwork::Testnet,
        bp_config::Network::Regtest => BitcoinNetwork::Regtest,
    }
}

/// The config network as upstream's SV2 apps see it, for the bitcoin-core IPC
/// socket layout declared-job validation connects to
/// ([`crate::jdp_hooks::ProductionJobValidator`]). `None` means upstream has no
/// network to point at, and the caller decides what to do about that.
///
/// **This cannot be derived from [`config_network_to_bitcoin`]** — the
/// legitimate difference `CLAUDE.md` asks to be stated rather than papered over.
/// The two enums disagree about which testnet exists. `rust-bitcoin` 0.32 has
/// one `Testnet` covering testnet3 and testnet4, which is correct *there*
/// because they share an address byte set. Upstream's enum is a **directory
/// layout**: it has `Testnet4`, and no testnet3 at all (it also has `Signet`,
/// which no `bp_config::Network` variant reaches today). Routing through
/// `bitcoin::Network` would throw away the only distinction that matters here —
/// both testnets would arrive as the same value, and whichever one this function
/// then picked would be wrong for the other: either validating against a socket
/// path that does not exist, or refusing validation on a network that supports
/// it.
pub(crate) fn config_network_to_sri(n: bp_config::Network) -> Option<SriBitcoinNetwork> {
    match n {
        bp_config::Network::Mainnet => Some(SriBitcoinNetwork::Mainnet),
        bp_config::Network::Testnet4 => Some(SriBitcoinNetwork::Testnet4),
        bp_config::Network::Regtest => Some(SriBitcoinNetwork::Regtest),
        // testnet3 is absent from upstream's enum — there is no socket layout to
        // point at, so there is nothing to convert to.
        bp_config::Network::Testnet => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_config::Network;

    /// What each config variant must map to in **both** targets, written as an
    /// exhaustive `match` rather than a list of vectors: a fifth
    /// `bp_config::Network` variant stops this file compiling until someone
    /// writes down here what it means to `rust-bitcoin` *and* to upstream.
    fn expected(n: Network) -> (BitcoinNetwork, &'static str) {
        match n {
            Network::Mainnet => (BitcoinNetwork::Bitcoin, "mainnet"),
            // One rust-bitcoin answer for both testnets, two different answers
            // upstream — this pair is the whole reason these are two functions
            // and not one composed of the other.
            Network::Testnet => (BitcoinNetwork::Testnet, "unsupported"),
            Network::Testnet4 => (BitcoinNetwork::Testnet, "testnet4"),
            Network::Regtest => (BitcoinNetwork::Regtest, "regtest"),
        }
    }

    /// Upstream's `BitcoinNetwork` derives neither `PartialEq` nor a stable
    /// discriminant, so the pin compares labels. This `match` is over *their*
    /// variants, not ours.
    fn sri_label(n: Option<SriBitcoinNetwork>) -> &'static str {
        match n {
            None => "unsupported",
            Some(SriBitcoinNetwork::Mainnet) => "mainnet",
            Some(SriBitcoinNetwork::Testnet4) => "testnet4",
            Some(SriBitcoinNetwork::Signet) => "signet",
            Some(SriBitcoinNetwork::Regtest) => "regtest",
        }
    }

    /// Two guards here, and only one of them is the compiler's.
    ///
    /// [`expected`] is exhaustive, so a fifth `bp_config::Network` variant does
    /// not compile until someone writes down what it means to `rust-bitcoin`
    /// *and* to upstream. That much is enforced. Which variants this loop
    /// actually *visits* comes from [`bp_config::Network::ALL`], which is a
    /// hand-written array and cannot be enforced — see its own doc for why no
    /// `match` trick closes that. So the length assertion below is the tripwire,
    /// and it is deliberately a literal: a grown enum has to come back here.
    ///
    /// An earlier draft of this test walked a successor chain and claimed a new
    /// variant "has to be placed in this chain to compile and is then visited by
    /// the pins below". The first half was true and the second was not — a
    /// terminal `Signet => None` arm satisfies the walk's exhaustive `match`,
    /// leaves the chain at four, keeps this assertion green, and never exercises
    /// the new variant. That is the "green while proving nothing" shape
    /// `CLAUDE.md` measured on 2026-08-03, rebuilt out of the machinery meant to
    /// prevent it.
    #[test]
    fn every_config_network_variant_has_a_pinned_mapping_in_both_targets() {
        let variants = Network::ALL;
        assert_eq!(
            variants.len(),
            4,
            "bp_config::Network grew: extend Network::ALL and the expected() \
             table together, because only the second is compiler-enforced"
        );
        for n in variants {
            let (want_bitcoin, want_sri) = expected(n);
            assert_eq!(
                config_network_to_bitcoin(n),
                want_bitcoin,
                "bitcoin::Network for {n:?}"
            );
            assert_eq!(
                sri_label(config_network_to_sri(n)),
                want_sri,
                "upstream network for {n:?}"
            );
        }
    }

    /// Standing control for those pins: they have to distinguish the mistakes
    /// they exist to catch, so the table cannot later be trimmed to rows that no
    /// longer do. Testnet3 / testnet4 is the pair to watch — indistinguishable
    /// in `bitcoin::Network`, distinct upstream — so pinning only one target
    /// would call either mapping of them correct.
    #[test]
    fn the_pins_would_catch_a_testnet3_testnet4_swap_and_a_mainnet_slip() {
        assert_eq!(
            config_network_to_bitcoin(Network::Testnet),
            config_network_to_bitcoin(Network::Testnet4),
            "if these ever differ, the bitcoin pin — not this control — is the \
             one that has to say so"
        );
        assert_ne!(
            sri_label(config_network_to_sri(Network::Testnet)),
            sri_label(config_network_to_sri(Network::Testnet4)),
            "swapping the two testnets is invisible to the bitcoin pin, so the \
             upstream pin is the only thing that catches it"
        );
        // The drift that costs money: a testnet byte set on a mainnet coinbase
        // or the reverse. Each of these three must be its own answer.
        assert_ne!(
            config_network_to_bitcoin(Network::Mainnet),
            config_network_to_bitcoin(Network::Testnet)
        );
        assert_ne!(
            config_network_to_bitcoin(Network::Mainnet),
            config_network_to_bitcoin(Network::Regtest)
        );
        assert_ne!(
            config_network_to_bitcoin(Network::Testnet),
            config_network_to_bitcoin(Network::Regtest)
        );
    }
}
