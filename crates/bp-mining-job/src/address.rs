// SPDX-License-Identifier: AGPL-3.0-or-later

//! BTC address → scriptPubKey derivation. Normalization lives in
//! `bp_common::normalize_btc_address`.

use std::str::FromStr;

use bitcoin::{Address, Network, ScriptBuf};
use bp_common::AddressId;

/// Convert a BTC address to its `scriptPubKey`; an address for another network
/// is rejected.
pub fn address_to_script(network: Network, address: &str) -> Result<ScriptBuf, AddressError> {
    let unchecked = Address::from_str(address).map_err(|e| AddressError::Parse(e.to_string()))?;
    let checked = unchecked
        .require_network(network)
        .map_err(|e| AddressError::NetworkMismatch(e.to_string()))?;
    Ok(checked.script_pubkey())
}

/// `raw` as an address of `network`, keyed the way stored rows are
/// ([`AddressId::normalized`]). `None` for anything else.
pub fn parse_pool_address(network: Network, raw: &str) -> Option<AddressId> {
    let trimmed = raw.trim();
    Address::from_str(trimmed)
        .ok()?
        .require_network(network)
        .ok()?;
    AddressId::normalized(trimmed).ok()
}

/// A miner's `user_identity` (`address[.worker]`, as SV2 channels and JDP
/// token requests carry it): the address part as an address of `network`,
/// keyed like [`parse_pool_address`], and the worker part as sent, as SV1
/// keeps it. `None` when the address part is no address of `network`.
pub fn parse_miner_identity(
    network: Network,
    user_identity: &str,
) -> Option<(AddressId, Option<&str>)> {
    let (address, worker) = bp_common::split_user_identity(user_identity);
    Some((parse_pool_address(network, address)?, worker))
}

#[derive(thiserror::Error, Debug)]
pub enum AddressError {
    #[error("failed to parse address: {0}")]
    Parse(String),
    #[error("address is not for the expected network: {0}")]
    NetworkMismatch(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address part decides, against the network; the worker part rides
    /// along.
    #[test]
    fn parse_miner_identity_splits_and_checks_the_network() {
        const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let parse = |raw: &str| {
            parse_miner_identity(Network::Regtest, raw)
                .map(|(a, w)| (a.into_inner(), w.map(str::to_owned)))
        };
        assert_eq!(parse(ADDR), Some((ADDR.to_string(), None)));
        assert_eq!(
            parse(&format!(" {ADDR}.gitgab ")),
            Some((ADDR.to_string(), Some("gitgab ".to_owned())))
        );
        assert_eq!(
            parse(&format!("{ADDR}.rig.1")),
            Some((ADDR.to_string(), Some("rig.1".to_owned())))
        );
        assert_eq!(parse(".worker"), None);
        assert_eq!(parse(&"x".repeat(200)), None);
        // A real address of another network.
        assert_eq!(parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), None);
    }

    #[test]
    fn parse_pool_address_keys_a_real_address_of_the_network() {
        let bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let parsed = |raw: &str| parse_pool_address(Network::Bitcoin, raw).map(|a| a.into_inner());
        assert_eq!(parsed(bech32).as_deref(), Some(bech32));
        assert_eq!(
            parsed(&format!(" {} ", bech32.to_uppercase())).as_deref(),
            Some(bech32)
        );
        let base58 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert_eq!(parsed(base58).as_deref(), Some(base58));
        for wrong in [
            &format!("<{bech32}>") as &str,
            "bc1qnotarealaddress",
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "",
        ] {
            assert_eq!(parsed(wrong), None, "{wrong:?}");
        }
    }

    #[test]
    fn address_to_script_p2wpkh_mainnet() {
        let script = address_to_script(
            Network::Bitcoin,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        )
        .unwrap();
        let bytes = script.to_bytes();
        // P2WPKH scriptPubKey: OP_0 (0x00) + OP_PUSHBYTES_20 (0x14) + 20-byte hash160.
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x14);
        assert_eq!(bytes.len(), 22);
    }

    #[test]
    fn address_to_script_p2pkh_mainnet() {
        let script =
            address_to_script(Network::Bitcoin, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
        let bytes = script.to_bytes();
        // P2PKH: OP_DUP OP_HASH160 0x14 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes.
        assert_eq!(bytes.len(), 25);
        assert_eq!(bytes[0], 0x76); // OP_DUP
        assert_eq!(bytes[1], 0xa9); // OP_HASH160
        assert_eq!(bytes[2], 0x14); // push 20
        assert_eq!(bytes[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(bytes[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn address_to_script_rejects_wrong_network() {
        // Testnet bech32 against mainnet — must be rejected.
        let result = address_to_script(
            Network::Bitcoin,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        );
        assert!(matches!(result, Err(AddressError::NetworkMismatch(_))));
    }

    #[test]
    fn address_to_script_rejects_garbage() {
        let result = address_to_script(Network::Bitcoin, "definitely-not-an-address");
        assert!(matches!(result, Err(AddressError::Parse(_))));
    }
}
