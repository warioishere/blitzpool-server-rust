// SPDX-License-Identifier: AGPL-3.0-or-later

//! BTC address → `scriptPubKey` derivation.
//!
//! The normalization rule that used to live here moved to
//! `bp_common::normalize_btc_address` — it had been copied into both engines
//! (which cannot depend on this crate: it is only a dev-dependency of theirs),
//! and the "must agree byte-for-byte" invariant the copies documented was
//! checked by nothing. `bp-common` is a dependency of all of them.

use std::str::FromStr;

use bitcoin::{Address, Network, ScriptBuf};

/// Convert a BTC address to its `scriptPubKey` bytes for the given network.
/// All address types supported by `rust-bitcoin` are handled (P2PKH, P2SH,
/// P2WPKH, P2WSH, P2TR). A network mismatch (e.g. testnet address with
/// `Network::Bitcoin`) is rejected.
pub fn address_to_script(network: Network, address: &str) -> Result<ScriptBuf, AddressError> {
    let unchecked = Address::from_str(address).map_err(|e| AddressError::Parse(e.to_string()))?;
    let checked = unchecked
        .require_network(network)
        .map_err(|e| AddressError::NetworkMismatch(e.to_string()))?;
    Ok(checked.script_pubkey())
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
