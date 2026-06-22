// SPDX-License-Identifier: AGPL-3.0-or-later

//! BTC address normalization and script derivation.

use std::str::FromStr;

use bitcoin::{Address, Network, ScriptBuf};

/// Normalize a BTC address for storage / equality comparison.
///
/// Bech32 / bech32m (BIP-173 / BIP-350) are case-insensitive by spec —
/// wallets may present them uppercase (QR-code optimization) but the
/// canonical wire form is lowercase. Legacy P2PKH / P2SH (base58) IS
/// case-sensitive — different cases are different addresses with
/// different checksums — and is left untouched.
///
/// Whitespace is trimmed. Empty input maps to empty output.
pub fn normalize_btc_address(address: &str) -> String {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("bc1")
        || lower.starts_with("tb1")
        || lower.starts_with("bcrt1")
        || lower.starts_with("sb1")
    {
        lower
    } else {
        trimmed.to_string()
    }
}

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
    fn bech32_normalized_to_lowercase() {
        assert_eq!(
            normalize_btc_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(
            normalize_btc_address("TB1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX"),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert_eq!(
            normalize_btc_address("BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080"),
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        );
    }

    #[test]
    fn legacy_preserves_case() {
        assert_eq!(
            normalize_btc_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        );
        assert_eq!(
            normalize_btc_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            normalize_btc_address("  bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4  "),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(normalize_btc_address(""), "");
        assert_eq!(normalize_btc_address("   "), "");
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
