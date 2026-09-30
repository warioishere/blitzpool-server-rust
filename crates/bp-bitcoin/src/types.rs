// SPDX-License-Identifier: AGPL-3.0-or-later

//! Response types for `getnetworkinfo`, `getmininginfo`, `getblockheader`,
//! `getblock`, `getrawtransaction`.
//!
//! Fields mirror the JSON output of bitcoin-core v29+. Fields that may be
//! absent in older / newer versions are wrapped in `Option`. Unknown
//! fields are silently ignored by `serde` so new fields in future
//! bitcoind releases do not break parsing.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// getnetworkinfo
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Server version as an integer (e.g. 290000 for 29.0.0).
    pub version: u64,
    pub subversion: String,
    /// P2P protocol version.
    pub protocolversion: u64,
    /// Hex string of the local services flag.
    pub localservices: String,
    /// Symbolic service names (NETWORK, WITNESS, …).
    #[serde(default)]
    pub localservicesnames: Vec<String>,
    pub localrelay: bool,
    pub timeoffset: i64,
    pub networkactive: bool,
    pub connections: u32,
    #[serde(default)]
    pub connections_in: Option<u32>,
    #[serde(default)]
    pub connections_out: Option<u32>,
    pub networks: Vec<NetworkInfoNetwork>,
    /// Minimum relay fee in BTC/kvB.
    pub relayfee: f64,
    pub incrementalfee: f64,
    #[serde(default)]
    pub localaddresses: Vec<LocalAddress>,
    /// Free-form warning string (typically "" or a soft-fork notice).
    /// In some bitcoind builds this becomes an array of strings; accept either.
    #[serde(default)]
    pub warnings: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfoNetwork {
    /// "ipv4" | "ipv6" | "onion" | "i2p" | "cjdns"
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalAddress {
    pub address: String,
    pub port: u16,
    pub score: i32,
}

// ---------------------------------------------------------------------------
// getmininginfo
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningInfo {
    pub blocks: u64,
    #[serde(default)]
    pub currentblockweight: Option<u64>,
    #[serde(default)]
    pub currentblocktx: Option<u64>,
    /// Current network difficulty as a float (used for the `/api/network` response shape).
    pub difficulty: f64,
    /// Estimated network hash rate in H/s (`networkhashps`).
    pub networkhashps: f64,
    pub pooledtx: u64,
    /// "main" | "test" | "signet" | "regtest"
    pub chain: String,
    #[serde(default)]
    pub warnings: serde_json::Value,
}

// ---------------------------------------------------------------------------
// getblockheader (verbose=true)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeaderInfo {
    /// Block hash (hex, big-endian display order).
    pub hash: String,
    /// Confirmations of this block on the **active** chain:
    /// `>= 1` when it is in the best chain (depth = this value),
    /// `-1` when the header is known but NOT on the active chain
    /// (i.e. the block was orphaned / reorged out). The block-found
    /// confirmation watcher treats `>= confirmation_depth` as confirmed
    /// and `< 0` as orphaned.
    pub confirmations: i64,
    /// Block height. Present for blocks on the active chain.
    #[serde(default)]
    pub height: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Fixture-based parsing tests ----
    //
    // These exercise only the deserialization of bitcoin-core's RPC output
    // (the HTTP path is covered by the regtests) — they catch shape-drift
    // between the struct definitions and the JSON the daemon emits.

    #[test]
    fn block_header_in_chain_parses_positive_confirmations() {
        let json = r#"{"hash":"00000000000000000001abcd","confirmations":5,"height":840000,"version":536870912}"#;
        let h: BlockHeaderInfo = serde_json::from_str(json).unwrap();
        assert_eq!(h.confirmations, 5);
        assert_eq!(h.height, Some(840000));
    }

    #[test]
    fn block_header_orphaned_parses_negative_confirmations() {
        // A header known to the node but NOT on the active chain reports
        // confirmations = -1 (and may omit height).
        let json = r#"{"hash":"00000000000000000001dead","confirmations":-1}"#;
        let h: BlockHeaderInfo = serde_json::from_str(json).unwrap();
        assert_eq!(h.confirmations, -1);
        assert_eq!(h.height, None);
    }

    #[test]
    fn network_info_parses_v29_sample() {
        let json = r#"{
            "version": 290000,
            "subversion": "/Satoshi:29.0.0/",
            "protocolversion": 70016,
            "localservices": "0000000000000409",
            "localservicesnames": ["NETWORK", "WITNESS"],
            "localrelay": true,
            "timeoffset": 0,
            "networkactive": true,
            "connections": 10,
            "connections_in": 2,
            "connections_out": 8,
            "networks": [
                {"name": "ipv4", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false}
            ],
            "relayfee": 0.00001000,
            "incrementalfee": 0.00001000,
            "localaddresses": [],
            "warnings": ""
        }"#;
        let info: NetworkInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.version, 290000);
        assert_eq!(info.connections, 10);
        assert_eq!(info.connections_in, Some(2));
        assert_eq!(info.networks[0].name, "ipv4");
        assert!((info.relayfee - 0.00001).abs() < 1e-9);
    }

    #[test]
    fn network_info_parses_warnings_as_array_too() {
        // Some bitcoind builds emit `warnings` as a string-array.
        let json = r#"{
            "version": 290000,
            "subversion": "/Satoshi:29.0.0/",
            "protocolversion": 70016,
            "localservices": "0000",
            "localrelay": true,
            "timeoffset": 0,
            "networkactive": true,
            "connections": 0,
            "networks": [],
            "relayfee": 0.0,
            "incrementalfee": 0.0,
            "warnings": ["unknown new soft fork"]
        }"#;
        let info: NetworkInfo = serde_json::from_str(json).unwrap();
        assert!(info.warnings.is_array());
    }

    #[test]
    fn mining_info_parses_regtest_sample() {
        let json = r#"{
            "blocks": 101,
            "currentblockweight": 4000,
            "currentblocktx": 1,
            "difficulty": 4.656542373906925e-10,
            "networkhashps": 0.0009765625,
            "pooledtx": 0,
            "chain": "regtest",
            "warnings": ""
        }"#;
        let info: MiningInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.blocks, 101);
        assert_eq!(info.chain, "regtest");
    }

    #[test]
    fn mining_info_parses_minimal_subset() {
        // Older / pruned builds might omit currentblock*. The struct
        // marks those optional so this still parses.
        let json = r#"{
            "blocks": 851234,
            "difficulty": 79351641.4,
            "networkhashps": 5.6e20,
            "pooledtx": 3,
            "chain": "main"
        }"#;
        let info: MiningInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.blocks, 851234);
        assert_eq!(info.currentblockweight, None);
        assert!(info.warnings.is_null());
    }
}

// ---------------------------------------------------------------------------
// getblock (verbosity 1) / getrawtransaction (verbose)
// ---------------------------------------------------------------------------

/// `getblock <hash> 1` — the fields the pool reads. Verbosity 1 lists txids
/// only, so a caller after the coinbase does not pull the whole block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxids {
    pub hash: String,
    pub height: u64,
    /// Txids in block order; `[0]` is the coinbase.
    pub tx: Vec<String>,
}

/// `getrawtransaction <txid> true <blockhash>` — the fields the pool reads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodedTransaction {
    pub txid: String,
    #[serde(default)]
    pub vout: Vec<TransactionOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// Value in BTC, as Core reports it.
    #[serde(default)]
    pub value: f64,
    #[serde(rename = "scriptPubKey", default)]
    pub script_pub_key: ScriptPubKey,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScriptPubKey {
    /// Present for outputs Core can express as an address. Absent for
    /// OP_RETURN (the witness commitment) and other non-address scripts.
    #[serde(default)]
    pub address: Option<String>,
}
