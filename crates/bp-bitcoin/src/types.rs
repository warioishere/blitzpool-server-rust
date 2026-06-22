// SPDX-License-Identifier: AGPL-3.0-or-later

//! Response types for `getnetworkinfo`, `getmininginfo`, `getpeerinfo`.
//!
//! Fields mirror the JSON output of bitcoin-core v29+. Fields that may be
//! absent in older / newer versions are wrapped in `Option`. Unknown
//! fields are silently ignored by `serde` so adding new fields in future
//! bitcoind releases does not break us.

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

// ---------------------------------------------------------------------------
// getpeerinfo (single-peer entry)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: u64,
    /// IP:port of the peer.
    pub addr: String,
    /// Local network address that peer connected to / from.
    #[serde(default)]
    pub addrbind: Option<String>,
    #[serde(default)]
    pub addrlocal: Option<String>,
    /// Symbolic service names (NETWORK, WITNESS, …).
    #[serde(default)]
    pub servicesnames: Vec<String>,
    #[serde(default)]
    pub services: Option<String>,
    pub relaytxes: bool,
    pub lastsend: i64,
    pub lastrecv: i64,
    pub bytessent: u64,
    pub bytesrecv: u64,
    pub conntime: i64,
    pub timeoffset: i64,
    #[serde(default)]
    pub pingtime: Option<f64>,
    #[serde(default)]
    pub minping: Option<f64>,
    /// Network discriminator the peer connects over —
    /// `"ipv4"` / `"ipv6"` / `"onion"` / `"i2p"` / `"cjdns"` /
    /// `"not_publicly_routable"`. Optional because some older
    /// bitcoin-core versions omit it. Used by `/api/info/peers`.
    #[serde(default)]
    pub network: Option<String>,

    /// Reported subversion string of the peer, e.g. `/Satoshi:29.0.0/`.
    pub subver: String,
    pub inbound: bool,
    /// `"inbound"` / `"manual"` / `"feeler"` / `"outbound-full-relay"` /
    /// `"block-relay-only"` / `"addr-fetch"`.
    #[serde(default)]
    pub connection_type: Option<String>,
    pub startingheight: i64,
    #[serde(default)]
    pub synced_headers: Option<i64>,
    #[serde(default)]
    pub synced_blocks: Option<i64>,
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Fixture-based parsing tests ----
    //
    // These exercise just the deserialization side of bitcoin-core's RPC
    // output. They don't validate the SQL/HTTP wire path (that's phase-3
    // regtest territory) — they catch shape-drift between our struct
    // definitions and the JSON the daemon actually emits.

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
        // Older / pruned builds might omit currentblock*. Our struct
        // marks those optional so this should still parse.
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

    #[test]
    fn peer_info_parses_array() {
        let json = r#"[
            {
                "id": 0,
                "addr": "1.2.3.4:8333",
                "services": "0000000000000409",
                "servicesnames": ["NETWORK", "WITNESS"],
                "relaytxes": true,
                "lastsend": 1700000000,
                "lastrecv": 1700000001,
                "bytessent": 123,
                "bytesrecv": 456,
                "conntime": 1699999000,
                "timeoffset": -1,
                "pingtime": 0.123,
                "minping": 0.100,
                "subver": "/Satoshi:29.0.0/",
                "inbound": false,
                "connection_type": "outbound-full-relay",
                "startingheight": 851000,
                "synced_headers": 851234,
                "synced_blocks": 851234,
                "version": 70016
            }
        ]"#;
        let peers: Vec<PeerInfo> = serde_json::from_str(json).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, "1.2.3.4:8333");
        assert_eq!(
            peers[0].connection_type.as_deref(),
            Some("outbound-full-relay")
        );
        assert!(!peers[0].inbound);
    }

    #[test]
    fn peer_info_tolerates_missing_optional_fields() {
        // Minimal subset older builds may emit.
        let json = r#"[{
            "id": 1,
            "addr": "5.6.7.8:8333",
            "relaytxes": false,
            "lastsend": 0,
            "lastrecv": 0,
            "bytessent": 0,
            "bytesrecv": 0,
            "conntime": 0,
            "timeoffset": 0,
            "subver": "/older:1.0/",
            "inbound": true,
            "startingheight": 0,
            "version": 70015
        }]"#;
        let peers: Vec<PeerInfo> = serde_json::from_str(json).unwrap();
        assert_eq!(peers[0].id, 1);
        assert_eq!(peers[0].connection_type, None);
    }
}
