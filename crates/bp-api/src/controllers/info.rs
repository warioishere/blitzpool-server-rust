// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/info/*` + `/api/pool` + `/api/network` + `/api/health`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::Json,
    routing::get,
    Router,
};
use bp_common::MiningMode;
use bp_db::{
    find_found_blocks, find_high_scores, find_network_difficulty_tracker,
    find_pool_mode_hashrate_since, find_user_agents,
};
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::Serialize;

use crate::error::ApiError;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::SharedState;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route("/api/info", get(info::<H, M>))
        .route("/api/info/chart/mode/:mode", get(chart_mode::<H, M>))
        .route("/api/info/version", get(version::<H, M>))
        .route("/api/info/core", get(core::<H, M>))
        .route("/api/info/peers", get(peers::<H, M>))
        .route("/api/info/difficulty", get(difficulty::<H, M>))
        .route("/api/info/block-template", get(block_template::<H, M>))
        .route(
            "/api/info/next-block-reward",
            get(next_block_reward::<H, M>),
        )
        .route(
            "/api/client/:address/block-template",
            get(client_block_template::<H, M>),
        )
        .route("/api/info/chart", get(chart::<H, M>))
        .route("/api/info/accepted", get(accepted::<H, M>))
        .route("/api/info/workers", get(workers::<H, M>))
        .route("/api/info/rejected", get(rejected::<H, M>))
        .route("/api/info/shares", get(shares::<H, M>))
        .route("/api/pool", get(pool::<H, M>))
        .route("/api/network", get(network::<H, M>))
        .route("/api/health", get(health::<H, M>))
}

// ─── /api/info/version ────────────────────────────────────────────

#[derive(Serialize)]
struct VersionResponse {
    /// Wire shape `{ version: "v<semver>" }` — the `v`-prefix is
    /// part of the string so the UI can render it verbatim.
    version: String,
}

async fn version<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<VersionResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Ok(Json(VersionResponse {
        version: format!("v{}", state.pool_version),
    }))
}

// ─── /api/info/core ───────────────────────────────────────────────

async fn core<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Box<serde_json::value::RawValue>, _, ApiError>(
            "CORE_INFO".to_string(),
            TtlKind::CoreInfo,
            async move {
                let rpc = s
                    .bitcoin_rpc
                    .as_ref()
                    .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
                rpc.get_network_info_raw().await.map_err(ApiError::from)
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/peers ──────────────────────────────────────────────

/// `/api/info/peers` entry. `version` is the bitcoin-RPC `subver`
/// string projected forward so the UI can render it verbatim.
#[derive(Serialize)]
struct PeerEntry {
    version: String,
    direction: &'static str,
    location: Option<String>,
    bytesrecv: u64,
    bytessent: u64,
    network: Option<String>,
    pingtime: Option<f64>,
}

async fn peers<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<PeerEntry>, _, ApiError>(
            "PEER_INFO".to_string(),
            TtlKind::PeerInfo,
            async move {
                let rpc = s
                    .bitcoin_rpc
                    .as_ref()
                    .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
                // Read the raw JSON rather than a typed `Vec<PeerInfo>` — bitcoin-core
                // keeps adding fields to `getpeerinfo` (v31: `last_inv_sequence`,
                // `inv_to_send`, `bip152_hb_to/from`, `presynced_headers`,
                // `last_transaction`, `last_block`). A strict struct deserialise
                // would fail the whole endpoint on every new field; the raw
                // projection only reads the keys the UI actually renders.
                let raw: serde_json::Value = rpc.call("getpeerinfo", serde_json::json!([])).await?;
                let peers = raw.as_array().cloned().unwrap_or_default();
                let mut out = Vec::with_capacity(peers.len());
                for p in peers {
                    let addr = p.get("addr").and_then(|v| v.as_str()).unwrap_or_default();
                    let ip = extract_ip(addr);
                    let location = if addr.contains(".onion") {
                        Some("hidden through tor".to_string())
                    } else if addr.contains(".i2p") {
                        Some("hidden through i2p".to_string())
                    } else {
                        match (&s.geoip, ip.as_deref()) {
                            (Some(handle), Some(ip)) => {
                                if is_public_ip(ip) {
                                    handle
                                        .get_location(ip)
                                        .await
                                        .filter(|loc| loc.is_meaningful())
                                        .map(|loc| format_location(&loc))
                                } else {
                                    Some("hidden through tor".to_string())
                                }
                            }
                            _ => None,
                        }
                    };
                    let subver = p
                        .get("subver")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let inbound = p.get("inbound").and_then(|v| v.as_bool()).unwrap_or(false);
                    let bytesrecv = p.get("bytesrecv").and_then(|v| v.as_u64()).unwrap_or(0);
                    let bytessent = p.get("bytessent").and_then(|v| v.as_u64()).unwrap_or(0);
                    let network = p
                        .get("network")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let pingtime = p.get("pingtime").and_then(|v| v.as_f64());
                    out.push(PeerEntry {
                        version: subver,
                        direction: if inbound { "inbound" } else { "outbound" },
                        location,
                        bytesrecv,
                        bytessent,
                        network,
                        pingtime,
                    });
                }
                Ok(out)
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

fn extract_ip(addr: &str) -> Option<String> {
    if let Some(stripped) = addr.strip_prefix('[') {
        // IPv6 form `[::1]:8333` → `::1`
        stripped.split_once(']').map(|(ip, _)| ip.to_string())
    } else {
        // IPv4 form `1.2.3.4:8333` → `1.2.3.4`. If no port present,
        // the whole string is the IP.
        Some(
            addr.rsplit_once(':')
                .map(|(ip, _)| ip.to_string())
                .unwrap_or_else(|| addr.to_string()),
        )
    }
}

fn is_public_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        let a = parts[0].parse::<u8>().unwrap_or(0);
        let b = parts[1].parse::<u8>().unwrap_or(0);
        if a == 10 || a == 127 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
        return true;
    }
    let lower = ip.to_lowercase();
    if lower == "::1" {
        return false;
    }
    if lower.starts_with("fc") || lower.starts_with("fd") {
        return false;
    }
    if lower.starts_with("fe8")
        || lower.starts_with("fe9")
        || lower.starts_with("fea")
        || lower.starts_with("feb")
    {
        return false;
    }
    !ip.is_empty()
}

fn format_location(loc: &bp_geoip::GeoLocation) -> String {
    match (&loc.city, &loc.country) {
        (Some(city), Some(country)) => format!("{city}, {country}"),
        (None, Some(country)) => country.clone(),
        (Some(city), None) => city.clone(),
        _ => String::new(),
    }
}

// ─── /api/info/difficulty ────────────────────────────────────────
//
// Returns the singleton tracker row maintained by
// bp-notifications::cron::network_difficulty. UI uses it to render
// the current network-difficulty + previous value for the delta arrow.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DifficultyResponse {
    current: f64,
    previous: Option<f64>,
    updated_at: String,
}

async fn difficulty<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<DifficultyResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let row = find_network_difficulty_tracker(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(DifficultyResponse {
        current: row.current_difficulty,
        previous: row.previous_difficulty,
        updated_at: crate::time_range::format_iso_ms(row.updated_at),
    }))
}

// ─── /api/info/block-template ────────────────────────────────────
//
// Exposes TDP-snapshot fields the UI can use to render "current
// template" without round-tripping bitcoin-core (see DEFERRED.md
// block-template entry for shape divergence notes).

async fn block_template<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<serde_json::Value>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    // Raw bitcoind `getblocktemplate` passthrough — the UI's
    // block-template preview consumes the full RPC response
    // (transactions, coinbasevalue, target, height, etc.). The
    // TDP-snapshot projection used previously only carries the
    // SV2-spec subset; the UI needs the whole document.
    let rpc = state
        .bitcoin_rpc
        .as_ref()
        .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
    let template: serde_json::Value = rpc
        .call(
            "getblocktemplate",
            serde_json::json!([{"rules": ["segwit", "taproot"]}]),
        )
        .await?;
    Ok(Json(template))
}

/// Next-block reward, computed server-side from the current `getblocktemplate`.
/// `coinbasevalue` is the authoritative subsidy + real mempool fees the pool
/// would mine (the same value the live coinbase payout is built from), split
/// into subsidy + fees via the shared halving helper. Lets the UI drop its
/// hard-coded subsidy and per-client mempool.space fetch.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NextBlockReward {
    reward_sats: u64,
    subsidy_sats: u64,
    fee_sats: u64,
    height: u64,
}

async fn next_block_reward<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<NextBlockReward>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let rpc = state
        .bitcoin_rpc
        .as_ref()
        .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
    let template: serde_json::Value = rpc
        .call(
            "getblocktemplate",
            serde_json::json!([{"rules": ["segwit", "taproot"]}]),
        )
        .await?;
    let reward_sats = template
        .get("coinbasevalue")
        .and_then(|v| v.as_u64())
        .ok_or(ApiError::Unavailable("template missing coinbasevalue"))?;
    let height = template
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or(ApiError::Unavailable("template missing height"))?;
    let subsidy_sats = crate::controllers::groups::block_subsidy_sats(height, state.network);
    let fee_sats = reward_sats.saturating_sub(subsidy_sats);
    Ok(Json(NextBlockReward {
        reward_sats,
        subsidy_sats,
        fee_sats,
        height,
    }))
}

/// Per-recipient payout row — `{address, percent, sats}` triple
/// the UI uses to render the distribution preview.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PayoutInfoEntry {
    address: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    sats: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientBlockTemplateResponse {
    block_template: serde_json::Value,
    /// `solo` / `pplns` / `group-solo` — drives the UI's
    /// distribution-preview labelling.
    mode: &'static str,
    payout_information: Vec<PayoutInfoEntry>,
    /// Set only when `mode == "group-solo"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    /// Full block hex (header + per-address coinbase + template txs)
    /// with a zero nonce, suitable for the UI's preview panel. Empty
    /// when payouts are unknown (PPLNS window not yet warm, etc.) or
    /// the assembly step fails — the panel then renders just the
    /// template + mode tile.
    block_hex: String,
    /// Per-address coinbase tx hex (witness form, zero extranonces).
    /// Same fallback behaviour as `blockHex`.
    coinbase_tx_hex: String,
}

async fn client_block_template<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    use bp_common::AddressId;

    let addr = AddressId::new(address.clone()).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("CLIENT_BLOCK_TEMPLATE_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<ClientBlockTemplateResponse, _, ApiError>(
            key,
            TtlKind::ClientBlockTemplate,
            async move {
                let rpc = s
                    .bitcoin_rpc
                    .as_ref()
                    .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
                let template: serde_json::Value = rpc
                    .call(
                        "getblocktemplate",
                        serde_json::json!([{"rules": ["segwit", "taproot"]}]),
                    )
                    .await?;
                let reward_sats = template
                    .get("coinbasevalue")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                // Mode resolution: group membership wins, then
                // Blockparty admin routing, then PPLNS window presence,
                // else solo (matches /api/pplns/mode/:address).
                let mut mode: &'static str = "solo";
                let mut group_id: Option<uuid::Uuid> = None;
                if let Some(member) = bp_db::find_group_member_by_address(&s.pool, &addr).await? {
                    mode = "group-solo";
                    group_id = Some(member.group_id);
                } else if let Some(bp) = s.blockparty.as_ref() {
                    if let Some(gid) = bp.routable_group_id_for_admin(&addr).await {
                        mode = "blockparty";
                        group_id = Some(gid);
                    }
                }
                if mode == "solo" {
                    if let Some(engine) = s.pplns.as_ref() {
                        if let Ok(Some(status)) = engine.reader().address_status(&address).await {
                            if status.current_window_shares > 0.0 {
                                mode = "pplns";
                            }
                        }
                    }
                }

                let payouts: Vec<PayoutInfoEntry> = match mode {
                    "group-solo" => {
                        let gid = group_id.expect("set when mode == group-solo");
                        match s.group_solo.as_ref() {
                            Some(engine) => {
                                match engine.build_distribution(gid, reward_sats, &addr).await {
                                    Ok(dist) => dist
                                        .payouts
                                        .iter()
                                        .map(|p| PayoutInfoEntry {
                                            address: p.address.as_str().to_string(),
                                            percent: p.percent,
                                            sats: p.sats.0 as u64,
                                        })
                                        .collect(),
                                    Err(_) => Vec::new(),
                                }
                            }
                            None => Vec::new(),
                        }
                    }
                    "blockparty" => {
                        let gid = group_id.expect("set when mode == blockparty");
                        match s.blockparty.as_ref() {
                            Some(bp) => match bp
                                .build_payouts(gid, bp_common::Sats(reward_sats as i64))
                                .await
                            {
                                Ok(Some(dist)) => dist
                                    .payouts
                                    .iter()
                                    .map(|p| PayoutInfoEntry {
                                        address: p.address.as_str().to_string(),
                                        percent: p.percent,
                                        sats: p.sats.0 as u64,
                                    })
                                    .collect(),
                                _ => Vec::new(),
                            },
                            None => Vec::new(),
                        }
                    }
                    "pplns" => match s.pplns.as_ref() {
                        Some(engine) => match engine.build_distribution(reward_sats).await {
                            Ok(dist) => dist
                                .payouts
                                .iter()
                                .map(|p| PayoutInfoEntry {
                                    address: p.address.as_str().to_string(),
                                    percent: p.percent,
                                    sats: p.sats.0 as u64,
                                })
                                .collect(),
                            Err(_) => Vec::new(),
                        },
                        None => Vec::new(),
                    },
                    _ => {
                        // Solo: fee_address (if configured) + miner address. Fee %
                        // is taken from the PPLNS engine config so a pool running
                        // without PPLNS still publishes the operator's intended
                        // fee split.
                        let (fee_address, fee_percent) = s
                            .pplns
                            .as_ref()
                            .map(|e| {
                                let cfg = e.reader().fee_config();
                                (cfg.fee_address, cfg.fee_percent)
                            })
                            .unwrap_or((None, 0.0));
                        let mut entries = Vec::new();
                        if let Some(fee_addr) = fee_address.filter(|a| !a.is_empty()) {
                            let fee_sats =
                                ((reward_sats as f64) * fee_percent / 100.0).floor() as u64;
                            let miner_sats = reward_sats.saturating_sub(fee_sats);
                            entries.push(PayoutInfoEntry {
                                address: fee_addr,
                                percent: fee_percent,
                                sats: fee_sats,
                            });
                            entries.push(PayoutInfoEntry {
                                address: addr.as_str().to_string(),
                                percent: 100.0 - fee_percent,
                                sats: miner_sats,
                            });
                        } else {
                            entries.push(PayoutInfoEntry {
                                address: addr.as_str().to_string(),
                                percent: 100.0,
                                sats: reward_sats,
                            });
                        }
                        entries
                    }
                };

                // Build the per-address coinbase + full block preview when we have
                // enough payout info. An empty distribution (e.g. PPLNS window
                // empty at startup) skips block assembly so the panel still
                // renders the template + mode tile.
                let (coinbase_tx_hex, block_hex) = if payouts.is_empty() {
                    (String::new(), String::new())
                } else {
                    assemble_block_preview(&template, &payouts, s.network, &s.pool_identifier)
                        .unwrap_or_else(|_| (String::new(), String::new()))
                };
                Ok(ClientBlockTemplateResponse {
                    block_template: template,
                    mode,
                    payout_information: payouts,
                    group_id: group_id.map(|g| g.to_string()),
                    block_hex,
                    coinbase_tx_hex,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

/// Construct a preview coinbase + full block from the payout list +
/// bitcoind's `getblocktemplate` response. The coinbase uses zero
/// extranonces (the miner fills them in at submit time) so the preview
/// is byte-stable across renders. The block carries every tx the
/// template proposed plus the just-built coinbase, with a zero nonce
/// in the header (preview, never submitted).
fn assemble_block_preview(
    template: &serde_json::Value,
    payouts: &[PayoutInfoEntry],
    network: bitcoin::Network,
    pool_identifier: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    use bitcoin::hashes::Hash;
    use bitcoin::{
        block::{Header, Version as BlockVersion},
        consensus, BlockHash, CompactTarget, Transaction, TxMerkleNode,
    };
    use bp_mining_job::{
        build_mining_job, CoinbaseTemplate, MiningJob, PayoutEntry, EXTRANONCE_SLOT_LEN,
    };
    let block_height = template
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or("missing template.height")? as u32;
    let coinbase_value_sats = template
        .get("coinbasevalue")
        .and_then(|v| v.as_u64())
        .ok_or("missing template.coinbasevalue")?;
    let dwc_hex = template
        .get("default_witness_commitment")
        .and_then(|v| v.as_str())
        .ok_or("missing template.default_witness_commitment")?;
    let dwc_bytes = hex::decode(dwc_hex)?;
    // OP_RETURN OP_PUSHBYTES_36 (4-byte magic + 32-byte commitment).
    if dwc_bytes.len() < 6 + 32 {
        return Err("default_witness_commitment too short".into());
    }
    let mut witness_commitment = [0u8; 32];
    witness_commitment.copy_from_slice(&dwc_bytes[6..6 + 32]);

    let payout_entries: Vec<PayoutEntry> = payouts
        .iter()
        .map(|p| PayoutEntry {
            address: p.address.clone(),
            percent: p.percent,
        })
        .collect();
    let cb_template = CoinbaseTemplate {
        block_height,
        coinbase_value_sats,
        witness_commitment,
    };
    let job: MiningJob = build_mining_job(
        network,
        &payout_entries,
        &cb_template,
        pool_identifier,
        EXTRANONCE_SLOT_LEN,
    )
    .map_err(|e| format!("build_mining_job: {e}"))?;

    // Zero extranonces — preview is byte-stable; the miner splices in
    // its own values at submit time.
    let zero_e1 = [0u8; 4];
    let zero_e2 = [0u8; 8];
    let coinbase_bytes = job.witness_coinbase_with_extranonce(&zero_e1, &zero_e2);
    let coinbase_tx_hex = hex::encode(&coinbase_bytes);

    // Deserialise all the template's transactions so consensus::serialize
    // re-emits them in the standard block layout.
    let mut txdata: Vec<Transaction> = Vec::new();
    let coinbase_tx: Transaction = consensus::deserialize(&coinbase_bytes)
        .map_err(|e| format!("coinbase deserialize: {e}"))?;
    txdata.push(coinbase_tx);
    if let Some(arr) = template.get("transactions").and_then(|v| v.as_array()) {
        for entry in arr {
            let data_hex = entry
                .get("data")
                .and_then(|v| v.as_str())
                .ok_or("template tx missing data")?;
            let bytes = hex::decode(data_hex)?;
            let tx: Transaction = consensus::deserialize(&bytes)?;
            txdata.push(tx);
        }
    }

    let version_raw = template
        .get("version")
        .and_then(|v| v.as_i64())
        .ok_or("missing template.version")? as i32;
    let prev_hex = template
        .get("previousblockhash")
        .and_then(|v| v.as_str())
        .ok_or("missing template.previousblockhash")?;
    let mut prev_bytes = hex::decode(prev_hex)?;
    if prev_bytes.len() != 32 {
        return Err("previousblockhash must be 32 bytes".into());
    }
    prev_bytes.reverse(); // RPC returns big-endian display order.
    let prev_blockhash = BlockHash::from_byte_array(
        <[u8; 32]>::try_from(prev_bytes.as_slice()).map_err(|_| "prevhash slice")?,
    );
    let bits_hex = template
        .get("bits")
        .and_then(|v| v.as_str())
        .ok_or("missing template.bits")?;
    let bits = CompactTarget::from_consensus(u32::from_str_radix(bits_hex, 16)?);
    let time = template
        .get("curtime")
        .or_else(|| template.get("mintime"))
        .and_then(|v| v.as_u64())
        .ok_or("missing template.curtime|mintime")? as u32;

    let merkle_root =
        bitcoin::merkle_tree::calculate_root(txdata.iter().map(bitcoin::Transaction::compute_txid))
            .map(|raw| TxMerkleNode::from_raw_hash(raw.into()))
            .unwrap_or(TxMerkleNode::all_zeros());

    let header = Header {
        version: BlockVersion::from_consensus(version_raw),
        prev_blockhash,
        merkle_root,
        time,
        bits,
        nonce: 0,
    };
    let block = bitcoin::Block { header, txdata };
    let block_hex = hex::encode(consensus::serialize(&block));
    Ok((coinbase_tx_hex, block_hex))
}

// ─── /api/pool ────────────────────────────────────────────────────

/// Pool-wide summary card. `blocksFound` is the full found-block
/// log (same projection `/api/info` returns under the `blockData`
/// key); the UI renders it as a tile list. `fee` is reported as `0`
/// for compatibility with the existing dashboard tile.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PoolResponse {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_hash_rate: f64,
    block_height: Option<i64>,
    total_miners: i64,
    blocks_found: Vec<FoundBlockEntry>,
    fee: i64,
}

async fn pool<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<PoolResponse, _, ApiError>(
            "POOL_INFO".to_string(),
            TtlKind::PoolInfo,
            async move {
                let total_hash_rate = bp_db::sum_active_pool_hashrate(&s.pool).await?;
                let total_miners: i64 =
                    sqlx::query_scalar!(r#"SELECT COUNT("userAgent") FROM client_entity"#,)
                        .fetch_one(&s.pool)
                        .await
                        .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?
                        .unwrap_or(0);
                let blocks_found: Vec<FoundBlockEntry> = find_found_blocks(&s.pool)
                    .await?
                    .into_iter()
                    .map(|b| FoundBlockEntry {
                        height: b.height,
                        miner_address: b.miner_address,
                        worker: b.worker,
                        session_id: b.session_id,
                    })
                    .collect();
                let block_height: Option<i64> = if let Some(rpc) = s.bitcoin_rpc.as_ref() {
                    rpc.get_block_count().await.ok().map(|h| h as i64)
                } else {
                    None
                };
                Ok(PoolResponse {
                    total_hash_rate,
                    block_height,
                    total_miners,
                    blocks_found,
                    fee: 0,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/network ─────────────────────────────────────────────────

async fn network<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let rpc = state
        .bitcoin_rpc
        .as_ref()
        .ok_or(ApiError::Unavailable("bitcoin-rpc not wired"))?;
    let raw = rpc.get_mining_info_raw().await?;
    Ok(JsonBytes(bytes::Bytes::from(raw.get().as_bytes().to_vec())))
}

// ─── /api/health ──────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
    version: String,
    uptime: u64,
    uptime_readable: String,
    checks: HealthChecks,
    timestamp: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthChecks {
    database: &'static str,
    bitcoin: Option<&'static str>,
    /// Redis/cache reachability. Informational only — a cache outage
    /// does NOT flip `status` to "degraded" (the share path is
    /// availability-first and survives a Redis blip). `None` when no
    /// Redis handle is wired into the API state.
    cache: Option<&'static str>,
    /// TDP (bitcoin-core template feed) freshness. `"connected"` when
    /// the last NewTemplate/SetNewPrevHash is within the configured
    /// staleness window, `"stale"` when bitcoin-core has stopped
    /// feeding fresh work for longer than that (auto-reconnect failed
    /// to recover, or core is wedged). `None` when no TDP handle is
    /// wired. Unlike `cache`, a stale feed DOES flip `status` to
    /// "degraded" — the pool can't hand out valid work without it.
    tdp: Option<&'static str>,
}

async fn health<H, M>(
    State(state): State<SharedState<H, M>>,
) -> Result<Json<HealthResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let now = chrono::Utc::now();
    let uptime_ms = (now.timestamp_millis() - state.start_time.timestamp_millis()).max(0) as u64;
    let database = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();
    let bitcoin_ok = if let Some(rpc) = state.bitcoin_rpc.as_ref() {
        Some(rpc.get_network_info().await.is_ok())
    } else {
        None
    };
    // Cache (Redis) round-trip: SET a 1s-TTL probe key, read it back.
    // Confirms Redis round-trips, not just TCP-accepts. Informational
    // only — a Redis outage doesn't make the pool "degraded".
    let cache_ok = if let Some(conn) = state.redis.as_ref() {
        Some(redis_health_roundtrip(conn.clone()).await)
    } else {
        None
    };
    // TDP feed freshness. `last_update_at` is the wall-clock of the last
    // template/prev-hash; when the feed has never produced one (boot,
    // or core never attached) we measure age from process start so a
    // core that never comes up still trips the staleness threshold
    // instead of staying silently "fresh" forever.
    let tdp_fresh = state.tdp.as_ref().map(|handle| {
        let last_update_at = handle.current_snapshot().last_update_at;
        tdp_is_fresh(
            last_update_at,
            state.start_time.timestamp_millis(),
            now.timestamp_millis(),
            state.tdp_staleness_threshold_ms,
        )
    });
    // `status` gates on database + bitcoin RPC + TDP freshness. Redis is
    // availability-first (surfaced in `checks.cache` but never degrading);
    // a stale TDP feed DOES degrade because the pool can't produce valid
    // work without fresh templates from bitcoin-core.
    let status = if database && bitcoin_ok.unwrap_or(true) && tdp_fresh.unwrap_or(true) {
        "healthy"
    } else {
        "degraded"
    };
    Ok(Json(HealthResponse {
        status,
        version: state.pool_version.to_string(),
        uptime: uptime_ms,
        uptime_readable: format_uptime(uptime_ms),
        checks: HealthChecks {
            database: if database {
                "connected"
            } else {
                "disconnected"
            },
            bitcoin: bitcoin_ok.map(|b| if b { "connected" } else { "disconnected" }),
            cache: cache_ok.map(|b| if b { "connected" } else { "disconnected" }),
            tdp: tdp_fresh.map(|fresh| if fresh { "connected" } else { "stale" }),
        },
        timestamp: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
}

/// Decide whether the TDP feed counts as fresh. `last_update_at` is the
/// wall-clock of the last template/prev-hash (None until the first one
/// arrives); when absent we measure age from `start_ms` so a core that
/// never attaches still trips the threshold instead of reading fresh
/// forever. Returns `true` when the age is within `threshold_ms`.
fn tdp_is_fresh(
    last_update_at: Option<i64>,
    start_ms: i64,
    now_ms: i64,
    threshold_ms: i64,
) -> bool {
    let last = last_update_at.unwrap_or(start_ms);
    let age_ms = (now_ms - last).max(0);
    age_ms <= threshold_ms
}

/// SET a short-TTL probe key and read it back — confirms Redis is
/// reachable AND round-tripping, not just TCP-accepting. Any error or
/// value mismatch reports `false` (disconnected).
async fn redis_health_roundtrip(mut conn: redis::aio::ConnectionManager) -> bool {
    use redis::AsyncCommands;
    const KEY: &str = "__health_check__";
    if conn.set_ex::<_, _, ()>(KEY, "ok", 1).await.is_err() {
        return false;
    }
    matches!(conn.get::<_, Option<String>>(KEY).await, Ok(Some(v)) if v == "ok")
}

fn format_uptime(ms: u64) -> String {
    let secs = ms / 1000;
    let mins = secs / 60;
    let hours = mins / 60;
    let days = hours / 24;
    if days > 0 {
        format!("{}d {}h", days, hours % 24)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins % 60)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

// ─── /api/info/chart ──────────────────────────────────────────────
//
// Pool-wide hashrate timeseries. Reads `pool_share_statistics_entity`,
// converts per-slot accepted-share weight into hashrate (H/s) via
// `accepted * 2^32 / 600` (10-min slot = 600 s), and emits one point
// per fixed slot boundary. Slots beyond the chart-visibility cutoff
// (the in-progress slot) are excluded so the tail of the chart never
// shows a half-filled bucket.

use crate::time_range::{chart_slot_boundaries, ChartPoint, Range, SlotCounts, SlotDataResponse};
use axum::extract::Query;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeQuery {
    range: Option<String>,
}

use crate::time_range::{DIFFICULTY_1, SLOT_SECONDS};

async fn chart<H, M>(
    State(state): State<SharedState<H, M>>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("SITE_HASHRATE_GRAPH_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::Chart, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let rows = bp_db::find_pool_share_statistics_since(&s.pool, since).await?;
            // One ChartPoint per DB row: slot-end label + rounded
            // hashrate; UI fills any gaps itself.
            Ok(rows
                .into_iter()
                .filter(|r| r.time < cutoff)
                .map(|r| ChartPoint {
                    label: crate::time_range::format_slot_label(r.time),
                    data: (r.accepted as f64 * DIFFICULTY_1 / SLOT_SECONDS).round(),
                })
                .collect())
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/accepted ───────────────────────────────────────────

async fn accepted<H, M>(
    State(state): State<SharedState<H, M>>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_ACCEPTED_STATS_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Accepted, async move {
            let since = crate::time_range::now_ms() - range.window_ms();
            let rows = bp_db::find_pool_share_statistics_since(&s.pool, since).await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let mut buckets: BTreeMap<i64, f64> = boundaries.iter().map(|&b| (b, 0.0)).collect();
            for r in rows {
                let k = crate::time_range::bucket_key(r.time, range.slot_size_ms());
                if let Some(v) = buckets.get_mut(&k) {
                    *v += r.accepted as f64;
                }
            }
            Ok(SlotDataResponse {
                slot_data: boundaries
                    .iter()
                    .map(|&b| {
                        let mut counts = BTreeMap::new();
                        counts.insert("accepted".into(), buckets.get(&b).copied().unwrap_or(0.0));
                        SlotCounts {
                            time: crate::time_range::format_slot_label(b),
                            counts,
                        }
                    })
                    .collect(),
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/workers ────────────────────────────────────────────
//
// Two counts per slot:
//   - `addresses` = DISTINCT payout-address count
//   - `workers`   = DISTINCT (address, client_name) pair count
//
// The slot bucket key is the row's stored slot-end timestamp.

async fn workers<H, M>(
    State(state): State<SharedState<H, M>>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_WORKER_STATS_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Workers, async move {
            let since = crate::time_range::now_ms() - range.window_ms();
            // Skinny projection (slot time + address + worker only) — the
            // distinct counting stays in-process; we just avoid shipping the
            // full 17-column stats row for every session in the window.
            let rows = bp_db::find_pool_worker_rows_since(&s.pool, since).await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let mut addresses_by_slot: BTreeMap<i64, std::collections::HashSet<String>> =
                BTreeMap::new();
            let mut workers_by_slot: BTreeMap<i64, std::collections::HashSet<(String, String)>> =
                BTreeMap::new();
            for r in &rows {
                let k = crate::time_range::bucket_key(r.time, range.slot_size_ms());
                addresses_by_slot
                    .entry(k)
                    .or_default()
                    .insert(r.address.clone());
                workers_by_slot
                    .entry(k)
                    .or_default()
                    .insert((r.address.clone(), r.client_name.clone()));
            }
            Ok(SlotDataResponse {
                slot_data: boundaries
                    .iter()
                    .map(|&b| {
                        let mut counts = BTreeMap::new();
                        counts.insert(
                            "addresses".into(),
                            addresses_by_slot.get(&b).map(|s| s.len()).unwrap_or(0) as f64,
                        );
                        counts.insert(
                            "workers".into(),
                            workers_by_slot.get(&b).map(|s| s.len()).unwrap_or(0) as f64,
                        );
                        SlotCounts {
                            time: crate::time_range::format_slot_label(b),
                            counts,
                        }
                    })
                    .collect(),
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/rejected ───────────────────────────────────────────
//
// Per-reason aggregation. Every slot bucket is pre-filled with all
// known reason keys so the UI's per-reason chart series always have
// a value (zero if no shares for that reason in that slot).

/// Reason keys the UI knows about. Pre-filled into every slot so chart
/// series stay continuous even when a slot has zero rejects of a given
/// reason.
pub(crate) const REJECT_REASON_KEYS: &[&str] = &[
    "OtherUnknown",
    "JobNotFound",
    "DuplicateShare",
    "LowDifficultyShare",
    "UnauthorizedWorker",
    "NotSubscribed",
    "Stale",
];

/// Normalise the reason string stored on `pool_rejected_statistics_entity`
/// to the camel-case key the UI expects. Old rows stored kebab-case
/// (`job-not-found`, `duplicate-share`, `low-difficulty`), new rows
/// write the camel-case form directly — this map covers both forms.
pub(crate) fn normalise_reject_reason(raw: &str) -> &'static str {
    match raw {
        // Camel-case (new writer + legacy rows).
        "OtherUnknown" => "OtherUnknown",
        "JobNotFound" => "JobNotFound",
        "DuplicateShare" => "DuplicateShare",
        "LowDifficultyShare" => "LowDifficultyShare",
        "UnauthorizedWorker" => "UnauthorizedWorker",
        "NotSubscribed" => "NotSubscribed",
        "Stale" => "Stale",
        // Legacy kebab-case from earlier Rust writer.
        "job-not-found" => "JobNotFound",
        "duplicate-share" => "DuplicateShare",
        "low-difficulty" | "low-difficulty-share" => "LowDifficultyShare",
        _ => "OtherUnknown",
    }
}

async fn rejected<H, M>(
    State(state): State<SharedState<H, M>>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_REJECTED_STATS_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Rejected, async move {
            let since = crate::time_range::now_ms() - range.window_ms();
            let rows = bp_db::find_pool_rejected_statistics_since(&s.pool, since).await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let mut buckets: BTreeMap<i64, BTreeMap<String, f64>> = BTreeMap::new();
            for r in rows {
                let k = crate::time_range::bucket_key(r.time, range.slot_size_ms());
                let key = normalise_reject_reason(&r.reason).to_string();
                *buckets.entry(k).or_default().entry(key).or_default() += r.count as f64;
            }
            Ok(SlotDataResponse {
                slot_data: boundaries
                    .iter()
                    .map(|&b| {
                        let mut counts: BTreeMap<String, f64> = REJECT_REASON_KEYS
                            .iter()
                            .map(|&k| (k.to_string(), 0.0))
                            .collect();
                        if let Some(seen) = buckets.remove(&b) {
                            for (k, v) in seen {
                                counts.insert(k, v);
                            }
                        }
                        SlotCounts {
                            time: crate::time_range::format_slot_label(b),
                            counts,
                        }
                    })
                    .collect(),
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/shares ─────────────────────────────────────────────
//
// Singleton totals: accepted/rejected over 1d, 14d, plus
// `acceptedSinceBlock` — sliced from the last block's `createdAt`
// in `blocks_entity`.

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SharesResponse {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    accepted_1d: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_1d: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    accepted_14d: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_14d: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    accepted_30d: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_30d: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    accepted_since_block: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_since_block: f64,
}

async fn shares<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SharesResponse, _, ApiError>(
            "POOL_SHARE_TOTALS".to_string(),
            TtlKind::Shares,
            async move {
                let now = crate::time_range::now_ms();
                const DAY: i64 = 24 * 60 * 60 * 1000;
                let day_rows = bp_db::find_pool_share_statistics_since(&s.pool, now - DAY).await?;
                let fortnight_rows =
                    bp_db::find_pool_share_statistics_since(&s.pool, now - 14 * DAY).await?;
                let month_rows =
                    bp_db::find_pool_share_statistics_since(&s.pool, now - 30 * DAY).await?;
                let accepted_1d = day_rows.iter().map(|r| r.accepted as f64).sum::<f64>();
                let rejected_1d = day_rows.iter().map(|r| r.rejected as f64).sum::<f64>();
                let accepted_14d = fortnight_rows
                    .iter()
                    .map(|r| r.accepted as f64)
                    .sum::<f64>();
                let rejected_14d = fortnight_rows
                    .iter()
                    .map(|r| r.rejected as f64)
                    .sum::<f64>();
                let accepted_30d = month_rows.iter().map(|r| r.accepted as f64).sum::<f64>();
                let rejected_30d = month_rows.iter().map(|r| r.rejected as f64).sum::<f64>();

                // Slice since the most-recent confirmed block; fall back to 0
                // (epoch → all-time total) when no block has ever been found.
                // Matches TS `sinceBlock = latestBlock?.createdAt ?? 0`: a pool
                // that hasn't found a block shows its cumulative share total,
                // not just the last day.
                let last_block_at: Option<i64> = sqlx::query_scalar(
                    r#"SELECT MAX("createdAt") FROM blocks_entity WHERE "deletedAt" IS NULL"#,
                )
                .fetch_one(&s.pool)
                .await
                .ok()
                .flatten();
                let since_block = last_block_at.unwrap_or(0);
                let block_rows =
                    bp_db::find_pool_share_statistics_since(&s.pool, since_block).await?;
                let accepted_since_block =
                    block_rows.iter().map(|r| r.accepted as f64).sum::<f64>();
                let rejected_since_block =
                    block_rows.iter().map(|r| r.rejected as f64).sum::<f64>();

                Ok(SharesResponse {
                    accepted_1d,
                    rejected_1d,
                    accepted_14d,
                    rejected_14d,
                    accepted_30d,
                    rejected_30d,
                    accepted_since_block,
                    rejected_since_block,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// Silence "unused" warning on the Arc import — used transitively
// through SharedState in every handler.
#[allow(dead_code)]
fn _force_arc_use(_: Arc<()>) {}

// ─── /api/info ────────────────────────────────────────────────────
//
// Top-level dashboard payload: found-block log, user-agent histogram,
// best-difficulty leaderboard, plus pool uptime.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundBlockEntry {
    height: i64,
    miner_address: String,
    worker: String,
    session_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserAgentEntry {
    user_agent: Option<String>,
    count: i64,
    best_difficulty: Option<f32>,
    total_hash_rate: Option<f64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HighScoreEntry {
    /// ISO-8601 timestamp; null if `updatedAt` is unrepresentable.
    updated_at: Option<String>,
    best_difficulty: f64,
    best_difficulty_user_agent: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoResponse {
    block_data: Vec<FoundBlockEntry>,
    user_agents: Vec<UserAgentEntry>,
    high_scores: Vec<HighScoreEntry>,
    /// Pool start time as ISO-8601 string.
    uptime: String,
}

async fn info<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<InfoResponse, _, ApiError>(
            "SITE_INFO".to_string(),
            TtlKind::SiteInfo,
            async move {
                let blocks = find_found_blocks(&s.pool).await?;
                let agents = find_user_agents(&s.pool).await?;
                let scores = find_high_scores(&s.pool).await?;
                Ok(InfoResponse {
                    block_data: blocks
                        .into_iter()
                        .map(|b| FoundBlockEntry {
                            height: b.height,
                            miner_address: b.miner_address,
                            worker: b.worker,
                            session_id: b.session_id,
                        })
                        .collect(),
                    user_agents: agents
                        .into_iter()
                        .map(|a| UserAgentEntry {
                            user_agent: a.user_agent,
                            count: a.count,
                            best_difficulty: a.best_difficulty,
                            total_hash_rate: a.total_hash_rate,
                        })
                        .collect(),
                    high_scores: scores
                        .into_iter()
                        .map(|s| HighScoreEntry {
                            updated_at: s.updated_at,
                            best_difficulty: s.best_difficulty,
                            best_difficulty_user_agent: s.best_difficulty_user_agent,
                        })
                        .collect(),
                    uptime: s
                        .start_time
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/chart/mode/:mode ────────────────────────────────────
//
// Per-payout-mode hashrate chart. Default range is `1d`; valid range
// presets are `1d`, `3d`, `7d` (NOTE: differs from `/api/info/chart`
// which also accepts `1m`). Unknown `:mode` → empty array.
//
// Aggregation:
//   - 10-min slots
//   - hide both the in-progress and just-ended slot (via the same
//     visibility-cutoff helper the writer uses)
//   - hashrate = ROUND(diff * DIFFICULTY_1 / 600)

async fn chart_mode<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(mode_str): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<ChartPoint>>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let mode: MiningMode = match mode_str.parse() {
        Ok(m) => m,
        Err(_) => return Ok(Json(Vec::new())),
    };
    // Local range parsing — this endpoint's set is {1d, 3d, 7d} with
    // default `7d`, narrower than the shared `Range::parse`.
    let (window_ms, _slot) = match q.range.as_deref().unwrap_or("7d") {
        "1d" => (24 * 60 * 60 * 1000_i64, 600_000_i64),
        "3d" => (3 * 24 * 60 * 60 * 1000_i64, 600_000_i64),
        _ => (7 * 24 * 60 * 60 * 1000_i64, 600_000_i64),
    };
    let since = crate::time_range::now_ms() - window_ms;
    let cutoff_slot = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
    let rows = find_pool_mode_hashrate_since(&state.pool, mode, since).await?;
    Ok(Json(
        rows.into_iter()
            .filter(|r| r.time < cutoff_slot)
            .map(|r| ChartPoint {
                label: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.time)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                    .unwrap_or_default(),
                data: ((r.diff as f64) * DIFFICULTY_1 / SLOT_SECONDS).round(),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_uptime_seconds_only() {
        assert_eq!(format_uptime(45_000), "45s");
    }

    #[test]
    fn tdp_fresh_when_recent_template() {
        // last update 10s ago, 120s threshold → fresh.
        let now = 1_000_000_000;
        assert!(tdp_is_fresh(Some(now - 10_000), now - 60_000, now, 120_000));
    }

    #[test]
    fn tdp_stale_when_template_older_than_threshold() {
        // last update 5min ago, 120s threshold → stale.
        let now = 1_000_000_000;
        assert!(!tdp_is_fresh(
            Some(now - 300_000),
            now - 600_000,
            now,
            120_000
        ));
    }

    #[test]
    fn tdp_no_template_measures_age_from_start() {
        let now = 1_000_000_000;
        // Booted 10s ago, no template yet → still inside the window.
        assert!(tdp_is_fresh(None, now - 10_000, now, 120_000));
        // Booted 5min ago, core never fed a template → stale.
        assert!(!tdp_is_fresh(None, now - 300_000, now, 120_000));
    }

    #[test]
    fn tdp_clock_skew_backwards_is_not_stale() {
        // last_update_at in the (apparent) future → age clamps to 0, fresh.
        let now = 1_000_000_000;
        assert!(tdp_is_fresh(Some(now + 5_000), now, now, 120_000));
    }

    #[test]
    fn format_uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(2 * 60_000 + 30_000), "2m 30s");
    }

    #[test]
    fn format_uptime_hours_and_minutes() {
        assert_eq!(format_uptime(3 * 3_600_000 + 17 * 60_000), "3h 17m");
    }

    #[test]
    fn format_uptime_days_and_hours() {
        assert_eq!(format_uptime(2 * 86_400_000 + 5 * 3_600_000), "2d 5h");
    }

    #[test]
    fn is_public_ip_classifies_correctly() {
        // Private ranges
        assert!(!is_public_ip("10.0.0.1"));
        assert!(!is_public_ip("10.255.255.255"));
        assert!(!is_public_ip("172.16.0.1"));
        assert!(!is_public_ip("172.31.255.255"));
        assert!(!is_public_ip("192.168.1.1"));
        assert!(!is_public_ip("127.0.0.1"));
        // IPv6 loopback + ULA + link-local
        assert!(!is_public_ip("::1"));
        assert!(!is_public_ip("fc00::1"));
        assert!(!is_public_ip("fd12:3456::1"));
        assert!(!is_public_ip("fe80::1"));
        // Public ranges
        assert!(is_public_ip("8.8.8.8"));
        assert!(is_public_ip("1.1.1.1"));
        assert!(is_public_ip("2001:db8::1"));
    }

    #[test]
    fn extract_ip_handles_ipv4_with_port() {
        assert_eq!(extract_ip("1.2.3.4:8333"), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn extract_ip_handles_ipv6_bracket_form() {
        assert_eq!(extract_ip("[::1]:8333"), Some("::1".to_string()));
    }

    #[test]
    fn extract_ip_handles_no_port() {
        assert_eq!(extract_ip("1.2.3.4"), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn normalise_reject_reason_covers_legacy_kebab_forms() {
        assert_eq!(normalise_reject_reason("job-not-found"), "JobNotFound");
        assert_eq!(normalise_reject_reason("duplicate-share"), "DuplicateShare");
        assert_eq!(
            normalise_reject_reason("low-difficulty"),
            "LowDifficultyShare"
        );
        assert_eq!(
            normalise_reject_reason("low-difficulty-share"),
            "LowDifficultyShare"
        );
        assert_eq!(normalise_reject_reason("totally-unknown"), "OtherUnknown");
    }

    #[test]
    fn normalise_reject_reason_passthrough_camel_forms() {
        for key in REJECT_REASON_KEYS {
            assert_eq!(normalise_reject_reason(key), *key);
        }
    }
}
