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
    find_pool_mode_hashrate_since,
};
use bp_mining_mode::MiningModeResult;
use serde::Serialize;

use crate::error::ApiError;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::SharedState;

pub(crate) fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/info", get(info))
        .route("/api/info/chart/mode/:mode", get(chart_mode))
        .route("/api/info/version", get(version))
        .route("/api/info/core", get(core))
        .route("/api/info/peers", get(peers))
        .route("/api/info/difficulty", get(difficulty))
        .route("/api/info/block-template", get(block_template))
        .route("/api/info/next-block-reward", get(next_block_reward))
        .route(
            "/api/client/:address/block-template",
            get(client_block_template),
        )
        .route("/api/info/chart", get(chart))
        .route("/api/info/accepted", get(accepted))
        .route("/api/info/max-difficulty", get(max_difficulty))
        .route("/api/info/workers", get(workers))
        .route("/api/info/rejected", get(rejected))
        .route("/api/info/shares", get(shares))
        .route("/api/pool", get(pool))
        .route("/api/network", get(network))
        .route("/api/health", get(health))
}

// ─── /api/info/version ────────────────────────────────────────────

#[derive(Serialize)]
struct VersionResponse {
    /// `v`-prefixed so the UI renders it verbatim.
    version: String,
}

async fn version(State(state): State<SharedState>) -> Result<Json<VersionResponse>, ApiError> {
    Ok(Json(VersionResponse {
        version: format!("v{}", state.pool_version),
    }))
}

// ─── /api/info/core ───────────────────────────────────────────────

async fn core(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
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

/// `version` is the RPC `subver`, rendered verbatim by the UI.
#[derive(Serialize)]
struct PeerEntry {
    version: String,
    direction: &'static str,
    location: Option<String>,
    bytesrecv: u64,
    bytessent: u64,
    network: Option<String>,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
    pingtime: Option<f64>,
}

async fn peers(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
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
                // Raw JSON, so a new `getpeerinfo` field cannot fail the endpoint.
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
        stripped.split_once(']').map(|(ip, _)| ip.to_string())
    } else {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DifficultyResponse {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    current: f64,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
    previous: Option<f64>,
    updated_at: String,
}

async fn difficulty(
    State(state): State<SharedState>,
) -> Result<Json<DifficultyResponse>, ApiError> {
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

async fn block_template(
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Raw `getblocktemplate` passthrough: the UI's template preview needs
    // the whole document, not the SV2 subset a TDP snapshot carries.
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

/// From the template's `coinbasevalue`, the same value the live coinbase is
/// built from, split into subsidy and fees.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NextBlockReward {
    reward_sats: u64,
    subsidy_sats: u64,
    fee_sats: u64,
    height: u64,
}

async fn next_block_reward(
    State(state): State<SharedState>,
) -> Result<Json<NextBlockReward>, ApiError> {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PayoutInfoEntry {
    address: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
    sats: u64,
}

impl PayoutInfoEntry {
    /// One coinbase output, with its share of `reward_sats` in percent.
    fn of_reward(address: String, sats: u64, reward_sats: u64) -> Self {
        let percent = if reward_sats == 0 {
            0.0
        } else {
            (sats as f64) * 100.0 / (reward_sats as f64)
        };
        Self {
            address,
            percent,
            sats,
        }
    }
}

/// What the real coinbase pays at this revenue, or nothing if the §4
/// evaluation fails.
fn payout_info_at(
    built: &bp_coinbase_snapshot::BuiltDistribution,
    reward_sats: u64,
) -> Vec<PayoutInfoEntry> {
    built
        .distribution
        .payout_entries_at(reward_sats)
        .map(|entries| {
            entries
                .into_iter()
                .map(|(a, sats)| PayoutInfoEntry::of_reward(a.into_inner(), sats, reward_sats))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientBlockTemplateResponse {
    block_template: serde_json::Value,
    mode: &'static str,
    payout_information: Vec<PayoutInfoEntry>,
    /// Set for the two group modes, `group-solo` and `blockparty`.
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    /// Zero-nonce preview block; empty when payouts are unknown or assembly
    /// fails, and the panel then renders only the template and mode.
    block_hex: String,
    /// Witness form, zero extranonces; same fallback as `block_hex`.
    coinbase_tx_hex: String,
    /// Group-Solo only: the member the preview names as finder (see
    /// `preview_finder`).
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_finder: Option<String>,
}

async fn client_block_template(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError> {
    use bp_common::AddressId;

    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
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

                // The same resolution `/api/pplns/mode/:address` reports, so
                // the preview shows the mode the pool is actually using.
                let resolved = crate::mode::resolve_address_mode(&s, &addr).await?;

                let mut previewed_finder: Option<String> = None;
                let payouts: Vec<PayoutInfoEntry> = match resolved {
                    MiningModeResult::GroupSolo(gid) => match s.group_solo.as_ref() {
                        Some(engine) => {
                            let window = engine
                                .reader()
                                .round_stats(gid)
                                .await
                                .map(|stats| stats.per_address)
                                .unwrap_or_default();
                            let finder = preview_finder(&addr, &window);
                            previewed_finder = Some(finder.as_str().to_string());
                            match engine.build_distribution(gid, reward_sats, &finder).await {
                                Ok(dist) => payout_info_at(&dist, reward_sats),
                                Err(_) => Vec::new(),
                            }
                        }
                        None => Vec::new(),
                    },
                    MiningModeResult::Blockparty(gid) => match s.blockparty.as_ref() {
                        Some(bp) => match bp
                            .payouts()
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
                    },
                    MiningModeResult::Pplns => match s.pplns.as_ref() {
                        Some(engine) => match engine.build_distribution(reward_sats).await {
                            Ok(dist) => payout_info_at(&dist, reward_sats),
                            Err(_) => Vec::new(),
                        },
                        None => Vec::new(),
                    },
                    MiningModeResult::Solo => {
                        // Exactly what the payout resolver builds, solo fee
                        // included, so the preview matches the real coinbase.
                        bp_mining_job::solo_payouts(addr.as_str(), &s.solo_fee, reward_sats)
                            .into_iter()
                            .map(|p| PayoutInfoEntry::of_reward(p.address, p.sats, reward_sats))
                            .collect()
                    }
                };

                let (coinbase_tx_hex, block_hex) = if payouts.is_empty() {
                    (String::new(), String::new())
                } else {
                    assemble_block_preview(&template, &payouts, s.network, &s.pool_identifier)
                        .unwrap_or_else(|_| (String::new(), String::new()))
                };
                Ok(ClientBlockTemplateResponse {
                    block_template: template,
                    mode: resolved.mode().as_str(),
                    payout_information: payouts,
                    group_id: resolved.group_id().map(|g| g.to_string()),
                    block_hex,
                    coinbase_tx_hex,
                    preview_finder: previewed_finder,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

/// Group-Solo preview finder: the asker if it has window shares (its own job
/// names it), else the largest window share, since a shareless address cannot
/// find the block. An empty window keeps the asker, as the real job does.
fn preview_finder(
    requester: &bp_common::AddressId,
    window: &std::collections::HashMap<String, f64>,
) -> bp_common::AddressId {
    if window
        .get(requester.as_str())
        .is_some_and(|shares| *shares > 0.0)
    {
        return requester.clone();
    }
    window
        .iter()
        .filter(|(_, shares)| **shares > 0.0)
        // Ties resolve by address so the preview does not flip between polls.
        .max_by(|(a, x), (b, y)| x.total_cmp(y).then_with(|| b.cmp(a)))
        .and_then(|(address, _)| bp_common::AddressId::new(address.clone()).ok())
        .unwrap_or_else(|| requester.clone())
}

/// Preview coinbase + full block from the payout list and a
/// `getblocktemplate` response. Zero extranonces and a zero nonce keep the
/// preview byte-stable across renders; it is never submitted.
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
            sats: p.sats,
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
        // A preview is never submitted, so no settlement hangs off it.
        [0u8; 32],
    )
    .map_err(|e| format!("build_mining_job: {e}"))?;

    let zero_e1 = [0u8; 4];
    let zero_e2 = [0u8; 8];
    let coinbase_bytes = job.witness_coinbase_with_extranonce(&zero_e1, &zero_e2);
    let coinbase_tx_hex = hex::encode(&coinbase_bytes);

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

/// `fee` is always `0`; the dashboard tile still reads the key.
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

async fn pool(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<PoolResponse, _, ApiError>(
            "POOL_INFO".to_string(),
            TtlKind::PoolInfo,
            async move {
                let total_hash_rate = crate::error::or_degraded(
                    bp_client_live::pool_hashrate(s.redis.as_ref()).await,
                    || 0.0,
                )?;
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

async fn network(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
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
    /// Informational only: the share path survives a Redis blip, so a cache
    /// outage does not degrade `status`.
    cache: Option<&'static str>,
    /// A stale feed degrades `status`: without fresh templates the pool
    /// cannot hand out valid work.
    tdp: Option<&'static str>,
}

async fn health(State(state): State<SharedState>) -> Result<Json<HealthResponse>, ApiError> {
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
    let cache_ok = if let Some(conn) = state.redis.as_ref() {
        Some(redis_health_roundtrip(conn.clone()).await)
    } else {
        None
    };
    let tdp_fresh = state.tdp.as_ref().map(|handle| {
        let last_update_at = handle.current_snapshot().last_update_at;
        tdp_is_fresh(
            last_update_at,
            state.start_time.timestamp_millis(),
            now.timestamp_millis(),
            state.tdp_staleness_threshold_ms,
        )
    });
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

/// Without any template yet, age counts from `start_ms`, so a core that never
/// attaches still trips the threshold.
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

/// Write and read back, so Redis must round-trip, not just accept TCP.
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
// The in-progress slot is excluded so the chart never ends half-filled.

use crate::time_range::{
    accepted_slot_data, chart_slot_boundaries, fold_into_slots, max_difficulty_slot_data,
    ChartPoint, Range, SlotDataResponse,
};
use axum::extract::Query;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeQuery {
    range: Option<String>,
}

use crate::time_range::SLOT_SECONDS;
use bp_common::HASHES_PER_DIFFICULTY_1;

async fn chart(
    State(state): State<SharedState>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("SITE_HASHRATE_GRAPH_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::Chart, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let rows = bp_db::find_pool_share_statistics_since(&s.pool, since).await?;
            // The UI fills gaps itself.
            Ok(rows
                .into_iter()
                .filter(|r| r.time < cutoff)
                .map(|r| ChartPoint {
                    label: crate::time_range::format_iso_ms(r.time),
                    data: (r.accepted as f64 * HASHES_PER_DIFFICULTY_1 / SLOT_SECONDS).round(),
                })
                .collect())
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/accepted ───────────────────────────────────────────

async fn accepted(
    State(state): State<SharedState>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_ACCEPTED_STATS_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Accepted, async move {
            let since = bp_common::now_ms() - range.window_ms();
            let rows = bp_db::find_pool_share_statistics_since(&s.pool, since).await?;
            Ok(accepted_slot_data(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.accepted as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/max-difficulty ─────────────────────────────────────

async fn max_difficulty(
    State(state): State<SharedState>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_MAX_DIFFICULTY_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Accepted, async move {
            let since = bp_common::now_ms() - range.window_ms();
            let rows = bp_db::find_pool_share_statistics_since(&s.pool, since).await?;
            Ok(max_difficulty_slot_data(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.max_difficulty as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/info/workers ────────────────────────────────────────────

async fn workers(
    State(state): State<SharedState>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_WORKER_STATS_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Workers, async move {
            let since = bp_common::now_ms() - range.window_ms();
            let rows = bp_db::find_pool_worker_rows_since(&s.pool, since).await?;
            Ok(worker_slots(
                &chart_slot_boundaries(since),
                rows.iter()
                    .map(|r| (r.time, (r.address.as_str(), r.client_name.as_str()))),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

/// `(time, (address, worker))` samples → distinct addresses + workers per slot.
fn worker_slots<'a>(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, (&'a str, &'a str))>,
) -> SlotDataResponse {
    type Seen = (HashSet<String>, HashSet<(String, String)>);
    let slots = fold_into_slots(
        boundaries,
        samples,
        |(addresses, workers): &mut Seen, (address, worker)| {
            addresses.insert(address.to_string());
            workers.insert((address.to_string(), worker.to_string()));
        },
    );
    SlotDataResponse::from_slots(slots, |(addresses, workers)| {
        BTreeMap::from([
            ("addresses".to_string(), addresses.len() as f64),
            ("workers".to_string(), workers.len() as f64),
        ])
    })
}

// ─── /api/info/rejected ───────────────────────────────────────────

/// Pre-filled into every slot so the UI's per-reason series stay continuous.
pub(crate) const REJECT_REASON_KEYS: &[&str] = &[
    "OtherUnknown",
    "JobNotFound",
    "DuplicateShare",
    "LowDifficultyShare",
    "UnauthorizedWorker",
    "NotSubscribed",
    "Stale",
    "VersionRollingNotAllowed",
];

/// Stored rows carry camel-case or kebab-case reasons; the UI expects camel-case.
pub(crate) fn normalise_reject_reason(raw: &str) -> &'static str {
    match raw {
        "OtherUnknown" => "OtherUnknown",
        "JobNotFound" => "JobNotFound",
        "DuplicateShare" => "DuplicateShare",
        "LowDifficultyShare" => "LowDifficultyShare",
        "VersionRollingNotAllowed" => "VersionRollingNotAllowed",
        "UnauthorizedWorker" => "UnauthorizedWorker",
        "NotSubscribed" => "NotSubscribed",
        "Stale" => "Stale",
        "job-not-found" => "JobNotFound",
        "duplicate-share" => "DuplicateShare",
        "low-difficulty" | "low-difficulty-share" => "LowDifficultyShare",
        _ => "OtherUnknown",
    }
}

async fn rejected(
    State(state): State<SharedState>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("POOL_REJECTED_STATS_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::Rejected, async move {
            let since = bp_common::now_ms() - range.window_ms();
            let rows = bp_db::find_pool_rejected_statistics_since(&s.pool, since).await?;
            Ok(rejected_slots(
                &chart_slot_boundaries(since),
                rows.iter()
                    .map(|r| (r.time, (r.reason.as_str(), r.count as f64))),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

fn rejected_slots<'a>(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, (&'a str, f64))>,
) -> SlotDataResponse {
    let slots = fold_into_slots(
        boundaries,
        samples,
        |seen: &mut BTreeMap<String, f64>, (reason, count)| {
            *seen
                .entry(normalise_reject_reason(reason).to_string())
                .or_default() += count;
        },
    );
    SlotDataResponse::from_slots(slots, with_all_reasons)
}

/// Every key of [`REJECT_REASON_KEYS`], defaulted, plus whatever `seen` holds.
fn with_all_reasons<X: Default>(seen: BTreeMap<String, X>) -> BTreeMap<String, X> {
    let mut counts: BTreeMap<String, X> = REJECT_REASON_KEYS
        .iter()
        .map(|&k| (k.to_string(), X::default()))
        .collect();
    counts.extend(seen);
    counts
}

/// `diff_minus_one` is the share-difficulty sum at the moment of rejection.
#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RejectCounts {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    count: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    diff_minus_one: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RejectedSlot {
    time: String,
    counts: BTreeMap<String, RejectCounts>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RejectSlotsResponse {
    slot_data: Vec<RejectedSlot>,
}

pub(crate) fn rejected_by_reason_slots<'a>(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, (&'a str, f64, f64))>,
) -> RejectSlotsResponse {
    let slots = fold_into_slots(
        boundaries,
        samples,
        |seen: &mut BTreeMap<String, RejectCounts>, (reason, count, diff1)| {
            let entry = seen
                .entry(normalise_reject_reason(reason).to_string())
                .or_default();
            entry.count += count;
            entry.diff_minus_one += diff1;
        },
    );
    RejectSlotsResponse {
        slot_data: slots
            .into_iter()
            .map(|(b, seen)| RejectedSlot {
                time: crate::time_range::format_iso_ms(b),
                counts: with_all_reasons(seen),
            })
            .collect(),
    }
}

// ─── /api/info/shares ─────────────────────────────────────────────

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

async fn shares(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SharesResponse, _, ApiError>(
            "POOL_SHARE_TOTALS".to_string(),
            TtlKind::Shares,
            async move {
                let now = bp_common::now_ms();
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

                // With no block ever found, epoch yields the cumulative total.
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

// Exists only to keep the `Arc` import used.
#[allow(dead_code)]
fn _force_arc_use(_: Arc<()>) {}

// ─── /api/info ────────────────────────────────────────────────────

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
    #[serde(serialize_with = "crate::time_range::ser_opt_f32_jsnum")]
    best_difficulty: Option<f32>,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
    total_hash_rate: Option<f64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HighScoreEntry {
    /// ISO-8601 timestamp; null if `updatedAt` is unrepresentable.
    updated_at: Option<String>,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    best_difficulty: f64,
    best_difficulty_user_agent: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoResponse {
    block_data: Vec<FoundBlockEntry>,
    user_agents: Vec<UserAgentEntry>,
    high_scores: Vec<HighScoreEntry>,
    /// Pool start time as an ISO-8601 string, not a duration.
    uptime: String,
}

async fn info(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<InfoResponse, _, ApiError>(
            "SITE_INFO".to_string(),
            TtlKind::SiteInfo,
            async move {
                let blocks = find_found_blocks(&s.pool).await?;
                let sessions = bp_db::find_active_session_keys(&s.pool).await?;
                let rows: Vec<bp_client_live::UserAgentSessionRow> = sessions
                    .into_iter()
                    .map(|r| bp_client_live::UserAgentSessionRow {
                        user_agent: r.user_agent,
                        address: r.address.into_inner(),
                        worker: r.client_name,
                        session_id: r.session_id,
                    })
                    .collect();
                let agents = crate::error::or_degraded(
                    bp_client_live::aggregate_by_user_agent(s.redis.as_ref(), &rows).await,
                    || bp_client_live::aggregate_offline(&rows),
                )?;
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
                            best_difficulty: Some(a.best_difficulty as f32),
                            total_hash_rate: Some(a.total_hash_rate),
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
// Unknown `:mode` answers an empty array.

async fn chart_mode(
    State(state): State<SharedState>,
    Path(mode_str): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<ChartPoint>>, ApiError> {
    let mode: MiningMode = match mode_str.parse() {
        Ok(m) => m,
        Err(_) => return Ok(Json(Vec::new())),
    };
    // Narrower than the shared `Range::parse`: {1d, 3d, 7d}, default `7d`.
    let (window_ms, _slot) = match q.range.as_deref().unwrap_or("7d") {
        "1d" => (24 * 60 * 60 * 1000_i64, 600_000_i64),
        "3d" => (3 * 24 * 60 * 60 * 1000_i64, 600_000_i64),
        _ => (7 * 24 * 60 * 60 * 1000_i64, 600_000_i64),
    };
    let since = bp_common::now_ms() - window_ms;
    let cutoff_slot = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
    let rows = find_pool_mode_hashrate_since(&state.pool, mode, since).await?;
    Ok(Json(
        rows.into_iter()
            .filter(|r| r.time < cutoff_slot)
            .map(|r| ChartPoint {
                label: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.time)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                    .unwrap_or_default(),
                data: ((r.diff as f64) * HASHES_PER_DIFFICULTY_1 / SLOT_SECONDS).round(),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod slot_json_tests {
    use super::*;

    const S: i64 = 600_000;
    const T0: i64 = 1_700_000_400_000;
    const BOUNDARIES: [i64; 3] = [T0, T0 + S, T0 + 2 * S];

    fn json<T: serde::Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    /// `/api/info/accepted`.
    #[test]
    fn accepted_json_is_unchanged() {
        let samples = vec![
            (T0, 1.5),
            (T0, 0.1_f32 as f64),
            (T0 + S + 123, 2.0),
            (T0 - S, 99.0),
            (T0 + 3 * S, 77.0),
        ];
        assert_eq!(
            json(&accepted_slot_data(&BOUNDARIES, samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"accepted":1.6000000014901161}},{"time":"2023-11-14T22:30:00.000Z","counts":{"accepted":2}},{"time":"2023-11-14T22:40:00.000Z","counts":{"accepted":0}}]}"#
        );
    }

    /// Max-difficulty keeps the highest share per slot, not the sum or last row.
    #[test]
    fn max_difficulty_json_keeps_the_highest_share_per_slot() {
        let samples = vec![
            (T0, 500.0),
            (T0, 300.0),
            (T0 + S + 5, 7.0),
            (T0 - S, 9e9),
            (T0 + 3 * S, 1e9),
        ];
        assert_eq!(
            json(&max_difficulty_slot_data(&BOUNDARIES, samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"maxDifficulty":500}},{"time":"2023-11-14T22:30:00.000Z","counts":{"maxDifficulty":7}},{"time":"2023-11-14T22:40:00.000Z","counts":{"maxDifficulty":0}}]}"#
        );
    }

    /// `/api/info/workers` — distinct addresses and (address, worker) pairs.
    #[test]
    fn workers_json_is_unchanged() {
        let samples = vec![
            (T0, ("a1", "w1")),
            (T0, ("a1", "w2")),
            (T0, ("a2", "w1")),
            (T0, ("a1", "w1")),
            (T0 + S + 9, ("a3", "w1")),
            (T0 + 3 * S, ("a9", "w9")),
        ];
        assert_eq!(
            json(&worker_slots(&BOUNDARIES, samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"addresses":2,"workers":3}},{"time":"2023-11-14T22:30:00.000Z","counts":{"addresses":1,"workers":1}},{"time":"2023-11-14T22:40:00.000Z","counts":{"addresses":0,"workers":0}}]}"#
        );
    }

    /// `/api/info/rejected` — counts only, every known reason pre-filled.
    #[test]
    fn rejected_json_is_unchanged() {
        let samples = vec![
            (T0, ("job-not-found", 2.0)),
            (T0, ("JobNotFound", 1.0)),
            (T0, ("low-difficulty", 0.1_f32 as f64)),
            (T0, ("something-new", 3.0)),
            (T0 + S + 7, ("Stale", 4.0)),
            (T0 + 3 * S, ("Stale", 50.0)),
        ];
        assert_eq!(
            json(&rejected_slots(&BOUNDARIES, samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"DuplicateShare":0,"JobNotFound":3,"LowDifficultyShare":0.10000000149011612,"NotSubscribed":0,"OtherUnknown":3,"Stale":0,"UnauthorizedWorker":0,"VersionRollingNotAllowed":0}},{"time":"2023-11-14T22:30:00.000Z","counts":{"DuplicateShare":0,"JobNotFound":0,"LowDifficultyShare":0,"NotSubscribed":0,"OtherUnknown":0,"Stale":4,"UnauthorizedWorker":0,"VersionRollingNotAllowed":0}},{"time":"2023-11-14T22:40:00.000Z","counts":{"DuplicateShare":0,"JobNotFound":0,"LowDifficultyShare":0,"NotSubscribed":0,"OtherUnknown":0,"Stale":0,"UnauthorizedWorker":0,"VersionRollingNotAllowed":0}}]}"#
        );
    }
}

#[cfg(test)]
mod tests {
    /// `previewFinder` is omitted, not null, when unset.
    #[test]
    fn preview_finder_field_is_absent_unless_set() {
        let response = |finder: Option<&str>| ClientBlockTemplateResponse {
            block_template: serde_json::json!({}),
            mode: "pplns",
            payout_information: Vec::new(),
            group_id: None,
            block_hex: String::new(),
            coinbase_tx_hex: String::new(),
            preview_finder: finder.map(str::to_string),
        };
        let without = serde_json::to_value(response(None)).unwrap();
        assert!(without.get("previewFinder").is_none());
        let with = serde_json::to_value(response(Some("bc1qfinder"))).unwrap();
        assert_eq!(with["previewFinder"], "bc1qfinder");
    }

    #[test]
    fn preview_finder_is_the_asker_only_when_it_has_window_shares() {
        use bp_common::AddressId;
        use std::collections::HashMap;
        let asker =
            AddressId::new("bc1qs84n0jqe6qdu4dzk4vjjfnnk9n8ulz5v72tts8".to_string()).unwrap();
        let top = "bc1qxd6lw5eeuv82sjl6qelac6er98grz5cnjc53v8".to_string();
        let small = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();

        // Mining: the preview is the asker's own job.
        let mining = HashMap::from([(asker.as_str().to_string(), 5.0), (top.clone(), 3_000.0)]);
        assert_eq!(preview_finder(&asker, &mining), asker);

        // Not mining: the largest window share is the finder, not the asker.
        let idle = HashMap::from([(top.clone(), 3_673_618_500.0), (small, 1_172.0)]);
        assert_eq!(preview_finder(&asker, &idle).as_str(), top);

        // A zero entry is no share either.
        let zero = HashMap::from([(asker.as_str().to_string(), 0.0), (top.clone(), 10.0)]);
        assert_eq!(preview_finder(&asker, &zero).as_str(), top);

        // Empty window: the asker bootstraps it.
        assert_eq!(preview_finder(&asker, &HashMap::new()), asker);
    }

    use super::*;

    /// A preview row's percent is its share of the reward; a zero reward
    /// shows 0 % instead of dividing by zero.
    #[test]
    fn a_preview_row_is_its_share_of_the_reward() {
        let row = PayoutInfoEntry::of_reward("a".into(), 25, 100);
        assert_eq!((row.address.as_str(), row.sats), ("a", 25));
        assert!((row.percent - 25.0).abs() < 1e-12);
        assert_eq!(PayoutInfoEntry::of_reward("a".into(), 25, 0).percent, 0.0);
    }

    #[test]
    fn format_uptime_seconds_only() {
        assert_eq!(format_uptime(45_000), "45s");
    }

    #[test]
    fn tdp_fresh_when_recent_template() {
        let now = 1_000_000_000;
        assert!(tdp_is_fresh(Some(now - 10_000), now - 60_000, now, 120_000));
    }

    #[test]
    fn tdp_stale_when_template_older_than_threshold() {
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
