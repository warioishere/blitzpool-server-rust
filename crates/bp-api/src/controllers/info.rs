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
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
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
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    current: f64,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
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
// template" without round-tripping bitcoin-core.

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
    /// `solo` / `pplns` / `group-solo` / `blockparty` — drives the UI's
    /// distribution-preview labelling.
    mode: &'static str,
    payout_information: Vec<PayoutInfoEntry>,
    /// Set for the two group modes, `group-solo` and `blockparty`.
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
    /// Group-Solo only: the member the preview names as finder, the one its
    /// finder bonus is paid to. The asking address when it has shares in
    /// the window, otherwise the member with the largest window share
    /// (see `preview_finder`). Absent for the modes without a finder bonus.
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_finder: Option<String>,
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
                let payouts: Vec<PayoutInfoEntry> = match resolved.mode {
                    MiningMode::GroupSolo => {
                        let gid = resolved
                            .group_id
                            .expect("group-solo resolves with its group");
                        match s.group_solo.as_ref() {
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
                                    // The §4 evaluation at this template's
                                    // revenue — what the real coinbase pays.
                                    Ok(dist) => dist
                                        .distribution
                                        .payout_entries_at(reward_sats)
                                        .map(|entries| {
                                            entries
                                                .into_iter()
                                                .map(|(address, sats)| PayoutInfoEntry {
                                                    percent: if reward_sats == 0 {
                                                        0.0
                                                    } else {
                                                        (sats as f64) * 100.0 / (reward_sats as f64)
                                                    },
                                                    address: address.as_str().to_string(),
                                                    sats,
                                                })
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                    Err(_) => Vec::new(),
                                }
                            }
                            None => Vec::new(),
                        }
                    }
                    MiningMode::Blockparty => {
                        let gid = resolved
                            .group_id
                            .expect("blockparty resolves with its group");
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
                    MiningMode::Pplns => match s.pplns.as_ref() {
                        Some(engine) => match engine.build_distribution(reward_sats).await {
                            // The §4 evaluation at this template's revenue —
                            // exactly what the real coinbase build runs.
                            Ok(dist) => dist
                                .distribution
                                .payout_entries_at(reward_sats)
                                .map(|entries| {
                                    entries
                                        .into_iter()
                                        .map(|(address, sats)| PayoutInfoEntry {
                                            percent: if reward_sats == 0 {
                                                0.0
                                            } else {
                                                (sats as f64) * 100.0 / (reward_sats as f64)
                                            },
                                            address: address.as_str().to_string(),
                                            sats,
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                            Err(_) => Vec::new(),
                        },
                        None => Vec::new(),
                    },
                    MiningMode::Solo => {
                        // Solo: exactly what the payout resolver would build.
                        // This used to be a second implementation reading the
                        // PPLNS fee config, so a solo miner saw a fee output
                        // that its real coinbase never carried.
                        //
                        // `static_address_verbatim` and not a directory lookup:
                        // this route's input is a path segment, not a live
                        // session, and bp-api has no rotating-identity directory
                        // to resolve one against. `verbatim` because that is
                        // byte-for-byte what this call passed before — the
                        // `AddressId` is already shape-validated. A rotating
                        // miner asking for its own preview gets its `payout_id`
                        // previewed as an address, which is the same limitation
                        // `assemble_block_preview` documents below and is fixed
                        // in the same place: by the preview taking
                        // `ResolvedPayouts` instead of display entries.
                        let miner =
                            bp_common::PayoutIdentity::static_address_verbatim(addr.as_str());
                        bp_mining_job::solo_payouts(&miner, &s.solo_fee, reward_sats)
                            .into_iter()
                            .map(|p| PayoutInfoEntry {
                                percent: if reward_sats == 0 {
                                    0.0
                                } else {
                                    (p.sats as f64) * 100.0 / (reward_sats as f64)
                                },
                                address: p.payout_id().to_string(),
                                sats: p.sats,
                            })
                            .collect()
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
                    mode: resolved.mode.as_str(),
                    payout_information: payouts,
                    group_id: resolved.group_id.map(|g| g.to_string()),
                    block_hex,
                    coinbase_tx_hex,
                    preview_finder: previewed_finder,
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
/// Who the Group-Solo preview names as the block's finder.
///
/// A member's miner mines a job that names that member as finder, so for an
/// address with shares in the current window the preview is its own job.
/// An address with no shares there cannot find the block; naming it would
/// pay it a finder bonus no real coinbase will pay. The preview then shows
/// the most likely block instead: the member with the largest window share
/// as finder. With no shares in the window at all, the asking address
/// stays the finder (that is how the first block of an empty window is
/// built).
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

    // Round-trip through the display type: `PayoutInfoEntry` carries an address
    // string, so a `PayoutIdentity` cannot survive it — a rotating identity would
    // come back out as a `Static` entry paying its ledger key rather than its
    // derived script, i.e. a preview that does not match the coinbase. Harmless
    // today (only `Static` exists) and it is the same shape the preview had
    // before, but it is the reason the preview must take `ResolvedPayouts`
    // directly once identities can rotate, not a `Vec<PayoutInfoEntry>`.
    let payout_entries: Vec<PayoutEntry> = payouts
        .iter()
        .map(|p| PayoutEntry::static_address(p.address.clone(), p.sats))
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

use crate::time_range::{
    accepted_slot_data, chart_slot_boundaries, fold_into_slots, ChartPoint, Range, SlotDataResponse,
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
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let rows = bp_db::find_pool_share_statistics_since(&s.pool, since).await?;
            // One ChartPoint per DB row: slot-end label + rounded
            // hashrate; UI fills any gaps itself.
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
            let since = bp_common::now_ms() - range.window_ms();
            // Skinny projection (slot time + address + worker only) — the
            // distinct counting stays in-process; we just avoid shipping the
            // full 17-column stats row for every session in the window.
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
    "VersionRollingNotAllowed",
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
        "VersionRollingNotAllowed" => "VersionRollingNotAllowed",
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

/// `(time, (reason, count))` samples → per-reason counts per slot.
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

/// Every key of [`REJECT_REASON_KEYS`], holding what `seen` recorded for
/// it or the default, plus anything else `seen` recorded.
fn with_all_reasons<X: Default>(seen: BTreeMap<String, X>) -> BTreeMap<String, X> {
    let mut counts: BTreeMap<String, X> = REJECT_REASON_KEYS
        .iter()
        .map(|&k| (k.to_string(), X::default()))
        .collect();
    counts.extend(seen);
    counts
}

/// Per-reason rejected-share bucket of the per-address and per-group
/// `/rejected` endpoints — `count` is the raw rejection count,
/// `diffMinusOne` is the share-difficulty sum at the moment of rejection.
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

/// `(time, (reason, count, diff1))` samples → per-reason counts and
/// diff-1 sums per slot, every known reason present.
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
// Per-payout-mode hashrate chart. Default range is `1d`; valid range
// presets are `1d`, `3d`, `7d` (NOTE: differs from `/api/info/chart`
// which also accepts `1m`). Unknown `:mode` → empty array.
//
// Aggregation:
//   - 10-min slots
//   - hide both the in-progress and just-ended slot (via the same
//     visibility-cutoff helper the writer uses)
//   - hashrate = ROUND(diff * HASHES_PER_DIFFICULTY_1 / 600)

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
    /// `previewFinder` is present for Group-Solo only; every other mode's
    /// JSON stays exactly as it was (no null, no key).
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

        // Empty window: nobody else to name, the asker bootstraps it.
        assert_eq!(preview_finder(&asker, &HashMap::new()), asker);
    }

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
