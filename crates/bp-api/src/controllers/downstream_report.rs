// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/downstream-report` — in-memory store of SV2 JDC-downstream
//! miner reports (5-min TTL, keyed by `jdcUserIdentity`).
//!
//! `storeReport` also pushes a vendor-derived userAgent into
//! the matching client_entity row (`ClientService.updateSv2UserAgentByAddress`).
//! That side-effect is wired via `bp_db::update_sv2_user_agent_by_address`.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::{extract::State, response::Json, routing::post, Router};
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::SharedState;

const TTL_MS: i64 = 5 * 60 * 1000;

/// In-memory report store. Process-global singleton — keeps the same
/// semantics for `/api/downstream-report` GET visibility. Each entry
/// stores the report + receive timestamp; entries past TTL are dropped
/// on every read.
static STORE: Lazy<Mutex<HashMap<String, (DownstreamMinerReport, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new().route(
        "/api/downstream-report",
        post(receive::<H, M>).get(list::<H, M>),
    )
}

/// Wire shape for downstream miner reports.
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DownstreamMinerReport {
    pub(crate) schema_version: u32,
    pub(crate) jdc_user_identity: String,
    pub(crate) miners: Vec<DownstreamMiner>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DownstreamMiner {
    pub(crate) vendor: String,
    #[serde(default)]
    pub(crate) hardware_version: Option<String>,
    #[serde(default)]
    pub(crate) firmware: Option<String>,
    #[serde(default)]
    pub(crate) device_id: Option<String>,
    #[serde(default)]
    pub(crate) nominal_hash_rate: Option<u64>,
    #[serde(default)]
    pub(crate) user_identity: Option<String>,
    #[serde(default)]
    pub(crate) connected_at: Option<String>,
}

/// Response shape: `{success: true, accepted: <number>}`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedResponse {
    success: bool,
    accepted: usize,
}

async fn receive<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(report): Json<DownstreamMinerReport>,
) -> Result<Json<AcceptedResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let now = crate::time_range::now_ms();
    let accepted = report.miners.len();
    let key = report.jdc_user_identity.clone();
    // Refine the matching client_entity rows from `<vendor>/sv2` /
    // `jd-client/sv2` placeholders to the primary downstream vendor
    // before storing the report.
    if let Some(primary) = primary_vendor(&report) {
        let new_ua = format!("{}/sv2", primary);
        let _ = bp_db::update_sv2_user_agent_by_address(&state.pool, &key, &new_ua).await;
    }
    let mut store = STORE
        .lock()
        .map_err(|_| ApiError::Internal("downstream store mutex poisoned".into()))?;
    store.insert(key, (report, now));
    drop_expired(&mut store, now);
    Ok(Json(AcceptedResponse {
        success: true,
        accepted,
    }))
}

/// Pick the most-common vendor across `report.miners`, normalised
/// by collapsing common firmware spellings.
fn primary_vendor(report: &DownstreamMinerReport) -> Option<String> {
    if report.miners.is_empty() {
        return None;
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for m in &report.miners {
        let v = normalize_vendor(&m.vendor);
        *counts.entry(v).or_insert(0) += 1;
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(v, _)| v)
}

fn normalize_vendor(raw: &str) -> String {
    let trimmed = raw
        .split_whitespace()
        .next()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split('V')
        .next()
        .unwrap_or("");
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("bosminer") || lower.contains("bos") {
        return "Braiins OS".to_string();
    }
    if lower.contains("cpuminer") {
        return "cpuminer".to_string();
    }
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

async fn list<H, M>(
    State(_state): State<SharedState<H, M>>,
) -> Result<Json<Vec<DownstreamMinerReport>>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let now = crate::time_range::now_ms();
    let mut store = STORE
        .lock()
        .map_err(|_| ApiError::Internal("downstream store mutex poisoned".into()))?;
    drop_expired(&mut store, now);
    Ok(Json(store.values().map(|(r, _)| r.clone()).collect()))
}

fn drop_expired(store: &mut HashMap<String, (DownstreamMinerReport, i64)>, now_ms: i64) {
    store.retain(|_, (_, recv_at)| now_ms - *recv_at < TTL_MS);
}
