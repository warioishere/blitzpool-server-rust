// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/client/:address/*` reader endpoints.

use axum::{
    extract::{Path, State},
    response::Json,
    routing::{get, post},
    Router,
};
use std::collections::BTreeSet;

use bp_common::AddressId;
use bp_db::{
    find_address_settings, find_client, find_client_statistics_since_for_address,
    find_clients_by_address, find_worker_shares, reset_address_settings_best_difficulty,
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
        .route("/api/client/:address", get(by_address::<H, M>))
        .route(
            "/api/client/:address/worker-shares",
            get(worker_shares::<H, M>),
        )
        .route("/api/client/:address/chart", get(chart::<H, M>))
        .route("/api/client/:address/accepted", get(accepted::<H, M>))
        .route("/api/client/:address/workers", get(workers::<H, M>))
        .route("/api/client/:address/rejected", get(rejected::<H, M>))
        .route("/api/client/:address/diff-scores", get(diff_scores::<H, M>))
        .route("/api/client/:address/reset", post(reset_address::<H, M>))
        .route(
            "/api/client/:address/delete-stats",
            post(delete_stats::<H, M>),
        )
        .route("/api/client/:address/delete-all", post(delete_all::<H, M>))
        // The triple-segment routes must come AFTER the specific
        // chart/accepted/workers/rejected paths so axum picks the
        // specific match first.
        .route("/api/client/:address/:worker", get(by_worker::<H, M>))
        .route(
            "/api/client/:address/:worker/:session",
            get(by_session::<H, M>),
        )
}

// ─── time-range chart endpoints ──────────────────────────────────

use crate::time_range::{
    bucket_key, chart_slot_boundaries, ChartPoint, Range, SlotCounts, SlotDataResponse,
};
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
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_CHART_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::ClientChart, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            let mut buckets: BTreeMap<i64, f64> = boundaries.iter().map(|&b| (b, 0.0)).collect();
            for r in &rows {
                let k = bucket_key(r.time, range.slot_size_ms());
                if let Some(v) = buckets.get_mut(&k) {
                    *v += r.shares as f64;
                }
            }
            Ok(boundaries
                .iter()
                .map(|&b| ChartPoint {
                    label: crate::time_range::format_slot_label(b),
                    data: (buckets.get(&b).copied().unwrap_or(0.0) * DIFFICULTY_1 / SLOT_SECONDS)
                        .round(),
                })
                .collect())
        })
        .await?;
    Ok(JsonBytes(bytes))
}

async fn accepted<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_ACCEPTED_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::ClientAccepted, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let mut buckets: BTreeMap<i64, f64> = boundaries.iter().map(|&b| (b, 0.0)).collect();
            for r in rows {
                let k = bucket_key(r.time, range.slot_size_ms());
                if let Some(v) = buckets.get_mut(&k) {
                    // Diff-1-weighted accepted shares (sum of share difficulty),
                    // NOT the raw share count: this tracks actual work, so the
                    // chart stays flat when vardiff trades share size for share
                    // rate at constant hashrate. The raw count (`accepted_count`)
                    // would drift up as per-share difficulty drops. (The rejected
                    // endpoint intentionally still reports raw full-share counts.)
                    *v += r.shares as f64;
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

async fn workers<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_WORKERS_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::ClientWorkers, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let mut sessions: BTreeMap<i64, std::collections::HashSet<String>> = BTreeMap::new();
            let mut workers_set: BTreeMap<i64, std::collections::HashSet<String>> = BTreeMap::new();
            for r in &rows {
                let k = bucket_key(r.time, range.slot_size_ms());
                sessions.entry(k).or_default().insert(r.session_id.clone());
                workers_set
                    .entry(k)
                    .or_default()
                    .insert(r.client_name.clone());
            }
            Ok(SlotDataResponse {
                slot_data: boundaries
                    .iter()
                    .map(|&b| {
                        let mut counts = BTreeMap::new();
                        counts.insert(
                            "workers".into(),
                            workers_set.get(&b).map(|s| s.len()).unwrap_or(0) as f64,
                        );
                        counts.insert(
                            "sessions".into(),
                            sessions.get(&b).map(|s| s.len()).unwrap_or(0) as f64,
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

async fn rejected<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_REJECTED_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<RejectedResponse, _, ApiError>(key, TtlKind::ClientRejected, async move {
            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_rejected_statistics_since_for_address(&s.pool, &addr, since)
                    .await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let mut buckets: BTreeMap<i64, BTreeMap<String, RejectCounts>> = BTreeMap::new();
            for r in rows {
                let k = bucket_key(r.time, range.slot_size_ms());
                let key = crate::controllers::info::normalise_reject_reason(&r.reason).to_string();
                let entry = buckets.entry(k).or_default().entry(key).or_default();
                entry.count += r.count as f64;
                entry.diff_minus_one += r.shares as f64;
            }
            Ok(RejectedResponse {
                slot_data: boundaries
                    .iter()
                    .map(|&b| {
                        let mut counts: BTreeMap<String, RejectCounts> =
                            crate::controllers::info::REJECT_REASON_KEYS
                                .iter()
                                .map(|&k| (k.to_string(), RejectCounts::default()))
                                .collect();
                        if let Some(seen) = buckets.remove(&b) {
                            for (k, v) in seen {
                                counts.insert(k, v);
                            }
                        }
                        RejectedSlot {
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

/// Per-reason rejected-share bucket — `count` is the raw rejection
/// count, `diffMinusOne` is the share-difficulty sum at the moment
/// of rejection.
#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct RejectCounts {
    count: f64,
    diff_minus_one: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectedSlot {
    time: String,
    counts: BTreeMap<String, RejectCounts>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectedResponse {
    slot_data: Vec<RejectedSlot>,
}

// ─── GET /api/client/:address ────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientResponse {
    best_difficulty: Option<u64>,
    workers_count: usize,
    total_shares: f64,
    total_hashrate: f64,
    workers: Vec<WorkerEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerEntry {
    session_id: String,
    name: String,
    /// Two-decimal string form so the UI can render the value
    /// without further formatting.
    best_difficulty: String,
    hash_rate: f64,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
    current_difficulty: Option<f64>,
    /// Mining channels on this worker's connection. `> 1` means a rental
    /// proxy bundled several same-rig devices onto one connection, so the
    /// UI renders the difficulty as aggregated instead of a single value.
    channel_count: i32,
    start_time: String,
    last_seen: String,
}

async fn by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("CLIENT_INFO_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<ClientResponse, _, ApiError>(key, TtlKind::ClientInfo, async move {
            let clients = find_clients_by_address(&s.pool, &addr).await?;
            // Weight each session's stored hashrate by how fresh its last share
            // is: a miner that just went offline fades to zero over the decay
            // window instead of counting at full until the dead-client sweep.
            // Keeps the per-worker values and the total consistent.
            let now = crate::time_range::now_ms();
            let decayed = |hash_rate: f64, updated_at: i64| -> f64 {
                hash_rate
                    * crate::time_range::hashrate_decay_factor(
                        now,
                        updated_at,
                        bp_db::HASHRATE_DECAY_WINDOW_MS,
                    )
            };
            let total_hashrate: f64 = clients.iter().map(|c| decayed(c.hash_rate, c.updated_at)).sum();
            let settings = find_address_settings(&s.pool, &addr).await?;
            let best_difficulty = settings.as_ref().map(|x| x.best_difficulty.floor() as u64);
            let total_shares = settings.map(|x| x.shares).unwrap_or(0.0);
            Ok(ClientResponse {
                best_difficulty,
                workers_count: clients.len(),
                total_shares,
                total_hashrate,
                workers: clients
                    .into_iter()
                    .map(|c| WorkerEntry {
                        session_id: c.session_id,
                        name: c.client_name,
                        best_difficulty: format!("{:.2}", c.best_difficulty as f64),
                        hash_rate: decayed(c.hash_rate, c.updated_at),
                        current_difficulty: c.current_difficulty.map(|d| d as f64),
                        channel_count: c.channel_count,
                        start_time: crate::time_range::format_slot_label(c.start_time),
                        last_seen: crate::time_range::format_slot_label(c.updated_at),
                    })
                    .collect(),
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address/worker-shares ──────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerShareEntry {
    worker_name: String,
    total_shares: i64,
    total_rejected: i64,
}

async fn worker_shares<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("CLIENT_WORKER_SHARES_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<WorkerShareEntry>, _, ApiError>(
            key,
            TtlKind::ClientWorkerShares,
            async move {
                // `worker_shares_entity` is keyed (address, clientName) — pull the
                // worker list, then one lookup per worker.
                let clients = find_clients_by_address(&s.pool, &addr).await?;
                let names: BTreeSet<String> = clients.into_iter().map(|c| c.client_name).collect();
                let mut out = Vec::with_capacity(names.len());
                for name in names {
                    if let Some(row) = find_worker_shares(&s.pool, &addr, &name).await? {
                        out.push(WorkerShareEntry {
                            worker_name: name,
                            total_shares: row.shares as i64,
                            total_rejected: row.rejected_shares as i64,
                        });
                    }
                }
                Ok(out)
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address/:worker ────────────────────────────

/// Per-slot chart entry for a worker page. Carries the hashrate
/// (`data`), the raw accepted-share weight, and the per-reason
/// rejection breakdowns (count + diff-1) the worker tile renders.
#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct WorkerChartEntry {
    label: String,
    data: f64,
    accepted: f64,
    rejected_job_not_found: f64,
    rejected_job_not_found_diff1: f64,
    rejected_duplicated_share: f64,
    rejected_duplicated_share_diff1: f64,
    rejected_low_difficulty_share: f64,
    rejected_low_difficulty_share_diff1: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerResponse {
    name: String,
    best_difficulty: i64,
    chart_data: Vec<WorkerChartEntry>,
}

async fn by_worker<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((address, worker)): Path<(String, String)>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!(
        "CLIENT_WORKER_GROUP_{}_{}_{}",
        addr.as_str(),
        worker,
        range.label()
    );
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<WorkerResponse, _, ApiError>(key, TtlKind::ClientWorkerGroup, async move {
            let clients = find_clients_by_address(&s.pool, &addr).await?;
            let matching: Vec<_> = clients
                .into_iter()
                .filter(|c| c.client_name == worker)
                .collect();
            if matching.is_empty() {
                return Err(ApiError::NotFound);
            }
            let best_difficulty = matching
                .iter()
                .map(|c| c.best_difficulty as f64)
                .fold(0.0_f64, f64::max)
                .floor() as i64;

            let now = crate::time_range::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let rows = find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            let mut grouped: BTreeMap<i64, WorkerChartEntry> = BTreeMap::new();
            for r in rows
                .iter()
                .filter(|r| r.client_name == worker && r.time < cutoff)
            {
                let entry = grouped.entry(r.time).or_insert_with(|| WorkerChartEntry {
                    label: crate::time_range::format_slot_label(r.time),
                    ..Default::default()
                });
                entry.accepted += r.shares as f64;
                entry.rejected_job_not_found += r.rejected_job_not_found_count as f64;
                entry.rejected_job_not_found_diff1 += r.rejected_job_not_found_diff1 as f64;
                entry.rejected_duplicated_share += r.rejected_duplicate_share_count as f64;
                entry.rejected_duplicated_share_diff1 += r.rejected_duplicate_share_diff1 as f64;
                entry.rejected_low_difficulty_share += r.rejected_low_difficulty_share_count as f64;
                entry.rejected_low_difficulty_share_diff1 +=
                    r.rejected_low_difficulty_share_diff1 as f64;
            }
            for e in grouped.values_mut() {
                e.data = e.accepted * DIFFICULTY_1 / SLOT_SECONDS;
            }
            let chart_data: Vec<WorkerChartEntry> = grouped.into_values().collect();
            Ok(WorkerResponse {
                name: worker,
                best_difficulty,
                chart_data,
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address/:worker/:session ───────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    session_id: String,
    name: String,
    best_difficulty: i64,
    chart_data: Vec<ChartPoint>,
    start_time: String,
}

async fn by_session<H, M>(
    State(state): State<SharedState<H, M>>,
    Path((address, worker, session)): Path<(String, String, String)>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!(
        "CLIENT_WORKER_SESSION_{}_{}_{}",
        addr.as_str(),
        worker,
        session
    );
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SessionResponse, _, ApiError>(
            key,
            TtlKind::ClientWorkerSession,
            async move {
                let row = find_client(&s.pool, &addr, &worker, &session)
                    .await?
                    .ok_or(ApiError::NotFound)?;

                let now = crate::time_range::now_ms();
                const DAY_MS: i64 = 24 * 60 * 60 * 1000;
                let since = now - DAY_MS;
                let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
                let rows = find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
                let mut grouped: BTreeMap<i64, f64> = BTreeMap::new();
                for r in rows.iter().filter(|r| {
                    r.client_name == worker && r.session_id == session && r.time < cutoff
                }) {
                    *grouped.entry(r.time).or_insert(0.0) += r.shares as f64;
                }
                let chart_data: Vec<ChartPoint> = grouped
                    .into_iter()
                    .map(|(t, shares)| ChartPoint {
                        label: crate::time_range::format_slot_label(t),
                        data: shares * DIFFICULTY_1 / SLOT_SECONDS,
                    })
                    .collect();

                Ok(SessionResponse {
                    session_id: row.session_id,
                    name: row.client_name,
                    best_difficulty: (row.best_difficulty as f64).floor() as i64,
                    chart_data,
                    start_time: crate::time_range::format_slot_label(row.start_time),
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── POST mutations: reset / delete-stats / delete-all ───────────
//
// Three admin-style endpoints that purge per-address data.
// Unauthenticated — token gating sits on the reverse proxy.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    status: &'static str,
    /// Omitted on `/reset` (shape `{status: "reset"}`); always present
    /// on `/delete-stats` and `/delete-all`.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
}

/// Drop every cached entry whose key references `addr`. Called by
/// the three mutating endpoints so the next read sees fresh data.
async fn invalidate_address_cache<H, M>(state: &SharedState<H, M>, addr: &AddressId)
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    for prefix in [
        "CLIENT_INFO_",
        "CLIENT_CHART_",
        "CLIENT_WORKER_SHARES_",
        "CLIENT_WORKERS_",
        "CLIENT_ACCEPTED_",
        "CLIENT_REJECTED_",
        "CLIENT_DIFF_SCORES_",
        "CLIENT_WORKER_GROUP_",
        "CLIENT_WORKER_SESSION_",
        "CLIENT_BLOCK_TEMPLATE_",
    ] {
        let full = format!("{prefix}{}", addr.as_str());
        state.cache.invalidate_prefix(&full).await;
    }
}

async fn reset_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    reset_address_settings_best_difficulty(&state.pool, &addr).await?;
    sqlx::query!(
        r#"DELETE FROM best_difficulty_tracker_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    invalidate_address_cache(&state, &addr).await;
    Ok(Json(StatusResponse {
        status: "reset",
        address: None,
    }))
}

/// Helper used by both delete-stats and delete-all to wipe every
/// per-address row across the four statistics tables + the worker
/// totals plus reset the address-level best-difficulty hints.
async fn purge_address_stats(pool: &sqlx::PgPool, addr: &AddressId) -> Result<(), ApiError> {
    sqlx::query!(
        r#"DELETE FROM client_statistics_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    sqlx::query!(
        r#"DELETE FROM client_rejected_statistics_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    sqlx::query!(
        r#"DELETE FROM client_difficulty_statistics_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    sqlx::query!(
        r#"DELETE FROM worker_shares_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    sqlx::query!(
        r#"DELETE FROM best_difficulty_tracker_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    reset_address_settings_best_difficulty(pool, addr).await?;
    Ok(())
}

async fn delete_stats<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    purge_address_stats(&state.pool, &addr).await?;
    invalidate_address_cache(&state, &addr).await;
    Ok(Json(StatusResponse {
        status: "stats-deleted",
        address: Some(addr.as_str().to_string()),
    }))
}

async fn delete_all<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    purge_address_stats(&state.pool, &addr).await?;
    // Hard-delete client rows + address-settings row.
    sqlx::query!(
        r#"DELETE FROM client_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    sqlx::query!(
        r#"DELETE FROM address_settings_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    invalidate_address_cache(&state, &addr).await;
    Ok(Json(StatusResponse {
        status: "all-deleted",
        address: Some(addr.as_str().to_string()),
    }))
}

// ─── GET /api/client/:address/diff-scores ────────────────────────
//
// Hourly maximum share-difficulty (sourced from
// `client_difficulty_statistics_entity.maxDifficulty`) over the
// requested range. Always emits a contiguous hour-aligned bucket list
// so the chart x-axis doesn't gap.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiffScoresQuery {
    range: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffScoreSlot {
    time: String,
    difficulty: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffScoresResponse {
    slot_data: Vec<DiffScoreSlot>,
}

async fn diff_scores<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    Query(q): Query<DiffScoresQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range_label = q.range.clone().unwrap_or_else(|| "1d".to_string());
    let key = format!("CLIENT_DIFF_SCORES_{}_{}", addr.as_str(), range_label);
    // Longer ranges scan more rows — cache them proportionally longer.
    let ttl_secs: u64 = match range_label.as_str() {
        "7d" => 1800,
        "30d" => 7200,
        _ => 300,
    };
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch_secs::<DiffScoresResponse, _, ApiError>(key, ttl_secs, async move {
            let hours: i64 = match range_label.as_str() {
                "7d" => 24 * 7,
                "30d" => 24 * 30,
                _ => 24,
            };
            let one_hour_ms: i64 = 60 * 60 * 1000;
            let now = crate::time_range::now_ms();
            let since = now - hours * one_hour_ms;
            let start_slot = (since / one_hour_ms) * one_hour_ms;
            let end_slot = (now / one_hour_ms) * one_hour_ms;

            let rows = sqlx::query!(
                r#"SELECT "slotTime" AS "slot_time: i64",
                          MAX("maxDifficulty") AS "max_diff: f32"
                   FROM client_difficulty_statistics_entity
                   WHERE address = $1
                     AND "slotTime" BETWEEN $2 AND $3
                   GROUP BY "slotTime""#,
                addr.as_str(),
                start_slot,
                end_slot,
            )
            .fetch_all(&s.pool)
            .await
            .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;

            let mut by_slot: std::collections::HashMap<i64, f64> = std::collections::HashMap::new();
            for r in rows {
                by_slot.insert(r.slot_time, r.max_diff.unwrap_or(0.0) as f64);
            }
            let mut slot_data = Vec::new();
            let mut t = start_slot;
            while t <= end_slot {
                slot_data.push(DiffScoreSlot {
                    time: crate::time_range::format_slot_label(t),
                    difficulty: by_slot.get(&t).copied().unwrap_or(0.0),
                });
                t += one_hour_ms;
            }
            Ok(DiffScoresResponse { slot_data })
        })
        .await?;
    Ok(JsonBytes(bytes))
}
