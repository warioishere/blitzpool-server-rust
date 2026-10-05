// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/client/:address/*` reader endpoints.

use axum::{
    extract::{Path, State},
    response::Json,
    routing::{get, post},
    Router,
};
use std::collections::{BTreeSet, HashMap};

use bp_common::AddressId;
use bp_db::{
    find_address_settings, find_client, find_client_statistics_since_for_address,
    find_clients_by_address, find_worker_shares_for_address,
    reset_address_settings_best_difficulty, WorkerSharesRow,
};
use serde::Serialize;

use crate::error::ApiError;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::SharedState;

pub(crate) fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/client/{address}", get(by_address))
        .route("/api/client/{address}/worker-shares", get(worker_shares))
        .route("/api/client/{address}/chart", get(chart))
        .route("/api/client/{address}/accepted", get(accepted))
        .route("/api/client/{address}/max-difficulty", get(max_difficulty))
        .route("/api/client/{address}/workers", get(workers))
        .route("/api/client/{address}/rejected", get(rejected))
        .route("/api/client/{address}/diff-scores", get(diff_scores))
        .route(
            "/api/client/{address}/best-difficulty/today",
            get(best_difficulty_today),
        )
        .route("/api/client/{address}/reset", post(reset_address))
        .route("/api/client/{address}/delete-stats", post(delete_stats))
        .route("/api/client/{address}/delete-all", post(delete_all))
        // The triple-segment routes must come AFTER the specific
        // chart/accepted/workers/rejected paths so axum picks the
        // specific match first.
        .route("/api/client/{address}/{worker}", get(by_worker))
        .route("/api/client/{address}/{worker}/{session}", get(by_session))
}

// ─── time-range chart endpoints ──────────────────────────────────

use crate::controllers::info::{
    client_reject_samples, rejected_by_reason_slots, RejectSlotsResponse,
};
use crate::time_range::{
    accepted_slot_data, chart_slot_boundaries, fold_into_slots, max_difficulty_slot_data,
    sum_into_slots, ChartPoint, Range, SlotDataResponse,
};
use axum::extract::Query;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeQuery {
    range: Option<String>,
}

use crate::time_range::slot_hashrate;

async fn chart(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_CHART_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::ClientChart, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            Ok(chart_points(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.shares as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

/// Hashrate per slot, rounded to a whole H/s, one point per boundary.
fn chart_points(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, f64)>,
) -> Vec<ChartPoint> {
    sum_into_slots(boundaries, samples)
        .into_iter()
        .map(|(b, shares)| ChartPoint {
            label: crate::time_range::format_iso_ms(b),
            data: slot_hashrate(shares),
        })
        .collect()
}

async fn accepted(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_ACCEPTED_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::ClientAccepted, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            // Diff-1-weighted accepted shares (sum of share difficulty), not
            // the raw count: it tracks work, so the chart stays flat when
            // vardiff trades share size for share rate. (The rejected
            // endpoint intentionally reports raw counts.)
            Ok(accepted_slot_data(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.shares as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

/// The highest single share difficulty of the address in each 10-minute
/// slot, over all its workers.
async fn max_difficulty(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_MAX_DIFFICULTY_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::ClientAccepted, async move {
            let since = bp_common::now_ms() - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            Ok(max_difficulty_slot_data(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.max_difficulty as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

async fn workers(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_WORKERS_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<SlotDataResponse, _, ApiError>(key, TtlKind::ClientWorkers, async move {
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            Ok(worker_slots(
                &chart_slot_boundaries(since),
                rows.iter()
                    .map(|r| (r.time, (r.client_name.as_str(), r.session_id.as_str()))),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

/// `(time, (worker, session))` samples → distinct workers + sessions per slot.
fn worker_slots<'a>(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, (&'a str, &'a str))>,
) -> SlotDataResponse {
    type Seen = (HashSet<String>, HashSet<String>);
    let slots = fold_into_slots(
        boundaries,
        samples,
        |(workers, sessions): &mut Seen, (worker, session)| {
            workers.insert(worker.to_string());
            sessions.insert(session.to_string());
        },
    );
    SlotDataResponse::from_slots(slots, |(workers, sessions)| {
        BTreeMap::from([
            ("workers".to_string(), workers.len() as f64),
            ("sessions".to_string(), sessions.len() as f64),
        ])
    })
}

async fn rejected(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("CLIENT_REJECTED_{}_{}", addr.as_str(), range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<RejectSlotsResponse, _, ApiError>(
            key,
            TtlKind::ClientRejected,
            async move {
                let now = bp_common::now_ms();
                let since = now - range.window_ms();
                let rows =
                    bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
                Ok(rejected_by_reason_slots(
                    &chart_slot_boundaries(since),
                    rows.iter().flat_map(client_reject_samples),
                ))
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address ────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientResponse {
    best_difficulty: Option<u64>,
    workers_count: usize,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_shares: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
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
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    hash_rate: f64,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
    current_difficulty: Option<f64>,
    /// Mining channels on this worker's connection. `> 1` means a rental
    /// proxy bundled several same-rig devices onto one connection, so the
    /// UI renders the difficulty as aggregated instead of a single value.
    channel_count: i32,
    start_time: String,
    last_seen: String,
    /// The stored custom extranonce prefix (8 hex chars), `null` for the
    /// pool-allocated one. Stored configuration only, not proof it is in
    /// effect: the stratum core's channel gates decide that in another process.
    extranonce: Option<String>,
}

async fn by_address(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("CLIENT_INFO_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<ClientResponse, _, ApiError>(key, TtlKind::ClientInfo, async move {
            let clients = find_clients_by_address(&s.pool, &addr).await?;
            // Live half from Redis, positionally aligned with `clients`.
            // A session without a live hash renders as 0/None — it stays
            // listed while its PG row is active.
            let live = crate::error::or_degraded(
                bp_client_live::live_fields_for_sessions(s.redis.as_ref(), &clients).await,
                || vec![None; clients.len()],
            )?;
            let total_hashrate: f64 = live.iter().flatten().map(|lf| lf.hash_rate).sum();
            let settings = find_address_settings(&s.pool, &addr).await?;
            let best_difficulty = settings.as_ref().map(|x| x.best_difficulty.floor() as u64);
            let total_shares = settings.map(|x| x.shares).unwrap_or(0.0);
            // Keyed by worker: the same worker on two sessions gets the same
            // prefix, which is what the override means.
            let overrides: BTreeMap<String, String> =
                bp_db::find_custom_extranonces_for_address(&s.pool, &addr)
                    .await?
                    .into_iter()
                    .map(|r| (r.worker, format!("{:08x}", r.prefix)))
                    .collect();
            Ok(ClientResponse {
                best_difficulty,
                workers_count: clients.len(),
                total_shares,
                total_hashrate,
                workers: clients
                    .into_iter()
                    .zip(live)
                    .map(|(c, lf)| {
                        let lf = lf.unwrap_or_default();
                        WorkerEntry {
                            session_id: c.session_id,
                            extranonce: overrides.get(&c.client_name).cloned(),
                            name: c.client_name,
                            best_difficulty: format!("{:.2}", c.best_difficulty),
                            hash_rate: lf.hash_rate,
                            current_difficulty: lf.current_difficulty,
                            channel_count: lf.channel_count.unwrap_or(1),
                            start_time: crate::time_range::format_iso_ms(c.start_time),
                            // No live hash → the freshest thing known is
                            // the session's own start.
                            last_seen: crate::time_range::format_iso_ms(
                                lf.updated_at_ms.unwrap_or(c.start_time),
                            ),
                        }
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

async fn worker_shares(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("CLIENT_WORKER_SHARES_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<WorkerShareEntry>, _, ApiError>(
            key,
            TtlKind::ClientWorkerShares,
            async move {
                // The address's connected workers, each with its lifetime row
                // if it has one, in name order.
                let clients = find_clients_by_address(&s.pool, &addr).await?;
                let names: BTreeSet<String> = clients.into_iter().map(|c| c.client_name).collect();
                let mut totals: HashMap<String, WorkerSharesRow> =
                    find_worker_shares_for_address(&s.pool, &addr)
                        .await?
                        .into_iter()
                        .map(|row| (row.client_name.clone(), row))
                        .collect();
                let out: Vec<WorkerShareEntry> = names
                    .into_iter()
                    .filter_map(|name| {
                        let row = totals.remove(&name)?;
                        Some(WorkerShareEntry {
                            worker_name: name,
                            total_shares: row.shares as i64,
                            total_rejected: row.rejected_shares as i64,
                        })
                    })
                    .collect();
                Ok(out)
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address/:worker ────────────────────────────

/// Per-slot chart entry for a worker page: hashrate, accepted weight and
/// per-reason rejects. **One field pair per `bp_stats::RejectedReason` is a
/// contract**: a reason missing here is a reject the operator sees in the
/// total and cannot find in the breakdown.
#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct WorkerChartEntry {
    label: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    data: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    accepted: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_job_not_found: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_job_not_found_diff1: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_duplicated_share: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_duplicated_share_diff1: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_low_difficulty_share: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_low_difficulty_share_diff1: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_version_rolling: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_version_rolling_diff1: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_stale: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    rejected_stale_diff1: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerResponse {
    name: String,
    best_difficulty: i64,
    chart_data: Vec<WorkerChartEntry>,
}

async fn by_worker(
    State(state): State<SharedState>,
    Path((address, worker)): Path<(String, String)>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
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
                .map(|c| c.best_difficulty)
                .fold(0.0_f64, f64::max)
                .floor() as i64;

            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let cutoff = bp_stats::slot::chart_visibility_cutoff_slot().as_millis();
            let rows = find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            let mut grouped: BTreeMap<i64, WorkerChartEntry> = BTreeMap::new();
            for r in rows
                .iter()
                .filter(|r| r.client_name == worker && r.time < cutoff)
            {
                let entry = grouped.entry(r.time).or_insert_with(|| WorkerChartEntry {
                    label: crate::time_range::format_iso_ms(r.time),
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
                entry.rejected_version_rolling += r.rejected_version_rolling_count as f64;
                entry.rejected_version_rolling_diff1 += r.rejected_version_rolling_diff1 as f64;
                entry.rejected_stale += r.rejected_stale_count as f64;
                entry.rejected_stale_diff1 += r.rejected_stale_diff1 as f64;
            }
            for e in grouped.values_mut() {
                e.data = slot_hashrate(e.accepted);
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

async fn by_session(
    State(state): State<SharedState>,
    Path((address, worker, session)): Path<(String, String, String)>,
) -> Result<JsonBytes, ApiError> {
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

                let now = bp_common::now_ms();
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
                        label: crate::time_range::format_iso_ms(t),
                        data: slot_hashrate(shares),
                    })
                    .collect();

                Ok(SessionResponse {
                    session_id: row.session_id,
                    name: row.client_name,
                    best_difficulty: row.best_difficulty.floor() as i64,
                    chart_data,
                    start_time: crate::time_range::format_iso_ms(row.start_time),
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── POST mutations: reset / delete-stats / delete-all ───────────
//
// Unauthenticated here: token gating sits on the reverse proxy.

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
async fn invalidate_address_cache(state: &SharedState, addr: &AddressId) {
    for prefix in [
        "CLIENT_INFO_",
        "CLIENT_CHART_",
        "CLIENT_WORKER_SHARES_",
        "CLIENT_WORKERS_",
        "CLIENT_ACCEPTED_",
        "CLIENT_MAX_DIFFICULTY_",
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

async fn reset_address(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    // The per-address value, the notification baseline and the session
    // bests. The public `allTimeBestDifficulty` is untouched by design.
    reset_address_settings_best_difficulty(&state.pool, &addr).await?;
    invalidate_address_cache(&state, &addr).await;
    Ok(Json(StatusResponse {
        status: "reset",
        address: None,
    }))
}

/// Helper used by both delete-stats and delete-all to wipe every
/// per-address row across the statistics tables + the worker
/// totals plus reset the address-level best-difficulty hints.
async fn purge_address_stats(pool: &sqlx::PgPool, addr: &AddressId) -> Result<(), ApiError> {
    sqlx::query!(
        r#"DELETE FROM client_statistics_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    // Nothing writes the next two tables; the deletes clear what they still
    // hold for this address until a migration drops them.
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
    // Zeroes the address-level best AND deletes the
    // `best_difficulty_tracker_entity` baseline; the reset is shared with
    // `/bestdiff_reset` so the two paths cannot drift apart.
    reset_address_settings_best_difficulty(pool, addr).await?;
    Ok(())
}

async fn delete_stats(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    purge_address_stats(&state.pool, &addr).await?;
    invalidate_address_cache(&state, &addr).await;
    Ok(Json(StatusResponse {
        status: "stats-deleted",
        address: Some(addr.as_str().to_string()),
    }))
}

async fn delete_all(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<StatusResponse>, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    purge_address_stats(&state.pool, &addr).await?;
    // Hard-delete the client rows.
    sqlx::query!(
        r#"DELETE FROM client_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    // The address-settings row is EMPTIED, not deleted: dropping it would
    // take `allTimeBestDifficulty` with it, the one value no path may lower.
    // What stays is the leaderboard record, which carries no address.
    sqlx::query!(
        r#"UPDATE address_settings_entity
           SET shares = 0,
               "miscCoinbaseScriptData" = NULL,
               "updatedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           WHERE address = $1"#,
        addr.as_str()
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    // Best-effort: drop the live hashes too, or the purged miner keeps
    // reporting hashrate for up to the TTL. Failure only delays that.
    if let Err(e) = bp_client_live::delete_address_live_keys(state.redis.as_ref(), &addr).await {
        tracing::warn!(target: "bp_api", error = %e, address = %addr, "delete_all: live-key purge failed");
    }
    invalidate_address_cache(&state, &addr).await;
    Ok(Json(StatusResponse {
        status: "all-deleted",
        address: Some(addr.as_str().to_string()),
    }))
}

// ─── GET /api/client/:address/diff-scores ────────────────────────
//
// Hourly max share difficulty over the range, as a contiguous
// hour-aligned bucket list so the chart x-axis does not gap.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiffScoresQuery {
    range: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffScoreSlot {
    time: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    difficulty: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffScoresResponse {
    slot_data: Vec<DiffScoreSlot>,
}

/// One diff-scores bucket.
const HOUR_MS: i64 = 60 * 60 * 1000;

/// Cache lifetime of a `diff-scores` response: longer ranges are cached
/// longer, but never past the next full hour. The response ends in an hourly
/// bucket, and scoreboard periods start on the hour, so a response cached
/// across that boundary would hide the new period's first bucket.
fn diff_scores_ttl_secs(range_label: &str, now_ms: i64) -> u64 {
    let by_range: u64 = match range_label {
        "7d" => 1800,
        "30d" => 7200,
        _ => 300,
    };
    let until_next_hour_ms = HOUR_MS - now_ms.rem_euclid(HOUR_MS);
    let until_next_hour = u64::try_from(until_next_hour_ms / 1000).unwrap_or(1).max(1);
    by_range.min(until_next_hour)
}

async fn diff_scores(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<DiffScoresQuery>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let range_label = q.range.clone().unwrap_or_else(|| "1d".to_string());
    let key = format!("CLIENT_DIFF_SCORES_{}_{}", addr.as_str(), range_label);
    let ttl_secs = diff_scores_ttl_secs(&range_label, bp_common::now_ms());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch_secs::<DiffScoresResponse, _, ApiError>(key, ttl_secs, async move {
            let hours: i64 = match range_label.as_str() {
                "7d" => 24 * 7,
                "30d" => 24 * 30,
                _ => 24,
            };
            let now = bp_common::now_ms();
            let since = now - hours * HOUR_MS;
            let start_slot = (since / HOUR_MS) * HOUR_MS;
            let end_slot = (now / HOUR_MS) * HOUR_MS;

            let rows = bp_db::find_max_difficulty_since_for_addresses(
                &s.pool,
                std::slice::from_ref(&addr),
                start_slot + bp_stats::SLOT_DURATION_MS,
            )
            .await?;

            // A 10-minute slot (keyed by its end) belongs to the hour it starts in.
            let mut by_slot: std::collections::HashMap<i64, f64> = std::collections::HashMap::new();
            for (slot_end, max) in rows {
                let hour = ((slot_end - bp_stats::SLOT_DURATION_MS) / HOUR_MS) * HOUR_MS;
                let best = by_slot.entry(hour).or_insert(0.0);
                *best = best.max(f64::from(max));
            }
            let mut slot_data = Vec::new();
            let mut t = start_slot;
            while t <= end_slot {
                slot_data.push(DiffScoreSlot {
                    time: crate::time_range::format_iso_ms(t),
                    difficulty: by_slot.get(&t).copied().unwrap_or(0.0),
                });
                t += HOUR_MS;
            }
            Ok(DiffScoresResponse { slot_data })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address/best-difficulty/today ──────────────
//
// Best share since the caller's local midnight `since`, from the 10-minute
// slots that start at or after it, so nothing pre-midnight shows; not
// cached, as `since` varies by zone.

/// Oldest `since` accepted, relative to now. A local midnight is at most
/// 24 h back, 25 h on a DST fall-back day; the extra hour is room for
/// client clock skew. The rows are kept longer, so the bound is on the
/// meaning of "today", not on retention.
const BEST_TODAY_MAX_LOOKBACK_MS: i64 = 26 * 60 * 60 * 1000;
/// Newest `since` accepted, relative to now — room for client clock skew.
const BEST_TODAY_MAX_LOOKAHEAD_MS: i64 = 60 * 60 * 1000;

#[derive(Deserialize)]
struct BestDifficultyTodayQuery {
    // Taken as a string and parsed here, so a non-numeric value gets the
    // JSON error envelope instead of axum's plain-text query rejection.
    since: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BestDifficultyTodayResponse {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    best_difficulty: f64,
}

async fn best_difficulty_today(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<BestDifficultyTodayQuery>,
) -> Result<Json<BestDifficultyTodayResponse>, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let since: i64 = q
        .since
        .as_deref()
        .ok_or(ApiError::InvalidQuery("since is required (epoch ms)"))?
        .parse()
        .map_err(|_| ApiError::InvalidQuery("since must be an integer (epoch ms)"))?;
    let now = bp_common::now_ms();
    if since < now - BEST_TODAY_MAX_LOOKBACK_MS || since > now + BEST_TODAY_MAX_LOOKAHEAD_MS {
        return Err(ApiError::InvalidQuery(
            "since must be within the last 26 h and at most 1 h ahead",
        ));
    }
    // Only slots that start at or after `since`: a slot is keyed by its end.
    let best = bp_db::find_max_difficulty_since_for_addresses(
        &state.pool,
        std::slice::from_ref(&addr),
        since + bp_stats::SLOT_DURATION_MS,
    )
    .await?
    .into_iter()
    .map(|(_, max)| f64::from(max))
    .fold(0.0, f64::max);
    Ok(Json(BestDifficultyTodayResponse {
        best_difficulty: best,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cached `diff-scores` response never outlives the hour bucket it ends
    /// in, so a scoreboard period starting on the hour sees its first bucket
    /// on the next fetch.
    #[test]
    fn a_diff_scores_response_expires_at_the_next_full_hour() {
        let hour = 3_600_000_i64;
        let just_before = 1_790_805_540_000_i64; // 21:59:00 UTC
        for range in ["1d", "7d", "30d"] {
            assert_eq!(diff_scores_ttl_secs(range, just_before), 60, "{range}");
        }
        // Mid-hour the range's own lifetime still applies when it is shorter.
        assert_eq!(
            diff_scores_ttl_secs("1d", 1_790_802_000_000 + hour / 2),
            300
        );
        assert_eq!(diff_scores_ttl_secs("30d", 1_790_802_000_000), 3600);
    }

    const S: i64 = 600_000;
    const T0: i64 = 1_700_000_400_000;
    const BOUNDARIES: [i64; 3] = [T0, T0 + S, T0 + 2 * S];

    fn json<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    /// Accepted-share samples: a slot with two rows (one f32-derived), a
    /// row inside the second slot but off its boundary, an empty third
    /// slot, and rows either side of the window that must be dropped.
    fn share_samples() -> Vec<(i64, f64)> {
        vec![
            (T0, 1.5),
            (T0, 0.1_f32 as f64),
            (T0 + S + 123, 2.0),
            (T0 - S, 99.0),
            (T0 + 3 * S, 77.0),
        ]
    }

    /// `/api/client/:address/chart` — dense, one point per slot, hashrate
    /// rounded to a whole number.
    #[test]
    fn chart_json_is_unchanged() {
        assert_eq!(
            json(&chart_points(&BOUNDARIES, share_samples())),
            r#"[{"label":"2023-11-14T22:20:00.000Z","data":11453246},{"label":"2023-11-14T22:30:00.000Z","data":14316558},{"label":"2023-11-14T22:40:00.000Z","data":0}]"#
        );
    }

    /// `/api/client/:address/accepted`.
    #[test]
    fn accepted_json_is_unchanged() {
        assert_eq!(
            json(&accepted_slot_data(&BOUNDARIES, share_samples())),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"accepted":1.6000000014901161}},{"time":"2023-11-14T22:30:00.000Z","counts":{"accepted":2}},{"time":"2023-11-14T22:40:00.000Z","counts":{"accepted":0}}]}"#
        );
    }

    /// `/api/client/:address/workers` — distinct workers and sessions.
    #[test]
    fn workers_json_is_unchanged() {
        let samples = vec![
            (T0, ("w1", "s1")),
            (T0, ("w1", "s2")),
            (T0, ("w1", "s1")),
            (T0 + S, ("w2", "s3")),
            (T0 + S + 5, ("w1", "s1")),
            (T0 + 3 * S, ("w9", "s9")),
        ];
        assert_eq!(
            json(&worker_slots(&BOUNDARIES, samples)),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"sessions":2,"workers":1}},{"time":"2023-11-14T22:30:00.000Z","counts":{"sessions":2,"workers":2}},{"time":"2023-11-14T22:40:00.000Z","counts":{"sessions":0,"workers":0}}]}"#
        );
    }

    /// `/api/client/:address/rejected` — every known reason pre-filled,
    /// legacy kebab-case folded into its camel-case key, unknown reasons
    /// into `OtherUnknown`.
    #[test]
    fn rejected_json_is_unchanged() {
        assert_eq!(
            json(&rejected_by_reason_slots(&BOUNDARIES, reject_samples())),
            r#"{"slotData":[{"time":"2023-11-14T22:20:00.000Z","counts":{"DuplicateShare":{"count":0,"diffMinusOne":0},"JobNotFound":{"count":3,"diffMinusOne":1.75},"LowDifficultyShare":{"count":0,"diffMinusOne":0},"NotSubscribed":{"count":0,"diffMinusOne":0},"OtherUnknown":{"count":3,"diffMinusOne":3},"Stale":{"count":0,"diffMinusOne":0},"UnauthorizedWorker":{"count":0,"diffMinusOne":0},"VersionRollingNotAllowed":{"count":0,"diffMinusOne":0}}},{"time":"2023-11-14T22:30:00.000Z","counts":{"DuplicateShare":{"count":0,"diffMinusOne":0},"JobNotFound":{"count":0,"diffMinusOne":0},"LowDifficultyShare":{"count":0,"diffMinusOne":0},"NotSubscribed":{"count":0,"diffMinusOne":0},"OtherUnknown":{"count":0,"diffMinusOne":0},"Stale":{"count":4,"diffMinusOne":0.10000000149011612},"UnauthorizedWorker":{"count":0,"diffMinusOne":0},"VersionRollingNotAllowed":{"count":0,"diffMinusOne":0}}},{"time":"2023-11-14T22:40:00.000Z","counts":{"DuplicateShare":{"count":0,"diffMinusOne":0},"JobNotFound":{"count":0,"diffMinusOne":0},"LowDifficultyShare":{"count":0,"diffMinusOne":0},"NotSubscribed":{"count":0,"diffMinusOne":0},"OtherUnknown":{"count":0,"diffMinusOne":0},"Stale":{"count":0,"diffMinusOne":0},"UnauthorizedWorker":{"count":0,"diffMinusOne":0},"VersionRollingNotAllowed":{"count":0,"diffMinusOne":0}}}]}"#
        );
    }

    fn reject_samples() -> Vec<(i64, (&'static str, f64, f64))> {
        vec![
            (T0, ("job-not-found", 2.0, 0.25)),
            (T0, ("JobNotFound", 1.0, 1.5)),
            (T0, ("something-new", 3.0, 3.0)),
            (T0 + S + 7, ("Stale", 4.0, 0.1_f32 as f64)),
            (T0 + 3 * S, ("Stale", 50.0, 50.0)),
        ]
    }
}
