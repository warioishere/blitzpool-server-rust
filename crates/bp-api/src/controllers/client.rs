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
        .route(
            "/api/client/:address/max-difficulty",
            get(max_difficulty::<H, M>),
        )
        .route("/api/client/:address/workers", get(workers::<H, M>))
        .route("/api/client/:address/rejected", get(rejected::<H, M>))
        .route("/api/client/:address/diff-scores", get(diff_scores::<H, M>))
        .route(
            "/api/client/:address/best-difficulty/today",
            get(best_difficulty_today::<H, M>),
        )
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

use crate::controllers::info::{rejected_by_reason_slots, RejectSlotsResponse};
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

use crate::time_range::SLOT_SECONDS;
use bp_common::HASHES_PER_DIFFICULTY_1;

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
            data: (shares * HASHES_PER_DIFFICULTY_1 / SLOT_SECONDS).round(),
        })
        .collect()
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
            let now = bp_common::now_ms();
            let since = now - range.window_ms();
            let rows =
                bp_db::find_client_statistics_since_for_address(&s.pool, &addr, since).await?;
            // Diff-1-weighted accepted shares (sum of share difficulty),
            // NOT the raw share count: this tracks actual work, so the
            // chart stays flat when vardiff trades share size for share
            // rate at constant hashrate. The raw count (`accepted_count`)
            // would drift up as per-share difficulty drops. (The rejected
            // endpoint intentionally still reports raw full-share counts.)
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
async fn max_difficulty<H, M>(
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
        .get_or_fetch::<RejectSlotsResponse, _, ApiError>(
            key,
            TtlKind::ClientRejected,
            async move {
                let now = bp_common::now_ms();
                let since = now - range.window_ms();
                let rows =
                    bp_db::find_client_rejected_statistics_since_for_address(&s.pool, &addr, since)
                        .await?;
                Ok(rejected_by_reason_slots(
                    &chart_slot_boundaries(since),
                    rows.iter()
                        .map(|r| (r.time, (r.reason.as_str(), r.count as f64, r.shares as f64))),
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
    /// The custom extranonce prefix stored for this worker (8 hex chars), or
    /// `null` when it runs on the pool-allocated one. This is the **stored
    /// configuration** from `pplns_custom_extranonce`, not proof that the
    /// prefix is in effect: whether a live connection carries it depends on
    /// the stratum core's Solo / Extended / primary-channel gates, which live
    /// in another process and leave no trace in this table.
    extranonce: Option<String>,
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
            // Custom extranonce overrides, keyed by worker. One query for the
            // address (a handful of rows at most), then a map lookup per
            // worker — the same worker on two sessions gets the same prefix,
            // which is exactly what the override means.
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
                            best_difficulty: format!("{:.2}", lf.best_difficulty),
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
///
/// **One field pair per `bp_stats::RejectedReason`, and that is a
/// contract, not tidiness.** The tile shows these against
/// `rejectedCount`, so a reason with no pair here is a reject the
/// operator sees in the total and cannot find in the breakdown — which
/// is exactly what happened to version rolling between migration 0010
/// (which gave it a column) and this struct learning to emit it.
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
            // Max over the worker's live per-session bests (a session
            // without a live hash contributes nothing, like a 0 column).
            let live = crate::error::or_degraded(
                bp_client_live::live_fields_for_sessions(s.redis.as_ref(), &matching).await,
                || vec![None; matching.len()],
            )?;
            let best_difficulty = live
                .iter()
                .flatten()
                .map(|lf| lf.best_difficulty)
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
                e.data = (e.accepted * HASHES_PER_DIFFICULTY_1 / SLOT_SECONDS).round();
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
                let live = crate::error::or_degraded(
                    bp_client_live::live_fields_for_sessions(
                        s.redis.as_ref(),
                        &[(addr.as_str(), worker.as_str(), session.as_str())],
                    )
                    .await,
                    || vec![None],
                )?;
                let live_best = live
                    .first()
                    .and_then(|o| o.as_ref())
                    .map(|lf| lf.best_difficulty)
                    .unwrap_or(0.0);

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
                        data: (shares * HASHES_PER_DIFFICULTY_1 / SLOT_SECONDS).round(),
                    })
                    .collect();

                Ok(SessionResponse {
                    session_id: row.session_id,
                    name: row.client_name,
                    best_difficulty: live_best.floor() as i64,
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
    // Clears the per-address value and the notification baseline. The
    // public `allTimeBestDifficulty` is untouched by design.
    reset_address_settings_best_difficulty(&state.pool, &addr).await?;
    // Best-effort second half: the per-session bests in Redis. A failure
    // here leaves stale worker rows until their next share, which is a
    // display lag, not a wrong total — so it must not fail the reset.
    if let Err(e) = bp_client_live::clear_address_best_difficulty(state.redis.as_ref(), &addr).await
    {
        tracing::warn!(target: "bp_api", error = %e, address = %addr, "reset: live best-difficulty clear failed");
    }
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
    // Zeroes the address-level best AND deletes the
    // `best_difficulty_tracker_entity` baseline — the tracker delete used
    // to be repeated here, and moved into the shared reset so this path
    // and `/bestdiff_reset` cannot drift apart again.
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
    // Hard-delete the client rows.
    sqlx::query!(
        r#"DELETE FROM client_entity WHERE address = $1"#,
        addr.as_str()
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    // The address-settings row is EMPTIED, not deleted: dropping it would
    // take `allTimeBestDifficulty` with it, and that is the one value no
    // path may lower (migration 0014). `purge_address_stats` already
    // zeroed the resettable best above; this clears the remaining
    // per-address state. What stays behind is the leaderboard record,
    // which carries no address — only a difficulty, a firmware string and
    // a timestamp.
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
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
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
            let now = bp_common::now_ms();
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
                    time: crate::time_range::format_iso_ms(t),
                    difficulty: by_slot.get(&t).copied().unwrap_or(0.0),
                });
                t += one_hour_ms;
            }
            Ok(DiffScoresResponse { slot_data })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── GET /api/client/:address/best-difficulty/today ──────────────
//
// The address's best share difficulty since `since` (epoch ms), which
// the caller sets to its own local midnight. Read from the same hourly
// rows as `diff-scores` (`client_difficulty_statistics_entity`), maxed
// over every worker of the address.
//
// The filter is `"slotTime" >= since`, with no flooring to the hour: a
// value from before the caller's midnight must never show after the
// reset. The rows are UTC hours, so for a timezone with a half- or
// quarter-hour offset the partial hour right after local midnight is
// not counted.
//
// Not cached: `since` differs per timezone, and the query is a range
// scan on the `(address, "slotTime")` index.

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

async fn best_difficulty_today<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    Query(q): Query<BestDifficultyTodayQuery>,
) -> Result<Json<BestDifficultyTodayResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
    let best = sqlx::query_scalar!(
        r#"SELECT MAX("maxDifficulty") AS "max_diff: f32"
           FROM client_difficulty_statistics_entity
           WHERE address = $1
             AND "slotTime" >= $2"#,
        addr.as_str(),
        since,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;
    Ok(Json(BestDifficultyTodayResponse {
        best_difficulty: best.map_or(0.0, f64::from),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
