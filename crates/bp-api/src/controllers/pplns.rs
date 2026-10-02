// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/pplns/*` — pure reader endpoints driven by
//! `PplnsEngine::reader()`.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Router,
};
use bp_common::AddressId;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::{AppState, SharedState};

pub(crate) fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/pplns", get(root))
        .route("/api/pplns/mode/{address}", get(mode))
        .route("/api/pplns/status", get(status))
        .route("/api/pplns/fees", get(fees))
        .route("/api/pplns/distribution", get(distribution))
        .route("/api/pplns/ledger", get(ledger))
        .route("/api/pplns/chart", get(chart))
        .route("/api/pplns/{address}", get(address_summary))
        .route("/api/pplns/{address}/history", get(address_history))
}

// ─── /api/pplns/chart ────────────────────────────────────────────
//
// Hashrate timeseries for the PPLNS mining mode, sourced from the
// `pool_mode_hashrate` table.

use crate::time_range::{chart_slot_boundaries, sum_into_slots, ChartPoint, Range};
use bp_common::MiningMode;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeQuery {
    range: Option<String>,
}

async fn chart(
    State(state): State<SharedState>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError> {
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("PPLNS_CHART_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::PplnsChart, async move {
            let now_ms = bp_common::now_ms();
            let since = now_ms - range.window_ms();
            let rows =
                bp_db::find_pool_mode_hashrate_since(&s.pool, MiningMode::Pplns, since).await?;
            Ok(chart_points(
                &chart_slot_boundaries(since),
                rows.iter().map(|r| (r.time, r.diff as f64)),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

/// Per-slot sum of the PPLNS accepted diff, one point per boundary.
fn chart_points(
    boundaries: &[i64],
    samples: impl IntoIterator<Item = (i64, f64)>,
) -> Vec<ChartPoint> {
    sum_into_slots(boundaries, samples)
        .into_iter()
        .map(|(b, diff)| ChartPoint {
            label: crate::time_range::format_iso_ms(b),
            data: diff,
        })
        .collect()
}

// ─── helpers ──────────────────────────────────────────────────────

fn require_pplns(state: &SharedState) -> Result<&bp_pplns_engine::engine::PplnsEngine, ApiError> {
    state
        .pplns
        .as_deref()
        .ok_or(ApiError::Unavailable("pplns-engine not wired"))
}

// ─── /api/pplns + /status ─────────────────────────────────────────

/// Window-stats body without the internal `networkDifficulty` field
/// the frontend ignores — kept slim for both `/status` and the root
/// info endpoint.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowStatsBody {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_shares: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    window_size: f64,
    miner_count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    enabled: bool,
    #[serde(flatten)]
    window: WindowStatsBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserAgentEntry {
    user_agent: Option<String>,
    /// String-as-number; the UI parses it with parseInt.
    count: String,
    best_difficulty: Option<u64>,
    #[serde(serialize_with = "crate::time_range::ser_opt_f64_jsnum")]
    total_hash_rate: Option<f64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RootResponse {
    enabled: bool,
    #[serde(flatten)]
    window: WindowStatsBody,
    user_agents: Vec<UserAgentEntry>,
}

async fn status(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<StatusResponse, _, ApiError>(
            "PPLNS_STATUS".to_string(),
            TtlKind::PplnsStatus,
            async move {
                let engine = require_pplns(&s)?;
                let ws = engine.reader().window_stats().await?;
                Ok(StatusResponse {
                    enabled: true,
                    window: WindowStatsBody {
                        total_shares: ws.total_shares,
                        window_size: ws.window_size,
                        miner_count: ws.miner_count,
                    },
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

async fn root(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<RootResponse, _, ApiError>(
            "PPLNS_ROOT".to_string(),
            TtlKind::PplnsRoot,
            async move { root_inner(&s).await },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

async fn root_inner(state: &SharedState) -> Result<RootResponse, ApiError> {
    let engine = require_pplns(state)?;
    let ws = engine.reader().window_stats().await?;
    let dist = engine.reader().current_distribution().await?;
    let addresses: Vec<String> = dist.into_iter().map(|a| a.address).collect();
    // Per-address user-agent aggregation.
    let user_agents = if addresses.is_empty() {
        Vec::new()
    } else {
        let sessions = bp_db::find_active_sessions_for_addresses(&state.pool, &addresses).await?;
        let rows: Vec<bp_client_live::UserAgentSessionRow> = sessions
            .into_iter()
            .map(|r| bp_client_live::UserAgentSessionRow {
                user_agent: r.user_agent,
                address: r.address.into_inner(),
                worker: r.client_name,
                session_id: r.session_id,
            })
            .collect();
        crate::error::or_degraded(
            bp_client_live::aggregate_by_user_agent(state.redis.as_ref(), &rows).await,
            || bp_client_live::aggregate_offline(&rows),
        )?
        .into_iter()
        .map(|a| UserAgentEntry {
            user_agent: a.user_agent,
            count: a.count.to_string(),
            best_difficulty: Some(a.best_difficulty.floor() as u64),
            total_hash_rate: Some(a.total_hash_rate),
        })
        .collect()
    };
    Ok(RootResponse {
        enabled: true,
        window: WindowStatsBody {
            total_shares: ws.total_shares,
            window_size: ws.window_size,
            miner_count: ws.miner_count,
        },
        user_agents,
    })
}

// ─── /api/pplns/mode/:address ─────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModeResponse {
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
}

async fn mode(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError> {
    let addr = AddressId::new(address).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("PPLNS_MODE_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<ModeResponse, _, ApiError>(key, TtlKind::PplnsMode, async move {
            let resolved = crate::mode::resolve_address_mode(&s, &addr).await?;
            Ok(ModeResponse {
                mode: resolved.mode().as_str(),
                group_id: resolved.group_id().map(|g| g.to_string()),
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/pplns/fees ──────────────────────────────────────────────

/// Full fee / coinbase-shape / port-gate breakdown the UI renders on
/// the PPLNS info page. The structural weight numbers and the dust
/// floor come from `bp-pplns::weight`; max-output counts are derived
/// from the configured weight budget.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FeesResponse {
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    fee_percent: f64,
    fee_address: Option<String>,
    coinbase_weight_budget: u32,
    /// Shared `[group_fees]` lane percent (Group-Solo + Blockparty).
    /// Falls back to the PPLNS `fee_percent` when no group fee is wired.
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    group_fee_percent: f64,
    group_fee_address: Option<String>,
    dust_limit_sats: u64,
    min_payout_sats: i64,
    coinbase_base_weight: u32,
    coinbase_output_weight: u32,
    coinbase_witness_commitment_weight: u32,
    max_miner_outputs: u32,
    max_miner_outputs_adaptive: u32,
    min_difficulty: u64,
}

async fn fees(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    use bp_pplns_engine::{
        max_coinbase_outputs, COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT,
        COINBASE_WITNESS_COMMITMENT_WEIGHT, DUST_LIMIT_SATS,
    };
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<FeesResponse, _, ApiError>(
            "PPLNS_FEES".to_string(),
            TtlKind::PplnsFees,
            async move {
                let engine = require_pplns(&s)?;
                let group_solo = s
                    .group_solo
                    .as_ref()
                    .ok_or(ApiError::Unavailable("group-solo not wired"))?
                    .config();
                let cfg = engine.reader().fee_config();
                let raw_cfg = engine.config();
                let coinbase_weight_budget =
                    live_pplns_budget(&s, cfg.coinbase_weight_budget).await;
                // The blockspace cut's worst-case ceiling at this budget. The
                // adaptive field has no mixed-type estimate behind it and
                // reports the same value.
                let max_miner_outputs =
                    u32::try_from(max_coinbase_outputs(coinbase_weight_budget)).unwrap_or(u32::MAX);
                let max_miner_outputs_adaptive = max_miner_outputs;
                Ok(FeesResponse {
                    fee_percent: cfg.fee_percent,
                    fee_address: cfg.fee_address,
                    coinbase_weight_budget,
                    // The Group-Solo engine's own resolved lane
                    // (`[group_fees]`, else `[pplns]`); Blockparty resolves
                    // the same way.
                    group_fee_percent: group_solo.fee_percent,
                    group_fee_address: group_solo
                        .fee_address
                        .as_ref()
                        .map(|a| a.as_str().to_string()),
                    dust_limit_sats: DUST_LIMIT_SATS,
                    min_payout_sats: cfg.min_payout_sats,
                    coinbase_base_weight: COINBASE_BASE_WEIGHT,
                    coinbase_output_weight: COINBASE_OUTPUT_WEIGHT,
                    coinbase_witness_commitment_weight: COINBASE_WITNESS_COMMITMENT_WEIGHT,
                    max_miner_outputs,
                    max_miner_outputs_adaptive,
                    min_difficulty: raw_cfg.min_difficulty,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

/// The PPLNS coinbase weight budget in force: with the autoscaler on, the live
/// value another process persists in Redis. Otherwise, or when the key is
/// missing or unreadable, the config budget (a leftover key would be stale).
async fn live_pplns_budget(state: &AppState, config_budget: u32) -> u32 {
    if !state.pplns_budget_autoscaled {
        return config_budget;
    }
    let Some(mut redis) = state.redis.clone() else {
        return config_budget;
    };
    match bp_coinbase_snapshot::read_coinbase_budget(
        &mut redis,
        bp_coinbase_snapshot::PPLNS_COINBASE_BUDGET_KEY,
    )
    .await
    {
        Ok(Some(live)) => live,
        Ok(None) => config_budget,
        Err(err) => {
            tracing::warn!(%err, "pplns fees: live budget unreadable; reporting the config budget");
            config_budget
        }
    }
}

// ─── /api/pplns/distribution ──────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DistributionEntry {
    address: String,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    total_shares: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    percent: f64,
}

async fn distribution(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<DistributionEntry>, _, ApiError>(
            "PPLNS_DISTRIBUTION".to_string(),
            TtlKind::PplnsDistribution,
            async move {
                let dist = require_pplns(&s)?.reader().current_distribution().await?;
                Ok(dist
                    .into_iter()
                    .map(|a| DistributionEntry {
                        address: a.address,
                        total_shares: a.total_shares,
                        percent: a.percent,
                    })
                    .collect())
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/pplns/ledger ────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LedgerResponse {
    total_credit_sats: i64,
    total_debit_sats: i64,
    net_drift_sats: i64,
    credit_holder_count: u32,
    debit_holder_count: u32,
    abandoned_credit_sats: i64,
    abandoned_debit_sats: i64,
    lifetime_paid_sats: i64,
    /// Configured inactivity threshold in days — UI renders the
    /// cutoff hint ("abandoned after N days") off this.
    abandoned_days: u32,
}

async fn ledger(State(state): State<SharedState>) -> Result<JsonBytes, ApiError> {
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<LedgerResponse, _, ApiError>(
            "PPLNS_LEDGER".to_string(),
            TtlKind::PplnsLedger,
            async move {
                let summary = require_pplns(&s)?.reader().ledger_summary().await?;
                Ok(LedgerResponse {
                    total_credit_sats: summary.total_credit_sats,
                    total_debit_sats: summary.total_debit_sats,
                    net_drift_sats: summary.net_drift_sats,
                    credit_holder_count: summary.credit_row_count,
                    debit_holder_count: summary.debit_row_count,
                    abandoned_credit_sats: summary.abandoned_credit_sats,
                    abandoned_debit_sats: summary.abandoned_debit_sats,
                    lifetime_paid_sats: summary.lifetime_paid_sats,
                    abandoned_days: summary.abandoned_balance_days,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/pplns/:address ──────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddressSummary {
    balance_sats: i64,
    total_paid_sats: i64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    current_window_shares: f64,
    #[serde(serialize_with = "crate::time_range::ser_f64_jsnum")]
    current_window_percent: f64,
    balance_label: &'static str,
}

async fn address_summary(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError> {
    let key = format!("PPLNS_ADDRESS_{address}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<AddressSummary, _, ApiError>(key, TtlKind::PplnsAddress, async move {
            // A dormant / not-yet-credited address (no balance row and no
            // window shares) is a valid zero state, not a 404 — return zeros
            // so the dashboard renders the address.
            let status = require_pplns(&s)?.reader().address_status(&address).await?;
            let (balance_sats, total_paid_sats, window_shares, window_percent) = match &status {
                Some(st) => (
                    st.balance_sats,
                    st.total_paid_sats,
                    st.current_window_shares,
                    st.current_window_percent,
                ),
                None => (0, 0, 0.0, 0.0),
            };
            let label = if balance_sats > 0 {
                "credit"
            } else if balance_sats < 0 {
                "debit"
            } else {
                "zero"
            };
            Ok(AddressSummary {
                balance_sats,
                total_paid_sats,
                current_window_shares: window_shares,
                current_window_percent: window_percent,
                balance_label: label,
            })
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/pplns/:address/history ──────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryQuery {
    /// Default 50, clamped at 200. Raw string so non-numeric values
    /// fall back to 50 instead of returning 400.
    limit: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    id: i32,
    block_height: i32,
    address: String,
    paid_sats: i64,
    #[serde(serialize_with = "crate::time_range::ser_f32_jsnum")]
    percent: f32,
    row_type: String,
    created_at: String,
}

async fn address_history(
    State(state): State<SharedState>,
    Path(address): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<JsonBytes, ApiError> {
    // No address-shape validation — malformed addresses return an empty list.
    let limit = q
        .limit
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let key = format!("PPLNS_ADDRESS_HISTORY_{}_{}", address, limit);
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<HistoryEntry>, _, ApiError>(
            key,
            TtlKind::PplnsAddressHistory,
            async move {
                let rows = sqlx::query!(
                    r#"SELECT id, "blockHeight" AS block_height, address, "paidSats" AS paid_sats, percent, "rowType" AS row_type, "createdAt" AS created_at
                       FROM pplns_payout_history
                       WHERE address = $1
                       ORDER BY "createdAt" DESC
                       LIMIT $2"#,
                    address,
                    limit
                )
                .fetch_all(&s.pool)
                .await
                .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?;

                Ok(rows
                    .into_iter()
                    .map(|r| HistoryEntry {
                        id: r.id,
                        block_height: r.block_height,
                        address: r.address,
                        paid_sats: r.paid_sats,
                        percent: r.percent,
                        row_type: r.row_type,
                        created_at: crate::time_range::format_iso_ms(r.created_at),
                    })
                    .collect())
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// `/api/pplns/chart` — dense, raw diff sum per slot, not rounded.
    #[test]
    fn chart_json_is_unchanged() {
        const S: i64 = 600_000;
        const T0: i64 = 1_700_000_400_000;
        let samples = vec![
            (T0, 1.5),
            (T0, 0.1_f32 as f64),
            (T0 + S + 123, 2.0),
            (T0 - S, 99.0),
            (T0 + 3 * S, 77.0),
        ];
        let points = chart_points(&[T0, T0 + S, T0 + 2 * S], samples);
        assert_eq!(
            serde_json::to_string(&points).unwrap(),
            r#"[{"label":"2023-11-14T22:20:00.000Z","data":1.6000000014901161},{"label":"2023-11-14T22:30:00.000Z","data":2},{"label":"2023-11-14T22:40:00.000Z","data":0}]"#
        );
    }

    /// The fees endpoint reports the live budget only while the autoscaler is on.
    #[tokio::test]
    async fn live_budget_is_read_only_while_the_autoscaler_is_on() {
        use redis::AsyncCommands;

        let Some(mut redis) =
            bp_test_support::connect_redis_in_range_or_skip(bp_test_support::redis_db::API, 0)
                .await
        else {
            return;
        };
        const CONFIG_BUDGET: u32 = 50_000;
        const LIVE_BUDGET: u32 = 123_456;
        bp_coinbase_snapshot::write_coinbase_budget(
            &mut redis,
            bp_coinbase_snapshot::PPLNS_COINBASE_BUDGET_KEY,
            LIVE_BUDGET,
        )
        .await
        .expect("seed live budget");

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1/unused")
            .expect("lazy pool");
        let mut state = AppState::new(pool, "0.0.0");
        state.redis = Some(redis.clone());

        state.pplns_budget_autoscaled = false;
        assert_eq!(
            live_pplns_budget(&state, CONFIG_BUDGET).await,
            CONFIG_BUDGET,
            "autoscaler off: a stored budget is stale and must be ignored"
        );

        state.pplns_budget_autoscaled = true;
        assert_eq!(
            live_pplns_budget(&state, CONFIG_BUDGET).await,
            LIVE_BUDGET,
            "autoscaler on: the live budget is the one in force"
        );

        let _: () = redis
            .del(bp_coinbase_snapshot::PPLNS_COINBASE_BUDGET_KEY)
            .await
            .expect("del");
        assert_eq!(
            live_pplns_budget(&state, CONFIG_BUDGET).await,
            CONFIG_BUDGET,
            "autoscaler on but nothing persisted yet: the config budget stands"
        );
    }

    #[test]
    fn history_entry_has_correct_shape() {
        // Pins the wire shape: no txid; rowType, id, address, percent present.
        let entry = HistoryEntry {
            id: 1,
            block_height: 800000,
            address: "bc1qtest".into(),
            paid_sats: 5000,
            percent: 0.5,
            row_type: "coinbase".into(),
            created_at: "2024-01-01T00:00:00.000Z".into(),
        };
        let v: Value = serde_json::to_value(&entry).unwrap();
        assert!(v.get("txid").is_none(), "txid must not be present");
        assert_eq!(v["rowType"], "coinbase");
        assert_eq!(v["blockHeight"], 800000);
        assert_eq!(v["paidSats"], 5000);
        assert_eq!(v["address"], "bc1qtest");
        assert!(v["createdAt"].is_string());
    }

    #[test]
    fn history_entry_created_at_is_iso_string() {
        let entry = HistoryEntry {
            id: 1,
            block_height: 800000,
            address: "bc1q".into(),
            paid_sats: 0,
            percent: 0.0,
            row_type: "pending".into(),
            created_at: crate::time_range::format_iso_ms(1_700_000_000_000),
        };
        let v: Value = serde_json::to_value(&entry).unwrap();
        let created_at = v["createdAt"].as_str().unwrap();
        assert!(created_at.contains('T'), "should be ISO-8601");
        assert!(created_at.ends_with('Z'), "should be UTC");
    }
}
