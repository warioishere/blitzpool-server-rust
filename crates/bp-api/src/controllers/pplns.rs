// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/pplns/*` — pure reader endpoints driven by
//! `PplnsEngine::reader()`.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Router,
};
use bp_common::AddressId;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::response_cache::{JsonBytes, TtlKind};
use crate::state::SharedState;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route("/api/pplns", get(root::<H, M>))
        .route("/api/pplns/mode/:address", get(mode::<H, M>))
        .route("/api/pplns/status", get(status::<H, M>))
        .route("/api/pplns/fees", get(fees::<H, M>))
        .route("/api/pplns/distribution", get(distribution::<H, M>))
        .route("/api/pplns/ledger", get(ledger::<H, M>))
        .route("/api/pplns/chart", get(chart::<H, M>))
        .route("/api/pplns/:address", get(address_summary::<H, M>))
        .route("/api/pplns/:address/history", get(address_history::<H, M>))
}

// ─── /api/pplns/chart ────────────────────────────────────────────
//
// Hashrate timeseries for the PPLNS mining mode, sourced from the
// `pool_mode_hashrate` table.

use crate::time_range::{aggregate_to_chart, chart_slot_boundaries, ChartPoint, Range};
use bp_common::MiningMode;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeQuery {
    range: Option<String>,
}

async fn chart<H, M>(
    State(state): State<SharedState<H, M>>,
    Query(q): Query<RangeQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let range = Range::parse(q.range.as_deref())?;
    let key = format!("PPLNS_CHART_{}", range.label());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<Vec<ChartPoint>, _, ApiError>(key, TtlKind::PplnsChart, async move {
            let now_ms = crate::time_range::now_ms();
            let since = now_ms - range.window_ms();
            let rows =
                bp_db::find_pool_mode_hashrate_since(&s.pool, MiningMode::Pplns, since).await?;
            let boundaries = chart_slot_boundaries(since, range.slot_size_ms());
            let samples = rows.iter().map(|r| (r.time, r.diff as f64));
            Ok(aggregate_to_chart(
                &boundaries,
                samples,
                range.slot_size_ms(),
            ))
        })
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── helpers ──────────────────────────────────────────────────────

fn require_pplns<H, M>(
    state: &SharedState<H, M>,
) -> Result<&bp_pplns_engine::engine::PplnsEngine, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
    total_shares: f64,
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
    /// String-as-number so existing UI can parse with parseInt.
    count: String,
    best_difficulty: Option<u64>,
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

async fn status<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn root<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn root_inner<H, M>(state: &SharedState<H, M>) -> Result<RootResponse, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let engine = require_pplns(state)?;
    let ws = engine.reader().window_stats().await?;
    let dist = engine.reader().current_distribution().await?;
    let addresses: Vec<String> = dist.into_iter().map(|a| a.address).collect();
    // Per-address user-agent aggregation.
    let user_agents = if addresses.is_empty() {
        Vec::new()
    } else {
        sqlx::query!(
            r#"SELECT
                "userAgent" AS user_agent,
                COUNT("userAgent")::bigint AS "count!",
                MAX("bestDifficulty") AS best_difficulty,
                SUM("hashRate") AS total_hash_rate
               FROM client_entity
               WHERE address = ANY($1)
               GROUP BY "userAgent"
               ORDER BY COUNT("userAgent") DESC"#,
            &addresses as &[String]
        )
        .fetch_all(&state.pool)
        .await
        .map_err(|e| ApiError::Db(bp_db::DbError::Sqlx(e)))?
        .into_iter()
        .map(|r| UserAgentEntry {
            user_agent: r.user_agent,
            count: r.count.to_string(),
            best_difficulty: r.best_difficulty.map(|d| d.floor() as u64),
            total_hash_rate: r.total_hash_rate,
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

async fn mode<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let addr = AddressId::new(address.clone()).map_err(|_| ApiError::InvalidAddress)?;
    let key = format!("PPLNS_MODE_{}", addr.as_str());
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<ModeResponse, _, ApiError>(key, TtlKind::PplnsMode, async move {
            // Live port-marker wins — 5-min TTL key written by stratum on every
            // accepted share. Reflects the actual port in use right now.
            if let Some(mut redis) = s.redis.clone() {
                let marker_key = format!("miner:{}:mode", addr.as_str());
                if let Ok(Some(raw)) = redis.get::<_, Option<String>>(&marker_key).await {
                    match raw.as_str() {
                        "solo" => {
                            return Ok(ModeResponse {
                                mode: "solo",
                                group_id: None,
                            })
                        }
                        "pplns" => {
                            return Ok(ModeResponse {
                                mode: "pplns",
                                group_id: None,
                            })
                        }
                        "blockparty" => {
                            if let Some(bp) = s.blockparty.as_ref() {
                                if let Some(gid) = bp.routable_group_id_for_admin(&addr).await {
                                    return Ok(ModeResponse {
                                        mode: "blockparty",
                                        group_id: Some(gid.to_string()),
                                    });
                                }
                            }
                            // Group dissolved between mark and read — fall through.
                        }
                        "group-solo" => {
                            if let Some(member) =
                                bp_db::find_group_member_by_address(&s.pool, &addr).await?
                            {
                                return Ok(ModeResponse {
                                    mode: "group-solo",
                                    group_id: Some(member.group_id.to_string()),
                                });
                            }
                            // Group dissolved between mark and read — fall through.
                        }
                        _ => {}
                    }
                }
            }

            // Steps 2-5: state-based fallback (no live marker or marker expired).
            if let Some(member) = bp_db::find_group_member_by_address(&s.pool, &addr).await? {
                return Ok(ModeResponse {
                    mode: "group-solo",
                    group_id: Some(member.group_id.to_string()),
                });
            }
            if let Some(bp) = s.blockparty.as_ref() {
                if let Some(group_id) = bp.routable_group_id_for_admin(&addr).await {
                    return Ok(ModeResponse {
                        mode: "blockparty",
                        group_id: Some(group_id.to_string()),
                    });
                }
            }
            if let Some(engine) = s.pplns.as_ref() {
                if let Ok(Some(status)) = engine.reader().address_status(&address).await {
                    if status.current_window_shares > 0.0 {
                        return Ok(ModeResponse {
                            mode: "pplns",
                            group_id: None,
                        });
                    }
                }
            }
            Ok(ModeResponse {
                mode: "solo",
                group_id: None,
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
    fee_percent: f64,
    fee_address: Option<String>,
    coinbase_weight_budget: u32,
    /// Shared `[group_fees]` lane percent (Group-Solo + Blockparty).
    /// Falls back to the PPLNS `fee_percent` when no group fee is wired.
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
    warmup_shares: u32,
}

async fn fees<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    use bp_pplns_engine::{
        COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT,
        DUST_LIMIT_SATS,
    };
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<FeesResponse, _, ApiError>(
            "PPLNS_FEES".to_string(),
            TtlKind::PplnsFees,
            async move {
                let engine = require_pplns(&s)?;
                let cfg = engine.reader().fee_config();
                let raw_cfg = engine.config();
                // Pessimistic worst-case: every output is a P2TR (172 WU).
                let usable_wu = cfg
                    .coinbase_weight_budget
                    .saturating_sub(COINBASE_BASE_WEIGHT + COINBASE_WITNESS_COMMITMENT_WEIGHT);
                let max_miner_outputs = usable_wu / COINBASE_OUTPUT_WEIGHT;
                // Adaptive count uses the same pessimistic bound until we
                // plumb a per-address-type mixed-weight estimate through
                // the engine; correct for current address-type populations.
                let max_miner_outputs_adaptive = max_miner_outputs;
                // Shared group-fee lane — reuses the resolved values
                // the Blockparty service was constructed with (same
                // chain `[group_fees]` → `[pplns]`). When Blockparty
                // isn't wired (e.g. PPLNS-only deployment) the fields
                // mirror the PPLNS lane.
                let (group_fee_percent, group_fee_address) = match s.blockparty.as_ref() {
                    Some(bp) => (
                        bp.pool_fee_percent(),
                        bp.fee_address().map(|a| a.into_inner()),
                    ),
                    None => (cfg.fee_percent, cfg.fee_address.clone()),
                };
                Ok(FeesResponse {
                    fee_percent: cfg.fee_percent,
                    fee_address: cfg.fee_address,
                    coinbase_weight_budget: cfg.coinbase_weight_budget,
                    group_fee_percent,
                    group_fee_address,
                    dust_limit_sats: DUST_LIMIT_SATS,
                    min_payout_sats: cfg.min_payout_sats,
                    coinbase_base_weight: COINBASE_BASE_WEIGHT,
                    coinbase_output_weight: COINBASE_OUTPUT_WEIGHT,
                    coinbase_witness_commitment_weight: COINBASE_WITNESS_COMMITMENT_WEIGHT,
                    max_miner_outputs,
                    max_miner_outputs_adaptive,
                    min_difficulty: raw_cfg.min_difficulty,
                    warmup_shares: raw_cfg.warmup_shares,
                })
            },
        )
        .await?;
    Ok(JsonBytes(bytes))
}

// ─── /api/pplns/distribution ──────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DistributionEntry {
    address: String,
    total_shares: f64,
    percent: f64,
}

async fn distribution<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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

async fn ledger<H, M>(State(state): State<SharedState<H, M>>) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
    current_window_shares: f64,
    current_window_percent: f64,
    balance_label: &'static str,
}

async fn address_summary<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let key = format!("PPLNS_ADDRESS_{address}");
    let s = state.clone();
    let bytes = state
        .cache
        .get_or_fetch::<AddressSummary, _, ApiError>(key, TtlKind::PplnsAddress, async move {
            let status = require_pplns(&s)?
                .reader()
                .address_status(&address)
                .await?
                .ok_or(ApiError::NotFound)?;
            let label = if status.balance_sats > 0 {
                "credit"
            } else if status.balance_sats < 0 {
                "debit"
            } else {
                "zero"
            };
            Ok(AddressSummary {
                balance_sats: status.balance_sats,
                total_paid_sats: status.total_paid_sats,
                current_window_shares: status.current_window_shares,
                current_window_percent: status.current_window_percent,
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
    percent: f32,
    row_type: String,
    created_at: String,
}

async fn address_history<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Result<JsonBytes, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
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
                        created_at: crate::time_range::format_slot_label(r.created_at),
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

    #[test]
    fn history_entry_has_correct_shape() {
        // Regression: old code selected non-existent txid column; was missing rowType, id, address, percent.
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
