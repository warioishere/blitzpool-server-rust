// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coordinator-tick flush: take each accumulator's due part, upsert its
//! table, hand it back on failure. One flusher's PG error does not abort the
//! tick; the handed-back deltas go out with the next one.

use std::collections::HashMap;
use std::sync::Arc;

use bp_db::{
    bulk_upsert_address_settings, bulk_upsert_client_statistics_entity,
    bulk_upsert_pool_mode_hashrate, bulk_upsert_pool_rejected_statistics,
    bulk_upsert_pool_share_statistics, bulk_upsert_worker_shares_entity, AddressSettingsUpsert,
    ClientStatsUpsert, PoolModeHashrateUpsert, PoolRejectedStatsUpsert, PoolShareStatsUpsert,
    WorkerSharesUpsert,
};
use bp_stats::{
    BestDifficultyAccumulator, ClientStatisticsAccumulator, FlushHealthMonitor,
    PoolModeHashrateAccumulator, PoolRejectedAccumulator, PoolSharesAccumulator,
    ShareTotalsAccumulator, TimeSlot,
};
use sqlx::PgPool;
use tracing::warn;

/// Flush-path key in [`FlushHealthMonitor`], so a sustained per-table outage
/// warns once per flusher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flusher {
    PoolShares,
    PoolModeHashrate,
    PoolRejected,
    ClientStatistics,
    AddressSettings,
    WorkerTotals,
}

/// The accumulators, shared with the hook impls on the share path.
pub struct Accumulators {
    pub pool_shares: PoolSharesAccumulator,
    pub pool_mode_hashrate: PoolModeHashrateAccumulator,
    pub pool_rejected: PoolRejectedAccumulator,
    pub client_statistics: ClientStatisticsAccumulator,
    pub share_totals: ShareTotalsAccumulator,
    pub best_difficulty: BestDifficultyAccumulator,
}

impl Default for Accumulators {
    fn default() -> Self {
        Self {
            pool_shares: PoolSharesAccumulator::new(),
            pool_mode_hashrate: PoolModeHashrateAccumulator::new(),
            pool_rejected: PoolRejectedAccumulator::new(),
            client_statistics: ClientStatisticsAccumulator::new(),
            share_totals: ShareTotalsAccumulator::new(),
            best_difficulty: BestDifficultyAccumulator::new(),
        }
    }
}

/// Which `client_statistics_entity` slots a flush writes. Every chart hides
/// the slot in progress, so a tick writes each slot once, after it ended;
/// the shutdown drain writes the open slot too, and the next process adds
/// onto that row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushScope {
    /// Only slots ending at or before this one's start.
    Before(TimeSlot),
    All,
}

/// One coordinator tick, sequenced per flusher. Each takes what is due and
/// hands it back on a failed write, so one table's outage leaves the others
/// flowing and loses nothing.
pub async fn flush_once(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
    scope: FlushScope,
) {
    flush_pool_shares(pool, accs, health).await;
    flush_pool_mode_hashrate(pool, accs, health).await;
    flush_pool_rejected(pool, accs, health).await;
    flush_client_statistics(pool, accs, health, scope).await;
    flush_address_settings(pool, accs, health).await;
    flush_worker_totals(pool, accs, health).await;
}

async fn flush_pool_shares(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.pool_shares.take();
    if snapshot.is_empty() {
        record_success(health, Flusher::PoolShares);
        return;
    }
    let rows: Vec<PoolShareStatsUpsert> = snapshot
        .iter()
        .map(|(slot, rec)| PoolShareStatsUpsert {
            time_ms: slot.as_millis(),
            accepted: rec.accepted as f32,
            rejected: rec.rejected as f32,
            max_difficulty: rec.max_difficulty as f32,
        })
        .collect();
    match bulk_upsert_pool_share_statistics(pool, &rows).await {
        Ok(_) => record_success(health, Flusher::PoolShares),
        Err(e) => {
            warn!(error = %e, "pool_share_statistics flush failed");
            accs.pool_shares.restore(snapshot);
            record_failure(health, Flusher::PoolShares);
        }
    }
}

async fn flush_pool_mode_hashrate(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.pool_mode_hashrate.take();
    if snapshot.is_empty() {
        record_success(health, Flusher::PoolModeHashrate);
        return;
    }
    let mut rows: Vec<PoolModeHashrateUpsert> = Vec::new();
    for (slot, modes) in &snapshot {
        for (mode, diff) in modes {
            rows.push(PoolModeHashrateUpsert {
                mode: mode.as_str().to_string(),
                time_ms: slot.as_millis(),
                diff: *diff as f32,
            });
        }
    }
    match bulk_upsert_pool_mode_hashrate(pool, &rows).await {
        Ok(_) => record_success(health, Flusher::PoolModeHashrate),
        Err(e) => {
            warn!(error = %e, "pool_mode_hashrate flush failed");
            accs.pool_mode_hashrate.restore(snapshot);
            record_failure(health, Flusher::PoolModeHashrate);
        }
    }
}

async fn flush_pool_rejected(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.pool_rejected.take();
    if snapshot.is_empty() {
        record_success(health, Flusher::PoolRejected);
        return;
    }
    let mut rows: Vec<PoolRejectedStatsUpsert> = Vec::new();
    for (slot, reasons) in &snapshot {
        for (reason, count) in reasons {
            rows.push(PoolRejectedStatsUpsert {
                time_ms: slot.as_millis(),
                reason: reason.as_str().to_string(),
                count: *count as f32,
            });
        }
    }
    match bulk_upsert_pool_rejected_statistics(pool, &rows).await {
        Ok(_) => record_success(health, Flusher::PoolRejected),
        Err(e) => {
            warn!(error = %e, "pool_rejected_statistics flush failed");
            accs.pool_rejected.restore(snapshot);
            record_failure(health, Flusher::PoolRejected);
        }
    }
}

async fn flush_client_statistics(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
    scope: FlushScope,
) {
    let snapshot = match scope {
        FlushScope::Before(current) => accs.client_statistics.take_before(current),
        FlushScope::All => accs.client_statistics.take(),
    };
    if snapshot.is_empty() {
        record_success(health, Flusher::ClientStatistics);
        return;
    }
    let rows: Vec<ClientStatsUpsert> = snapshot
        .iter()
        .map(|(key, rec)| ClientStatsUpsert {
            address: key.address.as_str().to_string(),
            client_name: key.client_name.clone(),
            session_id: key.session_id.clone(),
            time_ms: key.slot.as_millis(),
            shares: rec.shares as f32,
            rejected_job_not_found_count: rec.rejected_job_not_found_count as i32,
            rejected_job_not_found_diff1: rec.rejected_job_not_found_diff1 as f32,
            rejected_duplicate_share_count: rec.rejected_duplicate_share_count as i32,
            rejected_duplicate_share_diff1: rec.rejected_duplicate_share_diff1 as f32,
            rejected_low_difficulty_share_count: rec.rejected_low_difficulty_share_count as i32,
            rejected_low_difficulty_share_diff1: rec.rejected_low_difficulty_share_diff1 as f32,
            rejected_version_rolling_count: rec.rejected_version_rolling_count as i32,
            rejected_version_rolling_diff1: rec.rejected_version_rolling_diff1 as f32,
            rejected_stale_count: rec.rejected_stale_count as i32,
            rejected_stale_diff1: rec.rejected_stale_diff1 as f32,
            max_difficulty: rec.max_difficulty as f32,
        })
        .collect();
    // One statement: the columns travel as arrays, so the row count does not
    // add bind parameters.
    match bulk_upsert_client_statistics_entity(pool, &rows).await {
        Ok(_) => record_success(health, Flusher::ClientStatistics),
        Err(e) => {
            warn!(error = %e, rows = rows.len(), "client_statistics flush failed");
            accs.client_statistics.restore(snapshot);
            record_failure(health, Flusher::ClientStatistics);
        }
    }
}

/// Folds share totals and best difficulty into one `address_settings_entity`
/// upsert per address; a failed write hands both back.
async fn flush_address_settings(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let shares_snapshot = accs.share_totals.take_addresses();
    let best_snapshot = accs.best_difficulty.take();
    if shares_snapshot.is_empty() && best_snapshot.is_empty() {
        record_success(health, Flusher::AddressSettings);
        return;
    }

    // Union by address: an address may appear on either side or both.
    let mut merged: HashMap<String, (f64, f64, Option<String>)> = HashMap::new();
    for (addr, delta) in &shares_snapshot {
        merged.insert(addr.as_str().to_string(), (*delta, 0.0, None));
    }
    for (addr, entry) in &best_snapshot {
        merged
            .entry(addr.as_str().to_string())
            .and_modify(|(_, bd, ua)| {
                *bd = entry.best_difficulty;
                *ua = entry.user_agent.clone();
            })
            .or_insert((0.0, entry.best_difficulty, entry.user_agent.clone()));
    }

    let rows: Vec<AddressSettingsUpsert> = merged
        .into_iter()
        .map(
            |(address, (delta_shares, best_difficulty, user_agent))| AddressSettingsUpsert {
                address,
                delta_shares,
                best_difficulty,
                user_agent,
            },
        )
        .collect();

    match bulk_upsert_address_settings(pool, &rows).await {
        Ok(_) => record_success(health, Flusher::AddressSettings),
        Err(e) => {
            warn!(error = %e, "address_settings flush failed");
            accs.share_totals.restore_addresses(shares_snapshot);
            accs.best_difficulty.restore(best_snapshot);
            record_failure(health, Flusher::AddressSettings);
        }
    }
}

/// Accepted and rejected deltas per worker in one upsert; a failed write
/// hands both back.
async fn flush_worker_totals(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.share_totals.take_workers();
    let rejected = accs.share_totals.take_workers_rejected();
    if snapshot.is_empty() && rejected.is_empty() {
        record_success(health, Flusher::WorkerTotals);
        return;
    }
    // A worker with only rejected shares still gets an upsert so its row exists.
    let mut merged: HashMap<(String, String), (f64, f64)> = HashMap::new();
    for (key, delta) in &snapshot {
        merged
            .entry((key.address.as_str().to_string(), key.client_name.clone()))
            .or_default()
            .0 += *delta;
    }
    for (key, delta) in &rejected {
        merged
            .entry((key.address.as_str().to_string(), key.client_name.clone()))
            .or_default()
            .1 += *delta;
    }

    let rows: Vec<WorkerSharesUpsert> = merged
        .into_iter()
        .map(
            |((address, client_name), (delta_shares, delta_rejected_shares))| WorkerSharesUpsert {
                address,
                client_name,
                delta_shares,
                delta_rejected_shares,
            },
        )
        .collect();
    match bulk_upsert_worker_shares_entity(pool, &rows).await {
        Ok(_) => record_success(health, Flusher::WorkerTotals),
        Err(e) => {
            warn!(error = %e, "worker_shares_entity flush failed");
            accs.share_totals.restore_workers(snapshot);
            accs.share_totals.restore_workers_rejected(rejected);
            record_failure(health, Flusher::WorkerTotals);
        }
    }
}

fn record_success(health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>, flusher: Flusher) {
    health
        .lock()
        .expect("flush health monitor poisoned")
        .record_success(flusher);
}

fn record_failure(health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>, flusher: Flusher) {
    let outcome = health
        .lock()
        .expect("flush health monitor poisoned")
        .record_failure(flusher);
    if matches!(outcome, bp_stats::FlushHealth::JustCrossedThreshold { .. }) {
        warn!(
            flusher = ?flusher,
            "flush failure threshold crossed — sustained backlog building"
        );
    }
}
