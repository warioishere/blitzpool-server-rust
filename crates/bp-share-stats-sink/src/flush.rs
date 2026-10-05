// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coordinator-tick flush: drain each accumulator, upsert its table, confirm
//! on success. One flusher's PG error does not abort the tick; unconfirmed
//! deltas carry over to the next one.

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

/// One coordinator tick, sequenced per flusher so a failed table stays
/// unconfirmed while the others proceed.
pub async fn flush_once(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
    batch_size: usize,
    scope: FlushScope,
) {
    flush_pool_shares(pool, accs, health).await;
    flush_pool_mode_hashrate(pool, accs, health).await;
    flush_pool_rejected(pool, accs, health).await;
    flush_client_statistics(pool, accs, health, batch_size, scope).await;
    flush_address_settings(pool, accs, health).await;
    flush_worker_totals(pool, accs, health).await;
}

async fn flush_pool_shares(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.pool_shares.drain();
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
        Ok(_) => {
            accs.pool_shares.confirm(&snapshot);
            record_success(health, Flusher::PoolShares);
        }
        Err(e) => {
            warn!(error = %e, "pool_share_statistics flush failed");
            record_failure(health, Flusher::PoolShares);
        }
    }
}

async fn flush_pool_mode_hashrate(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.pool_mode_hashrate.drain();
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
        Ok(_) => {
            accs.pool_mode_hashrate.confirm(&snapshot);
            record_success(health, Flusher::PoolModeHashrate);
        }
        Err(e) => {
            warn!(error = %e, "pool_mode_hashrate flush failed");
            record_failure(health, Flusher::PoolModeHashrate);
        }
    }
}

async fn flush_pool_rejected(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.pool_rejected.drain();
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
        Ok(_) => {
            accs.pool_rejected.confirm(&snapshot);
            record_success(health, Flusher::PoolRejected);
        }
        Err(e) => {
            warn!(error = %e, "pool_rejected_statistics flush failed");
            record_failure(health, Flusher::PoolRejected);
        }
    }
}

async fn flush_client_statistics(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
    batch_size: usize,
    scope: FlushScope,
) {
    let mut snapshot = accs.client_statistics.drain();
    if let FlushScope::Before(current) = scope {
        snapshot.retain(|key, _| key.slot < current);
    }
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
            accepted_count: rec.accepted_count as i32,
            rejected_count: rec.rejected_count as i32,
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

    // Batch to stay under PG param-count caps. Confirm only the
    // successfully-flushed slice so a mid-batch failure retries cleanly.
    let mut confirmed_any_failure = false;
    let mut confirmed_keys: Vec<&bp_stats::ClientStatisticsKey> =
        Vec::with_capacity(snapshot.len());
    for (chunk, keys_chunk) in rows
        .chunks(batch_size)
        .zip(snapshot.keys().collect::<Vec<_>>().chunks(batch_size))
    {
        match bulk_upsert_client_statistics_entity(pool, chunk).await {
            Ok(_) => confirmed_keys.extend(keys_chunk.iter().copied()),
            Err(e) => {
                warn!(error = %e, batch_len = chunk.len(), "client_statistics batch failed");
                confirmed_any_failure = true;
            }
        }
    }
    if !confirmed_keys.is_empty() {
        let partial: bp_stats::ClientStatisticsSnapshot = confirmed_keys
            .iter()
            .map(|k| ((*k).clone(), snapshot.get(*k).cloned().unwrap_or_default()))
            .collect();
        accs.client_statistics.confirm(&partial);
    }
    if confirmed_any_failure {
        record_failure(health, Flusher::ClientStatistics);
    } else {
        record_success(health, Flusher::ClientStatistics);
    }
}

/// Folds share totals and best difficulty into one `address_settings_entity`
/// upsert per address; both accumulators are confirmed only on success.
async fn flush_address_settings(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let shares_snapshot = accs.share_totals.drain_addresses();
    let best_snapshot = accs.best_difficulty.drain();
    if shares_snapshot.is_empty() && best_snapshot.is_empty() {
        record_success(health, Flusher::AddressSettings);
        return;
    }

    // Union by address: the two drain/confirm cycles are independent, so an
    // address may appear on either side or both.
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
        Ok(_) => {
            accs.share_totals.confirm_addresses(&shares_snapshot);
            accs.best_difficulty.confirm(&best_snapshot);
            record_success(health, Flusher::AddressSettings);
        }
        Err(e) => {
            warn!(error = %e, "address_settings flush failed");
            record_failure(health, Flusher::AddressSettings);
        }
    }
}

/// Accepted and rejected deltas per worker in one upsert; both buffers are
/// confirmed only on success.
async fn flush_worker_totals(
    pool: &PgPool,
    accs: &Accumulators,
    health: &Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
) {
    let snapshot = accs.share_totals.drain_workers();
    let rejected = accs.share_totals.drain_workers_rejected();
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
        Ok(_) => {
            accs.share_totals.confirm_workers(&snapshot);
            accs.share_totals.confirm_workers_rejected(&rejected);
            record_success(health, Flusher::WorkerTotals);
        }
        Err(e) => {
            warn!(error = %e, "worker_shares_entity flush failed");
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
