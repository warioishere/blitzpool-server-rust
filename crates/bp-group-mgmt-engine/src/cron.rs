// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background expiry sweeps for invitations + join-requests.
//!
//! - Invitations: hourly tick, flips `pending → expired` past the
//!   row's `expiresAt`.
//! - Join requests: daily tick, flips `pending → expired` past 30
//!   days from `createdAt`.
//!
//! Both wrap the bp-db primitives + share the same shutdown handle
//! shape as the bp-notifications crons (`tokio::sync::watch<bool>`).

use std::time::Duration;

use bp_cron_utils::{Clock, SystemClock};
use bp_group_mgmt::constants::{JOIN_REQUEST_PENDING_EXPIRY_DAYS, MS_PER_DAY};
use sqlx::PgPool;
use tokio::sync::watch;
use tracing::{info, warn};

const HOURLY_TICK: Duration = Duration::from_secs(60 * 60);
const DAILY_TICK: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn the hourly invitation-expire sweep. Returns a shutdown
/// `watch::Sender<bool>` — sending `true` ends the loop on the next
/// tick. The first tick fires after `HOURLY_TICK` so the call site
/// can spawn this right after process start without an immediate
/// double-write race against the bp-db rows just seeded by tests.
pub fn spawn_invitation_expiry_cron<C: Clock + Send + Sync + 'static>(
    pool: PgPool,
    clock: C,
    startup_offset: Duration,
) -> watch::Sender<bool> {
    let (tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + HOURLY_TICK + startup_offset;
        let mut ticker = tokio::time::interval_at(start, HOURLY_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = rx.changed() => {
                    if *rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    let now = clock.now().timestamp_millis();
                    match bp_db::expire_pending_pplns_group_invitations(&pool, now).await {
                        Ok(0) => {},
                        Ok(n) => info!(target: "bp_group_mgmt_engine::cron",
                            count = n, "expired pending invitations"),
                        Err(e) => warn!(target: "bp_group_mgmt_engine::cron",
                            error = %e, "invitation-expire sweep failed"),
                    }
                }
            }
        }
    });
    tx
}

/// Spawn the daily join-request-expire sweep. Same shape as
/// [`spawn_invitation_expiry_cron`].
pub fn spawn_join_request_expiry_cron<C: Clock + Send + Sync + 'static>(
    pool: PgPool,
    clock: C,
    startup_offset: Duration,
) -> watch::Sender<bool> {
    let (tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + DAILY_TICK + startup_offset;
        let mut ticker = tokio::time::interval_at(start, DAILY_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = rx.changed() => {
                    if *rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    let cutoff = clock.now().timestamp_millis()
                        - JOIN_REQUEST_PENDING_EXPIRY_DAYS as i64 * MS_PER_DAY;
                    match bp_db::expire_pending_pplns_group_join_requests(&pool, cutoff).await {
                        Ok(0) => {},
                        Ok(n) => info!(target: "bp_group_mgmt_engine::cron",
                            count = n, "expired stale join requests"),
                        Err(e) => warn!(target: "bp_group_mgmt_engine::cron",
                            error = %e, "join-request-expire sweep failed"),
                    }
                }
            }
        }
    });
    tx
}

/// One-shot synchronous helper for tests + admin endpoints — runs the
/// invitation-expire sweep exactly once and returns the affected-row
/// count. Doesn't spawn a task.
pub async fn expire_invitations_once(pool: &PgPool) -> Result<u64, bp_db::DbError> {
    let now = SystemClock.now().timestamp_millis();
    bp_db::expire_pending_pplns_group_invitations(pool, now).await
}

/// One-shot synchronous helper for tests + admin endpoints — runs the
/// join-request-expire sweep exactly once and returns the affected-row
/// count.
pub async fn expire_join_requests_once(pool: &PgPool) -> Result<u64, bp_db::DbError> {
    let cutoff =
        SystemClock.now().timestamp_millis() - JOIN_REQUEST_PENDING_EXPIRY_DAYS as i64 * MS_PER_DAY;
    bp_db::expire_pending_pplns_group_join_requests(pool, cutoff).await
}
