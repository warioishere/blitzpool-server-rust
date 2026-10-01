// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background expiry sweeps: invitations hourly past `expiresAt`, join
//! requests daily past `JOIN_REQUEST_PENDING_EXPIRY_DAYS`.

use std::time::Duration;

use bp_cron_utils::{Clock, SystemClock};
use bp_group_mgmt::constants::{JOIN_REQUEST_PENDING_EXPIRY_DAYS, MS_PER_DAY};
use sqlx::PgPool;
use tokio::sync::watch;
use tracing::{info, warn};

const HOURLY_TICK: Duration = Duration::from_secs(60 * 60);
const DAILY_TICK: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn the hourly invitation-expire sweep; sending `true` on the
/// returned sender stops it. The first tick fires only after one
/// interval, so spawning at process start does no immediate write.
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

/// Run the invitation-expire sweep once; returns the affected-row count.
pub async fn expire_invitations_once(pool: &PgPool) -> Result<u64, bp_db::DbError> {
    let now = SystemClock.now().timestamp_millis();
    bp_db::expire_pending_pplns_group_invitations(pool, now).await
}

/// Run the join-request-expire sweep once; returns the affected-row count.
pub async fn expire_join_requests_once(pool: &PgPool) -> Result<u64, bp_db::DbError> {
    let cutoff =
        SystemClock.now().timestamp_millis() - JOIN_REQUEST_PENDING_EXPIRY_DAYS as i64 * MS_PER_DAY;
    bp_db::expire_pending_pplns_group_join_requests(pool, cutoff).await
}
