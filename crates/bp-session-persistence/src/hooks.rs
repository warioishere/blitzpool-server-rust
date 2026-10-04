// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook` trait implementations, protocol-blind so one impl serves
//! both the SV1 and SV2 servers.

use bp_common::now_ms;
use std::sync::Arc;

use async_trait::async_trait;
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use sqlx::PgPool;
use tokio::time::Instant;
use tracing::warn;

use crate::diff_stat_buffer::{DiffStatBuffer, DiffStatKeyRef};
use crate::hashrate_watchdog::HashrateWatchdog;
use crate::row_debounce::RowDebounce;
use crate::touch_buffer::{TouchBuffer, TouchKeyRef};

/// `SharedSessionPersistence` impl: pends the session for the debounced
/// row birth on register (no statement), soft-deletes born sessions on
/// deregister.
#[derive(Clone)]
pub struct SessionPersistenceHook {
    pool: PgPool,
    debounce: Arc<RowDebounce>,
}

impl SessionPersistenceHook {
    pub(crate) fn new(pool: PgPool, debounce: Arc<RowDebounce>) -> Self {
        Self { pool, debounce }
    }
}

#[async_trait]
impl SharedSessionPersistence for SessionPersistenceHook {
    async fn register_session(
        &self,
        session_id: &str,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
    ) {
        self.debounce.register(
            address,
            worker,
            session_id,
            user_agent,
            now_ms(),
            Instant::now(),
        );
    }

    async fn deregister_session(&self, session_id: &str) {
        // Only a born session owes the table a soft-delete.
        if !self.debounce.deregister(session_id) {
            return;
        }
        if let Err(e) = bp_db::delete_client_for_session(&self.pool, session_id).await {
            warn!(
                error = %e,
                session_id,
                "SessionPersistenceHook: soft-delete on deregister failed"
            );
        }
    }
}

/// Bumps the session's `client:live:*` hash (TTL, best/current difficulty,
/// vardiff's hashrate, channel count) on every accepted share, buffered to
/// one write per session per flush, and tells the watchdog the session is
/// still sending.
#[derive(Clone)]
pub struct ClientRowTouchSink {
    buffer: Arc<TouchBuffer>,
    watchdog: Arc<HashrateWatchdog>,
}

impl ClientRowTouchSink {
    pub(crate) fn new(buffer: Arc<TouchBuffer>, watchdog: Arc<HashrateWatchdog>) -> Self {
        Self { buffer, watchdog }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ClientRowTouchSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // An SV2 user_identity without `.<name>` gives an empty worker; the
        // session row was registered as "default", so this keeps the PK match.
        let worker = if share.worker.is_empty() {
            "default"
        } else {
            share.worker
        };
        let key = TouchKeyRef {
            address: share.address,
            client_name: worker,
            session_id: share.session_id,
        };
        // `effective_difficulty` is the session's current vardiff target.
        self.buffer.record(
            key,
            share.submission_difficulty as f32,
            Some(share.effective_difficulty as f32),
            share.hash_rate,
            share.channel_count as i32,
            // The front's accept time, not ours: a later stamp on a share that
            // arrives after the disconnect would make `kill_dead_clients`
            // revive a session that is already gone.
            share.ts_ms,
        );
        self.watchdog.record(key, Instant::now());
    }
}

/// One difficulty-statistics slot (1 hour) in ms.
const DIFF_STAT_SLOT_MS: i64 = 60 * 60 * 1000;

/// Records the per-`(address, worker, hour-slot)` max share difficulty into
/// `client_difficulty_statistics_entity`, batched: an inline upsert per new
/// max would burst after a restart and at every hour rollover.
#[derive(Clone)]
pub struct ClientDifficultyStatisticsSink {
    buffer: Arc<DiffStatBuffer>,
}

impl ClientDifficultyStatisticsSink {
    pub(crate) fn new(buffer: Arc<DiffStatBuffer>) -> Self {
        Self { buffer }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ClientDifficultyStatisticsSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let candidate = share.submission_difficulty;
        if !candidate.is_finite() || candidate <= 0.0 {
            return;
        }
        // The hour the share was accepted in, not the hour it was consumed in.
        let slot = (share.ts_ms / DIFF_STAT_SLOT_MS) * DIFF_STAT_SLOT_MS;
        // Same "default" PK convention as the client-row touch sink.
        let worker = if share.worker.is_empty() {
            "default"
        } else {
            share.worker
        };
        self.buffer.record(
            DiffStatKeyRef {
                address: share.address,
                worker,
                slot_ms: slot,
            },
            candidate as f32,
            share.ts_ms,
        );
    }
}
