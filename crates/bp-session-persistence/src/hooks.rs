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

/// Buffers every accepted share for the session's best (onto its row) and its
/// `client:live:*` hash (TTL, current difficulty, vardiff's hashrate, channel
/// count, freshest share), one write per session per flush.
#[derive(Clone)]
pub struct ClientRowTouchSink {
    buffer: Arc<TouchBuffer>,
}

impl ClientRowTouchSink {
    pub(crate) fn new(buffer: Arc<TouchBuffer>) -> Self {
        Self { buffer }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ClientRowTouchSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let key = TouchKeyRef {
            address: share.address,
            client_name: share.worker,
            session_id: share.session_id,
        };
        // `effective_difficulty` is the session's current vardiff target.
        self.buffer.record(
            key,
            share.submission_difficulty,
            Some(share.effective_difficulty as f32),
            share.hash_rate,
            share.channel_count as i32,
            // The front's accept time, not ours: a later stamp on a share that
            // arrives after the disconnect would make `kill_dead_clients`
            // revive a session that is already gone.
            share.ts_ms,
        );
    }
}
