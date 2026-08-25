// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook` trait implementations.
//!
//! Engines used to impl `bp_stratum_v1::hooks::{SessionPersistence,
//! AcceptedShareSink}` directly. The
//! session + per-share hook surfaces are decoupled from the wire
//! protocol via `bp-share-hook` so this single impl serves both
//! SV1 + SV2 servers.
//!
//! ## [`SessionPersistenceHook`]
//!
//! `bp_share_hook::SharedSessionPersistence` impl. Fires on every
//! authorize (register) and disconnect (deregister). Mode-blind. A
//! register writes NO statement — it only pends the session in the
//! `RowDebounce`; the row is born by the engine's birth flush once the
//! session has survived the debounce window, so probe connections that
//! authorize and hang up never reach Postgres at all. Deregister
//! soft-deletes only sessions that were actually born.

use bp_common::now_ms;
use std::sync::Arc;

use async_trait::async_trait;
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use sqlx::PgPool;
use tokio::time::Instant;
use tracing::warn;

use crate::diff_stat_buffer::{DiffStatBuffer, DiffStatKeyRef};
use crate::hashrate_sampler::HashrateSampler;
use crate::row_debounce::RowDebounce;
use crate::touch_buffer::{TouchBuffer, TouchKeyRef};

/// `SharedSessionPersistence` impl: pends the session for the debounced
/// row birth on register, soft-deletes born sessions on deregister.
/// Cheap to clone (two `Arc`s under the hood).
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
        // The authorize timestamp becomes the row's startTime/firstSeen
        // when (and if) the row is born — same value the synchronous
        // upsert used to stamp.
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
        // Only a born session owes the table a soft-delete; a probe's
        // teardown is a pure map removal and costs no statement.
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

/// `SharedAcceptedShareSink` impl that bumps the per-session
/// `client:live:*` hash on every accepted share — `updated_at_ms` and
/// the TTL (so the dead-session sweep doesn't reap it),
/// `best_difficulty` (max-merged), `current_difficulty` (latest vardiff
/// target), and `channel_count`. Without this, the live half of
/// `/api/client/:address` and the hashrate sums read zero for active
/// sessions.
///
/// Buffered: writes land in a shared `TouchBuffer` keyed by
/// `(address, clientName, sessionId)` and are flushed every 30s by the
/// engine's background task in one batched script. At ~250 shares/s on
/// a busy pool this collapses ~250 individual writes/s to
/// ≈ N_active_sessions per 30 s.
///
/// The same share also feeds the `HashrateSampler`, which owns the
/// `hash_rate` field: it accumulates the share's credited difficulty and
/// writes a self-zeroing 2-min moving average on its own 60 s cadence.
/// The touch buffer above deliberately does not write `hash_rate` — two
/// writers on one field would fight.
#[derive(Clone)]
pub struct ClientRowTouchSink {
    buffer: Arc<TouchBuffer>,
    sampler: Arc<HashrateSampler>,
}

impl ClientRowTouchSink {
    pub(crate) fn new(buffer: Arc<TouchBuffer>, sampler: Arc<HashrateSampler>) -> Self {
        Self { buffer, sampler }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ClientRowTouchSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let now_ms = now_ms();
        // Worker can be empty in some SV2 paths (no `.<name>` suffix in
        // user_identity); the SV2 session row was registered under the
        // same "default", so the fallback preserves the PK match. SV1
        // never sends an empty worker any more — its authorize parse
        // defaults a trailing dot to "worker" (letting "" through birthed
        // a row no touch could ever hit, and kill_dead_clients swept the
        // live session).
        let worker = if share.worker.is_empty() {
            "default"
        } else {
            share.worker
        };
        // Borrowed key — no heap allocation on the hot path. Both sinks
        // take it by value (it's `Copy`) and materialise an owned key only
        // when a session first appears in the current flush/sample window.
        let key = TouchKeyRef {
            address: share.address,
            client_name: worker,
            session_id: share.session_id,
        };
        // `effective_difficulty` is the vardiff target this share was
        // credited at = the difficulty currently assigned to the
        // session, so it keeps `current_difficulty` fresh as vardiff
        // ratchets (for both SV1 + SV2 — this sink is protocol-blind).
        self.buffer.record(
            key,
            share.submission_difficulty as f32,
            Some(share.effective_difficulty as f32),
            share.channel_count as i32,
            now_ms,
        );
        // Live hashrate: accumulate the same credited difficulty into the
        // sampler's current window. It owns the live hash's `hash_rate` and
        // writes a self-zeroing moving average — see [`HashrateSampler`].
        self.sampler.record(key, share.effective_difficulty);
    }
}

/// Length of one difficulty-statistics slot in ms (1 hour). Each
/// `(address, clientName, slotTime)` row records the maximum share
/// difficulty seen in that hour — the data behind the per-client
/// diff-scores chart.
const DIFF_STAT_SLOT_MS: i64 = 60 * 60 * 1000;

/// `SharedAcceptedShareSink` that records the per-`(address, worker,
/// hour-slot)` maximum share difficulty into
/// `client_difficulty_statistics_entity` (feeds `/api/client/:address/diff-scores`).
///
/// Coalesces in memory and writes in BATCHES: the share hot path merges the
/// per-slot max into `DiffStatBuffer`, and one flush loop upserts the whole
/// window in a single statement.
///
/// It used to upsert inline on every new max, which is cheap mid-slot and a
/// burst at the edges — after a restart and at every hour rollover, every
/// miner's first share is a new max and the next ones keep raising it. Measured
/// on prod 2026-08-05: 4.88 s for one of those single-row upserts, 2.5 minutes
/// after a payout restart.
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
        let now_ms = now_ms();
        let slot = (now_ms / DIFF_STAT_SLOT_MS) * DIFF_STAT_SLOT_MS;
        // Empty worker → "default", matching the PK convention the
        // client-row touch sink uses for the session row.
        let worker = if share.worker.is_empty() {
            "default"
        } else {
            share.worker
        };
        // Borrowed key: no allocation unless this is the slot's first share.
        // The buffer keeps the running max itself, so there is no second cache
        // to consult and nothing to await on the hot path.
        self.buffer.record(
            DiffStatKeyRef {
                address: share.address,
                worker,
                slot_ms: slot,
            },
            candidate as f32,
            now_ms,
        );
    }
}
