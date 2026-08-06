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
//! [`RowDebounce`]; the row is born by the engine's birth flush once the
//! session has survived the debounce window, so probe connections that
//! authorize and hang up never reach Postgres at all. Deregister
//! soft-deletes only sessions that were actually born.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
/// `client_entity` row on every accepted share — `updatedAt` (so
/// `kill_dead_clients` doesn't sweep), `firstSeen` (COALESCE safety
/// net in case the register INSERT raced), `bestDifficulty` (GREATEST),
/// `currentDifficulty` (latest vardiff target), and `channelCount`.
/// Without this, the `/api/info/workers`, `/api/info`, and
/// `/api/client/:address` endpoints all return zero for active sessions.
///
/// Buffered: writes land in a shared [`TouchBuffer`] keyed by
/// `(address, clientName, sessionId)` and are flushed every 30s by the
/// engine's background task in one bulk UPDATE statement. At ~250
/// shares/s on a busy pool this collapses ~250 individual DB UPDATEs/s
/// to ≈ N_active_sessions per 30 s.
///
/// The same share also feeds the [`HashrateSampler`], which owns the
/// `hashRate` column: it accumulates the share's credited difficulty and
/// writes a self-zeroing 2-min moving average on its own 60 s cadence.
/// The touch buffer above deliberately does not write `hashRate` — two
/// writers on one column would fight.
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
        // user_identity). The session row was registered with the
        // matching default ("default" in SV2, "" in SV1), so use the
        // same fallback here for the PK match.
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
        // session, so it keeps `currentDifficulty` fresh as vardiff
        // ratchets (for both SV1 + SV2 — this sink is protocol-blind).
        self.buffer.record(
            key,
            share.submission_difficulty as f32,
            Some(share.effective_difficulty as f32),
            share.channel_count as i32,
            now_ms,
        );
        // Live hashrate: accumulate the same credited difficulty into the
        // sampler's current window. It owns `client_entity.hashRate` and
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
/// per-slot max into [`DiffStatBuffer`], and one flush loop upserts the whole
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

/// Wall-clock milliseconds since the Unix epoch — the stamp for
/// `startTime`/`updatedAt`-family columns. `0` on a pre-1970 clock,
/// matching what the synchronous register path always did.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
