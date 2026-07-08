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
//! authorize (register) and disconnect (deregister). Mode-blind —
//! every session gets a `client_entity` row, stamped with the miner's
//! `user_agent` from the register call.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type DiffSlotCache = Arc<Mutex<HashMap<(String, String), (i64, f64)>>>;

use async_trait::async_trait;
use bp_db::upsert_client_difficulty_statistic;
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use sqlx::PgPool;
use tracing::warn;

use crate::client_row::{deregister_client, register_client};
use crate::hashrate_sampler::HashrateSampler;
use crate::touch_buffer::{TouchBuffer, TouchKeyRef};

/// `SharedSessionPersistence` impl that persists the `client_entity`
/// row on register + soft-deletes it on deregister. Cheap to clone
/// (single `Arc<PgPool>`).
#[derive(Clone)]
pub struct SessionPersistenceHook {
    pool: PgPool,
}

impl SessionPersistenceHook {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
        if let Err(e) = register_client(
            &self.pool, address, worker, session_id, user_agent, None, None,
        )
        .await
        {
            warn!(
                error = %e,
                session_id, address, worker,
                "SessionPersistenceHook: register_client failed"
            );
        }
    }

    async fn deregister_session(&self, session_id: &str) {
        if let Err(e) = deregister_client(&self.pool, session_id).await {
            warn!(
                error = %e,
                session_id,
                "SessionPersistenceHook: deregister_client failed"
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
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
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
/// Coalesces in memory: the per-slot max is monotonic, so a PG upsert
/// fires only when a share sets a NEW max for its current hour-slot —
/// rare after a slot's first minutes, so the share hot-path stays cheap.
/// The cache holds one entry per `(address, worker)`; the entry is
/// overwritten when the hour rolls over, so it stays bounded by the
/// active-miner count.
#[derive(Clone)]
pub struct ClientDifficultyStatisticsSink {
    pool: PgPool,
    // (address, worker) -> (slot_time_ms, max_difficulty_seen_in_slot)
    seen: DiffSlotCache,
}

impl ClientDifficultyStatisticsSink {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ClientDifficultyStatisticsSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let candidate = share.submission_difficulty;
        if !candidate.is_finite() || candidate <= 0.0 {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let slot = (now_ms / DIFF_STAT_SLOT_MS) * DIFF_STAT_SLOT_MS;
        // Empty worker → "default", matching the PK convention the
        // client-row touch sink uses for the session row.
        let worker = if share.worker.is_empty() {
            "default"
        } else {
            share.worker
        };
        let key = (share.address.to_string(), worker.to_string());

        // Decide under the lock whether this share sets a new per-slot max;
        // update the cache and capture the value to persist. No await while
        // the lock is held.
        let new_max = {
            let mut seen = self.seen.lock().expect("diff-stat seen mutex poisoned");
            match seen.get(&key).copied() {
                Some((s, m)) if s == slot => {
                    if candidate > m {
                        seen.insert(key.clone(), (slot, candidate));
                        Some(candidate)
                    } else {
                        None
                    }
                }
                // New miner, or the hour-slot rolled over → first share of
                // the slot is its max so far.
                _ => {
                    seen.insert(key.clone(), (slot, candidate));
                    Some(candidate)
                }
            }
        };
        let Some(max_difficulty) = new_max else {
            return;
        };

        if let Err(e) = upsert_client_difficulty_statistic(
            &self.pool,
            share.address,
            worker,
            slot,
            max_difficulty as f32,
            now_ms,
        )
        .await
        {
            warn!(
                error = %e,
                address = share.address,
                worker,
                slot,
                "ClientDifficultyStatisticsSink: upsert failed"
            );
        }
    }
}
