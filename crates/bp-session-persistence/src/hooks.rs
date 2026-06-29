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
//!
//! ## [`BestDifficultySink`]
//!
//! `bp_share_hook::SharedAcceptedShareSink` impl. On every accepted
//! share, checks the cached `bestDifficulty` and (if the candidate
//! exceeds it) writes through to PG + cache, stamping the share's
//! `user_agent` onto the all-time best-difficulty row.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type DiffSlotCache = Arc<Mutex<HashMap<(String, String), (i64, f64)>>>;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_db::{
    find_address_settings, upsert_address_best_difficulty, upsert_client_difficulty_statistic,
};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink, SharedSessionPersistence};
use sqlx::PgPool;
use tracing::warn;

use crate::address_settings_cache::{AddressSettingsCache, CachedAddressSettings};
use crate::client_row::{deregister_client, register_client};
use crate::touch_buffer::{TouchBuffer, TouchKey};

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
/// `currentDifficulty` (latest vardiff target), and `hashRate` (latest
/// non-zero sample). Without this, the `/api/info/workers`, `/api/info`,
/// and `/api/client/:address` endpoints all return zero for active
/// sessions.
///
/// Buffered: writes land in a shared [`TouchBuffer`] keyed by
/// `(address, clientName, sessionId)` and are flushed every 30s by the
/// engine's background task in one bulk UPDATE statement. At ~250
/// shares/s on a busy pool this collapses ~250 individual DB UPDATEs/s
/// to ≈ N_active_sessions per 30 s.
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
        // Skip writing hashRate when the vardiff engine hasn't
        // produced a non-zero sample yet (very first shares of a
        // session); `None` means COALESCE keeps the existing value.
        let hash_rate = if share.hash_rate > 0.0 {
            Some(share.hash_rate)
        } else {
            None
        };
        let key = TouchKey {
            address: share.address.to_string(),
            client_name: worker.to_string(),
            session_id: share.session_id.to_string(),
        };
        // `effective_difficulty` is the vardiff target this share was
        // credited at = the difficulty currently assigned to the
        // session, so it keeps `currentDifficulty` fresh as vardiff
        // ratchets (for both SV1 + SV2 — this sink is protocol-blind).
        self.buffer
            .record(
                key,
                share.submission_difficulty as f32,
                Some(share.effective_difficulty as f32),
                hash_rate,
                share.channel_count as i32,
                now_ms,
            )
            .await;
    }
}

/// `SharedAcceptedShareSink` impl that tracks per-address best
/// difficulty. Generic over the cache impl so tests can swap in
/// the in-memory variant; production will plug
/// [`crate::address_settings_cache::InMemoryAddressSettingsCache`].
pub struct BestDifficultySink<C: AddressSettingsCache> {
    pool: PgPool,
    cache: Arc<C>,
}

impl<C: AddressSettingsCache> BestDifficultySink<C> {
    pub fn new(pool: PgPool, cache: Arc<C>) -> Self {
        Self { pool, cache }
    }
}

#[async_trait]
impl<C: AddressSettingsCache> SharedAcceptedShareSink for BestDifficultySink<C> {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let address = share.address;
        let candidate = share.submission_difficulty;
        if !candidate.is_finite() || candidate <= 0.0 {
            return;
        }

        // Cache-read + cold-warm-on-miss: after a pool restart the cache
        // is empty. Without this read-through path, EVERY share with
        // candidate ≤ existing PG best would pay a PG round-trip until
        // a new best happens to bump the cache. Read PG once per
        // first-touch address, warm the cache, then run the predicate.
        let cached = match self.cache.get(address).await {
            Some(c) => c,
            None => {
                // Cache miss → cold-load from PG. The address may not
                // have a row yet (very first share ever) — fall back to
                // a zero baseline so the upsert below still fires the
                // INSERT path.
                let baseline = match warm_cache_from_pg(&self.pool, &self.cache, address).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            error = %e,
                            address,
                            "BestDifficultySink: cache cold-warm read failed; proceeding without cache"
                        );
                        // On read failure, optimistically try the
                        // upsert — the WHERE clause guards correctness.
                        CachedAddressSettings {
                            best_difficulty: 0.0,
                            best_difficulty_user_agent: None,
                        }
                    }
                };
                baseline
            }
        };
        if !cached.should_update(candidate) {
            return;
        }

        // PG compare-and-set: only commits when the candidate strictly
        // exceeds the stored value. Stamp the miner's firmware/vendor
        // string (threaded from the stratum accept path) so the all-time
        // best-difficulty row records which hardware found it.
        let rows =
            match upsert_address_best_difficulty(&self.pool, address, candidate, share.user_agent)
                .await
            {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        error = %e,
                        address, candidate,
                        "BestDifficultySink: PG upsert failed"
                    );
                    return;
                }
            };
        if rows == 0 {
            // Race: another miner beat us to the punch with a higher
            // share between our cache-read and the PG write. Refresh
            // the cache so the next share doesn't waste a round-trip.
            self.cache.invalidate(address).await;
            return;
        }

        self.cache
            .set(
                address,
                CachedAddressSettings {
                    best_difficulty: candidate,
                    best_difficulty_user_agent: share.user_agent.map(str::to_string),
                },
            )
            .await;
    }
}

/// Cache cold-read helper. Loads the current `bestDifficulty` from PG
/// and warms the cache so subsequent shares for this address can
/// short-circuit at the cache predicate without a PG round-trip.
/// Returns the loaded settings (whether warm-from-PG or zero-baseline
/// when the address has no row yet).
async fn warm_cache_from_pg<C: AddressSettingsCache>(
    pool: &PgPool,
    cache: &Arc<C>,
    address: &str,
) -> Result<CachedAddressSettings, bp_db::DbError> {
    let address_id = match AddressId::new(address.to_string()) {
        Ok(a) => a,
        Err(_) => {
            // Pre-authorize-stage rejection shouldn't reach this path;
            // defensive return of the zero-baseline.
            return Ok(CachedAddressSettings {
                best_difficulty: 0.0,
                best_difficulty_user_agent: None,
            });
        }
    };
    let row = find_address_settings(pool, &address_id).await?;
    let settings = match row {
        Some(r) => CachedAddressSettings {
            best_difficulty: r.best_difficulty,
            best_difficulty_user_agent: r.best_difficulty_user_agent,
        },
        // No row yet — first share for this address. Zero baseline
        // ensures the upsert INSERT-path fires next.
        None => CachedAddressSettings {
            best_difficulty: 0.0,
            best_difficulty_user_agent: None,
        },
    };
    cache.set(address, settings.clone()).await;
    Ok(settings)
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
