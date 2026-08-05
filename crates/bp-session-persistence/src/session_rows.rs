// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who gets a `client_entity` row, and when.
//!
//! ## The rule
//!
//! A session earns its row by **mining**, not by connecting. The row is
//! created on the session's first accepted share and retired when the
//! connection closes — and only if it was ever created.
//!
//! ## Why it moved off the authorize path
//!
//! Measured on prod 2026-08-05: **6 129 sessions in one hour from 57
//! addresses**, with a **median lifetime of 0.1 s**. Median 0.1 s against a
//! 61.8 s mean is two populations in one table — a flood of connections that
//! complete the handshake and hang up, alongside the real mining sessions.
//! The miners were unaffected throughout; it is probe/handshake traffic.
//!
//! Writing on authorize charged each of those an INSERT plus a soft-delete
//! UPDATE — ~12 200 statements/hour, every one its own commit and WAL fsync.
//! That is what the sampler caught the pool queueing on: backends waiting in
//! `LWLock/WALWrite` behind one `IO/WalSync`, with `pg_blocking_pids()` empty
//! (no lock contention at all).
//!
//! Deferring costs nothing, because the authorize path never had data the
//! share does not also carry: `register_client` passed `None` for both
//! `start_time_ms` and `current_difficulty`, so the old `startTime` was just
//! "when authorize happened", and `userAgent` rides on the share.
//!
//! ## What still answers "is this miner online?"
//!
//! Redis, not this table — and it did before this change too. The front
//! publishes its live-session set (`crate`-external `LiveSessionRegistry`),
//! and the device-status gate reads its session COUNT from there. Only
//! `first_seen_ms` comes from `client_entity`, and `device_first_seen`
//! aggregates over soft-deleted rows as well, so any worker seen within the
//! hard-delete retention already has a record.
//!
//! The one behaviour change: a `(address, worker)` pair the pool has **never**
//! seen appears in the DB-backed views at its first share instead of at
//! authorize. Seconds, for a miner that mines. Never, for one that does not —
//! which is the point.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};
use sqlx::PgPool;
use tracing::warn;

use crate::client_row::register_client;

/// Session ids whose `client_entity` row exists (or is being written).
///
/// Two transitions, no timers: [`Self::claim`] on a session's first accepted
/// share, [`Self::release`] when the connection closes. Bounded by the live
/// session count, because `release` runs on every teardown — including the
/// teardown of a session that never mined, which is simply absent.
#[derive(Default)]
pub(crate) struct PersistedSessions {
    inner: Mutex<HashSet<String>>,
}

impl PersistedSessions {
    /// Reserve `session_id` for writing. `true` means the caller is the one
    /// that has to write the row; `false` means someone already did.
    ///
    /// The reservation is taken BEFORE the write is awaited, so two shares of
    /// the same session arriving concurrently cannot both issue an INSERT.
    fn claim(&self, session_id: &str) -> bool {
        self.guard().insert(session_id.to_string())
    }

    /// Give the reservation back after a failed write, so the session's next
    /// share retries. The old authorize-time write had no equivalent: it only
    /// logged, and nothing ever tried again — which left the session with no
    /// row, and (before the touch became an upsert) permanently invisible.
    fn unclaim(&self, session_id: &str) {
        self.guard().remove(session_id);
    }

    /// Forget `session_id`, reporting whether it had a row. `false` means the
    /// session never mined, so there is nothing to retire and the teardown
    /// must not issue a statement.
    pub(crate) fn release(&self, session_id: &str) -> bool {
        self.guard().remove(session_id)
    }

    /// Recovering from a poisoned lock rather than panicking: a stray poison
    /// here would otherwise turn every subsequent share into a panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.guard().len()
    }
}

/// Creates the `client_entity` row on a session's first accepted share.
///
/// Front-side only. It is wired into the producing fan-out **before** the sink
/// that publishes to the accepted-share stream, so the row exists before the
/// share can reach the accounting role at all. That ordering is belt and
/// braces rather than load-bearing: `bulk_touch_clients_for_share` is an
/// upsert, so whoever gets there first creates the row.
#[derive(Clone)]
pub struct ClientRowSessionSink {
    pool: PgPool,
    persisted: Arc<PersistedSessions>,
}

impl ClientRowSessionSink {
    pub(crate) fn new(pool: PgPool, persisted: Arc<PersistedSessions>) -> Self {
        Self { pool, persisted }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ClientRowSessionSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        if !self.persisted.claim(share.session_id) {
            return;
        }

        // Same fallback the touch sink uses, so both agree on the PK. (The
        // retired authorize write disagreed with it: SV1 registered an empty
        // worker as "", while the touch looked up "default" — so an empty-worker
        // SV1 session never matched. One writer, one fallback, no drift.)
        let worker = if share.worker.is_empty() {
            "default"
        } else {
            share.worker
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // The same `register_client` the authorize path used, so there is one
        // row-construction in the crate rather than two that can drift. It now
        // gets the two values authorize never had: the vardiff target this
        // share was credited at (what the touch path keeps `currentDifficulty`
        // at) and an explicit start time.
        //
        // Awaited on purpose, once per session: it is the same statement
        // authorize used to run, so the exposure is unchanged in kind — only
        // its timing moved to the session's first share. The fan-out already
        // warns per sink past 100 ms, so a slow one says so instead of hiding
        // in a detached task.
        if let Err(e) = register_client(
            &self.pool,
            share.address,
            worker,
            share.session_id,
            share.user_agent,
            Some(now_ms),
            Some(share.effective_difficulty as f32),
        )
        .await
        {
            self.persisted.unclaim(share.session_id);
            warn!(
                error = %e,
                session_id = share.session_id,
                address = share.address,
                worker,
                "ClientRowSessionSink: session row write failed — retrying on the next share"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reservation is what stops two concurrent shares of one session from
    /// both issuing an INSERT, and what makes the teardown able to tell a
    /// session that mined from one that never did.
    #[test]
    fn claim_is_once_and_release_reports_whether_there_was_a_row() {
        let p = PersistedSessions::default();
        assert!(p.claim("sess-a"), "first share claims");
        assert!(!p.claim("sess-a"), "a second share must not claim again");
        assert_eq!(p.len(), 1);

        assert!(p.release("sess-a"), "release reports the row existed");
        assert_eq!(p.len(), 0);
        assert!(
            !p.release("sess-a"),
            "releasing twice must not claim a row exists"
        );
    }

    /// A session that never mined was never claimed, so its teardown must
    /// report "nothing to retire" — that is the whole point: a throwaway
    /// connection costs neither an INSERT nor a soft-delete.
    #[test]
    fn a_session_that_never_mined_is_absent() {
        let p = PersistedSessions::default();
        assert!(
            !p.release("probe"),
            "a session with no shares must not be retired"
        );
        assert_eq!(p.len(), 0);
    }

    /// A failed write hands the reservation back, so the next share retries.
    #[test]
    fn unclaim_lets_the_next_share_retry() {
        let p = PersistedSessions::default();
        assert!(p.claim("sess-b"));
        p.unclaim("sess-b");
        assert!(
            p.claim("sess-b"),
            "after a failed write the next share retries"
        );
    }
}
