// SPDX-License-Identifier: AGPL-3.0-or-later

//! Debounced client-row birth.
//!
//! `client_entity` used to get its row synchronously at authorize plus a
//! soft-delete at disconnect — two committed statements per connection,
//! no matter how short. Measured on prod (2026-08-06): ~43k connections
//! per day never submit a share, and 95 % of those disconnect within one
//! second. Their statements were pure overhead, and the rows they left
//! behind (soft-deleted, retained for the hard-delete window) bloated the
//! table every other `client_entity` writer pays for through full-page
//! writes.
//!
//! So the row is born late: `register_session` only records the session
//! in the in-memory [`RowDebounce`] map, and the birth flush writes it —
//! batched, one statement per tick — once it has survived
//! `row_debounce` (default 15 s). A session that disconnects while still
//! pending just drops out of the map: zero statements. Teardown
//! soft-deletes only sessions that were actually born.
//!
//! The debounce must stay well below the device-status gate's
//! `online_dwell` (90 s): the gate's liveness lookup drops
//! `(address, worker)` keys that have no `client_entity` row yet, so a
//! row late by more than the dwell would make the gate treat a connected
//! device as absent. 15–20 s of birth latency disappears inside the
//! dwell.
//!
//! ## The teardown race, and why it is left to `kill_dead_clients`
//!
//! A session can disconnect in the moment its row is in flight: the
//! entry is already drained (so `deregister` sees nothing pending) and
//! not yet marked born (so no soft-delete runs). The flush then commits
//! a row for a dead session. That ghost is exactly the case the 60 s
//! `kill_dead_clients` cron exists for — a teardown that did not stamp
//! its row — and is swept within its 5-min staleness window. The gate is
//! unaffected either way: its session counts come from the fronts' Redis
//! live-session sets, not from this table.

use std::collections::HashSet;
use std::sync::Mutex;

use bp_db::{bulk_upsert_clients, ClientUpsert, DbError};
use hashbrown::HashMap;
use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, warn};

use crate::touch_buffer::TouchKey;

/// How often a row-specific failure (a Postgres error for exactly this
/// row while the connection is healthy) is retried before the entry is
/// dropped. Transient outages (pool/IO errors) do not count against
/// this — they retry indefinitely, like the touch buffer's rebuffer.
pub(crate) const MAX_BIRTH_ATTEMPTS: u32 = 3;

/// One not-yet-born session. Values captured at `register_session`
/// (authorize) so the row the flush writes is exactly the row the old
/// synchronous path wrote — same `userAgent` (incl. the SV2
/// `jd-client/sv2` placeholder the downstream-report refinement matches
/// on), same authorize-time `startTime`/`firstSeen`.
pub(crate) struct PendingRow {
    pub user_agent: Option<String>,
    pub start_time_ms: i64,
    pub registered_at: Instant,
    pub attempts: u32,
}

#[derive(Default)]
struct Inner {
    /// Keyed on the row PK triple — NOT on `sessionId` alone: a rental
    /// proxy that switches worker names re-registers the SAME session id
    /// under a different `clientName`, and each pair needs its own row.
    pending: HashMap<TouchKey, PendingRow>,
    /// Session ids with at least one born row. Drives the teardown
    /// decision: only a born session gets the soft-delete statement
    /// (which is `sessionId`-wide, covering every worker of the
    /// session).
    ///
    /// Entries leave at deregister, so this tracks the currently-connected
    /// born sessions. Two cases add an entry nothing will ever remove, both
    /// bounded and deliberately not engineered around:
    ///
    /// - the teardown-race below: a session that disconnects between its
    ///   drain and its `mark_born` leaves its id here. That window is one
    ///   bulk INSERT wide, so at prod rates it is single-digit entries per
    ///   day — a few hundred bytes a year.
    /// - a teardown that never fires at all (task aborted mid-shutdown).
    ///   The same miss leaves a live `client_entity` row for
    ///   `kill_dead_clients` to sweep, which is the louder symptom of the
    ///   two, and the process is ending anyway.
    born: HashSet<String>,
}

/// Shared pending-session state. The hook writes into it on
/// authorize/disconnect; the birth flush drains it on every tick.
///
/// Locking is a plain `std::sync::Mutex`: no critical section spans an
/// `.await` (register/deregister mutate the maps; the flush drains
/// before the DB round-trip), matching the touch buffer's posture.
#[derive(Default)]
pub(crate) struct RowDebounce {
    inner: Mutex<Inner>,
}

impl RowDebounce {
    fn guard(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record a freshly-authorized session. Overwrites a pending entry
    /// for the same triple (defensive re-register): latest authorize
    /// wins, retry budget resets. A re-register of an already-born
    /// session pends again — the birth flush's `ON CONFLICT` arm then
    /// refreshes the row and clears its soft-delete, which is what the
    /// synchronous upsert did.
    pub(crate) fn register(
        &self,
        address: &str,
        client_name: &str,
        session_id: &str,
        user_agent: Option<&str>,
        start_time_ms: i64,
        now: Instant,
    ) {
        let key = TouchKey {
            address: address.to_string(),
            client_name: client_name.to_string(),
            session_id: session_id.to_string(),
        };
        self.guard().pending.insert(
            key,
            PendingRow {
                user_agent: user_agent.map(|s| s.to_string()),
                start_time_ms,
                registered_at: now,
                attempts: 0,
            },
        );
    }

    /// Session teardown. Drops every pending entry of the session (a
    /// probe's entire trace) and returns whether any row was born — the
    /// caller runs the session-wide soft-delete exactly then.
    pub(crate) fn deregister(&self, session_id: &str) -> bool {
        let mut guard = self.guard();
        guard.pending.retain(|k, _| k.session_id != session_id);
        guard.born.remove(session_id)
    }

    /// Remove and return every pending entry at least `min_age` old.
    pub(crate) fn drain_due(&self, min_age: Duration, now: Instant) -> Vec<(TouchKey, PendingRow)> {
        let mut guard = self.guard();
        let due: Vec<TouchKey> = guard
            .pending
            .iter()
            .filter(|(_, v)| now.duration_since(v.registered_at) >= min_age)
            .map(|(k, _)| k.clone())
            .collect();
        due.into_iter()
            .filter_map(|k| guard.pending.remove(&k).map(|v| (k, v)))
            .collect()
    }

    /// Mark a session as having at least one row in the table.
    pub(crate) fn mark_born(&self, session_id: &str) {
        self.guard().born.insert(session_id.to_string());
    }

    /// Fold entries whose write failed back into the pending map, with
    /// their (possibly incremented) retry state. A newer entry for the
    /// same triple — the session re-registered while the write was in
    /// flight — wins over the stale snapshot.
    pub(crate) fn restore(&self, rows: Vec<(TouchKey, PendingRow)>) {
        let mut guard = self.guard();
        for (k, v) in rows {
            guard.pending.entry(k).or_insert(v);
        }
    }

    /// Number of sessions currently awaiting birth. Diagnostic — the
    /// integration tests pin the retry/drop budget through it.
    pub(crate) fn pending_len(&self) -> usize {
        self.guard().pending.len()
    }
}

/// A Postgres statement-level error is row-specific and deterministic
/// for the same input (e.g. `22001` for an over-long `clientName`, which
/// the SV1 path does not length-check), so it counts against
/// [`MAX_BIRTH_ATTEMPTS`]. Everything else — pool exhaustion, IO, a
/// restarting Postgres — is an outage: the row is fine, the retry is
/// free, and dropping it would orphan the session's whole trace.
fn is_row_error(e: &DbError) -> bool {
    matches!(e, DbError::Sqlx(sqlx::Error::Database(_)))
}

fn to_upsert(key: &TouchKey, row: &PendingRow) -> ClientUpsert {
    ClientUpsert {
        address: key.address.clone(),
        client_name: key.client_name.clone(),
        session_id: key.session_id.clone(),
        user_agent: row.user_agent.clone(),
        start_time_ms: row.start_time_ms,
        current_difficulty: None,
    }
}

/// One birth pass: drain the due entries, write them in a single bulk
/// upsert, and on failure isolate per row so one poisoned entry cannot
/// starve the healthy ones. Returns the number of rows written.
pub(crate) async fn flush_once(debounce: &RowDebounce, pool: &PgPool, min_age: Duration) -> u64 {
    let due = debounce.drain_due(min_age, Instant::now());
    if due.is_empty() {
        return 0;
    }
    let rows: Vec<ClientUpsert> = due.iter().map(|(k, v)| to_upsert(k, v)).collect();
    match bulk_upsert_clients(pool, &rows).await {
        Ok(n) => {
            for (key, _) in &due {
                debounce.mark_born(&key.session_id);
            }
            debug!(born = n, "client row birth flushed");
            n
        }
        Err(bulk_err) => {
            // Per-row isolation. The bulk statement is all-or-nothing, so
            // a single bad row (22001 over-long name) would otherwise
            // poison every session in the batch — and an unbounded retry
            // would poison every FUTURE batch too, which is exactly how
            // the abandoned upsert-touch design failed.
            warn!(
                error = %bulk_err,
                rows = due.len(),
                "client row birth bulk write failed; retrying per row"
            );
            let mut written = 0u64;
            let mut keep = Vec::new();
            for (key, mut state) in due {
                let row = to_upsert(&key, &state);
                match bulk_upsert_clients(pool, std::slice::from_ref(&row)).await {
                    Ok(n) => {
                        debounce.mark_born(&key.session_id);
                        written += n;
                    }
                    Err(e) if is_row_error(&e) => {
                        state.attempts += 1;
                        if state.attempts >= MAX_BIRTH_ATTEMPTS {
                            error!(
                                error = %e,
                                address = %key.address,
                                client_name = %key.client_name,
                                session_id = %key.session_id,
                                attempts = state.attempts,
                                "client row birth failed on a row-specific error; dropping the row"
                            );
                        } else {
                            keep.push((key, state));
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            session_id = %key.session_id,
                            "client row birth hit a transient error; rebuffering for retry"
                        );
                        keep.push((key, state));
                    }
                }
            }
            debounce.restore(keep);
            written
        }
    }
}

/// Spawned birth-flush loop. Returns when `shutdown_rx` resolves.
///
/// Deliberately NO final drain on shutdown, unlike the touch flush: a
/// front that is shutting down is closing its sockets, so every still-
/// pending session is about to end — writing its row now would only
/// create work for `kill_dead_clients`.
pub(crate) async fn run_birth_loop(
    debounce: std::sync::Arc<RowDebounce>,
    pool: PgPool,
    min_age: Duration,
    flush_interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let start = Instant::now() + flush_interval;
    let mut ticker = tokio::time::interval_at(start, flush_interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                flush_once(&debounce, &pool, min_age).await;
            }
            _ = &mut shutdown_rx => {
                debug!("client row birth loop received shutdown");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(session: &str, worker: &str) -> TouchKey {
        TouchKey {
            address: "bcrt1qtestaddress0000000000000000000000000".to_string(),
            client_name: worker.to_string(),
            session_id: session.to_string(),
        }
    }

    fn register(d: &RowDebounce, session: &str, worker: &str, now: Instant) {
        d.register(&key(session, worker).address, worker, session, None, 1, now);
    }

    /// The probe path: a session that deregisters while pending leaves
    /// nothing behind, and `deregister` reports it was never born — the
    /// caller must not issue the soft-delete statement for it.
    #[test]
    fn a_probe_leaves_no_pending_entry_and_no_born_flag() {
        let d = RowDebounce::default();
        let now = Instant::now();
        register(&d, "sessP001", "w1", now);
        assert_eq!(d.pending_len(), 1);
        assert!(!d.deregister("sessP001"), "never born → no soft-delete");
        assert_eq!(d.pending_len(), 0, "probe trace must be gone");
        // And the flush after the fact has nothing to write.
        assert!(d.drain_due(Duration::ZERO, now).is_empty());
    }

    /// A born session is torn down exactly once: the first deregister
    /// reports born (soft-delete runs), a duplicate does not.
    #[test]
    fn deregister_reports_born_exactly_once() {
        let d = RowDebounce::default();
        register(&d, "sessB001", "w1", Instant::now());
        let due = d.drain_due(Duration::ZERO, Instant::now());
        assert_eq!(due.len(), 1);
        d.mark_born("sessB001");
        assert!(d.deregister("sessB001"), "born → soft-delete owed");
        assert!(!d.deregister("sessB001"), "second teardown is a no-op");
    }

    /// A rental proxy re-registers the SAME session id under a second
    /// worker name. Both pairs must pend independently, and one
    /// deregister drops the whole session's trace.
    #[test]
    fn two_workers_on_one_session_pend_independently() {
        let d = RowDebounce::default();
        let now = Instant::now();
        register(&d, "sessW001", "w1", now);
        register(&d, "sessW001", "w2", now);
        assert_eq!(
            d.pending_len(),
            2,
            "one entry per (address, worker, session)"
        );
        assert!(!d.deregister("sessW001"));
        assert_eq!(
            d.pending_len(),
            0,
            "teardown drops every worker of the session"
        );
    }

    /// Only entries older than the debounce drain; younger ones stay.
    #[test]
    fn drain_due_respects_the_debounce_age() {
        let d = RowDebounce::default();
        let old = Instant::now();
        register(&d, "sessO001", "w1", old);
        let newer = old + Duration::from_secs(10);
        register(&d, "sessN001", "w1", newer);
        let due = d.drain_due(Duration::from_secs(15), newer + Duration::from_secs(5));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0.session_id, "sessO001");
        assert_eq!(d.pending_len(), 1, "the young session keeps pending");
    }

    /// `restore` must not clobber a fresher re-register of the same
    /// triple that landed while the failed write was in flight.
    #[test]
    fn restore_keeps_the_newer_entry() {
        let d = RowDebounce::default();
        let t0 = Instant::now();
        register(&d, "sessR001", "w1", t0);
        let mut due = d.drain_due(Duration::ZERO, t0);
        assert_eq!(due.len(), 1);
        due[0].1.attempts = 2; // pretend the write failed twice
                               // The session re-registers while the write is in flight.
        register(&d, "sessR001", "w1", t0 + Duration::from_secs(1));
        d.restore(due);
        let after = d.drain_due(Duration::ZERO, t0 + Duration::from_secs(2));
        assert_eq!(after.len(), 1);
        assert_eq!(
            after[0].1.attempts, 0,
            "the fresh entry wins over the stale snapshot"
        );
    }
}
