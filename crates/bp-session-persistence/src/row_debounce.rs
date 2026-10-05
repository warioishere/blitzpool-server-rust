// SPDX-License-Identifier: AGPL-3.0-or-later

//! Debounced client-row birth: a `client_entity` row is written only once its
//! session survived `row_debounce`, so short-lived probes cost no statement.
//! The debounce must stay well below the device-status gate's `online_dwell`,
//! which treats a device without a row as absent.

use std::collections::HashSet;
use std::sync::Mutex;

use bp_db::{bulk_upsert_clients, ClientUpsert, DbError};
use hashbrown::HashMap;
use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, warn};

use crate::touch_buffer::TouchKey;

/// Retries for a row-specific Postgres error before the entry is dropped.
/// Transient outages (pool/IO errors) do not count and retry indefinitely.
pub(crate) const MAX_BIRTH_ATTEMPTS: u32 = 3;

/// One not-yet-born session, captured at authorize so the row carries the
/// authorize-time `userAgent` (incl. the SV2 `jd-client/sv2` placeholder the
/// downstream-report refinement matches on) and `startTime`.
pub(crate) struct PendingRow {
    pub user_agent: Option<String>,
    pub start_time_ms: i64,
    pub registered_at: Instant,
    pub attempts: u32,
}

#[derive(Default)]
struct Inner {
    /// Keyed on the row PK triple, not `sessionId` alone: a rental proxy can
    /// re-register the same session under another `clientName`.
    pending: HashMap<TouchKey, PendingRow>,
    /// Session ids with at least one born row; only those get the
    /// session-wide soft-delete at teardown.
    born: HashSet<String>,
}

/// Pending-session state: the hook writes on authorize/disconnect, the
/// birth flush drains it each tick. A `std::sync::Mutex` is enough because
/// no critical section spans an `.await`.
#[derive(Default)]
pub(crate) struct RowDebounce {
    inner: Mutex<Inner>,
}

impl RowDebounce {
    fn guard(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record a freshly-authorized session; the latest authorize wins and
    /// resets the retry budget. A born session pends again, and the flush's
    /// `ON CONFLICT` arm refreshes the row and clears its soft-delete.
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

    /// Session teardown: drops the session's pending entries and returns
    /// whether a row was born (then the caller soft-deletes). A row still in
    /// flight at teardown is left to `kill_dead_clients`, which sweeps it.
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

    /// Fold failed entries back into the pending map. A newer entry for the
    /// same triple (re-registered while the write was in flight) wins.
    pub(crate) fn restore(&self, rows: Vec<(TouchKey, PendingRow)>) {
        let mut guard = self.guard();
        for (k, v) in rows {
            guard.pending.entry(k).or_insert(v);
        }
    }

    /// Number of sessions awaiting birth; tests pin the retry budget with it.
    pub(crate) fn pending_len(&self) -> usize {
        self.guard().pending.len()
    }
}

/// A Postgres statement error is deterministic for the row (e.g. `22001`
/// over-long `clientName`), so it counts against [`MAX_BIRTH_ATTEMPTS`].
/// Anything else is an outage: retrying is free, dropping would orphan the row.
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
            // The bulk statement is all-or-nothing: retry per row so one
            // bad row cannot block the whole batch.
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
                            "client row birth hit a transient error; kept for retry"
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

/// Birth-flush loop until `shutdown_rx` resolves. No final drain: every
/// still-pending session is about to end with the shutdown anyway.
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

    /// A probe that deregisters while pending leaves nothing and owes no soft-delete.
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

    /// A born session reports born on the first deregister only.
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

    /// Two workers on one session pend independently; one deregister drops both.
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

    /// `restore` does not clobber a fresher re-register of the same triple.
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
