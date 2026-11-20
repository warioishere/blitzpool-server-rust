// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum session ids: one process-wide sequence for SV1 and SV2.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// The next Stratum session id. SV1 sessions and SV2 channels share the
/// live-session registry and the session rows, so both draw from this one
/// sequence: no two hold the same id before it wraps after 2^32 ids. The
/// sequence starts at a random point, so a restart is unlikely to hand out
/// the ids of the rows the last run left. Registered as
/// [`session_id_hex`].
pub fn next_session_id() -> u32 {
    static NEXT: OnceLock<AtomicU32> = OnceLock::new();
    NEXT.get_or_init(|| {
        let mut start = [0u8; 4];
        // A failed RNG only costs the random start; ids stay unique.
        let _ = getrandom::fill(&mut start);
        AtomicU32::new(u32::from_be_bytes(start))
    })
    .fetch_add(1, Ordering::Relaxed)
}

/// A session id the way logs, the wire and `client_entity.sessionId` carry
/// it: 8 lowercase hex digits.
pub fn session_id_hex(id: u32) -> String {
    format!("{id:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Ids drawn from many threads at once are all distinct.
    #[test]
    fn concurrent_session_ids_are_distinct() {
        let ids: Vec<u32> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| (0..10_000).map(|_| next_session_id()).collect::<Vec<_>>()))
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });
        let distinct: HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(distinct.len(), ids.len());
    }
}
