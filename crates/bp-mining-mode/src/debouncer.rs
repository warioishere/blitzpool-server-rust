// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process debouncer for live-marker writes.
//!
//! The stratum layer wants to write the active mining-mode marker after
//! every accepted share, but the marker's Redis TTL is 5 min — refreshing
//! it once a minute is plenty. This debouncer is the small in-memory
//! gate that the stratum layer consults before doing the Redis round-trip:
//!
//! - **Same mode within the refresh interval** → debounced (no write).
//! - **Mode change** → always allowed (port-switch detection is the
//!   whole point of the marker).
//! - **Refresh interval elapsed** → allowed.
//!
//! Matches `MinerActiveModeService::mark`'s `REFRESH_INTERVAL_MS` and
//! `lastMark` map.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bp_common::{AddressId, MiningMode};

/// 60 s refresh interval. A 4-minute safety margin under the 5-minute Redis
/// TTL of the marker itself.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub struct MarkDebouncer {
    last_mark: Mutex<HashMap<AddressId, LastMark>>,
    refresh_interval: Duration,
}

#[derive(Clone, Copy)]
struct LastMark {
    mode: MiningMode,
    at: Instant,
}

impl Default for MarkDebouncer {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkDebouncer {
    pub fn new() -> Self {
        Self {
            last_mark: Mutex::new(HashMap::new()),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
        }
    }

    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Atomically check whether a marker write should happen and, if so,
    /// record the new mark. Returns `true` if the caller should proceed
    /// with the actual Redis write, `false` if the same-mode write was
    /// debounced.
    ///
    /// Concurrent calls for the same address are linearised by the inner
    /// mutex — at most one caller per address-mode pair will see `true`
    /// within any `refresh_interval` window.
    pub fn try_acquire(&self, address: &AddressId, mode: MiningMode) -> bool {
        let now = Instant::now();
        let mut last = self.last_mark.lock().expect("debouncer mutex poisoned");

        let allow = !matches!(
            last.get(address),
            Some(prev) if prev.mode == mode
                && now.duration_since(prev.at) < self.refresh_interval
        );

        if allow {
            last.insert(address.clone(), LastMark { mode, at: now });
        }
        allow
    }

    /// Forget the last-mark record for `address` (e.g. when a session
    /// disconnects and we want the next reconnect's first share to write).
    pub fn forget(&self, address: &AddressId) {
        let mut last = self.last_mark.lock().expect("debouncer mutex poisoned");
        last.remove(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("test address well-formed")
    }

    #[test]
    fn first_call_always_acquires() {
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
    }

    #[test]
    fn same_mode_within_interval_is_debounced() {
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
    }

    #[test]
    fn mode_change_always_acquires_even_within_interval() {
        // Port-switch detection is the whole point of the marker; debounce
        // must NOT swallow mode changes.
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Solo));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::GroupSolo));
        // Same mode after the changes is now debounced against the
        // most-recent mark.
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::GroupSolo));
    }

    #[test]
    fn per_address_independence() {
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(d.try_acquire(&addr("bc1qbob"), MiningMode::Pplns));
        // Each address has its own slot.
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(!d.try_acquire(&addr("bc1qbob"), MiningMode::Pplns));
    }

    #[test]
    fn forget_resets_per_address() {
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Solo));
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::Solo));
        d.forget(&addr("bc1qalice"));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Solo));
    }

    #[tokio::test]
    async fn interval_elapsed_re_acquires() {
        // Tiny interval to keep the test fast.
        let d = MarkDebouncer::new().with_refresh_interval(Duration::from_millis(10));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
    }
}
