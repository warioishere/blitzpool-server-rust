// SPDX-License-Identifier: AGPL-3.0-or-later

//! Debouncer for the live mining-mode marker written on every accepted share.
//! The marker's Redis TTL is 5 min, so a same-mode refresh once a minute is
//! enough; a mode change always writes, since detecting it is the marker's point.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bp_common::{AddressId, MiningMode};

/// Well under the marker's 5-minute Redis TTL.
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

    /// `true` if the caller should write the marker, recording the mark
    /// atomically: at most one caller per address-mode pair gets `true`
    /// within a `refresh_interval`.
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

    /// Forget `address`, so the first share after a reconnect writes.
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
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Solo));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::GroupSolo));
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::GroupSolo));
    }

    #[test]
    fn per_address_independence() {
        let d = MarkDebouncer::new();
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(d.try_acquire(&addr("bc1qbob"), MiningMode::Pplns));
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
        let d = MarkDebouncer::new().with_refresh_interval(Duration::from_millis(10));
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        assert!(!d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(d.try_acquire(&addr("bc1qalice"), MiningMode::Pplns));
    }
}
