// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime configuration for the TDP wrapper.

use std::path::PathBuf;
use std::time::Duration;

/// Short enough that a bitcoind restart is transparent to miners (the last
/// template stays live), long enough that a hard-down core doesn't spin the
/// reconnect loop hot.
pub const DEFAULT_RECONNECT_BACKOFF_SECS: u64 = 2;

/// Mempool fee delta in sats that triggers a fresh `NewTemplate`: one template
/// per meaningful fee bump, not per noise.
pub const DEFAULT_FEE_THRESHOLD: u64 = 100_000;

/// Minimum seconds between two non-tip `NewTemplate`s; chain-tip updates
/// always go out immediately.
pub const DEFAULT_MIN_INTERVAL_SECS: u8 = 10;

/// Outbound broadcast buffer; a subscriber further behind gets `RecvError::Lagged`.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 64;

/// Bounded so pool requests feel back-pressure when the worker stalls.
pub const DEFAULT_SUBMIT_CAPACITY: usize = 32;

/// Advertised to bitcoin-core so its templates leave room for the pool's own
/// coinbase outputs.
#[derive(Debug, Clone, Copy)]
pub struct TdpCoinbaseConstraints {
    pub max_additional_size: u32,
    pub max_additional_sigops: u16,
}

impl Default for TdpCoinbaseConstraints {
    fn default() -> Self {
        // Room for one P2WPKH output plus a small tag; callers set the real
        // values via `with_coinbase_constraints`.
        Self {
            max_additional_size: 100,
            max_additional_sigops: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TdpConfig {
    pub socket_path: PathBuf,
    pub fee_threshold: u64,
    pub min_interval_secs: u8,
    pub coinbase_constraints: TdpCoinbaseConstraints,
    pub broadcast_capacity: usize,
    pub submit_capacity: usize,
    /// The worker reconnects until pool shutdown, so a bitcoind restart
    /// needs no pool restart.
    pub reconnect_backoff: Duration,
}

impl TdpConfig {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            fee_threshold: DEFAULT_FEE_THRESHOLD,
            min_interval_secs: DEFAULT_MIN_INTERVAL_SECS,
            coinbase_constraints: TdpCoinbaseConstraints::default(),
            broadcast_capacity: DEFAULT_BROADCAST_CAPACITY,
            submit_capacity: DEFAULT_SUBMIT_CAPACITY,
            reconnect_backoff: Duration::from_secs(DEFAULT_RECONNECT_BACKOFF_SECS),
        }
    }

    pub fn with_reconnect_backoff(mut self, backoff: Duration) -> Self {
        self.reconnect_backoff = backoff;
        self
    }

    pub fn with_fee_threshold(mut self, threshold: u64) -> Self {
        self.fee_threshold = threshold;
        self
    }

    pub fn with_min_interval_secs(mut self, secs: u8) -> Self {
        self.min_interval_secs = secs;
        self
    }

    pub fn with_coinbase_constraints(mut self, constraints: TdpCoinbaseConstraints) -> Self {
        self.coinbase_constraints = constraints;
        self
    }

    pub fn with_broadcast_capacity(mut self, capacity: usize) -> Self {
        self.broadcast_capacity = capacity;
        self
    }

    pub fn with_submit_capacity(mut self, capacity: usize) -> Self {
        self.submit_capacity = capacity;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let cfg = TdpConfig::new("/tmp/anything.sock");
        assert_eq!(cfg.fee_threshold, 100_000);
        assert_eq!(cfg.min_interval_secs, 10);
        assert_eq!(cfg.broadcast_capacity, 64);
        assert_eq!(cfg.submit_capacity, 32);
        assert_eq!(cfg.coinbase_constraints.max_additional_size, 100);
        assert_eq!(cfg.coinbase_constraints.max_additional_sigops, 0);
    }

    #[test]
    fn builder_overrides_chain() {
        let cfg = TdpConfig::new("/x.sock")
            .with_fee_threshold(7)
            .with_min_interval_secs(3)
            .with_broadcast_capacity(8)
            .with_submit_capacity(4)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: 256,
                max_additional_sigops: 4,
            });
        assert_eq!(cfg.fee_threshold, 7);
        assert_eq!(cfg.min_interval_secs, 3);
        assert_eq!(cfg.broadcast_capacity, 8);
        assert_eq!(cfg.submit_capacity, 4);
        assert_eq!(cfg.coinbase_constraints.max_additional_size, 256);
        assert_eq!(cfg.coinbase_constraints.max_additional_sigops, 4);
    }
}
