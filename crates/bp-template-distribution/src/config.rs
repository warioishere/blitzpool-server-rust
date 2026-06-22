// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime configuration for the TDP wrapper.

use std::path::PathBuf;
use std::time::Duration;

/// Default delay between reconnect attempts after the bitcoin-core IPC
/// connection drops mid-run (e.g. a `bitcoind` restart for a version
/// upgrade). Short enough that a ~10 s core restart is transparent to
/// miners (the last template stays live in the meantime), long enough
/// that a hard-down core doesn't spin the reconnect loop hot.
pub const DEFAULT_RECONNECT_BACKOFF_SECS: u64 = 2;

/// Default mempool fee delta (in satoshis) that triggers a fresh `NewTemplate`.
///
/// 100 000 sat ≈ 0.001 BTC. Bigger than the upstream example's 100-sat
/// default — we want one template per meaningful fee bump, not noise.
pub const DEFAULT_FEE_THRESHOLD: u64 = 100_000;

/// Default minimum interval (in seconds) between two consecutive non-tip
/// `NewTemplate` messages. Chain-tip updates always go out immediately.
pub const DEFAULT_MIN_INTERVAL_SECS: u8 = 10;

/// How big the outbound broadcast buffer is. Each subscriber sees the same
/// stream; slow subscribers receive `RecvError::Lagged` if they fall behind
/// by more than this many messages. 64 is enough for normal pool churn
/// without bloating per-subscriber memory.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 64;

/// Bound on the inbound mpsc that carries `submit`/`request_tx_data`/
/// `coinbase_constraints` messages from pool consumers to the TDP worker.
/// Bounded to apply back-pressure if the worker stalls.
pub const DEFAULT_SUBMIT_CAPACITY: usize = 32;

/// Coinbase-output constraints that the TDP worker advertises to bitcoin-core
/// at startup. bitcoin-core uses these to size the coinbase-tx-value-remaining
/// budget so the pool has room for its own outputs (payout, OP_RETURN,
/// witness commitment).
#[derive(Debug, Clone, Copy)]
pub struct TdpCoinbaseConstraints {
    /// Maximum additional bytes the pool may append to coinbase outputs.
    pub max_additional_size: u32,
    /// Maximum additional sigops the pool may consume across its added
    /// coinbase outputs.
    pub max_additional_sigops: u16,
}

impl Default for TdpCoinbaseConstraints {
    fn default() -> Self {
        // Conservative defaults: enough for a single P2WPKH payout output
        // (~31 bytes) plus a small OP_RETURN-style tag (~40 bytes). Real
        // values are caller-driven via [`TdpConfig::with_coinbase_constraints`].
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
    /// Delay between reconnect attempts after a mid-run IPC drop. The
    /// worker reconnects indefinitely (until pool shutdown) so a
    /// bitcoind restart doesn't require a pool restart.
    pub reconnect_backoff: Duration,
}

impl TdpConfig {
    /// Build a config with all defaults except the bitcoin-core IPC socket
    /// path, which is mandatory.
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
