// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V1 configuration: process-wide [`ServerConfig`] and one
//! [`PortConfig`] per listener. Defaults are the production values.

use bitcoin::Network;
use bp_common::MiningMode;
use bp_jobs_lifecycle::LifecycleConfig;

use crate::error::StratumV1Error;

/// Extranonce2 size advertised in `mining.subscribe`; with the 4-byte
/// extranonce1 the slot is 12 bytes. Hashpower marketplaces require ≥ 7.
pub(crate) const EXTRANONCE2_SIZE: u8 = 8;

/// BIP-310 version-rolling mask advertised in `mining.configure`.
pub(crate) const VERSION_ROLLING_MASK: u32 = 0x1fffe000;

/// How often each connection re-evaluates vardiff.
pub(crate) const DEFAULT_DIFFICULTY_CHECK_INTERVAL_MS: u64 = 60_000;

/// Session difficulty for a `cpuminer` user agent whose initial difficulty
/// is below [`CPUMINER_HIGH_DIFF_THRESHOLD`].
pub(crate) const CPUMINER_FALLBACK_DIFFICULTY: f64 = 0.1;

/// Above this initial difficulty the cpuminer fallback is skipped: such a
/// session was started high on purpose and is not a real CPU miner.
pub(crate) const CPUMINER_HIGH_DIFF_THRESHOLD: f64 = 1_000_000.0;

/// Vardiff target shares per minute when the port does not override it.
pub(crate) const DEFAULT_TARGET_SHARES_PER_MINUTE: f64 = 6.0;

/// Initial difficulty when the port sets none and no suggest_difficulty
/// was negotiated.
pub(crate) const DEFAULT_INITIAL_DIFFICULTY: f64 = 16_384.0;

/// Pool identifier in the coinbase scriptsig; dropped at build time if the
/// scriptsig would exceed 100 bytes.
pub const DEFAULT_POOL_IDENTIFIER: &str = "Public-Pool";

/// Process-wide configuration, shared across all connections.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub network: Network,
    /// Embedded in the coinbase scriptsig; dropped if the scriptsig would
    /// exceed the 100-byte consensus limit.
    pub pool_identifier: String,
    /// Job/template retire-and-age-out parameters for the registry.
    pub lifecycle: LifecycleConfig,
    /// How often each connection re-evaluates its vardiff target.
    pub difficulty_check_interval_ms: u64,
    /// Let vardiff treat silence as evidence and walk a quiet session down
    /// (see [`bp_vardiff`]). Off by default because it changes retargeting
    /// for every session.
    pub vardiff_silence_easing: bool,
    /// Log every inbound and outbound frame at DEBUG. Heavy, staging only.
    pub protocol_debug: bool,
    /// Per-share difficulty traces at DEBUG, without the frame firehose of
    /// [`Self::protocol_debug`].
    pub share_logs: bool,
    /// Log submit-to-ack latency per share at INFO; set by the same
    /// `debug.submit_latency` switch as SV2.
    pub log_submit_latency: bool,
}

impl ServerConfig {
    /// Construct a `ServerConfig` with production defaults for `network`.
    pub fn defaults_for(network: Network) -> Self {
        Self {
            network,
            pool_identifier: DEFAULT_POOL_IDENTIFIER.to_string(),
            lifecycle: LifecycleConfig::DEFAULT,
            difficulty_check_interval_ms: DEFAULT_DIFFICULTY_CHECK_INTERVAL_MS,
            vardiff_silence_easing: false,
            protocol_debug: false,
            share_logs: false,
            log_submit_latency: false,
        }
    }

    /// Validate cross-field invariants before any connection is accepted.
    pub fn validate(&self) -> Result<(), StratumV1Error> {
        if self.lifecycle.retention_ms < self.lifecycle.grace_ms {
            return Err(StratumV1Error::InvalidConfig(format!(
                "job_retention_ms {} must be ≥ the {} ms stale-grace window",
                self.lifecycle.retention_ms, self.lifecycle.grace_ms
            )));
        }
        if self.difficulty_check_interval_ms == 0 {
            return Err(StratumV1Error::InvalidConfig(
                "difficulty_check_interval_ms must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// Per-listener configuration: one instance per TCP port.
#[derive(Clone, Debug)]
pub struct PortConfig {
    pub port: u16,
    /// Starting difficulty. The cpuminer fallback and suggest_difficulty may
    /// lower it, but never below `minimum_difficulty` when that is set.
    pub initial_difficulty: f64,
    /// When `false`, `mining.suggest_difficulty` is rejected.
    pub allow_suggested_difficulty: bool,
    /// Vardiff target shares per minute.
    pub target_shares_per_minute: f64,
    /// Payout mode for shares on this port. The PPLNS port overrides any
    /// group membership: choosing the port is the session's opt-out.
    pub payout_mode: MiningMode,
    /// Vardiff floor when `> 0`, also clamping suggest_difficulty. Keeps
    /// sub-dust devices off the ledger on payout-mode ports.
    pub minimum_difficulty: f64,
}

impl PortConfig {
    /// Production defaults; the caller sets the initial difficulty because
    /// solo and PPLNS ports start very differently.
    pub fn new(port: u16, initial_difficulty: f64) -> Self {
        Self {
            port,
            initial_difficulty,
            allow_suggested_difficulty: true,
            target_shares_per_minute: DEFAULT_TARGET_SHARES_PER_MINUTE,
            payout_mode: MiningMode::Solo,
            minimum_difficulty: 0.0,
        }
    }

    /// The difficulty the first `mining.set_difficulty` advertises: a
    /// non-finite or non-positive start falls back to the default, then the
    /// floor is applied.
    pub fn effective_initial_difficulty(&self) -> f64 {
        let raw = if self.initial_difficulty.is_finite() && self.initial_difficulty > 0.0 {
            self.initial_difficulty
        } else {
            DEFAULT_INITIAL_DIFFICULTY
        };
        if self.minimum_difficulty > 0.0 {
            raw.max(self.minimum_difficulty)
        } else {
            raw
        }
    }

    /// Validate per-port invariants.
    pub fn validate(&self) -> Result<(), StratumV1Error> {
        if self.port == 0 {
            return Err(StratumV1Error::InvalidConfig("port must be > 0".into()));
        }
        // NaN/0 opt into the fallback; a negative value is a config error.
        if self.initial_difficulty.is_finite() && self.initial_difficulty < 0.0 {
            return Err(StratumV1Error::InvalidConfig(format!(
                "initial_difficulty {} must be ≥ 0 (use 0 / NaN to opt into the fallback)",
                self.initial_difficulty
            )));
        }
        if !(self.target_shares_per_minute > 0.0 && self.target_shares_per_minute.is_finite()) {
            return Err(StratumV1Error::InvalidConfig(format!(
                "target_shares_per_minute {} must be > 0 and finite",
                self.target_shares_per_minute
            )));
        }
        if self.minimum_difficulty.is_finite() && self.minimum_difficulty < 0.0 {
            return Err(StratumV1Error::InvalidConfig(format!(
                "minimum_difficulty {} must be ≥ 0",
                self.minimum_difficulty
            )));
        }
        if !self.minimum_difficulty.is_finite() {
            return Err(StratumV1Error::InvalidConfig(
                "minimum_difficulty must be finite".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ServerConfig {
        ServerConfig::defaults_for(Network::Bitcoin)
    }

    fn port(port: u16, diff: f64) -> PortConfig {
        PortConfig::new(port, diff)
    }

    // ── ServerConfig defaults pin the default constants ────────────────

    #[test]
    fn server_defaults_match_ts_constants() {
        let c = cfg();
        assert_eq!(c.network, Network::Bitcoin);
        assert_eq!(c.pool_identifier, "Public-Pool");
        assert_eq!(c.lifecycle, LifecycleConfig::DEFAULT);
        assert_eq!(c.difficulty_check_interval_ms, 60_000);
    }

    #[test]
    fn server_defaults_validate() {
        cfg().validate().expect("defaults must validate");
    }

    // ── ServerConfig validation ───────────────────────────────────────

    #[test]
    fn rejects_retention_below_grace() {
        // A job must outlive the grace window to be classifiable as stale.
        let mut c = cfg();
        c.lifecycle.retention_ms = 1_000;
        c.lifecycle.grace_ms = 5_000;
        assert!(matches!(
            c.validate(),
            Err(StratumV1Error::InvalidConfig(_))
        ));
    }

    // ── PortConfig defaults + validation ──────────────────────────────

    #[test]
    fn port_defaults_match_ts() {
        let p = port(3333, 1024.0);
        assert_eq!(p.port, 3333);
        assert_eq!(p.initial_difficulty, 1024.0);
        assert!(p.allow_suggested_difficulty);
        assert_eq!(p.target_shares_per_minute, 6.0);
        assert_eq!(p.payout_mode, MiningMode::Solo);
        assert_eq!(p.minimum_difficulty, 0.0);
    }

    #[test]
    fn port_defaults_validate() {
        port(3333, 1024.0)
            .validate()
            .expect("port defaults must validate");
    }

    #[test]
    fn port_rejects_zero_port() {
        let p = port(0, 1024.0);
        assert!(matches!(
            p.validate(),
            Err(StratumV1Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn port_rejects_negative_initial_difficulty() {
        let p = port(3333, -1.0);
        assert!(matches!(
            p.validate(),
            Err(StratumV1Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn port_rejects_zero_target_shares_per_minute() {
        let mut p = port(3333, 1024.0);
        p.target_shares_per_minute = 0.0;
        assert!(matches!(
            p.validate(),
            Err(StratumV1Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn port_rejects_nonfinite_minimum_difficulty() {
        let mut p = port(3333, 1024.0);
        p.minimum_difficulty = f64::INFINITY;
        assert!(matches!(
            p.validate(),
            Err(StratumV1Error::InvalidConfig(_))
        ));
    }

    // ── effective_initial_difficulty: clamping logic ────────────────────

    #[test]
    fn effective_initial_difficulty_fallback_on_nonfinite_input() {
        let p = port(3333, f64::NAN);
        assert_eq!(p.effective_initial_difficulty(), DEFAULT_INITIAL_DIFFICULTY);
        let p = port(3333, f64::INFINITY);
        assert_eq!(p.effective_initial_difficulty(), DEFAULT_INITIAL_DIFFICULTY);
        let p = port(3333, 0.0);
        assert_eq!(p.effective_initial_difficulty(), DEFAULT_INITIAL_DIFFICULTY);
        let p = port(3333, -10.0);
        assert_eq!(p.effective_initial_difficulty(), DEFAULT_INITIAL_DIFFICULTY);
    }

    #[test]
    fn effective_initial_difficulty_clamps_to_minimum_when_set() {
        let mut p = port(3333, 64.0);
        p.minimum_difficulty = 1024.0;
        assert_eq!(p.effective_initial_difficulty(), 1024.0);

        // Already above the floor — passes through unchanged.
        let mut p = port(3333, 8192.0);
        p.minimum_difficulty = 1024.0;
        assert_eq!(p.effective_initial_difficulty(), 8192.0);
    }

    #[test]
    fn effective_initial_difficulty_uses_raw_when_no_floor() {
        let p = port(3333, 4096.0);
        assert_eq!(p.effective_initial_difficulty(), 4096.0);
    }

    #[test]
    fn effective_initial_difficulty_applies_floor_on_nonfinite_input() {
        let mut p = port(3333, f64::NAN);
        p.minimum_difficulty = 100_000.0;
        assert_eq!(p.effective_initial_difficulty(), 100_000.0);
    }
}
