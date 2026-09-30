// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration for the Stratum V1 server and its listener ports.
//!
//! Two layers:
//!
//! - [`ServerConfig`]: process-wide defaults (network, pool identifier,
//!   job lifecycle). Built once at startup.
//! - [`PortConfig`]: per-listener overrides (initial difficulty, payout
//!   mode, vardiff floor). One per TCP port the operator
//!   exposes.
//!
//! Default values are the production values.

use bitcoin::Network;
use bp_common::MiningMode;
use bp_jobs_lifecycle::LifecycleConfig;

use crate::error::StratumV1Error;

/// SV1 `mining.subscribe` response advertises an extranonce-2 size of 8
/// bytes. Combined with the 4-byte extranonce-1 from the session id, total
/// extranonce slot is 12 bytes. Matches ckpool's `nonce2length` default
/// and is required by the Braiins Hashpower marketplace (≥ 7).
pub(crate) const EXTRANONCE2_SIZE: u8 = 8;

/// SV1 `mining.configure` response advertises BIP-310 version-rolling with
/// this mask. Standard value compatible with most ASIC firmwares.
pub(crate) const VERSION_ROLLING_MASK: u32 = 0x1fffe000;

/// Default vardiff sample-window evaluation interval (60 s). The
/// per-connection difficulty-check timer fires this often.
pub(crate) const DEFAULT_DIFFICULTY_CHECK_INTERVAL_MS: u64 = 60_000;

/// cpuminer fallback difficulty. When `userAgent == "cpuminer"` and the
/// initial difficulty is below [`CPUMINER_HIGH_DIFF_THRESHOLD`], the
/// session difficulty is pinned to this value.
pub(crate) const CPUMINER_FALLBACK_DIFFICULTY: f64 = 0.1;

/// Above this initial difficulty, the cpuminer fallback is skipped (the
/// session was deliberately started at high diff — typically a stress
/// test, not a real CPU miner).
pub(crate) const CPUMINER_HIGH_DIFF_THRESHOLD: f64 = 1_000_000.0;

/// Default vardiff target submission rate per minute. Used when the
/// port doesn't override it.
pub(crate) const DEFAULT_TARGET_SHARES_PER_MINUTE: f64 = 6.0;

/// Default initial session difficulty fallback when a port doesn't supply
/// one and the miner doesn't successfully negotiate via
/// `mining.suggest_difficulty`.
pub(crate) const DEFAULT_INITIAL_DIFFICULTY: f64 = 16_384.0;

/// Default pool identifier embedded in the coinbase scriptsig (after the
/// BIP-34 height push, before the extranonce slot). Dropped at coinbase-
/// build time if the resulting scriptsig would exceed 100 bytes.
pub const DEFAULT_POOL_IDENTIFIER: &str = "Public-Pool";

/// Process-wide configuration: bitcoin network, pool identity, lifecycle
/// constants. Held in an `Arc` and shared across all connections.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub network: Network,
    /// Embedded in the coinbase scriptsig. Dropped if the resulting
    /// scriptsig would exceed the 100-byte consensus limit.
    pub pool_identifier: String,
    /// Job/template retire-and-age-out parameters for the registry.
    /// Starts at [`LifecycleConfig::DEFAULT`]; production overrides only
    /// `retention_ms` (`[stratum] job_retention_ms`).
    pub lifecycle: LifecycleConfig,
    /// How often each connection re-evaluates its vardiff target.
    pub difficulty_check_interval_ms: u64,
    /// Whether vardiff may use elapsed silence as evidence and walk a
    /// quiet session's difficulty down (see [`bp_vardiff`]'s module doc,
    /// "Silence easing"). Off by default — it changes retarget behaviour
    /// for every session, so operators switch it on per deployment.
    pub vardiff_silence_easing: bool,
    /// When `true`, every inbound JSON-RPC line and every outbound
    /// frame the per-connection task writes is logged at DEBUG with
    /// `📨 RX:` / `📤 TX:` prefixes. Heavy — only enable in staging.
    pub protocol_debug: bool,
    /// When `true`, emit per-share diagnostic traces at DEBUG
    /// (`🎯 Share difficulty` + `✅ Share accepted`). Separate from
    /// [`Self::protocol_debug`] (raw frame dumps) so operators can tail
    /// per-share difficulty without the full JSON-RPC firehose.
    pub share_logs: bool,
    /// When `true`, log the pool-internal submit→ack latency (µs from the
    /// inbound `mining.submit` line being read to its response being
    /// written) at INFO, one line per accepted/rejected share. Mirrors
    /// the SV2 path; both are driven by the unified `debug.submit_latency`
    /// config so operators get one switch for SV1 + SV2.
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

    /// Validate cross-field invariants. Called by the server before any
    /// connection is accepted.
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
    /// Starting difficulty for new sessions on this port. The cpuminer
    /// fallback and the suggest-difficulty handshake may lower it; the
    /// `minimum_difficulty` floor (when > 0) is enforced on both.
    pub initial_difficulty: f64,
    /// When `false`, `mining.suggest_difficulty` is rejected with the
    /// "Suggest difficulty is disabled for this connection" error.
    pub allow_suggested_difficulty: bool,
    /// Target submission rate per minute. The vardiff engine retargets
    /// to keep observed shares/min close to this.
    pub target_shares_per_minute: f64,
    /// Payout-mode routing for shares accepted on this port. Solo gets
    /// per-miner coinbase; PPLNS shares a window-aggregated payout;
    /// GroupSolo uses per-group PROP rounds. The PPLNS port overrides
    /// any group membership the address has — the port choice is the
    /// session-level opt-out signal.
    pub payout_mode: MiningMode,
    /// VarDiff floor. When `> 0`, the per-session retarget will never
    /// drop below this value, and `mining.suggest_difficulty` is clamped
    /// to at least this. Used on payout-mode ports to keep sub-dust
    /// devices off the ledger.
    pub minimum_difficulty: f64,
}

impl PortConfig {
    /// Construct a `PortConfig` with production defaults for `port`, leaving the
    /// initial difficulty for the caller to set (no sensible default —
    /// solo ports run very different starts than PPLNS ones).
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

    /// Clamp the configured start: if `initial_difficulty` is non-finite or
    /// non-positive, fall back to `DEFAULT_INITIAL_DIFFICULTY`; if the
    /// minimum-difficulty floor is set, raise the initial to meet it.
    ///
    /// Returns the effective starting difficulty that the connection's
    /// first `mining.set_difficulty` should advertise.
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
        // initial_difficulty may be NaN/0 in the raw struct — the
        // effective value clamps that, but negatives are still rejected
        // as a configuration error.
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
        // job_retention_ms must be ≥ stale_grace_ms — a job has to survive
        // at least the grace window to be classifiable.
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
        // Check that non-finite values default to 16384.
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
        // Check that values are clamped to minimum difficulty when set.
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
        // When raw is non-finite AND a floor is set, fall back to 16384
        // then clamp to floor.
        let mut p = port(3333, f64::NAN);
        p.minimum_difficulty = 100_000.0;
        assert_eq!(p.effective_initial_difficulty(), 100_000.0);
    }
}
