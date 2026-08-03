// SPDX-License-Identifier: AGPL-3.0-or-later

//! `PplnsEngineConfig` — typed knobs for the PPLNS service-engine.
//!
//! Mirrors the `PPLNS_*` / `DUST_SWEEP_*` env-var groups in
//! `blitzpool.env`, plus a few engine-internal tunables (trim batch size,
//! snapshot TTL). Construction is fallible via [`PplnsEngineConfig::try_new`]
//! so the caller sees field-level errors before the engine spins up.
//!
//! Only knobs the *engine itself* needs at construction live here. Things
//! like the listener port, vardiff start-difficulty, warmup-shares-per-
//! session are bp-stratum-v1/v2's concern (warmup specifically lives in
//! `SessionState` per the 2026-05-16 decision) and not duplicated here.

use bp_common::{AddressId, Sats};
use bp_pplns::{
    validate_fee_payout_budget, FeePayoutBudgetError, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DEFAULT_MIN_PAYOUT_SATS,
};

/// PPLNS-engine construction knobs.
///
/// All fields validated by [`PplnsEngineConfig::try_new`]; the [`Default`]
/// impl returns values that pass validation and are tuned for mainnet
/// operation.
#[derive(Debug, Clone)]
pub struct PplnsEngineConfig {
    /// Coinbase output that receives the pool fee. `None` ⇒ no fee
    /// output (rare in production but supported — an empty
    /// `PPLNS_FEE_ADDRESS` is treated as "fee suppressed").
    pub fee_address: Option<AddressId>,

    /// Pool fee % as f64 (e.g. `1.5` for 1.5%). Must be `[0.0, 100.0]`.
    /// Read from `PPLNS_FEE_PERCENT` env var as a float.
    pub fee_percent: f64,

    /// Pool operational minimum payout. Outputs below this stay as
    /// pending credit in the signed ledger. Always clamped upward to
    /// `DUST_LIMIT_SATS` (546) — values below violate Bitcoin Core relay
    /// policy. Env var: `PPLNS_MIN_PAYOUT_SATS` (default 5000).
    pub min_payout_sats: Sats,

    /// Coinbase weight budget (WU). Handed straight to bitcoin-core
    /// over the TDP IPC stream (`tdp_constraint_for_budget`) — there is
    /// no `bitcoin.conf` knob to keep in sync. Default 50_000 (≈400
    /// P2WPKH outputs); floored at `bp_pplns::MIN_COINBASE_WEIGHT_BUDGET`.
    /// Env var: `PPLNS_COINBASE_WEIGHT_BUDGET`.
    pub coinbase_weight_budget: u32,

    /// Sliding-window size factor: `window_size = factor *
    /// network_difficulty`. Defaults to `4` (no env override).
    pub window_factor: f64,

    /// Snapshot TTL in seconds.
    ///
    /// Snapshots are keyed by the payout list they distribute, so one is
    /// written per distinct distribution — roughly (connections × template
    /// rate) — and only the applied block's own key is deleted. The TTL is
    /// therefore what bounds the keyspace. Nothing else does: the 10-minute
    /// `pplns:*` Redis→Postgres backup deliberately SKIPS per-job snapshot
    /// keys (`redis_backup::is_per_job_snapshot`), so once one expires its
    /// settlement inputs are gone from every store.
    ///
    /// A snapshot is only useful while a job built from it can still be
    /// mined, and a job is GC-eligible once `bp_jobs_lifecycle`'s
    /// `retention_ms` (10 min) has passed since it retired. The default of
    /// 1200 s is twice that — comfortably past any job's life, without
    /// hoarding an hour's worth of dead distributions the way the previous
    /// 3600 did. That value made sense when a single shared key was
    /// overwritten in place; per-job keys it merely multiplies.
    ///
    /// This is deliberately NOT sized against the confirmation window, and
    /// a found block must not depend on it being: at depth 3 the gated
    /// apply lands ~20 min after the block, against a TTL whose clock
    /// started when the winning job was built. That race is lost about half
    /// the time. The Core therefore resolves a found block's snapshot at
    /// the block-found instant and carries it in the parked blob — see
    /// `PplnsEngine::weight_snapshot_for_block_found`. Raising this value
    /// would only make the old race less visible, not correct.
    pub snapshot_ttl_secs: u32,

    /// Trim batch size — legacy per-share trim tunable. No longer used by the
    /// bucketed window (which trims whole buckets); kept for config compat.
    pub trim_batch_size: u32,

    /// Shares per count-bucket for the window (`PPLNS_BUCKET_SHARES`,
    /// default 10000). MUST match the TS pool's value since they share Redis.
    /// Higher = less memory + coarser trim; lower = more memory + finer.
    pub bucket_shares: u64,

    /// Touch-buffer flush interval. The hot path accumulates
    /// `lastAcceptedShareAt` updates in a SwapBuffer; every `N` seconds
    /// the buffer drains to a bulk `UPDATE pplns_balance …`. Defaults to
    /// 60s, aligned with the `bp-stats` flush cadence so DB-write
    /// spikes coalesce.
    pub touch_flush_interval_secs: u32,

    /// Whether the daily 03:00 UTC dust-sweep cron runs. Env var:
    /// `DUST_SWEEP_ENABLED`. Manual sweeps via admin trigger remain
    /// available independent of this flag.
    pub dust_sweep_enabled: bool,

    /// A balance row is sweep-eligible once `lastAcceptedShareAt` is
    /// older than this many days. Env var: `ABANDONED_BALANCE_DAYS`
    /// (default 90).
    pub abandoned_balance_days: u32,

    /// PPLNS-port vardiff floor — sub-`min_difficulty` retargets are
    /// clamped back up. Mirrored from the per-port toml so the
    /// `/api/pplns/fees` endpoint can render the operator's gate
    /// without taking a dep on bp-stratum-v1.
    pub min_difficulty: u64,

    /// Per-session ledger-warmup gate: first N accepted shares of a
    /// new session are validated but not credited to the PPLNS
    /// ledger. Mirrored from the per-port toml for the same reason
    /// as `min_difficulty`.
    pub warmup_shares: u32,

    /// Blocks between subsidy halvings on the network this pool runs
    /// on — the input to the settlement gate's floor
    /// (`bp_share::block_subsidy_sats`). NOT an operator knob: it is
    /// derived from the configured network at boot, because regtest
    /// halves every 150 blocks and the mainnet 210 000 would make
    /// every regtest block past height 150 look like it had burned
    /// part of its own subsidy.
    pub subsidy_halving_interval: u32,
}

impl Default for PplnsEngineConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: 0.0,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            window_factor: 4.0,
            snapshot_ttl_secs: 1_200,
            trim_batch_size: 100,
            bucket_shares: crate::window::DEFAULT_BUCKET_SHARES,
            touch_flush_interval_secs: 60,
            dust_sweep_enabled: true,
            abandoned_balance_days: 90,
            min_difficulty: 500,
            warmup_shares: 5,
            subsidy_halving_interval: bp_share::SUBSIDY_HALVING_INTERVAL,
        }
    }
}

impl PplnsEngineConfig {
    /// Validate field-level invariants and return a config or the first
    /// violation. Field-order matches the struct so error messages are
    /// predictable in tests.
    pub fn try_new(self) -> Result<Self, ConfigError> {
        // The fee / min-payout / coinbase-budget invariants are shared with
        // the Group-Solo engine; the checks + thresholds live in bp-pplns and
        // map into this engine's ConfigError via `From` (field order preserved).
        validate_fee_payout_budget(
            self.fee_percent,
            self.min_payout_sats.0,
            self.coinbase_weight_budget,
        )?;
        if !self.window_factor.is_finite() || self.window_factor <= 0.0 {
            return Err(ConfigError::InvalidWindowFactor {
                value: self.window_factor,
            });
        }
        if self.snapshot_ttl_secs == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "snapshot_ttl_secs",
            });
        }
        if self.trim_batch_size == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "trim_batch_size",
            });
        }
        if self.bucket_shares == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "bucket_shares",
            });
        }
        if self.touch_flush_interval_secs == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "touch_flush_interval_secs",
            });
        }
        if self.abandoned_balance_days == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "abandoned_balance_days",
            });
        }
        Ok(self)
    }

    /// Fee output disabled? Either no address configured or a zero
    /// percent (fee suppressed when `feePercent === 0`).
    pub fn fee_suppressed(&self) -> bool {
        self.fee_address.is_none() || self.fee_percent <= 0.0
    }
}

/// Field-level validation errors for [`PplnsEngineConfig::try_new`].
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ConfigError {
    #[error("fee_percent must be in [0.0, 100.0] and finite, got {value}")]
    InvalidFeePercent { value: f64 },
    #[error("min_payout_sats must be ≥ DUST_LIMIT_SATS ({dust}), got {value}")]
    MinPayoutBelowDustLimit { value: i64, dust: u64 },
    #[error("coinbase_weight_budget must be > {min} (base + safety margin), got {value}")]
    WeightBudgetTooLow { value: u32, min: u32 },
    #[error("window_factor must be > 0.0 and finite, got {value}")]
    InvalidWindowFactor { value: f64 },
    #[error("{field} must be > 0, got 0")]
    ZeroUnsignedField { field: &'static str },
}

impl From<FeePayoutBudgetError> for ConfigError {
    fn from(e: FeePayoutBudgetError) -> Self {
        match e {
            FeePayoutBudgetError::InvalidFeePercent { value } => {
                ConfigError::InvalidFeePercent { value }
            }
            FeePayoutBudgetError::MinPayoutBelowDust { value, dust } => {
                ConfigError::MinPayoutBelowDustLimit { value, dust }
            }
            FeePayoutBudgetError::WeightBudgetTooLow { value, min } => {
                ConfigError::WeightBudgetTooLow { value, min }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bp_pplns::{COINBASE_BASE_WEIGHT, DUST_LIMIT_SATS};

    use super::*;

    #[test]
    fn default_validates_clean() {
        PplnsEngineConfig::default().try_new().expect("default ok");
    }

    #[test]
    fn fee_percent_negative_rejects() {
        let cfg = PplnsEngineConfig {
            fee_percent: -0.1,
            ..PplnsEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidFeePercent { value: -0.1 }
        );
    }

    #[test]
    fn fee_percent_above_hundred_rejects() {
        let cfg = PplnsEngineConfig {
            fee_percent: 100.5,
            ..PplnsEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidFeePercent { value: 100.5 }
        );
    }

    #[test]
    fn fee_percent_nan_rejects() {
        let cfg = PplnsEngineConfig {
            fee_percent: f64::NAN,
            ..PplnsEngineConfig::default()
        };
        // NaN can't compare equal to NaN in the error variant; just
        // check the variant tag.
        match cfg.try_new().unwrap_err() {
            ConfigError::InvalidFeePercent { value } => assert!(value.is_nan()),
            other => panic!("expected InvalidFeePercent, got {other:?}"),
        }
    }

    #[test]
    fn min_payout_below_dust_limit_rejects() {
        let cfg = PplnsEngineConfig {
            min_payout_sats: Sats(545),
            ..PplnsEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::MinPayoutBelowDustLimit {
                value: 545,
                dust: DUST_LIMIT_SATS,
            }
        );
    }

    #[test]
    fn min_payout_exactly_dust_limit_accepts() {
        let cfg = PplnsEngineConfig {
            min_payout_sats: Sats(DUST_LIMIT_SATS as i64),
            ..PplnsEngineConfig::default()
        };
        cfg.try_new().expect("dust-limit exact ok");
    }

    #[test]
    fn weight_budget_below_minimum_rejects() {
        let cfg = PplnsEngineConfig {
            coinbase_weight_budget: COINBASE_BASE_WEIGHT,
            ..PplnsEngineConfig::default()
        };
        let err = cfg.try_new().unwrap_err();
        assert!(matches!(err, ConfigError::WeightBudgetTooLow { .. }));
    }

    #[test]
    fn window_factor_zero_rejects() {
        let cfg = PplnsEngineConfig {
            window_factor: 0.0,
            ..PplnsEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidWindowFactor { .. }
        ));
    }

    #[test]
    fn window_factor_negative_rejects() {
        let cfg = PplnsEngineConfig {
            window_factor: -1.0,
            ..PplnsEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidWindowFactor { .. }
        ));
    }

    #[test]
    fn window_factor_infinite_rejects() {
        let cfg = PplnsEngineConfig {
            window_factor: f64::INFINITY,
            ..PplnsEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidWindowFactor { .. }
        ));
    }

    #[test]
    fn zero_snapshot_ttl_rejects() {
        let cfg = PplnsEngineConfig {
            snapshot_ttl_secs: 0,
            ..PplnsEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::ZeroUnsignedField {
                field: "snapshot_ttl_secs",
            }
        );
    }

    #[test]
    fn zero_trim_batch_size_rejects() {
        let cfg = PplnsEngineConfig {
            trim_batch_size: 0,
            ..PplnsEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::ZeroUnsignedField {
                field: "trim_batch_size",
            }
        ));
    }

    #[test]
    fn zero_abandoned_balance_days_rejects() {
        let cfg = PplnsEngineConfig {
            abandoned_balance_days: 0,
            ..PplnsEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::ZeroUnsignedField {
                field: "abandoned_balance_days",
            }
        ));
    }

    #[test]
    fn fee_suppressed_when_no_address() {
        let cfg = PplnsEngineConfig::default();
        assert!(cfg.fee_suppressed());
    }

    #[test]
    fn fee_suppressed_when_zero_percent() {
        let cfg = PplnsEngineConfig {
            fee_address: Some(AddressId::new("bc1qexample0000000000000000000000").unwrap()),
            fee_percent: 0.0,
            ..PplnsEngineConfig::default()
        };
        assert!(cfg.fee_suppressed());
    }

    #[test]
    fn fee_active_when_address_and_percent() {
        let cfg = PplnsEngineConfig {
            fee_address: Some(AddressId::new("bc1qexample0000000000000000000000").unwrap()),
            fee_percent: 1.5,
            ..PplnsEngineConfig::default()
        };
        assert!(!cfg.fee_suppressed());
        cfg.try_new().expect("active fee config validates");
    }
}
