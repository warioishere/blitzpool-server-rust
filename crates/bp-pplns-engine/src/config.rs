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
/// All fields validated by [`PplnsEngineConfig::try_new`]. [`Default`] is a
/// field-filler for the `..Default::default()` spread, NOT a usable config:
/// it leaves `fee_address` unset, which `try_new` refuses. There is no
/// sensible default for the address a pool's fee is paid to, and defaulting
/// it to "none" is exactly the shape that pays every block to one miner.
#[derive(Debug, Clone)]
pub struct PplnsEngineConfig {
    /// Coinbase output that receives the pool fee — and, under the weight
    /// model, the §4 residual `pay_P`. **Required**, and
    /// [`Self::try_new`] refuses without it.
    ///
    /// It used to be documented as optional ("fee suppressed"). It never
    /// was: `build_weight_distribution` cannot produce a distribution
    /// without a pool output, so a pool that started without one served
    /// every PPLNS job a solo coinbase paying the whole block to one
    /// miner. The `Option` survives only because the type is threaded
    /// through the reader's public `/api/pplns/fees` shape; construction
    /// guarantees it is `Some`.
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
            self.fee_address.as_ref().map(|a| a.as_str()),
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
    #[error(
        "no fee_address configured — the pool output is structural under the \
         weight model (SV2 ext 0x0003 §4). Without it every block of this mode \
         falls back to a solo coinbase paying 100 % to one miner"
    )]
    MissingFeeAddress,
    #[error(
        "fee_address {value:?} is not a usable payout address — same effect as \
         none at all: every block falls back to a solo coinbase"
    )]
    InvalidFeeAddress { value: String },
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
            FeePayoutBudgetError::MissingFeeAddress => ConfigError::MissingFeeAddress,
            FeePayoutBudgetError::InvalidFeeAddress { value } => {
                ConfigError::InvalidFeeAddress { value }
            }
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
    const TEST_FEE_ADDRESS: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    /// A config that differs from [`PplnsEngineConfig::default`] only in having a
    /// usable pool-output recipient. The default deliberately does NOT —
    /// see `the_default_config_is_refused_because_it_has_no_fee_address`.
    fn valid() -> PplnsEngineConfig {
        PplnsEngineConfig {
            fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).expect("valid")),
            ..PplnsEngineConfig::default()
        }
    }

    /// The pool output is structural under §4, so there is no such thing
    /// as a usable config without one — and a pool that boots without it
    /// pays 100 % of every block to whichever miner connected.
    #[test]
    fn the_default_config_is_refused_because_it_has_no_fee_address() {
        assert_eq!(
            PplnsEngineConfig::default().try_new().unwrap_err(),
            ConfigError::MissingFeeAddress
        );
    }

    /// Shape-valid but unparseable is the same failure with a likelier
    /// cause (a typo), and `AddressId` does not catch it.
    #[test]
    fn a_typo_in_the_fee_address_is_refused() {
        let typo = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLX";
        let cfg = PplnsEngineConfig {
            fee_address: Some(AddressId::new(typo).expect("shape ok")),
            ..PplnsEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidFeeAddress {
                value: typo.to_string()
            }
        );
    }

    #[test]
    fn default_validates_clean() {
        valid().try_new().expect("default ok");
    }

    #[test]
    fn fee_percent_negative_rejects() {
        let cfg = PplnsEngineConfig {
            fee_percent: -0.1,
            ..valid()
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
            ..valid()
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
            ..valid()
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
            ..valid()
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
            ..valid()
        };
        cfg.try_new().expect("dust-limit exact ok");
    }

    #[test]
    fn weight_budget_below_minimum_rejects() {
        let cfg = PplnsEngineConfig {
            coinbase_weight_budget: COINBASE_BASE_WEIGHT,
            ..valid()
        };
        let err = cfg.try_new().unwrap_err();
        assert!(matches!(err, ConfigError::WeightBudgetTooLow { .. }));
    }

    #[test]
    fn window_factor_zero_rejects() {
        let cfg = PplnsEngineConfig {
            window_factor: 0.0,
            ..valid()
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
            ..valid()
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
            ..valid()
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
            ..valid()
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
            ..valid()
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
            ..valid()
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
        let cfg = valid();
        assert!(cfg.fee_suppressed());
    }

    #[test]
    fn fee_suppressed_when_zero_percent() {
        let cfg = PplnsEngineConfig {
            fee_address: Some(AddressId::new("bc1qexample0000000000000000000000").unwrap()),
            fee_percent: 0.0,
            ..valid()
        };
        assert!(cfg.fee_suppressed());
    }

    #[test]
    fn fee_active_when_address_and_percent() {
        // A REAL address: this used to read `bc1qexample000…`, which
        // `AddressId` accepts and `bitcoin::Address` does not — so the test
        // asserted that a config the coinbase builder cannot use validates
        // cleanly.
        let cfg = PplnsEngineConfig {
            fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).unwrap()),
            fee_percent: 1.5,
            ..valid()
        };
        assert!(!cfg.fee_suppressed());
        cfg.try_new().expect("active fee config validates");
    }
}
