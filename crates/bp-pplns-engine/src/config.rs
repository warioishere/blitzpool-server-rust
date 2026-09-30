// SPDX-License-Identifier: AGPL-3.0-or-later

//! `PplnsEngineConfig` — typed knobs for the PPLNS service-engine.
//!
//! Mirrors the `[pplns]` TOML section plus a few engine-internal tunables
//! (trim batch size, snapshot TTL). Construction is fallible via
//! [`PplnsEngineConfig::try_new`] so field-level errors surface before the
//! engine spins up. Listener port and vardiff settings belong to
//! bp-stratum-v1/v2 and are not duplicated here.

use bp_common::{AddressId, Sats};
use bp_pplns::{
    validate_fee_payout_budget, FeePayoutBudgetError, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DEFAULT_MIN_PAYOUT_SATS,
};

/// PPLNS-engine construction knobs.
///
/// All fields validated by [`PplnsEngineConfig::try_new`]. [`Default`] is a
/// field-filler for the `..Default::default()` spread, NOT a usable config:
/// it leaves `fee_address` unset, which `try_new` refuses. The fee address
/// has no sensible default, and "none" would pay every block to one miner.
#[derive(Debug, Clone)]
pub struct PplnsEngineConfig {
    /// Coinbase output that receives the pool fee — and, under the weight
    /// model, the §4 residual `pay_P`. **Required**, and
    /// [`Self::try_new`] refuses without it.
    ///
    /// `build_weight_distribution` cannot produce a distribution without a
    /// pool output; without one every PPLNS job would be a solo coinbase
    /// paying the whole block to one miner. The `Option` exists only for the
    /// reader's public `/api/pplns/fees` shape; construction guarantees
    /// `Some`.
    pub fee_address: Option<AddressId>,

    /// Pool fee % as f64 (e.g. `1.5` for 1.5%). Must be `[0.0, 100.0]`.
    /// `[pplns] fee_percent` in the TOML.
    pub fee_percent: f64,

    /// Pool operational minimum payout. Outputs below this stay as
    /// pending credit in the signed ledger. Always clamped upward to
    /// `DUST_LIMIT_SATS` (546) — values below violate Bitcoin Core relay
    /// policy. `[pplns] min_payout_sats` (default 5000).
    pub min_payout_sats: Sats,

    /// Coinbase weight budget (WU). Handed straight to bitcoin-core
    /// over the TDP IPC stream (`tdp_constraint_for_budget`) — there is
    /// no `bitcoin.conf` knob to keep in sync. Default 50_000 (≈400
    /// P2WPKH outputs); floored at `bp_pplns::MIN_COINBASE_WEIGHT_BUDGET`.
    /// `[pplns] coinbase_weight_budget`.
    pub coinbase_weight_budget: u32,

    /// Sliding-window size factor: `window_size = factor *
    /// network_difficulty`. Defaults to `4` (no env override).
    pub window_factor: f64,

    /// Snapshot TTL in seconds.
    ///
    /// One snapshot is written per distinct distribution and only the
    /// applied block's own key is deleted, so the TTL is what bounds the
    /// keyspace. The Redis->Postgres backup skips per-job snapshot keys
    /// (`redis_backup::is_per_job_snapshot`), so an expired snapshot is gone
    /// from every store.
    ///
    /// A snapshot is only useful while a job built from it can be mined; a
    /// job is GC-eligible 10 min (`bp_jobs_lifecycle`'s `retention_ms`)
    /// after it retired. The default of 1200 s is twice that.
    ///
    /// ⚠️ Deliberately NOT sized against the confirmation window: the gated
    /// apply can land after the TTL expires. A found block's snapshot is
    /// resolved at the block-found instant and carried in the parked blob
    /// (`PplnsEngine::weight_snapshot_for_block_found`), so settlement never
    /// depends on this value.
    pub snapshot_ttl_secs: u32,

    /// Shares per count-bucket for the window (default 10000). Higher = less
    /// Redis memory + coarser trim; lower = more memory + finer.
    ///
    /// Effectively a boot-time-only value on a populated window: the bucket
    /// id is `floor(pplns:counter / bucket_shares)` over a counter nothing
    /// ever resets, so raising it puts new shares in a bucket id *below* the
    /// live set, where the trim drops them again. See `WindowStore`'s
    /// `bucket_shares` field for the arithmetic and the safe direction.
    pub bucket_shares: u64,

    /// Touch-buffer flush interval. The hot path accumulates
    /// `lastAcceptedShareAt` updates in a SwapBuffer; every `N` seconds
    /// the buffer drains to a bulk `UPDATE pplns_balance …`. Defaults to
    /// 60s, aligned with the `bp-stats` flush cadence so DB-write
    /// spikes coalesce.
    pub touch_flush_interval_secs: u32,

    /// Whether the daily 03:00 UTC dust-sweep cron runs.
    /// `[pplns] dust_sweep_enabled`. Manual sweeps via admin trigger remain
    /// available independent of this flag.
    pub dust_sweep_enabled: bool,

    /// A balance row is sweep-eligible once `lastAcceptedShareAt` is
    /// older than this many days. `[pplns] abandoned_balance_days`
    /// (default 90).
    pub abandoned_balance_days: u32,

    /// PPLNS-port vardiff floor — sub-`min_difficulty` retargets are
    /// clamped back up. Mirrored from the per-port toml so the
    /// `/api/pplns/fees` endpoint can render the operator's gate
    /// without taking a dep on bp-stratum-v1.
    pub min_difficulty: u64,

    /// Blocks between subsidy halvings on the network this pool runs
    /// on — the input to the settlement gate's floor
    /// (`bp_share::block_subsidy_sats`). NOT an operator knob: it is
    /// derived from the configured network at boot, because regtest
    /// halves every 150 blocks and the mainnet 210 000 would make every
    /// regtest block past height 150 look like it burned part of its
    /// subsidy.
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
            bucket_shares: crate::window::DEFAULT_BUCKET_SHARES,
            touch_flush_interval_secs: 60,
            dust_sweep_enabled: true,
            abandoned_balance_days: 90,
            min_difficulty: 500,
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
        // pass through this engine's ConfigError unchanged (field order preserved).
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
}

/// Field-level validation errors for [`PplnsEngineConfig::try_new`].
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ConfigError {
    /// The fee / min-payout / coinbase-budget checks shared with the other
    /// payout engine; see [`FeePayoutBudgetError`].
    #[error(transparent)]
    FeePayoutBudget(#[from] FeePayoutBudgetError),
    #[error("window_factor must be > 0.0 and finite, got {value}")]
    InvalidWindowFactor { value: f64 },
    #[error("{field} must be > 0, got 0")]
    ZeroUnsignedField { field: &'static str },
}

/// Epoch-ms before which an owner counts as gone after `abandoned_days`
/// without a share. The one place that turns `[pplns]
/// abandoned_balance_days` into a boundary: the dust sweep's abandoned
/// credits, the window trim's age rule and the ledger summary's abandoned
/// buckets all read it through here.
pub(crate) fn abandoned_cutoff_ms(now_ms: i64, abandoned_days: u32) -> i64 {
    now_ms - (abandoned_days as i64) * 86_400_000
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

    /// The pool output is structural under §4; without a fee address every
    /// block would pay 100 % to one miner.
    #[test]
    fn the_default_config_is_refused_because_it_has_no_fee_address() {
        assert_eq!(
            PplnsEngineConfig::default().try_new().unwrap_err(),
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::MissingFeeAddress)
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
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::InvalidFeeAddress {
                value: typo.to_string()
            })
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
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::InvalidFeePercent { value: -0.1 })
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
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::InvalidFeePercent { value: 100.5 })
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
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::InvalidFeePercent { value }) => {
                assert!(value.is_nan())
            }
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
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::MinPayoutBelowDust {
                value: 545,
                dust: DUST_LIMIT_SATS,
            })
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
        assert!(matches!(
            err,
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::WeightBudgetTooLow { .. })
        ));
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

    /// A non-zero fee validates.
    #[test]
    fn a_non_zero_fee_validates() {
        PplnsEngineConfig {
            fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).unwrap()),
            fee_percent: 1.5,
            ..valid()
        }
        .try_new()
        .expect("active fee config validates");
    }
}
