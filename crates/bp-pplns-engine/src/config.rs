// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed knobs for the PPLNS engine: the `[pplns]` TOML section plus a few
//! internal tunables, validated by [`PplnsEngineConfig::try_new`] before boot.

use bp_common::{AddressId, Sats};
use bp_pplns::{
    validate_fee_payout_budget, FeePayoutBudgetError, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DEFAULT_MIN_PAYOUT_SATS,
};

/// PPLNS-engine construction knobs; [`Self::new`] fills every knob but the
/// fee address with its default.
#[derive(Debug, Clone)]
pub struct PplnsEngineConfig {
    /// Receives the pool fee and the ext 0x0003 residual `pay_P`; without a
    /// pool output every job would pay the whole block to one miner.
    pub fee_address: AddressId,

    /// Percent, `[0.0, 100.0]`.
    pub fee_percent: f64,

    /// Smaller amounts stay as ledger credit. At least `DUST_LIMIT_SATS`,
    /// below that Bitcoin Core will not relay the output.
    pub min_payout_sats: Sats,

    /// Weight units, handed to bitcoin-core over TDP; no `bitcoin.conf` knob
    /// to keep in sync. Floored at `bp_pplns::MIN_COINBASE_WEIGHT_BUDGET`.
    pub coinbase_weight_budget: u32,

    /// `window_size = factor * network_difficulty`.
    pub window_factor: f64,

    /// The TTL is what bounds the snapshot keyspace. Sized to outlive every
    /// job built on the snapshot: an active job lives until the next block,
    /// and a block interval past the default 2 h is about one block in
    /// 160,000 at a 10-minute mean (e^-12). Not sized against the confirmation
    /// window: a found block carries its snapshot in the parked blob, so
    /// settlement never needs it.
    pub snapshot_ttl_secs: u32,

    /// Shares per window bucket. Boot-time only on a populated window: raising
    /// it puts new shares below the live bucket ids, where the trim drops them
    /// (see `WindowStore`'s `bucket_shares`).
    pub bucket_shares: u64,

    /// How often buffered `lastAcceptedShareAt` updates flush to Postgres.
    pub touch_flush_interval_secs: u32,

    /// Switches the daily dust-sweep cron.
    pub dust_sweep_enabled: bool,

    /// Days without a share before a balance owner counts as gone.
    pub abandoned_balance_days: u32,

    /// PPLNS-port vardiff floor, mirrored here so `/api/pplns/fees` can show
    /// it without depending on bp-stratum-v1.
    pub min_difficulty: u64,
}

impl PplnsEngineConfig {
    /// Every knob at its default; the fee address has none, so it is given.
    pub fn new(fee_address: AddressId) -> Self {
        Self {
            fee_address,
            fee_percent: 0.0,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            window_factor: 4.0,
            snapshot_ttl_secs: 7_200,
            bucket_shares: crate::window::DEFAULT_BUCKET_SHARES,
            touch_flush_interval_secs: 60,
            dust_sweep_enabled: true,
            abandoned_balance_days: 90,
            min_difficulty: 500,
        }
    }

    /// Return the config or its first violation, in struct field order.
    pub fn try_new(self) -> Result<Self, ConfigError> {
        // Fee, min-payout and budget checks are shared with Group-Solo and
        // Blockparty.
        validate_fee_payout_budget(
            self.fee_percent,
            self.min_payout_sats.0,
            self.coinbase_weight_budget,
        )?;
        if self.bucket_shares == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "bucket_shares",
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
    /// The fee / min-payout / coinbase-budget checks every pool-fee mode
    /// shares; see [`FeePayoutBudgetError`].
    #[error(transparent)]
    FeePayoutBudget(#[from] FeePayoutBudgetError),
    #[error("{field} must be > 0, got 0")]
    ZeroUnsignedField { field: &'static str },
}

/// Epoch-ms before which an owner counts as gone. The one place that turns
/// `abandoned_balance_days` into a boundary, for the sweep, the window's
/// inactivity rule and the ledger summary alike.
pub(crate) fn abandoned_cutoff_ms(now_ms: i64, abandoned_days: u32) -> i64 {
    now_ms - (abandoned_days as i64) * 86_400_000
}

#[cfg(test)]
mod tests {
    use bp_pplns::{COINBASE_BASE_WEIGHT, DUST_LIMIT_SATS};

    use super::*;
    const TEST_FEE_ADDRESS: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    /// [`PplnsEngineConfig::new`] around a usable pool-output recipient.
    fn valid() -> PplnsEngineConfig {
        PplnsEngineConfig::new(AddressId::new(TEST_FEE_ADDRESS).expect("valid"))
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
    fn a_non_zero_fee_validates() {
        PplnsEngineConfig {
            fee_address: AddressId::new(TEST_FEE_ADDRESS).unwrap(),
            fee_percent: 1.5,
            ..valid()
        }
        .try_new()
        .expect("active fee config validates");
    }
}
