// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngineConfig` — engine-wide tunables.
//!
//! Per-group settings (`finder_bonus_sats`, `round_reset_preset`,
//! `round_reset_timezone`, `round_reset_interval_days`) live in the
//! `pplns_group` DB row keyed by `groupId`. The engine reads those
//! on demand at `get_payout_distribution` / round-reset time. Only
//! knobs that apply across *all* groups live here.
//!
//! Several fee/min-payout/weight-budget knobs are intentionally
//! duplicated with `bp_pplns_engine::config::PplnsEngineConfig` — both
//! engines read from the same `PPLNS_*` env vars independently. Each
//! engine owns its own typed config, and the bin/blitzpool wiring
//! populates both from one env source.

use bp_common::{AddressId, Sats};
use bp_pplns::{
    validate_fee_payout_budget, FeePayoutBudgetError, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DEFAULT_MIN_PAYOUT_SATS,
};

/// Engine-wide construction knobs.
#[derive(Debug, Clone)]
pub struct GroupSoloEngineConfig {
    /// Coinbase output that receives the pool fee. `None` ⇒ no fee
    /// output. Group-Solo reuses the PPLNS-side fee env var
    /// (`PPLNS_FEE_ADDRESS`) by convention.
    pub fee_address: Option<AddressId>,

    /// Pool fee % as f64 (`[0.0, 100.0]`). Reuses `PPLNS_FEE_PERCENT`
    /// at the env layer.
    pub fee_percent: f64,

    /// Operational minimum on-chain payout. Outputs below this stay
    /// as positive `pendingSats` in the group ledger until they
    /// either clear in a future block or get swept after dormancy.
    /// Clamped upward to `DUST_LIMIT_SATS` (546). Reuses
    /// `PPLNS_MIN_PAYOUT_SATS`.
    pub min_payout_sats: Sats,

    /// Coinbase weight budget (WU). Must match `bitcoin.conf`
    /// `blockreservedweight`. Reuses `PPLNS_COINBASE_WEIGHT_BUDGET`.
    pub coinbase_weight_budget: u32,

    /// Per-(group, finder) snapshot TTL in seconds. Defaults to 1h.
    pub snapshot_ttl_secs: u32,

    /// Whether the daily 03:00 UTC group-dust-sweep runs.
    pub dust_sweep_enabled: bool,

    /// Group-Solo legacy dust-sweep dormancy threshold (days).
    /// Defaults to 30. Shorter than PPLNS's 90d because group balances
    /// are all-positive and have no counterparty to wait for.
    pub dormant_balance_days: u32,
}

impl Default for GroupSoloEngineConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: 0.0,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            snapshot_ttl_secs: 3_600,
            dust_sweep_enabled: true,
            dormant_balance_days: 30,
        }
    }
}

impl GroupSoloEngineConfig {
    /// Validate field-level invariants. Mirrors
    /// `PplnsEngineConfig::try_new` so the two engines accept the
    /// same env values cleanly.
    pub fn try_new(self) -> Result<Self, ConfigError> {
        // The fee / min-payout / coinbase-budget invariants are shared with
        // the PPLNS engine; the checks + thresholds live in bp-pplns and map
        // into this engine's ConfigError via `From` (field order preserved).
        validate_fee_payout_budget(
            self.fee_percent,
            self.min_payout_sats.0,
            self.coinbase_weight_budget,
        )?;
        if self.snapshot_ttl_secs == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "snapshot_ttl_secs",
            });
        }
        if self.dormant_balance_days == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "dormant_balance_days",
            });
        }
        Ok(self)
    }

    /// `true` if the fee output is suppressed for this engine — either
    /// no address configured or `fee_percent <= 0`.
    pub fn fee_suppressed(&self) -> bool {
        self.fee_address.is_none() || self.fee_percent <= 0.0
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ConfigError {
    #[error("fee_percent must be in [0.0, 100.0] and finite, got {value}")]
    InvalidFeePercent { value: f64 },
    #[error("min_payout_sats must be ≥ DUST_LIMIT_SATS ({dust}), got {value}")]
    MinPayoutBelowDustLimit { value: i64, dust: u64 },
    #[error("coinbase_weight_budget must be > {min} (base + safety margin), got {value}")]
    WeightBudgetTooLow { value: u32, min: u32 },
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
        GroupSoloEngineConfig::default()
            .try_new()
            .expect("default ok");
    }

    #[test]
    fn fee_percent_negative_rejects() {
        let cfg = GroupSoloEngineConfig {
            fee_percent: -0.1,
            ..GroupSoloEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidFeePercent { value: -0.1 }
        );
    }

    #[test]
    fn fee_percent_above_hundred_rejects() {
        let cfg = GroupSoloEngineConfig {
            fee_percent: 105.0,
            ..GroupSoloEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::InvalidFeePercent { value: 105.0 }
        );
    }

    #[test]
    fn fee_percent_nan_rejects() {
        let cfg = GroupSoloEngineConfig {
            fee_percent: f64::NAN,
            ..GroupSoloEngineConfig::default()
        };
        match cfg.try_new().unwrap_err() {
            ConfigError::InvalidFeePercent { value } => assert!(value.is_nan()),
            other => panic!("expected InvalidFeePercent, got {other:?}"),
        }
    }

    #[test]
    fn min_payout_below_dust_rejects() {
        let cfg = GroupSoloEngineConfig {
            min_payout_sats: Sats(545),
            ..GroupSoloEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::MinPayoutBelowDustLimit { .. }
        ));
    }

    #[test]
    fn min_payout_exactly_dust_accepts() {
        let cfg = GroupSoloEngineConfig {
            min_payout_sats: Sats(DUST_LIMIT_SATS as i64),
            ..GroupSoloEngineConfig::default()
        };
        cfg.try_new().expect("dust-limit ok");
    }

    #[test]
    fn weight_budget_too_low_rejects() {
        let cfg = GroupSoloEngineConfig {
            coinbase_weight_budget: COINBASE_BASE_WEIGHT,
            ..GroupSoloEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::WeightBudgetTooLow { .. }
        ));
    }

    #[test]
    fn zero_snapshot_ttl_rejects() {
        let cfg = GroupSoloEngineConfig {
            snapshot_ttl_secs: 0,
            ..GroupSoloEngineConfig::default()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::ZeroUnsignedField {
                field: "snapshot_ttl_secs",
            }
        );
    }

    #[test]
    fn zero_dormant_balance_days_rejects() {
        let cfg = GroupSoloEngineConfig {
            dormant_balance_days: 0,
            ..GroupSoloEngineConfig::default()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::ZeroUnsignedField {
                field: "dormant_balance_days",
            }
        ));
    }

    #[test]
    fn fee_suppressed_when_no_address() {
        let cfg = GroupSoloEngineConfig::default();
        assert!(cfg.fee_suppressed());
    }

    #[test]
    fn fee_suppressed_when_zero_percent() {
        let cfg = GroupSoloEngineConfig {
            fee_address: Some(AddressId::new("bc1qfee0000000000000000000000000").unwrap()),
            fee_percent: 0.0,
            ..GroupSoloEngineConfig::default()
        };
        assert!(cfg.fee_suppressed());
    }

    #[test]
    fn fee_active_when_address_and_percent() {
        let cfg = GroupSoloEngineConfig {
            fee_address: Some(AddressId::new("bc1qfee0000000000000000000000000").unwrap()),
            fee_percent: 2.0,
            ..GroupSoloEngineConfig::default()
        };
        assert!(!cfg.fee_suppressed());
        cfg.try_new().expect("active fee config validates");
    }

    #[test]
    fn group_solo_default_dormant_days_is_30() {
        // Confirms the divergence from PPLNS's 90d default — group
        // balances have no counterparty to wait for.
        assert_eq!(GroupSoloEngineConfig::default().dormant_balance_days, 30);
    }
}
