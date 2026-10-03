// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngineConfig`: knobs that apply to all groups, from
//! `[group_solo]`; per-group settings live in the `pplns_group` row.

use bp_common::{AddressId, Sats};
use bp_pplns::{
    validate_fee_payout_budget, FeePayoutBudgetError, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DEFAULT_MIN_PAYOUT_SATS,
};

/// Engine-wide construction knobs.
#[derive(Debug, Clone)]
pub struct GroupSoloEngineConfig {
    /// Coinbase output that receives the pool fee and the §4 residual
    /// `pay_P`. Required: [`Self::try_new`] refuses without it, because a
    /// Group-Solo block cannot be paid correctly without a pool output.
    pub fee_address: Option<AddressId>,

    /// Pool fee % as f64 (`[0.0, 100.0]`).
    pub fee_percent: f64,

    /// Minimum on-chain payout (at least `DUST_LIMIT_SATS`). A member below it
    /// gets no output and their share goes to the pool (`WithheldValue::ToPool`);
    /// no carry-forward, which holds only while `GroupService` caps membership
    /// at coinbase capacity.
    pub min_payout_sats: Sats,

    /// Coinbase weight budget (WU), handed to bitcoin-core over the TDP IPC
    /// stream so no `bitcoin.conf` knob needs to match.
    pub coinbase_weight_budget: u32,

    /// Blocks between subsidy halvings, the input to the settlement gate's
    /// floor. Derived from the network at boot, not an operator knob: regtest
    /// halves every 150 blocks, and the mainnet value would make later regtest
    /// blocks look like they burned subsidy.
    pub subsidy_halving_interval: u32,
}

impl Default for GroupSoloEngineConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: 0.0,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            subsidy_halving_interval: bp_share::SUBSIDY_HALVING_INTERVAL,
        }
    }
}

impl GroupSoloEngineConfig {
    /// Validate field-level invariants.
    pub fn try_new(self) -> Result<Self, ConfigError> {
        // Shared with the PPLNS engine so both refuse the same configs.
        validate_fee_payout_budget(
            self.fee_address.as_ref().map(|a| a.as_str()),
            self.fee_percent,
            self.min_payout_sats.0,
            self.coinbase_weight_budget,
        )?;
        Ok(self)
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ConfigError {
    /// The fee / min-payout / coinbase-budget checks shared with the other
    /// payout engine; see [`FeePayoutBudgetError`].
    #[error(transparent)]
    FeePayoutBudget(#[from] FeePayoutBudgetError),
}

#[cfg(test)]
mod tests {
    use bp_pplns::{COINBASE_BASE_WEIGHT, DUST_LIMIT_SATS};

    use super::*;
    const TEST_FEE_ADDRESS: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    /// [`GroupSoloEngineConfig::default`] plus a usable pool-output recipient,
    /// which the default deliberately lacks.
    fn valid() -> GroupSoloEngineConfig {
        GroupSoloEngineConfig {
            fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).expect("valid")),
            ..GroupSoloEngineConfig::default()
        }
    }

    /// A config without a fee address is refused.
    #[test]
    fn the_default_config_is_refused_because_it_has_no_fee_address() {
        assert_eq!(
            GroupSoloEngineConfig::default().try_new().unwrap_err(),
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::MissingFeeAddress)
        );
    }

    /// A shape-valid but unparseable fee address is refused.
    #[test]
    fn a_typo_in_the_fee_address_is_refused() {
        let typo = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLX";
        let cfg = GroupSoloEngineConfig {
            fee_address: Some(AddressId::new(typo).expect("shape ok")),
            ..GroupSoloEngineConfig::default()
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
        let cfg = GroupSoloEngineConfig {
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
        let cfg = GroupSoloEngineConfig {
            fee_percent: 105.0,
            ..valid()
        };
        assert_eq!(
            cfg.try_new().unwrap_err(),
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::InvalidFeePercent { value: 105.0 })
        );
    }

    #[test]
    fn fee_percent_nan_rejects() {
        let cfg = GroupSoloEngineConfig {
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
    fn min_payout_below_dust_rejects() {
        let cfg = GroupSoloEngineConfig {
            min_payout_sats: Sats(545),
            ..valid()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::MinPayoutBelowDust { .. })
        ));
    }

    #[test]
    fn min_payout_exactly_dust_accepts() {
        let cfg = GroupSoloEngineConfig {
            min_payout_sats: Sats(DUST_LIMIT_SATS as i64),
            ..valid()
        };
        cfg.try_new().expect("dust-limit ok");
    }

    #[test]
    fn weight_budget_too_low_rejects() {
        let cfg = GroupSoloEngineConfig {
            coinbase_weight_budget: COINBASE_BASE_WEIGHT,
            ..valid()
        };
        assert!(matches!(
            cfg.try_new().unwrap_err(),
            ConfigError::FeePayoutBudget(FeePayoutBudgetError::WeightBudgetTooLow { .. })
        ));
    }

    #[test]
    fn a_non_zero_fee_validates() {
        GroupSoloEngineConfig {
            fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).unwrap()),
            fee_percent: 1.5,
            ..valid()
        }
        .try_new()
        .expect("active fee config validates");
    }
}
