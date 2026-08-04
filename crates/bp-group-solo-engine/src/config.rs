// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngineConfig` — engine-wide tunables.
//!
//! Per-group settings (`finder_bonus_sats`, `round_reset_preset`,
//! `round_reset_timezone`, `round_reset_interval_days`) live in the
//! `pplns_group` DB row keyed by `groupId`. The engine reads those
//! on demand at `get_payout_distribution` / round-reset time. Only
//! knobs that apply across *all* groups live here.
//!
//! Several fee/min-payout/weight-budget knobs are intentionally duplicated
//! with `bp_pplns_engine::config::PplnsEngineConfig`: each engine owns its own
//! typed config and `bin/blitzpool` populates both from the TOML. They are NOT
//! one source — `[group_fees]` carries this engine's fee address, percent and
//! weight budget, `[pplns]` the other's, and they routinely differ (a pool can
//! run 1 % PPLNS and 1.5 % on the group lane). Only the fee **address** falls
//! back from `[group_fees].address` to `[pplns].fee_address`.

use bp_common::{AddressId, Sats};
use bp_pplns::{
    validate_fee_payout_budget, FeePayoutBudgetError, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DEFAULT_MIN_PAYOUT_SATS,
};

/// Engine-wide construction knobs.
#[derive(Debug, Clone)]
pub struct GroupSoloEngineConfig {
    /// Coinbase output that receives the pool fee — and, under the weight
    /// model, the §4 residual `pay_P`. **Required**, and
    /// [`Self::try_new`] refuses without it, exactly as the PPLNS engine
    /// does (the check lives in the one shared
    /// `bp_pplns::validate_fee_payout_budget`, so the two cannot drift).
    ///
    /// Resolved from `[group_fees].address` with a fallback to
    /// `[pplns].fee_address`; a pool that sets neither cannot pay a
    /// Group-Solo block correctly and will not boot.
    pub fee_address: Option<AddressId>,

    /// Pool fee % as f64 (`[0.0, 100.0]`).
    pub fee_percent: f64,

    /// Operational minimum on-chain payout. A member below this gets NO
    /// output, and their share falls into the §4 residual — i.e. to the pool
    /// (`WithheldValue::ToPool`). There is no group ledger and no
    /// carry-forward: Group-Solo remembers nothing between blocks, which is
    /// what `GroupService`'s coinbase-capacity cap on membership buys.
    /// Clamped upward to `DUST_LIMIT_SATS` (546).
    pub min_payout_sats: Sats,

    /// Coinbase weight budget (WU). Handed straight to bitcoin-core
    /// over the Group-Solo TDP IPC stream — there is no `bitcoin.conf`
    /// knob to keep in sync. `[group_fees] coinbase_weight_budget`;
    /// floored at `bp_pplns::MIN_COINBASE_WEIGHT_BUDGET`.
    pub coinbase_weight_budget: u32,

    /// Per-(group, finder) snapshot TTL in seconds. Defaults to 1h.
    pub snapshot_ttl_secs: u32,

    /// Blocks between subsidy halvings on the network this pool runs
    /// on — the input to the settlement gate's floor
    /// (`bp_share::block_subsidy_sats`). NOT an operator knob: it is
    /// derived from the configured network at boot, because regtest
    /// halves every 150 blocks and the mainnet 210 000 would make
    /// every regtest block past height 150 look like it had burned
    /// part of its own subsidy.
    pub subsidy_halving_interval: u32,
}

impl Default for GroupSoloEngineConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: 0.0,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            snapshot_ttl_secs: 3_600,
            subsidy_halving_interval: bp_share::SUBSIDY_HALVING_INTERVAL,
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
            self.fee_address.as_ref().map(|a| a.as_str()),
            self.fee_percent,
            self.min_payout_sats.0,
            self.coinbase_weight_budget,
        )?;
        if self.snapshot_ttl_secs == 0 {
            return Err(ConfigError::ZeroUnsignedField {
                field: "snapshot_ttl_secs",
            });
        }
        Ok(self)
    }
}

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

    /// A config that differs from [`GroupSoloEngineConfig::default`] only in having a
    /// usable pool-output recipient. The default deliberately does NOT —
    /// see `the_default_config_is_refused_because_it_has_no_fee_address`.
    fn valid() -> GroupSoloEngineConfig {
        GroupSoloEngineConfig {
            fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).expect("valid")),
            ..GroupSoloEngineConfig::default()
        }
    }

    /// The pool output is structural under §4, so there is no such thing
    /// as a usable config without one — and a pool that boots without it
    /// pays 100 % of every block to whichever miner connected.
    #[test]
    fn the_default_config_is_refused_because_it_has_no_fee_address() {
        assert_eq!(
            GroupSoloEngineConfig::default().try_new().unwrap_err(),
            ConfigError::MissingFeeAddress
        );
    }

    /// Shape-valid but unparseable is the same failure with a likelier
    /// cause (a typo), and `AddressId` does not catch it.
    #[test]
    fn a_typo_in_the_fee_address_is_refused() {
        let typo = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLX";
        let cfg = GroupSoloEngineConfig {
            fee_address: Some(AddressId::new(typo).expect("shape ok")),
            ..GroupSoloEngineConfig::default()
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
        let cfg = GroupSoloEngineConfig {
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
        let cfg = GroupSoloEngineConfig {
            fee_percent: 105.0,
            ..valid()
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
            ..valid()
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
            ..valid()
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
            ConfigError::WeightBudgetTooLow { .. }
        ));
    }

    #[test]
    fn zero_snapshot_ttl_rejects() {
        let cfg = GroupSoloEngineConfig {
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

    /// A non-zero fee still validates. (The `fee_suppressed()` helper this
    /// used to also assert on is gone: it answered "is there a fee output?"
    /// with `fee_address.is_none() || fee_percent <= 0.0`, and §4 makes the
    /// pool output structural at every fee. Nothing in production read it —
    /// the same dead assumption that put `max_coinbase_outputs` one over.)
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
