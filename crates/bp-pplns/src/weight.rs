// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output weight constants + per-address type detection.

use std::str::FromStr;

use bitcoin::{Address, AddressType};

pub use bp_common::DUST_LIMIT_SATS;

/// Pool's default minimum on-chain payout. Outputs below stay as pending
/// credit in the signed ledger until they accumulate past the threshold.
pub const DEFAULT_MIN_PAYOUT_SATS: u64 = 5_000;

pub const DEFAULT_COINBASE_WEIGHT_BUDGET: u32 = 50_000;

/// Coinbase structural weight (version + input + output-count varint +
/// locktime + witness reserved value, with headroom for varint growth).
pub const COINBASE_BASE_WEIGHT: u32 = 328;

/// P2TR / P2WSH upper-bound output weight — used as the worst-case
/// fallback when an address's type cannot be detected.
pub const COINBASE_OUTPUT_WEIGHT: u32 = 172;

/// Segwit-commitment OP_RETURN output weight (~38-byte script → ~47 bytes
/// serialized → ~188 WU).
pub const COINBASE_WITNESS_COMMITMENT_WEIGHT: u32 = 188;

/// Headroom held back from the configured coinbase weight budget. Defends
/// against quiet drift between the constants here and the real serialized
/// coinbase weight (pool-identifier byte changes, future address types,
/// varint growth past 65 535 outputs).
pub const BUDGET_SAFETY_MARGIN_WU: u32 = 200;

/// What the blockspace cut reserves before the first miner output: the
/// structure, the segwit commitment and the pool output, which is structural
/// under §4 and counted at the worst-case type.
pub(crate) const CUT_RESERVED_WEIGHT: u32 =
    COINBASE_BASE_WEIGHT + COINBASE_WITNESS_COMMITMENT_WEIGHT + COINBASE_OUTPUT_WEIGHT;

/// Smallest budget that publishes one miner output: what the blockspace cut
/// reserves plus one worst-case ([`COINBASE_OUTPUT_WEIGHT`]) output. Below it
/// the cut publishes nothing and the §4 residual (`pay_P = T − Σpay`) hands
/// the pool the whole block, hence a hard config floor.
pub const MIN_COINBASE_WEIGHT_BUDGET: u32 =
    CUT_RESERVED_WEIGHT + BUDGET_SAFETY_MARGIN_WU + COINBASE_OUTPUT_WEIGHT;

/// Hard cap on the Group-Solo finder bonus in ppm of the miner cut (50 %),
/// a typo guard rather than policy. Must stay below 1 000 000: the bonus
/// weight is `S·ppm/(1e6 − ppm)` and the divisor has to remain positive.
pub const MAX_FINDER_BONUS_PPM: u32 = 500_000;

/// Whether `bitcoin::Address` can parse the address, network-agnostic.
/// An unparseable address would abort the whole coinbase build for every
/// miner; dropping it leaves the row unpaid this block but still in the
/// ledger. The network is checked elsewhere (`require_network`).
pub fn is_valid_payout_address(address: &str) -> bool {
    !address.is_empty() && Address::from_str(address).is_ok()
}

/// Per-output weight in WU. Unparseable or unknown types fall back to
/// `COINBASE_OUTPUT_WEIGHT` so the trim never undercounts.
pub fn output_weight_for_address(address: &str) -> u32 {
    if address.is_empty() {
        return 0;
    }
    let Ok(unchecked) = Address::from_str(address) else {
        return COINBASE_OUTPUT_WEIGHT;
    };
    // `assume_checked` only flips the type marker to read the script type;
    // the network is not validated here.
    match unchecked.assume_checked().address_type() {
        Some(AddressType::P2wpkh) => 124,
        Some(AddressType::P2sh) => 128,
        Some(AddressType::P2pkh) => 136,
        Some(AddressType::P2wsh) => 172,
        Some(AddressType::P2tr) => 172,
        _ => COINBASE_OUTPUT_WEIGHT,
    }
}

/// Worst-case miner outputs a budget can hold, assuming every output is the
/// heaviest type; at least 1. The pool output is reserved at every fee, as
/// the blockspace cut does: one slot too many would let `GroupService` admit
/// a member the coinbase cannot pay, whose share then goes to the pool.
pub fn max_coinbase_outputs(budget: u32) -> u64 {
    let fixed = CUT_RESERVED_WEIGHT + BUDGET_SAFETY_MARGIN_WU;
    if budget <= fixed {
        return 1;
    }
    ((budget - fixed) / COINBASE_OUTPUT_WEIGHT) as u64
}

/// Validation error for the fee / min-payout / coinbase-budget knobs shared
/// by the PPLNS and Group-Solo configs, so the checks and boot messages live
/// in one place.
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum FeePayoutBudgetError {
    /// No pool-output recipient configured. Structural under §4, not a
    /// preference — see [`validate_fee_payout_budget`].
    #[error(
        "no fee_address configured — the pool output is structural under the \
         weight model (SV2 ext 0x0003 §4). Without it every block of this mode \
         falls back to a solo coinbase paying 100 % to one miner"
    )]
    MissingFeeAddress,
    /// Configured but not a usable payout address; `AddressId` only checks
    /// the shape, so a typo gets this far.
    #[error(
        "fee_address {value:?} is not a usable payout address — same effect as \
         none at all: every block falls back to a solo coinbase"
    )]
    InvalidFeeAddress { value: String },
    /// `fee_percent` was non-finite or outside `[0.0, 100.0]`.
    #[error("fee_percent must be in [0.0, 100.0] and finite, got {value}")]
    InvalidFeePercent { value: f64 },
    /// `min_payout_sats` below the relay-policy dust floor.
    #[error("min_payout_sats must be ≥ DUST_LIMIT_SATS ({dust}), got {value}")]
    MinPayoutBelowDust { value: i64, dust: u64 },
    /// `coinbase_weight_budget` below [`MIN_COINBASE_WEIGHT_BUDGET`], which
    /// would hand the pool every block. `min` is the smallest accepted value.
    #[error("coinbase_weight_budget must be > {min} (base + safety margin), got {value}")]
    WeightBudgetTooLow { value: u32, min: u32 },
}

/// Validate the fee/payout/budget invariants both payout engines share.
/// The fee address comes first because it is structural: without the §4
/// pool output no distribution exists, and the solo fallback pays 100 % of
/// the block to whichever miner connected, with nothing booked.
pub fn validate_fee_payout_budget(
    fee_address: Option<&str>,
    fee_percent: f64,
    min_payout_sats: i64,
    coinbase_weight_budget: u32,
) -> Result<(), FeePayoutBudgetError> {
    let address = fee_address
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or(FeePayoutBudgetError::MissingFeeAddress)?;
    // `AddressId` accepts any short ASCII string; a typo would fail later in
    // the coinbase builder with the same 100 %-to-one-miner outcome.
    if !is_valid_payout_address(address) {
        return Err(FeePayoutBudgetError::InvalidFeeAddress {
            value: address.to_string(),
        });
    }
    if !fee_percent.is_finite() || !(0.0..=100.0).contains(&fee_percent) {
        return Err(FeePayoutBudgetError::InvalidFeePercent { value: fee_percent });
    }
    if min_payout_sats < DUST_LIMIT_SATS as i64 {
        return Err(FeePayoutBudgetError::MinPayoutBelowDust {
            value: min_payout_sats,
            dust: DUST_LIMIT_SATS,
        });
    }
    // Below one miner output the §4 residual hands the pool the whole block.
    if coinbase_weight_budget < MIN_COINBASE_WEIGHT_BUDGET {
        return Err(FeePayoutBudgetError::WeightBudgetTooLow {
            value: coinbase_weight_budget,
            min: MIN_COINBASE_WEIGHT_BUDGET,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_weight_by_address_type() {
        // P2WPKH: bc1q + 42 chars total, 22-byte script → 124 WU
        assert_eq!(
            output_weight_for_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            124
        );
        // P2PKH: 1... legacy
        assert_eq!(
            output_weight_for_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            136
        );
        // P2SH: 3... legacy
        assert_eq!(
            output_weight_for_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            128
        );
        // P2TR: bc1p... taproot
        assert_eq!(
            output_weight_for_address(
                "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
            ),
            172
        );
    }

    /// Real serialized non-witness weight of a coinbase TxOut paying
    /// `address`: `(8-byte value + scriptlen varint + scriptPubKey) × 4`.
    /// Coinbase outputs carry no witness data, so every byte is base data
    /// and counts ×4 toward weight (BIP-141).
    fn real_output_weight(address: &str) -> u32 {
        let script = Address::from_str(address)
            .expect("valid test address")
            .assume_checked()
            .script_pubkey();
        let scriptlen = script.len();
        let varint = if scriptlen < 0xfd {
            1
        } else if scriptlen <= 0xffff {
            3
        } else {
            5
        };
        ((8 + varint + scriptlen) as u32) * 4
    }

    /// Pins the per-output weight constants to the real serialized TxOut
    /// weight; an undershoot lets the coinbase overshoot its reserved
    /// weight and core rejects the found block.
    #[test]
    fn output_weight_constants_never_undershoot_real_serialized_txout() {
        let cases = [
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "P2WPKH"),
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "P2PKH"),
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "P2SH"),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                "P2WSH",
            ),
            (
                "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
                "P2TR",
            ),
        ];
        for (addr, kind) in cases {
            let real = real_output_weight(addr);
            let estimated = output_weight_for_address(addr);
            assert!(
                estimated >= real,
                "{kind} weight constant {estimated} UNDERSHOOTS real serialized weight \
                 {real} — coinbase could overshoot the reserved budget → core rejects the block"
            );
            // Exact, or the budget math and the autoscaler drift.
            assert_eq!(
                estimated, real,
                "{kind} weight constant {estimated} should equal the real serialized TxOut \
                 weight {real}"
            );
        }
    }

    /// Pins the segwit-commitment OP_RETURN weight to its real serialized size.
    #[test]
    fn witness_commitment_weight_matches_real_serialized_size() {
        let script_len = 1 /* OP_RETURN */ + 1 /* OP_PUSHBYTES_36 */ + 36;
        let real = ((8 + 1 + script_len) as u32) * 4;
        assert_eq!(
            COINBASE_WITNESS_COMMITMENT_WEIGHT, real,
            "witness-commitment weight constant must equal the real serialized OP_RETURN TxOut weight"
        );
    }

    #[test]
    fn output_weight_empty_is_zero() {
        assert_eq!(output_weight_for_address(""), 0);
    }

    /// Pins that the pool output always costs one member slot.
    #[test]
    fn max_outputs_reserves_a_slot_for_the_pool_output() {
        let fixed =
            COINBASE_BASE_WEIGHT + BUDGET_SAFETY_MARGIN_WU + COINBASE_WITNESS_COMMITMENT_WEIGHT;
        // One worst-case output of headroom above the non-pool overhead
        // still fits NO member: that slot is the pool's.
        assert_eq!(max_coinbase_outputs(fixed + COINBASE_OUTPUT_WEIGHT), 1);
        // Two, and exactly one member fits.
        assert_eq!(max_coinbase_outputs(fixed + 2 * COINBASE_OUTPUT_WEIGHT), 1);
        assert_eq!(max_coinbase_outputs(fixed + 3 * COINBASE_OUTPUT_WEIGHT), 2);
    }

    #[test]
    fn max_outputs_degenerate_budget_returns_at_least_one() {
        assert_eq!(max_coinbase_outputs(0), 1);
        assert_eq!(max_coinbase_outputs(COINBASE_BASE_WEIGHT), 1);
    }

    /// A usable pool-output recipient.
    const FEE: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    #[test]
    fn validate_fee_payout_budget_accepts_sane_values() {
        assert_eq!(
            validate_fee_payout_budget(Some(FEE), 1.5, DEFAULT_MIN_PAYOUT_SATS as i64, 50_000),
            Ok(())
        );
    }

    /// Pins that a missing or unparseable fee address is refused at construction.
    #[test]
    fn a_pool_without_a_usable_fee_address_is_refused() {
        // Absent, empty and whitespace-only are the same operator mistake.
        for missing in [None, Some(""), Some("   ")] {
            assert_eq!(
                validate_fee_payout_budget(missing, 1.5, 5_000, 50_000),
                Err(FeePayoutBudgetError::MissingFeeAddress),
                "{missing:?} must be refused"
            );
        }
        // Shape-valid for `AddressId`, but not a payout address.
        let typo = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLX";
        assert!(
            bp_common::AddressId::new(typo).is_ok(),
            "precondition: the shape check passes it, which is why this \
             check has to exist"
        );
        assert_eq!(
            validate_fee_payout_budget(Some(typo), 1.5, 5_000, 50_000),
            Err(FeePayoutBudgetError::InvalidFeeAddress {
                value: typo.to_string()
            })
        );
    }

    #[test]
    fn validate_fee_payout_budget_rejects_in_field_order() {
        // fee_address checked first — it is structural, the rest are knobs.
        assert_eq!(
            validate_fee_payout_budget(None, 101.0, 5_000, 50_000),
            Err(FeePayoutBudgetError::MissingFeeAddress)
        );
        // then fee_percent.
        assert_eq!(
            validate_fee_payout_budget(Some(FEE), 101.0, 5_000, 50_000),
            Err(FeePayoutBudgetError::InvalidFeePercent { value: 101.0 })
        );
        assert!(matches!(
            validate_fee_payout_budget(Some(FEE), f64::NAN, 5_000, 50_000),
            Err(FeePayoutBudgetError::InvalidFeePercent { .. })
        ));
        // then min_payout dust floor.
        assert_eq!(
            validate_fee_payout_budget(Some(FEE), 1.0, (DUST_LIMIT_SATS as i64) - 1, 50_000),
            Err(FeePayoutBudgetError::MinPayoutBelowDust {
                value: (DUST_LIMIT_SATS as i64) - 1,
                dust: DUST_LIMIT_SATS,
            })
        );
        // then budget floor.
        let too_low = MIN_COINBASE_WEIGHT_BUDGET - 1;
        assert_eq!(
            validate_fee_payout_budget(Some(FEE), 1.0, 5_000, too_low),
            Err(FeePayoutBudgetError::WeightBudgetTooLow {
                value: too_low,
                min: MIN_COINBASE_WEIGHT_BUDGET
            })
        );
    }

    /// Pins the budget floor to what the blockspace cut reserves before the
    /// first miner output, not a smaller structural-looking number.
    #[test]
    fn budget_floor_is_what_the_blockspace_cut_actually_reserves() {
        // Exactly the cut's own arithmetic, spelled out independently.
        let cut_reserves =
            COINBASE_BASE_WEIGHT + COINBASE_WITNESS_COMMITMENT_WEIGHT + COINBASE_OUTPUT_WEIGHT;
        let smallest_that_fits_one_output =
            cut_reserves + COINBASE_OUTPUT_WEIGHT + BUDGET_SAFETY_MARGIN_WU;
        assert_eq!(
            MIN_COINBASE_WEIGHT_BUDGET, smallest_that_fits_one_output,
            "the floor must track the cut's reservation, not a looser guess"
        );
        assert_eq!(MIN_COINBASE_WEIGHT_BUDGET, 1_060);

        // `base + margin` alone is not enough.
        let old_floor = COINBASE_BASE_WEIGHT + BUDGET_SAFETY_MARGIN_WU;
        assert!(old_floor < MIN_COINBASE_WEIGHT_BUDGET);
        for dead in [old_floor + 1, 700, 1_012, MIN_COINBASE_WEIGHT_BUDGET - 1] {
            assert!(
                validate_fee_payout_budget(Some(FEE), 1.0, 5_000, dead).is_err(),
                "budget {dead} publishes no miner output and must be refused"
            );
        }
        // `min` is the smallest accepted value, not the largest rejected one.
        assert_eq!(
            validate_fee_payout_budget(Some(FEE), 1.0, 5_000, MIN_COINBASE_WEIGHT_BUDGET),
            Ok(())
        );
    }

    #[test]
    fn output_weight_garbage_returns_worst_case() {
        assert_eq!(
            output_weight_for_address("definitely-not-an-address"),
            COINBASE_OUTPUT_WEIGHT
        );
    }
}
