// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output weight constants + per-address type detection.

use std::str::FromStr;

use bitcoin::{Address, AddressType};
use bp_common::Sats;

/// Bitcoin Core's default dust policy value for P2PKH at
/// `dustRelayFee = 3000 sat/kvB`. Outputs below this can't be relayed as
/// standard transactions.
pub const DUST_LIMIT_SATS: u64 = 546;

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

/// Resolve the operational minimum-payout setting from raw env input.
/// Clamped to ≥ DUST_LIMIT_SATS (Bitcoin Core relay policy floor).
pub fn resolve_min_payout_sats(raw: Option<&str>) -> Sats {
    let parsed = raw
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .map(|v| v as u64)
        .unwrap_or(DEFAULT_MIN_PAYOUT_SATS);
    let value = parsed.max(DUST_LIMIT_SATS);
    Sats(value as i64)
}

/// Network-agnostic syntactic check that an address can become a real
/// coinbase output. Returns `false` for anything `bitcoin::Address`
/// can't parse (junk / migration artifacts / seed-test rows like
/// `synthseed800001`).
///
/// Defensive sanitizer for the distribution input: an unparseable
/// address that reaches `build_payout_outputs` (bp-mining-job) fails
/// `address_to_script`, which aborts the *entire* coinbase build — so
/// one junk ledger row would block every miner's job. Dropping it from
/// the distribution is strictly safer (the row is simply not paid this
/// block; it stays in the ledger).
///
/// This does NOT validate the network — a wrong-network address (e.g.
/// a `tb1…` testnet address on a mainnet pool) parses here but would
/// still fail `require_network` at coinbase-build time. That case can't
/// arise from the normal share path (addresses are network-checked at
/// connection time) and is left to the build-time check.
pub fn is_valid_payout_address(address: &str) -> bool {
    !address.is_empty() && Address::from_str(address).is_ok()
}

/// Per-output weight in WU for the given address.
/// Falls back to `COINBASE_OUTPUT_WEIGHT` (P2TR upper bound) when the
/// address is empty, unparseable, or of an unknown type — guarantees the
/// trim never undercounts.
pub fn output_weight_for_address(address: &str) -> u32 {
    if address.is_empty() {
        return 0;
    }
    let Ok(unchecked) = Address::from_str(address) else {
        return COINBASE_OUTPUT_WEIGHT;
    };
    // `address_type()` lives on `Address<NetworkChecked>`. `assume_checked`
    // does not validate the network — it only flips the type-system marker
    // so we can read the script type without committing to a Network.
    match unchecked.assume_checked().address_type() {
        Some(AddressType::P2wpkh) => 124,
        Some(AddressType::P2sh) => 128,
        Some(AddressType::P2pkh) => 136,
        Some(AddressType::P2wsh) => 172,
        Some(AddressType::P2tr) => 172,
        _ => COINBASE_OUTPUT_WEIGHT,
    }
}

/// Worst-case maximum number of miner payout outputs the given coinbase
/// weight budget can hold. Pessimistic on purpose: assumes every output is
/// the heaviest standard address type (P2TR / P2WSH = `COINBASE_OUTPUT_WEIGHT`),
/// so real P2WPKH-heavy populations fit *more* than this. The fixed coinbase
/// overhead is reserved first — structural base, the budget safety margin, the
/// segwit-commitment OP_RETURN, and (when `has_fee_output`) the one pool-fee
/// output. Returns at least 1 even on a degenerate sub-overhead budget.
pub fn max_coinbase_outputs(budget: u32, has_fee_output: bool) -> u64 {
    let fee_w = if has_fee_output {
        COINBASE_OUTPUT_WEIGHT
    } else {
        0
    };
    let fixed =
        COINBASE_BASE_WEIGHT + BUDGET_SAFETY_MARGIN_WU + COINBASE_WITNESS_COMMITMENT_WEIGHT + fee_w;
    if budget <= fixed {
        return 1;
    }
    ((budget - fixed) / COINBASE_OUTPUT_WEIGHT) as u64
}

/// Field-level validation error for the fee / min-payout / coinbase-budget
/// knobs shared by the PPLNS and Group-Solo engine configs. Each engine maps
/// this into its own `ConfigError` (via `From`) so the three identical checks
/// — and their thresholds — live in exactly one place.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FeePayoutBudgetError {
    /// `fee_percent` was non-finite or outside `[0.0, 100.0]`.
    InvalidFeePercent { value: f64 },
    /// `min_payout_sats` below the relay-policy dust floor.
    MinPayoutBelowDust { value: i64, dust: u64 },
    /// `coinbase_weight_budget` at/below the structural floor (base + margin).
    WeightBudgetTooLow { value: u32, min: u32 },
}

/// Validate the three fee/payout/budget invariants both payout engines share.
/// The thresholds (dust floor, budget-floor formula) live here so a change
/// applies to every engine at once. Field order matches both engines' old
/// inline checks so error precedence is unchanged.
pub fn validate_fee_payout_budget(
    fee_percent: f64,
    min_payout_sats: i64,
    coinbase_weight_budget: u32,
) -> Result<(), FeePayoutBudgetError> {
    if !fee_percent.is_finite() || !(0.0..=100.0).contains(&fee_percent) {
        return Err(FeePayoutBudgetError::InvalidFeePercent { value: fee_percent });
    }
    if min_payout_sats < DUST_LIMIT_SATS as i64 {
        return Err(FeePayoutBudgetError::MinPayoutBelowDust {
            value: min_payout_sats,
            dust: DUST_LIMIT_SATS,
        });
    }
    // The pure-math layer adds BUDGET_SAFETY_MARGIN_WU to the base weight
    // before subtracting outputs; require at least that floor so callers
    // can't configure a budget that rejects every payout list.
    let min_budget = COINBASE_BASE_WEIGHT + BUDGET_SAFETY_MARGIN_WU;
    if coinbase_weight_budget <= min_budget {
        return Err(FeePayoutBudgetError::WeightBudgetTooLow {
            value: coinbase_weight_budget,
            min: min_budget,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_min_payout_uses_default_when_missing() {
        assert_eq!(
            resolve_min_payout_sats(None),
            Sats(DEFAULT_MIN_PAYOUT_SATS as i64)
        );
    }

    #[test]
    fn resolve_min_payout_uses_default_when_garbage() {
        assert_eq!(resolve_min_payout_sats(Some("notanumber")), Sats(5_000));
    }

    #[test]
    fn resolve_min_payout_clamps_to_dust_limit() {
        // Caller asked for 100 sats — below the relay-policy floor.
        assert_eq!(
            resolve_min_payout_sats(Some("100")),
            Sats(DUST_LIMIT_SATS as i64)
        );
    }

    #[test]
    fn resolve_min_payout_accepts_explicit_higher_value() {
        assert_eq!(resolve_min_payout_sats(Some("10000")), Sats(10_000));
    }

    #[test]
    fn resolve_min_payout_rejects_zero_and_negative() {
        assert_eq!(
            resolve_min_payout_sats(Some("0")),
            Sats(DEFAULT_MIN_PAYOUT_SATS as i64)
        );
        assert_eq!(
            resolve_min_payout_sats(Some("-100")),
            Sats(DEFAULT_MIN_PAYOUT_SATS as i64)
        );
    }

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

    /// CONSENSUS / MONEY guard: the per-output weight constants MUST NOT
    /// undershoot the real serialized TxOut weight. If they did, the
    /// trimmer would keep more outputs than the reserved coinbase budget
    /// can hold → the assembled coinbase overshoots `block_reserved_weight`
    /// → bitcoin-core rejects the found block (a lost block = lost money).
    /// Cross-checks each constant against the actual `script_pubkey()`
    /// serialization (the same script `bp-mining-job::address_to_script`
    /// emits, since both go through `bitcoin`'s `script_pubkey()`).
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
            // The constants are derived to be exact; a divergence means the
            // constant or the script encoding drifted and the budget math
            // (and the autoscaler) would be off.
            assert_eq!(
                estimated, real,
                "{kind} weight constant {estimated} should equal the real serialized TxOut \
                 weight {real}"
            );
        }
    }

    /// Same guard for the segwit-commitment OP_RETURN output the coinbase
    /// always carries (`0x6a 0x24 0xaa21a9ed || <32-byte commit>` = 38-byte
    /// script → 47-byte TxOut → 188 WU).
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

    #[test]
    fn max_outputs_reserves_one_slot_for_the_fee_output() {
        // With a fee output present, exactly one fewer member output fits —
        // the fee output costs the same worst-case slot as any miner output.
        let with_fee = max_coinbase_outputs(50_000, true);
        let without_fee = max_coinbase_outputs(50_000, false);
        assert_eq!(
            without_fee,
            with_fee + 1,
            "the reserved fee output must cost exactly one member slot"
        );
    }

    #[test]
    fn max_outputs_degenerate_budget_returns_at_least_one() {
        // Budget at/below the fixed overhead can't fit any member but never
        // reports zero capacity.
        assert_eq!(max_coinbase_outputs(0, true), 1);
        assert_eq!(max_coinbase_outputs(COINBASE_BASE_WEIGHT, false), 1);
    }

    #[test]
    fn validate_fee_payout_budget_accepts_sane_values() {
        assert_eq!(
            validate_fee_payout_budget(1.5, DEFAULT_MIN_PAYOUT_SATS as i64, 50_000),
            Ok(())
        );
    }

    #[test]
    fn validate_fee_payout_budget_rejects_in_field_order() {
        // fee_percent checked first.
        assert_eq!(
            validate_fee_payout_budget(101.0, 5_000, 50_000),
            Err(FeePayoutBudgetError::InvalidFeePercent { value: 101.0 })
        );
        assert!(matches!(
            validate_fee_payout_budget(f64::NAN, 5_000, 50_000),
            Err(FeePayoutBudgetError::InvalidFeePercent { .. })
        ));
        // then min_payout dust floor.
        assert_eq!(
            validate_fee_payout_budget(1.0, (DUST_LIMIT_SATS as i64) - 1, 50_000),
            Err(FeePayoutBudgetError::MinPayoutBelowDust {
                value: (DUST_LIMIT_SATS as i64) - 1,
                dust: DUST_LIMIT_SATS,
            })
        );
        // then budget floor.
        let min = COINBASE_BASE_WEIGHT + BUDGET_SAFETY_MARGIN_WU;
        assert_eq!(
            validate_fee_payout_budget(1.0, 5_000, min),
            Err(FeePayoutBudgetError::WeightBudgetTooLow { value: min, min })
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
