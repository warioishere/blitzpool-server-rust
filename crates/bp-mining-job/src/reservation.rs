// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a pool-built coinbase adds to its block, reserved with bitcoin-core
//! through TDP `CoinbaseOutputConstraints`: core builds the template for the
//! rest of the block, so a coinbase that outgrows the reservation in size or
//! in sigops makes the block invalid.

use bp_template_distribution::TdpCoinbaseConstraints;

/// Headroom over the byte-equivalent of a coinbase weight budget, so a
/// mismatch between the pre-trim weight estimate and the serialised size
/// never yields a coinbase larger than bitcoin-core reserved.
pub const COINBASE_SIZE_HEADROOM_BYTES: u32 = 256;

/// Serialised size of a P2PKH output: value 8, script length 1, script 25.
const P2PKH_OUTPUT_BYTES: u32 = 34;

/// Legacy sigops weigh this much in a block's sigop cost.
const WITNESS_SCALE_FACTOR: u32 = 4;

/// The bitcoin-core reservation for a coinbase weight budget. Boot, the
/// autoscaler and the Blockparty reservation all take it from here, so
/// core's reservation never drifts from what the trimmer fits.
pub fn coinbase_constraints_for_budget(weight_budget: u32) -> TdpCoinbaseConstraints {
    // Non-witness outputs weigh ~4 × bytes; ceil errs on the side of more
    // headroom.
    let max_additional_size = weight_budget
        .div_ceil(4)
        .saturating_add(COINBASE_SIZE_HEADROOM_BYTES);
    TdpCoinbaseConstraints {
        max_additional_size,
        max_additional_sigops: coinbase_sigop_cost_bound(max_additional_size),
    }
}

/// The most sigop cost a pool coinbase whose extra outputs take at most
/// `max_additional_size` bytes can carry. bitcoin-core counts legacy sigops
/// in every output script and in the coinbase scriptSig: each P2PKH payout
/// has an `OP_CHECKSIG`, the other payout types and the witness commitment
/// have none, and the pool's identifier and extranonce are pushed data.
fn coinbase_sigop_cost_bound(max_additional_size: u32) -> u16 {
    let payout_sigops = max_additional_size / P2PKH_OUTPUT_BYTES;
    u16::try_from(payout_sigops.saturating_mul(WITNESS_SCALE_FACTOR)).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{Address, Network, PubkeyHash, Transaction};

    use super::*;
    use crate::coinbase::{
        build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
    };

    /// The worst coinbase the pool can build for a budget: every payout P2PKH
    /// and as many as fit the reservation, every extranonce byte
    /// `OP_CHECKMULTISIG`. Its sigop cost, counted from the serialised
    /// transaction the way core counts it, is the payouts' alone and within
    /// the reservation; a reservation of 0 is the control.
    #[test]
    fn the_worst_case_coinbase_fits_its_sigop_reservation() {
        let constraints = coinbase_constraints_for_budget(4_000);
        let payout_count = (constraints.max_additional_size / P2PKH_OUTPUT_BYTES) as usize;
        let reward = 5_000_000_000u64;
        let each = reward / payout_count as u64;
        let payouts: Vec<PayoutEntry> = (0..payout_count)
            .map(|i| PayoutEntry {
                address: Address::p2pkh(
                    PubkeyHash::from_byte_array([i as u8; 20]),
                    Network::Bitcoin,
                )
                .to_string(),
                sats: if i == 0 {
                    reward - each * (payout_count as u64 - 1)
                } else {
                    each
                },
            })
            .collect();
        // BIP-34 height push, then a witness commitment like core's.
        let prefix = [0x03, 0x40, 0x0d, 0x03];
        let mut commitment = vec![0u8; 8];
        commitment.push(0x26);
        commitment.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
        commitment.extend_from_slice(&[0xCC; 32]);
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFF_FFFF,
            coinbase_tx_value_remaining: reward,
            coinbase_tx_outputs: &commitment,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        // No byte of it is a push opcode, so an unpushed slot's sigops would
        // be counted here rather than swallowed by a push.
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "blitzpool",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();
        let raw = job.witness_coinbase_with_extranonce(&[0xAE; 4], &[0xAE; 8]);
        let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(
            tx.output.len(),
            payout_count + 1,
            "precondition: every payout built"
        );

        let legacy_sigops = tx.input[0].script_sig.count_sigops_legacy()
            + tx.output
                .iter()
                .map(|o| o.script_pubkey.count_sigops_legacy())
                .sum::<usize>();
        assert_eq!(
            legacy_sigops, payout_count,
            "the pushed identifier and extranonce count nothing"
        );
        let cost = legacy_sigops * WITNESS_SCALE_FACTOR as usize;
        assert!(cost > 0, "control: a reservation of 0 does not cover it");
        assert!(
            cost <= usize::from(constraints.max_additional_sigops),
            "sigop cost {cost} over the reservation {}",
            constraints.max_additional_sigops
        );
    }
}
