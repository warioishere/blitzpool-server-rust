// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a found block's coinbase ACTUALLY paid: settlement books
//! `claim(T_actual) − actually_paid` from the real coinbase, never from what
//! anyone intended to pay. One decomposition for the pool and JDP paths.

use std::collections::HashMap;

use bitcoin::{Address, Network, Transaction};

/// The per-address payment record of one real coinbase.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActualCoinbase {
    /// Address → sats the coinbase paid it, EXCLUDING the pool output
    /// (output 0). Aggregated per address, so a script paid twice
    /// counts once with the sum.
    pub paid_by_address: HashMap<String, u64>,
    /// The pool output (`pay_P`, output 0 by §4 order), kept apart because
    /// the fee address may also mine and its two outputs must not blend.
    pub pool_paid_sats: u64,
    /// `Σ` of ALL output values = the block's actual revenue `T`.
    pub total_value_sats: u64,
}

impl ActualCoinbase {
    /// Decompose a real coinbase transaction. Output 0 is the pool
    /// output by the §4 output order. Outputs whose script
    /// has no address form (OP_RETURN, witness commitment) carry no
    /// value under §4 and are counted only into `total_value_sats`.
    pub fn from_coinbase(coinbase: &Transaction, network: Network) -> Self {
        let mut paid_by_address: HashMap<String, u64> = HashMap::new();
        let mut pool_paid_sats = 0u64;
        let mut total_value_sats = 0u64;
        for (index, output) in coinbase.output.iter().enumerate() {
            let sats = output.value.to_sat();
            total_value_sats = total_value_sats.saturating_add(sats);
            if index == 0 {
                pool_paid_sats = sats;
                continue;
            }
            if sats == 0 {
                continue;
            }
            if let Ok(address) = Address::from_script(&output.script_pubkey, network) {
                *paid_by_address.entry(address.to_string()).or_insert(0) += sats;
            }
        }
        Self {
            paid_by_address,
            pool_paid_sats,
            total_value_sats,
        }
    }

    /// `sats` as a percentage of the block's actual revenue, for the
    /// `percent` column of a payout-history row. Display only: nothing
    /// books from it. `0.0` for a zero-value coinbase.
    pub fn percent_of_total(&self, sats: u64) -> f32 {
        if self.total_value_sats > 0 {
            (sats as f64 / self.total_value_sats as f64 * 100.0) as f32
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxOut};
    use std::str::FromStr;

    fn coinbase_with(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: outputs,
        }
    }

    fn p2wpkh(addr: &str) -> ScriptBuf {
        Address::from_str(addr)
            .unwrap()
            .assume_checked()
            .script_pubkey()
    }

    const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const FEE: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    #[test]
    fn decomposes_pool_miners_and_zero_outputs() {
        let tx = coinbase_with(vec![
            TxOut {
                value: Amount::from_sat(400),
                script_pubkey: p2wpkh(FEE),
            },
            TxOut {
                value: Amount::from_sat(600),
                script_pubkey: p2wpkh(MINER),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6A, 0x01, 0xAA]),
            },
        ]);
        let actual = ActualCoinbase::from_coinbase(&tx, Network::Bitcoin);
        assert_eq!(actual.pool_paid_sats, 400);
        assert_eq!(actual.total_value_sats, 1000);
        assert_eq!(actual.paid_by_address.len(), 1);
        assert_eq!(actual.paid_by_address[MINER], 600);
    }

    #[test]
    fn percent_of_total_is_share_of_actual_revenue() {
        let actual = ActualCoinbase {
            paid_by_address: HashMap::new(),
            pool_paid_sats: 0,
            total_value_sats: 3_125_004_321,
        };
        for paid in [0u64, 1, 546, 1_000_000, 1_562_502_160, 3_125_004_321] {
            assert_eq!(
                actual.percent_of_total(paid),
                (paid as f64 / 3_125_004_321f64 * 100.0) as f32
            );
        }
        let empty = ActualCoinbase {
            paid_by_address: HashMap::new(),
            pool_paid_sats: 0,
            total_value_sats: 0,
        };
        assert_eq!(empty.percent_of_total(600), 0.0);
    }

    /// A fee address that also mines keeps its two outputs separate.
    #[test]
    fn fee_address_as_miner_does_not_blend() {
        let tx = coinbase_with(vec![
            TxOut {
                value: Amount::from_sat(400),
                script_pubkey: p2wpkh(FEE),
            },
            TxOut {
                value: Amount::from_sat(600),
                script_pubkey: p2wpkh(FEE), // fee address mines too
            },
        ]);
        let actual = ActualCoinbase::from_coinbase(&tx, Network::Bitcoin);
        assert_eq!(actual.pool_paid_sats, 400);
        assert_eq!(actual.paid_by_address[FEE], 600);
    }

    /// Duplicate miner outputs aggregate per address.
    #[test]
    fn duplicate_outputs_aggregate() {
        let tx = coinbase_with(vec![
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: p2wpkh(FEE),
            },
            TxOut {
                value: Amount::from_sat(300),
                script_pubkey: p2wpkh(MINER),
            },
            TxOut {
                value: Amount::from_sat(200),
                script_pubkey: p2wpkh(MINER),
            },
        ]);
        let actual = ActualCoinbase::from_coinbase(&tx, Network::Bitcoin);
        assert_eq!(actual.paid_by_address[MINER], 500);
        assert_eq!(actual.total_value_sats, 600);
    }
}
