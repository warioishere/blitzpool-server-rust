// SPDX-License-Identifier: AGPL-3.0-or-later

//! Payout-distribution computation + declared-coinbase validation for
//! SV2 ext 0x0003 (push model).
//!
//! One §4 evaluation serves every consumer: the JDS builds the
//! expected output vector from `(distribution, T)` and the validator
//! compares a declared coinbase POSITIONALLY against it (§7.1 — the
//! spec fixes the output order, so containment games like paying two
//! distributions at once are structurally impossible; nothing here
//! needs the old multiset machinery).
//!
//! `T` is taken as the sum of the declared coinbase's output values.
//! That is self-consistent: a §4-correct vector for revenue `T'` sums
//! to exactly `T'` (the pool output absorbs the remainder), so any
//! tampering either changes the sum — and with it every recomputed
//! amount — or changes a position; both are caught by the compare.

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{Amount, ScriptBuf, TxOut};
use bp_share::{compute_payout_amounts, WeightPayoutError};

/// One §3.1 payout slot as the registry stores it: a locking script
/// plus its relative weight (the TxOut amount field on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedOutput {
    pub script_pubkey: Vec<u8>,
    pub weight: u64,
}

impl WeightedOutput {
    /// Consensus-serialize as the §3.1 wire form: a `TxOut` whose
    /// amount field carries the weight.
    pub fn to_wire_txout(&self) -> Vec<u8> {
        let txout = TxOut {
            value: Amount::from_sat(self.weight),
            script_pubkey: ScriptBuf::from_bytes(self.script_pubkey.clone()),
        };
        let mut buf = Vec::with_capacity(9 + self.script_pubkey.len());
        txout
            .consensus_encode(&mut buf)
            .expect("Vec<u8> writer cannot fail");
        buf
    }
}

/// Why an expected output vector could not be computed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PayoutComputeError {
    #[error(transparent)]
    Weights(#[from] WeightPayoutError),
    /// An `additional_outputs` blob did not consensus-decode to a TxOut.
    #[error("additional output {index} is not a consensus TxOut")]
    UnparsableAdditionalOutput { index: usize },
    /// An `additional_outputs` TxOut carried a non-0 amount (§3.1 MUST).
    #[error("additional output {index} carries a non-zero amount")]
    NonZeroAdditionalOutput { index: usize },
}

/// Build the §4 expected coinbase output vector for revenue `t`:
/// `pool_payout` (amount `pay_P`), kept `payouts` in distribution
/// order (dust-pruned ones omitted), then `additional_outputs`
/// (amounts 0). Trailing JDC/TP outputs are NOT part of this vector —
/// the validator checks them separately (must be 0-value).
pub fn compute_payout_vector(
    pool_payout: &WeightedOutput,
    payouts: &[WeightedOutput],
    dust_limits: &[u32],
    additional_outputs: &[Vec<u8>],
    t: u64,
) -> Result<Vec<TxOut>, PayoutComputeError> {
    let weights: Vec<u64> = payouts.iter().map(|p| p.weight).collect();
    let amounts = compute_payout_amounts(pool_payout.weight, &weights, dust_limits, t)?;

    let mut outputs = Vec::with_capacity(1 + payouts.len() + additional_outputs.len());
    outputs.push(TxOut {
        value: Amount::from_sat(amounts.pool_pay),
        script_pubkey: ScriptBuf::from_bytes(pool_payout.script_pubkey.clone()),
    });
    for (payout, pay) in payouts.iter().zip(&amounts.pays) {
        if let Some(sats) = pay {
            outputs.push(TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: ScriptBuf::from_bytes(payout.script_pubkey.clone()),
            });
        }
    }
    for (index, blob) in additional_outputs.iter().enumerate() {
        let txout = TxOut::consensus_decode(&mut blob.as_slice())
            .map_err(|_| PayoutComputeError::UnparsableAdditionalOutput { index })?;
        if txout.value != Amount::ZERO {
            return Err(PayoutComputeError::NonZeroAdditionalOutput { index });
        }
        outputs.push(txout);
    }
    Ok(outputs)
}

/// How a declared coinbase violates its referenced distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionViolation {
    /// Output at `position` differs (script or amount) from the
    /// recomputed §4 vector.
    WrongOutputAt { position: usize },
    /// The declared coinbase ends before the recomputed vector does.
    MissingExpectedOutput { position: usize },
    /// A trailing (JDC/TP-appended) output carries a non-0 amount —
    /// §4 only permits 0-value outputs after the distribution block.
    NonZeroTrailingOutput { position: usize },
    /// The distribution itself cannot be evaluated (zero weight sum /
    /// malformed additional output) — a registry entry this JDS
    /// published should never trip this; treat as internal.
    Uncomputable,
}

/// Recompute-and-compare (§7.1) against POSITIONAL §4 order. Returns
/// the accepted revenue `T` (= Σ declared output values) so the caller
/// can band-check it for booking and stamp it onto the job.
pub fn validate_coinbase_outputs_against_distribution(
    declared: &[TxOut],
    pool_payout: &WeightedOutput,
    payouts: &[WeightedOutput],
    dust_limits: &[u32],
    additional_outputs: &[Vec<u8>],
) -> Result<u64, DistributionViolation> {
    let t: u64 = declared.iter().map(|o| o.value.to_sat()).sum();
    let expected = compute_payout_vector(pool_payout, payouts, dust_limits, additional_outputs, t)
        .map_err(|_| DistributionViolation::Uncomputable)?;

    for (position, want) in expected.iter().enumerate() {
        match declared.get(position) {
            None => return Err(DistributionViolation::MissingExpectedOutput { position }),
            Some(got) if got != want => {
                return Err(DistributionViolation::WrongOutputAt { position })
            }
            Some(_) => {}
        }
    }
    // Defense-in-depth: with `T := Σ declared`, a matching prefix
    // already forces every trailing output to 0 (the prefix alone sums
    // to T). This check only becomes load-bearing if T is ever derived
    // from something other than the declared outputs — keep it so that
    // change cannot silently open a valued-trailing-output hole.
    for (offset, got) in declared[expected.len()..].iter().enumerate() {
        if got.value != Amount::ZERO {
            return Err(DistributionViolation::NonZeroTrailingOutput {
                position: expected.len() + offset,
            });
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(tag: u8) -> Vec<u8> {
        // A plausible P2WPKH-shaped script, distinct per tag.
        let mut s = vec![0x00, 0x14];
        s.extend(std::iter::repeat_n(tag, 20));
        s
    }

    fn wo(tag: u8, weight: u64) -> WeightedOutput {
        WeightedOutput {
            script_pubkey: script(tag),
            weight,
        }
    }

    fn txout(value: u64, script_bytes: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        }
    }

    fn zero_op_return() -> Vec<u8> {
        let t = txout(0, vec![0x6A, 0x01, 0xEE]);
        let mut buf = Vec::new();
        t.consensus_encode(&mut buf).unwrap();
        buf
    }

    /// `expected vector: pool first, kept payouts, additional last`
    #[test]
    fn compute_orders_pool_payouts_additional() {
        let v = compute_payout_vector(
            &wo(0xFF, 1),
            &[wo(1, 6), wo(2, 3)],
            &[1, 1],
            &[zero_op_return()],
            1000,
        )
        .unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0], txout(100, script(0xFF))); // pool absorbs remainder
        assert_eq!(v[1], txout(600, script(1)));
        assert_eq!(v[2], txout(300, script(2)));
        assert_eq!(v[3].value, Amount::ZERO);
        let total: u64 = v.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(total, 1000);
    }

    /// `dust-pruned payout omitted; its value sits in the pool output`
    #[test]
    fn compute_omits_pruned_outputs() {
        let v = compute_payout_vector(&wo(0xFF, 1), &[wo(1, 6), wo(2, 3)], &[1, 400], &[], 1000)
            .unwrap();
        assert_eq!(v.len(), 2, "the 300-sat output is pruned (< 400)");
        assert_eq!(v[0], txout(400, script(0xFF)));
        assert_eq!(v[1], txout(600, script(1)));
    }

    /// `non-zero additional output is refused at compute time`
    #[test]
    fn compute_refuses_valued_additional_output() {
        let bad = {
            let t = txout(1, vec![0x6A]);
            let mut buf = Vec::new();
            t.consensus_encode(&mut buf).unwrap();
            buf
        };
        assert_eq!(
            compute_payout_vector(&wo(0xFF, 1), &[], &[], &[bad], 1000),
            Err(PayoutComputeError::NonZeroAdditionalOutput { index: 0 })
        );
    }

    /// `a §4-correct coinbase validates and returns its T`
    #[test]
    fn validate_accepts_correct_coinbase() {
        let pool = wo(0xFF, 1);
        let payouts = [wo(1, 6), wo(2, 3)];
        let dusts = [1, 1];
        let additional = [zero_op_return()];
        let declared =
            compute_payout_vector(&pool, &payouts, &dusts, &additional, 312_500_000).unwrap();
        let t = validate_coinbase_outputs_against_distribution(
            &declared,
            &pool,
            &payouts,
            &dusts,
            &additional,
        )
        .unwrap();
        assert_eq!(t, 312_500_000);
    }

    /// `1 sat moved between outputs (Σ preserved) is caught positionally`
    #[test]
    fn validate_rejects_moved_sat() {
        let pool = wo(0xFF, 1);
        let payouts = [wo(1, 6), wo(2, 3)];
        let dusts = [1, 1];
        let mut declared = compute_payout_vector(&pool, &payouts, &dusts, &[], 1000).unwrap();
        declared[1].value = Amount::from_sat(declared[1].value.to_sat() - 1);
        declared[2].value = Amount::from_sat(declared[2].value.to_sat() + 1);
        assert_eq!(
            validate_coinbase_outputs_against_distribution(&declared, &pool, &payouts, &dusts, &[]),
            Err(DistributionViolation::WrongOutputAt { position: 1 })
        );
    }

    /// `reordered payout outputs are rejected (spec fixes the order)`
    #[test]
    fn validate_rejects_reordered_outputs() {
        let pool = wo(0xFF, 1);
        let payouts = [wo(1, 6), wo(2, 3)];
        let dusts = [1, 1];
        let mut declared = compute_payout_vector(&pool, &payouts, &dusts, &[], 1000).unwrap();
        declared.swap(1, 2);
        assert!(validate_coinbase_outputs_against_distribution(
            &declared,
            &pool,
            &payouts,
            &dusts,
            &[]
        )
        .is_err());
    }

    /// `missing expected output is rejected`
    #[test]
    fn validate_rejects_missing_output() {
        let pool = wo(0xFF, 1);
        let payouts = [wo(1, 6)];
        let dusts = [1];
        let mut declared = compute_payout_vector(&pool, &payouts, &dusts, &[], 1000).unwrap();
        let removed = declared.pop().unwrap();
        // Keep Σ intact so the recompute still expects the output.
        declared[0].value = Amount::from_sat(declared[0].value.to_sat() + removed.value.to_sat());
        let err =
            validate_coinbase_outputs_against_distribution(&declared, &pool, &payouts, &dusts, &[])
                .unwrap_err();
        assert!(matches!(
            err,
            DistributionViolation::WrongOutputAt { .. }
                | DistributionViolation::MissingExpectedOutput { .. }
        ));
    }

    /// `0-value trailing outputs (JDC/TP appended) are allowed`
    #[test]
    fn validate_allows_zero_value_trailing() {
        let pool = wo(0xFF, 1);
        let payouts = [wo(1, 6)];
        let dusts = [1];
        let mut declared = compute_payout_vector(&pool, &payouts, &dusts, &[], 1000).unwrap();
        declared.push(txout(0, vec![0x6A, 0x01, 0x42])); // JDC OP_RETURN
        declared.push(txout(0, vec![0x6A, 0x24, 0xAA])); // TP witness commitment
        assert!(validate_coinbase_outputs_against_distribution(
            &declared,
            &pool,
            &payouts,
            &dusts,
            &[]
        )
        .is_ok());
    }

    /// `a valued trailing output is rejected — via the pool-output
    /// mismatch it necessarily causes (T := Σ declared makes a matching
    /// prefix force all trailing outputs to 0)`
    #[test]
    fn validate_rejects_valued_trailing_output() {
        let pool = wo(0xFF, 1);
        let payouts: [WeightedOutput; 0] = [];
        let declared = vec![
            txout(999, script(0xFF)),
            txout(1, script(0x77)), // someone slipping themselves a sat
        ];
        // T = 1000 → expected pool output = 1000, declared says 999.
        assert_eq!(
            validate_coinbase_outputs_against_distribution(&declared, &pool, &payouts, &[], &[]),
            Err(DistributionViolation::WrongOutputAt { position: 0 })
        );
    }

    /// `empty declared list against a real distribution is rejected`
    #[test]
    fn validate_rejects_empty_declared() {
        let pool = wo(0xFF, 1);
        assert_eq!(
            validate_coinbase_outputs_against_distribution(&[], &pool, &[], &[], &[]),
            // T = 0 → pool output expected with amount 0; absent → missing.
            Err(DistributionViolation::MissingExpectedOutput { position: 0 })
        );
    }

    /// `wire form of a WeightedOutput is a consensus TxOut with the weight as amount`
    #[test]
    fn weighted_output_wire_txout_roundtrip() {
        let w = wo(0x11, 123_456_789);
        let wire = w.to_wire_txout();
        let decoded = TxOut::consensus_decode(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded.value.to_sat(), 123_456_789);
        assert_eq!(decoded.script_pubkey.as_bytes(), &script(0x11)[..]);
    }
}
