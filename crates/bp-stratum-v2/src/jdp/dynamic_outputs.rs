// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output byte helpers shared by the JDP paths.
//!
//! The ext 0x0003 payout logic itself lives in
//! [`crate::jdp::payout_distribution`] (push model: `SetPayoutDistribution`
//! weights, §4 recompute-and-compare). What remains here are the byte-level
//! helpers both the base-protocol allocate path and the declare-time
//! validator need:
//!
//! - [`encode_coinbase_outputs`] — `(address, sats)` list → consensus
//!   `Vec<TxOut>` bytes (`AllocateMiningJobToken.Success.coinbase_tx_outputs`
//!   on the non-negotiated base path).
//! - [`parse_coinbase_suffix_outputs`] — the declared coinbase suffix →
//!   its output vector, fail-closed.
//! - [`PayoutBooking`] — the accounting identity a proven declaration
//!   carries to the block-found path.

use bitcoin::consensus::Encodable;
use bitcoin::{Amount, Network, TxOut};
use bp_common::{AddressId, Sats};
use bp_mining_job::address_to_script;

// ── DynamicOutput ────────────────────────────────────────────────────

/// One entry in a concrete coinbase output list (base-path allocate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicOutput {
    pub address: AddressId,
    pub sats: Sats,
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Address didn't parse or didn't match the configured network
    /// (delegated to `bp_mining_job::address_to_script`).
    #[error("address-to-script failed: {0}")]
    InvalidAddress(String),
    /// `bitcoin::consensus::encode` failure. Shouldn't fire in
    /// practice (we write to a `Vec<u8>`) but kept total.
    #[error("consensus encoding: {0}")]
    Consensus(String),
}

/// Serialise `outputs` as a consensus-encoded `Vec<TxOut>`.
///
/// Layout (per Bitcoin consensus):
/// - `VarInt(outputs.len())`
/// - Per output: `u64-LE value` + `VarInt(script_len)` + `script_pubkey`
///
/// Empty `outputs` returns `[0x00]` (single varint zero) — the
/// consensus encoding of an empty vector.
pub fn encode_coinbase_outputs(
    network: Network,
    outputs: &[DynamicOutput],
) -> Result<Vec<u8>, EncodeError> {
    if outputs.is_empty() {
        return Ok(vec![0x00]);
    }
    // Build TxOuts, then consensus-encode the whole vector.
    let mut txouts = Vec::with_capacity(outputs.len());
    for out in outputs {
        let script = address_to_script(network, out.address.as_str())
            .map_err(|e| EncodeError::InvalidAddress(format!("{e}")))?;
        let value_sats = out.sats.to_i64().max(0) as u64;
        txouts.push(TxOut {
            value: Amount::from_sat(value_sats),
            script_pubkey: script,
        });
    }
    let mut buf = Vec::with_capacity(64 + outputs.len() * 40);
    txouts
        .consensus_encode(&mut buf)
        .map_err(|e| EncodeError::Consensus(format!("{e}")))?;
    Ok(buf)
}

/// Parse the coinbase output vector out of a SV2 `coinbase_tx_suffix`.
///
/// The suffix is the coinbase bytes AFTER the extranonce slot:
/// `[nSequence: 4][output_count: CompactSize][TxOuts][nLockTime: 4]`. The
/// output vector is parsed as a consensus `Vec<TxOut>` that MUST consume the
/// region between nSequence and nLockTime exactly. Returns `None` if the
/// suffix is shorter than the 8 framing bytes or doesn't match this layout —
/// callers treat that as a validation failure (fail-closed: never accept an
/// output set we cannot actually verify).
pub fn parse_coinbase_suffix_outputs(coinbase_tx_suffix: &[u8]) -> Option<Vec<TxOut>> {
    if coinbase_tx_suffix.len() < 8 {
        return None;
    }
    // Strip the leading nSequence (4) and trailing nLockTime (4); the middle
    // MUST be exactly a consensus Vec<TxOut> (`deserialize` rejects trailing
    // bytes, so a non-standard scriptSig tail fails closed).
    let body = &coinbase_tx_suffix[4..coinbase_tx_suffix.len() - 4];
    bitcoin::consensus::deserialize::<Vec<TxOut>>(body).ok()
}

// ── PayoutBooking ───────────────────────────────────────────────────

/// The pool-side accounting identity riding on a proven declaration.
///
/// A JDC builds and owns its own coinbase; the pool only publishes a
/// weight distribution (ext 0x0003 §3.1). A found block may only be
/// booked once the declared coinbase was validated positionally against
/// that distribution (§7.1) — this rides along on that proof so the
/// block-found path can settle exactly the distribution the coinbase
/// pays (`claim(T_actual) − paid` from the settlement snapshot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutBooking {
    /// §3.1 `distribution_id` the declaration referenced.
    pub distribution_id: u64,
    /// Settlement-snapshot identity (weights fingerprint) of that
    /// distribution. Zeroed = the owning mode books without a snapshot.
    pub payouts_fingerprint: [u8; 32],
    /// The revenue the distribution's boosts were projected against —
    /// carried for the booking band + logs.
    pub reference_reward_sats: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Decodable;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    #[test]
    fn encode_empty_is_varint_zero() {
        assert_eq!(
            encode_coinbase_outputs(Network::Regtest, &[]).unwrap(),
            vec![0x00]
        );
    }

    #[test]
    fn encode_roundtrips_via_consensus_decode() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new(ADDR).unwrap(),
            sats: Sats(312_500_000),
        }];
        let bytes = encode_coinbase_outputs(Network::Regtest, &outputs).unwrap();
        let decoded = <Vec<TxOut>>::consensus_decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value.to_sat(), 312_500_000);
    }

    #[test]
    fn encode_rejects_invalid_address() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new("notanaddress").unwrap(),
            sats: Sats(1_000),
        }];
        assert!(matches!(
            encode_coinbase_outputs(Network::Regtest, &outputs),
            Err(EncodeError::InvalidAddress(_))
        ));
    }

    #[test]
    fn encode_clamps_negative_sats_to_zero() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new(ADDR).unwrap(),
            sats: Sats(-5),
        }];
        let bytes = encode_coinbase_outputs(Network::Regtest, &outputs).unwrap();
        let decoded = <Vec<TxOut>>::consensus_decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded[0].value.to_sat(), 0);
    }

    fn suffix_with(outputs_bytes: &[u8]) -> Vec<u8> {
        let mut suffix = vec![0xFE, 0xFF, 0xFF, 0xFF]; // nSequence
        suffix.extend_from_slice(outputs_bytes);
        suffix.extend_from_slice(&[0, 0, 0, 0]); // nLockTime
        suffix
    }

    #[test]
    fn suffix_parse_roundtrips() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new(ADDR).unwrap(),
            sats: Sats(42),
        }];
        let bytes = encode_coinbase_outputs(Network::Regtest, &outputs).unwrap();
        let parsed = parse_coinbase_suffix_outputs(&suffix_with(&bytes)).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value.to_sat(), 42);
    }

    #[test]
    fn suffix_parse_fails_closed_on_trailing_garbage() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new(ADDR).unwrap(),
            sats: Sats(42),
        }];
        let mut bytes = encode_coinbase_outputs(Network::Regtest, &outputs).unwrap();
        bytes.push(0xAA); // trailing byte between outputs and nLockTime
        assert!(parse_coinbase_suffix_outputs(&suffix_with(&bytes)).is_none());
    }

    #[test]
    fn suffix_parse_rejects_short_buffers() {
        assert!(parse_coinbase_suffix_outputs(&[0u8; 7]).is_none());
    }
}
