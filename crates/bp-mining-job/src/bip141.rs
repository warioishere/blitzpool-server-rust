// SPDX-License-Identifier: AGPL-3.0-or-later

//! BIP-141 witness stripping for SV2 extended-channel coinbase merkle roots.
//!
//! Witness-form coinbase layout:
//! ```text
//! [version:4][MARKER:1=0x00][FLAG:1=0x01][input_count:var][inputs...]
//! [output_count:var][outputs...]
//! [witness_count:1=0x01][witness_len:1=0x20][witness_data:32]
//! [locktime:4]
//! ```
//!
//! Non-witness form is the same minus marker/flag in the prefix and minus
//! witness_count/len/data in the suffix — total 36 bytes removed.

const MARKER_OFFSET: usize = 4;
const FLAG_OFFSET: usize = 5;
const MARKER_FLAG_LEN: usize = 2;
const WITNESS_COUNT_LEN: usize = 1;
const WITNESS_LEN_LEN: usize = 1;
const WITNESS_DATA_LEN: usize = 32;
const LOCKTIME_LEN: usize = 4;
const WITNESS_TOTAL_LEN: usize = WITNESS_COUNT_LEN + WITNESS_LEN_LEN + WITNESS_DATA_LEN;

const MIN_PREFIX_LEN: usize = 6;
const MIN_SUFFIX_LEN: usize = WITNESS_TOTAL_LEN + LOCKTIME_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrippedCoinbase {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Bip141Error {
    #[error("coinbase prefix too short for witness detection: {got} bytes (need {needed})")]
    PrefixTooShort { got: usize, needed: usize },
    #[error("coinbase suffix too short for witness stripping: {got} bytes (need {needed})")]
    SuffixTooShort { got: usize, needed: usize },
    #[error("invalid witness count: expected 0x01, got 0x{got:02x}")]
    InvalidWitnessCount { got: u8 },
    #[error("invalid witness length: expected 0x20, got 0x{got:02x}")]
    InvalidWitnessLength { got: u8 },
}

/// Detect and strip BIP-141 witness bytes from a coinbase prefix + suffix.
/// Returns `Ok(None)` if no witness bytes are present (already stripped, or
/// non-witness transaction).
pub fn strip_bip141(prefix: &[u8], suffix: &[u8]) -> Result<Option<StrippedCoinbase>, Bip141Error> {
    if prefix.len() < MIN_PREFIX_LEN {
        return Err(Bip141Error::PrefixTooShort {
            got: prefix.len(),
            needed: MIN_PREFIX_LEN,
        });
    }
    let has_marker = prefix[MARKER_OFFSET] == 0x00;
    let has_flag = prefix[FLAG_OFFSET] != 0x00;
    if !(has_marker && has_flag) {
        return Ok(None);
    }
    if suffix.len() < MIN_SUFFIX_LEN {
        return Err(Bip141Error::SuffixTooShort {
            got: suffix.len(),
            needed: MIN_SUFFIX_LEN,
        });
    }

    let locktime_pos = suffix.len() - LOCKTIME_LEN;
    let witness_count_pos = locktime_pos - WITNESS_TOTAL_LEN;
    let witness_len_pos = witness_count_pos + WITNESS_COUNT_LEN;

    let witness_count = suffix[witness_count_pos];
    let witness_len = suffix[witness_len_pos];

    if witness_count != 0x01 {
        return Err(Bip141Error::InvalidWitnessCount { got: witness_count });
    }
    if witness_len != 0x20 {
        return Err(Bip141Error::InvalidWitnessLength { got: witness_len });
    }

    let mut new_prefix = Vec::with_capacity(prefix.len() - MARKER_FLAG_LEN);
    new_prefix.extend_from_slice(&prefix[..MARKER_OFFSET]);
    new_prefix.extend_from_slice(&prefix[MARKER_OFFSET + MARKER_FLAG_LEN..]);

    let mut new_suffix = Vec::with_capacity(suffix.len() - WITNESS_TOTAL_LEN);
    new_suffix.extend_from_slice(&suffix[..witness_count_pos]);
    new_suffix.extend_from_slice(&suffix[locktime_pos..]);

    Ok(Some(StrippedCoinbase {
        prefix: new_prefix,
        suffix: new_suffix,
    }))
}

/// `true` iff the prefix carries BIP-141 witness marker + flag.
pub fn has_witness_bytes(prefix: &[u8]) -> bool {
    prefix.len() >= MIN_PREFIX_LEN && prefix[MARKER_OFFSET] == 0x00 && prefix[FLAG_OFFSET] != 0x00
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_witness_coinbase() -> (Vec<u8>, Vec<u8>) {
        // Minimal witness-form coinbase split into prefix + suffix.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes()); // version
        prefix.push(0x00); // marker
        prefix.push(0x01); // flag
        prefix.push(0x01); // input count
        prefix.extend_from_slice(&[0u8; 32]); // prev txid
        prefix.extend_from_slice(&0xffffffff_u32.to_le_bytes()); // prev vout
        prefix.push(0x00); // scriptsig len (0 for this minimal test)

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0xffffffff_u32.to_le_bytes()); // sequence
        suffix.push(0x00); // output count (no outputs)
        suffix.push(0x01); // witness count
        suffix.push(0x20); // witness len (32)
        suffix.extend_from_slice(&[0u8; 32]); // witness data
        suffix.extend_from_slice(&[0u8; 4]); // locktime
        (prefix, suffix)
    }

    #[test]
    fn strips_witness_marker_and_data() {
        let (prefix, suffix) = build_witness_coinbase();
        let stripped = strip_bip141(&prefix, &suffix).unwrap().unwrap();

        // Prefix lost marker + flag (2 bytes).
        assert_eq!(stripped.prefix.len(), prefix.len() - 2);
        assert_eq!(&stripped.prefix[..4], &prefix[..4]); // version intact
        assert_eq!(&stripped.prefix[4..], &prefix[6..]); // rest shifted up

        // Suffix lost witness_count + witness_len + witness_data (34 bytes).
        assert_eq!(stripped.suffix.len(), suffix.len() - 34);
        // Locktime preserved at end.
        assert_eq!(
            &stripped.suffix[stripped.suffix.len() - 4..],
            &suffix[suffix.len() - 4..]
        );
    }

    #[test]
    fn returns_none_when_no_witness_present() {
        // Plausible non-witness prefix: version(4) + input_count(1=0x01) + ...
        let prefix = vec![2u8, 0, 0, 0, 0x01, 0x20];
        let suffix = vec![0u8; 40];
        assert!(strip_bip141(&prefix, &suffix).unwrap().is_none());
    }

    #[test]
    fn errors_on_short_prefix() {
        let prefix = vec![0u8; 4];
        let suffix = vec![0u8; 40];
        assert!(matches!(
            strip_bip141(&prefix, &suffix),
            Err(Bip141Error::PrefixTooShort { .. })
        ));
    }

    #[test]
    fn errors_on_short_suffix_when_witness_detected() {
        let (prefix, _) = build_witness_coinbase();
        let suffix = vec![0u8; 10];
        assert!(matches!(
            strip_bip141(&prefix, &suffix),
            Err(Bip141Error::SuffixTooShort { .. })
        ));
    }

    #[test]
    fn errors_on_invalid_witness_count() {
        let (prefix, mut suffix) = build_witness_coinbase();
        // witness_count_pos = suffix.len() - 4 - 34 = 5.
        suffix[5] = 0x02;
        assert!(matches!(
            strip_bip141(&prefix, &suffix),
            Err(Bip141Error::InvalidWitnessCount { got: 0x02 })
        ));
    }

    #[test]
    fn errors_on_invalid_witness_length() {
        let (prefix, mut suffix) = build_witness_coinbase();
        suffix[6] = 0x21; // expected 0x20
        assert!(matches!(
            strip_bip141(&prefix, &suffix),
            Err(Bip141Error::InvalidWitnessLength { got: 0x21 })
        ));
    }

    #[test]
    fn has_witness_bytes_detects_correctly() {
        let (prefix, _) = build_witness_coinbase();
        assert!(has_witness_bytes(&prefix));

        let no_witness = vec![2u8, 0, 0, 0, 0x01, 0x20];
        assert!(!has_witness_bytes(&no_witness));

        let too_short = vec![0u8; 3];
        assert!(!has_witness_bytes(&too_short));
    }
}
