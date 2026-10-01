// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire codecs for SV2 extensions 0x0001 ([`RequestExtensions`]), 0x0002
//! (Worker-ID TLV, [`parse_worker_id_tlv`]) and 0x0003
//! ([`SetPayoutDistribution`] plus the `distribution_id` TLV).
//! 0x0001/0x0003 frames carry their own `extension_type`; the Worker-ID TLV
//! rides on `SubmitSharesExtended`, whose frame keeps 0x0000.
//!
//! **TLV headers are little-endian**: SV2 Overview/Stratum V2 TLV Encoding
//! Model types them as U16/U8, and U16 is LE in SV2. The big-endian `00 02`
//! examples there and in ext 0x0002/Extended SubmitSharesExtended Message
//! Format are treated as the error.

// ── Spec constants ─────────────────────────────────────────────────

pub const SV2_EXTENSION_TYPE_WORKER_ID: u16 = 0x0002;

pub const SV2_FIELD_TYPE_USER_IDENTITY: u8 = 0x01;

/// ext 0x0002/TLV Format for user_identity.
pub const SV2_USER_IDENTITY_MAX_BYTES: usize = 32;

pub const SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS: u16 = 0x0003;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtensionsParseError {
    #[error("buffer truncated: needed {needed} more bytes at offset {offset}")]
    Truncated { offset: usize, needed: usize },
}

// ── LE codec helpers ───────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<(), ExtensionsParseError> {
        if self.buf.len() < self.pos + n {
            return Err(ExtensionsParseError::Truncated {
                offset: self.pos,
                needed: n,
            });
        }
        Ok(())
    }
    fn read_u16_le(&mut self) -> Result<u16, ExtensionsParseError> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn read_u32_le(&mut self) -> Result<u32, ExtensionsParseError> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn read_u64_le(&mut self) -> Result<u64, ExtensionsParseError> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn read_b0_64k(&mut self) -> Result<Vec<u8>, ExtensionsParseError> {
        let len = self.read_u16_le()? as usize;
        self.need(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
    fn read_seq0_64k_u32(&mut self) -> Result<Vec<u32>, ExtensionsParseError> {
        let count = self.read_u16_le()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_u32_le()?);
        }
        Ok(out)
    }
    fn read_seq0_64k_b0_64k(&mut self) -> Result<Vec<Vec<u8>>, ExtensionsParseError> {
        let count = self.read_u16_le()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_b0_64k()?);
        }
        Ok(out)
    }
}

fn write_u16_le(dst: &mut Vec<u8>, v: u16) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn write_u32_le(dst: &mut Vec<u8>, v: u32) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn write_u64_le(dst: &mut Vec<u8>, v: u64) {
    dst.extend_from_slice(&v.to_le_bytes());
}
fn write_b0_64k(dst: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u16::MAX as usize);
    write_u16_le(dst, bytes.len() as u16);
    dst.extend_from_slice(bytes);
}
fn write_seq0_64k_u32(dst: &mut Vec<u8>, items: &[u32]) {
    debug_assert!(items.len() <= u16::MAX as usize);
    write_u16_le(dst, items.len() as u16);
    for &v in items {
        write_u32_le(dst, v);
    }
}
fn write_seq0_64k_b0_64k(dst: &mut Vec<u8>, items: &[Vec<u8>]) {
    debug_assert!(items.len() <= u16::MAX as usize);
    write_u16_le(dst, items.len() as u16);
    for item in items {
        write_b0_64k(dst, item);
    }
}

// ── 0x0001 Extensions Negotiation ──────────────────────────────────

/// Decoded `RequestExtensions`; the wire codec is in [`crate::codec_common`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestExtensions {
    pub request_id: u16,
    pub requested_extensions: Vec<u16>,
}

// ── 0x0003 Non-Custodial Payouts (push model) ──────────────────────

/// ext 0x0003/distribution_id TLV Field.
pub const SV2_FIELD_TYPE_DISTRIBUTION_ID: u8 = 0x01;

/// JDS → JDC (ext 0x0003/SetPayoutDistribution). MUST be the first message
/// after `RequestExtensions.Success`, re-sent with a higher id on every update.
/// Amounts in `pool_payout` / `payouts` are non-zero WEIGHTS, not satoshis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPayoutDistribution {
    /// Strictly increasing across all connections of this pool.
    pub distribution_id: u64,
    /// Locking script MUST be pool-controlled.
    pub pool_payout: Vec<u8>, // B0_64K
    pub payouts: Vec<Vec<u8>>, // SEQ0_64K[B0_64K]
    /// Satoshis, one per `payouts` entry.
    pub dust_limits: Vec<u32>, // SEQ0_64K[U32]
    /// Amount fields MUST be 0.
    pub additional_outputs: Vec<Vec<u8>>, // SEQ0_64K[B0_64K]
}

impl SetPayoutDistribution {
    pub fn serialize(&self) -> Vec<u8> {
        let payload_len: usize = 8
            + (2 + self.pool_payout.len())
            + 2
            + self.payouts.iter().map(|p| 2 + p.len()).sum::<usize>()
            + 2
            + self.dust_limits.len() * 4
            + 2
            + self
                .additional_outputs
                .iter()
                .map(|p| 2 + p.len())
                .sum::<usize>();
        let mut out = Vec::with_capacity(payload_len);
        write_u64_le(&mut out, self.distribution_id);
        write_b0_64k(&mut out, &self.pool_payout);
        write_seq0_64k_b0_64k(&mut out, &self.payouts);
        write_seq0_64k_u32(&mut out, &self.dust_limits);
        write_seq0_64k_b0_64k(&mut out, &self.additional_outputs);
        out
    }

    /// For tests standing in for a JDC; the JDS itself only serializes.
    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let distribution_id = r.read_u64_le()?;
        let pool_payout = r.read_b0_64k()?;
        let payouts = r.read_seq0_64k_b0_64k()?;
        let dust_limits = r.read_seq0_64k_u32()?;
        let additional_outputs = r.read_seq0_64k_b0_64k()?;
        Ok(Self {
            distribution_id,
            pool_payout,
            payouts,
            dust_limits,
            additional_outputs,
        })
    }
}

/// ext 0x0003/Error Codes, sent on `DeclareMiningJob.Error` /
/// `SetCustomMiningJob.Error`.
pub mod payout_distribution_error_codes {
    /// The `distribution_id` is unknown, past its grace window, or invalidated.
    pub const STALE_PAYOUT_DISTRIBUTION: &str = "stale-payout-distribution";
    /// The coinbase outputs violate ext 0x0003/Payout Computation.
    pub const INVALID_PAYOUT_DISTRIBUTION: &str = "invalid-payout-distribution";
}

/// The ext 0x0003 `distribution_id` TLV value, or `None` when absent or
/// malformed; the caller decides whether that is an error.
pub fn parse_distribution_id_tlv(tlvs: &[stratum_core::parsers_sv2::Tlv]) -> Option<u64> {
    tlvs.iter().find_map(|tlv| {
        (tlv.r#type.extension_type == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS
            && tlv.r#type.field_type == SV2_FIELD_TYPE_DISTRIBUTION_ID
            && tlv.value.len() == 8)
            .then(|| u64::from_le_bytes(tlv.value[..8].try_into().unwrap()))
    })
}

/// For tests standing in for a JDC.
pub fn encode_distribution_id_tlv(distribution_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13);
    buf.extend_from_slice(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS.to_le_bytes());
    buf.push(SV2_FIELD_TYPE_DISTRIBUTION_ID);
    buf.extend_from_slice(&8u16.to_le_bytes());
    buf.extend_from_slice(&distribution_id.to_le_bytes());
    buf
}

// ── 0x0002 Worker-ID TLV ───────────────────────────────────────────

/// The `user_identity` of the first Worker-ID TLV. A malformed one yields
/// `None`, so the share falls back to the channel's worker instead of failing.
pub fn parse_worker_id_tlv(tlvs: &[stratum_core::parsers_sv2::Tlv]) -> Option<&str> {
    let tlv = tlvs.iter().find(|tlv| {
        tlv.r#type.extension_type == SV2_EXTENSION_TYPE_WORKER_ID
            && tlv.r#type.field_type == SV2_FIELD_TYPE_USER_IDENTITY
    })?;
    if tlv.value.is_empty() || tlv.value.len() > SV2_USER_IDENTITY_MAX_BYTES {
        return None;
    }
    std::str::from_utf8(&tlv.value).ok()
}

/// The worker a share's Worker-ID TLV names, or `None` to keep the channel's.
/// The address prefix is ignored: the share stays booked to the channel's
/// address, the TLV only renames the worker.
pub fn resolve_share_worker_name_from_tlv(
    tlvs: &[stratum_core::parsers_sv2::Tlv],
    ext_0x0002_negotiated: bool,
) -> Option<String> {
    if !ext_0x0002_negotiated {
        return None;
    }
    let worker = match bp_common::split_user_identity(parse_worker_id_tlv(tlvs)?) {
        (bare, None) => bare,
        (_prefix, Some(worker)) => worker,
    };
    (!worker.is_empty()).then(|| worker.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 0x0003 SetPayoutDistribution (push model) ──────────────────

    fn sample_distribution() -> SetPayoutDistribution {
        SetPayoutDistribution {
            distribution_id: 42,
            pool_payout: vec![0xAA; 30],
            payouts: vec![vec![0x01; 31], vec![0x02; 33]],
            dust_limits: vec![546, 5_000],
            additional_outputs: vec![vec![0x6A, 0x00]],
        }
    }

    #[test]
    fn set_payout_distribution_roundtrip() {
        let msg = sample_distribution();
        let bytes = msg.serialize();
        assert_eq!(SetPayoutDistribution::deserialize(&bytes).unwrap(), msg);
    }

    /// Field order per ext 0x0003/SetPayoutDistribution, all LE.
    #[test]
    fn set_payout_distribution_wire_layout() {
        let msg = SetPayoutDistribution {
            distribution_id: 0x0102030405060708,
            pool_payout: vec![0xAA, 0xBB],
            payouts: vec![vec![0xCC]],
            dust_limits: vec![546],
            additional_outputs: vec![],
        };
        let bytes = msg.serialize();
        let expected = [
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // distribution_id LE
            0x02, 0x00, 0xAA, 0xBB, // pool_payout B0_64K
            0x01, 0x00, // payouts count
            0x01, 0x00, 0xCC, // payouts[0] B0_64K
            0x01, 0x00, // dust_limits count
            0x22, 0x02, 0x00, 0x00, // 546 U32-LE
            0x00, 0x00, // additional_outputs count
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn set_payout_distribution_truncated_refuses() {
        let bytes = sample_distribution().serialize();
        for cut in [0, 7, 9, bytes.len() - 1] {
            assert!(
                SetPayoutDistribution::deserialize(&bytes[..cut]).is_err(),
                "cut at {cut} must not parse"
            );
        }
    }

    #[test]
    fn set_payout_distribution_pool_only_roundtrip() {
        let msg = SetPayoutDistribution {
            distribution_id: 1,
            pool_payout: vec![0xAA; 30],
            payouts: vec![],
            dust_limits: vec![],
            additional_outputs: vec![],
        };
        let bytes = msg.serialize();
        assert_eq!(SetPayoutDistribution::deserialize(&bytes).unwrap(), msg);
    }

    #[test]
    fn distribution_id_tlv_roundtrip_via_reference_codec() {
        use stratum_core::parsers_sv2::Tlv;
        let wire = encode_distribution_id_tlv(0xDEADBEEF00C0FFEE);
        let parsed = Tlv::decode(&wire).expect("reference decode");
        assert_eq!(
            parse_distribution_id_tlv(std::slice::from_ref(&parsed)),
            Some(0xDEADBEEF00C0FFEE)
        );
        assert_eq!(parsed.encode().unwrap(), wire);
    }

    #[test]
    fn distribution_id_tlv_rejects_malformed() {
        use stratum_core::parsers_sv2::Tlv;
        let short = Tlv::new(0x0003, 0x01, vec![0x01, 0x02]);
        assert_eq!(parse_distribution_id_tlv(&[short]), None);
        let foreign = Tlv::new(0x0002, 0x01, vec![0u8; 8]);
        assert_eq!(parse_distribution_id_tlv(&[foreign]), None);
        let wrong_field = Tlv::new(0x0003, 0x02, vec![0u8; 8]);
        assert_eq!(parse_distribution_id_tlv(&[wrong_field]), None);
        assert_eq!(parse_distribution_id_tlv(&[]), None);
    }

    #[test]
    fn distribution_id_tlv_found_among_others() {
        use stratum_core::parsers_sv2::Tlv;
        let worker = Tlv::new(0x0002, 0x01, b"rig1".to_vec());
        let dist = Tlv::decode(&encode_distribution_id_tlv(7)).unwrap();
        assert_eq!(parse_distribution_id_tlv(&[worker, dist]), Some(7));
    }

    // ── 0x0002 Worker-ID TLV ───────────────────────────────────────

    use stratum_core::parsers_sv2::Tlv;

    fn worker_tlv(user_identity: &str) -> Tlv {
        Tlv::new(
            SV2_EXTENSION_TYPE_WORKER_ID,
            SV2_FIELD_TYPE_USER_IDENTITY,
            user_identity.as_bytes().to_vec(),
        )
    }

    /// The TLV header is LE; see the module doc for the spec's BE example.
    #[test]
    fn worker_id_tlv_wire_layout_is_little_endian() {
        let wire = hex::decode("0200010a00576f726b65725f303031").unwrap();
        let parsed = Tlv::decode(&wire).expect("reference decode");
        assert_eq!(
            parse_worker_id_tlv(std::slice::from_ref(&parsed)),
            Some("Worker_001")
        );
    }

    #[test]
    fn worker_id_tlv_roundtrips_utf8() {
        assert_eq!(
            parse_worker_id_tlv(&[worker_tlv("rig.€42")]),
            Some("rig.€42")
        );
    }

    #[test]
    fn worker_id_tlv_parser_rejects_malformed_values() {
        assert_eq!(parse_worker_id_tlv(&[worker_tlv("")]), None);
        assert_eq!(parse_worker_id_tlv(&[worker_tlv(&"A".repeat(33))]), None);
        assert_eq!(
            parse_worker_id_tlv(&[worker_tlv(&"A".repeat(32))]),
            Some("A".repeat(32).as_str())
        );
        let not_utf8 = Tlv::new(
            SV2_EXTENSION_TYPE_WORKER_ID,
            SV2_FIELD_TYPE_USER_IDENTITY,
            vec![0xFF, 0xFE],
        );
        assert_eq!(parse_worker_id_tlv(&[not_utf8]), None);
    }

    #[test]
    fn worker_id_tlv_returns_none_when_absent() {
        assert_eq!(parse_worker_id_tlv(&[]), None);
        assert_eq!(
            parse_worker_id_tlv(&[Tlv::new(0x0099, 0x01, vec![0x42])]),
            None
        );
    }

    #[test]
    fn worker_id_tlv_skips_unknown_leading_tlvs() {
        let unknown = Tlv::new(0x0099, 0x01, vec![0; 4]);
        assert_eq!(
            parse_worker_id_tlv(&[unknown, worker_tlv("rig42")]),
            Some("rig42")
        );
    }

    // ── resolve_share_worker_name_from_tlv ─────────────────────────

    fn resolve(user_identity: &str, negotiated: bool) -> Option<String> {
        resolve_share_worker_name_from_tlv(&[worker_tlv(user_identity)], negotiated)
    }

    #[test]
    fn resolve_returns_default_when_not_negotiated() {
        assert_eq!(resolve("hacker.evil", false), None);
    }

    #[test]
    fn resolve_returns_default_when_no_tlv() {
        assert_eq!(resolve_share_worker_name_from_tlv(&[], true), None);
    }

    #[test]
    fn resolve_accepts_bare_worker() {
        assert_eq!(resolve("rig42", true).as_deref(), Some("rig42"));
    }

    #[test]
    fn resolve_accepts_address_worker_form() {
        assert_eq!(resolve("addr1.rig42", true).as_deref(), Some("rig42"));
    }

    /// A TLV naming another address only renames the worker.
    #[test]
    fn resolve_strips_any_address_prefix() {
        assert_eq!(resolve("addr2.victim", true).as_deref(), Some("victim"));
    }

    #[test]
    fn resolve_handles_trailing_dot() {
        assert_eq!(resolve("addr1.", true), None);
    }

    #[test]
    fn resolve_preserves_nested_dots() {
        assert_eq!(
            resolve("addr1.farm.rig5", true).as_deref(),
            Some("farm.rig5")
        );
    }

    #[test]
    fn resolve_malformed_tlv_keeps_channel_worker() {
        assert_eq!(resolve(&"x".repeat(33), true), None);
    }
}
