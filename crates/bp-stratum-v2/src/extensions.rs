// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire codecs for the SV2 extensions used by Blitzpool. Three
//! extensions:
//!
//! - **0x0001 Extensions Negotiation** —
//!   [`RequestExtensions`] / [`RequestExtensionsSuccess`] /
//!   [`RequestExtensionsError`].
//! - **0x0002 Worker-Specific Hashrate Tracking** — Worker-ID TLV
//!   piggy-backed on `SubmitSharesExtended` (extension_type stays
//!   0x0000). See [`encode_worker_id_tlv`], [`parse_worker_id_tlv`],
//!   [`resolve_share_worker_name_from_tlv`].
//! - **0x0003 Non-Custodial Payouts** (push model) —
//!   [`SetPayoutDistribution`] (JDS→JDC) + the `distribution_id` TLV
//!   on `DeclareMiningJob` / `SetCustomMiningJob`.
//!
//! Frames for 0x0001 and 0x0003 messages set `extension_type` to the
//! extension's identifier (NOT 0x0000), because both extensions
//! introduce new messages. Worker-ID TLV piggy-backs on the existing
//! `SubmitSharesExtended` payload, whose frame retains
//! `extension_type = 0x0000`.
//!
//! Body fields use the standard SV2 little-endian encoding. **TLV
//! headers are little-endian too**: §3.4.3 types the header fields as
//! U16/U8, and U16 is little-endian everywhere in SV2. (The 0x0002
//! spec's §2 wire example shows the extension type as `00 02`, which
//! contradicts the base data-type convention — the example is the
//! error, not the rule.) Worker-ID has a 32-byte cap on
//! `user_identity` (spec §1.1).

// ── Spec constants ─────────────────────────────────────────────────

/// Extension identifier for **Worker-Specific Hashrate Tracking** (0x0002).
pub const SV2_EXTENSION_TYPE_WORKER_ID: u16 = 0x0002;

/// TLV field-type for `user_identity` inside the Worker-ID TLV (0x01).
pub const SV2_FIELD_TYPE_USER_IDENTITY: u8 = 0x01;

/// Maximum length of `user_identity` (spec §1.1) in bytes.
pub const SV2_USER_IDENTITY_MAX_BYTES: usize = 32;

/// Extension identifier for **Non-Custodial Pool Payouts** (0x0003).
pub const SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS: u16 = 0x0003;

// ── Errors ─────────────────────────────────────────────────────────

/// Parse-side errors for extension messages.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtensionsParseError {
    #[error("buffer truncated: needed {needed} more bytes at offset {offset}")]
    Truncated { offset: usize, needed: usize },
    #[error("declared length {declared} exceeds remaining {remaining} at offset {offset}")]
    LengthOverflow {
        offset: usize,
        declared: usize,
        remaining: usize,
    },
    #[error("invalid UTF-8 in string field at offset {offset}")]
    InvalidUtf8 { offset: usize },
}

/// Encode-side errors for the Worker-ID TLV.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkerIdEncodeError {
    #[error("user_identity must not be empty")]
    Empty,
    #[error("user_identity {got} bytes exceeds spec max {max}")]
    TooLong { got: usize, max: usize },
}

// ── Minimal LE/BE codec helpers (private) ──────────────────────────
//
// We keep these in-file rather than depend on `stratum_core::binary_sv2`
// because the SV2 spec pins exact byte sequences and we want the
// Rust tests to assert against the same fixtures with no abstraction
// drift. Everything is straight-line LE — body fields and TLV headers
// alike (§3.4.3 types TLV headers as U16/U8, and U16 is LE in SV2).

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
    fn read_seq0_64k_u16(&mut self) -> Result<Vec<u16>, ExtensionsParseError> {
        let count = self.read_u16_le()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_u16_le()?);
        }
        Ok(out)
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
fn write_seq0_64k_u16(dst: &mut Vec<u8>, items: &[u16]) {
    debug_assert!(items.len() <= u16::MAX as usize);
    write_u16_le(dst, items.len() as u16);
    for &v in items {
        write_u16_le(dst, v);
    }
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

/// `RequestExtensions` — JDC/Mining-client → server.
/// Frame: `extension_type = 0x0001`, `msg_type = 0x00`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestExtensions {
    pub request_id: u16,
    pub requested_extensions: Vec<u16>,
}

impl RequestExtensions {
    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let request_id = r.read_u16_le()?;
        let requested_extensions = r.read_seq0_64k_u16()?;
        Ok(Self {
            request_id,
            requested_extensions,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 2 * self.requested_extensions.len());
        write_u16_le(&mut out, self.request_id);
        write_seq0_64k_u16(&mut out, &self.requested_extensions);
        out
    }
}

/// `RequestExtensions.Success` — server → client.
/// Frame: `extension_type = 0x0001`, `msg_type = 0x01`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestExtensionsSuccess {
    pub request_id: u16,
    pub supported_extensions: Vec<u16>,
}

impl RequestExtensionsSuccess {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 2 * self.supported_extensions.len());
        write_u16_le(&mut out, self.request_id);
        write_seq0_64k_u16(&mut out, &self.supported_extensions);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let request_id = r.read_u16_le()?;
        let supported_extensions = r.read_seq0_64k_u16()?;
        Ok(Self {
            request_id,
            supported_extensions,
        })
    }
}

/// `RequestExtensions.Error` — server → client.
/// Frame: `extension_type = 0x0001`, `msg_type = 0x02`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestExtensionsError {
    pub request_id: u16,
    pub unsupported_extensions: Vec<u16>,
    pub required_extensions: Vec<u16>,
}

impl RequestExtensionsError {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            6 + 2 * (self.unsupported_extensions.len() + self.required_extensions.len()),
        );
        write_u16_le(&mut out, self.request_id);
        write_seq0_64k_u16(&mut out, &self.unsupported_extensions);
        write_seq0_64k_u16(&mut out, &self.required_extensions);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let request_id = r.read_u16_le()?;
        let unsupported_extensions = r.read_seq0_64k_u16()?;
        let required_extensions = r.read_seq0_64k_u16()?;
        Ok(Self {
            request_id,
            unsupported_extensions,
            required_extensions,
        })
    }
}

// ── 0x0003 Non-Custodial Payouts (push model) ──────────────────────

/// TLV field-type for `distribution_id` on `DeclareMiningJob` /
/// `SetCustomMiningJob` (ext 0x0003 §6).
pub const SV2_FIELD_TYPE_DISTRIBUTION_ID: u8 = 0x01;

/// `SetPayoutDistribution` — JDS → JDC (ext 0x0003 §3.1).
/// Frame: `extension_type = 0x0003`, `msg_type = 0x00`, channel bit 0.
///
/// MUST be the first message the JDS sends after `SetupConnection.Success`
/// and `RequestExtensions.Success`; re-sent (with a higher
/// `distribution_id`) whenever the pool updates the distribution.
/// Amount fields inside `pool_payout` / `payouts` carry relative
/// WEIGHTS, not satoshis — the JDC derives amounts per §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPayoutDistribution {
    /// Strictly increasing, universal across all connections of this
    /// pool (§3.1).
    pub distribution_id: u64,
    /// Consensus-serialized `TxOut`; amount field = `weight_P` (non-0).
    /// Locking script MUST be pool-controlled.
    pub pool_payout: Vec<u8>, // B0_64K
    /// Consensus-serialized `TxOut`s; amount fields = weights (non-0).
    pub payouts: Vec<Vec<u8>>, // SEQ0_64K[B0_64K]
    /// Per-`payouts[i]` dust limit in satoshis; same length as `payouts`.
    pub dust_limits: Vec<u32>, // SEQ0_64K[U32]
    /// Consensus-serialized `TxOut`s the pool appends (e.g. OP_RETURN);
    /// amount fields MUST be 0.
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

    /// Needed by our tests standing in for a JDC (and by any future
    /// client-side use); the JDS itself only serializes.
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

/// Error-code vocabulary for the push-model 0x0003 extension (§7.3),
/// emitted on `DeclareMiningJob.Error` / `SetCustomMiningJob.Error`.
pub mod payout_distribution_error_codes {
    /// §7.3 — the referenced `distribution_id` is not accepted: too
    /// old (outside the grace window), unknown, or invalidated by a
    /// settlement event (§10).
    pub const STALE_PAYOUT_DISTRIBUTION: &str = "stale-payout-distribution";
    /// §7.3 — the declared coinbase outputs violate §4 (recomputed
    /// vector mismatch, non-0-value trailing output, missing/mis-typed
    /// `distribution_id` TLV where the extension is negotiated).
    pub const INVALID_PAYOUT_DISTRIBUTION: &str = "invalid-payout-distribution";
}

/// Extract the ext 0x0003 `distribution_id` from parsed trailing TLVs
/// (§6: Type `0x0003`/`0x01`, length 8, value U64-LE). Returns `None`
/// when absent or malformed — the caller decides whether a missing
/// TLV is an error (it is, when the extension was negotiated).
pub fn parse_distribution_id_tlv(tlvs: &[stratum_core::parsers_sv2::Tlv]) -> Option<u64> {
    tlvs.iter().find_map(|tlv| {
        (tlv.r#type.extension_type == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS
            && tlv.r#type.field_type == SV2_FIELD_TYPE_DISTRIBUTION_ID
            && tlv.value.len() == 8)
            .then(|| u64::from_le_bytes(tlv.value[..8].try_into().unwrap()))
    })
}

/// Encode the `distribution_id` TLV in wire form (§6) — used by tests
/// standing in for a JDC.
pub fn encode_distribution_id_tlv(distribution_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13);
    buf.extend_from_slice(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS.to_le_bytes());
    buf.push(SV2_FIELD_TYPE_DISTRIBUTION_ID);
    buf.extend_from_slice(&8u16.to_le_bytes());
    buf.extend_from_slice(&distribution_id.to_le_bytes());
    buf
}

// ── 0x0002 Worker-ID TLV ───────────────────────────────────────────

/// Encode a Worker-ID TLV, ready to be appended to `SubmitSharesExtended`.
///
/// Wire shape (TLV header fields are U16/U8 per §3.4.3, so the U16s
/// are **little-endian** like every SV2 integer; value is UTF-8):
/// `[Type: ext_type U16-LE | field_type U8] [Length U16-LE] [UTF-8 bytes]`.
///
/// `"Worker_001"` therefore encodes as
/// `02 00 01 0A 00 57 6F 72 6B 65 72 5F 30 30 31`.
pub fn encode_worker_id_tlv(user_identity: &str) -> Result<Vec<u8>, WorkerIdEncodeError> {
    let value = user_identity.as_bytes();
    if value.is_empty() {
        return Err(WorkerIdEncodeError::Empty);
    }
    if value.len() > SV2_USER_IDENTITY_MAX_BYTES {
        return Err(WorkerIdEncodeError::TooLong {
            got: value.len(),
            max: SV2_USER_IDENTITY_MAX_BYTES,
        });
    }
    let mut buf = Vec::with_capacity(5 + value.len());
    buf.extend_from_slice(&SV2_EXTENSION_TYPE_WORKER_ID.to_le_bytes());
    buf.push(SV2_FIELD_TYPE_USER_IDENTITY);
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    Ok(buf)
}

/// Parse a Worker-ID TLV from a tail buffer (bytes appended after the
/// base `SubmitSharesExtended` serialisation). Returns the
/// `user_identity` string, or `None` if no 0x0002 TLV is present.
///
/// Unknown TLVs are skipped per ext 0x0001 §3 (receivers MUST ignore
/// unexpected TLVs). Little-endian header per the SV2 U16 convention.
///
/// Returns `None` on malformed TLV (truncated header / value, length
/// cap exceeded). Callers SHOULD treat a malformed TLV the same as
/// missing — fall back to the channel-default identity rather than
/// rejecting the share, since the share itself is structurally valid.
pub fn parse_worker_id_tlv(tail: &[u8]) -> Option<String> {
    let mut o = 0;
    while o + 5 <= tail.len() {
        let ext_type = u16::from_le_bytes([tail[o], tail[o + 1]]);
        let field_type = tail[o + 2];
        let length = u16::from_le_bytes([tail[o + 3], tail[o + 4]]) as usize;
        let value_start = o + 5;
        let value_end = value_start.checked_add(length)?;
        if value_end > tail.len() {
            return None;
        }
        if ext_type == SV2_EXTENSION_TYPE_WORKER_ID && field_type == SV2_FIELD_TYPE_USER_IDENTITY {
            if length == 0 || length > SV2_USER_IDENTITY_MAX_BYTES {
                return None;
            }
            return std::str::from_utf8(&tail[value_start..value_end])
                .ok()
                .map(String::from);
        }
        o = value_end;
    }
    None
}

/// Inputs for [`resolve_share_worker_name_from_tlv`].
pub struct ResolveWorkerNameInput<'a> {
    pub tail: &'a [u8],
    /// Channel-locked address, lowercase normalised (bech32 form). May
    /// be `None` for connections that haven't completed
    /// `OpenStandardMiningChannel` (in which case any TLV is treated
    /// as bare worker-name).
    pub channel_address: Option<&'a str>,
    /// Channel-default worker name to fall back to.
    pub channel_worker: &'a str,
    /// Whether ext 0x0002 was negotiated for this connection.
    pub ext_0x0002_negotiated: bool,
}

/// Decide which worker name to attribute a share to, given a possibly-
/// present ext 0x0002 Worker-ID TLV on `SubmitSharesExtended`.
///
/// Semantics:
/// - If ext 0x0002 isn't negotiated → channel default. The TLV (if
///   any) is silently ignored per ext 0x0001 §3.
/// - If the TLV is missing or malformed → channel default.
/// - If the TLV's `user_identity` is bare (`"workerName"`) → that's
///   the worker; channel address is implicit.
/// - If `user_identity` is `"<address>.<worker>"` → use the worker
///   part ONLY when the address matches the channel-locked one.
///   Otherwise fall back to channel default. (Cross-account
///   attribution is a security boundary — a multiplexing proxy must
///   stay within the address it opened the channel under.)
pub fn resolve_share_worker_name_from_tlv(opts: &ResolveWorkerNameInput<'_>) -> String {
    if !opts.ext_0x0002_negotiated {
        return opts.channel_worker.to_string();
    }
    if opts.tail.is_empty() {
        return opts.channel_worker.to_string();
    }
    let user_identity = match parse_worker_id_tlv(opts.tail) {
        Some(s) => s,
        None => return opts.channel_worker.to_string(),
    };
    match user_identity.find('.') {
        None => {
            if user_identity.is_empty() {
                opts.channel_worker.to_string()
            } else {
                user_identity
            }
        }
        Some(dot) => {
            let tlv_address = user_identity[..dot].to_lowercase();
            let tlv_worker = &user_identity[dot + 1..];
            if let Some(channel_addr) = opts.channel_address {
                if tlv_address != channel_addr.to_lowercase() {
                    // Cross-account attribution — silently drop.
                    return opts.channel_worker.to_string();
                }
            }
            if tlv_worker.is_empty() {
                opts.channel_worker.to_string()
            } else {
                tlv_worker.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 0x0001 RequestExtensions ───────────────────────────────────

    /// `round-trips a request with multiple requested extensions`
    #[test]
    fn request_extensions_roundtrip_multiple() {
        let buf = [
            0x05, 0x00, // request_id = 5
            0x02, 0x00, // count = 2
            0x02, 0x00, // ext 0x0002
            0x03, 0x00, // ext 0x0003
        ];
        let msg = RequestExtensions::deserialize(&buf).unwrap();
        assert_eq!(msg.request_id, 5);
        assert_eq!(msg.requested_extensions, vec![0x0002, 0x0003]);
    }

    /// `handles empty requested list`
    #[test]
    fn request_extensions_handles_empty_list() {
        let buf = [0x07, 0x00, 0x00, 0x00];
        let msg = RequestExtensions::deserialize(&buf).unwrap();
        assert_eq!(msg.request_id, 7);
        assert!(msg.requested_extensions.is_empty());
    }

    /// `serializes Success with the supported subset`
    #[test]
    fn request_extensions_success_serialize() {
        let buf = RequestExtensionsSuccess {
            request_id: 9,
            supported_extensions: vec![0x0003],
        }
        .serialize();
        assert_eq!(buf, vec![0x09, 0x00, 0x01, 0x00, 0x03, 0x00]);
    }

    /// `serializes Error with unsupported + required lists`
    #[test]
    fn request_extensions_error_serialize() {
        let buf = RequestExtensionsError {
            request_id: 0x1234,
            unsupported_extensions: vec![0x0002],
            required_extensions: vec![0x0005, 0x0006],
        }
        .serialize();
        assert_eq!(
            buf,
            vec![0x34, 0x12, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x05, 0x00, 0x06, 0x00,]
        );
    }

    /// Round-trip Success.
    #[test]
    fn request_extensions_success_roundtrip() {
        let original = RequestExtensionsSuccess {
            request_id: 9,
            supported_extensions: vec![0x0003],
        };
        let parsed = RequestExtensionsSuccess::deserialize(&original.serialize()).unwrap();
        assert_eq!(parsed, original);
    }

    /// Round-trip Error.
    #[test]
    fn request_extensions_error_roundtrip() {
        let original = RequestExtensionsError {
            request_id: 0x1234,
            unsupported_extensions: vec![0x0002],
            required_extensions: vec![0x0005, 0x0006],
        };
        let parsed = RequestExtensionsError::deserialize(&original.serialize()).unwrap();
        assert_eq!(parsed, original);
    }

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

    /// `SetPayoutDistribution round-trips`
    #[test]
    fn set_payout_distribution_roundtrip() {
        let msg = sample_distribution();
        let bytes = msg.serialize();
        assert_eq!(SetPayoutDistribution::deserialize(&bytes).unwrap(), msg);
    }

    /// `SetPayoutDistribution wire layout (§3.1 field order, all LE)`
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

    /// `truncated buffers refuse to parse`
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

    /// `empty payouts + dust_limits are legal (pool-only distribution)`
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

    /// `distribution_id TLV round-trips through the upstream Tlv codec`
    #[test]
    fn distribution_id_tlv_roundtrip_via_reference_codec() {
        use stratum_core::parsers_sv2::Tlv;
        let wire = encode_distribution_id_tlv(0xDEADBEEF00C0FFEE);
        let parsed = Tlv::decode(&wire).expect("reference decode");
        assert_eq!(
            parse_distribution_id_tlv(std::slice::from_ref(&parsed)),
            Some(0xDEADBEEF00C0FFEE)
        );
        // And the reference encoder produces our exact bytes.
        assert_eq!(parsed.encode().unwrap(), wire);
    }

    /// `wrong length or foreign TLVs yield None`
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

    /// `finds the distribution_id among other negotiated TLVs`
    #[test]
    fn distribution_id_tlv_found_among_others() {
        use stratum_core::parsers_sv2::Tlv;
        let worker = Tlv::new(0x0002, 0x01, b"rig1".to_vec());
        let dist = Tlv::decode(&encode_distribution_id_tlv(7)).unwrap();
        assert_eq!(parse_distribution_id_tlv(&[worker, dist]), Some(7));
    }

    // ── 0x0002 Worker-ID TLV ───────────────────────────────────────

    /// `wire layout: "Worker_001" with little-endian TLV header`
    #[test]
    fn worker_id_tlv_wire_layout_is_little_endian() {
        let tlv = encode_worker_id_tlv("Worker_001").unwrap();
        // §3.4.3 types the header as U16|U8 + U16 — U16 is LE in SV2.
        // (The 0x0002 spec's §2 example shows `00 02 …`, contradicting
        // the base data-type convention; the example is wrong.)
        assert_eq!(hex::encode(&tlv), "0200010a00576f726b65725f303031");
    }

    /// `wire-compatible with the reference TLV codec (parsers_sv2)`
    #[test]
    fn worker_id_tlv_matches_reference_codec() {
        use stratum_core::parsers_sv2::Tlv;
        let reference = Tlv::new(
            SV2_EXTENSION_TYPE_WORKER_ID,
            SV2_FIELD_TYPE_USER_IDENTITY,
            b"Worker_001".to_vec(),
        )
        .encode()
        .expect("reference encode");
        assert_eq!(encode_worker_id_tlv("Worker_001").unwrap(), reference);
        // And the reverse: reference-encoded bytes parse on our side.
        assert_eq!(
            parse_worker_id_tlv(&reference).as_deref(),
            Some("Worker_001")
        );
    }

    /// `round-trips arbitrary UTF-8`
    #[test]
    fn worker_id_tlv_roundtrips_utf8() {
        let tlv = encode_worker_id_tlv("rig.€42").unwrap();
        assert_eq!(parse_worker_id_tlv(&tlv).as_deref(), Some("rig.€42"));
    }

    /// `rejects empty user_identity at encode`
    #[test]
    fn worker_id_tlv_rejects_empty() {
        assert_eq!(encode_worker_id_tlv(""), Err(WorkerIdEncodeError::Empty));
    }

    /// `rejects > 32 byte user_identity at encode (spec §1.1)`
    #[test]
    fn worker_id_tlv_rejects_too_long() {
        let too_long = "x".repeat(33);
        assert_eq!(
            encode_worker_id_tlv(&too_long),
            Err(WorkerIdEncodeError::TooLong { got: 33, max: 32 })
        );
    }

    /// `parser returns null on > 32 byte declared length (malformed)`
    #[test]
    fn worker_id_tlv_parser_rejects_oversized_length() {
        // Forge a TLV header claiming length=33 (0x21 LE).
        let mut buf = vec![0x02, 0x00, 0x01, 0x21, 0x00];
        buf.extend(std::iter::repeat_n(0x41u8, 33));
        assert_eq!(parse_worker_id_tlv(&buf), None);
    }

    /// `returns null when no 0x0002 TLV is present`
    #[test]
    fn worker_id_tlv_returns_none_when_absent() {
        assert_eq!(parse_worker_id_tlv(&[]), None);
        // An unrelated TLV (extType=0x0099 LE).
        assert_eq!(
            parse_worker_id_tlv(&[0x99, 0x00, 0x01, 0x01, 0x00, 0x42]),
            None
        );
    }

    /// `skips unknown leading TLVs and finds the 0x0002 one`
    #[test]
    fn worker_id_tlv_skips_unknown_leading_tlvs() {
        // Unknown TLV first (ext=0x0099 LE, field=0x01, len=4, value=0x00000000), then 0x0002.
        let unknown = [0x99, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ours = encode_worker_id_tlv("rig42").unwrap();
        let mut buf = unknown.to_vec();
        buf.extend_from_slice(&ours);
        assert_eq!(parse_worker_id_tlv(&buf).as_deref(), Some("rig42"));
    }

    // ── resolve_share_worker_name_from_tlv ─────────────────────────

    fn resolve(tail: &[u8], negotiated: bool) -> String {
        resolve_share_worker_name_from_tlv(&ResolveWorkerNameInput {
            tail,
            channel_address: Some("addr1"),
            channel_worker: "default",
            ext_0x0002_negotiated: negotiated,
        })
    }

    /// `returns channel default when ext 0x0002 not negotiated (TLV ignored)`
    #[test]
    fn resolve_returns_default_when_not_negotiated() {
        let tail = encode_worker_id_tlv("hacker.evil").unwrap();
        assert_eq!(resolve(&tail, false), "default");
    }

    /// `returns channel default when no TLV present`
    #[test]
    fn resolve_returns_default_when_no_tlv() {
        assert_eq!(resolve(&[], true), "default");
    }

    /// `accepts bare worker name (no address prefix)`
    #[test]
    fn resolve_accepts_bare_worker() {
        let tail = encode_worker_id_tlv("rig42").unwrap();
        assert_eq!(resolve(&tail, true), "rig42");
    }

    /// `accepts "<channelAddress>.<worker>" form and returns just the worker`
    #[test]
    fn resolve_accepts_address_worker_form() {
        let tail = encode_worker_id_tlv("addr1.rig42").unwrap();
        assert_eq!(resolve(&tail, true), "rig42");
    }

    /// `SECURITY: drops cross-account TLV (address mismatch) → channel default`
    #[test]
    fn resolve_drops_cross_account_tlv() {
        let tail = encode_worker_id_tlv("addr2.victim").unwrap();
        assert_eq!(resolve(&tail, true), "default");
    }

    /// `SECURITY: address-match check is case-insensitive (bech32 lowercase)`
    #[test]
    fn resolve_address_match_is_case_insensitive() {
        let tail = encode_worker_id_tlv("ADDR1.rig").unwrap();
        assert_eq!(resolve(&tail, true), "rig");
    }

    /// `handles trailing-dot edge case ("addr.") → channel default (empty worker)`
    #[test]
    fn resolve_handles_trailing_dot() {
        let tail = encode_worker_id_tlv("addr1.").unwrap();
        assert_eq!(resolve(&tail, true), "default");
    }

    /// `preserves nested dots in worker name ("addr.a.b" → "a.b")`
    #[test]
    fn resolve_preserves_nested_dots() {
        let tail = encode_worker_id_tlv("addr1.farm.rig5").unwrap();
        assert_eq!(resolve(&tail, true), "farm.rig5");
    }

    /// `malformed TLV (truncated) → channel default, share remains accountable`
    #[test]
    fn resolve_malformed_truncated_tlv() {
        // Truncated 0x0002 TLV: claims length=10 (LE) but only 5 bytes follow.
        let malformed = [0x02, 0x00, 0x01, 0x0a, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45];
        assert_eq!(resolve(&malformed, true), "default");
    }
}
