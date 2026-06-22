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
//! - **0x0003 Non-Custodial Pool Payouts** —
//!   [`RequestPayoutOutputs`] / [`RequestPayoutOutputsSuccess`] /
//!   [`RequestPayoutOutputsError`].
//!
//! Frames for 0x0001 and 0x0003 messages set `extension_type` to the
//! extension's identifier (NOT 0x0000), because both extensions
//! introduce new messages. Worker-ID TLV piggy-backs on the existing
//! `SubmitSharesExtended` payload, whose frame retains
//! `extension_type = 0x0000`.
//!
//! Body fields use the standard SV2 little-endian encoding. **TLV
//! headers (only used by 0x0002) are big-endian** per spec §3.4.3 wire
//! example, even though §3.1 prose says LE — the on-wire example is
//! the canonical form and matches every other interop. Worker-ID has a
//! 32-byte cap on `user_identity` (spec §1.1).

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
// drift. Everything is straight-line LE for SV2 body fields and BE for
// TLV headers (per spec §3.4.3).

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
    fn read_b0_255(&mut self) -> Result<Vec<u8>, ExtensionsParseError> {
        self.need(1)?;
        let len = self.buf[self.pos] as usize;
        self.pos += 1;
        self.need(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
    fn read_b0_64k(&mut self) -> Result<Vec<u8>, ExtensionsParseError> {
        let len = self.read_u16_le()? as usize;
        self.need(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
    fn read_str0_255(&mut self) -> Result<String, ExtensionsParseError> {
        let off = self.pos;
        let bytes = self.read_b0_255()?;
        String::from_utf8(bytes).map_err(|_| ExtensionsParseError::InvalidUtf8 { offset: off })
    }
    fn read_seq0_64k_u16(&mut self) -> Result<Vec<u16>, ExtensionsParseError> {
        let count = self.read_u16_le()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_u16_le()?);
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
fn write_b0_255(dst: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= 255);
    dst.push(bytes.len() as u8);
    dst.extend_from_slice(bytes);
}
fn write_b0_64k(dst: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u16::MAX as usize);
    write_u16_le(dst, bytes.len() as u16);
    dst.extend_from_slice(bytes);
}
fn write_str0_255(dst: &mut Vec<u8>, s: &str) {
    write_b0_255(dst, s.as_bytes());
}
fn write_seq0_64k_u16(dst: &mut Vec<u8>, items: &[u16]) {
    debug_assert!(items.len() <= u16::MAX as usize);
    write_u16_le(dst, items.len() as u16);
    for &v in items {
        write_u16_le(dst, v);
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

// ── 0x0003 Non-Custodial Pool Payouts ──────────────────────────────

/// `RequestPayoutOutputs` — JDC → JDS (spec §2.1).
/// Frame: `extension_type = 0x0003`, `msg_type = 0x00`.
///
/// No `prev_hash` on the wire: payout freshness is resolved by the
/// validating party from its own accounting state (single-use payout
/// sets, see spec §4), not signalled per-request by the JDC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPayoutOutputs {
    pub request_id: u32,
    pub mining_job_token: Vec<u8>, // B0_255
    /// Amount, in satoshis, the returned output set MUST distribute
    /// (spec §2.1). The JDC derives it from `coinbase_tx_value_remaining`
    /// after accounting for any outputs it adds itself.
    pub available_payout_value: u64,
}

impl RequestPayoutOutputs {
    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let request_id = r.read_u32_le()?;
        let mining_job_token = r.read_b0_255()?;
        let available_payout_value = r.read_u64_le()?;
        Ok(Self {
            request_id,
            mining_job_token,
            available_payout_value,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + self.mining_job_token.len() + 8);
        write_u32_le(&mut out, self.request_id);
        write_b0_255(&mut out, &self.mining_job_token);
        write_u64_le(&mut out, self.available_payout_value);
        out
    }
}

/// `RequestPayoutOutputs.Success` — JDS → JDC (spec §2.2).
/// Frame: `extension_type = 0x0003`, `msg_type = 0x01`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPayoutOutputsSuccess {
    pub request_id: u32,
    /// Consensus-serialized `Vec<TxOut>` (varint count + per-output
    /// `{value_le8, varint_script_len, script_pub_key}`).
    pub coinbase_tx_outputs: Vec<u8>,
}

impl RequestPayoutOutputsSuccess {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.coinbase_tx_outputs.len());
        write_u32_le(&mut out, self.request_id);
        write_b0_64k(&mut out, &self.coinbase_tx_outputs);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let request_id = r.read_u32_le()?;
        let coinbase_tx_outputs = r.read_b0_64k()?;
        Ok(Self {
            request_id,
            coinbase_tx_outputs,
        })
    }
}

/// `RequestPayoutOutputs.Error` — JDS → JDC (spec §2.3).
/// Frame: `extension_type = 0x0003`, `msg_type = 0x02`.
///
/// `error_code` is a free `STR0_255`; the spec only mandates that the
/// JDS return this message when it cannot construct an output set that
/// both sums to `available_payout_value` and fits the token's coinbase
/// reservation. The symbolic codes below are our own internal vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPayoutOutputsError {
    pub request_id: u32,
    pub error_code: String,
}

/// Error-code vocabulary for the 0x0003 extension.
///
/// `STALE_PAYOUT_OUTPUTS` is the only spec-named code (§4): it is a
/// *job-declaration* rejection code (`DeclareMiningJob.Error` /
/// `SetCustomMiningJob.Error`), signalling the JDC to request a fresh
/// payout output set — NOT a `RequestPayoutOutputs.Error` code. The
/// rest are internal codes we emit on `RequestPayoutOutputs.Error`.
pub mod payout_outputs_error_codes {
    /// Spec §4 — job rejected because its payout output set is stale,
    /// superseded, unknown, or already used. The JDC SHOULD re-request.
    pub const STALE_PAYOUT_OUTPUTS: &str = "stale-payout-outputs";
    pub const INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";
    pub const REVENUE_TOO_LARGE: &str = "revenue-too-large";
    pub const COINBASE_SIZE_BUDGET_EXCEEDED: &str = "coinbase-size-budget-exceeded";
    pub const INTERNAL: &str = "internal";
}

impl RequestPayoutOutputsError {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.error_code.len());
        write_u32_le(&mut out, self.request_id);
        write_str0_255(&mut out, &self.error_code);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, ExtensionsParseError> {
        let mut r = Reader::new(buf);
        let request_id = r.read_u32_le()?;
        let error_code = r.read_str0_255()?;
        Ok(Self {
            request_id,
            error_code,
        })
    }
}

// ── 0x0002 Worker-ID TLV ───────────────────────────────────────────

/// Encode a Worker-ID TLV, ready to be appended to `SubmitSharesExtended`.
///
/// Wire shape (TLV header is **big-endian** per §3.4.3, value is UTF-8):
/// `[Type: ext_type U16-BE | field_type U8] [Length U16-BE] [UTF-8 bytes]`.
///
/// Spec wire example for `"Worker_001"` (§2):
/// `00 02 01 00 0A 57 6F 72 6B 65 72 5F 30 30 31`.
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
    buf.extend_from_slice(&SV2_EXTENSION_TYPE_WORKER_ID.to_be_bytes()); // 2 bytes BE
    buf.push(SV2_FIELD_TYPE_USER_IDENTITY);
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes()); // 2 bytes BE
    buf.extend_from_slice(value);
    Ok(buf)
}

/// Parse a Worker-ID TLV from a tail buffer (bytes appended after the
/// base `SubmitSharesExtended` serialisation). Returns the
/// `user_identity` string, or `None` if no 0x0002 TLV is present.
///
/// Unknown TLVs are skipped per ext 0x0001 §3 (receivers MUST ignore
/// unexpected TLVs). Same big-endian header convention as 0x0003.
///
/// Returns `None` on malformed TLV (truncated header / value, length
/// cap exceeded). Callers SHOULD treat a malformed TLV the same as
/// missing — fall back to the channel-default identity rather than
/// rejecting the share, since the share itself is structurally valid.
pub fn parse_worker_id_tlv(tail: &[u8]) -> Option<String> {
    let mut o = 0;
    while o + 5 <= tail.len() {
        let ext_type = u16::from_be_bytes([tail[o], tail[o + 1]]);
        let field_type = tail[o + 2];
        let length = u16::from_be_bytes([tail[o + 3], tail[o + 4]]) as usize;
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

    // ── 0x0003 RequestPayoutOutputs ────────────────────────────────

    /// `round-trips request_id, token, available_payout_value`
    #[test]
    fn request_payout_outputs_roundtrip() {
        let original = RequestPayoutOutputs {
            request_id: 0xdeadbeef,
            mining_job_token: b"jdp-token-42".to_vec(),
            available_payout_value: 312_500_000, // 3.125 BTC in sats
        };

        let wire = original.serialize();
        let parsed = RequestPayoutOutputs::deserialize(&wire).unwrap();
        assert_eq!(parsed, original);
    }

    /// `wire layout: U32-LE request_id, B0_255 token, U64-LE available_payout_value`
    #[test]
    fn request_payout_outputs_wire_layout() {
        let token = vec![0xde, 0xad];
        let wire = RequestPayoutOutputs {
            request_id: 0x01020304,
            mining_job_token: token.clone(),
            available_payout_value: 0x0000_0000_9988_7766,
        }
        .serialize();
        // 4 (U32) + 1 (token len prefix) + 2 (token bytes) + 8 (U64) = 15
        assert_eq!(wire.len(), 15);
        assert_eq!(&wire[0..4], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(wire[4], 0x02);
        assert_eq!(&wire[5..7], token.as_slice());
        assert_eq!(
            &wire[7..15],
            &[0x66, 0x77, 0x88, 0x99, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// `round-trips request_id and consensus-serialized outputs` (Success)
    #[test]
    fn request_payout_outputs_success_roundtrip() {
        let coinbase_tx_outputs = vec![
            0x01, // VarInt count = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // U64 value = 0
            0x00, // VarInt script_len = 0
        ];
        let original = RequestPayoutOutputsSuccess {
            request_id: 7,
            coinbase_tx_outputs,
        };
        let parsed = RequestPayoutOutputsSuccess::deserialize(&original.serialize()).unwrap();
        assert_eq!(parsed, original);
    }

    /// `wire layout: U32-LE request_id followed by B0_64K outputs`
    #[test]
    fn request_payout_outputs_success_wire_layout() {
        let outputs = vec![0xAA, 0xBB, 0xCC];
        let wire = RequestPayoutOutputsSuccess {
            request_id: 0x42,
            coinbase_tx_outputs: outputs.clone(),
        }
        .serialize();
        // 4 (U32) + 2 (B0_64K len prefix) + 3 (outputs) = 9
        assert_eq!(wire.len(), 9);
        assert_eq!(&wire[0..4], &[0x42, 0x00, 0x00, 0x00]);
        assert_eq!(&wire[4..6], &[0x03, 0x00]);
        assert_eq!(&wire[6..9], outputs.as_slice());
    }

    /// `round-trips each defined error code`
    #[test]
    fn request_payout_outputs_error_roundtrip() {
        use payout_outputs_error_codes::*;
        for code in [
            STALE_PAYOUT_OUTPUTS,
            INVALID_MINING_JOB_TOKEN,
            REVENUE_TOO_LARGE,
            COINBASE_SIZE_BUDGET_EXCEEDED,
            INTERNAL,
        ] {
            let wire = RequestPayoutOutputsError {
                request_id: 1,
                error_code: code.to_string(),
            }
            .serialize();
            let parsed = RequestPayoutOutputsError::deserialize(&wire).unwrap();
            assert_eq!(parsed.request_id, 1);
            assert_eq!(parsed.error_code, code);
        }
    }

    /// `wire layout: U32-LE request_id followed by STR0_255 error_code`
    #[test]
    fn request_payout_outputs_error_wire_layout() {
        let wire = RequestPayoutOutputsError {
            request_id: 0xCAFEBABE,
            error_code: "stale-payout-outputs".to_string(),
        }
        .serialize();
        // 4 (U32) + 1 (STR len prefix) + 20 ("stale-payout-outputs") = 25
        assert_eq!(wire.len(), 25);
        assert_eq!(&wire[0..4], &[0xBE, 0xBA, 0xFE, 0xCA]);
        assert_eq!(wire[4], 20);
        assert_eq!(
            std::str::from_utf8(&wire[5..25]).unwrap(),
            "stale-payout-outputs"
        );
    }

    // ── 0x0002 Worker-ID TLV ───────────────────────────────────────

    /// `matches the spec wire example: "Worker_001"`
    #[test]
    fn worker_id_tlv_matches_spec_wire_example() {
        let tlv = encode_worker_id_tlv("Worker_001").unwrap();
        // Per extensions/0x0002-worker-specific-hashrate-tracking.md §2:
        //   00 02 01 00 0A 57 6F 72 6B 65 72 5F 30 30 31
        assert_eq!(hex::encode(&tlv), "000201000a576f726b65725f303031");
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
        // Forge a TLV header claiming length=33.
        let mut buf = vec![0x00, 0x02, 0x01, 0x00, 0x21];
        buf.extend(std::iter::repeat_n(0x41u8, 33));
        assert_eq!(parse_worker_id_tlv(&buf), None);
    }

    /// `returns null when no 0x0002 TLV is present`
    #[test]
    fn worker_id_tlv_returns_none_when_absent() {
        assert_eq!(parse_worker_id_tlv(&[]), None);
        // An unrelated TLV (extType=0x0099 BE).
        assert_eq!(
            parse_worker_id_tlv(&[0x00, 0x99, 0x01, 0x00, 0x01, 0x42]),
            None
        );
    }

    /// `skips unknown leading TLVs and finds the 0x0002 one`
    #[test]
    fn worker_id_tlv_skips_unknown_leading_tlvs() {
        // Unknown TLV first (ext=0x0099, field=0x01, len=4, value=0x00000000), then 0x0002.
        let unknown = [0x00, 0x99, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
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
        // Truncated 0x0002 TLV: claims length=10 but only 5 bytes follow.
        let malformed = [0x00, 0x02, 0x01, 0x00, 0x0a, 0x41, 0x42, 0x43, 0x44, 0x45];
        assert_eq!(resolve(&malformed, true), "default");
    }
}
