// SPDX-License-Identifier: AGPL-3.0-or-later

//! What [`crate::server_codec`] and [`crate::jdp_server_codec`] share: wire
//! primitives, the messages both sub-protocols carry (`SetupConnection`,
//! ext 0x0001 `RequestExtensions`), [`CodecError`] and the frame writers, so
//! each exists once.

use stratum_core::binary_sv2::GetSize;
use stratum_core::codec_sv2::MessageFrame;
use stratum_core::common_messages_sv2::{
    SetupConnection, SetupConnectionErrorOwned, SetupConnectionSuccessOwned,
};
use stratum_core::extensions_sv2::extensions_negotiation::{
    RequestExtensions as Sv2RequestExtensions, RequestExtensionsErrorOwned,
    RequestExtensionsSuccessOwned,
};
use stratum_core::framing_sv2::framing::SerializedFrame;
use stratum_core::framing_sv2::header::Header;
use stratum_core::parsers_sv2::{
    AnyMessage, AnyMessageOwned, CommonMessagesOwned, ExtensionsNegotiationOwned, ExtensionsOwned,
    ParserError, Tlv, TlvList,
};

use crate::extensions::RequestExtensions;
use crate::noise::{NoiseError, NoiseTcpWriteHalf};
use crate::tokens::Token;

// ── Errors ──────────────────────────────────────────────────────────

/// Codec-layer failures. Production wiring logs + drops the frame;
/// the per-connection task continues. None of these are connection-fatal
/// in the spec sense.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// Inbound message arrived on the wrong sub-protocol port, e.g. a JDP
    /// frame on the mining listener. Protocol-neutral: both codecs raise it.
    #[error("message type not served on this sub-protocol port: {0:?}")]
    NotForThisSubProtocol(&'static str),
    /// Sv2 wire type → owned-data conversion failure. Typically a
    /// length mismatch on a fixed-size byte field.
    #[error("conversion: {0}")]
    Conversion(String),
    /// A miner-supplied string failed UTF-8 validation. Caller
    /// reports + drops, so downstream string handling only sees valid UTF-8.
    #[error("invalid UTF-8: {0}")]
    InvalidUtf8(String),
}

/// The SV2 name of a message, for the wrong-sub-protocol error.
pub(crate) fn message_name(m: &impl stratum_core::parsers_sv2::IsSv2Message) -> &'static str {
    stratum_core::parsers_sv2::message_type_to_name(m.message_type())
}

impl CodecError {
    /// Wrap any `Debug` conversion failure as [`CodecError::Conversion`].
    pub(crate) fn from_conv<E: core::fmt::Debug>(e: E) -> Self {
        CodecError::Conversion(format!("{e:?}"))
    }
}

/// Outbound-write failure modes, shared by both server tasks.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("noise io: {0:?}")]
    Io(NoiseError),
}

// ── Inbound frames ──────────────────────────────────────────────────

/// Bytes of TLV fields an inbound frame may carry after its message. The
/// TLVs the pool reads take at most 50 (ext 0x0002 Worker-ID 5+32, ext 0x0003
/// distribution_id 5+8); the rest is room for other extensions' TLVs, which
/// are skipped. Every TLV of a listed extension becomes its own heap value
/// from as little as 5 wire bytes, so without this bound one 16 MiB frame
/// costs over 100 MiB before any state is checked.
pub const MAX_INBOUND_TLV_BYTES: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum InboundParseError {
    #[error("parse: {0:?}")]
    Parser(ParserError),
    #[error(
        "{tlv_bytes} bytes of TLV fields after the message, more than {MAX_INBOUND_TLV_BYTES}"
    )]
    TlvAreaTooLarge { tlv_bytes: usize },
}

/// Decode an inbound frame and the TLVs of `extensions` that follow its
/// message, refusing a TLV area over [`MAX_INBOUND_TLV_BYTES`]. Shared by the
/// mining and the JDP server; the same steps as
/// `parsers_sv2::parse_message_frame_with_tlvs`, plus that bound.
pub fn parse_inbound_frame<'a>(
    header: Header,
    payload: &'a mut [u8],
    extensions: &[u16],
) -> Result<(AnyMessage<'a>, Option<Vec<Tlv>>), InboundParseError> {
    // The message borrows `payload`, so the TLV area is read from a copy.
    let raw = payload.to_vec();
    let message = AnyMessage::try_from((header, payload)).map_err(InboundParseError::Parser)?;
    let tlv_area = raw.get(message.get_size()..).unwrap_or_default();
    if tlv_area.len() > MAX_INBOUND_TLV_BYTES {
        return Err(InboundParseError::TlvAreaTooLarge {
            tlv_bytes: tlv_area.len(),
        });
    }
    let tlvs = TlvList::from_bytes(tlv_area).for_extensions(extensions);
    Ok((message, (!tlvs.is_empty()).then_some(tlvs)))
}

// ── Frame writers ───────────────────────────────────────────────────

/// Put a base-protocol message into its SV2 frame and write it.
pub(crate) async fn write_message(
    writer: &mut NoiseTcpWriteHalf,
    message: AnyMessageOwned,
) -> Result<(), WriteError> {
    let frame: MessageFrame<AnyMessageOwned> = message
        .try_into()
        .map_err(|e: ParserError| WriteError::Codec(CodecError::from_conv(e)))?;
    writer.write_frame(frame).await.map_err(WriteError::Io)
}

/// Frame `payload` by hand under `(ext_type, msg_type)` and write it. For
/// messages `stratum-core` has no type for (ext 0x0003): 6-byte header
/// (ext_type LE16 + msg_type + msg_length LE24) + payload.
pub(crate) async fn write_raw_frame(
    writer: &mut NoiseTcpWriteHalf,
    ext_type: u16,
    msg_type: u8,
    payload: Vec<u8>,
) -> Result<(), WriteError> {
    let msg_len = payload.len() as u32;
    if msg_len > 0x00FF_FFFF {
        return Err(WriteError::Codec(CodecError::Conversion(format!(
            "ext 0x{ext_type:04x} payload too large: {} bytes (max 16M-1)",
            payload.len()
        ))));
    }
    let mut bytes = Vec::with_capacity(6 + payload.len());
    bytes.extend_from_slice(&ext_type.to_le_bytes());
    bytes.push(msg_type);
    bytes.push((msg_len & 0xFF) as u8);
    bytes.push(((msg_len >> 8) & 0xFF) as u8);
    bytes.push(((msg_len >> 16) & 0xFF) as u8);
    bytes.extend_from_slice(&payload);
    // `SerializedFrame::from_bytes` re-reads the header just written and
    // refuses a frame whose length field and payload disagree.
    let frame = SerializedFrame::from_bytes(bytes).map_err(|hint| {
        WriteError::Codec(CodecError::Conversion(format!(
            "ext 0x{ext_type:04x} frame: {hint}"
        )))
    })?;
    writer.write_frame(frame).await.map_err(WriteError::Io)
}

// ── Wire primitives ─────────────────────────────────────────────────

pub(crate) fn utf8_from_bytes(b: &[u8]) -> Result<String, CodecError> {
    std::str::from_utf8(b)
        .map(|s| s.to_string())
        .map_err(|e| CodecError::InvalidUtf8(e.to_string()))
}

pub(crate) fn bytes_to_32(b: &[u8]) -> Result<[u8; 32], CodecError> {
    if b.len() != 32 {
        return Err(CodecError::Conversion(format!(
            "expected 32-byte field, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b);
    Ok(arr)
}

pub(crate) fn token_from_bytes(b: &[u8]) -> Result<Token, CodecError> {
    if b.len() != crate::tokens::TOKEN_LEN {
        return Err(CodecError::Conversion(format!(
            "expected {}-byte token, got {}",
            crate::tokens::TOKEN_LEN,
            b.len()
        )));
    }
    let mut arr = [0u8; crate::tokens::TOKEN_LEN];
    arr.copy_from_slice(b);
    Ok(Token(arr))
}

pub(crate) fn str0255(s: String) -> Result<stratum_core::binary_sv2::Str0255Owned, CodecError> {
    s.try_into().map_err(CodecError::from_conv)
}

// ── Messages both sub-protocols carry ───────────────────────────────

/// `protocol-version-mismatch`: the peer's `SetupConnection` version range
/// does not include [`crate::protocol_version::MIN_PROTOCOL_VERSION`].
/// One constant for both sub-protocols, as it answers the same message.
pub const ERR_PROTOCOL_VERSION_MISMATCH: &str = "protocol-version-mismatch";

/// `unsupported-protocol` — `SetupConnection.protocol` is not the
/// sub-protocol this port serves. Shared for the same reason as
/// [`ERR_PROTOCOL_VERSION_MISMATCH`].
pub const ERR_UNSUPPORTED_PROTOCOL: &str = "unsupported-protocol";

/// Inputs from a deserialized `SetupConnection` frame, narrowed to what the
/// handlers read. The mining and the JDP handler both take it.
#[derive(Clone, Debug)]
pub struct SetupConnectionInput {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub vendor: String,
}

/// The unused string fields are still checked: a non-UTF-8 one refuses the
/// connection setup.
pub(crate) fn decode_setup_connection(
    m: SetupConnection<'_>,
) -> Result<SetupConnectionInput, CodecError> {
    let vendor = utf8_from_bytes(m.vendor.as_bytes())?;
    utf8_from_bytes(m.firmware.as_bytes())?;
    utf8_from_bytes(m.hardware_version.as_bytes())?;
    utf8_from_bytes(m.device_id.as_bytes())?;
    Ok(SetupConnectionInput {
        protocol: m.protocol as u8,
        min_version: m.min_version,
        max_version: m.max_version,
        flags: m.flags,
        vendor,
    })
}

pub(crate) fn decode_request_extensions(m: Sv2RequestExtensions<'_>) -> RequestExtensions {
    RequestExtensions {
        request_id: m.request_id,
        requested_extensions: m.requested_extensions.into_inner(),
    }
}

pub(crate) fn setup_connection_success(used_version: u16, flags: u32) -> AnyMessageOwned {
    AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(
        SetupConnectionSuccessOwned {
            used_version,
            flags,
        },
    ))
}

pub(crate) fn setup_connection_error(
    flags: u32,
    error_code: String,
) -> Result<AnyMessageOwned, CodecError> {
    Ok(AnyMessageOwned::Common(
        CommonMessagesOwned::SetupConnectionError(SetupConnectionErrorOwned {
            flags,
            error_code: str0255(error_code)?,
        }),
    ))
}

pub(crate) fn request_extensions_success(
    request_id: u16,
    supported_extensions: Vec<u16>,
) -> Result<AnyMessageOwned, CodecError> {
    Ok(AnyMessageOwned::Extensions(
        ExtensionsOwned::ExtensionsNegotiation(
            ExtensionsNegotiationOwned::RequestExtensionsSuccess(RequestExtensionsSuccessOwned {
                request_id,
                supported_extensions: supported_extensions
                    .try_into()
                    .map_err(CodecError::from_conv)?,
            }),
        ),
    ))
}

pub(crate) fn request_extensions_error(
    request_id: u16,
    unsupported_extensions: Vec<u16>,
    required_extensions: Vec<u16>,
) -> Result<AnyMessageOwned, CodecError> {
    Ok(AnyMessageOwned::Extensions(
        ExtensionsOwned::ExtensionsNegotiation(ExtensionsNegotiationOwned::RequestExtensionsError(
            RequestExtensionsErrorOwned {
                request_id,
                unsupported_extensions: unsupported_extensions
                    .try_into()
                    .map_err(CodecError::from_conv)?,
                required_extensions: required_extensions
                    .try_into()
                    .map_err(CodecError::from_conv)?,
            },
        )),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::SV2_EXTENSION_TYPE_WORKER_ID;
    use stratum_core::codec_sv2::EncodableFrame;
    use stratum_core::mining_sv2::SubmitSharesStandard;
    use stratum_core::parsers_sv2::MiningOwned;

    /// A `SubmitSharesStandard` frame followed by `tlv_area`, split into the
    /// header and the payload the reader hands over.
    fn share_frame_with(tlv_area: &[u8]) -> (Header, Vec<u8>) {
        let msg =
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesStandard(SubmitSharesStandard {
                channel_id: 1,
                sequence_number: 2,
                job_id: 3,
                nonce: 4,
                ntime: 5,
                version: 0x2000_0000,
            }));
        let frame: MessageFrame<AnyMessageOwned> = msg.try_into().unwrap();
        let mut bytes = vec![0u8; frame.encoded_length()];
        frame.encode_into(&mut bytes).unwrap();
        bytes.extend_from_slice(tlv_area);
        let payload_len = (bytes.len() - Header::SIZE) as u32;
        bytes[3..6].copy_from_slice(&payload_len.to_le_bytes()[..3]);
        let header = Header::from_bytes(&bytes[..Header::SIZE]).unwrap();
        (header, bytes.split_off(Header::SIZE))
    }

    /// `n` empty Worker-ID TLVs, the cheapest kept TLV on the wire.
    fn empty_worker_tlvs(n: usize) -> Vec<u8> {
        let one = Tlv::new(SV2_EXTENSION_TYPE_WORKER_ID, 0x01, Vec::new())
            .encode()
            .unwrap();
        one.repeat(n)
    }

    /// An oversized TLV area is refused before any TLV is built, where the
    /// library parser builds every one; at the bound it still parses.
    #[test]
    fn an_inbound_tlv_area_is_bounded() {
        let per_tlv = empty_worker_tlvs(1).len();
        let over = MAX_INBOUND_TLV_BYTES / per_tlv + 1;
        let extensions = [SV2_EXTENSION_TYPE_WORKER_ID];

        let (header, mut payload) = share_frame_with(&empty_worker_tlvs(over));
        let (_, unbounded) = stratum_core::parsers_sv2::parse_message_frame_with_tlvs(
            header,
            &mut payload.clone(),
            &extensions,
        )
        .unwrap();
        assert_eq!(
            unbounded.map(|t| t.len()),
            Some(over),
            "control: the library keeps every TLV"
        );
        match parse_inbound_frame(header, &mut payload, &extensions) {
            Err(InboundParseError::TlvAreaTooLarge { tlv_bytes }) => {
                assert_eq!(tlv_bytes, over * per_tlv);
            }
            other => panic!("expected TlvAreaTooLarge, got {other:?}"),
        }

        let at_bound = MAX_INBOUND_TLV_BYTES / per_tlv;
        let (header, mut payload) = share_frame_with(&empty_worker_tlvs(at_bound));
        let (message, tlvs) = parse_inbound_frame(header, &mut payload, &extensions).unwrap();
        assert!(matches!(message, AnyMessage::Mining(_)));
        assert_eq!(tlvs.map(|t| t.len()), Some(at_bound));
    }
}
