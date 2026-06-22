// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 JDP-side wire-codec — analogous to [`crate::server_codec`] but
//! for the Job-Declaration sub-protocol.
//!
//! Maps `stratum_core::parsers_sv2::AnyMessage::JobDeclaration(...)`
//! variants ↔ the owned `Input` / `JdpOutboundFrame` shapes from
//! [`crate::jdp::client`]. Reuses [`crate::server_codec::CodecError`]
//! for error handling.
//!
//! ## Scope
//!
//! - **Inbound** (7 variants): SetupConnection (common), RequestExtensions
//!   (ext 0x0001), AllocateMiningJobToken, DeclareMiningJob,
//!   ProvideMissingTransactionsSuccess, PushSolution, and
//!   RequestPayoutOutputs (ext 0x0003 via the raw-bytes
//!   [`decode_jdp_inbound_ext_0x0003`] pre-decoder — `stratum-core::AnyMessage`
//!   doesn't carry it, so the IO layer dispatches by `extension_type`
//!   in the frame header).
//! - **Outbound** (10 variants): SetupConnection Success/Error,
//!   RequestExtensions Success/Error, AllocateMiningJobTokenSuccess,
//!   DeclareMiningJob Success/Error, ProvideMissingTransactions, and
//!   RequestPayoutOutputs Success/Error (ext 0x0003 via the raw-bytes
//!   [`encode_jdp_outbound_ext_0x0003`] pre-encoder, written into a
//!   `Sv2Frame::from_bytes_unchecked` with the manually-assembled
//!   6-byte header).
//!
//! ## Notes
//!
//! - **DeclareMiningJob.excess_data** is dropped on decode — reserved
//!   for future pool-side metadata.

use stratum_core::common_messages_sv2::{
    SetupConnection as Sv2SetupConnection, SetupConnectionError as Sv2SetupConnError,
    SetupConnectionSuccess as Sv2SetupConnSuccess,
};
use stratum_core::extensions_sv2::extensions_negotiation::{
    RequestExtensions as Sv2RequestExtensions, RequestExtensionsError as Sv2ReqExtError,
    RequestExtensionsSuccess as Sv2ReqExtSuccess,
};
use stratum_core::job_declaration_sv2::{
    AllocateMiningJobToken as Sv2AllocateMiningJobToken,
    AllocateMiningJobTokenSuccess as Sv2AllocateMiningJobTokenSuccess,
    DeclareMiningJob as Sv2DeclareMiningJob, DeclareMiningJobError as Sv2DeclareMiningJobError,
    DeclareMiningJobSuccess as Sv2DeclareMiningJobSuccess,
    ProvideMissingTransactions as Sv2ProvideMissingTransactions,
    ProvideMissingTransactionsSuccess as Sv2ProvideMissingTransactionsSuccess,
    PushSolution as Sv2PushSolution,
};
use stratum_core::parsers_sv2::{
    AnyMessage, CommonMessages, Extensions, ExtensionsNegotiation, JobDeclaration,
};

use crate::extensions::{
    RequestExtensions as LocalRequestExtensions, RequestPayoutOutputs as WireRequestPayoutOutputs,
    RequestPayoutOutputsError as WireRequestPayoutOutputsError,
    RequestPayoutOutputsSuccess as WireRequestPayoutOutputsSuccess,
    SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use crate::jdp::client::{
    AllocateMiningJobTokenInput, DeclareMiningJobInput, JdpOutboundFrame,
    ProvideMissingTransactionsSuccessInput, PushSolutionInput, RequestPayoutOutputsInput,
    SetupConnectionInput,
};
use crate::server_codec::CodecError;
use crate::tokens::Token;

// ── InboundJdpFrame ─────────────────────────────────────────────────

#[derive(Debug)]
pub enum InboundJdpFrame {
    SetupConnection(SetupConnectionInput),
    RequestExtensions(LocalRequestExtensions),
    AllocateMiningJobToken(AllocateMiningJobTokenInput),
    DeclareMiningJob(DeclareMiningJobInput),
    ProvideMissingTransactionsSuccess(ProvideMissingTransactionsSuccessInput),
    PushSolution(PushSolutionInput),
    /// ext 0x0003 §2.1 `RequestPayoutOutputs` — JDC → JDS. Not in
    /// `stratum-core::AnyMessage`, decoded via the raw-bytes path
    /// [`decode_jdp_inbound_ext_0x0003`] before the AnyMessage parser.
    RequestPayoutOutputs(RequestPayoutOutputsInput),
}

// ── decode_jdp_inbound ──────────────────────────────────────────────

/// ext 0x0003 §3 message types (channel_msg bit always unset).
pub const EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS: u8 = 0x00;
pub const EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_SUCCESS: u8 = 0x01;
pub const EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_ERROR: u8 = 0x02;

/// Raw-bytes decoder for ext 0x0003 inbound frames. Returns
/// `Ok(Some(_))` when the (extension_type, message_type) pair
/// identifies an ext 0x0003 frame this codec knows how to parse,
/// `Ok(None)` otherwise (caller falls through to the standard
/// `decode_jdp_inbound`).
///
/// The IO layer MUST call this **before** `parse_message_frame_with_tlvs`,
/// because `stratum-core::AnyMessage` doesn't carry the ext 0x0003
/// variants and the upstream parser would error on the unknown
/// `extension_type`.
pub fn decode_jdp_inbound_ext_0x0003(
    extension_type: u16,
    message_type: u8,
    payload: &[u8],
) -> Result<Option<InboundJdpFrame>, CodecError> {
    if extension_type != SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
        return Ok(None);
    }
    match message_type {
        EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS => {
            let wire = WireRequestPayoutOutputs::deserialize(payload).map_err(|e| {
                CodecError::Conversion(format!("ext 0x0003 RequestPayoutOutputs: {e:?}"))
            })?;
            // mining_job_token is B0_255 on the wire, but every token the
            // JDS ever issues is exactly TOKEN_LEN bytes. Reject any other
            // length rather than pad/truncate — a truncated >TOKEN_LEN
            // token could otherwise alias a different valid token's prefix.
            if wire.mining_job_token.len() != crate::tokens::TOKEN_LEN {
                return Err(CodecError::Conversion(format!(
                    "ext 0x0003 RequestPayoutOutputs: token len {} != {}",
                    wire.mining_job_token.len(),
                    crate::tokens::TOKEN_LEN
                )));
            }
            let mut token_bytes = [0u8; crate::tokens::TOKEN_LEN];
            token_bytes.copy_from_slice(&wire.mining_job_token);
            Ok(Some(InboundJdpFrame::RequestPayoutOutputs(
                RequestPayoutOutputsInput {
                    request_id: wire.request_id,
                    mining_job_token: Token(token_bytes),
                    available_payout_value: wire.available_payout_value,
                },
            )))
        }
        // 0x01 + 0x02 are JDS → JDC (Success / Error) — not expected inbound.
        other => Err(CodecError::Conversion(format!(
            "ext 0x0003 unknown / outbound-only msg_type 0x{other:02x}"
        ))),
    }
}

pub fn decode_jdp_inbound(msg: AnyMessage<'static>) -> Result<Option<InboundJdpFrame>, CodecError> {
    match msg {
        AnyMessage::Common(CommonMessages::SetupConnection(m)) => Ok(Some(
            InboundJdpFrame::SetupConnection(decode_setup_connection(m)?),
        )),
        AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensions(m),
        )) => Ok(Some(InboundJdpFrame::RequestExtensions(
            decode_request_extensions(m)?,
        ))),
        AnyMessage::JobDeclaration(m) => decode_job_declaration(m).map(Some),
        _ => Ok(None),
    }
}

fn decode_job_declaration(m: JobDeclaration<'static>) -> Result<InboundJdpFrame, CodecError> {
    match m {
        JobDeclaration::AllocateMiningJobToken(m) => {
            Ok(InboundJdpFrame::AllocateMiningJobToken(decode_allocate(m)?))
        }
        JobDeclaration::DeclareMiningJob(m) => {
            Ok(InboundJdpFrame::DeclareMiningJob(decode_declare(m)?))
        }
        JobDeclaration::ProvideMissingTransactionsSuccess(m) => Ok(
            InboundJdpFrame::ProvideMissingTransactionsSuccess(decode_provide_success(m)?),
        ),
        JobDeclaration::PushSolution(m) => {
            Ok(InboundJdpFrame::PushSolution(decode_push_solution(m)?))
        }
        other => Err(CodecError::NotMiningRelated(jdp_variant_name(&other))),
    }
}

fn jdp_variant_name(m: &JobDeclaration<'_>) -> &'static str {
    match m {
        JobDeclaration::AllocateMiningJobToken(_) => "AllocateMiningJobToken",
        JobDeclaration::AllocateMiningJobTokenSuccess(_) => "AllocateMiningJobTokenSuccess",
        JobDeclaration::DeclareMiningJob(_) => "DeclareMiningJob",
        JobDeclaration::DeclareMiningJobError(_) => "DeclareMiningJobError",
        JobDeclaration::DeclareMiningJobSuccess(_) => "DeclareMiningJobSuccess",
        JobDeclaration::ProvideMissingTransactions(_) => "ProvideMissingTransactions",
        JobDeclaration::ProvideMissingTransactionsSuccess(_) => "ProvideMissingTransactionsSuccess",
        JobDeclaration::PushSolution(_) => "PushSolution",
    }
}

// ── Per-variant decoders ────────────────────────────────────────────

fn decode_setup_connection(
    m: Sv2SetupConnection<'static>,
) -> Result<SetupConnectionInput, CodecError> {
    Ok(SetupConnectionInput {
        protocol: m.protocol as u8,
        min_version: m.min_version,
        max_version: m.max_version,
        flags: m.flags,
        vendor: utf8_from_bytes(m.vendor.inner_as_ref())?,
        firmware: utf8_from_bytes(m.firmware.inner_as_ref())?,
        hardware_version: utf8_from_bytes(m.hardware_version.inner_as_ref())?,
        device_id: utf8_from_bytes(m.device_id.inner_as_ref())?,
    })
}

fn decode_request_extensions(
    m: Sv2RequestExtensions<'static>,
) -> Result<LocalRequestExtensions, CodecError> {
    Ok(LocalRequestExtensions {
        request_id: m.request_id,
        requested_extensions: m.requested_extensions.into_inner(),
    })
}

fn decode_allocate(
    m: Sv2AllocateMiningJobToken<'static>,
) -> Result<AllocateMiningJobTokenInput, CodecError> {
    Ok(AllocateMiningJobTokenInput {
        request_id: m.request_id,
        user_identifier: utf8_from_bytes(m.user_identifier.inner_as_ref())?,
    })
}

fn decode_declare(m: Sv2DeclareMiningJob<'static>) -> Result<DeclareMiningJobInput, CodecError> {
    let mut wtxid_list = Vec::with_capacity(m.wtxid_list.inner_as_ref().len());
    for b in m.wtxid_list.inner_as_ref() {
        wtxid_list.push(bytes_to_32(b)?);
    }
    Ok(DeclareMiningJobInput {
        request_id: m.request_id,
        mining_job_token: token_from_bytes(m.mining_job_token.inner_as_ref())?,
        version: m.version,
        coinbase_tx_prefix: m.coinbase_tx_prefix.inner_as_ref().to_vec(),
        coinbase_tx_suffix: m.coinbase_tx_suffix.inner_as_ref().to_vec(),
        wtxid_list,
        // excess_data dropped — DEFERRED
    })
}

fn decode_provide_success(
    m: Sv2ProvideMissingTransactionsSuccess<'static>,
) -> Result<ProvideMissingTransactionsSuccessInput, CodecError> {
    let transaction_list: Vec<Vec<u8>> = m
        .transaction_list
        .inner_as_ref()
        .into_iter()
        .map(|b| b.to_vec())
        .collect();
    Ok(ProvideMissingTransactionsSuccessInput {
        request_id: m.request_id,
        transaction_list,
    })
}

fn decode_push_solution(m: Sv2PushSolution<'static>) -> Result<PushSolutionInput, CodecError> {
    Ok(PushSolutionInput {
        extranonce: m.extranonce.inner_as_ref().to_vec(),
        prev_hash: bytes_to_32(m.prev_hash.inner_as_ref())?,
        ntime: m.ntime,
        nonce: m.nonce,
        n_bits: m.nbits,
        version: m.version,
    })
}

// ── encode_jdp_outbound ─────────────────────────────────────────────

pub fn encode_jdp_outbound(frame: JdpOutboundFrame) -> Result<AnyMessage<'static>, CodecError> {
    match frame {
        JdpOutboundFrame::SetupConnectionSuccess {
            used_version,
            flags,
        } => Ok(AnyMessage::Common(CommonMessages::SetupConnectionSuccess(
            Sv2SetupConnSuccess {
                used_version,
                flags,
            },
        ))),
        JdpOutboundFrame::SetupConnectionError { flags, error_code } => {
            Ok(AnyMessage::Common(CommonMessages::SetupConnectionError(
                Sv2SetupConnError {
                    flags,
                    error_code: str0255(error_code)?,
                }
                .into_static(),
            )))
        }
        JdpOutboundFrame::RequestExtensionsSuccess {
            request_id,
            supported_extensions,
        } => Ok(AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensionsSuccess(
                Sv2ReqExtSuccess {
                    request_id,
                    supported_extensions: supported_extensions.into(),
                }
                .into_static(),
            ),
        ))),
        JdpOutboundFrame::RequestExtensionsError {
            request_id,
            unsupported_extensions,
            required_extensions,
        } => Ok(AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensionsError(
                Sv2ReqExtError {
                    request_id,
                    unsupported_extensions: unsupported_extensions.into(),
                    required_extensions: required_extensions.into(),
                }
                .into_static(),
            ),
        ))),
        JdpOutboundFrame::AllocateMiningJobTokenSuccess {
            request_id,
            mining_job_token,
            coinbase_outputs,
        } => Ok(AnyMessage::JobDeclaration(
            JobDeclaration::AllocateMiningJobTokenSuccess(
                Sv2AllocateMiningJobTokenSuccess {
                    request_id,
                    mining_job_token: mining_job_token.0.to_vec().try_into().map_err(conv)?,
                    coinbase_outputs: coinbase_outputs.try_into().map_err(conv)?,
                }
                .into_static(),
            ),
        )),
        JdpOutboundFrame::DeclareMiningJobSuccess {
            request_id,
            new_mining_job_token,
        } => Ok(AnyMessage::JobDeclaration(
            JobDeclaration::DeclareMiningJobSuccess(
                Sv2DeclareMiningJobSuccess {
                    request_id,
                    new_mining_job_token: new_mining_job_token
                        .0
                        .to_vec()
                        .try_into()
                        .map_err(conv)?,
                }
                .into_static(),
            ),
        )),
        JdpOutboundFrame::DeclareMiningJobError {
            request_id,
            error_code,
            error_details,
        } => Ok(AnyMessage::JobDeclaration(
            JobDeclaration::DeclareMiningJobError(
                Sv2DeclareMiningJobError {
                    request_id,
                    error_code: str0255(error_code)?,
                    error_details: error_details.try_into().map_err(conv)?,
                }
                .into_static(),
            ),
        )),
        JdpOutboundFrame::ProvideMissingTransactions {
            request_id,
            unknown_tx_position_list,
        } => Ok(AnyMessage::JobDeclaration(
            JobDeclaration::ProvideMissingTransactions(
                Sv2ProvideMissingTransactions {
                    request_id,
                    // u32 → u16 cast (SV2 wire field is u16; our local
                    // type uses u32 for ergonomic reasons. Values >65535
                    // would be a wtxid-list of >64K txs — impossible).
                    unknown_tx_position_list: unknown_tx_position_list
                        .into_iter()
                        .map(|x| x as u16)
                        .collect::<Vec<u16>>()
                        .into(),
                }
                .into_static(),
            ),
        )),
        // RequestPayoutOutputs Success/Error are ext 0x0003 — not in
        // `AnyMessage`. The JDP-server per-connection task takes them
        // through [`encode_jdp_outbound_ext_0x0003`] (raw-bytes path)
        // BEFORE falling back to this AnyMessage path.
        JdpOutboundFrame::RequestPayoutOutputsSuccess { .. }
        | JdpOutboundFrame::RequestPayoutOutputsError { .. } => {
            Err(CodecError::EncodeUnimplemented(
                "ext 0x0003 must go via encode_jdp_outbound_ext_0x0003",
            ))
        }
    }
}

/// Raw-bytes encoder for ext 0x0003 outbound frames. Returns
/// `Some((message_type, payload_bytes))` when the frame is an
/// ext 0x0003 variant the codec can serialise, `None` otherwise
/// (caller falls through to [`encode_jdp_outbound`]).
///
/// The returned `payload_bytes` is just the message body; the IO
/// layer wraps it in a `Sv2Frame` with the 6-byte header
/// `(extension_type=0x0003, message_type, msg_length=payload.len())`.
pub fn encode_jdp_outbound_ext_0x0003(frame: &JdpOutboundFrame) -> Option<(u8, Vec<u8>)> {
    match frame {
        JdpOutboundFrame::RequestPayoutOutputsSuccess {
            request_id,
            coinbase_outputs,
        } => {
            let wire = WireRequestPayoutOutputsSuccess {
                request_id: *request_id,
                coinbase_tx_outputs: coinbase_outputs.clone(),
            };
            Some((
                EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_SUCCESS,
                wire.serialize(),
            ))
        }
        JdpOutboundFrame::RequestPayoutOutputsError {
            request_id,
            error_code,
        } => {
            let wire = WireRequestPayoutOutputsError {
                request_id: *request_id,
                error_code: error_code.clone(),
            };
            Some((
                EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_ERROR,
                wire.serialize(),
            ))
        }
        _ => None,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn utf8_from_bytes(b: &[u8]) -> Result<String, CodecError> {
    std::str::from_utf8(b)
        .map(|s| s.to_string())
        .map_err(|e| CodecError::InvalidUtf8(e.to_string()))
}

fn bytes_to_32(b: &[u8]) -> Result<[u8; 32], CodecError> {
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

fn token_from_bytes(b: &[u8]) -> Result<Token, CodecError> {
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

fn str0255(s: String) -> Result<stratum_core::binary_sv2::Str0255<'static>, CodecError> {
    s.try_into().map_err(conv)
}

fn conv<E: core::fmt::Debug>(e: E) -> CodecError {
    CodecError::Conversion(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::{Seq064K, U256};
    use stratum_core::common_messages_sv2::Protocol;

    fn token(byte: u8) -> Token {
        Token([byte; 16])
    }

    #[test]
    fn decode_setup_connection_maps_fields() {
        let msg = AnyMessage::Common(CommonMessages::SetupConnection(Sv2SetupConnection {
            protocol: Protocol::JobDeclarationProtocol,
            min_version: 2,
            max_version: 2,
            flags: 1,
            endpoint_host: "host".to_string().try_into().unwrap(),
            endpoint_port: 4444,
            vendor: "v".to_string().try_into().unwrap(),
            hardware_version: "h".to_string().try_into().unwrap(),
            firmware: "f".to_string().try_into().unwrap(),
            device_id: "d".to_string().try_into().unwrap(),
        }));
        let out = decode_jdp_inbound(msg).unwrap().unwrap();
        match out {
            InboundJdpFrame::SetupConnection(i) => {
                assert_eq!(i.protocol, 1); // JobDeclarationProtocol
                assert_eq!(i.flags, 1);
                assert_eq!(i.vendor, "v");
            }
            _ => panic!("expected SetupConnection"),
        }
    }

    #[test]
    fn decode_allocate_token_maps_fields() {
        let msg = AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobToken(
            Sv2AllocateMiningJobToken {
                user_identifier: "bcrt1q...".to_string().try_into().unwrap(),
                request_id: 7,
            },
        ));
        let out = decode_jdp_inbound(msg).unwrap().unwrap();
        match out {
            InboundJdpFrame::AllocateMiningJobToken(i) => {
                assert_eq!(i.request_id, 7);
                assert_eq!(i.user_identifier, "bcrt1q...");
            }
            _ => panic!("expected AllocateMiningJobToken"),
        }
    }

    #[test]
    fn decode_declare_mining_job_maps_fields() {
        let wtxids: Vec<U256<'static>> = vec![[0x11u8; 32].into(), [0x22u8; 32].into()];
        let msg =
            AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJob(Sv2DeclareMiningJob {
                request_id: 5,
                mining_job_token: vec![0xAAu8; 16].try_into().unwrap(),
                version: 0x2000_0000,
                coinbase_tx_prefix: vec![0xBB; 8].try_into().unwrap(),
                coinbase_tx_suffix: vec![0xCC; 8].try_into().unwrap(),
                wtxid_list: Seq064K::new(wtxids).unwrap(),
                excess_data: vec![].try_into().unwrap(),
            }));
        let out = decode_jdp_inbound(msg).unwrap().unwrap();
        match out {
            InboundJdpFrame::DeclareMiningJob(i) => {
                assert_eq!(i.request_id, 5);
                assert_eq!(i.mining_job_token, Token([0xAA; 16]));
                assert_eq!(i.coinbase_tx_prefix, vec![0xBB; 8]);
                assert_eq!(i.wtxid_list.len(), 2);
                assert_eq!(i.wtxid_list[0], [0x11; 32]);
            }
            _ => panic!("expected DeclareMiningJob"),
        }
    }

    #[test]
    fn decode_push_solution_maps_fields() {
        let msg = AnyMessage::JobDeclaration(JobDeclaration::PushSolution(Sv2PushSolution {
            extranonce: vec![0xEE; 8].try_into().unwrap(),
            prev_hash: [0xAB; 32].into(),
            ntime: 0x6500_0001,
            nonce: 0xdeadbeef,
            nbits: 0x1d00_ffff,
            version: 0x2000_0000,
        }));
        let out = decode_jdp_inbound(msg).unwrap().unwrap();
        match out {
            InboundJdpFrame::PushSolution(i) => {
                assert_eq!(i.extranonce, vec![0xEE; 8]);
                assert_eq!(i.prev_hash, [0xAB; 32]);
                assert_eq!(i.nonce, 0xdeadbeef);
            }
            _ => panic!("expected PushSolution"),
        }
    }

    #[test]
    fn decode_provide_missing_success_maps_transactions() {
        let txs: Vec<stratum_core::binary_sv2::B016M<'static>> = vec![
            vec![0xAA, 0xBB].try_into().unwrap(),
            vec![0xCC, 0xDD].try_into().unwrap(),
        ];
        let msg = AnyMessage::JobDeclaration(JobDeclaration::ProvideMissingTransactionsSuccess(
            Sv2ProvideMissingTransactionsSuccess {
                request_id: 9,
                transaction_list: Seq064K::new(txs).unwrap(),
            },
        ));
        let out = decode_jdp_inbound(msg).unwrap().unwrap();
        match out {
            InboundJdpFrame::ProvideMissingTransactionsSuccess(i) => {
                assert_eq!(i.request_id, 9);
                assert_eq!(i.transaction_list.len(), 2);
                assert_eq!(i.transaction_list[0], vec![0xAA, 0xBB]);
            }
            _ => panic!("expected ProvideMissingTransactionsSuccess"),
        }
    }

    #[test]
    fn encode_setup_connection_success_roundtrips() {
        let frame = JdpOutboundFrame::SetupConnectionSuccess {
            used_version: 2,
            flags: 1,
        };
        let msg = encode_jdp_outbound(frame).unwrap();
        match msg {
            AnyMessage::Common(CommonMessages::SetupConnectionSuccess(s)) => {
                assert_eq!(s.used_version, 2);
                assert_eq!(s.flags, 1);
            }
            _ => panic!("expected SetupConnectionSuccess"),
        }
    }

    #[test]
    fn encode_allocate_token_success_maps_token_and_outputs() {
        let frame = JdpOutboundFrame::AllocateMiningJobTokenSuccess {
            request_id: 7,
            mining_job_token: token(0xAA),
            coinbase_outputs: vec![0x01, 0x02, 0x03],
        };
        let msg = encode_jdp_outbound(frame).unwrap();
        match msg {
            AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobTokenSuccess(s)) => {
                assert_eq!(s.request_id, 7);
                assert_eq!(s.mining_job_token.inner_as_ref(), &[0xAAu8; 16]);
                assert_eq!(s.coinbase_outputs.inner_as_ref(), &[0x01, 0x02, 0x03]);
            }
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    #[test]
    fn encode_declare_success_carries_new_token() {
        let frame = JdpOutboundFrame::DeclareMiningJobSuccess {
            request_id: 5,
            new_mining_job_token: token(0xCC),
        };
        let msg = encode_jdp_outbound(frame).unwrap();
        match msg {
            AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJobSuccess(s)) => {
                assert_eq!(s.request_id, 5);
                assert_eq!(s.new_mining_job_token.inner_as_ref(), &[0xCCu8; 16]);
            }
            _ => panic!("expected DeclareMiningJobSuccess"),
        }
    }

    #[test]
    fn encode_declare_error_carries_code_and_details() {
        let frame = JdpOutboundFrame::DeclareMiningJobError {
            request_id: 5,
            error_code: "invalid-mining-job-token".to_string(),
            error_details: b"token expired".to_vec(),
        };
        let msg = encode_jdp_outbound(frame).unwrap();
        match msg {
            AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJobError(s)) => {
                assert_eq!(
                    utf8_from_bytes(s.error_code.inner_as_ref()).unwrap(),
                    "invalid-mining-job-token"
                );
                assert_eq!(s.error_details.inner_as_ref(), b"token expired");
            }
            _ => panic!("expected DeclareMiningJobError"),
        }
    }

    #[test]
    fn encode_provide_missing_transactions_casts_positions() {
        let frame = JdpOutboundFrame::ProvideMissingTransactions {
            request_id: 7,
            unknown_tx_position_list: vec![0u32, 5u32, 1024u32],
        };
        let msg = encode_jdp_outbound(frame).unwrap();
        match msg {
            AnyMessage::JobDeclaration(JobDeclaration::ProvideMissingTransactions(s)) => {
                assert_eq!(s.request_id, 7);
                assert_eq!(s.unknown_tx_position_list.into_inner(), vec![0u16, 5, 1024]);
            }
            _ => panic!("expected ProvideMissingTransactions"),
        }
    }

    #[test]
    fn encode_request_payout_outputs_returns_unimplemented() {
        // ext 0x0003 lands in a separate codec path; the standard
        // codec rejects with EncodeUnimplemented.
        let frame = JdpOutboundFrame::RequestPayoutOutputsSuccess {
            request_id: 1,
            coinbase_outputs: vec![],
        };
        match encode_jdp_outbound(frame) {
            Err(CodecError::EncodeUnimplemented(s)) => {
                assert!(s.contains("ext 0x0003"));
            }
            _ => panic!("expected EncodeUnimplemented for ext 0x0003"),
        }
    }

    #[test]
    fn decode_mining_frame_returns_none() {
        // Mining-protocol frames are not JDP-relevant.
        let msg = AnyMessage::Mining(stratum_core::parsers_sv2::Mining::SubmitSharesStandard(
            stratum_core::mining_sv2::SubmitSharesStandard {
                channel_id: 1,
                sequence_number: 1,
                job_id: 1,
                nonce: 0,
                ntime: 0,
                version: 0,
            },
        ));
        assert!(decode_jdp_inbound(msg).unwrap().is_none());
    }

    // ── ext 0x0003 codec round-trips ────────────────────────────────

    #[test]
    fn ext_0x0003_inbound_decoder_parses_request_payout_outputs() {
        // Hand-build the wire payload: u32 request_id LE + B0_255 token
        // + u64 available_payout_value (NO prev_hash).
        let mut payload = Vec::new();
        payload.extend_from_slice(&42u32.to_le_bytes()); // request_id
        payload.push(16); // mining_job_token length (B0_255)
        let token_bytes: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];
        payload.extend_from_slice(&token_bytes);
        payload.extend_from_slice(&5_000_000_000u64.to_le_bytes()); // available_payout_value

        let frame = decode_jdp_inbound_ext_0x0003(
            0x0003,
            EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS,
            &payload,
        )
        .expect("decoder must accept")
        .expect("must produce a frame");

        match frame {
            InboundJdpFrame::RequestPayoutOutputs(input) => {
                assert_eq!(input.request_id, 42);
                assert_eq!(input.mining_job_token.0, token_bytes);
                assert_eq!(input.available_payout_value, 5_000_000_000);
            }
            other => panic!("expected RequestPayoutOutputs, got {other:?}"),
        }
    }

    #[test]
    fn ext_0x0003_inbound_decoder_rejects_wrong_token_length() {
        // request_id + B0_255 token of length 15 (≠ TOKEN_LEN) + value.
        for bad_len in [0u8, 15, 17] {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1u32.to_le_bytes());
            payload.push(bad_len);
            payload.extend(std::iter::repeat_n(0xAAu8, bad_len as usize));
            payload.extend_from_slice(&5_000_000_000u64.to_le_bytes());
            let r = decode_jdp_inbound_ext_0x0003(
                0x0003,
                EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS,
                &payload,
            );
            assert!(
                r.is_err(),
                "token len {bad_len} must be rejected, not padded"
            );
        }
    }

    #[test]
    fn ext_0x0003_inbound_decoder_returns_none_for_other_extensions() {
        let payload = vec![0u8; 16];
        let r = decode_jdp_inbound_ext_0x0003(0x0001, 0x00, &payload).unwrap();
        assert!(r.is_none(), "0x0001 frame must not match the 0x0003 path");
    }

    #[test]
    fn ext_0x0003_inbound_decoder_rejects_outbound_only_msg_types() {
        let payload = vec![0u8; 16];
        for outbound_only in [
            EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_SUCCESS,
            EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_ERROR,
        ] {
            let r = decode_jdp_inbound_ext_0x0003(0x0003, outbound_only, &payload);
            assert!(
                r.is_err(),
                "outbound-only msg_type 0x{outbound_only:02x} must error inbound"
            );
        }
    }

    #[test]
    fn ext_0x0003_outbound_encoder_serializes_success_frame() {
        let frame = JdpOutboundFrame::RequestPayoutOutputsSuccess {
            request_id: 99,
            coinbase_outputs: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let (msg_type, payload) =
            encode_jdp_outbound_ext_0x0003(&frame).expect("encoder must accept Success");
        assert_eq!(msg_type, EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_SUCCESS);
        // Wire layout: u32 request_id LE + B0_64K (u16 LE len) + bytes.
        assert_eq!(&payload[0..4], &99u32.to_le_bytes());
        assert_eq!(&payload[4..6], &4u16.to_le_bytes()); // outputs len
        assert_eq!(&payload[6..10], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn ext_0x0003_outbound_encoder_serializes_error_frame() {
        let frame = JdpOutboundFrame::RequestPayoutOutputsError {
            request_id: 7,
            error_code: "stale-payout-outputs".to_string(),
        };
        let (msg_type, payload) =
            encode_jdp_outbound_ext_0x0003(&frame).expect("encoder must accept Error");
        assert_eq!(msg_type, EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS_ERROR);
        assert_eq!(&payload[0..4], &7u32.to_le_bytes());
        // STR0_255 with 20-byte length prefix.
        assert_eq!(payload[4], 20);
        assert_eq!(&payload[5..25], b"stale-payout-outputs");
    }

    #[test]
    fn ext_0x0003_outbound_encoder_returns_none_for_non_ext_frames() {
        let frame = JdpOutboundFrame::SetupConnectionSuccess {
            used_version: 2,
            flags: 0,
        };
        assert!(encode_jdp_outbound_ext_0x0003(&frame).is_none());
    }

    #[test]
    fn ext_0x0003_roundtrip_inbound_decode_matches_wire_serialize() {
        use crate::extensions::RequestPayoutOutputs as Wire;
        let original = Wire {
            request_id: 12345,
            mining_job_token: vec![0xa1; 16],
            available_payout_value: 9_876_543_210,
        };
        let bytes = original.serialize();
        let frame = decode_jdp_inbound_ext_0x0003(
            0x0003,
            EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS,
            &bytes,
        )
        .unwrap()
        .unwrap();
        match frame {
            InboundJdpFrame::RequestPayoutOutputs(input) => {
                assert_eq!(input.request_id, original.request_id);
                assert_eq!(
                    &input.mining_job_token.0[..],
                    &original.mining_job_token[..]
                );
                assert_eq!(
                    input.available_payout_value,
                    original.available_payout_value
                );
            }
            _ => panic!("wrong variant"),
        }
    }
}
