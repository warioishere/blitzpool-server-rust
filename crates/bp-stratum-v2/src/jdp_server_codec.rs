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
//! - **Inbound** (6 variants): SetupConnection (common), RequestExtensions
//!   (ext 0x0001), AllocateMiningJobToken, DeclareMiningJob,
//!   ProvideMissingTransactionsSuccess and PushSolution. Ext 0x0003 has
//!   no inbound message — the payout distribution is server-push only.
//! - **Outbound** (9 variants): SetupConnection Success/Error,
//!   RequestExtensions Success/Error, AllocateMiningJobTokenSuccess,
//!   DeclareMiningJob Success/Error, ProvideMissingTransactions, and
//!   SetPayoutDistribution (ext 0x0003 via the raw-bytes
//!   [`encode_jdp_outbound_ext_0x0003`] pre-encoder —
//!   `stratum-core::AnyMessage` doesn't carry it, so it is written into
//!   a `Sv2Frame::from_bytes_unchecked` with the manually-assembled
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

use crate::extensions::RequestExtensions as LocalRequestExtensions;
use crate::jdp::client::{
    AllocateMiningJobTokenInput, DeclareMiningJobInput, JdpOutboundFrame,
    ProvideMissingTransactionsSuccessInput, PushSolutionInput, SetupConnectionInput,
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
}

// ── decode_jdp_inbound ──────────────────────────────────────────────

/// ext 0x0003 §8 message type: `SetPayoutDistribution` (JDS → JDC,
/// channel_msg bit unset). The push model defines no inbound ext-0x0003
/// frames — the `distribution_id` reference arrives as a §6 TLV on the
/// base-protocol `DeclareMiningJob` / `SetCustomMiningJob` frames.
pub const EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION: u8 = 0x00;

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
        vendor: utf8_from_bytes(m.vendor.as_bytes())?,
        firmware: utf8_from_bytes(m.firmware.as_bytes())?,
        hardware_version: utf8_from_bytes(m.hardware_version.as_bytes())?,
        device_id: utf8_from_bytes(m.device_id.as_bytes())?,
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
        user_identifier: utf8_from_bytes(m.user_identifier.as_bytes())?,
    })
}

fn decode_declare(m: Sv2DeclareMiningJob<'static>) -> Result<DeclareMiningJobInput, CodecError> {
    let mut wtxid_list = Vec::with_capacity(m.wtxid_list.as_slice().len());
    for b in m.wtxid_list.iter_bytes() {
        wtxid_list.push(bytes_to_32(b)?);
    }
    Ok(DeclareMiningJobInput {
        // §6 TLV — extracted by the IO layer from the frame's trailing
        // TLVs, not part of the base-message decode.
        distribution_id: None,
        request_id: m.request_id,
        mining_job_token: token_from_bytes(m.mining_job_token.as_bytes())?,
        version: m.version,
        coinbase_tx_prefix: m.coinbase_tx_prefix.as_bytes().to_vec(),
        coinbase_tx_suffix: m.coinbase_tx_suffix.as_bytes().to_vec(),
        wtxid_list,
        // excess_data dropped — DEFERRED
    })
}

fn decode_provide_success(
    m: Sv2ProvideMissingTransactionsSuccess<'static>,
) -> Result<ProvideMissingTransactionsSuccessInput, CodecError> {
    let transaction_list: Vec<Vec<u8>> = m
        .transaction_list
        .iter_bytes()
        .map(|b| b.to_vec())
        .collect();
    Ok(ProvideMissingTransactionsSuccessInput {
        request_id: m.request_id,
        transaction_list,
    })
}

fn decode_push_solution(m: Sv2PushSolution<'static>) -> Result<PushSolutionInput, CodecError> {
    Ok(PushSolutionInput {
        extranonce: m.extranonce.as_bytes().to_vec(),
        prev_hash: bytes_to_32(m.prev_hash.as_bytes())?,
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
                    supported_extensions: supported_extensions.try_into().map_err(conv)?,
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
                    unsupported_extensions: unsupported_extensions.try_into().map_err(conv)?,
                    required_extensions: required_extensions.try_into().map_err(conv)?,
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
                        .try_into()
                        .map_err(conv)?,
                }
                .into_static(),
            ),
        )),
        // SetPayoutDistribution is ext 0x0003 — not in `AnyMessage`.
        // The JDP-server per-connection task takes it through
        // [`encode_jdp_outbound_ext_0x0003`] (raw-bytes path) BEFORE
        // falling back to this AnyMessage path.
        JdpOutboundFrame::SetPayoutDistribution(_) => Err(CodecError::EncodeUnimplemented(
            "ext 0x0003 must go via encode_jdp_outbound_ext_0x0003",
        )),
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
        JdpOutboundFrame::SetPayoutDistribution(msg) => {
            Some((EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION, msg.serialize()))
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
                assert_eq!(s.mining_job_token.as_bytes(), &[0xAAu8; 16]);
                assert_eq!(s.coinbase_outputs.as_bytes(), &[0x01, 0x02, 0x03]);
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
                assert_eq!(s.new_mining_job_token.as_bytes(), &[0xCCu8; 16]);
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
                    utf8_from_bytes(s.error_code.as_bytes()).unwrap(),
                    "invalid-mining-job-token"
                );
                assert_eq!(s.error_details.as_bytes(), b"token expired");
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
    fn encode_set_payout_distribution_returns_unimplemented_on_anymessage_path() {
        // ext 0x0003 lands in a separate codec path; the standard
        // codec rejects with EncodeUnimplemented.
        let frame =
            JdpOutboundFrame::SetPayoutDistribution(crate::extensions::SetPayoutDistribution {
                distribution_id: 1,
                pool_payout: vec![0xAA; 30],
                payouts: vec![],
                dust_limits: vec![],
                additional_outputs: vec![],
            });
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

    // ── ext 0x0003 codec (push model) ───────────────────────────────

    #[test]
    fn ext_0x0003_outbound_encoder_serializes_set_payout_distribution() {
        let msg = crate::extensions::SetPayoutDistribution {
            distribution_id: 42,
            pool_payout: vec![0xAA; 30],
            payouts: vec![vec![0x01; 31]],
            dust_limits: vec![546],
            additional_outputs: vec![],
        };
        let (msg_type, payload) =
            encode_jdp_outbound_ext_0x0003(&JdpOutboundFrame::SetPayoutDistribution(msg.clone()))
                .expect("ext 0x0003 frame");
        assert_eq!(msg_type, EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION);
        let parsed = crate::extensions::SetPayoutDistribution::deserialize(&payload).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn ext_0x0003_outbound_encoder_returns_none_for_base_frames() {
        let frame = JdpOutboundFrame::SetupConnectionSuccess {
            used_version: 2,
            flags: 0,
        };
        assert!(encode_jdp_outbound_ext_0x0003(&frame).is_none());
    }
}
