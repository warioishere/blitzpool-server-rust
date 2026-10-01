// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 JDP wire codec: maps `AnyMessage::JobDeclaration(...)` to and from the
//! owned shapes in [`crate::jdp::client`].
//!
//! Ext 0x0003 has no inbound message. Its outbound `SetPayoutDistribution` is
//! not in `stratum-core::AnyMessage`, so [`encode_jdp_outbound`] returns it as
//! [`JdpWireFrame::Ext0x0003`] bytes for the IO layer to frame by hand.
//! `DeclareMiningJob.excess_data` is dropped on decode.

use stratum_core::job_declaration_sv2::{
    AllocateMiningJobToken as Sv2AllocateMiningJobToken,
    AllocateMiningJobTokenSuccessOwned as Sv2AllocateMiningJobTokenSuccess,
    DeclareMiningJob as Sv2DeclareMiningJob,
    DeclareMiningJobErrorOwned as Sv2DeclareMiningJobError,
    DeclareMiningJobSuccessOwned as Sv2DeclareMiningJobSuccess,
    ProvideMissingTransactionsOwned as Sv2ProvideMissingTransactions,
    ProvideMissingTransactionsSuccess as Sv2ProvideMissingTransactionsSuccess,
    PushSolution as Sv2PushSolution,
};
use stratum_core::parsers_sv2::{
    AnyMessage, AnyMessageOwned, CommonMessages, Extensions, ExtensionsNegotiation, JobDeclaration,
    JobDeclarationOwned,
};

use crate::codec_common::{
    bytes_to_32, decode_request_extensions, decode_setup_connection, request_extensions_error,
    request_extensions_success, setup_connection_error, setup_connection_success, str0255,
    token_from_bytes, utf8_from_bytes, CodecError, SetupConnectionInput,
};
use crate::extensions::RequestExtensions as LocalRequestExtensions;
use crate::jdp::client::{
    AllocateMiningJobTokenInput, DeclareMiningJobInput, JdpOutboundFrame,
    ProvideMissingTransactionsSuccessInput, PushSolutionInput, SolutionHeader,
};

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

/// ext 0x0003/Message Types: `SetPayoutDistribution` (JDS → JDC, channel_msg bit unset).
pub const EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION: u8 = 0x00;

pub fn decode_jdp_inbound(msg: AnyMessage<'_>) -> Result<Option<InboundJdpFrame>, CodecError> {
    match msg {
        AnyMessage::Common(CommonMessages::SetupConnection(m)) => Ok(Some(
            InboundJdpFrame::SetupConnection(decode_setup_connection(m)?),
        )),
        AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensions(m),
        )) => Ok(Some(InboundJdpFrame::RequestExtensions(
            decode_request_extensions(m),
        ))),
        AnyMessage::JobDeclaration(m) => decode_job_declaration(m).map(Some),
        _ => Ok(None),
    }
}

fn decode_job_declaration(m: JobDeclaration<'_>) -> Result<InboundJdpFrame, CodecError> {
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
        other => Err(CodecError::NotForThisSubProtocol(jdp_variant_name(&other))),
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

fn decode_allocate(
    m: Sv2AllocateMiningJobToken<'_>,
) -> Result<AllocateMiningJobTokenInput, CodecError> {
    Ok(AllocateMiningJobTokenInput {
        request_id: m.request_id,
        user_identifier: utf8_from_bytes(m.user_identifier.as_bytes())?,
    })
}

fn decode_declare(m: Sv2DeclareMiningJob<'_>) -> Result<DeclareMiningJobInput, CodecError> {
    let mut wtxid_list = Vec::with_capacity(m.wtxid_list.as_slice().len());
    for b in m.wtxid_list.iter_bytes() {
        wtxid_list.push(bytes_to_32(b)?);
    }
    Ok(DeclareMiningJobInput {
        // ext 0x0003/distribution_id TLV Field: filled in by the IO layer.
        distribution_id: None,
        request_id: m.request_id,
        mining_job_token: token_from_bytes(m.mining_job_token.as_bytes())?,
        version: m.version,
        coinbase_tx_prefix: m.coinbase_tx_prefix.as_bytes().to_vec(),
        coinbase_tx_suffix: m.coinbase_tx_suffix.as_bytes().to_vec(),
        wtxid_list,
    })
}

fn decode_provide_success(
    m: Sv2ProvideMissingTransactionsSuccess<'_>,
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

fn decode_push_solution(m: Sv2PushSolution<'_>) -> Result<PushSolutionInput, CodecError> {
    Ok(PushSolutionInput {
        extranonce: m.extranonce.as_bytes().to_vec(),
        header: SolutionHeader {
            prev_hash: bytes_to_32(m.prev_hash.as_bytes())?,
            version: m.version,
            ntime: m.ntime,
            nonce: m.nonce,
            n_bits: m.nbits,
        },
    })
}

// ── encode_jdp_outbound ─────────────────────────────────────────────

/// What the wire gets for one outbound JDP frame.
#[derive(Debug)]
pub enum JdpWireFrame {
    /// A base-protocol message; the IO layer wraps it in a `MessageFrame`.
    Message(AnyMessageOwned),
    /// An ext 0x0003 body; the IO layer frames it with `(0x0003, msg_type, len)`.
    Ext0x0003 { msg_type: u8, payload: Vec<u8> },
}

pub fn encode_jdp_outbound(frame: JdpOutboundFrame) -> Result<JdpWireFrame, CodecError> {
    let message = match frame {
        JdpOutboundFrame::SetupConnectionSuccess {
            used_version,
            flags,
        } => setup_connection_success(used_version, flags),
        JdpOutboundFrame::SetupConnectionError { flags, error_code } => {
            setup_connection_error(flags, error_code)?
        }
        JdpOutboundFrame::RequestExtensionsSuccess {
            request_id,
            supported_extensions,
        } => request_extensions_success(request_id, supported_extensions)?,
        JdpOutboundFrame::RequestExtensionsError {
            request_id,
            unsupported_extensions,
            required_extensions,
        } => request_extensions_error(request_id, unsupported_extensions, required_extensions)?,
        JdpOutboundFrame::AllocateMiningJobTokenSuccess {
            request_id,
            mining_job_token,
            coinbase_outputs,
        } => AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobTokenSuccess(
            Sv2AllocateMiningJobTokenSuccess {
                request_id,
                mining_job_token: mining_job_token
                    .0
                    .to_vec()
                    .try_into()
                    .map_err(CodecError::from_conv)?,
                coinbase_outputs: coinbase_outputs.try_into().map_err(CodecError::from_conv)?,
            },
        )),
        JdpOutboundFrame::DeclareMiningJobSuccess {
            request_id,
            new_mining_job_token,
        } => AnyMessageOwned::JobDeclaration(JobDeclarationOwned::DeclareMiningJobSuccess(
            Sv2DeclareMiningJobSuccess {
                request_id,
                new_mining_job_token: new_mining_job_token
                    .0
                    .to_vec()
                    .try_into()
                    .map_err(CodecError::from_conv)?,
            },
        )),
        JdpOutboundFrame::DeclareMiningJobError {
            request_id,
            error_code,
            error_details,
        } => AnyMessageOwned::JobDeclaration(JobDeclarationOwned::DeclareMiningJobError(
            Sv2DeclareMiningJobError {
                request_id,
                error_code: str0255(error_code)?,
                error_details: error_details.try_into().map_err(CodecError::from_conv)?,
            },
        )),
        JdpOutboundFrame::ProvideMissingTransactions {
            request_id,
            unknown_tx_position_list,
        } => AnyMessageOwned::JobDeclaration(JobDeclarationOwned::ProvideMissingTransactions(
            Sv2ProvideMissingTransactions {
                request_id,
                // Positions index a `Seq064K` list, so they fit in u16.
                unknown_tx_position_list: unknown_tx_position_list
                    .into_iter()
                    .map(|x| x as u16)
                    .collect::<Vec<u16>>()
                    .try_into()
                    .map_err(CodecError::from_conv)?,
            },
        )),
        JdpOutboundFrame::SetPayoutDistribution(msg) => {
            return Ok(JdpWireFrame::Ext0x0003 {
                msg_type: EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION,
                payload: msg.serialize(),
            });
        }
    };
    Ok(JdpWireFrame::Message(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::Token;
    use stratum_core::binary_sv2::{Seq064K, U256};
    use stratum_core::common_messages_sv2::Protocol;
    use stratum_core::common_messages_sv2::SetupConnection as Sv2SetupConnection;
    use stratum_core::parsers_sv2::CommonMessagesOwned;

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
            endpoint_host: "host".try_into().unwrap(),
            endpoint_port: 4444,
            vendor: "v".try_into().unwrap(),
            hardware_version: "h".try_into().unwrap(),
            firmware: "f".try_into().unwrap(),
            device_id: "d".try_into().unwrap(),
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
                user_identifier: "bcrt1q...".try_into().unwrap(),
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
        let wtxids: Vec<U256<'static>> = vec![(&[0x11u8; 32]).into(), (&[0x22u8; 32]).into()];
        let msg =
            AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJob(Sv2DeclareMiningJob {
                request_id: 5,
                mining_job_token: (&[0xAAu8; 16]).try_into().unwrap(),
                version: 0x2000_0000,
                coinbase_tx_prefix: (&[0xBB; 8]).try_into().unwrap(),
                coinbase_tx_suffix: (&[0xCC; 8]).try_into().unwrap(),
                wtxid_list: Seq064K::new(wtxids).unwrap(),
                excess_data: (&[0u8; 0]).try_into().unwrap(),
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
            extranonce: (&[0xEE; 8]).try_into().unwrap(),
            prev_hash: (&[0xAB; 32]).into(),
            ntime: 0x6500_0001,
            nonce: 0xdeadbeef,
            nbits: 0x1d00_ffff,
            version: 0x2000_0000,
        }));
        let out = decode_jdp_inbound(msg).unwrap().unwrap();
        match out {
            InboundJdpFrame::PushSolution(i) => {
                assert_eq!(i.extranonce, vec![0xEE; 8]);
                assert_eq!(i.header.prev_hash, [0xAB; 32]);
                assert_eq!(i.header.nonce, 0xdeadbeef);
                assert_eq!(i.header.n_bits, 0x1d00_ffff);
                assert_eq!(i.header.version, 0x2000_0000);
            }
            _ => panic!("expected PushSolution"),
        }
    }

    #[test]
    fn decode_provide_missing_success_maps_transactions() {
        let txs: Vec<stratum_core::binary_sv2::B016M<'static>> = vec![
            (&[0xAAu8, 0xBB]).try_into().unwrap(),
            (&[0xCCu8, 0xDD]).try_into().unwrap(),
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

    /// The base-protocol message an encoded frame carries; panics on ext 0x0003.
    fn message_of(frame: JdpOutboundFrame) -> AnyMessageOwned {
        match encode_jdp_outbound(frame).unwrap() {
            JdpWireFrame::Message(m) => m,
            other => panic!("expected a base-protocol message, got {other:?}"),
        }
    }

    #[test]
    fn encode_setup_connection_success_roundtrips() {
        let frame = JdpOutboundFrame::SetupConnectionSuccess {
            used_version: 2,
            flags: 1,
        };
        let msg = message_of(frame);
        match msg {
            AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(s)) => {
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
        let msg = message_of(frame);
        match msg {
            AnyMessageOwned::JobDeclaration(
                JobDeclarationOwned::AllocateMiningJobTokenSuccess(s),
            ) => {
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
        let msg = message_of(frame);
        match msg {
            AnyMessageOwned::JobDeclaration(JobDeclarationOwned::DeclareMiningJobSuccess(s)) => {
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
        let msg = message_of(frame);
        match msg {
            AnyMessageOwned::JobDeclaration(JobDeclarationOwned::DeclareMiningJobError(s)) => {
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
        let msg = message_of(frame);
        match msg {
            AnyMessageOwned::JobDeclaration(JobDeclarationOwned::ProvideMissingTransactions(s)) => {
                assert_eq!(s.request_id, 7);
                assert_eq!(s.unknown_tx_position_list.into_inner(), vec![0u16, 5, 1024]);
            }
            _ => panic!("expected ProvideMissingTransactions"),
        }
    }

    #[test]
    fn encode_set_payout_distribution_leaves_as_ext_0x0003_bytes() {
        let msg = crate::extensions::SetPayoutDistribution {
            distribution_id: 42,
            pool_payout: vec![0xAA; 30],
            payouts: vec![vec![0x01; 31]],
            dust_limits: vec![546],
            additional_outputs: vec![],
        };
        let JdpWireFrame::Ext0x0003 { msg_type, payload } =
            encode_jdp_outbound(JdpOutboundFrame::SetPayoutDistribution(msg.clone())).unwrap()
        else {
            panic!("ext 0x0003 must not be forced into AnyMessage");
        };
        assert_eq!(msg_type, EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION);
        let parsed = crate::extensions::SetPayoutDistribution::deserialize(&payload).unwrap();
        assert_eq!(parsed, msg);
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
}
