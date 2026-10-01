// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 mining wire-codec: the boundary between the borrowed
//! [`stratum_core::parsers_sv2`] types and the owned `Input` / `OutboundFrame`
//! shapes of [`crate::mining::client`], which stay lifetime-free so they test
//! easily. JDP has its own codec of the same shape, [`crate::jdp_server_codec`].

use stratum_core::mining_sv2::{
    CloseChannel as Sv2CloseChannel, NewExtendedMiningJobOwned as Sv2NewExtMiningJob,
    NewMiningJobOwned as Sv2NewMiningJob, OpenExtendedMiningChannel as Sv2OpenExtChannel,
    OpenExtendedMiningChannelSuccessOwned as Sv2OpenExtChannelSuccess,
    OpenMiningChannelErrorOwned as Sv2OpenChannelError,
    OpenStandardMiningChannel as Sv2OpenStdChannel,
    OpenStandardMiningChannelSuccessOwned as Sv2OpenStdChannelSuccess,
    SetCustomMiningJob as Sv2SetCustomMiningJob,
    SetCustomMiningJobErrorOwned as Sv2SetCustomMiningJobError,
    SetCustomMiningJobSuccessOwned as Sv2SetCustomMiningJobSuccess,
    SetExtranoncePrefixOwned as Sv2SetExtranoncePrefix,
    SetNewPrevHashOwned as Sv2MiningSetNewPrevHash, SetTargetOwned as Sv2SetTarget,
    SubmitSharesErrorOwned as Sv2SubmitSharesError,
    SubmitSharesExtended as Sv2SubmitSharesExtended,
    SubmitSharesStandard as Sv2SubmitSharesStandard,
    SubmitSharesSuccessOwned as Sv2SubmitSharesSuccess, UpdateChannel as Sv2UpdateChannel,
    UpdateChannelErrorOwned as Sv2UpdateChannelError,
};
use stratum_core::parsers_sv2::{
    AnyMessage, AnyMessageOwned, CommonMessages, Extensions, ExtensionsNegotiation, Mining,
    MiningOwned,
};

use crate::codec_common::{
    bytes_to_32, decode_request_extensions, decode_setup_connection, request_extensions_error,
    request_extensions_success, setup_connection_error, setup_connection_success, str0255,
    token_from_bytes, utf8_from_bytes, CodecError, SetupConnectionInput,
};
use crate::extensions::RequestExtensions as LocalRequestExtensions;
use crate::mining::client::{
    CloseChannelInput, OpenExtendedMiningChannelInput, OpenStandardMiningChannelInput,
    OutboundFrame, SetCustomMiningJobInput, UpdateChannelInput,
};
use crate::mining::submit::{SubmitSharesExtendedInput, SubmitSharesStandardInput};

// ── InboundMiningFrame ──────────────────────────────────────────────

/// Every wire-frame variant the mining server cares about, mapped to
/// the typed `Input` struct the matching `handle_*` function expects.
#[derive(Debug)]
pub enum InboundMiningFrame {
    SetupConnection(SetupConnectionInput),
    RequestExtensions(LocalRequestExtensions),
    OpenStandardMiningChannel(OpenStandardMiningChannelInput, Vec<u8>),
    OpenExtendedMiningChannel(OpenExtendedMiningChannelInput, Vec<u8>),
    UpdateChannel(UpdateChannelInput),
    CloseChannel(CloseChannelInput),
    SubmitSharesStandard(SubmitSharesStandardInput),
    SubmitSharesExtended(SubmitSharesExtendedInput),
    SetCustomMiningJob(SetCustomMiningJobInput),
}

// ── decode_mining_inbound ───────────────────────────────────────────

/// Translate one wire-shape SV2 message into an [`InboundMiningFrame`].
/// `Ok(None)` is "not a mining-server message" (log + ignore); `Err` is a
/// malformed frame, which is dropped while the connection survives.
pub fn decode_mining_inbound(
    msg: AnyMessage<'_>,
) -> Result<Option<InboundMiningFrame>, CodecError> {
    match msg {
        AnyMessage::Common(CommonMessages::SetupConnection(m)) => Ok(Some(
            InboundMiningFrame::SetupConnection(decode_setup_connection(m)?),
        )),
        AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensions(m),
        )) => Ok(Some(InboundMiningFrame::RequestExtensions(
            decode_request_extensions(m),
        ))),
        AnyMessage::Mining(m) => decode_mining_message(m).map(Some),
        _ => Ok(None),
    }
}

fn decode_mining_message(m: Mining<'_>) -> Result<InboundMiningFrame, CodecError> {
    match m {
        Mining::OpenStandardMiningChannel(m) => {
            let (input, prefix) = decode_open_std_channel(m)?;
            Ok(InboundMiningFrame::OpenStandardMiningChannel(input, prefix))
        }
        Mining::OpenExtendedMiningChannel(m) => {
            let (input, prefix) = decode_open_ext_channel(m)?;
            Ok(InboundMiningFrame::OpenExtendedMiningChannel(input, prefix))
        }
        Mining::UpdateChannel(m) => {
            Ok(InboundMiningFrame::UpdateChannel(decode_update_channel(m)?))
        }
        Mining::CloseChannel(m) => Ok(InboundMiningFrame::CloseChannel(decode_close_channel(m)?)),
        Mining::SubmitSharesStandard(m) => Ok(InboundMiningFrame::SubmitSharesStandard(
            decode_submit_shares_standard(m),
        )),
        Mining::SubmitSharesExtended(m) => Ok(InboundMiningFrame::SubmitSharesExtended(
            decode_submit_shares_extended(m)?,
        )),
        Mining::SetCustomMiningJob(m) => Ok(InboundMiningFrame::SetCustomMiningJob(
            decode_set_custom_mining_job(m)?,
        )),
        other => Err(CodecError::NotForThisSubProtocol(mining_variant_name(
            &other,
        ))),
    }
}

fn mining_variant_name(m: &Mining<'_>) -> &'static str {
    match m {
        Mining::CloseChannel(_) => "CloseChannel",
        Mining::NewExtendedMiningJob(_) => "NewExtendedMiningJob",
        Mining::NewMiningJob(_) => "NewMiningJob",
        Mining::OpenExtendedMiningChannel(_) => "OpenExtendedMiningChannel",
        Mining::OpenExtendedMiningChannelSuccess(_) => "OpenExtendedMiningChannelSuccess",
        Mining::OpenMiningChannelError(_) => "OpenMiningChannelError",
        Mining::OpenStandardMiningChannel(_) => "OpenStandardMiningChannel",
        Mining::OpenStandardMiningChannelSuccess(_) => "OpenStandardMiningChannelSuccess",
        Mining::SetCustomMiningJob(_) => "SetCustomMiningJob",
        Mining::SetCustomMiningJobError(_) => "SetCustomMiningJobError",
        Mining::SetCustomMiningJobSuccess(_) => "SetCustomMiningJobSuccess",
        Mining::SetExtranoncePrefix(_) => "SetExtranoncePrefix",
        Mining::SetGroupChannel(_) => "SetGroupChannel",
        Mining::SetNewPrevHash(_) => "SetNewPrevHash",
        Mining::SetTarget(_) => "SetTarget",
        Mining::SubmitSharesError(_) => "SubmitSharesError",
        Mining::SubmitSharesExtended(_) => "SubmitSharesExtended",
        Mining::SubmitSharesStandard(_) => "SubmitSharesStandard",
        Mining::SubmitSharesSuccess(_) => "SubmitSharesSuccess",
        Mining::UpdateChannel(_) => "UpdateChannel",
        Mining::UpdateChannelError(_) => "UpdateChannelError",
    }
}

// ── Per-variant decoders ────────────────────────────────────────────

fn decode_open_std_channel(
    m: Sv2OpenStdChannel<'_>,
) -> Result<(OpenStandardMiningChannelInput, Vec<u8>), CodecError> {
    let extranonce_prefix = Vec::new(); // OpenChannel.request doesn't carry one — pool allocates
    Ok((
        OpenStandardMiningChannelInput {
            request_id: m.get_request_id_as_u32(),
            user_identity: utf8_from_bytes(m.user_identity.as_bytes())?,
            nominal_hash_rate: m.nominal_hash_rate,
            max_target: bytes_to_32(m.max_target.as_bytes())?,
        },
        extranonce_prefix,
    ))
}

fn decode_open_ext_channel(
    m: Sv2OpenExtChannel<'_>,
) -> Result<(OpenExtendedMiningChannelInput, Vec<u8>), CodecError> {
    let extranonce_prefix = Vec::new();
    Ok((
        OpenExtendedMiningChannelInput {
            request_id: m.get_request_id_as_u32(),
            user_identity: utf8_from_bytes(m.user_identity.as_bytes())?,
            nominal_hash_rate: m.nominal_hash_rate,
            max_target: bytes_to_32(m.max_target.as_bytes())?,
            min_extranonce_size: m.min_extranonce_size,
        },
        extranonce_prefix,
    ))
}

fn decode_update_channel(m: Sv2UpdateChannel<'_>) -> Result<UpdateChannelInput, CodecError> {
    Ok(UpdateChannelInput {
        channel_id: m.channel_id,
        nominal_hash_rate: m.nominal_hash_rate,
        maximum_target: bytes_to_32(m.maximum_target.as_bytes())?,
    })
}

fn decode_close_channel(m: Sv2CloseChannel<'_>) -> Result<CloseChannelInput, CodecError> {
    Ok(CloseChannelInput {
        channel_id: m.channel_id,
        reason_code: utf8_from_bytes(m.reason_code.as_bytes())?,
    })
}

fn decode_submit_shares_standard(m: Sv2SubmitSharesStandard) -> SubmitSharesStandardInput {
    SubmitSharesStandardInput {
        channel_id: m.channel_id,
        sequence_number: m.sequence_number,
        job_id: m.job_id,
        nonce: m.nonce,
        ntime: m.ntime,
        version: m.version,
    }
}

fn decode_submit_shares_extended(
    m: Sv2SubmitSharesExtended<'_>,
) -> Result<SubmitSharesExtendedInput, CodecError> {
    Ok(SubmitSharesExtendedInput {
        channel_id: m.channel_id,
        sequence_number: m.sequence_number,
        job_id: m.job_id,
        nonce: m.nonce,
        ntime: m.ntime,
        version: m.version,
        extranonce: m.extranonce.as_bytes().into(),
        // Trailing TLVs (ext 0x0002 Worker-ID etc.) are not in the
        // `AnyMessage`; the IO layer extracts them via
        // `parse_message_frame_with_tlvs` and fills this field.
        tlvs: Vec::new(),
    })
}

fn decode_set_custom_mining_job(
    m: Sv2SetCustomMiningJob<'_>,
) -> Result<SetCustomMiningJobInput, CodecError> {
    Ok(SetCustomMiningJobInput {
        // ext 0x0003/distribution_id TLV Field — IO-layer-extracted from the
        // frame's trailing TLVs.
        distribution_id: None,
        channel_id: m.channel_id,
        request_id: m.request_id,
        mining_job_token: token_from_bytes(m.token.as_bytes())?,
        version: m.version,
        prev_hash: bytes_to_32(m.prev_hash.as_bytes())?,
        min_ntime: m.min_ntime,
        n_bits: m.nbits,
        coinbase_tx_version: m.coinbase_tx_version,
        coinbase_prefix: m.coinbase_prefix.as_bytes().to_vec(),
        coinbase_tx_input_n_sequence: m.coinbase_tx_input_n_sequence,
        coinbase_tx_outputs: m.coinbase_tx_outputs.as_bytes().to_vec(),
        coinbase_tx_locktime: m.coinbase_tx_locktime,
        merkle_path: merkle_path_from_seq(&m.merkle_path)?,
    })
}

// ── encode_mining_outbound ──────────────────────────────────────────

/// Translate an [`OutboundFrame`] into a wire-shape `AnyMessageOwned`,
/// which the per-connection task wraps in a `MessageFrame` for the Noise
/// stream.
pub fn encode_mining_outbound(frame: OutboundFrame) -> Result<AnyMessageOwned, CodecError> {
    match frame {
        OutboundFrame::SetupConnectionSuccess {
            used_version,
            flags,
        } => Ok(setup_connection_success(used_version, flags)),
        OutboundFrame::SetupConnectionError { flags, error_code } => {
            setup_connection_error(flags, error_code)
        }
        OutboundFrame::RequestExtensionsSuccess {
            request_id,
            supported_extensions,
        } => request_extensions_success(request_id, supported_extensions),
        OutboundFrame::RequestExtensionsError {
            request_id,
            unsupported_extensions,
            required_extensions,
        } => request_extensions_error(request_id, unsupported_extensions, required_extensions),
        OutboundFrame::OpenStandardMiningChannelSuccess {
            request_id,
            channel_id,
            target,
            extranonce_prefix,
            group_channel_id,
        } => Ok(AnyMessageOwned::Mining(
            MiningOwned::OpenStandardMiningChannelSuccess(Sv2OpenStdChannelSuccess {
                request_id,
                channel_id,
                target: target.into(),
                extranonce_prefix: extranonce_prefix
                    .try_into()
                    .map_err(CodecError::from_conv)?,
                group_channel_id,
            }),
        )),
        OutboundFrame::OpenExtendedMiningChannelSuccess {
            request_id,
            channel_id,
            target,
            extranonce_size,
            extranonce_prefix,
            group_channel_id,
        } => Ok(AnyMessageOwned::Mining(
            MiningOwned::OpenExtendedMiningChannelSuccess(Sv2OpenExtChannelSuccess {
                request_id,
                channel_id,
                target: target.into(),
                extranonce_size,
                extranonce_prefix: extranonce_prefix
                    .try_into()
                    .map_err(CodecError::from_conv)?,
                // Group this channel belongs to (SV2 Mining/Group Channel),
                // or 0 when un-grouped; the downstream infers membership
                // from it.
                group_channel_id,
            }),
        )),
        OutboundFrame::OpenMiningChannelError {
            request_id,
            error_code,
        } => Ok(AnyMessageOwned::Mining(
            MiningOwned::OpenMiningChannelError(Sv2OpenChannelError {
                request_id,
                error_code: str0255(error_code)?,
            }),
        )),
        OutboundFrame::SetTarget {
            channel_id,
            maximum_target,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::SetTarget(
            Sv2SetTarget {
                channel_id,
                maximum_target: maximum_target.into(),
            },
        ))),
        OutboundFrame::SetExtranoncePrefix {
            channel_id,
            extranonce_prefix,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::SetExtranoncePrefix(
            Sv2SetExtranoncePrefix {
                channel_id,
                extranonce_prefix: extranonce_prefix
                    .try_into()
                    .map_err(CodecError::from_conv)?,
            },
        ))),
        OutboundFrame::SetNewPrevHash {
            channel_id,
            job_id,
            prev_hash,
            min_ntime,
            n_bits,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::SetNewPrevHash(
            Sv2MiningSetNewPrevHash {
                channel_id,
                job_id,
                prev_hash: prev_hash.into(),
                min_ntime,
                nbits: n_bits,
            },
        ))),
        OutboundFrame::NewMiningJob {
            channel_id,
            job_id,
            version,
            merkle_root,
            min_ntime,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::NewMiningJob(
            Sv2NewMiningJob {
                channel_id,
                job_id,
                min_ntime: stratum_core::binary_sv2::Sv2OptionOwned::new(min_ntime),
                version,
                merkle_root: merkle_root.into(),
            },
        ))),
        OutboundFrame::NewExtendedMiningJob {
            channel_id,
            job_id,
            version,
            version_rolling_allowed,
            merkle_path,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            min_ntime,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::NewExtendedMiningJob(
            Sv2NewExtMiningJob {
                channel_id,
                job_id,
                min_ntime: stratum_core::binary_sv2::Sv2OptionOwned::new(min_ntime),
                version,
                version_rolling_allowed,
                merkle_path: seq_from_merkle_path(merkle_path)?,
                coinbase_tx_prefix: coinbase_tx_prefix
                    .try_into()
                    .map_err(CodecError::from_conv)?,
                coinbase_tx_suffix: coinbase_tx_suffix
                    .try_into()
                    .map_err(CodecError::from_conv)?,
            },
        ))),
        OutboundFrame::SubmitSharesSuccess {
            channel_id,
            last_sequence_number,
            new_submits_accepted_count,
            new_shares_sum,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::SubmitSharesSuccess(
            Sv2SubmitSharesSuccess {
                channel_id,
                last_sequence_number,
                new_submits_accepted_count,
                new_shares_sum,
            },
        ))),
        OutboundFrame::SubmitSharesError {
            channel_id,
            sequence_number,
            error_code,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::SubmitSharesError(
            Sv2SubmitSharesError {
                channel_id,
                sequence_number,
                error_code: str0255(error_code)?,
            },
        ))),
        OutboundFrame::UpdateChannelError {
            channel_id,
            error_code,
        } => Ok(AnyMessageOwned::Mining(MiningOwned::UpdateChannelError(
            Sv2UpdateChannelError {
                channel_id,
                error_code: str0255(error_code)?,
            },
        ))),
        OutboundFrame::SetCustomMiningJobSuccess {
            channel_id,
            request_id,
            job_id,
        } => Ok(AnyMessageOwned::Mining(
            MiningOwned::SetCustomMiningJobSuccess(Sv2SetCustomMiningJobSuccess {
                channel_id,
                request_id,
                job_id,
            }),
        )),
        OutboundFrame::SetCustomMiningJobError {
            channel_id,
            request_id,
            error_code,
        } => Ok(AnyMessageOwned::Mining(
            MiningOwned::SetCustomMiningJobError(Sv2SetCustomMiningJobError {
                channel_id,
                request_id,
                error_code: str0255(error_code)?,
            }),
        )),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn merkle_path_from_seq(
    seq: &stratum_core::binary_sv2::Seq0255<'_, stratum_core::binary_sv2::U256<'_>>,
) -> Result<Vec<[u8; 32]>, CodecError> {
    let mut out = Vec::with_capacity(seq.as_slice().len());
    for u in seq.iter_bytes() {
        out.push(bytes_to_32(u)?);
    }
    Ok(out)
}

fn seq_from_merkle_path(
    path: Vec<[u8; 32]>,
) -> Result<stratum_core::binary_sv2::Seq0255Owned<stratum_core::binary_sv2::U256Owned>, CodecError>
{
    let items: Vec<stratum_core::binary_sv2::U256Owned> =
        path.into_iter().map(Into::into).collect();
    items.try_into().map_err(CodecError::from_conv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::Seq064K;
    use stratum_core::common_messages_sv2::Protocol;
    use stratum_core::common_messages_sv2::SetupConnection as Sv2SetupConnection;
    use stratum_core::extensions_sv2::extensions_negotiation::RequestExtensions as Sv2RequestExtensions;
    use stratum_core::parsers_sv2::{
        CommonMessagesOwned, ExtensionsNegotiationOwned, ExtensionsOwned,
    };

    // ── decode_setup_connection ────────────────────────────────────

    fn build_setup_connection() -> Sv2SetupConnection<'static> {
        Sv2SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "127.0.0.1".try_into().unwrap(),
            endpoint_port: 3333,
            vendor: "test-vendor".try_into().unwrap(),
            hardware_version: "rev1".try_into().unwrap(),
            firmware: "0.1".try_into().unwrap(),
            device_id: "dev-1".try_into().unwrap(),
        }
    }

    #[test]
    fn decode_setup_connection_maps_fields() {
        let msg = AnyMessage::Common(CommonMessages::SetupConnection(build_setup_connection()));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::SetupConnection(i) => {
                assert_eq!(i.protocol, 0);
                assert_eq!(i.min_version, 2);
                assert_eq!(i.max_version, 2);
                assert_eq!(i.vendor, "test-vendor");
                assert_eq!(i.firmware, "0.1");
                assert_eq!(i.device_id, "dev-1");
            }
            _ => panic!("expected SetupConnection"),
        }
    }

    // ── decode_request_extensions ──────────────────────────────────

    #[test]
    fn decode_request_extensions_maps_fields() {
        let seq: Seq064K<u16> = vec![0x0002u16, 0x0003u16].try_into().unwrap();
        let msg = AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensions(Sv2RequestExtensions {
                request_id: 7,
                requested_extensions: seq,
            }),
        ));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::RequestExtensions(r) => {
                assert_eq!(r.request_id, 7);
                assert_eq!(r.requested_extensions, vec![0x0002u16, 0x0003u16]);
            }
            _ => panic!("expected RequestExtensions"),
        }
    }

    // ── decode_submit_shares_standard ─────────────────────────────

    #[test]
    fn decode_submit_shares_standard_maps_fields() {
        let msg = AnyMessage::Mining(Mining::SubmitSharesStandard(Sv2SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 2,
            job_id: 3,
            nonce: 0xdeadbeef,
            ntime: 0x6500_0001,
            version: 0x2000_0000,
        }));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::SubmitSharesStandard(i) => {
                assert_eq!(i.channel_id, 1);
                assert_eq!(i.sequence_number, 2);
                assert_eq!(i.job_id, 3);
                assert_eq!(i.nonce, 0xdeadbeef);
                assert_eq!(i.ntime, 0x6500_0001);
                assert_eq!(i.version, 0x2000_0000);
            }
            _ => panic!("expected SubmitSharesStandard"),
        }
    }

    // ── decode_open_std_channel ────────────────────────────────────

    #[test]
    fn decode_open_std_channel_maps_fields() {
        let msg = AnyMessage::Mining(Mining::OpenStandardMiningChannel(Sv2OpenStdChannel {
            request_id: 42u32,
            user_identity: "miner.worker1".try_into().unwrap(),
            nominal_hash_rate: 1_000_000.0,
            max_target: (&[0xFFu8; 32]).into(),
        }));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::OpenStandardMiningChannel(i, _) => {
                assert_eq!(i.request_id, 42);
                assert_eq!(i.user_identity, "miner.worker1");
                assert!((i.nominal_hash_rate - 1_000_000.0).abs() < 1.0);
                assert_eq!(i.max_target, [0xFFu8; 32]);
            }
            _ => panic!("expected OpenStandardMiningChannel"),
        }
    }

    // ── decode_open_ext_channel ────────────────────────────────────

    #[test]
    fn decode_open_ext_channel_maps_fields() {
        let msg = AnyMessage::Mining(Mining::OpenExtendedMiningChannel(Sv2OpenExtChannel {
            request_id: 99,
            user_identity: "miner.ext".try_into().unwrap(),
            nominal_hash_rate: 5.0e12,
            max_target: (&[0xAAu8; 32]).into(),
            min_extranonce_size: 8,
        }));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::OpenExtendedMiningChannel(i, _) => {
                assert_eq!(i.request_id, 99);
                assert_eq!(i.user_identity, "miner.ext");
                assert_eq!(i.min_extranonce_size, 8);
                assert_eq!(i.max_target, [0xAAu8; 32]);
            }
            _ => panic!("expected OpenExtendedMiningChannel"),
        }
    }

    // ── decode_update_channel + close_channel ──────────────────────

    #[test]
    fn decode_update_channel_maps_fields() {
        let msg = AnyMessage::Mining(Mining::UpdateChannel(Sv2UpdateChannel {
            channel_id: 5,
            nominal_hash_rate: 2.0e12,
            maximum_target: (&[0xCCu8; 32]).into(),
        }));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::UpdateChannel(i) => {
                assert_eq!(i.channel_id, 5);
                assert_eq!(i.maximum_target, [0xCCu8; 32]);
            }
            _ => panic!("expected UpdateChannel"),
        }
    }

    #[test]
    fn decode_close_channel_maps_fields() {
        let msg = AnyMessage::Mining(Mining::CloseChannel(Sv2CloseChannel {
            channel_id: 9,
            reason_code: "shutdown".try_into().unwrap(),
        }));
        let out = decode_mining_inbound(msg).unwrap().unwrap();
        match out {
            InboundMiningFrame::CloseChannel(i) => {
                assert_eq!(i.channel_id, 9);
                assert_eq!(i.reason_code, "shutdown");
            }
            _ => panic!("expected CloseChannel"),
        }
    }

    // ── encode roundtrips ──────────────────────────────────────────

    #[test]
    fn encode_setup_connection_success_roundtrip() {
        let frame = OutboundFrame::SetupConnectionSuccess {
            used_version: 2,
            flags: 0,
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(s)) => {
                assert_eq!(s.used_version, 2);
                assert_eq!(s.flags, 0);
            }
            _ => panic!("expected Common::SetupConnectionSuccess"),
        }
    }

    #[test]
    fn encode_setup_connection_error_uses_str0255() {
        let frame = OutboundFrame::SetupConnectionError {
            flags: 0,
            error_code: "unsupported-protocol".to_string(),
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionError(e)) => {
                assert_eq!(
                    utf8_from_bytes(e.error_code.as_bytes()).unwrap(),
                    "unsupported-protocol"
                );
            }
            _ => panic!("expected SetupConnectionError"),
        }
    }

    #[test]
    fn encode_submit_shares_success_maps_fields() {
        let frame = OutboundFrame::SubmitSharesSuccess {
            channel_id: 1,
            last_sequence_number: 42,
            new_submits_accepted_count: 1,
            new_shares_sum: 1024,
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesSuccess(s)) => {
                assert_eq!(s.channel_id, 1);
                assert_eq!(s.last_sequence_number, 42);
                assert_eq!(s.new_shares_sum, 1024);
            }
            _ => panic!("expected SubmitSharesSuccess"),
        }
    }

    #[test]
    fn encode_submit_shares_error_carries_wire_code() {
        let frame = OutboundFrame::SubmitSharesError {
            channel_id: 1,
            sequence_number: 7,
            error_code: "stale-share".to_string(),
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesError(e)) => {
                assert_eq!(e.channel_id, 1);
                assert_eq!(e.sequence_number, 7);
                assert_eq!(
                    utf8_from_bytes(e.error_code.as_bytes()).unwrap(),
                    "stale-share"
                );
            }
            _ => panic!("expected SubmitSharesError"),
        }
    }

    #[test]
    fn encode_set_target_round_trips_max_target() {
        let frame = OutboundFrame::SetTarget {
            channel_id: 1,
            maximum_target: [0xAA; 32],
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::SetTarget(s)) => {
                assert_eq!(s.channel_id, 1);
                assert_eq!(s.maximum_target.as_bytes(), &[0xAA; 32]);
            }
            _ => panic!("expected SetTarget"),
        }
    }

    #[test]
    fn encode_set_extranonce_prefix_round_trips_channel_and_prefix() {
        let frame = OutboundFrame::SetExtranoncePrefix {
            channel_id: 4,
            extranonce_prefix: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::SetExtranoncePrefix(s)) => {
                assert_eq!(s.channel_id, 4);
                assert_eq!(s.extranonce_prefix.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("expected SetExtranoncePrefix"),
        }
    }

    #[test]
    fn encode_set_new_prev_hash_carries_prev_hash_and_min_ntime() {
        let frame = OutboundFrame::SetNewPrevHash {
            channel_id: 1,
            job_id: 7,
            prev_hash: [0xAB; 32],
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::SetNewPrevHash(p)) => {
                assert_eq!(p.channel_id, 1);
                assert_eq!(p.job_id, 7);
                assert_eq!(p.prev_hash.as_bytes(), &[0xAB; 32]);
                assert_eq!(p.min_ntime, 0x6500_0001);
                assert_eq!(p.nbits, 0x1d00_ffff);
            }
            _ => panic!("expected SetNewPrevHash"),
        }
    }

    #[test]
    fn encode_new_mining_job_includes_merkle_root() {
        let frame = OutboundFrame::NewMiningJob {
            channel_id: 1,
            job_id: 7,
            version: 0x2000_0000,
            merkle_root: [0x12; 32],
            min_ntime: Some(0x6500_0001),
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::NewMiningJob(j)) => {
                assert_eq!(j.channel_id, 1);
                assert_eq!(j.job_id, 7);
                assert_eq!(j.version, 0x2000_0000);
                assert_eq!(j.merkle_root.as_bytes(), &[0x12; 32]);
                assert_eq!(j.min_ntime.clone().into_inner(), Some(0x6500_0001));
            }
            _ => panic!("expected NewMiningJob"),
        }
    }

    #[test]
    fn encode_new_extended_mining_job_maps_prefix_suffix_and_path() {
        let frame = OutboundFrame::NewExtendedMiningJob {
            channel_id: 1,
            job_id: 7,
            version: 0x2000_0000,
            version_rolling_allowed: true,
            merkle_path: vec![[0x11; 32], [0x22; 32]],
            coinbase_tx_prefix: vec![0xAA; 8],
            coinbase_tx_suffix: vec![0xBB; 8],
            min_ntime: Some(0x6500_0001),
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::NewExtendedMiningJob(j)) => {
                assert_eq!(j.channel_id, 1);
                assert!(j.version_rolling_allowed);
                assert_eq!(j.merkle_path.as_slice().len(), 2);
                assert_eq!(j.coinbase_tx_prefix.as_bytes(), &[0xAA; 8]);
                assert_eq!(j.coinbase_tx_suffix.as_bytes(), &[0xBB; 8]);
            }
            _ => panic!("expected NewExtendedMiningJob"),
        }
    }

    #[test]
    fn encode_open_std_channel_success_carries_extranonce_prefix() {
        let frame = OutboundFrame::OpenStandardMiningChannelSuccess {
            request_id: 42,
            channel_id: 1,
            target: [0xCC; 32],
            extranonce_prefix: vec![0x01, 0x02, 0x03, 0x04],
            group_channel_id: 0,
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannelSuccess(s)) => {
                assert_eq!(s.request_id, 42);
                assert_eq!(s.channel_id, 1);
                assert_eq!(s.target.as_bytes(), &[0xCC; 32]);
                assert_eq!(s.extranonce_prefix.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("expected OpenStandardMiningChannelSuccess"),
        }
    }

    #[test]
    fn encode_set_custom_mining_job_success_maps_ids() {
        let frame = OutboundFrame::SetCustomMiningJobSuccess {
            channel_id: 1,
            request_id: 5,
            job_id: 9,
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Mining(MiningOwned::SetCustomMiningJobSuccess(s)) => {
                assert_eq!(s.channel_id, 1);
                assert_eq!(s.request_id, 5);
                assert_eq!(s.job_id, 9);
            }
            _ => panic!("expected SetCustomMiningJobSuccess"),
        }
    }

    #[test]
    fn encode_request_extensions_success_maps_supported_list() {
        let frame = OutboundFrame::RequestExtensionsSuccess {
            request_id: 7,
            supported_extensions: vec![0x0002, 0x0003],
        };
        let msg = encode_mining_outbound(frame).unwrap();
        match msg {
            AnyMessageOwned::Extensions(ExtensionsOwned::ExtensionsNegotiation(
                ExtensionsNegotiationOwned::RequestExtensionsSuccess(s),
            )) => {
                assert_eq!(s.request_id, 7);
                assert_eq!(s.supported_extensions.into_inner(), vec![0x0002, 0x0003]);
            }
            _ => panic!("expected RequestExtensionsSuccess"),
        }
    }

    // ── Decode roundtrip with encode (sanity for symmetric variants) ─

    #[test]
    fn roundtrip_setup_connection_success_via_encode_then_decode() {
        let frame = OutboundFrame::SetupConnectionSuccess {
            used_version: 2,
            flags: 1,
        };
        let AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(s)) =
            encode_mining_outbound(frame).unwrap()
        else {
            panic!("expected SetupConnectionSuccess");
        };
        // SetupConnectionSuccess flows server→client, so decoding it yields
        // None. It has no borrowed fields, so the owned value is also the
        // wire-shape value.
        let msg = AnyMessage::Common(CommonMessages::SetupConnectionSuccess(s));
        assert!(decode_mining_inbound(msg).unwrap().is_none());
    }

    // ── Helper: not-mining-related is silently ignored ─────────────

    #[test]
    fn decode_template_distribution_returns_none() {
        let msg = AnyMessage::TemplateDistribution(
            stratum_core::parsers_sv2::TemplateDistribution::RequestTransactionData(
                stratum_core::template_distribution_sv2::RequestTransactionData { template_id: 1 },
            ),
        );
        let out = decode_mining_inbound(msg).unwrap();
        assert!(out.is_none(), "TDP frames silently ignored on mining port");
    }
}
