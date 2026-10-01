// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned wrappers around the `stratum_core` TDP payloads, instead of
//! re-exporting `TemplateDistributionOwned`: they shield downstream crates
//! from `stratum-core` major bumps, clone plainly for `broadcast` fan-out,
//! and expose only the four payloads that travel from bitcoin-core.

use stratum_core::parsers_sv2::TemplateDistributionOwned;

/// Updates that arrive **from** bitcoin-core via TDP and are fanned out to
/// every pool consumer.
#[derive(Debug, Clone)]
pub enum TemplateUpdate {
    NewTemplate(NewTemplate),
    SetNewPrevHash(SetNewPrevHash),
    RequestTransactionDataSuccess(RequestTransactionDataSuccess),
    RequestTransactionDataError(RequestTransactionDataError),
}

/// Mirror of `template_distribution_sv2::NewTemplate` with owned buffers.
#[derive(Debug, Clone)]
pub struct NewTemplate {
    pub template_id: u64,
    pub future_template: bool,
    pub version: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
}

/// Mirror of `template_distribution_sv2::SetNewPrevHash` with owned buffers.
#[derive(Debug, Clone)]
pub struct SetNewPrevHash {
    pub template_id: u64,
    pub prev_hash: [u8; 32],
    pub header_timestamp: u32,
    pub n_bits: u32,
    pub target: [u8; 32],
}

/// Latest-known TDP state for read-only consumers, built by
/// [`apply_to_snapshot`] and read via [`crate::TdpHandle::current_snapshot`].
/// `None` fields mean "not ready yet". The two halves can be one update apart;
/// a caller needing a coherent pair must compare their `template_id`s.
#[derive(Debug, Default, Clone)]
pub struct TemplateSnapshot {
    pub new_template: Option<NewTemplate>,
    pub set_new_prev_hash: Option<SetNewPrevHash>,
    /// Epoch-ms of the last absorbed update, for `/api/health`'s staleness
    /// check. Stamped only by the live tap in [`crate::TdpHandle::spawn`], not
    /// by [`apply_to_snapshot`]: staleness belongs to the running connection,
    /// not to a replayed stream.
    pub last_update_at: Option<i64>,
}

/// Apply one [`TemplateUpdate`] to a [`TemplateSnapshot`] in place. The
/// `RequestTransactionData*` responses are per-call, not pool state, so they
/// are ignored. Public so a TDP stream can be replayed without the handle.
pub fn apply_to_snapshot(snapshot: &mut TemplateSnapshot, update: &TemplateUpdate) {
    match update {
        TemplateUpdate::NewTemplate(t) => snapshot.new_template = Some(t.clone()),
        TemplateUpdate::SetNewPrevHash(p) => snapshot.set_new_prev_hash = Some(p.clone()),
        TemplateUpdate::RequestTransactionDataSuccess(_)
        | TemplateUpdate::RequestTransactionDataError(_) => {}
    }
}

/// Mirror of `template_distribution_sv2::RequestTransactionDataSuccess`;
/// `transaction_list` holds raw witness-serialised transactions in
/// bitcoin-core's order.
#[derive(Debug, Clone)]
pub struct RequestTransactionDataSuccess {
    pub template_id: u64,
    pub excess_data: Vec<u8>,
    pub transaction_list: Vec<Vec<u8>>,
}

/// Mirror of `template_distribution_sv2::RequestTransactionDataError`.
#[derive(Debug, Clone)]
pub struct RequestTransactionDataError {
    pub template_id: u64,
    pub error_code: String,
}

impl TemplateUpdate {
    /// Convert from the upstream enum; `None` for the variants that only ever
    /// travel towards bitcoin-core, which the worker logs and drops.
    pub fn from_upstream(msg: &TemplateDistributionOwned) -> Option<Self> {
        match msg {
            TemplateDistributionOwned::NewTemplate(t) => Some(Self::NewTemplate(NewTemplate {
                template_id: t.template_id,
                future_template: t.future_template,
                version: t.version,
                coinbase_tx_version: t.coinbase_tx_version,
                coinbase_prefix: t.coinbase_prefix.as_bytes().to_vec(),
                coinbase_tx_input_sequence: t.coinbase_tx_input_sequence,
                coinbase_tx_value_remaining: t.coinbase_tx_value_remaining,
                coinbase_tx_outputs_count: t.coinbase_tx_outputs_count,
                coinbase_tx_outputs: t.coinbase_tx_outputs.as_bytes().to_vec(),
                coinbase_tx_locktime: t.coinbase_tx_locktime,
                merkle_path: t
                    .merkle_path
                    .iter_bytes()
                    .map(|h| {
                        let mut out = [0u8; 32];
                        // Each merkle node is a 32-byte U256 — guard against
                        // unexpected lengths by padding/truncating.
                        let len = h.len().min(32);
                        out[..len].copy_from_slice(&h[..len]);
                        out
                    })
                    .collect(),
            })),
            TemplateDistributionOwned::SetNewPrevHash(p) => {
                let mut prev = [0u8; 32];
                let pref = p.prev_hash.as_bytes();
                let plen = pref.len().min(32);
                prev[..plen].copy_from_slice(&pref[..plen]);

                let mut tgt = [0u8; 32];
                let tref = p.target.as_bytes();
                let tlen = tref.len().min(32);
                tgt[..tlen].copy_from_slice(&tref[..tlen]);

                Some(Self::SetNewPrevHash(SetNewPrevHash {
                    template_id: p.template_id,
                    prev_hash: prev,
                    header_timestamp: p.header_timestamp,
                    n_bits: p.n_bits,
                    target: tgt,
                }))
            }
            TemplateDistributionOwned::RequestTransactionDataSuccess(s) => Some(
                Self::RequestTransactionDataSuccess(RequestTransactionDataSuccess {
                    template_id: s.template_id,
                    excess_data: s.excess_data.as_bytes().to_vec(),
                    transaction_list: s
                        .transaction_list
                        .iter_bytes()
                        .map(|t| t.to_vec())
                        .collect(),
                }),
            ),
            TemplateDistributionOwned::RequestTransactionDataError(e) => Some(
                Self::RequestTransactionDataError(RequestTransactionDataError {
                    template_id: e.template_id,
                    error_code: e.error_code.as_utf8_or_hex(),
                }),
            ),
            TemplateDistributionOwned::CoinbaseOutputConstraints(_)
            | TemplateDistributionOwned::RequestTransactionData(_)
            | TemplateDistributionOwned::SubmitSolution(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::{B0255Owned, B064KOwned, Seq0255Owned, U256Owned};
    use stratum_core::template_distribution_sv2::{
        CoinbaseOutputConstraints, NewTemplateOwned as TdNewTemplate, RequestTransactionData,
        RequestTransactionDataErrorOwned as TdRtdError,
        RequestTransactionDataSuccessOwned as TdRtdSuccess,
        SetNewPrevHashOwned as TdSetNewPrevHash, SubmitSolutionOwned as TdSubmitSolution,
    };

    fn u256(byte: u8) -> U256Owned {
        let mut buf = [0u8; 32];
        buf.fill(byte);
        U256Owned::from(buf)
    }

    fn b0255(bytes: Vec<u8>) -> B0255Owned {
        B0255Owned::try_from(bytes).expect("len ≤ 255")
    }

    fn b064k(bytes: Vec<u8>) -> B064KOwned {
        B064KOwned::try_from(bytes).expect("len ≤ u16::MAX")
    }

    #[test]
    fn maps_new_template() {
        let path = vec![u256(0x11), u256(0x22)];
        let upstream = TemplateDistributionOwned::NewTemplate(TdNewTemplate {
            template_id: 42,
            future_template: true,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: b0255(vec![3, 0xaa, 0xbb, 0xcc]),
            coinbase_tx_input_sequence: 0xffff_fffe,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: b064k(vec![0xde, 0xad, 0xbe, 0xef]),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255Owned::new(path).expect("len fits"),
        });

        let mapped = TemplateUpdate::from_upstream(&upstream).expect("NewTemplate maps");
        let TemplateUpdate::NewTemplate(t) = mapped else {
            panic!("wrong variant");
        };
        assert_eq!(t.template_id, 42);
        assert!(t.future_template);
        assert_eq!(t.version, 0x2000_0000);
        assert_eq!(t.coinbase_tx_version, 2);
        assert_eq!(t.coinbase_prefix, vec![3, 0xaa, 0xbb, 0xcc]);
        assert_eq!(t.coinbase_tx_input_sequence, 0xffff_fffe);
        assert_eq!(t.coinbase_tx_value_remaining, 5_000_000_000);
        assert_eq!(t.coinbase_tx_outputs_count, 1);
        assert_eq!(t.coinbase_tx_outputs, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(t.coinbase_tx_locktime, 0);
        assert_eq!(t.merkle_path.len(), 2);
        assert_eq!(t.merkle_path[0], [0x11; 32]);
        assert_eq!(t.merkle_path[1], [0x22; 32]);
    }

    #[test]
    fn maps_set_new_prev_hash() {
        let upstream = TemplateDistributionOwned::SetNewPrevHash(TdSetNewPrevHash {
            template_id: 7,
            prev_hash: u256(0xa1),
            header_timestamp: 1_700_000_000,
            n_bits: 0x1d00_ffff,
            target: u256(0xff),
        });
        let mapped = TemplateUpdate::from_upstream(&upstream).expect("maps");
        let TemplateUpdate::SetNewPrevHash(p) = mapped else {
            panic!("wrong variant");
        };
        assert_eq!(p.template_id, 7);
        assert_eq!(p.prev_hash, [0xa1; 32]);
        assert_eq!(p.header_timestamp, 1_700_000_000);
        assert_eq!(p.n_bits, 0x1d00_ffff);
        assert_eq!(p.target, [0xff; 32]);
    }

    #[test]
    fn maps_request_tx_data_success() {
        let txs = stratum_core::binary_sv2::Seq064KOwned::new(vec![
            stratum_core::binary_sv2::B016MOwned::try_from(vec![0x01, 0x02, 0x03])
                .expect("len fits"),
            stratum_core::binary_sv2::B016MOwned::try_from(vec![0x04, 0x05]).expect("len fits"),
        ])
        .expect("len fits");
        let upstream = TemplateDistributionOwned::RequestTransactionDataSuccess(TdRtdSuccess {
            template_id: 99,
            excess_data: b064k(vec![0x77, 0x88]),
            transaction_list: txs,
        });
        let mapped = TemplateUpdate::from_upstream(&upstream).expect("maps");
        let TemplateUpdate::RequestTransactionDataSuccess(s) = mapped else {
            panic!("wrong variant");
        };
        assert_eq!(s.template_id, 99);
        assert_eq!(s.excess_data, vec![0x77, 0x88]);
        assert_eq!(s.transaction_list.len(), 2);
        assert_eq!(s.transaction_list[0], vec![0x01, 0x02, 0x03]);
        assert_eq!(s.transaction_list[1], vec![0x04, 0x05]);
    }

    #[test]
    fn maps_request_tx_data_error() {
        let upstream = TemplateDistributionOwned::RequestTransactionDataError(TdRtdError {
            template_id: 13,
            error_code: stratum_core::binary_sv2::Str0255Owned::try_from(
                "stale-template-id".to_string(),
            )
            .expect("ascii len fits"),
        });
        let mapped = TemplateUpdate::from_upstream(&upstream).expect("maps");
        let TemplateUpdate::RequestTransactionDataError(e) = mapped else {
            panic!("wrong variant");
        };
        assert_eq!(e.template_id, 13);
        assert_eq!(e.error_code, "stale-template-id");
    }

    #[test]
    fn apply_to_snapshot_tracks_latest_pair() {
        let mut snap = TemplateSnapshot::default();
        assert!(snap.new_template.is_none());
        assert!(snap.set_new_prev_hash.is_none());

        // First a NewTemplate — only `new_template` populated.
        let upstream = TemplateDistributionOwned::NewTemplate(TdNewTemplate {
            template_id: 1,
            future_template: true,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: b0255(vec![3]),
            coinbase_tx_input_sequence: 0,
            coinbase_tx_value_remaining: 0,
            coinbase_tx_outputs_count: 0,
            coinbase_tx_outputs: b064k(vec![]),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255Owned::new(vec![]).unwrap(),
        });
        apply_to_snapshot(
            &mut snap,
            &TemplateUpdate::from_upstream(&upstream).unwrap(),
        );
        assert_eq!(snap.new_template.as_ref().unwrap().template_id, 1);
        assert!(snap.set_new_prev_hash.is_none());

        // Then the paired SetNewPrevHash.
        let upstream2 = TemplateDistributionOwned::SetNewPrevHash(TdSetNewPrevHash {
            template_id: 1,
            prev_hash: u256(0xaa),
            header_timestamp: 1_700_000_000,
            n_bits: 0x1d00_ffff,
            target: u256(0xff),
        });
        apply_to_snapshot(
            &mut snap,
            &TemplateUpdate::from_upstream(&upstream2).unwrap(),
        );
        assert_eq!(snap.set_new_prev_hash.as_ref().unwrap().template_id, 1);
        // new_template still present.
        assert_eq!(snap.new_template.as_ref().unwrap().template_id, 1);

        // A later NewTemplate replaces only `new_template`, prev_hash stays.
        let upstream3 = TemplateDistributionOwned::NewTemplate(TdNewTemplate {
            template_id: 2,
            future_template: false,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: b0255(vec![4]),
            coinbase_tx_input_sequence: 0,
            coinbase_tx_value_remaining: 0,
            coinbase_tx_outputs_count: 0,
            coinbase_tx_outputs: b064k(vec![]),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255Owned::new(vec![]).unwrap(),
        });
        apply_to_snapshot(
            &mut snap,
            &TemplateUpdate::from_upstream(&upstream3).unwrap(),
        );
        assert_eq!(snap.new_template.as_ref().unwrap().template_id, 2);
        // Lagged set_new_prev_hash still points at the old template_id.
        assert_eq!(snap.set_new_prev_hash.as_ref().unwrap().template_id, 1);
    }

    #[test]
    fn apply_to_snapshot_ignores_response_variants() {
        let mut snap = TemplateSnapshot::default();
        apply_to_snapshot(
            &mut snap,
            &TemplateUpdate::RequestTransactionDataError(RequestTransactionDataError {
                template_id: 1,
                error_code: "stale-template-id".into(),
            }),
        );
        assert!(snap.new_template.is_none());
        assert!(snap.set_new_prev_hash.is_none());
    }

    #[test]
    fn skips_inbound_only_variants() {
        let cases = [
            TemplateDistributionOwned::CoinbaseOutputConstraints(CoinbaseOutputConstraints {
                coinbase_output_max_additional_size: 100,
                coinbase_output_max_additional_sigops: 0,
            }),
            TemplateDistributionOwned::RequestTransactionData(RequestTransactionData {
                template_id: 1,
            }),
            TemplateDistributionOwned::SubmitSolution(TdSubmitSolution {
                template_id: 1,
                version: 0,
                header_timestamp: 0,
                header_nonce: 0,
                coinbase_tx: b064k(vec![0x01]),
            }),
        ];
        for msg in &cases {
            assert!(
                TemplateUpdate::from_upstream(msg).is_none(),
                "inbound-only variants must not produce outbound updates"
            );
        }
    }
}

/// Inbound message types that pool consumers can send **into** the TDP
/// worker. Each maps directly to a `TemplateDistribution` variant; the wrap
/// keeps the upstream type out of this crate's public API.
#[derive(Debug, Clone)]
pub enum TdpRequest {
    /// Re-advertise coinbase output constraints (size + sigops). The TDP
    /// worker sends a default `CoinbaseOutputConstraints` at startup from
    /// the config; this variant lets the pool change it later.
    SetCoinbaseConstraints {
        max_additional_size: u32,
        max_additional_sigops: u16,
    },
    /// Ask bitcoin-core for the raw transaction list of a known template.
    RequestTransactionData { template_id: u64 },
    /// Submit a found block back to bitcoin-core for validation + relay.
    SubmitSolution {
        template_id: u64,
        version: u32,
        header_timestamp: u32,
        header_nonce: u32,
        coinbase_tx: Vec<u8>,
    },
}
