// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public, owned, `Send`-able wrappers around the
//! `stratum_core::parsers_sv2::TemplateDistribution` payloads.
//!
//! Why a local wrap instead of re-exporting `TemplateDistribution<'static>`
//! directly:
//!
//! - **API stability.** The upstream `stratum-core` library is pulled in via
//!   a git-branch dep through `bitcoin_core_sv2`. Decoupling our public API
//!   shields downstream crates (`bp-stratum-v1`, `bp-stratum-v2`,
//!   eventually `bp-api`) from breaking changes there.
//! - **Owned bytes.** Upstream payloads carry `Cow`-shaped buffers tied to a
//!   `'decoder` lifetime; `into_static()` normalises them but we still want a
//!   trivially-clonable `Vec<u8>` so `broadcast::Sender` can fan out without
//!   reference counting tricks.
//! - **Surface area.** Pool consumers only ever care about the four payloads
//!   below — there is no need to expose the `CoinbaseOutputConstraints` /
//!   `RequestTransactionData` / `SubmitSolution` variants on the *outbound*
//!   channel.

use stratum_core::parsers_sv2::TemplateDistribution;

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

/// Latest-known TDP state for read-only consumers (e.g. the
/// `/api/info/block-template` REST endpoint). Built by
/// [`apply_to_snapshot`] from each [`TemplateUpdate`] the worker
/// broadcasts; the bp-api layer reads it through
/// [`crate::TdpHandle::current_snapshot`].
///
/// Both fields are `Option` because the snapshot starts empty at
/// process boot — bitcoin-core's first NewTemplate + SetNewPrevHash
/// pair arrives within a few ms of TDP attach, so callers should treat
/// `None` as "not ready yet" rather than an error.
///
/// The `prev_hash` field can lag the latest template by one tick under
/// normal operation (bitcoin-core sends NewTemplate first, then
/// SetNewPrevHash for the same `template_id`). Callers that need a
/// coherent pair should check `template_id` equality:
/// `snapshot.new_template?.template_id == snapshot.set_new_prev_hash?.template_id`.
#[derive(Debug, Default, Clone)]
pub struct TemplateSnapshot {
    pub new_template: Option<NewTemplate>,
    pub set_new_prev_hash: Option<SetNewPrevHash>,
    /// Wall-clock epoch-ms when the live snapshot last absorbed a
    /// fresh NewTemplate or SetNewPrevHash. `None` until the first
    /// update arrives. NOT touched by [`apply_to_snapshot`] (which
    /// stays a pure, clock-free replay primitive) — only the live
    /// snapshot-tap in [`crate::TdpHandle::spawn`] stamps it, since
    /// staleness is a property of the running connection, not of a
    /// replayed stream. Read by `/api/health` to flag a prolonged
    /// bitcoin-core outage (templates no longer arriving).
    pub last_update_at: Option<i64>,
}

/// Apply one [`TemplateUpdate`] to a [`TemplateSnapshot`] in-place.
/// Inbound-only variants (the two `RequestTransactionData*` payloads)
/// are intentionally ignored — they're per-call responses, not pool
/// state.
///
/// Used by the snapshot-tap task in [`crate::TdpHandle::spawn`] and
/// exposed publicly so consumers + tests can replay TDP streams
/// without holding the handle.
pub fn apply_to_snapshot(snapshot: &mut TemplateSnapshot, update: &TemplateUpdate) {
    match update {
        TemplateUpdate::NewTemplate(t) => snapshot.new_template = Some(t.clone()),
        TemplateUpdate::SetNewPrevHash(p) => snapshot.set_new_prev_hash = Some(p.clone()),
        TemplateUpdate::RequestTransactionDataSuccess(_)
        | TemplateUpdate::RequestTransactionDataError(_) => {}
    }
}

/// Extension trait that both per-protocol template assemblers
/// (SV1 in `bp-stratum-v1::notify`, SV2 in `bp-stratum-v2::mining::translator`)
/// implement so the bootstrap-from-snapshot logic can live in one
/// place. See [`bootstrap_assembler_from_snapshot`].
pub trait TemplateAssembler {
    /// Implementation-specific change description (TemplateChange::NewBlock /
    /// Refresh in both crates today; kept generic so neither protocol
    /// crate has to depend on the other's enum).
    type Change;
    /// Implementation-specific active template (ActiveSV1Template /
    /// ActiveSV2Template) — `Clone` so the caller can both stash a
    /// snapshot AND broadcast.
    type Active: Clone;

    fn apply(&mut self, update: &TemplateUpdate) -> Option<Self::Change>;
    fn current(&self) -> Option<&Self::Active>;
}

/// Replay a [`TemplateSnapshot`] through an assembler so a late
/// subscriber recovers the bootstrap state the broadcast missed.
/// Returns `Some((active, change))` when both halves of the pair are
/// present in the snapshot and apply cleanly; `None` otherwise.
///
/// The caller is responsible for the side-effects (updating its
/// own current_template mutex, broadcasting on its outbound
/// template_tx) since the shape of those varies per protocol.
pub fn bootstrap_assembler_from_snapshot<A: TemplateAssembler>(
    assembler: &mut A,
    snapshot: TemplateSnapshot,
) -> Option<(A::Active, A::Change)> {
    if let Some(t) = snapshot.new_template {
        let _ = assembler.apply(&TemplateUpdate::NewTemplate(t));
    }
    if let Some(p) = snapshot.set_new_prev_hash {
        if let Some(change) = assembler.apply(&TemplateUpdate::SetNewPrevHash(p)) {
            if let Some(active) = assembler.current().cloned() {
                return Some((active, change));
            }
        }
    }
    None
}

/// Mirror of `template_distribution_sv2::RequestTransactionDataSuccess`.
///
/// `transaction_list` is the ordered list of raw, witness-serialised
/// transactions, exactly as bitcoin-core delivered them. `excess_data` is
/// the opaque blob the SV2 spec reserves for "anything else the validator
/// needs" — in practice today it carries the SegWit commitment.
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
    /// Convert from the upstream `TemplateDistribution` enum to our owned
    /// wrap. Returns `None` for inbound-only variants
    /// (`CoinbaseOutputConstraints`, `RequestTransactionData`,
    /// `SubmitSolution`) which never travel outbound and so should never
    /// reach this code path; the worker logs and drops them instead.
    pub fn from_upstream(msg: &TemplateDistribution<'static>) -> Option<Self> {
        match msg {
            TemplateDistribution::NewTemplate(t) => Some(Self::NewTemplate(NewTemplate {
                template_id: t.template_id,
                future_template: t.future_template,
                version: t.version,
                coinbase_tx_version: t.coinbase_tx_version,
                coinbase_prefix: t.coinbase_prefix.inner_as_ref().to_vec(),
                coinbase_tx_input_sequence: t.coinbase_tx_input_sequence,
                coinbase_tx_value_remaining: t.coinbase_tx_value_remaining,
                coinbase_tx_outputs_count: t.coinbase_tx_outputs_count,
                coinbase_tx_outputs: t.coinbase_tx_outputs.inner_as_ref().to_vec(),
                coinbase_tx_locktime: t.coinbase_tx_locktime,
                merkle_path: t
                    .merkle_path
                    .to_vec()
                    .into_iter()
                    .map(|h| {
                        let mut out = [0u8; 32];
                        // U256 to_vec yields 32-byte arrays — guard against
                        // unexpected lengths by padding/truncating.
                        let len = h.len().min(32);
                        out[..len].copy_from_slice(&h[..len]);
                        out
                    })
                    .collect(),
            })),
            TemplateDistribution::SetNewPrevHash(p) => {
                let mut prev = [0u8; 32];
                let pref = p.prev_hash.inner_as_ref();
                let plen = pref.len().min(32);
                prev[..plen].copy_from_slice(&pref[..plen]);

                let mut tgt = [0u8; 32];
                let tref = p.target.inner_as_ref();
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
            TemplateDistribution::RequestTransactionDataSuccess(s) => Some(
                Self::RequestTransactionDataSuccess(RequestTransactionDataSuccess {
                    template_id: s.template_id,
                    excess_data: s.excess_data.inner_as_ref().to_vec(),
                    transaction_list: s.transaction_list.to_vec(),
                }),
            ),
            TemplateDistribution::RequestTransactionDataError(e) => Some(
                Self::RequestTransactionDataError(RequestTransactionDataError {
                    template_id: e.template_id,
                    error_code: e.error_code.as_utf8_or_hex(),
                }),
            ),
            TemplateDistribution::CoinbaseOutputConstraints(_)
            | TemplateDistribution::RequestTransactionData(_)
            | TemplateDistribution::SubmitSolution(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2::{Seq0255, B0255, B064K, U256};
    use stratum_core::template_distribution_sv2::{
        CoinbaseOutputConstraints, NewTemplate as TdNewTemplate, RequestTransactionData,
        RequestTransactionDataError as TdRtdError, RequestTransactionDataSuccess as TdRtdSuccess,
        SetNewPrevHash as TdSetNewPrevHash, SubmitSolution as TdSubmitSolution,
    };

    fn u256(byte: u8) -> U256<'static> {
        let mut buf = [0u8; 32];
        buf.fill(byte);
        U256::from(buf)
    }

    fn b0255(bytes: Vec<u8>) -> B0255<'static> {
        B0255::try_from(bytes).expect("len ≤ 255")
    }

    fn b064k(bytes: Vec<u8>) -> B064K<'static> {
        B064K::try_from(bytes).expect("len ≤ u16::MAX")
    }

    #[test]
    fn maps_new_template() {
        let path = vec![u256(0x11), u256(0x22)];
        let upstream = TemplateDistribution::NewTemplate(TdNewTemplate {
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
            merkle_path: Seq0255::new(path).expect("len fits"),
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
        let upstream = TemplateDistribution::SetNewPrevHash(TdSetNewPrevHash {
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
        let txs = stratum_core::binary_sv2::Seq064K::new(vec![
            stratum_core::binary_sv2::B016M::try_from(vec![0x01, 0x02, 0x03]).expect("len fits"),
            stratum_core::binary_sv2::B016M::try_from(vec![0x04, 0x05]).expect("len fits"),
        ])
        .expect("len fits");
        let upstream = TemplateDistribution::RequestTransactionDataSuccess(TdRtdSuccess {
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
        let upstream = TemplateDistribution::RequestTransactionDataError(TdRtdError {
            template_id: 13,
            error_code: stratum_core::binary_sv2::Str0255::try_from(
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
        let upstream = TemplateDistribution::NewTemplate(TdNewTemplate {
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
            merkle_path: Seq0255::new(vec![]).unwrap(),
        });
        apply_to_snapshot(
            &mut snap,
            &TemplateUpdate::from_upstream(&upstream).unwrap(),
        );
        assert_eq!(snap.new_template.as_ref().unwrap().template_id, 1);
        assert!(snap.set_new_prev_hash.is_none());

        // Then the paired SetNewPrevHash.
        let upstream2 = TemplateDistribution::SetNewPrevHash(TdSetNewPrevHash {
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
        let upstream3 = TemplateDistribution::NewTemplate(TdNewTemplate {
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
            merkle_path: Seq0255::new(vec![]).unwrap(),
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
            TemplateDistribution::CoinbaseOutputConstraints(CoinbaseOutputConstraints {
                coinbase_output_max_additional_size: 100,
                coinbase_output_max_additional_sigops: 0,
            }),
            TemplateDistribution::RequestTransactionData(RequestTransactionData { template_id: 1 }),
            TemplateDistribution::SubmitSolution(TdSubmitSolution {
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
/// worker. Each maps directly to a `TemplateDistribution` variant; we keep
/// the wrap so the upstream type is not part of our public API.
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
