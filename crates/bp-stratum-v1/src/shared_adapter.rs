// SPDX-License-Identifier: AGPL-3.0-or-later

//! Projects SV1's native share types into the protocol-agnostic
//! `bp_share_hook` views the server hands its sinks.
//!
//! Engines (PPLNS, group-solo, share-stats-sink, session-persistence)
//! implement the shared sink traits once; the SV1 server calls them
//! directly with what these functions build. SV2 has the symmetric pair
//! in `bp-stratum-v2`. See the `bp-share-hook` crate-level docs for the
//! full picture.

use bp_share_hook::{RejectedReason, SharedAcceptedShare, SharedRejectedShare};

use crate::submit::{RejectReason, ShareAccept};

/// The shared view of an accepted SV1 share.
pub(crate) fn shared_accepted<'a>(
    address: &'a str,
    worker: &'a str,
    session_id: &'a str,
    user_agent: Option<&'a str>,
    accept: &ShareAccept,
    hash_rate: f64,
) -> SharedAcceptedShare<'a> {
    SharedAcceptedShare {
        address,
        worker,
        session_id,
        user_agent,
        effective_difficulty: accept.effective_difficulty,
        submission_difficulty: accept.submission_difficulty,
        is_block_candidate: accept.is_block_candidate,
        hash_rate,
        // SV1 is one device per connection — never bundled.
        channel_count: 1,
        ts_ms: bp_common::now_ms(),
        // Producer-assigned downstream at the single fan-out point; the
        // protocol side has no global share sequence and no mode-gate, so it
        // leaves share_id/mode/group_id blank.
        share_id: "",
        mode: bp_common::MiningMode::Solo,
        group_id: None,
    }
}

/// Maps SV1's 4-variant `RejectReason` (Duplicate / JobNotFound / Stale /
/// LowDifficulty) into the canonical 3-variant `bp_stats::RejectedReason`.
/// `Stale` collapses into `JobNotFound` because both share the same reject
/// accumulator bucket (see `bp_share_stats_sink::hooks::map_reject_reason`
/// for the same mapping at the sink-side — centralized here).
fn map_sv1_reject(reason: RejectReason) -> RejectedReason {
    match reason {
        RejectReason::JobNotFound | RejectReason::Stale => RejectedReason::JobNotFound,
        RejectReason::DuplicateShare => RejectedReason::DuplicateShare,
        RejectReason::LowDifficulty => RejectedReason::LowDifficulty,
        RejectReason::VersionRollingNotAllowed => RejectedReason::VersionRollingNotAllowed,
    }
}

/// The shared view of a rejected SV1 share.
pub(crate) fn shared_rejected<'a>(
    address: Option<&'a str>,
    worker: Option<&'a str>,
    session_id: &'a str,
    reason: RejectReason,
    difficulty: f64,
) -> SharedRejectedShare<'a> {
    SharedRejectedShare {
        address,
        worker,
        session_id,
        reason: map_sv1_reject(reason),
        difficulty,
        // The producer (Core composite) stamps the group id from the mode
        // gate; the protocol side has none.
        group_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn synthetic_accept(eff: f64, sub: f64, candidate: bool) -> ShareAccept {
        use crate::ActiveSV1Template;
        use bp_jobs_lifecycle::JobClassification;
        use bp_mining_job::{CoinbaseTemplate, PayoutEntry};

        // Minimal MiningJob via the real builder.
        let payouts = [PayoutEntry::static_address(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            5_000_000_000,
        )];
        let template = CoinbaseTemplate {
            block_height: 1,
            coinbase_value_sats: 5_000_000_000,
            witness_commitment: [0u8; 32],
        };
        let job = bp_mining_job::build_mining_job(
            bitcoin::Network::Regtest,
            &payouts,
            &template,
            "test",
            bp_mining_job::EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .expect("build job");

        ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: eff,
            submission_difficulty: sub,
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: candidate,
            mining_job: Arc::new(job),
            template: Arc::new(ActiveSV1Template::from_template(
                bp_template_distribution::ActiveTemplate {
                    template_id: 1,
                    version: 0x2000_0000,
                    prev_hash: [0u8; 32],
                    n_bits: 0x1d00_ffff,
                    header_timestamp: 0,
                    coinbase_prefix: vec![],
                    coinbase_tx_version: 2,
                    coinbase_tx_input_sequence: 0xffff_ffff,
                    coinbase_tx_value_remaining: 5_000_000_000,
                    coinbase_tx_outputs: vec![],
                    coinbase_tx_outputs_count: 0,
                    coinbase_tx_locktime: 0,
                    merkle_path: vec![],
                },
            )),
            enonce1: [0u8; 4],
            extranonce2: [0u8; 8],
        }
    }

    #[test]
    fn projects_share_accept_into_shared_view() {
        let accept = synthetic_accept(1024.0, 2048.0, false);
        let share = shared_accepted(
            "bc1qalice",
            "rig1",
            "sess0001",
            Some("bitaxe/1.0"),
            &accept,
            0.0,
        );
        assert_eq!(share.address, "bc1qalice");
        assert_eq!(share.worker, "rig1");
        assert_eq!(share.session_id, "sess0001");
        assert_eq!(share.effective_difficulty, 1024.0);
        assert_eq!(share.submission_difficulty, 2048.0);
        assert!(!share.is_block_candidate);
        assert_eq!(share.user_agent, Some("bitaxe/1.0"));
        assert_eq!(share.channel_count, 1, "SV1 is one device per connection");
    }

    #[test]
    fn propagates_block_candidate_flag() {
        let accept = synthetic_accept(100.0, 1e15, true);
        assert!(shared_accepted("a", "w", "s", None, &accept, 0.0).is_block_candidate);
    }

    /// The projection is the birth point of `ts_ms` — it must stamp the
    /// Core accept time so downstream sinks (and the Core→Satellite stream)
    /// carry the real share time instead of a sink-side `now()`.
    #[test]
    fn stamps_accept_time() {
        let before = bp_common::now_ms();
        let accept = synthetic_accept(1024.0, 2048.0, false);
        let ts = shared_accepted("a", "w", "s", None, &accept, 0.0).ts_ms;
        let after = bp_common::now_ms();
        assert!(
            ts >= before && ts <= after,
            "ts_ms must be stamped at accept time (got {ts}, window [{before}, {after}])"
        );
    }

    /// Stale and job-not-found share one reject bucket.
    #[test]
    fn a_stale_reject_lands_in_the_job_not_found_bucket() {
        let share = shared_rejected(Some("a"), Some("w"), "s", RejectReason::Stale, 8.0);
        assert_eq!(share.reason, RejectedReason::JobNotFound);
        assert_eq!(share.difficulty, 8.0);
    }
}
