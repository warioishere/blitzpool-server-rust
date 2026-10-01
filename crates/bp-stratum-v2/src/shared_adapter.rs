// SPDX-License-Identifier: AGPL-3.0-or-later

//! Projects SV2's native share types into the protocol-agnostic
//! `bp_share_hook` views the server hands its sinks; the SV1 twin is
//! `bp_stratum_v1`'s `shared_adapter`.

use bp_share::Difficulty;
use bp_share_hook::{RejectedReason, SharedAcceptedShare, SharedRejectedShare};

use crate::mining::submit::{RejectReason, ShareAccept};

/// The shared view of an accepted SV2 share. `channel_count` is how many
/// mining channels the connection holds (`> 1` for a bundled rig).
pub(crate) fn shared_accepted<'a>(
    address: &'a str,
    worker: &'a str,
    session_id_hex: &'a str,
    user_agent: Option<&'a str>,
    accept: &ShareAccept,
    hash_rate: f64,
    channel_count: u32,
) -> SharedAcceptedShare<'a> {
    SharedAcceptedShare {
        address,
        worker,
        session_id: session_id_hex,
        user_agent,
        effective_difficulty: accept.effective_difficulty.as_f64(),
        submission_difficulty: accept.submission_difficulty.as_f64(),
        is_block_candidate: accept.is_block_candidate,
        hash_rate,
        channel_count,
        ts_ms: bp_common::now_ms(),
        // Producer-assigned downstream at the single fan-out point; the
        // protocol side has no global share sequence and no mode-gate, so it
        // leaves share_id/mode/group_id blank.
        share_id: "",
        mode: bp_common::MiningMode::Solo,
        group_id: None,
    }
}

/// Maps SV2's reject reasons onto the canonical `RejectedReason`; `None` for
/// protocol-validity rejects, which the per-address rejected-stats do not count.
fn map_sv2_reject(reason: RejectReason) -> Option<RejectedReason> {
    match reason {
        // A share for a retired job is stale; one for a job the channel
        // never had is job-not-found.
        RejectReason::StaleShare => Some(RejectedReason::Stale),
        RejectReason::InvalidJobId => Some(RejectedReason::JobNotFound),
        RejectReason::DuplicateShare => Some(RejectedReason::DuplicateShare),
        RejectReason::DifficultyTooLow => Some(RejectedReason::LowDifficulty),
        RejectReason::InvalidChannelId | RejectReason::BadExtranonceSize => None,
    }
}

/// The shared view of a rejected SV2 share, or `None` when the reject is a
/// protocol-validity failure the stats do not count (see [`map_sv2_reject`]).
pub(crate) fn shared_rejected<'a>(
    address: Option<&'a str>,
    worker: Option<&'a str>,
    session_id_hex: &'a str,
    reason: RejectReason,
    difficulty: Difficulty,
) -> Option<SharedRejectedShare<'a>> {
    Some(SharedRejectedShare {
        address,
        worker,
        session_id: session_id_hex,
        reason: map_sv2_reject(reason)?,
        difficulty: difficulty.as_f64(),
        // The producer (Core composite) stamps the group id from the mode
        // gate; the protocol side has none.
        group_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_jobs_lifecycle::JobClassification;

    fn synthetic_accept(eff: f64, sub: f64, candidate: bool) -> ShareAccept {
        ShareAccept {
            payouts_fingerprint: [0u8; 32],
            classification: JobClassification::Active,
            effective_difficulty: Difficulty(eff),
            submission_difficulty: Difficulty(sub),
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: candidate,
            template_id: None,
            jdp_claims_the_block: false,
            witness_coinbase: Vec::new(),
            effective_worker_name: None,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    #[test]
    fn projects_share_accept_into_shared_view() {
        let accept = synthetic_accept(512.0, 8192.0, false);
        let share = shared_accepted(
            "bc1qbob",
            "rig2",
            "sess-sv2-1",
            Some("antminer/sv2"),
            &accept,
            0.0,
            4,
        );
        assert_eq!(share.address, "bc1qbob");
        assert_eq!(share.worker, "rig2");
        assert_eq!(share.session_id, "sess-sv2-1");
        assert_eq!(share.effective_difficulty, 512.0);
        assert_eq!(share.submission_difficulty, 8192.0);
        assert!(!share.is_block_candidate);
        assert_eq!(share.user_agent, Some("antminer/sv2"));
        assert_eq!(
            share.channel_count, 4,
            "channel_count forwarded into shared view"
        );
    }

    #[test]
    fn propagates_block_candidate_flag() {
        let accept = synthetic_accept(100.0, 1e15, true);
        assert!(shared_accepted("a", "w", "s", None, &accept, 0.0, 1).is_block_candidate);
    }

    /// `ts_ms` is stamped at accept time, not at a downstream sink.
    #[test]
    fn stamps_accept_time() {
        let before = bp_common::now_ms();
        let accept = synthetic_accept(512.0, 8192.0, false);
        let ts = shared_accepted("a", "w", "s", None, &accept, 0.0, 1).ts_ms;
        let after = bp_common::now_ms();
        assert!(
            ts >= before && ts <= after,
            "ts_ms must be stamped at accept time (got {ts}, window [{before}, {after}])"
        );
    }

    /// A protocol-validity reject never reaches the stats sink.
    #[test]
    fn a_channel_id_reject_is_not_forwarded() {
        let r = shared_rejected(
            Some("a"),
            Some("w"),
            "s",
            RejectReason::InvalidChannelId,
            Difficulty(1.0),
        );
        assert!(r.is_none());
    }

    #[test]
    fn map_sv2_reject_distinguishes_duplicate_from_stale() {
        assert_eq!(
            map_sv2_reject(RejectReason::DuplicateShare),
            Some(RejectedReason::DuplicateShare)
        );
        assert_eq!(
            map_sv2_reject(RejectReason::StaleShare),
            Some(RejectedReason::Stale)
        );
        assert_eq!(
            map_sv2_reject(RejectReason::InvalidJobId),
            Some(RejectedReason::JobNotFound)
        );
        assert_eq!(
            map_sv2_reject(RejectReason::DifficultyTooLow),
            Some(RejectedReason::LowDifficulty)
        );
        assert_eq!(map_sv2_reject(RejectReason::InvalidChannelId), None);
        assert_eq!(map_sv2_reject(RejectReason::BadExtranonceSize), None);
    }
}
