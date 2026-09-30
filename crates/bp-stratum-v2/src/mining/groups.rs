// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection group-channel registry for SV2 mining channels.
//!
//! ## What is a group channel? (SV2 Mining/Group Channel / SV2 Mining/NewExtendedMiningJob)
//!
//! A **group channel** lets the pool broadcast ONE `NewExtendedMiningJob`
//! (and one `SetNewPrevHash`) addressed to a `group_channel_id` instead of
//! one job per member channel. The downstream (a proxy without the
//! `REQUIRES_STANDARD_JOBS` flag) splices each of its own channels'
//! `extranonce_prefix` into the shared coinbase to derive per-channel work.
//! It saves frames on connections that aggregate many channels.
//!
//! ## Grouping invariant
//!
//! Every channel in a group MUST share the EXACT SAME full extranonce size
//! (SV2 Mining/Group Channel / SV2 Mining/Extended Extranonce): the group's
//! single `coinbase_tx_prefix` carries a fixed scriptSig-length varint, so the
//! coinbase slot size must be identical for every member. So there is one
//! group per `(connection, full_extranonce_size)`, and a channel only joins
//! the group of its own size ([`GroupChannelRegistry::join_group_for_size`]).
//!
//! ## Shared job id
//!
//! A group broadcast carries ONE `job_id`, so the group owns a monotonic
//! counter ([`GroupChannel::alloc_job_id`]). The caller stores the job on
//! every member channel under that id, so per-channel `SubmitShares*`
//! validation (keyed by job id) works unchanged.
//!
//! ## Scope: per-connection, group id from the channel-id namespace
//!
//! [`GroupChannelRegistry`] is embedded in `MiningSessionState`
//! (per-connection). The `group_channel_id` MUST live in the SAME namespace as
//! `channel_id` and never collide (SV2 Mining/Group Channel), so the
//! **caller** allocates the id from the session's `next_channel_id` counter
//! and hands it to [`GroupChannelRegistry::join_group_for_size`] — the
//! registry never invents ids.

use std::collections::{HashMap, HashSet};

use super::jobs::ExtendedJob;

/// A single group: its id, the member channel ids, the shared full
/// extranonce size that defines it, and the monotonic job-id counter used
/// for group broadcasts.
///
/// `Eq` is intentionally not derived: [`current_job`](Self::current_job)
/// carries an [`ExtendedJob`] whose `Difficulty` fields are `f64`-backed
/// and therefore not `Eq`.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupChannel {
    pub id: u32,
    pub channel_ids: HashSet<u32>,
    /// The full extranonce size (bytes) every member shares — the grouping
    /// invariant. For an Extended member it's `extranonce_prefix.len() +
    /// extranonce_size`. (Only Extended channels are grouped.)
    pub full_extranonce_size: usize,
    /// Monotonic source of the shared `job_id` carried on group broadcasts.
    /// Starts at 1.
    next_job_id: u32,
    /// The `job_id` of the most recently broadcast group job, or `None`
    /// before the first broadcast. Lets a newly-opened member be onboarded
    /// onto the CURRENT job (same id) instead of sending the existing members
    /// a fresh job and a spurious new block.
    current_job_id: Option<u32>,
    /// The coinbase TEMPLATE of the group's current broadcast job, or `None`
    /// before the first broadcast. Stored on the group because an
    /// emptied-then-refilled group has no member to copy it from. Its
    /// `difficulty` is a placeholder; onboarding uses the new member's own.
    current_job: Option<ExtendedJob>,
}

impl GroupChannel {
    /// Allocate the next shared `job_id` for a group broadcast and record it
    /// as the group's current job. The caller stores the resulting job on
    /// every member channel under this id.
    pub fn alloc_job_id(&mut self) -> u32 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        self.current_job_id = Some(id);
        id
    }

    /// The `job_id` of the group's current broadcast job, or `None` before
    /// the first broadcast.
    pub fn current_job_id(&self) -> Option<u32> {
        self.current_job_id
    }

    /// Record the coinbase template of the group's current broadcast job.
    /// Called once per full group broadcast (after [`alloc_job_id`]); read
    /// by the onboard path to seed a freshly-opened member.
    ///
    /// [`alloc_job_id`]: Self::alloc_job_id
    pub fn set_current_job(&mut self, job: ExtendedJob) {
        self.current_job = Some(job);
    }

    /// The coinbase template of the group's current broadcast job, or `None`
    /// before the first broadcast.
    pub fn current_job(&self) -> Option<&ExtendedJob> {
        self.current_job.as_ref()
    }
}

/// Per-connection group-channel registry. Pure data structure — no I/O,
/// no locking, owned `&mut` by the connection task.
#[derive(Clone, Debug, Default)]
pub struct GroupChannelRegistry {
    groups: HashMap<u32, GroupChannel>,
}

impl GroupChannelRegistry {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn get(&self, group_id: u32) -> Option<&GroupChannel> {
        self.groups.get(&group_id)
    }

    pub fn get_mut(&mut self, group_id: u32) -> Option<&mut GroupChannel> {
        self.groups.get_mut(&group_id)
    }

    /// The group a channel belongs to, or `None` if un-grouped. Linear scan
    /// — fine for the single-digit-groups-per-connection scale.
    pub fn group_for_channel(&self, channel_id: u32) -> Option<u32> {
        self.groups
            .iter()
            .find_map(|(&id, g)| g.channel_ids.contains(&channel_id).then_some(id))
    }

    /// Add `channel_id` to the group of its `full_extranonce_size`, creating
    /// that group under `new_group_id()` when there is none yet, and return
    /// the group's id. The id is drawn only when a group is created; the
    /// caller takes it from the session's channel-id namespace so it can
    /// never collide with a channel id. Idempotent: re-adding a member is a
    /// no-op.
    pub fn join_group_for_size(
        &mut self,
        channel_id: u32,
        full_extranonce_size: usize,
        new_group_id: impl FnOnce() -> u32,
    ) -> u32 {
        let group_id = self
            .groups
            .iter()
            .find_map(|(&id, g)| (g.full_extranonce_size == full_extranonce_size).then_some(id))
            .unwrap_or_else(|| {
                let group_id = new_group_id();
                self.groups.insert(
                    group_id,
                    GroupChannel {
                        id: group_id,
                        channel_ids: HashSet::new(),
                        full_extranonce_size,
                        next_job_id: 1,
                        current_job_id: None,
                        current_job: None,
                    },
                );
                group_id
            });
        self.groups
            .get_mut(&group_id)
            .expect("found or inserted above")
            .channel_ids
            .insert(channel_id);
        group_id
    }

    /// Drop a channel from whichever group it's in (no-op if un-grouped).
    /// Called on channel close.
    pub fn remove_channel(&mut self, channel_id: u32) {
        if let Some(group_id) = self.group_for_channel(channel_id) {
            if let Some(group) = self.groups.get_mut(&group_id) {
                group.channel_ids.remove(&channel_id);
                // Group emptied: drop the stale current job so a later
                // re-joining member gets a fresh full broadcast, not the
                // onboard-reuse of a job pinned to a now-old block.
                if group.channel_ids.is_empty() {
                    group.current_job_id = None;
                    group.current_job = None;
                }
            }
        }
    }

    /// Drop an entire group + its membership. Returns the removed group.
    pub fn remove_group(&mut self, group_id: u32) -> Option<GroupChannel> {
        self.groups.remove(&group_id)
    }

    /// Allocate the next shared `job_id` for a group's broadcast. `None` if
    /// the group is unknown.
    pub fn alloc_job_id(&mut self, group_id: u32) -> Option<u32> {
        self.groups
            .get_mut(&group_id)
            .map(GroupChannel::alloc_job_id)
    }

    /// Iterate `(group_id, &GroupChannel)` — for the broadcast's
    /// "one job per group" fan-out.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &GroupChannel)> {
        self.groups.iter().map(|(&id, g)| (id, g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── join_group_for_size + size invariant ───────────────────────

    #[test]
    fn join_creates_a_group_under_the_caller_supplied_id() {
        let mut reg = GroupChannelRegistry::new();
        assert_eq!(reg.join_group_for_size(2, 12, || 7), 7);
        let g = reg.get(7).unwrap();
        assert_eq!(g.id, 7);
        assert_eq!(g.full_extranonce_size, 12);
        assert_eq!(g.channel_ids, [2].into_iter().collect());
    }

    /// A channel of an existing size joins that group without drawing an id;
    /// a channel of another size gets a group of its own, so no group ever
    /// mixes sizes (SV2 Mining/Group Channel).
    #[test]
    fn join_groups_by_full_extranonce_size() {
        let mut reg = GroupChannelRegistry::new();
        assert_eq!(reg.join_group_for_size(2, 12, || 7), 7);
        assert_eq!(
            reg.join_group_for_size(3, 12, || unreachable!("the size-12 group exists")),
            7
        );
        assert_eq!(reg.join_group_for_size(4, 16, || 8), 8);
        assert_eq!(
            reg.get(7).unwrap().channel_ids,
            [2, 3].into_iter().collect()
        );
        assert_eq!(reg.get(8).unwrap().channel_ids, [4].into_iter().collect());
    }

    #[test]
    fn join_is_idempotent() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        reg.join_group_for_size(2, 12, || unreachable!("the size-12 group exists"));
        assert_eq!(reg.get(7).unwrap().channel_ids.len(), 1);
    }

    // ── group_for_channel ──────────────────────────────────────────

    #[test]
    fn group_for_channel_finds_membership() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        assert_eq!(reg.group_for_channel(2), Some(7));
        assert_eq!(reg.group_for_channel(99), None);
    }

    // ── shared job-id allocation ───────────────────────────────────

    #[test]
    fn alloc_job_id_is_monotonic_and_shared_per_group() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(1, 12, || 7);
        assert_eq!(reg.alloc_job_id(7), Some(1));
        assert_eq!(reg.alloc_job_id(7), Some(2));
        assert_eq!(reg.alloc_job_id(7), Some(3));
        assert_eq!(reg.alloc_job_id(99), None);
    }

    #[test]
    fn current_job_id_tracks_last_alloc() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(1, 12, || 7);
        assert_eq!(reg.get(7).unwrap().current_job_id(), None);
        let j = reg.alloc_job_id(7).unwrap();
        assert_eq!(reg.get(7).unwrap().current_job_id(), Some(j));
        let j2 = reg.alloc_job_id(7).unwrap();
        assert_eq!(reg.get(7).unwrap().current_job_id(), Some(j2));
        assert_ne!(j, j2);
    }

    #[test]
    fn alloc_job_id_independent_across_groups() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(1, 12, || 7);
        reg.join_group_for_size(2, 16, || 8);
        assert_eq!(reg.alloc_job_id(7), Some(1));
        assert_eq!(reg.alloc_job_id(8), Some(1));
        assert_eq!(reg.alloc_job_id(7), Some(2));
    }

    // ── remove ─────────────────────────────────────────────────────

    #[test]
    fn remove_channel_drops_from_group() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        reg.remove_channel(2);
        assert!(reg.get(7).unwrap().channel_ids.is_empty());
        assert_eq!(reg.group_for_channel(2), None);
    }

    #[test]
    fn remove_channel_unknown_is_noop() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        reg.remove_channel(999); // must not panic
        assert_eq!(reg.get(7).unwrap().channel_ids.len(), 1);
    }

    fn dummy_job() -> ExtendedJob {
        ExtendedJob {
            payouts_fingerprint: [0u8; 32],
            coinbase_prefix: vec![0xAA],
            coinbase_suffix: vec![0xBB],
            merkle_path: vec![],
            extranonce_prefix: Vec::new(),
            version: 0x2000_0000,
            prev_hash: [0u8; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0,
            difficulty: bp_share::Difficulty(1024.0),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: Some(1),
            jdp_claims_the_block: false,
            created_at: 0,
            retired_at: None,
        }
    }

    /// Emptying a group drops its current job (id + template) so a later
    /// re-joining member gets a fresh full broadcast, not the onboard-reuse of
    /// a job pinned to a now-old block.
    #[test]
    fn remove_last_channel_clears_current_job_state() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        reg.alloc_job_id(7); // current_job_id = Some(1)
        reg.get_mut(7).unwrap().set_current_job(dummy_job());
        assert_eq!(reg.get(7).unwrap().current_job_id(), Some(1));
        assert!(reg.get(7).unwrap().current_job().is_some());

        reg.remove_channel(2); // group now empty → clear job state

        assert!(reg.get(7).is_some(), "empty group persists for re-join");
        assert_eq!(
            reg.get(7).unwrap().current_job_id(),
            None,
            "emptied group must drop its current job id"
        );
        assert!(
            reg.get(7).unwrap().current_job().is_none(),
            "emptied group must drop its current job template"
        );
    }

    /// Removing one of several members does NOT clear the group's current job
    /// (the group is still active for the remaining members).
    #[test]
    fn remove_non_last_channel_keeps_current_job_state() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        reg.join_group_for_size(3, 12, || 7);
        reg.alloc_job_id(7);
        reg.get_mut(7).unwrap().set_current_job(dummy_job());

        reg.remove_channel(2); // group still has channel 3

        assert_eq!(reg.get(7).unwrap().current_job_id(), Some(1));
        assert!(reg.get(7).unwrap().current_job().is_some());
    }

    #[test]
    fn remove_group_drops_entire_group() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(2, 12, || 7);
        let dropped = reg.remove_group(7).unwrap();
        assert!(dropped.channel_ids.contains(&2));
        assert_eq!(reg.len(), 0);
        assert!(reg.remove_group(7).is_none());
    }

    // ── iter ───────────────────────────────────────────────────────

    #[test]
    fn iter_yields_all_groups() {
        let mut reg = GroupChannelRegistry::new();
        reg.join_group_for_size(1, 12, || 7);
        reg.join_group_for_size(2, 16, || 8);
        let ids: HashSet<u32> = reg.iter().map(|(id, _)| id).collect();
        assert_eq!(ids, [7, 8].into_iter().collect());
    }
}
