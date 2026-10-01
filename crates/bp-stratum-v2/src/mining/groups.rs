// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection SV2 group channels: one `NewExtendedMiningJob` per group.
//! Members MUST share one full extranonce size, since the shared coinbase prefix
//! fixes the scriptSig-length varint (SV2 Mining/Group Channel). Group ids come
//! from the caller's channel-id namespace so they never collide with a channel id.

use std::collections::{HashMap, HashSet};

use super::jobs::ExtendedJob;

/// One group, defined by its shared full extranonce size. A broadcast carries
/// one `job_id`, stored on every member so per-channel validation works.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupChannel {
    pub id: u32,
    pub channel_ids: HashSet<u32>,
    /// The grouping invariant; only Extended channels are grouped.
    pub full_extranonce_size: usize,
    next_job_id: u32,
    /// Lets a newly-opened member join the CURRENT job instead of sending
    /// the existing members a fresh job and a spurious new block.
    current_job_id: Option<u32>,
    /// Kept on the group because an emptied-then-refilled group has no member
    /// to copy it from. Its `difficulty` is a placeholder.
    current_job: Option<ExtendedJob>,
}

impl GroupChannel {
    /// Next shared `job_id`, recorded as the group's current job.
    pub fn alloc_job_id(&mut self) -> u32 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        self.current_job_id = Some(id);
        id
    }

    pub fn current_job_id(&self) -> Option<u32> {
        self.current_job_id
    }

    /// Record the current broadcast's coinbase template; seeds a member that
    /// opens later.
    pub fn set_current_job(&mut self, job: ExtendedJob) {
        self.current_job = Some(job);
    }

    pub fn current_job(&self) -> Option<&ExtendedJob> {
        self.current_job.as_ref()
    }
}

/// Per-connection group-channel registry, owned by the connection task.
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

    /// The group a channel belongs to. A linear scan suits the few groups
    /// per connection.
    pub fn group_for_channel(&self, channel_id: u32) -> Option<u32> {
        self.groups
            .iter()
            .find_map(|(&id, g)| g.channel_ids.contains(&channel_id).then_some(id))
    }

    /// Add `channel_id` to the group of its size and return the group's id.
    /// `new_group_id` is called only when a group is created; it must come
    /// from the session's channel-id namespace. Idempotent.
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

    /// Drop a channel from its group on channel close.
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

    pub fn remove_group(&mut self, group_id: u32) -> Option<GroupChannel> {
        self.groups.remove(&group_id)
    }

    pub fn alloc_job_id(&mut self, group_id: u32) -> Option<u32> {
        self.groups
            .get_mut(&group_id)
            .map(GroupChannel::alloc_job_id)
    }

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

    /// Same size joins the existing group without drawing an id; another size
    /// gets its own group (SV2 Mining/Group Channel).
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

    /// Emptying a group drops its current job, so a re-joining member gets a
    /// fresh broadcast instead of a job pinned to an old block.
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

    /// Removing one of several members keeps the group's current job.
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
