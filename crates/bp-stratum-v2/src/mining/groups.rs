// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection group-channel registry for SV2 mining channels.
//!
//! ## What is a group channel? (SV2 spec §5.2.3 / §5.3.16)
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
//! (spec §5.2.3 line 187 / §5.1.2.1 line 104): the group's single
//! `coinbase_tx_prefix` carries a fixed scriptSig-length varint, so the
//! coinbase slot size must be identical for every member. We therefore key
//! one group per `(connection, full_extranonce_size)` and reject a member
//! whose size disagrees.
//!
//! ## Shared job id
//!
//! A group broadcast carries ONE `job_id`, so the group owns its own
//! monotonic `job_id` counter ([`GroupChannel::alloc_job_id`]). The caller
//! stores the resulting job record on every member channel under that same
//! shared id, so per-channel `SubmitShares*` validation (keyed by job id)
//! keeps working unchanged.
//!
//! ## Scope: per-connection, group id from the channel-id namespace
//!
//! [`GroupChannelRegistry`] is embedded in `MiningSessionState`
//! (per-connection). The `group_channel_id` MUST live in the SAME namespace
//! as `channel_id` and never collide (spec §5.2.3 line 185), so the **caller**
//! allocates the id from the session's `next_channel_id` counter and passes
//! it to [`GroupChannelRegistry::create`] — the registry never invents ids.

use std::collections::{HashMap, HashSet};

use super::jobs::ExtendedJob;

/// Errors returned by [`GroupChannelRegistry`] mutations. All are
/// caller-bug / policy conditions; the SV2 spec has no `SetGroupChannelError`
/// wire message, so we surface a typed error for the caller to log/assert.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupError {
    /// `group_channel_id` doesn't exist in the registry.
    #[error("unknown group channel {0}")]
    UnknownGroup(u32),
    /// A channel's full extranonce size disagrees with its group's fixed
    /// size — spec §5.2.3 forbids mixing sizes in one group.
    #[error("group {group_id} expects full extranonce size {expected}, got {got}")]
    FullExtranonceSizeMismatch {
        group_id: u32,
        expected: usize,
        got: usize,
    },
}

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
    /// before the first broadcast. Lets the broadcast ONBOARD a newly-opened
    /// member with the group's CURRENT job (same id) instead of issuing a
    /// fresh job + spurious new-block to the existing members.
    current_job_id: Option<u32>,
    /// The coinbase TEMPLATE of the group's current broadcast job, or `None`
    /// before the first broadcast. Stored at broadcast time so the onboard
    /// path can hand a freshly-opened member the current job WITHOUT scanning
    /// existing members — which would fail for a Standard-only group (Standard
    /// members store only a pre-computed merkle root, not the raw coinbase
    /// parts) or an emptied-then-refilled group. The `difficulty` field is a
    /// placeholder; the onboard path overrides it with the new member's own
    /// session difficulty.
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

    /// Create an empty group with a caller-supplied `group_id` (drawn from
    /// the session's channel-id namespace so it can never collide with a
    /// channel id) and the full extranonce size that defines it. Channels
    /// are added via [`add_channel`].
    pub fn create(&mut self, group_id: u32, full_extranonce_size: usize) {
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

    /// The existing group for a given full extranonce size, or `None`. Used
    /// by the open handler to find-or-create one group per size.
    pub fn group_for_size(&self, full_extranonce_size: usize) -> Option<u32> {
        self.groups
            .iter()
            .find_map(|(&id, g)| (g.full_extranonce_size == full_extranonce_size).then_some(id))
    }

    /// Add a channel to a group. Rejects with [`GroupError::UnknownGroup`] if
    /// the group doesn't exist, or [`GroupError::FullExtranonceSizeMismatch`]
    /// if the channel's full extranonce size disagrees with the group's.
    /// Idempotent: re-adding the same channel to the same group is a no-op.
    pub fn add_channel(
        &mut self,
        group_id: u32,
        channel_id: u32,
        full_extranonce_size: usize,
    ) -> Result<(), GroupError> {
        let group = self
            .groups
            .get_mut(&group_id)
            .ok_or(GroupError::UnknownGroup(group_id))?;
        if group.full_extranonce_size != full_extranonce_size {
            return Err(GroupError::FullExtranonceSizeMismatch {
                group_id,
                expected: group.full_extranonce_size,
                got: full_extranonce_size,
            });
        }
        group.channel_ids.insert(channel_id);
        Ok(())
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

    // ── create + lookup ────────────────────────────────────────────

    #[test]
    fn create_with_caller_supplied_id_and_size() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        let g = reg.get(7).unwrap();
        assert_eq!(g.id, 7);
        assert_eq!(g.full_extranonce_size, 12);
        assert!(g.channel_ids.is_empty());
    }

    #[test]
    fn group_for_size_finds_existing() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.create(8, 16);
        assert_eq!(reg.group_for_size(12), Some(7));
        assert_eq!(reg.group_for_size(16), Some(8));
        assert_eq!(reg.group_for_size(99), None);
    }

    // ── add_channel + size invariant ───────────────────────────────

    #[test]
    fn add_channel_matching_size_succeeds() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        assert_eq!(reg.add_channel(7, 2, 12), Ok(()));
        assert_eq!(reg.add_channel(7, 3, 12), Ok(()));
        assert_eq!(reg.get(7).unwrap().channel_ids.len(), 2);
    }

    #[test]
    fn add_channel_size_mismatch_rejects() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        assert_eq!(
            reg.add_channel(7, 2, 16),
            Err(GroupError::FullExtranonceSizeMismatch {
                group_id: 7,
                expected: 12,
                got: 16,
            })
        );
        assert!(reg.get(7).unwrap().channel_ids.is_empty());
    }

    #[test]
    fn add_channel_unknown_group_rejects() {
        let mut reg = GroupChannelRegistry::new();
        assert_eq!(
            reg.add_channel(99, 2, 12),
            Err(GroupError::UnknownGroup(99))
        );
    }

    #[test]
    fn add_channel_is_idempotent() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.add_channel(7, 2, 12).unwrap();
        reg.add_channel(7, 2, 12).unwrap();
        assert_eq!(reg.get(7).unwrap().channel_ids.len(), 1);
    }

    // ── group_for_channel ──────────────────────────────────────────

    #[test]
    fn group_for_channel_finds_membership() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.add_channel(7, 2, 12).unwrap();
        assert_eq!(reg.group_for_channel(2), Some(7));
        assert_eq!(reg.group_for_channel(99), None);
    }

    // ── shared job-id allocation ───────────────────────────────────

    #[test]
    fn alloc_job_id_is_monotonic_and_shared_per_group() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        assert_eq!(reg.alloc_job_id(7), Some(1));
        assert_eq!(reg.alloc_job_id(7), Some(2));
        assert_eq!(reg.alloc_job_id(7), Some(3));
        assert_eq!(reg.alloc_job_id(99), None);
    }

    #[test]
    fn current_job_id_tracks_last_alloc() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
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
        reg.create(7, 12);
        reg.create(8, 16);
        assert_eq!(reg.alloc_job_id(7), Some(1));
        assert_eq!(reg.alloc_job_id(8), Some(1));
        assert_eq!(reg.alloc_job_id(7), Some(2));
    }

    // ── remove ─────────────────────────────────────────────────────

    #[test]
    fn remove_channel_drops_from_group() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.add_channel(7, 2, 12).unwrap();
        reg.remove_channel(2);
        assert!(reg.get(7).unwrap().channel_ids.is_empty());
        assert_eq!(reg.group_for_channel(2), None);
    }

    #[test]
    fn remove_channel_unknown_is_noop() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.remove_channel(999); // must not panic
        assert!(reg.get(7).unwrap().channel_ids.is_empty());
    }

    fn dummy_job() -> ExtendedJob {
        ExtendedJob {
            coinbase_prefix: vec![0xAA],
            coinbase_suffix: vec![0xBB],
            merkle_path: vec![],
            version: 0x2000_0000,
            prev_hash: [0u8; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0,
            difficulty: bp_share::Difficulty(1024.0),
            network_difficulty: bp_share::Difficulty(1e9),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: Some(1),
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
        reg.create(7, 12);
        reg.add_channel(7, 2, 12).unwrap();
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
        reg.create(7, 12);
        reg.add_channel(7, 2, 12).unwrap();
        reg.add_channel(7, 3, 12).unwrap();
        reg.alloc_job_id(7);
        reg.get_mut(7).unwrap().set_current_job(dummy_job());

        reg.remove_channel(2); // group still has channel 3

        assert_eq!(reg.get(7).unwrap().current_job_id(), Some(1));
        assert!(reg.get(7).unwrap().current_job().is_some());
    }

    #[test]
    fn remove_group_drops_entire_group() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.add_channel(7, 2, 12).unwrap();
        let dropped = reg.remove_group(7).unwrap();
        assert!(dropped.channel_ids.contains(&2));
        assert_eq!(reg.len(), 0);
        assert!(reg.remove_group(7).is_none());
    }

    // ── iter ───────────────────────────────────────────────────────

    #[test]
    fn iter_yields_all_groups() {
        let mut reg = GroupChannelRegistry::new();
        reg.create(7, 12);
        reg.create(8, 16);
        let ids: HashSet<u32> = reg.iter().map(|(id, _)| id).collect();
        assert_eq!(ids, [7, 8].into_iter().collect());
    }
}
