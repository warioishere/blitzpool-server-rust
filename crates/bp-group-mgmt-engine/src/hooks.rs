// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group lifecycle side effects (Redis round-state cleanup, cron scheduling)
//! behind traits, so the binary injects the real implementation and tests
//! use [`NoopHooks`].

use async_trait::async_trait;
use bp_common::AddressId;
use bp_db::PplnsGroupRow;
use uuid::Uuid;

/// Hooks the `GroupService` calls during membership / lifecycle
/// transitions. None of the methods may panic — they're invoked from
/// inside admin request paths.
#[async_trait]
pub trait GroupServiceHooks: Send + Sync {
    /// Last accepted-share epoch-ms for `address` in `group_id`. The
    /// kick-inactivity check uses this; `None` means "never mined" and
    /// the caller falls back to `joined_at`.
    async fn last_active_for_member(&self, group_id: Uuid, address: &AddressId) -> Option<i64>;

    /// Best-effort Redis cleanup after a member-kick. Receives the
    /// kicked address + the surviving member list (snapshot taken
    /// before the DB delete). Errors are swallowed by the caller —
    /// they get logged but don't roll the kick back.
    async fn on_member_removed(
        &self,
        group_id: Uuid,
        kicked_address: &AddressId,
        remaining_addresses: &[AddressId],
    );

    /// Best-effort Redis + scheduler cleanup on group dissolve. Same
    /// no-op-on-failure semantics as [`Self::on_member_removed`].
    async fn on_group_dissolved(&self, group_id: Uuid);

    /// (Re-)apply the group's round-reset cron config. Idempotent —
    /// callers may invoke after every round-reset config PATCH.
    /// Receives the row as it sits in PG after the PATCH commits.
    async fn apply_round_reset_config(&self, group: &PplnsGroupRow);
}

/// Lets `create_group` and `add_member` refuse an address already in a
/// Blockparty, mirroring the Blockparty side's group-membership check.
/// Without Blockparty it stays unwired and the check short-circuits.
#[async_trait]
pub trait BlockpartyMembershipReader: Send + Sync {
    async fn is_member(&self, address: &AddressId) -> bool;
}

/// Fired after a membership change so OTHER processes (the Stratum Front)
/// rebuild their routing cache; `kind` is `"group"` / `"blockparty"`.
/// Must swallow its own failures: a missed invalidation is caught by the
/// Front's periodic rebuild, never an error on the mutation path.
#[async_trait]
pub trait MembershipChangeNotifier: Send + Sync {
    async fn membership_changed(&self, kind: &str);
}

/// A request to join a Team was stored; the Team's admin is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequestCreated {
    pub group_id: Uuid,
    pub group_name: String,
    /// The Team's admin at the time of the request.
    pub admin_address: AddressId,
    pub requester_address: AddressId,
}

/// Fired after a join request is stored, so the process that sends
/// notifications can tell the Team's admin. Must swallow its own failures:
/// the request stands whether or not the admin hears of it.
#[async_trait]
pub trait JoinRequestNotifier: Send + Sync {
    async fn join_request_created(&self, event: JoinRequestCreated);
}

/// Test sink that records every [`JoinRequestCreated`] in order.
#[derive(Debug, Default, Clone)]
pub struct CapturingJoinRequestNotifier {
    pub events: std::sync::Arc<std::sync::Mutex<Vec<JoinRequestCreated>>>,
}

impl CapturingJoinRequestNotifier {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events_snapshot(&self) -> Vec<JoinRequestCreated> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl JoinRequestNotifier for CapturingJoinRequestNotifier {
    async fn join_request_created(&self, event: JoinRequestCreated) {
        self.events.lock().unwrap().push(event);
    }
}

/// Sentinel for tests + early wiring: every hook does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopHooks;

#[async_trait]
impl GroupServiceHooks for NoopHooks {
    async fn last_active_for_member(&self, _group_id: Uuid, _address: &AddressId) -> Option<i64> {
        None
    }

    async fn on_member_removed(
        &self,
        _group_id: Uuid,
        _kicked_address: &AddressId,
        _remaining_addresses: &[AddressId],
    ) {
    }

    async fn on_group_dissolved(&self, _group_id: Uuid) {}

    async fn apply_round_reset_config(&self, _group: &PplnsGroupRow) {}
}

#[async_trait]
impl JoinRequestNotifier for NoopHooks {
    async fn join_request_created(&self, _event: JoinRequestCreated) {}
}
