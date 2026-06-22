// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hooks for cross-crate orchestration. Group lifecycle events (Redis
//! round-state cleanup, min-payout config, cron scheduling) are
//! projected into a small trait so the bin-level wiring can inject
//! the real implementation (e.g. `bp-group-solo-engine`).
//!
//! Tests use [`NoopHooks`] — every callback is a fast no-op returning
//! sensible defaults.

use async_trait::async_trait;
use bp_common::{AddressId, Sats};
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

    /// Pool-wide minimum payout threshold in sats. Used to reject
    /// finder-bonus values below dust floor. Implementations should
    /// return the pool's effective dust limit.
    fn min_payout_sats(&self) -> Sats;

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
    /// no-op-on-failure semantics as [`on_member_removed`].
    async fn on_group_dissolved(&self, group_id: Uuid);

    /// (Re-)apply the group's round-reset cron config. Idempotent —
    /// callers may invoke after every `updateRoundResetConfig` PATCH.
    /// Receives the row as it sits in PG after the PATCH commits.
    async fn apply_round_reset_config(&self, group: &PplnsGroupRow);
}

/// Cross-mode collision reader. The Blockparty service exposes the
/// connecting-address → group-id lookup so PPLNS-group `create_group`
/// + `add_member` can refuse an address that's already in a Blockparty
/// (symmetric to the Blockparty side's PplnsGroup-membership check).
///
/// Production wiring binds a `BlockpartyCache` here; deployments
/// without Blockparty pass `None` and the check short-circuits.
#[async_trait]
pub trait BlockpartyMembershipReader: Send + Sync {
    async fn is_member(&self, address: &AddressId) -> bool;
}

/// Fired after a membership change has updated this process's local routing
/// cache, so OTHER processes (notably the Stratum Front, which lives in a
/// separate process under the Core/Satellite split) can rebuild theirs.
/// `kind` names the cache (`"group"` / `"blockparty"`). Best-effort: the
/// implementation must swallow its own failures — a missed invalidation is
/// caught by the Front's periodic backstop rebuild, never a hard error on the
/// mutation path. Left unset (monolith / single-process) it's simply not called.
#[async_trait]
pub trait MembershipChangeNotifier: Send + Sync {
    async fn membership_changed(&self, kind: &str);
}

/// Sentinel for tests + early wiring: every hook does nothing.
/// `min_payout_sats` returns 1000 sats — enough for kick /
/// round-reset paths to compute, but most tests override the
/// per-call paths instead of relying on this constant.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopHooks;

#[async_trait]
impl GroupServiceHooks for NoopHooks {
    async fn last_active_for_member(&self, _group_id: Uuid, _address: &AddressId) -> Option<i64> {
        None
    }

    fn min_payout_sats(&self) -> Sats {
        Sats(1000)
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
