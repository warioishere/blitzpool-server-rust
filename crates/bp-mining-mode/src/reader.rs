// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dependency-inverted reader traits.
//!
//! `bp-mining-mode` is pure routing logic — it never talks to Redis, DB, or
//! anything else. Production wiring (in the service-layer crates) supplies
//! impls of the three traits below; the resolver composes them.
//!
//! ## Error semantics
//!
//! All trait methods return `Option<…>` / `bool`. By contract:
//!
//! - `Some(_) / true` = positive signal observed.
//! - `None / false` = no signal **or transient failure** (Redis down, DB
//!   timeout, etc.). Impls are responsible for logging the underlying error
//!   and surfacing `None / false` so the resolver's fallback kicks in. This
//!   behaviour ensures Redis-unavailable causes silent degradation to
//!   state-based detection rather than user-visible errors.

use std::sync::Arc;

use async_trait::async_trait;
use bp_common::{AddressId, MiningMode};

/// Reads the short-TTL live port-marker that the stratum layer writes on
/// every accepted share. The marker is the **primary** signal for
/// `ModeResolver` — when present it reflects the port the miner is
/// connected to *right now*.
#[async_trait]
pub trait LiveMarkerReader: Send + Sync {
    async fn get(&self, address: &AddressId) -> Option<MiningMode>;
}

/// Looks up the *active* group an address belongs to, or returns `None`
/// for addresses that are not in any active group (no membership, or
/// membership in an inactive group — e.g. one that hasn't reached the
/// minimum-member threshold yet).
///
/// Returns the group's UUID as a string. Conversion from
/// `uuid::Uuid` to the canonical string form lives at the repository
/// boundary so this crate stays UUID-crate-free.
#[async_trait]
pub trait GroupMembershipReader: Send + Sync {
    async fn active_group_for(&self, address: &AddressId) -> Option<String>;
}

/// Reports whether an address has at least one diff-weighted share in the
/// current PPLNS window. Used as a fallback signal when no live marker is
/// available (offline miner, marker expired, etc.).
#[async_trait]
pub trait PplnsWindowReader: Send + Sync {
    async fn contains(&self, address: &AddressId) -> bool;
}

/// Looks up an *active routable* Blockparty group by **admin** address.
/// Blockparty membership routes off the admin's address (the admin's
/// stratum connection is the hashpower source); regular member rows
/// don't carry a routing claim. `None` for any address not currently
/// owning an active group, or when Blockparty isn't wired at all.
///
/// Returns the group's UUID as a string so the crate stays
/// UUID-crate-free; conversion happens at the binding boundary.
#[async_trait]
pub trait BlockpartyMembershipReader: Send + Sync {
    async fn admin_group_for(&self, address: &AddressId) -> Option<String>;
}

// Blanket impls for `Arc<T>` so callers can share a single backing reader
// across multiple resolvers without losing the trait bound. The forwarder
// vtable cost is irrelevant at routing-decision frequencies.

#[async_trait]
impl<T: LiveMarkerReader + ?Sized> LiveMarkerReader for Arc<T> {
    async fn get(&self, address: &AddressId) -> Option<MiningMode> {
        (**self).get(address).await
    }
}

#[async_trait]
impl<T: GroupMembershipReader + ?Sized> GroupMembershipReader for Arc<T> {
    async fn active_group_for(&self, address: &AddressId) -> Option<String> {
        (**self).active_group_for(address).await
    }
}

#[async_trait]
impl<T: PplnsWindowReader + ?Sized> PplnsWindowReader for Arc<T> {
    async fn contains(&self, address: &AddressId) -> bool {
        (**self).contains(address).await
    }
}

#[async_trait]
impl<T: BlockpartyMembershipReader + ?Sized> BlockpartyMembershipReader for Arc<T> {
    async fn admin_group_for(&self, address: &AddressId) -> Option<String> {
        (**self).admin_group_for(address).await
    }
}

/// Reader stub for deployments without Blockparty wired — returns
/// `None` for every address.
pub struct NoopBlockpartyReader;

#[async_trait]
impl BlockpartyMembershipReader for NoopBlockpartyReader {
    async fn admin_group_for(&self, _address: &AddressId) -> Option<String> {
        None
    }
}
