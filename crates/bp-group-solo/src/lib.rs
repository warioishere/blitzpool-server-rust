// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo payout mode — pure logic.
//!
//! Group-Solo is one of three pool modes (alongside Solo and PPLNS). It
//! runs **PROP semantics**: a single share window per group, reset on
//! every block-found. Each member's coinbase cut is proportional to their
//! shares in the current round; trims and dust go to a per-group
//! pending-balance ledger.
//!
//! ## Scope
//!
//! This crate carries the **pure in-memory + math** half of Group-Solo:
//!
//! - [`GroupRoundState`] — per-group accumulator: address-shares,
//!   rejected-shares, last-accepted timestamps, best-share, total diff.
//!   Plain data; no I/O.
//! - [`build_group_solo_distribution`] — adapter on top of
//!   [`bp_pplns::build_coinbase_distribution`] that locks in the
//!   Group-Solo invariants (`suppress_matching_debits = true`, finder-
//!   bonus carve-out).
//!
//! ## What's deferred (see `DEFERRED.md`)
//!
//! - Redis-backed round-state mirror (`groupsolo:{groupId}:*` keys) →
//!   service-wiring crate.
//! - Snapshot persistence + per-finder snapshot keys → service-wiring.
//! - DB transactions for `pplns_group_block_history` /
//!   `pplns_group_balance` writes → `bp-db` writes + service-wiring.
//! - `InflightResultCache` for distribution dedup → reusable utility in a
//!   later session.
//! - Reentrancy guard / scheduled round reset / removal cleanup → caller
//!   orchestration.
//!
//! ## Companion piece
//!
//! Group **membership / activation / invitations / tokens** lives in
//! [`bp-group-mgmt`](../../bp-group-mgmt/index.html) — separate crate
//! because the I/O boundaries and consumer paths are different.

mod distribution;
mod round;

pub use distribution::{build_group_solo_distribution, GroupSoloDistributionInput};
pub use round::{BestShare, GroupRoundState, ShareEffect};

// Re-export the bp-pplns result type so callers don't need an explicit
// `bp_pplns` import for Group-Solo work.
pub use bp_pplns::{CoinbaseDistributionEntry, CoinbaseDistributionResult};
