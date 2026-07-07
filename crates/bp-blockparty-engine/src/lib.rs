// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty service layer — orchestrates group lifecycle, member
//! confirmations, share/block hooks, and the load-bearing routing
//! caches that the stratum layer reads on every share.
//!
//! Layered above:
//!   - [`bp_blockparty`] — pure math + status FSM + constants.
//!   - [`bp_db`] — sqlx queries against `blockparty_*` tables.
//!   - [`bp_group_mgmt`] — token gen/hash (reused as-is).
//!   - [`bp_group_mgmt_engine`] — `AddressCache` for the bidirectional
//!     mode-collision check against PplnsGroup membership.

mod api;
mod cache;
mod error;
mod hooks;
mod service;
mod util;

pub use api::BlockpartyApi;

pub use cache::{AdminCacheEntry, BlockpartyCache};
pub use error::BlockpartyServiceError;
pub use hooks::{BlockpartyHooks, NoopHooks};
pub use service::{
    BlockpartyCreateResult, BlockpartyService, BlockpartyServiceConfig, CoinbaseReservation,
    MarkMemberConfirmedResult, PendingPartyFeeRoute,
};
