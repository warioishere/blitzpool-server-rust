// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty service layer: group lifecycle, member confirmations,
//! share/block hooks, and the routing cache read on every share. The pure
//! math and status FSM live in [`bp_blockparty`].

mod cache;
mod error;
mod hooks;
mod service;
mod util;

pub use cache::{AdminCacheEntry, BlockpartyCache};
pub use error::BlockpartyServiceError;
pub use hooks::{BlockpartyHooks, NoopHooks};
pub use service::{
    BlockpartyCreateResult, BlockpartyService, BlockpartyServiceConfig, CoinbaseReservation,
    MarkMemberConfirmedResult, PendingPartyFeeRoute,
};
