// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo engine: each block is split by the members' shares, with an
//! optional finder bonus folded into the finder's weight. No ledger: an unpaid
//! member forfeits to the pool ([`bp_pplns::WithheldValue::ToPool`]), which holds
//! only while `GroupService` caps membership at what the coinbase can pay.

/// The API validator ([`bp_group_mgmt::MAX_FINDER_BONUS_PPM`]) and the build's
/// silent clamp ([`bp_pplns::MAX_FINDER_BONUS_PPM`]) must agree, or the pool
/// accepts a bonus it never pays; only this crate sees both.
const _: () = assert!(
    bp_group_mgmt::MAX_FINDER_BONUS_PPM as i64 == bp_pplns::MAX_FINDER_BONUS_PPM as i64,
    "bp_group_mgmt::MAX_FINDER_BONUS_PPM and bp_pplns::MAX_FINDER_BONUS_PPM must agree — \
     the API would otherwise accept a bonus the coinbase silently clamps"
);

pub mod config;
pub mod distribution;
pub mod engine;
pub mod error;
pub mod history;
pub mod hooks;
pub mod reader;
pub mod reset;
pub mod round;
