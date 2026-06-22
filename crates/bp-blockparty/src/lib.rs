// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty mining mode — pure math, no I/O.
//!
//! Fixed-percent loot-split for pooled hashpower rentals: each block
//! found while the party is `ready` or `active` pays out to members in
//! admin-configured basis-point shares of the miner cut (= reward minus
//! base pool fee). No shares tracked, no ledger, no carry-forward.
//!
//! Coinbase-output and payout-entry types are re-exported from
//! [`bp_pplns`] so SV1 / SV2 coinbase build paths consume identical
//! shapes across all modes.

mod constants;
mod distribution;
mod status;

pub use bp_pplns::{CoinbaseDistributionEntry, DUST_LIMIT_SATS};
pub use constants::{
    DEFAULT_INVITATION_TTL_DAYS, DISSOLVE_COOLDOWN_MS, EMAIL_MAX_LEN, MAX_PERCENT_BP,
    MIN_PERCENT_BP, NAME_MAX_LEN, NAME_MIN_LEN, TOTAL_PERCENT_BP,
};
pub use distribution::{
    build_blockparty_distribution, BlockpartyDistributionInput, BlockpartyDistributionResult,
    BlockpartyMemberInput, BlockpartySplitSnapshot,
};
pub use status::{BlockpartyStatus, ParseBlockpartyStatusError};
