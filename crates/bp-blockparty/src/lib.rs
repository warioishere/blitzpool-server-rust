// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty mining mode, pure math. A block found while the party is ready
//! or active pays members fixed basis-point shares of the miner cut; no
//! shares tracked, no ledger, no carry-forward.

mod constants;
mod distribution;
mod status;

pub use bp_common::DUST_LIMIT_SATS;
pub use constants::{
    DISSOLVE_COOLDOWN_MS, EMAIL_MAX_LEN, MAX_PERCENT_BP, MIN_PERCENT_BP, NAME_MAX_LEN,
    NAME_MIN_LEN, TOTAL_PERCENT_BP,
};
pub use distribution::{
    build_blockparty_distribution, BlockpartyDistributionInput, BlockpartyDistributionResult,
    BlockpartyMemberInput, BlockpartySplitSnapshot, CoinbaseDistributionEntry,
};
pub use status::{BlockpartyStatus, ParseBlockpartyStatusError};
