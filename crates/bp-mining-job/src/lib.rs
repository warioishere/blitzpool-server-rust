// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mining job construction — coinbase, merkle root, BIP-141 witness, block-header assembly.
//!
//! Pure functions plus a `MiningJob` value type that captures the per-template
//! coinbase split (prefix / extranonce-slot / suffix) so per-share extranonce
//! splicing is allocation-light and thread-safe.

mod address;
mod bip141;
pub mod bip54;
mod cache;
mod coinbase;
mod header;
mod merkle;

pub use address::{address_to_script, normalize_btc_address, AddressError};
pub use bip141::{has_witness_bytes, strip_bip141, Bip141Error, StrippedCoinbase};
pub use bip54::{check_coinbase as check_coinbase_bip54, decode_bip34_height, Bip54Violation};
pub use cache::{MiningJobCache, MiningJobCacheStats};
pub use coinbase::{
    build_mining_job, build_mining_job_from_tdp, CoinbaseTemplate, MiningJob, MiningJobError,
    PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
pub use header::build_block_header;
pub use merkle::merkle_root_from_coinbase;
