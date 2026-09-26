// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mining job construction — coinbase, merkle root, BIP-141 witness, block-header assembly.
//!
//! Pure functions plus a `MiningJob` value type that captures the per-template
//! coinbase split (prefix / extranonce-slot / suffix) so per-share extranonce
//! splicing is allocation-light and thread-safe.

mod address;
pub mod bip54;
mod cache;
mod coinbase;
mod header;
mod merkle;

pub use address::{address_to_script, AddressError};
pub use bip54::{check_coinbase as check_coinbase_bip54, decode_bip34_height, Bip54Violation};
pub use cache::{MiningJobCache, MiningJobCacheStats};
pub use coinbase::{
    assemble_witness_coinbase, build_mining_job, build_mining_job_from_tdp, is_payable_identity,
    serialize_coinbase_prefix, solo_payouts, CoinbaseTemplate, MiningJob, MiningJobError,
    PayoutEntry, ResolvedPayouts, SoloFeeConfig, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
pub use header::{
    build_block_header, meets_network_target, version_meets_consensus_floor,
    MIN_CONSENSUS_BLOCK_VERSION,
};
pub use merkle::{coinbase_merkle_branch, merkle_root_from_coinbase};
