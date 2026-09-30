// SPDX-License-Identifier: AGPL-3.0-or-later

//! `pplns:snapshot` Redis hash — per-block coinbase distribution
//! persistence so `on_block_found` mutates the ledger against the exact
//! state committed at template-build time, even across a pool restart.
//!
//! The format + read/write/delete logic lives in
//! [`bp_coinbase_snapshot::snapshot`], shared with Group-Solo so the wire
//! format has one source of truth. PPLNS keys each snapshot under the
//! [`super::KEY_SNAPSHOT`] prefix plus the payout-list fingerprint; the
//! [`super::WindowStore`] snapshot accessors pass that key to these
//! functions. This module re-exports the shared shapes.

pub use bp_coinbase_snapshot::snapshot::{
    delete_snapshot, read_weight_snapshot, write_weight_snapshot, StoredWeightSnapshot,
    WeightSnapshotEntry,
};
