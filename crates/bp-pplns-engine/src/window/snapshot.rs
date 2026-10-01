// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-template coinbase distribution, persisted so `on_block_found` books
//! the exact state committed at template-build time, even across a restart.
//! The format is shared with Group-Solo in [`bp_coinbase_snapshot::snapshot`];
//! PPLNS keys it under [`super::KEY_SNAPSHOT`] plus the payout fingerprint.

pub use bp_coinbase_snapshot::snapshot::{
    delete_snapshot, read_weight_snapshot, write_weight_snapshot, StoredWeightSnapshot,
    WeightSnapshotEntry,
};
