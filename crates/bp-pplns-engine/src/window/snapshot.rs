// SPDX-License-Identifier: AGPL-3.0-or-later

//! `pplns:snapshot` Redis hash — per-block coinbase distribution
//! persistence so `on_block_found` mutates the ledger against the exact
//! state committed at template-build time, even across a pool restart.
//!
//! The format + read/write/delete logic now lives in
//! [`bp_coinbase_snapshot::snapshot`] (shared with Group-Solo so the
//! wire format stays one source of truth). PPLNS uses a single fixed
//! key ([`super::KEY_SNAPSHOT`]); the [`super::WindowStore`] snapshot
//! accessors pass it to these functions. This module just re-exports
//! the shared shapes so existing `window::snapshot::…` paths resolve.

pub use bp_coinbase_snapshot::snapshot::{
    delete_snapshot, read_snapshot, write_snapshot, ParsedSnapshot, StoredSnapshot,
};
