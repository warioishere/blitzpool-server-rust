// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-side extranonce-prefix allocation.
//!
//! The implementation now lives in [`bp_common::extranonce`] so the SV1
//! and SV2 servers can share one allocator type (each on its own worker
//! partition, so their prefixes never overlap). Re-exported here to keep
//! the `crate::extranonce::ExtranonceAllocator` path stable for the SV2
//! server + its tests.

pub use bp_common::extranonce::{ExtranonceAllocator, ExtranonceError};
