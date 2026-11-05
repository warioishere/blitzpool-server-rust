// SPDX-License-Identifier: AGPL-3.0-or-later

//! Template Distribution Protocol client over bitcoin-core's SV2 IPC socket.
//! The upstream `BitcoinCoreSv2TDP` is `!Send` (capnp-rpc), so it lives on its
//! own OS thread behind a `Send + Clone` [`TdpHandle`]. Mining-protocol
//! translation and JDP live in the stratum crates, not here.

mod assembler;
mod config;
mod error;
mod handle;
mod message;
mod tx_cache;
mod worker;

pub use assembler::{ActiveFromTemplate, ActiveTemplate, TemplateAssembler, TemplateChange};
pub use config::{
    TdpCoinbaseConstraints, TdpConfig, DEFAULT_BROADCAST_CAPACITY, DEFAULT_FEE_THRESHOLD,
    DEFAULT_MIN_INTERVAL_SECS, DEFAULT_RECONNECT_BACKOFF_SECS, DEFAULT_SUBMIT_CAPACITY,
};
pub use error::TdpError;
pub use handle::TdpHandle;
pub use message::{
    apply_to_snapshot, NewTemplate, RequestTransactionDataError, RequestTransactionDataSuccess,
    SetNewPrevHash, TdpRequest, TemplateSnapshot, TemplateUpdate,
};
pub use tx_cache::TemplateTxCache;

/// The Bitcoin Core IPC schema family every IPC client in the pool speaks: the
/// TDP worker here and the JDP validation engine in the binary. Both talk to
/// the same node, so they share this one value.
pub const BITCOIN_CORE_VERSION: bitcoin_core_sv2::runtime_api::BitcoinCoreVersion =
    bitcoin_core_sv2::runtime_api::BitcoinCoreVersion::V32X;
