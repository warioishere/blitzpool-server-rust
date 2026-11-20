// SPDX-License-Identifier: AGPL-3.0-or-later

//! Template Distribution Protocol client over bitcoin-core's SV2 IPC socket.
//! The upstream `BitcoinCoreSv2TDP` is `!Send` (capnp-rpc), so it lives on its
//! own OS thread behind a `Send + Clone` [`TdpHandle`]. [`TemplateStreams`]
//! fans the assembled templates out to a Stratum server's connections; turning
//! them into protocol jobs, and JDP, live in the stratum crates.

mod assembler;
mod config;
mod error;
mod fanout;
mod handle;
mod message;
mod pacing;
mod tx_cache;
mod worker;

pub use assembler::{ActiveFromTemplate, ActiveTemplate, TemplateAssembler, TemplateChange};
pub use bitcoin_core_sv2::runtime_api::BitcoinCoreVersion;
pub use config::{
    TdpCoinbaseConstraints, TdpConfig, DEFAULT_BITCOIN_CORE_VERSION, DEFAULT_BROADCAST_CAPACITY,
    DEFAULT_FEE_THRESHOLD, DEFAULT_MIN_INTERVAL_SECS, DEFAULT_RECONNECT_BACKOFF_SECS,
    DEFAULT_SUBMIT_CAPACITY,
};
pub use error::TdpError;
pub use fanout::{StreamHandle, TemplateBroadcast, TemplateStreams};
pub use handle::TdpHandle;
pub use message::{
    apply_to_snapshot, NewTemplate, RequestTransactionDataError, RequestTransactionDataSuccess,
    SetNewPrevHash, TdpRequest, TemplateSnapshot, TemplateUpdate,
};
pub use pacing::{RefreshPacer, REFRESH_SPREAD};
pub use tx_cache::TemplateTxCache;
