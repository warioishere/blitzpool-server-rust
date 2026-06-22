// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V1 server — JSON-RPC parser/emitter, ckpool-style job lifecycle,
//! TDP→mining.notify translator, vardiff, share validator, per-connection
//! statemachine.
//!
//! The crate is built up module-by-module per `MIGRATION_PLAN.md`. See
//! `CHECKLIST.md` for the live status.
//!
//! Architecture notes:
//!
//! - **Multi-thread by default.** Per-connection task on the tokio
//!   multi-thread runtime; share validation runs inline (~µs hashes don't
//!   warrant `spawn_blocking`).
//! - **TDP is the upstream.** This crate consumes
//!   `bp_template_distribution::TdpHandle` for `NewTemplate` +
//!   `SetNewPrevHash` updates and translates them to SV1 `mining.notify`
//!   frames. There is no `getblocktemplate` polling.
//! - **Behavioural spec.** Frame shape, edge cases, vardiff cadence, and
//!   reject-strings follow the documented SV1 protocol behaviour.
//!   Internal performance improvements are allowed where they don't
//!   change observable behaviour. The single deliberate divergence is
//!   the 8-hex-padded form for `mining.notify[5..8]` (ckpool convention)
//!   — see `feedback-sv1-notify-hex-padded` memory.

mod client;
mod config;
mod error;
mod frame;
mod hooks;
mod jobs;
mod notify;
mod server;
mod shared_adapter;
mod submit;

pub use shared_adapter::{
    Sv1AcceptedShareAdapter, Sv1RejectedShareAdapter, Sv1SessionPersistenceAdapter,
};

pub use client::{
    apply_destroy, apply_new_template, apply_vardiff_check, dispatch, handle_authorize,
    handle_configure, handle_extranonce_subscribe, handle_submit, handle_subscribe,
    handle_suggest_difficulty, random_session_id_hex, HandlerOutcome, SessionEvent, SessionState,
};
pub use config::{
    PortConfig, ServerConfig, DEFAULT_CPUMINER_FALLBACK_DIFFICULTY,
    DEFAULT_CPUMINER_HIGH_DIFF_THRESHOLD, DEFAULT_DIFFICULTY_CHECK_INTERVAL_MS,
    DEFAULT_EXTERNAL_SHARE_MIN_DIFFICULTY, DEFAULT_INITIAL_DIFFICULTY, DEFAULT_JOB_RETENTION_MS,
    DEFAULT_MIN_RETAINED_JOBS, DEFAULT_POOL_IDENTIFIER, DEFAULT_STALE_GRACE_MS,
    DEFAULT_TARGET_SHARES_PER_MINUTE, DEFAULT_VERSION_ROLLING_MASK, EXTRANONCE2_SIZE,
};
pub use error::StratumV1Error;
pub use frame::{
    parse_request, refine_user_agent, write_authorize_response, write_configure_response,
    write_error, write_extranonce_subscribe_response, write_set_difficulty, write_set_extranonce,
    write_submit_success, write_subscribe_response, AuthorizeRequest, ConfigureRequest,
    FrameParseError, RpcId, SV1Request, SubmitRequest, SubscribeRequest, SuggestDifficultyRequest,
    ERR_DUPLICATE_SHARE, ERR_JOB_NOT_FOUND, ERR_LOW_DIFFICULTY_SHARE, ERR_NOT_SUBSCRIBED,
    ERR_OTHER_UNKNOWN, ERR_UNAUTHORIZED_WORKER, REJECT_DUPLICATE, REJECT_INVALID_ADDR,
    REJECT_JOB_NOT_FOUND, REJECT_LOW_DIFF, REJECT_NOT_SUBSCRIBED, REJECT_STALE,
    REJECT_SUGGEST_DISABLED, REJECT_UNAUTHORIZED, VALIDATION_INVALID_AUTHORIZE,
    VALIDATION_INVALID_CONFIGURE, VALIDATION_INVALID_SUBMIT, VALIDATION_INVALID_SUBSCRIBE,
    VALIDATION_INVALID_SUGGEST,
};
pub use hooks::{
    AcceptedShareSink, BlockSubmissionSink, DeviceStatusSink, NoOpHooks, PayoutResolver,
    RejectedShareSink, ServerHooks, SessionPersistence,
};
pub use jobs::{lifecycle_from_server_config, JobClassification, JobLookup, JobRegistry};
pub use notify::{
    build_notify_frame, network_difficulty_from_n_bits, swap_endian_words, ActiveSV1Template,
    SV1TemplateAssembler, TemplateChange,
};
pub use server::{StratumV1Server, TemplateBroadcast};
pub use submit::{
    validate_submit, RejectReason, SessionContext, SessionShareCache, ShareAccept, ShareReject,
    ShareValidation,
};
