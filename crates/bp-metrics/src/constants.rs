// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metric names + label names.
//!
//! Single source of truth so emit-sites in [`crate::recorder`] and
//! Grafana dashboards both see byte-identical strings.

// ── Stratum ──────────────────────────────────────────────────────────

pub const STRATUM_DIFFICULTY_ADJUSTMENTS_TOTAL: &str = "stratum_difficulty_adjustments_total";

// ── Block parking ───────────────────────────────────────────────────

/// Found blocks parked awaiting `confirmation_depth` before their ledger
/// apply. Normal to be non-zero briefly; a value that does not fall is a
/// block whose apply keeps failing.
pub const POOL_BLOCKS_PENDING_APPLY: &str = "pool_blocks_pending_apply";
/// Found blocks no automatic path could book, parked for the operator.
///
/// **This one should be zero.** Every entry is a block whose coinbase paid
/// miners on-chain and whose ledger entry they never got. Nothing else
/// reads that store, so this gauge is its only standing signal.
pub const POOL_BLOCKS_UNBOOKABLE: &str = "pool_blocks_unbookable";

// ── Core→Satellite stream consumers ─────────────────────────────────

/// Per-group consumer lag — entries added to the stream but not yet
/// delivered to this consumer group. A rising value means a satellite is
/// behind or down. Only emitted while Redis can compute it (see
/// [`STREAM_CONSUMER_LAG_COMPUTABLE`]).
pub const STREAM_CONSUMER_LAG: &str = "stream_consumer_lag";
/// Per-group pending (delivered-but-unacked) entries — the PEL size.
pub const STREAM_CONSUMER_PENDING: &str = "stream_consumer_pending";
/// `1` when Redis can compute the group's lag, `0` when it can't — which
/// happens exactly when the stream was trimmed below the group's last-read id
/// (probable entry loss). The plain lag gauge goes blind in that case, so
/// alert on `stream_consumer_lag_computable == 0`, not just on high lag.
pub const STREAM_CONSUMER_LAG_COMPUTABLE: &str = "stream_consumer_lag_computable";

// ── Label names ──────────────────────────────────────────────────────

pub const LABEL_STREAM: &str = "stream";
pub const LABEL_GROUP: &str = "group";
