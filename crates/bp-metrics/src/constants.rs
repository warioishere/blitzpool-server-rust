// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metric and label names, one source of truth for emit-sites in
//! [`crate::recorder`] and the Grafana dashboards.

// ── Stratum ──────────────────────────────────────────────────────────

pub const STRATUM_DIFFICULTY_ADJUSTMENTS_TOTAL: &str = "stratum_difficulty_adjustments_total";

// ── Block parking ───────────────────────────────────────────────────

/// Found blocks parked awaiting `confirmation_depth` before their ledger
/// apply. Normal to be non-zero briefly; a value that does not fall is a
/// block whose apply keeps failing.
pub const POOL_BLOCKS_PENDING_APPLY: &str = "pool_blocks_pending_apply";
/// Found blocks no automatic path could book, parked for the operator. Should
/// be zero: each one paid miners on-chain without a ledger entry, and this
/// gauge is the only standing signal for that store.
pub const POOL_BLOCKS_UNBOOKABLE: &str = "pool_blocks_unbookable";

// ── Core→Satellite stream consumers ─────────────────────────────────

/// Per-group entries not yet delivered; rising means a satellite is behind or
/// down. Only emitted while Redis can compute it
/// ([`STREAM_CONSUMER_LAG_COMPUTABLE`]).
pub const STREAM_CONSUMER_LAG: &str = "stream_consumer_lag";
/// Per-group pending (delivered-but-unacked) entries — the PEL size.
pub const STREAM_CONSUMER_PENDING: &str = "stream_consumer_pending";
/// `0` when the stream was trimmed below the group's last-read id (probable
/// entry loss), where the lag gauge goes blind; alert on this being `0`, not
/// only on high lag.
pub const STREAM_CONSUMER_LAG_COMPUTABLE: &str = "stream_consumer_lag_computable";

// ── Label names ──────────────────────────────────────────────────────

pub const LABEL_STREAM: &str = "stream";
pub const LABEL_GROUP: &str = "group";
