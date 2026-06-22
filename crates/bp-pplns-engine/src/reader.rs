// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only views consumed by `bp-api` HTTP routes.
//!
//! Each `ReaderView::*` method composes a Redis-window read with a
//! Postgres ledger read into a typed response struct. `bp-api`
//! serializes the struct to JSON; field names match the wire API so
//! the existing UI keeps working across the cut-over without
//! response-shape changes.
//!
//! Endpoints served:
//!
//! - `/api/pplns/status` ⇒ [`ReaderView::window_stats`]
//! - `/api/pplns/distribution` ⇒ [`ReaderView::current_distribution`]
//! - `/api/pplns/fees` ⇒ [`ReaderView::fee_config`]
//! - `/api/pplns/ledger` ⇒ [`ReaderView::ledger_summary`]
//! - `/api/pplns/:address` ⇒ [`ReaderView::address_status`]
//!
//! `/api/pplns/:address/history` is deferred to a future
//! consumer-driven bp-db read (per-address payout-history query).

use bp_common::{AddressId, Sats};
use bp_db::find_pplns_balance;
use chrono::Utc;

use crate::engine::{EngineError, PplnsEngine};

impl PplnsEngine {
    /// Returns a borrowed reader view. Cheap to construct; the
    /// underlying engine handles still live in `Arc`.
    pub fn reader(&self) -> ReaderView<'_> {
        ReaderView { engine: self }
    }
}

/// Read-only view-builder. Lifetime-bound to the engine handle.
pub struct ReaderView<'a> {
    engine: &'a PplnsEngine,
}

// ── Pool-wide window stats ─────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct WindowStats {
    /// Σ diff-1-weighted shares in the current window.
    pub total_shares: f64,
    /// `window_factor × network_difficulty` — the moving cap on
    /// `total_shares` (trim drops oldest above this).
    pub window_size: f64,
    /// Distinct addresses currently contributing.
    pub miner_count: u32,
    /// Current network difficulty (engine's view; the source of truth
    /// is the TDP template stream).
    pub network_difficulty: f64,
}

impl ReaderView<'_> {
    pub async fn window_stats(&self) -> Result<WindowStats, EngineError> {
        let by_addr = self.engine.window().read_window_by_address().await?;
        let total_shares: f64 = by_addr.values().sum();
        let window_size = self.engine.window().window_size();
        let network_difficulty = window_size
            / if self.engine.config().window_factor > 0.0 {
                self.engine.config().window_factor
            } else {
                1.0
            };
        Ok(WindowStats {
            total_shares,
            window_size,
            miner_count: by_addr.len() as u32,
            network_difficulty,
        })
    }
}

// ── Per-address window contribution + percent ──────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct AddressShare {
    pub address: String,
    pub total_shares: f64,
    /// `total_shares / Σ total_shares × 100`. `NaN`-safe (zero-share
    /// pool returns 0.0 for every address).
    pub percent: f64,
}

impl ReaderView<'_> {
    /// All addresses with current-window contribution, sorted by
    /// share-count descending. Empty Vec if the window is empty.
    pub async fn current_distribution(&self) -> Result<Vec<AddressShare>, EngineError> {
        let by_addr = self.engine.window().read_window_by_address().await?;
        let total: f64 = by_addr.values().sum();
        let mut out: Vec<AddressShare> = by_addr
            .into_iter()
            .map(|(address, total_shares)| {
                let percent = if total > 0.0 {
                    (total_shares / total) * 100.0
                } else {
                    0.0
                };
                AddressShare {
                    address,
                    total_shares,
                    percent,
                }
            })
            .collect();
        // Descending by total_shares; addresses with identical share
        // counts get stable alphabetic ordering as a tie-break so
        // dashboards don't flap.
        out.sort_by(|a, b| {
            b.total_shares
                .partial_cmp(&a.total_shares)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.address.cmp(&b.address))
        });
        Ok(out)
    }
}

// ── Per-address status ────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct AddressStatus {
    pub address: String,
    /// Signed ledger balance: positive = pool-owes, negative = miner-owes.
    pub balance_sats: i64,
    /// Lifetime on-chain sats paid to this address.
    pub total_paid_sats: i64,
    /// Current diff-1 share contribution within the window.
    pub current_window_shares: f64,
    /// `current_window_shares / window.total × 100`. 0.0 on empty window.
    pub current_window_percent: f64,
}

impl ReaderView<'_> {
    pub async fn address_status(
        &self,
        address: &str,
    ) -> Result<Option<AddressStatus>, EngineError> {
        // Per-address reads only need this address's share + the
        // pool-wide total for the percent denominator. Avoid the full
        // `HGETALL` (~30 KB transfer for a 600-miner pool) — single
        // `HGET` + the cached `GET` total are O(1).
        let window = self.engine.window();
        let current_window_shares = window.read_window_share_for_address(address).await?;
        let total = window.current_total().await?;
        let current_window_percent = if total > 0.0 {
            (current_window_shares / total) * 100.0
        } else {
            0.0
        };

        // Try to parse + look up the balance row. Invalid-address-format
        // input from the API just returns `Ok(None)` rather than 4xx —
        // permissive get-or-default behaviour.
        let Ok(addr_id) = AddressId::new(address.to_string()) else {
            // Malformed → no balance row + no window contribution (we
            // wouldn't have a HashMap entry for an invalid address
            // either). Surface as Some with zeros if window had it,
            // None otherwise.
            return Ok(if current_window_shares > 0.0 {
                Some(AddressStatus {
                    address: address.to_string(),
                    balance_sats: 0,
                    total_paid_sats: 0,
                    current_window_shares,
                    current_window_percent,
                })
            } else {
                None
            });
        };

        let row = find_pplns_balance(self.engine.pool(), &addr_id).await?;
        match (row, current_window_shares) {
            (None, 0.0) => Ok(None),
            (None, _) => Ok(Some(AddressStatus {
                address: address.to_string(),
                balance_sats: 0,
                total_paid_sats: 0,
                current_window_shares,
                current_window_percent,
            })),
            (Some(r), _) => Ok(Some(AddressStatus {
                address: address.to_string(),
                balance_sats: r.balance_sats.0,
                total_paid_sats: r.total_paid_sats.0,
                current_window_shares,
                current_window_percent,
            })),
        }
    }
}

// ── Pool-wide ledger summary ──────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Default)]
pub struct LedgerSummary {
    /// Σ of positive balance rows (pool owes miners).
    pub total_credit_sats: i64,
    /// Σ of |negative balance| rows (miners owe pool).
    pub total_debit_sats: i64,
    /// `total_credit_sats - total_debit_sats`. Should be ≈ 0 in a
    /// steady-state pool; persistent drift indicates ledger corruption.
    pub net_drift_sats: i64,
    /// Number of rows with positive balance.
    pub credit_row_count: u32,
    /// Number of rows with negative balance.
    pub debit_row_count: u32,
    /// Σ of positive balances whose owner has been inactive longer
    /// than `abandoned_balance_days` — the next dust sweep will
    /// pair-cancel these against the matching abandoned debits.
    pub abandoned_credit_sats: i64,
    /// Σ of |negative balances| in the abandoned bucket.
    pub abandoned_debit_sats: i64,
    /// `abandoned_balance_days` configured for this engine — exposed
    /// so dashboards can render the cutoff age.
    pub abandoned_balance_days: u32,
    /// Σ of `totalPaidSats` across every miner row (open + closed),
    /// i.e. the pool's lifetime on-chain payout.
    pub lifetime_paid_sats: i64,
}

impl ReaderView<'_> {
    pub async fn ledger_summary(&self) -> Result<LedgerSummary, EngineError> {
        let cfg = self.engine.config();
        let now_ms = Utc::now().timestamp_millis();
        let cutoff_ms = now_ms - (cfg.abandoned_balance_days as i64) * 86_400_000;

        // One PG round-trip — credit/debit sums, row counts, abandoned
        // buckets and lifetime payout are all computed in SQL. The
        // previous implementation fetched every non-zero balance row
        // into Rust and looped, which scaled poorly as historical
        // miner balances accumulated.
        let agg = bp_db::aggregate_pplns_balances(self.engine.pool(), cutoff_ms).await?;

        Ok(LedgerSummary {
            total_credit_sats: agg.credit_sats,
            total_debit_sats: agg.debit_sats,
            net_drift_sats: agg.credit_sats - agg.debit_sats,
            credit_row_count: agg.credit_row_count as u32,
            debit_row_count: agg.debit_row_count as u32,
            abandoned_credit_sats: agg.abandoned_credit_sats,
            abandoned_debit_sats: agg.abandoned_debit_sats,
            lifetime_paid_sats: agg.lifetime_paid_sats,
            abandoned_balance_days: cfg.abandoned_balance_days,
        })
    }
}

// ── Fee configuration (synchronous; no I/O) ───────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct FeeConfig {
    pub fee_address: Option<String>,
    pub fee_percent: f64,
    pub min_payout_sats: i64,
    pub coinbase_weight_budget: u32,
}

impl ReaderView<'_> {
    pub fn fee_config(&self) -> FeeConfig {
        let cfg = self.engine.config();
        FeeConfig {
            fee_address: cfg.fee_address.as_ref().map(|a| a.as_str().to_string()),
            fee_percent: cfg.fee_percent,
            min_payout_sats: cfg.min_payout_sats.0,
            coinbase_weight_budget: cfg.coinbase_weight_budget,
        }
    }
}

// Silence "unused" if Sats import isn't needed elsewhere.
#[allow(dead_code)]
fn _force_sats(_: Sats) {}
