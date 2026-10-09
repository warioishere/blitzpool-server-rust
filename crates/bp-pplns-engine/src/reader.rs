// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only views behind the `/api/pplns/*` routes: each method joins a
//! Redis window read with a Postgres ledger read. Field names match the
//! wire API the UI consumes.

use bp_common::AddressId;
use bp_db::find_pplns_balance;
use chrono::Utc;

use crate::engine::{EngineError, PplnsEngine};

impl PplnsEngine {
    pub fn reader(&self) -> ReaderView<'_> {
        ReaderView { engine: self }
    }
}

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
    /// Engine's view of network difficulty; the TDP template stream is
    /// the source of truth.
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

impl ReaderView<'_> {
    /// How many miners the most recently built coinbase pays, as opposed to
    /// [`WindowStats::miner_count`], which counts every address in the window.
    pub async fn published_output_count(&self) -> Result<Option<u32>, EngineError> {
        Ok(self.engine.window().read_published_outputs().await?)
    }
}

// ── Per-address window contribution + percent ──────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct AddressShare {
    pub address: String,
    pub total_shares: f64,
    /// `total_shares / Σ total_shares × 100`; 0.0 on an empty window.
    pub percent: f64,
}

impl ReaderView<'_> {
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
        // Address tie-break so equal shares do not flap on dashboards.
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
        // One `HGET` plus the cached total instead of a full `HGETALL`
        // of the window.
        let window = self.engine.window();
        let current_window_shares = window.read_window_share_for_address(address).await?;
        let total = window.current_total().await?;
        let current_window_percent = if total > 0.0 {
            (current_window_shares / total) * 100.0
        } else {
            0.0
        };

        let Ok(addr_id) = AddressId::new(address.to_string()) else {
            // A malformed address cannot have a balance row; answer from
            // the window alone instead of a 4xx.
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
    /// Σ of positive balances whose owner has been inactive longer than
    /// `abandoned_balance_days`. This is what the next dust sweep will try
    /// to close, and its counterparty pool is [`Self::total_debit_sats`] —
    /// **every** open debit, not the abandoned slice below.
    pub abandoned_credit_sats: i64,
    /// Σ of |negative balances| in the abandoned bucket. Informational only:
    /// the sweep pairs credits against debits of any age, so a 0 here does
    /// not mean it pairs nothing.
    pub abandoned_debit_sats: i64,
    /// Exposed so dashboards can render the cutoff age.
    pub abandoned_balance_days: u32,
    /// Σ of `totalPaidSats` across every miner row (open + closed),
    /// i.e. the pool's lifetime on-chain payout.
    pub lifetime_paid_sats: i64,
}

impl ReaderView<'_> {
    pub async fn ledger_summary(&self) -> Result<LedgerSummary, EngineError> {
        let cfg = self.engine.config();
        let now_ms = Utc::now().timestamp_millis();
        let cutoff_ms = crate::config::abandoned_cutoff_ms(now_ms, cfg.abandoned_balance_days);

        // Aggregated in SQL so no balance rows are fetched however many
        // accumulate.
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
