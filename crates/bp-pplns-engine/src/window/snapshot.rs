// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-template settlement inputs as one JSON string in Redis, so a found
//! block settles against the exact state committed at template-build time.
//! Keyed under [`super::KEY_SNAPSHOT`] plus the payout fingerprint
//! ([`super::snapshot_key_for`]). The same JSON travels in the block-found
//! event and the parked block.

use std::time::Duration;

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

/// One address's settlement inputs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeightSnapshotEntry {
    pub address: String,
    /// Integer share-fraction projection (`bp_pplns::SCORE_PRECISION`
    /// parts) — numerator of the settlement claim.
    pub score_weight: u64,
    /// Signed ledger balance at build time.
    pub balance_sats: i64,
}

/// A weight distribution's settlement INPUTS, not outcomes, so
/// `claim(T_actual) − paid` is correct at any revenue, pool or JDC job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredWeightSnapshot {
    /// Distribution order (published first — the coinbase output order).
    pub entries: Vec<WeightSnapshotEntry>,
    /// Pool fee in parts-per-million.
    pub fee_ppm: u32,
    /// Pool-output recipient.
    pub fee_address: String,
    /// Revenue the wire-weight boosts were projected against — the base
    /// [`StoredWeightSnapshot::extras_total`] re-projects satoshi promises
    /// from at settlement time.
    pub reference_revenue_sats: u64,
    /// `Σ score_weight` — denominator of every claim.
    pub score_total: u64,
}

impl StoredWeightSnapshot {
    /// `X` — the satoshi promises (ledger balances) on top of the score split.
    /// Recomputed rather than stored so build and settlement share one
    /// [`bp_share::project_extras`] and cannot drift apart.
    pub fn extras_total(&self) -> i64 {
        let extras: Vec<(u64, i64)> = self
            .entries
            .iter()
            .map(|e| (e.score_weight, e.balance_sats))
            .collect();
        bp_share::project_extras(
            &extras,
            self.score_total,
            self.fee_ppm,
            self.reference_revenue_sats,
        )
        .total
    }

    /// The settlement inputs of a built [`bp_pplns::WeightDistribution`].
    pub fn from_distribution(d: &bp_pplns::WeightDistribution) -> Self {
        Self {
            entries: d
                .entries
                .iter()
                .map(|e| WeightSnapshotEntry {
                    address: e.address.as_str().to_string(),
                    score_weight: e.score_weight,
                    balance_sats: e.balance_sats,
                })
                .collect(),
            fee_ppm: d.fee_ppm,
            fee_address: d.fee_address.as_str().to_string(),
            reference_revenue_sats: d.reference_revenue_sats,
            score_total: d.score_total,
        }
    }
}

/// Persist a weight snapshot with its TTL; `SET` replaces any earlier value
/// under the key atomically.
pub async fn write_weight_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
    snapshot: &StoredWeightSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    // Serialization cannot fail for these plain types.
    let json = serde_json::to_string(snapshot).expect("serialize weight snapshot");
    conn.set_ex(key, json, u64::from(ttl_seconds)).await
}

/// Load a weight snapshot, or `Ok(None)` when the key is missing or its value
/// does not parse with this version (warned).
pub async fn read_weight_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<StoredWeightSnapshot>, RedisError> {
    let Some(json): Option<String> = conn.get(key).await? else {
        return Ok(None);
    };
    match serde_json::from_str(&json) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(err) => {
            warn!(key, %err, "weight snapshot does not parse, treating as missing");
            Ok(None)
        }
    }
}

/// Retries for a transient Redis failure on a block-found snapshot read:
/// that read stands between a found block and its booking, and no caller
/// retries on its own. A missing snapshot (`Ok(None)`) is not retried.
const READ_RETRIES: u32 = 3;
/// Backoff between those attempts, multiplied by the attempt number.
const READ_BACKOFF: Duration = Duration::from_millis(80);

/// Read the snapshot a found block's job was built from, under the same key
/// the build wrote ([`super::snapshot_key_for`]). Call it at the block-found
/// instant, never at apply time: the key's TTL is sized for a live job and is
/// not backed up. A failed read is retried; `Ok(None)` is a terminal verdict.
pub async fn resolve_snapshot_for_block_found(
    conn: &mut ConnectionManager,
    weights_fingerprint: &[u8; 32],
) -> Result<Option<StoredWeightSnapshot>, RedisError> {
    let key = super::snapshot_key_for(weights_fingerprint);
    let mut attempt = 0;
    loop {
        match read_weight_snapshot(conn, &key).await {
            Ok(found) => return Ok(found),
            Err(err) if attempt < READ_RETRIES => {
                warn!(
                    %err,
                    key,
                    attempt,
                    "pplns: weight-snapshot read failed — retrying before giving up on the block"
                );
                attempt += 1;
                tokio::time::sleep(READ_BACKOFF * attempt).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::{AddressId, Sats};

    /// `from_distribution` lowers the built distribution 1:1.
    #[test]
    fn from_distribution_lowers_faithfully() {
        use std::collections::HashMap as StdMap;
        let a1 = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let fee = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let shares = StdMap::from([(a1.clone(), 2.0)]);
        let balances = StdMap::from([(a1.clone(), Sats(-500))]);
        let d = bp_pplns::build_weight_distribution(bp_pplns::WeightDistributionInput {
            address_shares: &shares,
            balances: &balances,
            fee_percent: 1.0,
            fee_address: &fee,
            coinbase_weight_budget: 50_000,
            min_payout_sats: Sats(5_000),
            finder_bonus_ppm: 0,
            finder_address: None,
            reference_revenue_sats: 312_500_000,
            withheld_value: bp_pplns::WithheldValue::ToOtherMiners,
        })
        .unwrap();
        let s = StoredWeightSnapshot::from_distribution(&d);
        assert_eq!(s.entries.len(), d.entries.len());
        assert_eq!(s.entries[0].address, a1.as_str());
        assert_eq!(s.entries[0].score_weight, d.entries[0].score_weight);
        assert_eq!(s.entries[0].balance_sats, -500);
        assert_eq!(s.fee_ppm, 10_000);
        assert_eq!(s.fee_address, fee.as_str());
        assert_eq!(s.score_total, d.score_total);
        assert_eq!(s.reference_revenue_sats, 312_500_000);
    }

    /// The re-derived `X` matches the build's, so coinbase and ledger split one pot.
    #[test]
    fn extras_total_reproduces_the_build() {
        use std::collections::HashMap as StdMap;
        let a1 = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let a2 = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
        let fee = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let shares = StdMap::from([(a1.clone(), 3.0), (a2.clone(), 1.0)]);
        // The bonus is plain score weight; what must reproduce is the ledger
        // side: credits, debts, and a promise larger than the block.
        for (balances, bonus_ppm) in [
            (StdMap::new(), 0u32),
            (StdMap::from([(a1.clone(), Sats(10_000_000))]), 0),
            (StdMap::from([(a2.clone(), Sats(-7_000_000))]), 0),
            (StdMap::new(), 160_000),
            (StdMap::from([(a1.clone(), Sats(10_000_000))]), 160_000),
            // Beyond the block: the solvency scale fires on the balance,
            // and settlement has to land on the same scaled figure.
            (StdMap::from([(a2.clone(), Sats(3_000_000_000))]), 160_000),
        ] {
            let d = bp_pplns::build_weight_distribution(bp_pplns::WeightDistributionInput {
                address_shares: &shares,
                balances: &balances,
                fee_percent: 1.5,
                fee_address: &fee,
                coinbase_weight_budget: 50_000,
                min_payout_sats: Sats(5_000),
                finder_bonus_ppm: bonus_ppm,
                finder_address: Some(&a1),
                reference_revenue_sats: 312_500_000,
                withheld_value: bp_pplns::WithheldValue::ToOtherMiners,
            })
            .unwrap();
            let s = StoredWeightSnapshot::from_distribution(&d);
            assert_eq!(
                s.extras_total(),
                d.extras_total,
                "snapshot X drifted from the build at bonus_ppm={bonus_ppm}"
            );
        }
    }
}
