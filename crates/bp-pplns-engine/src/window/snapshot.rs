// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-template coinbase distribution in a Redis hash, so `on_block_found`
//! settles against the exact state committed at template-build time, even
//! across a pool restart. Keyed under [`super::KEY_SNAPSHOT`] plus the payout
//! fingerprint ([`super::snapshot_key_for`]).

use std::collections::HashMap;
use std::time::Duration;

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

// ===========================================================================
// Weight snapshot (schema 3) — settlement INPUTS, not satoshi outcomes
// ===========================================================================

/// One address in a stored weight distribution — the raw settlement
/// inputs plus the published wire weight for audits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WeightSnapshotEntry {
    pub address: String,
    /// Integer share-fraction projection (`bp_pplns::SCORE_PRECISION`
    /// parts) — numerator of the settlement claim.
    pub score_weight: u64,
    /// Signed ledger balance at build time.
    pub balance_sats: i64,
    /// Published §3.1 weight; `0` = no coinbase output (folded/debt).
    pub wire_weight: u64,
    /// Per-output dust limit (consensus floor). Not the pool's `min_payout`,
    /// which decides at build time who is published at all, because a §4
    /// prune pays the withheld value to the pool output.
    pub dust_limit: u32,
}

/// Persistent weight distribution (schema 3): settlement INPUTS, not outcomes,
/// so `claim(T_actual) − paid` is correct at any revenue, pool or JDC job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredWeightSnapshot {
    /// Distribution order (published first — the coinbase output order).
    pub entries: Vec<WeightSnapshotEntry>,
    /// §3.1 `weight_P` (fee share + folded weights).
    pub weight_p: u64,
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

    /// Lower a built [`bp_pplns::WeightDistribution`] into the wire form.
    pub fn from_distribution(d: &bp_pplns::WeightDistribution) -> Self {
        Self {
            entries: d
                .entries
                .iter()
                .map(|e| WeightSnapshotEntry {
                    address: e.address.as_str().to_string(),
                    score_weight: e.score_weight,
                    balance_sats: e.balance_sats,
                    wire_weight: e.wire_weight,
                    dust_limit: bp_pplns::DUST_LIMIT_SATS as u32,
                })
                .collect(),
            weight_p: d.weight_p,
            fee_ppm: d.fee_ppm,
            fee_address: d.fee_address.as_str().to_string(),
            reference_revenue_sats: d.reference_revenue_sats,
            score_total: d.score_total,
        }
    }
}

/// Persist a weight snapshot as one atomic DEL + HSET + EXPIRE. The `schema`
/// field keeps any other format from hydrating through this parser: its
/// settlement math differs, so the reader treats it as missing.
pub async fn write_weight_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
    snapshot: &StoredWeightSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    let mut fields: Vec<(String, String)> = Vec::with_capacity(8 + snapshot.entries.len() * 5);
    fields.push(("schema".to_string(), "3".to_string()));
    fields.push(("weightP".to_string(), snapshot.weight_p.to_string()));
    fields.push(("feePpm".to_string(), snapshot.fee_ppm.to_string()));
    fields.push(("feeAddress".to_string(), snapshot.fee_address.clone()));
    fields.push((
        "referenceRevenueSats".to_string(),
        snapshot.reference_revenue_sats.to_string(),
    ));
    fields.push(("scoreTotal".to_string(), snapshot.score_total.to_string()));
    fields.push((
        "entry_count".to_string(),
        snapshot.entries.len().to_string(),
    ));
    for (i, e) in snapshot.entries.iter().enumerate() {
        fields.push((format!("e{i}_addr"), e.address.clone()));
        fields.push((format!("e{i}_score"), e.score_weight.to_string()));
        fields.push((format!("e{i}_balance"), e.balance_sats.to_string()));
        fields.push((format!("e{i}_wire"), e.wire_weight.to_string()));
        fields.push((format!("e{i}_dust"), e.dust_limit.to_string()));
    }

    let script = redis::Script::new(WRITE_SNAPSHOT_LUA);
    let mut invocation = script.key(key);
    invocation.arg(ttl_seconds as i64);
    for (field, value) in &fields {
        invocation.arg(field).arg(value);
    }
    let _: () = invocation.invoke_async(conn).await?;
    Ok(())
}

/// Atomic so no reader sees the key between `DEL` and `HSET`
/// ([`resolve_snapshot_for_block_found`] takes missing as final). The `DEL`
/// drops fields a longer earlier build left; per-field `HSET` instead of
/// `unpack` stays under Lua's C-stack argument limit.
const WRITE_SNAPSHOT_LUA: &str = r#"
redis.call('DEL', KEYS[1])
for i = 2, #ARGV, 2 do
    redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
"#;

/// Load a weight snapshot, or `Ok(None)` when the key is missing, has
/// a different schema or type, or fails to parse (warned, never a crash).
pub async fn read_weight_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<StoredWeightSnapshot>, RedisError> {
    let hash: HashMap<String, String> = match conn.hgetall(key).await {
        Ok(h) => h,
        Err(e) if bp_coinbase_snapshot::is_wrongtype(&e) => {
            warn!(
                key,
                error = %e,
                "weight snapshot: legacy or wrong-typed key, treating as missing"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if hash.is_empty() {
        return Ok(None);
    }
    match parse_weight_hash(&hash) {
        Some(parsed) => Ok(Some(parsed)),
        None => {
            warn!(
                key,
                "weight snapshot: failed to parse fields, treating as missing"
            );
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

fn parse_weight_hash(h: &HashMap<String, String>) -> Option<StoredWeightSnapshot> {
    // Exact match: a hash of any other schema must never hydrate into
    // this settlement math — see `write_weight_snapshot`.
    if h.get("schema")?.as_str() != "3" {
        return None;
    }
    let weight_p: u64 = h.get("weightP")?.parse().ok()?;
    let fee_ppm: u32 = h.get("feePpm")?.parse().ok()?;
    let fee_address = h.get("feeAddress")?.clone();
    let reference_revenue_sats: u64 = h.get("referenceRevenueSats")?.parse().ok()?;
    let score_total: u64 = h.get("scoreTotal")?.parse().ok()?;
    let entry_count: usize = h.get("entry_count")?.parse().ok()?;
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        entries.push(WeightSnapshotEntry {
            address: h.get(&format!("e{i}_addr"))?.clone(),
            score_weight: h.get(&format!("e{i}_score"))?.parse().ok()?,
            balance_sats: h.get(&format!("e{i}_balance"))?.parse().ok()?,
            wire_weight: h.get(&format!("e{i}_wire"))?.parse().ok()?,
            dust_limit: h.get(&format!("e{i}_dust"))?.parse().ok()?,
        });
    }
    Some(StoredWeightSnapshot {
        entries,
        weight_p,
        fee_ppm,
        fee_address,
        reference_revenue_sats,
        score_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::{AddressId, Sats};

    // ---- weight snapshot (schema 3) ----

    fn weight_snapshot_fixture() -> StoredWeightSnapshot {
        StoredWeightSnapshot {
            entries: vec![
                WeightSnapshotEntry {
                    address: "bc1qfoo0000000000000000000000000".to_string(),
                    score_weight: 750_000_000_000,
                    balance_sats: -1_234,
                    wire_weight: 749_999_000_000,
                    dust_limit: 5_000,
                },
                WeightSnapshotEntry {
                    address: "bc1qbar0000000000000000000000000".to_string(),
                    score_weight: 250_000_000_000,
                    balance_sats: 7_000,
                    wire_weight: 0,
                    dust_limit: 5_000,
                },
            ],
            weight_p: 15_228_426_395,
            fee_ppm: 15_000,
            fee_address: "bc1qfee0000000000000000000000000".to_string(),
            reference_revenue_sats: 312_500_000,
            score_total: 1_000_000_000_000,
        }
    }

    fn weight_hash_of(s: &StoredWeightSnapshot) -> HashMap<String, String> {
        // Mirrors write_weight_snapshot's field list.
        let mut h = HashMap::new();
        h.insert("schema".to_string(), "3".to_string());
        h.insert("weightP".to_string(), s.weight_p.to_string());
        h.insert("feePpm".to_string(), s.fee_ppm.to_string());
        h.insert("feeAddress".to_string(), s.fee_address.clone());
        h.insert(
            "referenceRevenueSats".to_string(),
            s.reference_revenue_sats.to_string(),
        );
        h.insert("scoreTotal".to_string(), s.score_total.to_string());
        h.insert("entry_count".to_string(), s.entries.len().to_string());
        for (i, e) in s.entries.iter().enumerate() {
            h.insert(format!("e{i}_addr"), e.address.clone());
            h.insert(format!("e{i}_score"), e.score_weight.to_string());
            h.insert(format!("e{i}_balance"), e.balance_sats.to_string());
            h.insert(format!("e{i}_wire"), e.wire_weight.to_string());
            h.insert(format!("e{i}_dust"), e.dust_limit.to_string());
        }
        h
    }

    #[test]
    fn parse_weight_hash_roundtrip() {
        let s = weight_snapshot_fixture();
        let parsed = parse_weight_hash(&weight_hash_of(&s)).expect("parse ok");
        assert_eq!(parsed, s);
    }

    /// A schema-2 hash does not hydrate even with every schema-3 field present.
    #[test]
    fn parse_weight_hash_refuses_a_schema_2_bonus_hash() {
        let s = weight_snapshot_fixture();
        let mut h = weight_hash_of(&s);
        h.insert("schema".to_string(), "2".to_string());
        h.insert("finderBonusAddr".to_string(), "bc1qold".to_string());
        h.insert("finderBonusSats".to_string(), "50000".to_string());
        assert!(
            parse_weight_hash(&h).is_none(),
            "a pre-proportion snapshot must be refused, not silently stripped of its bonus"
        );
    }

    /// A hash in any other layout never hydrates through the weight parser.
    #[test]
    fn parse_weight_hash_rejects_schema_1() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "312500000".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "0".to_string());
        assert!(parse_weight_hash(&h).is_none());
    }

    /// A truncated entry list refuses to hydrate.
    #[test]
    fn parse_weight_hash_truncated_entries_returns_none() {
        let s = weight_snapshot_fixture();
        let mut h = weight_hash_of(&s);
        h.remove("e1_wire");
        assert!(parse_weight_hash(&h).is_none());
    }

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
        assert_eq!(s.weight_p, d.weight_p);
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
