// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-block coinbase-distribution snapshot, persisted to a Redis hash
//! so `on_block_found` mutates the ledger against the exact state
//! committed at template-build time, even across a pool restart.
//!
//! Wire format (stable across deploy transitions):
//!
//! - `blockRewardSats` — scalar
//! - `consideredAddresses` — pipe-`|`-separated string
//! - `distribution_count` / `balanceAfter_count` — array length scalars
//! - `d{i}_addr` / `d{i}_pct` / `d{i}_sats` — one triple per
//!   distribution entry
//! - `b{i}_addr` / `b{i}_sats` — one pair per balanceAfter entry
//!
//! Callers pass a fully-built `key`: PPLNS uses a fixed `pplns:snapshot`;
//! Group-Solo builds `groupsolo:{groupId}:snapshot:{finderAddress}`.

use std::collections::HashMap;
use std::time::Duration;

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

/// Delete a snapshot key (called after `on_block_found` consumed it).
pub async fn delete_snapshot(conn: &mut ConnectionManager, key: &str) -> Result<(), RedisError> {
    let _: () = conn.del(key).await?;
    Ok(())
}

// ===========================================================================
// Weight snapshot (schema 2) — settlement INPUTS, not satoshi outcomes
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
    /// Per-output dust limit — the consensus floor (546). The pool's
    /// `min_payout` is not this field: it decides at build time who is
    /// published at all, because a §4 prune pays the withheld value to
    /// the pool output instead of to the other miners.
    pub dust_limit: u32,
}

/// Persistent form of a weight distribution (schema 3).
///
/// Where the schema-1 [`StoredSnapshot`] freezes the OUTCOME (exact
/// sats per output, valid for exactly one reward), this freezes the
/// INPUTS: settlement recomputes each address's claim from
/// `bp_share::claim_sats(score_weight, score_total, fee_ppm, T_actual)`
/// and books `claim − actually_paid` against the balance — correct for
/// ANY actual revenue inside the booking band, which is what makes one
/// snapshot serve the pool's own templates and every JDC's
/// independently-valued jobs alike.
///
/// Schema 3 dropped the `finder_bonus` field: the bonus is a proportion
/// now, already inside `score_weight`.
/// `deny_unknown_fields` is load-bearing, not tidiness. This struct is
/// serialized into the confirmation-gated pending-block queue, which
/// outlives a deploy by the whole confirmation window — far longer than
/// any snapshot TTL. A blob frozen by a pre-proportion build still
/// carries `finder_bonus`, and serde's default is to ignore a field it
/// no longer knows: the bonus would vanish from `extras_total` while
/// the coinbase had already paid it, and settlement would book the
/// finder a debt of nearly the whole bonus with the other members
/// taking the mirror credit. Refusing the blob outright makes it an
/// unparsable pending entry — pruned with a warning, having moved no
/// money.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredWeightSnapshot {
    /// Distribution order (published first — the coinbase output order).
    pub entries: Vec<WeightSnapshotEntry>,
    /// §3.1 `weight_P` (fee share + folded weights).
    pub weight_p: u64,
    /// Pool fee in parts-per-million.
    pub fee_ppm: u32,
    /// Pool-output recipient.
    pub fee_address: String,
    /// Revenue the wire-weight boosts were projected against; the
    /// booking band is checked against this.
    pub reference_revenue_sats: u64,
    /// `Σ score_weight` — denominator of every claim.
    pub score_total: u64,
}

impl StoredWeightSnapshot {
    /// `X` — the satoshi promises this distribution carried on top of
    /// the pure score split, recomputed the way the build computed it.
    ///
    /// Not a stored field, and deliberately so: it is a pure function
    /// of what IS stored (every entry's score weight and ledger
    /// balance, the fee and the reference revenue), and one shared
    /// [`bp_share::project_extras`] serving both sides is the only way
    /// build and settlement cannot drift apart. A second copy of this
    /// formula would be the next bug.
    ///
    /// The finder bonus is NOT in here any more: it is a proportion,
    /// carried as plain score weight, so it is exact at every revenue
    /// and has nothing to project. Only satoshi-denominated promises —
    /// ledger balances — still reach this.
    pub fn extras_total(&self) -> i64 {
        let extras = bp_share::extras_from_ledger(
            self.entries
                .iter()
                .map(|e| (e.address.as_str(), e.score_weight, e.balance_sats)),
        );
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
                    dust_limit: e.dust_limit,
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

/// Persist a weight snapshot under `key` with `ttl_seconds`. Same
/// DEL + HSET + EXPIRE shape (and rationale) as [`write_snapshot`];
/// the `schema` field is what keeps the formats from ever hydrating
/// through the wrong parser.
///
/// Schema 3: the finder bonus left this payload. A schema-2 hash still
/// carries `finderBonusAddr`/`finderBonusSats`, and its `extras_total`
/// INCLUDED that bonus — so hydrating one through the schema-3 parser
/// would compute every claim against a pot short by the bonus, booking
/// the finder a debt and the other members the mirror credit on a block
/// whose coinbase was perfectly correct. Refusing it is a
/// `SnapshotMissing`, which is logged loudly and books nothing.
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

/// `DEL` + `HSET` + `EXPIRE` as ONE indivisible step.
/// KEYS[1] = the snapshot key. ARGV[1] = TTL seconds, then alternating
/// field/value pairs.
///
/// Three separate round trips is what this replaces, and it was wrong twice
/// over. Between the `DEL` and the `HSET` the snapshot **did not exist**,
/// and a read landing there is the one case
/// [`read_weight_snapshot_with_retry`] deliberately does not retry: it takes
/// `Ok(None)` at face value on the grounds that a missing snapshot "will not
/// appear". Here it would have, microseconds later — and the caller maps that
/// `None` to a found block parked with no settlement inputs. The two sides
/// are the same process: the template build writes, the Stratum block-found
/// path reads.
///
/// The second failure is the one the write's own retry policy already
/// documents: a fault between the `DEL` and the `HSET` left the key
/// **deleted**, so a build that would have been a harmless rewrite of an
/// existing snapshot destroyed it instead. A script is all-or-nothing, so
/// that cannot happen either.
///
/// The `DEL` stays: a rebuild with FEWER entries has to drop the fields the
/// longer one left behind, or the parse reads a truncated entry list as a
/// longer one. Fields are set one at a time rather than through `unpack`, to
/// keep the argument count off Lua's C-stack limit at a full member set.
const WRITE_SNAPSHOT_LUA: &str = r#"
redis.call('DEL', KEYS[1])
for i = 2, #ARGV, 2 do
    redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
"#;

/// Load a weight snapshot, or `Ok(None)` when the key is missing, has
/// a different schema (including every schema-1 snapshot), or fails to
/// parse. Same warn-not-crash policy as [`read_snapshot`].
pub async fn read_weight_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<StoredWeightSnapshot>, RedisError> {
    let hash: HashMap<String, String> = match conn.hgetall(key).await {
        Ok(h) => h,
        Err(e) if is_wrongtype(&e) => {
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

/// How often a transient Redis failure on a block-found snapshot read is
/// retried before the caller gives up.
///
/// That read stands between a found block and its booking, and no caller
/// has a retry of its own. A connection reset mid-reconnect would
/// otherwise cost the block. A genuinely missing snapshot (`Ok(None)`)
/// is NOT retried — it will not appear.
const READ_RETRIES: u32 = 3;
/// Backoff between those attempts, multiplied by the attempt number.
const READ_BACKOFF: Duration = Duration::from_millis(80);

/// Resolve the settlement inputs a found block's coinbase was built
/// from — the READ twin of [`crate::build::build_and_snapshot`], and
/// the one implementation of it.
///
/// It takes the same `snapshot_key` seam the write side takes, for the
/// same reason: the two engines disagree only on the key scheme
/// (`pplns:snapshot:…` vs `groupsolo:{groupId}:jobsnapshot:…`), and a
/// resolution that does not go through the writer's own seam is a
/// resolution that can drift away from what was written.
///
/// **Call this at the block-found instant, never at apply time.** The
/// key carries a TTL sized for a live job, and both modes' applies can
/// run far past it — the confirmation-gated ones by design. Resolving
/// late loses the inputs outright: per-job snapshot keys are excluded
/// from the Redis→Postgres backup (see `redis_backup::is_per_job_snapshot`),
/// so nothing else holds them, and the block's own coinbase can only
/// say who WAS paid, never what the unpaid were owed.
///
/// `Ok(None)` is a verdict, not a failure: the key is gone or holds a
/// schema this build cannot settle from. The caller maps it to its own
/// terminal error.
pub async fn resolve_snapshot_for_block_found(
    conn: &mut ConnectionManager,
    snapshot_key: impl FnOnce(&[u8; 32]) -> String,
    weights_fingerprint: &[u8; 32],
    scope: &str,
) -> Result<Option<StoredWeightSnapshot>, RedisError> {
    let key = snapshot_key(weights_fingerprint);
    read_weight_snapshot_with_retry(conn, &key, scope).await
}

/// [`read_weight_snapshot`] with the block-found retry policy.
///
/// The twin of `build::write_with_retry`. Prefer
/// [`resolve_snapshot_for_block_found`], which pairs the retry with the
/// key seam; this is exposed for the paths that already hold a key.
pub async fn read_weight_snapshot_with_retry(
    conn: &mut ConnectionManager,
    key: &str,
    scope: &str,
) -> Result<Option<StoredWeightSnapshot>, RedisError> {
    let mut attempt = 0;
    loop {
        match read_weight_snapshot(conn, key).await {
            Ok(found) => return Ok(found),
            Err(err) if attempt < READ_RETRIES => {
                warn!(
                    %err,
                    scope,
                    key,
                    attempt,
                    "weight-snapshot read failed — retrying before giving up on the block"
                );
                attempt += 1;
                tokio::time::sleep(READ_BACKOFF * attempt).await;
            }
            Err(err) => return Err(err),
        }
    }
}

fn parse_weight_hash(h: &HashMap<String, String>) -> Option<StoredWeightSnapshot> {
    // Exact match, so a schema-2 hash (bonus still in `extras`) can
    // never hydrate into the schema-3 settlement math — see
    // `write_weight_snapshot`.
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

/// Returns true if the error is a `WRONGTYPE` from Redis (legacy STRING
/// snapshot on a key that's expected to be a Hash).
fn is_wrongtype(e: &RedisError) -> bool {
    matches!(
        e.kind(),
        redis::ErrorKind::TypeError | redis::ErrorKind::ResponseError
    ) && e.to_string().contains("WRONGTYPE")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::{AddressId, Sats};

    // ---- weight snapshot (schema 2) ----

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
        // Mirror of write_weight_snapshot's field list, so the parse
        // test exercises the same layout the writer produces.
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

    /// A schema-2 hash — written before the bonus became a proportion —
    /// must NOT hydrate, even though every field the schema-3 parser
    /// reads is present and well-formed.
    ///
    /// Its `extras_total` included the finder bonus; schema 3's does
    /// not. Parsing it would measure every claim against a pot short by
    /// the bonus, booking the finder a debt of nearly the whole bonus
    /// and the other members the mirror credit — real satoshis moved
    /// between miners on a correctly-paid block. Returning `None` makes
    /// it a `SnapshotMissing` instead: loud, and it books nothing.
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

    /// The OTHER carrier of a pre-proportion snapshot: the JSON blob in
    /// the confirmation-gated pending-block queue, which survives a
    /// deploy for the whole confirmation window.
    ///
    /// Serde's default would ignore the retired `finder_bonus` field and
    /// hand settlement a snapshot whose `extras_total` is short by the
    /// bonus the coinbase already paid. `deny_unknown_fields` turns that
    /// into a parse error, which the pending store prunes and warns on
    /// instead of mis-booking.
    #[test]
    fn a_pending_blob_carrying_the_retired_bonus_is_refused() {
        let s = weight_snapshot_fixture();
        let mut v = serde_json::to_value(&s).expect("serialize");
        v.as_object_mut().unwrap().insert(
            "finder_bonus".to_string(),
            serde_json::json!(["bc1qold", 50_000]),
        );
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            serde_json::from_str::<StoredWeightSnapshot>(&json).is_err(),
            "a blob still carrying finder_bonus must not deserialize into the \
             proportional model — its bonus would silently leave `extras_total`"
        );
        // The same blob without the retired field is still perfectly good.
        let clean = serde_json::to_string(&s).unwrap();
        assert_eq!(
            serde_json::from_str::<StoredWeightSnapshot>(&clean).expect("round-trips"),
            s
        );
    }

    /// `schema-1 hashes never hydrate through the weight parser`
    #[test]
    fn parse_weight_hash_rejects_schema_1() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "312500000".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "0".to_string());
        assert!(parse_weight_hash(&h).is_none());
    }

    /// `truncated entry list refuses to hydrate`
    #[test]
    fn parse_weight_hash_truncated_entries_returns_none() {
        let s = weight_snapshot_fixture();
        let mut h = weight_hash_of(&s);
        h.remove("e1_wire");
        assert!(parse_weight_hash(&h).is_none());
    }

    /// `from_distribution lowers the built distribution 1:1`
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
            min_payout_sats: Some(Sats(5_000)),
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

    /// Settlement measures every claim against `pot − X`, and it
    /// re-derives `X` here instead of reading it off a stored field.
    /// If that re-derivation ever disagreed with the build, the
    /// coinbase and the ledger would be splitting two different pots
    /// and every block would mint liabilities.
    #[test]
    fn extras_total_reproduces_the_build() {
        use std::collections::HashMap as StdMap;
        let a1 = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let a2 = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
        let fee = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let shares = StdMap::from([(a1.clone(), 3.0), (a2.clone(), 1.0)]);
        // The bonus is a proportion now — plain score weight, nothing to
        // project — so what still has to reproduce is the LEDGER side:
        // credits, debts, and a promise larger than the block.
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
                min_payout_sats: Some(Sats(5_000)),
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
