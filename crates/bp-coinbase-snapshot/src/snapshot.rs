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

use std::collections::{HashMap, HashSet};

use bp_common::{AddressId, Sats};
use bp_pplns::CoinbaseDistributionEntry;
use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

/// Persistent form of a per-block coinbase distribution + matching
/// ledger deltas.
///
/// `balance_after` is signed: PPLNS uses positive = credit, negative =
/// debit, zero = settle; Group-Solo only ever emits non-negative values
/// (its `pendingSats` is `≥ 0`) but keeps the field signed for wire
/// compatibility. Applied as an absolute UPDATE in the block-found TX.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredSnapshot {
    /// Coinbase output list, in coinbase-order (matters for byte-equal
    /// reconstruction).
    pub distribution: Vec<CoinbaseDistributionEntry>,
    /// The coinbase reward this snapshot was built for. A mismatch at
    /// `on_block_found` time triggers a CRITICAL fallback recompute.
    pub block_reward_sats: u64,
    /// Every address that was in shares OR balances at build time, so
    /// `on_block_found` can distinguish late arrivers from sub-dust /
    /// trimmed miners.
    pub considered_addresses: Vec<String>,
    /// Absolute new balance per address that changed.
    pub balance_after: Vec<(String, i64)>,
    /// The balance each of those addresses had when this distribution was
    /// computed. Together with `balance_after` it gives the DELTA the block
    /// applies, which is what makes the snapshot safe to book against a
    /// ledger that moved since — an absolute write would silently undo
    /// whatever moved it. Empty for snapshots written before this field
    /// existed (and by payout engines that do not use the delta path);
    /// readers fall back to the absolute value then.
    #[serde(default)]
    pub balance_before: Vec<(String, i64)>,
}

impl StoredSnapshot {
    /// Build a snapshot from the output of
    /// `bp_pplns::build_coinbase_distribution` — the
    /// `AddressId`/`Sats` → `String`/`i64` lowering both payout engines
    /// do identically before persisting. `payouts` is borrowed (the
    /// caller still moves it into its in-memory result afterwards).
    pub fn from_math(
        payouts: &[CoinbaseDistributionEntry],
        block_reward_sats: u64,
        considered_addresses: &HashSet<AddressId>,
        balance_after: &HashMap<AddressId, Sats>,
    ) -> Self {
        Self {
            distribution: payouts.to_vec(),
            block_reward_sats,
            considered_addresses: considered_addresses
                .iter()
                .map(|a| a.as_str().to_string())
                .collect(),
            balance_after: balance_after
                .iter()
                .map(|(a, s)| (a.as_str().to_string(), s.0))
                .collect(),
            balance_before: Vec::new(),
        }
    }

    /// [`Self::from_math`] plus the ledger state the distribution was
    /// computed against, recorded for exactly the addresses `balance_after`
    /// changes. Lets the apply write a delta instead of an absolute, so a
    /// block can still be booked correctly after another one moved the
    /// ledger.
    pub fn from_math_with_before(
        payouts: &[CoinbaseDistributionEntry],
        block_reward_sats: u64,
        considered_addresses: &HashSet<AddressId>,
        balance_after: &HashMap<AddressId, Sats>,
        ledger_at_build: &HashMap<AddressId, Sats>,
    ) -> Self {
        let mut snapshot = Self::from_math(
            payouts,
            block_reward_sats,
            considered_addresses,
            balance_after,
        );
        snapshot.balance_before = balance_after
            .keys()
            .map(|a| {
                let before = ledger_at_build.get(a).map(|s| s.0).unwrap_or(0);
                (a.as_str().to_string(), before)
            })
            .collect();
        snapshot
    }
}

/// Hydrated form returned by [`read_snapshot`]: `Set` / `HashMap` for
/// ergonomic call-site use; `distribution` stays a `Vec` because
/// coinbase-output order matters.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSnapshot {
    pub distribution: Vec<CoinbaseDistributionEntry>,
    pub block_reward_sats: u64,
    pub considered_addresses: HashSet<String>,
    pub balance_after: HashMap<String, i64>,
    /// See [`StoredSnapshot::balance_before`]. Empty when the snapshot
    /// predates the field — the caller then has only the absolute value.
    pub balance_before: HashMap<String, i64>,
}

impl From<StoredSnapshot> for ParsedSnapshot {
    /// Hydrate the wire form (Vec-backed) into the call-site-ergonomic form
    /// (`HashSet`/`HashMap`). Used when the snapshot arrives in the
    /// block-found event instead of from a Redis read — same shape
    /// `read_snapshot` produces, so `on_block_found` is agnostic to the
    /// source.
    fn from(s: StoredSnapshot) -> Self {
        Self {
            distribution: s.distribution,
            block_reward_sats: s.block_reward_sats,
            considered_addresses: s.considered_addresses.into_iter().collect(),
            balance_after: s.balance_after.into_iter().collect(),
            balance_before: s.balance_before.into_iter().collect(),
        }
    }
}

impl From<ParsedSnapshot> for StoredSnapshot {
    /// Back to the wire form, so a snapshot read from Redis can be carried in
    /// a block-found event. `distribution` keeps its coinbase order; the two
    /// collections are semantically a set and a map, so their order carries no
    /// meaning to lose.
    fn from(s: ParsedSnapshot) -> Self {
        Self {
            distribution: s.distribution,
            block_reward_sats: s.block_reward_sats,
            considered_addresses: s.considered_addresses.into_iter().collect(),
            balance_after: s.balance_after.into_iter().collect(),
            balance_before: s.balance_before.into_iter().collect(),
        }
    }
}

/// Persist a snapshot under `key` with `ttl_seconds`.
///
/// `DEL` before `HSET` guarantees the key has Hash type even if a
/// legacy STRING-typed snapshot survives from an earlier deploy
/// (otherwise the `HSET` would `WRONGTYPE`). Then `EXPIRE` to bound
/// staleness.
///
/// Three commands in sequence (not pipelined): the snapshot is written
/// at most once per block-template build, single-digit Hz at peak. The
/// extra RTTs are not worth a `MULTI/EXEC`.
pub async fn write_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
    snapshot: &StoredSnapshot,
    ttl_seconds: u32,
) -> Result<(), RedisError> {
    // Build the field list. `HSET` accepts an array of (field, value)
    // pairs; we slot the scalars + arrays in a stable order so a
    // Redis-CLI dump shows fields in a consistent order.
    let mut fields: Vec<(String, String)> =
        Vec::with_capacity(4 + snapshot.distribution.len() * 3 + snapshot.balance_after.len() * 2);

    fields.push((
        "blockRewardSats".to_string(),
        snapshot.block_reward_sats.to_string(),
    ));
    fields.push((
        "consideredAddresses".to_string(),
        snapshot.considered_addresses.join("|"),
    ));
    fields.push((
        "distribution_count".to_string(),
        snapshot.distribution.len().to_string(),
    ));
    fields.push((
        "balanceAfter_count".to_string(),
        snapshot.balance_after.len().to_string(),
    ));
    fields.push((
        "balanceBefore_count".to_string(),
        snapshot.balance_before.len().to_string(),
    ));

    for (i, entry) in snapshot.distribution.iter().enumerate() {
        fields.push((format!("d{i}_addr"), entry.address.as_str().to_string()));
        fields.push((format!("d{i}_pct"), entry.percent.to_string()));
        fields.push((format!("d{i}_sats"), entry.sats.0.to_string()));
    }

    for (i, (addr, sats)) in snapshot.balance_after.iter().enumerate() {
        fields.push((format!("b{i}_addr"), addr.clone()));
        fields.push((format!("b{i}_sats"), sats.to_string()));
    }

    for (i, (addr, sats)) in snapshot.balance_before.iter().enumerate() {
        fields.push((format!("bb{i}_addr"), addr.clone()));
        fields.push((format!("bb{i}_sats"), sats.to_string()));
    }

    let _: () = conn.del(key).await?;
    let _: () = conn.hset_multiple(key, &fields).await?;
    let _: () = conn.expire(key, ttl_seconds as i64).await?;
    Ok(())
}

/// Load + hydrate a snapshot, or return `Ok(None)` if the key is
/// missing or the stored payload is unparseable.
///
/// Unparseable values are logged via `tracing::warn!` rather than
/// returned as errors — a partially-corrupt snapshot is a CRITICAL
/// operational event but not one the engine should crash for; the
/// caller falls back to a recompute.
pub async fn read_snapshot(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<ParsedSnapshot>, RedisError> {
    let hash: HashMap<String, String> = match conn.hgetall(key).await {
        Ok(h) => h,
        Err(e) if is_wrongtype(&e) => {
            // Legacy STRING-typed snapshot survives from pre-Hash
            // rollout, or a future deploy accidentally wrote the wrong
            // shape. Surface the WRONGTYPE as "missing" with a warning
            // rather than crashing.
            warn!(
                key,
                error = %e,
                "coinbase snapshot: legacy or wrong-typed key, treating as missing"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if hash.is_empty() {
        return Ok(None);
    }
    match parse_hash(&hash) {
        Some(parsed) => Ok(Some(parsed)),
        None => {
            warn!(
                key,
                "coinbase snapshot: failed to parse fields, treating as missing"
            );
            Ok(None)
        }
    }
}

/// Delete a snapshot key (called after `on_block_found` consumed it).
pub async fn delete_snapshot(conn: &mut ConnectionManager, key: &str) -> Result<(), RedisError> {
    let _: () = conn.del(key).await?;
    Ok(())
}

fn parse_hash(h: &HashMap<String, String>) -> Option<ParsedSnapshot> {
    let block_reward_sats: u64 = h.get("blockRewardSats")?.parse().ok()?;
    let dist_count: usize = h.get("distribution_count")?.parse().ok()?;
    let bal_count: usize = h.get("balanceAfter_count")?.parse().ok()?;

    let mut distribution = Vec::with_capacity(dist_count);
    for i in 0..dist_count {
        let addr_str = h.get(&format!("d{i}_addr"))?;
        let percent: f64 = h.get(&format!("d{i}_pct"))?.parse().ok()?;
        let sats: i64 = h.get(&format!("d{i}_sats"))?.parse().ok()?;
        let address = AddressId::new(addr_str.clone()).ok()?;
        distribution.push(CoinbaseDistributionEntry {
            address,
            percent,
            sats: Sats(sats),
        });
    }

    let mut balance_after = HashMap::with_capacity(bal_count);
    for i in 0..bal_count {
        let addr = h.get(&format!("b{i}_addr"))?.clone();
        let sats: i64 = h.get(&format!("b{i}_sats"))?.parse().ok()?;
        balance_after.insert(addr, sats);
    }

    // Absent on snapshots written before the field existed — an empty map
    // means "no before state recorded", and the caller falls back to the
    // absolute value rather than treating 0 as the prior balance.
    let before_count: usize = h
        .get("balanceBefore_count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut balance_before = HashMap::with_capacity(before_count);
    for i in 0..before_count {
        let addr = h.get(&format!("bb{i}_addr"))?.clone();
        let sats: i64 = h.get(&format!("bb{i}_sats"))?.parse().ok()?;
        balance_before.insert(addr, sats);
    }

    let considered_addresses = h
        .get("consideredAddresses")
        .map(|s| {
            s.split('|')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string())
                .collect()
        })
        .unwrap_or_default();

    Some(ParsedSnapshot {
        distribution,
        block_reward_sats,
        considered_addresses,
        balance_after,
        balance_before,
    })
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

    let _: () = conn.del(key).await?;
    let _: () = conn.hset_multiple(key, &fields).await?;
    let _: () = conn.expire(key, ttl_seconds as i64).await?;
    Ok(())
}

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

    #[test]
    fn parse_hash_roundtrip() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "312500000".to_string());
        h.insert("distribution_count".to_string(), "2".to_string());
        h.insert("balanceAfter_count".to_string(), "1".to_string());
        h.insert(
            "consideredAddresses".to_string(),
            "bc1qfoo|bc1qbar|bc1qbaz".to_string(),
        );
        h.insert(
            "d0_addr".to_string(),
            "bc1qfoo0000000000000000000000000".to_string(),
        );
        h.insert("d0_pct".to_string(), "50.5".to_string());
        h.insert("d0_sats".to_string(), "156250000".to_string());
        h.insert(
            "d1_addr".to_string(),
            "bc1qbar0000000000000000000000000".to_string(),
        );
        h.insert("d1_pct".to_string(), "49.5".to_string());
        h.insert("d1_sats".to_string(), "156250000".to_string());
        h.insert(
            "b0_addr".to_string(),
            "bc1qbar0000000000000000000000000".to_string(),
        );
        h.insert("b0_sats".to_string(), "-1234".to_string());

        let parsed = parse_hash(&h).expect("parse ok");
        assert_eq!(parsed.block_reward_sats, 312_500_000);
        assert_eq!(parsed.distribution.len(), 2);
        assert_eq!(parsed.distribution[0].sats.0, 156_250_000);
        assert!((parsed.distribution[1].percent - 49.5).abs() < 1e-9);
        assert_eq!(parsed.balance_after.len(), 1);
        assert_eq!(
            parsed.balance_after["bc1qbar0000000000000000000000000"],
            -1234
        );
        assert_eq!(parsed.considered_addresses.len(), 3);
    }

    #[test]
    fn parse_hash_missing_scalar_returns_none() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "1".to_string());
        // distribution_count missing — should refuse to hydrate
        assert!(parse_hash(&h).is_none());
    }

    #[test]
    fn parse_hash_malformed_int_returns_none() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "not-a-number".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "0".to_string());
        assert!(parse_hash(&h).is_none());
    }

    #[test]
    fn parse_hash_empty_considered_addresses() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "100".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "0".to_string());
        h.insert("consideredAddresses".to_string(), String::new());
        let parsed = parse_hash(&h).unwrap();
        assert!(parsed.considered_addresses.is_empty());
    }

    #[test]
    fn from_math_lowers_addresses_and_sats_to_wire_form() {
        let a = AddressId::new("bc1qfoo0000000000000000000000000").unwrap();
        let b = AddressId::new("bc1qbar0000000000000000000000000").unwrap();
        let payouts = vec![CoinbaseDistributionEntry {
            address: a.clone(),
            percent: 100.0,
            sats: Sats(312_500_000),
        }];
        let considered: HashSet<AddressId> = [a.clone(), b.clone()].into_iter().collect();
        let mut balances = HashMap::new();
        balances.insert(b.clone(), Sats(-5_000));

        let snap = StoredSnapshot::from_math(&payouts, 312_500_000, &considered, &balances);
        assert_eq!(snap.block_reward_sats, 312_500_000);
        assert_eq!(snap.distribution.len(), 1);
        assert_eq!(snap.distribution[0].sats.0, 312_500_000);
        assert_eq!(snap.considered_addresses.len(), 2);
        assert_eq!(snap.balance_after.len(), 1);
        assert_eq!(snap.balance_after[0].0, "bc1qbar0000000000000000000000000");
        assert_eq!(snap.balance_after[0].1, -5_000);
    }

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

    /// `schema-2 hashes never hydrate through the schema-1 parser`
    #[test]
    fn parse_hash_rejects_schema_2() {
        let s = weight_snapshot_fixture();
        assert!(parse_hash(&weight_hash_of(&s)).is_none());
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

    #[test]
    fn parse_hash_signed_balance() {
        let mut h = HashMap::new();
        h.insert("blockRewardSats".to_string(), "100".to_string());
        h.insert("distribution_count".to_string(), "0".to_string());
        h.insert("balanceAfter_count".to_string(), "2".to_string());
        h.insert(
            "b0_addr".to_string(),
            "bc1qcredit0000000000000000000000".to_string(),
        );
        h.insert("b0_sats".to_string(), "5000".to_string());
        h.insert(
            "b1_addr".to_string(),
            "bc1qdebit00000000000000000000000".to_string(),
        );
        h.insert("b1_sats".to_string(), "-5000".to_string());
        let parsed = parse_hash(&h).unwrap();
        let credit = parsed.balance_after["bc1qcredit0000000000000000000000"];
        let debit = parsed.balance_after["bc1qdebit00000000000000000000000"];
        // Ledger symmetry: signed pair sums to zero.
        assert_eq!(credit + debit, 0);
    }
}
