// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Chain-observed reconciliation: did every block the pool actually mined
//! reach the ledger?
//!
//! Every other block-found path starts from something the pool was *told* —
//! a share it accepted, a solution a JD-client pushed. Each of those can be
//! missed (a snapshot that expired, a Redis blip, an event dropped on a
//! deploy) or, on the JDP path, asserted by a peer that never did the work.
//! This one starts from the chain instead: the pool runs bitcoin-core and can
//! read the coinbase of every block that actually landed. A block whose
//! coinbase pays the pool is the pool's, whatever the pool's own bookkeeping
//! thinks — and if there is no record of it, that is a payout somebody is owed
//! and nobody booked.
//!
//! **Reports, never books.** It is a check on the booking paths, so it must
//! not become one: the booking needs the distribution behind a coinbase, which
//! the chain does not carry. What it produces is the operator's list of blocks
//! to reprocess — and, when it stays empty, evidence that the paths it watches
//! are working.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bp_bitcoin::BitcoinRpc;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

/// Default cadence. Slow on purpose: a missed booking is not more urgent an
/// hour later, and each pass costs two RPCs per unseen block.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(3600);

/// How many blocks every pass re-walks. A height whose block a reorg replaced
/// needs a second look, and six is past the depth at which that stops
/// happening in practice.
const REORG_OVERLAP: u64 = 6;

/// How far back the first pass after a restart looks. ~1 day of blocks — far
/// enough to cover a deploy or an outage, short enough to stay cheap.
pub(crate) const DEFAULT_LOOKBACK: u64 = 144;

/// One block the chain says is the pool's, that the pool's books do not
/// account for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnbookedBlock {
    pub height: u64,
    pub hash: String,
    /// Coinbase outputs paying a pool address, as `(address, sats)`. This is
    /// what the block actually paid — the only surviving record of it once a
    /// distribution snapshot has expired.
    pub pool_outputs: Vec<(String, u64)>,
    pub gap: Gap,
}

/// Which of the two ways a block goes unaccounted for.
///
/// They are different failures with different fixes, so the report names
/// which one it is rather than lumping them together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gap {
    /// No `blocks_entity` row: the pool never registered the block at all. A
    /// JD-client block nothing told the pool about, or a found-block fan-out
    /// that never ran.
    NeverRegistered,
    /// Registered but no payout rows: the pool saw the block and the ledger
    /// apply did not happen — an unresolvable distribution, a dropped stream
    /// event. This is the one `blocks_entity` alone cannot see, because the
    /// front writes that row before any ledger applies.
    RegisteredButUnbooked,
}

/// The addresses whose presence in a coinbase marks a block as the pool's.
///
/// The pool fee output is the marker because it is in every coinbase the pool
/// builds and in every payout set it hands a JD-client, and no other party
/// pays it. A zero-fee deployment emits no such output and cannot be
/// recognised this way — [`PoolMarkers::new`] refuses to build one rather than
/// running a check that silently finds nothing.
#[derive(Clone, Debug)]
pub(crate) struct PoolMarkers {
    addresses: HashSet<String>,
}

impl PoolMarkers {
    /// `None` when no marker address is configured — the caller logs and skips
    /// the task.
    pub(crate) fn new(addresses: impl IntoIterator<Item = String>) -> Option<Self> {
        let addresses: HashSet<String> = addresses
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        if addresses.is_empty() {
            return None;
        }
        Some(Self { addresses })
    }

    fn matches(&self, address: &str) -> bool {
        self.addresses.contains(address)
    }
}

/// Does an address's payout mode keep a ledger the pool has to book into?
///
/// Solo does not — it pays in the coinbase and records nothing, so a Solo
/// block with no payout row is normal, not a miss. Without this distinction
/// the check would flag every Solo block and be ignored within a week.
pub(crate) trait ModeLedger: Send + Sync {
    fn keeps_a_ledger(&self, miner_address: &str) -> bool;
}

impl ModeLedger for crate::engines::BlitzpoolModeGate {
    fn keeps_a_ledger(&self, miner_address: &str) -> bool {
        self.keeps_a_payout_ledger(miner_address)
    }
}

/// Pick out the coinbase outputs that pay the pool.
///
/// Empty ⇒ this block is not the pool's. Outputs with no address (the witness
/// commitment's OP_RETURN) can never match and are skipped.
pub(crate) fn pool_outputs_of_coinbase(
    coinbase: &bp_bitcoin::DecodedTransaction,
    markers: &PoolMarkers,
) -> Vec<(String, u64)> {
    coinbase
        .vout
        .iter()
        .filter_map(|out| {
            let address = out.script_pub_key.address.as_deref()?;
            if !markers.matches(address) {
                return None;
            }
            Some((address.to_string(), btc_to_sats(out.value)))
        })
        .collect()
}

/// Value-bearing coinbase outputs paying somebody who is neither the pool
/// nor the miner the block was registered under.
///
/// This is what makes a missing booking visible on a mode that keeps no
/// ledger. The Solo exemption below asks the miner's ADDRESS whether a
/// ledger row was due — and the address is exactly the wrong witness: a
/// job-declaring client whose address is Solo-gated can mine a coinbase
/// that pays a SHARED distribution (it references the pool-wide payout
/// list), and then those miners are owed a ledger entry while the finder's
/// mode says none was due. The coinbase is the honest witness, and this
/// check is the only place that holds it.
///
/// A genuine Solo coinbase pays the miner plus, at most, a fee marker — so
/// this comes out empty and the exemption still stands.
pub(crate) fn third_party_outputs_of_coinbase(
    coinbase: &bp_bitcoin::DecodedTransaction,
    markers: &PoolMarkers,
    registered_miner: &str,
) -> Vec<(String, u64)> {
    coinbase
        .vout
        .iter()
        .filter_map(|out| {
            let address = out.script_pub_key.address.as_deref()?;
            if markers.matches(address) || address == registered_miner {
                return None;
            }
            let sats = btc_to_sats(out.value);
            // A 0-value output pays nobody — §4 permits them after the
            // distribution block (the witness commitment is one).
            (sats > 0).then(|| (address.to_string(), sats))
        })
        .collect()
}

/// Core reports output values in BTC. Round rather than truncate: the value is
/// a decimal that cannot always be represented exactly, so `x.99999999` is a
/// float artefact of a whole number of sats, not a value below it.
fn btc_to_sats(btc: f64) -> u64 {
    (btc * 100_000_000.0).round().max(0.0) as u64
}

/// Spawn the periodic reconciliation. Runs on the payout process, which is
/// where the ledger it checks is written.
pub(crate) fn spawn_reconcile_task(
    rpc: BitcoinRpc,
    pool: PgPool,
    markers: PoolMarkers,
    modes: Arc<dyn ModeLedger>,
    interval: Duration,
    lookback: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Highest height already checked. Starts unset so the first pass
        // covers the lookback window; after a restart that means re-checking
        // ground already covered, which is harmless because the pass only
        // reports.
        let mut checked_through: Option<u64> = None;
        info!(
            interval_secs = interval.as_secs(),
            lookback, "block-reconcile: task live (chain → ledger check)"
        );
        loop {
            tick.tick().await;
            match run_once(
                &rpc,
                &pool,
                &markers,
                modes.as_ref(),
                checked_through,
                lookback,
            )
            .await
            {
                Ok(pass) => {
                    checked_through = Some(pass.checked_through);
                    if pass.unbooked.is_empty() {
                        debug!(
                            from = pass.from_height,
                            to = pass.checked_through,
                            "block-reconcile: every pool block in range is booked"
                        );
                    }
                }
                Err(err) => warn!(%err, "block-reconcile: pass failed; retry next tick"),
            }
        }
    })
}

pub(crate) struct ReconcilePass {
    pub from_height: u64,
    pub checked_through: u64,
    pub unbooked: Vec<UnbookedBlock>,
}

/// Walk the unchecked range, and report every pool block with no ledger
/// record. Errors on a single block are logged and skipped — one unreadable
/// block must not stop the rest of the range from being checked.
pub(crate) async fn run_once(
    rpc: &BitcoinRpc,
    pool: &PgPool,
    markers: &PoolMarkers,
    modes: &dyn ModeLedger,
    checked_through: Option<u64>,
    lookback: u64,
) -> Result<ReconcilePass, bp_bitcoin::RpcError> {
    let tip = rpc.get_block_count().await?;
    let from_height = scan_start(checked_through, tip, lookback);
    let mut unbooked = Vec::new();
    if from_height > tip {
        return Ok(ReconcilePass {
            from_height,
            checked_through: tip,
            unbooked,
        });
    }

    let mut first_error: Option<u64> = None;
    for height in from_height..=tip {
        match inspect_block(rpc, pool, markers, modes, height).await {
            Ok(Some(block)) => {
                match block.gap {
                    Gap::NeverRegistered => error!(
                        height = block.height,
                        hash = %block.hash,
                        outputs = ?block.pool_outputs,
                        "block-reconcile: this block's coinbase pays the pool and the pool has \
                         no record of it at all — the miners it paid are owed their ledger entry"
                    ),
                    Gap::RegisteredButUnbooked => error!(
                        height = block.height,
                        hash = %block.hash,
                        outputs = ?block.pool_outputs,
                        "block-reconcile: the pool registered this block but no payout was ever \
                         booked for it — the miners it paid are owed their ledger entry"
                    ),
                }
                unbooked.push(block);
            }
            Ok(None) => {}
            Err(err) => {
                warn!(%err, height, "block-reconcile: could not check block; will retry");
                first_error.get_or_insert(height);
            }
        }
    }
    Ok(ReconcilePass {
        from_height,
        checked_through: next_watermark(tip, first_error),
        unbooked,
    })
}

/// Where the next pass starts.
///
/// Always re-walks the last [`REORG_OVERLAP`] blocks: a height checked while
/// one block sat there, then replaced by a reorg, would otherwise never be
/// looked at again — and the replacement is the block that actually pays.
fn scan_start(checked_through: Option<u64>, tip: u64, lookback: u64) -> u64 {
    match checked_through {
        Some(h) => h.saturating_add(1).min(tip.saturating_sub(REORG_OVERLAP)),
        None => tip.saturating_sub(lookback),
    }
}

/// How far this pass may claim to have checked.
///
/// Stops below the first height it could not read. A transient RPC failure
/// must cost a retry, not the block: advancing past it would leave a height
/// nothing ever looks at again, which is the failure this whole check exists
/// to catch.
fn next_watermark(tip: u64, first_error: Option<u64>) -> u64 {
    match first_error {
        Some(h) => h.saturating_sub(1),
        None => tip,
    }
}

/// `Some` when the block at `height` pays the pool and the ledger has no
/// record of it.
async fn inspect_block(
    rpc: &BitcoinRpc,
    pool: &PgPool,
    markers: &PoolMarkers,
    modes: &dyn ModeLedger,
    height: u64,
) -> Result<Option<UnbookedBlock>, bp_bitcoin::RpcError> {
    let hash = rpc.get_block_hash(height).await?;
    let block = rpc.get_block_txids(&hash).await?;
    let Some(coinbase_txid) = block.tx.first() else {
        return Ok(None);
    };
    let coinbase = rpc
        .get_raw_transaction_in_block(coinbase_txid, &hash)
        .await?;
    let pool_outputs = pool_outputs_of_coinbase(&coinbase, markers);
    if pool_outputs.is_empty() {
        return Ok(None);
    }
    // Two questions, not one. `blocks_entity` says the pool registered the
    // block; the payout tables say miners were credited for it. The front
    // writes the first the moment a block is found, before any ledger runs,
    // so only the second is evidence of a booking.
    let registered_miner = match bp_db::found_block_miner_at_height(pool, height as i64).await {
        Ok(v) => v,
        Err(err) => {
            // A DB error is not evidence of a gap — reporting on one would
            // send an operator to reprocess something already booked.
            warn!(%err, height, "block-reconcile: blocks_entity lookup failed; skipping");
            return Ok(None);
        }
    };
    let Some(miner) = registered_miner else {
        return Ok(Some(UnbookedBlock {
            height,
            hash,
            pool_outputs,
            gap: Gap::NeverRegistered,
        }));
    };
    // Registered. Whether a missing payout row is a fault depends on the
    // mode: Solo pays in the coinbase and keeps no ledger, so it has none by
    // design. Only a mode that books can be missing a booking.
    //
    // But the mode is read off the miner's ADDRESS, and that is not the same
    // question as "was anybody owed a ledger entry for this block". A
    // job-declaring client can reference a SHARED payout distribution while
    // its own address is Solo-gated; its coinbase then pays those miners and
    // the exemption would wave the block through. So the exemption needs
    // BOTH: the mode keeps no ledger AND the coinbase paid nobody but the
    // finder and the pool. Either one alone is a blind spot — and this is
    // the widening direction, so no block that was checked before stops
    // being checked (a one-miner PPLNS block still is, on the mode).
    let third_parties = third_party_outputs_of_coinbase(&coinbase, markers, &miner);
    if !modes.keeps_a_ledger(&miner) && third_parties.is_empty() {
        return Ok(None);
    }
    match bp_db::payout_recorded_at_height(pool, height as i32).await {
        Ok(true) => Ok(None),
        Ok(false) => Ok(Some(UnbookedBlock {
            height,
            hash,
            pool_outputs,
            gap: Gap::RegisteredButUnbooked,
        })),
        Err(err) => {
            warn!(%err, height, "block-reconcile: payout lookup failed; skipping");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_bitcoin::{DecodedTransaction, ScriptPubKey, TransactionOutput};

    fn markers() -> PoolMarkers {
        PoolMarkers::new(["bc1qpoolfee".to_string()]).expect("one address is enough")
    }

    fn out(address: Option<&str>, btc: f64) -> TransactionOutput {
        TransactionOutput {
            value: btc,
            script_pub_key: ScriptPubKey {
                address: address.map(str::to_string),
            },
        }
    }

    fn coinbase(outs: Vec<TransactionOutput>) -> DecodedTransaction {
        DecodedTransaction {
            txid: "ab".repeat(32),
            vout: outs,
        }
    }

    /// MONEY: the Solo exemption asks the miner's ADDRESS whether a ledger
    /// row was due, and that is the wrong witness.
    ///
    /// A job-declaring client whose address is Solo-gated can reference the
    /// pool-wide payout distribution and mine a coinbase that pays THOSE
    /// miners. They are owed a ledger entry; the finder's mode says none was
    /// due, so the exemption waved the block through and this check — the one
    /// component that holds the coinbase — stayed silent. The coinbase is the
    /// honest witness: it names who was actually paid.
    #[test]
    fn a_coinbase_paying_third_parties_is_not_a_solo_payout() {
        const MINER: &str = "bc1qsolominer";
        // A genuine Solo coinbase: the fee marker plus the finder, nobody
        // else. Nothing for a ledger to record, so the exemption stands.
        let solo = coinbase(vec![
            out(Some("bc1qpoolfee"), 0.0000_0001),
            out(Some(MINER), 3.125),
        ]);
        assert!(
            third_party_outputs_of_coinbase(&solo, &markers(), MINER).is_empty(),
            "a real Solo coinbase must stay exempt or every Solo block false-alarms"
        );

        // The Befund-2 shape: the same Solo-gated finder, but the coinbase
        // pays a shared distribution's miners.
        let shared = coinbase(vec![
            out(Some("bc1qpoolfee"), 0.046875),
            out(Some("bc1qpplnsminer1"), 2.0),
            out(Some("bc1qpplnsminer2"), 1.07),
            // §4 permits 0-value outputs after the distribution block; they
            // pay nobody and must not count as a third party.
            out(None, 0.0),
            out(Some("bc1qopreturnish"), 0.0),
        ]);
        let third = third_party_outputs_of_coinbase(&shared, &markers(), MINER);
        assert_eq!(
            third.len(),
            2,
            "both paid strangers must be named, and neither 0-value output: {third:?}"
        );
        assert_eq!(third[0], ("bc1qpplnsminer1".to_string(), 200_000_000));
        assert_eq!(third[1], ("bc1qpplnsminer2".to_string(), 107_000_000));
    }

    /// The finder itself is never a third party, whatever else the coinbase
    /// pays — otherwise every ordinary Group-Solo block where the finder is
    /// also a member would read as paying strangers.
    #[test]
    fn the_registered_miner_is_never_a_third_party() {
        const MINER: &str = "bc1qfinder";
        let cb = coinbase(vec![
            out(Some("bc1qpoolfee"), 0.046875),
            out(Some(MINER), 2.0),
        ]);
        assert!(third_party_outputs_of_coinbase(&cb, &markers(), MINER).is_empty());
    }

    /// A zero-fee deployment has no marker output, so the check cannot
    /// recognise its blocks. Refusing to construct is what makes that visible
    /// instead of a task that quietly reports nothing forever.
    /// A height that could not be read must be walked again, not skipped for
    /// good — the whole point of the check is that nothing goes unlooked-at.
    #[test]
    fn a_height_that_errored_is_not_marked_checked() {
        assert_eq!(
            next_watermark(120, None),
            120,
            "a clean pass covers the tip"
        );
        assert_eq!(
            next_watermark(120, Some(115)),
            114,
            "the watermark must stop below the first unreadable height"
        );
        // Two errors: the earliest one bounds the pass.
        assert_eq!(next_watermark(120, Some(0)), 0);
    }

    /// A reorg replaces the block at a height already checked. Without the
    /// overlap the replacement — the block that actually pays — is never seen.
    #[test]
    fn every_pass_re_walks_the_reorg_window() {
        // Caught up: still steps back over the last few blocks.
        assert_eq!(scan_start(Some(120), 120, DEFAULT_LOOKBACK), 114);
        // Behind: resumes where it stopped, no jumping ahead.
        assert_eq!(scan_start(Some(50), 120, DEFAULT_LOOKBACK), 51);
        // First pass after a restart: the lookback window.
        assert_eq!(scan_start(None, 500, DEFAULT_LOOKBACK), 356);
        // A chain shorter than the window starts at genesis rather than
        // underflowing.
        assert_eq!(scan_start(Some(3), 3, DEFAULT_LOOKBACK), 0);
        assert_eq!(scan_start(None, 10, DEFAULT_LOOKBACK), 0);
    }

    #[test]
    fn pool_markers_refuses_an_empty_configuration() {
        assert!(PoolMarkers::new(Vec::<String>::new()).is_none());
        assert!(PoolMarkers::new(["".to_string(), "   ".to_string()]).is_none());
    }

    #[test]
    fn a_coinbase_paying_the_fee_address_is_the_pools() {
        let cb = coinbase(vec![
            out(Some("bc1qsomeoneelse"), 3.0),
            out(Some("bc1qpoolfee"), 0.125),
        ]);
        assert_eq!(
            pool_outputs_of_coinbase(&cb, &markers()),
            vec![("bc1qpoolfee".to_string(), 12_500_000)]
        );
    }

    #[test]
    fn another_pools_coinbase_is_not_ours() {
        let cb = coinbase(vec![out(Some("bc1qsomeoneelse"), 3.125)]);
        assert!(pool_outputs_of_coinbase(&cb, &markers()).is_empty());
    }

    /// The witness commitment is an OP_RETURN with no address. It must not
    /// panic the scan or be mistaken for a payout.
    #[test]
    fn outputs_without_an_address_are_skipped() {
        let cb = coinbase(vec![out(None, 0.0), out(Some("bc1qpoolfee"), 0.01)]);
        assert_eq!(
            pool_outputs_of_coinbase(&cb, &markers()),
            vec![("bc1qpoolfee".to_string(), 1_000_000)]
        );
    }

    /// Core reports BTC as a decimal float; a whole number of sats can arrive
    /// as `x.99999999`. Truncating would under-report by a satoshi and make
    /// the reported amount disagree with the chain.
    #[test]
    fn btc_values_convert_without_losing_a_satoshi() {
        assert_eq!(btc_to_sats(3.125), 312_500_000);
        assert_eq!(btc_to_sats(0.00000001), 1);
        assert_eq!(btc_to_sats(0.0), 0);
        // 21 M BTC — the largest value that can appear.
        assert_eq!(btc_to_sats(21_000_000.0), 2_100_000_000_000_000);
    }
}

/// Regtest: the RPC shapes this module decodes (`getblock` verbosity 1,
/// `getrawtransaction` with a block hash) can only be verified against a real
/// bitcoin-core. Mine to a known address and check the pass sees the block as
/// the pool's and unbooked; a `blocks_entity` row then makes it stop reporting.
#[cfg(test)]
mod regtest {
    use super::*;
    use bp_regtest_harness::RegtestNode;
    use sqlx::postgres::PgPoolOptions;

    const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

    async fn pg_or_skip() -> Option<PgPool> {
        let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
        match tokio::time::timeout(
            Duration::from_secs(2),
            PgPoolOptions::new().max_connections(2).connect(&url),
        )
        .await
        {
            Ok(Ok(p)) => Some(p),
            _ => {
                eprintln!("pg unreachable — skipping block-reconcile regtest");
                None
            }
        }
    }

    /// Remove any rows another suite (or an aborted run) left at this height.
    /// The test database is shared and regtest heights are small, so the test
    /// establishes its own precondition rather than assuming a clean slate.
    async fn clear_height(pg: &PgPool, height: u64) {
        let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(height as i32)
            .execute(pg)
            .await;
        let _ = sqlx::query("DELETE FROM blocks_entity WHERE height = $1")
            .bind(height as i64)
            .execute(pg)
            .await;
    }

    /// A payout mode that keeps a ledger, and one that does not.
    struct Modes(bool);
    impl ModeLedger for Modes {
        fn keeps_a_ledger(&self, _miner_address: &str) -> bool {
            self.0
        }
    }

    /// Drives both gaps against a real chain. The second one is the reason
    /// this check cannot key on `blocks_entity` alone: the front writes that
    /// row the moment a block is found, so a block whose distribution never
    /// booked has one and would otherwise look accounted for.
    #[tokio::test]
    async fn both_ways_a_pool_block_goes_unaccounted_for_are_reported() {
        let Some(pg) = pg_or_skip().await else {
            return;
        };
        let node = match RegtestNode::start().await {
            Ok(n) => n,
            Err(err) => {
                eprintln!("bitcoin-node unavailable ({err}) — skipping");
                return;
            }
        };
        let rpc = node.bitcoin_rpc().expect("rpc handle");
        let fee_address = node.new_address("bech32").await.expect("address");
        let markers = PoolMarkers::new([fee_address.clone()]).expect("one address");
        let ledger_mode = Modes(true);

        let before = node.current_height().await.expect("height") as u64;
        node.generate_to_address(1, &fee_address)
            .await
            .expect("mine to the fee address");
        let mined = before + 1;
        clear_height(&pg, mined).await;
        // 1. The pool has no record of it at all.
        let pass = run_once(
            &rpc,
            &pg,
            &markers,
            &ledger_mode,
            Some(before),
            DEFAULT_LOOKBACK,
        )
        .await
        .expect("pass 1");
        let found = pass
            .unbooked
            .iter()
            .find(|b| b.height == mined)
            .expect("a pool block the pool never registered must be reported");
        assert_eq!(found.gap, Gap::NeverRegistered);
        assert!(
            found
                .pool_outputs
                .iter()
                .any(|(a, sats)| a == &fee_address && *sats > 0),
            "the report must carry what the coinbase paid: {:?}",
            found.pool_outputs
        );

        // 2. Registered by the front — but nothing booked a payout. This is
        //    the gap a `blocks_entity` check cannot see.
        bp_db::insert_found_block(
            &pg,
            mined as i64,
            &fee_address,
            "reconcile-regtest",
            "sid",
            &"00".repeat(80),
        )
        .await
        .expect("register the block");
        let pass = run_once(
            &rpc,
            &pg,
            &markers,
            &ledger_mode,
            Some(before),
            DEFAULT_LOOKBACK,
        )
        .await
        .expect("pass 2");
        assert_eq!(
            pass.unbooked
                .iter()
                .find(|b| b.height == mined)
                .map(|b| b.gap),
            Some(Gap::RegisteredButUnbooked),
            "registered but never booked must still be reported"
        );

        // 3. A mode that keeps no ledger (Solo pays in the coinbase) has no
        //    payout row by design and must not be flagged.
        let pass = run_once(
            &rpc,
            &pg,
            &markers,
            &Modes(false),
            Some(before),
            DEFAULT_LOOKBACK,
        )
        .await
        .expect("pass 3");
        assert!(
            !pass.unbooked.iter().any(|b| b.height == mined),
            "a Solo block keeps no ledger — flagging it would make the check noise"
        );

        // 4. Once the payout is booked, it stops being reported.
        sqlx::query(
            r#"INSERT INTO pplns_payout_history ("blockHeight", address, "paidSats", percent)
               VALUES ($1, $2, 1000, 100.0)"#,
        )
        .bind(mined as i32)
        .bind(&fee_address)
        .execute(&pg)
        .await
        .expect("book a payout");
        let pass = run_once(
            &rpc,
            &pg,
            &markers,
            &ledger_mode,
            Some(before),
            DEFAULT_LOOKBACK,
        )
        .await
        .expect("pass 4");
        assert!(
            !pass.unbooked.iter().any(|b| b.height == mined),
            "a booked block must not be reported"
        );

        clear_height(&pg, mined).await;
        node.shutdown().await.ok();
    }
}
