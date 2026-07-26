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
use std::time::Duration;

use bp_bitcoin::BitcoinRpc;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

/// Default cadence. Slow on purpose: a missed booking is not more urgent an
/// hour later, and each pass costs two RPCs per unseen block.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(3600);

/// How far back the first pass after a restart looks. ~1 day of blocks — far
/// enough to cover a deploy or an outage, short enough to stay cheap.
pub(crate) const DEFAULT_LOOKBACK: u64 = 144;

/// One block the chain says is the pool's, with no ledger record of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnbookedBlock {
    pub height: u64,
    pub hash: String,
    /// Coinbase outputs paying a pool address, as `(address, sats)`. This is
    /// what the block actually paid — the only surviving record of it once a
    /// distribution snapshot has expired.
    pub pool_outputs: Vec<(String, u64)>,
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
            match run_once(&rpc, &pool, &markers, checked_through, lookback).await {
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
    checked_through: Option<u64>,
    lookback: u64,
) -> Result<ReconcilePass, bp_bitcoin::RpcError> {
    let tip = rpc.get_block_count().await?;
    let from_height = match checked_through {
        Some(h) => h.saturating_add(1),
        None => tip.saturating_sub(lookback),
    };
    let mut unbooked = Vec::new();
    if from_height > tip {
        return Ok(ReconcilePass {
            from_height,
            checked_through: tip,
            unbooked,
        });
    }

    for height in from_height..=tip {
        match inspect_block(rpc, pool, markers, height).await {
            Ok(Some(block)) => {
                error!(
                    height = block.height,
                    hash = %block.hash,
                    outputs = ?block.pool_outputs,
                    "block-reconcile: this block's coinbase pays the pool but nothing booked \
                     it — the miners it paid are still owed their ledger entry"
                );
                unbooked.push(block);
            }
            Ok(None) => {}
            Err(err) => warn!(%err, height, "block-reconcile: could not check block"),
        }
    }
    Ok(ReconcilePass {
        from_height,
        checked_through: tip,
        unbooked,
    })
}

/// `Some` when the block at `height` pays the pool and the ledger has no
/// record of it.
async fn inspect_block(
    rpc: &BitcoinRpc,
    pool: &PgPool,
    markers: &PoolMarkers,
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
    match bp_db::block_recorded_at_height(pool, height as i64).await {
        Ok(true) => Ok(None),
        Ok(false) => Ok(Some(UnbookedBlock {
            height,
            hash,
            pool_outputs,
        })),
        Err(err) => {
            // A DB error is not evidence the block is unbooked — saying so
            // would send an operator to reprocess something already booked.
            warn!(%err, height, "block-reconcile: ledger lookup failed; skipping this block");
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

    /// A zero-fee deployment has no marker output, so the check cannot
    /// recognise its blocks. Refusing to construct is what makes that visible
    /// instead of a task that quietly reports nothing forever.
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

    #[tokio::test]
    async fn a_mined_pool_block_is_reported_until_the_ledger_records_it() {
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

        // A coinbase paying this address is, by definition, this pool's.
        let fee_address = node.new_address("bech32").await.expect("address");
        let markers = PoolMarkers::new([fee_address.clone()]).expect("one address");

        // Coinbases only mature into spendable outputs after 100 blocks, but
        // the scan reads them straight from the chain, so one block is enough.
        let before = node.current_height().await.expect("height") as u64;
        let _ = node
            .generate_to_address(1, &fee_address)
            .await
            .expect("mine to the fee address");

        let pass = run_once(&rpc, &pg, &markers, Some(before), DEFAULT_LOOKBACK)
            .await
            .expect("reconcile pass");
        let mined_height = before + 1;
        let found = pass
            .unbooked
            .iter()
            .find(|b| b.height == mined_height)
            .expect("the block we just mined pays the pool and nothing booked it");
        assert!(
            found
                .pool_outputs
                .iter()
                .any(|(a, sats)| a == &fee_address && *sats > 0),
            "the report must carry what the coinbase paid: {:?}",
            found.pool_outputs
        );

        // Record it the way a booked block would be, and it stops being
        // reported — otherwise the check would cry wolf on every pass.
        bp_db::insert_found_block(
            &pg,
            mined_height as i64,
            &fee_address,
            "reconcile-regtest",
            "sid",
            &"00".repeat(80),
        )
        .await
        .expect("record the block");
        let pass = run_once(&rpc, &pg, &markers, Some(before), DEFAULT_LOOKBACK)
            .await
            .expect("second pass");
        assert!(
            !pass.unbooked.iter().any(|b| b.height == mined_height),
            "a recorded block must not be reported"
        );

        let _ = sqlx::query("DELETE FROM blocks_entity WHERE height = $1")
            .bind(mined_height as i64)
            .execute(&pg)
            .await;
        node.shutdown().await.ok();
    }
}
