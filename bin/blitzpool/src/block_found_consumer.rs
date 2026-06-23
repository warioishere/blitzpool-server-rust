// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side block-found stream consumer.
//!
//! The Core submits the block + writes the durable `blocks_entity` record, then
//! publishes a [`BlockFoundEvent`] onto the block-found stream. Two independent
//! consumers drain it, each on its own group (see [`BlockFoundAction`]):
//!
//! - `Ledger` (the `payout` role) runs [`BlockFoundApplier::apply_block_found`]
//!   — the per-mode engine ledger-write + PPLNS confirmation-gate. The event is
//!   fully Core-stamped (mode / group_id / height), so it needs no mode gate
//!   and no bitcoin RPC.
//! - `Notify` (the `notify` role) runs [`BlockFoundApplier::notify_block_found`]
//!   — the dispatcher fan-out only. Split out so a notification change redeploys
//!   `notify` without restarting `payout`. A back holding both roles consumes
//!   both groups; the front produces the event and consumes neither.
//!
//! Block-found is rare + both sides are idempotent (the ledger via PG `UNIQUE`
//! constraints + the PPLNS pending store keyed by block hash; the notify via a
//! duplicate push being cosmetic), so a single consumer per group with
//! at-least-once delivery is enough: a crash before `XACK` redelivers and the
//! reprocess is harmless.

use std::time::Duration;

use bp_share_stream::{StreamConsumer, BLOCK_FOUND_STREAM_KEY};
use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::block_sink::{BlockFoundApplier, BlockFoundEvent};

const BATCH: usize = 64;
const BLOCK_MS: usize = 1000;
const ERROR_BACKOFF: Duration = Duration::from_millis(500);
const CONSUMER: &str = "c1";

/// What a block-found consumer does with each event, and on which consumer
/// group. The two run independently off the same stream: `payout` applies the
/// per-mode engine ledger, `notify` fans out the dispatcher notification. Split
/// so a notification change redeploys `notify` without touching `payout`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum BlockFoundAction {
    /// Engine ledger-write (PPLNS / Group-Solo / Blockparty). The `payout` role.
    Ledger,
    /// Dispatcher notification fan-out only. The `notify` role.
    Notify,
}

impl BlockFoundAction {
    /// Distinct consumer group per action so both drain every event
    /// independently (at-least-once, idempotent on each side).
    fn group(self) -> &'static str {
        match self {
            Self::Ledger => "satellite",
            Self::Notify => "notify",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Notify => "notify",
        }
    }
}

/// Live consumer task + its cancel token.
pub(crate) struct BlockFoundConsumerHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl BlockFoundConsumerHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "block-found-consumer: task join failed");
        }
    }
}

/// Spawn the block-found stream consumer. Owns the applier + a Redis handle.
/// `action` picks the consumer group + what each event does (ledger vs notify).
pub(crate) fn spawn(
    redis: ConnectionManager,
    applier: BlockFoundApplier,
    action: BlockFoundAction,
) -> BlockFoundConsumerHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let consumer: StreamConsumer<BlockFoundEvent> =
            StreamConsumer::new(redis, BLOCK_FOUND_STREAM_KEY, action.group(), CONSUMER);
        // Ledger is idempotent (PG UNIQUE) → replay history from id 0 safely.
        // Notify is NOT → a freshly-created group starts at the tail ($) so a
        // first start doesn't re-fire a push for every historical block.
        let ensured = match action {
            BlockFoundAction::Ledger => consumer.ensure_group().await,
            BlockFoundAction::Notify => consumer.ensure_group_at_tail().await,
        };
        if let Err(err) = ensured {
            warn!(%err, action = action.label(), "block-found-consumer: ensure_group failed; task not started");
            return;
        }

        // Resume: replay the delivered-but-unacked backlog before new events.
        loop {
            match consumer.read_pending(BATCH).await {
                Ok(batch) if batch.is_empty() => break,
                Ok(batch) => {
                    apply_and_ack(&consumer, &applier, action, batch, "pending").await;
                }
                Err(err) => {
                    warn!(%err, action = action.label(), "block-found-consumer: read_pending failed; continuing");
                    break;
                }
            }
        }

        info!(action = action.label(), "block-found-consumer: live");
        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                result = consumer.read_new(BATCH, BLOCK_MS) => match result {
                    Ok(batch) => {
                        apply_and_ack(&consumer, &applier, action, batch, "new").await;
                    }
                    Err(err) => {
                        warn!(%err, action = action.label(), "block-found-consumer: read_new failed; backing off");
                        tokio::time::sleep(ERROR_BACKOFF).await;
                    }
                },
            }
        }
        info!(action = action.label(), "block-found-consumer: stopped");
    });
    BlockFoundConsumerHandle { task, cancel }
}

/// Run each event through the chosen `action` (ledger apply or notify fan-out),
/// then `XACK` the batch. Acking after is safe: both sides are idempotent —
/// the ledger via PG constraints, the notify via a duplicate-push being cosmetic
/// — so a redelivery (crash before ack) does no harm.
async fn apply_and_ack(
    consumer: &StreamConsumer<BlockFoundEvent>,
    applier: &BlockFoundApplier,
    action: BlockFoundAction,
    batch: Vec<bp_share_stream::Consumed<BlockFoundEvent>>,
    kind: &str,
) {
    if batch.is_empty() {
        return;
    }
    let mut ids = Vec::with_capacity(batch.len());
    for entry in &batch {
        match action {
            BlockFoundAction::Ledger => applier.apply_block_found(&entry.value).await,
            BlockFoundAction::Notify => applier.notify_block_found(&entry.value).await,
        }
        ids.push(entry.id.clone());
    }
    match consumer.ack(&ids).await {
        Ok(n) => info!(
            n,
            kind,
            action = action.label(),
            "block-found-consumer: applied + acked"
        ),
        Err(err) => {
            warn!(%err, kind, action = action.label(), "block-found-consumer: ack failed (will redeliver)")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bp_common::MiningMode;
    use bp_notifications::command::ChatLanguageMap;
    use bp_notifications::dispatcher::{DispatcherConfig, NotificationDispatcher};
    use bp_share_stream::{Consumed, StreamConsumer, StreamProducer, BLOCK_FOUND_STREAM_KEY};
    use redis::aio::ConnectionManager;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;

    use super::*;
    use crate::block_sink::{BlockFoundApplier, BlockFoundEvent};

    const REDIS_URL: &str = "redis://127.0.0.1:16379";
    const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    fn solo_event() -> BlockFoundEvent {
        BlockFoundEvent {
            address: ADDR.to_string(),
            worker: "rig1".to_string(),
            session_id: "sid".to_string(),
            reward_sats: None,
            block_hash: Some("00".repeat(32)),
            block_data: "00".repeat(80),
            mode: MiningMode::Solo,
            group_id: None,
            height: 101,
            groupsolo_snapshot: None,
        }
    }

    /// `notify_block_found` with no dispatcher is a no-op — the `payout` ledger
    /// applier (dispatcher = None) must never try to notify. Pure, no I/O.
    #[tokio::test]
    async fn notify_is_noop_without_dispatcher() {
        let ledger = BlockFoundApplier::new(None, None, None, None, None);
        // Must return cleanly (no panic, no dispatcher access).
        ledger.notify_block_found(&solo_event()).await;
    }

    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let client = redis::Client::open(format!("{REDIS_URL}/{db}")).ok()?;
        let mut conn = tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client))
            .await
            .ok()?
            .ok()?;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.ok()?;
        Some(conn)
    }

    async fn connect_pg_or_skip() -> Option<PgPool> {
        tokio::time::timeout(
            Duration::from_secs(2),
            PgPoolOptions::new().max_connections(2).connect(PG_URL),
        )
        .await
        .ok()?
        .ok()
    }

    fn no_adapter_dispatcher(pool: PgPool) -> Arc<NotificationDispatcher> {
        let chat: ChatLanguageMap =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        Arc::new(NotificationDispatcher::new(
            pool,
            DispatcherConfig::default_zurich(),
            None,
            None,
            None,
            None,
            chat,
        ))
    }

    async fn drain_one(
        consumer: &StreamConsumer<BlockFoundEvent>,
    ) -> Vec<Consumed<BlockFoundEvent>> {
        let mut got = Vec::new();
        for _ in 0..5 {
            let batch = consumer.read_new(16, 500).await.expect("read_new");
            got.extend(batch);
            if !got.is_empty() {
                break;
            }
        }
        got
    }

    /// End-to-end over real Redis + PG: one block-found event, two independent
    /// consumer groups — `notify` fires the dispatcher fan-out, `satellite`
    /// runs the ledger apply (Solo → no-op) — each drains + acks the same event
    /// on its own group. Proves the split routing the `payout`/`notify` roles
    /// rely on.
    #[tokio::test]
    async fn block_found_dual_group_routes_ledger_and_notify() {
        let Some(redis) = connect_redis_or_skip(10).await else {
            eprintln!("redis unreachable — skipping block-found dual-group test");
            return;
        };
        let Some(pg) = connect_pg_or_skip().await else {
            eprintln!("pg unreachable — skipping block-found dual-group test");
            return;
        };

        let producer: StreamProducer<BlockFoundEvent> =
            StreamProducer::new(redis.clone(), BLOCK_FOUND_STREAM_KEY);
        producer.publish(&solo_event()).await.expect("publish");

        // Notify group: dispatcher present (no adapters → fan-out finds no subs
        // and is a clean no-op), no engines.
        let notify_applier =
            BlockFoundApplier::new(None, None, None, Some(no_adapter_dispatcher(pg)), None);
        let notify_consumer: StreamConsumer<BlockFoundEvent> = StreamConsumer::new(
            redis.clone(),
            BLOCK_FOUND_STREAM_KEY,
            BlockFoundAction::Notify.group(),
            CONSUMER,
        );
        notify_consumer.ensure_group().await.expect("ensure notify");
        let n_batch = drain_one(&notify_consumer).await;
        assert_eq!(n_batch.len(), 1, "notify group delivered the event");
        notify_applier.notify_block_found(&n_batch[0].value).await;
        let acked = notify_consumer
            .ack(&[n_batch[0].id.clone()])
            .await
            .expect("ack notify");
        assert_eq!(acked, 1);

        // Ledger group: no dispatcher, no engines → Solo branch logs, no notify.
        let ledger_applier = BlockFoundApplier::new(None, None, None, None, None);
        let ledger_consumer: StreamConsumer<BlockFoundEvent> = StreamConsumer::new(
            redis,
            BLOCK_FOUND_STREAM_KEY,
            BlockFoundAction::Ledger.group(),
            CONSUMER,
        );
        ledger_consumer
            .ensure_group()
            .await
            .expect("ensure satellite");
        let l_batch = drain_one(&ledger_consumer).await;
        assert_eq!(
            l_batch.len(),
            1,
            "satellite group independently delivered the same event"
        );
        ledger_applier.apply_block_found(&l_batch[0].value).await;
        let acked = ledger_consumer
            .ack(&[l_batch[0].id.clone()])
            .await
            .expect("ack ledger");
        assert_eq!(acked, 1);
    }
}
