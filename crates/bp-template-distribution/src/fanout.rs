// SPDX-License-Identifier: AGPL-3.0-or-later

//! The template fan-out both Stratum servers run: one translator task per
//! TDP stream assembles the stream's updates into the protocol's template and
//! broadcasts it to the server's connections, keeping the latest one for a
//! connection that joins or switches streams.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bp_common::StreamKind;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    ActiveFromTemplate, TemplateAssembler, TemplateChange, TemplateSnapshot, TemplateUpdate,
};

/// Broadcasts a connection may fall behind by; one further behind skips the
/// missed broadcasts and continues with the next one.
const TEMPLATE_BROADCAST_CAPACITY: usize = 32;

/// One assembled template as the translator broadcasts it. The template rides
/// in an `Arc` because `broadcast` clones the payload once per subscriber.
#[derive(Debug)]
pub struct TemplateBroadcast<A> {
    pub template: Arc<A>,
    pub change: TemplateChange,
}

impl<A> Clone for TemplateBroadcast<A> {
    fn clone(&self) -> Self {
        Self {
            template: Arc::clone(&self.template),
            change: self.change,
        }
    }
}

impl<A> TemplateBroadcast<A> {
    /// The broadcast a connection's next job goes out under: a block change
    /// while `owes_new_block` is set, which this clears. A connection owes one
    /// when it skipped broadcasts, got no job for a block change, or (SV2) got
    /// no first job at channel open; its next job must then announce the tip,
    /// or the miner keeps hashing the old one.
    pub fn for_next_job(self, owes_new_block: &mut bool) -> Self {
        if std::mem::take(owes_new_block) {
            Self {
                template: self.template,
                change: TemplateChange::NewBlock,
            }
        } else {
            self
        }
    }
}

/// One connection's claim on a stream: its own broadcast receiver plus the
/// template to boot from.
pub struct StreamHandle<A> {
    pub rx: broadcast::Receiver<TemplateBroadcast<A>>,
    pub initial: Option<Arc<A>>,
}

/// One stream's broadcast sender plus the latest template.
struct TemplateStream<A> {
    template_tx: broadcast::Sender<TemplateBroadcast<A>>,
    current_template: Arc<Mutex<Option<Arc<A>>>>,
}

impl<A> TemplateStream<A> {
    fn current(&self) -> Option<Arc<A>> {
        self.current_template
            .lock()
            .expect("current_template mutex poisoned")
            .clone()
    }

    fn handle(&self) -> StreamHandle<A> {
        StreamHandle {
            rx: self.template_tx.subscribe(),
            initial: self.current(),
        }
    }
}

/// A server's template streams: the PPLNS stream every connection boots on
/// and the fixed-reservation streams (Solo, Group-Solo, Blockparty) a
/// connection switches onto once its address resolves to that mode, each fed
/// by its own translator.
pub struct TemplateStreams<A> {
    /// Log prefix of the translators (`sv1`, `sv2`).
    label: &'static str,
    pplns: TemplateStream<A>,
    alt: HashMap<StreamKind, TemplateStream<A>>,
    /// PPLNS first; drained once by [`Self::drain`].
    translators: Mutex<Vec<JoinHandle<()>>>,
}

impl<A: ActiveFromTemplate + Send + Sync + 'static> TemplateStreams<A> {
    /// Start one translator per stream. Each initial snapshot must be taken
    /// alongside its receiver's `subscribe()`: the translator applies it
    /// first, because bitcoin-core's bootstrap pair may have gone out before
    /// the subscription existed. `on_active` runs for every assembled
    /// template, after it becomes the stream's current one and before it is
    /// broadcast. The translators stop on `cancel` or when their TDP source
    /// closes.
    pub fn spawn<F>(
        label: &'static str,
        updates_rx: broadcast::Receiver<TemplateUpdate>,
        initial_snapshot: TemplateSnapshot,
        alt_streams: Vec<(
            StreamKind,
            broadcast::Receiver<TemplateUpdate>,
            TemplateSnapshot,
        )>,
        cancel: &CancellationToken,
        on_active: F,
    ) -> Self
    where
        F: Fn(&A) + Clone + Send + Sync + 'static,
    {
        let mut translators = Vec::with_capacity(1 + alt_streams.len());
        let mut spawn_stream = |updates_rx, initial_snapshot| {
            let (template_tx, _) = broadcast::channel(TEMPLATE_BROADCAST_CAPACITY);
            let current_template = Arc::new(Mutex::new(None));
            translators.push(tokio::spawn(run_translator(
                label,
                updates_rx,
                initial_snapshot,
                template_tx.clone(),
                Arc::clone(&current_template),
                on_active.clone(),
                cancel.clone(),
            )));
            TemplateStream {
                template_tx,
                current_template,
            }
        };
        let pplns = spawn_stream(updates_rx, initial_snapshot);
        let alt = alt_streams
            .into_iter()
            .map(|(kind, updates_rx, initial_snapshot)| {
                (kind, spawn_stream(updates_rx, initial_snapshot))
            })
            .collect();
        Self {
            label,
            pplns,
            alt,
            translators: Mutex::new(translators),
        }
    }
}

impl<A> TemplateStreams<A> {
    /// The PPLNS stream's latest template; `None` until its translator pairs
    /// the first `NewTemplate` with a `SetNewPrevHash`.
    pub fn current(&self) -> Option<Arc<A>> {
        self.pplns.current()
    }

    /// A receiver on the PPLNS stream.
    pub fn subscribe(&self) -> broadcast::Receiver<TemplateBroadcast<A>> {
        self.pplns.template_tx.subscribe()
    }

    /// A new connection's handles: the PPLNS stream it boots on, and every
    /// alt stream it may switch onto.
    pub fn handles(&self) -> (StreamHandle<A>, HashMap<StreamKind, StreamHandle<A>>) {
        let alt = self
            .alt
            .iter()
            .map(|(kind, stream)| (*kind, stream.handle()))
            .collect();
        (self.pplns.handle(), alt)
    }

    /// Wait for each translator to stop, at most `timeout` each; call after
    /// cancelling them. A second call finds nothing to wait for.
    pub async fn drain(&self, timeout: Duration) {
        let label = self.label;
        let handles =
            std::mem::take(&mut *self.translators.lock().expect("translators mutex poisoned"));
        for handle in handles {
            match tokio::time::timeout(timeout, handle).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!("{label} translator task panicked during shutdown: {err}"),
                Err(_) => warn!("{label} translator didn't drain within {timeout:?}, detaching"),
            }
        }
    }
}

/// Assemble one stream's TDP updates into templates and broadcast them,
/// keeping `current_template` so a connection boots without waiting for the
/// next TDP message.
async fn run_translator<A, F>(
    label: &'static str,
    mut updates_rx: broadcast::Receiver<TemplateUpdate>,
    initial_snapshot: TemplateSnapshot,
    template_tx: broadcast::Sender<TemplateBroadcast<A>>,
    current_template: Arc<Mutex<Option<Arc<A>>>>,
    on_active: F,
    cancel: CancellationToken,
) where
    A: ActiveFromTemplate,
    F: Fn(&A),
{
    let mut assembler = TemplateAssembler::<A>::new();
    let publish = |active: A, change: TemplateChange| {
        let active = Arc::new(active);
        *current_template
            .lock()
            .expect("current_template mutex poisoned") = Some(Arc::clone(&active));
        on_active(&active);
        // Errors only without subscribers; a connection that joins later
        // boots from `current_template`.
        let _ = template_tx.send(TemplateBroadcast {
            template: active,
            change,
        });
    };

    if let Some((active, change)) = assembler.bootstrap_from_snapshot(initial_snapshot) {
        publish(active, change);
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("{label} translator shutting down");
                return;
            }
            update = updates_rx.recv() => {
                let update = match update {
                    Ok(u) => u,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Recovers with the next NewTemplate/SetNewPrevHash pair.
                        warn!("{label} translator lagged {n} TDP updates");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("{label} translator: TDP source closed");
                        return;
                    }
                };
                if let Some(change) = assembler.apply(&update) {
                    if let Some(active) = assembler.current().cloned() {
                        publish(active, change);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::tests::{new_template, set_new_prev_hash};
    use crate::ActiveTemplate;

    const WAIT: Duration = Duration::from_millis(500);

    fn streams(
        cancel: &CancellationToken,
    ) -> (
        broadcast::Sender<TemplateUpdate>,
        TemplateStreams<ActiveTemplate>,
    ) {
        let (updates_tx, updates_rx) = broadcast::channel(8);
        let streams = TemplateStreams::spawn(
            "test",
            updates_rx,
            TemplateSnapshot::default(),
            Vec::new(),
            cancel,
            |_: &ActiveTemplate| {},
        );
        (updates_tx, streams)
    }

    /// A future template is held until its `SetNewPrevHash`; the pair is
    /// broadcast as a block change and becomes the stream's current template.
    #[tokio::test]
    async fn translator_pairs_new_template_and_set_new_prev_hash() {
        let cancel = CancellationToken::new();
        let (updates_tx, streams) = streams(&cancel);
        let mut rx = streams.subscribe();

        updates_tx
            .send(TemplateUpdate::NewTemplate(new_template(1, true)))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(rx.try_recv().is_err(), "a future template alone is held");

        updates_tx
            .send(TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
                1,
                0x207f_ffff,
            )))
            .unwrap();
        let payload = tokio::time::timeout(WAIT, rx.recv())
            .await
            .expect("must broadcast")
            .expect("must succeed");
        assert_eq!(payload.change, TemplateChange::NewBlock);
        assert_eq!(payload.template.template_id, 1);
        assert_eq!(streams.current().map(|t| t.template_id), Some(1));

        cancel.cancel();
        streams.drain(WAIT).await;
    }

    /// A non-future template on the current tip is broadcast as a refresh,
    /// and `on_active` runs for every broadcast template.
    #[tokio::test]
    async fn translator_emits_refresh_and_runs_on_active() {
        let cancel = CancellationToken::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (updates_tx, updates_rx) = broadcast::channel(8);
        let streams = TemplateStreams::spawn(
            "test",
            updates_rx,
            TemplateSnapshot::default(),
            Vec::new(),
            &cancel,
            {
                let seen = Arc::clone(&seen);
                move |active: &ActiveTemplate| seen.lock().unwrap().push(active.template_id)
            },
        );
        let mut rx = streams.subscribe();

        updates_tx
            .send(TemplateUpdate::NewTemplate(new_template(1, true)))
            .unwrap();
        updates_tx
            .send(TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
                1,
                0x207f_ffff,
            )))
            .unwrap();
        let _ = tokio::time::timeout(WAIT, rx.recv()).await.unwrap();

        updates_tx
            .send(TemplateUpdate::NewTemplate(new_template(2, false)))
            .unwrap();
        let payload = tokio::time::timeout(WAIT, rx.recv())
            .await
            .expect("refresh must broadcast")
            .unwrap();
        assert_eq!(payload.change, TemplateChange::Refresh);
        assert_eq!(payload.template.template_id, 2);
        assert_eq!(*seen.lock().unwrap(), vec![1, 2]);

        cancel.cancel();
        streams.drain(WAIT).await;
    }

    /// An owed block change turns the next job's broadcast into one, once;
    /// without one owed, the broadcast passes unchanged.
    #[test]
    fn for_next_job_announces_an_owed_block_change_once() {
        let refresh = || TemplateBroadcast {
            template: Arc::new(7u32),
            change: TemplateChange::Refresh,
        };
        let mut owes = true;
        assert_eq!(
            refresh().for_next_job(&mut owes).change,
            TemplateChange::NewBlock
        );
        assert!(!owes, "announced once");
        assert_eq!(
            refresh().for_next_job(&mut owes).change,
            TemplateChange::Refresh
        );
        assert_eq!(*refresh().for_next_job(&mut owes).template, 7);
    }

    /// Cancelling stops every translator promptly.
    #[tokio::test]
    async fn translators_exit_on_cancel() {
        let cancel = CancellationToken::new();
        let (_updates_tx, streams) = streams(&cancel);
        let handles = std::mem::take(&mut *streams.translators.lock().unwrap());
        cancel.cancel();
        for handle in handles {
            tokio::time::timeout(WAIT, handle)
                .await
                .expect("translator must exit on cancel")
                .unwrap();
        }
    }

    /// A translator that never exits must not hold the drain past its
    /// timeout.
    #[tokio::test]
    async fn drain_detaches_a_translator_that_does_not_stop() {
        let cancel = CancellationToken::new();
        let (_updates_tx, streams) = streams(&cancel);
        streams
            .translators
            .lock()
            .unwrap()
            .push(tokio::spawn(std::future::pending::<()>()));
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(10), streams.drain(WAIT))
            .await
            .expect("drain must give up on a translator after its timeout");
    }
}
