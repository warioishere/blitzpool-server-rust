// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production wiring for the device-status debounce.
//!
//! [`bp_notifications::dispatcher::DeviceStatusGate`] is transport- and
//! storage-agnostic; this module supplies the two concrete pieces it
//! needs and the task that drives it:
//!
//! - [`PgLiveSessions`] — the live-session answer, read from
//!   `client_entity` (`deletedAt IS NULL`).
//! - [`spawn`] — a ticker that resolves due devices and hands whatever
//!   the gate releases to the [`NotificationDispatcher`].
//!
//! Both the in-process sink and the Satellite's stream consumer feed the
//! *same* gate instance, so a process that runs the front and the notify
//! role together debounces exactly like a split deployment.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bp_cron_utils::SystemClock;
use bp_notifications::dispatcher::{
    DeviceGateConfig, DeviceStatusGate, LiveSessionLookup, NotificationDispatcher,
};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// How often due devices are resolved. Well below the shortest dwell so
/// the added latency is a rounding error on the configured grace, and
/// cheap: a tick with nothing due costs one map scan and no query.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// The concrete gate the binary uses.
pub(crate) type Gate = DeviceStatusGate<SystemClock, PgLiveSessions>;

/// Live-session lookup backed by `client_entity`.
pub(crate) struct PgLiveSessions {
    pool: PgPool,
}

#[async_trait]
impl LiveSessionLookup for PgLiveSessions {
    async fn live_counts(
        &self,
        keys: &[(String, String)],
    ) -> Option<HashMap<(String, String), i64>> {
        let addresses: Vec<String> = keys.iter().map(|(a, _)| a.clone()).collect();
        let workers: Vec<String> = keys.iter().map(|(_, w)| w.clone()).collect();
        match bp_db::live_session_counts(&self.pool, &addresses, &workers).await {
            Ok(rows) => Some(rows.into_iter().map(|(a, w, n)| ((a, w), n)).collect()),
            Err(err) => {
                // Deliberately `None`, not an empty map: an empty map
                // reads as "nothing is connected" and would fire an
                // offline notification for every due device.
                warn!(%err, "device-status gate: live-session lookup failed — holding deadlines");
                None
            }
        }
    }
}

/// Build the gate. One instance per process; clone the `Arc` into every
/// producer.
pub(crate) fn build(cfg: DeviceGateConfig, pool: PgPool) -> Arc<Gate> {
    Arc::new(DeviceStatusGate::new(
        cfg,
        SystemClock,
        PgLiveSessions { pool },
    ))
}

/// Handle for the sweeper task.
pub(crate) struct DeviceStatusGateHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl DeviceStatusGateHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "device-status gate: sweeper join failed");
        }
    }
}

/// Drive the gate. Every tick resolves whatever is due and dispatches
/// the released messages.
pub(crate) fn spawn(
    gate: Arc<Gate>,
    dispatcher: Arc<NotificationDispatcher>,
) -> DeviceStatusGateHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(
            interval_s = SWEEP_INTERVAL.as_secs(),
            "device-status gate: sweeper started"
        );
        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                _ = tick.tick() => {
                    let notices = gate.poll_due().await;
                    if !notices.is_empty() {
                        debug!(count = notices.len(), "device-status gate: releasing");
                    }
                    for notice in &notices {
                        dispatcher.notify_device_notice(notice).await;
                    }
                }
            }
        }
        info!("device-status gate: sweeper stopped");
    });
    DeviceStatusGateHandle { cancel, task }
}
