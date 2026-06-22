// SPDX-License-Identifier: AGPL-3.0-or-later

//! `NotificationDispatcher` construction — Phase 7.7.
//!
//! Builds the single `Arc<NotificationDispatcher>` that fans
//! engine-side events (`block_found`, `best_diff`, `device_status`)
//! out across whichever transport adapters are live. The adapter
//! handles come from already-built singletons:
//!
//! - **FCM** + **Web-Push** from [`crate::hooks::ProductionHooks`]
//!   (Phase 7.3 / 7.7 — also used by the API push-register paths).
//! - **Telegram** + **ntfy** from [`crate::listeners::ListenerHandles`]
//!   (Phase 7.6 — same adapter instances also drive the long-poll +
//!   SSE listener loops, so per-adapter state stays consistent).
//!
//! Returns `None` when none of the four adapters are configured —
//! callers (cron-wiring + block-sink + device-status hooks) then
//! collapse their `notify_*` calls into no-ops rather than building
//! pointless event payloads.

use std::collections::HashMap;
use std::sync::Arc;

use bp_notifications::command::ChatLanguageMap;
use bp_notifications::dispatcher::{DispatcherConfig, NotificationDispatcher};
use tokio::sync::Mutex;
use tracing::info;

use crate::boot::FoundationHandles;
use crate::hooks::ProductionHooks;
use crate::listeners::ListenerHandles;

/// Build the dispatcher Arc when any of `[notifications.*]` is wired.
/// Returns `None` when every transport is absent — operational
/// staging deployments with no push channels skip the dispatcher
/// entirely.
pub(crate) fn build(
    foundation: &FoundationHandles,
    hooks: &ProductionHooks,
    listeners: &ListenerHandles,
) -> Option<Arc<NotificationDispatcher>> {
    let fcm = hooks.fcm.clone();
    let web_push = hooks.web_push.clone();
    let telegram = listeners.telegram_adapter();
    let ntfy = listeners.ntfy_adapter();

    if fcm.is_none() && web_push.is_none() && telegram.is_none() && ntfy.is_none() {
        info!(
            "dispatcher: SKIPPED — no transport adapters configured (no [notifications.fcm], \
             no [notifications.web_push], no [notifications.telegram], no [notifications.ntfy]). \
             block_found / best_diff / device_status events will have no fan-out."
        );
        return None;
    }

    // Use the in-memory per-chat language map from the command handler
    // (shared with the listener loops so /deutsch / /english take effect
    // for outbound Telegram notifications). Fall back to an empty map
    // when no listeners are configured.
    let chat_languages: ChatLanguageMap = listeners
        .chat_languages()
        .unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));

    let config = DispatcherConfig::default_zurich();
    info!(
        fcm = fcm.is_some(),
        web_push = web_push.is_some(),
        telegram = telegram.is_some(),
        ntfy = ntfy.is_some(),
        "dispatcher: built (Europe/Zurich timezone)"
    );
    Some(Arc::new(NotificationDispatcher::new(
        foundation.db.pool().clone(),
        config,
        telegram,
        ntfy,
        fcm,
        web_push,
        chat_languages,
    )))
}
