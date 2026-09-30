// SPDX-License-Identifier: AGPL-3.0-or-later

//! `NotificationDispatcher` construction.
//!
//! Builds the single `Arc<NotificationDispatcher>` that fans
//! engine-side events (`block_found`, `best_diff`, `device_status`)
//! out across whichever transport adapters are live. The adapters are
//! the already-built singletons, so each has one state:
//!
//! - **FCM** + **Web-Push** from [`crate::hooks::ProductionHooks`]
//!   (also used by the API push-register paths).
//! - **Telegram** + **ntfy** from [`crate::listeners::ListenerHandles`]
//!   (also driving the long-poll + SSE listener loops).
//!
//! Returns `None` when none of the four adapters are configured, so
//! callers skip building event payloads nobody receives.

use std::collections::HashMap;
use std::sync::Arc;

use bp_notifications::command::ChatLanguageMap;
use bp_notifications::dispatcher::NotificationDispatcher;
use tokio::sync::Mutex;
use tracing::info;

use crate::boot::FoundationHandles;
use crate::hooks::ProductionHooks;
use crate::listeners::ListenerHandles;

/// Build the dispatcher Arc when any of `[notifications.*]` is wired;
/// `None` when every transport is absent.
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

    // The command handler's per-chat language map, shared so /deutsch /
    // /english apply to outbound Telegram notifications too. Empty when
    // no listeners are configured.
    let chat_languages: ChatLanguageMap = listeners
        .chat_languages()
        .unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));

    info!(
        fcm = fcm.is_some(),
        web_push = web_push.is_some(),
        telegram = telegram.is_some(),
        ntfy = ntfy.is_some(),
        "dispatcher: built (Europe/Zurich timezone)"
    );
    Some(Arc::new(NotificationDispatcher::new(
        foundation.db.pool().clone(),
        telegram,
        ntfy,
        fcm,
        web_push,
        chat_languages,
    )))
}
