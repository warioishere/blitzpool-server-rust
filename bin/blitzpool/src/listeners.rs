// SPDX-License-Identifier: AGPL-3.0-or-later

//! Telegram long-poll + ntfy SSE listener wiring — Phase 7.6.
//!
//! For each `[notifications.telegram]` / `[notifications.ntfy]` block
//! that's configured, this module:
//!
//! 1. Builds the corresponding **outbound adapter**
//!    ([`TelegramAdapter`] / [`NtfyAdapter`]). Same adapter handles
//!    flow into both the listener's reply path and the
//!    `hourly_stats` cron (the cron-wiring lives in `crons.rs` and
//!    receives the adapters back through [`ListenerHandles::telegram_adapter`]
//!    + [`ListenerHandles::ntfy_adapter`]).
//! 2. Builds a single [`CommandHandler`] shared between the two
//!    listeners, with both engine readers attached so the read-side
//!    commands (`/pplns_status`, `/group_status`, `/show_workers`, …)
//!    answer with live data rather than the deferred-stub fallback.
//! 3. Spawns the long-poll / SSE loop. Each helper inside
//!    `bp-notifications` returns a `watch::Sender<bool>` that ends
//!    the loop on `send(true)`.
//!
//! If neither `[notifications.telegram]` nor `[notifications.ntfy]` is
//! configured (typical for staging / API-only deployments), the
//! returned [`ListenerHandles`] is the inert
//! [`ListenerHandles::disabled`] form — `shutdown` is a no-op and the
//! `_adapter()` accessors return `None`. The `hourly_stats` cron is
//! then skipped at the `crons::spawn` site.

use std::sync::Arc;

use bp_config::AppConfig;
use bp_notifications::adapter::{
    AdapterError, NtfyAdapter, NtfyConfig as AdapterNtfyConfig, TelegramAdapter,
    TelegramConfig as AdapterTelegramConfig,
};
use bp_notifications::command::{ChatLanguageMap, CommandHandler};
use bp_notifications::listener::{
    spawn_ntfy_listener, spawn_telegram_listener, NtfyListenerConfig, TelegramListenerConfig,
};
use thiserror::Error;
use tokio::sync::{watch, Notify};
use tracing::info;

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;

/// Default ntfy topic prefix when `[notifications.ntfy].topic_prefix`
/// is absent. Keeps outbound + inbound topic shape consistent.
const DEFAULT_NTFY_TOPIC_PREFIX: &str = "blitzpool-";

pub(crate) struct ListenerHandles {
    inner: Option<Inner>,
}

struct Inner {
    telegram_adapter: Option<Arc<TelegramAdapter>>,
    ntfy_adapter: Option<Arc<NtfyAdapter>>,
    telegram_shutdown: Option<watch::Sender<bool>>,
    ntfy_shutdown: Option<watch::Sender<bool>>,
    /// The `CommandHandler`'s per-chat Telegram language map, shared so
    /// the hourly-stats cron renders each chat's digest in its language.
    chat_languages: ChatLanguageMap,
}

impl ListenerHandles {
    /// Inert placeholder for early-exit paths (e.g. `--check-*`).
    /// Kept on a separate constructor so the spawn function can stay
    /// straight-line.
    pub(crate) fn disabled() -> Self {
        Self { inner: None }
    }

    /// Clone of the outbound Telegram adapter, when configured. The
    /// `hourly_stats` cron passes this to
    /// `bp_notifications::cron::hourly_stats::spawn_hourly_stats_cron`.
    pub(crate) fn telegram_adapter(&self) -> Option<Arc<TelegramAdapter>> {
        self.inner.as_ref().and_then(|i| i.telegram_adapter.clone())
    }

    /// Clone of the outbound ntfy adapter, when configured. Same use
    /// as [`telegram_adapter`].
    pub(crate) fn ntfy_adapter(&self) -> Option<Arc<NtfyAdapter>> {
        self.inner.as_ref().and_then(|i| i.ntfy_adapter.clone())
    }

    /// The shared per-chat Telegram language map, when listeners are
    /// configured. The `hourly_stats` cron passes this to
    /// `spawn_hourly_stats_cron` so digests honour each chat's language.
    pub(crate) fn chat_languages(&self) -> Option<ChatLanguageMap> {
        self.inner.as_ref().map(|i| i.chat_languages.clone())
    }

    /// `is_notify` distinguishes the two reasons `inner` can be `None`: the
    /// process doesn't run the notify role at all, vs. it does but no
    /// Telegram/ntfy transport is configured.
    pub(crate) fn log_summary(&self, is_notify: bool) {
        match &self.inner {
            None if !is_notify => {
                info!("listeners summary: not run on this process (no notify role)")
            }
            None => info!("listeners summary: none configured"),
            Some(inner) => info!(
                telegram = inner.telegram_adapter.is_some(),
                ntfy = inner.ntfy_adapter.is_some(),
                "listeners summary"
            ),
        }
    }

    /// Send `true` on each listener's shutdown channel. The loops
    /// observe it on their next `select!` iteration and exit cleanly.
    pub(crate) async fn shutdown(mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        if let Some(tx) = inner.telegram_shutdown {
            let _ = tx.send(true);
        }
        if let Some(tx) = inner.ntfy_shutdown {
            let _ = tx.send(true);
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ListenerSpawnError {
    #[error("telegram adapter init failed: {0}")]
    Telegram(AdapterError),
    #[error("ntfy adapter init failed: {0}")]
    Ntfy(AdapterError),
}

/// Build adapters from `[notifications.telegram]` + `[notifications.ntfy]`,
/// wire them into a single [`CommandHandler`], and spawn the matching
/// listener loops. Returns the aggregate handle (adapters exposed for
/// the cron-wiring + shutdown signals retained).
pub(crate) fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
) -> Result<ListenerHandles, ListenerSpawnError> {
    let telegram_adapter = build_telegram_adapter(cfg).map_err(ListenerSpawnError::Telegram)?;
    let ntfy_adapter = build_ntfy_adapter(cfg).map_err(ListenerSpawnError::Ntfy)?;

    if telegram_adapter.is_none() && ntfy_adapter.is_none() {
        info!(
            "listeners: neither [notifications.telegram] nor [notifications.ntfy] configured; \
             no listener loops will spawn"
        );
        return Ok(ListenerHandles::disabled());
    }

    let pool = foundation.db.pool().clone();

    // Reconnect signal shared with the ntfy listener so an ntfy
    // /subscribe or /remove refreshes its SSE topic set immediately.
    let ntfy_reconnect = Arc::new(Notify::new());

    // CommandHandler is shared between both listeners — it owns the
    // adapter clones used for replies (Telegram replies via Telegram,
    // ntfy replies via ntfy). Attach the engine readers so live data
    // flows into the read-side commands.
    let handler = Arc::new(
        CommandHandler::new(pool.clone(), telegram_adapter.clone(), ntfy_adapter.clone())
            .with_engines(
                engines.pplns.clone().map(Arc::new),
                Some(Arc::new(engines.group_solo.clone())),
            )
            .with_ntfy_reconnect(ntfy_reconnect.clone()),
    );

    let telegram_shutdown = telegram_adapter.as_ref().map(|_| {
        let bot_token = cfg
            .notifications
            .telegram
            .as_ref()
            .expect("telegram adapter present implies cfg present")
            .bot_token
            .clone();
        info!("listeners.telegram: long-poll loop spawning");
        spawn_telegram_listener(TelegramListenerConfig::new(bot_token), handler.clone())
    });

    let ntfy_shutdown = ntfy_adapter.as_ref().map(|_| {
        let ntfy_cfg = cfg
            .notifications
            .ntfy
            .as_ref()
            .expect("ntfy adapter present implies cfg present");
        let topic_prefix = ntfy_cfg
            .topic_prefix
            .clone()
            .unwrap_or_else(|| DEFAULT_NTFY_TOPIC_PREFIX.to_string());
        let mut listener_cfg = NtfyListenerConfig::new(ntfy_cfg.server_url.clone(), topic_prefix);
        listener_cfg.access_token = ntfy_cfg.access_token.clone();
        info!(
            server_url = %ntfy_cfg.server_url,
            "listeners.ntfy: SSE loop spawning"
        );
        spawn_ntfy_listener(
            listener_cfg,
            pool.clone(),
            handler.clone(),
            ntfy_reconnect.clone(),
        )
    });

    let chat_languages = handler.chat_languages();

    Ok(ListenerHandles {
        inner: Some(Inner {
            telegram_adapter,
            ntfy_adapter,
            telegram_shutdown,
            ntfy_shutdown,
            chat_languages,
        }),
    })
}

fn build_telegram_adapter(cfg: &AppConfig) -> Result<Option<Arc<TelegramAdapter>>, AdapterError> {
    let Some(tg_cfg) = cfg.notifications.telegram.as_ref() else {
        return Ok(None);
    };
    let adapter = TelegramAdapter::new(AdapterTelegramConfig {
        bot_token: tg_cfg.bot_token.clone(),
    })?;
    info!("listeners.telegram: adapter ready");
    Ok(Some(Arc::new(adapter)))
}

fn build_ntfy_adapter(cfg: &AppConfig) -> Result<Option<Arc<NtfyAdapter>>, AdapterError> {
    let Some(nt_cfg) = cfg.notifications.ntfy.as_ref() else {
        return Ok(None);
    };
    let topic_prefix = nt_cfg
        .topic_prefix
        .clone()
        .unwrap_or_else(|| DEFAULT_NTFY_TOPIC_PREFIX.to_string());
    let adapter = NtfyAdapter::new(AdapterNtfyConfig {
        server_url: nt_cfg.server_url.clone(),
        access_token: nt_cfg.access_token.clone(),
        topic_prefix,
    })?;
    info!(
        server_url = %nt_cfg.server_url,
        "listeners.ntfy: adapter ready"
    );
    Ok(Some(Arc::new(adapter)))
}
