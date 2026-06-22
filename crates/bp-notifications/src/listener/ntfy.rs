// SPDX-License-Identifier: AGPL-3.0-or-later

//! ntfy SSE listener.
//!
//! Subscribes to `GET {server}/{topics}/sse` (Server-Sent Events).
//! Each message-event JSON carries `topic` + `message` + `tags`. We
//! ignore our own echo by checking `tags` for `"bot"` (the
//! [`crate::adapter::NtfyAdapter`] sets `Tags: bot` on every outbound).
//!
//! The topic IS the user's mining address (after stripping the
//! deployment-wide prefix), so the originating [`Transport::Ntfy`] is
//! built directly from it.

use std::sync::Arc;
use std::time::Duration;

use bp_common::AddressId;
use bp_db::find_addresses_for_ntfy_listener;
use futures::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

use crate::command::{parse_command, CommandHandler, Transport};

#[derive(Debug, Clone)]
pub struct NtfyListenerConfig {
    /// Base URL — e.g. `https://ntfy.sh` or self-hosted instance.
    pub server_url: String,
    /// Optional Bearer for self-hosted instances that require auth.
    pub access_token: Option<String>,
    /// Topic prefix prepended to the address — same value the
    /// [`crate::adapter::NtfyAdapter`] uses (must match exactly so
    /// outbound + inbound topics align).
    pub topic_prefix: String,
    /// Backoff (seconds) after a stream interrupt before reconnecting.
    pub reconnect_backoff_seconds: u64,
}

impl NtfyListenerConfig {
    pub fn new(server_url: String, topic_prefix: String) -> Self {
        Self {
            server_url,
            access_token: None,
            topic_prefix,
            reconnect_backoff_seconds: 10,
        }
    }
}

/// Spawn the SSE listener loop. The topic set is read fresh from the DB
/// on every (re)connect via [`find_addresses_for_ntfy_listener`] (active
/// clients ∪ active ntfy subscriptions). `reconnect` lets the command
/// handler force an immediate reconnect — it fires on an ntfy
/// `/subscribe` or `/remove` so a newly subscribed topic is picked up at
/// once instead of waiting for the next stream break.
pub fn spawn_ntfy_listener(
    config: NtfyListenerConfig,
    pool: sqlx::PgPool,
    handler: Arc<CommandHandler>,
    reconnect: Arc<Notify>,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let client = match Client::builder().build() {
            Ok(c) => c,
            Err(e) => {
                warn!(target: "bp_notifications::listener::ntfy", error = %e, "client build failed");
                return;
            }
        };

        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            let topics = match find_addresses_for_ntfy_listener(&pool).await {
                Ok(addrs) => {
                    let mut joined: Vec<String> = addrs
                        .into_iter()
                        .map(|a| format!("{}{}", config.topic_prefix, a.as_str()))
                        .collect();
                    joined.sort();
                    joined.dedup();
                    joined
                }
                Err(e) => {
                    warn!(target: "bp_notifications::listener::ntfy", error = %e, "topic bootstrap");
                    tokio::time::sleep(Duration::from_secs(config.reconnect_backoff_seconds)).await;
                    continue;
                }
            };
            if topics.is_empty() {
                debug!(target: "bp_notifications::listener::ntfy", "no topics yet; sleeping before retry");
                tokio::time::sleep(Duration::from_secs(config.reconnect_backoff_seconds)).await;
                continue;
            }
            info!(
                target: "bp_notifications::listener::ntfy",
                topic_count = topics.len(),
                "SSE stream connecting"
            );

            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = reconnect.notified() => {
                    // A subscription changed — drop the current stream and
                    // loop straight back to re-read topics + reconnect (no
                    // backoff; this is an intentional, immediate refresh).
                    info!(target: "bp_notifications::listener::ntfy", "reconnect signal — refreshing topics");
                }
                _ = stream_until_break(&client, &config, &topics, &handler) => {
                    warn!(target: "bp_notifications::listener::ntfy", "SSE stream ended, reconnecting");
                    tokio::time::sleep(Duration::from_secs(config.reconnect_backoff_seconds)).await;
                }
            }
        }
        info!(target: "bp_notifications::listener::ntfy", "listener stopped");
    });
    shutdown_tx
}

async fn stream_until_break(
    client: &Client,
    config: &NtfyListenerConfig,
    topics: &[String],
    handler: &CommandHandler,
) {
    let joined = topics.join(",");
    let url = format!("{}/{}/sse", config.server_url.trim_end_matches('/'), joined);
    let mut req = client.get(&url);
    if let Some(token) = &config.access_token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let response = match req.send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            warn!(target: "bp_notifications::listener::ntfy", code = r.status().as_u16(), "SSE non-2xx");
            return;
        }
        Err(e) => {
            warn!(target: "bp_notifications::listener::ntfy", error = %e, "SSE request");
            return;
        }
    };
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "bp_notifications::listener::ntfy", error = %e, "SSE chunk");
                break;
            }
        };
        // ntfy's `/sse` endpoint is Server-Sent Events: each event is a
        // `data: {json}` line, framed by `event:` / `id:` / comment (`:`) /
        // blank separator lines. Only the `data:` field carries the ntfy
        // message JSON — the raw-line parser must skip the rest (the
        // EventSource client the reference impl uses does this framing for us;
        // here we do it explicitly). We accumulate partial chunks until `\n`.
        if let Ok(text) = std::str::from_utf8(&bytes) {
            buffer.push_str(text);
            while let Some(idx) = buffer.find('\n') {
                let line = buffer[..idx].to_string();
                buffer.drain(..=idx);
                let Some(payload) = sse_data_field(line.trim_end_matches('\r')) else {
                    continue;
                };
                process_event_line(handler, &config.topic_prefix, payload).await;
            }
        }
    }
}

/// Extract the JSON payload from an SSE `data:` line, or `None` for any other
/// line (`event:`, `id:`, comments starting `:`, blank separators). Per the SSE
/// spec a single optional space after the colon is stripped. ntfy emits each
/// event's JSON as one `data:` line, so the returned value is a complete object.
fn sse_data_field(line: &str) -> Option<&str> {
    let value = line.strip_prefix("data:")?;
    let value = value.strip_prefix(' ').unwrap_or(value);
    (!value.is_empty()).then_some(value)
}

async fn process_event_line(handler: &CommandHandler, topic_prefix: &str, line: &str) {
    let event: NtfyEvent = match serde_json::from_str(line) {
        Ok(e) => e,
        Err(e) => {
            debug!(target: "bp_notifications::listener::ntfy", error = %e, raw = line, "non-event line skipped");
            return;
        }
    };
    // ntfy emits keepalive `{"event":"keepalive",...}` events. Only
    // `event=="message"` carries user input.
    if event.event.as_deref() != Some("message") {
        return;
    }
    if event.tags.iter().any(|t| t.eq_ignore_ascii_case("bot")) {
        return;
    }
    let Some(topic) = event.topic else { return };
    let address_raw = match topic.strip_prefix(topic_prefix) {
        Some(rest) => rest,
        None => &topic,
    };
    let Ok(address) = AddressId::new(address_raw.to_string()) else {
        debug!(target: "bp_notifications::listener::ntfy", topic, "could not parse topic as address");
        return;
    };
    let Some(message) = event.message else { return };
    let command = parse_command(&message);
    let transport = Transport::Ntfy { address };
    handler.dispatch(&transport, &command).await;
}

#[derive(Debug, Deserialize)]
struct NtfyEvent {
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::sse_data_field;

    /// Only `data:` lines carry the ntfy message JSON; the SSE framing
    /// (`event:` / `id:` / comments / blanks) must be skipped, and the one
    /// optional space after `data:` stripped. This is the regression that made
    /// every line fail to JSON-parse (the raw line still had the `data:` prefix).
    #[test]
    fn sse_data_field_extracts_only_data_lines() {
        assert_eq!(
            sse_data_field("data: {\"event\":\"message\"}"),
            Some("{\"event\":\"message\"}")
        );
        // No space after the colon is still valid SSE.
        assert_eq!(sse_data_field("data:{\"x\":1}"), Some("{\"x\":1}"));
        // Control / framing lines carry no payload.
        assert_eq!(sse_data_field("event: message"), None);
        assert_eq!(sse_data_field("id: AbCd1234"), None);
        assert_eq!(sse_data_field(":keepalive comment"), None);
        assert_eq!(sse_data_field(""), None);
        assert_eq!(sse_data_field("data:"), None);
        // A leading space belongs to data content only after the first space is
        // consumed — a second space is preserved.
        assert_eq!(sse_data_field("data:  x"), Some(" x"));
    }
}
