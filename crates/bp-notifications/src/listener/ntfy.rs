// SPDX-License-Identifier: AGPL-3.0-or-later

//! ntfy SSE listener on `GET {server}/{topics}/sse`. The pool's own echo is
//! skipped via the `bot` tag [`crate::adapter::NtfyAdapter`] sets on every
//! outbound. The topic (minus the prefix) IS the mining address, so it
//! becomes the [`Transport::Ntfy`].

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

/// Spawn the SSE listener loop. Topics are re-read via
/// [`find_addresses_for_ntfy_listener`] on every (re)connect; `reconnect`
/// fires on an ntfy `/subscribe` or `/remove` so a new topic is picked up at
/// once instead of at the next stream break.
pub fn spawn_ntfy_listener(
    config: NtfyListenerConfig,
    pool: sqlx::PgPool,
    handler: Arc<CommandHandler>,
    reconnect: Arc<Notify>,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let client = match bp_http::client_builder().build() {
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
            let path_len: usize =
                topics.iter().map(|t| t.len()).sum::<usize>() + topics.len().saturating_sub(1);
            info!(
                target: "bp_notifications::listener::ntfy",
                topic_count = topics.len(),
                path_len,
                chunks = chunk_topics(&topics, MAX_TOPIC_PATH_LEN).len(),
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
                _ = stream_all_chunks(&client, &config, &topics, &handler) => {
                    warn!(target: "bp_notifications::listener::ntfy", "SSE stream ended, reconnecting");
                    tokio::time::sleep(Duration::from_secs(config.reconnect_backoff_seconds)).await;
                }
            }
        }
        info!(target: "bp_notifications::listener::ntfy", "listener stopped");
    });
    shutdown_tx
}

/// Longest comma-joined topic path put in one SSE URL. ntfy answers HTTP 400
/// once the path gets too long (somewhere past 14 830 characters); this sits
/// at about half that. It bounds the path, not the topic count, because
/// address lengths differ and a count-based split would drift with the mix.
const MAX_TOPIC_PATH_LEN: usize = 8_000;

/// Split `topics` so each chunk's comma-joined path stays within
/// `max_path_len`, preserving order. A single oversized topic still gets its
/// own chunk: an oversized path fails visibly, a dropped topic would not.
fn chunk_topics(topics: &[String], max_path_len: usize) -> Vec<Vec<String>> {
    let mut chunks: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut current_len = 0usize;
    for topic in topics {
        // +1 for the comma this topic needs once it is not the first.
        let added = if current.is_empty() {
            topic.len()
        } else {
            topic.len() + 1
        };
        if !current.is_empty() && current_len + added > max_path_len {
            chunks.push(std::mem::take(&mut current));
            current_len = 0;
        }
        current_len += if current.is_empty() {
            topic.len()
        } else {
            topic.len() + 1
        };
        current.push(topic.clone());
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Hold one SSE connection per chunk and return as soon as ANY of them ends,
/// so the caller's loop is the one place that refreshes the topic set.
async fn stream_all_chunks(
    client: &Client,
    config: &NtfyListenerConfig,
    topics: &[String],
    handler: &CommandHandler,
) {
    let chunks = chunk_topics(topics, MAX_TOPIC_PATH_LEN);
    let streams: Vec<_> = chunks
        .iter()
        .map(|chunk| Box::pin(stream_until_break(client, config, chunk, handler)))
        .collect();
    if streams.is_empty() {
        return;
    }
    let (_, _, _remaining) = futures::future::select_all(streams).await;
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
        // Partial chunks accumulate until `\n`; only SSE `data:` lines carry
        // the ntfy message JSON.
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
/// line. Per the SSE spec one optional space after the colon is stripped;
/// ntfy emits each event as one `data:` line, so the value is a whole object.
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
    use super::{chunk_topics, sse_data_field, MAX_TOPIC_PATH_LEN};

    /// Only `data:` lines yield a payload, with one optional space stripped.
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
        // Only the first space is framing; a second one is data.
        assert_eq!(sse_data_field("data:  x"), Some(" x"));
    }

    // ── Topic chunking ───────────────────────────────────────────────
    // ntfy accepts a 14 830-character path and rejects a 15 980 one.

    /// A topic of exactly `len` characters.
    fn topic(i: usize, len: usize) -> String {
        let seed = format!("bc1q{i:0>8}");
        let mut t = seed.clone();
        while t.len() < len {
            t.push('x');
        }
        t.truncate(len);
        t
    }

    fn path_len(chunk: &[String]) -> usize {
        chunk.iter().map(|t| t.len()).sum::<usize>() + chunk.len().saturating_sub(1)
    }

    /// Every chunk stays within the budget; counts sit above the server's
    /// failure point so the test cannot pass with chunking removed.
    #[test]
    fn every_chunk_stays_within_the_path_budget() {
        for count in [372usize, 500, 1_000] {
            let topics: Vec<String> = (0..count).map(|i| topic(i, 62)).collect();
            let unsplit = path_len(&topics);
            assert!(
                unsplit > 15_980,
                "precondition: {count} topics must exceed the length that returned 400 \
                 on the real server, got {unsplit}"
            );

            let chunks = chunk_topics(&topics, MAX_TOPIC_PATH_LEN);
            assert!(chunks.len() > 1, "{count} topics must be split at all");
            for chunk in &chunks {
                assert!(
                    path_len(chunk) <= MAX_TOPIC_PATH_LEN,
                    "{count} topics: a chunk of {} chars exceeds the {MAX_TOPIC_PATH_LEN} budget",
                    path_len(chunk)
                );
            }
        }
    }

    /// Splitting keeps every topic exactly once, in order.
    #[test]
    fn chunking_preserves_every_topic_exactly_once() {
        let topics: Vec<String> = (0..500).map(|i| topic(i, 62)).collect();
        let flattened: Vec<String> = chunk_topics(&topics, MAX_TOPIC_PATH_LEN)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(flattened, topics, "order and membership must both survive");
    }

    /// Mixed address lengths still respect the path budget.
    #[test]
    fn a_mixed_address_length_list_still_respects_the_budget() {
        let topics: Vec<String> = (0..600)
            .map(|i| topic(i, if i % 3 == 0 { 42 } else { 62 }))
            .collect();
        for chunk in chunk_topics(&topics, MAX_TOPIC_PATH_LEN) {
            assert!(path_len(&chunk) <= MAX_TOPIC_PATH_LEN);
        }
    }

    /// A list below the budget stays one chunk, one connection.
    #[test]
    fn a_short_list_is_left_as_one_chunk() {
        let topics: Vec<String> = (0..50).map(|i| topic(i, 62)).collect();
        assert_eq!(chunk_topics(&topics, MAX_TOPIC_PATH_LEN).len(), 1);
        assert!(chunk_topics(&[], MAX_TOPIC_PATH_LEN).is_empty());
    }

    /// A single topic wider than the budget gets its own chunk, never dropped.
    #[test]
    fn an_oversized_single_topic_is_kept_not_dropped() {
        let huge = topic(1, 200);
        let chunks = chunk_topics(std::slice::from_ref(&huge), 100);
        assert_eq!(chunks, vec![vec![huge]]);
    }

    /// A list past the last known-good path length is split.
    #[test]
    fn the_measured_production_list_gets_split() {
        let topics: Vec<String> = (0..358).map(|i| topic(i, 62)).collect();
        assert!(
            path_len(&topics) > 14_830,
            "precondition: past the last known-good path"
        );
        assert!(chunk_topics(&topics, MAX_TOPIC_PATH_LEN).len() >= 3);
    }
}
