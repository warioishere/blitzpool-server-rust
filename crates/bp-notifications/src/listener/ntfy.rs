// SPDX-License-Identifier: AGPL-3.0-or-later

//! ntfy SSE listener.
//!
//! Subscribes to `GET {server}/{topics}/sse` (Server-Sent Events).
//! Each message-event JSON carries `topic` + `message` + `tags`. The
//! pool's own echo is ignored by checking `tags` for `"bot"` (the
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

/// Longest comma-joined topic path put in one SSE URL.
///
/// ntfy answers **HTTP 400** once the path gets long enough: the server
/// accepts a 14 830-character path and rejects a 15 980-character one. The
/// budget sits at roughly half the known-good value, since the topic list
/// grows with the miner count.
///
/// It bounds the PATH, not the topic count, because addresses differ in length
/// (42 characters for a bech32 v0, 62 for the longest seen) and a count-based
/// split would drift with the address mix.
const MAX_TOPIC_PATH_LEN: usize = 8_000;

/// Split `topics` so each chunk's comma-joined path stays within
/// `max_path_len`. Order is preserved; no topic is dropped or duplicated.
///
/// A single topic longer than the budget still gets its own chunk: an
/// oversized path fails visibly, a dropped topic would not. ntfy's own topic
/// grammar (`[-_A-Za-z0-9]{1,64}`) makes it unreachable in practice.
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

/// Hold one SSE connection per chunk and return as soon as ANY of them ends.
///
/// Any break re-reads the topic list and rebuilds every chunk, so there is
/// one place that decides when the topic set is refreshed. With a handful of
/// chunks that is cheap.
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
        // ntfy's `/sse` endpoint is Server-Sent Events: each event is a
        // `data: {json}` line, framed by `event:` / `id:` / comment (`:`) /
        // blank separator lines. Only the `data:` field carries the ntfy
        // message JSON; the rest is skipped. Partial chunks accumulate
        // until `\n`.
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
    use super::{chunk_topics, sse_data_field, MAX_TOPIC_PATH_LEN};

    /// Only `data:` lines carry the ntfy message JSON; the SSE framing
    /// (`event:` / `id:` / comments / blanks) must be skipped, and the one
    /// optional space after `data:` stripped.
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

    // ── Topic chunking ───────────────────────────────────────────────
    //
    // ntfy answers 400 once one comma-joined path is long enough: 14 830
    // characters are accepted, 15 980 are not.

    /// A realistic topic: the longest address shape seen is 62 chars.
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

    /// ⚠️ Every count here is above the server's failure point; a count just
    /// under it would pass with the chunking removed and prove nothing.
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

    /// Splitting must not lose or duplicate a topic: a dropped one is a miner
    /// whose commands silently stop arriving.
    #[test]
    fn chunking_preserves_every_topic_exactly_once() {
        let topics: Vec<String> = (0..500).map(|i| topic(i, 62)).collect();
        let flattened: Vec<String> = chunk_topics(&topics, MAX_TOPIC_PATH_LEN)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(flattened, topics, "order and membership must both survive");
    }

    /// Mixed lengths, because a count-based split would drift with the address
    /// mix: bech32 v0 is 42 characters, the longest seen is 62.
    #[test]
    fn a_mixed_address_length_list_still_respects_the_budget() {
        let topics: Vec<String> = (0..600)
            .map(|i| topic(i, if i % 3 == 0 { 42 } else { 62 }))
            .collect();
        for chunk in chunk_topics(&topics, MAX_TOPIC_PATH_LEN) {
            assert!(path_len(&chunk) <= MAX_TOPIC_PATH_LEN);
        }
    }

    /// Below the budget a list stays one chunk, one connection; splitting a
    /// small pool would pay connection overhead for nothing.
    #[test]
    fn a_short_list_is_left_as_one_chunk() {
        let topics: Vec<String> = (0..50).map(|i| topic(i, 62)).collect();
        assert_eq!(chunk_topics(&topics, MAX_TOPIC_PATH_LEN).len(), 1);
        assert!(chunk_topics(&[], MAX_TOPIC_PATH_LEN).is_empty());
    }

    /// A single topic wider than the budget gets its own chunk rather than
    /// being dropped. Unreachable under ntfy's own grammar
    /// (`[-_A-Za-z0-9]{1,64}`), asserted so the loop cannot silently discard.
    #[test]
    fn an_oversized_single_topic_is_kept_not_dropped() {
        let huge = topic(1, 200);
        let chunks = chunk_topics(std::slice::from_ref(&huge), 100);
        assert_eq!(chunks, vec![vec![huge]]);
    }

    /// 358 topics of the longest observed shape exceed what the server
    /// accepts and must come out as more than one chunk.
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
