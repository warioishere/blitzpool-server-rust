// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

/// Outcome of a single adapter send-attempt.
pub type AdapterResult<T> = Result<T, AdapterError>;

/// Failure modes shared by every adapter. The dispatcher pattern-matches
/// on `InvalidRecipient` to prune dead subscription rows; other
/// variants get logged and the next subscriber is tried.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Caller passed a recipient string that fails server-side
    /// validation as a permanent condition (FCM `UNREGISTERED`,
    /// Web-Push `410 Gone`, Telegram `Forbidden: bot was blocked`).
    /// Dispatcher cleans up the underlying subscription row.
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    /// Network / transport failure (DNS, TCP, TLS). Transient by
    /// default — caller retries on the next event.
    #[error("transport error: {0}")]
    Transport(String),

    /// Upstream service returned an authentication / authorization
    /// error (SMTP-AUTH refused, FCM 401, Telegram 401). Indicates
    /// stale/misconfigured credentials — surface to operator logs.
    #[error("auth error: {0}")]
    Auth(String),

    /// Server accepted the request but signalled an HTTP / SMTP error.
    /// Carries the upstream status text for diagnostics.
    #[error("server error: {0}")]
    Server(String),

    /// Local-side error setting up the message (bad From-address,
    /// malformed payload). Permanent — caller should fix config.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// JSON / JWT / Base64 encoding failure during send. Permanent;
    /// indicates a bug in the adapter, not a transient outage.
    #[error("encoding error: {0}")]
    Encoding(String),
}
