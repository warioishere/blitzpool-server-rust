// SPDX-License-Identifier: AGPL-3.0-or-later

//! SMTP adapter — sends `template::EmailContent` triples via `lettre`.

use lettre::message::header::{ContentType, Header, HeaderName, HeaderValue};
use lettre::message::{Message, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::AsyncTransport;
use lettre::Tokio1Executor;

use super::error::{AdapterError, AdapterResult};
use crate::template::EmailContent;

// Custom transactional-email headers — lettre's `Header` trait requires
// one type per distinct header-name so we instantiate four trivial
// wrappers via a macro.
macro_rules! email_header {
    ($ty:ident, $name:literal) => {
        #[derive(Clone)]
        struct $ty(String);

        impl Header for $ty {
            fn name() -> HeaderName {
                HeaderName::new_from_ascii_str($name)
            }
            fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                Ok(Self(s.to_string()))
            }
            fn display(&self) -> HeaderValue {
                HeaderValue::new(Self::name(), self.0.clone())
            }
        }
    };
}

email_header!(ListUnsubscribe, "List-Unsubscribe");
email_header!(ListUnsubscribePost, "List-Unsubscribe-Post");
email_header!(AutoSubmitted, "Auto-Submitted");
email_header!(Precedence, "Precedence");

/// Configuration parsed from `SMTP_*` env vars at startup. `host` /
/// `user` / `pass` / `from` are required to enable sending; `reply_to`
/// and `unsubscribe_mailto` default to `from` when unset.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub user: String,
    pub pass: String,
    pub from: String,
    pub reply_to: Option<String>,
    pub unsubscribe_mailto: Option<String>,
}

/// SMTP send adapter — attaches `List-Unsubscribe` /
/// `Auto-Submitted` / `Precedence` headers on every message so
/// Gmail / Outlook keep us out of the bulk-folder.
pub struct SmtpAdapter {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    reply_to: String,
    unsubscribe_mailto: String,
}

impl SmtpAdapter {
    /// Build the adapter — fails on bad config (unparseable from-address,
    /// invalid host). Returns `Err(Config(...))` rather than panicking
    /// so the caller can disable the email pathway and keep the rest of
    /// the pool running.
    pub fn new(config: SmtpConfig) -> AdapterResult<Self> {
        let builder = if config.secure {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|e| AdapterError::Config(format!("smtp relay: {e}")))?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| AdapterError::Config(format!("smtp starttls relay: {e}")))?
        };
        let transport = builder
            .port(config.port)
            .credentials(Credentials::new(config.user, config.pass))
            .build();

        let reply_to = config.reply_to.unwrap_or_else(|| config.from.clone());
        let unsubscribe_mailto = config
            .unsubscribe_mailto
            .unwrap_or_else(|| config.from.clone());

        Ok(Self {
            transport,
            from: config.from,
            reply_to,
            unsubscribe_mailto,
        })
    }

    /// Build the lettre [`Message`] and dispatch it. Returns the same
    /// error variants for transport / auth / server failures so the
    /// dispatcher can decide whether to retry or log-and-drop.
    pub async fn send_email(&self, to: &str, content: &EmailContent) -> AdapterResult<()> {
        let from = self
            .from
            .parse()
            .map_err(|e| AdapterError::Config(format!("from-address parse: {e}")))?;
        let reply_to = self
            .reply_to
            .parse()
            .map_err(|e| AdapterError::Config(format!("reply-to parse: {e}")))?;
        let to_addr = to
            .parse()
            .map_err(|e| AdapterError::Config(format!("to-address parse: {e}")))?;

        let mut builder = Message::builder()
            .from(from)
            .reply_to(reply_to)
            .to(to_addr)
            .subject(&content.subject);

        // 4 transactional-email headers for deliverability.
        let unsubscribe_value = format!("<mailto:{}>", self.unsubscribe_mailto);
        builder = builder
            .header(ListUnsubscribe(unsubscribe_value))
            .header(ListUnsubscribePost(
                "List-Unsubscribe=One-Click".to_string(),
            ))
            .header(AutoSubmitted("auto-generated".to_string()))
            .header(Precedence("list".to_string()));

        let email = builder
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(content.text.clone()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(content.html.clone()),
                    ),
            )
            .map_err(|e| AdapterError::Config(format!("build email: {e}")))?;

        self.transport.send(email).await.map_err(map_smtp_error)?;
        Ok(())
    }
}

fn map_smtp_error(err: lettre::transport::smtp::Error) -> AdapterError {
    // lettre lumps a lot into one error type; bucket by which kind
    // of recovery the dispatcher can plausibly take.
    let s = err.to_string();
    if err.is_client() || err.is_response() {
        AdapterError::Auth(s)
    } else if err.is_transient() || err.is_timeout() {
        AdapterError::Transport(s)
    } else {
        // `is_permanent()` and the catch-all both surface as Server.
        AdapterError::Server(s)
    }
}
