// SPDX-License-Identifier: AGPL-3.0-or-later

/// Rendered email: subject plus HTML and plaintext bodies, kept apart from
/// the recipient so templates are testable without a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailContent {
    pub subject: String,
    pub html: String,
    pub text: String,
}
