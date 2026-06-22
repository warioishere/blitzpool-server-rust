// SPDX-License-Identifier: AGPL-3.0-or-later

/// Rendered email — subject line plus HTML and plaintext bodies.
///
/// The adapter layer (SMTP / push) consumes one of these and a
/// recipient address. The triple is explicit so templates can be
/// unit-tested independently of any transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailContent {
    pub subject: String,
    pub html: String,
    pub text: String,
}
