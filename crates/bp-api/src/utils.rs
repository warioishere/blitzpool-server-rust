// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-controller helpers — kept here so multiple controllers can
//! share the same wire-shape transforms (email masking, etc.) without
//! drifting per-file.

use bp_common::{AddressId, InvalidAddressError};

/// Normalize a user-supplied Bitcoin address and parse it into an [`AddressId`].
///
/// The single source of truth for the "normalize (trim + lowercase bech32) →
/// validate shape" step every address-taking endpoint runs, so the controllers
/// don't each re-spell `AddressId::new(normalize_btc_address(x))` (and can't
/// drift on whether they normalize first).
pub fn normalized_address_id(raw: &str) -> Result<AddressId, InvalidAddressError> {
    AddressId::new(bp_mining_job::normalize_btc_address(raw))
}

/// Mask an email for over-the-wire exposure.
///
/// Format: `<first-char-local>***@<first-char-SLD>***<tld-and-below>`.
///
/// - `alice@gmail.com` → `a***@g***.com`
/// - `bob@sub.example.co.uk` → `b***@s***.example.co.uk`
/// - empty string → empty string
/// - missing `@` → `***`
/// - `@x.com` / `a@` (empty local or domain) → `***`
/// - `a@nodomain` (no dot in domain) → `a***@***`
pub fn mask_email(email: &str) -> String {
    if email.is_empty() {
        return String::new();
    }
    let Some(at_idx) = email.find('@') else {
        return "***".to_owned();
    };
    if at_idx == 0 || at_idx == email.len() - 1 {
        return "***".to_owned();
    }
    let local = &email[..at_idx];
    let domain = &email[at_idx + 1..];
    let local_head = local.chars().next().expect("at_idx > 0 ensures non-empty");
    let Some(dot_idx) = domain.find('.') else {
        return format!("{local_head}***@***");
    };
    if dot_idx == 0 {
        return format!("{local_head}***@***");
    }
    let domain_head = domain
        .chars()
        .next()
        .expect("dot_idx > 0 ensures non-empty");
    let tld_and_below = &domain[dot_idx..]; // includes the leading dot
    format!("{local_head}***@{domain_head}***{tld_and_below}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_simple_email() {
        assert_eq!(mask_email("alice@gmail.com"), "a***@g***.com");
    }

    #[test]
    fn masks_multi_segment_domain() {
        assert_eq!(
            mask_email("bob@sub.example.co.uk"),
            "b***@s***.example.co.uk"
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(mask_email(""), "");
    }

    #[test]
    fn no_at_sign() {
        assert_eq!(mask_email("notanemail"), "***");
    }

    #[test]
    fn empty_local() {
        assert_eq!(mask_email("@gmail.com"), "***");
    }

    #[test]
    fn empty_domain() {
        assert_eq!(mask_email("alice@"), "***");
    }

    #[test]
    fn domain_without_dot() {
        assert_eq!(mask_email("alice@nodomain"), "a***@***");
    }

    #[test]
    fn normalized_address_id_trims_and_lowercases_bech32() {
        let a = normalized_address_id("  BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4  ")
            .expect("valid bech32");
        assert_eq!(a.as_str(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn normalized_address_id_rejects_empty() {
        assert!(normalized_address_id("   ").is_err());
    }
}
