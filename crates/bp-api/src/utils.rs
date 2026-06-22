// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-controller helpers — kept here so multiple controllers can
//! share the same wire-shape transforms (email masking, etc.) without
//! drifting per-file.

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
}
