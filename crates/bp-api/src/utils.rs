// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-controller helpers — kept here so multiple controllers can
//! share the same wire-shape transforms (email masking, etc.) without
//! drifting per-file.

/// Mask an email for over-the-wire exposure: `alice@gmail.com` →
/// `a***@g***.com`. Malformed input collapses to `***`.
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

// ─── Member pseudonymisation ───────────────────────────────────────
//
// The group detail endpoints open on a group id alone, so a full member
// address there would make the id a scraper key for every member's payouts.

/// Opaque, stable per-(group, member) id. Deterministic so every detail
/// endpoint produces the same id for the same member (the UI joins on it), and
/// one-way + group-scoped so it reveals neither the address nor cross-group
/// membership.
pub(crate) fn member_id(group_id: uuid::Uuid, address: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(group_id.as_bytes());
    h.update([0u8]); // domain-separate the two fields
    h.update(address.as_bytes());
    hex::encode(&h.finalize()[..8]) // 64-bit → collision-free within a group
}

/// Masked labels for a group's members: last-5 like the UI, widened to last-9
/// for members whose labels would collide, so two rows never look identical.
pub(crate) fn build_member_labels(
    addresses: &[String],
) -> std::collections::HashMap<String, String> {
    let mut base_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for a in addresses {
        *base_counts.entry(bp_common::short_address(a)).or_insert(0) += 1;
    }
    let mut out = std::collections::HashMap::with_capacity(addresses.len());
    for a in addresses {
        let base = bp_common::short_address(a);
        let label = if base_counts.get(&base).copied().unwrap_or(0) > 1 {
            bp_common::short_address_with_tail(a, 9)
        } else {
            base
        };
        out.insert(a.clone(), label);
    }
    out
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
    fn member_id_is_stable_group_scoped_and_opaque() {
        let g1 = uuid::Uuid::from_u128(1);
        let g2 = uuid::Uuid::from_u128(2);
        let a = "bc1qsomeaddressaaaa";
        // Deterministic.
        assert_eq!(member_id(g1, a), member_id(g1, a));
        // Group-scoped: same address, different group → different id.
        assert_ne!(member_id(g1, a), member_id(g2, a));
        // Different address → different id.
        assert_ne!(member_id(g1, a), member_id(g1, "bc1qsomeaddressbbbb"));
        // Opaque: doesn't leak the address, fixed 16-hex width.
        let id = member_id(g1, a);
        assert_eq!(id.len(), 16);
        // Pinned: the blitzpool-ui sidecar recomputes this id, so a change of
        // the algorithm must not pass silently.
        assert_eq!(id, "0fffe6b3af2a8384");
        assert!(!id.contains("address"));
    }

    #[test]
    fn build_member_labels_disambiguates_collisions() {
        // Same first-4 ("bc1q") AND same last-5 ("12345") → base labels collide
        // → both widened so two rows never render identically.
        let a = "bc1qAAAAAAAAA12345".to_string();
        let b = "bc1qBBBBBBBBB12345".to_string();
        let labels = build_member_labels(&[a.clone(), b.clone()]);
        assert_eq!(bp_common::short_address(&a), bp_common::short_address(&b)); // base collides
        assert_ne!(labels[&a], labels[&b], "colliding labels must be widened");
        // A non-colliding address keeps the short last-5 label.
        let c = "bc1qCCCCCCCCCC99999".to_string();
        let labels2 = build_member_labels(&[a, c.clone()]);
        assert_eq!(labels2[&c], bp_common::short_address(&c));
    }
}
