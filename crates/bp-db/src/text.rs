// SPDX-License-Identifier: AGPL-3.0-or-later

//! Miner-supplied text bound for Postgres.

use std::borrow::Cow;

/// `s` as a Postgres text column accepts it. Text rejects the NUL character,
/// which a worker name or user agent from a miner can carry, and one such
/// value fails the whole bulk statement it rides in; it becomes U+FFFD.
pub fn pg_text(s: &str) -> Cow<'_, str> {
    if s.contains('\0') {
        Cow::Owned(s.replace('\0', "\u{FFFD}"))
    } else {
        Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_nul_is_replaced_and_clean_text_is_not_copied() {
        assert!(matches!(pg_text("rig-1 ✓"), Cow::Borrowed("rig-1 ✓")));
        assert_eq!(pg_text("rig\0x\0"), "rig\u{FFFD}x\u{FFFD}");
    }
}
