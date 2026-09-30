// SPDX-License-Identifier: AGPL-3.0-or-later

//! How an identity is shortened for display.
//!
//! One rule: the first four characters, `...`, the last five. The pool API
//! (group member labels), the notification bot and the UI all show an identity
//! this way; on the Rust side this is the only implementation.
//!
//! The UI's twin is `formatBtcAddress` in blitzpool-ui
//! (`src/app/shared/address-format.ts`). TypeScript cannot call this, so the
//! two are pinned to the same test vectors instead: change both or neither.
//!
//! The rule does not look at what it shortens, on purpose. Every identity is
//! cut the same way, so none shows more of itself than another.

/// First 4 + `...` + last 5, trimmed; unchanged when too short to shorten.
pub fn short_address(address: &str) -> String {
    short_address_with_tail(address, 5)
}

/// [`short_address`] with a longer tail, for the one caller that widens
/// labels which would otherwise collide (group member labels).
pub fn short_address_with_tail(address: &str, tail: usize) -> String {
    let a = address.trim();
    let n = a.chars().count();
    if n <= 4 + tail {
        return a.to_string();
    }
    let first: String = a.chars().take(4).collect();
    let last: String = a.chars().skip(n - tail).collect();
    format!("{first}...{last}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared vectors. blitzpool-ui's `address-format.spec.ts` asserts the
    /// same inputs and outputs for `formatBtcAddress`.
    #[test]
    fn short_address_matches_the_shared_vectors() {
        for (input, want) in [
            ("bc1q1234567890abcdefxyz", "bc1q...efxyz"),
            ("bc1qxyzabcdefghijklmnop9k2p4", "bc1q...9k2p4"),
            ("  bc1q1234567890abcdefxyz  ", "bc1q...efxyz"),
            ("1234567890", "1234...67890"),
            // 9 characters or fewer: nothing to hide, returned as is.
            ("123456789", "123456789"),
            ("abc", "abc"),
            ("", ""),
        ] {
            assert_eq!(short_address(input), want, "{input:?}");
        }
    }

    #[test]
    fn a_wider_tail_keeps_more_and_never_the_middle() {
        let a = "bc1qxyzabcdefghijklmnop9k2p4";
        assert_eq!(short_address_with_tail(a, 9), "bc1q...mnop9k2p4");
        assert_eq!(short_address_with_tail("bc1qab", 5), "bc1qab");
        assert!(!short_address(a).contains("xyzabc"));
    }
}
