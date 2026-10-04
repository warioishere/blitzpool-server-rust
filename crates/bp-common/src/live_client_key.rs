// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key schema of the per-session live hashes in Redis, here so readers need not
//! depend on the writer. The prefix stays outside the backup allowlist: a `RESTORE`
//! recreates keys without TTL, i.e. immortal dead sessions. Keys can be evicted any
//! time, so missing means "no live data" and must never be written back as a value.

/// Common prefix of every per-session live hash.
pub const CLIENT_LIVE_PREFIX: &str = "client:live:";

/// Separator between `address` / `worker` / `session_id`; the unit separator
/// cannot appear in a Bitcoin address.
pub const KEY_SEP: char = '\u{1f}';

/// Hash field: live hashrate in H/s. May be the ONLY field present: the
/// watchdog's write can recreate an expired key with just this field.
pub const F_HASH_RATE: &str = "hash_rate";
/// Hash field: latest vardiff target observed on an accepted share.
pub const F_CURRENT_DIFFICULTY: &str = "current_difficulty";
/// Hash field: channel count of the session's freshest share.
pub const F_CHANNEL_COUNT: &str = "channel_count";
/// Hash field: per-session best share difficulty, max-merged within the key's
/// life and reset by eviction. Nothing durable reads it; the all-time best in
/// `address_settings_entity` is the one to trust.
pub const F_BEST_DIFFICULTY: &str = "best_difficulty";
/// Hash field: epoch-ms timestamp of the freshest accepted share.
pub const F_UPDATED_AT_MS: &str = "updated_at_ms";

/// Anything that identifies one mining session, so the key is built in one
/// place from whatever a reader already holds.
pub trait SessionKey {
    fn address(&self) -> &str;
    fn worker(&self) -> &str;
    fn session_id(&self) -> &str;
}

impl SessionKey for (&str, &str, &str) {
    fn address(&self) -> &str {
        self.0
    }
    fn worker(&self) -> &str {
        self.1
    }
    fn session_id(&self) -> &str {
        self.2
    }
}

/// The live-hash key of any [`SessionKey`].
pub fn key_of(s: &impl SessionKey) -> String {
    client_live_key(s.address(), s.worker(), s.session_id())
}

/// Key of one session's live hash.
pub fn client_live_key(address: &str, worker: &str, session_id: &str) -> String {
    let mut key = String::with_capacity(
        CLIENT_LIVE_PREFIX.len()
            + address.len()
            + worker.len()
            + session_id.len()
            + 2 * KEY_SEP.len_utf8(),
    );
    key.push_str(CLIENT_LIVE_PREFIX);
    key.push_str(address);
    key.push(KEY_SEP);
    key.push_str(worker);
    key.push(KEY_SEP);
    key.push_str(session_id);
    key
}

/// `SCAN MATCH` pattern covering every live hash.
pub const SCAN_PATTERN_ALL: &str = "client:live:*";

/// `SCAN MATCH` pattern covering one address's live hashes. The address
/// is glob-escaped so no input string can act as a wildcard.
pub fn scan_pattern_for_address(address: &str) -> String {
    let mut pat = String::with_capacity(CLIENT_LIVE_PREFIX.len() + address.len() + 2);
    pat.push_str(CLIENT_LIVE_PREFIX);
    for c in address.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            pat.push('\\');
        }
        pat.push(c);
    }
    pat.push(KEY_SEP);
    pat.push('*');
    pat
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins the byte layout every reader and SCAN pattern parses against.
    #[test]
    fn key_layout_is_prefix_and_unit_separated_triple() {
        assert_eq!(
            client_live_key("bc1qaddr", "rig-a", "ab12cd34"),
            "client:live:bc1qaddr\u{1f}rig-a\u{1f}ab12cd34"
        );
    }

    #[test]
    fn prefix_is_outside_the_backup_allowlist() {
        assert!(!CLIENT_LIVE_PREFIX.starts_with("pplns:"));
        assert!(!CLIENT_LIVE_PREFIX.starts_with("groupsolo:"));
    }

    #[test]
    fn address_pattern_matches_only_that_address() {
        assert_eq!(
            scan_pattern_for_address("bc1qaddr"),
            "client:live:bc1qaddr\u{1f}*"
        );
        // Without the trailing separator, address "bc1qa" would match
        // "bc1qaddr"'s keys too.
        assert!(scan_pattern_for_address("bc1qa").ends_with("bc1qa\u{1f}*"));
    }

    #[test]
    fn address_pattern_escapes_glob_metacharacters() {
        assert_eq!(
            scan_pattern_for_address("a*b?c[d]e\\f"),
            "client:live:a\\*b\\?c\\[d\\]e\\\\f\u{1f}*"
        );
    }
}
