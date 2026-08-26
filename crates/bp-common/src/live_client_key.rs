// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key schema for the per-session live-state hashes in Redis.
//!
//! One hash per mining session, keyed by the same triple as the
//! `client_entity` PK (`address`, `clientName`, `sessionId`), holding the
//! fields that change on every share: hashrate, current vardiff target,
//! channel count, per-session best difficulty, last-seen timestamp. The
//! writer is `bp-session-persistence`; the key/field names live here so
//! readers (`bp-api`, `bp-notifications`, the liveness sweep) share one
//! schema without depending on the writer crate.
//!
//! Two properties of the prefix are load-bearing:
//!
//! - It is deliberately OUTSIDE the Redis-backup allowlist (`pplns:*`,
//!   `groupsolo:*` — see `bin/blitzpool/src/redis_backup.rs`). Live
//!   session state must never be captured or restored: a `RESTORE`
//!   re-materialises keys **without a TTL**, which under the prod
//!   `volatile-lru` eviction policy would resurrect dead sessions as
//!   immortal keys.
//! - Every key carries a TTL, so under `volatile-lru` any of them can be
//!   evicted at any time. A reader must treat a missing key or field as
//!   "no live data" — and must never write a value derived from that
//!   absence (a 0 hashrate, an empty session list) back to durable
//!   storage.

/// Common prefix of every per-session live hash.
pub const CLIENT_LIVE_PREFIX: &str = "client:live:";

/// Separator between the key's `address` / `worker` / `session_id`
/// components. Same unit-separator convention as the `device:live:*`
/// hash fields: it cannot appear in a Bitcoin address, and worker /
/// session names that carry one were mangled long before they got here.
pub const KEY_SEP: char = '\u{1f}';

/// Hash field: live hashrate in H/s (2-sample moving average, written by
/// the sampler every 60 s). May be the ONLY field present — a share can
/// land after the key expired, and the sampler's write recreates the key
/// with just this field.
pub const F_HASH_RATE: &str = "hash_rate";
/// Hash field: latest vardiff target observed on an accepted share.
pub const F_CURRENT_DIFFICULTY: &str = "current_difficulty";
/// Hash field: channel count of the session's freshest share.
pub const F_CHANNEL_COUNT: &str = "channel_count";
/// Hash field: per-session best share difficulty. Monotone — the writer
/// max-merges against the stored value, mirroring the `GREATEST` the
/// `client_entity` column gets.
pub const F_BEST_DIFFICULTY: &str = "best_difficulty";
/// Hash field: epoch-ms timestamp of the freshest accepted share.
pub const F_UPDATED_AT_MS: &str = "updated_at_ms";

/// Anything that identifies one mining session. The live-hash key is
/// this triple, and it was being rebuilt by hand at seven call sites
/// across three crates — a fourth component or a normalisation step
/// would have had to be found in all of them, which is the drift shape
/// this codebase is most prone to. Implemented for `bp_db`'s row types
/// and for a bare triple, so every reader passes what it already has.
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
/// is glob-escaped: real Bitcoin addresses are alphanumeric, but this
/// helper must not turn a hostile string into a wildcard.
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

    // The exact byte layout is pinned: the backup allowlist exclusion,
    // the SCAN patterns, and every reader parse against it.
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
