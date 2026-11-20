// SPDX-License-Identifier: AGPL-3.0-or-later

//! Miner user-agent normalisation, shared by SV1 (`mining.subscribe`) and SV2
//! (SetupConnection `vendor`) so the same firmware is recorded under the same
//! name whichever way it connects.

/// What a connection that names no usable user agent is recorded under, on
/// SV1 and SV2 alike.
pub const UNKNOWN_USER_AGENT: &str = "unknown";

/// `raw` through [`normalize_user_agent`], or [`UNKNOWN_USER_AGENT`] when it is
/// absent or normalises to nothing.
pub fn recorded_user_agent(raw: Option<&str>) -> String {
    raw.and_then(named_user_agent)
        .unwrap_or_else(|| UNKNOWN_USER_AGENT.to_string())
}

/// `raw` through [`normalize_user_agent`]; `None` when that leaves nothing,
/// which callers record as [`UNKNOWN_USER_AGENT`].
pub fn named_user_agent(raw: &str) -> Option<String> {
    let normalized = normalize_user_agent(raw);
    (!normalized.is_empty()).then_some(normalized)
}

/// First space-/`/`-/`V`-bounded token, with known firmware tags collapsed
/// (case-sensitive). Empty when there is no first token: empty input, or
/// input starting with one of the separators.
pub fn normalize_user_agent(raw: &str) -> String {
    let first_token = raw
        .split(' ')
        .next()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split('V')
        .next()
        .unwrap_or("")
        .to_string();
    if first_token.contains("bosminer") || first_token.contains("bOS") {
        "Braiins OS".to_string()
    } else if first_token.contains("cpuminer") {
        "cpuminer".to_string()
    } else {
        first_token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing user agent, an empty one and one with no first token are all
    /// recorded as unknown; anything else as its normalised form.
    #[test]
    fn recorded_user_agent_falls_back_to_unknown() {
        assert_eq!(recorded_user_agent(None), UNKNOWN_USER_AGENT);
        assert_eq!(recorded_user_agent(Some("")), UNKNOWN_USER_AGENT);
        assert_eq!(recorded_user_agent(Some("/1.0")), UNKNOWN_USER_AGENT);
        assert_eq!(recorded_user_agent(Some("bitaxe/2.1")), "bitaxe");
    }

    /// `None` exactly where [`recorded_user_agent`] falls back to unknown.
    #[test]
    fn named_user_agent_is_none_without_a_name() {
        assert_eq!(named_user_agent(""), None);
        assert_eq!(named_user_agent("/1.0"), None);
        assert_eq!(named_user_agent("bitaxe/2.1").as_deref(), Some("bitaxe"));
    }

    #[test]
    fn normalize_user_agent_strips_after_separators() {
        assert_eq!(normalize_user_agent("cgminer/4.11.1"), "cgminer");
        assert_eq!(normalize_user_agent("bfgminer 5.5.0"), "bfgminer");
        assert_eq!(normalize_user_agent("antminerV1.2.3"), "antminer");
    }

    #[test]
    fn normalize_user_agent_collapses_braiins_firmware() {
        assert_eq!(normalize_user_agent("bosminer-plus/1.0"), "Braiins OS");
        assert_eq!(normalize_user_agent("S9-bOS+/9.0"), "Braiins OS");
    }

    #[test]
    fn normalize_user_agent_collapses_cpuminer() {
        assert_eq!(normalize_user_agent("cpuminer/2.5.0"), "cpuminer");
    }
}
