// SPDX-License-Identifier: AGPL-3.0-or-later

//! Miner user-agent normalisation, shared by SV1 (`mining.subscribe`), SV2
//! (SetupConnection `vendor`) and the API downstream report so the same
//! firmware is recorded under the same name whichever way it connects.

/// First space-/`/`-/`V`-bounded token, with known firmware tags collapsed
/// (case-sensitive).
/// Empty input yields an empty string; the caller decides what to record.
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
