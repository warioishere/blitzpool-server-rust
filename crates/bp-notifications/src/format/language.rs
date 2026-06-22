// SPDX-License-Identifier: AGPL-3.0-or-later

/// Two-language enum the dispatcher uses to render messages.
/// Language preference is stored per-subscription in the database
/// and per-chat in an in-memory map; both route through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    De,
    #[default]
    En,
}

impl Language {
    /// Parse the lowercase two-letter code stored in the database.
    /// Anything other than `"de"` falls back to English.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "de" => Language::De,
            _ => Language::En,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::De => "de",
            Language::En => "en",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_de() {
        assert_eq!(Language::parse("de"), Language::De);
        assert_eq!(Language::parse("DE"), Language::De);
        assert_eq!(Language::parse("  de  "), Language::De);
    }

    #[test]
    fn unknown_falls_back_to_english() {
        assert_eq!(Language::parse("en"), Language::En);
        assert_eq!(Language::parse(""), Language::En);
        assert_eq!(Language::parse("fr"), Language::En);
    }

    #[test]
    fn round_trip_via_as_str() {
        assert_eq!(Language::parse(Language::De.as_str()), Language::De);
        assert_eq!(Language::parse(Language::En.as_str()), Language::En);
    }
}
