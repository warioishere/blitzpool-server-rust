// SPDX-License-Identifier: AGPL-3.0-or-later

//! `NumberSuffix.to(value)` port — formats e.g. `158_000_000_000_000`
//! as `"158.00T"` (best-difficulty display).

const SUFFIXES: [&str; 11] = ["", "k", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q"];

/// Format `value` with a SI-style 1000-step suffix and 2 decimals.
///
/// - Negative / NaN inputs become `"0"`.
/// - `value < 1000` returns `"<value>.00"` (no suffix).
/// - Saturates at the largest known suffix (`Q` = quetta = 1e30).
pub fn format_number_suffix(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        return "0".to_string();
    }
    if value < 1.0 {
        return format!("{value:.2}");
    }
    let power = (value.log10() / 3.0).floor() as usize;
    let power = power.min(SUFFIXES.len() - 1);
    let scaled = value / 1000f64.powi(power as i32);
    format!("{scaled:.2}{}", SUFFIXES[power])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_returns_zero() {
        assert_eq!(format_number_suffix(-1.0), "0");
        assert_eq!(format_number_suffix(f64::NAN), "0");
    }

    #[test]
    fn small_values_unsuffixed() {
        assert_eq!(format_number_suffix(0.0), "0.00");
        assert_eq!(format_number_suffix(1.0), "1.00");
        assert_eq!(format_number_suffix(999.0), "999.00");
    }

    #[test]
    fn kilo_suffix_at_1000() {
        assert_eq!(format_number_suffix(1_000.0), "1.00k");
        assert_eq!(format_number_suffix(1_500.0), "1.50k");
        assert_eq!(format_number_suffix(999_999.0), "1000.00k");
    }

    #[test]
    fn mega_giga_tera() {
        assert_eq!(format_number_suffix(1.0e6), "1.00M");
        assert_eq!(format_number_suffix(2.5e9), "2.50G");
        assert_eq!(format_number_suffix(158.0e12), "158.00T");
    }

    #[test]
    fn saturates_at_top_suffix() {
        // 1e36 is past Q (1e30) — caller gets the Q suffix with a
        // large scaled value, not a panic.
        let s = format_number_suffix(1.0e36);
        assert!(s.ends_with('Q'));
    }
}
