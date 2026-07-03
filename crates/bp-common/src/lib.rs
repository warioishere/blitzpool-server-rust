// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared primitive types — `Sats`, `AddressId`, `MiningMode`, and the narrow
//! error variants that come with them.
//!
//! Intentionally there is no `BlitzError` umbrella enum. Each crate defines its
//! own `thiserror` type for its concerns; these primitives carry only the
//! narrow errors that arise from constructing/parsing them.
//!
//! With the `sqlx` Cargo feature enabled, `Sats` / `AddressId` / `MiningMode`
//! gain `sqlx::Type` + `Decode` + `Encode` impls for Postgres so they
//! round-trip the wire format automatically (lives here rather than in
//! `bp-db` to satisfy the orphan rule).

use std::fmt;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub mod extranonce;
pub use extranonce::{ExtranonceAllocator, ExtranonceError};

#[cfg(feature = "sqlx")]
mod sqlx_impls;

// ---------------------------------------------------------------------------
// Sats
// ---------------------------------------------------------------------------

/// Satoshis. Signed because the PPLNS ledger represents debits as negative
/// balances (see `pplns_balance.balanceSats` in the PG schema). For
/// amount-only contexts where only non-negative values are valid (payout
/// amounts, share rewards), check non-negativity at the boundary; this type
/// itself does not enforce a sign.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Sats(pub i64);

impl Sats {
    pub const ZERO: Sats = Sats(0);
    /// One whole bitcoin in sats.
    pub const ONE_BTC: Sats = Sats(100_000_000);

    /// Returns the raw signed integer value.
    pub fn to_i64(self) -> i64 {
        self.0
    }

    /// Saturating addition — clamps at `i64::MAX` / `i64::MIN` instead of overflowing.
    pub fn saturating_add(self, rhs: Sats) -> Sats {
        Sats(self.0.saturating_add(rhs.0))
    }

    pub fn saturating_sub(self, rhs: Sats) -> Sats {
        Sats(self.0.saturating_sub(rhs.0))
    }

    pub fn checked_add(self, rhs: Sats) -> Option<Sats> {
        self.0.checked_add(rhs.0).map(Sats)
    }

    pub fn checked_sub(self, rhs: Sats) -> Option<Sats> {
        self.0.checked_sub(rhs.0).map(Sats)
    }

    pub fn is_negative(self) -> bool {
        self.0 < 0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn abs(self) -> Sats {
        Sats(self.0.abs())
    }
}

impl Add for Sats {
    type Output = Sats;
    fn add(self, rhs: Sats) -> Sats {
        Sats(self.0 + rhs.0)
    }
}

impl AddAssign for Sats {
    fn add_assign(&mut self, rhs: Sats) {
        self.0 += rhs.0;
    }
}

impl Sub for Sats {
    type Output = Sats;
    fn sub(self, rhs: Sats) -> Sats {
        Sats(self.0 - rhs.0)
    }
}

impl SubAssign for Sats {
    fn sub_assign(&mut self, rhs: Sats) {
        self.0 -= rhs.0;
    }
}

impl Neg for Sats {
    type Output = Sats;
    fn neg(self) -> Sats {
        Sats(-self.0)
    }
}

impl From<i64> for Sats {
    fn from(v: i64) -> Sats {
        Sats(v)
    }
}

impl From<Sats> for i64 {
    fn from(v: Sats) -> i64 {
        v.0
    }
}

impl fmt::Display for Sats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// AddressId
// ---------------------------------------------------------------------------

/// A miner's Bitcoin address as the pool uses it — round-trips between PG
/// (`varchar(62)`), API JSON, and Stratum `authorize` frames as a string.
///
/// This type only enforces *shape*: non-empty, ASCII-graphic, ≤62 chars.
/// Cryptographic validation (network check, witness version, bech32/base58
/// checksum) belongs at the I/O boundary in `bp-share` (or wherever
/// `bitcoin::Address::from_str` is called), not here.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AddressId(String);

impl AddressId {
    /// Construct from any string-like. Validates shape; does not check
    /// crypto.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidAddressError> {
        let s = s.into();
        validate_address_shape(&s)?;
        Ok(AddressId(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

fn validate_address_shape(s: &str) -> Result<(), InvalidAddressError> {
    if s.is_empty() {
        return Err(InvalidAddressError::Empty);
    }
    if s.len() > 62 {
        return Err(InvalidAddressError::TooLong(s.len()));
    }
    for (i, c) in s.bytes().enumerate() {
        // Bitcoin addresses are ASCII; reject control/whitespace/non-ASCII.
        if !c.is_ascii_graphic() {
            return Err(InvalidAddressError::InvalidChar(i));
        }
    }
    Ok(())
}

impl FromStr for AddressId {
    type Err = InvalidAddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AddressId::new(s)
    }
}

impl fmt::Display for AddressId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AddressId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum InvalidAddressError {
    #[error("address is empty")]
    Empty,
    #[error("address contains non-ASCII-graphic byte at position {0}")]
    InvalidChar(usize),
    #[error("address is too long ({0} bytes, max 62)")]
    TooLong(usize),
}

// ---------------------------------------------------------------------------
// MiningMode
// ---------------------------------------------------------------------------

/// Payout mode used for routing a miner's shares.
///
/// Wire format is kebab-case (`solo`, `pplns`, `group-solo`,
/// `blockparty`) — used directly in `GET /api/pplns/mode/:address`
/// responses and the per-mode hashrate aggregation key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiningMode {
    Solo,
    Pplns,
    GroupSolo,
    Blockparty,
}

impl MiningMode {
    pub fn as_str(self) -> &'static str {
        match self {
            MiningMode::Solo => "solo",
            MiningMode::Pplns => "pplns",
            MiningMode::GroupSolo => "group-solo",
            MiningMode::Blockparty => "blockparty",
        }
    }
}

impl FromStr for MiningMode {
    type Err = UnknownMiningModeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "solo" => Ok(MiningMode::Solo),
            "pplns" => Ok(MiningMode::Pplns),
            "group-solo" => Ok(MiningMode::GroupSolo),
            "blockparty" => Ok(MiningMode::Blockparty),
            other => Err(UnknownMiningModeError(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// StreamKind
// ---------------------------------------------------------------------------

/// Which TDP template stream — i.e. which bitcoin-core coinbase reservation —
/// a connection mines on, and through which a found block is submitted. The
/// pool runs one stream per reservation class against a single bitcoind
/// (separate IPC connections).
///
/// **Phase 2** gives every non-PPLNS payout mode its own fixed-reservation
/// stream: `Solo` (1–2 outputs), `GroupSolo` (member-count sized), and
/// `Blockparty` (member-count sized). Only `Pplns` is PPLNS-autoscaled, and
/// it serves PPLNS exclusively (it is also the default/boot stream).
///
/// [`StreamKind::for_mode`] is the **single source of truth** for the
/// mode→stream mapping. The stratum stream-selection (which template a
/// connection builds jobs from) and the block-submission routing (which TDP
/// handle a solution goes to) both consult it, so they can never disagree —
/// submitting a job to a handle that doesn't know its template_id would be an
/// invalid block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum StreamKind {
    /// PPLNS-autoscaled stream — the primary stream every connection boots on
    /// before its mode is resolved. Serves PPLNS.
    #[default]
    Pplns,
    /// Tiny fixed-reservation stream — Solo coinbases (finder + optional
    /// dev-fee = 1–2 outputs) only.
    Solo,
    /// Fixed-reservation stream sized to the max Group-Solo group (members +
    /// fee output).
    GroupSolo,
    /// Fixed-reservation stream sized to the max Blockparty (members + fee
    /// output).
    Blockparty,
}

impl StreamKind {
    /// Every non-`Pplns` stream — the fixed-reservation classes a connection
    /// can be swapped onto once its payout mode resolves at
    /// authorize/OpenChannel. Order is irrelevant (callers key a map by it).
    pub const NON_PPLNS: [StreamKind; 3] = [
        StreamKind::Solo,
        StreamKind::GroupSolo,
        StreamKind::Blockparty,
    ];

    /// Map a resolved payout mode to its template stream. Every non-PPLNS mode
    /// has its own fixed-reservation stream; PPLNS rides the autoscaled
    /// `Pplns` stream.
    pub fn for_mode(mode: MiningMode) -> Self {
        match mode {
            MiningMode::Solo => StreamKind::Solo,
            MiningMode::GroupSolo => StreamKind::GroupSolo,
            MiningMode::Blockparty => StreamKind::Blockparty,
            MiningMode::Pplns => StreamKind::Pplns,
        }
    }

    /// `true` for the primary PPLNS-autoscaled stream every connection boots on.
    pub fn is_pplns(self) -> bool {
        matches!(self, StreamKind::Pplns)
    }

    /// Stable lower-kebab label for logs + TDP stream tags.
    pub fn as_label(self) -> &'static str {
        match self {
            StreamKind::Pplns => "pplns",
            StreamKind::Solo => "solo",
            StreamKind::GroupSolo => "group-solo",
            StreamKind::Blockparty => "blockparty",
        }
    }
}

impl fmt::Display for MiningMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("unknown mining mode: {0:?}")]
pub struct UnknownMiningModeError(pub String);

// ---------------------------------------------------------------------------
// LogThrottle — rate-limit hot-path log lines
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Time-based throttle for a hot-path log line that would otherwise flood —
/// e.g. a per-accepted-share warning while Redis is unreachable, which at a
/// few thousand shares/s would bury every other log and fill disk.
///
/// [`Self::allow`] returns `Some(suppressed)` at most once per `interval_ms`,
/// where `suppressed` is the number of calls swallowed since the previous
/// allowed one (so the caller can append "… (N suppressed)"). Lock-free;
/// share it behind the same handle the hot path already holds.
#[derive(Debug)]
pub struct LogThrottle {
    interval_ms: i64,
    last_ms: AtomicI64,
    suppressed: AtomicU64,
}

impl LogThrottle {
    pub fn new(interval_ms: i64) -> Self {
        Self {
            interval_ms: interval_ms.max(0),
            last_ms: AtomicI64::new(i64::MIN),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(suppressed_since_last)` when `now_ms` is at least `interval_ms`
    /// past the last allowed call (claims the slot atomically so only one
    /// caller wins under contention); `None` otherwise, after counting this
    /// call as suppressed.
    pub fn allow(&self, now_ms: i64) -> Option<u64> {
        let last = self.last_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= self.interval_ms
            && self
                .last_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// Emit a `tracing::warn!` at most once per the [`LogThrottle`]'s window,
/// auto-appending a `suppressed` field with the count dropped since the last
/// emit. Centralises the "a Redis outage fails every share — don't flood the
/// log" idiom: pass the throttle, the timestamp, then the usual `warn!`
/// fields + message. Expands to a no-op when the window hasn't elapsed.
///
/// ```ignore
/// warn_throttled!(self.warn_throttle, ts_ms, error = %e, address, "record_share failed");
/// ```
#[macro_export]
macro_rules! warn_throttled {
    ($throttle:expr, $now_ms:expr, $($fields:tt)+) => {
        if let Some(suppressed) = $throttle.allow($now_ms) {
            ::tracing::warn!(suppressed, $($fields)+);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- StreamKind ----

    #[test]
    fn stream_kind_for_mode_maps_every_mode_to_its_own_stream() {
        assert_eq!(StreamKind::for_mode(MiningMode::Solo), StreamKind::Solo);
        assert_eq!(
            StreamKind::for_mode(MiningMode::GroupSolo),
            StreamKind::GroupSolo
        );
        assert_eq!(
            StreamKind::for_mode(MiningMode::Blockparty),
            StreamKind::Blockparty
        );
        // Only PPLNS stays on the autoscaled Default stream.
        assert_eq!(StreamKind::for_mode(MiningMode::Pplns), StreamKind::Pplns);
    }

    #[test]
    fn stream_kind_default_is_pplns_variant() {
        assert_eq!(StreamKind::default(), StreamKind::Pplns);
        assert!(StreamKind::Pplns.is_pplns());
        assert!(!StreamKind::Solo.is_pplns());
    }

    #[test]
    fn stream_kind_non_pplns_excludes_pplns_and_covers_alt_modes() {
        assert!(!StreamKind::NON_PPLNS.contains(&StreamKind::Pplns));
        assert_eq!(StreamKind::NON_PPLNS.len(), 3);
        // Every alt stream is the `for_mode` image of some non-PPLNS mode.
        for kind in StreamKind::NON_PPLNS {
            assert!(!kind.is_pplns());
        }
    }

    #[test]
    fn stream_kind_labels_are_kebab_case() {
        assert_eq!(StreamKind::Pplns.as_label(), "pplns");
        assert_eq!(StreamKind::Solo.as_label(), "solo");
        assert_eq!(StreamKind::GroupSolo.as_label(), "group-solo");
        assert_eq!(StreamKind::Blockparty.as_label(), "blockparty");
    }

    // ---- Sats ----

    #[test]
    fn sats_zero_is_default() {
        assert_eq!(Sats::default(), Sats::ZERO);
        assert_eq!(Sats::ZERO, Sats(0));
    }

    #[test]
    fn sats_one_btc_constant() {
        assert_eq!(Sats::ONE_BTC.to_i64(), 100_000_000);
    }

    #[test]
    fn sats_arithmetic() {
        assert_eq!(Sats(100) + Sats(50), Sats(150));
        assert_eq!(Sats(100) - Sats(50), Sats(50));
        assert_eq!(-Sats(100), Sats(-100));
        let mut s = Sats(10);
        s += Sats(5);
        assert_eq!(s, Sats(15));
        s -= Sats(20);
        assert_eq!(s, Sats(-5));
    }

    #[test]
    fn sats_saturating_does_not_overflow() {
        assert_eq!(Sats(i64::MAX).saturating_add(Sats(1)), Sats(i64::MAX));
        assert_eq!(Sats(i64::MIN).saturating_sub(Sats(1)), Sats(i64::MIN));
    }

    #[test]
    fn sats_checked_returns_none_on_overflow() {
        assert_eq!(Sats(i64::MAX).checked_add(Sats(1)), None);
        assert_eq!(Sats(i64::MIN).checked_sub(Sats(1)), None);
        assert_eq!(Sats(1).checked_add(Sats(1)), Some(Sats(2)));
    }

    #[test]
    fn sats_predicates() {
        assert!(Sats(-5).is_negative());
        assert!(!Sats(5).is_negative());
        assert!(Sats::ZERO.is_zero());
        assert!(!Sats(1).is_zero());
        assert_eq!(Sats(-5).abs(), Sats(5));
    }

    #[test]
    fn sats_serde_transparent() {
        let s = Sats(12345);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "12345");
        let back: Sats = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn sats_serde_handles_negative() {
        let s = Sats(-9999);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "-9999");
        let back: Sats = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn sats_display_is_plain_integer() {
        assert_eq!(format!("{}", Sats(12345)), "12345");
        assert_eq!(format!("{}", Sats(-9999)), "-9999");
    }

    // ---- AddressId ----

    #[test]
    fn address_accepts_real_examples() {
        // Bech32 P2WPKH
        AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        // Bech32m P2TR (62 chars)
        AddressId::new("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297").unwrap();
        // Legacy P2PKH
        AddressId::new("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
        // Legacy P2SH
        AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
    }

    #[test]
    fn address_rejects_empty() {
        assert_eq!(AddressId::new(""), Err(InvalidAddressError::Empty));
    }

    #[test]
    fn address_rejects_whitespace() {
        assert!(matches!(
            AddressId::new(" bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Err(InvalidAddressError::InvalidChar(0))
        ));
        assert!(matches!(
            AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n"),
            Err(InvalidAddressError::InvalidChar(_))
        ));
    }

    #[test]
    fn address_rejects_too_long() {
        let too_long = "a".repeat(63);
        assert_eq!(
            AddressId::new(&too_long),
            Err(InvalidAddressError::TooLong(63))
        );
    }

    #[test]
    fn address_serde_transparent() {
        let a = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"");
        let back: AddressId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn address_from_str_round_trip() {
        let a: AddressId = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().unwrap();
        assert_eq!(a.to_string(), "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    }

    // ---- MiningMode ----

    #[test]
    fn mining_mode_wire_format_is_kebab_case() {
        // This is load-bearing — API consumers depend on exact strings.
        assert_eq!(MiningMode::Solo.as_str(), "solo");
        assert_eq!(MiningMode::Pplns.as_str(), "pplns");
        assert_eq!(MiningMode::GroupSolo.as_str(), "group-solo");

        assert_eq!(
            serde_json::to_string(&MiningMode::Solo).unwrap(),
            "\"solo\""
        );
        assert_eq!(
            serde_json::to_string(&MiningMode::Pplns).unwrap(),
            "\"pplns\""
        );
        assert_eq!(
            serde_json::to_string(&MiningMode::GroupSolo).unwrap(),
            "\"group-solo\""
        );
    }

    #[test]
    fn mining_mode_parse() {
        assert_eq!(MiningMode::from_str("solo").unwrap(), MiningMode::Solo);
        assert_eq!(MiningMode::from_str("pplns").unwrap(), MiningMode::Pplns);
        assert_eq!(
            MiningMode::from_str("group-solo").unwrap(),
            MiningMode::GroupSolo
        );
    }

    #[test]
    fn mining_mode_parse_rejects_unknown() {
        let err = MiningMode::from_str("groupsolo").unwrap_err();
        assert_eq!(err, UnknownMiningModeError("groupsolo".to_string()));
        // Pre-kebab variants must be rejected — protect against accidental
        // schema drift.
        assert!(MiningMode::from_str("Solo").is_err());
        assert!(MiningMode::from_str("PPLNS").is_err());
        assert!(MiningMode::from_str("group_solo").is_err());
    }

    #[test]
    fn mining_mode_roundtrip() {
        for m in [MiningMode::Solo, MiningMode::Pplns, MiningMode::GroupSolo] {
            assert_eq!(MiningMode::from_str(m.as_str()).unwrap(), m);
            let json = serde_json::to_string(&m).unwrap();
            let back: MiningMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, m);
        }
    }

    // ---- Property tests ----

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn sats_saturating_add_never_panics(a: i64, b: i64) {
            // Just exercising — no assertion needed; success = no panic.
            let _ = Sats(a).saturating_add(Sats(b));
        }

        #[test]
        fn sats_saturating_sub_never_panics(a: i64, b: i64) {
            let _ = Sats(a).saturating_sub(Sats(b));
        }

        #[test]
        fn sats_checked_matches_saturating_when_in_range(a: i64, b: i64) {
            if let Some(checked) = Sats(a).checked_add(Sats(b)) {
                prop_assert_eq!(checked, Sats(a).saturating_add(Sats(b)));
            }
        }

        #[test]
        fn sats_add_commutative_when_no_overflow(a in -1_000_000_000i64..1_000_000_000, b in -1_000_000_000i64..1_000_000_000) {
            prop_assert_eq!(Sats(a) + Sats(b), Sats(b) + Sats(a));
        }

        #[test]
        fn address_shape_round_trip(s in "[!-~]{1,62}") {
            // Any 1..=62 ASCII-graphic string round-trips through the
            // shape-only validator.
            let a = AddressId::new(s.clone()).unwrap();
            prop_assert_eq!(a.as_str(), s.as_str());
        }
    }

    // ---- LogThrottle ----

    #[test]
    fn log_throttle_first_call_allows_with_zero_suppressed() {
        let t = LogThrottle::new(5_000);
        assert_eq!(t.allow(1_000), Some(0));
    }

    #[test]
    fn log_throttle_suppresses_within_interval_then_reports_count() {
        let t = LogThrottle::new(5_000);
        assert_eq!(t.allow(0), Some(0)); // first allowed
        assert_eq!(t.allow(1_000), None); // within interval → suppressed
        assert_eq!(t.allow(2_000), None);
        assert_eq!(t.allow(4_999), None); // still within
                                          // 5_000ms after the allowed call → allowed again, 3 suppressed.
        assert_eq!(t.allow(5_000), Some(3));
        // counter reset after reporting.
        assert_eq!(t.allow(5_001), None);
        assert_eq!(t.allow(10_000), Some(1));
    }

    #[test]
    fn log_throttle_zero_interval_always_allows() {
        let t = LogThrottle::new(0);
        assert_eq!(t.allow(0), Some(0));
        assert_eq!(t.allow(0), Some(0));
    }
}
