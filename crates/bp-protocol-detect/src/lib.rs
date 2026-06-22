// SPDX-License-Identifier: AGPL-3.0-or-later

//! First-byte protocol router — given the first byte read off an
//! accepted TCP connection, classify it as SV1, SV2, HTTP, or reject
//! it as something we don't speak (TLS, unknown).
//!
//! Pure function — the TCP server lifecycle (listen, accept, read,
//! buffer the first chunk, hand off) lives in `bin/blitzpool` because
//! it composes the SV1/SV2/HTTP handlers.
//!
//! # Why a separate crate
//!
//! - Single source of truth for the detection bytes. Both SV1 and SV2
//!   handler crates can consume this without depending on each other.
//! - Decoupled from any I/O — unit tests pin every boundary byte from
//!   the protocol spec without spawning a TCP listener.
//!
//! # What's NOT here (see `DEFERRED.md` for tracker rows)
//!
//! - TCP server / accept loop / per-port config — composition concern,
//!   lives in `bin/blitzpool`.
//! - Fail-ban state (per-IP failure counter + ban TTL in Redis with
//!   in-memory fallback) — I/O, lives next to the Redis adapter.
//! - HTTP-to-API proxy fallback — composition with `bp-api`.
//! - Per-connection debug logging / `STRATUM_PROTOCOL_DEBUG` env gate —
//!   wiring concern.

/// Outcome of looking at the first byte of an incoming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Detected {
    /// SV1 JSON-RPC. First byte is `'{'` (`0x7B`) or one of the
    /// pre-JSON whitespace bytes `' '` / `'\n'` / `'\r'` that some
    /// SV1 implementations send.
    Sv1,
    /// SV2 binary protocol — Noise handshake. Any byte that isn't
    /// matched by the other variants falls here.
    Sv2,
    /// HTTP request — `'G'` (GET) or `'P'` (POST/PUT/PATCH). The
    /// pool proxies these to the API port so miners can POST
    /// downstream-miner reports to the same address they're already
    /// connecting to for shares.
    Http,
    /// TLS ClientHello (`0x16`). Not a valid stratum protocol —
    /// surfaced as its own variant so the caller can close the
    /// connection cheaply without going through the SV2 handshake
    /// machinery first (which would otherwise create an expensive
    /// state object per TLS probe).
    Tls,
}

impl Detected {
    /// Whether this variant is something the pool actually serves.
    /// `false` for [`Self::Tls`] (we hang up early).
    pub fn is_serviceable(self) -> bool {
        match self {
            Self::Sv1 | Self::Sv2 | Self::Http => true,
            Self::Tls => false,
        }
    }
}

/// Classify a connection based on its first byte. Pure function.
///
/// Pre-JSON-whitespace bytes (`' '`, `'\n'`, `'\r'`) are treated as
/// SV1 because some Stratum-V1 implementations have been observed
/// leading their first frame with whitespace. The official spec says
/// the first character is `{`, but real miners aren't always strict.
pub fn detect(first_byte: u8) -> Detected {
    match first_byte {
        // HTTP — GET (0x47) or POST/PUT/PATCH (0x50).
        b'G' | b'P' => Detected::Http,
        // SV1 — '{' (0x7B) or leading whitespace before the JSON body.
        b'{' | b' ' | b'\n' | b'\r' => Detected::Sv1,
        // TLS ClientHello — not a stratum protocol.
        0x16 => Detected::Tls,
        // Anything else: assume SV2 binary (Noise handshake).
        _ => Detected::Sv2,
    }
}

/// Look at the start of `chunk`. Returns `None` if the chunk is empty
/// (TCP can deliver a 0-byte read in pathological cases — caller waits
/// for more data); otherwise [`Some(Detected::*)`].
pub fn detect_chunk(chunk: &[u8]) -> Option<Detected> {
    chunk.first().copied().map(detect)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HTTP ─────────────────────────────────────────────────────────

    #[test]
    fn get_request_routes_to_http() {
        assert_eq!(detect(b'G'), Detected::Http);
        assert_eq!(detect_chunk(b"GET / HTTP/1.1"), Some(Detected::Http));
    }

    #[test]
    fn post_request_routes_to_http() {
        assert_eq!(detect(b'P'), Detected::Http);
        assert_eq!(detect_chunk(b"POST /api"), Some(Detected::Http));
        assert_eq!(detect_chunk(b"PUT /api"), Some(Detected::Http));
        assert_eq!(detect_chunk(b"PATCH /api"), Some(Detected::Http));
    }

    // ── SV1 ──────────────────────────────────────────────────────────

    #[test]
    fn open_brace_is_sv1() {
        assert_eq!(detect(b'{'), Detected::Sv1);
        assert_eq!(
            detect_chunk(br#"{"id":1,"method":"mining.subscribe"}"#),
            Some(Detected::Sv1)
        );
    }

    #[test]
    fn leading_whitespace_before_json_is_sv1() {
        // Some non-strict SV1 implementations lead with whitespace.
        for b in [b' ', b'\n', b'\r'] {
            assert_eq!(detect(b), Detected::Sv1, "byte 0x{b:02x}");
        }
    }

    // ── TLS ──────────────────────────────────────────────────────────

    #[test]
    fn tls_client_hello_is_rejected_early() {
        assert_eq!(detect(0x16), Detected::Tls);
        // TLS ClientHello typically: 0x16 0x03 0x01 ... (handshake, TLS 1.0)
        assert_eq!(
            detect_chunk(&[0x16, 0x03, 0x01, 0x00, 0x40]),
            Some(Detected::Tls)
        );
        assert!(!Detected::Tls.is_serviceable());
    }

    // ── SV2 catch-all ────────────────────────────────────────────────

    #[test]
    fn sv2_noise_handshake_is_default() {
        // A Noise XK first message starts with the ephemeral public key
        // (32 bytes) — the leading byte is whatever the curve happened
        // to produce. Sample some plausible bytes that aren't claimed
        // by the other branches.
        for b in [0x00, 0x01, 0x42, 0x80, 0xab, 0xfe, 0xff] {
            assert_eq!(detect(b), Detected::Sv2, "byte 0x{b:02x}");
        }
    }

    #[test]
    fn unrecognised_text_bytes_fall_through_to_sv2() {
        // Letters that aren't G/P (HTTP) and aren't JSON-opener whitespace
        // shouldn't be misclassified. Even though 'A'..'Z' is text-shaped,
        // only 'G' and 'P' are HTTP method initials; everything else falls
        // to the SV2 default.
        for b in [b'A', b'B', b'H', b'O', b'T', b'X', b'Z'] {
            assert_eq!(detect(b), Detected::Sv2, "letter '{}'", b as char);
        }
    }

    // ── Chunk wrapper ────────────────────────────────────────────────

    #[test]
    fn empty_chunk_returns_none() {
        assert_eq!(detect_chunk(&[]), None);
    }

    #[test]
    fn detect_chunk_only_looks_at_first_byte() {
        // Trailing bytes don't influence detection.
        assert_eq!(detect_chunk(b"{garbage"), Some(Detected::Sv1));
        assert_eq!(detect_chunk(b"Ghttp-ish-garbage"), Some(Detected::Http));
    }

    // ── is_serviceable invariant ─────────────────────────────────────

    #[test]
    fn serviceable_iff_not_tls() {
        assert!(Detected::Sv1.is_serviceable());
        assert!(Detected::Sv2.is_serviceable());
        assert!(Detected::Http.is_serviceable());
        assert!(!Detected::Tls.is_serviceable());
    }
}
