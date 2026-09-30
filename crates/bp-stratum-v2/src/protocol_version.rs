// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which SV2 protocol versions this pool speaks, and how a
//! `SetupConnection` version range is negotiated against them.
//!
//! One place, because the answer is a property of the POOL and not of a
//! sub-protocol: the mining listener and the JDP listener must not be able to
//! speak different SV2 versions. `stratum_core` ships no constant for this,
//! so the pool holds the numbers.
//!
//! What stays per sub-protocol is the REFUSAL (the `SetupConnection.Error`
//! each handler sends); this module only decides whether the ranges
//! intersect.

/// Minimum SV2 protocol version served. SV2 Overview/SetupConnection pins
/// `min_version`/`max_version` at 2 for the current specification.
pub const MIN_PROTOCOL_VERSION: u16 = 2;

/// Maximum SV2 protocol version served. Bump when the spec adds a revision
/// this pool supports.
pub const MAX_PROTOCOL_VERSION: u16 = 2;

/// Negotiate a client's advertised `[min_version, max_version]` against what
/// this pool serves.
///
/// `Some(used_version)` when the ranges intersect — the highest version both
/// sides speak, which is what `SetupConnection.Success.used_version` carries.
/// `None` when they do not; the caller sends its own sub-protocol's
/// `SetupConnection.Error` and closes.
pub fn negotiate_version(min_version: u16, max_version: u16) -> Option<u16> {
    negotiate_against(
        min_version,
        max_version,
        MIN_PROTOCOL_VERSION,
        MAX_PROTOCOL_VERSION,
    )
}

/// The rule itself, with the served range as parameters.
///
/// Split from [`negotiate_version`] so it can be exercised against a range
/// WIDER than one version. With `MIN_PROTOCOL_VERSION == MAX_PROTOCOL_VERSION`
/// the two bounds are interchangeable, so a test that only passes the real
/// constants cannot tell a wrong-bound comparison or clamp from a correct
/// one; those mistakes would surface only once `MAX` is raised.
fn negotiate_against(
    client_min: u16,
    client_max: u16,
    serve_min: u16,
    serve_max: u16,
) -> Option<u16> {
    // A client that names a minimum above its own maximum has named no range
    // at all. Without this the two comparisons below can both pass — take
    // `client 4–2` against `serve 2–4` — and the result is `2`, a version the
    // client said was beneath it.
    if client_min > client_max {
        return None;
    }
    if client_min > serve_max || client_max < serve_min {
        return None;
    }
    // Clamping against the upper bound alone is enough: the check above
    // already established `client_max >= serve_min`, so the result cannot
    // fall below the minimum.
    Some(client_max.min(serve_max))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A served range wider than one version. Every rule test below runs
    /// against THIS rather than the real constants — see
    /// [`negotiate_against`].
    const SERVE_MIN: u16 = 2;
    const SERVE_MAX: u16 = 4;

    fn negotiate(client_min: u16, client_max: u16) -> Option<u16> {
        negotiate_against(client_min, client_max, SERVE_MIN, SERVE_MAX)
    }

    #[test]
    fn a_client_offering_more_gets_the_highest_we_serve() {
        assert_eq!(negotiate(2, 9), Some(SERVE_MAX));
        assert_eq!(negotiate(0, 9), Some(SERVE_MAX));
    }

    #[test]
    fn a_client_inside_our_range_gets_its_own_maximum() {
        assert_eq!(negotiate(2, 3), Some(3));
        assert_eq!(negotiate(3, 3), Some(3));
    }

    #[test]
    fn a_range_entirely_below_ours_is_refused() {
        assert_eq!(negotiate(0, 1), None);
    }

    #[test]
    fn a_range_entirely_above_ours_is_refused() {
        assert_eq!(negotiate(5, 9), None);
    }

    /// Touching at exactly one end still negotiates — the boundary the two
    /// comparisons are written around.
    #[test]
    fn touching_at_either_end_is_enough() {
        assert_eq!(negotiate(0, SERVE_MIN), Some(SERVE_MIN));
        assert_eq!(negotiate(SERVE_MAX, 9), Some(SERVE_MAX));
    }

    /// A range whose minimum sits above its maximum is no range and
    /// negotiates nothing.
    #[test]
    fn an_inverted_range_negotiates_nothing() {
        assert_eq!(negotiate_against(4, 2, SERVE_MIN, SERVE_MAX), None);
        assert_eq!(negotiate_against(9, 0, SERVE_MIN, SERVE_MAX), None);
        assert_eq!(negotiate_version(4, 2), None);
    }

    /// Whatever comes back is a version BOTH sides named. Swept over every
    /// client range in and around the served one.
    #[test]
    fn a_negotiated_version_is_one_both_sides_named() {
        // Every ordered pair, INVERTED ONES INCLUDED, so the
        // `used >= client_min` assertion meets the case that can break it.
        for client_min in 0u16..8 {
            for client_max in 0u16..8 {
                let got = negotiate(client_min, client_max);
                let overlaps =
                    client_min <= client_max && client_min <= SERVE_MAX && client_max >= SERVE_MIN;
                assert_eq!(
                    got.is_some(),
                    overlaps,
                    "client {client_min}–{client_max} against {SERVE_MIN}–{SERVE_MAX}"
                );
                if let Some(used) = got {
                    assert!(
                        (SERVE_MIN..=SERVE_MAX).contains(&used),
                        "negotiated {used}, which we do not serve"
                    );
                    assert!(
                        used >= client_min && used <= client_max,
                        "negotiated {used}, outside the client's {client_min}–{client_max}"
                    );
                }
            }
        }
    }

    /// The wiring, separately from the rule: the public entry point really
    /// does hand the pool's own constants to it.
    #[test]
    fn the_public_entry_point_uses_the_pools_own_range() {
        assert_eq!(
            negotiate_version(0, u16::MAX),
            negotiate_against(0, u16::MAX, MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION)
        );
        assert_eq!(
            negotiate_version(MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION),
            Some(MAX_PROTOCOL_VERSION)
        );
        assert_eq!(negotiate_version(MAX_PROTOCOL_VERSION + 1, u16::MAX), None);
        assert_eq!(negotiate_version(0, MIN_PROTOCOL_VERSION - 1), None);
    }
}
