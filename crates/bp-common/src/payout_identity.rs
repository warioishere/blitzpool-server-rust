// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`PayoutIdentity`] — what a miner presented on the wire, as the thing that
//! decides where its money goes.
//!
//! Today every identity is a literal address: one string that serves as ledger
//! key, mode key, and coinbase script source at once. A rotating identity
//! (an xpub the pool derives a fresh script from per block) splits those roles
//! apart — the ledger key must stay fixed or `pplns_balance`'s
//! `PRIMARY KEY (address)` grows a row per block, while the script must change
//! or rotation is not happening.
//!
//! This module holds the type that makes those two roles different values, the
//! one implementation of the `address.worker` split, and nothing else.
//! Descriptor parsing and script derivation are deliberately elsewhere: they
//! need `bitcoin`/`miniscript`, `bp-common` is a dependency of 21 crates, and
//! the rule that a script is derived at a *height* belongs next to
//! `address_to_script` where the only coinbase-path script derivation already
//! lives.
//!
//! **`Rotating` is now constructible, and the derivation is a trait object.**
//! [`RotatingScriptSource`] is how those two facts coexist: the *type* every
//! crate touches stays here, while the one implementation lives in
//! `bp-payout-descriptor` with the `miniscript` dependency. The trait's
//! signature is `bitcoin`-free on purpose — script **bytes**, not a `ScriptBuf`
//! — which is the same shape the coinbase seam already produces.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::{normalize_btc_address, AddressId, InvalidAddressError};

/// The height [`PayoutIdentity::probe_payable`] derives at.
///
/// An arbitrary in-range index — see that method for why it is not 0. Any real
/// block height works; this one is a round number well inside the range a
/// wildcard descriptor accepts (`0..=2^31-1` for a non-hardened step).
const PROBE_HEIGHT: u32 = 1_000_000;

/// Why a rotating identity could not produce a script.
///
/// **No payload, deliberately** — the same rule
/// `bp_payout_descriptor::IntakeError` is built on. A descriptor is a
/// wallet-watching capability and a parser's error text can contain key
/// material, so there is nowhere here to put one. Every variant is a fixed
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RotationError {
    /// Derivation at this height failed. Unreachable for an identity built
    /// through `bp_payout_descriptor`'s intake, which asserts derivability at
    /// construction — so this variant means the invariant was established
    /// somewhere else, and the coinbase must fail rather than guess a script.
    #[error("rotating payout identity could not derive a script at this height")]
    NotDerivable,
}

/// What a [`PayoutIdentity::Rotating`] asks for its per-block script.
///
/// **This trait is why `PayoutIdentity` can stay in `bp-common`.** Deriving a
/// script needs `miniscript`, and `bp-common` is depended on by 19 crates, 11 of
/// which take no `bitcoin` dependency at all — so the derivation cannot live
/// here. The trait's signature is deliberately `bitcoin`-free (`Vec<u8>` of
/// script bytes, not a `ScriptBuf`), which is exactly what the coinbase seam
/// already produces: `address_to_script(...).into_bytes()`.
///
/// The one implementation is `bp_payout_descriptor::RotatingPayout`, and one is
/// the point. `CLAUDE.md`'s opening line is about the same concept implemented
/// twice; a second impl of this trait would be a second answer to "which script
/// does this miner get at height H", which is the shape of the 2026-07-25/26
/// entry (the same fix landed in two PRs a day apart).
///
/// `Send + Sync` because a resolved identity is carried across the async payout
/// path. Measured 2026-08-10: `Descriptor<DescriptorPublicKey>` **is**
/// `Send + Sync + 'static` in `miniscript 13.1.0`, so the one implementation can
/// satisfy this without storing a canonical string and re-parsing per use.
pub trait RotatingScriptSource: fmt::Debug + Send + Sync {
    /// The `scriptPubKey` this identity is paid at `height`, as raw bytes.
    ///
    /// Must be a pure function of `(self, height)`: re-deriving at the same
    /// height must give the same script, or an orphan reconvergence pays a
    /// different address on the replacement block. Pinned on the one
    /// implementation by `derivation_is_idempotent_at_a_fixed_height`.
    fn script_at(&self, height: u32) -> Result<Vec<u8>, RotationError>;

    /// The canonical descriptor, for a miner to verify a payout against
    /// `bitcoin-cli deriveaddresses` and for the `miner_identity` row.
    ///
    /// **A credential for logging purposes** — it is a wallet-watching
    /// capability over every address the pool will ever pay this miner. It must
    /// not reach a log line or an unauthenticated endpoint, which is why
    /// [`RotatingDescriptor`]'s `Debug` redacts it rather than delegating here.
    fn canonical_descriptor(&self) -> &str;
}

/// The descriptor a [`PayoutIdentity::Rotating`] derives its per-block script
/// from.
///
/// A newtype over `Arc<dyn RotatingScriptSource>` rather than the trait object
/// bare, so `PayoutIdentity` keeps `Clone` (the payout path clones entries
/// freely) and so the `Debug` redaction below cannot be bypassed by a caller
/// that happens to hold the `Arc`.
///
/// # What this replaced, and why the replacement is the load-bearing part
///
/// Through Phase 2 this struct held an uninhabited field, so it could not be
/// constructed *anywhere* — including inside this module — and every site that
/// would one day need a rotating script wrote an `absurd()` arm the compiler
/// certified as dead. That was not a stylistic choice: it made Phase 1 a
/// refactor with a compiler-checked no-op guarantee, and it made the list of
/// sites to change something the compiler produced rather than something a human
/// grepped for.
///
/// Giving it values is what cashed that in. All four `absurd()` calls became
/// compile errors in one build — `bp_mining_job::coinbase::payout_script`,
/// `bp_stratum_v1`'s authorize probe, `bp_stratum_v2`'s channel-open probe, and
/// the JDP resolver's tailored-Solo route in `bin/blitzpool/src/jdp_hooks.rs` —
/// and each had to be answered with a real derivation, a real check, or an
/// explicit refusal. None of them could be answered with a stub, because there
/// is no longer an uninhabited value to discharge.
///
/// The fourth is the one worth naming: nobody enumerating "where does a payout
/// script get built" by hand would have listed the JDP hook, because it does not
/// build one — it decides whether a declared job *can* be tailored. The compiler
/// listed it.
#[derive(Clone)]
pub struct RotatingDescriptor(Arc<dyn RotatingScriptSource>);

impl RotatingDescriptor {
    /// Wrap the one implementation. Called by `bp-payout-descriptor` after its
    /// three intake assertions have run — see
    /// `bp_payout_descriptor::assert_derivable`, which is what makes
    /// [`Self::script_at`] unable to panic.
    pub fn new(source: Arc<dyn RotatingScriptSource>) -> Self {
        Self(source)
    }

    /// The script this identity is paid at `height`.
    pub fn script_at(&self, height: u32) -> Result<Vec<u8>, RotationError> {
        self.0.script_at(height)
    }

    /// The canonical descriptor. **Do not log it** — see
    /// [`RotatingScriptSource::canonical_descriptor`]. This exists for the
    /// `miner_identity` write and for a miner-authenticated read, and nothing
    /// else.
    pub fn canonical_descriptor(&self) -> &str {
        self.0.canonical_descriptor()
    }
}

impl fmt::Debug for RotatingDescriptor {
    /// **Redacted, not delegated.** `PayoutIdentity` derives nothing and this
    /// type is inside it; a `#[derive(Debug)]` here would put the descriptor
    /// into every `?identity` and `?payouts` field in the codebase, and there
    /// are several on the payout path. A descriptor in a log is the miner's
    /// whole wallet-watching capability.
    ///
    /// The `payout_id` is the greppable handle, and it is already in
    /// `PayoutIdentity`'s own `Debug` beside this.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RotatingDescriptor(<redacted>)")
    }
}

/// Two rotating descriptors are equal when they are the **same descriptor**, not
/// when they are the same allocation.
///
/// Hand-written because a trait object cannot derive it, and the definition is a
/// money question rather than a formality: `payout_id` is a hash of the
/// canonical descriptor (`bp_payout_descriptor::payout_id_for`), so comparing
/// canonical strings here agrees with comparing ledger keys. `Arc::ptr_eq` would
/// not — the same xpub parsed twice is two allocations and one identity, and a
/// pointer comparison would report a miner as two miners in anything that
/// deduplicates payout entries.
impl PartialEq for RotatingDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_descriptor() == other.canonical_descriptor()
    }
}

impl Eq for RotatingDescriptor {}

/// Consistent with [`PartialEq`] — same canonical descriptor, same hash. Both
/// must key on the same field or a `HashMap<PayoutIdentity, _>` silently loses
/// entries.
impl Hash for RotatingDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical_descriptor().hash(state);
    }
}

/// Where a miner's share of a coinbase goes.
///
/// The two roles this separates:
///
/// 1. **[`payout_id`](Self::payout_id)** — the ledger key and the mode key.
///    Height-invariant by construction.
/// 2. **the payout script** — varies by height, and only for `Rotating`.
///    Derived in `bp-mining-job`, which owns the `bitcoin` dependency.
///
/// For `Static` the two coincide, which is why a `String` has sufficed so far.
///
/// # Why a sum type and not `Option<Descriptor>`
///
/// `descriptor.is_some()` reads as "is this miner rotating?" and answers "did
/// someone populate this field?". A row with both fields set pays whichever
/// branch the reader happened to check, and there are two readers (the coinbase
/// builder and whatever books the ledger). `CLAUDE.md` names this: *"The same
/// goes for `is_some()` on a per-mode field: it reads as a mode test and answers
/// a different question."*
///
/// The precedent is in this repo's history, 2026-08-03: a found block's
/// settlement inputs were stamped by `if resolved.mode == MiningMode::GroupSolo`,
/// PPLNS fell out of that `if`, and roughly half its blocks lost the inputs for
/// good against a 20-minute TTL. Several reviews passed over the line. An
/// `Option` on a per-mode field is that defect with a different keyword —
/// `is_some()` is no more exhaustive than `if mode ==`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PayoutIdentity {
    /// A literal Bitcoin address, paid verbatim at every height.
    Static {
        /// **Not an [`AddressId`], and the reason changed on 2026-08-12.**
        ///
        /// It used to be the length: `AddressId` capped at 62 characters, a
        /// **regtest P2TR address is 64** (`bcrt1p` + 1 + 52 + 6; the same
        /// formula gives 44 for `bcrt1q`, which is what the node hands the
        /// regtests), so narrowing this would have failed passing tests. That
        /// break is fixed — [`crate::MAX_ADDRESS_LEN`] is 90 and migration
        /// `0015_widen_identity_columns.sql` widened the columns behind it.
        ///
        /// What survives is the weaker but still sufficient reason: this is the
        /// same unconstrained `String` the coinbase seam carries, and
        /// [`static_address_verbatim`](PayoutIdentity::static_address_verbatim)
        /// exists to preserve a caller's bytes exactly — the pool's own fee
        /// address out of config, and the weight-entry lowering, which passes
        /// through strings that were already validated upstream. Narrowing this
        /// to `AddressId` would move shape validation onto a seam that
        /// deliberately does not validate, so it is a separate decision with its
        /// own argument, not a leftover of the width fix.
        address: String,
    },
    /// An extended public key the pool derives a fresh script from per block.
    Rotating {
        /// The descriptor to derive from.
        descriptor: RotatingDescriptor,
        /// The height-invariant ledger key. A rotating miner's script changes
        /// every block; this does not, or PPLNS carry-forward silently stops
        /// working (`pplns_balance` is `PRIMARY KEY (address)`).
        payout_id: AddressId,
    },
}

impl PayoutIdentity {
    /// A literal address, normalized ([`normalize_btc_address`]) but **not**
    /// shape-validated — matching what the coinbase seam accepts today.
    ///
    /// Callers that want the shape check keep doing what they do now: the
    /// authorize/channel-open probes run `address_to_script`, which is a
    /// stronger check than `AddressId` anyway (it parses the address and
    /// verifies the network).
    pub fn static_address(address: impl AsRef<str>) -> Self {
        PayoutIdentity::Static {
            address: normalize_btc_address(address.as_ref()),
        }
    }

    /// A literal address taken verbatim, with no normalization.
    ///
    /// For the paths that already normalized (or that deliberately preserve a
    /// caller's bytes, like the pool's own fee addresses read from config).
    /// Prefer [`static_address`](Self::static_address) when the string came off
    /// the wire.
    pub fn static_address_verbatim(address: impl Into<String>) -> Self {
        PayoutIdentity::Static {
            address: address.into(),
        }
    }

    /// The ledger key and the mode key — **height-invariant**.
    ///
    /// This is what goes in `pplns_balance.address`,
    /// `pplns_payout_history.address`, `worker_shares_entity.address`, and
    /// every mode lookup. It is NOT what goes in a coinbase output: for
    /// `Rotating` those are different values, which is the entire reason this
    /// type is a sum type.
    ///
    /// Returns `&str` rather than `&AddressId` because the `Static` arm does not
    /// hold an `AddressId` — see [`PayoutIdentity::Static::address`] for why
    /// that is still true now that the 62-char cap is gone.
    pub fn payout_id(&self) -> &str {
        match self {
            PayoutIdentity::Static { address } => address,
            PayoutIdentity::Rotating { payout_id, .. } => payout_id.as_str(),
        }
    }

    /// A rotating identity from its validated descriptor and ledger key.
    ///
    /// Called only by `bp_payout_descriptor`, which runs the three intake
    /// assertions first. Nothing here re-checks them — this module has no
    /// `miniscript` to check them with, which is the whole reason the
    /// derivation is a trait object.
    pub fn rotating(descriptor: RotatingDescriptor, payout_id: AddressId) -> Self {
        PayoutIdentity::Rotating {
            descriptor,
            payout_id,
        }
    }

    /// **The payout script at `height`, as raw bytes — role 3.**
    ///
    /// Not `payout_id()`. For a `Static` identity the two coincide, which is why
    /// one `String` sufficed before this type existed; for a `Rotating` one they
    /// are different values, and confusing them is the mistake this sum type
    /// exists to make unwriteable.
    ///
    /// The `Static` arm returns `None` rather than a script: this module cannot
    /// parse an address (no `bitcoin` dependency), so the caller keeps doing what
    /// it does today. `None` means *"not my answer, use `address_to_script` on
    /// `payout_id()`"*, and the coinbase seam's `match` is what makes that
    /// explicit rather than implied — see `bp_mining_job::coinbase::payout_script`.
    ///
    /// Returning `Option<Result<…>>` and not flattening: a `Static` identity has
    /// no derivation to fail, and collapsing "nothing to derive" into an error
    /// would make the coinbase seam treat every static payout as a failure it
    /// then has to recover from.
    pub fn script_at(&self, height: u32) -> Option<Result<Vec<u8>, RotationError>> {
        match self {
            PayoutIdentity::Static { .. } => None,
            PayoutIdentity::Rotating { descriptor, .. } => Some(descriptor.script_at(height)),
        }
    }

    /// **Can this identity be paid at all?** The authorize / channel-open probe.
    ///
    /// One implementation for both protocols. SV1's `mining.authorize` and SV2's
    /// `OpenMiningChannel` both have to answer it, they are in different crates,
    /// and `CLAUDE.md`'s opening line is about exactly the shape where two copies
    /// of one rule drift apart. The `Static` half stays at the call sites because
    /// it needs `address_to_script` (network-checked, `bitcoin`-dependent, and
    /// already there); this is the half that is the same in both.
    ///
    /// `Static` is `Ok(())` and does **not** silently pass: the caller's `match`
    /// is what routes a static identity to `address_to_script`, and this method
    /// returning `Ok` for it would be wrong only if a caller used this *instead*
    /// of that check. That is why the arms are explicit at both call sites rather
    /// than this being a single call covering both.
    ///
    /// # What this probe does and does not prove
    ///
    /// It derives at one height, so it proves that height. The real guarantee —
    /// that *every* height derives — comes from `bp_payout_descriptor`'s three
    /// intake assertions, which run before a `Rotating` identity can exist.
    /// This is defence in depth: it catches an identity that reached the payout
    /// path without going through intake, at connection time, instead of at
    /// coinbase assembly for a found block.
    ///
    /// The probe height is deliberately not 0. A wildcard descriptor derives at
    /// index 0 as readily as anywhere, but 0 is also the stand-in
    /// `payout_height` uses for a template with no decodable BIP-34 push, and a
    /// probe that only ever exercised the one height a fabricated template
    /// produces would be the weakest possible choice.
    pub fn probe_payable(&self) -> Result<(), RotationError> {
        match self {
            PayoutIdentity::Static { .. } => Ok(()),
            PayoutIdentity::Rotating { descriptor, .. } => {
                descriptor.script_at(PROBE_HEIGHT).map(|_| ())
            }
        }
    }

    /// Is this identity paid a different script per block?
    ///
    /// A `match`, so it cannot answer a stale question if a third variant is
    /// added. Read-only classification — it is NOT a substitute for matching
    /// where behaviour differs, and a caller that branches on it to *choose a
    /// script* has reintroduced exactly the `is_some()` defect this type
    /// exists to prevent. Intended for logging and metrics.
    pub fn rotates(&self) -> bool {
        match self {
            PayoutIdentity::Static { .. } => false,
            PayoutIdentity::Rotating { .. } => true,
        }
    }
}

/// Split a wire identity into its payout part and its worker part.
///
/// **The one implementation of this rule.** It existed four times — once per
/// protocol path that reads a `user_identity`:
///
/// | Site | Form |
/// |---|---|
/// | `bp-stratum-v1/src/frame.rs` | `split_once('.')`, worker defaults to `"worker"` |
/// | `bp-stratum-v2/src/mining/client.rs` | `find('.')`, worker defaults to `"default"` |
/// | `bp-stratum-v2/src/jdp/client.rs` | `find('.')`, worker discarded |
/// | `bp-stratum-v2/src/extensions.rs` | `find('.')` for the Worker-ID TLV, worker attribution only |
///
/// All four agreed on the rule and each said so in its own words. The JDP one
/// records the money consequence of getting it wrong: *"otherwise the trailing
/// `.worker` makes `address_to_script` reject the address at coinbase-output
/// encode time, collapsing the pool payout to an empty output set
/// (`coinbase_tx_outputs = 0x00`)."*
///
/// Split on the **first** dot; the worker name keeps any further dots.
///
/// The worker part is `Option`, not a defaulted `&str`, because *no dot* and *an
/// empty worker after a dot* are different inputs and the four sites do not
/// treat them the same way — SV1 defaults `"addr"` to worker `"worker"` but
/// leaves `"addr."` as the empty string. Returning `""` for both would silently
/// change SV1's behaviour. Nothing is trimmed: the address part is trimmed
/// downstream by [`normalize_btc_address`], and trimming the worker part here
/// would change what SV2 reports as a worker name.
///
/// This is the split ONLY. It does not decide whether the payout part is an
/// address or an xpub — that is [`parse_payout_identity`]'s job, so the four
/// sites do not each have to learn a new grammar.
pub fn split_identity_and_worker(raw: &str) -> (&str, Option<&str>) {
    match raw.find('.') {
        Some(idx) => (&raw[..idx], Some(&raw[idx + 1..])),
        None => (raw, None),
    }
}

/// The pool's rotating-identity intake, as seen from a protocol crate.
///
/// **Why this is a trait and not a function.** Turning a wire string into a
/// rotating identity needs `miniscript` (three intake assertions and a
/// descriptor parse), and `bp-common` is depended on by 19 crates, 11 of which
/// take no `bitcoin` dependency at all. So the *decision* lives here and the
/// *implementation* lives in `bin/blitzpool` on top of `bp-payout-descriptor` —
/// the same split, for the same reason, as [`RotatingScriptSource`].
///
/// It is also the local idiom: a capability a protocol crate needs but cannot
/// itself provide arrives as an injected hook (`ServerHooks`, `PayoutResolver`,
/// `BlockSubmissionSink`). This is one more of those.
///
/// **One implementation, and that is the point.** SV1's `mining.authorize` and
/// SV2's `OpenMiningChannel` both have to answer "is this an xpub, and may this
/// pool accept it?", they are in different crates, and `CLAUDE.md`'s opening
/// line is about exactly the shape where two copies of one rule drift apart.
pub trait RotatingIntake: Send + Sync {
    /// Intake `payout_part` (the wire identity with any `.worker` suffix
    /// already removed).
    ///
    /// - `Ok(None)` — not an extended-key attempt. The caller's existing static
    ///   address path handles it, byte for byte as before.
    /// - `Ok(Some(_))` — a validated rotating identity.
    /// - `Err(_)` — it *was* an extended-key attempt and this pool refuses it:
    ///   an invalid key, a descriptor that cannot rotate, or the operator flag
    ///   being off. Deliberately not `Ok(None)`: falling through to the address
    ///   path would refuse the same connection with a length-related message and
    ///   leave the miner debugging the wrong thing.
    fn intake(&self, payout_part: &str) -> Result<Option<PayoutIdentity>, IdentityRefused>;
}

/// The pool refused this payout identity. **Carries no detail, deliberately.**
///
/// Two reasons, and both are load-bearing:
///
/// 1. **The credential rule.** A descriptor parser's error text can contain a
///    private key — measured, `Descriptor::from_str` on a bare `xprv` returns a
///    131-character error containing the whole key. `Copy` is what makes the
///    variant a leak would need (one holding the parser's `String`) a compile
///    error, the same guard `bp_payout_descriptor::IntakeError` is built on.
/// 2. **The informative log already happened.** The implementation of
///    [`RotatingIntake`] is the only thing that knows *which* refusal this was,
///    and it is where the operator-facing line is written. Both protocol sites
///    have exactly one rejection code to offer a miner
///    (`REJECT_INVALID_ADDR` / `ERR_UNKNOWN_USER`), so a detail carried up here
///    would have nowhere to go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the pool refused this payout identity")]
pub struct IdentityRefused;

/// Why a wire identity could not become a [`PayoutIdentity`].
///
/// Deliberately narrow, and deliberately carrying no borrowed text from a
/// parser. The error text is a hazard rather than a convenience:
/// `Descriptor::from_str` on a bare `xprv` returns a 131-char error that
/// **contains the whole private key**. The local idiom next door
/// (`Address::from_str(a).map_err(|e| AddressError::Parse(e.to_string()))`) is
/// correct for a public address and would write a spendable key into the pool's
/// logs if copied here.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentityParseError {
    /// Nothing before the first dot, or nothing at all.
    #[error("identity has no payout part")]
    Empty,
    /// The payout part is not a usable address shape.
    #[error("identity payout part is not a valid address: {0}")]
    InvalidAddress(InvalidAddressError),
    /// The payout part was an extended-key attempt and the pool refused it.
    /// See [`IdentityRefused`] for why nothing more is said here.
    #[error("identity payout part was refused: {0}")]
    Refused(IdentityRefused),
}

/// Parse a wire identity (`<payout>` or `<payout>.<worker>`) into a
/// [`PayoutIdentity`] plus the raw worker part, with **no** rotating intake.
///
/// Always `Static`, and that is right for the callers that keep using it: the
/// JDP `user_identifier` helper and the Worker-ID TLV, neither of which is a
/// place a miner presents a payout identity for the first time.
///
/// Shape-validates through [`AddressId`], which is what the sites that call
/// this already do. It does NOT parse the address or check the network — that is
/// `address_to_script`, and the two sites that run it keep running it, so their
/// rejection behaviour is unchanged.
pub fn parse_payout_identity(
    raw: &str,
) -> Result<(PayoutIdentity, Option<&str>), IdentityParseError> {
    parse_payout_identity_with(raw, None)
}

/// [`parse_payout_identity`], plus the pool's rotating intake when one is
/// installed.
///
/// **The one implementation of the whole rule**, and the short form above
/// delegates to it rather than repeating the static half. That matters more than
/// it looks: the static half is four steps (split, normalize, shape-check, keep
/// the un-narrowed `String`) and each of those was once spelled differently at
/// each of four call sites.
///
/// Order of operations, all three of which are decisions:
///
/// 1. **Split off the worker first.** A bare xpub contains no dot, but
///    `<xpub>.<worker>` does, and intake must see the key without the suffix.
/// 2. **Intake before normalization.** [`normalize_btc_address`] lowercases
///    bech32; base58 is case-sensitive and an extended key is base58, so
///    lowercasing one would corrupt it. (It does not today — an xpub matches
///    none of the bech32 prefixes — but relying on that is relying on a
///    coincidence in another function.)
/// 3. **A refusal is an error, not a fall-through.** See
///    [`RotatingIntake::intake`].
///
/// `rotating: None` means no intake is installed, which is *not* the same as
/// "the feature is off": the operator flag lives inside the implementation, so
/// flag-off still refuses an xpub with a reason rather than reporting it as a
/// malformed address. `None` is for the call sites that have no intake to
/// consult at all.
pub fn parse_payout_identity_with<'a>(
    raw: &'a str,
    rotating: Option<&dyn RotatingIntake>,
) -> Result<(PayoutIdentity, Option<&'a str>), IdentityParseError> {
    let (payout_part, worker) = split_identity_and_worker(raw);
    if let Some(intake) = rotating {
        match intake.intake(payout_part) {
            Ok(Some(identity)) => return Ok((identity, worker)),
            Err(refused) => return Err(IdentityParseError::Refused(refused)),
            // Not an extended-key attempt — fall through to the static path
            // below, unchanged.
            Ok(None) => {}
        }
    }
    let normalized = normalize_btc_address(payout_part);
    if normalized.is_empty() {
        return Err(IdentityParseError::Empty);
    }
    // Shape-check, then keep the normalized string rather than the `AddressId`:
    // `Static` holds an unconstrained `String` so a 64-char regtest P2TR still
    // works. The check is what the sites do today; the storage is what the
    // coinbase seam does today.
    AddressId::new(normalized.clone()).map_err(IdentityParseError::InvalidAddress)?;
    Ok((PayoutIdentity::static_address_verbatim(normalized), worker))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- split_identity_and_worker ----

    #[test]
    fn split_takes_the_first_dot_and_the_worker_keeps_the_rest() {
        assert_eq!(
            split_identity_and_worker("bc1qfoo.rig1.board2"),
            ("bc1qfoo", Some("rig1.board2"))
        );
    }

    #[test]
    fn split_distinguishes_no_dot_from_an_empty_worker() {
        // The distinction SV1 depends on: no dot defaults the worker to
        // "worker", a trailing dot leaves it empty. Collapsing both to `""`
        // would change SV1's authorize behaviour.
        assert_eq!(split_identity_and_worker("bc1qfoo"), ("bc1qfoo", None));
        assert_eq!(split_identity_and_worker("bc1qfoo."), ("bc1qfoo", Some("")));
    }

    #[test]
    fn split_reports_an_empty_payout_part_rather_than_guessing() {
        assert_eq!(split_identity_and_worker(".rig1"), ("", Some("rig1")));
        assert_eq!(split_identity_and_worker(""), ("", None));
    }

    #[test]
    fn split_does_not_trim() {
        // The address part is trimmed downstream by `normalize_btc_address`;
        // trimming the worker here would change what SV2 reports.
        assert_eq!(
            split_identity_and_worker("  bc1qfoo  .  rig1  "),
            ("  bc1qfoo  ", Some("  rig1  "))
        );
    }

    // ---- parse_payout_identity ----

    #[test]
    fn parse_yields_a_static_identity_and_normalizes_the_address() {
        let (identity, worker) =
            parse_payout_identity("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4.rig1").unwrap();
        assert_eq!(
            identity,
            PayoutIdentity::Static {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()
            }
        );
        assert_eq!(worker, Some("rig1"));
    }

    #[test]
    fn parse_preserves_base58_case() {
        let (identity, _) = parse_payout_identity("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.w").unwrap();
        assert_eq!(identity.payout_id(), "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    }

    #[test]
    fn parse_rejects_an_empty_payout_part() {
        assert_eq!(parse_payout_identity(""), Err(IdentityParseError::Empty));
        assert_eq!(
            parse_payout_identity(".rig1"),
            Err(IdentityParseError::Empty)
        );
        assert_eq!(
            parse_payout_identity("   .rig1"),
            Err(IdentityParseError::Empty)
        );
    }

    #[test]
    fn parse_rejects_an_over_long_payout_part() {
        // A bare xpub is 111 chars. This is the rejection an xpub meets today,
        // at one of four differently-shaped layers; intake replaces it.
        let xpub = "x".repeat(111);
        assert_eq!(
            parse_payout_identity(&xpub),
            Err(IdentityParseError::InvalidAddress(
                InvalidAddressError::TooLong(111)
            ))
        );
    }

    // ---- PayoutIdentity ----

    #[test]
    fn static_address_normalizes_but_static_address_verbatim_does_not() {
        assert_eq!(
            PayoutIdentity::static_address("  BC1QFOO  ").payout_id(),
            "bc1qfoo"
        );
        assert_eq!(
            PayoutIdentity::static_address_verbatim("  BC1QFOO  ").payout_id(),
            "  BC1QFOO  "
        );
    }

    /// A regtest P2TR address is 64 characters and now goes **everywhere**: the
    /// seam, `AddressId`, and the identity columns behind it.
    ///
    /// This pair of assertions used to read the other way round — `AddressId`
    /// rejecting it with `TooLong(64)` as a "negative control" for why `Static`
    /// holds a `String`. That was the latent break; migration
    /// `0015_widen_identity_columns.sql` and [`crate::MAX_ADDRESS_LEN`] fixed it,
    /// and this is the test that would have failed before them.
    #[test]
    fn a_regtest_p2tr_address_is_64_chars_and_fits_everywhere_now() {
        // A real bech32m P2TR on regtest: `bcrt1p` + 52 data + 6 checksum.
        let regtest_p2tr = "bcrt1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusgm2jyk";
        assert_eq!(
            regtest_p2tr.len(),
            64,
            "regtest P2TR must be 64 chars for this test to mean anything"
        );
        assert!(
            regtest_p2tr.len() > 62,
            "and longer than the old cap, or it proves nothing about the widening"
        );

        // The cap that used to reject it.
        assert!(
            AddressId::new(regtest_p2tr).is_ok(),
            "the identity columns are varchar(90) and this is the address that \
             made them move"
        );

        // ... and `Static` carries it, as it always did.
        let identity = PayoutIdentity::static_address(regtest_p2tr);
        assert_eq!(identity.payout_id(), regtest_p2tr);
    }

    /// `parse_payout_identity` applies the cap, and the cap is now 90.
    ///
    /// Both directions in one test: the address that used to be refused is
    /// accepted, and one character past [`crate::MAX_ADDRESS_LEN`] is still
    /// refused — so this cannot pass by the cap having been removed rather than
    /// widened.
    #[test]
    fn parse_applies_the_widened_cap() {
        let regtest_p2tr = "bcrt1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusgm2jyk";
        assert_eq!(
            parse_payout_identity(regtest_p2tr)
                .map(|(id, worker)| (id.payout_id().to_string(), worker)),
            Ok((regtest_p2tr.to_string(), None)),
            "a regtest taproot payout address parses now"
        );

        let too_long = "a".repeat(crate::MAX_ADDRESS_LEN + 1);
        assert_eq!(
            parse_payout_identity(&too_long),
            Err(IdentityParseError::InvalidAddress(
                InvalidAddressError::TooLong(crate::MAX_ADDRESS_LEN + 1)
            )),
            "the cap moved; it did not disappear"
        );
    }
}
