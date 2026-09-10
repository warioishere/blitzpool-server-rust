// SPDX-License-Identifier: AGPL-3.0-or-later

//! Intake for **rotating** payout identities: a miner supplies a bare xpub, the
//! pool wraps it in ITS OWN descriptor, and every block pays a fresh script
//! derived at that block's height.
//!
//! # The one place the payout descriptor is spelled
//!
//! [`POOL_DESCRIPTOR_TEMPLATE`] is the whole answer to "where does a rotating
//! miner's money go". It is pool-fixed, not miner-selectable, and it is a
//! constant rather than a computation for three reasons that all cash out in
//! this repo:
//!
//! 1. **Group-Solo's ledger-free invariant stays a constant.** `CLAUDE.md`:
//!    *"Group-Solo keeps no ledger. That holds only while every member fits in
//!    the coinbase."* `max_coinbase_outputs` assumes 172 WU per output; a fixed
//!    P2WPKH derivation is 124 WU, known at compile time, so the cap is safe by
//!    a fixed margin. Miner-selectable script types would make the real
//!    per-output weight a function of which members are paid in *this* block —
//!    a ceiling that moves block to block, which that design has no answer for.
//! 2. **One descriptor per xpub, therefore one [`payout_id`] per xpub.** The
//!    same xpub at `/0/*` and at `/1/*` is two identities a miner reasonably
//!    believes is one, and PPLNS would carry two balance rows for them.
//! 3. **A miner can verify a payout without asking us.** One sentence conveys
//!    it, and any descriptor-importing wallet checks it.
//!
//! # Why this is its own crate and not `bp-common`
//!
//! [`bp_common`] is depended on by 19 crates, 11 of which take no `bitcoin`
//! dependency at all (`bp-db`, `bp-stats`, `bp-notifications`, …). `miniscript`
//! pulls `bitcoin` plus `bech32`, so putting descriptor handling there would
//! push a Bitcoin-script dependency onto every crate in the workspace to serve
//! the few that derive scripts. The type that *everything* touches
//! ([`bp_common::PayoutIdentity`]) stays in `bp-common`; the parsing that only
//! the money path touches lives here.
//!
//! This crate depends on `bp-common`, never the reverse.
//!
//! # The credential rule
//!
//! **Never propagate the descriptor parser's error text.** Measured against
//! `miniscript 13.1.0` on 2026-08-10: `Descriptor::from_str` on a bare `xprv`
//! returns a 131-character error **containing the full private key**, while
//! `Xpub::from_str` on the same input returns `unknown version magic bytes:
//! [4, 136, 173, 228]` — 47 characters, no key material. So intake parses with
//! [`bitcoin::bip32::Xpub::from_str`] FIRST and every error here is a fixed
//! variant carrying no borrowed input.
//!
//! This matters locally because the adjacent idiom in
//! `bp_mining_job::address_to_script` is
//! `Address::from_str(a).map_err(|e| ...(e.to_string()))` — correct for an
//! address, which is public, and a spendable key in the logs if copied to a
//! descriptor parser. Note what "reject xprv" does not buy: the rejection *is*
//! the error being formatted, so listing xprv as rejected does not by itself
//! prevent the leak.
//!
//! **Which half of that rule actually carries the weight, measured by mutation
//! on 2026-08-10 rather than assumed:**
//!
//! - Reordering so the *descriptor* parser sees the raw input first, with its
//!   error still mapped to a fixed variant, leaks **nothing** and the suite
//!   stays green. `Xpub::from_str`-first is defence in depth and a clear
//!   statement of intent — it is not the mechanism.
//! - The mechanism is [`IntakeError`] being `Copy`. Adding the variant that a
//!   leak would really need — one holding the parser's `String` — **fails to
//!   compile** (`E0204: the trait Copy cannot be implemented for this type`).
//!
//! So the guard is a type-level one, in the same spirit as `Rotating` being
//! unconstructible in Phase 1: the bad state is unrepresentable rather than
//! merely untaken. `intake_errors_are_copy_and_therefore_cannot_borrow_input`
//! is what holds it, and removing that derive is the change to refuse in
//! review.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::bip32::Xpub;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Address, Network, ScriptBuf};
use bp_common::{
    AddressId, PayoutIdentity, RotatingDescriptor, RotatingScriptSource, RotationError,
};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use miniscript::ForEachKey;

/// THE payout descriptor, as a format template with one `{xpub}` hole.
///
/// `wpkh(<xpub>/0/*)` — BIP-84, P2WPKH, external chain. A miner's payout at
/// height `H` is `m/84'/0'/0'/0/H` of the xpub they supplied, which is the form
/// a hardware wallet displays; the descriptor form is what Core's
/// `importdescriptors` and `deriveaddresses` want. Both spellings are the same
/// path and both belong in the miner-facing documentation.
///
/// **P2WPKH and not P2TR, deliberately — and one of the two reasons is now
/// spent.** It was chosen for both:
///
/// 1. *Width.* Measured 2026-08-10: a regtest P2TR address (`bcrt1p…`) is 64
///    characters against what was then a 62-character cap in `bp_common` and in
///    every identity column. **This reason is gone as of 2026-08-12** —
///    `bp_common::MAX_ADDRESS_LEN` is 90 and migration
///    `0015_widen_identity_columns.sql` widened the columns, as its own change
///    with its own rollback story, exactly as `CLAUDE.md` requires.
/// 2. *Weight.* A P2WPKH output is 124 WU against P2TR's 172, so the same
///    coinbase weight budget pays ~39 % more miners. **This reason stands**, and
///    it is now the whole of the argument.
///
/// So P2TR has become *possible* here, not *advisable*: it would cost ~39 % of
/// the pool's payout capacity per block. And switching is not a config tweak —
/// see the paragraph below, which applies to a script-type change as much as to
/// an edit of the derivation path.
///
/// Changing this constant re-homes every future rotating payout. It does NOT
/// re-home past ones: a `payout_id` is a hash of the descriptor built from this
/// template, so an edit here mints new identities and orphans the ledger rows of
/// the old ones. Treat it as a migration, not a config tweak.
pub const POOL_DESCRIPTOR_TEMPLATE: &str = "wpkh({xpub}/0/*)";

/// The BIP-32 path a miner sees in their wallet, for documentation and support.
/// Must describe the same derivation as [`POOL_DESCRIPTOR_TEMPLATE`]; the two
/// are pinned together by `the_documented_bip32_path_matches_the_descriptor`.
pub const POOL_DERIVATION_PATH_BIP32: &str = "m/84'/0'/0'/0/H";

/// Human-readable script type of every derived payout output.
pub const POOL_SCRIPT_TYPE: &str = "p2wpkh";

/// Serialized weight of one derived payout output, in weight units.
///
/// `8` (value) + `1` (script len) + `22` (OP_0 PUSH20) = 31 bytes, non-witness,
/// so `31 × 4 = 124` WU. Pinned by `a_derived_output_weighs_the_documented_wu`
/// against a real derivation rather than trusted as arithmetic, because
/// `bp_pplns::max_coinbase_outputs` sizes Group-Solo's member cap from a
/// per-output weight and `CLAUDE.md` records that going wrong once.
pub const POOL_OUTPUT_WEIGHT_WU: usize = 124;

/// Why `payout_id` is base58 and not hex — **and why that is now frozen rather
/// than merely chosen.**
///
/// A rotating identity needs a stable, height-invariant key for the ledger
/// (`pplns_balance`, `pplns_payout_history`, `worker_shares_entity`,
/// `blockparty_member`). Measured 2026-08-10 over the canonical descriptor
/// string, against the 62-character cap those columns had at the time:
///
/// | encoding            | `payout_id` width | fit 62 | fit 90 |
/// |---------------------|-------------------|--------|--------|
/// | sha256 **base58**   | 47                | yes    | yes    |
/// | ripemd160 base58    | 31                | yes    | yes    |
/// | sha256 **hex**      | 67                | **no** | yes    |
/// | ripemd160 hex       | 43                | yes    | yes    |
///
/// The original reason was the fourth column not existing: hex would have forced
/// a 32-column migration and base58 would not. **That reason is spent** — the
/// columns are `varchar(90)` since 2026-08-12
/// (`0015_widen_identity_columns.sql`), so hex would fit now. The tripwire that
/// said so was the control assertion in
/// `payout_id_is_base58_and_fits_the_identity_columns`, and it fired as designed.
///
/// What replaces it is stronger than the width argument ever was: **a
/// `payout_id` is content-addressed, so the encoding IS the identity.** Every
/// ledger row already written names a miner by this spelling. Switching to hex
/// would not reformat those keys, it would mint different ones and orphan the
/// balances they hold — the same hazard as editing
/// [`POOL_DESCRIPTOR_TEMPLATE`], and treated the same way: a migration, never a
/// cleanup. `payout_id_is_the_documented_spelling` pins the exact string for a
/// known xpub so a change of encoding, prefix or hash cannot pass quietly.
///
/// sha256 over ripemd160 was, and remains, that the shorter hash buys nothing:
/// both fit, and only one has a collision story worth telling.
const PAYOUT_ID_PREFIX: &str = "xpb";

/// Everything intake can refuse, with **no borrowed input in any variant**.
///
/// That is the credential rule expressed in the type: a variant that carried a
/// `String` would be one `format!` away from a private key in the logs, so
/// there is nowhere to put one. See the module docs.
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum IntakeError {
    /// Not a valid extended PUBLIC key. Covers an `xprv` (the leak case), a
    /// truncated key, a bad checksum, and the wrong network's magic bytes —
    /// deliberately one variant, because distinguishing them means describing
    /// the input.
    #[error("not a valid extended public key")]
    NotAnXpub,
    /// The pool's own template failed to parse or derive. Unreachable via miner
    /// input; it means [`POOL_DESCRIPTOR_TEMPLATE`] was edited into something
    /// invalid, and it is an error rather than a panic because intake runs on
    /// the connection path.
    #[error("the pool payout descriptor is misconfigured")]
    PoolDescriptorInvalid,
    /// No `*` — a descriptor that cannot rotate. Rejected because a
    /// non-wildcard descriptor pays the same script at every height, which is a
    /// static identity wearing a rotating one's clothes.
    #[error("payout descriptor does not rotate (no wildcard)")]
    NoWildcard,
    /// A hardened step in the derivation path. **This one guards a panic**, not
    /// an error — see [`assert_derivable`].
    #[error("payout descriptor has a hardened derivation step")]
    HardenedStepRejected,
    /// A multipath (`<0;1>`) descriptor. Derivation returns
    /// `multipath key cannot be a DerivedDescriptorKey`, and "which of the two
    /// paths gets paid" has no answer the pool should be inventing.
    #[error("payout descriptor is multipath")]
    MultipathRejected,
    /// The miner supplied an extended key but the operator has not enabled
    /// rotating identities (`[payout_identity] allow_rotating`, default false).
    #[error("rotating payout identities are not enabled on this pool")]
    FeatureDisabled,
    /// A stored `miner_identity.descriptor` will not parse or will not derive.
    /// Distinct from [`Self::PoolDescriptorInvalid`] because the input is a
    /// database row rather than this module's own template — the operator needs
    /// to know which one to go and look at.
    #[error("a stored payout descriptor is unusable")]
    StoredIdentityUnusable,
    /// A stored descriptor parses and derives but does **not** hash to the
    /// `payoutId` it was fetched under. The ledger has been crediting one wallet
    /// and the row would pay another; see [`rehydrate_stored_identity`].
    #[error("a stored payout descriptor does not match its payout id")]
    StoredIdentityMismatch,
}

/// A validated rotating payout identity: the pool's descriptor around a miner's
/// xpub, plus the ledger key derived from it.
///
/// Construction is the only way to get one, and construction runs
/// [`assert_derivable`] — so every value of this type can be derived at any
/// height without panicking. That is the invariant the whole module exists to
/// establish.
#[derive(Clone, Debug)]
pub struct RotatingPayout {
    /// The parsed descriptor. Kept parsed rather than re-parsed per use:
    /// measured 2026-08-10, `Descriptor<DescriptorPublicKey>` **is**
    /// `Send + Sync + 'static`, so it can live in shared state (this was an
    /// open question; the fallback of storing the canonical string and parsing
    /// per use measured 1.4× and is not needed).
    descriptor: Descriptor<DescriptorPublicKey>,
    /// Canonical descriptor string — what `payout_id` hashes and what a miner
    /// can paste into `bitcoin-cli deriveaddresses`.
    canonical: String,
    payout_id: AddressId,
}

impl RotatingPayout {
    /// Wrap a **bare xpub** in the pool's descriptor and validate it.
    ///
    /// Bare xpub is the intake form on purpose: 111 characters, no dot (so the
    /// `identity.worker` split cannot bite), no descriptor-syntax collisions,
    /// and origin-key information is *unrepresentable* — which is what closes
    /// the "two spellings of one wallet, two ledger rows, one script" hazard at
    /// the door rather than by normalization.
    pub fn from_xpub_str(raw: &str) -> Result<Self, IntakeError> {
        // Xpub FIRST, and its error is discarded rather than mapped. See the
        // module docs: this ordering is the credential rule.
        let xpub = Xpub::from_str(raw.trim()).map_err(|_| IntakeError::NotAnXpub)?;
        Self::from_xpub(&xpub)
    }

    /// Same as [`Self::from_xpub_str`] for an already-parsed key.
    pub fn from_xpub(xpub: &Xpub) -> Result<Self, IntakeError> {
        let spelled = POOL_DESCRIPTOR_TEMPLATE.replace("{xpub}", &xpub.to_string());
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&spelled)
            // Not `e.to_string()`. The input here is pool-built and contains no
            // private key, but the rule is the rule: no parser text escapes this
            // module, so the habit cannot be copied to a path where it would.
            .map_err(|_| IntakeError::PoolDescriptorInvalid)?;

        assert_derivable(&descriptor)?;

        let canonical = descriptor.to_string();
        let payout_id = payout_id_for(&canonical);
        Ok(Self {
            descriptor,
            canonical,
            payout_id,
        })
    }

    /// The height-invariant ledger key. Safe to store in any identity column —
    /// they are `character varying(90)` since
    /// `0015_widen_identity_columns.sql`, and a `payout_id` is 47 characters.
    /// See [`PAYOUT_ID_PREFIX`].
    ///
    /// This is **not** a payout script and cannot be spent to. The
    /// `PayoutIdentity` sum type is what keeps that confusion inexpressible:
    /// `payout_id()` and [`Self::script_at`] have different return types.
    pub fn payout_id(&self) -> &AddressId {
        &self.payout_id
    }

    /// The canonical descriptor, for storage and for a miner to verify against
    /// `bitcoin-cli deriveaddresses "<desc>" [H,H]`.
    pub fn canonical_descriptor(&self) -> &str {
        &self.canonical
    }

    /// The script this identity is paid at block height `H`.
    ///
    /// Cannot panic: [`assert_derivable`] ran at construction and this type has
    /// no other constructor. Derivation is idempotent at a fixed height
    /// (measured), which is what makes height-indexing safe across an orphan
    /// reconvergence — re-mining height `H` pays the same script.
    pub fn script_at(&self, height: u32) -> Result<ScriptBuf, IntakeError> {
        Ok(self
            .descriptor
            .at_derivation_index(height)
            .map_err(|_| IntakeError::PoolDescriptorInvalid)?
            .script_pubkey())
    }

    /// The address form of [`Self::script_at`], for logs, the API and regtest
    /// cross-checks against Core.
    pub fn address_at(&self, network: Network, height: u32) -> Result<Address, IntakeError> {
        self.descriptor
            .at_derivation_index(height)
            .map_err(|_| IntakeError::PoolDescriptorInvalid)?
            .address(network)
            .map_err(|_| IntakeError::PoolDescriptorInvalid)
    }
}

impl fmt::Display for RotatingPayout {
    /// The `payout_id`, NOT the descriptor. A descriptor in a log line is a
    /// miner's whole wallet-watching capability; the id is an opaque key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.payout_id.as_str())
    }
}

/// **The one implementation**, and the reason
/// [`bp_common::PayoutIdentity`] can live in a `bitcoin`-free crate.
///
/// See [`RotatingScriptSource`]'s docs for why the trait exists at all. What
/// matters here is that this is the only `impl` of it in the workspace: a second
/// one would be a second answer to "which script does this miner get at height
/// H", which is the shape of the 2026-07-25/26 entry in `CLAUDE.md` (the same
/// fix landing in two PRs a day apart).
impl RotatingScriptSource for RotatingPayout {
    /// `Vec<u8>` and not `ScriptBuf` because the trait is `bitcoin`-free —
    /// `bp-common` cannot name `ScriptBuf`. Raw bytes are what the coinbase seam
    /// wants anyway; its static arm produces them the same way
    /// (`address_to_script(...).into_bytes()`).
    ///
    /// The error is flattened to [`RotationError::NotDerivable`], dropping which
    /// [`IntakeError`] it was. Nothing is lost that a caller could use: by the
    /// time an identity exists, [`assert_derivable`] has already run, so every
    /// failure here means the invariant was established somewhere other than
    /// intake — and the only safe response to that is to fail the coinbase,
    /// regardless of which variant it was.
    fn script_at(&self, height: u32) -> Result<Vec<u8>, RotationError> {
        RotatingPayout::script_at(self, height)
            .map(|s| s.into_bytes())
            .map_err(|_| RotationError::NotDerivable)
    }

    fn canonical_descriptor(&self) -> &str {
        RotatingPayout::canonical_descriptor(self)
    }
}

impl RotatingPayout {
    /// This rotating payout as a [`PayoutIdentity`] — **the only route from
    /// intake into the payout path.**
    ///
    /// `PayoutIdentity::rotating` is `pub` and could be called with any
    /// `RotatingScriptSource`, but this crate is the only place that has one,
    /// and this method is the only place that wraps it. So "every rotating
    /// identity in the pool passed the three intake assertions" is a property of
    /// one function rather than of a convention.
    ///
    /// Consumes `self`: the descriptor moves into the `Arc` the payout path
    /// clones, so there is no second copy that could drift from the `payout_id`
    /// hashed off it.
    pub fn into_payout_identity(self) -> PayoutIdentity {
        let payout_id = self.payout_id.clone();
        PayoutIdentity::rotating(RotatingDescriptor::new(Arc::new(self)), payout_id)
    }
}

/// Does this wire identity **look like** an attempt at an extended key?
///
/// A prefix test, not validation — it exists so intake can tell "this miner
/// meant to give us an xpub and got it wrong" (report [`IntakeError`]) from
/// "this is an address" (the existing static path, unchanged). Getting that
/// wrong in the permissive direction would turn a typo'd address into a
/// confusing descriptor error; in the strict direction it would silently send a
/// real xpub down the address path, where it fails the shape check with a message
/// about length (111 characters against `bp_common::MAX_ADDRESS_LEN`, which is 90
/// since 2026-08-12 and still nowhere near admitting a key).
///
/// The four prefixes are the mainnet/testnet spellings of a BIP-32 extended
/// **public** key and the BIP-49/84 variants (`ypub`/`zpub` and their testnet
/// forms) a miner may paste from a wallet that labels them that way. An `xprv`
/// deliberately matches too: it must reach intake and be refused there, because
/// the alternative is it going down the address path and being logged.
pub fn looks_like_extended_key(raw: &str) -> bool {
    let t = raw.trim();
    // 111 characters is the length of every BIP-32 extended key in base58; a
    // prefix alone would match a short typo and send it to the wrong reporter.
    t.len() >= 100
        && (t.starts_with("xpub")
            || t.starts_with("tpub")
            || t.starts_with("ypub")
            || t.starts_with("zpub")
            || t.starts_with("upub")
            || t.starts_with("vpub")
            || t.starts_with("xprv")
            || t.starts_with("tprv"))
}

/// Turn a wire identity into a rotating payout, subject to the operator's flag.
///
/// `allow_rotating` is `config.payout_identity.allow_rotating` and defaults to
/// `false`. It is taken as an argument rather than read from a global so this
/// crate stays free of `bp-config` — and so the gate is visible in the signature
/// at every call site.
///
/// Returns:
/// - `Ok(None)` — not an extended-key attempt. The caller's existing static
///   address path handles it, byte for byte as before.
/// - `Err(FeatureDisabled)` — it *was* an attempt, and the operator has not
///   enabled the feature. Deliberately an error and not `Ok(None)`: falling
///   through to the address path would refuse the same connection with a
///   length-related message and leave the miner debugging the wrong thing.
/// - `Err(_)` / `Ok(Some(_))` — intake's verdict on the key.
///
/// Verified by mutation, 2026-08-10: replacing the `allow_rotating` check with
/// `let _ = allow_rotating;` fails exactly `the_flag_is_what_admits_a_rotating_identity`
/// and `the_flag_does_not_relax_the_assertions`, and no other test in the
/// workspace notices. The flag is only as real as those two.
pub fn intake_wire_identity(
    raw: &str,
    allow_rotating: bool,
) -> Result<Option<RotatingPayout>, IntakeError> {
    if !looks_like_extended_key(raw) {
        return Ok(None);
    }
    if !allow_rotating {
        return Err(IntakeError::FeatureDisabled);
    }
    RotatingPayout::from_xpub_str(raw).map(Some)
}

/// Rebuild a stored rotating identity, and prove it is the one its key names.
///
/// The settlement half of intake. A block found at height `H` is booked ~100
/// blocks later, by which time the in-memory directory may not hold the miner at
/// all — it is refcounted to *connection* lifetime — so the descriptor comes back
/// out of `miner_identity` instead. That row is the only place it survives a
/// restart, and this is the one function that turns it back into something
/// payable.
///
/// **The integrity check is the point, not the parse.** `payout_id` is
/// `"xpb" + base58(sha256(canonical descriptor))`, so the mapping is
/// content-addressed and 1:1: a row whose descriptor does not re-hash to the key
/// it was fetched under is corrupt, and the alternative to noticing is deriving a
/// payout script for a *different* wallet than the one the ledger has been
/// crediting. Both halves live here, together, so a caller cannot do the parse
/// and forget the comparison — which is why this takes the stored key rather than
/// returning a [`RotatingPayout`] for the caller to check.
///
/// It also re-runs [`assert_derivable`]. A stored row predates any change to
/// those assertions, so a descriptor that was acceptable when it was written is
/// re-judged by today's rules rather than trusted for having once passed.
///
/// The credential rule applies unchanged: no parser text escapes, and an `xprv`
/// cannot get through — `Descriptor<DescriptorPublicKey>` has nowhere to put a
/// private key, so `wpkh(xprv…/0/*)` fails the parse rather than being stored and
/// re-derived. [`IntakeError`] is still `Copy`, which is what keeps a
/// well-meaning `#[error("… {descriptor}")]` from compiling.
pub fn rehydrate_stored_identity(
    payout_id: &str,
    descriptor: &str,
) -> Result<RotatingPayout, IntakeError> {
    // Not `e.to_string()`, for the same reason as everywhere else in this module.
    let parsed = Descriptor::<DescriptorPublicKey>::from_str(descriptor.trim())
        .map_err(|_| IntakeError::StoredIdentityUnusable)?;
    assert_derivable(&parsed)?;

    let canonical = parsed.to_string();
    let rebuilt = payout_id_for(&canonical);
    if rebuilt.as_str() != payout_id {
        return Err(IntakeError::StoredIdentityMismatch);
    }
    Ok(RotatingPayout {
        descriptor: parsed,
        canonical,
        payout_id: rebuilt,
    })
}

/// The three assertions, in one function, applied to anything derivable.
///
/// | descriptor | `has_wildcard()` | `at_derivation_index()` |
/// |---|---|---|
/// | `wpkh(xpub…/0/*)` | `true` | `Ok` |
/// | **hardened step** | `true` | ***PANIC*** |
/// | **multipath** `<0;1>` | `true` | `Err` |
///
/// Measured against `miniscript 13.1.0` on 2026-08-10; the panic is at
/// `descriptor/key.rs:868`, *"The key should not contain any wildcards at this
/// point: HardenedStep"*.
///
/// **The hardened-step check is the one that matters.** `has_wildcard()` is
/// `true` for all three, so the wildcard-only guard that the obvious
/// implementation reaches for lets a hardened descriptor straight through to a
/// panic — and that panic is not a rejected share, it is a panic **inside
/// coinbase assembly**, on a path that runs for every job for every connected
/// miner. There is no derive-time handling to fall back on, because the
/// derive-time failure mode is not an error.
pub fn assert_derivable(d: &Descriptor<DescriptorPublicKey>) -> Result<(), IntakeError> {
    if !d.has_wildcard() {
        return Err(IntakeError::NoWildcard);
    }
    // `for_each_key` is all-keys (`for_any_key` is the "any" form) — so this
    // reads "every key is free of hardened steps".
    if !d.for_each_key(|k: &DescriptorPublicKey| !k.has_hardened_step()) {
        return Err(IntakeError::HardenedStepRejected);
    }
    if d.is_multipath() {
        return Err(IntakeError::MultipathRejected);
    }
    Ok(())
}

/// `payout_id` = `"xpb" + base58(sha256(canonical descriptor))`, 47 characters.
///
/// The prefix makes a rotating identity greppable in a ledger row and keeps the
/// id out of the address namespace — no base58 hash can be mistaken for an
/// address that anything would try to pay. See [`PAYOUT_ID_PREFIX`] for why
/// base58 rather than hex.
fn payout_id_for(canonical: &str) -> AddressId {
    let digest = sha256::Hash::hash(canonical.as_bytes());
    let encoded = bitcoin::base58::encode(digest.as_byte_array());
    // 3 + 43..=44 chars, comfortably inside `bp_common::MAX_ADDRESS_LEN`;
    // `expect` is the honest form here because a failure would mean the
    // arithmetic above is wrong, which
    // `payout_id_is_base58_and_fits_the_identity_columns` pins.
    AddressId::new(format!("{PAYOUT_ID_PREFIX}{encoded}"))
        .expect("a base58 sha256 digest with a 3-char prefix fits the identity shape")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-32 test vector xpub (no funds, published in the BIP).
    const XPUB: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    /// The matching xprv. Used ONLY to prove the leak is closed.
    const XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    fn spell(xpub: &str) -> String {
        POOL_DESCRIPTOR_TEMPLATE.replace("{xpub}", xpub)
    }

    /// The refusal from [`intake_wire_identity`], or a panic naming what came
    /// back instead.
    ///
    /// This exists so tests can compare errors without a `PartialEq` derive on
    /// [`RotatingPayout`]. The compiler offers that derive; taking it would make
    /// structural equality of two payout identities silently available on the
    /// money path, where "same descriptor" and "same identity" are a question
    /// for `payout_id`, not for field-by-field comparison.
    fn intake_err(raw: &str, allow_rotating: bool) -> IntakeError {
        match intake_wire_identity(raw, allow_rotating) {
            Err(e) => e,
            Ok(Some(_)) => panic!("expected a refusal, got an admitted rotating identity"),
            Ok(None) => panic!("expected a refusal, got a fall-through to the static path"),
        }
    }

    // ── Decision 7: the pool constant, with its negative control ───────

    /// The pool's own descriptor satisfies all three assertions.
    ///
    /// On its own this test is nearly worthless — it would pass just as happily
    /// against an `assert_derivable` whose body was `Ok(())`. What gives it
    /// teeth is the negative control immediately below, which shares the
    /// template and the xpub and differs only in the hardened step. Per
    /// `CLAUDE.md`: *"A test that claims a safeguard must be shown to fail
    /// without it."*
    #[test]
    fn the_pool_descriptor_satisfies_all_three_assertions() {
        let d = Descriptor::<DescriptorPublicKey>::from_str(&spell(XPUB))
            .expect("the pool template must parse");
        assert!(d.has_wildcard(), "the pool descriptor must rotate");
        assert!(
            d.for_each_key(|k: &DescriptorPublicKey| !k.has_hardened_step()),
            "the pool descriptor must have no hardened step"
        );
        assert!(
            !d.is_multipath(),
            "the pool descriptor must not be multipath"
        );
        assert_eq!(assert_derivable(&d), Ok(()));
        // And it actually derives — the assertions exist to promise this.
        assert!(d.at_derivation_index(800_000).is_ok());
    }

    /// **The negative control for the test above.**
    ///
    /// A hardened variant of the same template with the same xpub is rejected —
    /// so the assertions are doing work, and the positive test cannot be
    /// passing on a precondition that silently did not hold.
    ///
    /// It also pins the thing that makes the hardened check non-optional:
    /// `has_wildcard()` is `true` here too. A wildcard-only guard admits this
    /// descriptor, and admitting it means a panic inside coinbase assembly.
    #[test]
    fn a_hardened_variant_of_the_pool_descriptor_is_rejected() {
        let hardened = spell(XPUB).replace("/0/*", "/0h/*");
        let d = Descriptor::<DescriptorPublicKey>::from_str(&hardened)
            .expect("miniscript parses a hardened descriptor happily — that is the problem");

        assert!(
            d.has_wildcard(),
            "precondition: the wildcard-only guard would ADMIT this, which is \
             why the hardened assertion exists"
        );
        assert_eq!(assert_derivable(&d), Err(IntakeError::HardenedStepRejected));
    }

    /// The third assertion, with the same shape of control: multipath parses,
    /// has a wildcard, and must still be refused.
    #[test]
    fn a_multipath_variant_of_the_pool_descriptor_is_rejected() {
        let multi = spell(XPUB).replace("/0/*", "/<0;1>/*");
        let d = Descriptor::<DescriptorPublicKey>::from_str(&multi).expect("multipath parses");
        assert!(
            d.has_wildcard(),
            "precondition: wildcard-only admits this too"
        );
        assert_eq!(assert_derivable(&d), Err(IntakeError::MultipathRejected));
    }

    /// A descriptor with no `*` is refused: it would pay one script forever.
    #[test]
    fn a_non_wildcard_descriptor_is_rejected() {
        let fixed = spell(XPUB).replace("/0/*", "/0/7");
        let d = Descriptor::<DescriptorPublicKey>::from_str(&fixed).expect("a fixed index parses");
        assert_eq!(assert_derivable(&d), Err(IntakeError::NoWildcard));
    }

    /// Intake refuses a hardened descriptor *before* it can reach derivation.
    ///
    /// The guarded call really does abort the process, so this asserts the
    /// guard from the outside: `RotatingPayout` has one constructor, it runs
    /// `assert_derivable`, and therefore no value of the type can panic in
    /// `script_at`. The panic itself is pinned by
    /// `a_hardened_descriptor_panics_at_derivation` below.
    #[test]
    fn every_rotating_payout_derives_at_any_height_without_panicking() {
        let p = RotatingPayout::from_xpub_str(XPUB).expect("a bare xpub is the intake form");
        for h in [0u32, 1, 800_000, u32::MAX / 2] {
            assert!(p.script_at(h).is_ok(), "height {h} must derive");
        }
    }

    /// **The panic, demonstrated.** This is the failure mode the hardened
    /// assertion prevents, caught rather than described — so the doc comment on
    /// [`assert_derivable`] is checked by the suite instead of trusted.
    #[test]
    fn a_hardened_descriptor_panics_at_derivation() {
        let hardened = spell(XPUB).replace("/0/*", "/0h/*");
        let d = Descriptor::<DescriptorPublicKey>::from_str(&hardened).unwrap();

        let prior = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the expected panic out of the log
        let outcome = std::panic::catch_unwind(|| d.at_derivation_index(800_000));
        std::panic::set_hook(prior);

        assert!(
            outcome.is_err(),
            "miniscript 13.1.0 PANICS on a hardened step at derivation — if this \
             ever becomes an Err, the hardened assertion is still required, but \
             this test's rationale needs rewriting"
        );
    }

    // ── Decision 6: the credential rule ────────────────────────────────

    /// An `xprv` is refused, and — the part that matters — the error carries
    /// none of it.
    ///
    /// The control is the measured leak: `Descriptor::from_str` on the same
    /// input produces an error containing the full private key. If this test
    /// only asserted `Err(NotAnXpub)` it would pass against an implementation
    /// that formatted the key into its message.
    #[test]
    fn an_xprv_is_refused_and_the_error_carries_no_key_material() {
        let err = RotatingPayout::from_xpub_str(XPRV).expect_err("an xprv is not an xpub");
        assert_eq!(err, IntakeError::NotAnXpub);

        let text = err.to_string();
        let body = &XPRV[4..40]; // a distinctive slice of the key
        assert!(
            !text.contains(body) && !text.contains(XPRV),
            "intake error leaked key material: {text}"
        );

        // Negative control: this is what we did NOT do, and it is a real leak.
        let leaky = Descriptor::<DescriptorPublicKey>::from_str(XPRV)
            .expect_err("a bare xprv is not a descriptor")
            .to_string();
        assert!(
            leaky.contains(body),
            "precondition: miniscript's error is supposed to contain the key — if \
             it no longer does, `Xpub::from_str`-first is still right, but this \
             control has stopped controlling for anything"
        );
    }

    /// No `IntakeError` variant can carry input, so none can be made to leak.
    ///
    /// **This is the test that actually holds the credential rule**, verified by
    /// mutation 2026-08-10: adding the variant a leak would need — one holding
    /// the parser's `String` — does not fail this assertion at runtime, it fails
    /// to *compile*, with `E0204: the trait Copy cannot be implemented for this
    /// type`. Meanwhile letting the descriptor parser see the raw input first
    /// leaks nothing as long as this derive stands.
    ///
    /// So `Copy` here is load-bearing and not decoration. A future author who
    /// needs richer intake errors must add a *variant without a payload*, or
    /// consciously replace this guard with something equally mechanical.
    #[test]
    fn intake_errors_are_copy_and_therefore_cannot_borrow_input() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<IntakeError>();
    }

    /// Garbage and empty input are refused as the same variant — intake never
    /// describes what was wrong with a credential.
    #[test]
    fn malformed_input_is_refused_without_description() {
        for raw in ["", "   ", "not-a-key", "xpub", &XPUB[..40], "bc1qxyz"] {
            let err = RotatingPayout::from_xpub_str(raw)
                .err()
                .unwrap_or_else(|| panic!("{raw:?} must be refused"));
            assert_eq!(
                err,
                IntakeError::NotAnXpub,
                "{raw:?} must be refused as NotAnXpub"
            );
        }
    }

    // ── payout_id ──────────────────────────────────────────────────────

    /// The `payout_id` fits every identity column, with room to spare.
    ///
    /// This test used to carry a control asserting that the **hex** spelling of
    /// the same digest did NOT fit, because that was the entire reason base58 was
    /// chosen, and it said in as many words: *"if it does, the 62-char cap moved
    /// and this decision needs revisiting"*. The cap moved on 2026-08-12
    /// (`0015_widen_identity_columns.sql`), the control fired, and the revisiting
    /// is recorded at [`PAYOUT_ID_PREFIX`]: the decision stands, on the ground
    /// that the encoding is now the identity rather than because hex is too wide.
    ///
    /// So the width claim keeps only the assertions that are still true, and
    /// `payout_id_is_the_documented_spelling` carries what the control used to.
    #[test]
    fn payout_id_is_base58_and_fits_the_identity_columns() {
        let p = RotatingPayout::from_xpub_str(XPUB).unwrap();
        let id = p.payout_id().as_str();

        assert!(id.starts_with(PAYOUT_ID_PREFIX), "{id} must be greppable");
        assert!(
            id.len() <= bp_common::MAX_ADDRESS_LEN,
            "payout_id is {} chars and the identity columns are varchar({})",
            id.len(),
            bp_common::MAX_ADDRESS_LEN
        );
        // It round-trips through the shape gate every ledger column is behind.
        assert!(AddressId::new(id).is_ok());
    }

    /// **The exact spelling of a `payout_id`, for a known xpub.** A golden value,
    /// because the id is content-addressed: a change of hash, encoding or prefix
    /// does not reformat the ledger keys already written, it mints different ones
    /// and orphans the balances the old ones hold.
    ///
    /// It replaces the width control that `varchar(90)` retired — same job, and
    /// it does not depend on any column being narrow. The hex assertion below is
    /// what makes it bite in the direction that is actually tempting:
    /// `to_string()` on a `sha256::Hash` is hex, one keystroke from
    /// `bitcoin::base58::encode`.
    #[test]
    fn payout_id_is_the_documented_spelling() {
        let p = RotatingPayout::from_xpub_str(XPUB).unwrap();
        assert_eq!(
            p.payout_id().as_str(),
            "xpbDvdXsU17hMXJncLySBtpKYsBPNZVX1AZmUcG8ccuQZz9",
            "the ledger key for the BIP-32 test vector must not move — see \
             PAYOUT_ID_PREFIX"
        );

        let hex = sha256::Hash::hash(p.canonical_descriptor().as_bytes()).to_string();
        assert_eq!(hex.len(), 64, "sha256 hex is 64 chars");
        assert_ne!(
            format!("{PAYOUT_ID_PREFIX}{hex}"),
            p.payout_id().as_str(),
            "the hex spelling is a DIFFERENT identity for the same wallet, and it \
             fits the widened columns now — so nothing but this test stops the \
             switch"
        );
    }

    /// The ledger key does not move with the height. This is what makes PPLNS
    /// carry-forward work for a rotating miner: one `pplns_balance` row, not one
    /// per block.
    #[test]
    fn payout_id_is_height_invariant_while_the_script_rotates() {
        let p = RotatingPayout::from_xpub_str(XPUB).unwrap();
        let id = p.payout_id().clone();

        let a = p.script_at(800_000).unwrap();
        let b = p.script_at(800_001).unwrap();
        assert_ne!(a, b, "precondition: the script must actually rotate");
        assert_eq!(p.payout_id(), &id, "the ledger key must not rotate with it");
    }

    /// Same xpub, same id — the ledger key is a function of the identity, not of
    /// when it was parsed.
    #[test]
    fn the_same_xpub_yields_the_same_payout_id() {
        let a = RotatingPayout::from_xpub_str(XPUB).unwrap();
        let b = RotatingPayout::from_xpub_str(&format!("  {XPUB}  ")).unwrap();
        assert_eq!(a.payout_id(), b.payout_id(), "whitespace is not identity");
        assert_eq!(a.canonical_descriptor(), b.canonical_descriptor());
    }

    // ── derivation properties ──────────────────────────────────────────

    /// Re-deriving at the same height gives the same script. This is the
    /// property that makes indexing by height safe when a block is orphaned and
    /// height `H` is re-mined.
    #[test]
    fn derivation_is_idempotent_at_a_fixed_height() {
        let p = RotatingPayout::from_xpub_str(XPUB).unwrap();
        assert_eq!(p.script_at(800_000).unwrap(), p.script_at(800_000).unwrap());
    }

    /// The documented constants describe the real derivation.
    ///
    /// `POOL_OUTPUT_WEIGHT_WU` is measured off an actual derived script, not
    /// recomputed from the same arithmetic that produced the constant — a
    /// per-output weight is what `bp_pplns::max_coinbase_outputs` sizes
    /// Group-Solo's ledger-free member cap from.
    #[test]
    fn a_derived_output_weighs_the_documented_wu() {
        let p = RotatingPayout::from_xpub_str(XPUB).unwrap();
        let script = p.script_at(800_000).unwrap();
        assert!(
            script.is_p2wpkh(),
            "the pool constant promises {POOL_SCRIPT_TYPE}"
        );

        // 8 value + 1 script-len + script, non-witness ⇒ ×4.
        let wu = (8 + 1 + script.len()) * 4;
        assert_eq!(wu, POOL_OUTPUT_WEIGHT_WU);

        // And it stays under the worst case `max_coinbase_outputs` sizes
        // Group-Solo's ledger-free member cap from. Read from `bp_pplns` rather
        // than written as `172`, so raising one and not the other is a failure
        // here instead of a member cap that is quietly no longer safe.
        assert!(
            POOL_OUTPUT_WEIGHT_WU < bp_pplns::COINBASE_OUTPUT_WEIGHT as usize,
            "a rotating output ({POOL_OUTPUT_WEIGHT_WU} WU) must stay under the \
             worst case the member cap assumes ({} WU), or Group-Solo's \
             ledger-free invariant is no longer safe by construction",
            bp_pplns::COINBASE_OUTPUT_WEIGHT
        );
    }

    /// Derived addresses fit the identity shape on every network.
    ///
    /// The P2TR block below **used to be the control**: it asserted that the same
    /// derivation as taproot produces a 64-character `bcrt1p…` against a
    /// 62-character cap, documenting a pre-existing latent break that this feature
    /// was not allowed to fix. Phase 5 fixed it separately
    /// (`0015_widen_identity_columns.sql`, `MAX_ADDRESS_LEN = 90`), so the same
    /// address is now asserted to *pass* — the break is closed, and this is the
    /// test that says so rather than a comment claiming it.
    ///
    /// Which leaves the pool path on P2WPKH for weight alone — 124 WU against
    /// P2TR's 172 — pinned by `a_derived_output_weighs_the_documented_wu`, not
    /// here.
    #[test]
    fn derived_addresses_fit_the_identity_shape_on_every_network() {
        let p = RotatingPayout::from_xpub_str(XPUB).unwrap();
        for network in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Regtest,
            Network::Signet,
        ] {
            let a = p.address_at(network, 800_000).unwrap().to_string();
            assert!(
                a.len() <= bp_common::MAX_ADDRESS_LEN && AddressId::new(&a).is_ok(),
                "{network:?} derived address is {} chars: {a}",
                a.len()
            );
        }

        // The widest address this repo can produce, and the one that did not fit
        // before Phase 5. Kept as a live assertion because it is the only place a
        // regtest P2TR address is constructed at all.
        let tr = Descriptor::<DescriptorPublicKey>::from_str(&format!("tr({XPUB}/0/*)")).unwrap();
        let tr_addr = tr
            .at_derivation_index(800_000)
            .unwrap()
            .address(Network::Regtest)
            .unwrap()
            .to_string();
        assert_eq!(tr_addr.len(), 64, "a regtest P2TR address is 64 chars");
        assert!(
            AddressId::new(&tr_addr).is_ok(),
            "a regtest P2TR address must fit the identity shape now — it did not \
             until MAX_ADDRESS_LEN moved to {}",
            bp_common::MAX_ADDRESS_LEN
        );
    }

    // ── the flag, and the intake seam ──────────────────────────────────

    /// **With the flag off — the default — an xpub is refused and nothing
    /// rotates.** This is the state every existing deployment upgrades into.
    ///
    /// The `Ok(Some(_))` case with the flag on is the negative control: without
    /// it, an `intake_wire_identity` that returned `Err` unconditionally would
    /// satisfy every assertion here.
    #[test]
    fn the_flag_is_what_admits_a_rotating_identity() {
        // Off: refused, and refused as the *feature* being off — not as a bad
        // key, which would send a miner hunting a typo that isn't there.
        assert_eq!(intake_err(XPUB, false), IntakeError::FeatureDisabled);

        // On: admitted.
        let admitted = intake_wire_identity(XPUB, true)
            .expect("a valid xpub with the flag on is admitted")
            .expect("and it is an extended-key attempt");
        assert!(admitted.payout_id().as_str().starts_with(PAYOUT_ID_PREFIX));

        // An address is not an extended-key attempt in either flag state, so
        // the static path keeps handling it byte for byte as before.
        for flag in [false, true] {
            let out = intake_wire_identity("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", flag)
                .expect("an address is not an intake error");
            assert!(
                out.is_none(),
                "an address must fall through to the static path (flag={flag})"
            );
        }
    }

    /// The flag gates the feature, it does not weaken validation: a bad key with
    /// the flag ON is still refused.
    ///
    /// And an `xprv` is reported as `FeatureDisabled` when the flag is off,
    /// which is the *right* order — the pool says "not enabled here" without
    /// having parsed the credential at all.
    #[test]
    fn the_flag_does_not_relax_the_assertions() {
        assert_eq!(
            intake_err(XPRV, true),
            IntakeError::NotAnXpub,
            "the flag admits the feature, not invalid keys"
        );
        assert_eq!(
            intake_err(XPRV, false),
            IntakeError::FeatureDisabled,
            "with the feature off the pool need not parse a credential at all"
        );
        // Either way the refusal carries no key material — the flag gate is a
        // second path to the same rule Decision 6 sets.
        for flag in [false, true] {
            let text = intake_err(XPRV, flag).to_string();
            assert!(
                !text.contains(&XPRV[4..24]),
                "a refusal must never echo the credential (flag={flag}): {text}"
            );
        }
    }

    /// The look-like test decides which *reporter* an identity gets, so its two
    /// failure directions are both bugs: a real xpub falling through to the
    /// address path (rejected for its length — 111 chars against the identity
    /// shape), or a typo'd address being answered with a descriptor error.
    #[test]
    fn looks_like_extended_key_separates_keys_from_addresses() {
        for key in [XPUB, XPRV, &format!("  {XPUB}  ")] {
            assert!(looks_like_extended_key(key), "{key} is an extended key");
        }
        for not_key in [
            "",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "bcrt1q05r5k9ad5tr3hw4grwnvgl7pcg0dt37pke9new",
            "xpub",      // a prefix alone is a typo, not an attempt
            &XPUB[..50], // truncated — too short to be a key
            "worker.name",
        ] {
            assert!(
                !looks_like_extended_key(not_key),
                "{not_key:?} must go down the address path"
            );
        }
        // A real extended key is 111 chars; the length floor must sit below it
        // and above an address (the longest here is a 64-char regtest P2TR).
        assert_eq!(XPUB.len(), 111);
    }

    /// The two published spellings of the path must not drift apart. They are
    /// two constants and nothing but this test connects them.
    #[test]
    fn the_documented_bip32_path_matches_the_descriptor() {
        // wpkh ⇒ BIP-84 purpose 84', and `/0/*` ⇒ external chain, index = H.
        assert!(POOL_DESCRIPTOR_TEMPLATE.starts_with("wpkh("));
        assert!(POOL_DERIVATION_PATH_BIP32.starts_with("m/84'"));
        assert!(
            POOL_DESCRIPTOR_TEMPLATE.ends_with("/0/*)"),
            "the descriptor's external chain + wildcard must match {POOL_DERIVATION_PATH_BIP32}"
        );
        assert!(POOL_DERIVATION_PATH_BIP32.ends_with("/0/H"));
    }

    // ── Rehydration from `miner_identity` (plan Phase 4a) ──────────────

    /// A stored row round-trips to the identity that wrote it, and derives the
    /// same script.
    ///
    /// The script assertion is the one that matters. Comparing `payout_id`s only
    /// proves the hash agrees with itself; comparing the derived script at a
    /// height proves the *rehydrated descriptor pays where the coinbase paid*,
    /// which is the only thing settlement needs from this function.
    #[test]
    fn a_stored_identity_rehydrates_to_the_same_payouts() {
        let original = RotatingPayout::from_xpub_str(XPUB).expect("intake");
        let rebuilt = rehydrate_stored_identity(
            original.payout_id().as_str(),
            original.canonical_descriptor(),
        )
        .expect("rehydrate");

        assert_eq!(rebuilt.payout_id(), original.payout_id());
        assert_eq!(
            rebuilt.canonical_descriptor(),
            original.canonical_descriptor()
        );
        for height in [0u32, 1, 840_000, 2_099_999] {
            assert_eq!(
                rebuilt.script_at(height).expect("rebuilt derives"),
                original.script_at(height).expect("original derives"),
                "rehydrated identity must pay the same script at {height}"
            );
        }
    }

    /// **The negative control for the integrity check**, and the reason
    /// [`rehydrate_stored_identity`] takes the key instead of returning the
    /// identity for the caller to compare.
    ///
    /// A row that pairs one miner's `payoutId` with another miner's descriptor is
    /// exactly the corruption that would pay wallet B while the ledger credits
    /// wallet A. Both descriptors here are individually valid and individually
    /// derivable, so nothing but the hash comparison can tell them apart —
    /// delete that comparison and this test is the only thing in the workspace
    /// that fails.
    #[test]
    fn a_stored_descriptor_paired_with_another_miners_key_is_refused() {
        let mine = RotatingPayout::from_xpub_str(XPUB).expect("intake");
        // A second, real, distinct xpub — the same one `payout_identities.rs`
        // uses as `XPUB_B`. Fabricating one does not work: base58 is checksummed,
        // so an invented string is refused as `NotAnXpub` and the test would
        // "pass" on the wrong refusal.
        let theirs = RotatingPayout::from_xpub_str(
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        )
        .expect("a second valid xpub");
        assert_ne!(
            mine.payout_id(),
            theirs.payout_id(),
            "precondition: the two identities must differ"
        );

        let err =
            rehydrate_stored_identity(mine.payout_id().as_str(), theirs.canonical_descriptor())
                .expect_err("a mismatched pair must be refused");
        assert_eq!(err, IntakeError::StoredIdentityMismatch);
    }

    /// The assertions are re-run on the way back in, not assumed from the fact
    /// that the row exists.
    ///
    /// A hardened descriptor is the one that *panics* at derivation
    /// (`a_hardened_descriptor_panics_at_derivation`), so a stored row is the one
    /// place it could reach coinbase assembly without passing intake — a direct
    /// `INSERT`, or a row written before the assertion existed.
    #[test]
    fn a_stored_descriptor_is_re_judged_by_todays_assertions() {
        let hardened = spell(XPUB).replace("/0/*", "/0h/*");
        let parsed =
            Descriptor::<DescriptorPublicKey>::from_str(&hardened).expect("hardened parses");
        let key = payout_id_for(&parsed.to_string());

        // Precondition: the pairing is internally consistent, so ONLY the
        // assertion can refuse it.
        let err = rehydrate_stored_identity(key.as_str(), &hardened)
            .expect_err("a hardened stored descriptor must be refused");
        assert_eq!(err, IntakeError::HardenedStepRejected);
    }

    /// An `xprv` cannot survive a round-trip through the store, and the refusal
    /// still says nothing about it.
    ///
    /// `Descriptor<DescriptorPublicKey>` has nowhere to put a private key, so
    /// this is refused by the type rather than by a check someone could delete.
    /// Asserted anyway: the guarantee is worth a test that fails loudly if a
    /// future `Descriptor<DescriptorSecretKey>` ever becomes the parse target.
    #[test]
    fn a_stored_xprv_descriptor_is_refused_without_describing_it() {
        let leaky = spell(XPRV);
        let err = rehydrate_stored_identity("xpbwhatever", &leaky)
            .expect_err("an xprv descriptor must be refused");
        assert_eq!(err, IntakeError::StoredIdentityUnusable);
        let rendered = err.to_string();
        assert!(
            !rendered.contains(XPRV) && !rendered.contains(&XPRV[..16]),
            "the refusal must not echo the key: {rendered}"
        );
    }

    /// Garbage in the column is refused as `StoredIdentityUnusable`, distinctly
    /// from the pool's own template being broken.
    ///
    /// The distinction is operational: `PoolDescriptorInvalid` means go and look
    /// at [`POOL_DESCRIPTOR_TEMPLATE`], this means go and look at a row.
    #[test]
    fn stored_garbage_is_refused_as_a_row_problem() {
        for raw in ["", "   ", "wpkh(", "not-a-descriptor", XPUB] {
            let err =
                rehydrate_stored_identity("xpbwhatever", raw).expect_err("{raw:?} must be refused");
            assert_eq!(
                err,
                IntakeError::StoredIdentityUnusable,
                "{raw:?} must be refused as a row problem"
            );
        }
    }
}
