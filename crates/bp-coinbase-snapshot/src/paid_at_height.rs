// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which address each ledger key was actually paid under, for ONE found block.
//!
//! # The problem this exists to solve
//!
//! Settlement is `claim − actually_paid` per ledger key, and `actually_paid`
//! comes out of [`crate::ActualCoinbase::paid_by_address`] — a map keyed on
//! `Address::from_script(output.script_pubkey, network).to_string()`. For a
//! static miner the ledger key *is* that address, so the lookup is direct and
//! always was.
//!
//! A rotating miner's ledger key is a `payout_id` (`xpb…`), which is a hash and
//! can never equal a rendered address. Looked up directly it returns `0`, and
//! `claim − 0 == claim` books the miner a full-claim credit it has already been
//! paid — every block, compounding — while the address the coinbase *did* pay
//! falls into the "outside the distribution" arm and mints a second row under a
//! key that changes every block. One block, two wrong rows, opposite directions.
//!
//! This type is the translation that stops that: given the identities behind a
//! snapshot's entries, the block's height and the network, it answers *which
//! address was this ledger key paid under here*, and the inverse *is this paid
//! address already claimed by an entry*.
//!
//! # Why an address and not a script
//!
//! Because the alternative costs more than it buys, and both costs were measured
//! rather than guessed (plan Amendment 1a):
//!
//! - `ActualCoinbase` is serialized into the pending-block blob that survives the
//!   ~100-block confirmation wait, in Redis, **with no TTL and no schema
//!   version**. Giving it a script-keyed map means either breaking every blob in
//!   flight across a deploy, or defaulting the new field — at which point an old
//!   blob loads an *empty* script map and settlement sees every **static** miner
//!   as unpaid. That failure is bigger than the one being fixed and it lands on
//!   the miners this feature does not touch.
//! - Neither engine depends on `bitcoin` in production (both have it under
//!   `[dev-dependencies]`, for the regtests). `paid_by_address` being
//!   `HashMap<String, u64>` follows from that boundary. A `ScriptBuf` key would
//!   move `bitcoin` into two accounting crates to avoid one `to_string()`.
//!
//! So the rendering happens here, in the crate that owns `ActualCoinbase`,
//! through the **same** `Address::from_script(_, network)` call that built the map
//! it will be compared against. One function, both sides.
//!
//! # Why this is not "a height-dependent value in a height-invariant store"
//!
//! The plan forbids putting a derived address into [`crate::StoredWeightSnapshot`]
//! — that snapshot's fingerprint deliberately excludes height, so a snapshot
//! carrying height-`H` addresses would be reachable under an identity that says
//! nothing about `H`. This type stores nothing. It is built at settlement, from
//! the height settlement already holds, used once, and dropped.
//!
//! # What it cannot do
//!
//! An output whose `script_pubkey` has no address form (bare, non-standard) has
//! no key in `paid_by_address` either, so it cannot be attributed. Every derived
//! payout under `bp_payout_descriptor::POOL_DESCRIPTOR_TEMPLATE` is P2WPKH and
//! always renders. This is declined rather than overlooked — see the plan.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use bitcoin::{Address, Network, Script};
use bp_common::PayoutIdentity;

/// Why a block's payment attribution could not be built.
///
/// Every variant is a refusal to settle, never a value settlement can proceed
/// past: each one means at least one miner's payment cannot be attributed, and
/// booking the rest would credit that miner its whole claim a second time.
///
/// The `payout_id` in each variant is a hash the pool publishes to the miner it
/// belongs to, so naming it is safe. **A descriptor must never join it** — that
/// string is a wallet-watching capability over every address the pool will ever
/// pay that miner, which is why `bp_payout_descriptor::IntakeError` is `Copy` and
/// why `RotatingDescriptor`'s `Debug` redacts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaidAtHeightError {
    /// A rotating identity would not derive at this height. Should be
    /// unreachable — `bp_payout_descriptor::assert_derivable` runs before a
    /// rotating identity can exist — so reaching it means an identity was built
    /// somewhere other than intake.
    #[error("payout identity {payout_id} does not derive at height {height}")]
    NotDerivable { payout_id: String, height: u32 },
    /// The derived script has no address form, so nothing in
    /// `paid_by_address` can ever match it.
    #[error(
        "payout identity {payout_id} derives a script with no address form at height {height}"
    )]
    NoAddressForm { payout_id: String, height: u32 },
    /// Two ledger keys are paid the same address at this height.
    ///
    /// The `payout_id` collision class, caught at the only place it becomes
    /// money: whichever key were looked up second would be credited an output
    /// the first was already credited. Refuse the block rather than pick one.
    #[error("payout identity {payout_id} shares its paid address at height {height} with {other}")]
    Collision {
        payout_id: String,
        other: String,
        height: u32,
    },
    /// A ledger key in the distribution matches no identity the resolver can
    /// find — not in memory, not in `miner_identity`.
    #[error("ledger key {payout_id} resolves to no payout identity")]
    Unresolvable { payout_id: String },
    /// The identity store could not be read at all.
    ///
    /// Carries no cause **on purpose**: the row it failed to read holds a
    /// descriptor, and an error string that quotes a row is how a
    /// wallet-watching capability reaches a log line. The implementation logs
    /// the underlying error against the `payout_id` and returns this.
    #[error("the payout identity store could not be read")]
    IdentityLookupFailed,
    /// A stored identity was read and refused — it will not parse, will not
    /// derive, or does not hash to the key it was stored under.
    #[error("the stored payout identity for {payout_id} was refused")]
    StoredIdentityRejected { payout_id: String },
    /// The resolver returned a map that does not cover the distribution it was
    /// asked about. A caller bug: settling anyway would credit that entry its
    /// whole claim on top of what the coinbase already paid it.
    #[error("payment attribution does not cover ledger key {payout_id}")]
    NotCoveringSnapshot { payout_id: String },
    /// The attribution was derived for a different block than the one being
    /// settled. A rotating identity's address changes with the height, so this
    /// would compare claims against scripts this block never paid.
    #[error(
        "payment attribution was derived for height {attributed}, but block \
         {block_height} is being settled"
    )]
    WrongHeight { attributed: u32, block_height: i32 },
}

impl PaidAtHeightError {
    /// Would retrying this ever succeed?
    ///
    /// Lives here, next to the errors, so the two engines cannot disagree about
    /// it — the same reason `LedgerError` owns its own `is_terminal`. The
    /// confirmation watcher re-applies a pending block every tick and only drops
    /// it on `Ok`, so a verdict returned as non-terminal becomes an infinite
    /// retry behind a repeating warning.
    ///
    /// The one deliberate non-terminal verdict is [`Self::Unresolvable`]: an
    /// identity row can legitimately appear after the first attempt (the process
    /// that authorized the miner is not necessarily the process settling the
    /// block), and the retry costs nothing but a tick.
    pub fn is_terminal(&self) -> bool {
        match self {
            // Verdicts. A descriptor that will not derive, a script with no
            // address form, two keys on one output, a map that does not cover
            // its own snapshot, an attribution for the wrong block — none of
            // these change on the next tick.
            PaidAtHeightError::NotDerivable { .. }
            | PaidAtHeightError::NoAddressForm { .. }
            | PaidAtHeightError::Collision { .. }
            | PaidAtHeightError::StoredIdentityRejected { .. }
            | PaidAtHeightError::NotCoveringSnapshot { .. }
            | PaidAtHeightError::WrongHeight { .. } => true,
            // Both clear on their own: a store that was unreachable, and a row
            // that has not arrived yet.
            PaidAtHeightError::IdentityLookupFailed | PaidAtHeightError::Unresolvable { .. } => {
                false
            }
        }
    }
}

/// For one found block: the address each ledger key was paid under.
///
/// Total over the identities it was built from — a static entry maps to itself
/// rather than being omitted. That is deliberate: [`Self::paid_address`] returning
/// `None` then means *"this entry was never resolved"*, which is a bug the caller
/// must refuse, instead of silently falling back to the ledger key and booking a
/// rotating miner's claim twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidAtHeight {
    height: u32,
    by_ledger_key: HashMap<String, String>,
    by_paid_address: HashMap<String, String>,
}

impl PaidAtHeight {
    /// Resolve every entry identity for the block at `height`.
    ///
    /// `identities` must cover **every** entry of the snapshot being settled,
    /// including the static ones. For a static entry that is
    /// `PayoutIdentity::static_address_verbatim(entry.address)` — `verbatim`, not
    /// `static_address`, because the latter normalizes and the ledger key must
    /// come back byte-for-byte identical or the lookup misses.
    ///
    /// Branches on the identity with a `match`, per `CLAUDE.md`: a third variant
    /// would not compile here rather than falling into a default that pays the
    /// wrong script.
    pub fn resolve<'a, I>(
        identities: I,
        network: Network,
        height: u32,
    ) -> Result<Self, PaidAtHeightError>
    where
        I: IntoIterator<Item = &'a PayoutIdentity>,
    {
        let mut by_ledger_key = HashMap::new();
        let mut by_paid_address: HashMap<String, String> = HashMap::new();

        for identity in identities {
            let ledger_key = identity.payout_id().to_string();
            let paid_address = match identity {
                // Unchanged from every release before rotation existed: the
                // ledger key is the address, and `paid_by_address` is keyed on it.
                PayoutIdentity::Static { .. } => ledger_key.clone(),
                // Rendered through the same call that built `paid_by_address`
                // (`ActualCoinbase::from_coinbase`), so the two strings are equal
                // by construction and not by convention.
                PayoutIdentity::Rotating { descriptor, .. } => {
                    let bytes = descriptor.script_at(height).map_err(|_| {
                        PaidAtHeightError::NotDerivable {
                            payout_id: ledger_key.clone(),
                            height,
                        }
                    })?;
                    let script = Script::from_bytes(&bytes);
                    Address::from_script(script, network)
                        .map_err(|_| PaidAtHeightError::NoAddressForm {
                            payout_id: ledger_key.clone(),
                            height,
                        })?
                        .to_string()
                }
            };

            if let Some(other) = by_paid_address.get(&paid_address) {
                if other != &ledger_key {
                    return Err(PaidAtHeightError::Collision {
                        payout_id: ledger_key,
                        other: other.clone(),
                        height,
                    });
                }
            }
            by_paid_address.insert(paid_address.clone(), ledger_key.clone());
            by_ledger_key.insert(ledger_key, paid_address);
        }

        Ok(Self {
            height,
            by_ledger_key,
            by_paid_address,
        })
    }

    /// The map for a block whose every entry is a static address.
    ///
    /// Not a `Default`: the height is not optional. A settlement that does not
    /// know which height it is booking cannot check that this map was built for
    /// the same one, and [`Self::height`] exists precisely so it can.
    pub fn static_only(height: u32) -> Self {
        Self {
            height,
            by_ledger_key: HashMap::new(),
            by_paid_address: HashMap::new(),
        }
    }

    /// The height every address in here was derived for.
    ///
    /// Settlement compares this against the height it is booking. An off-by-one
    /// is otherwise invisible: a rotating miner would resolve to a perfectly
    /// valid address that this block did not pay, and be credited its whole claim
    /// on top of what it was already paid.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The address `ledger_key` was paid under, or `None` if it was never
    /// resolved — which the caller must treat as a refusal to settle, not as
    /// "paid nothing". See the type docs.
    ///
    /// The lifetimes are load-bearing: borrowing the result from `&self` alone
    /// means `unwrap_or(ledger_key)` does not compile. Measured 2026-08-11 —
    /// writing that fallback required widening the signature first, so the
    /// signature is part of the guard and not just decoration.
    pub fn paid_address(&self, ledger_key: &str) -> Option<&str> {
        self.by_ledger_key.get(ledger_key).map(String::as_str)
    }

    /// The ledger key a coinbase-paid address belongs to, if any entry claims it.
    ///
    /// The inverse direction, and the reason both live in one type: the
    /// "coinbase paid an address outside the distribution" arm must not mint a
    /// row for an address a rotating entry was just credited under, and
    /// Group-Solo — which writes one history row per *paid* address — has to
    /// write that row under the member's height-invariant key. Two maps built in
    /// the same pass cannot disagree about that; two functions could.
    pub fn ledger_key(&self, paid_address: &str) -> Option<&str> {
        self.by_paid_address.get(paid_address).map(String::as_str)
    }

    /// Is this coinbase-paid address claimed by one of the entries?
    ///
    /// One implementation, two readings — [`Self::ledger_key`] answers *whose*,
    /// this answers *whether*, and they cannot drift apart.
    pub fn claims(&self, paid_address: &str) -> bool {
        self.ledger_key(paid_address).is_some()
    }

    /// Refuse an attribution built for a different block than the one being
    /// settled.
    ///
    /// Called by both engines immediately after resolving. Without it, pairing
    /// the wrong map with a block is invisible: every rotating entry resolves to
    /// a perfectly valid address, none of them appear in `paid_by_address`, and
    /// each miner is credited its whole claim on top of what it was already paid.
    pub fn require_height(&self, block_height: i32) -> Result<(), PaidAtHeightError> {
        if u32::try_from(block_height).is_ok_and(|h| h == self.height) {
            return Ok(());
        }
        Err(PaidAtHeightError::WrongHeight {
            attributed: self.height,
            block_height,
        })
    }

    /// Ledger keys resolved. Used by the tests that assert this phase is inert.
    pub fn len(&self) -> usize {
        self.by_ledger_key.len()
    }

    /// Whether anything was resolved at all.
    pub fn is_empty(&self) -> bool {
        self.by_ledger_key.is_empty()
    }
}

/// **Who is behind a ledger key** — asked twice per block, from the two ends of
/// the split, through one trait.
///
/// | Asked | By | When | An unanswerable key |
/// |---|---|---|---|
/// | [`Self::paid_at_height`] | settlement | ~100 blocks after the block was found | is an **error**: booking the rest credits that miner its whole claim on top of what the coinbase already paid it |
/// | [`Self::derived_payout_keys`] | the distribution build, before the coinbase | seconds before a template goes out | is **absent from the answer**, so the row is dropped as it is today |
///
/// The two differ on purpose and the reason is the retry: a settlement is
/// re-attempted every tick until it succeeds, and a job is not. See
/// [`Self::derived_payout_keys`].
///
/// **Why this is injected rather than passed in.** Both engines read their own
/// weight snapshot when the block-found event did not carry one — the
/// fingerprint fallback for a Redis blip at the found instant. In that path the
/// caller does not know the distribution's entries and so cannot build the
/// attribution itself. Leaving the fallback path unattributed would put the hole
/// exactly where a rotating miner is most likely to be misbooked, so resolution
/// happens inside the engine, after the snapshot is in hand, through this.
///
/// One trait, one production implementation, used by PPLNS and Group-Solo alike
/// — the seam doc at `payout_resolver.rs` exists because this translation was
/// written twice before. Both questions live on it for the same reason: two
/// traits would be two answers to "is this key a rotating identity", and the
/// filter that drops a row and the settlement that books it must not disagree.
#[async_trait::async_trait]
pub trait PayoutIdentityResolver: fmt::Debug + Send + Sync {
    /// Resolve every one of `ledger_keys` for the block at `height`.
    ///
    /// Must be **total**: the returned map has to answer for every key it was
    /// given, or the engine refuses the block
    /// ([`PaidAtHeightError::NotCoveringSnapshot`]). A key it cannot resolve is
    /// an error, never a key mapped to itself.
    async fn paid_at_height(
        &self,
        ledger_keys: &[String],
        height: u32,
    ) -> Result<PaidAtHeight, PaidAtHeightError>;

    /// Which of `ledger_keys` are paid by a **derived** script rather than by
    /// being an address — and, by returning them, that the coinbase can pay them.
    ///
    /// The distribution build gates on this (plan Decision 8 part 2, Amendment
    /// 2). It is a set of keys rather than a map of identities because the crate
    /// that consumes it is `bp-pplns`, the ~2 000-line weight model, which must
    /// not learn what an xpub is: from there a key in this set means *"payable,
    /// and its output is a P2WPKH"*, which is everything the filter and the
    /// weight estimate need.
    ///
    /// # Why this cannot fail
    ///
    /// There is no `Result`, and that is the decision, not an omission. This runs
    /// on the job path: the caller is building the template that goes out in the
    /// next `mining.notify`, and one unpayable entry does not fail one miner — it
    /// fails `build_payout_outputs`, which fails
    /// `MiningJobCache::get_or_build(…).ok()?`, which sends **no job to any
    /// connection sharing this payout set**. For PPLNS that is every miner in the
    /// pool, on every template, with no log line. So a key this cannot resolve is
    /// left out and its row is dropped — costing that one miner its share of one
    /// template — and the implementation logs why. Settlement makes the opposite
    /// choice ([`PaidAtHeightError::is_terminal`]) because a settlement gets
    /// another tick and a template does not.
    ///
    /// Keys that are already payable addresses do not need to be in here, and
    /// returning them would not be wrong — the consumer's predicate is
    /// `is_valid_payout_address(key) || derived.contains(key)`, which fails safe:
    /// an implementation that answers with an empty set degrades to exactly the
    /// behaviour this pool had before rotating identities existed.
    async fn derived_payout_keys(&self, ledger_keys: &[String]) -> HashSet<String>;
}

/// The resolver for a pool with no rotating identities: every ledger key is the
/// address it was paid under.
///
/// This is the engines' default, and the default is what makes installing the
/// real resolver non-optional rather than merely advisable. It **refuses** a
/// ledger key that is not a payable address — so a pool that starts handing out
/// `payout_id`s without wiring a descriptor-aware resolver gets a refused block
/// and a loud error, not a settlement that credits every rotating miner its whole
/// claim a second time.
///
/// The payability test is `bp_pplns::is_valid_payout_address`, called and not
/// re-spelled: this crate already routes the distribution build through it
/// (`build.rs`), and a second copy of "which strings can be paid" is the exact
/// drift `CLAUDE.md` opens with.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticPaidAddresses;

#[async_trait::async_trait]
impl PayoutIdentityResolver for StaticPaidAddresses {
    async fn paid_at_height(
        &self,
        ledger_keys: &[String],
        height: u32,
    ) -> Result<PaidAtHeight, PaidAtHeightError> {
        let identities: Vec<PayoutIdentity> = ledger_keys
            .iter()
            .map(|key| {
                if !bp_pplns::is_valid_payout_address(key) {
                    return Err(PaidAtHeightError::Unresolvable {
                        payout_id: key.clone(),
                    });
                }
                // `verbatim`, not `static_address`: normalizing here would hand
                // back a key the ledger cannot look up.
                Ok(PayoutIdentity::static_address_verbatim(key.clone()))
            })
            .collect::<Result<_, _>>()?;
        // The network is unused for a static key — the address is already
        // rendered — so any value produces the same map. Passing the real one
        // would mean plumbing it in for nothing.
        PaidAtHeight::resolve(identities.iter(), Network::Bitcoin, height)
    }

    /// None. This resolver is the "no rotating identities here" answer, so every
    /// key it is asked about is either an address the distribution build already
    /// accepts or a key it already drops — which is this pool's behaviour on
    /// every release before rotation existed, and the behaviour a deployment that
    /// has not installed the real resolver must keep having.
    ///
    /// Note the asymmetry with [`Self::paid_at_height`], which *refuses* a key it
    /// cannot resolve rather than falling back: there, silence would book a
    /// rotating miner's claim a second time; here, silence is the status quo.
    async fn derived_payout_keys(&self, _ledger_keys: &[String]) -> HashSet<String> {
        HashSet::new()
    }
}

/// The one resolver an engine uses — installed once at startup, read from two
/// places.
///
/// # Why this is a type and not two `OnceLock` fields
///
/// It already existed twice: both engines held
/// `OnceLock<Arc<dyn PayoutIdentityResolver>>` and both spelled out the same
/// default (`match …get() { Some(r) => r.clone(), None => Arc::new(StaticPaidAddresses) }`).
/// Amendment 2 needs a **third** reader — the distribution builder, which asks
/// [`PayoutIdentityResolver::derived_payout_keys`] on the job path — and adding
/// it as another `OnceLock` would have made four copies of "unset means
/// static-only". That is the drift `CLAUDE.md` opens with, so the rule lives here
/// once instead.
///
/// # Why the two readers must share the handle and not just the rule
///
/// The filter that decides a rotating miner's row survives into the coinbase and
/// the settlement that books what that coinbase paid are answering the same
/// question about the same key. If the builder read one resolver and settlement
/// another, a row could be paid by a resolver that knows it and then booked by one
/// that does not — which is exactly the double-credit
/// [`PaidAtHeightError::Unresolvable`] exists to refuse. `Clone` here is an
/// `Arc` clone of the *cell*, so an `install` after the clone is visible to both.
#[derive(Clone, Default)]
pub struct InstalledResolver {
    cell: Arc<OnceLock<Arc<dyn PayoutIdentityResolver>>>,
}

impl InstalledResolver {
    /// Install the descriptor-aware resolver. Idempotent-by-refusal: returns
    /// `false` if one was already installed, and keeps the first.
    ///
    /// Refusing rather than replacing is deliberate — a second install would mean
    /// two answers to "who is behind this ledger key" existed in one process, and
    /// whichever arrived later would silently win for every future block.
    pub fn install(&self, resolver: Arc<dyn PayoutIdentityResolver>) -> bool {
        self.cell.set(resolver).is_ok()
    }

    /// The installed resolver, or [`StaticPaidAddresses`].
    ///
    /// The default is the safe one in both directions: it refuses a `payout_id`
    /// at settlement (rather than booking a full-claim credit on top of what the
    /// coinbase paid) and returns no derived keys on the job path (which is
    /// this pool's behaviour on every release before rotation existed).
    pub fn get(&self) -> Arc<dyn PayoutIdentityResolver> {
        match self.cell.get() {
            Some(resolver) => resolver.clone(),
            None => Arc::new(StaticPaidAddresses),
        }
    }
}

impl fmt::Debug for InstalledResolver {
    /// Reports *whether* one is installed, not what it is. The production
    /// resolver holds the identity directory and hand-writes its own `Debug` so a
    /// `{:?}` cannot print descriptors; not forwarding here means this type does
    /// not depend on every future implementation having remembered to.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstalledResolver")
            .field("installed", &self.cell.get().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxOut};
    use bp_payout_descriptor::RotatingPayout;

    /// BIP-32 test-vector xpubs (published, no funds).
    const XPUB_A: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const XPUB_B: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
    /// A real regtest P2WPKH address, so the static arm is exercised against
    /// something `bitcoin::Address` actually parses.
    const STATIC_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn rotating(xpub: &str) -> PayoutIdentity {
        RotatingPayout::from_xpub_str(xpub)
            .expect("test vector xpub")
            .into_payout_identity()
    }

    /// The load-bearing property: the address this type resolves is the address
    /// `ActualCoinbase` derives from the coinbase output built from the same
    /// script.
    ///
    /// Both sides go through `Address::from_script`, which is the point — the test
    /// would still hold if the rendering changed, and would fail the moment the
    /// two sides stopped being the same call.
    #[test]
    fn a_resolved_address_is_the_key_actual_coinbase_uses() {
        let network = Network::Regtest;
        let height = 840_123u32;
        let payout = RotatingPayout::from_xpub_str(XPUB_A).expect("intake");
        let identity = payout.clone().into_payout_identity();

        let paid = PaidAtHeight::resolve([&identity], network, height).expect("resolve");
        let resolved = paid
            .paid_address(payout.payout_id().as_str())
            .expect("the rotating entry must resolve");

        // Build a real coinbase paying exactly that derived script.
        let coinbase = coinbase_paying(payout.script_at(height).expect("derives"), 5_000);
        let actual = crate::ActualCoinbase::from_coinbase(&coinbase, network);

        assert_eq!(
            actual.paid_by_address.get(resolved).copied(),
            Some(5_000),
            "the resolved address must be the key ActualCoinbase built"
        );
        assert!(paid.claims(resolved), "and the inverse must agree");
    }

    /// **The negative control for the height.** Resolving at the wrong height
    /// yields a valid address that the block did not pay — which is why
    /// [`PaidAtHeight::height`] exists for settlement to check.
    #[test]
    fn resolving_at_the_wrong_height_finds_nothing_paid() {
        let network = Network::Regtest;
        let payout = RotatingPayout::from_xpub_str(XPUB_A).expect("intake");
        let identity = payout.clone().into_payout_identity();

        let script = payout.script_at(500).expect("derives");
        let actual = crate::ActualCoinbase::from_coinbase(&coinbase_paying(script, 7_000), network);

        let off_by_one = PaidAtHeight::resolve([&identity], network, 501).expect("resolve");
        let wrong = off_by_one
            .paid_address(payout.payout_id().as_str())
            .expect("resolves");
        assert_eq!(
            actual.paid_by_address.get(wrong),
            None,
            "height 501's address must not be found in a block that paid height 500's"
        );
        assert_eq!(
            off_by_one.height(),
            501,
            "and the map must say which height"
        );
    }

    /// A static entry maps to itself, and is present rather than omitted.
    ///
    /// Presence is the property: `paid_address` returning `None` has to mean
    /// "never resolved", so an omitted static would be indistinguishable from a
    /// caller that forgot an entry.
    #[test]
    fn a_static_entry_maps_to_itself_and_is_present() {
        let identity = PayoutIdentity::static_address_verbatim(STATIC_ADDR);
        let paid = PaidAtHeight::resolve([&identity], Network::Regtest, 1).expect("resolve");
        assert_eq!(paid.paid_address(STATIC_ADDR), Some(STATIC_ADDR));
        assert!(paid.claims(STATIC_ADDR));
        assert_eq!(paid.len(), 1);
    }

    /// An entry nobody resolved is `None`, not the ledger key.
    ///
    /// This is the whole reason the map is total. With a `unwrap_or(ledger_key)`
    /// fallback instead, a rotating entry missing from the map would compare its
    /// `payout_id` against `paid_by_address`, find 0, and book a full-claim credit
    /// on top of the payment it already received.
    #[test]
    fn an_unresolved_key_is_none_and_not_a_fallback() {
        let paid = PaidAtHeight::static_only(9);
        assert_eq!(paid.paid_address("xpbsomethingelse"), None);
        assert!(!paid.claims("xpbsomethingelse"));
        assert!(paid.is_empty());
    }

    /// Two identities paid the same address at one height is refused, not
    /// resolved to whichever came last.
    ///
    /// Built by handing the same identity under two ledger keys, which is what a
    /// `payout_id` collision would look like from here.
    #[test]
    fn two_keys_sharing_one_paid_address_are_refused() {
        let shared = RotatingPayout::from_xpub_str(XPUB_A).expect("intake");
        let script = shared.script_at(77).expect("derives");
        let rendered = Address::from_script(script.as_script(), Network::Regtest)
            .expect("p2wpkh renders")
            .to_string();

        // A static entry whose address IS the address the rotating one derives.
        let statically = PayoutIdentity::static_address_verbatim(rendered);
        let rotating = shared.into_payout_identity();

        let err = PaidAtHeight::resolve([&statically, &rotating], Network::Regtest, 77)
            .expect_err("a shared paid address must be refused");
        assert!(
            matches!(err, PaidAtHeightError::Collision { .. }),
            "expected a collision, got {err:?}"
        );
    }

    /// Distinct xpubs resolve to distinct addresses — the precondition without
    /// which the collision test above would pass for the wrong reason.
    #[test]
    fn distinct_identities_resolve_to_distinct_addresses() {
        let a = rotating(XPUB_A);
        let b = rotating(XPUB_B);
        let paid = PaidAtHeight::resolve([&a, &b], Network::Regtest, 5).expect("resolve");
        assert_eq!(paid.len(), 2);
        assert_ne!(
            paid.paid_address(a.payout_id()),
            paid.paid_address(b.payout_id())
        );
    }

    /// **The guard on forgetting to wire the real resolver.** The default
    /// resolver refuses a `payout_id`, so a pool that starts issuing rotating
    /// identities without a descriptor-aware resolver refuses the block instead
    /// of crediting every rotating miner its whole claim a second time.
    ///
    /// Negative control in the same test: a real address resolves fine, so the
    /// refusal cannot be "this resolver refuses everything".
    #[tokio::test]
    async fn the_default_resolver_refuses_a_payout_id_and_accepts_an_address() {
        let payout_id = RotatingPayout::from_xpub_str(XPUB_A)
            .expect("intake")
            .payout_id()
            .as_str()
            .to_string();

        let err = StaticPaidAddresses
            .paid_at_height(std::slice::from_ref(&payout_id), 12)
            .await
            .expect_err("a payout_id is not a payable address");
        assert_eq!(err, PaidAtHeightError::Unresolvable { payout_id });
        assert!(
            !err.is_terminal(),
            "an unresolvable key must retry — the row can still arrive"
        );

        let ok = StaticPaidAddresses
            .paid_at_height(&[STATIC_ADDR.to_string()], 12)
            .await
            .expect("a real address resolves");
        assert_eq!(ok.paid_address(STATIC_ADDR), Some(STATIC_ADDR));
    }

    /// An attribution for another block is refused by `require_height`, and the
    /// refusal is terminal — pairing the wrong map with a block is a caller bug
    /// that will not clear on the next tick.
    #[test]
    fn an_attribution_for_another_block_is_refused() {
        let paid = PaidAtHeight::static_only(100);
        assert!(paid.require_height(100).is_ok());
        let err = paid.require_height(101).expect_err("wrong block");
        assert_eq!(
            err,
            PaidAtHeightError::WrongHeight {
                attributed: 100,
                block_height: 101
            }
        );
        assert!(err.is_terminal());
        // A negative height cannot compare equal by wrapping.
        assert!(PaidAtHeight::static_only(0).require_height(-1).is_err());
    }

    /// The error text names the `payout_id` and nothing else — no descriptor.
    #[test]
    fn refusals_carry_no_descriptor() {
        let err = PaidAtHeightError::NotDerivable {
            payout_id: "xpbabc".into(),
            height: 3,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("xpbabc"));
        assert!(
            !rendered.contains("wpkh") && !rendered.contains("xpub"),
            "a refusal must not carry descriptor material: {rendered}"
        );
    }

    /// A resolver that claims every key it is asked about is derived, so an
    /// installed answer is distinguishable from the default's empty set.
    #[derive(Debug)]
    struct EverythingIsDerived;

    #[async_trait::async_trait]
    impl PayoutIdentityResolver for EverythingIsDerived {
        async fn paid_at_height(
            &self,
            _ledger_keys: &[String],
            height: u32,
        ) -> Result<PaidAtHeight, PaidAtHeightError> {
            Ok(PaidAtHeight::static_only(height))
        }

        async fn derived_payout_keys(&self, ledger_keys: &[String]) -> HashSet<String> {
            ledger_keys.iter().cloned().collect()
        }
    }

    /// **The load-bearing property of [`InstalledResolver`]:** a clone taken
    /// *before* the install sees the installed resolver.
    ///
    /// This is what lets the distribution builder (job path) and the engine
    /// (settlement) hold the same handle when the builder is constructed in
    /// `spawn`, minutes before `bin/blitzpool` installs the real resolver. Both
    /// directions are asserted in one test: the clone answers the default's empty
    /// set before, and the installed resolver's full set after, so it cannot pass
    /// because neither side was ever wired.
    #[tokio::test]
    async fn a_clone_taken_before_the_install_sees_it() {
        let handle = InstalledResolver::default();
        let taken_early = handle.clone();
        let keys = vec!["xpbwhoever".to_string()];

        assert!(
            taken_early
                .get()
                .derived_payout_keys(&keys)
                .await
                .is_empty(),
            "before the install, the default answers with no derived keys"
        );

        assert!(handle.install(Arc::new(EverythingIsDerived)));
        assert_eq!(
            taken_early.get().derived_payout_keys(&keys).await.len(),
            1,
            "the clone taken before the install must see it"
        );

        // Idempotent-by-refusal: the second install is rejected and the first kept.
        assert!(!handle.install(Arc::new(StaticPaidAddresses)));
        assert_eq!(
            handle.get().derived_payout_keys(&keys).await.len(),
            1,
            "a second install must not replace the first"
        );
    }

    /// The default refuses a `payout_id` at settlement — the same guard
    /// [`StaticPaidAddresses`] carries, reached through the handle, so an engine
    /// that never had a resolver installed cannot misbook one.
    #[tokio::test]
    async fn the_uninstalled_handle_is_the_static_only_refusal() {
        let payout_id = RotatingPayout::from_xpub_str(XPUB_A)
            .expect("intake")
            .payout_id()
            .as_str()
            .to_string();
        let err = InstalledResolver::default()
            .get()
            .paid_at_height(std::slice::from_ref(&payout_id), 40)
            .await
            .expect_err("an uninstalled handle must refuse a payout_id");
        assert_eq!(err, PaidAtHeightError::Unresolvable { payout_id });
    }

    /// A coinbase paying `script` — behind a pool output, because
    /// `from_coinbase` treats output 0 as the pool's by the §4 output order and
    /// excludes it from `paid_by_address`.
    fn coinbase_paying(script: ScriptBuf, sats: u64) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey: script,
                },
            ],
        }
    }
}
