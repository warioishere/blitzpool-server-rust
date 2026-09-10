// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `payout_id → PayoutIdentity` directory, and the pool's one
//! [`RotatingIntake`].
//!
//! # The gap this closes
//!
//! Rotation splits one string into two values — a height-invariant `payout_id`
//! for the ledger and a per-height script for the coinbase (see
//! [`bp_common::PayoutIdentity`]). The protocol layer resolves the first at
//! authorize/channel-open and then forgets everything else: `resolve_payouts`
//! takes a `&str` (SV1) or an `&AddressId` (SV2), and nothing else. So the
//! descriptor needs somewhere to live between the two.
//!
//! ## Why a directory and not a wider `resolve_payouts`
//!
//! Threading the identity down the connection would serve Solo and **nothing
//! else**, because the shapes of the modes differ in the one way that matters:
//!
//! | Mode | Whose identities the coinbase pays |
//! |---|---|
//! | Solo | the connecting miner's |
//! | PPLNS | **every miner in the window** — hundreds, almost none connected to this session |
//! | Group-Solo | **every member of the group** |
//! | Blockparty | the admin's members', which are operator-entered and never rotate |
//!
//! PPLNS's distribution is a list of `AddressId`s out of Redis/Postgres. There is
//! no connection to have carried a descriptor for the other 499 miners in the
//! window, so a per-connection channel cannot answer PPLNS's question at all —
//! it would have to be joined by `payout_id` against something anyway. Building
//! the per-connection thing for Solo now and the lookup for PPLNS in Phase 4
//! would be two mechanisms for one question, which is `CLAUDE.md`'s opening
//! failure mode with the ink still wet.
//!
//! Phase 2 already staged this shape: `bp_db::find_rotating_identities` exists
//! and its doc says *"for the payout path to resolve descriptors in bulk"*. And
//! the in-repo precedent is [`crate::engines::BlitzpoolModeGate`] — a
//! payout-id-keyed, refcounted, in-memory map populated at authorize and read
//! synchronously by the payout resolver. This is the same pattern for the
//! adjacent fact.
//!
//! ## Why it is refcounted the same way the mode gate is
//!
//! Two connections can present the same xpub (a miner with two rigs). One
//! disconnecting must not remove the descriptor the other is still being paid
//! through — that is verbatim the reason `BlitzpoolModeGate` refcounts, and
//! getting it wrong here is worse than getting it wrong there: a missing mode
//! falls back to Solo, while a missing descriptor means a rotating miner's
//! entry cannot be built at all.
//!
//! ## What is deliberately NOT in here
//!
//! Static identities. The directory holds rotating ones only, and a lookup miss
//! is not an error — it is the answer *"this payout_id is a literal address, pay
//! it verbatim"*, which is what the pool has always done. Storing every static
//! address here too would make the map the size of the miner base to answer a
//! question the `payout_id` already answers by being an address.
//!
//! That asymmetry is the one thing in this module that could rot into the
//! `is_some()` defect `CLAUDE.md` names, so it is confined to
//! [`PayoutIdentityDirectory::identity_for`], which returns a `PayoutIdentity`
//! and never an `Option` — callers get an identity to `match` on, not a
//! "was it found?" boolean to branch on.
//!
//! ## The other half: settlement
//!
//! The directory answers *"how do I pay this miner now"*, on the template path,
//! for a miner that is connected. [`PoolPaidAddresses`] answers the settlement
//! question — *"which address did this ledger key get paid at height H"* — ~100
//! blocks later, when the miner is usually gone and often the process with it.
//! It lives next to the directory because it reads it first, and it falls back to
//! `miner_identity`, which is why [`PoolRotatingIntake`] writes that row.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::Network;
use bp_coinbase_snapshot::{PaidAtHeight, PaidAtHeightError, PayoutIdentityResolver};
use bp_common::{IdentityRefused, PayoutIdentity, RotatingIntake};
use bp_payout_descriptor::{intake_wire_identity, IntakeError};
use sqlx::PgPool;
use tracing::{debug, error, info, warn};

/// How many disconnected-but-vouched identities the second tier keeps.
///
/// Bounds only the *disconnected* set — the connected tier is refcounted and
/// unbounded, so a miner with a live session is never evicted. Overflowing this
/// costs a store read at settlement, or one dropped row on one template, which is
/// the behaviour the pool had before the tier existed.
const VOUCHED_CAPACITY: usize = 4096;

/// In-memory `payout_id → rotating identity`, in two tiers.
///
/// | Tier | Lifetime | Who fills it |
/// |---|---|---|
/// | `connected` | refcounted to the session | intake, at authorize / channel-open |
/// | `vouched` | until evicted (FIFO, [`VOUCHED_CAPACITY`]) | the distribution build, for every rotating key it lets into a coinbase |
///
/// # Why the second tier is not optional
///
/// The connected tier is refcounted to a *connection* and the PPLNS window is
/// not. A rotating miner who mines and then disconnects is still in the window,
/// still scored, still filtered into the distribution — and a distribution is
/// cached for 30 s and lowered to scripts *after* that filter. With one tier,
/// `identity_for` misses, the lowering gets `Static { address: payout_id }`,
/// `address_to_script` refuses it, and `build_payout_outputs` fails the whole
/// coinbase: **no `mining.notify` frame for any connection sharing that payout
/// set**, which for PPLNS is the entire pool, with no log line (plan Amendment 2).
///
/// So whatever vouches for a key at filter time has to be able to answer for it
/// at render time. [`Self::vouch`] is that promise, and it is safe to keep past
/// the connection because the map is content-addressed: `payout_id` is the hash of
/// the canonical descriptor, so an entry under a key can only be the identity that
/// hashes to it. A stale entry is a correct entry.
pub(crate) struct PayoutIdentityDirectory {
    connected: Mutex<HashMap<String, RefcountedIdentity>>,
    vouched: Mutex<VouchedTier>,
}

#[derive(Debug)]
struct RefcountedIdentity {
    identity: PayoutIdentity,
    count: usize,
}

/// FIFO-bounded identities kept past their connection. `order` is insertion
/// order, not use order: an LRU would need a write on every read of a map that is
/// read once per template per connection, and the eviction penalty here is a store
/// read rather than a wrong payment.
#[derive(Debug, Default)]
struct VouchedTier {
    by_key: HashMap<String, PayoutIdentity>,
    order: VecDeque<String>,
}

impl PayoutIdentityDirectory {
    pub(crate) fn new() -> Self {
        Self {
            connected: Mutex::new(HashMap::new()),
            vouched: Mutex::new(VouchedTier::default()),
        }
    }

    /// Publish a rotating identity, or bump its refcount if it is already here.
    ///
    /// Called from intake — the one moment an identity comes into existence —
    /// rather than from a session-registration hook, because intake is the only
    /// place that holds the descriptor. By the time `register_session` runs, the
    /// wire string has already been replaced by the `payout_id`.
    fn publish(&self, identity: PayoutIdentity) {
        let key = identity.payout_id().to_string();
        let mut guard = self
            .connected
            .lock()
            .expect("payout-identity mutex poisoned");
        guard
            .entry(key)
            .and_modify(|e| e.count += 1)
            .or_insert(RefcountedIdentity { identity, count: 1 });
    }

    /// **Keep this identity answerable past its connection**, because something
    /// has just let its ledger key into a coinbase.
    ///
    /// Called by [`PoolPaidAddresses::derived_payout_keys`] for every rotating key
    /// it vouches for — whether it came from the connected tier or from
    /// `miner_identity`. The connected case matters as much as the stored one: the
    /// filter runs when the distribution is built and the lowering runs per
    /// template for up to the cache TTL afterwards, so a session that ends in
    /// between would otherwise take the whole pool's jobs down with it.
    ///
    /// A `Static` identity is ignored rather than rejected — the caller has one
    /// `match` on the identity and this is the arm with nothing to remember, the
    /// same asymmetry [`PoolRotatingIntake::persist`] has.
    fn vouch(&self, identity: PayoutIdentity) {
        let key = match &identity {
            PayoutIdentity::Static { .. } => return,
            PayoutIdentity::Rotating { payout_id, .. } => payout_id.as_str().to_string(),
        };
        let mut guard = self.vouched.lock().expect("payout-identity mutex poisoned");
        if guard.by_key.contains_key(&key) {
            // Content-addressed: an existing entry under this key IS this
            // identity, so re-inserting would only churn the eviction order.
            return;
        }
        guard.order.push_back(key.clone());
        guard.by_key.insert(key, identity);
        while guard.order.len() > VOUCHED_CAPACITY {
            if let Some(evicted) = guard.order.pop_front() {
                guard.by_key.remove(&evicted);
            }
        }
    }

    /// Drop one reference; remove the entry at zero.
    ///
    /// A `payout_id` that was never published is a no-op — the common case, since
    /// every static miner's disconnect reaches here too.
    ///
    /// Deliberately does **not** touch the vouched tier. That is the point of the
    /// tier: this miner's key may already be in a distribution that has not been
    /// lowered to scripts yet.
    pub(crate) fn release(&self, payout_id: &str) {
        let mut guard = self
            .connected
            .lock()
            .expect("payout-identity mutex poisoned");
        if let Some(entry) = guard.get_mut(payout_id) {
            if entry.count <= 1 {
                guard.remove(payout_id);
            } else {
                entry.count -= 1;
            }
        }
    }

    /// **The payout path's question: how do I pay this `payout_id`?**
    ///
    /// Always an answer, never an `Option`. A hit is a rotating identity — from
    /// the connected tier, or from the vouched one for a miner whose session has
    /// ended while their share is still in the window. A miss means the id is a
    /// literal address, which is what every identity in this pool was before this
    /// feature. The caller gets a `PayoutIdentity` to `match` on either way, so
    /// there is no "found it?" branch for a mode to fall out of.
    ///
    /// Note what a miss for a *rotating* miner would mean: a `payout_id`
    /// (`xpb…` + a base58 hash) returned as a `Static` address, which
    /// `address_to_script` then refuses — so the coinbase fails to build rather
    /// than paying anything wrong. That is the correct failure direction, and it is
    /// why this can be a plain map lookup with no fallback logic. It is also
    /// pool-wide when it happens, which is why the vouched tier exists to make it
    /// not happen.
    pub(crate) fn identity_for(&self, payout_id: &str) -> PayoutIdentity {
        if let Some(identity) = self
            .connected
            .lock()
            .expect("payout-identity mutex poisoned")
            .get(payout_id)
            .map(|e| e.identity.clone())
        {
            return identity;
        }
        if let Some(identity) = self
            .vouched
            .lock()
            .expect("payout-identity mutex poisoned")
            .by_key
            .get(payout_id)
            .cloned()
        {
            return identity;
        }
        PayoutIdentity::static_address_verbatim(payout_id)
    }

    /// Publish a rotating identity without going through intake, for tests in
    /// other modules that need a directory which answers `Rotating` — the
    /// Blockparty refusal in [`crate::payout_resolver`] is one.
    ///
    /// [`Self::publish`] stays private so that at runtime intake remains the only
    /// way an identity comes into existence.
    #[cfg(test)]
    pub(crate) fn publish_for_test(&self, identity: PayoutIdentity) {
        self.publish(identity);
    }

    /// How many rotating identities have a live connection. Diagnostics and tests
    /// only — the vouched tier is deliberately not counted here, so the refcount
    /// tests keep measuring the refcount.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.connected
            .lock()
            .expect("payout-identity mutex poisoned")
            .len()
    }

    /// How many identities are being kept past their connection. Tests only.
    #[cfg(test)]
    pub(crate) fn vouched_len(&self) -> usize {
        self.vouched
            .lock()
            .expect("payout-identity mutex poisoned")
            .by_key
            .len()
    }
}

/// The pool's [`RotatingIntake`] — `bp_payout_descriptor`'s intake plus the
/// operator flag plus publication to the directory.
///
/// One implementation, shared by SV1's `mining.authorize` and SV2's
/// `OpenMiningChannel`. Both protocols get the same verdict on the same input
/// because there is only one thing to ask.
pub(crate) struct PoolRotatingIntake {
    directory: Arc<PayoutIdentityDirectory>,
    /// `[payout_identity] allow_rotating`, default `false`. Held here rather
    /// than read per call so the flag is fixed for the process lifetime — an
    /// operator turning it off does not orphan the descriptors of miners already
    /// connected under it.
    allow_rotating: bool,
    /// Where an admitted descriptor is written so **settlement** can still find
    /// it. See [`Self::persist`].
    pool: PgPool,
}

impl PoolRotatingIntake {
    pub(crate) fn new(
        directory: Arc<PayoutIdentityDirectory>,
        allow_rotating: bool,
        pool: PgPool,
    ) -> Self {
        if allow_rotating {
            info!(
                descriptor_template = bp_payout_descriptor::POOL_DESCRIPTOR_TEMPLATE,
                derivation_path = bp_payout_descriptor::POOL_DERIVATION_PATH_BIP32,
                "payout-identity: rotating identities ENABLED"
            );
        }
        Self {
            directory,
            allow_rotating,
            pool,
        }
    }

    /// Persist an admitted identity so settlement can rehydrate it.
    ///
    /// **Not an optimisation — the only correct source at settlement time.** The
    /// directory is refcounted to *connection* lifetime and a found block is
    /// booked ~100 blocks later, so by then the miner has usually disconnected and
    /// the process may have restarted. `miner_identity` is the one place the
    /// descriptor survives that, and [`PoolPaidAddresses`] reads it there.
    ///
    /// Fire-and-forget because [`RotatingIntake::intake`] is synchronous: it runs
    /// on the authorize / channel-open path, which must not wait on Postgres to
    /// answer a miner. A lost write is not silent — the upsert is idempotent so
    /// every reconnect retries it, and a settlement that finds no row refuses the
    /// block by name (`PaidAtHeightError::Unresolvable`, non-terminal) rather than
    /// booking a rotating miner's claim twice.
    fn persist(&self, identity: &PayoutIdentity) {
        // Exhaustive on purpose. A third identity kind has to decide here whether
        // it leaves anything behind for settlement, rather than falling into a
        // silent "no" — `CLAUDE.md`'s 2026-08-03 entry is what an `if` costs.
        let (payout_id, descriptor) = match identity {
            // Nothing to store: the ledger key IS the address, and the resolver
            // maps it to itself without consulting a row.
            PayoutIdentity::Static { .. } => return,
            PayoutIdentity::Rotating {
                descriptor,
                payout_id,
            } => (
                payout_id.as_str().to_string(),
                descriptor.canonical_descriptor().to_string(),
            ),
        };
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let now_ms = chrono::Utc::now().timestamp_millis();
            // The line carries the DbError and the `payout_id` (a published hash)
            // — never `descriptor`, which is in scope here and is a
            // wallet-watching capability over every address the pool will pay
            // this miner.
            match bp_db::upsert_rotating_identity(&pool, &payout_id, &descriptor, now_ms).await {
                Ok(()) => debug!(
                    payout_id,
                    "payout-identity: descriptor persisted for settlement"
                ),
                Err(err) => warn!(
                    %err,
                    payout_id,
                    "payout-identity: persisting the descriptor failed; settlement cannot \
                     rehydrate this miner until a reconnect re-writes the row"
                ),
            }
        });
    }
}

impl RotatingIntake for PoolRotatingIntake {
    fn intake(&self, payout_part: &str) -> Result<Option<PayoutIdentity>, IdentityRefused> {
        let rotating = match intake_wire_identity(payout_part, self.allow_rotating) {
            Ok(None) => return Ok(None),
            Ok(Some(r)) => r,
            // **The operator-facing line is written here and nowhere else.**
            // `IdentityRefused` carries no detail on purpose (a descriptor
            // parser's error text can contain a private key), so this is the
            // only place that knows which refusal it was — and `IntakeError`'s
            // `Display` is a fixed string per variant, never borrowed input.
            //
            // Deliberately not logging `payout_part`: it is an extended key. For
            // `FeatureDisabled` that is a public key and harmless, but
            // `NotAnXpub` covers the `xprv` case, and one call site that logs
            // the input is how the credential rule gets undone. The variant is
            // enough to support a miner.
            Err(e) => {
                match e {
                    IntakeError::FeatureDisabled => warn!(
                        "payout-identity: a miner presented an extended key but \
                         [payout_identity] allow_rotating is false; refusing the connection"
                    ),
                    other => warn!(
                        refusal = %other,
                        "payout-identity: refusing a rotating identity at intake"
                    ),
                }
                return Err(IdentityRefused);
            }
        };

        let identity = rotating.into_payout_identity();
        self.directory.publish(identity.clone());
        // Both halves, together: the directory serves the coinbase while this
        // connection lives, the row serves settlement after it is gone.
        self.persist(&identity);
        debug!(
            payout_id = identity.payout_id(),
            "payout-identity: rotating identity admitted"
        );
        Ok(Some(identity))
    }
}

/// **The pool's [`PayoutIdentityResolver`]: which address a ledger key was paid
/// under, at one block's height.**
///
/// Settlement is `claim − actually_paid` per ledger key, and `actually_paid` is
/// keyed on the address the coinbase output rendered to. A rotating miner's
/// ledger key is a `payout_id` — a hash that can never equal a rendered address —
/// so without this translation it settles at `claim − 0` (a full-claim credit for
/// money already paid) *and* the address the coinbase did pay falls into the
/// "outside the distribution" arm and mints a second row. One block, two wrong
/// rows, opposite directions. See [`bp_coinbase_snapshot::paid_at_height`].
///
/// ## Why it is built here
///
/// This is the only layer holding all of the inputs at once: the network
/// (`[network]`), the identity sources (the directory above and Postgres), and —
/// through the engine that calls it — the height. `bp-coinbase-snapshot` owns the
/// *type* because both engines need it and it already renders `paid_by_address`
/// through the same `Address::from_script`; this owns the *lookup*.
///
/// ## Directory, then Postgres, then refuse
///
/// 1. The directory, for a miner still connected — free, and content-addressed so
///    it cannot disagree with the row.
/// 2. `miner_identity`, in **one** bulk read per settlement
///    (`find_rotating_identities`), for everyone else. The descriptor is
///    rehydrated through `bp_payout_descriptor::rehydrate_stored_identity`, which
///    re-hashes it and refuses a row that does not reproduce the `payout_id` it
///    was fetched under.
/// 3. A key that resolves to neither is an **error** — never
///    `static_address_verbatim(payout_id)`. That fallback is what
///    `PayoutIdentityDirectory::identity_for` returns on a miss, and it is exactly
///    right for the coinbase path (an unpayable hash fails to build a block) and
///    exactly wrong here (a `payout_id` compared against `paid_by_address` finds
///    nothing and books the two rows above).
///
/// The classifier between (1) and (2) is `bp_pplns::is_valid_payout_address` —
/// called, not re-spelled. It is already the predicate the distribution build
/// gates on, and a second copy of "which strings can be paid" is the drift
/// `CLAUDE.md` opens with.
pub(crate) struct PoolPaidAddresses {
    directory: Arc<PayoutIdentityDirectory>,
    pool: PgPool,
    /// Rendering is network-dependent (`bcrt1…` vs `bc1…`), and the same script
    /// on the wrong network renders to a string this block's coinbase cannot
    /// contain — every rotating miner then looks unpaid. Threaded, never assumed.
    network: Network,
}

impl PoolPaidAddresses {
    pub(crate) fn new(
        directory: Arc<PayoutIdentityDirectory>,
        pool: PgPool,
        network: Network,
    ) -> Self {
        Self {
            directory,
            pool,
            network,
        }
    }

    /// Rebuild the identities for keys the directory did not hold, from
    /// `miner_identity`.
    ///
    /// One query for the whole batch, not one per entry — which is what
    /// `find_rotating_identities`' own doc comment (*"for the payout path to
    /// resolve descriptors in bulk"*) was written for.
    ///
    /// # Why the verdict is per key
    ///
    /// Both questions in [`PayoutIdentityResolver`] land here, and they disagree
    /// about what a bad key means — settlement refuses the block, the job path
    /// drops the row (plan Amendment 2). An all-or-nothing return would force the
    /// job path to take the second-worst option in either direction: refuse
    /// everything, and one junk row unvouches every rotating miner in the batch and
    /// the coinbase loses them all; or ignore the distinction, and settlement stops
    /// refusing a block it must refuse. So this reports what it found and the
    /// callers decide.
    ///
    /// The `Err` is reserved for the read itself failing — that is not a verdict
    /// about any key.
    async fn rehydrate_from_the_store(
        &self,
        keys: &[&String],
    ) -> Result<Vec<(String, StoredOutcome)>, PaidAtHeightError> {
        let rows = bp_db::find_rotating_identities(&self.pool)
            .await
            .map_err(|err| {
                // The cause is logged HERE and dropped from the returned error:
                // `IdentityLookupFailed` carries no payload because the rows it
                // failed to read hold descriptors. `%err` is the DbError, and no
                // descriptor is interpolated into this line.
                error!(
                    %err,
                    unresolved = keys.len(),
                    "payout-identity: miner_identity could not be read; this block's \
                     settlement will retry"
                );
                PaidAtHeightError::IdentityLookupFailed
            })?;
        // `kind`, not `descriptor.is_some()`: reading the presence of a per-kind
        // field as the kind is the defect `CLAUDE.md` names, and the query's own
        // `WHERE` is not visible from here.
        let stored: HashMap<&str, &str> = rows
            .iter()
            .filter(|row| row.kind == bp_db::KIND_ROTATING)
            .filter_map(|row| {
                row.descriptor
                    .as_deref()
                    .map(|d| (row.payout_id.as_str(), d))
            })
            .collect();

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(descriptor) = stored.get(key.as_str()) else {
                warn!(
                    payout_id = key.as_str(),
                    "payout-identity: no identity for a ledger key — settlement refuses the \
                     block (retryable: the row can still arrive), a distribution build drops \
                     the row"
                );
                out.push(((*key).clone(), StoredOutcome::Absent));
                continue;
            };
            // Re-hashes the descriptor and refuses a row that does not reproduce
            // this key. Content-addressing is only a property of the system if
            // something checks it.
            match bp_payout_descriptor::rehydrate_stored_identity(key, descriptor) {
                Ok(payout) => out.push((
                    (*key).clone(),
                    StoredOutcome::Resolved(payout.into_payout_identity()),
                )),
                Err(refusal) => {
                    // `IntakeError` is `Copy` and its `Display` is a fixed string
                    // per variant — it cannot carry the row's descriptor.
                    error!(
                        payout_id = key.as_str(),
                        %refusal,
                        "payout-identity: the stored identity for a ledger key was refused; the \
                         ledger and the row disagree about which wallet this miner is"
                    );
                    out.push(((*key).clone(), StoredOutcome::Rejected));
                }
            }
        }
        Ok(out)
    }
}

/// What `miner_identity` had to say about one ledger key.
///
/// Three outcomes and not two, because the two callers of
/// [`PoolPaidAddresses::rehydrate_from_the_store`] need to tell them apart in
/// different ways: settlement maps `Absent` to a **retryable** refusal and
/// `Rejected` to a terminal one ([`PaidAtHeightError::is_terminal`]), while the
/// job path treats both as "not payable this build". Collapsing them would make a
/// row filed under the wrong key look like a row that has not arrived yet, and the
/// confirmation watcher would retry it forever behind a repeating warning.
enum StoredOutcome {
    /// A row that parses, derives, and hashes back to the key it was filed under.
    Resolved(PayoutIdentity),
    /// No row for this key.
    Absent,
    /// A row that will not parse, will not derive, or does not hash to its key.
    Rejected,
}

/// Manual, so a `{:?}` of an engine cannot walk into the directory's
/// descriptors. `RotatingDescriptor`'s own `Debug` redacts, so this is the second
/// layer rather than the only one — the trait requires `Debug`, and the cheapest
/// way to keep a capability out of a log line is to have nothing to print.
impl fmt::Debug for PoolPaidAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolPaidAddresses")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PayoutIdentityResolver for PoolPaidAddresses {
    async fn paid_at_height(
        &self,
        ledger_keys: &[String],
        height: u32,
    ) -> Result<PaidAtHeight, PaidAtHeightError> {
        let mut identities: Vec<PayoutIdentity> = Vec::with_capacity(ledger_keys.len());
        let mut needing_the_store: Vec<&String> = Vec::new();

        for key in ledger_keys {
            let identity = self.directory.identity_for(key);
            match &identity {
                // A connected rotating miner. The directory cannot hand back the
                // wrong descriptor: `payout_id` is its hash.
                PayoutIdentity::Rotating { .. } => identities.push(identity),
                PayoutIdentity::Static { address } => {
                    if bp_pplns::is_valid_payout_address(address) {
                        // Genuinely a literal address — what every identity in
                        // this pool was before rotation existed.
                        identities.push(identity);
                    } else {
                        // The directory's miss branch, handing back a `payout_id`
                        // dressed as an address. Postgres decides, not this.
                        needing_the_store.push(key);
                    }
                }
            }
        }

        if !needing_the_store.is_empty() {
            for (key, outcome) in self.rehydrate_from_the_store(&needing_the_store).await? {
                // Exhaustive: settlement's whole contract is that a key it cannot
                // attribute is an error and never a key mapped to itself, so a
                // fourth outcome has to decide here rather than fall into a
                // default that books a full-claim credit on money already paid.
                match outcome {
                    StoredOutcome::Resolved(identity) => identities.push(identity),
                    StoredOutcome::Absent => {
                        return Err(PaidAtHeightError::Unresolvable { payout_id: key })
                    }
                    StoredOutcome::Rejected => {
                        return Err(PaidAtHeightError::StoredIdentityRejected { payout_id: key })
                    }
                }
            }
        }

        PaidAtHeight::resolve(identities.iter(), self.network, height)
    }

    /// The job-path half: which of these keys is a rotating identity the coinbase
    /// can pay at any height.
    ///
    /// Every key it answers `yes` for is also [vouched](PayoutIdentityDirectory::vouch)
    /// into the directory, which is the load-bearing part rather than a cache. This
    /// runs when the distribution is *built*; the identity is needed again when
    /// each template *lowers* that distribution to scripts, for up to the build
    /// cache's TTL afterwards. A miner whose session ends in between would
    /// otherwise be unrenderable, and an unrenderable entry does not cost that
    /// miner a share — it fails `build_payout_outputs` and serves no job to
    /// anybody sharing the payout set.
    ///
    /// No `Result`, per the trait: a key nobody can resolve is left out and its row
    /// is dropped. See [`PayoutIdentityResolver::derived_payout_keys`] for why that
    /// is the opposite of what settlement does with the same key.
    async fn derived_payout_keys(&self, ledger_keys: &[String]) -> HashSet<String> {
        let mut derived = HashSet::with_capacity(ledger_keys.len());
        let mut needing_the_store: Vec<&String> = Vec::new();

        for key in ledger_keys {
            let identity = self.directory.identity_for(key);
            // `match`, not `identity.rotates()`: the Static arm has a real
            // decision in it (literal address vs the directory's miss branch), and
            // a boolean would hide that this is where the second one is routed.
            match identity {
                PayoutIdentity::Rotating { .. } => {
                    // The directory is keyed by `payout_id`, so a hit means the
                    // identity's own id IS `key` — insert what the caller holds.
                    self.directory.vouch(identity);
                    derived.insert(key.clone());
                }
                PayoutIdentity::Static { ref address } => {
                    if !bp_pplns::is_valid_payout_address(address) {
                        // The miss branch, handing back a `payout_id` dressed as an
                        // address. Postgres decides, not this.
                        needing_the_store.push(key);
                    }
                    // A literal address needs no entry here: the consumer's
                    // predicate is `is_valid_payout_address(key) || derived
                    // .contains(key)` and the first half already accepts it.
                }
            }
        }

        if needing_the_store.is_empty() {
            return derived;
        }
        let outcomes = match self.rehydrate_from_the_store(&needing_the_store).await {
            Ok(outcomes) => outcomes,
            Err(err) => {
                // The store is unreachable. Every one of these rows is dropped
                // from this build — which costs those miners one template, and is
                // the same degradation `load_inputs` accepts for an unreadable
                // ledger. Failing instead would serve no job to anybody.
                error!(
                    %err,
                    unresolved = needing_the_store.len(),
                    "payout-identity: miner_identity could not be read on the job path; these \
                     rotating miners are dropped from this distribution build and rejoin when \
                     it is rebuilt"
                );
                return derived;
            }
        };
        for (key, outcome) in outcomes {
            match outcome {
                StoredOutcome::Resolved(identity) => {
                    self.directory.vouch(identity);
                    derived.insert(key);
                }
                // Both already logged per key by `rehydrate_from_the_store`, and
                // both mean the same thing here: not payable this build. The
                // distinction is settlement's, not this path's.
                StoredOutcome::Absent | StoredOutcome::Rejected => {}
            }
        }
        derived
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The BIP-32 test-vector master public keys, vectors 1 and 2. Real keys
    /// with real checksums — a made-up one fails `Xpub::from_str` and every
    /// "admitted" assertion below would pass vacuously against `Err`.
    ///
    /// Two *distinct* keys, so the two-miners tests are not accidentally
    /// testing one.
    const XPUB_A: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const XPUB_B: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";

    /// The regtest addresses `XPUB_A` / `XPUB_B` derive to at [`HEIGHT`], from
    /// `RotatingPayout::address_at` — the other rendering path, so a resolver
    /// asserted against these is not being checked against itself.
    const HEIGHT: u32 = 842_000;
    const ADDR_A_AT_HEIGHT: &str = "bcrt1qq6eq76f0xuvmc5h9gqp8a7g6795csn39rd6ae5";

    /// A real regtest address, because [`bp_pplns::is_valid_payout_address`] is
    /// what tells a literal address from the directory's miss branch, and it
    /// parses. `format!("{prefix}aaa")` would classify as a miss.
    const STATIC_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    /// Ledger-key shaped, and the hash of nothing: no descriptor produces it, so
    /// no test and no run can have stored it. `Unresolvable` is what it must be.
    const ABSENT_ID: &str = "xpbZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

    /// Also ledger-key shaped, and the key a *stored* descriptor is deliberately
    /// filed under wrongly — `xpbGde…` is `XPUB_B`'s real id with one character
    /// changed, so the row is exactly the plausible corruption.
    const MISMATCHED_ID: &str = "xpbGde6AcmBoPFVk7mbMgRXUshU81Q7vkEb95vk51jQu1vb";

    /// Every intake test needs a runtime: admitting an xpub `tokio::spawn`s the
    /// row settlement will later read (see [`PoolRotatingIntake::persist`]), and
    /// `spawn` outside a runtime panics.
    ///
    /// The pool it gets is never reachable, on purpose. These tests are about the
    /// directory half; a live pool would make them depend on Postgres for facts
    /// that have nothing to do with it, and would silently pass if the write
    /// stopped happening. That the write happens, and that settlement can read it
    /// back, is
    /// `an_admitted_identity_is_readable_by_settlement_after_the_miner_disconnects`.
    fn directory_and_intake(allow: bool) -> (Arc<PayoutIdentityDirectory>, PoolRotatingIntake) {
        let dir = Arc::new(PayoutIdentityDirectory::new());
        (
            dir.clone(),
            PoolRotatingIntake::new(dir, allow, unreachable_pool()),
        )
    }

    /// Port 1 is privileged and unbound. `connect_lazy` does not dial, so this
    /// cannot fail here; anything that actually queries fails fast — which is how
    /// the resolver tests below prove they never queried.
    ///
    /// The short `acquire_timeout` is what makes "fast" true: sqlx retries a
    /// refused connection until the timeout, and the 30 s default turned one test
    /// into a 30 s test.
    fn unreachable_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://bp-test:bp-test@127.0.0.1:1/bp_never")
            .expect("a lazy pool does not connect, so it cannot fail to")
    }

    /// A static address is not this module's business, and the directory must
    /// stay empty for it — the asymmetry the module doc describes.
    #[tokio::test]
    async fn a_static_address_passes_through_and_is_not_published() {
        let (dir, intake) = directory_and_intake(true);
        let out = intake.intake("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(out, Ok(None), "a static address is not an intake attempt");
        assert_eq!(dir.len(), 0, "nothing static belongs in the directory");
    }

    /// The whole Phase 3 mechanism in one test: intake admits the key, the
    /// directory holds it, and `identity_for` gives back something that
    /// **rotates** — not the `payout_id` as an address.
    #[tokio::test]
    async fn an_admitted_xpub_is_resolvable_from_the_directory_as_a_rotating_identity() {
        let (dir, intake) = directory_and_intake(true);
        let identity = intake
            .intake(XPUB_A)
            .expect("intake must not refuse a valid xpub")
            .expect("a valid xpub is an intake attempt");
        assert!(identity.rotates());
        let payout_id = identity.payout_id().to_string();

        let resolved = dir.identity_for(&payout_id);
        assert_eq!(resolved, identity, "same identity back out");
        assert!(
            resolved.script_at(842_000).is_some(),
            "a rotating identity resolved from the directory must derive a script; \
             a `Static` fallback here is the failure this test exists to catch"
        );
    }

    /// The negative control for the test above, in the same file: an id the
    /// directory has never seen comes back `Static`, so the assertion above is
    /// not passing on a default.
    #[test]
    fn an_unknown_payout_id_comes_back_static() {
        let dir = PayoutIdentityDirectory::new();
        let resolved = dir.identity_for("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(!resolved.rotates());
        assert!(
            resolved.script_at(842_000).is_none(),
            "a static identity has no derivation"
        );
    }

    /// Two rigs, one xpub, one disconnect. The surviving connection must still
    /// be payable — the reason this is refcounted rather than a plain insert.
    #[tokio::test]
    async fn one_of_two_connections_disconnecting_leaves_the_descriptor_in_place() {
        let (dir, intake) = directory_and_intake(true);
        let first = intake.intake(XPUB_A).unwrap().unwrap();
        let second = intake.intake(XPUB_A).unwrap().unwrap();
        assert_eq!(first, second, "one xpub is one identity");
        assert_eq!(dir.len(), 1, "and one directory entry");
        let payout_id = first.payout_id().to_string();

        dir.release(&payout_id);
        assert!(
            dir.identity_for(&payout_id).rotates(),
            "the second rig is still connected and still has to be paid"
        );

        dir.release(&payout_id);
        assert!(
            !dir.identity_for(&payout_id).rotates(),
            "with nobody connected the entry is gone"
        );
        assert_eq!(dir.len(), 0);
    }

    /// Releasing an id that was never published is the common case — every
    /// static miner's disconnect — and must not disturb anything.
    #[tokio::test]
    async fn releasing_an_unpublished_id_is_a_no_op() {
        let (dir, intake) = directory_and_intake(true);
        let identity = intake.intake(XPUB_A).unwrap().unwrap();
        dir.release("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(dir.identity_for(identity.payout_id()).rotates());
        assert_eq!(dir.len(), 1);
    }

    /// Two xpubs are two identities and two entries — the directory keys on the
    /// `payout_id`, and a collision here would pay one miner another's money.
    #[tokio::test]
    async fn two_xpubs_are_two_entries() {
        let (dir, intake) = directory_and_intake(true);
        let a = intake.intake(XPUB_A).unwrap().unwrap();
        let b = intake.intake(XPUB_B).unwrap().unwrap();
        assert_ne!(a.payout_id(), b.payout_id());
        assert_eq!(dir.len(), 2);
        assert_eq!(dir.identity_for(a.payout_id()), a);
        assert_eq!(dir.identity_for(b.payout_id()), b);
    }

    /// Flag off: refused, and **not** passed through to the static path. The
    /// distinction is the whole reason `intake` returns `Err` rather than
    /// `Ok(None)` here — a fall-through would refuse this miner with a message
    /// about address length.
    #[tokio::test]
    async fn the_flag_is_what_admits_an_xpub_and_a_refusal_publishes_nothing() {
        let (dir, intake) = directory_and_intake(false);
        assert_eq!(intake.intake(XPUB_A), Err(IdentityRefused));
        assert_eq!(dir.len(), 0, "a refused identity must not be published");
    }

    // ── Settlement attribution (plan Phase 4a) ─────────────────────────────

    /// The cheap path, and the one that runs when a block is found while the
    /// miner is still connected. The pool here is **unreachable**: if this
    /// resolver went to Postgres for a key the directory already covers, the
    /// call would fail instead of answering — so the assertion is also the
    /// proof that a settlement costs zero queries when nobody has left.
    #[tokio::test]
    async fn a_connected_rotating_miner_is_attributed_from_the_directory_without_a_query() {
        let (dir, intake) = directory_and_intake(true);
        let payout_id = intake
            .intake(XPUB_A)
            .unwrap()
            .unwrap()
            .payout_id()
            .to_string();

        let resolver = PoolPaidAddresses::new(dir, unreachable_pool(), Network::Regtest);
        let paid = resolver
            .paid_at_height(std::slice::from_ref(&payout_id), HEIGHT)
            .await
            .expect("a published identity needs no store");

        assert_eq!(
            paid.paid_address(&payout_id),
            Some(ADDR_A_AT_HEIGHT),
            "the address the coinbase paid at this height is the one the ledger \
             key must be credited under"
        );
        assert_eq!(paid.height(), HEIGHT);
    }

    /// Every miner in this pool before rotation existed, and most after: the
    /// ledger key **is** the address. No directory entry, no row, no query — and
    /// specifically not the `Unresolvable` a "not in the directory ⇒ look it up"
    /// resolver would produce for it.
    #[tokio::test]
    async fn a_literal_address_is_attributed_to_itself_without_a_query() {
        let resolver = PoolPaidAddresses::new(
            Arc::new(PayoutIdentityDirectory::new()),
            unreachable_pool(),
            Network::Regtest,
        );
        let paid = resolver
            .paid_at_height(&[STATIC_ADDR.to_string()], HEIGHT)
            .await
            .expect("a literal address is its own attribution");
        assert_eq!(paid.paid_address(STATIC_ADDR), Some(STATIC_ADDR));
    }

    /// Postgres unreachable, with a key only Postgres could answer.
    ///
    /// The distinction this pins is worth money: a *retryable* failure leaves the
    /// block pending and settles it on a later tick, while a terminal one parks it
    /// in `unbookable` and a human has to go and get it. A database that blinked
    /// must not do the second. *Mutation:* return `Unresolvable` here, or make
    /// `IdentityLookupFailed` terminal in `PaidAtHeightError::is_terminal`, and
    /// this fails.
    #[tokio::test]
    async fn a_store_that_cannot_be_read_is_retryable_and_leaks_nothing() {
        let resolver = PoolPaidAddresses::new(
            Arc::new(PayoutIdentityDirectory::new()),
            unreachable_pool(),
            Network::Regtest,
        );
        let err = resolver
            .paid_at_height(&[ABSENT_ID.to_string()], HEIGHT)
            .await
            .expect_err("an unresolvable key must not be attributed to itself");

        assert_eq!(err, PaidAtHeightError::IdentityLookupFailed);
        assert!(
            !err.is_terminal(),
            "a block must not be parked in unbookable because Postgres blinked"
        );
        let text = err.to_string();
        assert!(
            !text.contains("127.0.0.1") && !text.contains("bp-test"),
            "the sqlx cause is logged locally and dropped from the error; a \
             connection string carries credentials: {text}"
        );
    }

    /// Two refusals out of the real store, read together because the pair is the
    /// decision: a key with **no** row is retryable (the row can still arrive — a
    /// restarted process re-writes it when the miner reconnects), and a row that
    /// does **not** hash to the key it is filed under is terminal. The second is
    /// the one that would otherwise pay another wallet.
    #[tokio::test]
    async fn an_absent_row_is_retryable_and_a_row_under_the_wrong_key_is_not() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let resolver = PoolPaidAddresses::new(
            Arc::new(PayoutIdentityDirectory::new()),
            pool.clone(),
            Network::Regtest,
        );

        let absent = resolver
            .paid_at_height(&[ABSENT_ID.to_string()], HEIGHT)
            .await
            .expect_err("no row is no attribution");
        assert_eq!(
            absent,
            PaidAtHeightError::Unresolvable {
                payout_id: ABSENT_ID.to_string()
            }
        );
        assert!(
            !absent.is_terminal(),
            "the row can still arrive; settling later is right, parking is not"
        );

        // File a real descriptor under a key it does not hash to — the plausible
        // corruption, since the id differs from the real one by one character.
        let b = bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB_B)
            .expect("a BIP-32 vector is a valid xpub");
        assert_ne!(
            b.payout_id().as_str(),
            MISMATCHED_ID,
            "the precondition: this row is filed under the WRONG key"
        );
        bp_db::upsert_rotating_identity(&pool, MISMATCHED_ID, b.canonical_descriptor(), 1)
            .await
            .expect("write the corrupt row");

        let mismatch = resolver
            .paid_at_height(&[MISMATCHED_ID.to_string()], HEIGHT)
            .await
            .expect_err("a descriptor that does not hash to the key is not this miner's wallet");
        assert_eq!(
            mismatch,
            PaidAtHeightError::StoredIdentityRejected {
                payout_id: MISMATCHED_ID.to_string()
            }
        );
        assert!(
            mismatch.is_terminal(),
            "no later tick fixes a row that disagrees with the ledger; a human has to"
        );
    }

    /// **The reason `persist` exists, end to end.** Intake admits an xpub, the
    /// row lands, the miner disconnects and the directory forgets it — the state
    /// settlement actually runs in, ~100 blocks later and usually a process
    /// restart away — and attribution still names the address the coinbase paid.
    ///
    /// Two negative controls, and both were necessary:
    ///
    /// - The directory release. Without it this passes on the in-memory hit and
    ///   proves nothing about the row.
    /// - The `DELETE` below. The upsert is idempotent, so *an earlier run's row*
    ///   is indistinguishable from this run's — measured, not supposed: with the
    ///   `persist` call commented out this test still passed until the delete
    ///   existed, on a row a previous run had left behind.
    #[tokio::test]
    async fn an_admitted_identity_is_readable_by_settlement_after_the_miner_disconnects() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let expected_id = bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB_A)
            .expect("a BIP-32 vector is a valid xpub")
            .payout_id()
            .as_str()
            .to_string();
        // Not `query!`: a runtime-checked statement keeps a test-only DELETE out
        // of the `.sqlx` cache the production queries live in.
        sqlx::query(r#"DELETE FROM miner_identity WHERE "payoutId" = $1"#)
            .bind(&expected_id)
            .execute(&pool)
            .await
            .expect("clear any earlier run's row");

        let dir = Arc::new(PayoutIdentityDirectory::new());
        let intake = PoolRotatingIntake::new(dir.clone(), true, pool.clone());
        let payout_id = intake
            .intake(XPUB_A)
            .expect("the flag is on")
            .expect("an xpub is an intake attempt")
            .payout_id()
            .to_string();
        assert_eq!(
            payout_id, expected_id,
            "the row just deleted must be the row intake writes"
        );

        // The write is spawned, because `RotatingIntake::intake` is synchronous.
        // Wait for it rather than racing it.
        let mut row = None;
        for _ in 0..40 {
            row = bp_db::find_miner_identity(&pool, &payout_id)
                .await
                .expect("read miner_identity");
            if row.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let row = row.expect(
            "intake must persist the descriptor: without this row, a block found \
             after this miner disconnects cannot be settled at all",
        );
        assert_eq!(row.kind, bp_db::KIND_ROTATING);

        dir.release(&payout_id);
        assert!(
            !dir.identity_for(&payout_id).rotates(),
            "the precondition: the directory can no longer answer for this miner"
        );

        let resolver = PoolPaidAddresses::new(dir, pool, Network::Regtest);
        let paid = resolver
            .paid_at_height(std::slice::from_ref(&payout_id), HEIGHT)
            .await
            .expect("the stored descriptor is the whole reason it is stored");
        assert_eq!(
            paid.paid_address(&payout_id),
            Some(ADDR_A_AT_HEIGHT),
            "settlement must credit the ledger key under the same address the \
             coinbase paid at that height"
        );
    }

    // ── The job path (plan Amendment 2) ────────────────────────────────────

    /// **Amendment 2's gap, from the directory alone.** A distribution is
    /// filtered when it is built and lowered to scripts on every template for up
    /// to the build cache's TTL afterwards. A miner whose session ends in between
    /// must still be renderable, because an unrenderable entry does not cost that
    /// miner a share — it fails `build_payout_outputs` and serves **no job to
    /// anybody** sharing the payout set.
    ///
    /// The negative control is the second identity, admitted the same way and
    /// never asked about: after the same release it is unresolvable, so the
    /// assertion above is `vouch`'s doing and not the refcount's.
    #[tokio::test]
    async fn a_key_the_job_path_vouched_for_outlives_its_connection() {
        let (dir, intake) = directory_and_intake(true);
        let vouched_id = intake
            .intake(XPUB_A)
            .unwrap()
            .unwrap()
            .payout_id()
            .to_string();
        let control_id = intake
            .intake(XPUB_B)
            .unwrap()
            .unwrap()
            .payout_id()
            .to_string();

        let resolver = PoolPaidAddresses::new(dir.clone(), unreachable_pool(), Network::Regtest);
        // Only the first key is offered to the filter. The pool is unreachable,
        // so a store read here would fail rather than answer — which also proves
        // a connected miner costs the job path zero queries.
        let derived = resolver
            .derived_payout_keys(std::slice::from_ref(&vouched_id))
            .await;
        assert_eq!(
            derived,
            HashSet::from([vouched_id.clone()]),
            "a connected rotating miner is payable, so its row must survive the filter"
        );
        assert_eq!(dir.vouched_len(), 1, "and the promise was recorded");

        // The connections end — both of them.
        dir.release(&vouched_id);
        dir.release(&control_id);
        assert_eq!(dir.len(), 0, "the precondition: nobody is connected");

        let still = dir.identity_for(&vouched_id);
        assert!(
            still.rotates(),
            "the vouched key must still resolve to a rotating identity: this is \
             the template that would otherwise serve no job to the whole pool"
        );
        assert!(
            still.script_at(HEIGHT).is_some(),
            "and it must derive a script, not hand back a payout_id as an address"
        );
        assert!(
            !dir.identity_for(&control_id).rotates(),
            "control: an identity nothing vouched for is gone with its connection, \
             so the assertion above is the vouch and not the refcount"
        );
    }

    /// **The rest of Amendment 2's gap: the store alone.** The state a real pool
    /// reaches within minutes — the miner has disconnected, the process may have
    /// restarted, and only `miner_identity` remembers the descriptor. The filter
    /// must still call this key payable, and after it does, the lowering must be
    /// able to render it.
    ///
    /// Both directions are asserted, because the pair is the mechanism: the key is
    /// unresolvable *before* the filter runs and renderable *after* it. A test that
    /// only checked the returned set would pass against a resolver that answered
    /// from the store and vouched nothing — which is the version that takes the
    /// pool's jobs down one template later.
    #[tokio::test]
    async fn a_disconnected_rotating_miner_is_payable_and_renderable_from_the_store_alone() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let dir = Arc::new(PayoutIdentityDirectory::new());
        let intake = PoolRotatingIntake::new(dir.clone(), true, pool.clone());
        let payout_id = intake
            .intake(XPUB_A)
            .unwrap()
            .unwrap()
            .payout_id()
            .to_string();

        // `persist` is spawned, because intake is synchronous. Wait for the row
        // rather than racing it.
        for _ in 0..40 {
            if bp_db::find_miner_identity(&pool, &payout_id)
                .await
                .expect("read miner_identity")
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // The miner leaves, and this directory is the one the pool kept — so
        // whatever answers now answers from Postgres.
        dir.release(&payout_id);
        assert!(
            !dir.identity_for(&payout_id).rotates(),
            "the precondition: in-memory, this miner no longer exists"
        );

        let resolver = PoolPaidAddresses::new(dir.clone(), pool, Network::Regtest);
        let derived = resolver
            .derived_payout_keys(std::slice::from_ref(&payout_id))
            .await;
        assert!(
            derived.contains(&payout_id),
            "the filter must keep a disconnected rotating miner's row: its shares \
             are still in the window, and dropping them pays its money to the \
             other miners"
        );

        let rendered = dir.identity_for(&payout_id);
        assert!(
            rendered.rotates(),
            "and having kept the row, the lowering must be able to render it — \
             the same resolution feeds both, which is what stops them disagreeing"
        );
        assert_eq!(
            bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB_A)
                .unwrap()
                .address_at(Network::Regtest, HEIGHT)
                .unwrap()
                .to_string(),
            ADDR_A_AT_HEIGHT,
            "the fixture address is this key's, independently derived"
        );
    }

    /// The other half of Amendment 2's decision, and the two halves are asserted
    /// **together** because they are deliberately opposite: the same unresolvable
    /// key is *dropped* by the job path and *refused* by settlement.
    ///
    /// A settlement retries on the next tick; a job does not. Dropping one row
    /// costs that miner one template, and refusing the build costs every miner in
    /// the payout set every template until the key ages out of the window — which
    /// is strictly worse than the money bug Phase 4b exists to fix.
    #[tokio::test]
    async fn an_unresolvable_key_is_dropped_by_the_job_path_and_refused_by_settlement() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let resolver = PoolPaidAddresses::new(
            Arc::new(PayoutIdentityDirectory::new()),
            pool,
            Network::Regtest,
        );
        let keys = vec![ABSENT_ID.to_string(), STATIC_ADDR.to_string()];

        let derived = resolver.derived_payout_keys(&keys).await;
        assert!(
            derived.is_empty(),
            "neither key is payable BY DERIVATION: the absent one is not payable \
             at all, and the literal address does not need to be — the consumer's \
             predicate accepts it by parsing"
        );
        assert!(
            bp_pplns::is_payable_payout_key(STATIC_ADDR, &derived),
            "so the literal miner keeps its row while the unresolvable one loses \
             its own, which is the whole point of dropping rather than refusing"
        );
        assert!(!bp_pplns::is_payable_payout_key(ABSENT_ID, &derived));

        // Same key, same store, the other question.
        let err = resolver
            .paid_at_height(&keys, HEIGHT)
            .await
            .expect_err("settlement must not attribute a key it cannot resolve");
        assert_eq!(
            err,
            PaidAtHeightError::Unresolvable {
                payout_id: ABSENT_ID.to_string()
            },
            "settlement refuses the whole block instead: it would otherwise book \
             a full-claim credit for money the coinbase already paid"
        );
        assert!(!err.is_terminal(), "and retries, which a job cannot");
    }

    /// The vouched tier is kept past its connections, so it needs a ceiling or a
    /// long-lived pool leaks one entry per rotating miner it has ever seen.
    ///
    /// FIFO, and the eviction penalty is a store read on the next build rather
    /// than a wrong payment — which is why insertion order is enough and an LRU
    /// (a write on every read, once per template per connection) is not worth it.
    ///
    /// The identities are minted by walking `child_number` over one real xpub:
    /// every one is a distinct, valid extended key with a real checksum, and
    /// `from_xpub_str` derives from each before it will hand one back. Fabricated
    /// strings would fail intake and this test would count zero of them.
    #[test]
    fn the_vouched_tier_is_bounded() {
        use std::str::FromStr;

        let dir = PayoutIdentityDirectory::new();
        let base = bitcoin::bip32::Xpub::from_str(XPUB_A).expect("a BIP-32 vector");
        let mut first_key = None;

        for i in 0..(VOUCHED_CAPACITY as u32 + 8) {
            let mut xpub = base;
            xpub.depth = 1;
            xpub.child_number = bitcoin::bip32::ChildNumber::from_normal_idx(i).unwrap();
            let identity = bp_payout_descriptor::RotatingPayout::from_xpub_str(&xpub.to_string())
                .expect("a re-serialized xpub is still an xpub")
                .into_payout_identity();
            if i == 0 {
                first_key = Some(identity.payout_id().to_string());
            }
            dir.vouch(identity);
        }

        assert_eq!(
            dir.vouched_len(),
            VOUCHED_CAPACITY,
            "the tier must not grow past its ceiling"
        );
        let first = first_key.expect("minted at i = 0");
        assert!(
            !dir.identity_for(&first).rotates(),
            "and the oldest entries are the ones evicted (FIFO), which self-heals \
             from the store on the next build"
        );
    }

    /// Vouching the same identity twice must not consume two slots — the map is
    /// content-addressed, so an entry under a `payout_id` can only be the identity
    /// that hashes to it. Without this, a rotating miner reconnecting on every
    /// template would evict the tier on its own.
    #[tokio::test]
    async fn vouching_one_identity_twice_costs_one_slot() {
        let (dir, intake) = directory_and_intake(true);
        let identity = intake.intake(XPUB_A).unwrap().unwrap();
        let resolver = PoolPaidAddresses::new(dir.clone(), unreachable_pool(), Network::Regtest);
        let keys = vec![identity.payout_id().to_string()];

        resolver.derived_payout_keys(&keys).await;
        resolver.derived_payout_keys(&keys).await;
        assert_eq!(dir.vouched_len(), 1);
    }
}
