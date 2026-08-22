// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP-port server: handle + per-connection task.
//!
//! Mirrors [`crate::server`]'s shape but for the Job-Declaration
//! sub-protocol. Different from the mining server:
//!
//! - **No TemplateBroadcast arm**: JDP doesn't broadcast templates;
//!   the JDC builds its own and declares them. The pool-side
//!   `current_prev_hash` snapshot comes from a separate
//!   [`CurrentPrevHashProvider`] hook (typically backed by
//!   `bp-template-distribution::TdpHandle`).
//! - **No vardiff-tick**: JDP doesn't have vardiff (the JDC chooses
//!   its own work).
//! - **JobDeclared → bridge.register**: each accepted
//!   `DeclareMiningJob` produces a [`crate::jdp::client::JdpSessionEvent::JobDeclared`]
//!   which the IO layer turns into a
//!   `bridge.register(token, RegisteredDeclaredJob)` call so the
//!   mining server's `SetCustomMiningJob` handler can cross-check the
//!   token later.
//! - **Async-heavy hooks**: AllocateMiningJobToken needs a
//!   miner-address + encoded-coinbase-outputs resolution before the
//!   handler can run; DeclareMiningJob needs a template-tx-snapshot
//!   plus current-prev-hash; ProvideMissingTransactionsSuccess needs
//!   current-prev-hash again; PushSolution emits a
//!   BlockSubmissionCandidate event that fans out to a JDP-specific
//!   block-submission sink.
//!
//! ## Notes
//!
//! - **ext 0x0003 (Non-Custodial Pool Payouts)** is push-only: the
//!   `SetPayoutDistribution` message isn't in `stratum-core::AnyMessage`, so
//!   the per-connection task serialises it via the raw-bytes pre-encoder —
//!   first frame after `RequestExtensions.Success`
//!   (ext 0x0003/SetPayoutDistribution), then re-published by the publisher
//!   task on
//!   interval / settlement invalidation.
//! - **Payout validation** in `accept_declaration` is positional
//!   recompute-and-compare (ext 0x0003/Output Verification) against the
//!   distribution the declaration's `distribution_id` TLV names in the bridge
//!   registry.
//! - **Full-block assembly + submitblock** is split by design — the handler
//!   emits a `BlockSubmissionCandidate` event carrying the raw components; the
//!   bin's production hook reconstructs the block via rust-bitcoin and submits
//!   via `TdpHandle::submit_solution`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bp_common::AddressId;
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::job_declaration_sv2::MESSAGE_TYPE_DECLARE_MINING_JOB;
use stratum_core::parsers_sv2::{parse_message_frame_with_tlvs, AnyMessage};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bridge::{
    AllocatedTokenRef, AllocationKind, DistributionAcceptance, DistributionAccounting,
    DistributionScope, JdpDeclaredJobRegistry, PayoutDistributionEntry, RegisteredDeclaredJob,
};
use crate::extensions::{
    parse_distribution_id_tlv, SetPayoutDistribution, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use crate::jdp::client::{
    handle_allocate_token, handle_declare_mining_job, handle_provide_missing_transactions_success,
    handle_push_solution, handle_request_extensions, handle_setup_connection,
    parse_user_identifier_as_address, AllocateTokenContext, DeclarationContext, JdpHandlerOutcome,
    JdpOutboundFrame, JdpSessionEvent, JdpSessionState,
};
use crate::jdp::dynamic_outputs::CandidateBacking;
use crate::jdp::payout_distribution::WeightedOutput;
use crate::jdp::tx_validation::{merge_provided_with_known, partition_against_template};
use crate::jdp_server_codec::{
    decode_jdp_inbound, encode_jdp_outbound, encode_jdp_outbound_ext_0x0003, InboundJdpFrame,
};
use crate::noise::{accept_pool_noise, NoiseConfig, NoiseTcpWriteHalf};
use crate::server_codec::CodecError;
use crate::tokens::Token;

// ── JDP-server hooks ────────────────────────────────────────────────

/// Resolve `(miner_address, encoded_coinbase_outputs)` for an
/// inbound `AllocateMiningJobToken`. Production wiring parses
/// `user_identifier` as a BTC address (or falls back to an IP-based
/// lookup), then computes the pool's payout outputs via
/// [`crate::hooks::PayoutResolver`] + [`crate::jdp::dynamic_outputs::encode_coinbase_outputs`].
/// Tests use a no-op + a custom fixture.
#[async_trait]
pub trait JdpAllocateResolver: Send + Sync {
    /// `remote_addr` is the connection's remote IP (string form, e.g.
    /// `"127.0.0.1:48292"`). Caller provides it so IP-based miner
    /// lookup is possible without leaking sockets into the handler.
    ///
    /// `payout_distribution_negotiated` — ext 0x0003 is active on this
    /// connection. ext 0x0003/Negotiation then REQUIRES `coinbase_tx_outputs`
    /// to be empty (the distribution replaces the base
    /// SV2 JDP/AllocateMiningJobToken.Success output semantics); the resolver
    /// must not build outputs at all in that case.
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        remote_addr: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome;
}

/// What the pool does with an `AllocateMiningJobToken`.
///
/// The two negative arms are NOT the same thing, and collapsing them into
/// `None` is what left a refused JDC hanging on an open socket: SV2 gives
/// `AllocateMiningJobToken` no error message, so the only way to tell a
/// client "not here" is to stop talking to it. [`Self::Refused`] does that
/// deliberately; [`Self::Ignored`] keeps the pre-existing behaviour for an
/// identifier that resolves to nothing at all.
pub enum AllocateOutcome {
    /// Issue a token with these outputs.
    Granted(AllocateTokenContext),
    /// The pool cannot serve this miner on this protocol at all — close the
    /// connection so the JDC's SV2 JDP/Job Declarator Client fallback ("JDS
    /// fails to respond … JDC is responsible for switching to a new Pool+JDS
    /// or solo mining") fires immediately instead of after a timeout, or
    /// never.
    Refused { reason: &'static str },
    /// Nothing resolvable (unparseable `user_identifier`). Dropped
    /// silently, as before.
    Ignored,
}

/// Snapshot the pool's template-tx cache (`wtxid → raw_tx`) for the
/// JDP-server's `DeclareMiningJob` partition step. Production wiring
/// pulls from the same template state that drives the mining server's
/// translator; tests can return an empty map (the handler then
/// requests all txs via `ProvideMissingTransactions`).
#[async_trait]
pub trait TemplateTxProvider: Send + Sync {
    async fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>>;
}

/// Provide the pool's current `prev_hash`. Used by `DeclareMiningJob`
/// to stamp the declared job's prev_hash (matched later by PushSolution).
#[async_trait]
pub trait CurrentPrevHashProvider: Send + Sync {
    async fn current_prev_hash(&self) -> Option<[u8; 32]>;
}

/// A freshly-built payout distribution, ready to publish as
/// `SetPayoutDistribution` (ext 0x0003/SetPayoutDistribution) and to register
/// in the bridge for ext 0x0003/Output Verification validation.
#[derive(Clone, Debug)]
pub struct BuiltPayoutDistribution {
    /// The pool output (`weight_P` in the amount field).
    pub pool_payout: WeightedOutput,
    /// Miner payout slots in ext 0x0003/Payout Computation coinbase order.
    pub payouts: Vec<WeightedOutput>,
    /// Parallel to `payouts` (ext 0x0003/SetPayoutDistribution).
    pub dust_limits: Vec<u32>,
    /// Consensus-serialized 0-value TxOuts the pool appends.
    pub additional_outputs: Vec<Vec<u8>>,
    /// Revenue the weight boosts were projected against.
    pub reference_reward_sats: u64,
    /// Settlement-snapshot identity. `None` = the owning mode books
    /// without a snapshot (Solo).
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// Whether a found block on this distribution may be booked
    /// (`false` when the snapshot write failed).
    pub bookable: bool,
}

/// Floor the publish interval at 1s.
///
/// `tokio::time::interval` PANICS on a zero period, and the publisher
/// runs as a detached task — the panic is confined to it, so the JDP
/// listener keeps accepting while no distribution is ever published:
/// `current_pool_wide()` stays empty, 0x0003 is never offered, and
/// every JDC silently drops to the base protocol with no non-custodial
/// payout enforcement at all. Nothing in the logs would name the config
/// value. `jdp_payout_distribution_interval_secs = 0` reads as "as fast
/// as possible", so clamp and say so rather than refuse to boot.
fn sane_publish_interval(interval: Duration) -> Duration {
    if interval.is_zero() {
        warn!(
            "jdp: payout-distribution interval of 0 is not a valid period — using 1s. \
             Set [sv2].jdp_payout_distribution_interval_secs to a positive value."
        );
        return Duration::from_secs(1);
    }
    interval
}

/// What the pool can publish for one JDP session's miner.
///
/// The three cases are deliberately distinct. Collapsing "this miner
/// rides the pool-wide distribution" and "the tailored build failed"
/// into a single `None` made every failure path — missing fee address,
/// engine error, no template yet — silently serve a Solo or Group-Solo
/// JDC the PPLNS distribution, so its block paid the PPLNS window and
/// booked under the PPLNS fingerprint.
///
/// **Which modes JDP serves.** PPLNS rides `PoolWide`; Solo and
/// Group-Solo get `Built`. **Blockparty is not offered over JDP at all**
/// and resolves to `Unavailable` — a Blockparty group is a rental whose
/// hashrate is pointed straight at an address and whose coinbase the pool
/// splits by fixed per-member percentages from Postgres, so there is
/// nothing a job-declaring client adds. The refusal lives in the
/// production `build_for_miner`.
#[derive(Debug)]
pub enum TailoredDistribution {
    /// PPLNS-mode miner: the pool-wide distribution IS their accounting.
    PoolWide,
    /// A distribution tailored to this miner, carrying WHICH accounting it
    /// was built for. The kind travels with the build because the caller
    /// cannot re-derive it: Solo and Group-Solo produce different payout
    /// vectors for the same one address, so an owner address alone cannot
    /// tell the two apart later — see [`DistributionAccounting`].
    Built {
        accounting: DistributionAccounting,
        built: Box<BuiltPayoutDistribution>,
    },
    /// The tailored build could not be produced. This miner's shares do
    /// not enter the PPLNS window, so the pool-wide distribution is the
    /// wrong answer — the session must be served nothing until a later
    /// build succeeds.
    Unavailable,
    /// The pool does not know this address's payout mode yet, so it cannot
    /// know WHICH distribution is the right one.
    ///
    /// Distinct from `Unavailable` because the cure is different: that one is
    /// a build that failed and may fail again, this one resolves by itself the
    /// moment a mining session registers, and the caller should retry rather
    /// than give up on the session.
    ///
    /// It is the normal state at JDC startup, not an edge case. Solo and PPLNS
    /// are told apart only by the port a MINER connects to, the mode gate is
    /// session-scoped, and a JDC allocates ~8 s before its mining channel
    /// exists — so at allocate time the pool routinely knows nothing. Guessing
    /// there is a money error in either direction: a tailored plan pays one
    /// miner out of a shared window, the pool-wide one pays a Solo miner's
    /// block into the PPLNS window.
    ModeUnknown,
}

/// Build the pool's payout distributions for the ext 0x0003 push model.
///
/// The publisher task calls [`Self::build_pool_wide`] on its interval
/// (and forced after a settlement); the per-connection task calls
/// [`Self::build_for_miner`] once an allocate reveals the miner's
/// identity (Solo and Group-Solo get a tailored distribution; a PPLNS miner
/// rides the pool-wide one; Blockparty is not served over JDP — see
/// [`TailoredDistribution`]).
/// [`Self::next_distribution_id`] allocates the
/// ext 0x0003/SetPayoutDistribution strictly-
/// increasing pool-global id — infra-backed in production (the stratum
/// crate stays free of Redis), monotonic-counter in tests.
#[async_trait]
pub trait PayoutDistributionSource: Send + Sync {
    /// `None` ⇒ nothing publishable right now (no PPLNS engine / no
    /// template yet) — ext 0x0003 is then not offered in negotiation.
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution>;
    /// What this session's miner should be served. See
    /// [`TailoredDistribution`] — `PoolWide` and `Unavailable` are NOT
    /// interchangeable.
    async fn build_for_miner(&self, miner_address: &AddressId) -> TailoredDistribution;
    /// Which accounting this address is on RIGHT NOW, without building
    /// anything — `None` when the pool has no live mining session for it and
    /// therefore no answer (the same distinction [`TailoredDistribution::
    /// ModeUnknown`] draws).
    ///
    /// A session is served ONE plan, decided when its mode first became
    /// known, and a mode can move underneath it: the cache-sync reconcile
    /// flips a live miner between Solo and Group-Solo the moment its group
    /// membership changes, deliberately without a reconnect. So the plan on
    /// file has to be re-asked, and it is asked per inbound frame rather than
    /// pushed at the gate: a lost push leaves a session serving the wrong plan
    /// forever and silently, while a missed poll simply happens again on the
    /// next frame. The cost is the reason it can be per-frame — this is a
    /// lookup that builds nothing.
    async fn current_mode(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind>;
    /// `None` ⇒ the allocator is unavailable; the publish is skipped
    /// (the previously-published distribution stays valid).
    async fn next_distribution_id(&self) -> Option<u64>;
}

/// Block-submission sink for `PushSolution` candidates. Production
/// wiring reconstructs the block via rust-bitcoin's `Block` + calls
/// `TdpHandle::submit_solution`; tests use a recording sink.
///
/// `booking` is `Some` only when the declared coinbase was validated
/// positionally against a published payout distribution
/// (ext 0x0003/Output Verification declare-time check). `None` means the pool
/// cannot say what this block paid it — report it, book nothing.
#[async_trait]
pub trait JdpBlockSubmissionSink: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        new_token: Token,
        backing: CandidateBacking,
        coinbase_raw: Vec<u8>,
        transactions: Vec<Vec<u8>>,
        prev_hash: [u8; 32],
        version: u32,
        ntime: u32,
        nonce: u32,
        n_bits: u32,
    );
}

/// `position → raw_tx` in declaration order. The node-side validator wants a
/// plain list; the position map is how the pool tracks the round-trip.
fn ordered_raw_txs(by_position: &std::collections::HashMap<u32, Vec<u8>>) -> Vec<Vec<u8>> {
    let mut positions: Vec<&u32> = by_position.keys().collect();
    positions.sort_unstable();
    positions
        .into_iter()
        .filter_map(|p| by_position.get(p).cloned())
        .collect()
}

/// SV2 JDP/Job Declarator Server lists "Maintaining an internal mempool (via
/// RPCs (or similar) to a Bitcoin Node)" among the JDS's responsibilities, and
/// Full-Template mode exists precisely so the pool can check what
/// Coinbase-only mode has to take on trust (SV2 JDP/Coinbase-only Mode: a
/// miner declaring a coinbase whose template has a different fee revenue, or
/// invalid transactions — "in many ways identical to block withholding").
///
/// This is the seam where a declared job is handed to a Bitcoin node for a real
/// verdict. `None` in [`JdpServerHooks::job_validator`] keeps the pool's
/// template-only behaviour: every declaration is accepted on the JDC's word.
#[async_trait]
pub trait DeclaredJobValidator: Send + Sync {
    /// Ask the node whether this declared job is valid.
    async fn validate_declaration(&self, job: DeclaredJobToValidate<'_>) -> JobVerdict;
}

/// One declared job, in the shape a node-side validator needs.
pub struct DeclaredJobToValidate<'a> {
    /// The JDP session the declaration came in on. A node-side validator keeps
    /// per-downstream state, so declarations must not be attributed to the
    /// wrong connection.
    pub session_id: u32,
    pub version: u32,
    pub coinbase_tx_prefix: &'a [u8],
    pub coinbase_tx_suffix: &'a [u8],
    /// Declared wtxids in declaration order (wire byte order).
    pub wtxid_list: &'a [[u8; 32]],
    /// Raw transactions the pool can already supply. The node reports back
    /// whatever it still misses rather than guessing.
    pub known_raw_txs: &'a [Vec<u8>],
}

/// What the node said about a declared job.
pub enum JobVerdict {
    /// Validated — the node accepts the job.
    Accepted,
    /// Rejected. Carries the SV2 error code for `DeclareMiningJob.Error`.
    Rejected(String),
    /// The node is missing transactions the pool did not supply. NOT a
    /// rejection: the pool's own `ProvideMissingTransactions` round-trip
    /// fetches them from the JDC and the second leg asks again.
    NeedsTransactions,
}

#[derive(Clone)]
pub struct JdpServerHooks {
    pub allocate_resolver: Arc<dyn JdpAllocateResolver>,
    pub template_tx_provider: Arc<dyn TemplateTxProvider>,
    pub prev_hash_provider: Arc<dyn CurrentPrevHashProvider>,
    pub block_submission_sink: Arc<dyn JdpBlockSubmissionSink>,
    /// ext 0x0003 distribution source (push model). Wired in
    /// production by `bin/blitzpool::jdp_hooks`; the [`NoOpJdpHooks`]
    /// returns `None` everywhere (extension not offered).
    pub distribution_source: Arc<dyn PayoutDistributionSource>,
    /// Node-side validation of declared jobs (SV2 JDP/Job Declarator Server).
    /// `None` → the pool accepts every declaration on the JDC's word, which is
    /// what it did before this hook existed.
    pub job_validator: Option<Arc<dyn DeclaredJobValidator>>,
}

impl JdpServerHooks {
    pub fn no_op() -> Self {
        let n: Arc<NoOpJdpHooks> = Arc::new(NoOpJdpHooks);
        Self {
            allocate_resolver: n.clone(),
            template_tx_provider: n.clone(),
            prev_hash_provider: n.clone(),
            block_submission_sink: n.clone(),
            distribution_source: n,
            job_validator: None,
        }
    }
}

/// Drop-in no-op implementation for tests + the regtest harness.
pub struct NoOpJdpHooks;

#[async_trait]
impl JdpAllocateResolver for NoOpJdpHooks {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        _remote_addr: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        // Pure parse — no IP fallback. Production wiring overrides.
        let Some(addr) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };
        if payout_distribution_negotiated {
            return AllocateOutcome::Granted(AllocateTokenContext {
                miner_address: addr,
                coinbase_outputs: Vec::new(), // ext 0x0003/Negotiation MUST: empty under 0x0003
            });
        }
        // SV2 JDP/AllocateMiningJobToken.Success wants ONE designated payout
        // output at 0 sats. This used to answer `vec![0u8]` — an EMPTY output
        // vector, which designates nothing, so every base-protocol job built
        // against a no-op harness was refused `invalid-mining-job-token` while
        // looking like it was served. Paying the miner mirrors what production
        // does for Solo.
        //
        // `bp_mining_job::address_to_script` is not used here because it
        // enforces a configured network and a no-op hook has none; the
        // address carries its own.
        let Ok(parsed) = addr.as_str().parse::<bitcoin::Address<_>>() else {
            return AllocateOutcome::Ignored;
        };
        let txout = bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: parsed.assume_checked().script_pubkey(),
        };
        AllocateOutcome::Granted(AllocateTokenContext {
            miner_address: addr,
            coinbase_outputs: bitcoin::consensus::serialize(&vec![txout]),
        })
    }
}

#[async_trait]
impl TemplateTxProvider for NoOpJdpHooks {
    async fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>> {
        HashMap::new()
    }
}

#[async_trait]
impl CurrentPrevHashProvider for NoOpJdpHooks {
    async fn current_prev_hash(&self) -> Option<[u8; 32]> {
        None
    }
}

#[async_trait]
impl JdpBlockSubmissionSink for NoOpJdpHooks {
    async fn submit_block_candidate(
        &self,
        _: AddressId,
        _: Token,
        _: CandidateBacking,
        _: Vec<u8>,
        _: Vec<Vec<u8>>,
        _: [u8; 32],
        _: u32,
        _: u32,
        _: u32,
        _: u32,
    ) {
    }
}

#[async_trait]
impl PayoutDistributionSource for NoOpJdpHooks {
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution> {
        // No distribution to publish → ext 0x0003 is never offered.
        None
    }
    async fn build_for_miner(&self, _miner_address: &AddressId) -> TailoredDistribution {
        // Nothing wired: no tailored distribution and no pool-wide one
        // either, so there is nothing to fall back TO.
        TailoredDistribution::PoolWide
    }
    async fn current_mode(&self, _miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        // No mode gate wired, so the honest answer is "no answer" — which
        // leaves whatever a session is being served alone, exactly as this
        // no-op leaves everything else alone.
        None
    }
    async fn next_distribution_id(&self) -> Option<u64> {
        None
    }
}

// ── StratumV2JdpServer ──────────────────────────────────────────────

#[derive(Clone)]
pub struct StratumV2JdpServer {
    inner: Arc<Inner>,
}

struct Inner {
    noise_config: NoiseConfig,
    hooks: JdpServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    cancel: CancellationToken,
    next_session_id: Mutex<u32>,
    /// Latest pool-wide `distribution_id` published (0 = none yet).
    /// Connections watch this and push the fresh distribution to every
    /// negotiated JDC.
    dist_watch: tokio::sync::watch::Sender<u64>,
    /// Nudges the publisher out of its interval sleep — settlement
    /// invalidation (ext 0x0003/Implementation Notes) must be followed by an
    /// immediate publish.
    refresh: Arc<tokio::sync::Notify>,
}

/// Settlement hook (ext 0x0003/Implementation Notes): a booked block
/// invalidates every published distribution at once; the publisher then pushes
/// a fresh one immediately. Handed to the block-booking sink via
/// [`StratumV2JdpServer::distribution_handle`].
#[derive(Clone)]
pub struct DistributionInvalidationHandle {
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    refresh: Arc<tokio::sync::Notify>,
}

impl DistributionInvalidationHandle {
    /// ext 0x0003/Implementation Notes settlement invalidation + forced fresh
    /// publish.
    pub fn settle(&self) {
        self.bridge
            .write()
            .expect("bridge RwLock poisoned")
            .invalidate_all_distributions();
        self.refresh.notify_one();
    }
}

impl StratumV2JdpServer {
    pub fn spawn(
        noise_config: NoiseConfig,
        hooks: JdpServerHooks,
        bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
        payout_distribution_interval: Duration,
    ) -> Self {
        let (dist_watch, _) = tokio::sync::watch::channel(0u64);
        let server = Self {
            inner: Arc::new(Inner {
                noise_config,
                hooks,
                bridge,
                cancel: CancellationToken::new(),
                next_session_id: Mutex::new(1),
                dist_watch,
                refresh: Arc::new(tokio::sync::Notify::new()),
            }),
        };
        server.spawn_distribution_publisher(sane_publish_interval(payout_distribution_interval));
        server
    }

    /// The ext 0x0003/Implementation Notes settlement hook for the
    /// block-booking sink.
    pub fn distribution_handle(&self) -> DistributionInvalidationHandle {
        DistributionInvalidationHandle {
            bridge: self.inner.bridge.clone(),
            refresh: self.inner.refresh.clone(),
        }
    }

    /// The pool-wide publisher (ext 0x0003/Update Policy): builds the current
    /// distribution on the interval (and forced after a settlement),
    /// publishes it into the bridge, and nudges every connection via
    /// the watch channel. Skips a tick when the settlement identity is
    /// unchanged — the wire stays quiet while the window is quiet.
    fn spawn_distribution_publisher(&self, interval: Duration) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_fingerprint: Option<[u8; 32]> = None;
            // A forced pass (settlement) that aborts before publishing
            // MUST stay owed. `last_fingerprint` describes what this
            // task last published, not what the registry holds: after a
            // settlement the registry holds nothing usable, so skipping
            // the next tick as "unchanged" leaves `current_pool_wide()`
            // empty — 0x0003 stops being offered and every declare is
            // rejected until the window's weights happen to move.
            let mut force_pending = false;
            loop {
                let forced = tokio::select! {
                    biased;
                    _ = inner.cancel.cancelled() => break,
                    _ = inner.refresh.notified() => true,
                    _ = tick.tick() => false,
                };
                force_pending |= forced;
                let Some(built) = inner.hooks.distribution_source.build_pool_wide().await else {
                    // No template yet / PPLNS build failed. Retry on the
                    // next tick with the debt still owed.
                    continue;
                };
                if !force_pending
                    && built.payouts_fingerprint.is_some()
                    && built.payouts_fingerprint == last_fingerprint
                {
                    continue;
                }
                let Some(distribution_id) =
                    inner.hooks.distribution_source.next_distribution_id().await
                else {
                    warn!("jdp publisher: distribution-id allocator unavailable — publish skipped");
                    continue;
                };
                last_fingerprint = built.payouts_fingerprint;
                let entry = entry_from_built(
                    distribution_id,
                    built,
                    DistributionAccounting::PoolWide,
                    None,
                    now_ms(),
                );
                inner
                    .bridge
                    .write()
                    .expect("bridge RwLock poisoned")
                    .publish_pool_wide(entry);
                // Only now is a forced republish actually discharged.
                force_pending = false;
                let _ = inner.dist_watch.send(distribution_id);
                debug!(
                    distribution_id,
                    "jdp publisher: pool-wide distribution published"
                );
            }
        });
    }

    /// Per-connection task. The TCP-accept loop calls this for
    /// each socket identified as JDP by `bp_protocol_detect`.
    pub fn accept_connection(&self, socket: TcpStream, remote_addr: String) -> JoinHandle<()> {
        let noise_config = self.inner.noise_config.clone();
        let hooks = self.inner.hooks.clone();
        let bridge = self.inner.bridge.clone();
        let cancel = self.inner.cancel.clone();
        let dist_rx = self.inner.dist_watch.subscribe();
        let session_id = self.alloc_session_id();
        tokio::spawn(async move {
            let res = run_jdp_connection(
                session_id,
                noise_config,
                hooks,
                bridge,
                socket,
                remote_addr,
                cancel,
                dist_rx,
            )
            .await;
            if let Err(err) = res {
                debug!("jdp connection ended: {err}");
            }
        })
    }

    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
    }

    fn alloc_session_id(&self) -> u32 {
        let mut g = self.inner.next_session_id.lock().expect("poisoned");
        let id = *g;
        *g = g.wrapping_add(1).max(1);
        id
    }
}

// ── Per-connection task ─────────────────────────────────────────────

/// What a session is being served, and why. Three outcomes rather than a
/// bool, because "served nothing" hides two states whose cures differ: a
/// build that failed and may fail again, and a mode that is not known YET and
/// resolves by itself the moment a mining session registers.
///
/// Collapsing them is what published a Solo distribution to every JDC that
/// allocated before its miner connected.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionDistribution {
    /// A plan is on file for this session, carrying the accounting it was
    /// BUILT for — which is what makes "is this still the right plan?"
    /// answerable later. `PoolWide` means the pool-wide push IS this miner's
    /// accounting (PPLNS); the tailored kinds carry their owner address, so
    /// nothing is lost by not holding one separately.
    ///
    /// One variant and not a tailored/pool-wide pair: they are the same
    /// concept — the accounting being served — and splitting them made every
    /// consumer re-join them, including one that had to synthesize a
    /// `DistributionAccounting::PoolWide` out of thin air to ask the shared
    /// question.
    Served(DistributionAccounting),
    /// The mode is not known YET. Nothing is published, and the caller retries
    /// on the next inbound frame — the check is a map lookup, so doing it per
    /// frame is free, and the answer normally arrives within milliseconds of
    /// the miner opening its channel.
    AwaitingMode,
    /// Nothing published because the build FAILED, or no distribution id was
    /// available. Retried on the session's own frames like `AwaitingMode`, but
    /// on a throttle ([`rebuild_due`]): unlike `AwaitingMode` this one runs the
    /// whole distribution build before it fails, and a JDC sends frames
    /// continuously, so retrying it unthrottled turns one failure into a
    /// rebuild per frame.
    ///
    /// Splitting this from `AwaitingMode` is the point of the type. They were
    /// briefly one variant, and that is precisely the collapse this enum was
    /// introduced to prevent — two states that look alike from outside and
    /// need different treatment.
    Denied,
}

impl SessionDistribution {
    /// The accounting this session is being served, or `None` while it is
    /// served nothing.
    ///
    /// The two "serving nothing" states are not merely the absence of a plan:
    /// a plan on file is REFERENCEABLE — `distribution_acceptance` answers
    /// with it, and ext 0x0003/Grace Window keeps the immediately-previous one
    /// answerable too. So when a plan stops being the right one it has to be
    /// dropped, not just superseded.
    fn accounting(&self) -> Option<&DistributionAccounting> {
        match self {
            Self::Served(accounting) => Some(accounting),
            Self::AwaitingMode | Self::Denied => None,
        }
    }
}

/// How long a session that was refused a distribution waits before the pool
/// tries to build it one again, on its own frames.
///
/// Below the publisher's 60 s default, because the publisher is the path this
/// backs up — and above anything a JDC's frame rate could turn into a rebuild
/// storm.
const DENIED_REBUILD_INTERVAL_MS: u64 = 30_000;

/// Whether an inbound frame should make the pool re-decide what this session
/// is served, given the accounting its address is on right now.
///
/// A `match`, and exhaustive, because the four states want four different
/// answers and a fifth added later must be classified rather than inherit
/// whichever one the `if` happened to be written around:
///
/// - `AwaitingMode` — every frame. The check is a mode lookup that returns
///   before anything is built, and the answer normally arrives within
///   milliseconds of the miner opening its channel.
/// - `Denied` — throttled, because this one runs the WHOLE distribution build
///   before it fails, and a JDC sends frames continuously. Retried at all
///   because the alternative was not retrying: the publisher's tick is the
///   only other path, and it skips a tick whose fingerprint is unchanged — on
///   a quiet window a session refused once stays refused with nothing left to
///   wake it.
/// - `Tailored` / `PoolWide` — only when the mode MOVED. These used to answer
///   `false` unconditionally, on the reasoning that a served session
///   re-decides when its slot is invalidated
///   (ext 0x0003/Implementation Notes). That holds for a settlement and for
///   nothing else:
///   `cache_sync::reconcile_gate_modes` flips a live address between Solo and
///   Group-Solo on a group join or leave, deliberately without a reconnect,
///   and until the pool next found a block the session kept being served the
///   plan for the mode it no longer had.
fn rebuild_due(
    served: &SessionDistribution,
    current_mode: Option<bp_common::StreamKind>,
    now_ms: u64,
    last_rebuild_ms: u64,
) -> bool {
    match served {
        SessionDistribution::AwaitingMode => true,
        SessionDistribution::Denied => {
            now_ms.saturating_sub(last_rebuild_ms) >= DENIED_REBUILD_INTERVAL_MS
        }
        // The one shared table, so a session is never served a plan the
        // mining side or the declare path would then refuse.
        SessionDistribution::Served(accounting) => {
            !crate::bridge::accounting_fits_mode(accounting, current_mode)
        }
    }
}

/// Makes "this session is still waiting for its mode" visible.
///
/// `AwaitingMode` is the NORMAL first answer for every JDC — it allocates ~8 s
/// before its mining channel opens, so warning on entry would fire once per
/// healthy start and mean nothing. What is not normal is STAYING there. An
/// address that never opens a mining session — a JDC pointed at the pool with
/// no miner behind it, or one whose miner mines somewhere else — waits
/// forever: it is denied the pool-wide distribution the whole time, publishes
/// nothing, and every trace of that is at `debug`. From outside it is
/// indistinguishable from a healthy session that happens not to be declaring,
/// which is the worst property a permanent refusal can have.
///
/// So the wait is timed and reported once, with the one thing an operator can
/// act on: the pool learns Solo from PPLNS from the PORT a miner connects on,
/// and until some miner opens a session for this address there is no answer to
/// be had. The recovery is reported too, so the log says how long it took
/// rather than trailing off.
struct AwaitingModeWatch {
    /// When the current wait started. `None` = not waiting.
    since_ms: Option<u64>,
    /// Whether THIS wait has already been reported. Reset with the wait, so a
    /// session that flaps gets one line per episode, not one per frame — the
    /// retry runs on every inbound frame.
    warned: bool,
}

impl AwaitingModeWatch {
    /// Comfortably past the ~8 s a healthy JDC needs, and under the
    /// publisher's 60 s tick so the per-frame retry is what trips it.
    const WARN_AFTER_MS: u64 = 30_000;

    fn new() -> Self {
        Self {
            since_ms: None,
            warned: false,
        }
    }

    /// Feed EVERY `served` transition through here, including the ones that
    /// resolve it.
    fn observe(
        &mut self,
        served: &SessionDistribution,
        session_id_hex: &str,
        miner: &AddressId,
        now: u64,
    ) {
        let SessionDistribution::AwaitingMode = served else {
            if self.warned {
                info!(
                    miner = miner.as_str(),
                    waited_ms = now.saturating_sub(self.since_ms.unwrap_or(now)),
                    "jdp {session_id_hex} payout mode known now — serving it again"
                );
            }
            self.since_ms = None;
            self.warned = false;
            return;
        };
        let since = *self.since_ms.get_or_insert(now);
        let waited_ms = now.saturating_sub(since);
        if !self.warned && waited_ms >= Self::WARN_AFTER_MS {
            self.warned = true;
            warn!(
                miner = miner.as_str(),
                waited_ms,
                "jdp {session_id_hex} has no known payout mode — it is served no payout \
                 distribution and cannot declare. The pool learns Solo from PPLNS off the port \
                 a miner connects on, so this clears only once a miner opens a mining session \
                 for this address"
            );
        }
    }
}

/// Build and push a fresh tailored distribution for `miner` on this session.
///
/// Three callers, one implementation: the first allocate; a
/// ext 0x0003/Implementation Notes settlement, which invalidates a tailored
/// slot exactly like the pool-wide one while the publisher only ever
/// republishes the latter; and the session's own frames, which retry an
/// undecided or refused build and answer a mode that moved.
///
/// It rebuilds from the mode gate every time, so it needs to be told nothing
/// about WHY it was called. What the mode-moved caller has to do on top is
/// drop the plan on file first — see [`SessionDistribution::is_serving_a_plan`].
#[allow(clippy::too_many_arguments)]
async fn republish_tailored(
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    writer: &mut NoiseTcpWriteHalf<AnyMessage<'static>>,
    session_id: u32,
    session_id_hex: &str,
    miner: &AddressId,
    // What this session is being served RIGHT NOW. Compared against what the
    // rebuild produces, so a plan that stops being the right one is dropped
    // rather than merely superseded — ext 0x0003/Grace Window keeps the
    // immediately-previous entry of a slot acceptable, which is exactly long
    // enough to declare against once more.
    //
    // The comparison lives here and not at a call site because there are
    // three call sites and only one of them ever knew a mode had moved. The
    // allocate path republishes unconditionally on every token request, and an
    // SRI jd-client allocates before nearly every declare — so a flip observed
    // on an allocate frame slid the old-mode plan into the grace slot with
    // nothing left to notice.
    serving: &SessionDistribution,
    // The pool-wide distribution id this session was last WRITTEN, or `None`
    // if what it is holding is not a pool-wide one (none was ever pushed, or a
    // tailored push has replaced it since — ext 0x0003/Payout Computation
    // gives the client ONE current distribution, not one per stream). Updated
    // in place, so the catch-up below can tell "already has it" from "is
    // holding something else".
    last_pool_wide_written: &mut Option<u64>,
) -> SessionDistribution {
    let (accounting, built) = match hooks.distribution_source.build_for_miner(miner).await {
        TailoredDistribution::Built { accounting, built } => (accounting, *built),
        // This miner rides the pool-wide distribution — either it always did
        // (its mode simply became known) or it changed under us and is PPLNS
        // now. Three things have to happen together, and leaving any one out
        // strands the session:
        //
        // 1. **Drop a tailored slot it may still hold.** `distribution_accep-
        //    tance` under `JdpSession` scope PREFERS that slot, so one left
        //    behind answers for every pool-wide id pushed afterwards — and
        //    every one of them resolves `Stale`.
        // 2. **Lift the denial**, or the acceptance answers `Unknown`.
        // 3. **Push the current distribution NOW**, unless the session
        //    demonstrably already holds it. Everything that reaches this arm
        //    from somewhere other than the pool-wide stream is holding
        //    something else: a session that was awaiting its mode was excluded
        //    from the pool-wide pushes and holds an id that has since fallen
        //    out of the ext 0x0003/Grace Window, and a tailored one
        //    holds its own plan, which ext 0x0003/Payout Computation makes
        //    authoritative for it. Only `stale-chain-tip` is a benign declare
        //    error for an SRI jd-client; `stale-payout-distribution` ends the
        //    session. Waiting for the next publish is not a recovery — the
        //    publisher skips a tick whose fingerprint is unchanged, so on a
        //    quiet window there is no next publish.
        TailoredDistribution::PoolWide => {
            let current = {
                let mut guard = bridge.write().expect("bridge RwLock poisoned");
                let had_tailored = guard.clear_tailored(session_id);
                guard.allow_pool_wide(session_id);
                if had_tailored {
                    debug!(
                        "jdp {session_id_hex} tailored slot dropped — this miner is on the \
                         pool-wide distribution now"
                    );
                }
                guard.current_pool_wide()
            };
            match current {
                // Already holding it — a session that has been on the
                // pool-wide stream all along receives its pushes like every
                // other, and re-sending the same id per frame would be
                // traffic for its own sake.
                Some(entry) if *last_pool_wide_written == Some(entry.distribution_id) => {}
                Some(entry) => {
                    let wire = wire_from_entry(&entry);
                    if let Err(err) = write_jdp_outbound_frames(
                        writer,
                        vec![JdpOutboundFrame::SetPayoutDistribution(wire)],
                    )
                    .await
                    {
                        warn!("jdp {session_id_hex} pool-wide catch-up write: {err:?}");
                    } else {
                        *last_pool_wide_written = Some(entry.distribution_id);
                        debug!(
                            distribution_id = entry.distribution_id,
                            "jdp {session_id_hex} pool-wide catch-up pushed"
                        );
                    }
                }
                // Nothing published yet at all. The session is allowed on the
                // pool-wide stream, so the publisher's first push reaches it.
                None => {
                    debug!("jdp {session_id_hex} on the pool-wide distribution, none published yet")
                }
            }
            return SessionDistribution::Served(DistributionAccounting::PoolWide);
        }
        // Not known YET. Publish nothing and keep pool-wide denied: both
        // guesses are a money error, in opposite directions. The caller
        // retries on the next inbound frame, by which time the miner has
        // usually opened its channel and the port has spoken.
        TailoredDistribution::ModeUnknown => {
            // Read first. This arm runs on EVERY inbound frame while the mode
            // is undecided, and after the first one there is nothing to write
            // — a write lock per frame would serialize the registry against
            // the mining side to re-insert an id that is already in the set.
            // Racing readers both deciding to write is harmless: the write is
            // an idempotent insert.
            let already_denied = bridge
                .read()
                .expect("bridge RwLock poisoned")
                .is_pool_wide_denied(session_id);
            if !already_denied {
                bridge
                    .write()
                    .expect("bridge RwLock poisoned")
                    .deny_pool_wide(session_id);
            }
            return SessionDistribution::AwaitingMode;
        }
        TailoredDistribution::Unavailable => {
            warn!(
                miner = miner.as_str(),
                "jdp {session_id_hex} tailored republish unavailable — \
                 refusing to fall back to the pool-wide distribution"
            );
            bridge
                .write()
                .expect("bridge RwLock poisoned")
                .deny_pool_wide(session_id);
            return SessionDistribution::Denied;
        }
    };
    let Some(distribution_id) = hooks.distribution_source.next_distribution_id().await else {
        warn!(
            "jdp {session_id_hex} tailored republish skipped — \
             distribution-id allocator unavailable"
        );
        bridge
            .write()
            .expect("bridge RwLock poisoned")
            .deny_pool_wide(session_id);
        return SessionDistribution::Denied;
    };
    let entry = entry_from_built(
        distribution_id,
        built,
        accounting.clone(),
        Some(session_id),
        now_ms(),
    );
    let wire = wire_from_entry(&entry);
    {
        let mut guard = bridge.write().expect("bridge RwLock poisoned");
        // Same lock as the publish, so there is no window in which the session
        // has neither plan. Only when the accounting actually changed: a
        // rebuild for the SAME accounting (an ext 0x0003/Implementation Notes
        // settlement, a fresh allocate) legitimately supersedes, and
        // ext 0x0003/Grace Window's grace entry is what a declaration already
        // in flight resolves against.
        if serving.accounting().is_some_and(|was| *was != accounting) {
            let dropped = guard.clear_tailored(session_id);
            info!(
                miner = miner.as_str(),
                was = ?serving.accounting(),
                now = ?accounting,
                dropped,
                "jdp {session_id_hex} payout mode moved — the plan built for the old one is \
                 dropped, not superseded"
            );
        }
        guard.publish_tailored(session_id, entry);
        guard.allow_pool_wide(session_id);
    }
    if let Err(err) =
        write_jdp_outbound_frames(writer, vec![JdpOutboundFrame::SetPayoutDistribution(wire)]).await
    {
        warn!("jdp {session_id_hex} tailored republish write: {err:?}");
    }
    // Whatever pool-wide id this session was holding, it is not holding it any
    // more — ext 0x0003/Payout Computation makes the LATEST push the one it
    // must use. If it ever comes back to the pool-wide distribution it has to
    // be pushed one again, even an id it has already seen.
    *last_pool_wide_written = None;
    debug!(distribution_id, "jdp {session_id_hex} tailored republished");
    SessionDistribution::Served(accounting)
}

#[allow(clippy::too_many_arguments)]
async fn run_jdp_connection(
    session_id: u32,
    noise_config: NoiseConfig,
    hooks: JdpServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    socket: TcpStream,
    remote_addr: String,
    cancel: CancellationToken,
    mut dist_rx: tokio::sync::watch::Receiver<u64>,
) -> std::io::Result<()> {
    let session_id_hex = format!("jdp-{session_id:08x}");

    let noise = match accept_pool_noise::<AnyMessage<'static>>(socket, &noise_config).await {
        Ok(n) => n,
        Err(err) => {
            debug!("jdp {session_id_hex} noise handshake failed: {err:?}");
            return Ok(());
        }
    };
    let (mut reader, mut writer) = noise.into_split();

    let mut state = JdpSessionState::new(session_id);
    // What this session is being served. Once an identity is known, a session
    // that is NOT on the pool-wide distribution must not receive the pool-wide
    // push — ext 0x0003/Payout Computation makes the newest received
    // distribution "the basis for all subsequently declared jobs", so its own
    // stream is authoritative, and for a Solo or Group-Solo miner the
    // pool-wide one is the PPLNS window's, not theirs.
    let mut served = SessionDistribution::AwaitingMode;
    // The miner this session belongs to, learned from the first allocate and
    // never cleared. Kept so an ext 0x0003/Implementation Notes settlement can
    // be answered with a FRESH tailored distribution, and so an undecided mode
    // can be re-asked — the publisher only ever republishes the pool-wide one,
    // which this session is (correctly) not listening for.
    let mut identity: Option<AddressId> = None;
    let mut awaiting = AwaitingModeWatch::new();
    // When the pool last tried to build this session a distribution, so the
    // refused case can be retried on the session's own frames without
    // rebuilding once per frame. Stamped after every attempt, whatever it
    // returned.
    let mut last_rebuild_ms: u64 = 0;
    // The pool-wide distribution id last written to this client, so a session
    // arriving on that stream can be told whether it is behind. `None` while
    // it is holding something else (nothing yet, or a tailored push).
    let mut last_pool_wide_written: Option<u64> = None;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            // Ext 0x0003 push (ext 0x0003/SetPayoutDistribution): a fresh
            // pool-wide distribution was published — forward it to every
            // negotiated, non-tailored session. (The FIRST distribution after
            // RequestExtensions is appended synchronously in the inbound arm,
            // not here — the watch channel can't order itself against the
            // RequestExtensions.Success write.)
            changed = dist_rx.changed() => {
                if changed.is_err() {
                    break; // publisher gone = server shutting down
                }
                if !state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                {
                    continue;
                }
                // No identity yet: nothing else can be right, so the
                // pool-wide push stands (that is also the PPLNS default).
                if identity.is_some() && !matches!(
                    served,
                    SessionDistribution::Served(DistributionAccounting::PoolWide)
                ) {
                    // A tailored session ignores the pool-wide push —
                    // ext 0x0003/Payout Computation makes the newest received
                    // distribution the basis for every subsequent declaration,
                    // so its own stream is authoritative. But the publisher
                    // fires this watch after an
                    // ext 0x0003/Implementation Notes settlement too, and a
                    // settlement invalidates EVERY distribution including this
                    // session's. Nobody else republishes a tailored one, so
                    // without this the JDC is answered
                    // `stale-payout-distribution` forever and simply stops
                    // declaring.
                    let still_current = bridge
                        .read()
                        .expect("bridge RwLock poisoned")
                        .current_tailored(session_id)
                        .is_some();
                    if still_current {
                        continue;
                    }
                    let Some(miner) = identity.clone() else {
                        continue;
                    };
                    // Also the slow backstop for an undecided mode: if the
                    // mode was unknown at allocate time and no frame has
                    // arrived since, this retries it on the publisher's tick.
                    // `None` on the way out is deliberate — better no
                    // distribution than the PPLNS one.
                    let next = republish_tailored(
                        &hooks,
                        &bridge,
                        &mut writer,
                        session_id,
                        &session_id_hex,
                        &miner,
                        &served,
                        &mut last_pool_wide_written,
                    )
                    .await;
                    served = next;
                    last_rebuild_ms = now_ms();
                    awaiting.observe(&served, &session_id_hex, &miner, now_ms());
                    continue;
                }
                let current = bridge
                    .read()
                    .expect("bridge RwLock poisoned")
                    .current_pool_wide();
                if let Some(entry) = current {
                    let frame =
                        JdpOutboundFrame::SetPayoutDistribution(wire_from_entry(&entry));
                    if let Err(err) = write_jdp_outbound_frames(&mut writer, vec![frame]).await {
                        warn!("jdp {session_id_hex} distribution push write: {err:?}");
                        break;
                    }
                    last_pool_wide_written = Some(entry.distribution_id);
                }
            }
            frame_recv = reader.read_frame() => {
                let frame = match frame_recv {
                    Ok(f) => f,
                    Err(err) => {
                        debug!("jdp {session_id_hex} read_frame: {err:?}");
                        break;
                    }
                };
                let mut sv2_frame = match frame {
                    Frame::Sv2(f) => f,
                    Frame::HandShake(_) => {
                        warn!("jdp {session_id_hex} unexpected HandShakeFrame post-setup");
                        continue;
                    }
                };
                let header = match sv2_frame.get_header() {
                    Some(h) => h,
                    None => {
                        warn!("jdp {session_id_hex} frame missing header");
                        continue;
                    }
                };
                // The push model defines no inbound ext-0x0003 frames
                // (`SetPayoutDistribution` is JDS→JDC only;
                // ext 0x0003/distribution_id TLV Field references arrive as
                // TLVs on base frames). An ext-0x0003 frame from a client is a
                // protocol error — drop it.
                let ext_type = header.ext_type_without_channel_msg();
                if ext_type == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
                    warn!("jdp {session_id_hex} unexpected inbound ext-0x0003 frame — ignoring");
                    continue;
                }
                let mut tlv_extensions: Vec<u16> =
                    state.negotiated_extensions.iter().copied().collect();
                // ext 0x0003/Negotiation: a 0x0003 reference from a client
                // that never negotiated the extension MUST be rejected — so
                // the TLV has to be SEEN, not silently filtered away with the
                // rest of the un-negotiated tail. Widen the filter for the one
                // message that carries it; the declare handler enforces the
                // gate.
                if header.msg_type() == MESSAGE_TYPE_DECLARE_MINING_JOB
                    && !tlv_extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                {
                    tlv_extensions.push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
                }
                let (any_message, tlvs) = match parse_message_frame_with_tlvs(
                    header,
                    sv2_frame.payload(),
                    &tlv_extensions,
                ) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        warn!("jdp {session_id_hex} parse: {err:?}");
                        continue;
                    }
                };
                let mut inbound = match decode_jdp_inbound(any_message) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        debug!("jdp {session_id_hex} non-JDP frame, ignoring");
                        continue;
                    }
                    Err(err) => {
                        warn!("jdp {session_id_hex} decode: {err}");
                        continue;
                    }
                };
                // ext 0x0003/distribution_id TLV Field: the distribution
                // reference is a TLV on the base DeclareMiningJob frame (frame
                // ext_type stays 0x0000).
                if let InboundJdpFrame::DeclareMiningJob(ref mut input) = inbound {
                    input.distribution_id =
                        tlvs.as_deref().and_then(parse_distribution_id_tlv);
                }
                let was_request_extensions =
                    matches!(inbound, InboundJdpFrame::RequestExtensions(_));
                let negotiated_before = state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
                // What accounting the session's OWN plan was built for is
                // still current — asked once per frame, and about `identity`
                // because that is what the plan on file belongs to. The declare
                // path asks its own question about its own token's address; the
                // two are not the same address in general, which is why they
                // are two lookups and not one value passed around.
                //
                // Asked at all because a served session's plan is otherwise
                // decided once and never revisited, while `cache_sync` flips a
                // live address between Solo and Group-Solo on a group join
                // without any reconnect.
                let current_mode = match (&identity, negotiated_before) {
                    (Some(miner), true) => hooks.distribution_source.current_mode(miner).await,
                    // Nothing to ask about: no miner yet, or a session that
                    // never negotiated 0x0003 and so holds no plan to be wrong
                    // about.
                    _ => None,
                };
                let mut outcome = dispatch_jdp_inbound(
                    &mut state,
                    inbound,
                    &hooks,
                    &bridge,
                    session_id,
                    &remote_addr,
                    now_ms(),
                )
                .await;
                // ext 0x0003/SetPayoutDistribution first-message guarantee:
                // the moment 0x0003 lands in the negotiated set, the current
                // distribution goes out IN THE SAME WRITE BATCH, right after
                // RequestExtensions.Success — deterministic ordering the watch
                // channel cannot give.
                if was_request_extensions
                    && !negotiated_before
                    && state
                        .negotiated_extensions
                        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                {
                    let current = bridge
                        .read()
                        .expect("bridge RwLock poisoned")
                        .current_pool_wide();
                    match current {
                        Some(entry) => {
                            last_pool_wide_written = Some(entry.distribution_id);
                            outcome.outbound.push(JdpOutboundFrame::SetPayoutDistribution(
                                wire_from_entry(&entry),
                            ));
                        }
                        // Negotiation offered 0x0003 only when a
                        // distribution was publishable; hitting this
                        // means it vanished in between — loud, and the
                        // JDC will be rejected at declare time.
                        None => warn!(
                            "jdp {session_id_hex} 0x0003 negotiated but no pool-wide \
                             distribution available for the first push"
                        ),
                    }
                }
                // SV2 Overview/SetupConnection.Error: `SetupConnection.Error`
                // is sent "prior to closing the connection". Read the request
                // BEFORE the write consumes the outbound batch; act on it
                // AFTER, so the client still receives the frame telling it
                // why.
                let disconnect = outcome.events.iter().find_map(|e| match e {
                    JdpSessionEvent::Disconnect { reason } => Some(reason.clone()),
                    _ => None,
                });
                // Register declared jobs in the bridge BEFORE the frames go
                // out, and therefore before `fan_out_events`.
                //
                // Two reasons, and the first one is a race: the outbound batch
                // contains `DeclareMiningJobSuccess{new_mining_job_token}`,
                // and the JDC's MINING connection is a separate socket served
                // by an independent task. The moment that token is on the wire
                // the JDC may send `SetCustomMiningJob` for it. Per
                // ext 0x0003/distribution_id TLV Field a Full-Template frame
                // carries no `distribution_id` TLV, so everything backing that
                // job — the declaration binding AND its distribution reference
                // — lives in the bridge entry alone; a lookup that misses
                // answers `invalid-mining-job-token`, which an SRI jd-client
                // treats as fatal. Publishing first closes the window at no
                // cost: an entry for a token whose Success frame then fails to
                // send simply expires unused.
                //
                // Second, unchanged: the bridge must be populated by the time
                // the JobDeclared event is visible to other hooks.
                register_bridge_entries(&state, &bridge, session_id, &outcome.events);
                if let Err(err) = write_jdp_outbound_frames(&mut writer, outcome.outbound).await {
                    warn!("jdp {session_id_hex} write: {err:?}");
                    break;
                }
                outcome.outbound = Vec::new();
                if let Some(reason) = disconnect {
                    // Two sources now: a refused `SetupConnection` (which
                    // wrote its Error frame just above) and a refused
                    // allocate, which has no error frame to write because
                    // SV2 defines none — there the close IS the answer.
                    debug!("jdp {session_id_hex} closing: {reason}");
                    break;
                }
                // Identity became known (allocate) on a negotiated
                // session → check for a tailored distribution (Solo or
                // Group-Solo). PPLNS miners ride the pool-wide push;
                // Blockparty is refused a distribution altogether.
                if state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                {
                    for event in &outcome.events {
                        let JdpSessionEvent::TokenAllocated { miner_address, .. } = event else {
                            continue;
                        };
                        // One implementation, shared with the
                        // ext 0x0003/Implementation Notes-settlement republish
                        // above. This used to be a second copy of it, and the
                        // copy had already drifted: on a failed
                        // `next_distribution_id` it skipped the publish
                        // WITHOUT denying pool-wide, so a Solo or Group-Solo
                        // session ended up with no tailored slot and no denial
                        // — and `distribution_acceptance` then falls back to
                        // the pool-wide slot, which is the PPLNS window's.
                        // That session could declare a coinbase paying PPLNS;
                        // for Solo the booking resolves the mode from the
                        // miner's address and books nothing at all, so the
                        // PPLNS miners are paid on-chain and their ledger
                        // never hears about it.
                        identity = Some(miner_address.clone());
                        let next = republish_tailored(
                            &hooks,
                            &bridge,
                            &mut writer,
                            session_id,
                            &session_id_hex,
                            miner_address,
                            &served,
                            &mut last_pool_wide_written,
                        )
                        .await;
                        served = next;
                        last_rebuild_ms = now_ms();
                        awaiting.observe(&served, &session_id_hex, miner_address, now_ms());
                    }

                    // Re-decide on the session's OWN frames, not only on the
                    // publisher's 60 s tick. Two states reach this:
                    //
                    // - Served nothing yet. A JDC allocates ~8 s before its
                    //   mining channel opens, so at allocate time the mode is
                    //   routinely unknown — but it becomes known milliseconds
                    //   after that channel opens, and the JDC keeps sending. On
                    //   the tick alone the client would spend up to a minute
                    //   with no distribution, declare without one, and a PPLNS
                    //   address would be refused `custom-jobs-require-solo` —
                    //   trading a wrong distribution for a fatal one. `Denied`
                    //   rides the same path on a throttle.
                    // - Served a plan whose MODE HAS MOVED. `cache_sync` flips
                    //   a live address between Solo and Group-Solo on a group
                    //   join or leave, deliberately without a reconnect; until
                    //   this existed the session kept being served the plan
                    //   for the mode it no longer had, and only an
                    //   ext 0x0003/Implementation Notes settlement or a
                    //   reconnect
                    //   ever corrected it.
                    //
                    // `rebuild_due` owns which state gets which treatment, off
                    // the mode read before the dispatch.
                    if let (Some(miner), true) = (
                        &identity,
                        rebuild_due(&served, current_mode, now_ms(), last_rebuild_ms),
                    ) {
                        let miner = miner.clone();
                        let was = served.clone();
                        let next = republish_tailored(
                            &hooks,
                            &bridge,
                            &mut writer,
                            session_id,
                            &session_id_hex,
                            &miner,
                            &was,
                            &mut last_pool_wide_written,
                        )
                        .await;
                        served = next;
                        // A plan on file AND a rebuild due can only mean the
                        // mode moved — that is the sole condition under which
                        // `rebuild_due` says yes for a served state. If the
                        // rebuild produced a plan, `republish_tailored` has
                        // already replaced the old one; if it produced NOTHING
                        // (the build failed, or the mode went unknown between
                        // the probe and the build) the old one still has to
                        // go. It pays the wrong set of miners, and the pool
                        // has no replacement to offer instead.
                        //
                        // Dropped after the attempt, not before, so a rebuild
                        // that succeeds never opens a window in which the
                        // session has no plan at all.
                        if was.accounting().is_some() && served.accounting().is_none() {
                            let dropped = bridge
                                .write()
                                .expect("bridge RwLock poisoned")
                                .clear_tailored(session_id);
                            warn!(
                                miner = miner.as_str(),
                                was = ?was.accounting(),
                                ?current_mode,
                                dropped,
                                "jdp {session_id_hex} payout mode moved but no plan could be \
                                 built for the new one — dropping the old plan and serving \
                                 nothing rather than a coinbase paying the wrong miners"
                            );
                        }
                        last_rebuild_ms = now_ms();
                        awaiting.observe(&served, &session_id_hex, &miner, now_ms());
                    }
                }
                fan_out_events(outcome.events, &hooks).await;
            }
        }
    }

    // On disconnect: evict all of this JDP-session's bridge entries so
    // the mining server doesn't keep stale `RegisteredDeclaredJob`s.
    let evicted = bridge
        .write()
        .expect("bridge RwLock poisoned")
        .evict_for_jdp_session(session_id);
    if evicted > 0 {
        debug!("jdp {session_id_hex} disconnect evicted {evicted} declared jobs from bridge");
    }
    let _ = writer.shutdown().await;
    Ok(())
}

/// Dispatch one inbound JDP frame to the matching `handle_*` function.
/// Resolves async-hook context per-variant before calling the (sync)
/// handler.
#[allow(clippy::too_many_arguments)]
async fn dispatch_jdp_inbound(
    state: &mut JdpSessionState,
    inbound: InboundJdpFrame,
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    session_id: u32,
    remote_addr: &str,
    now_ms: u64,
) -> JdpHandlerOutcome {
    match inbound {
        InboundJdpFrame::SetupConnection(input) => handle_setup_connection(state, &input),
        InboundJdpFrame::RequestExtensions(input) => {
            // ext 0x0003/SetPayoutDistribution makes `SetPayoutDistribution`
            // the mandatory first push after this exchange — only offer 0x0003
            // when one is actually publishable right now.
            let distribution_available = bridge
                .read()
                .expect("bridge RwLock poisoned")
                .current_pool_wide()
                .is_some();
            handle_request_extensions(state, &input, distribution_available)
        }
        InboundJdpFrame::AllocateMiningJobToken(input) => {
            let negotiated = state
                .negotiated_extensions
                .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
            match hooks
                .allocate_resolver
                .resolve_allocate_context(&input.user_identifier, remote_addr, negotiated)
                .await
            {
                AllocateOutcome::Granted(ctx) => handle_allocate_token(state, &input, ctx, now_ms),
                // SV2 has no `AllocateMiningJobToken.Error`, so the only way
                // to tell a JDC "this pool cannot serve you" is to stop
                // talking. Closing turns an indefinite wait into the
                // SV2 JDP/Job Declarator Client fallback the JDC already
                // implements.
                AllocateOutcome::Refused { reason } => {
                    warn!(
                        session_id,
                        user_identifier = %input.user_identifier,
                        reason,
                        "jdp: refusing to allocate a token — closing the connection"
                    );
                    JdpHandlerOutcome {
                        outbound: Vec::new(),
                        events: vec![JdpSessionEvent::Disconnect {
                            reason: format!("allocate refused: {reason}"),
                        }],
                    }
                }
                // Couldn't resolve a miner address — drop silently
                // (return default outcome, no error frame).
                AllocateOutcome::Ignored => JdpHandlerOutcome::default(),
            }
        }
        InboundJdpFrame::DeclareMiningJob(input) => {
            let template_txs = hooks.template_tx_provider.snapshot().await;
            // SV2 JDP/Job Declarator Server: hand the declaration to a Bitcoin
            // node before committing to it. Whatever the local template
            // already covers is supplied, so the node only reports what it is
            // genuinely missing. Rejection short-circuits: nothing is
            // registered, so there is no state to roll back.
            if let Some(validator) = hooks.job_validator.as_ref() {
                let partition = partition_against_template(&input.wtxid_list, &template_txs);
                let known = ordered_raw_txs(&partition.known_raw_txs);
                if let JobVerdict::Rejected(error_code) = validator
                    .validate_declaration(DeclaredJobToValidate {
                        session_id,
                        version: input.version,
                        coinbase_tx_prefix: &input.coinbase_tx_prefix,
                        coinbase_tx_suffix: &input.coinbase_tx_suffix,
                        wtxid_list: &input.wtxid_list,
                        known_raw_txs: &known,
                    })
                    .await
                {
                    warn!(
                        session_id,
                        error_code, "jdp: node rejected the declared job — not accepting it"
                    );
                    return JdpHandlerOutcome::with_frame_pub(
                        JdpOutboundFrame::DeclareMiningJobError {
                            request_id: input.request_id,
                            error_code,
                            error_details: b"declared job rejected by the pool's bitcoin node"
                                .to_vec(),
                        },
                    );
                }
            }
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            let distribution =
                resolve_distribution_acceptance(bridge, session_id, input.distribution_id);
            // The mode of the address THIS TOKEN belongs to — not of whichever
            // address allocated last on this connection. One session may hold
            // tokens for several addresses (the allocate carries the address,
            // and nothing binds a connection to one), and the handler resolves
            // the declaration's miner from the token. Judging that declaration
            // against another address's mode refuses a correct plan and never
            // recovers.
            let current_mode =
                current_mode_for_token(state, hooks, &input.mining_job_token, now_ms).await;
            handle_declare_mining_job(
                state,
                &input,
                &template_txs,
                DeclarationContext {
                    current_prev_hash,
                    distribution,
                    current_mode,
                    now_ms,
                },
            )
        }
        InboundJdpFrame::ProvideMissingTransactionsSuccess(input) => {
            // Second leg: the JDC just filled the gaps, so the node can now
            // see the whole transaction set. Asking again is the point — a
            // JDC could otherwise hide an invalid transaction by declaring it
            // as one we were missing.
            if let Some(validator) = hooks.job_validator.as_ref() {
                if let Some(pending) = state.pending_declaration.as_ref() {
                    let merged = merge_provided_with_known(
                        pending.pending.clone(),
                        input.transaction_list.clone(),
                    )
                    .ok();
                    if let Some(merged) = merged {
                        let known = ordered_raw_txs(&merged);
                        let declared = pending.input.clone();
                        if let JobVerdict::Rejected(error_code) = validator
                            .validate_declaration(DeclaredJobToValidate {
                                session_id,
                                version: declared.version,
                                coinbase_tx_prefix: &declared.coinbase_tx_prefix,
                                coinbase_tx_suffix: &declared.coinbase_tx_suffix,
                                wtxid_list: &declared.wtxid_list,
                                known_raw_txs: &known,
                            })
                            .await
                        {
                            warn!(
                                session_id,
                                error_code,
                                "jdp: node rejected the completed declaration — not accepting it"
                            );
                            // Drop the pending declaration with it, otherwise
                            // the session keeps a half-finished round-trip.
                            state.pending_declaration = None;
                            return JdpHandlerOutcome::with_frame_pub(
                                JdpOutboundFrame::DeclareMiningJobError {
                                    request_id: declared.request_id,
                                    error_code,
                                    error_details:
                                        b"declared job rejected by the pool's bitcoin node".to_vec(),
                                },
                            );
                        }
                    }
                }
            }
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            // ext 0x0003/Grace Window + Implementation Notes are judged when
            // the declaration is ACCEPTED — re-resolve against the pending
            // declare's referenced id, so a supersession or settlement during
            // the round-trip is seen.
            let pending_distribution_id = state
                .pending_declaration
                .as_ref()
                .and_then(|p| p.input.distribution_id);
            let distribution =
                resolve_distribution_acceptance(bridge, session_id, pending_distribution_id);
            // Same rule as the declare above: the miner is the one the pending
            // declaration was accepted for, which `accept_declaration` reads
            // back out of it.
            let pending_miner = state
                .pending_declaration
                .as_ref()
                .map(|p| p.miner_address.clone());
            let current_mode = match pending_miner {
                Some(miner) => hooks.distribution_source.current_mode(&miner).await,
                None => None,
            };
            handle_provide_missing_transactions_success(
                state,
                &input,
                DeclarationContext {
                    current_prev_hash,
                    distribution,
                    current_mode,
                    now_ms,
                },
            )
        }
        // The handler matches the solution to a declaration and reads the
        // miner off that same declaration, so there is nothing to resolve
        // here.
        InboundJdpFrame::PushSolution(input) => handle_push_solution(state, &input),
    }
}

/// The accounting the address behind `token` is on right now.
///
/// Keyed on the TOKEN and not on the connection: an allocate carries its own
/// miner address and nothing binds a JDP session to a single one, so the
/// session-scoped "last address that allocated" answers a different question
/// than the declare asks. `None` when the token is unknown or expired — the
/// handler refuses it on its own grounds a moment later.
async fn current_mode_for_token(
    state: &mut JdpSessionState,
    hooks: &JdpServerHooks,
    token: &Token,
    now_ms: u64,
) -> Option<bp_common::StreamKind> {
    let miner = state
        .tokens
        .lookup_active(token, now_ms)
        .map(|t| t.miner_address.clone())?;
    hooks.distribution_source.current_mode(&miner).await
}

/// Resolve an ext 0x0003/distribution_id TLV Field reference
/// against the bridge's acceptance window, under the declare path's session
/// scope. `None` TLV → `None` (the handler decides whether that's an error —
/// it is, on a negotiated connection).
fn resolve_distribution_acceptance(
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    session_id: u32,
    distribution_id: Option<u64>,
) -> Option<DistributionAcceptance> {
    distribution_id.map(|id| {
        bridge
            .read()
            .expect("bridge RwLock poisoned")
            .distribution_acceptance(id, DistributionScope::JdpSession(session_id))
    })
}

/// Lower a [`BuiltPayoutDistribution`] into the bridge's registry entry.
fn entry_from_built(
    distribution_id: u64,
    built: BuiltPayoutDistribution,
    accounting: DistributionAccounting,
    jdp_session_id: Option<u32>,
    published_at_ms: u64,
) -> PayoutDistributionEntry {
    PayoutDistributionEntry {
        distribution_id,
        pool_payout: built.pool_payout,
        payouts: built.payouts,
        dust_limits: built.dust_limits,
        additional_outputs: built.additional_outputs,
        reference_reward_sats: built.reference_reward_sats,
        payouts_fingerprint: built.payouts_fingerprint,
        bookable: built.bookable,
        accounting,
        jdp_session_id,
        published_at_ms,
    }
}

/// The ext 0x0003/SetPayoutDistribution wire form of a registry entry.
fn wire_from_entry(entry: &PayoutDistributionEntry) -> SetPayoutDistribution {
    SetPayoutDistribution {
        distribution_id: entry.distribution_id,
        pool_payout: entry.pool_payout.to_wire_txout(),
        payouts: entry.payouts.iter().map(|p| p.to_wire_txout()).collect(),
        dust_limits: entry.dust_limits.clone(),
        additional_outputs: entry.additional_outputs.clone(),
    }
}

/// Fan out [`JdpSessionEvent`]s: SetupComplete is informational,
/// TokenAllocated and JobDeclared were registered in the bridge before the
/// outbound write, BlockSubmissionCandidate goes to the
/// block-submission sink. Disconnect is not handled here — the
/// connection loop reads it off the outcome and breaks after the write.
async fn fan_out_events(events: Vec<JdpSessionEvent>, hooks: &JdpServerHooks) {
    for event in events {
        match event {
            JdpSessionEvent::SetupComplete => {}
            // Both already registered in the bridge, before the outbound
            // write — see the `register_bridge_entries` call in
            // `run_jdp_connection`, which has the session state this
            // fan-out does not carry. Do not register here as well.
            JdpSessionEvent::TokenAllocated { .. } => {}
            JdpSessionEvent::JobDeclared { .. } => {}
            JdpSessionEvent::BlockSubmissionCandidate {
                miner_address,
                new_token,
                backing,
                coinbase_raw,
                transactions,
                prev_hash,
                version,
                ntime,
                nonce,
                n_bits,
            } => {
                hooks
                    .block_submission_sink
                    .submit_block_candidate(
                        miner_address,
                        new_token,
                        backing,
                        coinbase_raw,
                        transactions,
                        prev_hash,
                        version,
                        ntime,
                        nonce,
                        n_bits,
                    )
                    .await;
            }
            // Acted on in the connection loop, which owns the socket —
            // it breaks once the rejection frame is written.
            JdpSessionEvent::Disconnect { .. } => {}
        }
    }
}

/// Serialise + write each [`JdpOutboundFrame`] through the noise
/// stream. Same pattern as `server::write_outbound_frames`. ext 0x0003
/// frames (RequestPayoutOutputs Success/Error) take the manual raw-bytes
/// path below (they're not in `AnyMessage`); all other frames go through
/// `encode_jdp_outbound`.
async fn write_jdp_outbound_frames(
    writer: &mut NoiseTcpWriteHalf<AnyMessage<'static>>,
    outbound: Vec<JdpOutboundFrame>,
) -> Result<(), WriteError> {
    for frame in outbound {
        // ext 0x0003 (Non-Custodial Pool Payouts) frames take the
        // raw-bytes path — they're not in `AnyMessage`. Build the SV2
        // frame manually: 6-byte header (ext_type LE16 + msg_type +
        // msg_length LE24) + payload.
        if let Some((msg_type, payload)) = encode_jdp_outbound_ext_0x0003(&frame) {
            let mut bytes = Vec::with_capacity(6 + payload.len());
            // ext_type = 0x0003 LE
            bytes.extend_from_slice(&0x0003u16.to_le_bytes());
            bytes.push(msg_type);
            // msg_length = payload.len() as LE U24 (3 bytes)
            let msg_len = payload.len() as u32;
            if msg_len > 0x00FF_FFFF {
                return Err(WriteError::Codec(CodecError::Conversion(format!(
                    "ext 0x0003 payload too large: {} bytes (max 16M-1)",
                    payload.len()
                ))));
            }
            bytes.push((msg_len & 0xFF) as u8);
            bytes.push(((msg_len >> 8) & 0xFF) as u8);
            bytes.push(((msg_len >> 16) & 0xFF) as u8);
            bytes.extend_from_slice(&payload);

            // Sv2Frame::from_bytes_unchecked wraps pre-serialised
            // bytes; the phantom `AnyMessage` type isn't actually
            // touched because `serialized = Some(...)` short-circuits
            // the encoder.
            let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
                StandardSv2Frame::from_bytes_unchecked(bytes.into());
            writer
                .write_frame(Frame::Sv2(sv2_frame))
                .await
                .map_err(WriteError::Io)?;
            continue;
        }

        let any_message = match encode_jdp_outbound(frame) {
            Ok(m) => m,
            Err(CodecError::EncodeUnimplemented(what)) => {
                debug!("jdp write: skipping unimplemented frame ({what})");
                continue;
            }
            Err(e) => return Err(WriteError::Codec(e)),
        };
        let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
            any_message
                .try_into()
                .map_err(|e: stratum_core::parsers_sv2::ParserError| {
                    WriteError::Codec(CodecError::Conversion(format!("{e:?}")))
                })?;
        writer
            .write_frame(Frame::Sv2(sv2_frame))
            .await
            .map_err(WriteError::Io)?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("noise io: {0:?}")]
    Io(crate::noise::NoiseError),
}

/// What the bridge does with an allocate token.
///
/// A value and not four inline match arms, because three of the four say
/// "register nothing" and only ONE of those three is a fault. Told apart by
/// outcome they are indistinguishable — which is how an ext 0x0003 allocate,
/// whose empty `coinbase_tx_outputs` ext 0x0003/Negotiation REQUIRES, came to
/// be logged as a pool bug on every Coinbase-only 0x0003 connection. As a
/// value each reason is testable on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationDisposition<'a> {
    /// Base-protocol Coinbase-only: the allocate is the pool's ONLY record of
    /// this token (SV2 JDP/Coinbase-only Mode — that mode never declares), so
    /// the mining side resolves it here and holds the custom job's coinbase to
    /// this script.
    Register { payout_script: &'a [u8] },
    /// Full-Template: the declaration is the record, not this. Registering its
    /// allocate token too would let the JDC skip `DeclareMiningJob`, where
    /// bitcoin-core validates its transaction set
    /// (SV2 JDP/Job Declarator Server), and mine a job no node ever saw — no
    /// tip binding, no merkle-path check.
    LeftToTheDeclaration,
    /// ext 0x0003: ext 0x0003/Negotiation requires the allocate's outputs to
    /// be empty, so there is no designated script by design. The job is judged
    /// by the ext 0x0003/Output Verification recompute against the referenced
    /// distribution, which is the stronger check.
    ///
    /// Registered all the same, as [`AllocationKind::JudgedByDistribution`] —
    /// the SV2 JDP/AllocateMiningJobToken.Success test cannot stand in for
    /// ext 0x0003/Output Verification because the entry says which it is. It
    /// used to register nothing, on the reasoning that the coinbase was
    /// already better checked; that reasoning is about the coinbase and left
    /// the TOKEN unknown to the mining side, which then bound neither the
    /// miner address nor the chain tip for such a job.
    JudgedByTheDistribution,
    /// A base-protocol allocate that designated nothing. The pool built that
    /// blob, so this is OUR bug, not the client's — and it is invisible from
    /// the client side, which just gets `invalid-mining-job-token` on every
    /// job it ever builds.
    DesignatedNothing,
}

/// Which of the four an allocate token is. Pure and total on purpose: it takes
/// only the three flags that decide it, so every combination can be asserted
/// without a connection, and a case added later has to be classified rather
/// than fall into an existing arm.
pub(crate) fn classify_allocation(
    payout_script: Option<&[u8]>,
    full_template_mode: bool,
    payout_distribution_negotiated: bool,
) -> AllocationDisposition<'_> {
    match (
        payout_script,
        full_template_mode,
        payout_distribution_negotiated,
    ) {
        (Some(payout_script), false, false) => AllocationDisposition::Register { payout_script },
        (_, true, _) => AllocationDisposition::LeftToTheDeclaration,
        (_, false, true) => AllocationDisposition::JudgedByTheDistribution,
        (None, false, false) => AllocationDisposition::DesignatedNothing,
    }
}

/// Register the latest declared job in the bridge so the mining
/// server's `SetCustomMiningJob` handler can find it. Called from
/// the per-connection task after `dispatch_jdp_inbound` returns —
/// at that point `state.declared_jobs` has the fresh entry keyed by
/// `new_token` (the handler's accept-path inserted it).
///
/// Public-`pub(crate)` so unit tests can drive it without spinning
/// up a real connection.
pub(crate) fn register_bridge_entries(
    state: &JdpSessionState,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    jdp_session_id: u32,
    events: &[JdpSessionEvent],
) {
    let mut reg = bridge.write().expect("bridge RwLock poisoned");
    for event in events {
        match event {
            JdpSessionEvent::JobDeclared { new_token } => {
                if let Some(declared_job) = state.declared_jobs.get(new_token) {
                    reg.register(
                        *new_token,
                        RegisteredDeclaredJob {
                            declared_job: declared_job.clone(),
                            jdp_session_id,
                        },
                    );
                }
            }
            // Base-protocol Coinbase-only allocate: that mode never declares
            // (SV2 JDP/Coinbase-only Mode), so this is the only record the
            // mining side will have when its `SetCustomMiningJob` arrives.
            //
            // Which of the four this is: [`classify_allocation`], which owns
            // the reasoning and is asserted over every combination. Note the
            // negotiation flag is asked EXPLICITLY rather than inferred from
            // `payout_script: None` — ext 0x0003/Negotiation empties the
            // outputs on a negotiated session, so a legitimate 0x0003 allocate
            // and a broken base one look identical here.
            JdpSessionEvent::TokenAllocated {
                token,
                miner_address,
                payout_script,
                expires_at_ms,
            } => match classify_allocation(
                payout_script.as_deref(),
                state.full_template_mode,
                state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS),
            ) {
                AllocationDisposition::Register { payout_script } => {
                    reg.register_allocation(
                        *token,
                        AllocatedTokenRef {
                            miner_address: miner_address.clone(),
                            kind: AllocationKind::DesignatedOutput(payout_script.to_vec()),
                            jdp_session_id,
                            expires_at_ms: *expires_at_ms,
                        },
                        now_ms(),
                    );
                }
                AllocationDisposition::JudgedByTheDistribution => {
                    reg.register_allocation(
                        *token,
                        AllocatedTokenRef {
                            miner_address: miner_address.clone(),
                            kind: AllocationKind::JudgedByDistribution,
                            jdp_session_id,
                            expires_at_ms: *expires_at_ms,
                        },
                        now_ms(),
                    );
                }
                AllocationDisposition::LeftToTheDeclaration => {}
                AllocationDisposition::DesignatedNothing => {
                    warn!(
                        session_id = jdp_session_id,
                        "jdp: base-protocol allocate designated no payout output — the token \
                         cannot back a custom job (every SetCustomMiningJob on it will be \
                         refused)"
                    );
                }
            },
            // Neither reaches the bridge. Spelled out rather than swallowed
            // by a wildcard so a new event has to be classified here.
            JdpSessionEvent::SetupComplete
            | JdpSessionEvent::BlockSubmissionCandidate { .. }
            | JdpSessionEvent::Disconnect { .. } => {}
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jdp::client::AllocateMiningJobTokenInput;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn noise_cfg() -> NoiseConfig {
        NoiseConfig::parse_strings(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72",
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n",
            crate::noise::DEFAULT_CERT_VALIDITY,
        )
        .unwrap()
    }

    fn fresh_bridge() -> Arc<RwLock<JdpDeclaredJobRegistry>> {
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()))
    }

    fn fresh_session() -> JdpSessionState {
        let mut s = JdpSessionState::new(1);
        // Deterministic RNG so allocated tokens are predictable.
        s.set_token_rng(Some(Box::new(|buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = 0;
            }
            Ok(())
        })));
        s
    }

    fn jdp_setup() -> crate::jdp::client::SetupConnectionInput {
        crate::jdp::client::SetupConnectionInput {
            protocol: crate::jdp::client::PROTOCOL_JOB_DECLARATION,
            min_version: 2,
            max_version: 2,
            flags: crate::jdp::client::FLAG_DECLARE_TX_DATA,
            vendor: "v".to_string(),
            firmware: "f".to_string(),
            hardware_version: "h".to_string(),
            device_id: "d".to_string(),
        }
    }

    /// Minimal ext 0x0003/SetPayoutDistribution registry entry: one weight-9
    /// miner slot behind a weight-1 pool output.
    fn test_distribution(id: u64) -> PayoutDistributionEntry {
        PayoutDistributionEntry {
            distribution_id: id,
            pool_payout: WeightedOutput {
                script_pubkey: vec![0x51],
                weight: 1,
            },
            payouts: vec![WeightedOutput {
                script_pubkey: vec![0x00, 0x14, 0xAA],
                weight: 9,
            }],
            dust_limits: vec![546],
            additional_outputs: vec![],
            reference_reward_sats: 312_500_000,
            payouts_fingerprint: Some([id as u8; 32]),
            bookable: true,
            accounting: DistributionAccounting::PoolWide,
            jdp_session_id: None,
            published_at_ms: 1_000,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_handle_is_cloneable_and_shutdown_idempotent() {
        let bridge = fresh_bridge();
        let server = StratumV2JdpServer::spawn(
            noise_cfg(),
            JdpServerHooks::no_op(),
            bridge,
            Duration::from_secs(3600),
        );
        let _clone = server.clone();
        server.shutdown().await;
        server.shutdown().await; // idempotent
    }

    #[tokio::test(flavor = "current_thread")]
    async fn allocate_session_ids_monotonic_per_handle() {
        let bridge = fresh_bridge();
        let server = StratumV2JdpServer::spawn(
            noise_cfg(),
            JdpServerHooks::no_op(),
            bridge,
            Duration::from_secs(3600),
        );
        assert_eq!(server.alloc_session_id(), 1);
        assert_eq!(server.alloc_session_id(), 2);
        assert_eq!(server.alloc_session_id(), 3);
        server.shutdown().await;
    }

    fn granted(outcome: AllocateOutcome) -> AllocateTokenContext {
        match outcome {
            AllocateOutcome::Granted(ctx) => ctx,
            AllocateOutcome::Refused { reason } => panic!("refused: {reason}"),
            AllocateOutcome::Ignored => panic!("ignored"),
        }
    }

    /// The no-op hook has to designate a payout output like production
    /// does, or the base-protocol path it stands in for is untestable: a
    /// blob with no first output designates nothing, the bridge registers
    /// no allocation, and every custom job built on the token is refused
    /// `invalid-mining-job-token` while the harness looks green.
    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_designates_the_miners_own_output() {
        let hooks = NoOpJdpHooks;
        let ctx = granted(
            hooks
                .resolve_allocate_context(ADDR, "1.2.3.4:1234", false)
                .await,
        );
        assert_eq!(ctx.miner_address.as_str(), ADDR);
        let outputs: Vec<bitcoin::TxOut> =
            bitcoin::consensus::deserialize(&ctx.coinbase_outputs).expect("outputs decode");
        assert_eq!(
            outputs.len(),
            1,
            "SV2 JDP/AllocateMiningJobToken.Success designates ONE payout output"
        );
        assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
        assert_eq!(
            crate::jdp::dynamic_outputs::designated_payout_script(&ctx.coinbase_outputs).as_deref(),
            Some(outputs[0].script_pubkey.as_bytes()),
            "the blob must yield a designated script the bridge can register"
        );
    }

    /// ext 0x0003/Negotiation: with ext 0x0003 negotiated the
    /// `SetPayoutDistribution` push replaces the base output semantics —
    /// `coinbase_tx_outputs` in `AllocateMiningJobToken.Success` MUST be
    /// empty.
    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_empty_outputs_when_0x0003_negotiated() {
        let hooks = NoOpJdpHooks;
        let ctx = granted(
            hooks
                .resolve_allocate_context(ADDR, "1.2.3.4:1234", true)
                .await,
        );
        assert_eq!(ctx.miner_address.as_str(), ADDR);
        assert!(ctx.coinbase_outputs.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_rejects_garbage_user_identifier() {
        let hooks = NoOpJdpHooks;
        let outcome = hooks
            .resolve_allocate_context(&"x".repeat(200), "1.2.3.4:1234", false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Ignored),
            "garbage user-identifier is ignored, not refused — the connection stays open"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_allocate_token_emits_success_with_resolver() {
        let mut state = fresh_session();
        // Need setup_complete first.
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        let hooks = JdpServerHooks::no_op();
        let bridge = fresh_bridge();
        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::AllocateMiningJobToken(AllocateMiningJobTokenInput {
                request_id: 7,
                user_identifier: ADDR.to_string(),
            }),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            1_000,
        )
        .await;
        match &outcome.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                request_id,
                mining_job_token: _,
                coinbase_outputs,
            } => {
                assert_eq!(*request_id, 7);
                // SV2 JDP/AllocateMiningJobToken.Success: one designated
                // payout output, 0 sats. This used to assert `[0x00]` — an
                // EMPTY output vector, i.e. the no-op hook designating
                // nothing, which is what made every base-protocol custom job
                // unservable.
                let outputs: Vec<bitcoin::TxOut> =
                    bitcoin::consensus::deserialize(coinbase_outputs).expect("outputs decode");
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
            }
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    // ── SV2 JDP/Job Declarator Server node-side validation of declared jobs ───

    /// The marker the SV2 JDP/Job Declarator Server gate stamps on its own
    /// rejections. Lets a test tell "the node refused this" apart from the
    /// ordinary handler errors (an unallocated token, say) that have nothing
    /// to do with the gate.
    const NODE_REFUSAL: &[u8] = b"declared job rejected by the pool's bitcoin node";

    fn refused_by_node(outcome: &JdpHandlerOutcome) -> bool {
        outcome.outbound.iter().any(|f| {
            matches!(
                f,
                JdpOutboundFrame::DeclareMiningJobError { error_details, .. }
                    if error_details.as_slice() == NODE_REFUSAL
            )
        })
    }

    /// Stands in for bitcoin-core: answers with whatever verdict the test
    /// wants and records that it was actually consulted.
    struct StubValidator {
        verdict: std::sync::Mutex<Option<JobVerdict>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl StubValidator {
        fn new(verdict: JobVerdict) -> Arc<Self> {
            Arc::new(Self {
                verdict: std::sync::Mutex::new(Some(verdict)),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl DeclaredJobValidator for StubValidator {
        async fn validate_declaration(&self, _job: DeclaredJobToValidate<'_>) -> JobVerdict {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match self.verdict.lock().expect("verdict lock").take() {
                Some(JobVerdict::Rejected(code)) => JobVerdict::Rejected(code),
                Some(JobVerdict::NeedsTransactions) => JobVerdict::NeedsTransactions,
                _ => JobVerdict::Accepted,
            }
        }
    }

    fn declare_input() -> crate::jdp::client::DeclareMiningJobInput {
        crate::jdp::client::DeclareMiningJobInput {
            request_id: 11,
            mining_job_token: Token([0xAA; 16]),
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0xBB; 8],
            coinbase_tx_suffix: vec![0xCC; 8],
            wtxid_list: vec![[0x11; 32]],
            distribution_id: None,
        }
    }

    /// A node rejection must stop the declaration dead: the JDC gets a
    /// `DeclareMiningJob.Error` and nothing is registered. Accepting it would
    /// mean paying shares for a job the pool's own node says is invalid.
    #[tokio::test(flavor = "current_thread")]
    async fn a_node_rejected_declaration_is_refused() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let validator = StubValidator::new(JobVerdict::Rejected("invalid-coinbase-tx".to_string()));
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input()),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            1_000,
        )
        .await;

        assert_eq!(validator.calls(), 1, "the node must actually be consulted");
        match &outcome.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError {
                request_id,
                error_code,
                ..
            } => {
                assert_eq!(*request_id, 11);
                assert_eq!(error_code, "invalid-coinbase-tx");
            }
            other => panic!("expected DeclareMiningJobError, got {other:?}"),
        }
        assert!(
            state.pending_declaration.is_none(),
            "a refused declaration must leave no half-finished round-trip behind"
        );
    }

    /// Without a validator wired the pool keeps its previous behaviour —
    /// declarations are taken on the JDC's word. Guards against the gate
    /// silently becoming mandatory.
    #[tokio::test(flavor = "current_thread")]
    async fn without_a_validator_the_declaration_is_not_refused() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let hooks = JdpServerHooks::no_op();
        assert!(hooks.job_validator.is_none());
        let bridge = fresh_bridge();

        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input()),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            1_000,
        )
        .await;

        assert!(
            !refused_by_node(&outcome),
            "no validator must mean no node-driven rejection: {:?}",
            outcome.outbound
        );
    }

    /// `NeedsTransactions` is not a rejection: the node simply cannot judge
    /// yet. The pool's own ProvideMissingTransactions round-trip has to run.
    #[tokio::test(flavor = "current_thread")]
    async fn needs_transactions_is_not_a_rejection() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let validator = StubValidator::new(JobVerdict::NeedsTransactions);
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input()),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            1_000,
        )
        .await;

        assert_eq!(validator.calls(), 1);
        assert!(
            !refused_by_node(&outcome),
            "a node that lacks transactions must not fail the declaration: {:?}",
            outcome.outbound
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_setup_connection_emits_success() {
        let mut state = fresh_session();
        let hooks = JdpServerHooks::no_op();
        let bridge = fresh_bridge();
        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::SetupConnection(jdp_setup()),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            0,
        )
        .await;
        assert!(matches!(
            outcome.outbound[0],
            JdpOutboundFrame::SetupConnectionSuccess { .. }
        ));
        assert!(state.setup_complete);
    }

    /// ext 0x0003/SetPayoutDistribution makes `SetPayoutDistribution` the
    /// mandatory first push after the extensions exchange — so 0x0003 is only
    /// offered while a pool-wide distribution is actually publishable.
    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_request_extensions_offers_0x0003_only_when_publishable() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        let hooks = JdpServerHooks::no_op();
        let bridge = fresh_bridge();
        let request = |id: u16| {
            InboundJdpFrame::RequestExtensions(crate::extensions::RequestExtensions {
                request_id: id,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            })
        };

        // No distribution published yet → the extension is not offered.
        let outcome = dispatch_jdp_inbound(
            &mut state,
            request(1),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            1_000,
        )
        .await;
        match &outcome.outbound[0] {
            JdpOutboundFrame::RequestExtensionsError {
                unsupported_extensions,
                ..
            } => {
                assert!(unsupported_extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS))
            }
            other => panic!("expected RequestExtensionsError, got {other:?}"),
        }
        assert!(!state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));

        // With a publishable pool-wide distribution the offer stands.
        bridge
            .write()
            .unwrap()
            .publish_pool_wide(test_distribution(1));
        let outcome = dispatch_jdp_inbound(
            &mut state,
            request(2),
            &hooks,
            &bridge,
            1,
            "1.2.3.4:5555",
            2_000,
        )
        .await;
        match &outcome.outbound[0] {
            JdpOutboundFrame::RequestExtensionsSuccess {
                supported_extensions,
                ..
            } => assert!(supported_extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)),
            other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
        }
        assert!(state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));
    }

    /// The four states get four answers, and the two that rebuild get them for
    /// different reasons. Without the `Denied` arm a session refused once has
    /// only the publisher's tick left — and that tick is skipped whenever the
    /// fingerprint is unchanged, so on a quiet window nothing wakes it at all.
    #[test]
    fn only_the_states_that_have_something_to_gain_rebuild_on_a_frame() {
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        let solo = Some(bp_common::StreamKind::Solo);
        // Undecided: every frame, the check returns before anything is built.
        assert!(rebuild_due(&SessionDistribution::AwaitingMode, solo, 0, 0));
        assert!(rebuild_due(&SessionDistribution::AwaitingMode, solo, 1, 0));

        // Refused: not on the next frame, but not never either.
        assert!(!rebuild_due(
            &SessionDistribution::Denied,
            solo,
            1_000,
            1_000
        ));
        assert!(!rebuild_due(
            &SessionDistribution::Denied,
            solo,
            1_000 + DENIED_REBUILD_INTERVAL_MS - 1,
            1_000
        ));
        assert!(rebuild_due(
            &SessionDistribution::Denied,
            solo,
            1_000 + DENIED_REBUILD_INTERVAL_MS,
            1_000
        ));

        // Being served the plan its mode calls for: its own traffic decides
        // nothing, however long it keeps sending.
        for (served, mode) in [
            (
                SessionDistribution::Served(DistributionAccounting::Solo(miner.clone())),
                bp_common::StreamKind::Solo,
            ),
            (
                SessionDistribution::Served(DistributionAccounting::GroupSolo(miner.clone())),
                bp_common::StreamKind::GroupSolo,
            ),
            (
                SessionDistribution::Served(DistributionAccounting::PoolWide),
                bp_common::StreamKind::Pplns,
            ),
        ] {
            assert!(
                !rebuild_due(&served, Some(mode), u64::MAX, 0),
                "{served:?} on {mode:?}"
            );
        }
    }

    /// The mode moving under a served session is the ONE thing that re-opens
    /// it — every pair that is not the one it was built for, in both
    /// directions, so a fix that only caught the group-join direction fails
    /// here.
    #[test]
    fn a_served_session_rebuilds_exactly_when_its_mode_moved() {
        use bp_common::StreamKind as Sk;
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        let served_for = |accounting: DistributionAccounting| match accounting {
            DistributionAccounting::PoolWide => {
                SessionDistribution::Served(DistributionAccounting::PoolWide)
            }
            tailored => SessionDistribution::Served(tailored),
        };
        for (accounting, built_for) in [
            (DistributionAccounting::Solo(miner.clone()), Sk::Solo),
            (
                DistributionAccounting::GroupSolo(miner.clone()),
                Sk::GroupSolo,
            ),
            (DistributionAccounting::PoolWide, Sk::Pplns),
        ] {
            let served = served_for(accounting);
            for now in [Sk::Solo, Sk::GroupSolo, Sk::Pplns, Sk::Blockparty] {
                assert_eq!(
                    rebuild_due(&served, Some(now), u64::MAX, 0),
                    now != built_for,
                    "{served:?} was built for {built_for:?}, gate now says {now:?}"
                );
            }
            // …and "the gate has never heard of this address" is not a move.
            // A miner behind a JDC that drops for a moment must not cost the
            // session the plan it is correctly being served.
            assert!(
                !rebuild_due(&served, None, u64::MAX, 0),
                "{served:?} must survive an unknown mode"
            );
        }
    }

    /// The declare's mode is looked up for the address of the TOKEN it names,
    /// not for whichever address allocated last on the connection.
    ///
    /// Nothing binds a JDP session to a single payout address — the allocate
    /// carries one, and a client may allocate for two. The session-scoped
    /// `identity` (which the loop keeps for its OWN plan) is then the wrong
    /// operand for the declare: address A's correct, current plan gets judged
    /// against address B's mode and refused `stale-payout-distribution`, fatal
    /// for an SRI jd-client and permanent, because every later declare re-reads
    /// B's mode.
    #[tokio::test]
    async fn a_declares_mode_comes_from_its_own_tokens_address() {
        struct PerAddress;
        #[async_trait]
        impl PayoutDistributionSource for PerAddress {
            async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution> {
                None
            }
            async fn build_for_miner(&self, _: &AddressId) -> TailoredDistribution {
                TailoredDistribution::ModeUnknown
            }
            async fn current_mode(&self, miner: &AddressId) -> Option<bp_common::StreamKind> {
                match miner.as_str() {
                    ADDR => Some(bp_common::StreamKind::Solo),
                    _ => Some(bp_common::StreamKind::Pplns),
                }
            }
            async fn next_distribution_id(&self) -> Option<u64> {
                None
            }
        }
        let mut hooks = JdpServerHooks::no_op();
        hooks.distribution_source = Arc::new(PerAddress);

        let other = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v";
        let mut state = JdpSessionState::new(1);
        let a = state
            .tokens
            .allocate(1_000, AddressId::new(ADDR.to_string()).unwrap(), vec![0u8])
            .expect("token for A")
            .token;
        // SV2 JDP/AllocateMiningJobToken rate-limits token issuance to 1/s per
        // connection.
        let b = state
            .tokens
            .allocate(3_000, AddressId::new(other.to_string()).unwrap(), vec![0u8])
            .expect("token for B")
            .token;

        assert_eq!(
            current_mode_for_token(&mut state, &hooks, &a, 3_000).await,
            Some(bp_common::StreamKind::Solo),
            "A's token must be judged by A's mode, even though B allocated last"
        );
        assert_eq!(
            current_mode_for_token(&mut state, &hooks, &b, 3_000).await,
            Some(bp_common::StreamKind::Pplns)
        );
        assert_eq!(
            current_mode_for_token(&mut state, &hooks, &Token([0xEE; 16]), 3_000).await,
            None,
            "an unknown token has no address to ask about"
        );
    }

    /// Only a served session has a plan on file to drop — and it is the
    /// dropping that matters: ext 0x0003/Grace Window keeps the
    /// immediately-previous entry acceptable, so a plan merely superseded is
    /// still declarable against.
    #[test]
    fn only_a_served_session_has_a_plan_to_drop() {
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        for accounting in [
            DistributionAccounting::PoolWide,
            DistributionAccounting::Solo(miner.clone()),
            DistributionAccounting::GroupSolo(miner),
        ] {
            assert_eq!(
                SessionDistribution::Served(accounting.clone()).accounting(),
                Some(&accounting)
            );
        }
        assert_eq!(SessionDistribution::AwaitingMode.accounting(), None);
        assert_eq!(SessionDistribution::Denied.accounting(), None);
    }

    /// The denial is readable without taking the write lock — the whole point
    /// of the accessor, since a session awaiting its mode asks once per frame.
    #[test]
    fn a_denial_can_be_read_before_deciding_to_write_it() {
        let mut reg = JdpDeclaredJobRegistry::new();
        assert!(!reg.is_pool_wide_denied(7), "a fresh session is not denied");
        reg.deny_pool_wide(7);
        assert!(reg.is_pool_wide_denied(7));
        reg.deny_pool_wide(7);
        assert!(
            reg.is_pool_wide_denied(7),
            "denying twice is a no-op, not a flip"
        );
        reg.allow_pool_wide(7);
        assert!(!reg.is_pool_wide_denied(7));
    }

    /// A healthy JDC start must not warn. It allocates ~8 s before its mining
    /// channel opens, so `AwaitingMode` on the first frames is the normal
    /// path — a line there would fire once per JDC and train the operator to
    /// ignore the one that matters.
    #[test]
    fn a_short_wait_for_the_mode_is_not_reported() {
        let mut w = AwaitingModeWatch::new();
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        for t in [0, 3_000, 8_000] {
            w.observe(&SessionDistribution::AwaitingMode, "jdp-test", &miner, t);
        }
        assert!(!w.warned, "8 s is the measured normal, not an anomaly");
        w.observe(
            &SessionDistribution::Served(DistributionAccounting::Solo(miner.clone())),
            "jdp-test",
            &miner,
            8_100,
        );
        assert_eq!(w.since_ms, None, "a resolved wait must reset");
    }

    /// A wait that outlasts the threshold is reported exactly once, however
    /// many frames arrive — the retry runs on EVERY inbound frame, so a line
    /// per observation would be a line per frame.
    #[test]
    fn a_stuck_session_is_reported_once_and_its_recovery_too() {
        let mut w = AwaitingModeWatch::new();
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        w.observe(
            &SessionDistribution::AwaitingMode,
            "jdp-test",
            &miner,
            1_000,
        );
        assert!(!w.warned);
        w.observe(
            &SessionDistribution::AwaitingMode,
            "jdp-test",
            &miner,
            1_000 + AwaitingModeWatch::WARN_AFTER_MS,
        );
        assert!(w.warned, "the threshold must trip it");
        assert_eq!(w.since_ms, Some(1_000), "the wait's start must not move");

        // Recovery clears BOTH, so a second episode on the same connection is
        // reported again instead of being swallowed by the first one's flag.
        w.observe(
            &SessionDistribution::Served(DistributionAccounting::PoolWide),
            "jdp-test",
            &miner,
            999_000,
        );
        assert!(!w.warned);
        assert_eq!(w.since_ms, None);
        w.observe(
            &SessionDistribution::AwaitingMode,
            "jdp-test",
            &miner,
            999_500,
        );
        assert_eq!(
            w.since_ms,
            Some(999_500),
            "a new episode starts its own clock"
        );
    }

    /// `Denied` is not `AwaitingMode`. It has its own warning at the point it
    /// happens (the build failed, and it says why); counting it as a wait for
    /// the mode would report the wrong cure — "no miner has connected for this
    /// address" — for a session whose mode is perfectly well known.
    #[test]
    fn a_denied_session_is_not_counted_as_awaiting_its_mode() {
        let mut w = AwaitingModeWatch::new();
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        for t in [0, 60_000, 600_000] {
            w.observe(&SessionDistribution::Denied, "jdp-test", &miner, t);
        }
        assert!(!w.warned);
        assert_eq!(w.since_ms, None);
    }

    /// The ext 0x0003/SetPayoutDistribution wire form mirrors the registry
    /// entry: weights ride in the TxOut amount field, dust limits and
    /// additional outputs pass through unchanged.
    #[test]
    fn wire_from_entry_carries_weights_and_dust_limits() {
        let entry = test_distribution(7);
        let wire = wire_from_entry(&entry);
        assert_eq!(wire.distribution_id, 7);
        assert_eq!(wire.pool_payout, entry.pool_payout.to_wire_txout());
        assert_eq!(wire.payouts.len(), 1);
        assert_eq!(wire.payouts[0], entry.payouts[0].to_wire_txout());
        assert_eq!(wire.dust_limits, vec![546]);
        assert!(wire.additional_outputs.is_empty());
    }

    /// `register_bridge_entries` pulls the declared-job
    /// payload out of the session state and writes a
    /// `RegisteredDeclaredJob` into the cross-server bridge.
    #[tokio::test(flavor = "current_thread")]
    async fn register_bridge_entries_pushes_declared_jobs_to_registry() {
        use crate::jdp::declarations::DeclaredJob;
        let mut state = fresh_session();
        let token = Token([0xAA; 16]);
        let job = DeclaredJob {
            new_token: token,
            miner_address: AddressId::new(ADDR.to_string()).unwrap(),
            version: 0,
            coinbase_tx_prefix: vec![],
            coinbase_tx_suffix: vec![],
            wtxid_list: vec![],
            raw_transactions: HashMap::new(),
            prev_hash: Some([0xCC; 32]),
            declared_at_ms: 500,
            booking: None,
            distribution_id: None,
        };
        state.declared_jobs.insert(job);
        let bridge = fresh_bridge();
        let events = vec![JdpSessionEvent::JobDeclared { new_token: token }];
        register_bridge_entries(&state, &bridge, 42, &events);
        let r = bridge.read().unwrap();
        let entry = r.job_ref(&token).expect("must be registered");
        assert_eq!(entry.jdp_session_id, 42);
        assert_eq!(entry.miner_address.as_str(), ADDR);
        assert_eq!(entry.declared_prev_hash, Some([0xCC; 32]));
    }

    /// Both Coinbase-only allocates reach the mining side, each saying WHICH
    /// kind it is — and the third shape, a base-protocol allocate that
    /// designated nothing, still registers nothing.
    ///
    /// Driven through TWO sessions on purpose. The 0x0003 case is decided by
    /// `state.negotiated_extensions`, not by the event, so running it on a
    /// non-negotiated session classifies it as `DesignatedNothing` and the
    /// test would pass while proving the opposite of its name — which is what
    /// the earlier single-session version did.
    #[tokio::test(flavor = "current_thread")]
    async fn register_bridge_entries_pushes_both_coinbase_only_kinds() {
        let bridge = fresh_bridge();
        let base = Token([0xBB; 16]);
        let broken = Token([0xDD; 16]);
        let negotiated = Token([0xCC; 16]);

        let plain = fresh_session();
        register_bridge_entries(
            &plain,
            &bridge,
            42,
            &[
                JdpSessionEvent::TokenAllocated {
                    token: base,
                    miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                    payout_script: Some(vec![0x00, 0x14, 0xAB]),
                    expires_at_ms: u64::MAX,
                },
                // Base protocol with no designated output: the pool built a
                // blob it cannot hold a coinbase to. Still nothing to register.
                JdpSessionEvent::TokenAllocated {
                    token: broken,
                    miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                    payout_script: None,
                    expires_at_ms: u64::MAX,
                },
            ],
        );

        let mut ext_session = fresh_session();
        ext_session
            .negotiated_extensions
            .insert(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        register_bridge_entries(
            &ext_session,
            &bridge,
            43,
            &[JdpSessionEvent::TokenAllocated {
                token: negotiated,
                miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                // ext 0x0003/Negotiation requires the outputs empty — this is
                // the conformant shape.
                payout_script: None,
                expires_at_ms: u64::MAX,
            }],
        );

        let r = bridge.read().unwrap();
        let entry = r.allocation_ref(&base, 0).expect("base allocate registers");
        assert_eq!(entry.jdp_session_id, 42);
        assert_eq!(entry.miner_address.as_str(), ADDR);
        assert_eq!(
            entry.kind,
            AllocationKind::DesignatedOutput(vec![0x00, 0x14, 0xAB])
        );
        assert!(
            r.allocation_ref(&broken, 0).is_none(),
            "a base-protocol allocate that designated nothing has nothing to hold a coinbase to"
        );
        // The ext 0x0003 allocate registers too, and says WHICH kind it is —
        // so the mining side can bind its miner address and the chain tip
        // without the SV2 JDP/AllocateMiningJobToken.Success output test ever
        // standing in for ext 0x0003/Output Verification. It used to register
        // nothing, which left both bindings off that path entirely.
        let ext = r
            .allocation_ref(&negotiated, 1_000)
            .expect("an ext 0x0003 allocate is still a token the pool issued");
        assert_eq!(ext.kind, AllocationKind::JudgedByDistribution);
        assert_eq!(ext.miner_address.as_str(), ADDR);
        assert_eq!(ext.jdp_session_id, 43);
    }

    /// All eight combinations, because three of the four dispositions register
    /// nothing and the registry cannot tell them apart — only the reason
    /// differs, and only ONE of them is a fault.
    ///
    /// The row this pins is `(script: None, Coinbase-only, negotiated)`.
    /// ext 0x0003/Negotiation REQUIRES an ext 0x0003 allocate to carry empty
    /// `coinbase_tx_outputs`, so it has no designated script — and reading
    /// that absence as "the pool built a broken blob" made every Coinbase-only
    /// 0x0003 connection log a pool bug and predict `invalid-mining-job-token`
    /// on every job it would ever build. Those jobs are served: the
    /// ext 0x0003/distribution_id TLV Field rides the frame in that mode and
    /// the ext 0x0003/Output Verification recompute judges them.
    #[test]
    fn an_allocate_is_classified_by_all_three_flags() {
        use AllocationDisposition as D;
        const SCRIPT: &[u8] = &[0x00, 0x14, 0xAB];

        // (payout_script, full_template_mode, negotiated) → disposition
        let cases: [(Option<&[u8]>, bool, bool, D); 8] = [
            // Coinbase-only, base protocol: the one row that registers.
            (
                Some(SCRIPT),
                false,
                false,
                D::Register {
                    payout_script: SCRIPT,
                },
            ),
            // Coinbase-only + ext 0x0003: NOT a fault — ext 0x0003/Negotiation
            // empties the outputs and ext 0x0003/Output Verification does the
            // judging.
            (None, false, true, D::JudgedByTheDistribution),
            // The same session shape with a script somehow present is still
            // the distribution's to judge — registering would let the weak
            // SV2 JDP/AllocateMiningJobToken.Success check stand in for the
            // ext 0x0003/Output Verification recompute.
            (Some(SCRIPT), false, true, D::JudgedByTheDistribution),
            // Full-Template: the declaration is the record, whatever else is
            // true. Registering would let the JDC skip
            // SV2 JDP/Job Declarator Server validation.
            (Some(SCRIPT), true, false, D::LeftToTheDeclaration),
            (Some(SCRIPT), true, true, D::LeftToTheDeclaration),
            (None, true, false, D::LeftToTheDeclaration),
            (None, true, true, D::LeftToTheDeclaration),
            // The only fault: a base allocate the pool designated nothing in.
            (None, false, false, D::DesignatedNothing),
        ];

        for (script, full_template, negotiated, want) in cases {
            assert_eq!(
                classify_allocation(script, full_template, negotiated),
                want,
                "script={:?} full_template={full_template} negotiated={negotiated}",
                script.map(|s| s.len())
            );
        }
    }
}
