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
//!   first frame after `RequestExtensions.Success` (§3.1), then re-published
//!   by the publisher task on interval / settlement invalidation.
//! - **Payout validation** in `accept_declaration` is positional
//!   recompute-and-compare (§7.1) against the distribution the declaration's
//!   `distribution_id` TLV names in the bridge registry.
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
use tracing::{debug, warn};

use crate::bridge::{
    DistributionAcceptance, DistributionScope, JdpDeclaredJobRegistry, PayoutDistributionEntry,
    RegisteredDeclaredJob,
};
use crate::extensions::{
    parse_distribution_id_tlv, SetPayoutDistribution, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use crate::jdp::client::{
    handle_allocate_token, handle_declare_mining_job, handle_provide_missing_transactions_success,
    handle_push_solution, handle_request_extensions, handle_setup_connection,
    parse_user_identifier_as_address, AllocateTokenContext, JdpHandlerOutcome, JdpOutboundFrame,
    JdpSessionEvent, JdpSessionState,
};
use crate::jdp::dynamic_outputs::PayoutBooking;
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
    /// connection. §2 then REQUIRES `coinbase_tx_outputs` to be empty
    /// (the distribution replaces the base §6.4.3 output semantics);
    /// the resolver must not build outputs at all in that case.
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        remote_addr: &str,
        payout_distribution_negotiated: bool,
    ) -> Option<AllocateTokenContext>;
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
/// `SetPayoutDistribution` (ext 0x0003 §3.1) and to register in the
/// bridge for §7.1 validation.
#[derive(Clone, Debug)]
pub struct BuiltPayoutDistribution {
    /// The pool output (`weight_P` in the amount field).
    pub pool_payout: WeightedOutput,
    /// Miner payout slots in §4 coinbase order.
    pub payouts: Vec<WeightedOutput>,
    /// Parallel to `payouts` (§3.1).
    pub dust_limits: Vec<u32>,
    /// Consensus-serialized 0-value TxOuts the pool appends.
    pub additional_outputs: Vec<Vec<u8>>,
    /// Revenue the weight boosts were projected against.
    pub reference_reward_sats: u64,
    /// Settlement-snapshot identity. `None` = the owning mode books
    /// without a snapshot (Solo / Blockparty).
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
    /// A distribution tailored to this miner.
    Built(Box<BuiltPayoutDistribution>),
    /// The tailored build could not be produced. This miner's shares do
    /// not enter the PPLNS window, so the pool-wide distribution is the
    /// wrong answer — the session must be served nothing until a later
    /// build succeeds.
    Unavailable,
}

/// Build the pool's payout distributions for the ext 0x0003 push model.
///
/// The publisher task calls [`Self::build_pool_wide`] on its interval
/// (and forced after a settlement); the per-connection task calls
/// [`Self::build_for_miner`] once an allocate reveals the miner's
/// identity (Solo and Group-Solo get a tailored distribution; a PPLNS
/// miner rides the pool-wide one; Blockparty is not served over JDP —
/// see [`TailoredDistribution`]).
/// [`Self::next_distribution_id`] allocates the §3.1 strictly-
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
    /// `None` ⇒ the allocator is unavailable; the publish is skipped
    /// (the previously-published distribution stays valid).
    async fn next_distribution_id(&self) -> Option<u64>;
}

/// Block-submission sink for `PushSolution` candidates. Production
/// wiring reconstructs the block via rust-bitcoin's `Block` + calls
/// `TdpHandle::submit_solution`; tests use a recording sink.
///
/// `booking` is `Some` only when the declared coinbase was validated
/// positionally against a published payout distribution (ext 0x0003 §7.1
/// declare-time check). `None` means the pool cannot say what this block
/// paid it — report it, book nothing.
#[async_trait]
pub trait JdpBlockSubmissionSink: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        new_token: Token,
        booking: Option<PayoutBooking>,
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

/// SV2 §6.1 lists "Maintaining an internal mempool (via RPCs (or similar) to a
/// Bitcoin Node)" among the JDS's responsibilities, and Full-Template mode
/// exists precisely so the pool can check what Coinbase-only mode has to take
/// on trust (§6.3.1: a miner declaring a coinbase whose template has a
/// different fee revenue, or invalid transactions — "in many ways identical to
/// block withholding").
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
    /// Node-side validation of declared jobs (§6.1). `None` → the pool
    /// accepts every declaration on the JDC's word, which is what it did
    /// before this hook existed.
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
    ) -> Option<AllocateTokenContext> {
        // Pure parse — no IP fallback. Production wiring overrides.
        parse_user_identifier_as_address(user_identifier).map(|addr| AllocateTokenContext {
            miner_address: addr,
            coinbase_outputs: if payout_distribution_negotiated {
                Vec::new() // §2 MUST: empty when 0x0003 is negotiated
            } else {
                vec![0u8]
            },
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
        _: Option<PayoutBooking>,
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
    /// invalidation (§10) must be followed by an immediate publish.
    refresh: Arc<tokio::sync::Notify>,
}

/// Settlement hook (§10): a booked block invalidates every published
/// distribution at once; the publisher then pushes a fresh one
/// immediately. Handed to the block-booking sink via
/// [`StratumV2JdpServer::distribution_handle`].
#[derive(Clone)]
pub struct DistributionInvalidationHandle {
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    refresh: Arc<tokio::sync::Notify>,
}

impl DistributionInvalidationHandle {
    /// §10 settlement invalidation + forced fresh publish.
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

    /// The §10 settlement hook for the block-booking sink.
    pub fn distribution_handle(&self) -> DistributionInvalidationHandle {
        DistributionInvalidationHandle {
            bridge: self.inner.bridge.clone(),
            refresh: self.inner.refresh.clone(),
        }
    }

    /// The pool-wide publisher (§3.1.1): builds the current
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
                let entry = entry_from_built(distribution_id, built, None, None, now_ms());
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

/// Build and push a fresh tailored distribution for `miner` on this
/// session. Returns `false` when the session was left WITHOUT one — the
/// caller must not then treat it as tailored-and-served.
///
/// Used both on the first allocate and after a §10 settlement, which
/// invalidates a tailored slot exactly like the pool-wide one while the
/// publisher only ever republishes the latter.
async fn republish_tailored(
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    writer: &mut NoiseTcpWriteHalf<AnyMessage<'static>>,
    session_id: u32,
    session_id_hex: &str,
    miner: &AddressId,
) -> bool {
    let built = match hooks.distribution_source.build_for_miner(miner).await {
        TailoredDistribution::Built(b) => *b,
        // The miner's mode changed under us (now PPLNS): the pool-wide
        // push is its accounting again.
        TailoredDistribution::PoolWide => {
            bridge
                .write()
                .expect("bridge RwLock poisoned")
                .allow_pool_wide(session_id);
            return false;
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
            return false;
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
        return false;
    };
    let entry = entry_from_built(
        distribution_id,
        built,
        Some(miner.clone()),
        Some(session_id),
        now_ms(),
    );
    let wire = wire_from_entry(&entry);
    {
        let mut guard = bridge.write().expect("bridge RwLock poisoned");
        guard.publish_tailored(session_id, entry);
        guard.allow_pool_wide(session_id);
    }
    if let Err(err) =
        write_jdp_outbound_frames(writer, vec![JdpOutboundFrame::SetPayoutDistribution(wire)]).await
    {
        warn!("jdp {session_id_hex} tailored republish write: {err:?}");
    }
    debug!(distribution_id, "jdp {session_id_hex} tailored republished");
    true
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
    // Whether this session got a tailored distribution (Solo /
    // Group-Solo / Blockparty); the pool-wide push then stops for it —
    // §4 "latest MUST be used" makes the tailored stream authoritative.
    let mut tailored_active = false;
    // The miner a tailored distribution was built for. Kept so a §10
    // settlement can be answered with a FRESH tailored distribution —
    // the publisher only ever republishes the pool-wide one, which this
    // session is (correctly) not listening for.
    let mut tailored_miner: Option<AddressId> = None;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            // Ext 0x0003 push (§3.1): a fresh pool-wide distribution was
            // published — forward it to every negotiated, non-tailored
            // session. (The FIRST distribution after RequestExtensions
            // is appended synchronously in the inbound arm, not here —
            // the watch channel can't order itself against the
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
                if tailored_active {
                    // A tailored session ignores the pool-wide push —
                    // §4 "latest MUST be used" makes its own stream
                    // authoritative. But the publisher fires this watch
                    // after a §10 settlement too, and a settlement
                    // invalidates EVERY distribution including this
                    // session's. Nobody else republishes a tailored one,
                    // so without this the JDC is answered
                    // `stale-payout-distribution` forever and simply
                    // stops declaring.
                    let still_current = bridge
                        .read()
                        .expect("bridge RwLock poisoned")
                        .current_tailored(session_id)
                        .is_some();
                    if still_current {
                        continue;
                    }
                    let Some(miner) = tailored_miner.clone() else {
                        continue;
                    };
                    if !republish_tailored(
                        &hooks,
                        &bridge,
                        &mut writer,
                        session_id,
                        &session_id_hex,
                        &miner,
                    )
                    .await
                    {
                        // Left denied / unpublished on purpose — better
                        // no distribution than the PPLNS one.
                        tailored_active = false;
                    }
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
                // (`SetPayoutDistribution` is JDS→JDC only; §6 references
                // arrive as TLVs on base frames). An ext-0x0003 frame
                // from a client is a protocol error — drop it.
                let ext_type = header.ext_type_without_channel_msg();
                if ext_type == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
                    warn!("jdp {session_id_hex} unexpected inbound ext-0x0003 frame — ignoring");
                    continue;
                }
                let mut tlv_extensions: Vec<u16> =
                    state.negotiated_extensions.iter().copied().collect();
                // §2: a 0x0003 reference from a client that never
                // negotiated the extension MUST be rejected — so the
                // TLV has to be SEEN, not silently filtered away with
                // the rest of the un-negotiated tail. Widen the filter
                // for the one message that carries it; the declare
                // handler enforces the gate.
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
                // §6: the distribution reference is a TLV on the base
                // DeclareMiningJob frame (frame ext_type stays 0x0000).
                if let InboundJdpFrame::DeclareMiningJob(ref mut input) = inbound {
                    input.distribution_id =
                        tlvs.as_deref().and_then(parse_distribution_id_tlv);
                }
                let was_request_extensions =
                    matches!(inbound, InboundJdpFrame::RequestExtensions(_));
                let negotiated_before = state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
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
                // §3.1 first-message guarantee: the moment 0x0003 lands
                // in the negotiated set, the current distribution goes
                // out IN THE SAME WRITE BATCH, right after
                // RequestExtensions.Success — deterministic ordering the
                // watch channel cannot give.
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
                        Some(entry) => outcome.outbound.push(
                            JdpOutboundFrame::SetPayoutDistribution(wire_from_entry(&entry)),
                        ),
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
                // Register declared jobs in the bridge BEFORE the frames go
                // out, and therefore before `fan_out_events`.
                //
                // Two reasons, and the first one is a race: the outbound batch
                // contains `DeclareMiningJobSuccess{new_mining_job_token}`, and
                // the JDC's MINING connection is a separate socket served by an
                // independent task. The moment that token is on the wire the
                // JDC may send `SetCustomMiningJob` for it. Per ext 0x0003 §6 a
                // Full-Template frame carries no `distribution_id` TLV, so
                // everything backing that job — the declaration binding AND its
                // distribution reference — lives in the bridge entry alone; a
                // lookup that misses answers `invalid-mining-job-token`, which
                // an SRI jd-client treats as fatal. Publishing first closes the
                // window at no cost: an entry for a token whose Success frame
                // then fails to send simply expires unused.
                //
                // Second, unchanged: the bridge must be populated by the time
                // the JobDeclared event is visible to other hooks.
                register_declared_jobs_in_bridge(
                    &state,
                    &bridge,
                    session_id,
                    now_ms(),
                    &outcome.events,
                );
                if let Err(err) = write_jdp_outbound_frames(&mut writer, outcome.outbound).await {
                    warn!("jdp {session_id_hex} write: {err:?}");
                    break;
                }
                outcome.outbound = Vec::new();
                // Identity became known (allocate) on a negotiated
                // session → check for a tailored distribution (Solo /
                // Group-Solo / Blockparty). PPLNS miners get `None`
                // and keep riding the pool-wide push.
                if state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                {
                    for event in &outcome.events {
                        let JdpSessionEvent::TokenAllocated { miner_address, .. } = event else {
                            continue;
                        };
                        // One implementation, shared with the §10-settlement
                        // republish above. This used to be a second copy of
                        // it, and the copy had already drifted: on a failed
                        // `next_distribution_id` it skipped the publish
                        // WITHOUT denying pool-wide, so a Solo or Group-Solo
                        // session ended up with no tailored slot and no
                        // denial — and `distribution_acceptance` then falls
                        // back to the pool-wide slot, which is the PPLNS
                        // window's. That session could declare a coinbase
                        // paying PPLNS; for Solo the booking resolves the
                        // mode from the miner's address and books nothing at
                        // all, so the PPLNS miners are paid on-chain and
                        // their ledger never hears about it.
                        if republish_tailored(
                            &hooks,
                            &bridge,
                            &mut writer,
                            session_id,
                            &session_id_hex,
                            miner_address,
                        )
                        .await
                        {
                            tailored_active = true;
                            tailored_miner = Some(miner_address.clone());
                        }
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
            // §3.1 makes `SetPayoutDistribution` the mandatory first
            // push after this exchange — only offer 0x0003 when one is
            // actually publishable right now.
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
            let Some(ctx) = hooks
                .allocate_resolver
                .resolve_allocate_context(&input.user_identifier, remote_addr, negotiated)
                .await
            else {
                // Couldn't resolve a miner address — drop silently
                // (return default outcome, no error frame).
                return JdpHandlerOutcome::default();
            };
            handle_allocate_token(state, &input, ctx, now_ms)
        }
        InboundJdpFrame::DeclareMiningJob(input) => {
            let template_txs = hooks.template_tx_provider.snapshot().await;
            // §6.1: hand the declaration to a Bitcoin node before committing
            // to it. Whatever the local template already covers is supplied,
            // so the node only reports what it is genuinely missing. Rejection
            // short-circuits: nothing is registered, so there is no state to
            // roll back.
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
            handle_declare_mining_job(
                state,
                &input,
                &template_txs,
                current_prev_hash,
                distribution,
                now_ms,
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
            // §7.2/§10 are judged when the declaration is ACCEPTED —
            // re-resolve against the pending declare's referenced id,
            // so a supersession or settlement during the round-trip is
            // seen.
            let pending_distribution_id = state
                .pending_declaration
                .as_ref()
                .and_then(|p| p.input.distribution_id);
            let distribution =
                resolve_distribution_acceptance(bridge, session_id, pending_distribution_id);
            handle_provide_missing_transactions_success(
                state,
                &input,
                current_prev_hash,
                distribution,
                now_ms,
            )
        }
        InboundJdpFrame::PushSolution(input) => {
            // The miner_address is bound to the declared job's
            // RegisteredDeclaredJob in the bridge; but the
            // push-solution handler accepts it as an argument
            // because the JDP-session itself doesn't carry the
            // address (multi-token-per-connection means different
            // pushes might map to different addresses, but in
            // practice one connection = one miner). Lookup via the
            // declared_jobs store (already has prev_hash matching).
            let miner_address = state
                .declared_jobs
                .match_for_solution(&input.prev_hash)
                .map(|j| j.new_token)
                .and_then(|token| state.tokens.lookup(&token).map(|a| a.miner_address.clone()))
                .unwrap_or_else(|| {
                    AddressId::new("unknown".to_string()).unwrap_or_else(|_| {
                        // AddressId::new requires non-empty + valid
                        // chars; "unknown" passes. Defensive fallback.
                        AddressId::new("u".to_string()).expect("'u' is a valid AddressId")
                    })
                });
            handle_push_solution(state, &input, miner_address)
        }
    }
}

/// Resolve a §6 `distribution_id` reference against the bridge's
/// acceptance window, under the declare path's session scope. `None`
/// TLV → `None` (the handler decides whether that's an error — it is,
/// on a negotiated connection).
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
    owner: Option<AddressId>,
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
        owner,
        jdp_session_id,
        published_at_ms,
    }
}

/// The §3.1 wire form of a registry entry.
fn wire_from_entry(entry: &PayoutDistributionEntry) -> SetPayoutDistribution {
    SetPayoutDistribution {
        distribution_id: entry.distribution_id,
        pool_payout: entry.pool_payout.to_wire_txout(),
        payouts: entry.payouts.iter().map(|p| p.to_wire_txout()).collect(),
        dust_limits: entry.dust_limits.clone(),
        additional_outputs: entry.additional_outputs.clone(),
    }
}

/// Fan out [`JdpSessionEvent`]s: SetupComplete and TokenAllocated are
/// informational, JobDeclared was registered in the bridge before the
/// outbound write, BlockSubmissionCandidate goes to the
/// block-submission sink, Disconnect closes the connection (caller
/// handles via the cancel-token path).
async fn fan_out_events(events: Vec<JdpSessionEvent>, hooks: &JdpServerHooks) {
    for event in events {
        match event {
            JdpSessionEvent::SetupComplete { .. } => {}
            JdpSessionEvent::TokenAllocated { .. } => {}
            // Already registered, before the outbound write — see the
            // `register_declared_jobs_in_bridge` call in
            // `run_jdp_connection`, which has the session state this
            // fan-out does not carry. Do not register here as well.
            JdpSessionEvent::JobDeclared { .. } => {}
            JdpSessionEvent::BlockSubmissionCandidate {
                miner_address,
                new_token,
                booking,
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
                        booking,
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
            JdpSessionEvent::Disconnect { .. } => {
                // Disconnect signal — connection-task break-condition.
                // The select-loop already broke once we hit this; no
                // additional action.
            }
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

/// Register the latest declared job in the bridge so the mining
/// server's `SetCustomMiningJob` handler can find it. Called from
/// the per-connection task after `dispatch_jdp_inbound` returns —
/// at that point `state.declared_jobs` has the fresh entry keyed by
/// `new_token` (the handler's accept-path inserted it).
///
/// Public-`pub(crate)` so unit tests can drive it without spinning
/// up a real connection.
pub(crate) fn register_declared_jobs_in_bridge(
    state: &JdpSessionState,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    jdp_session_id: u32,
    now_ms: u64,
    events: &[JdpSessionEvent],
) {
    let mut reg = bridge.write().expect("bridge RwLock poisoned");
    for event in events {
        if let JdpSessionEvent::JobDeclared {
            new_token,
            miner_address,
            ..
        } = event
        {
            if let Some(declared_job) = state.declared_jobs.get(new_token) {
                reg.register(
                    *new_token,
                    RegisteredDeclaredJob {
                        declared_job: declared_job.clone(),
                        miner_address: miner_address.clone(),
                        jdp_session_id,
                        registered_at_ms: now_ms,
                    },
                );
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Public re-export for the IO-layer wire-up ───────────────────────

/// Drain timeout placeholder — re-exported to match
/// `ServerConfig::shutdown_drain_timeout` semantics. Not yet wired:
/// `StratumV2JdpServer::shutdown` is fire-and-forget for now (the
/// cancel-token causes all per-connection tasks to exit on their
/// next select tick).
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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

    /// Minimal §3.1 registry entry: one weight-9 miner slot behind a
    /// weight-1 pool output.
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
            owner: None,
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

    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_parses_user_identifier_as_address() {
        let hooks = NoOpJdpHooks;
        let ctx = hooks
            .resolve_allocate_context(ADDR, "1.2.3.4:1234", false)
            .await;
        let ctx = ctx.expect("valid address resolves");
        assert_eq!(ctx.miner_address.as_str(), ADDR);
        assert_eq!(
            ctx.coinbase_outputs.as_slice(),
            &[0u8],
            "without 0x0003 the base §6.4.3 outputs apply"
        );
    }

    /// §2: with ext 0x0003 negotiated the `SetPayoutDistribution` push
    /// replaces the base output semantics — `coinbase_tx_outputs` in
    /// `AllocateMiningJobToken.Success` MUST be empty.
    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_empty_outputs_when_0x0003_negotiated() {
        let hooks = NoOpJdpHooks;
        let ctx = hooks
            .resolve_allocate_context(ADDR, "1.2.3.4:1234", true)
            .await;
        let ctx = ctx.expect("valid address resolves");
        assert_eq!(ctx.miner_address.as_str(), ADDR);
        assert!(ctx.coinbase_outputs.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_rejects_garbage_user_identifier() {
        let hooks = NoOpJdpHooks;
        let ctx = hooks
            .resolve_allocate_context(&"x".repeat(200), "1.2.3.4:1234", false)
            .await;
        assert!(ctx.is_none(), "garbage user-identifier yields None");
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
                assert_eq!(coinbase_outputs.as_slice(), &[0u8]);
            }
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    // ── §6.1 node-side validation of declared jobs ──────────────────

    /// The marker the §6.1 gate stamps on its own rejections. Lets a test tell
    /// "the node refused this" apart from the ordinary handler errors (an
    /// unallocated token, say) that have nothing to do with the gate.
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

    /// §3.1 makes `SetPayoutDistribution` the mandatory first push after
    /// the extensions exchange — so 0x0003 is only offered while a
    /// pool-wide distribution is actually publishable.
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

    /// The §3.1 wire form mirrors the registry entry: weights ride in
    /// the TxOut amount field, dust limits and additional outputs pass
    /// through unchanged.
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

    /// `register_declared_jobs_in_bridge` pulls the declared-job
    /// payload out of the session state and writes a
    /// `RegisteredDeclaredJob` into the cross-server bridge.
    #[tokio::test(flavor = "current_thread")]
    async fn register_declared_jobs_in_bridge_pushes_to_registry() {
        use crate::jdp::declarations::DeclaredJob;
        let mut state = fresh_session();
        let token = Token([0xAA; 16]);
        let job = DeclaredJob {
            new_token: token,
            original_token: Token([0xBB; 16]),
            request_id: 1,
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
        let events = vec![JdpSessionEvent::JobDeclared {
            new_token: token,
            original_token: Token([0xBB; 16]),
            miner_address: AddressId::new(ADDR.to_string()).unwrap(),
            prev_hash: Some([0xCC; 32]),
        }];
        register_declared_jobs_in_bridge(&state, &bridge, 42, 1_000, &events);
        let r = bridge.read().unwrap();
        let entry = r.lookup(&token).expect("must be registered");
        assert_eq!(entry.jdp_session_id, 42);
        assert_eq!(entry.miner_address.as_str(), ADDR);
        assert_eq!(entry.declared_job.prev_hash, Some([0xCC; 32]));
    }
}
