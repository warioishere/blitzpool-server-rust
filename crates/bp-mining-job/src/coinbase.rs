// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase transaction construction with multi-output payouts, BIP-34 block-height
//! encoding, BIP-141 witness commitment, and stateless extranonce splicing.

use bitcoin::Network;
use bp_common::PayoutIdentity;
use bp_share::sha256d_from_parts;
use tracing::warn;

use crate::address;

/// Length in bytes of the extranonce slot embedded in the scriptsig.
/// 4 bytes enonce1 + 8 bytes enonce2 — matches ckpool's
/// default `nonce2length = 8` (Braiins Hashpower spec requires ≥ 7).
pub const EXTRANONCE_SLOT_LEN: usize = 12;

const MAX_SCRIPT_SIZE: usize = 100;
const WITNESS_COMMIT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Non-final coinbase input `nSequence` required by BIP-54 (anything but
/// `0xffffffff`). Matches the value Core 31's template provider emits.
const COINBASE_NONFINAL_SEQUENCE: u32 = 0xffff_fffe;

/// A miner-payout entry for the coinbase outputs.
///
/// Carries the EXACT satoshi amount for the output — the payout distributors
/// (PPLNS / Group-Solo / Blockparty) already do the precise integer allocation
/// (largest-remainder residuum, fixed finder bonus, solvency cap), so the
/// coinbase builder must place those sats verbatim. Deriving amounts from a
/// float percentage here would re-floor each output and silently drop up to a
/// sat per output (e.g. a 50 000 000-sat finder bonus rounding to 49 999 999).
///
/// The payout target is a [`PayoutIdentity`] rather than a `String` so that
/// "which address is this" and "which script does this block pay" can be
/// different questions. They are the same answer for every identity that exists
/// today ([`PayoutIdentity::Static`]); they stop being the same answer for a
/// rotating identity, and the type is what forces each reader to say which one
/// it meant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayoutEntry {
    /// Where this output pays.
    pub identity: PayoutIdentity,
    /// Exact output amount in satoshis.
    pub sats: u64,
}

impl PayoutEntry {
    /// A literal address, taken **verbatim**, with exact sats.
    ///
    /// Verbatim and not normalized: that is what this seam did before the
    /// identity type existed, and normalizing here would be a behaviour change
    /// smuggled into a refactor. The wire paths normalize at intake, which is
    /// where the miner's bytes actually arrive.
    pub fn static_address(address: impl Into<String>, sats: u64) -> Self {
        Self {
            identity: PayoutIdentity::static_address_verbatim(address),
            sats,
        }
    }

    /// Percentage-based convenience: floor `percent`% of `reward_sats` to an
    /// exact output. For the Solo split (dev-fee / 100%-to-miner) and the
    /// percentage-oriented tests. The PPLNS / Group-Solo / Blockparty
    /// distributors bypass this — they carry exact per-output sats already.
    pub fn from_percent(address: impl Into<String>, percent: f64, reward_sats: u64) -> Self {
        Self::static_address(
            address,
            ((percent / 100.0) * reward_sats as f64).floor() as u64,
        )
    }

    /// The ledger key / mode key for this entry — **height-invariant**.
    ///
    /// NOT the payout script. For a `Static` entry the two coincide, which is
    /// why one `String` sufficed; for a rotating one they do not, and reading
    /// this where a script was meant is the mistake [`PayoutIdentity`] exists to
    /// make unwriteable. Scripts come from `payout_script` only.
    pub fn payout_id(&self) -> &str {
        self.identity.payout_id()
    }
}

/// A resolved payout list plus the identity of the distribution it was
/// derived from — what a `PayoutResolver` hands the job build.
///
/// Under the weight model the fingerprint is a property of the
/// DISTRIBUTION (settlement inputs), not of the concrete satoshi list:
/// the same distribution yields different sats at different template
/// revenues, and they all settle through one snapshot. It therefore
/// travels WITH the entries instead of being derived from them.
/// A zeroed fingerprint means "books without a snapshot" (Solo /
/// Blockparty, which settle by their own recompute paths).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPayouts {
    pub entries: Vec<PayoutEntry>,
    pub payouts_fingerprint: [u8; 32],
}

impl ResolvedPayouts {
    /// A list that books without a settlement snapshot (zeroed
    /// fingerprint): Solo and Blockparty, plus every fallback path.
    pub fn unsnapshotted(entries: Vec<PayoutEntry>) -> Self {
        Self {
            entries,
            payouts_fingerprint: [0u8; 32],
        }
    }

    /// **No payout list at all — serve no job.**
    ///
    /// The answer for a mode whose distribution could not be built. The
    /// alternative a resolver reaches for is a solo list, and for PPLNS or
    /// Group-Solo that is not a degraded answer but a wrong one: it pays
    /// the whole block to whichever miner happened to connect, so a
    /// transient Postgres or Redis fault would cost every OTHER miner the
    /// block. Withholding the job costs the one miner some hashing time
    /// and nobody else anything.
    ///
    /// Both protocols already read an empty list this way: SV1's
    /// `build_notify_for_template` sends no `mining.notify`, SV2's
    /// `resolve_template_mining_job_inputs` yields no job inputs. The
    /// miner keeps hashing whatever job it holds.
    pub fn none() -> Self {
        Self::unsnapshotted(Vec::new())
    }

    /// Is this "serve no job"?
    pub fn is_none(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The block-template fields needed for coinbase construction.
#[derive(Clone, Debug)]
pub struct CoinbaseTemplate {
    pub block_height: u32,
    pub coinbase_value_sats: u64,
    /// 32-byte witness commitment hash, already double-SHA256'd by the
    /// template provider (TDP `NewTemplate.witness_commitment` or RPC
    /// `getblocktemplate.default_witness_commitment`).
    pub witness_commitment: [u8; 32],
}

/// A coinbase transaction split into its non-witness bytes before and
/// after the extranonce slot. Per-share submission splices the
/// miner-supplied extranonce in to compute the coinbase txid without
/// re-building or mutating shared state.
///
/// `MiningJob` is immutable after construction — `&MiningJob` is `Send + Sync`.
#[derive(Clone, Debug)]
pub struct MiningJob {
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    /// Lowercase-hex of `coinbase_prefix`/`coinbase_suffix`, precomputed at
    /// build time. The `MiningJob` is shared (one per template for PPLNS), so
    /// the SV1 `mining.notify` broadcast borrows these instead of re-hex-
    /// encoding the coinbase for every per-client build.
    coinbase_prefix_hex: String,
    coinbase_suffix_hex: String,
    /// Identity of the payout list this coinbase pays — see
    /// `payouts_fingerprint`. Carried on the job so a block found on it
    /// can look up the exact distribution the pool must book, instead of
    /// whatever the shared snapshot key holds by then. 32 inline bytes, no
    /// allocation, computed once per job build.
    payouts_fingerprint: [u8; 32],
}

impl MiningJob {
    pub fn coinbase_prefix(&self) -> &[u8] {
        &self.coinbase_prefix
    }

    pub fn coinbase_suffix(&self) -> &[u8] {
        &self.coinbase_suffix
    }

    /// Identity of the payout list this job's coinbase pays.
    pub fn payouts_fingerprint(&self) -> &[u8; 32] {
        &self.payouts_fingerprint
    }

    /// Precomputed lowercase-hex of the coinbase prefix — the `coinb1` slot of
    /// a `mining.notify`.
    pub fn coinbase_prefix_hex(&self) -> &str {
        &self.coinbase_prefix_hex
    }

    /// Precomputed lowercase-hex of the coinbase suffix — the `coinb2` slot of
    /// a `mining.notify`.
    pub fn coinbase_suffix_hex(&self) -> &str {
        &self.coinbase_suffix_hex
    }

    /// Splice the 4-byte extranonce1 and 8-byte extranonce2 into the
    /// scriptsig and return the resulting coinbase txid (sha256d of the
    /// non-witness serialization).
    pub fn coinbase_txid_with_extranonce(&self, enonce1: &[u8; 4], enonce2: &[u8; 8]) -> [u8; 32] {
        // Stream prefix + extranonce + suffix straight into the hasher — no
        // per-share `Vec` (SHA-256 is a streaming hash, so this yields the exact
        // same txid as hashing the concatenation).
        sha256d_from_parts(&[
            self.coinbase_prefix.as_slice(),
            enonce1.as_slice(),
            enonce2.as_slice(),
            self.coinbase_suffix.as_slice(),
        ])
    }

    /// Splice the extranonce in and return the **witness-form** coinbase
    /// bytes for block submission (BIP-141 layout: marker `0x00` + flag
    /// `0x01` inserted after version, 32-zero witness reserved value
    /// inserted before locktime).
    ///
    /// Used by the block-found path (TDP `SubmitSolution`); the
    /// share-validation hot path stays on `coinbase_txid_with_extranonce`
    /// which only needs the non-witness form.
    pub fn witness_coinbase_with_extranonce(
        &self,
        enonce1: &[u8; 4],
        enonce2: &[u8; 8],
    ) -> Vec<u8> {
        // Non-witness layout (what we have stored, split around the slot):
        //   prefix = [version:4][input_count:1][prev_txid:32][prev_vout:4]
        //            [scriptsig_len:varint][scriptsig: prefix_part]
        //   slot    = [enonce1:4][enonce2:8]
        //   suffix = [scriptsig: suffix_part][sequence:4][output_count:varint]
        //            [outputs...][locktime:4]
        //
        // Witness layout differs only at two points:
        //   - bytes 4..4: insert [marker=0x00][flag=0x01] (right after version)
        //   - before the trailing locktime: insert
        //     [witness_count=0x01][witness_len=0x20][32 zero bytes]
        let prefix = &self.coinbase_prefix;
        let suffix = &self.coinbase_suffix;
        let locktime_at = suffix.len() - 4;

        let total = prefix.len() + 2 + EXTRANONCE_SLOT_LEN + locktime_at + 1 + 1 + 32 + 4;
        let mut buf = Vec::with_capacity(total);
        // version
        buf.extend_from_slice(&prefix[..4]);
        // BIP-141 marker + flag
        buf.push(0x00);
        buf.push(0x01);
        // rest of the non-witness prefix (input_count onwards)
        buf.extend_from_slice(&prefix[4..]);
        // extranonce slot
        buf.extend_from_slice(enonce1);
        buf.extend_from_slice(enonce2);
        // non-witness suffix up to (not including) locktime
        buf.extend_from_slice(&suffix[..locktime_at]);
        // witness stack: 1 item of 32 bytes (the coinbase's mandatory reserved value)
        buf.push(0x01);
        buf.push(0x20);
        buf.extend_from_slice(&[0u8; 32]);
        // locktime
        buf.extend_from_slice(&suffix[locktime_at..]);
        buf
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MiningJobError {
    #[error("scriptsig would exceed 100-byte consensus limit ({0} bytes)")]
    ScriptSigTooLong(usize),
    #[error("invalid payout address: {0}")]
    InvalidAddress(#[from] address::AddressError),
    #[error("at least one payout entry is required")]
    NoPayouts,
    /// A rotating identity needs the block height to derive its script, and the
    /// template's `coinbase_prefix` carried no decodable BIP-34 push.
    ///
    /// **Reachable as of Phase 3.** It exists so the failure is a refused job
    /// rather than a coinbase built at a fabricated height, which would pay a
    /// script the miner cannot spend. `ResolvedPayouts::none()` documents the
    /// same choice for a distribution that could not be built: serve no job
    /// rather than guess.
    #[error("template carried no decodable BIP-34 height and a payout identity needs one")]
    MissingBlockHeight,
    /// A rotating identity's descriptor would not derive at this height.
    ///
    /// Should be unreachable: `bp_payout_descriptor`'s intake asserts
    /// derivability at construction and `RotatingPayout` has no other
    /// constructor, so every rotating identity that exists derives at every
    /// height. Kept as a refused job rather than an `expect`, because the
    /// alternative on this path is a panic **inside coinbase assembly** — which
    /// is the exact failure the hardened-step assertion exists to prevent, and
    /// re-introducing it here would undo that at the last step.
    ///
    /// Carries no detail on purpose: the parser's text can contain key material
    /// (see `bp_payout_descriptor`'s credential rule), and this error is
    /// formatted into logs.
    #[error("a rotating payout identity failed to derive its script at this height")]
    RotationFailed,
}

/// Build a `MiningJob` for the given template + payouts.
///
/// Scriptsig layout: BIP-34 height push, pool identifier (dropped if it
/// would exceed the 100-byte consensus limit), `extranonce_slot_size`
/// bytes for the extranonce slot (zeroed at build time, spliced per
/// share).
///
/// `extranonce_slot_size` is the total channel-negotiated extranonce
/// width baked into the scriptsig. SV1 callers pass
/// [`EXTRANONCE_SLOT_LEN`] (the pool default of 4-byte enonce1 +
/// 8-byte enonce2 = 12); SV2 Extended callers pass
/// `channel.extranonce_prefix.len() + channel.extranonce_size` so the
/// scriptsig_len varint matches the wire bytes exactly.
///
/// Each `PayoutEntry` carries its exact sats, placed verbatim. Any shortfall
/// vs `coinbase_value_sats` (normally zero — the distributor sums to the
/// reward) is swept onto `outs[0]` so the coinbase consumes it exactly.
///
/// The coinbase is built BIP-54-compliant: `nLockTime = block_height - 1`
/// and a non-final `nSequence` (`0xfffffffe`). The TDP path
/// ([`build_mining_job_from_tdp`]) instead passes through Core's
/// `NewTemplate` values, which a BIP-54-aware node already sets compliantly.
///
/// `payouts_fingerprint` identifies the DISTRIBUTION this coinbase was
/// built from, so a block found on it can be settled against the right
/// snapshot. It is passed in rather than derived: the same distribution
/// legitimately yields different satoshi vectors at different template
/// revenues, so nothing about the concrete payout list identifies it.
/// `[0u8; 32]` means "no settlement behind this job" — what a caller
/// that only wants the coinbase bytes (a preview) passes.
pub fn build_mining_job(
    network: Network,
    payouts: &[PayoutEntry],
    template: &CoinbaseTemplate,
    pool_identifier: &str,
    extranonce_slot_size: usize,
    payouts_fingerprint: [u8; 32],
) -> Result<MiningJob, MiningJobError> {
    if payouts.is_empty() {
        return Err(MiningJobError::NoPayouts);
    }

    let height_encoded = encode_block_height_minimal(template.block_height);
    let height_len = height_encoded.len();
    let padding_len = extranonce_slot_size + 3usize.saturating_sub(height_len);
    let padding = vec![0u8; padding_len];

    // Try with identifier first; drop it if the resulting scriptsig would
    // exceed the consensus limit.
    let identifier_bytes = pool_identifier.as_bytes();
    let mut script_sig = build_scriptsig(&height_encoded, identifier_bytes, &padding);
    if script_sig.len() > MAX_SCRIPT_SIZE {
        script_sig = build_scriptsig(&height_encoded, &[], &padding);
    }
    if script_sig.len() > MAX_SCRIPT_SIZE {
        return Err(MiningJobError::ScriptSigTooLong(script_sig.len()));
    }

    let outputs = build_outputs(
        network,
        payouts,
        template.coinbase_value_sats,
        &template.witness_commitment,
        template.block_height,
    )?;

    // BIP-54: nLockTime = block_height - 1, non-final nSequence. Serialize the
    // prefix (up to the extranonce slot) and suffix (from nSequence on)
    // DIRECTLY into their own buffers — the slot bytes between them are never
    // materialized (spliced per-share), so there is no full-coinbase buffer to
    // build and slice. Version 2 is the RPC-path coinbase version.
    let locktime = template.block_height.saturating_sub(1);
    let coinbase_prefix = serialize_coinbase_prefix(2, &script_sig, extranonce_slot_size);
    let coinbase_suffix = serialize_coinbase_suffix(
        COINBASE_NONFINAL_SEQUENCE,
        outputs.len() as u64,
        &outputs,
        &[], // RPC path: no template-provided raw outputs (witness commit is in `outputs`)
        locktime,
    );
    let coinbase_prefix_hex = hex::encode(&coinbase_prefix);
    let coinbase_suffix_hex = hex::encode(&coinbase_suffix);

    Ok(MiningJob {
        coinbase_prefix,
        coinbase_suffix,
        coinbase_prefix_hex,
        coinbase_suffix_hex,
        payouts_fingerprint,
    })
}

/// TDP-side template fields needed for coinbase assembly.
///
/// Mirrors the relevant `template_distribution_sv2::NewTemplate` fields:
/// the BIP-34-prepared scriptsig prefix, the input sequence, the value
/// remaining after bitcoin-core's required outputs, the pre-serialized
/// required outputs blob (typically just the witness-commitment
/// OP_RETURN — bitcoin-core has already done the SegWit work for us),
/// and the locktime / version. All fields come straight from
/// `NewTemplate`, no transformation needed.
#[derive(Clone, Debug)]
pub struct TdpCoinbaseTemplate<'a> {
    /// `NewTemplate.coinbase_prefix` — BIP-34 height push + any pool-side
    /// data bitcoin-core was configured to inject. We append our own pool
    /// identifier + the 12-byte extranonce slot after this.
    pub coinbase_prefix: &'a [u8],
    /// `NewTemplate.coinbase_tx_version` — typically 2.
    pub coinbase_tx_version: u32,
    /// `NewTemplate.coinbase_tx_input_sequence` — typically 0xFFFFFFFF or
    /// 0xFFFFFFFE.
    pub coinbase_tx_input_sequence: u32,
    /// `NewTemplate.coinbase_tx_value_remaining` — subsidy + fees minus
    /// the value already allocated to bitcoin-core's required outputs.
    /// This is what gets split across our payout entries.
    pub coinbase_tx_value_remaining: u64,
    /// `NewTemplate.coinbase_tx_outputs` — raw concatenated TxOut bytes
    /// (each output = 8-byte LE value + scriptlen varint + script).
    /// **NOT** prefixed with an output-count varint; the count lives in
    /// `coinbase_tx_outputs_count` separately.
    pub coinbase_tx_outputs: &'a [u8],
    /// `NewTemplate.coinbase_tx_outputs_count` — number of TxOuts encoded
    /// in `coinbase_tx_outputs`. Combined with our payout count to form
    /// the final coinbase's output-count varint.
    pub coinbase_tx_outputs_count: u32,
    /// `NewTemplate.coinbase_tx_locktime` — typically 0.
    pub coinbase_tx_locktime: u32,
}

impl TdpCoinbaseTemplate<'_> {
    /// The block height this template builds on, decoded from
    /// `coinbase_prefix`.
    ///
    /// **There is no height field, on this struct or on any production
    /// template**, and adding one would be the wrong fix. Checked at `f070414`:
    /// neither `NewTemplate` (`bp-template-distribution`), `ActiveSV1Template`
    /// (`bp-stratum-v1/src/notify.rs`), nor `ActiveSV2Template` carries a height
    /// — only the RPC-path [`CoinbaseTemplate`] does. Threading one down from
    /// Core would mean widening an IPC message and three template structs to
    /// carry a value that is *already in the bytes*.
    ///
    /// Core pre-encodes the BIP-34 height push at the start of
    /// `coinbase_prefix` — it must, for the block to be valid — so the height is
    /// recoverable locally with [`crate::decode_bip34_height`], which already
    /// exists and is already exercised against a real Core template
    /// (`tests/regtest_bip54.rs`). No IPC or RPC change, and no new field that
    /// could disagree with the bytes actually being mined.
    ///
    /// `None` when the prefix does not begin with a 1..=4-byte push: hand-built
    /// test templates with an empty or synthetic prefix. A `Static` payout does
    /// not care, which is why this returns `Option` instead of erroring — a
    /// missing height must not fail a job that never needed one. A rotating
    /// payout does care, and the caller
    /// ([`build_mining_job_from_tdp`]) is where that becomes an error.
    pub fn block_height(&self) -> Option<u32> {
        crate::bip54::decode_bip34_height(self.coinbase_prefix)
    }
}

/// Build a `MiningJob` from a TDP `NewTemplate`'s coinbase fields plus
/// the pool's per-job payout split.
///
/// Differences from [`build_mining_job`]:
///
/// - Scriptsig prefix is taken from `template.coinbase_prefix` (bitcoin-core
///   has already encoded BIP-34 height + any other configured data) — we
///   only append the pool identifier (if it fits) and the 12-byte
///   extranonce slot.
/// - Required outputs come from `template.coinbase_tx_outputs` verbatim
///   (typically the witness-commitment OP_RETURN). We prepend our payout
///   outputs in front, so the final output order is:
///   `[payout_0, payout_1, …, payout_N-1, tdp_outputs…]`.
/// - `version`, `input_sequence`, and `locktime` are taken from the
///   template fields rather than hard-coded.
///
/// The returned `MiningJob` carries the same `coinbase_prefix` /
/// `coinbase_suffix` split shape as `build_mining_job`, so the per-share
/// hot path (`coinbase_txid_with_extranonce`) and the block-found path
/// (`witness_coinbase_with_extranonce`) work identically.
pub fn build_mining_job_from_tdp(
    network: Network,
    payouts: &[PayoutEntry],
    template: &TdpCoinbaseTemplate<'_>,
    pool_identifier: &str,
    extranonce_slot_size: usize,
    payouts_fingerprint: [u8; 32],
) -> Result<MiningJob, MiningJobError> {
    if payouts.is_empty() {
        return Err(MiningJobError::NoPayouts);
    }

    // Height first, and before the scriptsig check — not for its own sake but
    // because [`crate::cache::MiningJobCache`] has no choice: the height is part
    // of the outputs cache key, which it consults before it ever runs the
    // scriptsig check inside the build closure. The cache's contract is "same
    // errors in the same precedence" as this function, so the order is settled
    // there and copied here. Unobservable today (`MissingBlockHeight` is
    // unreachable while no identity rotates); the point is that it stays
    // unobservable when one does.
    let block_height = payout_height(template, payouts)?;

    // Scriptsig SECOND, outputs third — keeps the error precedence
    // (NoPayouts → ScriptSigTooLong → InvalidAddress) identical to the
    // pre-split function so callers matching/logging the variant see
    // the same failure cause for the same inputs.
    let script_sig = checked_tdp_scriptsig(
        template.coinbase_prefix,
        pool_identifier,
        extranonce_slot_size,
    )?;

    let payout_outputs = build_payout_outputs(
        network,
        payouts,
        template.coinbase_tx_value_remaining,
        block_height,
    )?;

    Ok(assemble_tdp_job(
        script_sig,
        &payout_outputs,
        template,
        extranonce_slot_size,
        payouts_fingerprint,
    ))
}

/// Build the TDP scriptsig (template prefix + pool identifier +
/// extranonce slot), dropping the identifier if the result would exceed
/// the 100-byte consensus limit — mirrors `build_mining_job`'s "drop on
/// overflow" behavior. Split out so [`crate::cache::MiningJobCache`]
/// runs the same check in the same order as
/// [`build_mining_job_from_tdp`].
pub(crate) fn checked_tdp_scriptsig(
    tdp_prefix: &[u8],
    pool_identifier: &str,
    extranonce_slot_size: usize,
) -> Result<Vec<u8>, MiningJobError> {
    let mut script_sig =
        build_tdp_scriptsig(tdp_prefix, pool_identifier.as_bytes(), extranonce_slot_size);
    if script_sig.len() > MAX_SCRIPT_SIZE {
        script_sig = build_tdp_scriptsig(tdp_prefix, &[], extranonce_slot_size);
    }
    if script_sig.len() > MAX_SCRIPT_SIZE {
        return Err(MiningJobError::ScriptSigTooLong(script_sig.len()));
    }
    Ok(script_sig)
}

/// Assemble a `MiningJob` from an ALREADY-CHECKED scriptsig and
/// ALREADY-BUILT payout outputs — the two fallible steps
/// ([`checked_tdp_scriptsig`], [`build_payout_outputs`]) factored out
/// so [`crate::cache::MiningJobCache`] can reuse parsed outputs across
/// builds that differ only in slot size / template coinbase fields.
/// Serialization itself cannot fail.
pub(crate) fn assemble_tdp_job(
    script_sig: Vec<u8>,
    payout_outputs: &[(u64, Vec<u8>)],
    template: &TdpCoinbaseTemplate<'_>,
    extranonce_slot_size: usize,
    // Taken as a parameter rather than derived here: `payout_outputs` is
    // already reduced to (sats, script), and the fingerprint is defined over
    // the addresses. Callers hold the `PayoutEntry` slice and pass it in.
    payouts_fingerprint: [u8; 32],
) -> MiningJob {
    let total_output_count =
        payout_outputs.len() as u64 + u64::from(template.coinbase_tx_outputs_count);

    // Serialize prefix (up to the extranonce slot) and suffix (from nSequence
    // on) DIRECTLY — the slot bytes in between are never materialized (spliced
    // per-share), so there is no full-coinbase buffer to build and slice.
    let coinbase_prefix = serialize_coinbase_prefix(
        template.coinbase_tx_version,
        &script_sig,
        extranonce_slot_size,
    );
    let coinbase_suffix = serialize_coinbase_suffix(
        template.coinbase_tx_input_sequence,
        total_output_count,
        payout_outputs,
        template.coinbase_tx_outputs,
        template.coinbase_tx_locktime,
    );
    let coinbase_prefix_hex = hex::encode(&coinbase_prefix);
    let coinbase_suffix_hex = hex::encode(&coinbase_suffix);

    MiningJob {
        coinbase_prefix,
        coinbase_suffix,
        coinbase_prefix_hex,
        coinbase_suffix_hex,
        payouts_fingerprint,
    }
}

fn build_tdp_scriptsig(tdp_prefix: &[u8], identifier: &[u8], slot_len: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(tdp_prefix.len() + identifier.len() + slot_len);
    s.extend_from_slice(tdp_prefix);
    s.extend_from_slice(identifier);
    s.extend(std::iter::repeat_n(0u8, slot_len));
    s
}

/// Serialize the coinbase **prefix**: everything up to (but not including) the
/// extranonce slot — version, input count, null prev-outpoint, the scriptsig
/// length varint, and the scriptsig bytes *before* the slot.
///
/// The scriptsig length varint encodes the **full** scriptsig length (the real
/// coinbase carries the extranonce inside the scriptsig); only the trailing
/// `slot_len` scriptsig bytes are omitted here — the per-share hot path splices
/// the extranonce into exactly that gap. Building the prefix directly (rather
/// than serializing the whole coinbase and slicing) avoids one full-buffer
/// allocation + copy per job and never materializes the discarded slot bytes.
fn serialize_coinbase_prefix(version: u32, scriptsig: &[u8], slot_len: usize) -> Vec<u8> {
    let head = scriptsig.len() - slot_len;
    let mut buf = Vec::with_capacity(4 + 1 + 32 + 4 + 9 + head);
    // version (LE u32 — consensus-equivalent to i32 for positive values)
    buf.extend_from_slice(&version.to_le_bytes());
    // input count = 1
    buf.push(0x01);
    // prev txid (32 zeros) + prev vout = 0xFFFFFFFF
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // scriptsig length (FULL length, incl. the slot) + scriptsig up to the slot
    encode_varint(&mut buf, scriptsig.len() as u64);
    buf.extend_from_slice(&scriptsig[..head]);
    buf
}

/// Serialize the coinbase **suffix**: everything from nSequence on — input
/// sequence, output-count varint, our payout outputs, any template-provided raw
/// outputs (TDP path; empty on the RPC path), and locktime. Counterpart to
/// [`serialize_coinbase_prefix`]; together they replace the old
/// build-full-then-slice path.
fn serialize_coinbase_suffix(
    input_sequence: u32,
    total_output_count: u64,
    payout_outputs: &[(u64, Vec<u8>)],
    raw_extra_outputs: &[u8],
    locktime: u32,
) -> Vec<u8> {
    let payout_size: usize = payout_outputs.iter().map(|(_, s)| 8 + 9 + s.len()).sum();
    let cap = 4 + 9 + payout_size + raw_extra_outputs.len() + 4;
    let mut buf = Vec::with_capacity(cap);
    // input sequence
    buf.extend_from_slice(&input_sequence.to_le_bytes());
    // total output count (payouts + any template-provided outputs)
    encode_varint(&mut buf, total_output_count);
    // our payout outputs first
    for (value, script) in payout_outputs {
        buf.extend_from_slice(&value.to_le_bytes());
        encode_varint(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
    }
    // template-provided outputs (already in raw TxOut wire form; empty on RPC)
    buf.extend_from_slice(raw_extra_outputs);
    // locktime
    buf.extend_from_slice(&locktime.to_le_bytes());
    buf
}

fn build_scriptsig(height_encoded: &[u8], identifier: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(1 + height_encoded.len() + identifier.len() + padding.len());
    // BIP-34 push opcode = length of the encoded height (1..=4 typically).
    s.push(height_encoded.len() as u8);
    s.extend_from_slice(height_encoded);
    s.extend_from_slice(identifier);
    s.extend_from_slice(padding);
    s
}

/// The `scriptPubKey` this entry is paid at `block_height`.
///
/// **The one place an identity becomes coinbase bytes.** Every other
/// `address_to_script` call in the repo is a test, an authorize-time validation
/// probe, or a weight estimate.
///
/// `block_height` is what makes rotation expressible: a rotating identity's
/// script is a function of it, a static one's is not. The `Static` arm ignores
/// it, and the type says so rather than a comment hoping for it.
pub(crate) fn payout_script(
    network: Network,
    identity: &PayoutIdentity,
    block_height: u32,
) -> Result<Vec<u8>, MiningJobError> {
    match identity {
        // Verbatim today's behaviour: `address_to_script` on the literal string,
        // height unused.
        PayoutIdentity::Static { address } => {
            let _ = block_height;
            Ok(address::address_to_script(network, address)?.into_bytes())
        }
        // Derived at THIS block's height. `network` is unused: a descriptor
        // carries its own key material and derives a `scriptPubKey` directly,
        // and a script is network-agnostic — the network only ever mattered for
        // *rendering* an address, which is what the `Static` arm parses. That is
        // also the property that makes the regtest gate meaningful: the same
        // descriptor at the same height gives the same script on regtest as on
        // mainnet, so `bitcoin-cli deriveaddresses` is an independent check and
        // not a second copy of this code.
        //
        // The error path is real but should be unreachable: intake's
        // `assert_derivable` ran before this identity could exist. Failing the
        // build is the only safe answer — a coinbase that cannot derive one
        // miner's script must not be published paying somebody else.
        PayoutIdentity::Rotating { descriptor, .. } => {
            let _ = network;
            descriptor
                .script_at(block_height)
                .map_err(|_| MiningJobError::RotationFailed)
        }
    }
}

/// **Can a coinbase pay this identity at all?**
///
/// The same question [`payout_script`] answers by succeeding, asked where there
/// is no height yet: the distribution build, which decides *whose* rows survive
/// into a snapshot that is height-invariant by construction (Decision 8).
///
/// It lives here, three lines from the renderer, because the only failure mode
/// this predicate has is disagreeing with it — and a disagreement is not a
/// cosmetic drift:
///
/// - says yes, renderer says no ⇒ `build_payout_outputs` fails the whole
///   coinbase, and `MiningJobCache::get_or_build(…).ok()?` in the SV1 client
///   turns that into **no `mining.notify` for every connection sharing this
///   payout set** — all of PPLNS, silently.
/// - says no, renderer would have said yes ⇒ a miner's row is dropped from the
///   distribution before the score total is taken, so the other miners are paid
///   its share. Under PPLNS the dropped miner keeps its ledger balance and the
///   pool then owes more than the block paid; under Group-Solo there is no
///   ledger and the loss is permanent.
///
/// `a_payable_identity_is_exactly_one_the_renderer_can_render` pins the two
/// together.
///
/// # Why it takes the network and `is_valid_payout_address` does not
///
/// `bp_pplns::is_valid_payout_address` is `Address::from_str(…).is_ok()` —
/// network-agnostic, and its doc says so, on the grounds that a wrong-network
/// address cannot arrive from the share path. This is the predicate *paired with
/// the renderer*, and the renderer is `address_to_script(network, …)`, so it has
/// to ask the same thing the renderer asks or the pin test above is vacuous.
/// The two therefore differ for exactly one input class — a well-formed address
/// on another network — and this one is the stricter: it drops that row rather
/// than letting it abort a block.
pub fn is_payable_identity(network: Network, identity: &PayoutIdentity) -> bool {
    match identity {
        // The renderer's own call, so "payable" cannot mean something else here.
        PayoutIdentity::Static { address } => address::address_to_script(network, address).is_ok(),
        // Payability was settled at intake: `bp_payout_descriptor` derives the
        // descriptor once (`assert_derivable`) before a `RotatingPayout` can
        // exist, and the wildcard index space it derives over is every height a
        // block can have. There is no height here to ask about, and inventing one
        // would make this predicate answer for a block other than the one being
        // built.
        PayoutIdentity::Rotating { .. } => true,
    }
}

/// The height [`payout_script`] must derive at, for a TDP template.
///
/// **The one implementation of this rule**, called by
/// [`build_mining_job_from_tdp`] and by [`crate::cache::MiningJobCache`]. Two
/// copies would be two answers to "which height was this output set derived
/// at?", and the cache keys its parsed outputs on that answer — a disagreement
/// is a coinbase paying scripts derived for another block, which is precisely
/// the class of bug `CLAUDE.md` opens with.
///
/// The height comes from Core's pre-encoded BIP-34 push (see
/// [`TdpCoinbaseTemplate::block_height`]). A prefix without a decodable push
/// means a hand-built test template; every identity that exists today is
/// `Static` and ignores the height, so `0` is a faithful stand-in rather than a
/// guess that could pay the wrong script. The moment an identity's script
/// depends on the height, `payout_script` must not be reachable with a
/// fabricated one — which is what [`MiningJobError::MissingBlockHeight`] is for.
///
/// The guard is `!rotates()` over every entry rather than a `match` because the
/// question is a property of the whole slice, not of one identity: `all` over a
/// per-variant `match` is the exhaustive form of it. `rotates()` is itself a
/// `match`, so adding a variant forces a decision there.
pub(crate) fn payout_height(
    template: &TdpCoinbaseTemplate<'_>,
    payouts: &[PayoutEntry],
) -> Result<u32, MiningJobError> {
    match template.block_height() {
        Some(h) => Ok(h),
        None if payouts.iter().all(|p| !p.identity.rotates()) => Ok(0),
        None => Err(MiningJobError::MissingBlockHeight),
    }
}

/// Build the payout outputs for a coinbase at `block_height`.
///
/// `block_height` is threaded in for [`payout_script`] — see there for why. It
/// is NOT used for the BIP-34 scriptsig push, which the two builders handle
/// separately (the RPC path encodes it from `CoinbaseTemplate::block_height`,
/// the TDP path takes Core's pre-encoded `coinbase_prefix` verbatim).
pub(crate) fn build_payout_outputs(
    network: Network,
    payouts: &[PayoutEntry],
    reward_sats: u64,
    block_height: u32,
) -> Result<Vec<(u64, Vec<u8>)>, MiningJobError> {
    let mut outputs: Vec<(u64, Vec<u8>)> = Vec::with_capacity(payouts.len());
    let mut total_paid: u64 = 0;

    for p in payouts {
        // Place the exact sats the distributor computed. No percent re-derivation
        // — the distribution already summed to `reward_sats` precisely.
        let amount = p.sats;
        total_paid = total_paid.saturating_add(amount);
        let script = payout_script(network, &p.identity, block_height)?;
        outputs.push((amount, script));
    }

    // Reconcile to consume EXACTLY `reward_sats` so the coinbase can never be
    // rejected as bad-cb-amount. The distributors already sum to the reward, so
    // this is normally a no-op — it's a defensive guard, not the primary path.
    match total_paid.cmp(&reward_sats) {
        // Undershoot (an edge-case forfeited residuum): sweep the shortfall onto
        // the first output so the full reward is claimed.
        std::cmp::Ordering::Less => {
            outputs[0].0 = outputs[0].0.saturating_add(reward_sats - total_paid);
        }
        // Overshoot must never happen — the PPLNS solvency cap / group-solo /
        // blockparty allocators bound the sum at the reward. If a distributor bug
        // ever breaches that, a verbatim over-value coinbase would forfeit a real
        // found block; trimming the excess off the trailing outputs keeps the
        // block valid (strictly better than a lost block). `debug_assert` makes
        // the invariant loud in tests.
        std::cmp::Ordering::Greater => {
            debug_assert!(
                false,
                "coinbase payout overshoot: total_paid {total_paid} > reward {reward_sats}"
            );
            let mut excess = total_paid - reward_sats;
            for out in outputs.iter_mut().rev() {
                if excess == 0 {
                    break;
                }
                let cut = out.0.min(excess);
                out.0 -= cut;
                excess -= cut;
            }
        }
        std::cmp::Ordering::Equal => {}
    }

    Ok(outputs)
}

fn build_outputs(
    network: Network,
    payouts: &[PayoutEntry],
    reward_sats: u64,
    witness_commitment: &[u8; 32],
    block_height: u32,
) -> Result<Vec<(u64, Vec<u8>)>, MiningJobError> {
    let mut outputs = build_payout_outputs(network, payouts, reward_sats, block_height)?;

    // Witness commitment OP_RETURN: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed || commit
    let mut commit_data = [0u8; 36];
    commit_data[..4].copy_from_slice(&WITNESS_COMMIT_MAGIC);
    commit_data[4..].copy_from_slice(witness_commitment);
    let mut commit_script = Vec::with_capacity(38);
    commit_script.push(0x6a); // OP_RETURN
    commit_script.push(0x24); // OP_PUSHBYTES_36
    commit_script.extend_from_slice(&commit_data);
    outputs.push((0, commit_script));

    Ok(outputs)
}

/// BIP-34 minimal CScriptNum encoding of a positive block height.
/// Strips trailing zero bytes (high-order in LE) and appends a 0x00 sign
/// disambiguator if the most-significant byte's high bit would otherwise
/// indicate a negative number.
fn encode_block_height_minimal(height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![];
    }
    let mut bytes = height.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if let Some(&last) = bytes.last() {
        if last & 0x80 != 0 {
            bytes.push(0x00);
        }
    }
    bytes
}

fn encode_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// `bp_stratum_v1::client::solo_payouts`'s inputs).
#[derive(Clone, Debug)]
pub struct SoloFeeConfig {
    /// Bitcoin address that receives the dev fee on solo payouts.
    /// `None` disables dev fee — full reward to miner.
    pub dev_fee_address: Option<String>,
    /// Dev fee in `[0.0, 100.0]`. Ignored when `dev_fee_address` is `None`.
    pub dev_fee_percent: f64,
}

impl Default for SoloFeeConfig {
    fn default() -> Self {
        Self {
            dev_fee_address: None,
            dev_fee_percent: 0.0,
        }
    }
}

/// Solo-mode coinbase split — the ONE implementation.
///
/// It lives here because two callers need the same answer and used to
/// disagree: the payout resolver that builds the real coinbase, and the
/// `/api/client/:address/block-template` preview, which had its own copy
/// reading the PPLNS fee config and so showed a solo miner a fee output
/// its actual `mining.notify` never carried. A preview that does not
/// call the same code is a second rule, and it will drift again.
///
/// The rule:
/// 100%-to-miner, or `dev_fee_percent` to dev + remainder to miner. Amounts are
/// exact sats — the dev fee floors, the miner takes the remainder so both
/// outputs sum to exactly `reward_sats`.
///
/// # Why the miner is a [`PayoutIdentity`] and the dev fee is not
///
/// The miner's target is whatever it presented on the wire, which may rotate.
/// The dev-fee address is **the pool's own**, read from operator config, and it
/// is `Static` here by construction rather than by convention.
///
/// That is deliberate and it is the thing to preserve. The plan is explicit:
/// *"The `match` must not accidentally make the pool-fee address rotatable."*
/// Taking one identity and one `&str` is how this function cannot do that — not
/// a rule a reader has to check, but the only shape the signature allows. The
/// same applies to the sibling pool-side route,
/// `blockparty_pending_fee_route`, which builds a `Static` entry from a
/// `fee_address` for the same reason.
///
/// It also means the caller has to have resolved an identity, which is what
/// keeps a `payout_id` from being passed off as an address: hand this the string
/// and the compiler asks which one you meant.
pub fn solo_payouts(
    miner: &PayoutIdentity,
    fee: &SoloFeeConfig,
    reward_sats: u64,
) -> Vec<PayoutEntry> {
    let dev_addr = fee
        .dev_fee_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let percent = fee.dev_fee_percent;
    let full_to_miner = || {
        vec![PayoutEntry {
            identity: miner.clone(),
            sats: reward_sats,
        }]
    };
    // The empty-identity case is `payout_id().is_empty()` and not a `match` on
    // the variant: it asks "did the caller hand us nothing", which is a property
    // of the ledger key both variants have. A rotating identity's `payout_id` is
    // a 47-char hash and can never be empty, so this is the static case as it
    // always was.
    match (miner.payout_id().is_empty(), dev_addr) {
        (true, _) => vec![],
        (false, None) => full_to_miner(),
        (false, Some(_dev)) if !(0.0..=100.0).contains(&percent) => {
            // Defensive: out-of-range dev percent → ignore the fee, full to miner.
            warn!(
                percent,
                "solo dev_fee_percent out of [0,100]; ignoring fee + paying 100% to miner"
            );
            full_to_miner()
        }
        (false, Some(_dev)) if percent <= 0.0 => {
            // Dev address configured but a zero (or negative) percent — the
            // common "set dev_fee_address, forgot dev_fee_percent" misconfig,
            // since the production default is 0.0. Emitting a dev output at 0 %
            // would put a useless zero-value output in the coinbase; pay the
            // whole reward to the miner instead.
            full_to_miner()
        }
        (false, Some(dev)) => {
            // `from_percent` builds a `Static` entry, and that is the pool's own
            // fee address — see this function's docs.
            let dev = PayoutEntry::from_percent(dev, percent, reward_sats);
            let miner_sats = reward_sats.saturating_sub(dev.sats);
            vec![
                dev,
                PayoutEntry {
                    identity: miner.clone(),
                    sats: miner_sats,
                },
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Decodable;

    fn template_with_height(height: u32) -> CoinbaseTemplate {
        CoinbaseTemplate {
            block_height: height,
            coinbase_value_sats: 5_000_000_000, // 50 BTC subsidy
            witness_commitment: [0u8; 32],
        }
    }

    fn single_payout(addr: &str) -> Vec<PayoutEntry> {
        // Single output → the builder's remainder guard tops it up to the full
        // reward regardless of the exact value seeded here.
        vec![PayoutEntry::static_address(addr.to_string(), 5_000_000_000)]
    }

    // ---- encode_block_height_minimal ----

    #[test]
    fn encode_block_height_well_known() {
        assert_eq!(encode_block_height_minimal(0), Vec::<u8>::new());
        assert_eq!(encode_block_height_minimal(1), vec![0x01]);
        assert_eq!(encode_block_height_minimal(0x7f), vec![0x7f]);
        // High bit set in single byte → append 0x00 disambiguator.
        assert_eq!(encode_block_height_minimal(0x80), vec![0x80, 0x00]);
        assert_eq!(encode_block_height_minimal(0xff), vec![0xff, 0x00]);
        // Multi-byte: 800000 = 0xC3500 → LE [0x00, 0x35, 0x0C, 0x00] → strip → [0x00, 0x35, 0x0C]
        assert_eq!(encode_block_height_minimal(800_000), vec![0x00, 0x35, 0x0c]);
    }

    // ---- varint ----

    #[test]
    fn varint_encoding_boundaries() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0xFC);
        assert_eq!(buf, vec![0xFC]);

        buf.clear();
        encode_varint(&mut buf, 0xFD);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        buf.clear();
        encode_varint(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);

        buf.clear();
        encode_varint(&mut buf, 0x10000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    // ---- build_mining_job ----

    #[test]
    fn build_rejects_empty_payouts() {
        let template = template_with_height(100);
        assert!(matches!(
            build_mining_job(
                Network::Bitcoin,
                &[],
                &template,
                "BP",
                EXTRANONCE_SLOT_LEN,
                [0u8; 32]
            ),
            Err(MiningJobError::NoPayouts)
        ));
    }

    #[test]
    fn build_returns_non_empty_prefix_and_suffix() {
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();
        assert!(!job.coinbase_prefix().is_empty());
        assert!(!job.coinbase_suffix().is_empty());
    }

    #[test]
    fn coinbase_txid_changes_with_extranonce() {
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let h1 = job.coinbase_txid_with_extranonce(&[1; 4], &[2; 8]);
        let h2 = job.coinbase_txid_with_extranonce(&[1; 4], &[3; 8]);
        let h3 = job.coinbase_txid_with_extranonce(&[9; 4], &[3; 8]);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
    }

    #[test]
    fn coinbase_with_extranonce_parses_as_valid_bitcoin_tx() {
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let enonce1 = [0x01, 0x02, 0x03, 0x04];
        let enonce2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&enonce1);
        full.extend_from_slice(&enonce2);
        full.extend_from_slice(job.coinbase_suffix());

        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice())
            .expect("non-witness coinbase must parse as a valid bitcoin tx");

        assert_eq!(tx.input.len(), 1);
        // 1 payout output + 1 witness-commit OP_RETURN.
        assert_eq!(tx.output.len(), 2);
        // First output value matches the full reward (single payout = 100%).
        assert_eq!(tx.output[0].value.to_sat(), 5_000_000_000);
        // Second output is the OP_RETURN witness commitment (zero value, 38-byte script).
        assert_eq!(tx.output[1].value.to_sat(), 0);
        assert_eq!(tx.output[1].script_pubkey.to_bytes().len(), 38);
        // Scriptsig must contain our spliced extranonce in the right slot.
        let scriptsig_bytes = tx.input[0].script_sig.to_bytes();
        let slot_start = scriptsig_bytes.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&scriptsig_bytes[slot_start..slot_start + 4], &enonce1);
        assert_eq!(&scriptsig_bytes[slot_start + 4..], &enonce2);
    }

    #[test]
    fn build_mining_job_is_bip54_compliant() {
        // BIP-54: coinbase nLockTime = height-1, non-final nSequence,
        // witness-stripped size != 64.
        let height = 800_000;
        let template = template_with_height(height);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());

        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();
        assert_eq!(tx.lock_time.to_consensus_u32(), height - 1);
        assert_eq!(tx.input[0].sequence.0, COINBASE_NONFINAL_SEQUENCE);
        assert_ne!(tx.input[0].sequence.0, 0xffff_ffff);

        // Full BIP-54 validation against the non-witness bytes.
        crate::bip54::check_coinbase(&full, height).expect("BIP-54 compliant");
    }

    #[test]
    fn build_payout_outputs_places_exact_sats_verbatim() {
        // Regression: the distributor computes exact per-output sats (fixed
        // finder bonus, largest-remainder residuum). The coinbase builder must
        // place them verbatim — NOT re-derive `floor(percent/100 × reward)`,
        // which silently dropped a sat (a 50 000 000-sat bonus rounding to
        // 49 999 999). Mirrors a real Group-Solo block-template payout set.
        let reward = 316_672_616;
        let payouts = vec![
            PayoutEntry::static_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 4_750_092),
            // finder bonus — must stay EXACT
            PayoutEntry::static_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 50_000_000),
            PayoutEntry::static_address(
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                reward - 4_750_092 - 50_000_000,
            ),
        ];
        let outs = build_payout_outputs(Network::Bitcoin, &payouts, reward, 800_000).unwrap();
        assert_eq!(outs[0].0, 4_750_092);
        assert_eq!(
            outs[1].0, 50_000_000,
            "finder bonus placed verbatim, not floored"
        );
        assert_eq!(outs[2].0, reward - 4_750_092 - 50_000_000);
        let total: u64 = outs.iter().map(|(amt, _)| *amt).sum();
        assert_eq!(total, reward, "coinbase sums to exactly the reward");
    }

    #[test]
    fn floor_remainder_added_to_first_output() {
        // 5_000_000_000 split 3 ways with floor: each gets 1_666_666_666, total = 4_999_999_998.
        // Remainder of 2 sats goes to outs[0] → 1_666_666_668.
        let template = template_with_height(100);
        let percent = 100.0 / 3.0;
        let payouts = vec![
            PayoutEntry::from_percent(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                percent,
                5_000_000_000,
            ),
            PayoutEntry::from_percent("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", percent, 5_000_000_000),
            PayoutEntry::from_percent("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", percent, 5_000_000_000),
        ];
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        // Parse the full coinbase via rust-bitcoin and inspect outputs.
        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        assert_eq!(tx.output[0].value.to_sat(), 1_666_666_668);
        assert_eq!(tx.output[1].value.to_sat(), 1_666_666_666);
        assert_eq!(tx.output[2].value.to_sat(), 1_666_666_666);
        // Sum of payouts must equal the full reward.
        let payout_sum: u64 = tx.output.iter().take(3).map(|o| o.to_sat_value()).sum();
        assert_eq!(payout_sum, 5_000_000_000);
    }

    #[test]
    fn witness_coinbase_is_valid_segwit_tx() {
        // The witness-form coinbase must round-trip through rust-bitcoin's
        // SegWit-aware decoder with marker/flag present and the 32-zero
        // witness reserved value attached to input 0.
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let enonce1 = [0x01, 0x02, 0x03, 0x04];
        let enonce2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];
        let bytes = job.witness_coinbase_with_extranonce(&enonce1, &enonce2);

        // BIP-141 marker + flag must sit right after the 4-byte version.
        assert_eq!(bytes[4], 0x00);
        assert_eq!(bytes[5], 0x01);

        let tx = bitcoin::Transaction::consensus_decode(&mut bytes.as_slice())
            .expect("witness-form coinbase must decode as a SegWit tx");

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        // Coinbase witness: exactly one stack item, 32 zero bytes.
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 1);
        let item = witness.iter().next().unwrap();
        assert_eq!(item, &[0u8; 32]);
        // Scriptsig still contains our extranonce in the slot position.
        let ss = tx.input[0].script_sig.to_bytes();
        let slot_start = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[slot_start..slot_start + 4], &enonce1);
        assert_eq!(&ss[slot_start + 4..], &enonce2);
    }

    #[test]
    fn witness_and_non_witness_share_the_same_outputs_and_scriptsig() {
        // Beyond the marker/flag insertion + witness-stack append, the two
        // forms must encode the same coinbase. Confirms our witness path
        // doesn't accidentally diverge from the non-witness path.
        let template = template_with_height(100);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let e1 = [0x11; 4];
        let e2 = [0x22; 8];

        let mut non_witness = Vec::new();
        non_witness.extend_from_slice(job.coinbase_prefix());
        non_witness.extend_from_slice(&e1);
        non_witness.extend_from_slice(&e2);
        non_witness.extend_from_slice(job.coinbase_suffix());

        let nw_tx = bitcoin::Transaction::consensus_decode(&mut non_witness.as_slice()).unwrap();
        let witness_bytes = job.witness_coinbase_with_extranonce(&e1, &e2);
        let w_tx = bitcoin::Transaction::consensus_decode(&mut witness_bytes.as_slice()).unwrap();

        assert_eq!(nw_tx.version, w_tx.version);
        assert_eq!(nw_tx.lock_time, w_tx.lock_time);
        assert_eq!(nw_tx.input[0].script_sig, w_tx.input[0].script_sig);
        assert_eq!(nw_tx.input[0].sequence, w_tx.input[0].sequence);
        assert_eq!(nw_tx.output, w_tx.output);
        // txid (non-witness hash) must be identical.
        assert_eq!(nw_tx.compute_txid(), w_tx.compute_txid());
    }

    #[test]
    fn pool_identifier_dropped_when_scriptsig_overflows() {
        // 90-char pool identifier + height push + padding will exceed 100 bytes.
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let long_id = "x".repeat(90);
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            &long_id,
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        let scriptsig = tx.input[0].script_sig.to_bytes();
        assert!(scriptsig.len() <= MAX_SCRIPT_SIZE);
        // Identifier bytes ('x'*90) must NOT appear in the scriptsig.
        let xxx = b"xxxxxxxxxx";
        assert!(!scriptsig.windows(10).any(|w| w == xxx));
    }

    // Small helper shim because rust-bitcoin's `Amount` doesn't expose
    // `to_sat_value` — readability of the assertion above.
    trait ToSatVal {
        fn to_sat_value(&self) -> u64;
    }
    impl ToSatVal for bitcoin::TxOut {
        fn to_sat_value(&self) -> u64 {
            self.value.to_sat()
        }
    }

    // ---- build_mining_job_from_tdp ----

    /// Synthesize a witness-commit OP_RETURN TxOut as bitcoin-core would
    /// emit it in `NewTemplate.coinbase_tx_outputs`. Layout per TxOut:
    /// `[value:8 LE][scriptlen:varint][script:N]`.
    fn synthetic_witness_commit_txout_bytes(commit: [u8; 32]) -> Vec<u8> {
        let mut script = Vec::with_capacity(38);
        script.push(0x6a); // OP_RETURN
        script.push(0x24); // OP_PUSHBYTES_36
        script.extend_from_slice(&WITNESS_COMMIT_MAGIC);
        script.extend_from_slice(&commit);
        let mut out = Vec::with_capacity(8 + 1 + 38);
        out.extend_from_slice(&0u64.to_le_bytes()); // value = 0
        out.push(0x26); // 38-byte varint (<0xfd path, single byte)
        out.extend_from_slice(&script);
        out
    }

    /// Build a minimal-realistic `TdpCoinbaseTemplate`: BIP-34 height push
    /// as the coinbase_prefix (height 800k), one OP_RETURN witness-commit
    /// output, version 2, sequence 0xFFFFFFFF, locktime 0.
    fn tdp_template_for(commit: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        // BIP-34 prefix = `[push_height_len][height_LE_minimal]`.
        // For height 800_000 → [0x03, 0x00, 0x35, 0x0c].
        let mut prefix = Vec::new();
        prefix.push(0x03);
        prefix.extend_from_slice(&[0x00, 0x35, 0x0c]);
        let outputs = synthetic_witness_commit_txout_bytes(commit);
        (prefix, outputs)
    }

    /// Bit-identity guard for the direct prefix/suffix serialization: it MUST
    /// produce exactly the bytes the pre-refactor path did (serialize the whole
    /// coinbase, then slice out prefix/suffix around the extranonce slot). The
    /// reference oracle below IS that old algorithm, kept in the test so any
    /// future drift in the direct writers is caught.
    #[test]
    fn tdp_direct_split_matches_full_serialize_then_split() {
        let (prefix, outputs) = tdp_template_for([0x5A; 32]);
        // Two payouts so the output loop + the count varint are exercised, and
        // a non-default sequence / locktime so those fields can't silently drift.
        let payouts = vec![
            PayoutEntry::static_address(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                3_000_000_000,
            ),
            PayoutEntry::static_address(
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".to_string(),
                2_000_000_000,
            ),
        ];
        let slot = EXTRANONCE_SLOT_LEN;
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFF_FFFE,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 42,
        };
        let job =
            build_mining_job_from_tdp(Network::Bitcoin, &payouts, &template, "BP", slot, [0u8; 32])
                .unwrap();

        // Reference oracle = the pre-refactor "build full, then slice" path.
        let script_sig = checked_tdp_scriptsig(template.coinbase_prefix, "BP", slot).unwrap();
        let payout_outputs = build_payout_outputs(
            Network::Bitcoin,
            &payouts,
            template.coinbase_tx_value_remaining,
            payout_height(&template, &payouts).unwrap(),
        )
        .unwrap();
        let total_output_count =
            payout_outputs.len() as u64 + u64::from(template.coinbase_tx_outputs_count);
        let mut full = Vec::new();
        full.extend_from_slice(&template.coinbase_tx_version.to_le_bytes());
        full.push(0x01);
        full.extend_from_slice(&[0u8; 32]);
        full.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        encode_varint(&mut full, script_sig.len() as u64);
        full.extend_from_slice(&script_sig);
        full.extend_from_slice(&template.coinbase_tx_input_sequence.to_le_bytes());
        encode_varint(&mut full, total_output_count);
        for (v, s) in &payout_outputs {
            full.extend_from_slice(&v.to_le_bytes());
            encode_varint(&mut full, s.len() as u64);
            full.extend_from_slice(s);
        }
        full.extend_from_slice(template.coinbase_tx_outputs);
        full.extend_from_slice(&template.coinbase_tx_locktime.to_le_bytes());

        let varint_len = match script_sig.len() as u64 {
            n if n < 0xfd => 1,
            n if n <= 0xffff => 3,
            n if n <= 0xffff_ffff => 5,
            _ => 9,
        };
        let prefix_end = 4 + 1 + 32 + 4 + varint_len + script_sig.len() - slot;
        let suffix_start = prefix_end + slot;

        assert_eq!(
            job.coinbase_prefix(),
            &full[..prefix_end],
            "direct prefix must equal the old full-then-split prefix"
        );
        assert_eq!(
            job.coinbase_suffix(),
            &full[suffix_start..],
            "direct suffix must equal the old full-then-split suffix"
        );
        // The precomputed hex mirrors the bytes exactly.
        assert_eq!(job.coinbase_prefix_hex(), hex::encode(&full[..prefix_end]));
        assert_eq!(
            job.coinbase_suffix_hex(),
            hex::encode(&full[suffix_start..])
        );
    }

    #[test]
    fn tdp_build_rejects_empty_payouts() {
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        assert!(matches!(
            build_mining_job_from_tdp(
                Network::Bitcoin,
                &[],
                &template,
                "BP",
                EXTRANONCE_SLOT_LEN,
                [0u8; 32]
            ),
            Err(MiningJobError::NoPayouts)
        ));
    }

    #[test]
    fn tdp_build_returns_decodable_coinbase() {
        let (prefix, outputs) = tdp_template_for([0xAA; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let e1 = [0x01, 0x02, 0x03, 0x04];
        let e2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];
        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&e1);
        full.extend_from_slice(&e2);
        full.extend_from_slice(job.coinbase_suffix());

        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice())
            .expect("TDP-built coinbase must parse as a valid bitcoin tx");

        assert_eq!(tx.input.len(), 1);
        // 1 payout output + 1 TDP-provided witness-commit OP_RETURN.
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 5_000_000_000);
        assert_eq!(tx.output[1].value.to_sat(), 0);
        // Second output is the OP_RETURN witness commitment (38-byte script).
        assert_eq!(tx.output[1].script_pubkey.to_bytes().len(), 38);
        // Scriptsig must end with our spliced extranonce.
        let ss = tx.input[0].script_sig.to_bytes();
        let slot_start = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[slot_start..slot_start + 4], &e1);
        assert_eq!(&ss[slot_start + 4..], &e2);
        // BIP-34 height push must still be at the start.
        assert_eq!(&ss[..4], &prefix[..]);
    }

    #[test]
    fn tdp_build_honors_version_sequence_and_locktime() {
        // Non-default values for all three fields. Verifies they aren't
        // hard-coded to the build_mining_job(...) constants.
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 1,
            coinbase_tx_input_sequence: 0xFFFFFFFE, // BIP-125 RBF signal
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0x12345678,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        assert_eq!(tx.version.0, 1);
        assert_eq!(tx.input[0].sequence.0, 0xFFFFFFFE);
        assert_eq!(tx.lock_time.to_consensus_u32(), 0x12345678);
    }

    #[test]
    fn tdp_build_floor_remainder_goes_to_first_payout() {
        // Same arithmetic as the non-TDP test: 5_000_000_000 / 3 with floor
        // leaves 2 sats remainder that lands on outs[0].
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let percent = 100.0 / 3.0;
        let payouts = vec![
            PayoutEntry::from_percent(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                percent,
                5_000_000_000,
            ),
            PayoutEntry::from_percent("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", percent, 5_000_000_000),
            PayoutEntry::from_percent("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", percent, 5_000_000_000),
        ];
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        // Output order: payouts first, then TDP-provided OP_RETURN.
        assert_eq!(tx.output.len(), 4);
        assert_eq!(tx.output[0].value.to_sat(), 1_666_666_668);
        assert_eq!(tx.output[1].value.to_sat(), 1_666_666_666);
        assert_eq!(tx.output[2].value.to_sat(), 1_666_666_666);
        assert_eq!(tx.output[3].value.to_sat(), 0); // witness-commit
        let payout_sum: u64 = tx.output.iter().take(3).map(|o| o.to_sat_value()).sum();
        assert_eq!(payout_sum, 5_000_000_000);
    }

    #[test]
    fn tdp_build_pool_identifier_dropped_on_overflow() {
        // TDP prefix already 4 bytes (BIP-34 height push for 800k); add a
        // 90-char identifier and the resulting scriptsig (4 + 90 + 12 = 106)
        // overflows the 100-byte limit. Function must drop identifier.
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let long_id = "x".repeat(90);
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            &long_id,
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .expect("must succeed by dropping the identifier");

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();
        let ss = tx.input[0].script_sig.to_bytes();
        // BIP-34 prefix (4) + slot (12) = 16 bytes. No identifier bytes.
        assert_eq!(ss.len(), 4 + EXTRANONCE_SLOT_LEN);
        assert_eq!(&ss[..4], &prefix[..]);
        // No 'x' bytes anywhere.
        assert!(!ss.contains(&b'x'));
    }

    #[test]
    fn tdp_build_pool_identifier_kept_when_it_fits() {
        // 4-byte prefix + 10-byte identifier + 12-byte slot = 26 bytes — fits.
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();
        let ss = tx.input[0].script_sig.to_bytes();
        // Identifier must be present between prefix and slot.
        let id_start = prefix.len();
        let id_end = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[id_start..id_end], b"Blitzpool");
    }

    #[test]
    fn tdp_build_txid_changes_with_extranonce() {
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let h1 = job.coinbase_txid_with_extranonce(&[1; 4], &[2; 8]);
        let h2 = job.coinbase_txid_with_extranonce(&[1; 4], &[3; 8]);
        let h3 = job.coinbase_txid_with_extranonce(&[9; 4], &[3; 8]);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
    }

    #[test]
    fn tdp_build_witness_coinbase_decodes_as_segwit_tx() {
        // The shared MiningJob layout means the witness path works
        // identically for TDP-built jobs.
        let (prefix, outputs) = tdp_template_for([0xCC; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let e1 = [0x01, 0x02, 0x03, 0x04];
        let e2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];
        let bytes = job.witness_coinbase_with_extranonce(&e1, &e2);

        let tx = bitcoin::Transaction::consensus_decode(&mut bytes.as_slice())
            .expect("witness-form TDP coinbase must decode as a SegWit tx");
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 1);
        assert_eq!(witness.iter().next().unwrap(), &[0u8; 32]);
    }

    #[test]
    fn tdp_build_multiple_tdp_outputs_are_passed_through() {
        // Synthesize TWO TDP outputs (an OP_RETURN witness-commit + a
        // policy output bitcoin-core's `CoinbaseOutputConstraints` might
        // include later). Both must land in the final coinbase verbatim,
        // after our payout outputs, in the order given.
        let mut tdp_outputs = synthetic_witness_commit_txout_bytes([0xEE; 32]);
        // Second TDP output: 100-sat OP_RETURN with "POL".
        tdp_outputs.extend_from_slice(&100u64.to_le_bytes());
        tdp_outputs.push(0x05); // scriptlen = 5
        tdp_outputs.extend_from_slice(&[0x6a, 0x03, b'P', b'O', b'L']);

        let (prefix, _) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &tdp_outputs,
            coinbase_tx_outputs_count: 2,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        // 1 payout + 2 TDP outputs.
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].value.to_sat(), 5_000_000_000);
        assert_eq!(tx.output[1].value.to_sat(), 0); // witness-commit
        assert_eq!(tx.output[2].value.to_sat(), 100); // policy output
                                                      // Policy output script is exactly what we put in the TDP blob.
        assert_eq!(
            tx.output[2].script_pubkey.to_bytes(),
            vec![0x6a, 0x03, b'P', b'O', b'L']
        );
    }
}

#[cfg(test)]
mod payability_tests {
    use super::*;
    use bp_payout_descriptor::RotatingPayout;

    /// A BIP-32 test-vector master public key — published, no funds. A made-up
    /// string fails `Xpub::from_str`, and every assertion below would then be
    /// made about an identity that could not be built.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    /// A real regtest P2WPKH address, per `CLAUDE.md`: `format!("{p}aaa")` would
    /// make the payable case unpayable and the test would pass on the wrong arm.
    const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    /// Well-formed, and on the wrong network. The one input class where
    /// [`is_payable_identity`] and `bp_pplns::is_valid_payout_address` differ.
    const MAINNET_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    /// Height classes, not a sample: the genesis edge, a halving, a plausible
    /// current height, and the top of the BIP-32 unhardened index space, which is
    /// where derivation stops (see
    /// `the_top_of_the_derivation_range_is_where_the_pair_stops_agreeing`).
    const HEIGHTS: [u32; 5] = [0, 1, 840_000, 1 << 30, (1 << 31) - 1];

    fn rotating() -> PayoutIdentity {
        RotatingPayout::from_xpub_str(XPUB)
            .expect("a BIP-32 vector is a valid xpub")
            .into_payout_identity()
    }

    /// **The pin.** `is_payable_identity` is asked at distribution-build time,
    /// where there is no height; `payout_script` is asked per block. They must
    /// answer the same question, or the pool either drops a payable miner's row
    /// or publishes a distribution whose coinbase cannot be built — and the
    /// second one blanks `mining.notify` for every miner sharing the payout set,
    /// silently (`MiningJobCache::get_or_build(…).ok()?`).
    ///
    /// *Mutation that must fail this:* flip either arm of either `match`.
    #[test]
    fn a_payable_identity_is_exactly_one_the_renderer_can_render() {
        let network = Network::Regtest;
        let payout_id = RotatingPayout::from_xpub_str(XPUB)
            .expect("vector")
            .payout_id()
            .as_str()
            .to_string();

        let cases: Vec<(&str, PayoutIdentity)> = vec![
            (
                "a literal regtest address",
                PayoutIdentity::static_address_verbatim(REGTEST_ADDR),
            ),
            ("a rotating identity", rotating()),
            // The Amendment 2 case: a ledger key that reached the coinbase
            // builder as an address because nothing could resolve it.
            (
                "a payout_id in an address field",
                PayoutIdentity::static_address_verbatim(payout_id),
            ),
            (
                "a mainnet address on regtest",
                PayoutIdentity::static_address_verbatim(MAINNET_ADDR),
            ),
            (
                "an empty address",
                PayoutIdentity::static_address_verbatim(""),
            ),
            (
                "a fabricated address",
                PayoutIdentity::static_address_verbatim("bcrt1qaaa"),
            ),
        ];

        let mut payable = 0usize;
        for (what, identity) in &cases {
            let predicate = is_payable_identity(network, identity);
            payable += usize::from(predicate);
            for height in HEIGHTS {
                assert_eq!(
                    predicate,
                    payout_script(network, identity, height).is_ok(),
                    "the predicate and the renderer disagree about {what} at height {height}"
                );
            }
        }
        // The control: without it, `fn is_payable_identity(..) -> bool { false }`
        // paired with a renderer that always failed would pass the loop above.
        assert_eq!(
            payable,
            2,
            "exactly the literal address and the rotating identity are payable; \
             a different count means a case changed arms: {:?}",
            cases
                .iter()
                .map(|(w, i)| (*w, is_payable_identity(network, i)))
                .collect::<Vec<_>>()
        );
    }

    /// The one place the pair above is knowingly not equal, recorded rather than
    /// left for someone to discover: BIP-32 unhardened derivation covers
    /// `0..2^31`, so a *rotating* identity is payable at every height a chain can
    /// reach and unrenderable above that. `2^31` blocks is ~40 000 years of
    /// 10-minute blocks, and `payout_height` cannot produce one — Core's BIP-34
    /// push is the only source, and a block that high is not a block.
    ///
    /// This test exists so the divergence is a *measured* boundary. If a future
    /// descriptor template derives past it, this fails and the doc on
    /// `is_payable_identity` gets corrected instead of quietly becoming false.
    #[test]
    fn the_top_of_the_derivation_range_is_where_the_pair_stops_agreeing() {
        let identity = rotating();
        assert!(is_payable_identity(Network::Regtest, &identity));
        assert!(
            payout_script(Network::Regtest, &identity, (1 << 31) - 1).is_ok(),
            "the whole unhardened range must derive"
        );
        assert!(
            payout_script(Network::Regtest, &identity, 1 << 31).is_err(),
            "hardened indices are not derivable from an xpub; if this ever \
             succeeds, is_payable_identity's Rotating arm is no longer bounded \
             by anything and its doc must say what it is bounded by instead"
        );
        // A static identity has no such boundary: the height is unused.
        let literal = PayoutIdentity::static_address_verbatim(REGTEST_ADDR);
        assert!(payout_script(Network::Regtest, &literal, u32::MAX).is_ok());
    }
}

#[cfg(test)]
mod solo_split_tests {
    use super::*;

    const REWARD: u64 = 5_000_000_000;

    fn fee(address: Option<&str>, percent: f64) -> SoloFeeConfig {
        SoloFeeConfig {
            dev_fee_address: address.map(str::to_string),
            dev_fee_percent: percent,
        }
    }

    /// The miner argument. A helper and not an inline constructor at each of the
    /// eight call sites below, so that "what kind of identity is the miner" is
    /// one line to change when a rotating variant of these cases is added.
    fn miner(address: &str) -> PayoutIdentity {
        PayoutIdentity::static_address_verbatim(address)
    }

    /// The reported bug: a solo miner's `/block-template` preview showed a
    /// fee output its real `mining.notify` did not carry, because the
    /// preview read the PPLNS fee config. With no solo dev fee configured
    /// the split is one output, and both callers now get that same answer
    /// from here.
    #[test]
    fn without_a_dev_fee_the_solo_split_is_a_single_output() {
        let out = solo_payouts(&miner("bc1qminer"), &fee(None, 0.0), REWARD);
        assert_eq!(out.len(), 1, "no second output: {out:?}");
        assert_eq!(out[0].payout_id(), "bc1qminer");
        assert_eq!(out[0].sats, REWARD);
    }

    /// A dev address with the production-default 0 % is the common
    /// misconfiguration; emitting a zero-value output would be worse than
    /// dropping the fee.
    #[test]
    fn a_zero_percent_dev_fee_is_not_an_output() {
        let out = solo_payouts(&miner("bc1qminer"), &fee(Some("bc1qdev"), 0.0), REWARD);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sats, REWARD);
    }

    /// A configured fee does split, and the two outputs sum to exactly the
    /// reward — the coinbase must not lose or invent a satoshi.
    #[test]
    fn a_configured_dev_fee_splits_and_conserves_every_satoshi() {
        let out = solo_payouts(&miner("bc1qminer"), &fee(Some("bc1qdev"), 1.0), REWARD);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payout_id(), "bc1qdev");
        assert_eq!(out[1].payout_id(), "bc1qminer");
        assert_eq!(
            out[0].sats + out[1].sats,
            REWARD,
            "the split must conserve the reward exactly"
        );
    }

    #[test]
    fn an_empty_or_whitespace_dev_address_is_ignored() {
        assert_eq!(
            solo_payouts(&miner("bc1qminer"), &fee(Some(""), 1.0), REWARD).len(),
            1
        );
        assert_eq!(
            solo_payouts(&miner("bc1qminer"), &fee(Some("   "), 1.0), REWARD).len(),
            1
        );
    }

    #[test]
    fn an_out_of_range_percent_falls_back_to_the_miner() {
        assert_eq!(
            solo_payouts(&miner("bc1qminer"), &fee(Some("bc1qdev"), 101.0), REWARD).len(),
            1
        );
        assert_eq!(
            solo_payouts(&miner("bc1qminer"), &fee(Some("bc1qdev"), -1.0), REWARD).len(),
            1
        );
    }

    #[test]
    fn an_empty_miner_address_yields_nothing() {
        assert!(solo_payouts(&miner(""), &fee(None, 0.0), REWARD).is_empty());
    }
}
