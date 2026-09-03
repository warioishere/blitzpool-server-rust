# Upstream Dependencies — Bump-Strategy & Audit-Trail

> Living document. Whenever we add / change / drop an upstream-sourced
> dependency, this file gets updated in the same commit. Production
> ops uses this as the bump-checklist (which crates need attention,
> which are pinned, what could break on update).

**Last touched:** 2026-09-03 — corrected a month of drift. The pins moved to
upstream tag `v0.7.0` back on 2026-08-03 (in `ebce898`) and **this file was
not updated with them**, so it still described a fork we no longer use. The
fork is gone: upstream fixed #541 in `a4a9b840`, which `v0.7.0` carries. See
§2 for why we sit on the tag and do **not** follow `main`.

---

## 1. Mental model — two upstream Git repos

We use code from two *separate but related* Rust git repositories
maintained by the SRI (Stratum Reference Implementation) project. The
distinction is important because they update independently and we
track them differently.

### `stratum-mining/stratum` — **Protocol library**

- GitHub: <https://github.com/stratum-mining/stratum>
- Local clone path: `~/github_repos/stratum/`
- Local clone path: `/home/warioishere/github_repos/stratum/` (Linux user dir)
- **What it is**: the *protocol-layer* monorepo. Contains the wire
  formats, codecs, state machines, and message types for the SV2
  protocol. Pure SV2 — no application logic, no bitcoin-core
  integration, no I/O abstraction. The crate `stratum-core` re-exports
  all sub-crates.
- **What's inside (sub-crates we transitively use)**:
  - `binary_sv2` — SV2 wire datatypes (B032, U256, Str0255, etc.)
  - `framing_sv2` — frame headers + framing
  - `codec_sv2` — frame encoder/decoder + Noise state-machine
    integration
  - `noise_sv2` — Noise-XK handshake (production-ready Initiator/
    Responder)
  - `mining_sv2` — mining-protocol message types
    (OpenStandardMiningChannel, NewMiningJob, SubmitShares, etc.)
  - `template_distribution_sv2` — TDP messages
  - `job_declaration_sv2` — JDP messages
  - `common_messages_sv2` — SetupConnection / Reconnect / etc.
  - `parsers_sv2` — message type dispatch
  - `channels_sv2` — channel management primitives, vardiff helpers
  - `handlers_sv2` — message routing helpers
  - `buffer_sv2` — memory-pooling for serialisation
- **License**: dual MIT / Apache 2.0 (compatible with our AGPL-3.0)
- **Stability**: actively developed; main branch can change weekly.

### `stratum-mining/sv2-apps` — **Application-layer toolkit**

- GitHub: <https://github.com/stratum-mining/sv2-apps>
- Local clone path: `~/github_repos/sv2-apps/`
- Local clone path: `/home/warioishere/github_repos/sv2-apps/` (Linux user dir)
- **What it is**: the *application-layer* repo built on top of
  `stratum-core`. Provides higher-level helpers and reference
  binaries.
- **What's inside (subdirs we care about)**:
  - `stratum-apps/` — crate name `stratum-apps`. Convenience layer:
    Noise-wrapped tokio `TcpStream` (`NoiseTcpStream`,
    `accept_noise_connection`), `task_manager`, `custom_mutex`,
    `key_utils`. Feature-flagged (`pool` / `jd_server` / `jd_client` /
    `translator` / `mining_device`). We use feature `pool`.
  - `bitcoin-core-sv2/` — crate name `bitcoin_core_sv2`. IPC bridge to
    bitcoin-core v31 over Cap'n-Proto. Provides
    `BitcoinCoreSv2TDP` (Template Distribution Protocol client) and
    `BitcoinCoreSv2JDP` (Job Declaration Protocol pool-side client).
    Used by our `bp-template-distribution` + `bp-job-declaration`
    crates.
  - `pool-apps/`, `miner-apps/` — runnable reference binaries
    (`pool_sv2`, `jd_server_sv2`, `jd_client_sv2`, `translator_sv2`).
    **We do NOT use these.** They're useful as behavior references but
    we explicitly write our own pool-side state machine.
- **License**: dual MIT / Apache 2.0 (compatible with our AGPL-3.0)
- **Stability**: actively developed; we pin a release **tag** in our
  `Cargo.toml`, never a branch.

### Visualisation

```
stratum-mining/stratum   ←—— protocol primitives (codecs, frames, messages)
        ▲
        │  depends on
        │
stratum-mining/sv2-apps  ←—— app-layer helpers (Noise-TCP, IPC, task mgmt)
                             + runnable reference binaries we don't use
```

`sv2-apps` depends on `stratum`. Our Rust crates depend on **both**:
we pin `bitcoin_core_sv2` + `stratum-apps` from sv2-apps, and `stratum-core`
from stratum. Cargo's resolver picks ONE version of each transitive
crate (e.g. `binary_sv2`), so the tag / version choices need to be
consistent or the build de-duplicates correctly.

---

## 2. The dependencies — current pins + bump strategy

All entries are in the workspace `Cargo.toml` (root). Each consumer
crate uses `<dep> = { workspace = true }` so the version is centralised.

### A. SV2-protocol-stack git dependencies

| Crate | Source | Pin type | Current pin |
|---|---|---|---|
| `stratum-core` | crates.io | `version` | `0.5.1` (→ `binary_sv2 v6`) |
| `stratum-apps` | `github.com/stratum-mining/sv2-apps.git` (upstream) | `tag = "..."` | `v0.7.0` |
| `bitcoin_core_sv2` | `github.com/stratum-mining/sv2-apps.git` (upstream) | `tag = "..."` | `v0.7.0` |

**Why they must agree**: `bitcoin_core_sv2` at `v0.7.0` *transitively* pins
`stratum-core = "0.5.1"` from crates.io. We declare the SAME `0.5.1` at the
workspace level so Cargo de-duplicates into one `stratum-core` build instead
of two. Both sv2-apps crates carry the same tag for the same reason — a
mismatch splits the transitive `stratum` graph and the build breaks.

We consume the **`v31x`** backend (prod runs Bitcoin Core v31):
`bitcoin_core_sv2::unix_capnp::v31x::{template_distribution_protocol,
job_declaration_protocol}` plus `bitcoin_core_sv2::runtime_api` for the
message types. (`runtime_api` is the post-v0.6.0 rename of the old `common`
module; it landed in `v0.7.0` and our call sites already use it.)

### ⚠️ Why we sit on the tag and do NOT follow upstream `main`

This is the one thing to read before proposing a bump. Since roughly
2026-08, upstream `main` no longer pins `stratum-core` to a crates.io
version — it tracks a moving branch:

```toml
# sv2-apps main, bitcoin-core-sv2/Cargo.toml
stratum-core = { git = "https://github.com/stratum-mining/stratum", branch = "main" }
```

Its history is a stream of `chore(deps): update stratum-core to <sha>`
commits. Following `main` therefore means:

- **No reproducible build.** The dependency resolves to whatever that branch
  points at, recorded only as a Cargo.lock SHA.
- **A `binary_sv2` major bump comes with it** (6 → 7). The 0.5.0 move alone
  cost ~63 migrated call sites; expect the same class of work again.
- Tags remain the only reproducible anchor. `v0.7.0` is the newest.

So: bump **tag to tag**, never onto `main`, and only when a tag carries
something we actually need. Drift on its own only adds risk — that rule has
held through three bumps now.

#### When to bump `stratum-core` (crates.io semver)

`stratum-core` is a crates.io version pin (`"0.5.1"`). It moves only
when we bump the sv2-apps **tag** to a release that pins a newer `stratum-core`
(each release pins an exact crates.io version). Bumping can introduce
breaking changes (renamed types, field-shape changes, message-variant
additions) — e.g. the `0.4.0 → 0.5.0` bump brought `binary_sv2 v6`.

**Trigger**: when the `sv2-apps` tag we track moves to a release that pins
a newer `stratum-core`. Otherwise leave alone — drift
doesn't help us; it only adds risk. Keep the workspace `stratum-core`
version identical to what the pinned `bitcoin_core_sv2` pins.

**Bump procedure**:
1. Read `stratum-apps`'s `Cargo.toml` at the rev we're tracking — note
   which `stratum` commit it transitively expects (look at its
   own `branch = "..."` or `rev = "..."` for stratum-core).
2. `cargo update -p stratum-core` to advance.
3. Run `cargo check --workspace` — fix any breaking changes in our
   wrapper code (typically in `bp-template-distribution`,
   `bp-job-declaration`).
4. Run `cargo test --workspace` — most-affected: `bp-stratum-v2`
   wire-codec tests if any SV2 byte-layout drifted (very unusual).
5. Document the new commit in this file's audit log below.

#### When to bump `bitcoin_core_sv2` + `stratum-apps` (tag-pinned)

Both carry the **same** sv2-apps tag. Bumping one without the other breaks
the build (transitive `stratum` graph disagreement).

**Trigger**: bitcoin-core protocol changes (new TDP/JDP message
variants), security fixes to sv2-apps, or when we need a fresh
`stratum-apps::network_helpers` helper that doesn't exist in our
pinned rev.

**Bump procedure**:
1. Check sv2-apps git log: <https://github.com/stratum-mining/sv2-apps/commits/main>
   — read recent changes since our rev. Look especially for
   `bitcoin-core-sv2/`, `stratum-apps/network_helpers/`,
   `stratum-apps/Cargo.toml` changes.
2. Pick the target **tag** (`git -C ~/github_repos/sv2-apps tag | sort -V`).
   Never a branch — see §2 for why.
3. Update **both** lines in workspace `Cargo.toml`:
   ```toml
   bitcoin_core_sv2 = { ... tag = "<new>" }
   stratum-apps     = { ... tag = "<new>", features = ["pool"] }
   ```
   The tag MUST match between the two lines so Cargo dedupes the
   transitive `stratum` crate-graph.
4. Reconcile `stratum-core`: read `bitcoin-core-sv2/Cargo.toml` at the new
   tag and copy the crates.io version it pins into our workspace pin.
   ⚠️ If that tag pins `stratum-core` by **git branch** rather than by
   version, stop and re-read §2 — that is the unreproducible case, and
   taking it means a `binary_sv2` major migration.
5. `cargo update -p bitcoin_core_sv2 -p stratum-apps -p stratum-core`.
6. **Verify bitcoin-core version compatibility**: the
   `bitcoin_core_sv2` crate's Cap'n-Proto schema is pinned to a
   specific bitcoin-core release. If we bump, confirm the schema
   still matches our deployed bitcoin-core v31.0 (or whatever the
   pool is running). The schema files live under
   `bitcoin-core-sv2/src/ipc-protocol.capnp` upstream.
7. Run `cargo check --workspace && cargo test --workspace`. The
   regtest integration tests in `bp-template-distribution/tests/` +
   `bp-job-declaration/tests/` are the canaries.
8. Document below + update memory `reference-sv2-apps` if the rev
   choice rationale changes.

### B. Crates.io dependencies (protocol-relevant)

| Crate | Version | Why we use it | Bump policy |
|---|---|---|---|
| `bitcoin` | `"0.32"` | rust-bitcoin core types (Address, Transaction, Network, ScriptBuf, secp256k1 re-export). Used everywhere a Bitcoin type crosses our internal API. | Semver-major bumps need careful review of bp-mining-job + bp-stratum-v1 — these consume rust-bitcoin types directly. Pin to `"0.32"` until 0.33+ has a clear migration win. |
| `secp256k1` | `"0.29"` | Direct dep for key-utils in tests + JDP token generation. Transitive via `bitcoin`. | Track `bitcoin`'s peer dep. |
| `siphasher` | `"1"` | SipHash-2-4 — pool-side internal use (SHORT_TX_ID-style hashing per SV2 ext 0x0002 if we ever wire it). NOT the older `siphash` crate (stagnant). | Stable. Bump semver-major if needed. |
| `getrandom` | `"0.2"` | CSPRNG byte-fill for JDP token suffixes (`tokens.rs`) + admin/invitation tokens (`bp-group-mgmt`). | Stable. 0.3 has a new API; defer bump until both consumers are ready. |
| `async-channel` | `"1.5"` | Used by `bitcoin_core_sv2` IPC layer — we mirror its version so Sender/Receiver compatibility holds across the I/O boundary. | Track sv2-apps's choice when bumping rev (it may move to 2.x). |

### C. Crates.io dependencies (rest of stack)

Not protocol-relevant; standard semver-bumps apply. Listed for completeness
since this doc is the operational reference:

- **Async**: `tokio` 1.x, `tokio-util` 0.7, `futures` 0.3, `async-trait` 0.1
- **Errors / logging**: `thiserror` 1, `anyhow` 1, `tracing` 0.1,
  `tracing-subscriber` 0.3
- **Serialization**: `serde` 1, `serde_json` 1, `bytes` 1, `hex` 0.4
- **DB**: `sqlx` 0.8, `uuid` 1
- **Network out**: `redis` 0.27, `reqwest` 0.12
- **HTTP server**: `axum` 0.7, `tower` 0.5, `tower-http` 0.6
- **Hashing/math**: `sha2` 0.10, `num-bigint` 0.4, `num-traits` 0.2
- **Misc**: `subtle` 2.6, `tempfile` 3, `proptest` 1

Bumps for these follow normal Rust ecosystem conventions — pure semver
discipline, no special procedure.

---

## 3. Production checklist (when bumping SV2-stack deps)

Run this checklist on any rev/branch bump in section A:

- [ ] Both sv2-apps crates (`bitcoin_core_sv2` + `stratum-apps`) carry
      the **same** tag — and it is a tag, not `branch = "main"`
- [ ] `stratum-core` pin doesn't conflict with what sv2-apps
      transitively requires (Cargo will warn loudly if it does)
- [ ] `cargo update -p <bumped-crates>` ran cleanly
- [ ] `cargo check --workspace` — no breaking type changes that
      haven't been reconciled in our wrappers
- [ ] `cargo test --workspace` — particularly:
  - `bp-template-distribution` regtest e2e
  - `bp-job-declaration` regtest e2e
  - `bp-stratum-v2` wire-codec tests (extranonce, extensions)
- [ ] **bitcoin-core compat**: schema in `bitcoin-core-sv2` still
      matches the bitcoin-core release we deploy (currently v31.0).
      Check by spawning the regtest harness + running TDP smoke.
- [ ] If `pool-apps/` schema changed: re-read `reference-sv2-apps`
      memory to see if any of our "we don't use this" assumptions
      need revisiting
- [ ] Update the audit log below with the new rev + brief reason
- [ ] If a behavioural change in `stratum-core` invalidates a memory
      (e.g. a Noise-XK test-vector changes), update the memory in the
      same commit

---

## 4. Audit log

| Date | Component | From → To | Reason | PR / commit |
|---|---|---|---|---|
| 2026-05-15 | `bitcoin_core_sv2` | (initial) → `4c0a65680c91...` | Phase 3 — first introduction of TDP/JDP bridge to bitcoin-core v31. | initial commit |
| 2026-05-15 | `stratum-core` | (initial) → `branch=main` (Cargo.lock pinned `7af1b737...`) | Phase 3 — to dedupe transitive stratum graph; `branch=main` matches what `bitcoin_core_sv2` uses. | initial commit |
| 2026-05-16 | `stratum-apps` | (introduced) → `4c0a65680c91...` | Phase 5 Teil 3 — needed `network_helpers::accept_noise_connection`, `task_manager`, `key_utils` for bp-stratum-v2's I/O layer. Rev chosen to match `bitcoin_core_sv2` (same sv2-apps commit). | initial bp-stratum-v2 commit |
| 2026-05-16 | `siphasher` | (introduced) → `"1"` | SipHash-2-4 for SV2 SHORT_TX_ID hashing (ext 0x0002 etc.). Originally specced as `siphash` crate but that's been stagnant since 0.0.5 (2017); `siphasher` is the maintained successor. | initial bp-stratum-v2 commit |
| 2026-06-09 | _(checked, not bumped)_ | sv2-apps `4c0a6568` (91 behind `98c6434b`), stratum-core `7af1b737` (22 behind `127e6546`) | Upstream review only. `bitcoin-core-sv2/` changes cosmetic, **no `.capnp` schema change** (v31 compat intact). Only relevant breaking change: `stratum` `dd7898d5` channels_sv2 ref-getters → accessor APIs (would need wrapper adaptation on bump). Rest = tproxy/jdc/per-upstream-user_identity (unused). #541 + #516 still unmerged. Stayed pinned per "drift only adds risk". | — |
| 2026-06-25 | `bitcoin_core_sv2` + `stratum-apps` | `4c0a6568` (0.2.0) → **FORK** `8f7043b6` (0.4.0) | Took the #516 multi-version refactor (`unix_capnp::v30x/v31x` + `common`) early, on our schedule, rather than mid-production. Refactor is unreleased (upstream `main` `27985c63`, no tag); fork = that commit + ONE patch carrying the #541 min_interval skip-instead-of-sleep fix (still unfixed upstream). Adaptation was tiny: wrapper imports → `unix_capnp::v31x` + `common::job_declaration_protocol::io`, one `error_code.to_string()`. `cargo test-strict` GREEN (1695 passed); v31x TDP+JDP regtests pass against real Core v31. stratum-core stays branch=main. Revert recipe: §2 "FORK pin". | feature branch `bump-bitcoin-core-sv2-0.4.0` |
| 2026-07-16 | `bitcoin_core_sv2` + `stratum-apps` + `stratum-core` | **FORK** `8f7043b6` (main `27985c63`) → **FORK** `c2cf6f2f` (release tag `v0.6.0`); `stratum-core` git-`main` `7af1b737` (0.4.0) → crates.io `0.5.0` | Moved off tracking upstream `main` onto the first tagged release containing the refactor (`v0.6.0`), rebasing our one #541 skip-patch onto it. v0.6.0 pins `stratum-core 0.5.0` = **`binary_sv2 v6`**, which dropped `inner_as_ref()`/`Seq::to_vec()` → migrated ~63 call sites (`.as_bytes()` for `B0xx`/`U256`, `.as_slice()`/`.iter_bytes()` for `Seq`, `TryFrom` for `Seq` construction) across `bp-template-distribution`, `bp-job-declaration`, `bp-stratum-v2` codecs + regtests. v0.6.0 keeps the `common` module (the `runtime_api` rename is post-v0.6.0 on `main` — deferred). `cargo test-strict` GREEN (1316 passed); TDP/JDP/mining/block-submit regtests pass against real Core v31 (blocks accepted). Revert recipe: §2 "FORK pin". | feature branch `migrate/sv2-apps-v0.6.0` |
| 2026-08-03 | `bitcoin_core_sv2` + `stratum-apps` + `stratum-core` | **FORK** `c2cf6f2f` (tag `v0.6.0` + patch) → **upstream** tag `v0.7.0`; `stratum-core` crates.io `0.5.0` → `0.5.1` | **Fork dropped — upstream fixed the reason for it.** `a4a9b840` (*throttle fee templates inside waitNext instead of sleeping*) supersedes our one skip-patch, and issue #541 is closed; `v0.7.0` carries it, so there is nothing left to carry ourselves. The tag also lands the `common` → `runtime_api` rename that v0.6.0 had deferred — our call sites use `runtime_api` accordingly. Still the `v31x` backend against Core v31. ⚠️ This bump rode along inside an unrelated PR and **this file was not updated with it**; the drift was only caught on 2026-09-03, a month later. That is exactly what the header rule exists to prevent. | `ebce898` (inside PR #11) |

---

## 5. What we explicitly **don't** use

These exist upstream but we deliberately skip them — recorded so the
omission survives onboarding:

| Component | Source | Why we skip |
|---|---|---|
| `pool_sv2` | `sv2-apps/pool-apps/pool/` | Reference pool binary. Different channel topology and different hook points than ours. We use it as a behaviour reference (see `mining_message_handler.rs` for the `bad-extranonce-size` wire-code precedent — see memory `feedback-sv2-bad-extranonce-size-hard-reject`), never as a library. |
| `jd_server_sv2` | `sv2-apps/pool-apps/jd-server/` | Designed as a standalone service tightly coupled to its own bitcoin-core IPC wiring. We can't drop it in as a library — we write our own JDS state machine in `bp-stratum-v2/src/jdp/*` on top of the message types in `stratum-core::job_declaration_sv2`. |
| `jd_client_sv2` / `translator_sv2` / `mining_device_sv2` | `sv2-apps/miner-apps/*` | Miner-side reference binaries. We're a pool, not a miner. |
| `sv1_api` | `stratum-core` (feature-gated `sv1`) | We use our own SV1 stack (`bp-stratum-v1`). It predates this dependency set and carries pool-side behaviour the generic API does not. |
| `with_buffer_pool` | feature on `stratum-core` + `stratum-apps` | Object-pooling for serialisation. Defer until profiling shows a hot path benefiting. |
| `monitoring` | feature on `stratum-apps` | HTTP-API for channel metrics. Our own metrics path lives in `bp-metrics` (Phase 6). |

Updating these decisions: when one of these gets adopted (e.g. a
performance reason to enable `with_buffer_pool`), edit the row above
to remove the deferred status + document why in the audit log.

---

## 6. How to find what changed upstream

When prepping a bump:

```bash
# stratum-mining/stratum changes since our pinned commit
git -C ~/github_repos/stratum log --oneline v0.5.1..main | head -40

# sv2-apps changes since our pinned tag
git -C ~/github_repos/sv2-apps log --oneline v0.7.0..main | head -40

# bitcoin_core_sv2-specific changes
git -C ~/github_repos/sv2-apps log --oneline v0.7.0..main -- bitcoin-core-sv2/

# stratum-apps-specific changes
git -C ~/github_repos/sv2-apps log --oneline v0.7.0..main -- stratum-apps/
```

Look for:
- `BREAKING:` / `breaking:` commit-message prefixes
- Cap'n-Proto schema changes under `bitcoin-core-sv2/src/ipc-protocol.capnp`
- Public API renames in `stratum-apps/src/network_helpers/`
- Message-variant additions in `subprotocols/{mining,template-distribution,job-declaration}/`

The release notes (when SRI publishes them) live at the upstream
GitHub release pages.
