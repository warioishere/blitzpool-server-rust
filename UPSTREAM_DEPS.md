# Upstream Dependencies: pins and bump strategy

Which upstream crates this workspace depends on, which of them are pinned and
why, and what to check before moving a pin. Any change to a pin in §2 A
updates this file in the same commit. The workspace `Cargo.toml` is the source
of truth for the actual versions.

---

## 1. Mental model: two upstream Git repos

The SV2 stack comes from two *separate but related* Rust git repositories
maintained by the SRI (Stratum Reference Implementation) project. They update
independently and are tracked differently.

### `stratum-mining/stratum`: protocol library

- GitHub: <https://github.com/stratum-mining/stratum>
- **What it is**: the *protocol-layer* monorepo. Wire formats, codecs, state
  machines and message types for SV2. No application logic, no bitcoin-core
  integration, no I/O abstraction. The crate `stratum-core` re-exports all
  sub-crates.
- **Sub-crates used transitively**:
  - `binary_sv2`: SV2 wire datatypes (B032, U256, Str0255, etc.)
  - `framing_sv2`: frame headers + framing
  - `codec_sv2`: frame encoder/decoder + Noise state-machine integration
  - `noise_sv2`: Noise-XK handshake (Initiator/Responder)
  - `mining_sv2`: mining-protocol message types (OpenStandardMiningChannel,
    NewMiningJob, SubmitShares, etc.)
  - `template_distribution_sv2`: TDP messages
  - `job_declaration_sv2`: JDP messages
  - `common_messages_sv2`: SetupConnection / Reconnect / etc.
  - `parsers_sv2`: message type dispatch
  - `channels_sv2`: channel management primitives, vardiff helpers
  - `handlers_sv2`: message routing helpers
  - `buffer_sv2`: memory pooling for serialisation
- **License**: dual MIT / Apache 2.0 (compatible with AGPL-3.0)
- **Stability**: actively developed; `main` can change weekly.

### `stratum-mining/sv2-apps`: application-layer toolkit

- GitHub: <https://github.com/stratum-mining/sv2-apps>
- **What it is**: the *application-layer* repo built on top of
  `stratum-core`. Higher-level helpers and reference binaries.
- **Relevant subdirs**:
  - `stratum-apps/`: crate `stratum-apps`. Noise-wrapped tokio `TcpStream`
    (`network_helpers::accept_noise_connection`), `task_manager`,
    `key_utils`. Feature-flagged (`pool` / `jd_server` / `jd_client` /
    `translator` / `mining_device`); this workspace enables `pool`.
  - `bitcoin-core-sv2/`: crate `bitcoin_core_sv2`. IPC bridge to
    bitcoin-core over Cap'n-Proto. Provides `BitcoinCoreSv2TDP` (Template
    Distribution Protocol client) and `BitcoinCoreSv2JDP` (Job Declaration
    Protocol pool-side client). `bp-template-distribution` uses the TDP
    client; `bin/blitzpool/src/jdp_hooks.rs` uses `runtime_api` and reaches
    the JDP side through `jd_server_sv2` (see §4).
  - `pool-apps/`, `miner-apps/`: runnable reference binaries (`pool_sv2`,
    `jd_server_sv2`, `jd_client_sv2`, `translator_sv2`). Not run here; see §4.
- **License**: dual MIT / Apache 2.0 (compatible with AGPL-3.0)
- **Stability**: actively developed; pinned to a release **tag** in
  `Cargo.toml`, never a branch.

### Dependency graph

```
stratum-mining/stratum   <-- protocol primitives (codecs, frames, messages)
        ^
        |  depends on
        |
stratum-mining/sv2-apps  <-- app-layer helpers (Noise-TCP, IPC, task mgmt)
                             + runnable reference binaries (unused)
```

`sv2-apps` depends on `stratum`. The workspace depends on **both**:
`bitcoin_core_sv2`, `stratum-apps` and `jd_server_sv2` from sv2-apps, and
`stratum-core` from stratum. Cargo's resolver builds one version of each
transitive crate (e.g. `binary_sv2`) only if all pins agree.

---

## 2. Current pins and bump strategy

All entries live in the workspace `Cargo.toml` (root). Each consumer crate
uses `<dep> = { workspace = true }`, so the version is set in one place.

### A. SV2 protocol stack

| Crate | Source | Pin type | Current pin |
|---|---|---|---|
| `stratum-core` | crates.io | `version` | `0.7.0` (`binary_sv2 v8`) |
| `stratum-apps` | `github.com/stratum-mining/sv2-apps.git` | `tag = "..."` | `v0.9.0` |
| `bitcoin_core_sv2` | `github.com/stratum-mining/sv2-apps.git` | `tag = "..."` | `v0.9.0` |
| `jd_server_sv2` | `github.com/stratum-mining/sv2-apps.git` | `tag = "..."` | `v0.9.0` |

**Why they must agree**: `bitcoin_core_sv2` at `v0.9.0` transitively pins
`stratum-core = "0.7.0"` from crates.io. The workspace declares the same
`0.7.0` so Cargo builds one `stratum-core` instead of two. All three sv2-apps
crates carry the same tag for the same reason: a mismatch splits the
transitive `stratum` graph and the build breaks. This is a type-level
requirement, not only a build-size concern: `jdp_hooks.rs` hands
`DeclareMiningJobOwned` values to `jd_server_sv2`, and two `binary_sv2` majors
side by side do not type-check.

The code goes through the version-agnostic `bitcoin_core_sv2::runtime_api`
and selects the **`v32x`** backend (Bitcoin Core v32) with one constant,
`bp_template_distribution::BITCOIN_CORE_VERSION`, shared by the TDP worker and
the JDP validation engine. A pushed JDP solution is propagated through the same
engine (`BitcoinCoreIPCEngine::handle_push_solution`, IPC `submitBlock`).

### Tag to tag, never upstream `main`

Read this before proposing a bump. Between its release tags, upstream `main`
does not pin `stratum-core` to a crates.io version; it tracks a moving branch:

```toml
# sv2-apps main between tags, bitcoin-core-sv2/Cargo.toml
stratum-core = { git = "https://github.com/stratum-mining/stratum", branch = "main" }
```

Its history is a stream of `chore(deps): update stratum-core to <sha>`
commits. Following `main` therefore means:

- **No reproducible build.** The dependency resolves to whatever that branch
  points at, recorded only as a Cargo.lock SHA.
- **Every `binary_sv2` major lands unannounced**, with renamed types,
  changed field shapes and new message variants.
- Tags are the only reproducible anchor: each release commit switches the
  pin back to an exact crates.io version.

So: bump **tag to tag**, and only when a tag carries something actually
needed (a protocol change, a security fix, a fix in code that runs inside
this process). Drift on its own only adds risk.

### Bump procedure

`stratum-core` never moves on its own. It follows the sv2-apps tag: its
workspace version is always the exact crates.io version the pinned
`bitcoin_core_sv2` pins.

1. Read the sv2-apps changes since the current tag (commands in §5). Look
   especially at `bitcoin-core-sv2/`, `stratum-apps/` and
   `pool-apps/jd-server/`.
2. Pick the target **tag** (`git tag | sort -V` in an sv2-apps clone). Never
   a branch, see above.
3. Update **all three** sv2-apps lines in the workspace `Cargo.toml`:
   ```toml
   bitcoin_core_sv2 = { ... tag = "<new>" }
   stratum-apps     = { ... tag = "<new>", features = ["pool"] }
   jd_server_sv2    = { ... tag = "<new>" }
   ```
4. Reconcile `stratum-core`: read `bitcoin-core-sv2/Cargo.toml` at the new
   tag and copy the crates.io version it pins into the workspace pin.
   If that tag pins `stratum-core` by **git branch** rather than by version,
   stop: that is the unreproducible case described above.
5. `cargo update -p bitcoin_core_sv2 -p stratum-apps -p jd_server_sv2 -p stratum-core`.
6. **Bitcoin Core compatibility**: the Cap'n-Proto schema in
   `bitcoin_core_sv2` targets specific Bitcoin Core releases. Confirm the
   backend in `BITCOIN_CORE_VERSION` still matches the Core version the pool
   runs against. The schema files live under `bitcoin-core-sv2/` upstream.
7. `cargo check --workspace`, then `cargo test --workspace -- --nocapture`.
   Breaking changes usually surface in `bp-template-distribution`,
   `bin/blitzpool/src/jdp_hooks.rs` and the `bp-stratum-v2` codecs. The
   regtests in `bp-template-distribution/tests/` and `bp-stratum-v2/tests/`
   run only locally against a real Bitcoin Core.
8. Update §2 A of this file in the same commit.

### B. Crates.io dependencies with a constraint

| Crate | Why it is constrained | Bump policy |
|---|---|---|
| `bitcoin` | rust-bitcoin types (Address, Transaction, Network, ScriptBuf, the `secp256k1` re-export) cross the internal API everywhere, and `stratum-core` exposes the same major. | A semver-major bump needs careful review of `bp-mining-job` and `bp-stratum-v1`, which consume these types directly, and must stay compatible with what `stratum-core` uses. |
| `async-channel` | `bitcoin_core_sv2`'s IPC layer hands its Sender/Receiver across the boundary into `bp-template-distribution`. | The major follows what the pinned sv2-apps tag uses, not the newest release. Dependabot ignores its majors for this reason (`.github/dependabot.yml`). |

### C. Everything else

All other dependencies in the workspace `Cargo.toml` follow normal semver;
Dependabot groups minor and patch bumps and opens one PR per major. No
special procedure.

---

## 3. Checklist for a §2 A bump

- [ ] All three sv2-apps crates (`bitcoin_core_sv2` + `stratum-apps` +
      `jd_server_sv2`) carry the **same** tag, and it is a tag, not
      `branch = "main"`
- [ ] Workspace `stratum-core` equals the crates.io version that tag pins
- [ ] `cargo update -p <bumped-crates>` ran cleanly
- [ ] `cargo check --workspace`: every breaking type change reconciled in the
      wrappers
- [ ] `cargo test --workspace -- --nocapture`, including the local-only
      regtests, particularly:
  - `bp-template-distribution` regtest e2e
  - `bp-stratum-v2` regtests (`regtest_*`, `jdp_push_distribution_e2e`)
  - `bp-stratum-v2` wire-codec tests (extranonce, extensions)
- [ ] **Bitcoin Core compat**: the schema in `bitcoin-core-sv2` still matches
      the Core release the pool runs against; the TDP regtests pass against
      it
- [ ] If `pool-apps/` changed: re-check §4 for anything that now fits
- [ ] §2 A of this file updated in the same commit

---

## 4. Not used

These exist upstream but are deliberately not used:

| Component | Source | Why not |
|---|---|---|
| `pool_sv2` | `sv2-apps/pool-apps/pool/` | Reference pool binary. Different channel topology and different hook points. Used as a behaviour reference (e.g. the `bad-extranonce-size` wire code in its `channel_manager/mining_message_handler.rs`), never as a library. |
| `jd_server_sv2` as a **service** | `sv2-apps/pool-apps/jd-server/` | Not run; the JDS state machine lives in `bp-stratum-v2/src/jdp/*`. The crate is a library dependency for exactly one item, `job_declarator::job_validation::bitcoin_core_ipc::BitcoinCoreIPCEngine` (declared-job validation through Core's `checkBlock`, used in `bin/blitzpool/src/jdp_hooks.rs`), which is why it is pinned in §2 A. |
| `jd_client_sv2` / `translator_sv2` / `mining_device_sv2` | `sv2-apps/miner-apps/*` | Miner-side reference binaries; this is a pool. |
| `sv1_api` | `stratum-core` (feature-gated `sv1`) | The SV1 stack is `bp-stratum-v1`, which carries pool-side behaviour the generic API does not. |
| `with_buffer_pool` as a deliberate choice | feature on `stratum-core` + `stratum-apps` | Enabled only because `stratum-apps`' `pool` feature turns it on. Not profiled; no claim about its effect. |
| `monitoring` | feature on `stratum-apps` | HTTP API for channel metrics. Metrics come from `bp-metrics`. |

When one of these gets adopted, edit its row and say why.

---

## 5. How to find what changed upstream

Run from clones of both upstream repos (`$STRATUM` and `$SV2_APPS` below are
their paths):

```bash
# stratum-mining/stratum changes since the commit the pinned stratum-core was
# published from. That repo's tags are v1.x and do not follow the crate
# version, so take the commit from the published crate itself:
SHA=$(grep -o '"sha1": "[0-9a-f]*"' \
  ~/.cargo/registry/src/*/stratum-core-0.7.0/.cargo_vcs_info.json | cut -d'"' -f4)
git -C "$STRATUM" log --oneline "$SHA"..origin/main | head -40

# sv2-apps changes since the pinned tag
git -C "$SV2_APPS" log --oneline v0.9.0..origin/main | head -40

# bitcoin_core_sv2-specific changes
git -C "$SV2_APPS" log --oneline v0.9.0..origin/main -- bitcoin-core-sv2/

# stratum-apps-specific changes
git -C "$SV2_APPS" log --oneline v0.9.0..origin/main -- stratum-apps/

# jd_server_sv2-specific changes (only the validation engine is used)
git -C "$SV2_APPS" log --oneline v0.9.0..origin/main -- pool-apps/jd-server/
```

Look for:
- `BREAKING:` / `breaking:` commit-message prefixes
- Cap'n-Proto schema changes under `bitcoin-core-sv2/`
- Public API renames in `stratum-apps/src/network_helpers/`
- Message-variant additions in `subprotocols/{mining,template-distribution,job-declaration}/`

Release notes, when SRI publishes them, are on the upstream GitHub release
pages.
