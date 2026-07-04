# ⚡ Blitzpool (Rust) — Non-Custodial Bitcoin Mining Pool

**Blitzpool** is an open-source Bitcoin mining pool with a single distinguishing feature: **every payout — Solo, PPLNS, Group-Solo, Blockparty — is written directly into the coinbase transaction of the block that earned it.** No pool wallet, no custody period, no FPPS-style intermediate. Your sats arrive at your address with the block itself.

This is the **ground-up Rust rebuild** of the original TypeScript Blitzpool — same non-custodial payout philosophy, re-architected around a multi-stream template pipeline, a self-tuning coinbase budget, and a Core/Satellite split that lets the pool scale horizontally. The protocol behaviour (Stratum V1/V2, coinbase distribution) is feature-equivalent with the TS pool; the internals are not.

License: **GNU AGPL v3 (AGPL-3.0-or-later)**.

---

## What makes Blitzpool different

| | Blitzpool | Typical FPPS / PPS+ | Custodial PPLNS |
|---|---|---|---|
| Payouts go directly on-chain | ✅ same block as the find | ❌ batch cron, hours to days | ❌ threshold-based |
| Pool holds miner sats | ❌ never | ✅ between find & payout | ✅ until threshold |
| Minimum payout | *none* — it's just a coinbase output | typically 0.001 BTC+ | same |
| Stratum V1 | ✅ | ✅ | ✅ |
| Stratum V2 (Noise + TDP + JDP + extended channels) | ✅ actively developed | rare | almost never |
| Non-custodial Group-Solo (friends mine together, split on-chain) | ✅ | — | — |
| Non-custodial Blockparty (co-funded rentals, fixed-% on-chain split) | ✅ | — | — |

Every block mined on Blitzpool has the miner address(es) as the **direct** coinbase destination. An operator can't withhold payouts — they'd have to refuse to relay the block at all, and the miner could submit it elsewhere.

---

## The four payout modes

All four write their payout straight into the coinbase. They differ only in *how the reward is split*.

### 🎯 Solo
You versus Bitcoin. Your share wins → the entire coinbase goes to your address. No fee, no custody.

### 🔗 PPLNS (Pay Per Last N Shares)
Sliding-window pooled mining with a **multi-output coinbase** and a **signed credit/debit ledger**. Every miner in the window gets their proportional cut as their own coinbase output.

- Window size: `window_factor × networkDifficulty` (default `4×`) in diff-1-weighted shares — anti-hop by design (sliding window, not per-block reset).
- A per-miner **signed balance** keeps the pool non-custodial to the sat: trimmed / sub-dust sats become a *pending credit* for the miner who earned them; the bonus recipient of the same block picks up a matching *pending debit*. Pool-wide balances sum to ~0 (bounded floor-rounding drift).

### 👥 Group-Solo
Friends mine together as a closed group; every block the group finds is split proportionally to each member's shares in that round, paid in the coinbase. Address-driven routing, admin-token auth, email-verified invitations. Per-block round reset is **opt-in** per group.

### 🎉 Blockparty
A directed group sharing a hashpower rental. Each member gets a **fixed cut** (basis points) of every block the rented hashrate finds, paid on-chain. Splits are agreed and signed off up front; trimmed/residual sats fold into the pool-fee output.

---

## Architecture highlights (what's new in the Rust build)

### 1. One IPC template stream per payout mode

Blitzpool talks to **bitcoin-core v31 over its Cap'n-Proto IPC socket** (Template Distribution Protocol), not `getblocktemplate` + ZMQ. Each payout mode gets its **own IPC client = its own template stream** from core:

| Stream | Reservation | Serves |
|---|---|---|
| **PPLNS** (default) | autoscaled (see §2) | PPLNS connections |
| **Solo** | fixed | Solo connections |
| **Group-Solo** | fixed | Group-Solo connections |
| **Blockparty** | fixed (only when configured) | Blockparty rentals |

Per stream, the pool tells core exactly how much coinbase space to reserve via the IPC `coinbase_output_max_additional_size` field — derived from each mode's coinbase weight budget. **There is no `blockreservedweight` to set in `bitcoin.conf`**: the reservation is handed to core per-stream at runtime, and the streams are independent (only one stream's block ultimately wins, so reservations don't sum against a shared limit). A process only spawns the TDP streams when it holds the `front` role (see §4).

### 2. PPLNS coinbase autoscaler

The PPLNS stream's coinbase weight budget **self-tunes** instead of being a fixed reservation. It steps between a floor (`[pplns].coinbase_weight_budget`, default 50 000 WU) and a hard ceiling (`[coinbase_autoscale].max_weight_budget`):

- **Steps up** when utilization ≥ `up_threshold` (default 0.85 — i.e. 15 % before it would trim) after `up_debounce` samples.
- **Steps down** when utilization ≤ `down_threshold` (default 0.50) after `down_debounce` samples.
- Multiplicative `step_factor` (default 1.15 = ±15 %), with a `cooldown_secs` floor between changes.

Effect: as the PPLNS window grows, the reservation grows ahead of it; when the window shrinks, the reservation shrinks and **reclaims block space for fee-paying transactions**. The alt streams (Solo / Group-Solo / Blockparty) stay on small fixed reservations sized to the largest group you expect.

### 3. Always-valid blocks via weight-budget trim

The distribution builder reserves the structural coinbase overhead, then greedily keeps the largest payouts that fit the stream's budget and **trims the smallest payouts to pending** (carry-forward). Because the assembled coinbase can therefore *never* exceed the reservation core was told about, **a found block is always valid** — the pool can never build a coinbase that overflows its template and gets rejected by core.

Trimmed sats are **never lost**: in PPLNS they become a signed pending credit; in Group-Solo they stay as positive `pendingSats` and clear in a future block. Under-sizing a budget costs *fairness* (a small miner waits a block or two for their payout), never *validity*. A capacity-alert cron emails the operator before anyone is actually trimmed, and a `GET /api/pplns/groups/coinbase-capacity` endpoint surfaces the live member ceiling.

### 4. Core/Satellite split (horizontal scale)

The pool runs as role-gated processes that communicate over **Redis streams**:

- `front` — Stratum listeners, template streams, job building, block submit
- `api` — read-only HTTP API
- `payout` — ledger apply, confirmation gating, dust sweep
- `stats` — share-stats aggregation
- `notify` — Telegram / ntfy / push / email fan-out

Roles are selected with `--roles` / `BLITZPOOL_ROLES` (independent of payout mode). Block-found and accepted/rejected shares flow Core→Satellite over Redis streams with exactly-once semantics; routing-cache invalidation is broadcast cross-process. See [`full-setup/DEPLOYMENT.md`](full-setup/DEPLOYMENT.md).

### 5. Confirmation-gated, orphan-safe payouts

PPLNS and Group-Solo **freeze** a block's distribution and park it in Redis keyed by block hash; a confirmation watcher applies the ledger only after `confirmation_depth` (default 3) confirmations and **discards orphaned candidates** — no payout is ever booked for a block that didn't survive on-chain. Ledger applies are idempotent (history UNIQUE constraint + history-gated balance upsert), so stream redelivery or a duplicate block-found can't double-credit.

---

## Stratum support

- **Stratum V1** — full SV1 stack with vardiff, `mining.notify` (ckpool-convention hex-padded fields), per-port difficulty.
- **Stratum V2** — Noise handshake, standard + extended channels (extranonce rolling, merkle reconstruction, pool-side share validation), Template Distribution Protocol, Job Declaration Protocol, SipHash-2-4. SV1 and SV2 share the same TCP ports; protocol detection on the first byte routes the socket.

### Endpoints (operator-configured per-port TOML)

| Role | Starting difficulty | Purpose |
|---|---|---|
| Default entry | configured (e.g. 1 000) | Solo / Group-Solo / Blockparty |
| **High-diff rental** | **1 000 000** | NiceHash / MRR / Braiins rentals — also the canonical Blockparty rental port |
| PPLNS opt-in | adaptive | Explicit opt-in to PPLNS payout |
| SV2 JDP | — | Job Declaration Protocol (when enabled) |

Routing priority on connect: **explicit PPLNS port → Blockparty admin address → Group-Solo membership → Solo**. Group-Solo and Blockparty are mutually exclusive per address. Extranonce2 size is 8 bytes (ample headroom for rental work distribution).

---

## Configuration

Configuration is **TOML-first** (parsed by `bp-config`), grouped into sections — the most relevant:

| Section / key | Purpose |
|---|---|
| `[tdp].socket_path` | bitcoin-core IPC socket for the template streams |
| `[pplns].coinbase_weight_budget` | PPLNS budget **floor** (default 50 000 WU); autoscaler grows from here |
| `[coinbase_autoscale]` | `max_weight_budget` (ceiling), `up/down_threshold`, `step_factor`, debounce, cooldown |
| `[group_fees].coinbase_weight_budget` | Group-Solo + Blockparty fixed budget (default 10 000 WU ≈ 50 members) |
| `[group_fees].address` / `.percent` | Shared Group-Solo/Blockparty fee lane (falls back to `[pplns]` fee) |
| `[solo].coinbase_weight_budget` / `[blockparty].coinbase_weight_budget` | Per-mode fixed alt-stream reservations |
| `[capacity_alert]` | Operator capacity-alert email thresholds |
| `--roles` / `BLITZPOOL_ROLES` | Deployment topology override (front/api/payout/stats/notify) |

Schema is applied via **sqlx migrations run at boot** (advisory-locked + idempotent, so every process in a split can run them safely). Postgres + Redis are required — there is no SQLite path. Upstream SV2-stack dependency pins and bump strategy live in [`UPSTREAM_DEPS.md`](UPSTREAM_DEPS.md).

---

## API

The HTTP API (served by the `api` role) mirrors the TS pool's surface — pool-wide (`/api/info/*`, `/api/network`), per-address (`/api/client/:address/*`, `/api/pplns/mode/:address`), PPLNS (`/api/pplns/*`), Group-Solo (`/api/pplns/groups/*`), Blockparty (`/api/blockparty/*`), and email-binding endpoints. Rust-build additions include:

- `GET /api/pplns/groups/coinbase-capacity` — worst-case member ceiling for the Group-Solo coinbase budget (UI shows used / free slots per group).
- `GET /api/pplns/groups/finder-bonus-cap` — current block subsidy, used to cap the finder-bonus input.

---

## Build & test

```bash
cargo build --release            # builds the `blitzpool` binary
cargo test --workspace           # unit + integration tests (~40% of the tree is tests)
cargo clippy --workspace         # lints
```

Regtest-driven integration tests (TDP/IPC + RPC paths) spin up bitcoin-core via the in-tree `bp-regtest-harness`; the `bp-template-distribution` and `bp-job-declaration` test suites are the bitcoin-core compatibility canaries. A regtest deploy helper lives at `build_and_deploy_regtest.sh`, and the split-validation runbook at [`full-setup/REGTEST-SPLIT-VALIDATION.md`](full-setup/REGTEST-SPLIT-VALIDATION.md).

---

## Tech stack

Rust workspace of **37 crates** (`bp-*` + the `blitzpool` binary). Async on **tokio**; HTTP on **axum**; DB on **sqlx** (Postgres); **Redis** for the share/cache/stream bus. SV2 protocol primitives from the SRI `stratum-core`; bitcoin-core IPC bridge from `sv2-apps` (`bitcoin_core_sv2`) — see [`UPSTREAM_DEPS.md`](UPSTREAM_DEPS.md).

---

## UI

The frontend lives in its own repo: **[blitzpool-ui](https://github.com/warioishere/blitzpool-ui)** (Angular). It talks to the `api` role's HTTP endpoints and exposes the per-miner dashboard, payout-group + Blockparty admin flows, public group directory, and a mining-modes explainer.

---

## Credits + contact

Built by the Blitzpool team at [yourdevice.ch](https://yourdevice.ch). The non-custodial coinbase-payout design originated in the TypeScript [Blitzpool](https://github.com/warioishere/blitzpool) (itself a fork of [public-pool](https://github.com/benjamin-wilson/public-pool)); this repository is the independent Rust reimplementation.

Made in Switzerland. 🇨🇭

> *by Bitcoiners, for Bitcoiners who verify instead of trust.*
