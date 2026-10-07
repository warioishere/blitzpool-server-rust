# ⚡ Blitzpool (Rust) — Non-Custodial Bitcoin Mining Pool

**Blitzpool** is an open-source Bitcoin mining pool with a single distinguishing feature: **every payout — Solo, PPLNS, Team Mining, Blockparty — is written directly into the coinbase transaction of the block that earned it.** No pool wallet, no custody period, no FPPS-style intermediate. Your sats arrive at your address with the block itself.

This is the **ground-up Rust rebuild** of the original TypeScript Blitzpool — same non-custodial payout philosophy, re-architected around a multi-stream template pipeline, a self-tuning coinbase budget, and a Core/Satellite split that lets the pool scale horizontally. It replaces the TS pool and has since gone beyond it, with Team Mining window payouts and the SV2 non-custodial payouts extension among the additions.

License: **GNU AGPL v3 (AGPL-3.0-or-later)**.

> **Run a release, not `main`.** `main` is the development branch and can change
> config keys, migrations or behaviour without warning. To operate a pool, use
> the latest [release](https://github.com/warioishere/blitzpool-server-rust/releases)
> or the `stable` branch, which only ever points at the latest release, and read
> the release's **Upgrade notes** before every update.

---

## What makes Blitzpool different

| | Blitzpool | Typical FPPS / PPS+ | Custodial PPLNS |
|---|---|---|---|
| Payouts go directly on-chain | ✅ same block as the find | ❌ batch cron, hours to days | ❌ threshold-based |
| Pool holds miner sats | ❌ never | ✅ between find & payout | ✅ until threshold |
| Minimum payout | *none* — it's just a coinbase output | typically 0.001 BTC+ | same |
| Stratum V1 | ✅ | ✅ | ✅ |
| Stratum V2 (Noise + TDP + JDP + extended channels) | ✅ actively developed | rare | almost never |
| Non-custodial Team Mining (friends mine together, split on-chain) | ✅ | — | — |
| Non-custodial Blockparty (co-funded rentals, fixed-% on-chain split) | ✅ | — | — |

Every block mined on Blitzpool has the miner address(es) as the **direct** coinbase destination. An operator can't withhold payouts — they'd have to refuse to relay the block at all, and the miner could submit it elsewhere.

---

## The four payout modes

All four write their payout straight into the coinbase. They differ only in *how the reward is split*.

### 🎯 Solo
You versus Bitcoin. Your share wins → the entire coinbase goes to your address. No fee, no custody.

### 🔗 PPLNS (Pay Per Last N Shares)
Sliding-window pooled mining with a **multi-output coinbase** and a **signed credit/debit ledger**. Every miner in the window gets their proportional cut as their own coinbase output.

- Window size: `4 × networkDifficulty` in diff-1-weighted shares, kept in buckets of 10 000 shares — anti-hop by design (sliding window, not per-block reset). Buckets older than `abandoned_balance_days` (default 90) leave the window as well.
- A per-miner **signed balance** keeps the pool non-custodial to the sat: sats a block's coinbase could not pay a miner (trimmed or sub-dust) become a *pending credit* for that miner, and the miners paid in its place book matching *pending debits*. Pool-wide balances sum to ~0 (bounded floor-rounding drift).

### 👥 Team Mining
Friends mine together as a team; every block the team finds is split among the members in the coinbase. Each team picks its payout mode at creation, and it never changes: **Prop** splits by each member's shares in the current round (resetting the round after every block is opt-in), **Window** by the shares of the last N days. An optional finder bonus goes to the member who found the block. Members join through an invite link (with optional admin approval) or by request from the public team directory, after proving their address by email or by signature; the admin manages the team with an admin token. Configured as `[group_solo]`.

### 🎉 Blockparty
A directed group sharing a hashpower rental. Each member gets a **fixed cut** (basis points) of every block the rented hashrate finds, paid on-chain. Every member confirms the split before the party goes live; trimmed/residual sats fold into the pool-fee output.

---

## Architecture highlights (what's new in the Rust build)

### 1. One IPC template stream per payout mode

Blitzpool talks to **bitcoin-core v31 over its Cap'n-Proto IPC socket** (Template Distribution Protocol), not `getblocktemplate` + ZMQ. Each payout mode gets its **own IPC client = its own template stream** from core:

| Stream | Reservation | Serves |
|---|---|---|
| **PPLNS** (default) | autoscaled (see §2) | PPLNS connections |
| **Solo** | fixed | Solo connections |
| **Team Mining** | fixed (only when configured) | Team Mining connections |
| **Blockparty** | fixed (only when configured) | Blockparty rentals |

Per stream, the pool tells core exactly how much coinbase space to reserve via the IPC `coinbase_output_max_additional_size` field — derived from each mode's coinbase weight budget. **There is no `blockreservedweight` to set in `bitcoin.conf`**: the reservation is handed to core per-stream at runtime, and the streams are independent (only one stream's block ultimately wins, so reservations don't sum against a shared limit). A process only spawns the TDP streams when it holds the `front` role (see §4).

### 2. PPLNS coinbase autoscaler

The PPLNS stream's coinbase weight budget **self-tunes** instead of being a fixed reservation. It steps between a floor (`[pplns].coinbase_weight_budget`, 50 000 WU in the example config) and a hard ceiling (`[pplns.coinbase_autoscale].max_weight_budget`):

- **Steps up** when utilization ≥ `up_threshold` (default 0.85 — i.e. 15 % before it would trim) after `up_debounce` samples.
- **Steps down** when utilization ≤ `down_threshold` (default 0.50) after `down_debounce` samples.
- Multiplicative `step_factor` (default 1.15 = ±15 %), with a `cooldown_secs` floor between changes.

Effect: as the PPLNS window grows, the reservation grows ahead of it; when the window shrinks, the reservation shrinks and **reclaims block space for fee-paying transactions**. The alt streams (Solo / Team Mining / Blockparty) stay on small fixed reservations sized to the largest team or party you expect.

### 3. Always-valid blocks via weight-budget trim

The distribution builder reserves the structural coinbase overhead, then greedily keeps the largest payouts that fit the stream's budget and **trims the smallest payouts to pending** (carry-forward). Because the assembled coinbase can therefore *never* exceed the reservation core was told about, **a found block is always valid** — the pool can never build a coinbase that overflows its template and gets rejected by core.

Where a trimmed payout goes differs by mode, deliberately. **PPLNS**: the value stays inside the miners' cut as a signed pending credit and is repaid from a later block (`WithheldValue::ToOtherMiners`). **Team Mining**: it is paid to the pool (`WithheldValue::ToPool`) — there is no team ledger and no carry-forward, which is why membership is hard-capped at what the coinbase can actually pay. Under-sizing a PPLNS budget therefore costs *fairness* (a small miner waits a block or two), never *validity*.

Capacity is monitored externally rather than by the pool: `GET /api/pplns/groups/coinbase-capacity` reports the member ceiling and `GET /api/pplns/fees` the PPLNS `maxMinerOutputsAdaptive`, each divided into the current fill (`members.length` from the team detail, or the length of `GET /api/pplns/distribution`).

### 4. Core/Satellite split (horizontal scale)

The pool runs as role-gated processes that communicate over **Redis streams**:

- `front` — Stratum listeners, template streams, job building, block submit
- `api` — HTTP API
- `payout` — ledger apply for PPLNS, Team Mining and Blockparty, confirmation gating, dust sweep
- `stats` — share-stats aggregation
- `notify` — Telegram / ntfy / push / email fan-out

Roles are selected with `--roles` / `BLITZPOOL_ROLES` (independent of payout mode). Block-found and accepted/rejected shares flow Core→Satellite over Redis streams with exactly-once semantics; routing-cache invalidation is broadcast cross-process. See [`full-setup/DEPLOYMENT.md`](full-setup/DEPLOYMENT.md).

### 5. Confirmation-gated, orphan-safe payouts

PPLNS, Team Mining and Blockparty **park** a found block in Redis keyed by block hash, together with what is needed to settle it: the block's own coinbase and, for PPLNS, a snapshot of the share weights. A confirmation watcher settles it only after `confirmation_depth` (default 3) confirmations, against what that coinbase actually paid, and **discards orphaned candidates** — no payout is ever booked for a block that didn't survive on-chain. Booking is idempotent: a block height is booked once and a replay with different numbers is refused, so stream redelivery or a duplicate block-found can't double-credit.

---

## Stratum support

- **Stratum V1** — full SV1 stack with vardiff, `mining.notify` (ckpool-convention hex-padded fields), per-port difficulty.
- **Stratum V2** — Noise handshake, standard + extended channels (extranonce rolling, merkle reconstruction, pool-side share validation), Template Distribution Protocol, Job Declaration Protocol with the non-custodial payouts extension (0x0003), which hands a miner that builds its own template the payout distribution its coinbase must pay, SipHash-2-4. SV1 and SV2 share the same TCP ports; the opening bytes of a connection decide its protocol.

### Endpoints (operator-configured per-port TOML)

| Port | Starting difficulty | Purpose |
|---|---|---|
| Solo | configured (e.g. 5 000) | Solo, and Team Mining / Blockparty (routed by address) |
| **Solo high-diff** | configured (e.g. 1 000 000) | NiceHash / MRR / Braiins rentals — also the canonical Blockparty rental port |
| PPLNS | configured | PPLNS payout (only when `[pplns]` is configured) |
| PPLNS high-diff | configured | PPLNS for rentals |
| SV2 JDP | — | Job Declaration Protocol (when enabled) |

Routing on connect: **Team Mining membership → Blockparty admin address → the port's own mode (Solo or PPLNS)**. An address is either in a team or in a Blockparty, never both. SV1 extranonce2 size is 8 bytes (ample headroom for rental work distribution).

---

## Getting started

**[`DEPLOYMENT.md`](DEPLOYMENT.md)** sets up a working Solo pool with Docker
Compose from [`simple-setup/`](simple-setup/README.md): the only prerequisite
is Bitcoin Core 31 with its IPC socket, and the compose file can run that node
for you. [`full-setup/`](full-setup/README.md) is the four-process layout for
redeploying single processes. Start from
[`blitzpool.example.toml`](blitzpool.example.toml) (Solo) and add sections from
[`blitzpool.full.example.toml`](blitzpool.full.example.toml) to switch on PPLNS,
Team Mining or Blockparty.

---

## Configuration

Configuration is **TOML-first** (parsed by `bp-config`), grouped into sections — the most relevant:

| Section / key | Purpose |
|---|---|
| `[tdp].socket_path` | bitcoin-core IPC socket for the template streams |
| `[pplns].coinbase_weight_budget` | PPLNS budget **floor** (default 50 000 WU); autoscaler grows from here |
| `[pplns.coinbase_autoscale]` | `max_weight_budget` (ceiling), `up/down_threshold`, `step_factor`, debounce, cooldown |
| `[pplns]` / `[group_solo]` (Team Mining) / `[blockparty]` | Presence switches the mode on; absent means off. Solo is always on |
| `[solo]` / `[pplns]` / `[group_solo]` / `[blockparty]` `.fee_address` + `.fee_percent` | Each mode's own pool fee (optional on Solo) |
| `[solo]` / `[group_solo]` / `[blockparty]` `.coinbase_weight_budget` | Per-mode fixed alt-stream reservations (Team Mining default 10 000 WU ≈ 50 members) |
| `--roles` / `BLITZPOOL_ROLES` | Deployment topology override (front/api/payout/stats/notify) |

Schema is applied via **sqlx migrations run at boot** (advisory-locked + idempotent, so every process in a split can run them safely). Postgres + Redis are required — there is no SQLite path. Upstream SV2-stack dependency pins and bump strategy live in [`UPSTREAM_DEPS.md`](UPSTREAM_DEPS.md).

---

## API

The HTTP API (served by the `api` role) mirrors the TS pool's surface — pool-wide (`/api/info/*`, `/api/network`), per-address (`/api/client/:address/*`, `/api/pplns/mode/:address`), PPLNS (`/api/pplns/*`), Team Mining (`/api/pplns/groups/*`), Blockparty (`/api/blockparty/*`), and email-binding endpoints. Rust-build additions include:

- `GET /api/pplns/groups/coinbase-capacity` — worst-case member ceiling for the Team Mining coinbase budget (UI shows used / free slots per team).
- `/api/address/ownership/*` — prove control of a mining address by signing a challenge.
- `/api/address/extranonce/*` — lets a Solo miner pin its own extranonce prefix per worker, see [`CUSTOM-EXTRANONCE-API.md`](CUSTOM-EXTRANONCE-API.md).

---

## Build & test

```bash
cargo build --release            # builds the `blitzpool` binary
cargo test --workspace           # unit + integration tests (about half of the tree is tests)
cargo clippy --workspace         # lints
```

Regtest-driven integration tests (TDP/IPC + RPC paths) spin up bitcoin-core via the in-tree `bp-regtest-harness`; the `bp-template-distribution` test suite is the bitcoin-core compatibility canary. The split-validation runbook lives at [`full-setup/REGTEST-SPLIT-VALIDATION.md`](full-setup/REGTEST-SPLIT-VALIDATION.md).

---

## Tech stack

Rust workspace of **35 library crates** (`bp-*`) plus the `blitzpool` binary. Async on **tokio**; HTTP on **axum**; DB on **sqlx** (Postgres); **Redis** for the share/cache/stream bus. SV2 protocol primitives from the SRI `stratum-core`; bitcoin-core IPC bridge from `sv2-apps` (`bitcoin_core_sv2`) — see [`UPSTREAM_DEPS.md`](UPSTREAM_DEPS.md).

---

## UI

The official Blitzpool web UI is not open source. The server is, and so is the HTTP API the UI is built on: the `api` role serves everything a frontend needs, from the per-miner dashboard data to the Team Mining and Blockparty admin flows and the public team directory. The endpoints live in [`crates/bp-api`](crates/bp-api). Anyone is free to build their own frontend on top of it.

---

## Credits + contact

Built by the Blitzpool team at [yourdevice.ch](https://yourdevice.ch). The non-custodial coinbase-payout design originated in the TypeScript [Blitzpool](https://github.com/warioishere/blitzpool) (itself a fork of [public-pool](https://github.com/benjamin-wilson/public-pool)); this repository is the independent Rust reimplementation.

Made in Switzerland. 🇨🇭

> *by Bitcoiners, for Bitcoiners who verify instead of trust.*
