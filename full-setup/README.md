# blitzpool-rust — docker-compose stack

Single `docker-compose.yml`. Profiles select the bitcoin network (mainnet /
testnet4 / regtest); one shared postgres + valkey back every network. The
pool itself runs as **four processes** from one image + one shared config,
differing only by `BLITZPOOL_ROLES` — `core` (front), `api`, `payout,stats`,
`notify`. There is no single-process "monolith": the front and the back must
run separately so a back-office fix redeploys without dropping miners (see
`DEPLOYMENT.md`).

| Profile  | Stratum host ports (on `core`) | API (on `api`) | bitcoin host RPC port |
|----------|--------------------------------|----------------|------------------------|
| mainnet  | 3333 / 3339 / 3340 / 3349 / 3335 / 3337 | 3334 | 127.0.0.1:8332 |
| testnet4 | 3333 / 3339 / 3340 / 3349 / 3335 / 3337 | 3334 | 127.0.0.1:48332 |
| regtest  | 3333 / 3339 / 3340 / 3349 / 3335 / 3337 | 3334 | 127.0.0.1:28443 |

Only one profile can be active at a time — bitcoin's IPC socket is on
a single shared named volume (`blitzpool-ipc`) and all profiles share
the same host port numbers.

## What's in the stack

- **postgres** — `postgres:18-alpine`. Single shared instance. The
  TS-pool's TypeORM schema (`../db/schema.sql`) is auto-applied to
  the empty data volume on first boot.
- **redis** — `valkey/valkey:8-alpine` with AOF + `everysec` fsync,
  `volatile-lru` eviction.
- **bitcoin-{mainnet,testnet4,regtest}** — Bitcoin Core 31's
  multi-process build (`libexec/bitcoin-node`). Per-network
  Dockerfile under `docker/bitcoin/`.
- **blitzpool-{core,api,payout,notify}** — the Rust pool, built once
  from the repo-root `Dockerfile` and run as four role-gated processes:
  - `core` (`roles=front`) — Stratum listeners + share producer + block
    submit + JDP. Holds the miner connections; the only process that needs
    the bitcoin IPC socket.
  - `api` (`roles=api`) — read-only HTTP API (charts / admin).
  - `payout` (`roles=payout,stats`) — accounting ledger + stream consumers
    + maintenance crons + statistics.
  - `notify` (`roles=notify`) — dispatcher (FCM / Web-Push / Telegram /
    ntfy) + command listeners + notification crons.

## bitcoin ↔ blitzpool: two channels

- **TDP IPC** over the shared `/ipc/node.sock` (Unix socket on the
  named volume `blitzpool-ipc`). High-throughput template stream —
  per-template hot path. Only the `core` process mounts it.
- **JSON-RPC** over the internal docker network (`http://bitcoin:8332`
  etc.). Used for one-shot calls: `getblockchaininfo` (PPLNS window
  size needs current network difficulty), `submitblock` (fallback +
  JDP orphan path), chain-tip stale-detection reads.

## First-run checklist

```bash
cd full-setup/

# 1. Create + chown the persistent data dirs (idempotent, safe to re-run).
./prepare.sh

# 2. Per network, edit the matching toml in ../.local/ (gitignored).
#    mainnet  → ../.local/blitzpool.toml
#    testnet4 → ../.local/blitzpool-testnet4.toml
#    regtest  → ../.local/blitzpool-regtest.toml
#
# A regtest example with sane defaults already lives at the path above.
# Copy + adapt for testnet4 / mainnet as needed. Keep `roles` OUT of the
# toml — BLITZPOOL_ROLES in the compose file decides each process's role.

# 3. Bring up exactly one network (starts infra + the four pool processes).
#    mainnet uses ../.local/blitzpool.toml by default:
docker compose --profile mainnet up -d --build
#    testnet4 / regtest point BLITZPOOL_CONFIG at their config:
BLITZPOOL_CONFIG=blitzpool-regtest.toml docker compose --profile regtest up -d --build

# First build pulls Core 31 (~70 MB) + compiles the Rust workspace
# (~10-15 min the first time; cargo-chef caches deps so subsequent
# builds are seconds). All four pool processes share the one image.

# 4. Tail logs.
docker compose logs -f blitzpool-core      # the front / miner-facing process
```

## Switching networks

```bash
# Stop the current profile.
docker compose --profile mainnet down

# Bring up another. Shared postgres + redis stay up across switches.
BLITZPOOL_CONFIG=blitzpool-testnet4.toml docker compose --profile testnet4 up -d
```

## Operating

The pool is four processes — recreate only the one your change touches, and
the others (and the miners) stay up. See `DEPLOYMENT.md` for the full
build-then-swap matrix.

```bash
# Ship an accounting/payout fix without dropping miners (core + api stay up).
docker compose build blitzpool-payout
docker compose up -d --no-deps blitzpool-payout

# Tail any service.
docker compose logs -f bitcoin-mainnet

# Stop everything (volumes persist — chain + DB + redis kept).
docker compose --profile mainnet down

# WIPE: stop + delete all data volumes. Drops the chain, DB, redis,
# pool logs. Never run on production.
docker compose --profile mainnet down -v
./prepare.sh        # recreate empty data dirs
```

## Data layout

Persistent state lives under `full-setup/data/`, gitignored:

```
data/
├── bitcoin-mainnet/          # full mainnet chain + chainstate
├── bitcoin-testnet4/         # testnet4 chain
├── bitcoin-regtest/          # regtest chain
├── postgres/                 # shared PG cluster
├── redis/                    # AOF + RDB
└── blitzpool-logs/           # pool tracing-JSON (all processes, all profiles)
```

Plus `../.local/` (also gitignored) for the TOML configs, SV2
authority keys, FCM service-account JSON, web-push VAPID keys.

## Database name

Default `PG_DATABASE=public_pool` matches the TS-pool legacy schema
name. When attaching to an existing prod DB the env override
mechanism is in `.env.example` — copy to `.env` and uncomment.

## Image sizes (approximate)

| Service   | Image base                     | Compressed |
|-----------|--------------------------------|------------|
| bitcoin   | debian:bookworm-slim + bitcoin | ~30 MB     |
| postgres  | postgres:18-alpine             | ~110 MB    |
| redis     | valkey/valkey:8-alpine         | ~10 MB     |
| blitzpool | debian:bookworm-slim + binary  | ~30 MB     |

The four pool processes all run the one `blitzpool:latest` image. Build
images (rust:1.93-slim, debian build stages) are discarded after the final
image is assembled.

## Schema sync

The PG schema is owned by the TS pool's TypeORM migrations. To
refresh `db/schema.sql` from a running prod DB, see `../db/README.md`
— never commit data dumps (only `--schema-only` output).
