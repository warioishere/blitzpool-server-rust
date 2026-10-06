# Deploying Blitzpool

> **Run a release, not `main`.** `main` is the development branch and can change
> config keys, migrations or behaviour without warning. To operate a pool, use
> the latest [release](https://github.com/warioishere/blitzpool-server-rust/releases)
> or the `stable` branch, which only ever points at the latest release, and read
> the release's **Upgrade notes** before every update.

This sets up a working **Solo** pool: every block pays the miner who found it.
PPLNS, Group-Solo and Blockparty are optional and switched on later by adding
config sections (see [Enabling more payout modes](#enabling-more-payout-modes)).

Everything below runs from the `simple-setup/` directory with Docker Compose.
The repository has two setups; both run every payout mode:

| | `simple-setup/` | `full-setup/` |
|---|---|---|
| Pool processes | 2 | 4 |
| Bitcoin node | bundled (optional) or your own | bundled |
| For | a new pool: start here | redeploying the API, payouts and notifications one at a time |

## What runs

| Service | What it does |
|---|---|
| `front` | Pool process with roles `front,api`: holds the miner connections (Stratum V1 and V2 on the same ports), builds and submits blocks, serves the HTTP API |
| `back` | Pool process with roles `payout,stats,notify`: books payouts, writes statistics, sends notifications |
| `postgres`, `redis` | Storage. Not published on the host |
| `bitcoin` | Optional Bitcoin Core 31 node (`--profile bitcoin`) |

`front` and `back` are the same image with the same config. They talk through
Redis streams, so `back` can restart without disconnecting a miner. They cannot
be merged into one process: the pool refuses to start with `front` and
`payout` in the same process.

## Requirements

- Linux with Docker Engine and Docker Compose **2.20 or newer** (`docker compose version`).
- **Bitcoin Core 31**, either:
  - the bundled node in this compose file (it syncs the chain itself), or
  - your own node, run as the multi-process binary `bitcoin-node` with an IPC
    socket. Plain `bitcoind` has no IPC socket and does not work.

The pool gets its block templates over that IPC socket (Template Distribution
Protocol) and uses JSON-RPC only for one-off calls.

## 1. Get the code and create the config

```bash
git clone --branch stable https://github.com/warioishere/blitzpool-server-rust.git
cd blitzpool-server-rust/simple-setup
cp ../blitzpool.example.toml blitzpool.toml
docker compose build
docker compose run --rm --no-deps front --sv2-keygen
```

The build compiles the pool and takes a while the first time. The last line
prints a new Stratum V2 key:

```
[sv2]
authority_privkey_hex = "…"

# Public key for SV2 miners and JD clients:
# 9…
```

`blitzpool.toml` holds your secrets and is ignored by git. Set these values:

| Where | What |
|---|---|
| `blitzpool.toml` `[sv2] authority_privkey_hex` | the line printed by `--sv2-keygen`. Keep it: SV2 miners pin the public key printed with it, so a new key means reconfiguring every SV2 miner |
| `blitzpool.toml` `[bitcoin_rpc] password` | the node's `rpcpassword` (next step) |
| `blitzpool.toml` `network` | `mainnet`, `testnet4` or `regtest`, matching the node |

A `.env` file next to `docker-compose.yml` is optional: it is needed for your
own node, for testnet4 or regtest on the bundled node, or to set
`PG_PASSWORD`. Start from `cp .env.example .env`. Postgres is not published on
the host, so the default password `postgres` is reachable only by the pool
containers; publish the port only after setting `PG_PASSWORD` (and the same
value in `[database] password`) on a fresh database volume.

## 2a. With the bundled node

Edit `simple-setup/bitcoin.conf` and set `rpcpassword` to the same value as
`[bitcoin_rpc] password` in `blitzpool.toml`. The default chain is mainnet;
for testnet4 or regtest set `BITCOIN_CHAIN` in `.env` (`test4`, `regtest`) and
the matching `network` and `[bitcoin_rpc] port` (48332, 18443) in
`blitzpool.toml`.

```bash
docker compose --profile bitcoin up -d --build
```

The first build compiles the pool and takes a while. On mainnet the node then
needs its initial sync (days, depending on the machine) before the pool can
serve work.

## 2b. With your own node

Run Bitcoin Core 31's `bitcoin-node` (in `libexec/` of the release tarball)
with an IPC socket in a directory of its own, and RPC reachable from Docker:

```bash
sudo mkdir -p /var/lib/bitcoin-ipc && sudo chown <node-user> /var/lib/bitcoin-ipc

bitcoin-node -server=1 \
  -ipcbind=unix:/var/lib/bitcoin-ipc/node.sock \
  -rpcuser=blitzpool -rpcpassword=<password> \
  -rpcbind=0.0.0.0 \
  -rpcallowip=127.0.0.1 -rpcallowip=172.16.0.0/12
```

(or the same options in `bitcoin.conf`). `-rpcallowip` limits RPC to the host
and Docker's networks; keep the RPC port (8332 on mainnet) closed in the
firewall as well. Then:

- `.env`: `BITCOIN_IPC_DIR=/var/lib/bitcoin-ipc`
- `blitzpool.toml`: `[bitcoin_rpc] url = "http://host.docker.internal"`

**The node must run as UID 1000**, the user the pool container runs as.
Bitcoin Core creates the socket readable and writable by its owner only, so
any other UID locks the pool out of it.

```bash
docker compose up -d --build
```

## 3. Check that it runs

```bash
docker compose ps                       # front and back "Up", postgres and redis "healthy"
docker compose logs front | grep "process live"
curl -s localhost:3334/api/health
```

`/api/health` answers `"status":"healthy"` once the database, Redis, the node
and the template feed are connected. The front logs the SV2 public key on
every start:

```bash
docker compose logs front | grep "authority public key"
```

## 4. Connect miners

| | |
|---|---|
| Stratum V1 | `stratum+tcp://<host>:3333` |
| Stratum V2 | `<host>:3333`, public key from the log line above |
| Large rigs, rented hashrate | port `3339` (starts at a higher difficulty) |
| Username | `<your bitcoin address>.<worker name>` |
| Password | anything |

The address must be valid for the configured `network`; a found block pays it
directly.

## Try it on regtest first

A private chain with CPU-minable blocks, to see the whole path work in a few
minutes. In `blitzpool.toml` set `network = "regtest"`, `[bitcoin_rpc] port =
18443`, and for a CPU miner `solo_start_difficulty = 1`. In `.env` set
`BITCOIN_CHAIN=regtest`.

```bash
docker compose --profile bitcoin up -d bitcoin
CLI="docker compose exec -T bitcoin /app/bin/bitcoin-cli -chain=regtest -rpcuser=blitzpool -rpcpassword=<password>"
$CLI createwallet test
$CLI generatetoaddress 101 "$($CLI getnewaddress)"   # the pool needs a chain to build on
docker compose --profile bitcoin up -d --build
```

Point any SHA-256 miner (for example `minerd -a sha256d`) at
`stratum+tcp://localhost:3333` with a `bcrt1…` address as username. A found
block's coinbase pays that address at once:
`$CLI getblock "$($CLI getbestblockhash)" 2`. `curl localhost:3334/api/info`
lists it too, but serves a cached answer for up to five minutes
(`[api.cache] site_info_secs`, default 300).

## Enabling more payout modes

Each mode is switched on by its section; copy them from
[`blitzpool.full.example.toml`](blitzpool.full.example.toml), which documents
every key.

| Mode | Section | Also needs |
|---|---|---|
| PPLNS | `[pplns]` | publish ports `3340` and `3349` in `docker-compose.yml` |
| Group-Solo | `[group_solo]` | `[smtp]` and `pool_base_url`: members verify an email before joining |
| Blockparty | `[blockparty]` | `[smtp]` and `pool_base_url`, as for Group-Solo |

Every mode's section carries its own `fee_address` and `fee_percent`;
nothing is inherited from another section. On Solo the fee is optional.

After a config change, restart both pool processes:

```bash
docker compose up -d --force-recreate front back
```

A section that is removed again switches its mode off. For Group-Solo the
pool refuses to start while active groups still exist, so no member is
silently moved to Solo; dissolve the groups first or keep `[group_solo]`.

## Operating

**Update:** read the **Upgrade notes** of every release since yours first;
they name config keys to remove and anything else the update needs.

```bash
git pull                                # on `stable`: the latest release
docker compose build
docker compose up -d --no-deps back     # no miner notices this
docker compose up -d --no-deps front    # miners reconnect
```

Miners only reconnect when `front` restarts. While `back` is down, shares wait
in Redis and are booked when it comes back.

**Logs:** `docker compose logs -f front` (or `back`). More detail with
`RUST_LOG=debug` in `.env`.

**Backups:** the Postgres volume holds payouts and statistics, the Redis
volume the live payout state (PPLNS window, blocks awaiting confirmation).
Back up both, for example `docker compose exec postgres pg_dump -U postgres
blitzpool > blitzpool.sql`.

**Config check without starting:**
`docker compose run --rm front --config /app/blitzpool.toml --check-config`.
It names the first missing or unknown key; the example configs list every
required one.

## Without Docker

Build with `cargo build --release` (needs Rust, `capnproto` and
`libcapnp-dev`; see the `Dockerfile`), then run the same binary twice with
the same config:

```bash
blitzpool --config blitzpool.toml --roles front,api
blitzpool --config blitzpool.toml --roles payout,stats,notify
```

with Postgres and Redis reachable at the hosts in the config, and
`[tdp] socket_path` pointing at the node's socket.

## Four processes: `full-setup/`

[`full-setup/`](full-setup/README.md) runs the API, payouts and notifications
as separate processes, so each can be redeployed alone. It is the layout the
public Blitzpool instance runs; for a new pool, `simple-setup/` is the simpler start.
