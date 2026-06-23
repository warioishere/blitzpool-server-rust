# Two-process split validation on regtest

The one empirical step the automated tests don't cover: run the split as
**two real processes** against a regtest node, find a block from a real
miner, and confirm (a) bitcoin-core accepts it and (b) the satellite applies
the ledger — including across a `payout` restart. Proves the *deployment*
(the validity logic is already proven by `regtest_split_e2e.rs` + the
in-process regtest tests).

Uses the server-local `docker-compose-regtest-pg-split.yml` (core / api /
payout, `blitzpool-regtest.toml`). Commands assume the test server's
regtest node container `blitzpool-bitcoin-regtest` (bitcoin-cli at
`/app/bin/bitcoin-cli`, rpc `bitcoin:bitcoin`).

```bash
cd full-setup
COMPOSE="-f docker-compose-regtest-pg-split.yml"
BCLI="docker exec blitzpool-bitcoin-regtest /app/bin/bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin"
```

## 1. Bring up the split stack

```bash
docker compose $COMPOSE up -d --build
docker compose $COMPOSE ps                       # postgres, redis, bitcoin-regtest, core, api, payout, notify up
docker logs blitzpool-core   2>&1 | grep "bound: process live"   # roles=[Front]  stratum_ports=Some([...])
docker logs blitzpool-payout 2>&1 | grep -E "consumer: live"     # money/stats-session/block-found(ledger)/rejected live
docker logs blitzpool-notify 2>&1 | grep -E "consumer: live"     # block-found(notify) + device-status live
```

## 2. Initialise the chain (IBD-exit + coinbase maturity)

TDP only emits templates once the node has a tip + a spendable subsidy, so
mine 101 blocks to a throwaway regtest address:

```bash
ADDR=bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l   # any bcrt1 address
$BCLI generatetoaddress 101 $ADDR
$BCLI getblockcount                                  # 101
docker logs --tail 20 blitzpool-core 2>&1 | grep -i "template"   # core is now serving jobs
```

## 3. Point a miner at the core

Connect your regtest stratum miner to the **core** (not the api/payout):

* PPLNS: `stratum+tcp://<server-ip>:3340`
* Solo:  `stratum+tcp://<server-ip>:3333`

Username = a regtest payout address (`bcrt1q…`), optionally `.worker`.
Regtest network difficulty is trivial, so accepted shares meet the network
target almost immediately → the pool finds a block fast.

## 4. Confirm bitcoin-core accepted the pool-built block

```bash
$BCLI getblockcount                                              # rises past 101
docker logs --tail 80 blitzpool-core 2>&1 \
  | grep -iE "block-found: submitting solution|published to stream"
```

A rising block count = **bitcoin-core accepted the coinbase the split built**
(sat sums, scripts, witness commitment, merkle root all valid). A stuck tip
would mean the coinbase was rejected — that's the thing this run rules out.

## 5. Confirm the satellite applied the ledger

```bash
docker logs --tail 80 blitzpool-payout 2>&1 \
  | grep -iE "block-found-consumer: applied|on_block_found|ledger applied"
# PPLNS balances written for the block:
$BCLI getblockcount   # note the height H, then:
docker exec blitzpool-postgres psql -U postgres -d public_pool \
  -c 'SELECT address, "balanceSats" FROM pplns_balance ORDER BY "updatedAt" DESC LIMIT 5;'
```

## 6. The split's point: restart payout mid-mining

With the miner still hashing, recreate **only** the payout process:

```bash
docker compose $COMPOSE build blitzpool-payout                  # old keeps running
docker compose $COMPOSE up -d --no-deps blitzpool-payout        # swap payout only
```

Expect:

* the miner **stays connected** (core untouched) and keeps submitting;
* while payout is down, shares + any block-found buffer in the Redis streams;
* on restart, `blitzpool-payout` logs `consumer: live`, drains the pending
  backlog (`drained pending backlog` / `applied + acked`), and the windows /
  balances catch up — nothing lost.

## Teardown

```bash
docker compose $COMPOSE down            # keeps ./data (chain + PG + redis)
# docker compose $COMPOSE down -v       # also wipes the regtest chain/state
```
