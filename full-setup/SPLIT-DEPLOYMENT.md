# Split deployment runbook (core / api / payout / notify)

Run blitzpool as **four processes** from one image + one shared config so a
back-office fix can be deployed by recreating a single container — the
**miners never reconnect** (the core stays up), the **API/charts stay up** when
payout restarts, and the **payout (PPLNS) ledger stays up** when you ship a
notification change.

| Container | `BLITZPOOL_ROLES` | Holds | Restart impact |
|---|---|---|---|
| `blitzpool-core` | `front` | Stratum listeners + share producer + block submit + JDP | **miners reconnect** — avoid unless fixing the share path / coinbase math |
| `blitzpool-api` | `api` | read-only HTTP API (charts, admin) | none (read-only; recreate freely) |
| `blitzpool-payout` | `payout,stats` | PPLNS + Group-Solo + Blockparty ledger (block-found ledger apply), confirmation watcher, maintenance crons, statistics | API + miners + notifications unaffected; a few seconds of accounting lag, then catches up |
| `blitzpool-notify` | `notify` | dispatcher (FCM/Web-Push/Telegram/ntfy), command listeners, notification crons (network-/best-difficulty, hourly stats), notify-only fan-out of block-found + device-status | payout + API + miners unaffected; recreate freely for a notification change |

All four share `../.local/blitzpool.toml`. The topology comes from
`BLITZPOOL_ROLES` (env), which overrides `mode`/`roles` in the file — so you
keep editing one config.

> **`payout` and `notify` must both run.** Splitting notifications out means the
> `payout,stats` process holds **no dispatcher** — it logs a loud `WARN` at boot
> if it can't see a notify role, and notifications simply won't fire until a
> `notify` process is up. (The `monolith` / `satellite` *modes* still bundle
> notify by default; only an explicit `BLITZPOOL_ROLES` split separates them.)

## How it stays consistent

* Core → Satellite over Redis streams: the core `XADD`s accepted/rejected
  shares, block-found events, and device-status (miner online/offline) events.
  The payout process consumes accepted/rejected + block-found *for the ledger*;
  the notify process consumes block-found + device-status *for the push*. Each
  consumer is its own group, so payout and notify drain the same block-found
  stream independently.
* While `blitzpool-payout` (or `notify`) is down, events **buffer in the Redis
  stream** (capped at ~1M entries ≈ hours). On restart it resumes from the
  consumer-group offset (pending backlog first, then new) — nothing lost for a
  normal restart.
* Only the **core** needs the bitcoin-core IPC socket (TDP is front-only); the
  `api`, `payout`, and `notify` containers don't mount it.

## Bring-up

1. Start the infra (postgres / redis / bitcoin) from the main compose:

   ```bash
   cd full-setup
   docker compose --profile mainnet up -d postgres redis bitcoin-mainnet
   ```

2. Start the four blitzpool processes:

   ```bash
   docker compose -f docker-compose.split.yml up -d
   ```

3. Verify the roles each process took:

   ```bash
   docker logs blitzpool-core   2>&1 | grep "bound: process live"   # roles=[Front]  stratum_ports=Some([...])
   docker logs blitzpool-api    2>&1 | grep "bound: process live"   # roles=[Api]    api=Some(0.0.0.0:3334)
   docker logs blitzpool-payout 2>&1 | grep -E "consumer: live|bound: process live"   # roles=[Payout, Stats]  block-found-consumer action=ledger live
   docker logs blitzpool-notify 2>&1 | grep -E "consumer: live|bound: process live"   # roles=[Notify]  block-found-consumer action=notify + device-status-consumer live
   ```

> Do **not** also run the monolith `blitzpool-mainnet` service — it and the
> split processes would both bind the stratum/api ports and both consume the
> streams.

## Deploying a fix (build-then-swap, minimal downtime)

> The examples use `$COMPOSE` for the compose file so they work regardless of
> its name. Set it once per shell:
>
> ```bash
> COMPOSE="-f docker-compose-mainnet-pg-split.yml"   # test server
> # COMPOSE="-f docker-compose.split.yml"            # repo example
> ```

A deploy is **two separate steps** — and that's what gives you near-zero
downtime:

1. **`docker compose $COMPOSE build <service>`** — builds the new image. The
   **old container keeps running the whole time**; `build` never touches a
   running container. This is the slow part, and it has **zero downtime**.
2. **`docker compose $COMPOSE up -d --no-deps <service>`** — only *now* stops
   the old container and starts the new one. This is the only downtime: a
   **few seconds**, for that one service.

`--no-deps` means "recreate only this service, leave its `depends_on`
(postgres / redis / bitcoin) alone" — so the swap never disturbs the core or
the infra.

> **Always name the service in the `up`.** All three services share
> `image: blitzpool:latest`, so `build` updates that shared tag. A bare
> `docker compose $COMPOSE up -d` would then also recreate `core` + `api` onto
> the new image — i.e. disconnect the miners. Naming the service (with
> `--no-deps`) keeps the swap surgical.

**Accounting / payout / stats fix** (most common — PPLNS ledger, Group-Solo,
Blockparty, crons, notifications, charts data) → recreate only `payout`:

```bash
docker compose $COMPOSE build blitzpool-payout              # builds; old payout keeps running
docker compose $COMPOSE up -d --no-deps blitzpool-payout   # ~seconds swap, payout only
#   → core + api untouched → miners stay connected, API/charts stay up.
#   While payout is down the shares buffer in the Redis stream; on restart it
#   resumes from the consumer-group offset and catches up — nothing lost.
```

**Notification fix** (FCM/Web-Push/Telegram/ntfy adapters, push/digest crons,
block-found / device-status / best-diff message rendering, bot commands) →
recreate only `notify`:

```bash
docker compose $COMPOSE build blitzpool-notify
docker compose $COMPOSE up -d --no-deps blitzpool-notify
#   → core + api + payout (PPLNS) untouched → the ledger never restarts for a
#   notification change. While notify is down, block-found/device-status events
#   buffer in their streams; on restart it drains the backlog and fires the
#   pending pushes.
```

**API / admin fix** (routes, read views) → recreate only `api`:

```bash
docker compose $COMPOSE build blitzpool-api
docker compose $COMPOSE up -d --no-deps blitzpool-api
#   → core + payout + notify untouched.
```

**Front / share-path / coinbase-distribution-math fix** (Stratum, vardiff,
validation, `build_distribution`) → recreate `core`. This *does* bump the
miners, because the coinbase is built on the core:

```bash
docker compose $COMPOSE build blitzpool-core
docker compose $COMPOSE up -d --no-deps blitzpool-core
#   → miners reconnect (unavoidable for this class of change).
```

**Verify the swap took:**

```bash
docker compose $COMPOSE ps                              # the recreated container shows a fresh "Up <seconds>"
docker logs --tail 20 blitzpool-payout 2>&1 | grep -E "engines ready|consumer: live"
```

> **Build everything once, swap selectively.** You can `docker compose $COMPOSE
> build` (no service) to rebuild the shared image once, then swap each process
> on your own schedule with separate `up -d --no-deps <service>` calls. The
> build doesn't restart anything; only the `up` does.
>
> A few seconds of swap downtime for one back-office service is the design's
> accepted floor (the satellite is restartable; shares buffer). True
> zero-gap (blue-green: a second container + a proxy flip) is deliberately not
> done here — it's not worth the complexity for a process whose lag the Redis
> stream already absorbs.

## Which fix goes where

* **Notifications** (dispatcher adapters, push/digest/best-diff crons,
  block-found / device-status push, Telegram/ntfy bot commands) →
  `blitzpool-notify` → no miner disconnect, **payout untouched**.
* **Accounting ledger** (record_share, on_block_found ledger apply, balances,
  payouts), confirmation watcher, maintenance crons, statistics →
  `blitzpool-payout` → no miner disconnect.
* **API / admin** (routes, read views) → `blitzpool-api` → no miner disconnect.
* **Stratum protocol, vardiff, share validation, template/job handling, and
  the coinbase distribution *math* (`build_distribution`)** → `blitzpool-core`
  → miners reconnect. (The math runs on the core because the core builds the
  coinbase.)

## Caveats

* **API block-template endpoint**: `/info/block-template` needs TDP, which is
  front-only, so it returns 503 on the `api` process. Everything else
  (balances, charts, stats, admin) needs no TDP and works fully.
* **One shared config**: keep `mode`/`roles` *out* of `blitzpool.toml` (or
  leave `mode` at its default) — `BLITZPOOL_ROLES` in the compose file is what
  decides each process's topology.
* **Notify must be running**: with an explicit `BLITZPOOL_ROLES` split, the
  `payout,stats` process holds no dispatcher — notifications only fire if a
  `notify` process is up. The payout process logs a loud `WARN` at boot when it
  runs accounting without notify. (The `monolith` / `satellite` *modes* bundle
  notify automatically; the warning is only about explicit role splits.)
* **`payout` and `stats` not yet split from each other**: they run in one
  process for now (the statistics flush loop must be single-writer). To split
  them later set `BLITZPOOL_ROLES=payout` and `BLITZPOOL_ROLES=stats` on two
  containers — but that needs the engine-layer single-writer work first; don't
  do it yet. (`notify` *is* fully split out — that's this section's whole
  point.)

## Rollback

Re-deploy the previous image tag for the affected container only:

```bash
docker compose -f docker-compose.split.yml up -d --no-deps <service>   # with the old image
```

The core is never part of a back-office rollback, so miners are unaffected.
