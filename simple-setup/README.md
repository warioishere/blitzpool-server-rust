# simple-setup

The starting point for a new pool: two pool processes, Postgres, Valkey and
an optional Bitcoin Core 31 node, all from one `docker-compose.yml`. Every
payout mode works here; Solo is on by default, the others are switched on in
the config.

Step by step: [`../DEPLOYMENT.md`](../DEPLOYMENT.md).

| | `simple-setup/` | [`full-setup/`](../full-setup/README.md) |
|---|---|---|
| Pool processes | 2 (`front,api` + `payout,stats,notify`) | 4 (core, api, payout, notify) |
| Bitcoin node | bundled (optional) or your own | bundled |
| Storage | Docker volumes, nothing to prepare | `data/` directories, `prepare.sh` first |
| For | a new pool | redeploying the API, payouts and notifications one at a time |
