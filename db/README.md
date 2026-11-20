# DB schema + sqlx offline-cache workflow

## Schema

The whole schema lives in **`crates/bp-db/migrations/*.sql`**.
`Db::run_migrations()` applies the migrations at boot, serialised by an
advisory lock, so every process of the core/satellite split runs them safely.
A deploy needs no separate schema or migration step.

- `0000_baseline.sql` creates the base tables on an **empty** database (the
  schema as of `0016`). On a database that already has one of them, it does
  nothing and is only recorded as applied.
- `0001`… change the schema from there.

**Adding a migration:**
1. Create `crates/bp-db/migrations/NNNN_description.sql` (idempotent,
   `IF NOT EXISTS`). A binary one release older must keep running against it
   (`bp_db::with_boot_policy`).
2. Migrate the local Postgres and regenerate the sqlx cache (see below).

A migration that has been applied anywhere is **never** edited: sqlx checks
its checksum. That holds for `0000_baseline.sql` too.

## sqlx offline cache (`.sqlx/` at the repo root)

`bp-db` uses the **`sqlx::query!` / `sqlx::query_as!` macros** for
compile-time SQL validation. They need either a live Postgres at build time
OR a pre-generated cache (`.sqlx/` at the repo root, committed).

**CI / production builds** use the committed cache via `SQLX_OFFLINE=true`
(set in `.github/workflows/ci.yml`). No database access at build time.

**Dev loop when you change or add a query:**

1. Start a local Postgres (the major version the compose files run):
   ```bash
   docker run -d --name bp-test-pg \
       -p 15433:5432 \
       -e POSTGRES_DB=blitzpool \
       -e POSTGRES_USER=postgres \
       -e POSTGRES_PASSWORD=postgres \
       postgres:18
   # wait until ready: docker exec bp-test-pg pg_isready -U postgres
   ```

2. Build the schema (once after the container starts, and after a new
   migration):
   ```bash
   DATABASE_URL='postgres://postgres:postgres@localhost:15433/blitzpool' \
       cargo sqlx migrate run --source crates/bp-db/migrations
   ```

3. Regenerate the cache:
   ```bash
   DATABASE_URL='postgres://postgres:postgres@localhost:15433/blitzpool' \
       cargo sqlx prepare --workspace
   ```

4. Commit the changed `.sqlx/query-*.json` files.

5. Check that offline mode still builds:
   ```bash
   unset DATABASE_URL
   SQLX_OFFLINE=true cargo check --workspace
   ```

**Rule:** run `cargo sqlx prepare` only against a local container, never
against a shared or production database.

## What lives here

Only this README. `.gitignore` is an allow-list: local data dumps in this
folder stay uncommitted, since they hold miner addresses, emails and tokens.
