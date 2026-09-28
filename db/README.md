# DB-Schema + sqlx Offline-Cache Workflow

## Schema

Das ganze Schema liegt in **`crates/bp-db/migrations/*.sql`**.
`Db::run_migrations()` wendet die Migrationen beim Boot an — Advisory-Lock-
serialisiert, also fahren alle Prozesse im Core/Satellite-Split sie gefahrlos.
Der Deploy braucht keinen separaten Schema- oder Migrations-Schritt.

- `0000_baseline.sql` legt auf einer **leeren** DB die Basis-Tabellen an (Stand
  nach `0016`). Auf einer DB, die schon eine davon hat (prod, Testserver, alte
  TS-Pool-DB), tut sie nichts und wird nur als angewandt eingetragen.
- `0001`… ändern das Schema danach wie gehabt.

**Neue Migration hinzufügen:**
1. `crates/bp-db/migrations/NNNN_beschreibung.sql` anlegen (idempotent,
   `IF NOT EXISTS`). Sie muss ein Binary eine Version älter weiter laufen
   lassen (`bp_db::with_boot_policy`).
2. Lokales Postgres migrieren + sqlx-Cache regenerieren (siehe unten).

Eine einmal irgendwo angewandte Migration wird **nie** editiert — sqlx prüft
ihre Checksumme. Das gilt auch für `0000_baseline.sql`.

## sqlx-Offline-Cache (`.sqlx/` im Repo-Root)

`bp-db` nutzt **`sqlx::query!` / `sqlx::query_as!` Makros** für compile-time
SQL-Validierung. Diese brauchen entweder eine Live-PG-Verbindung beim Build
ODER einen vorab generierten Cache (`.sqlx/` im Repo-Root, committet).

**CI / Production builds:** Nutzen den committeten Cache via `SQLX_OFFLINE=true`
(in `.github/workflows/ci.yml` gesetzt). Kein DB-Zugriff beim Build nötig.

**Dev-Loop wenn du eine Query änderst/hinzufügst:**

1. Lokales Postgres starten (matched die prod-Version 18.1):
   ```bash
   docker run -d --name blitzpool-rust-pg --rm \
       -p 15433:5432 \
       -e POSTGRES_DB=public_pool \
       -e POSTGRES_USER=postgres \
       -e POSTGRES_PASSWORD=postgres \
       postgres:18
   # warten bis ready: docker exec blitzpool-rust-pg pg_isready -U postgres
   ```

2. Schema bauen (einmal nach Container-Start oder nach einer neuen Migration):
   ```bash
   DATABASE_URL='postgres://postgres:postgres@localhost:15433/public_pool' \
       cargo sqlx migrate run --source crates/bp-db/migrations
   ```

3. Cache regenerieren:
   ```bash
   DATABASE_URL='postgres://postgres:postgres@localhost:15433/public_pool' \
       cargo sqlx prepare --workspace
   ```

4. Die geänderten `.sqlx/query-*.json` Files committen.

5. Verifikation dass Offline-Mode noch durchläuft:
   ```bash
   unset DATABASE_URL
   SQLX_OFFLINE=true cargo check --workspace
   ```

**Regel:** Nie `cargo sqlx prepare` gegen den test-server oder prod ausführen —
nur gegen lokalen Docker-Container.

## Was hier liegt

Nur diese README. `.gitignore` ist eine Allow-list: lokale Daten-Dumps in
diesem Ordner bleiben uncommittet — sie enthalten Miner-Adressen, Emails,
Tokens.
