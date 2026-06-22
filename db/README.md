# DB Schema Reference + sqlx Offline-Cache Workflow

Dieser Ordner enthält den **Schema-Snapshot** der produktiven Blitzpool-PG-Datenbank.
Er dient als Read-Only-Referenz für den sqlx-Offline-Cache (`bp-db` schreibt
`sqlx`-Queries gegen dieses Schema).

## Schema-Migrationen (Rust-seitig)

Schema-Änderungen laufen jetzt über **sqlx-Migrationen** in
`crates/bp-db/migrations/*.sql` (versioniert, idempotent via `IF NOT EXISTS`).
`Db::run_migrations()` wendet sie beim Boot an — Advisory-Lock-serialisiert, also
fahren alle Prozesse im Core/Satellite-Split die Migration gefahrlos. Der
Deploy braucht keinen separaten Migrations-Schritt mehr.

`schema.sql` bleibt der **Baseline-Snapshot** für frische DBs + die sqlx-Offline-
Validierung; bei jeder neuen Migration wird die betroffene `CREATE TABLE` hier
nachgezogen, damit Snapshot + Migrationen denselben Zielzustand beschreiben.

**Neue Migration hinzufügen:**
1. `crates/bp-db/migrations/NNNN_beschreibung.sql` anlegen (idempotentes
   `ALTER TABLE ... IF NOT EXISTS`).
2. Die `CREATE TABLE` in `db/schema.sql` auf den neuen Zielzustand anpassen.
3. Lokales Postgres migrieren + sqlx-Cache regenerieren (siehe unten).

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

2. Schema laden (einmal nach Container-Start oder wenn `db/schema.sql` aktualisiert wurde):
   ```bash
   docker exec -i blitzpool-rust-pg psql -U postgres -d public_pool < db/schema.sql
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
nur gegen lokalen Docker-Container. Siehe `feedback-local-services-for-tests`
in der Memory.

## Was hier liegt

| File | Zweck |
|---|---|
| `schema.sql` | `pg_dump --schema-only` Output. Wird committed. Wird beim Wechsel des prod-Schemas neu erzeugt. |
| `.gitignore` | Allow-list: nur `README.md` + `schema.sql` + `*.example` werden committed. Daten-Dumps bleiben lokal. |

## Wie aktualisieren

### Option A — aus laufender prod-PG (Read-Only)

```bash
PG_HOST=... PG_PORT=5432 PG_USER=... PG_DATABASE=public_pool \
  ./scripts/dump-pg-schema.sh > db/schema.sql
```

Das Skript ruft `pg_dump --schema-only --no-owner --no-privileges` auf und strippt
TypeORM-spezifische Boilerplate (Search-Path, `SET` Statements) raus.

### Option B — aus frischem TS-Pool-Boot (lokal)

Wenn keine prod-Verbindung möglich oder gewünscht:

1. Lokale PG starten (z.B. `docker run postgres:16`).
2. TS-Pool aus `../blitzpool` mit `DB_TYPE=postgres` + `DB_RUN_MIGRATIONS=true` einmal hochfahren.
   Migrations unter `../blitzpool/src/migrations/*.ts` laufen automatisch durch.
3. Pool wieder stoppen (Schema steht, Daten leer).
4. Dump ziehen wie in Option A.

Option B ist reproduzierbar ohne prod-Zugang und damit der bevorzugte Pfad
für CI-Schema-Validierung später.

## Was NICHT hier liegt

- **Keine Daten-Dumps** (`pg_dump --data-only`). Enthält Miner-Adressen, Emails, Tokens.
- **Keine Migration-Files hier.** Die liegen in `crates/bp-db/migrations/` (siehe
  oben „Schema-Migrationen"). Dieser Ordner hält nur den Baseline-Snapshot.
- **Keine sqlx-offline-Cache-Files** (`.sqlx/*.json`). Die landen in `crates/bp-db/.sqlx/`,
  nicht hier.
