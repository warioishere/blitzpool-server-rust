#!/usr/bin/env bash
# Dump the Blitzpool Postgres schema (no data, no owners, no privileges) to stdout.
# Output is meant for db/schema.sql — read-only reference for bp-db.
#
# Usage:
#   PG_HOST=... PG_PORT=5432 PG_USER=... PG_DATABASE=public_pool \
#     PG_PASSWORD=... ./scripts/dump-pg-schema.sh > db/schema.sql
#
# All PG_* env vars are required except PG_PORT (defaults to 5432) and PG_PASSWORD
# (omitted if unset — use .pgpass or PGSERVICE for prod).

set -euo pipefail

: "${PG_HOST:?PG_HOST is required}"
: "${PG_USER:?PG_USER is required}"
: "${PG_DATABASE:?PG_DATABASE is required}"
PG_PORT="${PG_PORT:-5432}"

# pg_dump reads PGPASSWORD from env automatically.
if [[ -n "${PG_PASSWORD:-}" ]]; then
    export PGPASSWORD="$PG_PASSWORD"
fi

pg_dump \
    --host="$PG_HOST" \
    --port="$PG_PORT" \
    --username="$PG_USER" \
    --dbname="$PG_DATABASE" \
    --schema-only \
    --no-owner \
    --no-privileges \
    --no-comments \
  | grep -vE '^(SET |SELECT pg_catalog\.set_config|\\restrict |\\unrestrict )'
