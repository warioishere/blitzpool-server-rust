#!/usr/bin/env bash
# Prepare the on-disk layout for the blitzpool-rust docker-compose
# stack. Creates the persistent data directories with the right
# ownership (UID:GID 1000:1000 for bitcoin + blitzpool's service
# users) so `docker compose up` doesn't fail on EACCES.
#
# Usage:
#   ./prepare.sh
#
# Run once before the first `docker compose --profile <network> up`.
# Idempotent — safe to re-run.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DATA="$ROOT/data"

echo "[+] preparing $DATA/ ..."

# postgres + redis: their containers run as their own service users
# (postgres=70, valkey=999) and initialize the directories themselves.
# We create them via a busybox container to sidestep the
# "host user can't chown" / "docker created dir as root" problem.
docker run --rm -v "$DATA:/data" alpine sh -c '
    mkdir -p \
        /data/bitcoin-mainnet \
        /data/bitcoin-testnet4 \
        /data/bitcoin-regtest \
        /data/postgres \
        /data/redis \
        /data/blitzpool-logs
    # bitcoin + blitzpool both run as UID 1000.
    chown -R 1000:1000 \
        /data/bitcoin-mainnet \
        /data/bitcoin-testnet4 \
        /data/bitcoin-regtest \
        /data/blitzpool-logs
'

mkdir -p "$ROOT/../.local"

echo "[+] checking required configs ..."
LOCAL="$ROOT/../.local"
[ -f "$LOCAL/blitzpool.toml" ] || \
    echo "[!] $LOCAL/blitzpool.toml missing (needed for --profile mainnet)"
[ -f "$LOCAL/blitzpool-testnet4.toml" ] || \
    echo "[!] $LOCAL/blitzpool-testnet4.toml missing (needed for --profile testnet4)"
[ -f "$LOCAL/blitzpool-regtest.toml" ] || \
    echo "[!] $LOCAL/blitzpool-regtest.toml missing (needed for --profile regtest)"

echo "[✓] layout ready. Bring a profile up (starts infra + core/api/payout/notify)."
echo "  mainnet uses blitzpool.toml by default:"
echo "    docker compose --profile mainnet  up -d --build"
echo "  testnet4 / regtest pick their config via BLITZPOOL_CONFIG:"
echo "    BLITZPOOL_CONFIG=blitzpool-testnet4.toml docker compose --profile testnet4 up -d --build"
echo "    BLITZPOOL_CONFIG=blitzpool-regtest.toml  docker compose --profile regtest  up -d --build"
