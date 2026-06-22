# Bitcoin Core 31 — mainnet build for blitzpool-rust.
#
# Uses `libexec/bitcoin-node` (multi-process build) — required for
# TDP IPC. See regtest/Dockerfile for the full rationale.

FROM debian:bookworm-slim AS build

ARG BITCOIN_CORE_VER=31.0
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN set -eu \
    && case "${TARGETARCH:-amd64}" in \
         amd64) ARCH=x86_64-linux-gnu ;; \
         arm64) ARCH=aarch64-linux-gnu ;; \
         *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSL \
         "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_CORE_VER}/bitcoin-${BITCOIN_CORE_VER}-${ARCH}.tar.gz" \
       | tar xzf - --strip-components=1

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 bitcoin \
    && useradd --system --uid 1000 --gid 1000 --home-dir /app --shell /usr/sbin/nologin bitcoin \
    && mkdir -p /app/data /ipc \
    && chown -R bitcoin:bitcoin /app /ipc

COPY --from=build --chown=bitcoin:bitcoin /app/bin/bitcoin-cli /app/bin/bitcoin-cli
COPY --from=build --chown=bitcoin:bitcoin /app/libexec/bitcoin-node /app/libexec/bitcoin-node

USER bitcoin
WORKDIR /app

EXPOSE 8332 8333 28332

ENTRYPOINT ["/usr/bin/tini", "--", "/app/libexec/bitcoin-node"]
CMD ["-printtoconsole", "-datadir=/app/data", "-conf=/app/data/bitcoin.conf", "-ipcbind=unix:/ipc/node.sock"]
