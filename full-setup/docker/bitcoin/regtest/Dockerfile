# Bitcoin Core 31 — regtest build for blitzpool-rust.
#
# Uses the multi-process binary `libexec/bitcoin-node` (NOT the
# monolithic `bin/bitcoind`). Only the multi-process build exposes
# the TDP IPC server that blitzpool-rust subscribes to via Unix
# domain socket. The official `bitcoin/bitcoin:31` Docker image
# does NOT ship `bitcoin-node`, hence the tarball install.

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

# UID 1000 matches blitzpool-rust's runtime user so the IPC socket
# in the shared /ipc volume is r/w from both sides.
RUN groupadd --system --gid 1000 bitcoin \
    && useradd --system --uid 1000 --gid 1000 --home-dir /app --shell /usr/sbin/nologin bitcoin \
    && mkdir -p /app/data /ipc \
    && chown -R bitcoin:bitcoin /app /ipc

# We only need bin/bitcoin-cli + libexec/bitcoin-node from the tarball.
# Dropping bitcoind, bitcoin-qt, test_bitcoin etc. keeps the runtime
# layer minimal (~80 MB instead of ~250 MB).
COPY --from=build --chown=bitcoin:bitcoin /app/bin/bitcoin-cli /app/bin/bitcoin-cli
COPY --from=build --chown=bitcoin:bitcoin /app/libexec/bitcoin-node /app/libexec/bitcoin-node

USER bitcoin
WORKDIR /app

# Regtest RPC defaults to :18443. No P2P port exposed.
EXPOSE 18443

ENTRYPOINT ["/usr/bin/tini", "--", "/app/libexec/bitcoin-node"]
CMD ["-printtoconsole", "-regtest", "-datadir=/app/data", "-conf=/app/data/bitcoin.conf", "-ipcbind=unix:/ipc/node.sock"]
