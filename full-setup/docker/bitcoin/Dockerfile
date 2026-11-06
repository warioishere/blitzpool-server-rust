# Bitcoin Core 32 for blitzpool-rust, one image for every network. The
# compose service picks the network: mainnet runs the default command,
# testnet4 and regtest pass their own (`-testnet4`, `-regtest`).
#
# Uses the multi-process binary `libexec/bitcoin-node` (NOT the
# monolithic `bin/bitcoind`). Only the multi-process build exposes
# the TDP IPC server that blitzpool-rust subscribes to via Unix
# domain socket. The official `bitcoin/bitcoin` Docker image
# does NOT ship `bitcoin-node`, hence the tarball install.

FROM debian:bookworm-slim AS build

ARG BITCOIN_CORE_VER=32.1
# SHA-256 of the release tarballs as listed in that release's SHA256SUMS,
# which the Guix builders sign. Another BITCOIN_CORE_VER needs its own two
# values; the build stops when the tarball does not match.
ARG BITCOIN_CORE_SHA256_X86_64=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
ARG BITCOIN_CORE_SHA256_AARCH64=7ed37c7373eb6aa3e3f72842596a1afeba1b223717033cade9842b25773e1922
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN set -eu \
    && case "${TARGETARCH:-amd64}" in \
         amd64) ARCH=x86_64-linux-gnu; SHA256="${BITCOIN_CORE_SHA256_X86_64}" ;; \
         arm64) ARCH=aarch64-linux-gnu; SHA256="${BITCOIN_CORE_SHA256_AARCH64}" ;; \
         *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && TARBALL="bitcoin-${BITCOIN_CORE_VER}-${ARCH}.tar.gz" \
    && curl -fsSLo "/tmp/${TARBALL}" \
         "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_CORE_VER}/${TARBALL}" \
    && echo "${SHA256}  /tmp/${TARBALL}" | sha256sum -c - \
    && tar xzf "/tmp/${TARBALL}" --strip-components=1 \
    && rm "/tmp/${TARBALL}"

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

# Ports are published per network by the compose file.

ENTRYPOINT ["/usr/bin/tini", "--", "/app/libexec/bitcoin-node"]
CMD ["-printtoconsole", "-datadir=/app/data", "-conf=/app/data/bitcoin.conf", "-ipcbind=unix:/ipc/node.sock"]
