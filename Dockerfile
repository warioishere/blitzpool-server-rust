# syntax=docker/dockerfile:1.7
#
# blitzpool-rust container image — multi-stage.
#
# Stage 1 (cargo-chef plan):  generate a recipe of all workspace deps so
#                             stage 2 can be cached cleanly.
# Stage 2 (cargo-chef cook):  build all 3rd-party deps. Cached as long as
#                             Cargo.toml / Cargo.lock are unchanged.
# Stage 3 (build):            compile blitzpool-rust workspace.
# Stage 4 (runtime):          debian:bookworm-slim with the binary + a
#                             non-root user. No build toolchain.

ARG RUST_VERSION=1.93
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS chef
# The slim image lacks the toolchain bits cargo-chef + sqlx-cli + a few
# sys-deps need at build time. Install in one layer, no apt cache.
# `build-essential` (gcc + make) is required to compile jemalloc from C
# source via `tikv-jemalloc-sys` (the global allocator on linux); without
# it `cargo build` panics with `make: No such file or directory`. It lands
# only in the builder stages — the runtime image below stays slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        ca-certificates \
        capnproto \
        libcapnp-dev \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install cargo-chef --locked --version ^0.1
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# BuildKit cache mounts persist `target/` + the cargo registry across
# Docker builds on the same daemon. Without them, every source change
# invalidates the `COPY . .` layer below and the workspace crates
# (~30 of them) re-compile from scratch — ~5 min per build. With the
# cache mounts, only crates whose source actually changed re-compile.
#
# Cache-mount data is NOT propagated into the final image, so the
# binary must be `cp`'d out to a regular filesystem path within the
# same `RUN` step before the mount detaches. The runtime stage then
# COPYs from `/usr/local/bin/blitzpool` (regular path) instead of
# `target/release/blitzpool` (cache-mount path).
RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
ENV SQLX_OFFLINE=true
RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bin blitzpool \
    && cp target/release/blitzpool /usr/local/bin/blitzpool

FROM debian:${DEBIAN_VERSION}-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. UID 1000 matches the bitcoin container so the shared
# IPC volume is read/writable on both sides without extra chowning.
RUN groupadd --system --gid 1000 blitzpool \
    && useradd  --system --uid 1000 --gid 1000 --home-dir /app --shell /usr/sbin/nologin blitzpool \
    && mkdir -p /app /app/logs /app/keys \
    && chown -R blitzpool:blitzpool /app

COPY --from=builder /usr/local/bin/blitzpool /usr/local/bin/blitzpool

USER blitzpool
WORKDIR /app

# Stratum V1: solo / high-diff
EXPOSE 3333 3339
# JDP
EXPOSE 3335
# PPLNS: standard / high-diff
EXPOSE 3340 3349
# HTTP API
EXPOSE 3334
# Prometheus metrics
EXPOSE 9000

# The TOML config is mounted from the host. We don't bake it into the
# image so secrets and per-deployment settings stay outside the build.
# Compose mounts blitzpool.toml read-only at /app/blitzpool.toml.

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/blitzpool"]
CMD ["--config", "/app/blitzpool.toml"]
