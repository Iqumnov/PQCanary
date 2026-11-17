# ─── Stage 1: Build Rust Binaries (CLI, REST Daemon, MCP Server) ───────────────
FROM rust:1-bookworm AS rust-builder
WORKDIR /usr/src/pqcanary

# Install Z3 and build dependencies (including libudev-dev for serialport)
RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev libudev-dev z3 libz3-dev \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace source files
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY cli ./cli
COPY mcp ./mcp
COPY web/src-tauri ./web/src-tauri

# Build production binaries
RUN cargo build --release --bin pqcanary --bin pqcanary-mcp

# ─── Stage 2: Build SolidStart Web Application ─────────────────────────────────
FROM node:20-bookworm AS web-builder
WORKDIR /usr/src/pqcanary

RUN corepack enable && corepack prepare pnpm@9.15.4 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY web/package.json ./web/

RUN pnpm install --no-frozen-lockfile

COPY web ./web
COPY core/pkg ./core/pkg
RUN cd web && pnpm run build


# ─── Stage 3: Final Lightweight Microservice Image ──────────────────────────────
FROM debian:bookworm-slim AS runner

# OCI Standard Image Annotations
LABEL org.opencontainers.image.title="PQCanary" \
      org.opencontainers.image.description="Post-Quantum Cryptographic Security Scanner, Concolic Execution Engine & Side-Channel Audit Platform" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.authors="Matvei Igumnov" \
      org.opencontainers.image.vendor="Matvei Igumnov" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/Iqumnov/PQCanary"

WORKDIR /app

# Install runtime dependencies: Z3 SMT solver, Git, OpenSSL 3, libudev, CA certificates
RUN apt-get update && apt-get install -y \
    z3 \
    git \
    ca-certificates \
    libssl3 \
    libudev1 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -ms /bin/bash pqcanary \
    && mkdir -p /app/scans /tmp/pqcanary-temp \
    && chown -R pqcanary:pqcanary /app /tmp/pqcanary-temp

# Copy compiled native Rust binaries from builder
COPY --from=rust-builder /usr/src/pqcanary/target/release/pqcanary /usr/local/bin/pqcanary
COPY --from=rust-builder /usr/src/pqcanary/target/release/pqcanary-mcp /usr/local/bin/pqcanary-mcp

# Copy built web application assets
COPY --from=web-builder /usr/src/pqcanary/web/.output /app/web/.output
COPY --from=web-builder /usr/src/pqcanary/web/.output/public /app/web_dist

# Expose ports:
#   8080 — PQCanary REST API & Public URL Scanner Daemon
#   9090 — Prometheus Metrics / Secondary service port
EXPOSE 8080 9090

# Default environment variables
ENV PQCANARY_PORT=8080 \
    PQCANARY_WEB_DIR=/app/web_dist \
    RUST_LOG=info \
    TMPDIR=/tmp/pqcanary-temp

# Switch to non-root user for security best practices
USER pqcanary

# Container Healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Default entrypoint starts the PQCanary REST API daemon
ENTRYPOINT ["pqcanary", "serve", "--port", "8080"]

