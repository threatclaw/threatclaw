# ──────────────────────────────────────────────────────────────────────────────
# ThreatClaw Core — Multi-Stage Production Dockerfile
#
# Build:
#   docker build -f docker/Dockerfile -t threatclaw/core:latest .
#
# Run:
#   docker run --env-file .env -p 18789:18789 threatclaw/core:latest
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build the Rust binary ────────────────────────────────────────────
FROM rust:1.92-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        libpq-dev \
        protobuf-compiler \
        cmake \
        clang \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

# Install WASM target and tools (needed for tool sandbox compilation)
RUN rustup target add wasm32-wasip2 \
    && cargo install wasm-tools

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Create a dummy main.rs so cargo can resolve the workspace and cache deps
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && mkdir -p benches && touch benches/safety_check.rs benches/safety_pipeline.rs

# Copy build script (needed for dependency resolution)
COPY build.rs build.rs

# Pre-build dependencies (this layer is cached unless Cargo.toml/Cargo.lock change)
RUN cargo build --release --bin threatclaw 2>/dev/null || true

# Copy full source tree
COPY src/ src/
COPY tests/ tests/
COPY migrations/ migrations/
COPY registry/ registry/
COPY channels-src/ channels-src/
COPY tools-src/ tools-src/
COPY wit/ wit/
COPY providers.json providers.json
COPY benches/ benches/

# Touch main.rs to invalidate the dummy and force a real build
RUN touch src/main.rs

# Build the release binary
RUN cargo build --release --bin threatclaw \
    && strip /app/target/release/threatclaw

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="ThreatClaw Core" \
      org.opencontainers.image.description="Autonomous cybersecurity agent for SMBs" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/threatclaw/threatclaw" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libpq5 \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /app/target/release/threatclaw /usr/local/bin/threatclaw

# Copy migrations for automatic schema setup on first run
COPY --from=builder /app/migrations /app/migrations

# Copy default registry (tool/skill definitions)
COPY --from=builder /app/registry /app/registry

# Copy provider configuration
COPY --from=builder /app/providers.json /app/providers.json

# Create non-root user
RUN groupadd -r -g 1000 threatclaw \
    && useradd -r -u 1000 -g threatclaw -m -d /home/threatclaw -s /bin/bash threatclaw \
    && mkdir -p /app/data \
    && chown -R threatclaw:threatclaw /app

USER threatclaw
WORKDIR /app

# Expose the core API port
EXPOSE 18789

# Runtime environment defaults
ENV RUST_LOG=threatclaw=info \
    TC_PERMISSION_LEVEL=ALERT_ONLY

# Health check — hit the core API health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:18789/health || exit 1

ENTRYPOINT ["threatclaw"]
