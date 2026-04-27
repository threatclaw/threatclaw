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
FROM rust:1.94-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        libpq-dev \
        protobuf-compiler \
        libprotobuf-dev \
        cmake \
        clang \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

# libprotobuf-dev is required (not just protobuf-compiler) — it ships the
# Protocol Buffers well-known types (/usr/include/google/protobuf/empty.proto,
# timestamp.proto, ...) that the Velociraptor api.proto imports. Without it,
# tonic-build fails with "google.protobuf.Empty is not defined" even though
# protoc itself is present.

# Install WASM target and tools (needed for tool sandbox compilation).
# wasm-tools pinned to 1.240 — later versions pull constant_time_eq 0.4.3
# which requires rustc 1.95+; our base image is rust:1.94. Bump the image
# tag (and remove this pin) once the base is updated.
RUN rustup target add wasm32-wasip2 \
    && cargo install --locked wasm-tools@1.240.0

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Create a dummy main.rs so cargo can resolve the workspace and cache deps
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && mkdir -p benches && touch benches/safety_check.rs benches/safety_pipeline.rs

# Copy build script (needed for dependency resolution)
COPY build.rs build.rs

# Velociraptor v0.76 proto tree — compiled by build.rs via tonic-build
# into $OUT_DIR for skill-velociraptor's gRPC client. Must arrive BEFORE
# the deps-cache cargo build below, otherwise build.rs fires "proto tree
# missing", skips tonic compile, caches that incomplete state, and the
# real build fails because src/connectors/velociraptor_proto.rs's
# include_proto! macros can't resolve.
COPY proto/ proto/

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
COPY docs/ docs/
COPY crates/ crates/
COPY assets/ assets/
COPY AGENT_SOUL.toml AGENT_SOUL.toml
COPY templates/ templates/
COPY skills/ skills/
COPY skills-src/ skills-src/
COPY skills-catalog/ skills-catalog/

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
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Install minimal runtime dependencies + PostgreSQL client + nmap (for network scanning)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libpq5 \
        ca-certificates \
        curl \
        xz-utils \
        postgresql-client \
        nmap \
        fonts-noto-core || true \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for ephemeral skill containers — nuclei, trivy, etc.)
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz \
    | tar -xz --strip-components=1 -C /usr/local/bin docker/docker

# Install Typst for PDF generation
RUN curl -sSfL https://github.com/typst/typst/releases/download/v0.13.1/typst-x86_64-unknown-linux-musl.tar.xz \
       -o /tmp/typst.tar.xz \
    && tar -xJf /tmp/typst.tar.xz --strip-components=1 -C /usr/local/bin typst-x86_64-unknown-linux-musl/typst \
    && rm /tmp/typst.tar.xz \
    && typst --version

# Copy the compiled binary
COPY --from=builder /app/target/release/threatclaw /usr/local/bin/threatclaw

# Copy migrations for automatic schema setup on first run
COPY --from=builder /app/migrations /app/migrations

# Copy default registry (tool/skill definitions)
COPY --from=builder /app/registry /app/registry

# Copy provider configuration
COPY --from=builder /app/providers.json /app/providers.json

# Copy AGENT_SOUL, OUI database, and report templates
COPY --from=builder /app/AGENT_SOUL.toml /app/AGENT_SOUL.toml
COPY --from=builder /app/assets /app/assets
COPY --from=builder /app/templates /app/templates

# Copy skill catalogs (manifests for dashboard display)
COPY --from=builder /app/skills-catalog /app/skills-catalog
COPY --from=builder /app/skills /app/skills
COPY --from=builder /app/skills-src /app/skills-src

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
