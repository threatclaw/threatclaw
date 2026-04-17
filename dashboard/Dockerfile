# ──────────────────────────────────────────────────────────────────────────────
# ThreatClaw Dashboard — Multi-Stage Production Dockerfile
#
# Build:
#   docker build -f dashboard/Dockerfile -t threatclaw/dashboard:latest ./dashboard
#
# Run:
#   docker run -p 3000:3000 threatclaw/dashboard:latest
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Install dependencies ────────────────────────────────────────────
FROM node:22-alpine AS deps

RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy package manifests
COPY package.json ./
COPY package-lock.json* yarn.lock* pnpm-lock.yaml* ./

# Install dependencies based on available lockfile
RUN if [ -f pnpm-lock.yaml ]; then \
        corepack enable pnpm && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then \
        yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then \
        npm ci; \
    else \
        npm install; \
    fi

# ── Stage 2: Build the Next.js application ──────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Enable Next.js standalone output for minimal production image
ENV NEXT_TELEMETRY_DISABLED=1

# Build the application
RUN if [ -f pnpm-lock.yaml ]; then \
        corepack enable pnpm && pnpm run build; \
    else \
        npm run build; \
    fi

# ── Stage 3: Production runtime ─────────────────────────────────────────────
FROM node:22-alpine AS runner

LABEL org.opencontainers.image.title="ThreatClaw Dashboard" \
      org.opencontainers.image.description="Security operations dashboard for ThreatClaw" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/threatclaw/threatclaw" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

# Install curl for health checks
RUN apk add --no-cache curl

# Create non-root user
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

# Copy public assets
COPY --from=builder /app/public ./public

# Copy the standalone build output (if standalone mode is configured)
# If standalone output exists, use it for minimal image size;
# otherwise fall back to the full .next directory with node_modules.
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Copy next.config.js for runtime configuration
COPY --from=builder /app/next.config.js ./next.config.js

USER nextjs

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:3000/ || exit 1

CMD ["node_modules/.bin/next", "start"]
