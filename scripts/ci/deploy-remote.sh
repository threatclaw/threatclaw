#!/usr/bin/env bash
# ThreatClaw — runs on the staging host to pull the new images and restart.
#
# Called via SSH by the deploy-staging.yml workflow after the payload
# tarball has been extracted to /tmp/tc-deploy/. Expects the tarball to
# contain docker-compose.yml, entrypoint.sh, dashboard-entrypoint.sh,
# fluent-bit/, migrations/, nginx.conf, generate-certs.sh.
#
# IMAGE_TAG env var tells which ghcr tag to pull (defaults to `staging`).
# Pass the commit SHA too so the restart message is traceable.
#
# Fails hard on any step. The caller runs snapshot-db.sh BEFORE this and
# rollback.sh AFTER if smoke fails.

set -euo pipefail

TC_DIR="/opt/threatclaw"
PAYLOAD="/tmp/tc-deploy"
IMAGE_TAG="${IMAGE_TAG:-staging}"
SHA="${SHA:-unknown}"
# Forgejo staging registry — defaults to the DEV WG address when unset so
# the script is runnable standalone for debugging. The CI workflow passes
# REGISTRY explicitly.
REGISTRY="${REGISTRY:-10.10.10.5:3100}"
# docker-compose.yml references the public ghcr.io tags. On staging we pull
# from the Forgejo registry and retag locally so compose picks them up
# without any change to the compose file.
COMPOSE_CORE_IMAGE="ghcr.io/threatclaw/core:latest"
COMPOSE_DASHBOARD_IMAGE="ghcr.io/threatclaw/dashboard:latest"

echo "[deploy] tag=${IMAGE_TAG} sha=${SHA} registry=${REGISTRY}"

if [ ! -d "$PAYLOAD" ]; then
    echo "[deploy] ERROR: ${PAYLOAD} missing — did scp step run?"; exit 1
fi

# ── Sync payload files into /opt/threatclaw/ ──────────────────────────────
echo "[deploy] syncing config files"
sudo cp "$PAYLOAD/docker-compose.yml"        "$TC_DIR/docker-compose.yml"
sudo cp "$PAYLOAD/entrypoint.sh"             "$TC_DIR/entrypoint.sh"
sudo chmod +x "$TC_DIR/entrypoint.sh"
if [ -f "$PAYLOAD/dashboard-entrypoint.sh" ]; then
    sudo cp "$PAYLOAD/dashboard-entrypoint.sh" "$TC_DIR/dashboard-entrypoint.sh"
    sudo chmod +x "$TC_DIR/dashboard-entrypoint.sh"
fi
if [ -f "$PAYLOAD/generate-certs.sh" ]; then
    sudo cp "$PAYLOAD/generate-certs.sh" "$TC_DIR/generate-certs.sh"
    sudo chmod +x "$TC_DIR/generate-certs.sh"
fi
if [ -f "$PAYLOAD/nginx.conf" ]; then
    sudo cp "$PAYLOAD/nginx.conf" "$TC_DIR/nginx.conf"
fi
if [ -d "$PAYLOAD/fluent-bit" ]; then
    sudo mkdir -p "$TC_DIR/fluent-bit"
    sudo cp -f "$PAYLOAD/fluent-bit/"* "$TC_DIR/fluent-bit/"
fi
if [ -d "$PAYLOAD/migrations" ]; then
    sudo mkdir -p "$TC_DIR/migrations"
    sudo cp -f "$PAYLOAD/migrations/"* "$TC_DIR/migrations/"
fi

# ── PostgreSQL TLS certs — MUST be generated manually on first install ──
# The CI user (tc-deploy) does not have sudo bash in its sudoers, so it
# cannot run generate-certs.sh which needs root to write /var/lib/postgresql.
# Abort early with a clear message rather than silently skipping.
if [ ! -f "$TC_DIR/certs/pg-server.crt" ]; then
    echo "[deploy] ERROR: PostgreSQL TLS certs missing at $TC_DIR/certs/"
    echo "[deploy] Run 'sudo bash $TC_DIR/generate-certs.sh \$(hostname -f)' manually as a full admin."
    exit 1
fi

# ── Docker secrets — migrate from .env if secrets/ is empty ──────────────
if [ ! -s "$TC_DIR/secrets/tc_db_password.txt" ]; then
    echo "[deploy] creating Docker secrets from .env"
    sudo mkdir -p "$TC_DIR/secrets"
    if [ -f "$TC_DIR/.env" ]; then
        DB_PASS=$(sudo grep '^TC_DB_PASSWORD=' "$TC_DIR/.env" | cut -d= -f2 || true)
        AUTH_TOK=$(sudo grep '^TC_AUTH_TOKEN=' "$TC_DIR/.env" | cut -d= -f2 || true)
        [ -n "$DB_PASS" ] && echo -n "$DB_PASS" | sudo tee "$TC_DIR/secrets/tc_db_password.txt" > /dev/null
        [ -n "$AUTH_TOK" ] && echo -n "$AUTH_TOK" | sudo tee "$TC_DIR/secrets/tc_auth_token.txt" > /dev/null
    fi
    sudo chmod 700 "$TC_DIR/secrets"
    sudo chmod 644 "$TC_DIR/secrets/"*.txt 2>/dev/null || true
fi

# ── Docker login to Forgejo registry (ephemeral) ─────────────────────────
# Credentials land via env from the CI workflow. We prefer this over a
# persistent ~tc-deploy/.docker/config.json so a leaked token is short-lived
# and bound to the current deploy session only.
if [ -n "${REGISTRY_USER:-}" ] && [ -n "${REGISTRY_TOKEN:-}" ]; then
    echo "[deploy] docker login ${REGISTRY}"
    echo "$REGISTRY_TOKEN" | docker login "$REGISTRY" -u "$REGISTRY_USER" --password-stdin
fi

# ── Pull + retag images ──────────────────────────────────────────────────
# docker-compose.yml references ghcr.io/threatclaw/core:latest; we pull
# the Forgejo staging image and retag it locally so compose picks it up
# without needing a per-environment compose override.
cd "$TC_DIR"
echo "[deploy] pull + retag"
docker pull "${REGISTRY}/threatclaw/core:${IMAGE_TAG}"
docker tag "${REGISTRY}/threatclaw/core:${IMAGE_TAG}" "${COMPOSE_CORE_IMAGE}"
docker pull "${REGISTRY}/threatclaw/dashboard:${IMAGE_TAG}"
docker tag "${REGISTRY}/threatclaw/dashboard:${IMAGE_TAG}" "${COMPOSE_DASHBOARD_IMAGE}"

# Clean up the docker auth so no long-lived credential stays on CASE.
if [ -n "${REGISTRY_USER:-}" ]; then
    docker logout "$REGISTRY" >/dev/null 2>&1 || true
fi

echo "[deploy] docker compose up -d --force-recreate"
# TC_HTTPS_PORT / TC_HTTP_PORT stay constant; exporting here keeps the env
# stable even if the shell session didn't source /etc/environment.
# No sudo — tc-deploy is in the docker group.
export TC_HTTPS_PORT=8445
export TC_HTTP_PORT=8880
docker compose up -d --force-recreate

# ── Wait for core to be healthy ──────────────────────────────────────────
echo "[deploy] waiting for core health (max 120 s)"
for i in $(seq 1 60); do
    if curl -sf --max-time 3 http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
        echo "[deploy] core healthy after $((i * 2)) s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[deploy] ERROR: core did not become healthy in 120 s"
        docker compose ps
        docker compose logs --tail=50 threatclaw-core
        exit 1
    fi
    sleep 2
done

# ── Record current image tag for rollback traceability ───────────────────
CURRENT_DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' \
    "${REGISTRY}/threatclaw/core:${IMAGE_TAG}" 2>/dev/null || echo "unknown")
echo "$CURRENT_DIGEST" | sudo tee "$TC_DIR/backups/last-deployed-digest.txt" > /dev/null || true

# ── Cleanup payload ──────────────────────────────────────────────────────
rm -rf "$PAYLOAD"

echo "[deploy] done — commit ${SHA}, tag ${IMAGE_TAG}"
