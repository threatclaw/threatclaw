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

# Images were already loaded on staging by the workflow via `docker load`
# from the gzipped tarball uploaded from DEV. No pull required.
cd "$TC_DIR"
echo "[deploy] verifying loaded images"
docker image inspect "${COMPOSE_CORE_IMAGE}" >/dev/null || {
    echo "[deploy] ERROR: ${COMPOSE_CORE_IMAGE} missing — did the image load step run?"; exit 1;
}
docker image inspect "${COMPOSE_DASHBOARD_IMAGE}" >/dev/null || {
    echo "[deploy] ERROR: ${COMPOSE_DASHBOARD_IMAGE} missing — did the image load step run?"; exit 1;
}

echo "[deploy] docker compose up -d --force-recreate (staging scope)"
# TC_HTTPS_PORT / TC_HTTP_PORT stay constant; exporting here keeps the env
# stable even if the shell session didn't source /etc/environment.
# No sudo — tc-deploy is in the docker group.
export TC_HTTPS_PORT=8445
export TC_HTTP_PORT=8880
# fluent-bit is intentionally excluded — staging runs alongside Wazuh
# which already binds UDP 514 as the syslog endpoint. On bare-metal prod
# (no Wazuh) the full compose still covers fluent-bit because the manual
# installer runs `docker compose up -d` without a service filter.
STAGING_SERVICES=(
    threatclaw-core
    threatclaw-dashboard
    threatclaw-db
    ollama
    ml-engine
    nginx
    docker-proxy
)
docker compose up -d --force-recreate "${STAGING_SERVICES[@]}"

# ── Wait for core to be healthy ──────────────────────────────────────────
# Core's port 3000 is only exposed inside the docker network — we go
# through nginx on localhost:8445 (HTTPS, self-signed).
echo "[deploy] waiting for core health (max 120 s)"
for i in $(seq 1 60); do
    if curl -skf --max-time 3 https://127.0.0.1:8445/api/tc/health >/dev/null 2>&1; then
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

# ── Record deployed image ID for rollback traceability ───────────────────
CURRENT_ID=$(docker inspect --format '{{.Id}}' "${COMPOSE_CORE_IMAGE}" 2>/dev/null || echo "unknown")
echo "${CURRENT_ID} sha=${SHA}" | sudo tee "$TC_DIR/backups/last-deployed-digest.txt" > /dev/null || true

# ── Cleanup payload ──────────────────────────────────────────────────────
rm -rf "$PAYLOAD"

echo "[deploy] done — commit ${SHA}, tag ${IMAGE_TAG}"
