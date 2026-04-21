#!/usr/bin/env bash
# ThreatClaw — restore the staging DB from the most recent pre-deploy
# snapshot. Invoked by deploy-staging.yml when the smoke suite fails.
#
# Does NOT restart the core/dashboard containers on its own — the DB is
# the piece we can't recover from a bad migration, so restoring it is
# the priority. After the DB is back, the workflow pulls the previous
# image tag (if available) or leaves the rollback as a "DB-only restore
# + manual investigation" so a human can decide whether to repull the
# old image.

set -euo pipefail

BACKUP_DIR="/opt/threatclaw/backups"
SNAPSHOT="${SNAPSHOT:-${BACKUP_DIR}/last-pre-deploy.sql.gz}"
DB_CONTAINER="${DB_CONTAINER:-threatclaw-threatclaw-db-1}"
DB_USER="${DB_USER:-threatclaw}"
DB_NAME="${DB_NAME:-threatclaw}"
TC_DIR="/opt/threatclaw"

if [ ! -f "$SNAPSHOT" ]; then
    echo "[rollback] ERROR: no snapshot at ${SNAPSHOT}"
    exit 1
fi

SIZE=$(sudo du -h "$SNAPSHOT" | cut -f1)
echo "[rollback] restoring ${SNAPSHOT} (${SIZE})"

# Stop app services so no writes land during the restore. The DB
# container stays up — we restore into it with DROP / CREATE wrapping.
cd "$TC_DIR"
sudo docker compose stop threatclaw-core threatclaw-dashboard fluent-bit 2>/dev/null || true

# Drop + recreate schema to avoid conflicts on restore. Any connection
# lingering from core/dashboard (we just stopped them but the DB may
# still hold idle connections for up to statement_timeout) will block
# DROP DATABASE — terminate them explicitly first.
sudo docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d postgres <<SQL
REVOKE CONNECT ON DATABASE ${DB_NAME} FROM PUBLIC;
SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS ${DB_NAME};
CREATE DATABASE ${DB_NAME};
GRANT CONNECT ON DATABASE ${DB_NAME} TO PUBLIC;
SQL

# Restore
sudo zcat "$SNAPSHOT" | sudo docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME"

echo "[rollback] DB restored — restarting app services"
sudo docker compose up -d --force-recreate threatclaw-core threatclaw-dashboard fluent-bit

# Give it a moment so the workflow log shows it came back
sleep 8
sudo docker compose ps

echo "[rollback] done — DB is at pre-deploy state. Images were not touched."
echo "[rollback] If the bad image is still tagged staging, the next deploy will attempt the same change."
echo "[rollback] Investigate and either fix forward on main or manually retag a known-good image."
