#!/usr/bin/env bash
# ThreatClaw — snapshot the staging PostgreSQL database before a deploy.
#
# Runs on the staging host (CASE). Writes a compressed pg_dump to
# /opt/threatclaw/backups/snapshot-<timestamp>.sql.gz and symlinks the most
# recent one to /opt/threatclaw/backups/last-pre-deploy.sql.gz so rollback.sh
# can find it without arguments.
#
# Keeps the 5 most recent snapshots. Older ones are deleted so the /opt
# partition doesn't fill over time.
#
# Exit 0 on success, non-zero on any failure.

set -euo pipefail

BACKUP_DIR="/opt/threatclaw/backups"
DB_CONTAINER="${DB_CONTAINER:-threatclaw-threatclaw-db-1}"
DB_USER="${DB_USER:-threatclaw}"
DB_NAME="${DB_NAME:-threatclaw}"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="${BACKUP_DIR}/snapshot-${STAMP}.sql.gz"

sudo mkdir -p "$BACKUP_DIR"

if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    echo "[snapshot] WARN: ${DB_CONTAINER} not running — skipping (first deploy?)"
    exit 0
fi

echo "[snapshot] writing ${OUT}"
docker exec "${DB_CONTAINER}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" \
    | gzip -9 \
    | sudo tee "$OUT" > /dev/null

SIZE=$(sudo du -h "$OUT" | cut -f1)
echo "[snapshot] done — ${SIZE}"

# Symlink for rollback.sh
sudo ln -sfn "$OUT" "${BACKUP_DIR}/last-pre-deploy.sql.gz"

# Retention: keep 5 most recent real snapshots (not the symlink)
sudo find "$BACKUP_DIR" -maxdepth 1 -name 'snapshot-*.sql.gz' -type f \
    | sort -r \
    | tail -n +6 \
    | sudo xargs -r rm -f

echo "[snapshot] retention: $(sudo find "$BACKUP_DIR" -maxdepth 1 -name 'snapshot-*.sql.gz' -type f | wc -l) snapshots kept"
