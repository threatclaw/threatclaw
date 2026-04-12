#!/bin/sh
# Strelka Relay — watches extracted files, submits to Strelka, forwards results to ThreatClaw.
# Runs as a lightweight sidecar container (curlimages/curl).

set -e

THREATCLAW_URL="${THREATCLAW_URL:-http://threatclaw-core:3000}"
STRELKA_URL="${STRELKA_URL:-http://strelka-frontend:57314}"
WATCH_DIR="${WATCH_DIR:-/mnt/extracted}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"
PROCESSED_DIR="/tmp/processed"

mkdir -p "$PROCESSED_DIR"

# Read auth token
TOKEN=""
if [ -f /shared/auth_token ]; then
    TOKEN=$(cat /shared/auth_token)
fi

echo "Strelka Relay starting..."
echo "  ThreatClaw: $THREATCLAW_URL"
echo "  Strelka: $STRELKA_URL"
echo "  Watch dir: $WATCH_DIR"
echo "  Poll interval: ${POLL_INTERVAL}s"

while true; do
    # Find new files not yet processed
    if [ -d "$WATCH_DIR" ]; then
        find "$WATCH_DIR" -type f -newer "$PROCESSED_DIR/.last_scan" 2>/dev/null | while read -r filepath; do
            filename=$(basename "$filepath")

            # Skip if already processed
            if [ -f "$PROCESSED_DIR/$filename" ]; then
                continue
            fi

            echo "Scanning: $filename"

            # Submit to Strelka frontend
            result=$(curl -s -X POST "$STRELKA_URL/strelka/scan" \
                -F "file=@$filepath" \
                --connect-timeout 10 \
                --max-time 120 \
                2>/dev/null) || true

            if [ -n "$result" ] && [ "$result" != "null" ]; then
                # Forward result to ThreatClaw webhook
                curl -s -X POST "$THREATCLAW_URL/api/tc/webhook/ingest/strelka" \
                    -H "Content-Type: application/json" \
                    -H "Authorization: Bearer $TOKEN" \
                    -d "$result" \
                    --connect-timeout 5 \
                    --max-time 10 \
                    >/dev/null 2>&1 || true

                echo "  -> Forwarded to ThreatClaw"
            fi

            # Mark as processed
            touch "$PROCESSED_DIR/$filename"
        done
    fi

    # Update last scan timestamp
    touch "$PROCESSED_DIR/.last_scan"

    sleep "$POLL_INTERVAL"
done
