#!/bin/sh
# Load auth token from shared volume (written by core entrypoint)
if [ -f /shared/.env.token ]; then
  export $(cat /shared/.env.token | xargs)
  echo "[dashboard] Token loaded from core"
fi

exec node server.js
