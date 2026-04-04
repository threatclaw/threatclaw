#!/bin/sh
# Load auth token — priority: Docker secret > shared volume > env var
if [ -f /run/secrets/tc_auth_token ]; then
  export TC_CORE_TOKEN="$(cat /run/secrets/tc_auth_token)"
  echo "[dashboard] Token loaded from Docker secret"
elif [ -f /shared/.env.token ]; then
  export $(cat /shared/.env.token | xargs)
  echo "[dashboard] Token loaded from shared volume"
fi

exec node server.js
