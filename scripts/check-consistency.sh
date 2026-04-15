#!/usr/bin/env bash
# ThreatClaw — cross-file consistency checks that compilers cannot catch.
#
# Usage: scripts/check-consistency.sh
#
# Exit 0 if all checks pass. Exit 1 if any FAIL item is reported. Warnings
# (WARN) are informational and do not affect the exit code.
#
# Motivation: our pre-launch bug-fixing marathon uncovered half a dozen
# drifts where the compiler passed but runtime behaviour was wrong because
# related files fell out of sync. This script catches the cases we have
# actually hit in production:
#
#   1. Version strings across Cargo.toml / README badge / CHANGELOG / install.sh
#   2. i18n.ts fr vs en keys (any key present in one locale but not the other)
#   3. /api/tc/* endpoints declared in Rust that are never called from dashboard
#   4. Migrations that ADD COLUMN without a matching field in the Rust store
#   5. skill-catalog/*.json skills not registered in sync_scheduler
#   6. Missing COPY in Dockerfile for directories referenced at runtime

set -euo pipefail

cd "$(dirname "$0")/.."

FAIL=0
WARN=0

fail() { echo "  FAIL  $*" >&2; FAIL=$((FAIL + 1)); }
warn() { echo "  WARN  $*" >&2; WARN=$((WARN + 1)); }
ok()   { echo "  OK    $*"; }
section() { echo; echo "── $* ──"; }

# ── 1. Version consistency ────────────────────────────────────────────────────

section "1. Version strings"

CARGO_VERSION=$(awk '
  /^\[package\]/ { in_pkg = 1; next }
  in_pkg && /^\[/ { exit }
  in_pkg && /^version *= *"/ {
    match($0, /"[^"]*"/)
    print substr($0, RSTART + 1, RLENGTH - 2); exit
  }
' Cargo.toml)
echo "  Cargo.toml version: $CARGO_VERSION"

# README badge — shields.io double-encodes hyphens inside the value field.
# The badge captures can use either `v0.1-red` or `v0.1--beta-red` etc.
if grep -Eq "badge/version-[A-Za-z0-9.-]+--?[A-Za-z0-9.-]+-red" README.md; then
  README_VERSION=$(grep -oE "badge/version-[^-]+(--[A-Za-z0-9.]+)?" README.md \
    | sed 's|badge/version-||; s|--|-|g' | head -1)
  if [ "$README_VERSION" = "$CARGO_VERSION" ]; then
    ok "README.md badge matches ($README_VERSION)"
  else
    fail "README.md badge has '$README_VERSION', Cargo.toml has '$CARGO_VERSION'"
  fi
fi

# installer/install.sh TC_VERSION
if [ -f installer/install.sh ]; then
  INSTALL_VERSION=$(grep -oE 'readonly TC_VERSION="[^"]*"' installer/install.sh \
    | sed 's|readonly TC_VERSION="||;s|"||' || true)
  if [ -n "$INSTALL_VERSION" ]; then
    if [ "$INSTALL_VERSION" = "$CARGO_VERSION" ]; then
      ok "installer/install.sh TC_VERSION matches"
    else
      fail "installer/install.sh TC_VERSION='$INSTALL_VERSION' ≠ Cargo.toml '$CARGO_VERSION'"
    fi
  fi
fi

# CHANGELOG top entry
if [ -f CHANGELOG.md ]; then
  CHANGELOG_VERSION=$(awk '/^## \[/ { match($0, /\[[^]]*\]/); print substr($0, RSTART+1, RLENGTH-2); exit }' CHANGELOG.md)
  if [ "$CHANGELOG_VERSION" = "$CARGO_VERSION" ]; then
    ok "CHANGELOG.md top entry matches"
  else
    warn "CHANGELOG.md top entry is '$CHANGELOG_VERSION' — Cargo.toml is '$CARGO_VERSION' (add a new section before releasing)"
  fi
fi

# ── 2. i18n fr/en parity ──────────────────────────────────────────────────────

section "2. i18n fr/en parity (dashboard/src/lib/i18n.ts)"

if [ -f dashboard/src/lib/i18n.ts ]; then
  # Each entry looks like:
  #   key: { fr: "...", en: "..." },
  # Extract keys that have only fr or only en.
  missing=$(awk '
    /^  [a-zA-Z][a-zA-Z0-9_]*: *\{/ {
      match($0, /^  [a-zA-Z_][a-zA-Z0-9_]*/)
      key = substr($0, 3, RLENGTH - 2)
      has_fr = index($0, "fr:") > 0
      has_en = index($0, "en:") > 0
      if (has_fr && !has_en) print "  missing en: " key
      if (has_en && !has_fr) print "  missing fr: " key
    }
  ' dashboard/src/lib/i18n.ts)
  if [ -z "$missing" ]; then
    ok "all i18n entries have both fr and en"
  else
    echo "$missing" | while read -r line; do warn "$line"; done
  fi
fi

# ── 3. /api/tc endpoints — Rust declares but dashboard does not use ───────────
#
# NOTE: This check is intentionally restrictive. Many endpoints are meant to be
# called externally (webhooks, CLI tools, integration hooks) and SHOULD NOT be
# called from the dashboard. We only flag endpoints whose name suggests a
# dashboard-only function (skill config, asset edit, etc.) — everything else
# is assumed to be an external API surface.

section "3. Dashboard-specific /api/tc/* endpoints"

if [ -f src/channels/web/handlers/threatclaw_api.rs ]; then
  # Only check endpoints that look dashboard-specific (assets, skills, incidents,
  # findings, alerts). Webhooks, /test/, /version/, /telegram/, /auth/ are skipped.
  rust_routes=$(grep -hoE '"/api/tc/(assets|skills|incidents|findings|alerts|config|notifications|remediation|backups|sources)[^"]*"' \
    src/channels/web/server.rs src/channels/web/handlers/threatclaw_api.rs 2>/dev/null \
    | sed 's|"||g' | sort -u)
  unused_count=0
  for route in $rust_routes; do
    prefix=$(echo "$route" | sed 's|{[^}]*}||g' | sed 's|/$||')
    if ! grep -rq "$prefix" dashboard/src/ 2>/dev/null; then
      warn "endpoint $route looks dashboard-specific but is not called from dashboard/src/"
      unused_count=$((unused_count + 1))
    fi
  done
  if [ "$unused_count" -eq 0 ]; then
    ok "all dashboard-specific /api/tc/* endpoints are referenced"
  fi
fi

# ── 4. Migration ADD COLUMN vs Rust struct fields ─────────────────────────────

section "4. Migrations vs Rust store fields"

if [ -d migrations ] && [ -f src/db/pg_threatclaw.rs ]; then
  for mig in migrations/V*.sql; do
    # Extract column names from `ADD COLUMN [IF NOT EXISTS] name TYPE ...`.
    # Using awk instead of grep so we can skip SQL keywords cleanly.
    cols=$(awk '
      BEGIN { IGNORECASE = 1 }
      /add[[:space:]]+column/ {
        # Strip comments then lowercase for matching
        line = tolower($0)
        sub(/--.*$/, "", line)
        # Extract the identifier that immediately follows "add column" or
        # "add column if not exists"
        if (match(line, /add[[:space:]]+column[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?[a-z_][a-z0-9_]*/)) {
          s = substr(line, RSTART, RLENGTH)
          sub(/.*[[:space:]]/, "", s)
          print s
        }
      }
    ' "$mig" || true)
    for col in $cols; do
      # Skip SQL keywords and nonsense (regex fallback)
      case "$col" in
        add|column|if|not|exists|true|false|null) continue ;;
      esac
      if ! grep -qi "\"$col\"\|\.$col\b" src/db/pg_threatclaw.rs; then
        warn "$(basename "$mig") adds column '$col' not referenced in pg_threatclaw.rs"
      fi
    done
  done
  ok "migration column check complete (warnings above if any)"
fi

# ── 5. Skill catalog vs sync_scheduler ────────────────────────────────────────

section "5. Skill catalog vs sync_scheduler"

if [ -d skills-catalog ] && [ -f src/connectors/sync_scheduler.rs ]; then
  # Each skill manifest has an "id" field.
  miss=0
  for f in skills-catalog/skill-*.json; do
    id=$(python3 -c "import json,sys; print(json.load(open('$f'))['id'])" 2>/dev/null || true)
    if [ -n "$id" ]; then
      # Not every skill needs the scheduler — only connectors do. But we at least
      # warn if a connector-type skill is not referenced anywhere in sync_scheduler.
      type=$(python3 -c "import json,sys; print(json.load(open('$f')).get('type',''))" 2>/dev/null || true)
      if [ "$type" = "connector" ] && ! grep -q "\"$id\"\|${id//-/_}" src/connectors/sync_scheduler.rs 2>/dev/null; then
        warn "connector skill '$id' ($f) is not referenced in sync_scheduler.rs"
        miss=$((miss + 1))
      fi
    fi
  done
  if [ "$miss" -eq 0 ]; then
    ok "all connector skills are referenced in sync_scheduler.rs"
  fi
fi

# ── 6. Dockerfile COPY coverage ───────────────────────────────────────────────

section "6. Dockerfile COPY coverage for runtime-loaded directories"

if [ -f Dockerfile ]; then
  # Directories loaded by Rust code at runtime (tc_catalog.rs, pdf generator, etc.)
  for dir in skills-catalog templates migrations AGENT_SOUL.toml; do
    if [ -e "$dir" ]; then
      if grep -q "COPY.* $dir" Dockerfile; then
        ok "Dockerfile COPY $dir"
      else
        fail "Dockerfile does not COPY $dir — runtime will fail"
      fi
    fi
  done
fi

# ── Summary ───────────────────────────────────────────────────────────────────

section "Summary"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
