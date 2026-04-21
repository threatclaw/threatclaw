#!/usr/bin/env bash
# ThreatClaw — propagate the version in Cargo.toml to every other file that
# mentions it. Cargo.toml is the source of truth.
#
# Usage: scripts/sync-version.sh                (dry-run, just prints diffs)
#        scripts/sync-version.sh --apply        (actually writes the changes)
#
# Touches (add new entries here when a new version reference is introduced):
#
#   README.md                                      — version badge
#   CHANGELOG.md                                   — top `## [x.y.z]` header if present
#   docker/docker-compose.yml                      — header comment
#   dashboard/src/app/test-ui/page.tsx             — fallback version literal
#   dashboard/src/app/setup/page.tsx               — version display (if present)
#   .github/ISSUE_TEMPLATE/bug_report.yml          — placeholder
#   skills-src/skill-report-gen/src/lib.rs         — PDF footer version (currently stripped)
#   installer/install.sh                           — TC_VERSION constant
#
# Skipped intentionally:
#
#   Cargo.lock             — managed by cargo update -p threatclaw
#   dashboard/package.json — dashboard has its own Next.js version, not the product version
#
# Exit 0 on success, non-zero if any file cannot be patched.

set -euo pipefail

cd "$(dirname "$0")/.."

APPLY=false
if [ "${1:-}" = "--apply" ]; then
  APPLY=true
fi

# ── Read source-of-truth version from Cargo.toml ──────────────────────────────

VERSION=$(awk '
  /^\[package\]/ { in_pkg = 1; next }
  in_pkg && /^\[/ { exit }
  in_pkg && /^version *= *"/ {
    match($0, /"[^"]*"/)
    v = substr($0, RSTART + 1, RLENGTH - 2)
    print v
    exit
  }
' Cargo.toml)

if [ -z "$VERSION" ]; then
  echo "ERROR: could not read version from Cargo.toml" >&2
  exit 1
fi

echo "== source version: $VERSION =="
echo

# ── Patch helper ──────────────────────────────────────────────────────────────

# patch_file <file> <sed-pattern>
#
# If --apply is set, runs sed -i. Otherwise shows a unified diff preview
# and returns success only if the file actually changes.
patch_file() {
  local file="$1"
  local pattern="$2"

  if [ ! -f "$file" ]; then
    echo "  SKIP  $file (not found)"
    return 0
  fi

  local tmp
  tmp=$(mktemp)
  sed "$pattern" "$file" > "$tmp"

  if diff -q "$file" "$tmp" >/dev/null 2>&1; then
    echo "  OK    $file (already at $VERSION)"
    rm -f "$tmp"
    return 0
  fi

  if $APPLY; then
    mv "$tmp" "$file"
    echo "  WROTE $file"
  else
    echo "  DIFF  $file"
    diff -u "$file" "$tmp" | sed 's/^/        /'
    rm -f "$tmp"
  fi
}

# ── Targets ───────────────────────────────────────────────────────────────────

# README badge — version-X.Y.Z--beta-red / version-X.Y.Z-red
# The -- encoding is used by shields.io for hyphens inside the value field.
readme_val=$(printf '%s' "$VERSION" | sed 's/-/--/g')
patch_file README.md "s|badge/version-[0-9A-Za-z.-]\{1,\}-red|badge/version-${readme_val}-red|"

# CHANGELOG is intentionally NOT auto-patched: a version bump needs a new
# section with real release notes, not a rename of the previous header.
# Edit CHANGELOG.md by hand when cutting a release.

# docker-compose.yml header
patch_file docker/docker-compose.yml "s|ThreatClaw v[0-9][0-9A-Za-z.\-]*|ThreatClaw v${VERSION}|"

# dashboard test-ui fallback
patch_file dashboard/src/app/test-ui/page.tsx "s|\"v[0-9][0-9A-Za-z.\-]*\"|\"v${VERSION}\"|"

# bug_report.yml placeholder
patch_file .github/ISSUE_TEMPLATE/bug_report.yml "s|v[0-9][0-9A-Za-z.\-]*|v${VERSION}|"

# install.sh TC_VERSION constant
patch_file installer/install.sh "s|^readonly TC_VERSION=\"[^\"]*\"|readonly TC_VERSION=\"${VERSION}\"|"

echo
if $APPLY; then
  echo "== applied. Run 'git diff' to review. =="
else
  echo "== dry-run only. Re-run with --apply to write changes. =="
fi
