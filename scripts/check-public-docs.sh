#!/usr/bin/env bash
# ThreatClaw — public docs leak detector
#
# Greps the public-facing markdown surface for terms that would document
# internal primitives, exact LLM models, internal API paths, env vars, table
# names, defense-layer mechanics, retired pricing, and other items that an
# attacker could turn into an evasion roadmap or that a competitor could turn
# into a blueprint.
#
# Public docs are a brand layer. Engineering detail belongs in internal/
# (Forgejo-only). See feedback_public_docs_brand_layer.md.
#
# Usage:
#   scripts/check-public-docs.sh                  — scan the default file set
#   scripts/check-public-docs.sh path/to/file.md  — scan a single file
#
# Exit 0 = clean, 1 = leak(s) found.
#
# Skip with care: this gate runs in pre-push and in CI. To bypass locally
# (only when the match is a documented false positive) add the offending
# pattern to ALLOWLIST below or wrap the line with a `<!-- doc-leak-ok: ... -->`
# trailer on the same line, and document the rationale in the commit message.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# Files to scan. Excludes:
# - docs/api.md          — public API surface, by design lists /api/tc/ paths
# - docs/SKILL_DEVELOPMENT_GUIDE.md — targets contributors, can be technical
# - LICENSE, LICENSE-COMMERCIAL — boilerplate, no leak vector
# - internal/**          — Forgejo-only, may contain anything
# - .github/, .forgejo/  — workflow definitions
DEFAULT_FILES=(
  README.md
  CHANGELOG.md
  SECURITY.md
  CONTRIBUTING.md
  CLA.md
  CODE_OF_CONDUCT.md
  CONTRIBUTORS.md
  docs/getting-started.md
  docs/configuration.md
  docs/skills.md
  docs/sizing.md
  docs/telemetry.md
)

if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  FILES=()
  for f in "${DEFAULT_FILES[@]}"; do
    [ -f "$f" ] && FILES+=("$f")
  done
fi

# Patterns: each entry is "regex|category|why".
# Categories: migration, adr, api, env, table, crate, model, pricing, internal_path.
PATTERNS=(
  # Migration numbers in CHANGELOG-style references.
  '\bV[0-9]{2,3}__[a-z_]+|\bMigration V[0-9]+\b|\bV[0-9]{2,3}\.sql\b|migrations/V[0-9]+|database schema \([0-9]+ migrations\)|\([0-9]+ migrations\)|Migration `V[0-9]+|`V[0-9]{2,3}\b|\(V[0-9]{2,3}\)|\(V[0-9]{2,3} |- V[0-9]{2,3} |seeds the validation|seeded entries|migration `V[0-9]+|migration V[0-9]+|via migration V[0-9]+|migration applies V[0-9]+'
  '|migration|reveals DB schema depth and exact migration order'
  # ADR references.
  '\bADR-[0-9]{2,4}\b'
  '|adr|exposes the internal architecture-decision catalog'
  # Internal API paths beyond what docs/api.md publishes.
  '/api/tc/(remediation|incidents/\{?id\}?/blast-radius|suppression-rules|metrics/kev-tta|reports/monthly|governance/qualify-shadow-ai|webhook/token|endpoint-agents|test/cleanup|test/status|assets/\{?id\}?/criticality|admin/phase-g-acceptance|investigation-graphs|graphs)'
  '|api|specific operational/admin endpoints leak the internal API surface'
  # Internal env vars.
  '\bTC_[A-Z][A-Z0-9_]{3,}'
  '|env|reveals internal environment knobs that aren'\''t part of public config'
  # Internal table names commonly cited.
  '\b(graph_nodes|graph_edges|graph_edge_catalog|sigma_alerts|firewall_events|kev_tta_metrics|monthly_rssi_summary|suppression_rules|suppression_audit|cve_exposure_alerts|agent_audit_log|ai_systems|llm_endpoint_feed|incidents_pattern_key|billable_assets|verdict_source)\b'
  '|table|leaks internal table names'
  # Internal crates and libs we depend on for sensitive paths.
  '\b(petgraph|cel-interpreter|antlr4rust|refinery|tonic-build|libprotobuf-dev|wasm-tools)\b'
  '|crate|reveals dependency choices (some are evasion-relevant)'
  # GGUF / specific local model identifiers.
  '\b(qwen3:[0-9]+b|qwen2\.[0-9]+:|gemma[0-9]?:[a-z0-9_-]+|gemma[0-9]?-[a-z0-9]+|mistral-small:[0-9]+b|mistral-small-[0-9]|threatclaw-l[0-9]|Foundation-Sec(-8B)?|nomic-embed|llama\.cpp|fhs\.cqo|ollama 0\.[0-9]+\.[0-9]+|Ollama [0-9]+\.[0-9]+\.[0-9]+)'
  '|model|exposes the exact LLM stack and version pins'
  # Retired pricing / commercial terms.
  '\b(Action Pack|hub\.threatclaw\.io|/year/skill|premium-skill|premium skill|Premium Skill|tier=premium|skill-velociraptor-actions|skill-opnsense-actions|skill-stormshield|skill-sophos-xgs|early adopter.*50.*%)\b'
  '|pricing|references the retired premium-skills licensing model'
  # Internal file paths cited from public docs.
  '\binternal/[A-Za-z0-9._/-]+\.md\b'
  '|internal_path|leaks internal documentation file paths'
  # Defense-layer enumerations.
  '\b([45] (independent )?protection layers|five (independent )?protection layers|safety pillars: soul|HMAC memory|kill switch, XML wrapper|soul manifest|Argon2id|AES-256-GCM|HKDF|BLAKE3 .*hash|Ed25519 (offline cert|signature)|Bloom filter|Isolation Forest|DBSCAN|Random Forest \+ LSTM|RITA-style|Naabu over rustscan|Apache AGE|sslmode=require)\b'
  '|defense|enumerates internal defense primitives — evasion roadmap'
  # Specific detection thresholds (numbers + signal name on same line).
  '(±[0-9]+ ?% delta|impossible-travel.*[0-9]+ ?min|[0-9]+ ?min.*impossible-travel|dedup window 1[ -]?h|1[ -]?h dedup|dedup.*1[ -]?h|600[ ]?s.*timeout|timeout.*600[ ]?s|TTL 90[ ]?j|TTL 90[ ]?d|CVSS × CISA KEV × EPSS|score = 50 \(neutral)'
  '|threshold|publishes detection-threshold values an attacker can calibrate against'
)

# Allowlist: pairs "category:filename" where the category is documented to be
# acceptable in that specific file (for instance, env vars in the configuration
# guide are user-facing config, not engineering leakage).
ALLOWLIST=(
  "env:docs/configuration.md"      # configuration guide — user-set env vars belong here
  "env:docs/getting-started.md"    # install guide — first-boot env vars belong here
  "env:docs/telemetry.md"          # telemetry doc — TC_TELEMETRY_DISABLED is the documented opt-out
  "api:docs/configuration.md"      # configuration mentions /api/tc/agent/mode
)

is_allowed() {
  local cat="$1" file="$2"
  for entry in "${ALLOWLIST[@]}"; do
    if [ "$entry" = "${cat}:${file}" ]; then
      return 0
    fi
  done
  return 1
}

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

failures=0

bold "Public docs leak check"
echo "  Files: ${FILES[*]}"
echo "  Patterns: $((${#PATTERNS[@]} / 2))"
echo

i=0
while [ $i -lt ${#PATTERNS[@]} ]; do
  regex="${PATTERNS[$i]}"
  meta="${PATTERNS[$((i + 1))]}"
  category="${meta#|}"; category="${category%%|*}"
  reason="${meta##*|}"

  # grep -nE against all files at once. -H prefixes file:line for clarity.
  raw_matches=$(grep -nHE "$regex" "${FILES[@]}" 2>/dev/null \
            | grep -v 'doc-leak-ok' \
            || true)

  # Filter out matches whose file is allowlisted for this category.
  matches=""
  if [ -n "$raw_matches" ]; then
    while IFS= read -r line; do
      file="${line%%:*}"
      if is_allowed "$category" "$file"; then
        continue
      fi
      matches+="${line}"$'\n'
    done <<< "$raw_matches"
    matches="${matches%$'\n'}"
  fi

  if [ -n "$matches" ]; then
    red "  [LEAK:${category}] $reason"
    while IFS= read -r line; do
      printf '         %s\n' "$line" >&2
    done <<< "$matches"
    echo >&2
    failures=$((failures + $(echo "$matches" | wc -l)))
  fi

  i=$((i + 2))
done

if [ "$failures" -eq 0 ]; then
  green "  OK — no leak patterns matched."
  exit 0
fi

red "FAIL — $failures leak match(es) found in public docs."
red ""
red "Each match above lists file:line:matched-text. Either:"
red "  1. Rewrite the line at brand level (the right answer 95% of the time)."
red "  2. Move the engineering detail to internal/ (Forgejo-only)."
red "  3. If the match is a documented false positive, append"
red "     '<!-- doc-leak-ok: <one-line rationale> -->' on the same line."
red ""
red "See: scripts/check-public-docs.sh + memory feedback_public_docs_brand_layer.md"
exit 1
