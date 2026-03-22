#!/usr/bin/env bash
# ThreatClaw — Offline Bundle Downloader
# Downloads CVE, MITRE ATT&CK, CrowdSec, and Sigma data for air-gapped environments.
#
# Usage: ./scripts/download-offline-bundle.sh [output_dir]
# Default output: ./offline-bundle/

set -euo pipefail

BUNDLE_DIR="${1:-./offline-bundle}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "╔══════════════════════════════════════════════════╗"
echo "║  ThreatClaw — Offline Bundle Downloader         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

mkdir -p "$BUNDLE_DIR"/{cve,mitre,sigma,crowdsec}

# ── 1. MITRE ATT&CK Enterprise (STIX JSON) ──
echo "[1/5] Downloading MITRE ATT&CK Enterprise..."
curl -sL -o "$BUNDLE_DIR/mitre/enterprise-attack.json" \
  "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_COUNT=$(python3 -c "import json; d=json.load(open('$BUNDLE_DIR/mitre/enterprise-attack.json')); print(len([o for o in d['objects'] if o.get('type')=='attack-pattern' and not o.get('revoked')]))" 2>/dev/null || echo "?")
echo "    ✓ ${MITRE_COUNT} techniques"

# ── 2. NVD CVE Feed (CVSS ≥ 7.0, recent) ──
echo "[2/5] Downloading NVD CVE feed (CVSS ≥ 7.0, last 120 days)..."
# NVD API v2 — fetch recent critical/high CVEs
START_DATE=$(date -d "-120 days" +%Y-%m-%dT00:00:00.000 2>/dev/null || date -v-120d +%Y-%m-%dT00:00:00.000 2>/dev/null || echo "2026-01-01T00:00:00.000")
curl -sL -o "$BUNDLE_DIR/cve/nvd-recent-high.json" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&pubStartDate=${START_DATE}&resultsPerPage=2000" || true
curl -sL -o "$BUNDLE_DIR/cve/nvd-recent-critical.json" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=${START_DATE}&resultsPerPage=2000" || true
CVE_HIGH=$(python3 -c "import json; d=json.load(open('$BUNDLE_DIR/cve/nvd-recent-high.json')); print(d.get('totalResults',0))" 2>/dev/null || echo "?")
CVE_CRIT=$(python3 -c "import json; d=json.load(open('$BUNDLE_DIR/cve/nvd-recent-critical.json')); print(d.get('totalResults',0))" 2>/dev/null || echo "?")
echo "    ✓ ${CVE_CRIT} critical + ${CVE_HIGH} high CVEs"

# ── 3. CISA KEV (Known Exploited Vulnerabilities) ──
echo "[3/5] Downloading CISA KEV catalog..."
curl -sL -o "$BUNDLE_DIR/cve/cisa-kev.json" \
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_COUNT=$(python3 -c "import json; d=json.load(open('$BUNDLE_DIR/cve/cisa-kev.json')); print(len(d.get('vulnerabilities',[])))" 2>/dev/null || echo "?")
echo "    ✓ ${KEV_COUNT} known exploited vulnerabilities"

# ── 4. Sigma Rules (SigmaHQ) ──
echo "[4/5] Downloading Sigma detection rules..."
curl -sL -o "$BUNDLE_DIR/sigma/sigma-rules.tar.gz" \
  "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz"
SIGMA_SIZE=$(du -sh "$BUNDLE_DIR/sigma/sigma-rules.tar.gz" 2>/dev/null | cut -f1 || echo "?")
echo "    ✓ Sigma rules archive (${SIGMA_SIZE})"

# ── 5. CrowdSec Community Blocklist ──
echo "[5/5] Downloading CrowdSec community blocklist..."
curl -sL -o "$BUNDLE_DIR/crowdsec/community-blocklist.txt" \
  "https://raw.githubusercontent.com/crowdsecurity/crowdsec-cloud-blocklists/main/data/firehol_level1.netset" || true
CS_COUNT=$(wc -l < "$BUNDLE_DIR/crowdsec/community-blocklist.txt" 2>/dev/null || echo "0")
echo "    ✓ ${CS_COUNT} blocked IPs"

# ── Bundle metadata ──
BUNDLE_SIZE=$(du -sh "$BUNDLE_DIR" | cut -f1)
cat > "$BUNDLE_DIR/bundle-meta.json" <<METAEOF
{
  "version": "1.0",
  "created_at": "$(date -Iseconds)",
  "cve_critical": ${CVE_CRIT:-0},
  "cve_high": ${CVE_HIGH:-0},
  "kev_count": ${KEV_COUNT:-0},
  "mitre_techniques": ${MITRE_COUNT:-0},
  "crowdsec_ips": ${CS_COUNT:-0},
  "sigma_archive": true,
  "bundle_size": "${BUNDLE_SIZE}"
}
METAEOF

echo ""
echo "══════════════════════════════════════════════════"
echo "  Bundle ready: $BUNDLE_DIR"
echo "  Size: $BUNDLE_SIZE"
echo ""
echo "  To use in air-gapped mode:"
echo "    1. Copy $BUNDLE_DIR to the target machine"
echo "    2. Set TC_OFFLINE_BUNDLE=$BUNDLE_DIR in .env"
echo "    3. Restart ThreatClaw"
echo "══════════════════════════════════════════════════"
