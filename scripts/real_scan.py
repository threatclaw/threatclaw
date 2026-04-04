#!/usr/bin/env python3
"""Real scan of the local host using Nuclei + nmap, results pushed to ThreatClaw API."""

import json
import os
import subprocess
import sys

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from threatclaw_sdk import ThreatClawClient, Finding, Severity

TARGET = os.environ.get("TC_SCAN_TARGET", "127.0.0.1")
API_URL = "http://127.0.0.1:3000"
API_TOKEN = os.environ.get("TC_API_TOKEN", "")

client = ThreatClawClient(api_url=API_URL, api_token=API_TOKEN)

# Verify API connection
try:
    health = client.health()
    print(f"[+] API connectée: {health['status']} v{health['version']}")
except Exception as e:
    print(f"[-] API non disponible: {e}")
    sys.exit(1)

# ── Step 1: Nmap port scan ──
print(f"\n[*] Scan nmap sur {TARGET}...")
try:
    nmap_result = subprocess.run(
        ["nmap", "-sV", "--top-ports", "100", "-oX", "-", TARGET],
        capture_output=True, text=True, timeout=120
    )
    nmap_output = nmap_result.stdout

    # Parse XML output for open ports
    import xml.etree.ElementTree as ET
    root = ET.fromstring(nmap_output)

    ports_found = []
    for host in root.findall(".//host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                portid = port.get("portid")
                protocol = port.get("protocol")
                service = port.find("service")
                svc_name = service.get("name", "unknown") if service is not None else "unknown"
                svc_version = service.get("version", "") if service is not None else ""
                svc_product = service.get("product", "") if service is not None else ""

                ports_found.append({
                    "port": portid,
                    "protocol": protocol,
                    "service": svc_name,
                    "product": svc_product,
                    "version": svc_version,
                })

                # Determine severity based on service
                severity = Severity.INFO
                title = f"Port {portid}/{protocol} ouvert — {svc_name}"

                if svc_name in ("ssh",):
                    severity = Severity.LOW
                    title = f"SSH ouvert sur port {portid}"
                elif svc_name in ("http", "http-proxy"):
                    severity = Severity.LOW
                    title = f"HTTP ouvert sur port {portid} ({svc_product} {svc_version})".strip()
                elif svc_name in ("mysql", "postgresql", "redis", "mongodb"):
                    severity = Severity.HIGH
                    title = f"Base de données {svc_name} exposée sur port {portid}"
                elif svc_name in ("ftp", "telnet"):
                    severity = Severity.HIGH
                    title = f"Service non sécurisé {svc_name} sur port {portid}"

                finding_id = client.report_finding(Finding(
                    skill_id="skill-vuln-scan",
                    title=title,
                    severity=severity,
                    asset=f"{TARGET}:{portid}",
                    source="nmap",
                    category="scanning",
                    description=f"Service: {svc_product} {svc_version}".strip() if svc_product else None,
                    metadata={"port": portid, "protocol": protocol, "service": svc_name,
                              "product": svc_product, "version": svc_version},
                ))
                print(f"  [+] Finding #{finding_id}: {title} [{severity}]")

    print(f"  [=] {len(ports_found)} ports ouverts détectés")

except FileNotFoundError:
    print("  [-] nmap non installé, skip")
except subprocess.TimeoutExpired:
    print("  [-] nmap timeout")
except Exception as e:
    print(f"  [-] nmap erreur: {e}")

# ── Step 2: Nuclei scan via Docker ──
print(f"\n[*] Scan Nuclei sur {TARGET}...")
try:
    nuclei_result = subprocess.run(
        ["docker", "exec", "docker-nuclei-1", "nuclei",
         "-target", TARGET,
         "-severity", "critical,high,medium",
         "-json",
         "-silent",
         "-rate-limit", "50",
         "-timeout", "5",
         "-retries", "1",
         "-bulk-size", "25",
         "-concurrency", "10"],
        capture_output=True, text=True, timeout=300
    )

    nuclei_findings = 0
    for line in nuclei_result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        try:
            result = json.loads(line)
            template_id = result.get("template-id", "unknown")
            name = result.get("info", {}).get("name", template_id)
            severity = result.get("info", {}).get("severity", "info").lower()
            matched_at = result.get("matched-at", TARGET)
            description = result.get("info", {}).get("description", "")
            tags = result.get("info", {}).get("tags", [])
            reference = result.get("info", {}).get("reference", [])

            # Map severity
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            sev = sev_map.get(severity, Severity.INFO)

            finding_id = client.report_finding(Finding(
                skill_id="skill-vuln-scan",
                title=f"{name}",
                severity=sev,
                asset=matched_at,
                source="nuclei",
                category="scanning",
                description=description[:500] if description else None,
                metadata={"template": template_id, "tags": tags,
                          "reference": reference[:3] if reference else []},
            ))
            nuclei_findings += 1
            print(f"  [+] Finding #{finding_id}: {name} [{severity}] @ {matched_at}")
        except json.JSONDecodeError:
            continue

    print(f"  [=] {nuclei_findings} vulnérabilités Nuclei détectées")

    if nuclei_result.stderr:
        errors = [l for l in nuclei_result.stderr.split("\n") if "ERR" in l or "WRN" in l]
        if errors:
            print(f"  [!] {len(errors)} warnings/errors Nuclei")

except subprocess.TimeoutExpired:
    print("  [-] Nuclei timeout (5 min)")
except Exception as e:
    print(f"  [-] Nuclei erreur: {e}")

# ── Step 3: Check final metrics ──
print("\n[*] Métriques finales:")
try:
    metrics = client.get_dashboard_metrics()
    print(f"  Critiques : {metrics.get('findings_critical', 0)}")
    print(f"  Hautes    : {metrics.get('findings_high', 0)}")
    print(f"  Moyennes  : {metrics.get('findings_medium', 0)}")
    print(f"  Basses    : {metrics.get('findings_low', 0)}")
    print(f"  Alertes   : {metrics.get('alerts_total', 0)}")
except Exception as e:
    print(f"  [-] Erreur métriques: {e}")

print("\n[+] Scan terminé — les résultats sont visibles sur le dashboard")
