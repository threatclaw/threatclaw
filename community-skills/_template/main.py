#!/usr/bin/env python3
"""
skill-CHANGEME — CHANGEME description.

This skill [does what] by [using which API/method]
and reports findings to ThreatClaw for AI correlation.
"""

import json
import os
import sys
import urllib.request
import urllib.error

# ── ThreatClaw SDK ──────────────────────────────────────

THREATCLAW_API = os.environ.get("THREATCLAW_API_URL", "http://host.docker.internal:3000")
SKILL_ID = "skill-CHANGEME"


def get_config() -> dict:
    """Load skill configuration from ThreatClaw."""
    try:
        req = urllib.request.Request(f"{THREATCLAW_API}/api/tc/config/{SKILL_ID}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {item["key"]: item["value"] for item in data.get("config", [])}
    except Exception as e:
        print(f"[WARN] Could not load config: {e}", file=sys.stderr)
        return {}


def report_finding(title: str, severity: str, asset: str, source: str,
                   description: str = "", category: str = "general",
                   metadata: dict = None):
    """Submit a finding to ThreatClaw."""
    finding = {
        "skill_id": SKILL_ID,
        "title": title,
        "severity": severity,
        "asset": asset,
        "source": source,
        "description": description,
        "category": category,
        "metadata": metadata or {},
    }
    body = json.dumps(finding).encode()
    req = urllib.request.Request(
        f"{THREATCLAW_API}/api/tc/findings",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            print(f"[OK] Finding reported: {title}")
            return result
    except Exception as e:
        print(f"[ERROR] Could not submit finding: {e}", file=sys.stderr)
        return None


def get_findings(limit: int = 100) -> list:
    """Read existing findings from ThreatClaw (useful for correlation skills)."""
    try:
        req = urllib.request.Request(f"{THREATCLAW_API}/api/tc/findings?limit={limit}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("findings", [])
    except Exception:
        return []


# ── Your logic here ─────────────────────────────────────

def check(api_key: str, target: str) -> list:
    """
    CHANGEME — Implement your check logic here.

    Args:
        api_key: API key from the skill configuration.
        target: The target to check (IP, domain, email, etc.)

    Returns:
        List of findings (dicts) to report.
    """
    findings = []

    try:
        # CHANGEME — Replace with your API call
        req = urllib.request.Request(
            f"https://api.example.com/v1/check?q={target}",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

            # CHANGEME — Parse the response and create findings
            if data.get("risk_score", 0) > 70:
                findings.append({
                    "title": f"Issue detected: {target}",
                    "severity": "HIGH",
                    "asset": target,
                    "source": "example-api",
                    "category": "monitoring",
                    "description": f"Risk score: {data['risk_score']}",
                    "metadata": data,
                })

    except urllib.error.HTTPError as e:
        print(f"[ERROR] API error for {target}: HTTP {e.code}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Check failed for {target}: {e}", file=sys.stderr)

    return findings


# ── Main ────────────────────────────────────────────────

def main():
    print(f"[INFO] {SKILL_ID} starting")

    config = get_config()
    api_key = config.get("api_key", "")
    targets = config.get("targets", "")

    if not api_key:
        print("[ERROR] No API key configured — go to Dashboard > Skills > Configure", file=sys.stderr)
        sys.exit(1)

    if not targets:
        print("[WARN] No targets configured — nothing to check", file=sys.stderr)
        sys.exit(0)

    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    print(f"[INFO] Checking {len(target_list)} target(s)")

    total = 0
    for target in target_list:
        for finding in check(api_key, target):
            report_finding(**finding)
            total += 1

    print(f"[INFO] Done — {total} finding(s) reported")


if __name__ == "__main__":
    main()
