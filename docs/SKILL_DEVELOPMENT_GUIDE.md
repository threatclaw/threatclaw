# ThreatClaw Skill Development Guide

## What is a Skill?

A skill is a **sensor** that feeds ThreatClaw with security data. It observes, checks, verifies — then reports what it found. ThreatClaw's AI engine correlates the findings from all your skills to detect real threats.

```
Your Skill                          ThreatClaw Core
┌──────────────────────┐           ┌──────────────────────┐
│                      │           │                      │
│  Check an IP on      │  finding  │  Stores in database  │
│  AbuseIPDB           │ ───────→  │  AI correlates with  │
│                      │           │  other findings      │
│  Check a domain's    │  finding  │  Proposes actions    │
│  SSL certificate     │ ───────→  │  Alerts the RSSI     │
│                      │           │                      │
│  Scan a WordPress    │  finding  │  Triggers response   │
│  for known CVEs      │ ───────→  │  via HITL            │
│                      │           │                      │
└──────────────────────┘           └──────────────────────┘

A skill OBSERVES.
ThreatClaw DECIDES and ACTS.
```

**A skill can NOT:**
- Execute commands on the host
- Access the database directly
- Modify ThreatClaw's configuration
- Access other skills' data
- Access the filesystem

**A skill can:**
- Call external APIs (with declared permissions)
- Read its own configuration (API keys, targets)
- Submit findings to ThreatClaw
- Read existing findings (for correlation skills like compliance checks)

---

## Two Types of Skills

| | Community Skill | Official Skill |
|---|---|---|
| **Language** | Python | Rust |
| **Runtime** | Docker container (isolated) | WASM sandbox (fuel-metered) |
| **Who writes it** | Anyone | ThreatClaw team |
| **Security** | network:none, 256MB RAM, read-only FS, timeout 5min | Cryptographically signed, 10MB RAM, fuel-metered |
| **Distribution** | GitHub PR → review → merge | Ships with ThreatClaw |
| **Best for** | API integrations, compliance checks, custom scanners | Core functionality, high-performance |

**This guide focuses on community skills (Python).** If you want to build an official skill in Rust/WASM, see [Official Skills](#official-skills-rustwasm) at the end.

---

## Quick Start — Your First Skill in 10 Minutes

### 1. Create the structure

```bash
mkdir skill-my-checker && cd skill-my-checker
```

```
skill-my-checker/
├── main.py              # Your code
├── requirements.txt     # Python dependencies
├── Dockerfile           # Container definition
├── skill.json           # Metadata (required)
├── README.md            # Documentation (required)
└── tests/
    └── test_main.py     # At least 3 tests (required)
```

### 2. Define your skill — `skill.json`

```json
{
  "id": "skill-my-checker",
  "name": "My Security Checker",
  "version": "1.0.0",
  "description": "Checks something useful for security",
  "author": "Your Name <you@example.com>",
  "license": "Apache-2.0",
  "trust": "community",
  "category": "monitoring",
  "runtime": "docker",

  "requires_network": true,
  "timeout_seconds": 300,
  "memory_mb": 256,

  "config_fields": [
    {
      "key": "api_key",
      "label": "API Key",
      "type": "password",
      "required": true,
      "placeholder": "Your API key from example.com",
      "help_url": "https://example.com/get-api-key"
    },
    {
      "key": "targets",
      "label": "Targets to check",
      "type": "text",
      "required": true,
      "placeholder": "example.com, example.org",
      "description": "Comma-separated list of domains"
    }
  ],

  "capabilities": {
    "http_allowed": true,
    "http_allowlist": [
      "https://api.example.com/*"
    ],
    "workspace_read": false,
    "secrets": ["api_key"]
  },

  "test": {
    "endpoint": "https://api.example.com/v1/status",
    "method": "GET",
    "auth_header": "Authorization",
    "auth_format": "Bearer {api_key}",
    "expected_status": 200
  }
}
```

**Categories:** `scanning`, `monitoring`, `compliance`, `intel`, `reporting`, `infrastructure`

### 3. Write your skill — `main.py`

```python
#!/usr/bin/env python3
"""
skill-my-checker — Checks domains for security issues.

This skill connects to an external API, checks configured domains,
and reports findings to ThreatClaw for AI correlation.
"""

import json
import os
import sys
import urllib.request
import urllib.error

# ── ThreatClaw SDK ──────────────────────────────────────

THREATCLAW_API = os.environ.get("THREATCLAW_API_URL", "http://host.docker.internal:3000")

def get_config(skill_id: str) -> dict:
    """Load skill configuration from ThreatClaw."""
    try:
        req = urllib.request.Request(f"{THREATCLAW_API}/api/tc/config/{skill_id}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {item["key"]: item["value"] for item in data.get("config", [])}
    except Exception as e:
        print(f"[WARN] Could not load config: {e}", file=sys.stderr)
        return {}

def report_finding(finding: dict):
    """Submit a finding to ThreatClaw."""
    body = json.dumps(finding).encode()
    req = urllib.request.Request(
        f"{THREATCLAW_API}/api/tc/findings",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[ERROR] Could not submit finding: {e}", file=sys.stderr)
        return None

def get_findings(limit: int = 100) -> list:
    """Read existing findings from ThreatClaw (for correlation skills)."""
    try:
        req = urllib.request.Request(f"{THREATCLAW_API}/api/tc/findings?limit={limit}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("findings", [])
    except Exception:
        return []

# ── Your skill logic ────────────────────────────────────

def check_domain(api_key: str, domain: str) -> list:
    """Check a domain and return findings."""
    findings = []

    try:
        req = urllib.request.Request(
            f"https://api.example.com/v1/check?domain={domain}",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

            if data.get("issues"):
                for issue in data["issues"]:
                    findings.append({
                        "skill_id": "skill-my-checker",
                        "title": f"{issue['type']}: {domain}",
                        "description": issue.get("description", ""),
                        "severity": issue.get("severity", "MEDIUM").upper(),
                        "category": "domain-security",
                        "asset": domain,
                        "source": "my-checker-api",
                        "metadata": {"raw": issue},
                    })

    except urllib.error.HTTPError as e:
        print(f"[ERROR] API error for {domain}: {e.code}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Check failed for {domain}: {e}", file=sys.stderr)

    return findings

# ── Main ────────────────────────────────────────────────

def main():
    print("[INFO] skill-my-checker starting")

    # Load config
    config = get_config("skill-my-checker")
    api_key = config.get("api_key", "")
    targets = config.get("targets", "")

    if not api_key:
        print("[ERROR] No API key configured", file=sys.stderr)
        sys.exit(1)

    if not targets:
        print("[ERROR] No targets configured", file=sys.stderr)
        sys.exit(1)

    domains = [d.strip() for d in targets.split(",") if d.strip()]
    print(f"[INFO] Checking {len(domains)} domain(s)")

    total_findings = 0
    for domain in domains:
        findings = check_domain(api_key, domain)
        for finding in findings:
            result = report_finding(finding)
            if result:
                total_findings += 1
                print(f"[OK] Finding reported: {finding['title']}")

    print(f"[INFO] Done — {total_findings} finding(s) reported")

if __name__ == "__main__":
    main()
```

### 4. Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# Security: non-root user
RUN useradd -m -s /bin/sh skilluser

# Install dependencies (if any)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# Copy skill code
COPY main.py skill.json ./

USER skilluser
CMD ["python3", "main.py"]
```

### 5. Test locally

```bash
# Set your API key for testing
export THREATCLAW_API_URL="http://localhost:3000"

# Run directly
python3 main.py

# Or via Docker
docker build -t skill-my-checker .
docker run --rm \
  -e THREATCLAW_API_URL=http://host.docker.internal:3000 \
  --network none \
  --memory 256m \
  --read-only \
  --tmpfs /tmp:size=64m \
  skill-my-checker
```

### 6. Write tests — `tests/test_main.py`

```python
import unittest
from unittest.mock import patch, MagicMock
from main import check_domain

class TestMyChecker(unittest.TestCase):

    @patch("main.urllib.request.urlopen")
    def test_check_domain_with_issues(self, mock_urlopen):
        """Should return findings when issues are detected."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"issues": [{"type": "expired-cert", "severity": "HIGH", "description": "SSL expired"}]}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        findings = check_domain("test-key", "example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("example.com", findings[0]["title"])

    @patch("main.urllib.request.urlopen")
    def test_check_domain_clean(self, mock_urlopen):
        """Should return empty list when no issues found."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"issues": []}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        findings = check_domain("test-key", "google.com")
        self.assertEqual(len(findings), 0)

    @patch("main.urllib.request.urlopen")
    def test_check_domain_api_error(self, mock_urlopen):
        """Should handle API errors gracefully."""
        mock_urlopen.side_effect = Exception("Connection refused")

        findings = check_domain("test-key", "unreachable.com")
        self.assertEqual(len(findings), 0)  # Graceful failure

if __name__ == "__main__":
    unittest.main()
```

Run tests: `python3 -m pytest tests/ -v`

---

## Examples — 3 Common Skill Types

### Type 1: API Lookup (most common)

**Use case:** Check an IP/domain/hash against a threat intelligence API.

```python
# skill-ip-reputation/main.py
def check_ip(api_key, ip):
    """Check IP reputation on an external API."""
    req = urllib.request.Request(
        f"https://api.threatintel.com/v1/ip/{ip}",
        headers={"X-API-Key": api_key},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())

    if data["risk_score"] > 70:
        report_finding({
            "skill_id": "skill-ip-reputation",
            "title": f"High-risk IP detected: {ip} (score: {data['risk_score']})",
            "severity": "HIGH" if data["risk_score"] > 90 else "MEDIUM",
            "category": "threat-intel",
            "asset": ip,
            "source": "threatintel-api",
            "metadata": {"score": data["risk_score"], "tags": data.get("tags", [])},
        })
```

**Other examples:** AbuseIPDB, Shodan, VirusTotal, CrowdSec, GreyNoise, AlienVault OTX, URLhaus.

### Type 2: Compliance Check

**Use case:** Read existing findings and map them to a compliance framework.

```python
# skill-compliance-pci/main.py
def check_pci_compliance():
    """Map findings to PCI-DSS 4.0 requirements."""
    findings = get_findings(limit=500)

    # PCI-DSS 4.0 requirements mapping
    pci_reqs = {
        "1.1": {"title": "Network segmentation", "checks": ["open-port", "firewall"]},
        "2.1": {"title": "Default credentials", "checks": ["default-creds", "weak-password"]},
        "6.1": {"title": "Vulnerability management", "checks": ["cve-critical", "cve-high"]},
        "8.1": {"title": "Access control", "checks": ["brute-force", "no-mfa"]},
        # ... 12 requirements
    }

    for req_id, req in pci_reqs.items():
        # Check if any finding covers this requirement
        covered = any(
            f["category"] in req["checks"]
            for f in findings
        )
        if not covered:
            report_finding({
                "skill_id": "skill-compliance-pci",
                "title": f"PCI-DSS {req_id} not covered: {req['title']}",
                "severity": "MEDIUM",
                "category": "compliance-pci",
                "asset": "organization",
                "source": "pci-dss-4.0",
            })
```

**Other examples:** ANSSI Hygiene 42, NIST CSF, CIS Controls, HIPAA, SOC 2.

### Type 3: Monitoring / Watchdog

**Use case:** Continuously check for a specific condition.

```python
# skill-cert-monitor/main.py
import ssl
import socket
import datetime

def check_certificate(domain):
    """Check SSL certificate expiry."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days

        if days_left < 30:
            severity = "CRITICAL" if days_left < 7 else "HIGH" if days_left < 14 else "MEDIUM"
            report_finding({
                "skill_id": "skill-cert-monitor",
                "title": f"SSL certificate expires in {days_left} days: {domain}",
                "severity": severity,
                "category": "certificate",
                "asset": domain,
                "source": "cert-check",
                "metadata": {"expiry": expiry.isoformat(), "days_left": days_left},
            })

    except Exception as e:
        report_finding({
            "skill_id": "skill-cert-monitor",
            "title": f"SSL certificate unreachable: {domain}",
            "severity": "HIGH",
            "category": "certificate",
            "asset": domain,
            "source": "cert-check",
            "metadata": {"error": str(e)},
        })
```

**Other examples:** DNS record changes, GitHub secret leaks, domain expiry, HTTP uptime.

---

## Finding Format

Every finding you submit must follow this schema:

```json
{
  "skill_id": "skill-your-id",
  "title": "Short, clear title of what was found",
  "description": "Detailed explanation",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "category": "threat-intel | compliance | certificate | vulnerability | credential-leak | ...",
  "asset": "The affected resource (IP, domain, hostname, email, ...)",
  "source": "Where the data came from (api-name, scan-tool, ...)",
  "metadata": {}
}
```

| Field | Required | Description |
|---|---|---|
| `skill_id` | Yes | Must match your `skill.json` id |
| `title` | Yes | One line, actionable. "Expired SSL on example.com" not "SSL check" |
| `severity` | Yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `category` | Yes | Used by the AI for correlation |
| `asset` | Yes | What is affected — the AI uses this to link findings |
| `source` | Yes | Data provenance |
| `description` | No | Detailed explanation for the RSSI |
| `metadata` | No | Raw data, scores, timestamps — stored as JSON |

**Severity guidelines:**

| Severity | When to use | Example |
|---|---|---|
| `CRITICAL` | Immediate action required, active exploit | RCE vulnerability, leaked credentials, active brute force |
| `HIGH` | Significant risk, should be fixed soon | Expired SSL, open RDP, known CVE with public exploit |
| `MEDIUM` | Notable but not urgent | Missing SPF record, outdated software, weak cipher |
| `LOW` | Informational, best practice | Missing DKIM, DNS info disclosure, non-critical finding |

---

## Security Constraints

Community skills run in a **Docker container** with these restrictions:

```yaml
# These are enforced by ThreatClaw — you cannot override them
network_mode: "none"              # No network access by default
mem_limit: 256m                   # 256 MB maximum RAM
cpu_shares: 512                   # Limited CPU
read_only: true                   # Read-only filesystem
tmpfs:
  - /tmp:size=64m                 # Only /tmp is writable (64 MB)
security_opt:
  - no-new-privileges:true        # No privilege escalation
cap_drop:
  - ALL                           # No Linux capabilities
```

**If your skill needs network access** (to call an API), set `"requires_network": true` in `skill.json` and declare allowed URLs in `capabilities.http_allowlist`. ThreatClaw will grant network access **only to those URLs**.

**Communication with ThreatClaw:** via the `THREATCLAW_API_URL` environment variable, which points to the internal API. This is the only allowed endpoint regardless of network settings.

---

## Submission Process

### 1. Prepare

- [ ] `skill.json` with all required fields
- [ ] `main.py` with clear logic and error handling
- [ ] `Dockerfile` based on `python:3.12-slim`
- [ ] `requirements.txt` (keep dependencies minimal)
- [ ] `README.md` with: what it does, prerequisites, configuration, example output
- [ ] `tests/test_main.py` with at least 3 tests
- [ ] No hardcoded credentials in code
- [ ] No `os.system()`, `subprocess`, `exec()`, `eval()` calls
- [ ] Graceful error handling (never crash on API errors)

### 2. Test

```bash
# Run tests
python3 -m pytest tests/ -v

# Build and run in Docker
docker build -t skill-your-name .
docker run --rm --network none --memory 256m --read-only --tmpfs /tmp:size=64m skill-your-name
```

### 3. Submit

1. Fork [github.com/threatclaw/threatclaw](https://github.com/threatclaw/threatclaw)
2. Create `community-skills/skill-your-name/` with all files
3. Open a Pull Request with the **Skill Submission** template
4. Describe: what it does, which API it uses, what findings it produces
5. The ThreatClaw team reviews your code

### 4. Review Process

Your PR will go through:

1. **Automated checks** — Dockerfile builds, tests pass, `skill.json` validates
2. **Code review** — No dangerous calls, clean error handling, useful findings
3. **Security review** — No data exfiltration, no excessive permissions
4. **Functional test** — We run the skill with a test API key to verify output

After approval, your skill is merged and available to all ThreatClaw users.

---

## Review Checklist

| Check | Required | Why |
|---|---|---|
| `skill.json` has all fields | Yes | Dashboard needs it to display config |
| No `os.system`, `subprocess`, `exec`, `eval` | Yes | Security — no command execution |
| No file access outside `/app/` and `/tmp/` | Yes | Sandbox integrity |
| `Dockerfile` uses `python:3.12-slim` | Yes | Consistent base, small image |
| Error handling on all API calls | Yes | Skills must never crash |
| At least 3 unit tests | Yes | Quality assurance |
| Dependencies < 50MB installed | Yes | Image size limit |
| `README.md` with description and examples | Yes | Documentation |
| `LICENSE` or license in `skill.json` | Yes | Legal clarity |
| API key not hardcoded | Yes | Security 101 |
| Rate limiting respected | Recommended | Don't get the user's API key banned |
| Findings have correct severity | Recommended | AI correlation quality |

---

## Official Skills (Rust/WASM)

Official skills are written in Rust and compiled to WebAssembly. They run in the WASM sandbox with stronger isolation:

- **Fuel metering:** max 1.2 billion operations per execution
- **Memory:** max 10 MB
- **Signed:** cryptographic integrity verified at load time
- **No filesystem:** only `host::workspace_read()` with validated paths
- **HTTP allowlist:** only declared endpoints are reachable
- **Credential injection:** API keys are injected at the HTTP boundary, never visible to WASM code
- **Leak detection:** all outputs are scanned for credential patterns

Official skills ship with ThreatClaw and are maintained by the core team. If you want to contribute an official skill, open an issue first to discuss the design.

### Structure

```
skills-src/skill-name/
├── Cargo.toml
├── src/lib.rs
└── skill.json
```

### Minimal lib.rs

```rust
wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;

struct MySkill;
export!(MySkill);

impl Guest for MySkill {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "my-skill: starting");

        let params: serde_json::Value =
            serde_json::from_str(&req.params).unwrap_or_default();

        // Your logic here...
        // Submit findings via host::http_request()

        Response {
            output: Some("done".to_string()),
            error: None,
        }
    }

    fn schema() -> String {
        r#"{"type": "object", "properties": {}}"#.to_string()
    }

    fn description() -> String {
        "What this skill does.".to_string()
    }
}
```

### Compile

```bash
cargo build --release --target wasm32-wasip2
# Output: target/wasm32-wasip2/release/skill_name.wasm
```

---

## FAQ

**Q: Can my skill call any URL?**
No. You must declare allowed URLs in `skill.json` under `capabilities.http_allowlist`. ThreatClaw blocks all other URLs.

**Q: How does my skill get its API key?**
The user configures it in the ThreatClaw dashboard (Settings > Skills > Configure). Your skill reads it via `get_config("skill-id")`.

**Q: Can I use `requests` instead of `urllib`?**
Yes, add it to `requirements.txt`. But `urllib` is built-in and keeps the image smaller.

**Q: How often does my skill run?**
That depends on the ThreatClaw scheduler. By default, monitoring skills run every 30 minutes, but the RSSI can configure the frequency per skill.

**Q: Can my skill read findings from other skills?**
Yes. Use `get_findings()` to read existing findings. This is how compliance skills work — they read all findings and map them to a framework.

**Q: What happens if my skill crashes?**
ThreatClaw catches the error, logs it, and continues. Your skill's findings from before the crash are preserved. A crashed skill doesn't affect other skills or the core agent.

**Q: Can I test without a running ThreatClaw instance?**
Yes. Mock the API calls in your tests. The SDK functions use standard HTTP — you can use `unittest.mock` to test everything locally.

---

## Need Help?

- [GitHub Discussions](https://github.com/threatclaw/threatclaw/discussions) — Ask questions, share ideas
- [Existing skills](https://github.com/threatclaw/threatclaw/tree/main/skills-src) — Read the source of official skills for inspiration
- [Issue: Skill Request](https://github.com/threatclaw/threatclaw/issues/new?template=skill_submission.yml) — Propose a new skill idea before coding
