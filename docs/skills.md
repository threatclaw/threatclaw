# Skills

ThreatClaw skills are WASM-sandboxed modules that extend the agent's capabilities. Each skill runs in a secure sandbox with no filesystem access, limited memory (10MB), and controlled network access.

## Official Skills

| Skill | Description | Requires API Key |
|-------|------------|-----------------|
| `skill-email-audit` | Checks SPF, DKIM, DMARC records via DNS | No |
| `skill-cti-crowdsec` | IP reputation from CrowdSec community threat intelligence | Free (sign up at app.crowdsec.net) |
| `skill-abuseipdb` | IP abuse score from AbuseIPDB (1000 req/day free) | Free |
| `skill-darkweb-monitor` | Credential leak detection via Have I Been Pwned | Paid (~$3.50/month) |
| `skill-compliance-nis2` | Maps findings to NIS2 Directive Art.21 | No |
| `skill-compliance-iso27001` | Maps findings to ISO 27001:2022 Annex A | No |
| `skill-report-gen` | Generates HTML security reports | No |
| `skill-wazuh` | Imports alerts from an existing Wazuh SIEM | Wazuh credentials |
| `skill-virustotal` | Multi-AV file/URL analysis | Free |
| `skill-shodan` | External attack surface discovery | Paid ($49/year) |

## Installing Skills

WASM skills are placed in `~/.threatclaw/tools/`:

```bash
# Build from source
cd skills-src/skill-email-audit
cargo build --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/skill_email_audit.wasm ~/.threatclaw/tools/

# Create capabilities file
cp skill-email-audit.capabilities.json ~/.threatclaw/tools/
```

Skills are loaded automatically when ThreatClaw starts.

## Building Community Skills

Community skills run in isolated Docker containers. See [SKILL_DEVELOPMENT_GUIDE.md](SKILL_DEVELOPMENT_GUIDE.md) for details.

### Security constraints for community skills

```yaml
network_mode: "none"        # No network access
mem_limit: 256m             # 256MB RAM max
read_only: true             # Read-only filesystem
tmpfs: /tmp:size=64m        # Only /tmp is writable
```

Community skills communicate with ThreatClaw exclusively via the Python SDK over a Unix socket.
